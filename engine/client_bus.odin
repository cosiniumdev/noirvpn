// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import cnet "core:net"
import "core:strings"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:platform/event"
import "noir:proto/mss"
import "noir:proto/push"
import "noir:proto/session"

// Client side of the control bus: events and
// operations (section 5). Runs on the loop thread; the bus never blocks it.
//
// Credentials: if `auth-user-pass` has no file, stdin is not a terminal and the
// control socket is on, the daemon does not prompt. It publishes
// `client.auth_needed` and waits for `auth.supply`. The same applies after a
// refused login with `auth-retry interact` if the credentials did not come from
// the terminal. Challenge/response (`kind: "challenge"`) is NOT offered: the
// client session does not support CRV1 challenges.

// -------------------------------------------------------------------- state

// The state word for `client.state` and `status`.
client_bus_state :: proc(d: ^Daemon) -> string {
	switch {
	case d.exit, d.hold:
		return "stopped"
	case d.state == .Idle:
		return "waiting"
	case d.state == .Tcp_Connecting || d.state == .Proxy_Connecting || d.state == .Tls_Handshaking || d.state == .Ws_Upgrading:
		return "connecting"
	}
	if !d.s_ok || d.close_reason != .None {
		return "closing"
	}
	#partial switch session.session_state(&d.s) {
	case .Closing:
		return "closing"
	}
	return "up" if d.up else "handshake"
}

// Publishes `client.state` when the state changed. `d.bus_reason` (set by the
// caller) says why for a move to `waiting` or `stopped`; it is used up here.
client_note_state :: proc(d: ^Daemon) {
	now_state := client_bus_state(d)
	reason := d.bus_reason
	if now_state == d.bus_state {
		if d.service && now_state == "stopped" {
			// Already reported: a later end of the closing connection adds nothing.
			d.bus_reason = ""
		}
		return
	}
	prev := d.bus_state
	d.bus_state = now_state
	detail := d.detail_next
	if now_state != "waiting" && now_state != "stopped" {
		reason, detail = "", ""
	} else {
		d.detail_next = ""
	}
	d.bus_reason = ""
	d.state_reason = reason
	d.state_detail = detail
	if w := ev_begin(d); w != nil {
		client_state_write(w, d, now_state, prev, reason, detail)
		ev_emit(d, "client.state")
	}
}

// The fields of `client.state`.
client_state_write :: proc(w: ^bus.Writer, d: ^Daemon, state, prev, reason: string, detail := "") {
	bus.kv_str(w, "state", state)
	bus.kv_str(w, "prev", prev)
	bus.kv_str_or_null(w, "reason", reason, reason != "")
	bus.kv_str_or_null(w, "detail", detail, detail != "")
	remote, has_remote := client_remote(d)
	bus.kv_str_or_null(w, "remote", remote, has_remote)
	bus.kv_u64(w, "attempt", d.stats.attempts)
	path, has_path := client_datapath(d)
	bus.kv_str_or_null(w, "datapath", path, has_path)
}

// `host:port` of the server being tried (an address).
client_remote :: proc(d: ^Daemon) -> (string, bool) {
	if d.state == .Idle && !d.s_ok {
		return "", false
	}
	return cnet.endpoint_to_string(d.endpoint, context.temp_allocator), true
}

// ------------------------------------------------------------ tunnel settings

// What the server pushed, once per connection, before `client.state` `up`.
client_ev_tunnel_settings :: proc(d: ^Daemon, po: ^push.Pushed_Options) {
	if w := ev_begin(d); w != nil {
		client_write_tunnel_settings(w, d, po)
		ev_emit(d, "client.tunnel_settings")
	}
}

// The fields of `client.tunnel_settings`; `status` has them too, as
// `client.settings`.
client_write_tunnel_settings :: proc(w: ^bus.Writer, d: ^Daemon, po: ^push.Pushed_Options) {
	bus.kv_u64(w, "peer_id", u64(session.session_peer_id(&d.s)))
	bus.kv_str(w, "cipher", push.cipher_name(session.session_cipher(&d.s)))
	bus.kv_str(w, "data_format", session.session_data_format_name(&d.s))
	bus.kv_obj(w, "ifconfig")
	if ic, ok := po.ifconfig.?; ok {
		bus.kv_str(w, "addr4", ip4_str(ic.a))
		bus.kv_str(w, "netmask4", ip4_str(ic.b))
	} else {
		bus.kv_null(w, "addr4")
		bus.kv_null(w, "netmask4")
	}
	if gw, ok := po.route_gateway.?; ok {
		bus.kv_str(w, "gateway4", ip4_str(gw))
	} else {
		bus.kv_null(w, "gateway4")
	}
	if ic6, ok := po.ifconfig6.?; ok {
		bus.kv_str(w, "addr6", ip6_str(ic6.addr))
		bus.kv_int(w, "prefix6", i64(ic6.bits))
	} else {
		bus.kv_null(w, "addr6")
		bus.kv_null(w, "prefix6")
	}
	bus.end(w)
	if d.plan_ok && d.plan.mtu > 0 {
		bus.kv_int(w, "mtu", i64(d.plan.mtu))
	} else if m, ok := po.tun_mtu.?; ok {
		bus.kv_int(w, "mtu", i64(m))
	} else {
		bus.kv_null(w, "mtu")
	}
	// null: no clamp (mssfix off, or a kernel data path that does not clamp).
	if d.mss4 > 0 && client_mss_line(d) != MSS_NOT_APPLIED {
		bus.kv_int(w, "mss4", i64(d.mss4))
		bus.kv_int(w, "mss6", i64(mss.mss_ipv6(d.mss4)))
	} else {
		bus.kv_null(w, "mss4")
		bus.kv_null(w, "mss6")
	}
	bus.kv_arr(w, "routes")
	for r in po.routes {
		bus.begin_obj(w)
		bus.kv_str(w, "net", fmt.tprintf("%s/%d", ip4_str(r.net), mask_bits(r.mask)))
		gw, has_gw := route_gateway_text(r.gateway, po.route_gateway)
		bus.kv_str_or_null(w, "gateway", gw, has_gw)
		metric, has_metric := r.metric.?
		if !has_metric {
			metric, has_metric = po.route_metric.?
		}
		if has_metric {
			bus.kv_int(w, "metric", i64(metric))
		} else {
			bus.kv_null(w, "metric")
		}
		bus.end(w)
	}
	for r in po.routes6 {
		bus.begin_obj(w)
		bus.kv_str(w, "net", fmt.tprintf("%s/%d", ip6_str(r.net), r.bits))
		gw: string
		has_gw := false
		#partial switch r.gateway.kind {
		case .Addr:
			gw, has_gw = ip6_str(r.gateway.addr), true
		case .Default, .Vpn_Gateway:
			if g, ok := po.route_ipv6_gateway.?; ok {
				gw, has_gw = ip6_str(g), true
			}
		}
		bus.kv_str_or_null(w, "gateway", gw, has_gw)
		metric, has_metric := r.metric.?
		if !has_metric {
			metric, has_metric = po.route_metric.?
		}
		if has_metric {
			bus.kv_int(w, "metric", i64(metric))
		} else {
			bus.kv_null(w, "metric")
		}
		bus.end(w)
	}
	bus.end(w)
	plan: ^client.Plan = &d.plan if d.plan_ok else nil
	client_dns_lists(w, len(d.cfg.dns_options) > 0, plan, po)
	bus.kv_bool(w, "redirect_gateway", po.redirect_gateway.set)
	bus.kv_arr(w, "push")
	for line in d.push_lines {
		bus.val_str(w, line)
	}
	bus.end(w)
	bus.kv_arr(w, "notes")
	if d.plan_ok {
		for n in d.plan.notes {
			if plan_note_for_user(n.kind) {
				bus.val_str(w, n.text)
			}
		}
	}
	bus.end(w)
}

// `dns_servers` and `dns_domains` of the settings event: the pushed lists, or
// with local DNS lines the merged lists of the plan (`plan` nil: no plan).
client_dns_lists :: proc(w: ^bus.Writer, has_local: bool, plan: ^client.Plan, po: ^push.Pushed_Options) {
	bus.kv_arr(w, "dns_servers")
	if has_local {
		if plan != nil && plan.has_dns {
			for s in plan.dns.servers {
				bus.val_str(w, cnet.address_to_string(s.address, context.temp_allocator))
			}
		}
	} else {
		for a in po.dhcp_dns {
			bus.val_str(w, push_ip_text(a))
		}
		for s in po.dns_servers {
			for a in s.addresses {
				bus.val_str(w, push_ip_text(a.ip))
			}
		}
	}
	bus.end(w)
	bus.kv_arr(w, "dns_domains")
	if has_local {
		if plan != nil && plan.has_dns {
			for s in plan.dns.search_domains {
				bus.val_str(w, s)
			}
		}
	} else {
		for s in po.dhcp_domains {
			bus.val_str(w, s)
		}
		for s in po.dns_search_domains {
			bus.val_str(w, s)
		}
	}
	bus.end(w)
}

push_ip_text :: proc(a: push.Ip_Addr) -> string {
	if a.v6 {
		return ip6_str(a.bytes)
	}
	return ip4_str({a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]})
}

route_gateway_text :: proc(g: push.Route_Gw, vpn_gw: Maybe([4]u8)) -> (string, bool) {
	#partial switch g.kind {
	case .Addr:
		return ip4_str(g.addr), true
	case .Default, .Vpn_Gateway:
		if v, ok := vpn_gw.?; ok {
			return ip4_str(v), true
		}
	}
	return "", false
}

// The number of one bits in a netmask.
mask_bits :: proc "contextless" (m: [4]u8) -> int {
	n := 0
	for b in m {
		x := b
		for x != 0 {
			n += int(x & 1)
			x >>= 1
		}
	}
	return n
}

// The options of one PUSH_REPLY message, one line each, for the settings
// event. Secrets are not kept; the total size is capped.
PUSH_LINES_MAX :: 256
PUSH_LINES_BYTES :: 16 * 1024

client_capture_push :: proc(d: ^Daemon, options: string) {
	rest := options
	for len(rest) > 0 {
		item, _ := push.next_item(&rest, ',')
		line := strings.trim_space(item)
		if line == "" || strings.has_prefix(line, "auth-token") || line == "PUSH_REPLY" {
			continue
		}
		if len(d.push_lines) >= PUSH_LINES_MAX || d.push_bytes + len(line) > PUSH_LINES_BYTES {
			return
		}
		append(&d.push_lines, strings.clone(line))
		d.push_bytes += len(line)
	}
}

client_clear_push :: proc(d: ^Daemon) {
	for s in d.push_lines {
		delete(s)
	}
	clear(&d.push_lines)
	d.push_bytes = 0
}

// -------------------------------------------------------------- credentials

// Writes the fields of `client.auth_needed`.
client_write_auth_needed :: proc(w: ^bus.Writer, d: ^Daemon, reason: string, waiting: bool) {
	bus.kv_str(w, "kind", "key_pass" if d.creds_key else "credentials")
	bus.kv_str(w, "reason", reason)
	user := string(d.creds.user[:d.creds.user_n])
	if d.creds_key {
		user = ""
	}
	bus.kv_str_or_null(w, "username", user, user != "")
	bus.kv_null(w, "prompt")
	bus.kv_bool(w, "echo", false)
	bus.kv_null(w, "timeout_s")
}

// The daemon needs credentials. `waiting`: it waits for `auth.supply` (else the
// event only tells that the login failed).
client_publish_auth_needed :: proc(d: ^Daemon, reason: string, waiting: bool) {
	if waiting {
		d.creds_wait = true
		d.creds_reason = reason
		d.creds_announced = true
		logf(.Notice, "waiting for credentials on the control bus (%s)", reason)
	}
	if w := ev_begin(d); w != nil {
		client_write_auth_needed(w, d, reason, waiting)
		ev_emit(d, "client.auth_needed")
	}
}

// ----------------------------------------------------------------- the stats

client_write_stats :: proc(w: ^bus.Writer, d: ^Daemon) {
	dco_client_refresh(d)
	bus.kv_str(w, "datapath", daemon_datapath(d))
	bus.kv_u64(w, "uptime_s", u64(max(now_of(d) - d.started, 0) / time.Second))
	bus.kv_obj(w, "totals")
	bus.kv_u64(w, "bytes_in", d.stats.tun_write_bytes)
	bus.kv_u64(w, "bytes_out", d.stats.tun_read_bytes)
	bus.kv_u64(w, "packets_in", d.stats.tun_write_pkts)
	bus.kv_u64(w, "packets_out", d.stats.tun_read_pkts)
	bus.end(w)
	bus.kv_obj(w, "counters")
	write_u64_fields(w, &d.stats)
	if d.guest != nil {
		guest_write_stats(w, d.guest)
	}
	off_sync_batches(&d.off, &d.rx_batch, {&d.tx_batch})
	write_u64_fields(w, &d.off)
	if d.s_ok {
		c := session.session_counters(&d.s)
		write_u64_fields(w, &c, "session_")
	}
	bus.end(w)
	pool_write_bus(w, d.wk)
}

on_cli_stats_tick :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.t_stats.on = false
	if d.shutting {
		return
	}
	if w := ev_begin(d); w != nil {
		client_write_stats(w, d)
		bus.kv_int(w, "interval_s", i64(d.stats_secs))
		ev_emit(d, "stats.tick")
	}
	client_stats_arm(d)
}

client_stats_arm :: proc(d: ^Daemon) {
	if d.stats_secs <= 0 || !host_events_on(d) {
		timer_clear(d, &d.t_stats)
		return
	}
	timer_set(d, &d.t_stats, now_of(d) + time.Duration(d.stats_secs) * time.Second, on_cli_stats_tick)
}
