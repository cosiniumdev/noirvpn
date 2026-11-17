// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:time"
import "noir:bus"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/session"
import "noir:server"

// The server's side of the control bus: events and
// operations (section 5). The login that waits for a controller is in
// server_auth_ext.odin. Everything runs on the loop thread; the bus never blocks it.

// ------------------------------------------------------------------ events

srv_session_text :: proc(c: ^Conn) -> string {
	return fmt.tprintf("s-%d", c.sess)
}

// The facts of a session as the bus shows them.
srv_view :: proc(d: ^Srv, c: ^Conn) -> Peer_View {
	v: Peer_View
	v.session = srv_session_text(c)
	if c.named {
		v.name = server.identity_str(&c.name)
		v.has_name = true
		v.name_from = identity_source_text(c.idsrc)
	}
	v.pin, v.has_pin = c.pin, c.has_pin
	v.real_addr = endpoint_text(c.ep)
	v.proto = conn_proto(c)
	v.backend = "daemon"
	if conn_in_service(d, c) {
		v.backend = "kernel" if d.dco.kind == .Kernel else "service"
	}
	switch {
	case c.parked:
		v.state = "auth_pending"
	case c.up:
		v.state = "active"
	case:
		v.state = "handshake"
	}
	if c.up {
		v.peer_id = c.peer_id
		v.vpn4, v.vpn6 = c.vpn4, c.vpn6
		v.cipher = push.cipher_name(c.cipher)
		v.data_format = c.data_format
		v.connected_at = c.up_wall
	}
	v.bytes_in, v.bytes_out = c.in_bytes, c.out_bytes
	v.packets_in, v.packets_out = c.in_pkts, c.out_pkts
	v.proofs = c.proofs
	return v
}

// The common first fields of the early events of a login.
srv_write_login :: proc(w: ^bus.Writer, c: ^Conn) {
	bus.kv_str(w, "session", srv_session_text(c))
	name := ""
	if c.named {
		name = server.identity_str(&c.name)
	}
	write_who(w, name, c.named, c.pin, c.has_pin)
	bus.kv_str(w, "real_addr", endpoint_text(c.ep))
	bus.kv_str(w, "proto", conn_proto(c))
}

// TLS finished and the identity is known, before the accept decision.
srv_ev_handshake :: proc(d: ^Srv, c: ^Conn) {
	if c.ev_handshake {
		return
	}
	c.ev_handshake = true
	if w := bus_ev(); w != nil {
		srv_write_login(w, c)
		bus_emit("peer.handshake")
	}
}

// The login waits for a controller. `info` is the peer-info text of the client.
srv_ev_auth_pending :: proc(d: ^Srv, c: ^Conn, info: string, timeout_s: int) {
	if w := bus_ev(); w != nil {
		srv_write_login(w, c)
		bus.kv_str_or_null(w, "identity_source", identity_source_text(c.idsrc), c.named && c.idsrc != .None)
		bus.kv_bool(w, "web_auth", c.web_auth)
		write_proofs(w, c.proofs)
		bus.kv_raw(w, "peer_info", nil_or_peer_info(info))
		bus.kv_int(w, "timeout_s", i64(timeout_s))
		buf: [24]u8
		deadline := time.time_add(time.now(), time.Duration(timeout_s) * time.Second)
		bus.kv_str(w, "deadline", bus.format_ts(deadline, &buf))
		bus_emit("peer.auth_pending")
	}
}

// The peer-info object as JSON text, built in the second writer's tail so the
// event writer stays free. Temp allocated.
nil_or_peer_info :: proc(info: string) -> []byte {
	pw: bus.Writer
	bus.writer_init(&pw, context.temp_allocator)
	write_peer_info(&pw, info)
	return bus.writer_bytes(&pw)
}

srv_ev_auth_fail :: proc(d: ^Srv, c: ^Conn, reason, detail: string) {
	if c.ev_fail {
		return
	}
	c.ev_fail = true
	if w := bus_ev(); w != nil {
		v := Auth_Fail_View {
			session    = srv_session_text(c),
			has_sess   = true,
			has_pin    = c.has_pin,
			pin        = c.pin,
			real_addr  = endpoint_text(c.ep),
			proto      = conn_proto(c),
			reason     = reason,
			detail     = detail,
			has_detail = detail != "",
		}
		if c.named {
			v.name = server.identity_str(&c.name)
			v.has_name = true
		}
		write_auth_fail(w, &v)
		bus_emit("auth.fail")
	}
}

// A session that ended before the login: a TLS failure, or a key the pin check
// refused.
srv_ev_handshake_failed :: proc(d: ^Srv, c: ^Conn, text: string, why: session.Fail_Reason = .Tls) {
	if c.ev_fail {
		return
	}
	reason := "tls_failed"
	#partial switch why {
	case .Cert_Revoked:
		reason = "cert_revoked"
	case .Crl_Failed:
		reason = "crl_failed"
	}
	switch c.refusal {
	case .None:
	case .Unknown:
		reason = "unknown_key"
	case .Disabled:
		reason = "key_disabled"
	}
	srv_ev_auth_fail(d, c, reason, text)
}

// Remembers which key a pin check refused for this client. The check runs inside
// TLS, in the call that fed this conn, so the first pump after it is the conn's.
srv_note_refusal :: proc(d: ^Srv, c: ^Conn) {
	if !d.srv_ok {
		return
	}
	ps := &d.srv.pins
	if ps.refusal_seq == d.pin_seq_seen {
		return
	}
	d.pin_seq_seen = ps.refusal_seq
	c.refusal = ps.refusal_kind
	c.refusal_key = ps.refusal_spki
	c.pin = ps.refusal_spki
	c.has_pin = true
}

srv_ev_connect :: proc(d: ^Srv, c: ^Conn) {
	c.ev_connect = true
	if w := bus_ev(); w != nil {
		v := srv_view(d, c)
		write_peer_fields(w, &v)
		bus.kv_arr(w, "push")
		rest := c.push_text
		for len(rest) > 0 {
			line := rest
			if i := strings.index_byte(rest, '\n'); i >= 0 {
				line, rest = rest[:i], rest[i + 1:]
			} else {
				rest = ""
			}
			bus.val_str(w, line)
		}
		bus.end(w)
		bus_emit("peer.connect")
	}
}

srv_ev_disconnect :: proc(d: ^Srv, c: ^Conn) {
	if !c.ev_connect || c.ev_disconnect {
		return
	}
	c.ev_disconnect = true
	if w := bus_ev(); w != nil {
		bus.kv_str(w, "session", srv_session_text(c))
		bus.kv_u64(w, "peer_id", u64(c.peer_id))
		write_who(w, server.identity_str(&c.name), c.named, c.pin, c.has_pin)
		bus.kv_str(w, "real_addr", endpoint_text(c.ep))
		bus.kv_str(w, "proto", conn_proto(c))
		if a, ok := c.vpn4.?; ok {
			bus.kv_str(w, "vpn4", ip4_str(a))
		} else {
			bus.kv_null(w, "vpn4")
		}
		if a, ok := c.vpn6.?; ok {
			bus.kv_str(w, "vpn6", ip6_str(a))
		} else {
			bus.kv_null(w, "vpn6")
		}
		bus.kv_str(w, "reason", disconnect_reason(c.end))
		detail := string(c.detail[:c.detail_n])
		if detail == "" && c.fail_n > 0 {
			detail = string(c.fail[:c.fail_n])
		}
		if detail == "" && (c.end == .Kicked || c.end == .Kicked_Key) {
			detail = end_text(c.end)
		}
		bus.kv_str_or_null(w, "detail", detail, detail != "")
		bus.kv_u64(w, "duration_s", u64(max(now_srv(d) - c.up_at, 0) / time.Second))
		bus.kv_u64(w, "bytes_in", c.in_bytes)
		bus.kv_u64(w, "bytes_out", c.out_bytes)
		bus.kv_u64(w, "packets_in", c.in_pkts)
		bus.kv_u64(w, "packets_out", c.out_pkts)
		bus_emit("peer.disconnect")
	}
}

srv_ev_rekey :: proc(d: ^Srv, c: ^Conn, key_id: u8, by_peer: bool) {
	if w := bus_ev(); w != nil {
		bus.kv_str(w, "session", srv_session_text(c))
		bus.kv_u64(w, "peer_id", u64(c.peer_id))
		bus.kv_int(w, "key_id", i64(key_id))
		bus.kv_str(w, "by", "peer" if by_peer else "local")
		bus.kv_u64(w, "count", c.rekeys)
		bus_emit("peer.rekey")
	}
}

srv_ev_float :: proc(d: ^Srv, c: ^Conn, old: net.Endpoint) {
	if w := bus_ev(); w != nil {
		bus.kv_str(w, "session", srv_session_text(c))
		bus.kv_u64(w, "peer_id", u64(c.peer_id))
		bus.kv_str(w, "old_addr", endpoint_text(old))
		bus.kv_str(w, "new_addr", endpoint_text(c.ep))
		bus_emit("peer.float")
	}
}

// ---------------------------------------------------------------- the stats

// The body of `stats.get` (and of `stats.tick`) for the whole daemon.
srv_write_stats :: proc(w: ^bus.Writer, d: ^Srv) {
	srv_dco_refresh_all(d)
	bus.kv_str(w, "datapath", bus_datapath())
	now := now_srv(d)
	bus.kv_u64(w, "uptime_s", u64(max(now - d.started, 0) / time.Second))
	t := d.ended
	live := 0
	for c in d.conns {
		if c != nil && c.up {
			t.in_pkts += c.in_pkts
			t.in_bytes += c.in_bytes
			t.out_pkts += c.out_pkts
			t.out_bytes += c.out_bytes
		}
		if c != nil && c.up && !c.closing {
			live += 1
		}
	}
	bus.kv_obj(w, "totals")
	bus.kv_u64(w, "bytes_in", t.in_bytes)
	bus.kv_u64(w, "bytes_out", t.out_bytes)
	bus.kv_u64(w, "packets_in", t.in_pkts)
	bus.kv_u64(w, "packets_out", t.out_pkts)
	bus.end(w)
	bus.kv_obj(w, "counters")
	write_u64_fields(w, &d.stats)
	srv_sync_off(d)
	write_u64_fields(w, &d.off)
	total := d.agg
	for c in d.conns {
		if c != nil && c.s_ok {
			counters_add(&total, session.session_counters(&c.s))
		}
	}
	write_u64_fields(w, &total, "session_")
	if d.srv_ok {
		for cnt, v in d.srv.reg.counters {
			if v == .Drop_Bad_Source && !srv_bad_source_known(d) {
				continue
			}
			bus.kv_u64(w, strings.to_lower(fmt.tprintf("route_%v", v), context.temp_allocator), cnt)
		}
		ps := &d.srv.pins
		bus.kv_u64(w, "pins_accepted", sync.atomic_load(&ps.accepted))
		bus.kv_u64(w, "pins_refused_unknown", sync.atomic_load(&ps.refused_unknown))
		bus.kv_u64(w, "pins_refused_disabled", sync.atomic_load(&ps.refused_disabled))
	}
	bus.kv_u64(w, "auth_pending", u64(d.parked))
	bus.end(w)
	bus.kv_int(w, "peers", i64(live))
	pool_write_bus(w, d.wk)
}

on_srv_stats_tick :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Srv)(user)
	B.t_stats.on = false
	if d.finished || d.stopping {
		return
	}
	if w := bus_ev(); w != nil {
		srv_write_stats(w, d)
		bus.kv_int(w, "interval_s", i64(B.stats_secs))
		bus_emit("stats.tick")
	}
	srv_stats_arm(d)
}

srv_stats_arm :: proc(d: ^Srv) {
	if B.stats_secs <= 0 || !B.events_on {
		stimer_clear(&d.loop, &B.t_stats)
		return
	}
	stimer_set(&d.loop, &B.t_stats, now_srv(d) + time.Duration(B.stats_secs) * time.Second, on_srv_stats_tick, d)
}

// ---------------------------------------------------------------- the loop

on_srv_bus :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	bus_drain(srv_bus_request)
}

srv_bus_request :: proc(req: ^bus.Request) {
	d := &SV
	switch req.op {
	case "status", "stats.get", "peers.list", "peer.get":
		srv_dco_refresh_all(d)
	}
	switch req.op {
	case "status":
		srv_op_status(d, req)
	case "stats.get":
		srv_op_stats(d, req)
	case "peers.list":
		srv_op_peers_list(d, req)
	case "peer.get":
		srv_op_peer_get(d, req)
	case "peer.kick":
		srv_op_peer_kick(d, req)
	case "peers.reload":
		srv_op_peers_reload(d, req)
	case "passwords.reload":
		srv_op_passwords_reload(d, req)
	case "log.level":
		bus_op_log_level(req)
	case "auth.decide":
		srv_op_auth_decide(d, req)
	case "auth.credentials":
		srv_op_auth_credentials(d, req)
	case "daemon.reload":
		srv_op_daemon_reload(d, req)
	case "daemon.shutdown":
		srv_op_shutdown(d, req)
	case:
		bus_err(req, .Unknown_Op, "no such operation")
	}
}

// Mutating operations are refused once the daemon is stopping.
srv_busy_stopping :: proc(d: ^Srv, req: ^bus.Request) -> bool {
	if d.stopping || d.finished {
		bus_err(req, .Busy, "the daemon is shutting down")
		return true
	}
	return false
}

// The session with this id, if it is still there and not closing.
srv_find_session :: proc(d: ^Srv, text: string) -> ^Conn {
	n, ok := parse_session(text)
	if !ok {
		return nil
	}
	for c in d.conns {
		if c != nil && c.sess == n && !c.closing && !c.releasing {
			return c
		}
	}
	return nil
}

srv_op_status :: proc(d: ^Srv, req: ^bus.Request) {
	w := bus_res()
	bus_status_head(w)
	bus.kv_obj(w, "server")
	bus.kv_str(w, "state", "stopping" if d.stopping || d.finished else "running")
	bus.kv_int(w, "peers", i64(srv_clients_up(d)))
	bus.kv_int(w, "pending_auth", i64(d.parked))
	if d.cfg.max_clients > 0 {
		bus.kv_int(w, "max_clients", i64(d.cfg.max_clients))
	} else {
		bus.kv_null(w, "max_clients")
	}
	bus.kv_str(w, "datapath", bus_datapath())
	bus.kv_str_or_null(w, "tls_tun", srv_tls_tun_name(d), d.dco.mixed)
	pool_write_bus(w, d.wk)
	bus.kv_arr(w, "listen")
	for i in 0 ..< d.n_listen {
		bus.val_str(w, d.listeners[i].text)
	}
	bus.end(w)
	bus.end(w)
	bus_ok(req)
}

srv_op_stats :: proc(d: ^Srv, req: ^bus.Request) {
	text, e := bus.arg_str(req, "session")
	if e != .None && e != .Missing {
		bus_bad_arg(req, "session", e)
		return
	}
	w := bus_res()
	if e == .Missing {
		srv_write_stats(w, d)
		bus_ok(req)
		return
	}
	c := srv_find_session(d, text)
	if c == nil {
		bus_err(req, .Not_Found, "no such session")
		return
	}
	bus.kv_u64(w, "uptime_s", u64(max(now_srv(d) - c.created, 0) / time.Second))
	bus.kv_obj(w, "totals")
	bus.kv_u64(w, "bytes_in", c.in_bytes)
	bus.kv_u64(w, "bytes_out", c.out_bytes)
	bus.kv_u64(w, "packets_in", c.in_pkts)
	bus.kv_u64(w, "packets_out", c.out_pkts)
	bus.end(w)
	bus.kv_obj(w, "counters")
	if c.s_ok {
		counters := session.session_counters(&c.s)
		write_u64_fields(w, &counters)
	}
	bus.kv_u64(w, "drops", c.drops)
	bus.end(w)
	bus.kv_str(w, "session", srv_session_text(c))
	if c.up {
		bus.kv_u64(w, "peer_id", u64(c.peer_id))
	} else {
		bus.kv_null(w, "peer_id")
	}
	bus_ok(req)
}

// Sessions in the order `peers.list` shows them: by the time they came up
// (those that are not up yet last), then by session number.
srv_sorted :: proc(d: ^Srv, all: bool, name: string, has_name: bool) -> []^Conn {
	list := make([dynamic]^Conn, context.temp_allocator)
	for c in d.conns {
		if c == nil || c.closing || c.releasing || c.ev_disconnect {
			continue
		}
		if !all && !(c.up && !c.parked) {
			continue
		}
		if has_name && !(c.named && server.name_equal(server.identity_str(&c.name), name)) {
			continue
		}
		append(&list, c)
	}
	slice.sort_by(list[:], proc(a, b: ^Conn) -> bool {
		if a.up != b.up {
			return a.up
		}
		if a.up && a.up_wall != b.up_wall {
			return time.diff(b.up_wall, a.up_wall) < 0
		}
		return a.sess < b.sess
	})
	return list[:]
}

srv_op_peers_list :: proc(d: ^Srv, req: ^bus.Request) {
	all, e1 := bus.arg_bool(req, "all")
	if e1 != .None && e1 != .Missing {
		bus_bad_arg(req, "all", e1)
		return
	}
	name, e2 := bus.arg_str(req, "name")
	if e2 != .None && e2 != .Missing {
		bus_bad_arg(req, "name", e2)
		return
	}
	limit, e3 := bus.arg_int_range(req, "limit", 1, 2000)
	if e3 == .Missing {
		limit = 500
	} else if e3 != .None {
		bus_bad_arg(req, "limit", e3)
		return
	}
	offset, e4 := bus.arg_int_range(req, "offset", 0, 1 << 40)
	if e4 == .Missing {
		offset = 0
	} else if e4 != .None {
		bus_bad_arg(req, "offset", e4)
		return
	}
	list := srv_sorted(d, all, name, e2 == .None)
	w := bus_res()
	bus.kv_int(w, "count", i64(len(list)))
	bus.kv_arr(w, "peers")
	first := int(min(offset, i64(len(list))))
	last := int(min(i64(first) + limit, i64(len(list))))
	for c in list[first:last] {
		v := srv_view(d, c)
		write_peer(w, &v)
	}
	bus.end(w)
	bus_ok(req)
}

srv_op_peer_get :: proc(d: ^Srv, req: ^bus.Request) {
	text, e1 := bus.arg_str(req, "session")
	id, e2 := bus.arg_int_range(req, "peer_id", 0, 0xFFFFFE)
	if (e1 == .None) == (e2 == .None) {
		bus_err(req, .Bad_Request, "give exactly one of session and peer_id")
		return
	}
	if e1 != .None && e1 != .Missing {
		bus_bad_arg(req, "session", e1)
		return
	}
	if e2 != .None && e2 != .Missing {
		bus_bad_arg(req, "peer_id", e2)
		return
	}
	found: ^Conn
	if e1 == .None {
		found = srv_find_session(d, text)
	} else {
		for c in d.conns {
			if c != nil && c.up && !c.closing && !c.ev_disconnect && u64(c.peer_id) == u64(id) {
				found = c
				break
			}
		}
	}
	if found == nil {
		bus_err(req, .Not_Found, "no such peer")
		return
	}
	v := srv_view(d, found)
	w := bus_res()
	bus.key(w, "peer")
	write_peer(w, &v)
	bus_ok(req)
}

srv_op_peer_kick :: proc(d: ^Srv, req: ^bus.Request) {
	if srv_busy_stopping(d, req) {
		return
	}
	text, e1 := bus.arg_str(req, "session")
	id, e2 := bus.arg_int_range(req, "peer_id", 0, 0xFFFFFE)
	name, e3 := bus.arg_str(req, "name")
	serial_text, e6 := bus.arg_str(req, "serial")
	pin_text, e7 := bus.arg_str(req, "pin")
	// `name` may also go with `serial` or `pin`, as one more condition.
	by_cert := e6 == .None
	by_pin := e7 == .None
	if !kick_selectors_ok(e1 == .None, e2 == .None, e3 == .None, by_cert, by_pin) {
		bus_err(req, .Bad_Request, "give exactly one of session, peer_id, name, serial and pin (name may go with serial or pin)")
		return
	}
	for pair in ([5]struct {
			n: string,
			e: bus.Arg_Error,
		}{{"session", e1}, {"peer_id", e2}, {"name", e3}, {"serial", e6}, {"pin", e7}}) {
		if pair.e != .None && pair.e != .Missing {
			bus_bad_arg(req, pair.n, pair.e)
			return
		}
	}
	serial_want: [ossl.SERIAL_BYTES_MAX]u8
	serial_n: int
	if by_cert {
		ok: bool
		if serial_n, ok = server.serial_parse(serial_text, &serial_want); !ok {
			bus_bad_arg(req, "serial", .Out_Of_Range)
			return
		}
	}
	pin_want: [32]u8
	if by_pin {
		ok: bool
		if pin_want, ok = pin_parse(pin_text); !ok {
			bus_bad_arg(req, "pin", .Out_Of_Range)
			return
		}
	}
	if (by_cert || by_pin) && e3 == .None && name == "" {
		bus_bad_arg(req, "name", .Out_Of_Range)
		return
	}
	halt, e4 := bus.arg_bool(req, "halt")
	if e4 != .None && e4 != .Missing {
		bus_bad_arg(req, "halt", e4)
		return
	}
	reason := ""
	if r, e5 := bus.arg_str(req, "reason"); e5 == .None {
		clean, ok := clean_reason(r)
		if !ok {
			bus_bad_arg(req, "reason", .Out_Of_Range)
			return
		}
		reason = clean
	} else if e5 != .Missing {
		bus_bad_arg(req, "reason", e5)
		return
	}

	targets := make([dynamic]^Conn, context.temp_allocator)
	switch {
	case by_cert:
		// A match is a client certificate that the CA chain let in. No match is
		// an empty result.
		for c in d.conns {
			if c == nil || c.closing || c.releasing || !c.s_ok {
				continue
			}
			if cn, serial, ok := session.session_server_chain_cert(&c.s); ok && server.cert_selected(serial_want[:serial_n], name, cn, serial) {
				append(&targets, c)
			}
		}
	case by_pin:
		// Only the sessions of this key (and of the name, when given).
		for c in d.conns {
			if c == nil || c.closing || c.releasing || !c.has_pin || c.pin != pin_want {
				continue
			}
			if e3 == .None && !(c.named && server.name_equal(server.identity_str(&c.name), name)) {
				continue
			}
			append(&targets, c)
		}
	case e1 == .None:
		if c := srv_find_session(d, text); c != nil {
			append(&targets, c)
		}
	case e2 == .None:
		for c in d.conns {
			if c != nil && c.up && !c.closing && !c.releasing && u64(c.peer_id) == u64(id) {
				append(&targets, c)
			}
		}
	case e3 == .None:
		for c in d.conns {
			if c != nil && !c.closing && !c.releasing && c.named && server.name_equal(server.identity_str(&c.name), name) {
				append(&targets, c)
			}
		}
	}
	if len(targets) == 0 && !by_cert {
		bus_err(req, .Not_Found, "no such session")
		return
	}
	ids := make([dynamic]string, context.temp_allocator)
	for c in targets {
		append(&ids, srv_session_text(c))
	}
	kind := session.Close_Kind.Halt if halt else session.Close_Kind.Restart
	for c in targets {
		logf(.Notice, "bus: kicking client %s%s%s", conn_label(c), ": " if reason != "" else "", reason)
		c.detail_n = copy(c.detail[:], reason)
		d.stats.kicks += 1
		if halt {
			// A halted client must not come back with its token.
			srv_signin_end(d, c)
		}
		if c.parked {
			srv_park_deny(d, c, "kicked")
		} else {
			conn_close(d, c, kind, .Admin_Kick)
		}
	}
	w := bus_res()
	bus.kv_arr(w, "kicked")
	for s in ids {
		bus.val_str(w, s)
	}
	bus.end(w)
	bus_ok(req)
}

// -------------------------------------------------------------- the peers file

Peers_Report :: struct {
	pins, added, removed, disabled, kicked: int,
}

// Reads the peers file. nil and a text (temp allocated) when it has errors.
srv_peers_load :: proc(d: ^Srv) -> (t: ^server.Pin_Table, err: string) {
	table, text := server.pin_table_load(d.cfg.peer_keys)
	if table == nil {
		defer delete(text)
		return nil, strings.clone(first_line_limit(text, 300), context.temp_allocator)
	}
	return table, ""
}

first_line_limit :: proc(s: string, limit: int) -> string {
	text := strings.trim_space(s)
	if i := strings.index_byte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	if len(text) > limit {
		text = text[:limit]
	}
	return text
}

// Swaps in a new table and ends the sessions it no longer allows.
srv_peers_apply :: proc(d: ^Srv, t: ^server.Pin_Table) -> (rep: Peers_Report) {
	now := now_srv(d)
	r := server.server_reload_peers(&d.srv, t)
	rep.pins = server.pin_table_len(t)
	rep.kicked = len(r.kicks)
	for ch in r.changes {
		#partial switch ch.kind {
		case .Added:
			rep.added += 1
		case .Removed:
			rep.removed += 1
		case .Disabled:
			rep.disabled += 1
		}
	}
	logf(.Notice, "reload: peers file %s: %d keys, %d change(s), %d session(s) to end", d.cfg.peer_keys, rep.pins, len(r.changes), len(r.kicks))
	for ch in r.changes {
		logf(.Notice, "reload: %v %s", ch.kind, ch.user)
	}
	for k in r.kicks {
		p := server.peers_get(&d.srv.reg.peers, k.handle)
		if p == nil {
			continue
		}
		c := d.conns[p.user]
		logf(.Notice, "reload: ending the session of %s (%v)", p.identity, k.reason)
		d.stats.kicks += 1
		if c != nil {
			// A revoked client is told to stop (HALT).
			conn_close(d, c, .Halt, .Revoked)
		} else {
			server.server_disconnect(&d.srv, k.handle, now)
		}
	}
	server.reload_result_destroy(&r)
	srv_flush_all(d)
	return
}

srv_op_peers_reload :: proc(d: ^Srv, req: ^bus.Request) {
	if srv_busy_stopping(d, req) {
		return
	}
	if d.cfg.peer_keys == "" {
		bus_err(req, .Conflict, "no peers file is configured (peer-keys)")
		return
	}
	t, err := srv_peers_load(d)
	if t == nil {
		logf(.Error, "reload: peers file %s has errors, so the old one is kept: %s", d.cfg.peer_keys, err)
		bus_err(req, .Internal, fmt.tprintf("peers file %s: %s", d.cfg.peer_keys, err))
		return
	}
	rep := srv_peers_apply(d, t)
	w := bus_res()
	bus.kv_int(w, "pins", i64(rep.pins))
	bus.kv_int(w, "added", i64(rep.added))
	bus.kv_int(w, "removed", i64(rep.removed))
	bus.kv_int(w, "disabled", i64(rep.disabled))
	bus.kv_int(w, "kicked", i64(rep.kicked))
	bus_ok(req)
}

// SIGHUP: the same without a reply.
srv_reload :: proc(d: ^Srv) {
	if d.pw.on {
		srv_pw_reload(d)
	}
	if d.cfg.peer_keys == "" {
		if !d.pw.on {
			logf(.Notice, "reload: no peers file is configured, so there is nothing to reload")
		}
		return
	}
	t, err := srv_peers_load(d)
	if t == nil {
		logf(.Error, "reload: peers file %s has errors, so the old one is kept: %s", d.cfg.peer_keys, err)
		return
	}
	srv_peers_apply(d, t)
}

srv_op_daemon_reload :: proc(d: ^Srv, req: ^bus.Request) {
	if srv_busy_stopping(d, req) {
		return
	}
	plan: Reload_Plan
	defer reload_plan_destroy(&plan)
	if err := reload_prepare(&plan); err != "" {
		logf(.Error, "reload: %s", err)
		bus_reload_report(req, nil, nil, err)
		return
	}
	// Read the peers file before anything is applied: an error stops the reload.
	table: ^server.Pin_Table
	if d.cfg.peer_keys != "" {
		t, err := srv_peers_load(d)
		if t == nil {
			msg := fmt.tprintf("peers file %s: %s", d.cfg.peer_keys, err)
			logf(.Error, "reload: %s", msg)
			bus_reload_report(req, nil, nil, msg)
			return
		}
		table = t
	}
	reloaded := make([dynamic]string, context.temp_allocator)
	reload_apply_common(&plan, &reloaded)
	if B.stats_secs != plan.cfg.server.stats_interval {
		B.stats_secs = plan.cfg.server.stats_interval
		srv_stats_arm(d)
		append(&reloaded, "stats-interval")
	}
	if table != nil {
		srv_peers_apply(d, table)
		append(&reloaded, "peers")
	}
	if d.pw.on {
		if rep := srv_pw_reload(d); !rep.lost {
			append(&reloaded, "peer-passwords")
		}
	}
	if crl_poll(&d.set.crl, true) {
		append(&reloaded, "crl-verify")
	}
	for name in plan.ignored {
		logf(.Notice, "reload: %s changed, so a restart is needed", name)
	}
	logf(.Notice, "reload: applied %v", reloaded[:])
	bus_reload_report(req, reloaded[:], plan.ignored[:], "")
}

srv_op_shutdown :: proc(d: ^Srv, req: ^bus.Request) {
	secs, e := bus.arg_int_range(req, "timeout_s", 0, 60)
	if e == .Missing {
		secs = 5
	} else if e != .None {
		bus_bad_arg(req, "timeout_s", e)
		return
	}
	w := bus_res()
	bus.kv_bool(w, "stopping", true)
	bus_ok(req)
	if d.stopping || d.finished {
		return
	}
	logf(.Notice, "bus: shutdown requested (%d s for the exit notices)", secs)
	B.stop_reason = "request"
	d.stop_wait = time.Duration(secs) * time.Second
	srv_begin_stop(d)
}

// `peer.disconnect` `reason` for the way a session ended.
disconnect_reason :: proc "contextless" (r: End_Reason) -> string {
	switch r {
	case .Client_Exit:
		return "client_exit"
	case .Kicked, .Kicked_Key:
		return "replaced"
	case .Admin_Kick:
		return "kicked"
	case .Revoked:
		return "key_revoked"
	case .Shutdown:
		return "server_stop"
	case .Limit:
		return "session_timeout"
	case .Timeout:
		return "timeout"
	case .Tcp_Lost:
		return "transport_closed"
	case .Failed:
		return "protocol_error"
	case .Cert_Revoked:
		return "cert_revoked"
	case .Crl_Failed:
		return "crl_failed"
	case .Password_Gone:
		return "user_removed"
	case .Password_Changed:
		return "password_changed"
	case .Reauth_Refused:
		return "reauth_failed"
	case .Sign_In_Ended:
		return "sign_in_ended"
	case .None, .Closed, .Refused, .Slow, .Datapath:
		return "error"
	}
	return "error"
}
