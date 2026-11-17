// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"

// Applies a supported or new option.
@(private)
handle :: proc(b: ^Build, d: ^Directive, ls: ^Link_State, blk: ^Block) {
	if b.ctx == .Ccd {
		if !handle_ccd(b, d) {
			gerr(b, d, "internal error: option '%s' has no handler", d.name)
		}
		return
	}
	if handle_link(b, d, ls, blk) {
		return
	}
	if handle_tls(b, d) || handle_common(b, d) || handle_client(b, d) || handle_server(b, d) {
		return
	}
	gerr(b, d, "internal error: option '%s' has no handler", d.name)
}

// Options of both roles that are not link or TLS settings. Returns false if
// the option is not one of them.
@(private)
handle_common :: proc(b: ^Build, d: ^Directive) -> bool {
	a := d.args
	c := &b.common
	switch d.name {
	case "config", "ignore-unknown-option":
	// Includes were expanded by the parser; the unknown list was read earlier.
	case "cd":
		if !strings.has_prefix(a[0], "/") {
			berr(b, d, "needs an absolute path, but '%s' is not one", a[0])
		} else {
			c.cd = a[0]
		}
	case "persist-tun":
		c.persist_tun = true
	case "block-ipv6":
		c.block_ipv6 = true
	case "user":
		c.user = a[0]
	case "group":
		c.group = a[0]
	case "writepid":
		c.writepid = a[0]
	case "mlock":
		c.mlock = true
	case "verb":
		if v, ok := arg_num(b, d, 0, 0, 11, "level"); ok {
			c.verb = v
		}
	case "dev":
		c.dev = a[0]
		b.dev_set = true
		b.first[d.name] = d // the last one wins, and messages point at it
	case "dev-type":
		b.dev_type = a[0]
		b.first[d.name] = d
	case "mode":
		note_first(b, d)
		if a[0] != "server" {
			berr(
				b,
				d,
				"mode '%s' is not supported; only server is available (use `client` for a client config)",
				a[0],
			)
		}
	case "topology":
		switch a[0] {
		case "subnet":
			c.topology_subnet = true
		case "net30", "p2p":
			berr(
				b,
				d,
				"topology %s is not supported; noirvpn only uses topology subnet (the default), so remove the line",
				a[0],
			)
		case:
			berr(b, d, "unknown topology '%s'; only subnet is supported", a[0])
		}
	case "allow-compression":
		if a[0] != "no" {
			berr(
				b,
				d,
				"'%s' is not supported because compression has been removed (only `allow-compression no` is accepted)",
				a[0],
			)
		}
	case "auth":
		b.auth_raw = a[0]
		b.auth_pos = d
	case "tran-window":
		if v, ok := arg_secs(b, d, 0, 1, "seconds"); ok {
			c.tls.tran_window = v
		}
	case "hand-window":
		if v, ok := arg_secs(b, d, 0, 1, "seconds"); ok {
			c.tls.hand_window = v
		}
	case "tls-timeout":
		if v, ok := arg_secs(b, d, 0, 1, "seconds"); ok {
			c.tls.tls_timeout = v
		}
	case "reneg-sec":
		handle_reneg_sec(b, d)
	case "reneg-bytes":
		if v, ok := arg_num64(b, d, 0, 0, 1 << 60, "bytes"); ok {
			c.tls.reneg_bytes = v
		}
	case "reneg-pkts":
		if v, ok := arg_num64(b, d, 0, 0, 1 << 60, "packets"); ok {
			c.tls.reneg_pkts = v
		}
	case "replay-window":
		if v, ok := arg_num(b, d, 0, 1, 65535, "size"); ok {
			c.replay_window = v
		}
		if len(a) == 2 {
			if v, ok := arg_secs(b, d, 1, 1, "seconds"); ok {
				c.replay_time = v
			}
		}
	case "max-packet-size":
		handle_max_packet_size(b, d)
	case "keepalive":
		handle_keepalive(b, d)
	case "ping":
		if v, ok := arg_num(b, d, 0, 0, 86400, "seconds"); ok {
			c.ping = v
		}
	case "ping-exit":
		if v, ok := arg_num(b, d, 0, 0, 86400, "seconds"); ok {
			c.ping_exit = v
			b.ping_exit_set = true
			note_first(b, d)
		}
	case "ping-restart":
		if v, ok := arg_num(b, d, 0, 0, 86400, "seconds"); ok {
			c.ping_restart = v
			b.ping_restart_set = true
			note_first(b, d)
		}
	case "ping-timer-rem":
		c.ping_timer_rem = true
	case "inactive":
		if v, ok := arg_num(b, d, 0, 0, MAX_SECONDS, "seconds"); ok {
			c.inactive_secs = v
		}
		if len(a) == 2 {
			if v, ok := arg_num(b, d, 1, 0, 1 << 40, "bytes"); ok {
				c.inactive_bytes = v
			}
		}
	case "session-timeout":
		if v, ok := arg_secs(b, d, 0, 0, "seconds"); ok {
			c.session_timeout = v
		}
	case "sndbuf":
		if v, ok := arg_num(b, d, 0, 0, 1 << 30, "bytes"); ok {
			c.sndbuf = v
		}
	case "rcvbuf":
		if v, ok := arg_num(b, d, 0, 0, 1 << 30, "bytes"); ok {
			c.rcvbuf = v
		}
	case "txqueuelen":
		if v, ok := arg_num(b, d, 0, 1, 1 << 20, "packets"); ok {
			c.txqueuelen = v
		}
	case "mark":
		if v, ok := arg_num64(b, d, 0, 0, 0xffff_ffff, "mark"); ok {
			c.mark = u32(v)
		}
	case "route-table":
		if v, ok := arg_num(b, d, 0, 1, 0x7fff_ffff, "table id"); ok {
			c.route_table = v
		}
	case "ifconfig-noexec":
		c.ifconfig_noexec = true
	case "route-noexec":
		c.route_noexec = true
	case "route":
		handle_route(b, d)
	case "route-ipv6":
		handle_route6(b, d)
	case "workers":
		if v, ok := arg_num(b, d, 0, 0, MAX_WORKERS, "worker count"); ok {
			c.workers = v
		}
	case "datapath":
		switch a[0] {
		case "auto":
			c.datapath = .Auto
		case "userspace":
			c.datapath = .Userspace
		case "udco":
			c.datapath = .Udco
		case "dco":
			c.datapath = .Dco
		case:
			berr(b, d, "must be userspace, dco, udco or auto, not '%s'", a[0])
			return true
		}
		b.datapath_set = true
		note_first(b, d)
	case "dco-socket":
		c.dco_socket = a[0]
		note_first(b, d)
	case "disable-dco":
		b.disable_dco = true
		note_first(b, d)
	case "pq-mode":
		switch a[0] {
		case "off":
			c.tls.pq_mode = .Off
		case "prefer":
			c.tls.pq_mode = .Prefer
		case "require":
			c.tls.pq_mode = .Require
		case:
			berr(b, d, "must be off, prefer or require, not '%s'", a[0])
			return true
		}
		note_first(b, d)
	case "bus-events":
		c.bus_events = parse_bus_endpoint(b, d)
	case "bus-control":
		c.bus_control = parse_bus_endpoint(b, d)
	case "bus-allow":
		handle_bus_allow(b, d)
	case "stats-interval":
		if v, ok := arg_num(b, d, 0, 0, 86400, "seconds"); ok {
			c.stats_interval = v
			note_first(b, d)
		}
	case:
		return false
	}
	return true
}

// `reneg-sec max [min]`.
@(private)
handle_reneg_sec :: proc(b: ^Build, d: ^Directive) {
	c := &b.common
	max_v, ok := arg_secs(b, d, 0, 0, "seconds")
	if !ok {
		return
	}
	min_v := -1
	if len(d.args) == 2 {
		min_v, ok = arg_secs(b, d, 1, 0, "minimum seconds")
		if !ok {
			return
		}
		if min_v > max_v {
			berr(b, d, "the minimum (%d) is larger than the maximum (%d)", min_v, max_v)
			return
		}
	}
	c.tls.reneg_sec = max_v
	c.tls.reneg_sec_min = min_v
}

// `max-packet-size`: clamped to 154..2048, and also acts as `mssfix size mtu`
// unless mssfix was set before.
@(private)
handle_max_packet_size :: proc(b: ^Build, d: ^Directive) {
	v, ok := arg_num(b, d, 0, 0, 1 << 20, "size")
	if !ok {
		return
	}
	if v < 154 || v > 2048 {
		clamped := clamp(v, 154, 2048)
		bwarn(b, d, "%d is outside the range 154 to 2048, so %d will be used instead", v, clamped)
		v = clamped
	}
	b.common.max_packet_size = v
	if b.g.s.mssfix.kind == .Default {
		b.g.s.mssfix = Mssfix{.Mtu, v}
	}
}

// `keepalive interval timeout`, expanded as the man page says.
@(private)
handle_keepalive :: proc(b: ^Build, d: ^Directive) {
	c := &b.common
	interval, ok1 := arg_num(b, d, 0, 1, 86400, "interval")
	timeout, ok2 := arg_num(b, d, 1, 1, 86400, "timeout")
	if !ok1 || !ok2 {
		return
	}
	if b.role == .Server {
		if timeout > 43200 {
			berr(
				b,
				d,
				"the timeout can be at most 43200 seconds in server mode (it is doubled), but it is %d",
				timeout,
			)
			return
		}
		c.ping = interval
		c.ping_restart = timeout * 2
		add_push(b, "ping %d", interval)
		add_push(b, "ping-restart %d", timeout)
	} else {
		c.ping = interval
		c.ping_restart = timeout
	}
	b.ping_restart_set = true
}

// Where a `-1` default metric reads as "not given".
@(private)
parse_metric :: proc(b: ^Build, d: ^Directive, s: string) -> (m: int, ok: bool) {
	if s == "default" || s == "" {
		return -1, true
	}
	v, vok := parse_range(s, 0, 0x7fff_ffff)
	if !vok {
		berr(b, d, "metric must be a number, not '%s'", s)
		return 0, false
	}
	return int(v), true
}

// A host name or keyword that is safe to keep as text.
@(private)
plausible_host :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for ch in transmute([]u8)s {
		switch ch {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '-', '_', ':':
		case:
			return false
		}
	}
	return true
}

// `route network [netmask [gateway [metric]]]`. "default" or an empty
// argument means the default.
@(private)
handle_route :: proc(b: ^Build, d: ^Directive) {
	a := d.args
	r := Route {
		network = a[0],
		metric  = -1,
	}
	if !plausible_host(r.network) {
		berr(b, d, "'%s' is not a network address or host name", r.network)
		return
	}
	if len(a) >= 2 && a[1] != "default" && a[1] != "" {
		mask, mok := ipv4_parse(a[1])
		if !mok {
			berr(b, d, "netmask '%s' is not a dotted IPv4 mask", a[1])
			return
		}
		if _, vok := ipv4_mask_prefix(mask); !vok {
			berr(b, d, "netmask '%s' is not a valid mask (it must be ones followed by zeros)", a[1])
			return
		}
		r.netmask = a[1]
	}
	if len(a) >= 3 && a[2] != "default" && a[2] != "" {
		if !plausible_host(a[2]) {
			berr(b, d, "gateway '%s' is not an address or host name", a[2])
			return
		}
		r.gateway = a[2]
	}
	if len(a) == 4 {
		m, ok := parse_metric(b, d, a[3])
		if !ok {
			return
		}
		r.metric = m
	}
	append(&b.routes, r)
}

// `route-ipv6 addr/bits [gateway [metric]]`.
@(private)
handle_route6 :: proc(b: ^Build, d: ^Directive) {
	a := d.args
	if _, _, ok := ipv6_parse_cidr(a[0]); !ok {
		berr(b, d, "'%s' is not an IPv6 prefix in addr/bits form", a[0])
		return
	}
	r := Route6 {
		prefix = a[0],
		metric = -1,
	}
	if len(a) >= 2 && a[1] != "default" && a[1] != "" {
		if !plausible_host(a[1]) {
			berr(b, d, "gateway '%s' is not an address or host name", a[1])
			return
		}
		r.gateway = a[1]
	}
	if len(a) == 3 {
		m, ok := parse_metric(b, d, a[2])
		if !ok {
			return
		}
		r.metric = m
	}
	append(&b.routes6, r)
}

// Adds a formatted string to the push list.
@(private)
add_push :: proc(b: ^Build, format: string, args: ..any) {
	append(&b.push, fmt_alloc(b, format, ..args))
}

// `bus-events` / `bus-control`: `off`, or `path [mode MODE] [group GROUP]`.
@(private)
parse_bus_endpoint :: proc(b: ^Build, d: ^Directive) -> (e: Bus_Endpoint) {
	a := d.args
	if a[0] == "off" {
		if len(a) != 1 {
			berr(b, d, "'off' cannot be followed by other arguments")
			return {}
		}
		return Bus_Endpoint{state = .Off}
	}
	e.state = .Custom
	e.path = a[0]
	i := 1
	for i < len(a) {
		if i + 1 >= len(a) {
			berr(b, d, "'%s' needs a value", a[i])
			return {}
		}
		switch a[i] {
		case "mode":
			m, ok := parse_octal(a[i + 1])
			if !ok || m > 0o777 || m == 0 {
				berr(b, d, "mode must be an octal number up to 0777, not '%s'", a[i + 1])
				return {}
			}
			e.mode = m
		case "group":
			e.group = a[i + 1]
		case:
			berr(b, d, "unknown keyword '%s'; use mode or group", a[i])
			return {}
		}
		i += 2
	}
	return
}

@(private)
parse_octal :: proc(s: string) -> (v: u32, ok: bool) {
	if len(s) == 0 || len(s) > 6 {
		return 0, false
	}
	for ch in transmute([]u8)s {
		if ch < '0' || ch > '7' {
			return 0, false
		}
		v = v * 8 + u32(ch - '0')
	}
	return v, true
}

// `bus-allow uid|gid id|name role[,role] ...`, or `bus-allow sid SID|name ...`.
@(private)
handle_bus_allow :: proc(b: ^Build, d: ^Directive) {
	a := d.args
	ba := Bus_Allow{}
	switch a[0] {
	case "uid":
		ba.kind = .Uid
	case "gid":
		ba.kind = .Gid
	case "sid":
		ba.kind = .Sid
	case:
		berr(b, d, "must be uid, gid or sid, not '%s'", a[0])
		return
	}
	if ba.kind == .Sid {
		if !plausible_account(a[1]) {
			berr(b, d, "'%s' is not a SID or an account name", a[1])
			return
		}
		ba.name = a[1]
	} else if v, ok := parse_range(a[1], 0, 0xffff_fffe); ok {
		ba.id = u32(v)
	} else if plausible_name(a[1]) {
		ba.name = a[1]
	} else {
		berr(b, d, "'%s' is not a numeric id or a user or group name", a[1])
		return
	}
	for arg in a[2:] {
		it := arg
		for role in strings.split_iterator(&it, ",") {
			switch role {
			case "read":
				ba.roles += {.Read}
			case "operator":
				ba.roles += {.Operator}
			case "auth":
				ba.roles += {.Auth}
			case "admin":
				ba.roles += {.Admin}
			case:
				berr(b, d, "unknown role '%s'; use read, operator, auth or admin", role)
				return
			}
		}
	}
	if ba.roles == {} {
		berr(b, d, "no role is given; use read, operator, auth or admin")
		return
	}
	append(&b.bus_allow, ba)
}

// A SID ("S-1-5-32-544") or a Windows account name ("BUILTIN\Users"): the
// bus checks it when it builds the policy.
@(private)
plausible_account :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for ch in transmute([]u8)s {
		if ch < 0x20 || ch == 0x7f || ch == '"' {
			return false
		}
	}
	return true
}

@(private)
plausible_name :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for ch in transmute([]u8)s {
		switch ch {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '-', '_', '@', '$':
		case:
			return false
		}
	}
	return true
}
