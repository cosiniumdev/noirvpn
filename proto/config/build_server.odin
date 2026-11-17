// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"

// Server-only options. Returns false if the option is not one of them.
@(private)
handle_server :: proc(b: ^Build, d: ^Directive) -> bool {
	a := d.args
	sv := &b.server
	switch d.name {
	case "tls-server":
		note_first(b, d)
	case "server":
		handle_server_net(b, d)
	case "server-ipv6":
		handle_server_ipv6(b, d)
	case "push":
		handle_push(b, d)
	case "client-to-client":
		sv.client_to_client = true
	case "client-config-dir":
		sv.client_config_dir = a[0]
		note_first(b, d)
	case "ccd-exclusive":
		sv.ccd_exclusive = true
		note_first(b, d)
	case "duplicate-cn":
		sv.duplicate_cn = true
	case "max-clients":
		if v, ok := arg_num(b, d, 0, 1, 0xfffffe, "count"); ok {
			sv.max_clients = v
		}
	case "max-routes-per-client":
		if v, ok := arg_num(b, d, 0, 1, 1 << 24, "count"); ok {
			sv.max_routes_per_client = v
		}
	case "connect-freq":
		if r, ok := parse_rate(b, d); ok {
			sv.connect_freq = r
		}
	case "connect-freq-initial":
		if r, ok := parse_rate(b, d); ok {
			sv.connect_freq_initial = r
		}
	case "connect-freq-source":
		if v, ok := arg_num(b, d, 0, 0, 1 << 24, "count"); ok {
			sv.connect_freq_source = v
		}
	case "ifconfig-pool":
		handle_pool(b, d)
	case "ifconfig-ipv6-pool":
		addr, _, ok := ipv6_parse_cidr(a[0])
		if !ok {
			berr(b, d, "'%s' is not an IPv6 prefix in addr/bits form", a[0])
		} else {
			sv.pool6 = addr
		}
	case "ifconfig-pool-persist":
		pp := Pool_Persist {
			file    = a[0],
			seconds = 600,
		}
		if len(a) == 2 {
			v, ok := arg_secs(b, d, 1, 0, "seconds")
			if !ok {
				return true
			}
			pp.seconds = v
		}
		sv.pool_persist = pp
	case "multihome":
		sv.multihome = true
		if len(a) == 1 {
			if a[0] != "same-interface" {
				berr(b, d, "unknown flag '%s'; the only valid flag is same-interface", a[0])
				return true
			}
			sv.multihome_same_iface = true
		}
	case "verify-client-cert":
		switch a[0] {
		case "require":
			sv.verify_client_cert = .Require
		case "optional":
			sv.verify_client_cert = .Optional
		case "none":
			sv.verify_client_cert = .None
		case:
			berr(b, d, "must be require, optional or none, not '%s'", a[0])
			return true
		}
		note_first(b, d)
	case "tls-crypt-v2-max-age":
		if v, ok := arg_num(b, d, 0, 1, 36500, "days"); ok {
			sv.tls_crypt_v2_max_age = v
			note_first(b, d)
		}
	case "peer-keys":
		sv.peer_keys = a[0]
		note_first(b, d)
	case "peer-keys-mode":
		switch a[0] {
		case "pin":
			sv.peer_keys_mode = .Pin
		case "both":
			sv.peer_keys_mode = .Both
		case "either":
			sv.peer_keys_mode = .Either
		case:
			berr(b, d, "must be pin, both or either, not '%s'", a[0])
			return true
		}
		note_first(b, d)
	case "peer-passwords":
		sv.peer_passwords = a[0]
		note_first(b, d)
	case "auth-external":
		ae := Auth_External {
			timeout = 30,
		}
		if len(a) == 1 {
			v, ok := arg_num(b, d, 0, 1, 3600, "timeout seconds")
			if !ok {
				return true
			}
			ae.timeout = v
		}
		sv.auth_external = ae
		note_first(b, d)
	case "auth-web":
		sv.auth_web = true
		note_first(b, d)
	case:
		return false
	}
	return true
}

// `connect-freq n sec`.
@(private)
parse_rate :: proc(b: ^Build, d: ^Directive) -> (r: Rate_Limit, ok: bool) {
	n := arg_num(b, d, 0, 1, 1 << 24, "count") or_return
	s := arg_secs(b, d, 1, 1, "seconds") or_return
	return Rate_Limit{n, s}, true
}

// `server network netmask [nopool]` for topology subnet (man page, "--server").
@(private)
handle_server_net :: proc(b: ^Build, d: ^Directive) {
	a := d.args
	if "server" in b.first {
		berr(b, d, "is given more than once")
		return
	}
	note_first(b, d)
	net, ok := ipv4_parse(a[0])
	if !ok {
		berr(b, d, "'%s' is not an IPv4 network address", a[0])
		return
	}
	mask, mok := ipv4_parse(a[1])
	if !mok {
		berr(b, d, "'%s' is not a dotted IPv4 netmask", a[1])
		return
	}
	prefix, pok := ipv4_mask_prefix(mask)
	if !pok {
		berr(b, d, "netmask '%s' is not valid (it must be ones followed by zeros)", a[1])
		return
	}
	if prefix > 29 || prefix < 1 {
		berr(
			b,
			d,
			"the network /%d is not usable; it must be between /1 and /29 so that there is room for the server and its clients",
			prefix,
		)
		return
	}
	if ipv4_to_u32(net) & ~ipv4_to_u32(mask) != 0 {
		berr(b, d, "network address '%s' has host bits set for netmask '%s'", a[0], a[1])
		return
	}
	nopool := false
	if len(a) == 3 {
		if a[2] != "nopool" {
			berr(b, d, "unknown flag '%s'; the only valid flag is nopool", a[2])
			return
		}
		nopool = true
	}
	sv := &b.server
	base := ipv4_to_u32(net)
	sv.net = Server_Net {
		network     = net,
		prefix      = u8(prefix),
		netmask     = mask,
		server_addr = ipv4_from_u32(base + 1),
		nopool      = nopool,
	}
	// Subnet topology: the pool runs from network+2 to broadcast-2.
	if !nopool && sv.pool == nil {
		bcast := base | ~ipv4_to_u32(mask)
		sv.pool = Pool4{ipv4_from_u32(base + 2), ipv4_from_u32(bcast - 2)}
	}
	add_push(b, "topology subnet")
	add_push(
		b,
		"route-gateway %d.%d.%d.%d",
		sv.net.server_addr[0],
		sv.net.server_addr[1],
		sv.net.server_addr[2],
		sv.net.server_addr[3],
	)
	b.common.topology_subnet = true
}

// `server-ipv6 addr/bits`: ifconfig-ipv6, ifconfig-ipv6-pool, push tun-ipv6.
@(private)
handle_server_ipv6 :: proc(b: ^Build, d: ^Directive) {
	addr, bits, ok := ipv6_parse_cidr(d.args[0])
	if !ok {
		berr(b, d, "'%s' is not an IPv6 prefix in addr/bits form", d.args[0])
		return
	}
	if bits < 1 || bits > 112 {
		berr(b, d, "the prefix length /%d is not usable; use /1 to /112", bits)
		return
	}
	n := Server_Net6 {
		prefix = addr,
		bits   = u8(bits),
	}
	// A zero host part: the server takes ::1 and the pool starts there too.
	if ipv6_host_part_is_zero(addr, bits) {
		n.server_addr = ipv6_add(addr, 1)
		n.pool_base = ipv6_add(addr, 1)
	} else {
		n.server_addr = addr
		n.pool_base = addr
	}
	b.server.net6 = n
	add_push(b, "tun-ipv6")
}

// `ifconfig-pool start end [netmask]`.
@(private)
handle_pool :: proc(b: ^Build, d: ^Directive) {
	start, ok1 := ipv4_parse(d.args[0])
	end, ok2 := ipv4_parse(d.args[1])
	if !ok1 || !ok2 {
		berr(b, d, "the start and end must be IPv4 addresses")
		return
	}
	if ipv4_to_u32(start) > ipv4_to_u32(end) {
		berr(b, d, "the start address comes after the end address")
		return
	}
	if len(d.args) == 3 {
		if _, ok := ipv4_parse(d.args[2]); !ok {
			berr(b, d, "netmask '%s' is not a dotted IPv4 netmask", d.args[2])
			return
		}
	}
	b.server.pool = Pool4{start, end}
}

// `push "option args"`: the string must be a valid option line.
@(private)
handle_push :: proc(b: ^Build, d: ^Directive) {
	line := trim_space(d.args[0])
	if !check_push_line(b, d, line) {
		return
	}
	append(&b.push, line)
}

// Checks one pushed option line. Returns false for lines that must not be pushed.
@(private)
check_push_line :: proc(b: ^Build, d: ^Directive, line: string) -> bool {
	if line == "" {
		berr(b, d, "the pushed option is empty")
		return false
	}
	toks := make([dynamic]string, b.alloc)
	scratch := make([dynamic]u8, b.alloc)
	if err := lex_line(line, &toks, &scratch, b.alloc); err != .None || len(toks) == 0 {
		berr(b, d, "the pushed option '%s' is malformed: %s", line, lex_error_text(err))
		return false
	}
	name := toks[0]
	if name == "topology" && len(toks) > 1 && toks[1] != "subnet" {
		berr(b, d, "topology %s is not supported; push `topology subnet` or do not push a topology", toks[1])
		return false
	}
	opt := option_find(name)
	switch {
	case opt == nil:
		bwarn(b, d, "'%s' is not a known option; clients may ignore it", name)
	case .Pushable not_in opt.flags && .Push_Only not_in opt.flags:
		bwarn(b, d, "'%s' cannot be pushed, so clients will ignore it", name)
	case opt.disp == .Rejected:
		bwarn(b, d, "'%s' is rejected by noirvpn clients: %s", name, opt.note)
	}
	return true
}

// Options legal in a client-config-dir file. Returns false if not handled.
@(private)
handle_ccd :: proc(b: ^Build, d: ^Directive) -> bool {
	a := d.args
	sp := &b.specific
	switch d.name {
	case "config":
	case "max-routes-per-client":
		if v, ok := arg_num(b, d, 0, 1, 1 << 24, "count"); ok {
			sp.max_routes = v
		}
	case "push":
		handle_push(b, d)
	case "push-reset":
		sp.push_reset = true
	case "push-remove":
		append(&b.push_remove, a[0])
	case "disable":
		sp.disable = true
	case "session-timeout":
		if v, ok := arg_secs(b, d, 0, 0, "seconds"); ok {
			sp.session_timeout = v
		}
	case "iroute":
		handle_iroute(b, d)
	case "iroute-ipv6":
		addr, bits, ok := ipv6_parse_cidr(a[0])
		if !ok {
			berr(b, d, "'%s' is not an IPv6 prefix in addr/bits form", a[0])
		} else {
			append(&b.iroutes6, Iroute6{addr, u8(bits)})
		}
	case "ifconfig-push":
		ip := Ifconfig_Push {
			local          = a[0],
			remote_netmask = a[1],
		}
		if len(a) == 3 {
			ip.alias = a[2]
		}
		ip.local_ip, ip.local_is_ip = ipv4_parse(a[0])
		if !ip.local_is_ip && !plausible_host(a[0]) {
			berr(b, d, "'%s' is not an IPv4 address or host name", a[0])
			return true
		}
		sp.ifconfig_push = ip
	case "ifconfig-ipv6-push":
		addr, bits, ok := ipv6_parse_cidr(a[0])
		if !ok {
			berr(b, d, "'%s' is not an IPv6 address in addr/bits form", a[0])
			return true
		}
		ip6 := Ifconfig6_Push {
			addr = addr,
			bits = u8(bits),
		}
		if len(a) == 2 {
			ip6.remote = a[1]
		}
		sp.ifconfig_ipv6_push = ip6
	case:
		return false
	}
	return true
}

// `iroute network [netmask]`. A missing netmask means a single host.
@(private)
handle_iroute :: proc(b: ^Build, d: ^Directive) {
	net, ok := ipv4_parse(d.args[0])
	if !ok {
		berr(b, d, "'%s' is not an IPv4 network address", d.args[0])
		return
	}
	prefix := 32
	if len(d.args) == 2 {
		mask, mok := ipv4_parse(d.args[1])
		if !mok {
			berr(b, d, "netmask '%s' is not a dotted IPv4 netmask", d.args[1])
			return
		}
		p, pok := ipv4_mask_prefix(mask)
		if !pok {
			berr(b, d, "netmask '%s' is not valid (it must be ones followed by zeros)", d.args[1])
			return
		}
		prefix = p
	}
	if ipv4_to_u32(net) & ~ipv4_to_u32(ipv4_prefix_mask(prefix)) != 0 {
		berr(b, d, "network address '%s' has host bits set", d.args[0])
		return
	}
	append(&b.iroutes, Iroute{net, u8(prefix)})
}

// Checks that only apply once all directives are read.
@(private)
finish_server :: proc(b: ^Build) {
	sv := &b.server
	c := &b.common
	t := &c.tls
	if "server" not_in b.first {
		marker := b.first["tls-server"]
		if marker == nil {
			marker = b.first["mode"]
		}
		gerr(
			b,
			marker,
			"a server needs the `server` directive, for example `server 10.8.0.0 255.255.255.0`",
		)
	}
	if sv.pool != nil && "server" in b.first {
		p := sv.pool.?
		net := sv.net
		if ipv4_to_u32(p.start) & ipv4_to_u32(net.netmask) != ipv4_to_u32(net.network) ||
		   ipv4_to_u32(p.end) & ipv4_to_u32(net.netmask) != ipv4_to_u32(net.network) {
			gerr(
				b,
				b.first["server"],
				"the address pool %d.%d.%d.%d - %d.%d.%d.%d is outside the server network",
				p.start[0],
				p.start[1],
				p.start[2],
				p.start[3],
				p.end[0],
				p.end[1],
				p.end[2],
				p.end[3],
			)
		}
	}
	// Listening sockets.
	g := b.g
	finish_link(b, &g)
	listens := make([dynamic]Listen, b.alloc)
	for r in b.listens {
		append(
			&listens,
			Listen {
				host = r.host,
				port = r.port if r.port_set else g.s.lport,
				proto = r.proto if r.proto_set else g.s.proto,
				tls = r.tls if r.proto_set else g.s.tls,
				family = r.family if r.proto_set else g.s.family,
			},
		)
	}
	if len(listens) == 0 {
		append(&listens, Listen{port = g.s.lport, proto = g.s.proto, tls = g.s.tls, family = g.s.family})
	}
	sv.listens = listens[:]
	any_tls := false
	for l in listens {
		any_tls ||= l.tls
	}
	// `datapath dco` or `udco` with a `tls-server` listener is a mixed server: the
	// DCO service or kernel driver runs the udp and tcp peers; the tls peers run
	// in the daemon on a second tun device (`tls_tun_name`).
	mixed := any_tls && datapath_is_dco(c.datapath)
	if mixed {
		name := tls_tun_name(c.dev, t.transport_dev, context.temp_allocator)
		switch {
		case len(name) > TUN_NAME_MAX:
			gerr(
				b,
				b.first["tls-transport-dev"] if t.transport_dev != "" else b.first["dev"],
				"the name of the second tun device, '%s', is longer than %d bytes (set a shorter one with `tls-transport-dev`)",
				name,
				TUN_NAME_MAX,
			)
		case !tun_name_ok(name):
			gerr(b, b.first["tls-transport-dev"], "`tls-transport-dev %s` is not a valid device name", name)
		case name == c.dev:
			gerr(b, b.first["tls-transport-dev"], "`tls-transport-dev` cannot be the same as `dev` because the two devices need different names")
		}
	} else if t.transport_dev != "" {
		gwarn(
			b,
			b.first["tls-transport-dev"],
			"`tls-transport-dev` has no effect because the second tun device only exists with `datapath dco` or `udco` and a `proto tls-server` listener",
		)
	}
	if key_source_is_set(t.transport_cert) != key_source_is_set(t.transport_key) {
		gerr(
			b,
			b.first["tls-transport-cert"] if key_source_is_set(t.transport_cert) else b.first["tls-transport-key"],
			"`tls-transport-cert` and `tls-transport-key` must be given together",
		)
	} else if key_source_is_set(t.transport_cert) && !any_tls {
		gwarn(b, b.first["tls-transport-cert"], "`tls-transport-cert` has no effect because no listener uses `proto tls-server`")
	}
	if t.transport_ws != "" {
		any_stream := false
		any_tcp := false
		for l in listens {
			any_stream ||= l.proto == .Tcp
			any_tcp ||= l.proto == .Tcp && !l.tls
		}
		switch {
		case !any_stream:
			gwarn(b, b.first["tls-transport-ws"], "`tls-transport-ws` has no effect because no listener uses `proto tls-server` or `proto tcp-server`")
		case any_tcp && datapath_is_dco(c.datapath):
			// Neither the DCO service nor the kernel speaks WebSocket, and the second tun device exists for `tls-server` listeners only.
			gerr(b, b.first["tls-transport-ws"], "datapath %s can only serve WebSocket clients on a tls listener (a tcp-server listener with tls-transport-ws needs `datapath userspace` or `auto`)", datapath_name(c.datapath))
		}
	}
	if t.transport_accept_tcp && !any_tls {
		gwarn(b, b.first["tls-transport-accept-tcp"], "`tls-transport-accept-tcp` has no effect because no listener uses `proto tls-server`")
	}
	if datapath_is_dco(c.datapath) {
		// The service and kernel driver serve one transport: one UDP socket, or TCP
		// streams (one TCP listener, and raw connections of `tls-server` listeners
		// with `tls-transport-accept-tcp`). The tls listeners stay with the daemon.
		own := 0
		udp := false
		for l in listens {
			if !l.tls {
				own += 1
				udp ||= l.proto == .Udp
			}
		}
		if own > 1 {
			gerr(b, b.first["datapath"], "`datapath %s` supports only one listening socket besides the `tls-server` ones, but there are %d (use `datapath auto` or `userspace`)", datapath_name(c.datapath), own)
		} else if udp && any_tls && t.transport_accept_tcp {
			gerr(b, b.first["datapath"], "`datapath %s` handles either udp or tcp, not both, so a udp listener cannot be combined with `tls-transport-accept-tcp`", datapath_name(c.datapath))
		}
	}
	check_wrap(b, g.s.wrap, "")
	// Identity and client verification.
	if !key_source_is_set(t.cert) || !key_source_is_set(t.key) {
		gerr(
			b,
			b.first["cert"] if key_source_is_set(t.cert) else b.first["key"],
			"a server needs `cert` and `key`",
		)
	}
	has_ca := key_source_is_set(t.ca) || t.capath != ""
	has_pins := sv.peer_keys != ""
	has_fp := len(b.fingerprints) > 0
	ext := sv.auth_external != nil
	if sv.peer_keys_mode == .Both || sv.peer_keys_mode == .Either {
		if !has_ca || !has_pins {
			gerr(b, b.first["peer-keys-mode"], "`peer-keys-mode %s` needs `ca` and `peer-keys`", "both" if sv.peer_keys_mode == .Both else "either")
		}
	} else {
		if has_ca && has_pins {
			if "peer-keys-mode" in b.first {
				gerr(
					b,
					b.first["peer-keys-mode"],
					"`peer-keys-mode pin` cannot be used with `ca`; use `both` (a chain and a pin) or `either` (a pin, or else a chain)",
				)
			} else {
				// `ca` and `peer-keys` together: a pin, else a chain.
				sv.peer_keys_mode = .Either
			}
		}
		if !has_pins && "peer-keys-mode" in b.first {
			gerr(b, b.first["peer-keys-mode"], "`peer-keys-mode` needs `peer-keys`")
		}
	}
	if has_pins && has_fp {
		gerr(
			b,
			b.first["peer-fingerprint"],
			"`peer-fingerprint` and `peer-keys` cannot be combined; put the keys in the peers file",
		)
	}
	switch sv.verify_client_cert {
	case .Require:
	case .Optional:
		if !ext && sv.peer_passwords == "" {
			gerr(
				b,
				b.first["verify-client-cert"],
				"`verify-client-cert optional` needs a password source, either `peer-passwords` or `auth-external`",
			)
		}
	case .None:
		gerr(
			b,
			b.first["verify-client-cert"],
			"`verify-client-cert none` is not supported; use `optional` with `peer-passwords` or `auth-external`",
		)
	}
	if sv.auth_web {
		if !ext {
			gerr(b, b.first["auth-web"], "`auth-web` needs `auth-external` because a controller handles the web sign-in")
		}
		if sv.verify_client_cert != .Optional {
			gerr(b, b.first["auth-web"], "`auth-web` needs `verify-client-cert optional` because the client does not send a certificate")
		}
	}
	// `optional` with a password source and no certificate check is a server for
	// password logins only: it asks no client for a certificate.
	if sv.verify_client_cert == .Require && !has_ca && !has_pins && !has_fp {
		gerr(
			b,
			nil,
			"there is no way to verify clients: add `ca`, `peer-keys` or `peer-fingerprint`, or use `verify-client-cert optional` with `peer-passwords` or `auth-external`",
		)
	}
	if sv.ccd_exclusive && sv.client_config_dir == "" {
		gerr(b, b.first["ccd-exclusive"], "`ccd-exclusive` needs `client-config-dir`")
	}
	if sv.tls_crypt_v2_max_age > 0 && g.s.wrap.tls_crypt_v2 == nil {
		gwarn(
			b,
			b.first["tls-crypt-v2-max-age"],
			"tls-crypt-v2-max-age has no effect without tls-crypt-v2",
		)
	}
}

// Control wrapping combinations. A client may use one mode; a server may add
// tls-crypt-v2 to tls-auth or tls-crypt, but not both of those.
@(private)
check_wrap :: proc(b: ^Build, w: Wrap, label: string) {
	n := 0
	if w.tls_auth != nil {
		n += 1
	}
	if w.tls_crypt != nil {
		n += 1
	}
	if w.tls_crypt_v2 != nil {
		n += 1
	}
	if b.role == .Client && n > 1 {
		gerr(
			b,
			b.first["tls-auth"],
			"a client can use only one of tls-auth, tls-crypt and tls-crypt-v2 (remote '%s')",
			label,
		)
	}
	if b.role == .Server && w.tls_auth != nil && w.tls_crypt != nil {
		gerr(b, b.first["tls-auth"], "tls-auth and tls-crypt cannot be used together")
	}
}

// Everything after the last directive.
@(private)
finish :: proc(b: ^Build) {
	c := &b.common
	t := &c.tls
	// tls-auth digest.
	digest := Auth_Digest.Sha1
	if b.auth_raw != "" {
		dg, ok := parse_digest(b.auth_raw)
		if ok {
			digest = dg
		}
		if !ok && has_tls_auth(b) {
			berr(
				b,
				b.auth_pos,
				"digest '%s' is not supported for tls-auth; use SHA1, SHA256 or SHA512",
				b.auth_raw,
			)
		}
		if !has_tls_auth(b) {
			bwarn(b, b.auth_pos, "has no effect without tls-auth (the data channel only uses AEAD)")
		}
	}
	apply_digest(b, &b.g.s, digest)
	for &e in b.entries {
		if e.block {
			apply_digest(b, &e.conn.link, digest)
		}
	}
	// Lists.
	t.fingerprints = b.fingerprints[:]
	t.remote_cert_ku = b.remote_cert_ku[:]
	c.routes = b.routes[:]
	c.routes6 = b.routes6[:]
	c.bus_allow = b.bus_allow[:]
	if c.dco_socket == "" {
		c.dco_socket = DCO_SOCKET_DEFAULT
	}
	// Device.
	finish_dev(b)
	// Cross-field checks.
	if c.ping_exit > 0 && c.ping_restart > 0 && b.ping_exit_set && b.ping_restart_set {
		gerr(b, b.first["ping-exit"], "`ping-exit` and `ping-restart` cannot be used together")
	}
	if t.version_min != .Default && t.version_max != .Default && t.version_min > t.version_max {
		gerr(b, b.first["tls-version-min"], "tls-version-min is higher than tls-version-max")
	}
	if t.tls_groups != "" && "pq-mode" in b.first {
		// An explicit group list wins over pq-mode.
		hybrid := strings.contains(t.tls_groups, "MLKEM")
		d := b.first["pq-mode"]
		switch {
		case t.pq_mode == .Require && !hybrid:
			gerr(
				b,
				d,
				"pq-mode is require, but tls-groups '%s' does not include a hybrid group such as X25519MLKEM768",
				t.tls_groups,
			)
		case t.pq_mode == .Off && hybrid:
			gwarn(
				b,
				d,
				"pq-mode is off, but tls-groups '%s' includes a hybrid group; the group list will be used",
				t.tls_groups,
			)
		case t.pq_mode == .Prefer && !hybrid:
			gwarn(
				b,
				d,
				"pq-mode is prefer, but tls-groups '%s' does not include a hybrid group, so the group list will be used and no hybrid key share will be sent",
				t.tls_groups,
			)
		}
	}
	if b.disable_dco {
		if b.datapath_set && c.datapath != .Userspace {
			gerr(
				b,
				b.first["disable-dco"],
				"`disable-dco` conflicts with `datapath %s`",
				datapath_name(c.datapath),
			)
		}
		c.datapath = .Userspace
		c.disable_dco = true
	}
	finish_link(b, &b.g)
	c.link = b.g.s
	switch b.role {
	case .Client:
		finish_client(b)
	case .Server:
		b.server.push = b.push[:]
		finish_server(b)
	case .None:
	}
}

@(private)
has_tls_auth :: proc(b: ^Build) -> bool {
	if b.g.s.wrap.tls_auth != nil {
		return true
	}
	for e in b.entries {
		if e.block && e.conn.wrap.tls_auth != nil {
			return true
		}
	}
	return false
}

@(private)
apply_digest :: proc(b: ^Build, s: ^Link_Settings, dg: Auth_Digest) {
	if ta, ok := s.wrap.tls_auth.?; ok {
		ta.digest = dg
		s.wrap.tls_auth = ta
	}
}

// `dev` and `dev-type`: tun only.
@(private)
finish_dev :: proc(b: ^Build) {
	c := &b.common
	dev := c.dev
	switch {
	case b.dev_type == "tap" || strings.has_prefix(dev, "tap"):
		gerr(
			b,
			b.first["dev-type"] if b.dev_type == "tap" else b.first["dev"],
			"TAP (layer 2) is not supported; use `dev tun`",
		)
	case dev == "null":
		gerr(b, b.first["dev"], "`dev null` is not supported; use `dev tun`")
	case b.dev_type != "" && b.dev_type != "tun":
		gerr(b, b.first["dev-type"], "unknown device type '%s'; only tun is supported", b.dev_type)
	case !strings.has_prefix(dev, "tun") &&
	     b.dev_type != "tun" &&
	     dev != "utun" &&
	     !strings.has_prefix(dev, "utun"):
		gerr(
			b,
			b.first["dev"],
			"device '%s' is not a tun device; use a name starting with tun, or add `dev-type tun`",
			dev,
		)
	}
}

// The longest name of a network device (IFNAMSIZ is 16, with the end byte).
TUN_NAME_MAX :: 15

// Name of the second tun device for tls clients (a server with `datapath dco` or
// `udco` and a `tls-server` listener opens it): `tls-transport-dev`, or `dev`
// plus `-tls` (`tun0` gives `tun0-tls`, `tun` gives `tun-tls`). The caller
// checks the length (`TUN_NAME_MAX`).
tls_tun_name :: proc(dev, explicit: string, allocator := context.allocator) -> string {
	if explicit != "" {
		return explicit
	}
	return strings.concatenate({dev if dev != "" else "tun", "-tls"}, allocator)
}

// A device name the kernel takes: not empty, no '/' and no blank, not '.' or '..'.
tun_name_ok :: proc "contextless" (name: string) -> bool {
	if len(name) == 0 || name == "." || name == ".." {
		return false
	}
	for ch in transmute([]u8)name {
		if ch == '/' || ch <= ' ' || ch == 0x7f {
			return false
		}
	}
	return true
}
