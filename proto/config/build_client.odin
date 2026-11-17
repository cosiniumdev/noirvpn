// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

// Client-only options. Returns false if the option is not one of them.
@(private)
handle_client :: proc(b: ^Build, d: ^Directive) -> bool {
	a := d.args
	cl := &b.client
	switch d.name {
	case "client", "pull", "tls-client":
		note_first(b, d)
	case "client-service":
		cl.service = true
		note_first(b, d)
	case "remote-random":
		cl.remote_random = true
	case "tls-transport-strict":
		cl.tls_transport_strict = true
		note_first(b, d)
	case "tls-transport-hello":
		switch a[0] {
		case "default":
			cl.tls_transport_hello = .Default
		case "chrome":
			cl.tls_transport_hello = .Chrome
		case:
			berr(b, d, "must be default or chrome, not '%s'", a[0])
			return true
		}
		note_first(b, d)
	case "tls-transport-sni":
		if _, v4 := ipv4_parse(a[0]); v4 {
			berr(b, d, "'%s' is an IP address, but the server name must be a host name (leave the option out to send no name)", a[0])
		} else if _, v6 := ipv6_parse(a[0]); v6 || a[0] == "" {
			berr(b, d, "'%s' is not a host name", a[0])
		} else {
			cl.tls_transport_sni = a[0]
		}
	case "resolv-retry":
		if a[0] == "infinite" {
			cl.resolv_retry = -1
		} else if v, ok := arg_secs(b, d, 0, 0, "seconds (or infinite)"); ok {
			cl.resolv_retry = v
		}
	case "proto-force":
		p, _, tls, ok := parse_proto(b, d, a[0])
		if ok && tls {
			berr(b, d, "must be udp or tcp, not '%s' (tcp also keeps the tls remotes)", a[0])
		} else if ok {
			cl.proto_force = p
		}
	case "auth-user-pass":
		handle_auth_user_pass(b, d)
	case "auth-retry":
		switch a[0] {
		case "none":
			cl.auth_retry = .None
		case "nointeract":
			cl.auth_retry = .Nointeract
		case "interact":
			cl.auth_retry = .Interact
		case:
			berr(b, d, "must be none, nointeract or interact, not '%s'", a[0])
		}
	case "pull-filter":
		pf := Pull_Filter {
			text = a[1],
		}
		switch a[0] {
		case "accept":
			pf.action = .Accept
		case "ignore":
			pf.action = .Ignore
		case "reject":
			pf.action = .Reject
		case:
			berr(b, d, "must be accept, ignore or reject, not '%s'", a[0])
			return true
		}
		append(&b.pull_filters, pf)
	case "route-nopull":
		cl.route_nopull = true
	case "push-peer-info":
		cl.push_peer_info = true
	case "redirect-gateway":
		if f, ok := parse_redirect_flags(b, d); ok {
			cl.redirect_gateway += f
			cl.redirect_gateway_set = true
		}
	case "redirect-private":
		if f, ok := parse_redirect_flags(b, d); ok {
			cl.redirect_private += f
			cl.redirect_private_set = true
		}
	case "route-gateway":
		cl.route_gateway = a[0]
	case "route-ipv6-gateway":
		cl.route_ipv6_gateway = a[0]
	case "route-metric":
		if m, ok := arg_num(b, d, 0, 0, 0x7fff_ffff, "metric"); ok {
			cl.route_metric = m
		}
	case "ifconfig":
		cl.ifconfig = [2]string{a[0], a[1]}
	case "ifconfig-ipv6":
		second := a[1] if len(a) == 2 else ""
		cl.ifconfig_ipv6 = [2]string{a[0], second}
	case "dns":
		handle_dns(b, d)
	case "dhcp-option":
		append(&b.dns_options, Raw_Option{name = d.name, args = a})
	case "auth-token", "auth-token-user":
	// Pushed only; `apply` already refused these in a file.
	case:
		return false
	}
	return true
}

@(private)
handle_dns :: proc(b: ^Build, d: ^Directive) {
	switch d.args[0] {
	case "search-domains":
		if len(d.args) < 2 {
			berr(b, d, "search-domains needs at least one domain")
			return
		}
	case "server":
		if len(d.args) < 3 {
			berr(b, d, "server needs an id and an option, for example `dns server 0 address 1.1.1.1`")
			return
		}
		if _, ok := parse_range(d.args[1], -128, 127, true); !ok {
			berr(b, d, "server id must be a number from -128 to 127, but it is '%s'", d.args[1])
			return
		}
	case:
		berr(b, d, "unknown sub-option '%s'; use search-domains or server", d.args[0])
		return
	}
	append(&b.dns_options, Raw_Option{name = d.name, args = d.args})
}

@(private)
parse_redirect_flags :: proc(b: ^Build, d: ^Directive) -> (f: Redirect_Flags, ok: bool) {
	for s in d.args {
		switch s {
		case "local":
			f += {.Local}
		case "autolocal":
			f += {.Autolocal}
		case "def1":
			f += {.Def1}
		case "bypass-dhcp":
			f += {.Bypass_Dhcp}
		case "bypass-dns":
			f += {.Bypass_Dns}
		case "block-local":
			f += {.Block_Local}
		case "ipv6":
			f += {.Ipv6}
		case "!ipv4":
			f += {.Not_Ipv4}
		case:
			berr(b, d, "unknown flag '%s'", s)
			return {}, false
		}
	}
	return f, true
}

// `auth-user-pass`, `auth-user-pass file`, `auth-user-pass username-only`,
// or an inline block.
@(private)
handle_auth_user_pass :: proc(b: ^Build, d: ^Directive) {
	aup := Auth_User_Pass{}
	if d.has_body {
		if trim_space(d.body) == "" {
			berr(b, d, "the inline block is empty")
			return
		}
		aup.data, aup.is_inline = d.body, true
	} else if len(d.args) == 1 {
		if d.args[0] == "username-only" {
			aup.username_only = true
		} else {
			aup.file = d.args[0]
		}
	}
	b.client.auth_user_pass = aup
}

// Checks that only apply once all directives are read.
@(private)
finish_client :: proc(b: ^Build) {
	cl := &b.client
	c := &b.common
	cl.pull_filters = b.pull_filters[:]
	cl.dns_options = b.dns_options[:]
	if b.service {
		// The base config holds service settings only: the profile checks below
		// are skipped.
		return
	}
	if "pull" not_in b.first && "client" not_in b.first {
		if d, ok := b.first["tls-client"]; ok {
			gerr(
				b,
				d,
				"a client needs `pull`, so add the `client` directive: without it no tunnel address is configured, and `ifconfig` is not supported",
			)
		}
	}
	if !b.ping_restart_set && !b.ping_exit_set {
		c.ping_restart = 120 // upstream client default
	}
	// Remote list, in file order.
	list := make([dynamic]Connection, b.alloc)
	g := b.g
	for e in b.entries {
		if e.block {
			append(&list, e.conn)
			continue
		}
		r := e.raw
		conn := Connection {
			link = g.s,
			host = r.host,
		}
		conn.rport = r.port if r.port_set else g.s.rport
		if r.proto_set {
			conn.proto, conn.tls, conn.family = r.proto, r.tls, r.family
		}
		finish_proxy(b, &conn, &g)
		append(&list, conn)
	}
	cl.connections = list[:]
	if len(list) == 0 {
		gerr(b, nil, "a client needs at least one `remote`")
	}
	if pf, ok := cl.proto_force.?; ok {
		match := false
		for conn in list {
			if conn.proto == pf {
				match = true
			}
		}
		if !match && len(list) > 0 {
			d := b.first["proto-force"]
			gerr(
				b,
				d,
				"proto-force %s does not match any of the remotes",
				"udp" if pf == .Udp else "tcp",
			)
		}
	}
	for conn in list {
		check_wrap(b, conn.wrap, conn.host)
	}
	if cl.tls_transport_strict {
		any_tls := false
		for conn in list {
			any_tls ||= conn.tls
		}
		if !any_tls {
			gwarn(b, b.first["tls-transport-strict"], "`tls-transport-strict` has no effect because no remote uses `proto tls-client`")
		}
	}
	if c.tls.transport_ws != "" {
		any_tls := false
		for conn in list {
			any_tls ||= conn.tls
		}
		if !any_tls {
			gerr(b, b.first["tls-transport-ws"], "tls-transport-ws needs proto tls-client")
		}
	}
	if "tls-transport-hello" in b.first {
		any_tls := false
		for conn in list {
			any_tls ||= conn.tls
		}
		if !any_tls {
			gerr(b, b.first["tls-transport-hello"], "tls-transport-hello needs proto tls-client")
		}
	}
	t := &c.tls
	// Verify the server somehow.
	if !key_source_is_set(t.ca) && t.capath == "" && len(b.fingerprints) == 0 {
		gerr(
			b,
			b.first["remote-cert-tls"],
			"there is no way to verify the server: add `ca` (or `capath`) or `peer-fingerprint`",
		)
	}
	// Our identity.
	has_cert, has_key := key_source_is_set(t.cert), key_source_is_set(t.key)
	if has_cert != has_key {
		gerr(
			b,
			b.first["cert"] if has_cert else b.first["key"],
			"`cert` and `key` must be given together",
		)
	} else if !has_cert && cl.auth_user_pass == nil && !iv_sso_has_webauth(cl.iv_sso) {
		gerr(b, nil, "the client has no identity; add `cert` and `key`, `auth-user-pass`, or `setenv IV_SSO webauth` (to let the server sign the user in)")
	}
}

// True when a `setenv IV_SSO` list holds `webauth`. A client that can do a web
// sign-in needs no certificate and no login of its own.
@(private)
iv_sso_has_webauth :: proc(methods: string) -> bool {
	rest := methods
	for len(rest) > 0 {
		end := len(rest)
		for c, i in transmute([]u8)rest {
			if c == ',' {
				end = i
				break
			}
		}
		if rest[:end] == "webauth" {
			return true
		}
		rest = rest[min(end + 1, len(rest)):]
	}
	return false
}
