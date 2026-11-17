// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"

// State of one `<connection>` block while it is read.
@(private)
Block :: struct {
	remote:      Raw_Remote,
	have_remote: bool,
}

// Handles a `<connection>` block: a copy of the global link settings so far,
// changed by the block's own options.
@(private)
handle_connection :: proc(b: ^Build, d: ^Directive) {
	ls := b.g
	blk := Block{}
	for i in 0 ..< len(d.block) {
		apply(b, &d.block[i], &ls, &blk)
	}
	if !blk.have_remote {
		gerr(b, d, "a <connection> block needs a remote line")
		return
	}
	finish_link(b, &ls)
	r := blk.remote
	conn := Connection {
		link = ls.s,
		host = r.host,
	}
	conn.rport = r.port if r.port_set else ls.s.rport
	if r.proto_set {
		conn.proto = r.proto
		conn.tls = r.tls
		conn.family = r.family
	}
	finish_proxy(b, &conn, &ls)
	append(&b.entries, Conn_Entry{block = true, conn = conn})
}

// Protocol names: udp, tcp, tcp-client, tcp-server, tls, tls-client, tls-server,
// each with an optional 4 or 6 (one IP version). -server forms are for servers,
// -client forms for clients. `tls` is TCP in an outer TLS stream: it returns as
// `.Tcp` with `tls` true.
@(private)
parse_proto :: proc(b: ^Build, d: ^Directive, s: string) -> (p: Proto, f: Family, tls: bool, ok: bool) {
	rest: string
	switch {
	case strings.has_prefix(s, "udp"):
		p, rest = .Udp, s[3:]
	case strings.has_prefix(s, "tcp"):
		p, rest = .Tcp, s[3:]
	case strings.has_prefix(s, "tls"):
		p, rest, tls = .Tcp, s[3:], true
	case:
		berr(b, d, "unknown protocol '%s'; use udp, tcp-client, tcp-server, tls-client or tls-server (add 4 or 6 to pick an IP version)", s)
		return {}, {}, false, false
	}
	if len(rest) > 0 && (rest[0] == '4' || rest[0] == '6') {
		f = .V4 if rest[0] == '4' else .V6
		rest = rest[1:]
	}
	name := "tls" if tls else "tcp"
	switch {
	case rest == "":
	case p == .Tcp && rest == "-client":
		if b.role == .Server {
			berr(b, d, "a server cannot use '%s'; use %s-server", s, name)
			return {}, {}, false, false
		}
	case p == .Tcp && rest == "-server":
		if b.role == .Client {
			berr(b, d, "a client cannot use '%s'; use %s-client", s, name)
			return {}, {}, false, false
		}
	case:
		berr(b, d, "unknown protocol '%s'; use udp, tcp-client, tcp-server, tls-client or tls-server (add 4 or 6 to pick an IP version)", s)
		return {}, {}, false, false
	}
	return p, f, tls, true
}

// Parses a port number 1 to 65535.
@(private)
arg_port :: proc(b: ^Build, d: ^Directive, i: int, allow_zero := false) -> (port: u16, ok: bool) {
	v, vok := arg_num(b, d, i, 0 if allow_zero else 1, 65535, "port")
	return u16(v), vok
}

// Options that may be in a `<connection>` block. `ls` is the state they
// change; `blk` is non-nil inside a block. Returns false for any other option.
@(private)
handle_link :: proc(b: ^Build, d: ^Directive, ls: ^Link_State, blk: ^Block) -> bool {
	s := &ls.s
	a := d.args
	switch d.name {
	case "proto":
		p, f, tls, ok := parse_proto(b, d, a[0])
		if ok {
			s.proto, s.family, s.tls = p, f, tls
		}
	case "port":
		if port, ok := arg_port(b, d, 0); ok {
			s.lport, s.rport = port, port
		}
	case "lport":
		if port, ok := arg_port(b, d, 0, true); ok {
			s.lport = port
		}
	case "rport":
		if port, ok := arg_port(b, d, 0); ok {
			s.rport = port
		}
	case "local":
		handle_local(b, d, ls, blk)
	case "nobind":
		s.nobind = true
	case "bind":
		if len(a) == 1 {
			if a[0] != "ipv6only" {
				berr(b, d, "unknown flag '%s'; the only valid flag is ipv6only", a[0])
				return true
			}
			s.bind_v6only = true
		}
	case "float":
		s.float = true
	case "mssfix":
		handle_mssfix(b, d, ls)
	case "tun-mtu":
		if v, ok := arg_num(b, d, 0, 100, 65535, "MTU"); ok {
			s.tun_mtu = v
		}
		if len(a) == 2 {
			if v, ok := arg_num(b, d, 1, 100, 65535, "OCC MTU"); ok {
				s.occ_mtu = v
			}
		}
	case "explicit-exit-notify":
		n := 1
		if len(a) == 1 {
			v, ok := arg_num(b, d, 0, 1, 10, "count")
			if !ok {
				return true
			}
			n = v
		}
		// On a server n picks the client's reaction: 1 reconnect to the same
		// server, 2 advance to the next one. Other values behave like 1.
		if b.role == .Server && n > 2 {
			bwarn(
				b,
				d,
				"on a server only 1 and 2 are defined (reconnect to the same server, or move on to the next one), so 1 will be used instead of %d",
				n,
			)
			n = 1
		}
		s.explicit_exit_notify = n
	case "connect-retry":
		if v, ok := arg_secs(b, d, 0, 0, "seconds"); ok {
			s.connect_retry = v
		}
		if len(a) == 2 {
			if v, ok := arg_secs(b, d, 1, 1, "maximum seconds"); ok {
				s.connect_retry_max_wait = v
			}
		}
	case "connect-retry-max":
		if v, ok := arg_num(b, d, 0, 0, 1_000_000, "count"); ok {
			s.connect_retry_max = v
		}
	case "connect-timeout", "server-poll-timeout":
		if v, ok := arg_secs(b, d, 0, 1, "seconds"); ok {
			s.connect_timeout = v
		}
	case "mtu-disc":
		switch a[0] {
		case "no":
			s.mtu_disc = .No
		case "maybe":
			s.mtu_disc = .Maybe
		case "yes":
			s.mtu_disc = .Yes
		case:
			berr(b, d, "must be no, maybe or yes, not '%s'", a[0])
		}
	case "key-direction":
		switch a[0] {
		case "0":
			ls.key_dir = .Zero
		case "1":
			ls.key_dir = .One
		case:
			berr(b, d, "must be 0 or 1, not '%s'", a[0])
			return true
		}
		ls.key_dir_set = true
	case "tls-auth":
		handle_tls_auth(b, d, ls)
	case "tls-crypt":
		if check_inline_nonempty(b, d) {
			s.wrap.tls_crypt = key_source_of(d, 0)
		}
	case "tls-crypt-v2":
		handle_tls_crypt_v2(b, d, ls)
	case "remote":
		handle_remote(b, d, blk)
	case "http-proxy":
		handle_http_proxy(b, d, ls)
	case "http-proxy-option":
		handle_http_proxy_option(b, d, ls)
	case "http-proxy-user-pass":
		if check_inline_nonempty(b, d) {
			ls.px_user_pass = key_source_of(d, 0)
			ls.px_other = d
		}
	case:
		return false
	}
	return true
}

// `http-proxy host port [authfile|auto|none] [none|basic]`. The AUTHFILE
// gives Basic from the first request; `auto` waits for the proxy to ask.
@(private)
handle_http_proxy :: proc(b: ^Build, d: ^Directive, ls: ^Link_State) {
	a := d.args
	if a[0] == "" {
		berr(b, d, "the host name is empty")
		return
	}
	port, ok := arg_port(b, d, 1)
	if !ok {
		return
	}
	file := ""
	auto := false
	if len(a) >= 3 {
		switch a[2] {
		case "auto":
			auto = true
		case "auto-nct":
			berr(b, d, "auto-nct is not supported because there is no proxy authentication method without clear text; use auto, which accepts Basic")
			return
		case "none":
		case:
			file = a[2]
		}
	}
	basic := false
	if len(a) == 4 {
		switch a[3] {
		case "none":
		case "basic":
			basic = true
		case:
			berr(b, d, "proxy authentication method '%s' is not supported; only basic proxy authentication is available", a[3])
			return
		}
	}
	p := Http_Proxy {
		host    = a[0],
		port    = port,
		http10  = ls.px.http10,
		agent   = ls.px.agent,
		headers = ls.px.headers,
	}
	switch {
	case basic || file != "":
		p.auth = .Basic
		p.creds = Key_Source{path = file} if file != "" else Key_Source{}
	case auto:
		p.auth = .Auto
	}
	ls.px, ls.px_set, ls.px_pos = p, true, d
}

// `http-proxy-option VERSION 1.0|1.1`, `AGENT string`, `CUSTOM-HEADER name content`.
@(private)
handle_http_proxy_option :: proc(b: ^Build, d: ^Directive, ls: ^Link_State) {
	a := d.args
	want := 0
	switch strings.to_upper(a[0], context.temp_allocator) {
	case "VERSION":
		want = 2
	case "AGENT":
		want = 2
	case "CUSTOM-HEADER":
		want = 3
	case:
		berr(b, d, "unknown proxy option type '%s'; use VERSION, AGENT or CUSTOM-HEADER", a[0])
		return
	}
	if len(a) != want {
		berr(b, d, "%s needs %d argument%s, but the line has %d", a[0], want - 1, plural(want - 1), len(a) - 1)
		return
	}
	for v in a[1:] {
		if has_control(v) {
			berr(b, d, "a header cannot contain a line break or a control character")
			return
		}
	}
	switch strings.to_upper(a[0], context.temp_allocator) {
	case "VERSION":
		switch a[1] {
		case "1.0":
			ls.px.http10 = true
		case "1.1":
			ls.px.http10 = false
		case:
			berr(b, d, "VERSION must be 1.0 or 1.1, not '%s'", a[1])
			return
		}
	case "AGENT":
		ls.px.agent = a[1]
	case "CUSTOM-HEADER":
		if a[1] == "" || strings.contains_any(a[1], ": ") {
			berr(b, d, "'%s' is not a valid header name", a[1])
			return
		}
		list := make([]Proxy_Header, len(ls.px.headers) + 1, b.alloc)
		copy(list, ls.px.headers)
		list[len(list) - 1] = Proxy_Header{a[1], a[2]}
		ls.px.headers = list
	}
	ls.px_other = d
}

// True if `s` has a byte that cannot be in a header line.
@(private)
has_control :: proc(s: string) -> bool {
	for c in transmute([]u8)s {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return true
		}
	}
	return false
}

// Joins the proxy settings of a finished remote into `conn.proxy` and checks
// them against the remote.
@(private)
finish_proxy :: proc(b: ^Build, conn: ^Connection, ls: ^Link_State) {
	if !ls.px_set {
		if ls.px_other != nil && !b.px_warned {
			b.px_warned = true
			gwarn(b, ls.px_other, "`%s` has no effect because there is no `http-proxy`", ls.px_other.name)
		}
		return
	}
	p := ls.px
	d := ls.px_pos
	if conn.proto == .Udp {
		berr(b, d, "remote %s uses udp, but an HTTP CONNECT tunnel only supports TCP; use tcp-client or tls-client for this remote", conn.host)
		return
	}
	if !key_source_is_set(p.creds) {
		p.creds = ls.px_user_pass
	}
	switch p.auth {
	case .None:
		if key_source_is_set(ls.px_user_pass) {
			bwarn(b, d, "`http-proxy-user-pass` will not be used unless you add `auto` or `basic` to the http-proxy line")
		}
	case .Basic:
		if !key_source_is_set(p.creds) {
			berr(b, d, "basic proxy authentication needs credentials; give an AUTHFILE or add http-proxy-user-pass")
			return
		}
	case .Auto:
		if !key_source_is_set(p.creds) {
			bwarn(b, d, "`auto` has no credentials (http-proxy-user-pass), so the connection will fail if the proxy asks for authentication")
		}
	}
	conn.proxy = p
}

// An inline block must have some text in it.
@(private)
check_inline_nonempty :: proc(b: ^Build, d: ^Directive) -> bool {
	if d.has_body && trim_space(d.body) == "" {
		berr(b, d, "the inline block is empty")
		return false
	}
	return true
}

@(private)
handle_local :: proc(b: ^Build, d: ^Directive, ls: ^Link_State, blk: ^Block) {
	a := d.args
	host := a[0]
	if host == "*" {
		host = ""
	}
	if b.role == .Server && blk == nil {
		rl := Raw_Listen {
			host = host,
		}
		if len(a) >= 2 {
			port, ok := arg_port(b, d, 1)
			if !ok {
				return
			}
			rl.port, rl.port_set = port, true
		}
		if len(a) == 3 {
			p, f, tls, ok := parse_proto(b, d, a[2])
			if !ok {
				return
			}
			rl.proto, rl.family, rl.tls, rl.proto_set = p, f, tls, true
		}
		append(&b.listens, rl)
		return
	}
	s := &ls.s
	s.local_host = host
	if len(a) >= 2 {
		port, ok := arg_port(b, d, 1, true)
		if !ok {
			return
		}
		s.lport = port
	}
	if len(a) == 3 {
		p, f, tls, ok := parse_proto(b, d, a[2])
		if !ok {
			return
		}
		s.proto, s.family, s.tls = p, f, tls
	}
}

// `mssfix`, `mssfix max`, `mssfix max mtu`, `mssfix max fixed`.
@(private)
handle_mssfix :: proc(b: ^Build, d: ^Directive, ls: ^Link_State) {
	a := d.args
	if len(a) == 0 {
		ls.s.mssfix = {}
		return
	}
	v, ok := arg_num(b, d, 0, 0, 65535, "size")
	if !ok {
		return
	}
	if v != 0 && v < 100 {
		berr(b, d, "size must be 0 (off) or at least 100, but it is %d", v)
		return
	}
	m := Mssfix {
		kind  = .Link,
		value = v,
	}
	if len(a) == 2 {
		switch a[1] {
		case "mtu":
			m.kind = .Mtu
		case "fixed":
			m.kind = .Fixed
		case:
			berr(b, d, "unknown flag '%s'; use mtu or fixed", a[1])
			return
		}
	}
	if v == 0 {
		m.kind = .Off
	}
	ls.s.mssfix = m
}

@(private)
handle_tls_auth :: proc(b: ^Build, d: ^Directive, ls: ^Link_State) {
	if !check_inline_nonempty(b, d) {
		return
	}
	ta := Tls_Auth {
		key = key_source_of(d, 0),
	}
	if !d.has_body && len(d.args) == 2 {
		switch d.args[1] {
		case "0":
			ta.dir = .Zero
		case "1":
			ta.dir = .One
		case:
			berr(b, d, "direction must be 0 or 1, not '%s'", d.args[1])
			return
		}
		ls.auth_dir_given = true
	} else {
		ls.auth_dir_given = false
	}
	ls.s.wrap.tls_auth = ta
	ls.auth_pos = d
}

@(private)
handle_tls_crypt_v2 :: proc(b: ^Build, d: ^Directive, ls: ^Link_State) {
	if !check_inline_nonempty(b, d) {
		return
	}
	v2 := Tls_Crypt_V2 {
		key = key_source_of(d, 0),
	}
	if !d.has_body && len(d.args) == 2 {
		switch d.args[1] {
		case "force-cookie":
			v2.cookie = .Force
		case "allow-noncookie":
			v2.cookie = .Allow_Noncookie
		case:
			berr(b, d, "unknown mode '%s'; use force-cookie or allow-noncookie", d.args[1])
			return
		}
	}
	ls.s.wrap.tls_crypt_v2 = v2
}

// `remote host [port [proto]]`.
@(private)
handle_remote :: proc(b: ^Build, d: ^Directive, blk: ^Block) {
	a := d.args
	r := Raw_Remote {
		host = a[0],
		pos  = d,
	}
	if r.host == "" {
		berr(b, d, "the host name is empty")
		return
	}
	if len(a) >= 2 {
		port, ok := arg_port(b, d, 1)
		if !ok {
			return
		}
		r.port, r.port_set = port, true
	}
	if len(a) == 3 {
		p, f, tls, ok := parse_proto(b, d, a[2])
		if !ok {
			return
		}
		r.proto, r.family, r.tls, r.proto_set = p, f, tls, true
	}
	if blk != nil {
		if blk.have_remote {
			berr(b, d, "a <connection> block can only have one remote")
			return
		}
		blk.remote, blk.have_remote = r, true
		return
	}
	append(&b.entries, Conn_Entry{raw = r})
}

// Applies the `key-direction` default and the `auth` digest to a finished
// link, and checks which control wrapping modes are combined.
@(private)
finish_link :: proc(b: ^Build, ls: ^Link_State) {
	s := &ls.s
	if ta, ok := s.wrap.tls_auth.?; ok {
		if !ls.auth_dir_given && ls.key_dir_set {
			ta.dir = ls.key_dir
		}
		s.wrap.tls_auth = ta
	}
}
