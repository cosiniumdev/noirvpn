// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:mem"

// Server side: struct to PUSH_REPLY messages.
//
// Order as a stock server (4.2): configured options (routes, DNS, redirect, then
// route-gateway, topology, ping, ping-restart), then the per-client tail
// (ifconfig-ipv6, ifconfig, peer-id, auth-token, cipher, protocol-flags or
// key-derivation, tun-mtu).
//
// Sizes (4.3), all counts include the closing NUL:
//   - Message: at most 1024 bytes (the sender's hard limit).
//   - Configured options: added while the message stays under 940 bytes (1024 - 84
//     tail headroom). Captured parts: 930 and 939 bytes before
//     `,push-continuation N`.
//   - Tail options may use the headroom, up to 1024 - 20 (continuation option).
//   - More than one message: all but the last end with `push-continuation 2`, the
//     last with `push-continuation 1`. A single message has none.
//
// SPEC-GAP: the spec gives 940 as the limit for configured options; captured parts
// reach 939. Exactly 940 was not observed. This builder stays under 940.

PUSH_MESSAGE_MAX :: CMD_SEND_MAX_LEN // 1024
PUSH_HEAD_LIMIT :: 940 // configured options keep the message under this
PUSH_CONT_LEN :: len(",push-continuation 2")
@(private)
PUSH_NAME_LEN :: len("PUSH_REPLY")

Dns_Group_Spec :: struct {
	prio:            int, // 0 to 127
	addresses:       []Dns_Address, // up to 8
	resolve_domains: []string,
	dnssec:          Dns_Dnssec,
	transport:       Dns_Transport,
	sni:             string,
}

// What the server pushes to one client. Zero values mean "not pushed".
Push_Reply_Params :: struct {
	// Configured options.
	routes:                []Route,
	routes6:               []Route6,
	dhcp_dns:              []Ip_Addr,
	dhcp_domains:          []string,
	// The v2 `dns` option. Fill these only for a client that sent IV_PROTO
	// bit 11; the legacy fields above are for the rest.
	dns_search_domains:    []string,
	dns_servers:           []Dns_Group_Spec,
	redirect_gateway:      Redirect,
	redirect_private:      Redirect,
	block_ipv6:            bool,
	// More options, already formatted (`name arg arg`), pushed as they are.
	extra:                 []string,
	route_gateway:         Maybe([4]u8),
	route_ipv6_gateway:    Maybe([16]u8),
	topology:              Topology,
	ping:                  Maybe(int),
	ping_restart:          Maybe(int),

	// Per client.
	ifconfig6:             Maybe(Ifconfig6),
	ifconfig:              Maybe(Ifconfig),
	peer_id:               Maybe(u32),
	auth_token:            string,
	auth_token_user:       string,
	cipher:                Cipher,
	protocol_flags:        Protocol_Flags,
	// `key-derivation tls-ekm` instead of `protocol-flags` (see `Negotiation`).
	legacy_key_derivation: bool,
	tun_mtu:               Maybe(int),
}

// Frees what `push_reply_build` returned.
push_messages_destroy :: proc(msgs: [dynamic]string) {
	for m in msgs {
		delete(m, msgs.allocator)
	}
	delete(msgs)
}

// A word as the receiver's tokenizer reads it back. It is quoted when it holds
// a space, quote or backslash, starts with `;` or `#`, or is empty. A comma or
// a control byte cannot be carried at all.
@(private)
wr_word :: proc "contextless" (w: ^Wr, s: string) -> bool {
	need_quote := len(s) == 0 || s[0] == ';' || s[0] == '#'
	for c in transmute([]u8)s {
		if c == ',' || c < 0x20 || c == 0x7F {
			return false
		}
		if c == ' ' || c == '"' || c == '\'' || c == '\\' {
			need_quote = true
		}
	}
	if !need_quote {
		wr_str(w, s)
		return true
	}
	wr_byte(w, '"')
	for c in transmute([]u8)s {
		if c == '"' || c == '\\' {
			wr_byte(w, '\\')
		}
		wr_byte(w, c)
	}
	wr_byte(w, '"')
	return true
}

@(private)
wr_ip :: proc "contextless" (w: ^Wr, ip: Ip_Addr) {
	if ip.v6 {
		wr_ipv6(w, ip.bytes)
	} else {
		wr_ipv4(w, {ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3]})
	}
}

@(private)
wr_route_gw :: proc "contextless" (w: ^Wr, kind: Route_Gw_Kind) -> bool {
	switch kind {
	case .Vpn_Gateway, .Default:
		wr_str(w, "vpn_gateway")
	case .Net_Gateway:
		wr_str(w, "net_gateway")
	case .Remote_Host:
		wr_str(w, "remote_host")
	case .Addr:
		return false
	}
	return true
}

@(private)
wr_redirect_flags :: proc "contextless" (w: ^Wr, f: Redirect_Flags) {
	names := [Redirect_Flag]string {
		.Local       = "local",
		.Autolocal   = "autolocal",
		.Def1        = "def1",
		.Bypass_Dhcp = "bypass-dhcp",
		.Bypass_Dns  = "bypass-dns",
		.Block_Local = "block-local",
		.Ipv6        = "ipv6",
		.Not_Ipv4    = "!ipv4",
	}
	for flag in Redirect_Flag {
		if flag in f {
			wr_byte(w, ' ')
			wr_str(w, names[flag])
		}
	}
}

@(private)
Opt_List :: struct {
	items:     [dynamic]string,
	allocator: mem.Allocator,
	err:       Error,
}

// Formats one option with `fill` and keeps it.
@(private)
opt_push :: proc(l: ^Opt_List, text: string) {
	if l.err != .None {
		return
	}
	s, ok := clone_str(text, l.allocator)
	if !ok {
		l.err = .Out_Of_Memory
		return
	}
	if _, err := append(&l.items, s); err != nil {
		delete(s, l.allocator)
		l.err = .Out_Of_Memory
	}
}

@(private)
opt_done :: proc(l: ^Opt_List, w: ^Wr, ok := true) {
	if l.err != .None {
		return
	}
	if !ok {
		l.err = .Bad_Argument
		return
	}
	if w.over {
		l.err = .Oversize
		return
	}
	opt_push(l, string(w.buf[:w.n]))
}

@(private)
build_options :: proc(p: ^Push_Reply_Params, head, tail: ^Opt_List) {
	tmp: [PUSH_MESSAGE_MAX]u8
	for r in p.routes {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "route ")
		wr_ipv4(&w, r.net)
		wr_byte(&w, ' ')
		wr_ipv4(&w, r.mask)
		ok := true
		_, has_metric := r.metric.?
		if r.gateway.kind != .Default || has_metric {
			wr_byte(&w, ' ')
			if r.gateway.kind == .Addr {
				wr_ipv4(&w, r.gateway.addr)
			} else {
				ok = wr_route_gw(&w, r.gateway.kind)
			}
		}
		if m, mok := r.metric.?; mok {
			wr_byte(&w, ' ')
			wr_uint(&w, u64(m))
		}
		opt_done(head, &w, ok)
	}
	for r in p.routes6 {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "route-ipv6 ")
		wr_ipv6(&w, r.net)
		wr_byte(&w, '/')
		wr_uint(&w, u64(r.bits))
		ok := true
		_, has_metric := r.metric.?
		if r.gateway.kind != .Default || has_metric {
			wr_byte(&w, ' ')
			if r.gateway.kind == .Addr {
				wr_ipv6(&w, r.gateway.addr)
			} else {
				ok = wr_route_gw(&w, r.gateway.kind)
			}
		}
		if m, mok := r.metric.?; mok {
			wr_byte(&w, ' ')
			wr_uint(&w, u64(m))
		}
		opt_done(head, &w, ok)
	}
	for ip in p.dhcp_dns {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "dhcp-option DNS6 " if ip.v6 else "dhcp-option DNS ")
		wr_ip(&w, ip)
		opt_done(head, &w)
	}
	for d in p.dhcp_domains {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "dhcp-option DOMAIN ")
		ok := len(d) > 0 && wr_word(&w, d)
		opt_done(head, &w, ok)
	}
	if len(p.dns_search_domains) > 0 {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "dns search-domains")
		ok := true
		for d in p.dns_search_domains {
			wr_byte(&w, ' ')
			ok = len(d) > 0 && wr_word(&w, d) && ok
		}
		opt_done(head, &w, ok)
	}
	for &g in p.dns_servers {
		build_dns_group(&g, head, tmp[:])
	}
	if p.redirect_gateway.set {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "redirect-gateway")
		wr_redirect_flags(&w, p.redirect_gateway.flags)
		opt_done(head, &w)
	}
	if p.redirect_private.set {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "redirect-private")
		wr_redirect_flags(&w, p.redirect_private.flags)
		opt_done(head, &w)
	}
	if p.block_ipv6 {
		opt_push(head, "block-ipv6")
	}
	for x in p.extra {
		if len(x) == 0 || !cmd_bytes_ok(x) || has_comma(x) {
			head.err = .Bad_Argument
			break
		}
		opt_push(head, x)
	}
	if a, ok := p.route_gateway.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "route-gateway ")
		wr_ipv4(&w, a)
		opt_done(head, &w)
	}
	if a, ok := p.route_ipv6_gateway.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "route-ipv6-gateway ")
		wr_ipv6(&w, a)
		opt_done(head, &w)
	}
	switch p.topology {
	case .Subnet:
		opt_push(head, "topology subnet")
	case .Net30:
		opt_push(head, "topology net30")
	case .P2p:
		opt_push(head, "topology p2p")
	case .Unset:
	}
	if v, ok := p.ping.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "ping ")
		wr_uint(&w, u64(v))
		opt_done(head, &w)
	}
	if v, ok := p.ping_restart.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "ping-restart ")
		wr_uint(&w, u64(v))
		opt_done(head, &w)
	}

	// Per client.
	if c, ok := p.ifconfig6.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "ifconfig-ipv6 ")
		wr_ipv6(&w, c.addr)
		wr_byte(&w, '/')
		wr_uint(&w, u64(c.bits))
		wr_byte(&w, ' ')
		wr_ipv6(&w, c.gateway)
		opt_done(tail, &w)
	}
	if c, ok := p.ifconfig.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "ifconfig ")
		wr_ipv4(&w, c.a)
		wr_byte(&w, ' ')
		wr_ipv4(&w, c.b)
		opt_done(tail, &w)
	}
	if id, ok := p.peer_id.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "peer-id ")
		wr_uint(&w, u64(id))
		opt_done(tail, &w, id < 0xFFFFFF)
	}
	if len(p.auth_token) > 0 {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "auth-token ")
		ok := wr_word(&w, p.auth_token)
		opt_done(tail, &w, ok)
	}
	if len(p.auth_token_user) > 0 {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "auth-token-user ")
		ok := wr_word(&w, p.auth_token_user)
		opt_done(tail, &w, ok)
	}
	if p.cipher != .None {
		opt_push(tail, "cipher AES-128-GCM" if p.cipher == .Aes_128_Gcm else ("cipher AES-256-GCM" if p.cipher == .Aes_256_Gcm else "cipher CHACHA20-POLY1305"))
	}
	if p.legacy_key_derivation {
		opt_push(tail, "key-derivation tls-ekm")
	} else if p.protocol_flags != {} {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "protocol-flags")
		for f in Protocol_Flag {
			if f in p.protocol_flags {
				wr_byte(&w, ' ')
				wr_str(&w, protocol_flag_name(f))
			}
		}
		opt_done(tail, &w)
	}
	if v, ok := p.tun_mtu.?; ok {
		w := Wr{buf = tmp[:]}
		wr_str(&w, "tun-mtu ")
		wr_uint(&w, u64(v))
		opt_done(tail, &w)
	}
}

@(private)
has_comma :: proc "contextless" (s: string) -> bool {
	for c in transmute([]u8)s {
		if c == ',' {
			return true
		}
	}
	return false
}

@(private)
build_dns_group :: proc(g: ^Dns_Group_Spec, head: ^Opt_List, tmp: []u8) {
	if g.prio < 0 || g.prio > 127 || len(g.addresses) == 0 || len(g.addresses) > MAX_DNS_ADDRESSES {
		head.err = .Bad_Argument
		return
	}
	wa := Wr{buf = tmp}
	wr_str(&wa, "dns server ")
	wr_uint(&wa, u64(g.prio))
	wr_str(&wa, " address")
	for a in g.addresses {
		wr_byte(&wa, ' ')
		switch {
		case a.port == 0:
			wr_ip(&wa, a.ip)
		case a.ip.v6:
			wr_byte(&wa, '[')
			wr_ip(&wa, a.ip)
			wr_str(&wa, "]:")
			wr_uint(&wa, u64(a.port))
		case:
			wr_ip(&wa, a.ip)
			wr_byte(&wa, ':')
			wr_uint(&wa, u64(a.port))
		}
	}
	opt_done(head, &wa)
	if len(g.resolve_domains) > 0 {
		w := Wr{buf = tmp}
		wr_str(&w, "dns server ")
		wr_uint(&w, u64(g.prio))
		wr_str(&w, " resolve-domains")
		ok := true
		for d in g.resolve_domains {
			wr_byte(&w, ' ')
			ok = len(d) > 0 && wr_word(&w, d) && ok
		}
		opt_done(head, &w, ok)
	}
	if g.dnssec != .Unset {
		w := Wr{buf = tmp}
		wr_str(&w, "dns server ")
		wr_uint(&w, u64(g.prio))
		wr_str(&w, " dnssec ")
		switch g.dnssec {
		case .Yes:
			wr_str(&w, "yes")
		case .No:
			wr_str(&w, "no")
		case .Optional:
			wr_str(&w, "optional")
		case .Unset:
		}
		opt_done(head, &w)
	}
	if g.transport != .Unset {
		w := Wr{buf = tmp}
		wr_str(&w, "dns server ")
		wr_uint(&w, u64(g.prio))
		wr_str(&w, " transport ")
		switch g.transport {
		case .Plain:
			wr_str(&w, "plain")
		case .Doh:
			wr_str(&w, "DoH")
		case .Dot:
			wr_str(&w, "DoT")
		case .Unset:
		}
		opt_done(head, &w)
	}
	if len(g.sni) > 0 {
		w := Wr{buf = tmp}
		wr_str(&w, "dns server ")
		wr_uint(&w, u64(g.prio))
		wr_str(&w, " sni ")
		ok := wr_word(&w, g.sni)
		opt_done(head, &w, ok)
	}
}

// Cuts option lists into messages. `head` options keep a message under 940
// bytes; `tail` options may use the room up to 1024 less the continuation.
// Returns message texts (no NUL), allocated with `allocator`; free with
// `push_messages_destroy`.
push_reply_pack :: proc(head, tail: []string, allocator := context.allocator) -> (msgs: [dynamic]string, err: Error) {
	// One message if it all fits.
	head_len := PUSH_NAME_LEN + 1
	for o in head {
		head_len += 1 + len(o)
	}
	all_len := head_len
	for o in tail {
		all_len += 1 + len(o)
	}
	if head_len < PUSH_HEAD_LIMIT && all_len <= PUSH_MESSAGE_MAX {
		return pack_single(head, tail, all_len, allocator)
	}

	// Several. Greedy; each part leaves room for `,push-continuation N`.
	msgs = make([dynamic]string, 0, 4, allocator)
	defer if err != .None {
		push_messages_destroy(msgs)
		msgs = nil
	}
	n_head := len(head)
	total := n_head + len(tail)
	opt_at :: proc(head, tail: []string, i: int) -> string {
		return head[i] if i < len(head) else tail[i - len(head)]
	}
	cur := make([dynamic]u8, 0, PUSH_MESSAGE_MAX, allocator)
	defer delete(cur)
	append(&cur, "PUSH_REPLY")
	cur_len := PUSH_NAME_LEN + 1
	count := 0
	for i in 0 ..< total {
		o := opt_at(head, tail, i)
		add := 1 + len(o)
		limit := PUSH_HEAD_LIMIT - 1 if i < n_head else PUSH_MESSAGE_MAX - PUSH_CONT_LEN
		if PUSH_NAME_LEN + 1 + add + PUSH_CONT_LEN > PUSH_MESSAGE_MAX {
			return msgs, .Oversize // one option cannot fit even alone
		}
		if count > 0 && cur_len + add > limit {
			if err = flush_part(&cur, &msgs, ",push-continuation 2", allocator); err != .None {
				return msgs, err
			}
			clear(&cur)
			append(&cur, "PUSH_REPLY")
			cur_len, count = PUSH_NAME_LEN + 1, 0
		}
		append(&cur, ',')
		append(&cur, o)
		cur_len += add
		count += 1
	}
	err = flush_part(&cur, &msgs, ",push-continuation 1", allocator)
	return msgs, err
}

@(private)
flush_part :: proc(cur: ^[dynamic]u8, msgs: ^[dynamic]string, suffix: string, allocator: mem.Allocator) -> Error {
	append(cur, suffix)
	s, ok := clone_str(string(cur[:]), allocator)
	if !ok {
		return .Out_Of_Memory
	}
	if _, aerr := append(msgs, s); aerr != nil {
		delete(s, allocator)
		return .Out_Of_Memory
	}
	return .None
}

@(private)
pack_single :: proc(head, tail: []string, total: int, allocator: mem.Allocator) -> (msgs: [dynamic]string, err: Error) {
	msgs = make([dynamic]string, 0, 1, allocator)
	buf := make([]u8, total, allocator)
	defer delete(buf, allocator)
	copy(buf, "PUSH_REPLY")
	i := PUSH_NAME_LEN
	for lst in ([2][]string{head, tail}) {
		for o in lst {
			buf[i] = ','
			copy(buf[i + 1:], o)
			i += 1 + len(o)
		}
	}
	s, ok := clone_str(string(buf[:i]), allocator)
	if !ok {
		delete(msgs)
		return nil, .Out_Of_Memory
	}
	append(&msgs, s)
	return msgs, .None
}

// From the struct to the messages. Each result is one command text (no NUL);
// write each with its own TLS write (`cmd_frame`).
// Errors:
// - `.Bad_Argument`: a value that cannot be written (comma or control byte in a
//   string, prio above 127, dns group with no address)
// - `.Oversize`: one option that cannot fit a message
push_reply_build :: proc(p: ^Push_Reply_Params, allocator := context.allocator) -> (msgs: [dynamic]string, err: Error) {
	head := Opt_List {
		items     = make([dynamic]string, 0, 16, allocator),
		allocator = allocator,
	}
	tail := Opt_List {
		items     = make([dynamic]string, 0, 8, allocator),
		allocator = allocator,
	}
	defer {
		for s in head.items {
			delete(s, allocator)
		}
		for s in tail.items {
			delete(s, allocator)
		}
		delete(head.items)
		delete(tail.items)
	}
	build_options(p, &head, &tail)
	if head.err != .None {
		return nil, head.err
	}
	if tail.err != .None {
		return nil, tail.err
	}
	return push_reply_pack(head.items[:], tail.items[:], allocator)
}
