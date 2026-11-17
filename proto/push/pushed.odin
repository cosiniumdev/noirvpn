// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:mem"
import "core:slice"

// PUSH_REPLY parsing: the options a client must handle, typed
//. Not on the hot path: allocates from the
// allocator you pass, with bounds on every list.
//
// Flow on a client:
//
//	a: Push_Assembler
//	push_assembler_init(&a)
//	... for each PUSH_REPLY command (`Push_Reply_Msg.options`) ...
//	status, err := push_assembler_feed(&a, msg.options)
//	if status == .Complete {
//		res := pushed_options_validate(&a.po, &params)   // may refuse the connection
//		... apply a.po ...
//		push_assembler_reset(&a)
//	}
//	push_assembler_destroy(&a)
//
// Options not applied go into `po.notes` with a disposition.
// Only the text structure can cause the parse to fail; a bad option is a note,
// like a stock client logging and skipping it.

// Bounds. A real reply is a few hundred to a few thousand bytes.
MAX_PUSH_REPLY_BYTES :: 64 * 1024 // all parts of one reply together
MAX_PUSH_PARTS :: 64
MAX_PUSH_OPTIONS :: 2048 // options in one reply, all parts
MAX_PUSH_NOTES :: 256
MAX_DNS_GROUPS :: 16
MAX_DNS_ADDRESSES :: 8 // per dns server group

Topology :: enum u8 {
	Unset,
	Subnet,
	Net30,
	P2p,
}

Disposition :: enum u8 {
	// Applied. (Not stored in notes; here for completeness.)
	Accept,
	// Parsed or recognised, and dropped.
	Ignore,
	// The connection must fail (see `pushed_options_validate`).
	Reject,
}

Note_Reason :: enum u8 {
	// Name is not in the table of options a client handles.
	Unknown_Option,
	// A known option that does not apply to noirvpn (Windows only, management
	// hooks, DHCP extras, ...).
	Not_Applicable,
	// Wrong number of words, bad number or address, unclosed quote, ...
	Malformed,
	// Known option, a value or flag this version does not handle.
	Unsupported_Value,
	// `topology net30` or `p2p`.
	Unsupported_Topology,
	// `comp-lzo` or `compress` asking for compression framing.
	Compression,
	// A list is full (too many dns groups, addresses, notes).
	Limit,
}

Option_Note :: struct {
	// Option name, the first word. Empty if the text could not be split.
	name:        string,
	// The option as it came (auth-token options are never noted).
	text:        string,
	disposition: Disposition,
	reason:      Note_Reason,
}

// `ifconfig <a> <b>`. With topology subnet: `a` is the address, `b` the netmask.
Ifconfig :: struct {
	a: [4]u8,
	b: [4]u8,
}

// `ifconfig-ipv6 <addr>/<bits> <gateway>`.
Ifconfig6 :: struct {
	addr:    [16]u8,
	bits:    u8,
	gateway: [16]u8,
}

Route_Gw_Kind :: enum u8 {
	// No gateway word: the default (the VPN gateway).
	Default,
	Vpn_Gateway,
	Net_Gateway,
	Remote_Host,
	// A literal address, in `Route_Gw.addr`.
	Addr,
}

Route_Gw :: struct {
	kind: Route_Gw_Kind,
	addr: [4]u8,
}

Route_Gw6 :: struct {
	kind: Route_Gw_Kind,
	addr: [16]u8,
}

// `route <net> [<mask> [<gateway> [<metric>]]]`. Mask is 255.255.255.255 when
// the word is missing.
Route :: struct {
	net:     [4]u8,
	mask:    [4]u8,
	gateway: Route_Gw,
	metric:  Maybe(int),
}

// `route-ipv6 <net>/<bits> [<gateway> [<metric>]]`.
Route6 :: struct {
	net:     [16]u8,
	bits:    u8,
	gateway: Route_Gw6,
	metric:  Maybe(int),
}

Redirect_Flag :: enum u8 {
	Local,
	Autolocal,
	Def1,
	Bypass_Dhcp,
	Bypass_Dns,
	Block_Local,
	Ipv6,
	Not_Ipv4, // `!ipv4`
}

Redirect_Flags :: bit_set[Redirect_Flag;u8]

// `redirect-gateway` / `redirect-private`. `set` is true once the option was
// seen, even with no flags.
Redirect :: struct {
	set:   bool,
	flags: Redirect_Flags,
}

// An address with an optional port (0 = the transport's default).
Ip_Addr :: struct {
	v6:    bool,
	// IPv4 uses the first four bytes.
	bytes: [16]u8,
}

Dns_Address :: struct {
	ip:   Ip_Addr,
	port: u16,
}

Dns_Dnssec :: enum u8 {
	Unset,
	Yes,
	No,
	Optional,
}

Dns_Transport :: enum u8 {
	Unset,
	Plain,
	Doh,
	Dot,
}

// One `dns server <prio> ...` group, built from every option with that
// priority.
Dns_Server :: struct {
	prio:            int,
	addresses:       [dynamic]Dns_Address,
	resolve_domains: [dynamic]string,
	dnssec:          Dns_Dnssec,
	transport:       Dns_Transport,
	sni:             string,
}

Inactive :: struct {
	seconds: int,
	// Bytes of traffic below which the connection counts as idle; 0 if none.
	bytes:   int,
}

// Everything a client takes from a PUSH_REPLY. The struct owns its strings and
// lists: free it with `pushed_options_destroy`. Fields marked `Maybe` are
// absent unless the server pushed them.
Pushed_Options :: struct {
	allocator:            mem.Allocator,
	strs:                 [dynamic]string, // owner of every string below

	// Address and routes.
	topology:             Topology,
	ifconfig:             Maybe(Ifconfig),
	ifconfig6:            Maybe(Ifconfig6),
	route_gateway:        Maybe([4]u8),
	// `route-gateway dhcp` was pushed (noirvpn ignores it).
	route_gateway_dhcp:   bool,
	route_ipv6_gateway:   Maybe([16]u8),
	route_metric:         Maybe(int),
	route_delay:          Maybe(int),
	routes:               [dynamic]Route,
	routes6:              [dynamic]Route6,
	redirect_gateway:     Redirect,
	redirect_private:     Redirect,
	block_ipv6:           bool,

	// DNS. `dhcp_*` come from `dhcp-option`, the rest from the v2 `dns` option.
	dhcp_dns:             [dynamic]Ip_Addr,
	dhcp_domains:         [dynamic]string,
	dns_search_domains:   [dynamic]string,
	dns_servers:          [dynamic]Dns_Server, // by priority, lowest first, after finish

	// Timers and policy.
	ping:                 Maybe(int),
	ping_restart:         Maybe(int),
	ping_exit:            Maybe(int),
	inactive:             Maybe(Inactive),
	session_timeout:      Maybe(int),
	// `explicit-exit-notify [n]`. 0 means the word had no number.
	explicit_exit_notify: Maybe(int),
	tun_mtu:              Maybe(int),
	sndbuf:               Maybe(int),
	rcvbuf:               Maybe(int),
	tcp_nodelay:          bool,
	persist_tun:          bool,
	persist_key:          bool,

	// Cryptography and session.
	peer_id:              Maybe(u32),
	cipher:               string, // as pushed; "" if none
	key_derivation_ekm:   bool, // `key-derivation tls-ekm`
	protocol_flags:       Protocol_Flags,
	// The token is a secret: do not log it.
	auth_token:           string,
	auth_token_user:      string, // base64, as pushed

	// Bookkeeping.
	option_count:         int, // options seen
	other_count:          int, // ... that were not auth-token or auth-token-user
	notes:                [dynamic]Option_Note,
	notes_dropped:        int,
}

// Starts an empty set. Every allocation uses `allocator`.
pushed_options_init :: proc(po: ^Pushed_Options, allocator := context.allocator) {
	po^ = {}
	po.allocator = allocator
	po.strs = make([dynamic]string, 0, 0, allocator)
	po.routes = make([dynamic]Route, 0, 0, allocator)
	po.routes6 = make([dynamic]Route6, 0, 0, allocator)
	po.dhcp_dns = make([dynamic]Ip_Addr, 0, 0, allocator)
	po.dhcp_domains = make([dynamic]string, 0, 0, allocator)
	po.dns_search_domains = make([dynamic]string, 0, 0, allocator)
	po.dns_servers = make([dynamic]Dns_Server, 0, 0, allocator)
	po.notes = make([dynamic]Option_Note, 0, 0, allocator)
}

// Frees everything, including the strings. The struct is empty afterwards.
pushed_options_destroy :: proc(po: ^Pushed_Options) {
	a := po.allocator
	for s in po.strs {
		delete(s, a)
	}
	delete(po.strs)
	delete(po.routes)
	delete(po.routes6)
	delete(po.dhcp_dns)
	delete(po.dhcp_domains)
	delete(po.dns_search_domains)
	for &g in po.dns_servers {
		delete(g.addresses)
		delete(g.resolve_domains)
	}
	delete(po.dns_servers)
	delete(po.notes)
	po^ = {}
}

// True if the reply holds only auth-token options. The client takes the new
// token and changes nothing else.
pushed_options_token_only :: proc "contextless" (po: ^Pushed_Options) -> bool {
	return po.option_count > 0 && po.other_count == 0 && len(po.auth_token) > 0
}

// The first note with disposition `.Reject`, if any.
pushed_options_first_reject :: proc(po: ^Pushed_Options) -> (note: Option_Note, ok: bool) {
	for n in po.notes {
		if n.disposition == .Reject {
			return n, true
		}
	}
	return {}, false
}

// ------------------------------------------------------------------- parse

@(private)
intern :: proc(po: ^Pushed_Options, s: string) -> (r: string, err: Error) {
	if len(s) == 0 {
		return "", .None
	}
	c, ok := clone_str(s, po.allocator)
	if !ok {
		return "", .Out_Of_Memory
	}
	if _, aerr := append(&po.strs, c); aerr != nil {
		delete(c, po.allocator)
		return "", .Out_Of_Memory
	}
	return c, .None
}

@(private)
add_note :: proc(po: ^Pushed_Options, name, raw: string, d: Disposition, reason: Note_Reason) -> Error {
	if len(po.notes) >= MAX_PUSH_NOTES {
		po.notes_dropped += 1
		return .None
	}
	n, err := intern(po, name)
	if err != .None {
		return err
	}
	t: string
	t, err = intern(po, raw)
	if err != .None {
		return err
	}
	if _, aerr := append(&po.notes, Option_Note{n, t, d, reason}); aerr != nil {
		return .Out_Of_Memory
	}
	return .None
}

// Adds a comma separated option list (the text after `PUSH_REPLY,`). Empty items
// (trailing comma) are skipped. A reply may be added in several calls; the lists
// grow.
// Errors: `.Too_Many_Options` and `.Out_Of_Memory` only. A bad option is a note.
// The struct stays valid after an error.
pushed_options_add :: proc(po: ^Pushed_Options, options: string) -> Error {
	rest := options
	for len(rest) > 0 {
		item, _ := next_item(&rest, ',')
		if len(item) == 0 {
			continue
		}
		if err := pushed_options_add_option(po, item); err != .None {
			return err
		}
	}
	return .None
}

// Adds one option (one comma-free item, for example `route 10.0.0.0
// 255.0.0.0`). Used for each item of a PUSH_UPDATE.
pushed_options_add_option :: proc(po: ^Pushed_Options, item: string) -> Error {
	if po.option_count >= MAX_PUSH_OPTIONS {
		return .Too_Many_Options
	}
	po.option_count += 1
	w: Words
	terr := tokenize_option(item, &w)
	if terr != .None || w.count == 0 {
		// A comment-only item has no words; it is just skipped.
		if terr == .None {
			po.option_count -= 1
			return .None
		}
		po.other_count += 1
		name := item
		for c, i in transmute([]u8)item {
			if c == ' ' {
				name = item[:i]
				break
			}
		}
		return add_note(po, name, item, .Ignore, .Malformed)
	}
	name := words_get(&w, 0)
	if name != "auth-token" && name != "auth-token-user" {
		po.other_count += 1
	}
	return apply_option(po, &w, name, item)
}

@(private)
bad :: proc(po: ^Pushed_Options, name, raw: string) -> Error {
	return add_note(po, name, raw, .Ignore, .Malformed)
}

@(private)
not_applicable :: proc(po: ^Pushed_Options, name, raw: string) -> Error {
	return add_note(po, name, raw, .Ignore, .Not_Applicable)
}

@(private)
set_seconds :: proc(po: ^Pushed_Options, w: ^Words, name, raw: string, dst: ^Maybe(int)) -> Error {
	if w.count != 2 {
		return bad(po, name, raw)
	}
	v, ok := parse_uint_max(words_get(w, 1), 0x7FFFFFFF)
	if !ok {
		return bad(po, name, raw)
	}
	dst^ = int(v)
	return .None
}

@(private)
apply_option :: proc(po: ^Pushed_Options, w: ^Words, name, raw: string) -> Error {
	arg :: proc(w: ^Words, i: int) -> string {
		return words_get(w, i)
	}
	n := w.count
	switch name {
	case "topology":
		if n != 2 {
			return bad(po, name, raw)
		}
		switch arg(w, 1) {
		case "subnet":
			po.topology = .Subnet
		case "net30":
			po.topology = .Net30
			return add_note(po, name, raw, .Reject, .Unsupported_Topology)
		case "p2p":
			po.topology = .P2p
			return add_note(po, name, raw, .Reject, .Unsupported_Topology)
		case:
			return bad(po, name, raw)
		}
	case "ifconfig":
		a, aok := parse_ipv4(arg(w, 1))
		b, bok := parse_ipv4(arg(w, 2))
		if n != 3 || !aok || !bok {
			return bad(po, name, raw)
		}
		po.ifconfig = Ifconfig{a, b}
	case "ifconfig-ipv6":
		if n != 3 {
			return bad(po, name, raw)
		}
		addr, bits, ok := parse_ipv6_prefix(arg(w, 1))
		gw, gok := parse_ipv6(arg(w, 2))
		if !ok || !gok || bits < 64 || bits > 124 {
			return bad(po, name, raw)
		}
		po.ifconfig6 = Ifconfig6{addr, u8(bits), gw}
	case "route":
		return apply_route(po, w, name, raw)
	case "route-ipv6":
		return apply_route6(po, w, name, raw)
	case "route-gateway":
		if n != 2 {
			return bad(po, name, raw)
		}
		if arg(w, 1) == "dhcp" {
			po.route_gateway_dhcp = true
			return not_applicable(po, name, raw)
		}
		a, ok := parse_ipv4(arg(w, 1))
		if !ok {
			return bad(po, name, raw)
		}
		po.route_gateway = a
	case "route-ipv6-gateway":
		a, ok := parse_ipv6(arg(w, 1))
		if n != 2 || !ok {
			return bad(po, name, raw)
		}
		po.route_ipv6_gateway = a
	case "route-metric":
		return set_seconds(po, w, name, raw, &po.route_metric)
	case "route-delay":
		// `route-delay <n> [<window>]`: the first number is what matters.
		if n < 2 || n > 3 {
			return bad(po, name, raw)
		}
		v, ok := parse_uint_max(arg(w, 1), 0x7FFFFFFF)
		if !ok {
			return bad(po, name, raw)
		}
		po.route_delay = int(v)
	case "route-method", "block-outside-dns", "tun-ipv6", "ping-timer-rem":
		return not_applicable(po, name, raw)
	case "redirect-gateway":
		return apply_redirect(po, w, name, raw, &po.redirect_gateway)
	case "redirect-private":
		return apply_redirect(po, w, name, raw, &po.redirect_private)
	case "block-ipv6":
		po.block_ipv6 = true
	case "dhcp-option":
		return apply_dhcp_option(po, w, name, raw)
	case "dns":
		return apply_dns(po, w, name, raw)
	case "ping":
		return set_seconds(po, w, name, raw, &po.ping)
	case "ping-restart":
		return set_seconds(po, w, name, raw, &po.ping_restart)
	case "ping-exit":
		return set_seconds(po, w, name, raw, &po.ping_exit)
	case "keepalive":
		a, aok := parse_uint_max(arg(w, 1), 0x7FFFFFFF)
		b, bok := parse_uint_max(arg(w, 2), 0x7FFFFFFF)
		if n != 3 || !aok || !bok {
			return bad(po, name, raw)
		}
		po.ping = int(a)
		po.ping_restart = int(b)
	case "inactive":
		if n < 2 || n > 3 {
			return bad(po, name, raw)
		}
		secs, sok := parse_uint_max(arg(w, 1), 0x7FFFFFFF)
		bytes: u64
		bok := true
		if n == 3 {
			bytes, bok = parse_uint_max(arg(w, 2), 0x7FFFFFFF)
		}
		if !sok || !bok {
			return bad(po, name, raw)
		}
		po.inactive = Inactive{int(secs), int(bytes)}
	case "session-timeout":
		return set_seconds(po, w, name, raw, &po.session_timeout)
	case "explicit-exit-notify":
		// SPEC-GAP: the number is optional (`[<n>]`) but the spec does not say
		// what the bare form means. It is stored as 0, "no number", and the
		// session layer picks its own default.
		if n == 1 {
			po.explicit_exit_notify = 0
		} else {
			return set_seconds(po, w, name, raw, &po.explicit_exit_notify)
		}
	case "persist-tun":
		po.persist_tun = true
	case "persist-key":
		po.persist_key = true
	case "tun-mtu":
		// `tun-mtu <n> [<occ-mtu>]`; the stock range is 100 to 65536.
		if n < 2 || n > 3 {
			return bad(po, name, raw)
		}
		v, ok := parse_uint_max(arg(w, 1), 65536)
		if !ok || v < 100 {
			return bad(po, name, raw)
		}
		po.tun_mtu = int(v)
	case "sndbuf":
		return set_seconds(po, w, name, raw, &po.sndbuf)
	case "rcvbuf":
		return set_seconds(po, w, name, raw, &po.rcvbuf)
	case "socket-flags":
		for k in 1 ..< n {
			if arg(w, k) == "TCP_NODELAY" {
				po.tcp_nodelay = true
			} else if err := add_note(po, name, raw, .Ignore, .Unsupported_Value); err != .None {
				return err
			}
		}
	case "shaper", "verb", "mute", "echo", "parameter", "setenv-safe", "custom-control":
		return not_applicable(po, name, raw)
	case "push-continuation":
	// Handled by the assembler.
	case "cipher":
		if n != 2 {
			return bad(po, name, raw)
		}
		s, err := intern(po, arg(w, 1))
		if err != .None {
			return err
		}
		po.cipher = s
	case "peer-id":
		v, ok := parse_uint_max(arg(w, 1), 0xFFFFFE)
		if n != 2 || !ok {
			return bad(po, name, raw)
		}
		po.peer_id = u32(v)
	case "key-derivation":
		if n != 2 || arg(w, 1) != "tls-ekm" {
			return bad(po, name, raw)
		}
		po.key_derivation_ekm = true
	case "protocol-flags":
		if n < 2 {
			return bad(po, name, raw)
		}
		for k in 1 ..< n {
			if f, ok := protocol_flag_from_name(arg(w, k)); ok {
				po.protocol_flags += {f}
			} else if err := add_note(po, name, raw, .Ignore, .Unsupported_Value); err != .None {
				return err
			}
		}
	case "auth-token":
		if n != 2 {
			return bad(po, name, "auth-token")
		}
		s, err := intern(po, arg(w, 1))
		if err != .None {
			return err
		}
		po.auth_token = s
	case "auth-token-user":
		if n != 2 {
			return bad(po, name, "auth-token-user")
		}
		s, err := intern(po, arg(w, 1))
		if err != .None {
			return err
		}
		po.auth_token_user = s
	case "comp-lzo":
		if n == 2 && arg(w, 1) == "no" {
			return .None
		}
		return add_note(po, name, raw, .Reject, .Compression)
	case "compress":
		if n == 1 {
			return .None
		}
		return add_note(po, name, raw, .Reject, .Compression)
	case:
		return add_note(po, name, raw, .Ignore, .Unknown_Option)
	}
	return .None
}

// `<addr>/<bits>`.
@(private)
parse_ipv6_prefix :: proc "contextless" (s: string) -> (a: [16]u8, bits: int, ok: bool) {
	for c, i in transmute([]u8)s {
		if c == '/' {
			addr, aok := parse_ipv6(s[:i])
			b, bok := parse_uint_max(s[i + 1:], 128)
			return addr, int(b), aok && bok
		}
	}
	return {}, 0, false
}

@(private)
parse_route_gw :: proc "contextless" (s: string) -> (gw: Route_Gw, ok: bool) {
	switch s {
	case "vpn_gateway":
		return Route_Gw{kind = .Vpn_Gateway}, true
	case "net_gateway":
		return Route_Gw{kind = .Net_Gateway}, true
	case "remote_host":
		return Route_Gw{kind = .Remote_Host}, true
	}
	a, aok := parse_ipv4(s)
	return Route_Gw{kind = .Addr, addr = a}, aok
}

@(private)
parse_route_gw6 :: proc "contextless" (s: string) -> (gw: Route_Gw6, ok: bool) {
	switch s {
	case "vpn_gateway":
		return Route_Gw6{kind = .Vpn_Gateway}, true
	case "net_gateway":
		return Route_Gw6{kind = .Net_Gateway}, true
	case "remote_host":
		return Route_Gw6{kind = .Remote_Host}, true
	}
	a, aok := parse_ipv6(s)
	return Route_Gw6{kind = .Addr, addr = a}, aok
}

@(private)
parse_metric :: proc "contextless" (s: string) -> (m: Maybe(int), ok: bool) {
	if s == "default" {
		return nil, true
	}
	v, vok := parse_uint_max(s, 0x7FFFFFFF)
	return int(v), vok
}

// SPEC-GAP: the spec lists `<net>` only as an address. A host name, `default`,
// or the gateway keywords in the network position are not supported and are
// noted as malformed.
@(private)
apply_route :: proc(po: ^Pushed_Options, w: ^Words, name, raw: string) -> Error {
	n := w.count
	if n < 2 || n > 5 {
		return bad(po, name, raw)
	}
	r: Route
	ok: bool
	r.net, ok = parse_ipv4(words_get(w, 1))
	if !ok {
		return bad(po, name, raw)
	}
	r.mask = {255, 255, 255, 255}
	if n >= 3 {
		r.mask, ok = parse_ipv4(words_get(w, 2))
		if !ok || !netmask_is_contiguous(r.mask) {
			return bad(po, name, raw)
		}
	}
	if n >= 4 {
		r.gateway, ok = parse_route_gw(words_get(w, 3))
		if !ok {
			return bad(po, name, raw)
		}
	}
	if n == 5 {
		r.metric, ok = parse_metric(words_get(w, 4))
		if !ok {
			return bad(po, name, raw)
		}
	}
	if _, err := append(&po.routes, r); err != nil {
		return .Out_Of_Memory
	}
	return .None
}

@(private)
apply_route6 :: proc(po: ^Pushed_Options, w: ^Words, name, raw: string) -> Error {
	n := w.count
	if n < 2 || n > 4 {
		return bad(po, name, raw)
	}
	r: Route6
	net, bits, ok := parse_ipv6_prefix(words_get(w, 1))
	if !ok {
		return bad(po, name, raw)
	}
	r.net, r.bits = net, u8(bits)
	if n >= 3 {
		r.gateway, ok = parse_route_gw6(words_get(w, 2))
		if !ok {
			return bad(po, name, raw)
		}
	}
	if n == 4 {
		r.metric, ok = parse_metric(words_get(w, 3))
		if !ok {
			return bad(po, name, raw)
		}
	}
	if _, err := append(&po.routes6, r); err != nil {
		return .Out_Of_Memory
	}
	return .None
}

// Flags are ORed in: a second `redirect-gateway` adds to the first. An unknown
// flag is noted and the known ones still count (a stock client skips the whole
// option; for a VPN, silently dropping the redirect is worse).
//
// SPEC-GAP: the spec says a malformed option is skipped. Keeping flags is our
// choice for this option only.
@(private)
apply_redirect :: proc(po: ^Pushed_Options, w: ^Words, name, raw: string, dst: ^Redirect) -> Error {
	dst.set = true
	for k in 1 ..< w.count {
		switch words_get(w, k) {
		case "local":
			dst.flags += {.Local}
		case "autolocal":
			dst.flags += {.Autolocal}
		case "def1":
			dst.flags += {.Def1}
		case "block-local":
			dst.flags += {.Block_Local}
		case "ipv6":
			dst.flags += {.Ipv6}
		case "!ipv4":
			dst.flags += {.Not_Ipv4}
		case "bypass-dhcp":
			dst.flags += {.Bypass_Dhcp}
			if err := not_applicable(po, name, raw); err != .None {
				return err
			}
		case "bypass-dns":
			dst.flags += {.Bypass_Dns}
			if err := not_applicable(po, name, raw); err != .None {
				return err
			}
		case:
			if err := add_note(po, name, raw, .Ignore, .Unsupported_Value); err != .None {
				return err
			}
		}
	}
	return .None
}

@(private)
apply_dhcp_option :: proc(po: ^Pushed_Options, w: ^Words, name, raw: string) -> Error {
	if w.count < 2 {
		return bad(po, name, raw)
	}
	switch words_get(w, 1) {
	case "DOMAIN", "ADAPTER_DOMAIN_SUFFIX", "DOMAIN-SEARCH":
		if w.count != 3 || len(words_get(w, 2)) == 0 {
			return bad(po, name, raw)
		}
		s, err := intern(po, words_get(w, 2))
		if err != .None {
			return err
		}
		if _, aerr := append(&po.dhcp_domains, s); aerr != nil {
			return .Out_Of_Memory
		}
	case "DNS":
		a, ok := parse_ipv4(words_get(w, 2))
		if w.count != 3 || !ok {
			return bad(po, name, raw)
		}
		ip := Ip_Addr{}
		copy(ip.bytes[:4], a[:])
		if _, aerr := append(&po.dhcp_dns, ip); aerr != nil {
			return .Out_Of_Memory
		}
	case "DNS6":
		a, ok := parse_ipv6(words_get(w, 2))
		if w.count != 3 || !ok {
			return bad(po, name, raw)
		}
		if _, aerr := append(&po.dhcp_dns, Ip_Addr{v6 = true, bytes = a}); aerr != nil {
			return .Out_Of_Memory
		}
	case "NBS", "NBT", "WINS", "NTP", "NBDD", "DISABLE-NBT", "PROXY_HTTP", "PROXY_HTTPS", "PROXY_AUTO_CONFIG_URL", "PROXY_BYPASS", "PROXY_OVERRIDE", "DHCP":
		return not_applicable(po, name, raw)
	case:
		return add_note(po, name, raw, .Ignore, .Unknown_Option)
	}
	return .None
}

// `ip`, `ip:port`, `[ipv6]:port`, or a bare IPv6 address. The client also
// reads the local `dns server N address` lines with it.
parse_dns_address :: proc "contextless" (s: string) -> (d: Dns_Address, ok: bool) {
	if len(s) == 0 {
		return {}, false
	}
	if s[0] == '[' {
		close := -1
		for c, i in transmute([]u8)s {
			if c == ']' {
				close = i
				break
			}
		}
		if close < 0 {
			return {}, false
		}
		a, aok := parse_ipv6(s[1:close])
		if !aok {
			return {}, false
		}
		d.ip = Ip_Addr{v6 = true, bytes = a}
		rest := s[close + 1:]
		if len(rest) == 0 {
			return d, true
		}
		if rest[0] != ':' {
			return {}, false
		}
		p, pok := parse_uint_max(rest[1:], 65535)
		if !pok || p == 0 {
			return {}, false
		}
		d.port = u16(p)
		return d, true
	}
	colons := 0
	last := 0
	for c, i in transmute([]u8)s {
		if c == ':' {
			colons += 1
			last = i
		}
	}
	switch colons {
	case 0:
		a, aok := parse_ipv4(s)
		copy(d.ip.bytes[:4], a[:])
		return d, aok
	case 1:
		a, aok := parse_ipv4(s[:last])
		p, pok := parse_uint_max(s[last + 1:], 65535)
		copy(d.ip.bytes[:4], a[:])
		d.port = u16(p)
		return d, aok && pok && p != 0
	}
	a, aok := parse_ipv6(s)
	return Dns_Address{ip = Ip_Addr{v6 = true, bytes = a}}, aok
}

@(private)
find_dns_group :: proc(po: ^Pushed_Options, prio: int) -> (g: ^Dns_Server, err: Error) {
	for &x in po.dns_servers {
		if x.prio == prio {
			return &x, .None
		}
	}
	if len(po.dns_servers) >= MAX_DNS_GROUPS {
		return nil, .Too_Many_Options
	}
	ng := Dns_Server {
		prio            = prio,
		addresses       = make([dynamic]Dns_Address, 0, 0, po.allocator),
		resolve_domains = make([dynamic]string, 0, 0, po.allocator),
	}
	if _, aerr := append(&po.dns_servers, ng); aerr != nil {
		delete(ng.addresses)
		delete(ng.resolve_domains)
		return nil, .Out_Of_Memory
	}
	return &po.dns_servers[len(po.dns_servers) - 1], .None
}

// The `dns` option, version 2.
@(private)
apply_dns :: proc(po: ^Pushed_Options, w: ^Words, name, raw: string) -> Error {
	n := w.count
	if n < 3 {
		return bad(po, name, raw)
	}
	switch words_get(w, 1) {
	case "search-domains":
		for k in 2 ..< n {
			s, err := intern(po, words_get(w, k))
			if err != .None {
				return err
			}
			if _, aerr := append(&po.dns_search_domains, s); aerr != nil {
				return .Out_Of_Memory
			}
		}
		return .None
	case "server":
		// `server <prio> <keyword> <args...>`
		if n < 5 {
			return bad(po, name, raw)
		}
		prio, pok := parse_uint_max(words_get(w, 2), 127)
		if !pok {
			return bad(po, name, raw)
		}
		keyword := words_get(w, 3)
		// Check the arguments before a group is created for them.
		switch keyword {
		case "address", "resolve-domains":
		case "dnssec", "transport", "sni":
			if n != 5 {
				return bad(po, name, raw)
			}
		case:
			return add_note(po, name, raw, .Ignore, .Unknown_Option)
		}
		g, gerr := find_dns_group(po, int(prio))
		if gerr == .Too_Many_Options {
			return add_note(po, name, raw, .Ignore, .Limit)
		}
		if gerr != .None {
			return gerr
		}
		switch keyword {
		case "address":
			for k in 4 ..< n {
				d, ok := parse_dns_address(words_get(w, k))
				if !ok {
					return bad(po, name, raw)
				}
				if len(g.addresses) >= MAX_DNS_ADDRESSES {
					return add_note(po, name, raw, .Ignore, .Limit)
				}
				if _, aerr := append(&g.addresses, d); aerr != nil {
					return .Out_Of_Memory
				}
			}
		case "resolve-domains":
			for k in 4 ..< n {
				s, err := intern(po, words_get(w, k))
				if err != .None {
					return err
				}
				if _, aerr := append(&g.resolve_domains, s); aerr != nil {
					return .Out_Of_Memory
				}
			}
		case "dnssec":
			switch words_get(w, 4) {
			case "yes":
				g.dnssec = .Yes
			case "no":
				g.dnssec = .No
			case "optional":
				g.dnssec = .Optional
			case:
				return bad(po, name, raw)
			}
		case "transport":
			switch words_get(w, 4) {
			case "plain":
				g.transport = .Plain
			case "DoH":
				g.transport = .Doh
			case "DoT":
				g.transport = .Dot
			case:
				return bad(po, name, raw)
			}
		case "sni":
			s, err := intern(po, words_get(w, 4))
			if err != .None {
				return err
			}
			g.sni = s
		}
		return .None
	}
	return add_note(po, name, raw, .Ignore, .Unknown_Option)
}

// Sorts the dns groups by priority and drops groups with no address (a
// server entry needs at least one). Called when a reply is complete.
pushed_options_finish :: proc(po: ^Pushed_Options) -> Error {
	i := 0
	for i < len(po.dns_servers) {
		if len(po.dns_servers[i].addresses) == 0 {
			g := po.dns_servers[i]
			delete(g.addresses)
			delete(g.resolve_domains)
			ordered_remove(&po.dns_servers, i)
			if err := add_note(po, "dns", "dns server without address", .Ignore, .Malformed); err != .None {
				return err
			}
			continue
		}
		i += 1
	}
	slice.sort_by(po.dns_servers[:], proc(a, b: Dns_Server) -> bool {
		return a.prio < b.prio
	})
	return .None
}

// Parses a whole option list in one call (no continuation handling). For
// callers and tests that have the full text.
pushed_options_parse :: proc(po: ^Pushed_Options, options: string, allocator := context.allocator) -> Error {
	pushed_options_init(po, allocator)
	if err := pushed_options_add(po, options); err != .None {
		return err
	}
	return pushed_options_finish(po)
}

// ------------------------------------------------------------ continuation

Push_Status :: enum u8 {
	// More parts are coming (`push-continuation 2`).
	More,
	// The reply is whole (`push-continuation 1`, or a message without one).
	Complete,
}

// Collects the parts of one PUSH_REPLY. The client must not start the data
// channel before `.Complete`.
Push_Assembler :: struct {
	po:       Pushed_Options,
	parts:    int,
	bytes:    int,
	complete: bool,
}

push_assembler_init :: proc(a: ^Push_Assembler, allocator := context.allocator) {
	a^ = {}
	pushed_options_init(&a.po, allocator)
}

push_assembler_destroy :: proc(a: ^Push_Assembler) {
	pushed_options_destroy(&a.po)
	a^ = {}
}

// Forgets the reply (free `po` first if it is still needed: this destroys it)
// and gets ready for the next one.
push_assembler_reset :: proc(a: ^Push_Assembler) {
	alloc := a.po.allocator
	pushed_options_destroy(&a.po)
	push_assembler_init(a, alloc)
}

// Finds `push-continuation N` in the options of one message. 0 if absent.
@(private)
find_continuation :: proc(options: string) -> (value: int, err: Error) {
	rest := options
	found := false
	for len(rest) > 0 {
		item, _ := next_item(&rest, ',')
		// A cheap test first: only items that start with the name need a split.
		trimmed := item
		for len(trimmed) > 0 && trimmed[0] == ' ' {
			trimmed = trimmed[1:]
		}
		name :: "push-continuation"
		if len(trimmed) < len(name) || trimmed[:len(name)] != name {
			continue
		}
		w: Words
		if tokenize_option(item, &w) != .None || words_get(&w, 0) != name {
			continue
		}
		if found || w.count != 2 {
			return 0, .Bad_Continuation
		}
		switch words_get(&w, 1) {
		case "1":
			value = 1
		case "2":
			value = 2
		case:
			return 0, .Bad_Continuation
		}
		found = true
	}
	return value, .None
}

// Adds one PUSH_REPLY message (`Push_Reply_Msg.options`, the text after
// `PUSH_REPLY,`). Returns `.Complete` when the reply is whole, and finishes the
// dns groups. Then call `push_assembler_reset` before the next reply; feeding
// again without it gives `.Bad_Continuation`.
//
// Errors:
// - `.Bad_Continuation`: value other than 1 or 2, two continuation options in one
//   message, or a message after `.Complete`
// - `.Too_Many_Options`: more than 64 parts, 64 KiB, or 2048 options
// - `.Out_Of_Memory`
push_assembler_feed :: proc(a: ^Push_Assembler, options: string) -> (st: Push_Status, err: Error) {
	if a.complete {
		return .Complete, .Bad_Continuation
	}
	a.parts += 1
	a.bytes += len(options)
	if a.parts > MAX_PUSH_PARTS || a.bytes > MAX_PUSH_REPLY_BYTES {
		return .More, .Too_Many_Options
	}
	cont: int
	cont, err = find_continuation(options)
	if err != .None {
		return .More, err
	}
	if err = pushed_options_add(&a.po, options); err != .None {
		return .More, err
	}
	if cont == 2 {
		return .More, .None
	}
	a.complete = true
	if err = pushed_options_finish(&a.po); err != .None {
		return .Complete, err
	}
	return .Complete, .None
}

// ------------------------------------------------------------ PUSH_UPDATE

// Options a PUSH_UPDATE may change.
@(private)
UPDATABLE :: [?]string {
	"block-ipv6",
	"block-outside-dns",
	"dhcp-option",
	"dns",
	"ifconfig",
	"ifconfig-ipv6",
	"push-continuation",
	"redirect-gateway",
	"redirect-private",
	"route",
	"route-gateway",
	"route-ipv6",
	"route-metric",
	"topology",
	"tun-mtu",
	"keepalive",
}

// One item of a PUSH_UPDATE: an option with its prefix.
Update_Item :: struct {
	// `-` prefix: remove this option type.
	remove:   bool,
	// `?` prefix: skip it if it cannot be applied.
	optional: bool,
	// False for `?-` (invalid) or an option not in the update list. The
	// client must not apply it.
	allowed:  bool,
	name:     string,
	// The option without its prefix characters, ready for
	// `pushed_options_add_option`.
	text:     string,
}

// Splits the text after `PUSH_UPDATE,` into items and finds the continuation
// value (0 if none). Items alias `options`. The continuation item itself is
// not listed. Over 256 items gives `.Too_Many_Options`.
push_update_parse :: proc(options: string, items: ^[dynamic]Update_Item) -> (continuation: int, err: Error) {
	clear(items)
	continuation, err = find_continuation(options)
	if err != .None {
		return 0, err
	}
	rest := options
	for len(rest) > 0 {
		item, _ := next_item(&rest, ',')
		for len(item) > 0 && item[0] == ' ' {
			item = item[1:]
		}
		if len(item) == 0 {
			continue
		}
		it := Update_Item{allowed = true}
		text := item
		switch {
		case len(text) >= 2 && text[0] == '-' && text[1] == '?':
			it.remove, it.optional = true, true
			text = text[2:]
		case len(text) >= 2 && text[0] == '?' && text[1] == '-':
			it.allowed = false // `?-` is invalid
			text = text[2:]
		case text[0] == '-':
			it.remove = true
			text = text[1:]
		case text[0] == '?':
			it.optional = true
			text = text[1:]
		}
		it.text = text
		name := text
		for c, i in transmute([]u8)text {
			if c == ' ' {
				name = text[:i]
				break
			}
		}
		it.name = name
		listed := false
		for u in UPDATABLE {
			if u == name {
				listed = true
				break
			}
		}
		if !listed {
			it.allowed = false
		}
		if name == "push-continuation" {
			continue
		}
		if len(items) >= 256 {
			return 0, .Too_Many_Options
		}
		if _, aerr := append(items, it); aerr != nil {
			return 0, .Out_Of_Memory
		}
	}
	return continuation, .None
}

// ------------------------------------------------------------ validation

// What the client knows, for the checks that need more than the reply.
Validate_Params :: struct {
	// The client's data-ciphers list.
	own_ciphers:           []Cipher,
	// The cipher item of the server's options string, for the case where no
	// `cipher` is pushed.
	server_options_cipher: string,
	// The `IV_MTU` the client sent; 0 if it sent none.
	iv_mtu:                int,
	// A peer id from the peer-info exchange (`ID=`) is in force.
	have_peer_id:          bool,
}

Validate_Failure :: enum u8 {
	None,
	// A note with disposition `.Reject` (net30, p2p, compression).
	Rejected_Option,
	// No `topology` was pushed: the client would assume net30.
	Missing_Topology,
	// Neither `key-derivation tls-ekm` nor `protocol-flags tls-ekm`.
	No_Key_Derivation,
	// The pushed cipher is not in the client's list.
	Cipher_Not_Allowed,
	// No cipher was pushed and the server's options cipher is not usable.
	No_Usable_Cipher,
	// `aead-epoch` without a peer id in force.
	Epoch_Needs_Peer_Id,
	// `aead-epoch` without a negotiated AEAD cipher.
	Epoch_Needs_Aead,
	// `tun-mtu` above what the client announced (or announced nothing).
	Mtu_Too_Large,
}

Validate_Result :: struct {
	failure: Validate_Failure,
	// The option that caused the failure.
	option:  string,
	// The negotiated cipher, when `failure` is `.None`.
	cipher:  Cipher,
}

// The checks that decide whether the
// connection goes on. Run it when the reply is complete, before applying
// anything. A reply that only renews the auth-token (`pushed_options_token_only`)
// is not validated.
//
// SPEC-GAP: a reply without `ifconfig` is no failure here; the session layer
// decides.
pushed_options_validate :: proc(po: ^Pushed_Options, p: ^Validate_Params) -> (r: Validate_Result) {
	if n, ok := pushed_options_first_reject(po); ok {
		r.failure, r.option = .Rejected_Option, n.name
		return
	}
	if po.topology == .Unset {
		r.failure, r.option = .Missing_Topology, "topology"
		return
	}
	if !po.key_derivation_ekm && .Tls_Ekm not_in po.protocol_flags {
		r.failure, r.option = .No_Key_Derivation, "key-derivation"
		return
	}
	cipher, cerr := ncp_client_check(po.cipher, p.server_options_cipher, p.own_ciphers)
	switch cerr {
	case .None:
	case .Cipher_Not_Allowed:
		r.failure, r.option = .Cipher_Not_Allowed, "cipher"
		return
	case .No_Usable_Cipher:
		r.failure, r.option = .No_Usable_Cipher, "cipher"
		return
	}
	if .Aead_Epoch in po.protocol_flags {
		if po.peer_id == nil && !p.have_peer_id {
			r.failure, r.option = .Epoch_Needs_Peer_Id, "protocol-flags"
			return
		}
		if cipher == .None {
			r.failure, r.option = .Epoch_Needs_Aead, "protocol-flags"
			return
		}
	}
	if mtu, ok := po.tun_mtu.?; ok && (p.iv_mtu == 0 || mtu > p.iv_mtu) {
		r.failure, r.option = .Mtu_Too_Large, "tun-mtu"
		return
	}
	r.cipher = cipher
	return
}
