// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:strings"
import "core:testing"

build_one :: proc(t: ^testing.T, p: ^Push_Reply_Params, loc := #caller_location) -> string {
	msgs, err := push_reply_build(p, context.temp_allocator)
	testing.expect_value(t, err, Error.None, loc = loc)
	testing.expect_value(t, len(msgs), 1, loc = loc)
	if len(msgs) != 1 {
		return ""
	}
	return msgs[0]
}

@(test)
reply_build_minimal_and_empty :: proc(t: ^testing.T) {
	p: Push_Reply_Params
	testing.expect_value(t, build_one(t, &p), "PUSH_REPLY")
	p.topology = .Subnet
	p.ifconfig = Ifconfig{{10, 8, 0, 2}, {255, 255, 255, 0}}
	testing.expect_value(t, build_one(t, &p), "PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0")
}

@(test)
reply_build_full_order :: proc(t: ^testing.T) {
	routes := []Route {
		{net = {10, 1, 0, 0}, mask = {255, 255, 0, 0}},
		{net = {192, 168, 5, 0}, mask = {255, 255, 255, 0}, gateway = {kind = .Vpn_Gateway}},
		{net = {10, 4, 0, 0}, mask = {255, 255, 255, 0}, gateway = {kind = .Addr, addr = {10, 8, 0, 1}}, metric = 7},
		{net = {10, 5, 0, 0}, mask = {255, 255, 255, 0}, metric = 9},
		{net = {10, 6, 0, 0}, mask = {255, 255, 255, 255}, gateway = {kind = .Net_Gateway}},
	}
	fd01, _ := parse_ipv6("fd01::")
	fd00_1, _ := parse_ipv6("fd00::1")
	routes6 := []Route6 {
		{net = {0 = 0xfd, 1 = 0, 3 = 1}, bits = 64},
		{net = fd01, bits = 48, gateway = {kind = .Addr, addr = fd00_1}, metric = 3},
	}
	dns_v6, _ := parse_ipv6("fd00::53")
	dhcp_dns := []Ip_Addr{{bytes = {0 = 10, 1 = 8, 2 = 0, 3 = 53}}, {v6 = true, bytes = dns_v6}}
	dhcp_domains := []string{"corp.example", "two words.example"}
	search := []string{"a.example", "b.example"}
	addrs := []Dns_Address{{ip = {bytes = {0 = 9, 1 = 9, 2 = 9, 3 = 9}}}, {ip = {v6 = true, bytes = dns_v6}, port = 5353}, {ip = {bytes = {0 = 192, 1 = 0, 2 = 2, 3 = 1}}, port = 853}}
	resolve := []string{"corp.example"}
	groups := []Dns_Group_Spec{{prio = 1, addresses = addrs, resolve_domains = resolve, dnssec = .Optional, transport = .Dot, sni = "dns.quad9.net"}}
	gw6, _ := parse_ipv6("fd00:8::1")
	a6, _ := parse_ipv6("fd00:8::1000")
	extra := []string{"sndbuf 65536", "explicit-exit-notify 1"}
	p := Push_Reply_Params {
		routes             = routes,
		routes6            = routes6,
		dhcp_dns           = dhcp_dns,
		dhcp_domains       = dhcp_domains,
		dns_search_domains = search,
		dns_servers        = groups,
		redirect_gateway   = {set = true, flags = {.Def1, .Ipv6}},
		redirect_private   = {set = true},
		block_ipv6         = true,
		extra              = extra,
		route_gateway      = [4]u8{10, 8, 0, 1},
		route_ipv6_gateway = gw6,
		topology           = .Subnet,
		ping               = 10,
		ping_restart       = 60,
		ifconfig6          = Ifconfig6{addr = a6, bits = 112, gateway = gw6},
		ifconfig           = Ifconfig{{10, 8, 0, 2}, {255, 255, 255, 0}},
		peer_id            = u32(5),
		auth_token         = "TOK+/=",
		auth_token_user    = "YWxpY2U=",
		cipher             = .Chacha20_Poly1305,
		protocol_flags     = {.Tls_Ekm, .Aead_Epoch},
		tun_mtu            = 1400,
	}
	want := strings.join(
		{
			"PUSH_REPLY",
			"route 10.1.0.0 255.255.0.0",
			"route 192.168.5.0 255.255.255.0 vpn_gateway",
			"route 10.4.0.0 255.255.255.0 10.8.0.1 7",
			"route 10.5.0.0 255.255.255.0 vpn_gateway 9",
			"route 10.6.0.0 255.255.255.255 net_gateway",
			"route-ipv6 fd00:1::/64",
			"route-ipv6 fd01::/48 fd00::1 3",
			"dhcp-option DNS 10.8.0.53",
			"dhcp-option DNS6 fd00::53",
			"dhcp-option DOMAIN corp.example",
			`dhcp-option DOMAIN "two words.example"`,
			"dns search-domains a.example b.example",
			"dns server 1 address 9.9.9.9 [fd00::53]:5353 192.0.2.1:853",
			"dns server 1 resolve-domains corp.example",
			"dns server 1 dnssec optional",
			"dns server 1 transport DoT",
			"dns server 1 sni dns.quad9.net",
			"redirect-gateway def1 ipv6",
			"redirect-private",
			"block-ipv6",
			"sndbuf 65536",
			"explicit-exit-notify 1",
			"route-gateway 10.8.0.1",
			"route-ipv6-gateway fd00:8::1",
			"topology subnet",
			"ping 10",
			"ping-restart 60",
			"ifconfig-ipv6 fd00:8::1000/112 fd00:8::1",
			"ifconfig 10.8.0.2 255.255.255.0",
			"peer-id 5",
			"auth-token TOK+/=",
			"auth-token-user YWxpY2U=",
			"cipher CHACHA20-POLY1305",
			"protocol-flags tls-ekm aead-epoch",
			"tun-mtu 1400",
		},
		",",
		context.temp_allocator,
	)
	got := build_one(t, &p)
	testing.expect_value(t, got, want)

	// And the client's parser reads every typed option back.
	po: Pushed_Options
	defer pushed_options_destroy(&po)
	err := pushed_options_parse(&po, got[len("PUSH_REPLY,"):])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(po.notes), 0)
	testing.expect_value(t, len(po.routes), 5)
	testing.expect_value(t, po.routes[2].gateway.addr, [4]u8{10, 8, 0, 1})
	testing.expect_value(t, po.routes[2].metric, 7)
	testing.expect_value(t, po.routes[3].metric, 9)
	testing.expect_value(t, len(po.routes6), 2)
	testing.expect_value(t, po.routes6[1].bits, 48)
	testing.expect_value(t, len(po.dhcp_dns), 2)
	testing.expect_value(t, po.dhcp_domains[1], "two words.example")
	testing.expect_value(t, len(po.dns_servers), 1)
	testing.expect_value(t, len(po.dns_servers[0].addresses), 3)
	testing.expect_value(t, po.dns_servers[0].sni, "dns.quad9.net")
	testing.expect(t, po.redirect_gateway.set && po.redirect_private.set && po.block_ipv6)
	testing.expect_value(t, po.redirect_gateway.flags, Redirect_Flags{.Def1, .Ipv6})
	testing.expect_value(t, po.peer_id, 5)
	testing.expect_value(t, po.auth_token, "TOK+/=")
	testing.expect_value(t, po.cipher, "CHACHA20-POLY1305")
	testing.expect_value(t, po.protocol_flags, Protocol_Flags{.Tls_Ekm, .Aead_Epoch})
	testing.expect_value(t, po.tun_mtu, 1400)
	testing.expect_value(t, po.explicit_exit_notify, 1)
	testing.expect_value(t, po.sndbuf, 65536)
}

@(test)
reply_build_legacy_key_derivation :: proc(t: ^testing.T) {
	p := Push_Reply_Params {
		topology              = .Subnet,
		cipher                = .Aes_256_Gcm,
		protocol_flags        = {.Tls_Ekm, .Cc_Exit},
		legacy_key_derivation = true,
	}
	// A client without IV_PROTO bit 7 does not read protocol-flags.
	testing.expect_value(t, build_one(t, &p), "PUSH_REPLY,topology subnet,cipher AES-256-GCM,key-derivation tls-ekm")
}

@(test)
reply_build_rejects_bad_values :: proc(t: ^testing.T) {
	check :: proc(t: ^testing.T, p: ^Push_Reply_Params, want: Error, what: string, loc := #caller_location) {
		msgs, err := push_reply_build(p, context.temp_allocator)
		testing.expectf(t, err == want, "%s: got %v, want %v", what, err, want, loc = loc)
		testing.expectf(t, len(msgs) == 0, "%s: messages returned with an error", what, loc = loc)
	}
	p := Push_Reply_Params{}
	p.dhcp_domains = {"a,b"}
	check(t, &p, .Bad_Argument, "comma in a domain")
	p = {}
	p.dhcp_domains = {"a\nb"}
	check(t, &p, .Bad_Argument, "control byte in a domain")
	p = {}
	p.peer_id = u32(0xFFFFFF)
	check(t, &p, .Bad_Argument, "peer-id 0xFFFFFF")
	p = {}
	p.dhcp_domains = {""}
	check(t, &p, .Bad_Argument, "empty domain")
	p = {}
	p.dns_search_domains = {"ok.example", ""}
	check(t, &p, .Bad_Argument, "empty search domain")
	p = {}
	p.dns_servers = {{prio = 1, addresses = {{}}, resolve_domains = {""}}}
	check(t, &p, .Bad_Argument, "empty resolve domain")
	p = {}
	p.extra = {"a,b"}
	check(t, &p, .Bad_Argument, "comma in extra")
	p = {}
	p.extra = {""}
	check(t, &p, .Bad_Argument, "empty extra")
	p = {}
	p.extra = {"x\x01"}
	check(t, &p, .Bad_Argument, "control byte in extra")
	p = {}
	p.auth_token = "a,b"
	check(t, &p, .Bad_Argument, "comma in token")
	p = {}
	p.dns_servers = {{prio = 128, addresses = {{}}}}
	check(t, &p, .Bad_Argument, "dns prio 128")
	p = {}
	p.dns_servers = {{prio = 1}}
	check(t, &p, .Bad_Argument, "dns group without address")
	p = {}
	p.dns_servers = {{prio = 1, addresses = {{}}, sni = "a,b"}}
	check(t, &p, .Bad_Argument, "comma in sni")
	long := make([]u8, 1100, context.temp_allocator)
	for &c in long {
		c = 'a'
	}
	p = {}
	p.extra = {string(long)}
	check(t, &p, .Oversize, "one option over 1024 bytes")
	p = {}
	p.auth_token = string(long)
	check(t, &p, .Oversize, "token over 1024 bytes")
	p = {}
	p.dhcp_domains = {string(long)}
	check(t, &p, .Oversize, "domain over 1024 bytes")
}

@(test)
reply_build_quotes_words :: proc(t: ^testing.T) {
	p := Push_Reply_Params {
		dhcp_domains       = {"plain.example", `has"quote`, `back\slash`, ";semi", "#hash", "it's"},
		dns_search_domains = {"two words"},
	}
	msg := build_one(t, &p)
	po: Pushed_Options
	defer pushed_options_destroy(&po)
	testing.expect_value(t, pushed_options_parse(&po, msg[len("PUSH_REPLY,"):]), Error.None)
	testing.expect_value(t, len(po.notes), 0)
	testing.expect_value(t, len(po.dhcp_domains), 6)
	want := []string{"plain.example", `has"quote`, `back\slash`, ";semi", "#hash", "it's"}
	for w, i in want {
		testing.expectf(t, i < len(po.dhcp_domains) && po.dhcp_domains[i] == w, "domain %d: %q", i, po.dhcp_domains[i] if i < len(po.dhcp_domains) else "")
	}
	testing.expect_value(t, po.dns_search_domains[0], "two words")
}

// --------------------------------------------------------------- packing

filler :: proc(n: int, c: u8 = 'a') -> string {
	b := make([]u8, n, context.temp_allocator)
	for &x in b {
		x = c
	}
	return string(b)
}

@(test)
pack_single_message_limits :: proc(t: ^testing.T) {
	// 11 bytes ("PUSH_REPLY" and NUL) plus 1 + len per option.
	// head option of 927: text 939 with NUL: one message.
	msgs, err := push_reply_pack({filler(927)}, nil, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msgs), 1)
	testing.expect_value(t, len(msgs[0]) + 1, 939)
	testing.expect(t, !strings.contains(msgs[0], "push-continuation"))

	// 940 or more of configured options: more than one message.
	msgs, err = push_reply_pack({filler(928)}, nil, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msgs), 1)
	testing.expect(t, strings.has_suffix(msgs[0], ",push-continuation 1"))

	// Tail options may use the room up to 1024: head 939, tail fills to 1024.
	msgs, err = push_reply_pack({filler(927)}, {filler(84)}, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msgs), 1)
	testing.expect_value(t, len(msgs[0]) + 1, 1024)
	// One byte more: the tail option goes into its own message.
	msgs, err = push_reply_pack({filler(927)}, {filler(85)}, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msgs), 2)
	testing.expect(t, strings.has_suffix(msgs[0], ",push-continuation 2"))
	testing.expect(t, strings.has_suffix(msgs[1], ",push-continuation 1"))
	testing.expect(t, strings.has_prefix(msgs[1], "PUSH_REPLY,aaaa"))
	for m in msgs {
		testing.expect(t, len(m) + 1 <= PUSH_MESSAGE_MAX)
	}

	// Nothing at all.
	msgs, err = push_reply_pack(nil, nil, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msgs), 1)
	testing.expect_value(t, msgs[0], "PUSH_REPLY")

	// A configured option that cannot fit with its continuation, even alone:
	// 1024 - 11 - 1 - 20 = 992 is the largest.
	_, err = push_reply_pack({filler(993)}, nil, context.temp_allocator)
	testing.expect_value(t, err, Error.Oversize)
	msgs, err = push_reply_pack({filler(992)}, nil, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msgs), 1)
	testing.expect_value(t, len(msgs[0]) + 1, 1024)
	// A tail option may fill a whole single message (1012 bytes), but when it
	// has to be split it needs room for the continuation too.
	msgs, err = push_reply_pack(nil, {filler(1000)}, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msgs), 1)
	testing.expect_value(t, len(msgs[0]) + 1, 1012)
	_, err = push_reply_pack(nil, {filler(1013)}, context.temp_allocator)
	testing.expect_value(t, err, Error.Oversize)
}

@(test)
pack_random_option_lists :: proc(t: ^testing.T) {
	// For many random lists: every message is at most 1024 bytes, every part
	// but the last says `push-continuation 2` and the last `1`, a single
	// message has none, and the options come back in order.
	rng := Rng {
		s = 0x1234_5678_9abc_def1,
	}
	for round in 0 ..< 400 {
		head := make([dynamic]string, context.temp_allocator)
		tail := make([dynamic]string, context.temp_allocator)
		for _ in 0 ..< rng_below(&rng, 60) {
			append(&head, filler(1 + rng_below(&rng, 120), u8('a' + rng_below(&rng, 26))))
		}
		for _ in 0 ..< rng_below(&rng, 12) {
			append(&tail, filler(1 + rng_below(&rng, 150), u8('A' + rng_below(&rng, 26))))
		}
		msgs, err := push_reply_pack(head[:], tail[:], context.temp_allocator)
		testing.expectf(t, err == .None, "round %d: %v", round, err)
		if err != .None {
			continue
		}
		all := make([dynamic]string, context.temp_allocator)
		for m, i in msgs {
			testing.expectf(t, len(m) + 1 <= PUSH_MESSAGE_MAX, "round %d: message %d is %d bytes", round, i, len(m) + 1)
			testing.expect(t, strings.has_prefix(m, "PUSH_REPLY"))
			text := m[len("PUSH_REPLY"):]
			last := i == len(msgs) - 1
			cont := ""
			switch {
			case strings.has_suffix(text, ",push-continuation 2"):
				cont = ",push-continuation 2"
				testing.expectf(t, !last, "round %d: last message says 2", round)
			case strings.has_suffix(text, ",push-continuation 1"):
				cont = ",push-continuation 1"
				testing.expectf(t, last, "round %d: message %d says 1", round, i)
			case:
				testing.expectf(t, len(msgs) == 1, "round %d: message %d has no continuation", round, i)
			}
			text = text[:len(text) - len(cont)]
			if len(text) > 0 {
				testing.expect(t, text[0] == ',')
				parts, _ := strings.split(text[1:], ",", context.temp_allocator)
				append(&all, ..parts)
			}
			// Configured-only parts stay under 940 with their NUL, before the suffix.
			if len(tail) == 0 && len(msgs) > 1 && !last {
				testing.expectf(t, len(m) + 1 - len(cont) < PUSH_HEAD_LIMIT, "round %d: part %d is %d", round, i, len(m) + 1)
			}
		}
		want := make([dynamic]string, context.temp_allocator)
		append(&want, ..head[:])
		append(&want, ..tail[:])
		testing.expectf(t, len(all) == len(want), "round %d: %d options back, want %d", round, len(all), len(want))
		for i in 0 ..< min(len(all), len(want)) {
			if all[i] != want[i] {
				testing.expectf(t, false, "round %d: option %d differs", round, i)
				break
			}
		}
	}
}

@(test)
build_then_assemble_many_routes :: proc(t: ^testing.T) {
	// 300 routes need several parts; the assembler gets them back whole, and
	// every part is a valid command that the reader frames.
	routes := make([]Route, 300, context.temp_allocator)
	for &r, i in routes {
		r = Route {
			net  = {10, u8(i / 250), u8(i % 250), 0},
			mask = {255, 255, 255, 0},
		}
	}
	p := Push_Reply_Params {
		routes        = routes,
		route_gateway = [4]u8{10, 8, 0, 1},
		topology      = .Subnet,
		ping          = 5,
		ping_restart  = 30,
		ifconfig      = Ifconfig{{10, 8, 0, 2}, {255, 255, 255, 0}},
		peer_id       = u32(7),
		cipher        = .Aes_256_Gcm,
		protocol_flags = {.Tls_Ekm},
		tun_mtu       = 1500,
	}
	msgs, err := push_reply_build(&p)
	defer push_messages_destroy(msgs)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, len(msgs) >= 8)

	a: Push_Assembler
	push_assembler_init(&a)
	defer push_assembler_destroy(&a)
	st := Push_Status.More
	for m, i in msgs {
		frame: [MAX_COMMAND_LEN]u8
		n, ferr := cmd_frame(frame[:], m, PUSH_MESSAGE_MAX)
		testing.expect_value(t, ferr, Error.None)
		r: Cmd_Reader
		rest := frame[:n]
		text, rst := cmd_reader_next(&r, &rest)
		testing.expect_value(t, rst, Cmd_Status.Command)
		cmd, cerr := command_parse(text, .Client)
		testing.expect_value(t, cerr, Error.None)
		pr, ok := cmd.(Push_Reply_Msg)
		testing.expect(t, ok)
		var_err: Error
		st, var_err = push_assembler_feed(&a, pr.options)
		testing.expect_value(t, var_err, Error.None)
		testing.expect_value(t, st == .Complete, i == len(msgs) - 1)
	}
	testing.expect_value(t, st, Push_Status.Complete)
	testing.expect_value(t, len(a.po.routes), 300)
	testing.expect_value(t, a.po.routes[299].net, [4]u8{10, 1, 49, 0})
	testing.expect_value(t, a.po.topology, Topology.Subnet)
	testing.expect_value(t, a.po.peer_id, 7)
	testing.expect_value(t, a.po.tun_mtu, 1500)
	testing.expect_value(t, len(a.po.notes), 0)
}
