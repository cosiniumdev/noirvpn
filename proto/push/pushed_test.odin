// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

words_of :: proc(opt: string) -> (out: []string, err: Error) {
	w: Words
	err = tokenize_option(opt, &w)
	if err != .None {
		return nil, err
	}
	res := make([]string, w.count, context.temp_allocator)
	for i in 0 ..< w.count {
		s := words_get(&w, i)
		c := make([]u8, len(s), context.temp_allocator)
		copy(c, s)
		res[i] = string(c)
	}
	return res, .None
}

expect_words :: proc(t: ^testing.T, opt: string, want: []string, loc := #caller_location) {
	got, err := words_of(opt)
	testing.expect_value(t, err, Error.None, loc = loc)
	testing.expectf(t, len(got) == len(want), "%q: got %q, want %q", opt, got, want, loc = loc)
	if len(got) == len(want) {
		for i in 0 ..< len(got) {
			testing.expectf(t, got[i] == want[i], "%q word %d: got %q, want %q", opt, i, got[i], want[i], loc = loc)
		}
	}
}

@(test)
tokenizer_plain_words :: proc(t: ^testing.T) {
	expect_words(t, "route 10.0.0.0 255.0.0.0", {"route", "10.0.0.0", "255.0.0.0"})
	expect_words(t, "ping 5", {"ping", "5"})
	expect_words(t, "block-ipv6", {"block-ipv6"})
	expect_words(t, "", {})
	// Leading spaces are ignored and more than one space separates words.
	expect_words(t, "  dhcp-option   DNS    10.8.0.1  ", {"dhcp-option", "DNS", "10.8.0.1"})
	expect_words(t, "   ", {})
}

@(test)
tokenizer_quotes_and_escapes :: proc(t: ^testing.T) {
	expect_words(t, `dhcp-option DOMAIN "my domain.example"`, {"dhcp-option", "DOMAIN", "my domain.example"})
	expect_words(t, `dhcp-option DOMAIN 'my domain.example'`, {"dhcp-option", "DOMAIN", "my domain.example"})
	expect_words(t, `echo "it's"`, {"echo", "it's"})
	expect_words(t, `echo 'say "hi"'`, {"echo", `say "hi"`})
	expect_words(t, `echo a\ b c`, {"echo", "a b", "c"})
	expect_words(t, `echo a\\b`, {"echo", `a\b`})
	expect_words(t, `echo \"quoted\"`, {"echo", `"quoted"`})
	// Backslash is literal inside single quotes.
	expect_words(t, `echo 'a\b'`, {"echo", `a\b`})
	expect_words(t, `echo 'a\'`, {"echo", `a\`})
	// Backslash before another character stays.
	expect_words(t, `echo a\nb`, {"echo", `a\nb`})
	// An escaped quote inside double quotes.
	expect_words(t, `echo "a\"b"`, {"echo", `a"b`})
	// Empty quoted word.
	expect_words(t, `echo "" x`, {"echo", "", "x"})
	// A quote may start in the middle of a word.
	expect_words(t, `echo ab"c d"ef`, {"echo", "abc def"})
	// A trailing backslash is kept.
	expect_words(t, `echo a\`, {"echo", `a\`})
}

@(test)
tokenizer_comments :: proc(t: ^testing.T) {
	// A word that starts with ; or # drops the rest of the option.
	expect_words(t, "route 10.0.0.0 ; comment here", {"route", "10.0.0.0"})
	expect_words(t, "ping 5 # five", {"ping", "5"})
	expect_words(t, "; all comment", {})
	expect_words(t, "# all comment", {})
	// In the middle of a word it is just a character.
	expect_words(t, "echo a;b c#d", {"echo", "a;b", "c#d"})
	// Quoting protects it.
	expect_words(t, `echo ";x"`, {"echo", ";x"})
	expect_words(t, `echo '#x'`, {"echo", "#x"})
}

@(test)
tokenizer_errors :: proc(t: ^testing.T) {
	_, err := words_of(`echo "unterminated`)
	testing.expect_value(t, err, Error.Bad_Quoting)
	_, err = words_of(`echo 'unterminated`)
	testing.expect_value(t, err, Error.Bad_Quoting)
	_, err = words_of(`echo "a'b`)
	testing.expect_value(t, err, Error.Bad_Quoting)
	// Too many words.
	b := make([dynamic]u8, context.temp_allocator)
	for _ in 0 ..< MAX_OPTION_WORDS + 1 {
		append(&b, "a ")
	}
	_, err = words_of(string(b[:]))
	testing.expect_value(t, err, Error.Too_Many_Words)
	// Exactly the maximum is fine.
	resize(&b, 2 * MAX_OPTION_WORDS)
	got, gerr := words_of(string(b[:]))
	testing.expect_value(t, gerr, Error.None)
	testing.expect_value(t, len(got), MAX_OPTION_WORDS)
	// Too long.
	long := make([]u8, MAX_COMMAND_LEN, context.temp_allocator)
	for &c in long {
		c = 'a'
	}
	_, err = words_of(string(long))
	testing.expect_value(t, err, Error.Oversize)
	_, err = words_of(string(long[:MAX_COMMAND_LEN - 1]))
	testing.expect_value(t, err, Error.None)
}

// ----------------------------------------------------------- Pushed_Options

parse_pushed :: proc(t: ^testing.T, text: string, loc := #caller_location) -> Pushed_Options {
	po: Pushed_Options
	err := pushed_options_parse(&po, text)
	testing.expect_value(t, err, Error.None, loc = loc)
	return po
}

note_count :: proc(po: ^Pushed_Options, d: Disposition, r: Note_Reason) -> int {
	n := 0
	for x in po.notes {
		if x.disposition == d && x.reason == r {
			n += 1
		}
	}
	return n
}

@(test)
pushed_stock_reply :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		"route-gateway 10.8.0.1,topology subnet,ping 5,ping-restart 30,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt aead-epoch,tun-mtu 1500",
	)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, po.topology, Topology.Subnet)
	testing.expect_value(t, po.route_gateway, [4]u8{10, 8, 0, 1})
	testing.expect_value(t, po.ping, 5)
	testing.expect_value(t, po.ping_restart, 30)
	ic, _ := po.ifconfig.?
	testing.expect_value(t, ic.a, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, ic.b, [4]u8{255, 255, 255, 0})
	testing.expect_value(t, po.peer_id, 0)
	testing.expect_value(t, po.cipher, "AES-256-GCM")
	testing.expect_value(t, po.protocol_flags, Protocol_Flags{.Cc_Exit, .Tls_Ekm, .Dyn_Tls_Crypt, .Aead_Epoch})
	testing.expect_value(t, po.tun_mtu, 1500)
	testing.expect_value(t, len(po.notes), 0)
	testing.expect_value(t, po.option_count, 9)
	testing.expect(t, !pushed_options_token_only(&po))
}

@(test)
pushed_routes :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		"route 10.1.0.0 255.255.0.0,route 192.168.5.0,route 10.2.0.0 255.255.255.0 vpn_gateway,route 10.3.0.0 255.255.255.0 net_gateway 200,route 10.4.0.0 255.255.255.0 10.8.0.1 default,route 10.5.0.0 255.255.255.0 remote_host,route-ipv6 fd00::/64,route-ipv6 fd01::/48 fd00::1 50,route-ipv6 fd02::/32 net_gateway",
	)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, len(po.routes), 6)
	testing.expect_value(t, len(po.routes6), 3)
	testing.expect_value(t, len(po.notes), 0)
	r := po.routes[0]
	testing.expect_value(t, r.net, [4]u8{10, 1, 0, 0})
	testing.expect_value(t, r.mask, [4]u8{255, 255, 0, 0})
	testing.expect_value(t, r.gateway.kind, Route_Gw_Kind.Default)
	// Mask defaults to /32.
	testing.expect_value(t, po.routes[1].mask, [4]u8{255, 255, 255, 255})
	testing.expect_value(t, po.routes[2].gateway.kind, Route_Gw_Kind.Vpn_Gateway)
	testing.expect_value(t, po.routes[3].gateway.kind, Route_Gw_Kind.Net_Gateway)
	testing.expect_value(t, po.routes[3].metric, 200)
	testing.expect_value(t, po.routes[4].gateway.kind, Route_Gw_Kind.Addr)
	testing.expect_value(t, po.routes[4].gateway.addr, [4]u8{10, 8, 0, 1})
	_, has_metric := po.routes[4].metric.?
	testing.expect(t, !has_metric) // "default"
	testing.expect_value(t, po.routes[5].gateway.kind, Route_Gw_Kind.Remote_Host)
	testing.expect_value(t, po.routes6[0].bits, 64)
	testing.expect_value(t, po.routes6[0].net[0], 0xfd)
	testing.expect_value(t, po.routes6[1].gateway.kind, Route_Gw_Kind.Addr)
	testing.expect_value(t, po.routes6[1].gateway.addr[15], 1)
	testing.expect_value(t, po.routes6[1].metric, 50)
	testing.expect_value(t, po.routes6[2].gateway.kind, Route_Gw_Kind.Net_Gateway)
}

@(test)
pushed_bad_routes_are_notes :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		"route,route 1.2.3.4 255.0.255.0,route 300.1.1.1,route 1.2.3.4 255.0.0.0 gw.example,route 1.2.3.4 255.0.0.0 vpn_gateway x y,route example.com,route-ipv6 fd00::/129,route-ipv6 nonsense,route-ipv6",
	)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, len(po.routes), 0)
	testing.expect_value(t, len(po.routes6), 0)
	testing.expect_value(t, note_count(&po, .Ignore, .Malformed), 9)
}

@(test)
pushed_ifconfig_and_topology :: proc(t: ^testing.T) {
	po := parse_pushed(t, "ifconfig-ipv6 fd00:8::1000/112 fd00:8::1,ifconfig 10.8.0.2 255.255.255.0,topology subnet,route-ipv6-gateway fd00:8::1,route-metric 5,route-delay 3 2,redirect-gateway def1,block-ipv6")
	defer pushed_options_destroy(&po)
	c6, ok := po.ifconfig6.?
	testing.expect(t, ok)
	testing.expect_value(t, c6.bits, 112)
	testing.expect_value(t, c6.addr[0], 0xfd)
	testing.expect_value(t, c6.addr[15], 0)
	testing.expect_value(t, c6.addr[14], 0x10)
	testing.expect_value(t, c6.gateway[15], 1)
	testing.expect_value(t, po.topology, Topology.Subnet)
	g6, _ := po.route_ipv6_gateway.?
	testing.expect_value(t, g6[15], 1)
	testing.expect_value(t, po.route_metric, 5)
	testing.expect_value(t, po.route_delay, 3)
	testing.expect(t, po.redirect_gateway.set)
	testing.expect_value(t, po.redirect_gateway.flags, Redirect_Flags{.Def1})
	testing.expect(t, po.block_ipv6)
	testing.expect(t, !po.redirect_private.set)

	// ifconfig-ipv6: prefix length 64 to 124, and the length is in the first word.
	po2 := parse_pushed(t, "ifconfig-ipv6 fd00::2/63 fd00::1,ifconfig-ipv6 fd00::2/125 fd00::1,ifconfig-ipv6 fd00::2/64,ifconfig-ipv6 fd00::2 fd00::1")
	defer pushed_options_destroy(&po2)
	_, ok = po2.ifconfig6.?
	testing.expect(t, !ok)
	testing.expect_value(t, note_count(&po2, .Ignore, .Malformed), 4)
	po3 := parse_pushed(t, "ifconfig-ipv6 fd00::2/64 fd00::1")
	defer pushed_options_destroy(&po3)
	_, ok = po3.ifconfig6.?
	testing.expect(t, ok)
	po4 := parse_pushed(t, "ifconfig-ipv6 fd00::2/124 fd00::1")
	defer pushed_options_destroy(&po4)
	_, ok = po4.ifconfig6.?
	testing.expect(t, ok)
}

@(test)
pushed_topology_rejects :: proc(t: ^testing.T) {
	// net30 and p2p are rejected.
	for top in ([]string{"net30", "p2p"}) {
		text := top
		po := parse_pushed(t, "topology net30" if text == "net30" else "topology p2p")
		testing.expect_value(t, po.topology, Topology.Net30 if text == "net30" else Topology.P2p)
		n, ok := pushed_options_first_reject(&po)
		testing.expect(t, ok)
		testing.expect_value(t, n.name, "topology")
		testing.expect_value(t, n.reason, Note_Reason.Unsupported_Topology)
		pushed_options_destroy(&po)
	}
	po := parse_pushed(t, "topology weird")
	defer pushed_options_destroy(&po)
	testing.expect_value(t, po.topology, Topology.Unset)
	testing.expect_value(t, note_count(&po, .Ignore, .Malformed), 1)
	_, rej := pushed_options_first_reject(&po)
	testing.expect(t, !rej)
}

@(test)
pushed_redirect_flags :: proc(t: ^testing.T) {
	po := parse_pushed(t, "redirect-gateway local def1 ipv6 !ipv4 block-local autolocal,redirect-private def1,redirect-gateway bypass-dhcp bypass-dns")
	defer pushed_options_destroy(&po)
	testing.expect_value(t, po.redirect_gateway.flags, Redirect_Flags{.Local, .Autolocal, .Def1, .Bypass_Dhcp, .Bypass_Dns, .Block_Local, .Ipv6, .Not_Ipv4})
	testing.expect_value(t, po.redirect_private.flags, Redirect_Flags{.Def1})
	// bypass-* are accepted by the parser and noted as not applicable.
	testing.expect_value(t, note_count(&po, .Ignore, .Not_Applicable), 2)

	// No flags is valid.
	po2 := parse_pushed(t, "redirect-gateway")
	defer pushed_options_destroy(&po2)
	testing.expect(t, po2.redirect_gateway.set)
	testing.expect_value(t, po2.redirect_gateway.flags, Redirect_Flags{})

	// An unknown flag is noted, and the known flags still count.
	po3 := parse_pushed(t, "redirect-gateway def1 shiny")
	defer pushed_options_destroy(&po3)
	testing.expect_value(t, po3.redirect_gateway.flags, Redirect_Flags{.Def1})
	testing.expect_value(t, note_count(&po3, .Ignore, .Unsupported_Value), 1)
}

@(test)
pushed_dhcp_options :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		`dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00::53,dhcp-option DOMAIN corp.example,dhcp-option ADAPTER_DOMAIN_SUFFIX suffix.example,dhcp-option DOMAIN-SEARCH "a.example",dhcp-option WINS 1.2.3.4,dhcp-option NBT 2,dhcp-option PROXY_HTTP h 8080,dhcp-option FUTURE x,dhcp-option DNS notanip,dhcp-option DNS6 10.1.1.1,dhcp-option DOMAIN`,
	)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, len(po.dhcp_dns), 2)
	testing.expect(t, !po.dhcp_dns[0].v6)
	testing.expect_value(t, po.dhcp_dns[0].bytes[3], 1)
	testing.expect(t, po.dhcp_dns[1].v6)
	testing.expect_value(t, po.dhcp_dns[1].bytes[15], 0x53)
	testing.expect_value(t, len(po.dhcp_domains), 3)
	testing.expect_value(t, po.dhcp_domains[0], "corp.example")
	testing.expect_value(t, po.dhcp_domains[1], "suffix.example")
	testing.expect_value(t, po.dhcp_domains[2], "a.example")
	testing.expect_value(t, note_count(&po, .Ignore, .Not_Applicable), 3)
	testing.expect_value(t, note_count(&po, .Ignore, .Unknown_Option), 1)
	testing.expect_value(t, note_count(&po, .Ignore, .Malformed), 3)
}

@(test)
pushed_dns_v2 :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		"dns search-domains corp.example lab.example,dns server 10 address 10.8.0.53 [fd00::53]:5353 192.0.2.1:853,dns server 1 address 9.9.9.9,dns server 1 resolve-domains a.example b.example,dns server 1 dnssec optional,dns server 1 transport DoT,dns server 1 sni dns.quad9.net,dns server 10 transport plain,dns server 10 dnssec no,dns server 10 resolve-domains corp.example",
	)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, len(po.dns_search_domains), 2)
	testing.expect_value(t, po.dns_search_domains[1], "lab.example")
	// Groups come out in ascending priority.
	testing.expect_value(t, len(po.dns_servers), 2)
	g1 := po.dns_servers[0]
	g10 := po.dns_servers[1]
	testing.expect_value(t, g1.prio, 1)
	testing.expect_value(t, g10.prio, 10)
	testing.expect_value(t, len(g1.addresses), 1)
	testing.expect_value(t, g1.addresses[0].ip.bytes[0], 9)
	testing.expect_value(t, g1.dnssec, Dns_Dnssec.Optional)
	testing.expect_value(t, g1.transport, Dns_Transport.Dot)
	testing.expect_value(t, g1.sni, "dns.quad9.net")
	testing.expect_value(t, len(g1.resolve_domains), 2)
	testing.expect_value(t, len(g10.addresses), 3)
	testing.expect_value(t, g10.addresses[0].port, 0)
	testing.expect(t, g10.addresses[1].ip.v6)
	testing.expect_value(t, g10.addresses[1].port, 5353)
	testing.expect_value(t, g10.addresses[2].port, 853)
	testing.expect_value(t, g10.addresses[2].ip.bytes[0], 192)
	testing.expect_value(t, g10.transport, Dns_Transport.Plain)
	testing.expect_value(t, g10.dnssec, Dns_Dnssec.No)
	testing.expect_value(t, len(po.notes), 0)
}

@(test)
pushed_dns_v2_errors :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		"dns server 200 address 1.2.3.4,dns server x address 1.2.3.4,dns server 1 address,dns server 1 address bad,dns server 1 dnssec maybe,dns server 1 transport carrier-pigeon,dns server 1 sni,dns server 1 wiggle x,dns server 5 resolve-domains only.example,dns bogus x y,dns,dns server,dns server 3 address 1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7 1.1.1.8 1.1.1.9",
	)
	defer pushed_options_destroy(&po)
	// Group 5 has no address and is dropped at finish; group 3 keeps 8 of 9.
	testing.expect_value(t, len(po.dns_servers), 1)
	testing.expect_value(t, po.dns_servers[0].prio, 3)
	testing.expect_value(t, len(po.dns_servers[0].addresses), MAX_DNS_ADDRESSES)
	testing.expect(t, len(po.notes) >= 10)
	testing.expect_value(t, note_count(&po, .Ignore, .Limit), 1)
}

@(test)
pushed_dns_group_limit :: proc(t: ^testing.T) {
	b := make([dynamic]u8, context.temp_allocator)
	for i in 0 ..< MAX_DNS_GROUPS + 3 {
		if i > 0 {
			append(&b, ',')
		}
		append(&b, "dns server ")
		append(&b, u8('0' + i / 10), u8('0' + i % 10))
		append(&b, " address 1.1.1.1")
	}
	po := parse_pushed(t, string(b[:]))
	defer pushed_options_destroy(&po)
	testing.expect_value(t, len(po.dns_servers), MAX_DNS_GROUPS)
	testing.expect_value(t, note_count(&po, .Ignore, .Limit), 3)
}

@(test)
pushed_timers_and_policy :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		"ping 10,ping-restart 60,ping-exit 120,inactive 300 1000,session-timeout 3600,explicit-exit-notify 2,tun-mtu 1400 1500,sndbuf 65536,rcvbuf 131072,socket-flags TCP_NODELAY,persist-tun,persist-key,keepalive 7 33",
	)
	defer pushed_options_destroy(&po)
	// keepalive sets ping and ping-restart, in order.
	testing.expect_value(t, po.ping, 7)
	testing.expect_value(t, po.ping_restart, 33)
	testing.expect_value(t, po.ping_exit, 120)
	in_, _ := po.inactive.?
	testing.expect_value(t, in_, Inactive{300, 1000})
	testing.expect_value(t, po.session_timeout, 3600)
	testing.expect_value(t, po.explicit_exit_notify, 2)
	testing.expect_value(t, po.tun_mtu, 1400)
	testing.expect_value(t, po.sndbuf, 65536)
	testing.expect_value(t, po.rcvbuf, 131072)
	testing.expect(t, po.tcp_nodelay && po.persist_tun && po.persist_key)
	testing.expect_value(t, len(po.notes), 0)

	po2 := parse_pushed(t, "explicit-exit-notify,inactive 60")
	defer pushed_options_destroy(&po2)
	testing.expect_value(t, po2.explicit_exit_notify, 0)
	in_, _ = po2.inactive.?
	testing.expect_value(t, in_, Inactive{60, 0})

	// Bad numbers and ranges.
	po3 := parse_pushed(t, "ping x,ping-restart -5,ping,tun-mtu 99,tun-mtu 65537,tun-mtu abc,tun-mtu,keepalive 5,inactive,session-timeout 99999999999,sndbuf 1 2")
	defer pushed_options_destroy(&po3)
	_, has := po3.ping.?
	testing.expect(t, !has)
	_, has = po3.tun_mtu.?
	testing.expect(t, !has)
	testing.expect_value(t, note_count(&po3, .Ignore, .Malformed), 11)
	po4 := parse_pushed(t, "tun-mtu 100,tun-mtu 65536")
	defer pushed_options_destroy(&po4)
	testing.expect_value(t, po4.tun_mtu, 65536)
	testing.expect_value(t, len(po4.notes), 0)
}

@(test)
pushed_crypto_options :: proc(t: ^testing.T) {
	po := parse_pushed(t, "peer-id 16777214,key-derivation tls-ekm,protocol-flags tls-ekm cc-exit future-flag,cipher CHACHA20-POLY1305")
	defer pushed_options_destroy(&po)
	testing.expect_value(t, po.peer_id, 0xFFFFFE)
	testing.expect(t, po.key_derivation_ekm)
	testing.expect_value(t, po.protocol_flags, Protocol_Flags{.Tls_Ekm, .Cc_Exit})
	testing.expect_value(t, note_count(&po, .Ignore, .Unsupported_Value), 1)
	testing.expect_value(t, po.cipher, "CHACHA20-POLY1305")

	// peer-id 0xFFFFFF is "undefined" and refused.
	po2 := parse_pushed(t, "peer-id 16777215,peer-id -1,peer-id,key-derivation other,key-derivation,protocol-flags,cipher")
	defer pushed_options_destroy(&po2)
	_, has := po2.peer_id.?
	testing.expect(t, !has)
	testing.expect(t, !po2.key_derivation_ekm)
	testing.expect_value(t, note_count(&po2, .Ignore, .Malformed), 7)
}

@(test)
pushed_compression_is_rejected :: proc(t: ^testing.T) {
	// every value except `comp-lzo no` and a bare `compress`.
	for text in ([]string{"comp-lzo", "comp-lzo yes", "comp-lzo adaptive", "compress lz4", "compress lz4-v2", "compress stub-v2 asym"}) {
		po := parse_pushed(t, text)
		n, ok := pushed_options_first_reject(&po)
		testing.expectf(t, ok, "%q must be rejected", text)
		testing.expect_value(t, n.reason, Note_Reason.Compression)
		pushed_options_destroy(&po)
	}
	for text in ([]string{"comp-lzo no", "compress"}) {
		po := parse_pushed(t, text)
		_, ok := pushed_options_first_reject(&po)
		testing.expectf(t, !ok, "%q is a valid no-compression form", text)
		testing.expect_value(t, len(po.notes), 0)
		pushed_options_destroy(&po)
	}
}

@(test)
pushed_unknown_and_not_applicable :: proc(t: ^testing.T) {
	po := parse_pushed(
		t,
		"brand-new-option 1 2,block-outside-dns,route-method exe,tun-ipv6,ping-timer-rem,shaper 1000,verb 5,mute 3,echo hello,parameter x,setenv-safe A B,custom-control proto1,route-gateway dhcp,redirect-private bypass-dns",
	)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, note_count(&po, .Ignore, .Unknown_Option), 1)
	// Eleven table entries plus route-gateway dhcp and the bypass flag.
	testing.expect_value(t, note_count(&po, .Ignore, .Not_Applicable), 13)
	testing.expect(t, po.route_gateway_dhcp)
	_, has := po.route_gateway.?
	testing.expect(t, !has)
	// Nothing is lost silently: each note keeps the name and the text.
	testing.expect_value(t, po.notes[0].name, "brand-new-option")
	testing.expect_value(t, po.notes[0].text, "brand-new-option 1 2")
	_, rej := pushed_options_first_reject(&po)
	testing.expect(t, !rej)
}

@(test)
pushed_quoted_arguments :: proc(t: ^testing.T) {
	po := parse_pushed(t, `dhcp-option DOMAIN "two words.example",dhcp-option DOMAIN 'a b',cipher "AES-256-GCM"`)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, len(po.dhcp_domains), 2)
	testing.expect_value(t, po.dhcp_domains[0], "two words.example")
	testing.expect_value(t, po.dhcp_domains[1], "a b")
	testing.expect_value(t, po.cipher, "AES-256-GCM")
	// Bad quoting is a note.
	po2 := parse_pushed(t, `dhcp-option DOMAIN "oops,ping 5`)
	defer pushed_options_destroy(&po2)
	testing.expect_value(t, note_count(&po2, .Ignore, .Malformed), 1)
	testing.expect_value(t, po2.notes[0].name, "dhcp-option")
	// A comma ends an option even inside quotes: `dhcp-option DOMAIN "oops` is
	// one option (bad quoting) and `ping 5` is the next one.
	testing.expect_value(t, po2.ping, 5)
}

@(test)
pushed_empty_items_and_comments :: proc(t: ^testing.T) {
	// A trailing comma and empty items are fine; a comment-only item is skipped.
	po := parse_pushed(t, "ping 5,,ping-restart 30,; nothing,# more,")
	defer pushed_options_destroy(&po)
	testing.expect_value(t, po.ping, 5)
	testing.expect_value(t, po.ping_restart, 30)
	testing.expect_value(t, len(po.notes), 0)
	testing.expect_value(t, po.option_count, 2)

	// Empty reply.
	po2 := parse_pushed(t, "")
	defer pushed_options_destroy(&po2)
	testing.expect_value(t, po2.option_count, 0)
	testing.expect_value(t, po2.topology, Topology.Unset)
}

@(test)
pushed_too_many_options :: proc(t: ^testing.T) {
	b := make([dynamic]u8, context.temp_allocator)
	for _ in 0 ..< MAX_PUSH_OPTIONS + 1 {
		append(&b, "persist-tun,")
	}
	po: Pushed_Options
	err := pushed_options_parse(&po, string(b[:]))
	defer pushed_options_destroy(&po)
	testing.expect_value(t, err, Error.Too_Many_Options)
	testing.expect_value(t, po.option_count, MAX_PUSH_OPTIONS)
}

@(test)
pushed_notes_are_bounded :: proc(t: ^testing.T) {
	b := make([dynamic]u8, context.temp_allocator)
	for _ in 0 ..< MAX_PUSH_NOTES + 20 {
		append(&b, "unknown-thing 1,")
	}
	po := parse_pushed(t, string(b[:]))
	defer pushed_options_destroy(&po)
	testing.expect_value(t, len(po.notes), MAX_PUSH_NOTES)
	testing.expect_value(t, po.notes_dropped, 20)
}

@(test)
pushed_auth_token :: proc(t: ^testing.T) {
	po := parse_pushed(t, "auth-token SESS_ID_AT_abc123+/=,auth-token-user YWxpY2U=")
	defer pushed_options_destroy(&po)
	testing.expect_value(t, po.auth_token, "SESS_ID_AT_abc123+/=")
	testing.expect_value(t, po.auth_token_user, "YWxpY2U=")
	// Only token options: the client changes nothing else.
	testing.expect(t, pushed_options_token_only(&po))

	po2 := parse_pushed(t, "auth-token T")
	defer pushed_options_destroy(&po2)
	testing.expect(t, pushed_options_token_only(&po2))

	po3 := parse_pushed(t, "auth-token T,ping 5")
	defer pushed_options_destroy(&po3)
	testing.expect(t, !pushed_options_token_only(&po3))

	// A malformed token option never puts the token text in a note.
	po4 := parse_pushed(t, "auth-token SECRET extra words")
	defer pushed_options_destroy(&po4)
	testing.expect_value(t, len(po4.notes), 1)
	testing.expect_value(t, po4.notes[0].text, "auth-token")
	testing.expect(t, !pushed_options_token_only(&po4))
}

// ------------------------------------------------------------ continuation

@(test)
assembler_single_message :: proc(t: ^testing.T) {
	a: Push_Assembler
	push_assembler_init(&a)
	defer push_assembler_destroy(&a)
	st, err := push_assembler_feed(&a, "topology subnet,ping 5")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, st, Push_Status.Complete)
	testing.expect_value(t, a.po.topology, Topology.Subnet)
	// Feeding again needs a reset.
	_, err = push_assembler_feed(&a, "ping 6")
	testing.expect_value(t, err, Error.Bad_Continuation)
	push_assembler_reset(&a)
	st, err = push_assembler_feed(&a, "auth-token ABC")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, st, Push_Status.Complete)
	testing.expect(t, pushed_options_token_only(&a.po))
}

@(test)
assembler_continuation :: proc(t: ^testing.T) {
	a: Push_Assembler
	push_assembler_init(&a)
	defer push_assembler_destroy(&a)
	st, err := push_assembler_feed(&a, "route 10.1.0.0 255.255.0.0,route 10.2.0.0 255.255.0.0,push-continuation 2")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, st, Push_Status.More)
	testing.expect_value(t, a.po.option_count, 3)
	st, err = push_assembler_feed(&a, "dhcp-option DNS 10.8.0.1,push-continuation 2")
	testing.expect_value(t, st, Push_Status.More)
	st, err = push_assembler_feed(&a, "topology subnet,ifconfig 10.8.0.2 255.255.255.0,push-continuation 1")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, st, Push_Status.Complete)
	testing.expect_value(t, len(a.po.routes), 2)
	testing.expect_value(t, len(a.po.dhcp_dns), 1)
	testing.expect_value(t, a.po.topology, Topology.Subnet)
	testing.expect_value(t, len(a.po.notes), 0)
	testing.expect_value(t, a.parts, 3)
}

@(test)
assembler_continuation_errors :: proc(t: ^testing.T) {
	a: Push_Assembler
	push_assembler_init(&a)
	defer push_assembler_destroy(&a)
	_, err := push_assembler_feed(&a, "ping 5,push-continuation 3")
	testing.expect_value(t, err, Error.Bad_Continuation)
	push_assembler_reset(&a)
	_, err = push_assembler_feed(&a, "ping 5,push-continuation")
	testing.expect_value(t, err, Error.Bad_Continuation)
	push_assembler_reset(&a)
	_, err = push_assembler_feed(&a, "push-continuation 1,push-continuation 2")
	testing.expect_value(t, err, Error.Bad_Continuation)
	push_assembler_reset(&a)
	_, err = push_assembler_feed(&a, "push-continuation x")
	testing.expect_value(t, err, Error.Bad_Continuation)
	push_assembler_reset(&a)
	_, err = push_assembler_feed(&a, "push-continuation 1 2")
	testing.expect_value(t, err, Error.Bad_Continuation)
	push_assembler_reset(&a)

	// A message with no continuation option after a `2` completes the reply
	// (the sender broke the rule, the reply is taken as final).
	st, err2 := push_assembler_feed(&a, "ping 5,push-continuation 2")
	testing.expect_value(t, err2, Error.None)
	testing.expect_value(t, st, Push_Status.More)
	st, err2 = push_assembler_feed(&a, "ping-restart 30")
	testing.expect_value(t, err2, Error.None)
	testing.expect_value(t, st, Push_Status.Complete)
	// `push-continuation 1` alone, first message: complete at once.
	push_assembler_reset(&a)
	st, err2 = push_assembler_feed(&a, "push-continuation 1")
	testing.expect_value(t, err2, Error.None)
	testing.expect_value(t, st, Push_Status.Complete)
}

@(test)
assembler_part_and_size_bounds :: proc(t: ^testing.T) {
	a: Push_Assembler
	push_assembler_init(&a)
	defer push_assembler_destroy(&a)
	st: Push_Status
	err: Error
	for _ in 0 ..< MAX_PUSH_PARTS {
		st, err = push_assembler_feed(&a, "ping 1,push-continuation 2")
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, st, Push_Status.More)
	}
	_, err = push_assembler_feed(&a, "ping 1,push-continuation 2")
	testing.expect_value(t, err, Error.Too_Many_Options)

	// Total bytes: 64 KiB over all parts. Options of 1000 bytes keep the
	// option count low, so the byte limit is the one that trips.
	push_assembler_reset(&a)
	part := make([dynamic]u8, context.temp_allocator)
	for _ in 0 ..< 30 {
		for _ in 0 ..< 999 {
			append(&part, 'a')
		}
		append(&part, ',')
	}
	append(&part, "push-continuation 2")
	for i in 0 ..< 3 {
		st, err = push_assembler_feed(&a, string(part[:]))
		if i < 2 {
			testing.expect_value(t, err, Error.None)
		}
	}
	testing.expect_value(t, err, Error.Too_Many_Options)
}

@(test)
update_items :: proc(t: ^testing.T) {
	items := make([dynamic]Update_Item, context.temp_allocator)
	cont, err := push_update_parse("-route,?dns search-domains a.example,route 10.9.0.0 255.255.0.0,-?block-ipv6,?-block-ipv6,ping 5,-keepalive,push-continuation 2", &items)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, cont, 2)
	testing.expect_value(t, len(items), 7)
	testing.expect(t, items[0].remove && !items[0].optional && items[0].allowed)
	testing.expect_value(t, items[0].name, "route")
	testing.expect(t, !items[1].remove && items[1].optional && items[1].allowed)
	testing.expect_value(t, items[1].text, "dns search-domains a.example")
	testing.expect(t, !items[2].remove && !items[2].optional && items[2].allowed)
	testing.expect(t, items[3].remove && items[3].optional && items[3].allowed)
	// `?-` is invalid.
	testing.expect(t, !items[4].allowed)
	// ping is not updatable.
	testing.expect_value(t, items[5].name, "ping")
	testing.expect(t, !items[5].allowed)
	testing.expect(t, items[6].allowed) // keepalive is in the list

	// An item's text feeds the option parser.
	po: Pushed_Options
	pushed_options_init(&po)
	defer pushed_options_destroy(&po)
	testing.expect_value(t, pushed_options_add_option(&po, items[2].text), Error.None)
	testing.expect_value(t, len(po.routes), 1)

	// No continuation.
	cont, err = push_update_parse("route 1.2.3.0 255.255.255.0", &items)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, cont, 0)
	testing.expect_value(t, len(items), 1)
	// Bad continuation value.
	_, err = push_update_parse("route 1.2.3.0,push-continuation 7", &items)
	testing.expect_value(t, err, Error.Bad_Continuation)
}

// ------------------------------------------------------------ validation

ALL_CIPHERS := [?]Cipher{.Aes_256_Gcm, .Aes_128_Gcm, .Chacha20_Poly1305}
ONLY_128 := [?]Cipher{.Aes_128_Gcm}

good_params :: proc() -> Validate_Params {
	return Validate_Params{own_ciphers = ALL_CIPHERS[:], server_options_cipher = "AES-256-GCM", iv_mtu = 1600}
}

validate_text :: proc(t: ^testing.T, text: string, p: Validate_Params) -> Validate_Result {
	po := parse_pushed(t, text)
	defer pushed_options_destroy(&po)
	pp := p
	return pushed_options_validate(&po, &pp)
}

@(test)
validate_accepts_stock_reply :: proc(t: ^testing.T) {
	r := validate_text(t, "route-gateway 10.8.0.1,topology subnet,ping 5,ping-restart 30,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt aead-epoch,tun-mtu 1500", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.None)
	testing.expect_value(t, r.cipher, Cipher.Aes_256_Gcm)
	// key-derivation instead of protocol-flags.
	r = validate_text(t, "topology subnet,key-derivation tls-ekm,cipher AES-128-GCM", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.None)
	testing.expect_value(t, r.cipher, Cipher.Aes_128_Gcm)
}

@(test)
validate_failures :: proc(t: ^testing.T) {
	r := validate_text(t, "topology net30,key-derivation tls-ekm", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.Rejected_Option)
	testing.expect_value(t, r.option, "topology")
	r = validate_text(t, "key-derivation tls-ekm", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.Missing_Topology)
	// An empty PUSH_REPLY is also a missing topology.
	r = validate_text(t, "", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.Missing_Topology)
	r = validate_text(t, "topology subnet,cipher AES-256-GCM", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.No_Key_Derivation)
	r = validate_text(t, "topology subnet,protocol-flags cc-exit,cipher AES-256-GCM", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.No_Key_Derivation)
	r = validate_text(t, "topology subnet,key-derivation tls-ekm,compress lz4", good_params())
	testing.expect_value(t, r.failure, Validate_Failure.Rejected_Option)

	// Cipher.
	p := good_params()
	r = validate_text(t, "topology subnet,key-derivation tls-ekm,cipher AES-256-CBC", p)
	testing.expect_value(t, r.failure, Validate_Failure.Cipher_Not_Allowed)
	p.own_ciphers = ONLY_128[:]
	r = validate_text(t, "topology subnet,key-derivation tls-ekm,cipher AES-256-GCM", p)
	testing.expect_value(t, r.failure, Validate_Failure.Cipher_Not_Allowed)
	// No cipher pushed: the server's options-string cipher must be in the list.
	r = validate_text(t, "topology subnet,key-derivation tls-ekm", p)
	testing.expect_value(t, r.failure, Validate_Failure.No_Usable_Cipher)
	p.server_options_cipher = "AES-128-GCM"
	r = validate_text(t, "topology subnet,key-derivation tls-ekm", p)
	testing.expect_value(t, r.failure, Validate_Failure.None)
	testing.expect_value(t, r.cipher, Cipher.Aes_128_Gcm)

	// aead-epoch needs a peer id and a cipher.
	p = good_params()
	r = validate_text(t, "topology subnet,protocol-flags tls-ekm aead-epoch,cipher AES-256-GCM", p)
	testing.expect_value(t, r.failure, Validate_Failure.Epoch_Needs_Peer_Id)
	p.have_peer_id = true
	r = validate_text(t, "topology subnet,protocol-flags tls-ekm aead-epoch,cipher AES-256-GCM", p)
	testing.expect_value(t, r.failure, Validate_Failure.None)
	p.have_peer_id = false
	r = validate_text(t, "topology subnet,protocol-flags tls-ekm aead-epoch,cipher AES-256-GCM,peer-id 4", p)
	testing.expect_value(t, r.failure, Validate_Failure.None)

	// tun-mtu must not pass IV_MTU, and needs one.
	p = good_params()
	r = validate_text(t, "topology subnet,key-derivation tls-ekm,tun-mtu 1601", p)
	testing.expect_value(t, r.failure, Validate_Failure.Mtu_Too_Large)
	r = validate_text(t, "topology subnet,key-derivation tls-ekm,tun-mtu 1600", p)
	testing.expect_value(t, r.failure, Validate_Failure.None)
	p.iv_mtu = 0
	r = validate_text(t, "topology subnet,key-derivation tls-ekm,tun-mtu 1400", p)
	testing.expect_value(t, r.failure, Validate_Failure.Mtu_Too_Large)
}
