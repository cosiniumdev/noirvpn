// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

// Fuzz-style tests: random and mutated input into every parser. Nothing may
// crash, hang or leak (the test runner checks leaks). Results are not checked
// except for a few invariants. The generator is seeded, so a failure repeats.

FUZZ_ROUNDS :: 4000

// Pieces that give random option text the look of a PUSH_REPLY.
FRAGMENTS := [?]string {
	"route ", "route-ipv6 ", "ifconfig ", "ifconfig-ipv6 ", "dhcp-option ", "dns ", "server ", "address ",
	"search-domains ", "resolve-domains ", "dnssec ", "transport ", "sni ", "redirect-gateway ", "def1 ", "ipv6 ",
	"topology ", "subnet ", "net30 ", "ping ", "ping-restart ", "peer-id ", "cipher ", "key-derivation ",
	"protocol-flags ", "tun-mtu ", "auth-token ", "explicit-exit-notify ", "push-continuation ", "compress ",
	"comp-lzo ", "block-ipv6", "10.8.0.1", "255.255.255.0", "fd00::1", "fd00::/64", "[fd00::53]:5353",
	"1.2.3.4:853", "AES-256-GCM", "tls-ekm", "cc-exit", "DNS", "DOMAIN", "vpn_gateway", "net_gateway",
	"0", "1", "2", "5", "65536", "99999999999", "-1", ",", ",", ",", " ", " ", " ", "\"", "'", "\\", ";", "#",
	":", ".", "[", "]", "/", "-", "?", "!", "a", "z", "AUTH_FAILED", "TEMP", "[backoff 5,advance addr]",
	"RESTART", "[N]", "[P]", "INFO_PRE", "SESSION", "CRV1:R,E:", "WEB_AUTH::", "\x00", "\x01", "\x7f", "\n", "\r\n",
	"\xc3\xa9", "\xff",
}

random_text :: proc(r: ^Rng, max_pieces: int) -> string {
	b := make([dynamic]u8, context.temp_allocator)
	n := rng_below(r, max_pieces + 1)
	for _ in 0 ..< n {
		append(&b, FRAGMENTS[rng_below(r, len(FRAGMENTS))])
	}
	return string(b[:])
}

random_bytes :: proc(r: ^Rng, max_len: int) -> []u8 {
	b := make([]u8, rng_below(r, max_len + 1), context.temp_allocator)
	rng_fill(r, b)
	return b
}

// Flips, drops, repeats and inserts bytes of a seed.
mutate :: proc(r: ^Rng, seed: []u8) -> []u8 {
	b := make([dynamic]u8, context.temp_allocator)
	append(&b, ..seed)
	for _ in 0 ..< 1 + rng_below(r, 6) {
		if len(b) == 0 {
			append(&b, u8(rng_next(r)))
			continue
		}
		i := rng_below(r, len(b))
		switch rng_below(r, 6) {
		case 0:
			b[i] = u8(rng_next(r) >> 24)
		case 1:
			b[i] ~= u8(1 << u32(rng_below(r, 8)))
		case 2:
			ordered_remove(&b, i)
		case 3:
			inject_at(&b, i, u8(rng_next(r) >> 24))
		case 4:
			resize(&b, i) // truncate
		case 5:
			// Duplicate a chunk.
			end := min(len(b), i + 1 + rng_below(r, 16))
			chunk := make([]u8, end - i, context.temp_allocator)
			copy(chunk, b[i:end])
			inject_at(&b, i, ..chunk)
		}
	}
	return b[:]
}

// Hex digits and one letter that is not.
HEX_ALPHABET := "0123456789abcdefABCDEFg"

as_text :: proc(b: []u8) -> string {
	return string(b)
}

seed_pushed := [?]string {
	"route-gateway 10.8.0.1,topology subnet,ping 5,ping-restart 30,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt aead-epoch,tun-mtu 1500",
	"route 10.1.0.0 255.255.0.0,route 10.2.0.0 255.255.255.0 vpn_gateway 5,route-ipv6 fd00::/64 fd00::1,dhcp-option DNS 10.8.0.53,dhcp-option DOMAIN \"a b\",push-continuation 2",
	"dns server 1 address 9.9.9.9 [fd00::53]:5353,dns server 1 dnssec optional,dns server 1 transport DoT,dns search-domains a.example b.example,redirect-gateway def1 ipv6 !ipv4",
	"auth-token SESS_ID_AT_abc,auth-token-user YWxpY2U=,ifconfig-ipv6 fd00:8::1000/112 fd00:8::1,compress lz4,explicit-exit-notify 3,push-continuation 1",
}

seed_commands := [?]string {
	"PUSH_REQUEST", "PUSH_REPLY,route 10.1.0.0,ping 5", "PUSH_UPDATE,-route,?dns search-domains a.example", "AUTH_FAILED",
	"AUTH_FAILED,SESSION", "AUTH_FAILED,TEMP[backoff 5,advance addr]: server is busy", "AUTH_FAILED,CRV1:R,E:abc:YWxpY2U=:Enter code",
	"AUTH_PENDING,timeout 300", "INFO_PRE,WEB_AUTH:proxy=h;8080:https://x/y", "INFO,hello", "CR_RESPONSE,YWJj",
	"RESTART", "RESTART,[PN] going down", "HALT,[P] bye", "EXIT", "ACC,x",
}

@(test)
fuzz_keymethod_decode :: proc(t: ^testing.T) {
	rng := Rng {
		s = 0xC0FFEE_0001,
	}
	seeds: [3][KEY_METHOD_MAX_LEN]u8
	seed_lens: [3]int
	kms := [3]Key_Method{client_msg("alice", "pw"), client_msg(), {sender = .Server, random = fake_random(KEY_METHOD_RANDOM_SERVER), options = stock_options_server}}
	for &km, i in kms {
		n, err := keymethod_encode(seeds[i][:], &km)
		testing.expect_value(t, err, Error.None)
		seed_lens[i] = n
	}
	for _ in 0 ..< FUZZ_ROUNDS {
		var: []u8
		if rng_below(&rng, 4) == 0 {
			var = random_bytes(&rng, 2200)
		} else {
			k := rng_below(&rng, 3)
			var = mutate(&rng, seeds[k][:seed_lens[k]])
		}
		for sender in Role {
			for final in ([]bool{false, true}) {
				km: Key_Method
				used, err := keymethod_decode(var, sender, &km, final)
				if err == .None {
					testing.expect(t, used >= KEY_METHOD_PREFIX_LEN && used <= len(var))
					testing.expect(t, len(km.options) <= OPTIONS_MAX_LEN)
				}
				// Whatever was decoded can be encoded again without a crash.
				if err == .None {
					out: [KEY_METHOD_MAX_LEN + 64]u8
					_, _ = keymethod_encode(out[:], &km)
				}
			}
		}
		// The string parsers on whatever came out of the message too.
		info: Options_Info
		_ = options_parse(as_text(var), &info)
		pi: Peer_Info
		_ = peer_info_parse(as_text(var), &pi)
	}
}

@(test)
fuzz_options_and_peer_info :: proc(t: ^testing.T) {
	rng := Rng {
		s = 0xC0FFEE_0002,
	}
	seeds := [?]string{stock_options_client, stock_options_server, stock_peer_info_277, "IV_CIPHERS=AES-256-GCM:AES-128-GCM\nIV_PROTO=8094\nID=1f\n"}
	for _ in 0 ..< FUZZ_ROUNDS {
		var: string
		switch rng_below(&rng, 3) {
		case 0:
			var = random_text(&rng, 40)
		case 1:
			var = as_text(random_bytes(&rng, 700))
		case:
			var = as_text(mutate(&rng, transmute([]u8)seeds[rng_below(&rng, len(seeds))]))
		}
		a, b: Options_Info
		e1 := options_parse(var, &a)
		_ = options_parse(stock_options_client, &b)
		_ = options_compare(&a, &b)
		testing.expect(t, e1 == .None || e1 == .Oversize)
		pi: Peer_Info
		e2 := peer_info_parse(var, &pi)
		testing.expect(t, e2 == .None || e2 == .Oversize)
		testing.expect(t, pi.cipher_count <= MAX_PEER_CIPHERS && pi.line_count <= MAX_PEER_INFO_LINES)
		_ = peer_info_ciphers(&pi)
		_, _ = peer_info_get(&pi, "IV_PROTO")
		// Negotiation on any peer-info does not crash.
		offer := Server_Offer {
			ciphers = ALL_CIPHERS[:],
			allow   = {.Cc_Exit, .Dyn_Tls_Crypt, .Aead_Epoch},
		}
		_ = negotiate_server(&pi, a.cipher, &offer)
	}
}

@(test)
fuzz_commands :: proc(t: ^testing.T) {
	rng := Rng {
		s = 0xC0FFEE_0003,
	}
	for _ in 0 ..< FUZZ_ROUNDS {
		var: string
		switch rng_below(&rng, 3) {
		case 0:
			var = random_text(&rng, 12)
		case 1:
			var = as_text(random_bytes(&rng, 300))
		case:
			var = as_text(mutate(&rng, transmute([]u8)seed_commands[rng_below(&rng, len(seed_commands))]))
		}
		for receiver in Role {
			cmd, _ := command_parse(var, receiver)
			// Every typed value formats back without a crash where a
			// formatter exists.
			buf: [MAX_COMMAND_LEN + 8]u8
			#partial switch v in cmd {
			case Auth_Failed:
				_, _ = format_auth_failed(buf[:], v.reason)
			case Restart:
				_, _ = format_restart(buf[:], v.text, v.keep_credentials, v.next_remote)
			case Info_Msg:
				_ = info_pre_parse(v.text)
			case Push_Reply_Msg:
				po: Pushed_Options
				_ = pushed_options_parse(&po, v.options)
				pushed_options_destroy(&po)
			}
		}
		_ = command_kind(var)
		_ = info_pre_parse(var)
		items := make([dynamic]Update_Item, context.temp_allocator)
		_, _ = push_update_parse(var, &items)

		// The reader on random chunks of random bytes: the stream may be
		// split anywhere.
		r: Cmd_Reader
		data := as_text(mutate(&rng, transmute([]u8)var))
		stream := transmute([]u8)data
		for len(stream) > 0 {
			cut := min(len(stream), 1 + rng_below(&rng, 40))
			chunk := stream[:cut]
			stream = stream[cut:]
			for len(chunk) > 0 {
				text, st := cmd_reader_next(&r, &chunk)
				if st == .Oversize {
					cmd_reader_reset(&r)
					break
				}
				if st == .Command {
					testing.expect(t, len(text) < MAX_COMMAND_LEN && cmd_bytes_ok(text))
					_, _ = command_parse(text, .Client)
				}
			}
		}
	}
}

@(test)
fuzz_tokenizer_and_pushed_options :: proc(t: ^testing.T) {
	rng := Rng {
		s = 0xC0FFEE_0004,
	}
	for _ in 0 ..< FUZZ_ROUNDS {
		var: string
		switch rng_below(&rng, 4) {
		case 0:
			var = random_text(&rng, 60)
		case 1:
			var = as_text(random_bytes(&rng, 400))
		case:
			var = as_text(mutate(&rng, transmute([]u8)seed_pushed[rng_below(&rng, len(seed_pushed))]))
		}
		w: Words
		err := tokenize_option(var, &w)
		testing.expect(t, err == .None || err == .Bad_Quoting || err == .Too_Many_Words || err == .Oversize)
		if err == .None {
			testing.expect(t, w.count <= MAX_OPTION_WORDS)
			for i in 0 ..< w.count {
				_ = words_get(&w, i)
			}
			out: [MAX_COMMAND_LEN]u8
			_ = words_join(&w, out[:])
		}

		po: Pushed_Options
		perr := pushed_options_parse(&po, var)
		testing.expect(t, perr == .None || perr == .Too_Many_Options || perr == .Oversize)
		testing.expect(t, len(po.notes) <= MAX_PUSH_NOTES)
		testing.expect(t, len(po.dns_servers) <= MAX_DNS_GROUPS)
		for g in po.dns_servers {
			testing.expect(t, len(g.addresses) <= MAX_DNS_ADDRESSES)
		}
		own := ALL_CIPHERS
		vp := Validate_Params {
			own_ciphers           = own[:],
			server_options_cipher = "AES-256-GCM",
			iv_mtu                = 1600,
		}
		_ = pushed_options_validate(&po, &vp)
		_ = pushed_options_token_only(&po)
		_, _ = pushed_options_first_reject(&po)
		// What the parser accepted can be built again, without a crash. The
		// builder may refuse (a value it cannot carry).
		pp := params_from(&po)
		msgs, berr := push_reply_build(&pp, context.temp_allocator)
		if berr == .None {
			for m in msgs {
				testing.expect(t, len(m) + 1 <= PUSH_MESSAGE_MAX)
			}
		}
		pushed_options_destroy(&po)
	}
}

@(test)
fuzz_assembler_sequences :: proc(t: ^testing.T) {
	rng := Rng {
		s = 0xC0FFEE_0005,
	}
	for _ in 0 ..< FUZZ_ROUNDS / 4 {
		a: Push_Assembler
		push_assembler_init(&a)
		for _ in 0 ..< 1 + rng_below(&rng, 6) {
			var: string
			if rng_below(&rng, 3) == 0 {
				var = random_text(&rng, 30)
			} else {
				var = as_text(mutate(&rng, transmute([]u8)seed_pushed[rng_below(&rng, len(seed_pushed))]))
			}
			st, err := push_assembler_feed(&a, var)
			if err != .None || st == .Complete {
				push_assembler_reset(&a)
			}
		}
		push_assembler_destroy(&a)
	}
}

@(test)
fuzz_number_and_address_parsers :: proc(t: ^testing.T) {
	rng := Rng {
		s = 0xC0FFEE_0006,
	}
	for _ in 0 ..< FUZZ_ROUNDS * 2 {
		var := random_text(&rng, 10)
		if rng_below(&rng, 2) == 0 {
			var = as_text(random_bytes(&rng, 50))
		}
		_, _ = parse_uint(var)
		_, _ = parse_uint_max(var, 255)
		_, _ = scan_uint_prefix(var)
		_, _ = scan_uint_prefix(var, hex = true)
		a4, ok4 := parse_ipv4(var)
		if ok4 {
			buf: [32]u8
			w := Wr{buf = buf[:]}
			wr_ipv4(&w, a4)
			back, ok := parse_ipv4(string(buf[:w.n]))
			testing.expect(t, ok && back == a4)
		}
		a6, ok6 := parse_ipv6(var)
		if ok6 {
			// Anything accepted formats and parses back to the same bytes.
			buf: [64]u8
			w := Wr{buf = buf[:]}
			wr_ipv6(&w, a6)
			back, ok := parse_ipv6(string(buf[:w.n]))
			testing.expectf(t, ok && back == a6, "%q -> %q", var, string(buf[:w.n]))
		}
	}
	// Structured IPv6 text: random groups with random `::` placement.
	for _ in 0 ..< FUZZ_ROUNDS {
		b := make([dynamic]u8, context.temp_allocator)
		groups := rng_below(&rng, 10)
		dc := rng_below(&rng, groups + 2)
		for g in 0 ..< groups {
			if g == dc {
				append(&b, ':')
			} else if g > 0 {
				append(&b, ':')
			}
			for _ in 0 ..< 1 + rng_below(&rng, 5) {
				append(&b, HEX_ALPHABET[rng_below(&rng, len(HEX_ALPHABET))])
			}
		}
		if dc >= groups {
			append(&b, "::")
		}
		a6, ok6 := parse_ipv6(string(b[:]))
		if ok6 {
			buf: [64]u8
			w := Wr{buf = buf[:]}
			wr_ipv6(&w, a6)
			back, ok := parse_ipv6(string(buf[:w.n]))
			testing.expectf(t, ok && back == a6, "%q -> %q", string(b[:]), string(buf[:w.n]))
		}
	}
}

SAFE_EXTRA := [?]string{"sndbuf 65536", "rcvbuf 1000", "persist-tun", "explicit-exit-notify 1", "inactive 300 1000"}

@(test)
fuzz_builders_with_random_params :: proc(t: ^testing.T) {
	rng := Rng {
		s = 0xC0FFEE_0007,
	}
	for _ in 0 ..< FUZZ_ROUNDS / 2 {
		routes := make([]Route, rng_below(&rng, 80), context.temp_allocator)
		for &r in routes {
			r.net = {u8(rng_next(&rng)), u8(rng_next(&rng)), u8(rng_next(&rng)), 0}
			r.mask = {255, 255, 255, 0}
			if rng_below(&rng, 4) == 0 {
				r.metric = rng_below(&rng, 1000)
			}
			r.gateway.kind = Route_Gw_Kind(rng_below(&rng, 4))
		}
		domains := make([]string, rng_below(&rng, 6), context.temp_allocator)
		for &d in domains {
			d = random_text(&rng, 4)
		}
		extra := make([]string, rng_below(&rng, 4), context.temp_allocator)
		for &x in extra {
			x = SAFE_EXTRA[rng_below(&rng, len(SAFE_EXTRA))]
		}
		p := Push_Reply_Params {
			routes       = routes,
			dhcp_domains = domains,
			extra        = extra,
			topology     = Topology(rng_below(&rng, 4)),
			ping         = rng_below(&rng, 100),
			peer_id      = u32(rng_next(&rng) & 0xFFFFFF),
			cipher       = Cipher(rng_below(&rng, 4)),
			auth_token   = random_text(&rng, 8),
		}
		msgs, err := push_reply_build(&p, context.temp_allocator)
		if err == .None {
			// What the builder wrote, the parser takes without notes about
			// malformed text, in the same number of parts.
			a: Push_Assembler
			push_assembler_init(&a)
			for m, i in msgs {
				testing.expect(t, len(m) + 1 <= PUSH_MESSAGE_MAX)
				cmd, cerr := command_parse(m, .Client)
				testing.expect_value(t, cerr, Error.None)
				pr, is_reply := cmd.(Push_Reply_Msg)
				testing.expect(t, is_reply)
				st, ferr := push_assembler_feed(&a, pr.options)
				testing.expect_value(t, ferr, Error.None)
				testing.expect_value(t, st == .Complete, i == len(msgs) - 1)
			}
			testing.expect_value(t, len(a.po.routes), len(routes))
			for n in a.po.notes {
				testing.expectf(t, n.reason != .Malformed, "malformed note for %q", n.text)
			}
			push_assembler_destroy(&a)
		}
	}
}

@(test)
fuzz_builder_with_random_extra_text :: proc(t: ^testing.T) {
	// Extra options are passed through as they are. Random text must not crash
	// the builder; it either builds messages within the limit or refuses.
	rng := Rng {
		s = 0xC0FFEE_0008,
	}
	for _ in 0 ..< FUZZ_ROUNDS / 2 {
		extra := make([]string, rng_below(&rng, 5), context.temp_allocator)
		for &x in extra {
			x = random_text(&rng, 40)
		}
		p := Push_Reply_Params {
			extra      = extra,
			auth_token = random_text(&rng, 100),
			dns_servers = {{prio = rng_below(&rng, 200), addresses = {{port = u16(rng_next(&rng))}}, sni = random_text(&rng, 5)}},
		}
		msgs, err := push_reply_build(&p, context.temp_allocator)
		if err == .None {
			for m in msgs {
				testing.expect(t, len(m) + 1 <= PUSH_MESSAGE_MAX)
				testing.expect(t, cmd_bytes_ok(m))
			}
		}
	}
}
