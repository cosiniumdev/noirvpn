// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

// A client message the way a stock 2.7.7 client writes it (peer-info too),
// with fake random bytes.
stock_options_client :: "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client"
stock_options_server :: "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
stock_peer_info_277 :: "IV_VER=2.7.7\nIV_PLAT=linux\nIV_TCPNL=1\nIV_MTU=1600\nIV_CIPHERS=AES-256-GCM\nIV_PROTO=8094\nIV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\n"

client_msg :: proc(user := "", pass := "", peer_info := stock_peer_info_277) -> Key_Method {
	return Key_Method {
		sender = .Client,
		random = fake_random(KEY_METHOD_RANDOM_CLIENT),
		options = stock_options_client,
		username = user,
		password = pass,
		peer_info = peer_info,
	}
}

@(test)
keymethod_client_layout :: proc(t: ^testing.T) {
	km := client_msg()
	buf: [KEY_METHOD_MAX_LEN]u8
	n, err := keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.None)
	// 388 bytes, like the stock client's message.
	testing.expect_value(t, n, 388)
	testing.expect_value(t, keymethod_encoded_len(&km), 388)
	expect_bytes(t, buf[:5], unhex("00000000 02"), "prefix")
	expect_bytes(t, buf[5:117], km.random, "random block")
	// options: length counts the NUL.
	testing.expect_value(t, int(buf[117]) << 8 | int(buf[118]), len(stock_options_client) + 1)
	i := 117 + 2 + len(stock_options_client) + 1
	// empty username and password: length 0, no bytes.
	expect_bytes(t, buf[i:][:4], unhex("0000 0000"), "empty login")
	i += 4
	testing.expect_value(t, int(buf[i]) << 8 | int(buf[i + 1]), len(stock_peer_info_277) + 1)
	testing.expect_value(t, buf[n - 1], 0)
	testing.expect_value(t, buf[n - 2], '\n')
}

@(test)
keymethod_server_layout :: proc(t: ^testing.T) {
	km := Key_Method {
		sender  = .Server,
		random  = fake_random(KEY_METHOD_RANDOM_SERVER),
		options = stock_options_server,
	}
	buf: [KEY_METHOD_MAX_LEN]u8
	n, err := keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.None)
	// 5 + 64 + 2 + 129 + 2 + 2 + 2 = 206, as the stock server writes it.
	testing.expect_value(t, n, 206)
	// A server with nothing to say writes 00 00 for the peer-info.
	expect_bytes(t, buf[n - 6:n], unhex("0000 0000 0000"), "empty login and peer-info")
}

@(test)
keymethod_round_trip :: proc(t: ^testing.T) {
	buf: [KEY_METHOD_MAX_LEN]u8
	for role in Role {
		km := client_msg("alice", "secret-pw")
		if role == .Server {
			km = Key_Method {
				sender    = .Server,
				random    = fake_random(KEY_METHOD_RANDOM_SERVER, 9),
				options   = stock_options_server,
				peer_info = "ID=1f\n",
			}
		}
		n, err := keymethod_encode(buf[:], &km)
		testing.expect_value(t, err, Error.None)
		got: Key_Method
		used, derr := keymethod_decode(buf[:n], role, &got)
		testing.expect_value(t, derr, Error.None)
		testing.expect_value(t, used, n)
		testing.expect_value(t, got.options, km.options)
		testing.expect_value(t, got.username, km.username)
		testing.expect_value(t, got.password, km.password)
		testing.expect_value(t, got.peer_info, km.peer_info)
		testing.expect(t, got.has_peer_info)
		expect_bytes(t, got.random, km.random, "random")
		// Decoded strings alias the input.
		testing.expect(t, raw_data(got.options) == &buf[KEY_METHOD_PREFIX_LEN + len(km.random) + 2], "options alias the input")
	}
}

@(test)
keymethod_decode_needs_more_at_every_cut :: proc(t: ^testing.T) {
	km := client_msg("alice", "secret-pw")
	buf: [KEY_METHOD_MAX_LEN]u8
	n, _ := keymethod_encode(buf[:], &km)
	for cut in 0 ..< n {
		got: Key_Method
		_, err := keymethod_decode(buf[:cut], .Client, &got)
		testing.expectf(t, err == .Need_More, "cut %d: %v", cut, err)
		// With final = true a short message is Truncated, except when it
		// ends right after the password (no peer-info).
		_, ferr := keymethod_decode(buf[:cut], .Client, &got, final = true)
		pw_end := n - (2 + len(stock_peer_info_277) + 1)
		if cut == pw_end {
			testing.expectf(t, ferr == .None, "cut %d final: %v", cut, ferr)
			testing.expect(t, !got.has_peer_info)
			testing.expect_value(t, got.password, "secret-pw")
		} else {
			testing.expectf(t, ferr == .Truncated, "cut %d final: %v", cut, ferr)
		}
	}
	got: Key_Method
	used, err := keymethod_decode(buf[:n], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, used, n)
}

@(test)
keymethod_ignores_bytes_after_the_message :: proc(t: ^testing.T) {
	// nothing after the peer-info is read. The decoder
	// reports `consumed` so the caller can feed the rest to the command reader.
	km := client_msg()
	buf: [KEY_METHOD_MAX_LEN]u8
	n, _ := keymethod_encode(buf[:], &km)
	copy(buf[n:], "PUSH_REQUEST\x00")
	got: Key_Method
	used, err := keymethod_decode(buf[:n + 13], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, used, n)
	testing.expect_value(t, string(buf[used:][:12]), "PUSH_REQUEST")
}

@(test)
keymethod_negative_cases :: proc(t: ^testing.T) {
	// a non-zero leading u32 and key_method with
	// high flag bits are accepted; another method is fatal.
	km := client_msg()
	buf: [KEY_METHOD_MAX_LEN]u8
	n, _ := keymethod_encode(buf[:], &km)
	got: Key_Method

	b := buf
	b[0], b[1], b[2], b[3] = 0xde, 0xad, 0xbe, 0xef
	_, err := keymethod_decode(b[:n], .Client, &got)
	testing.expect_value(t, err, Error.None)

	b = buf
	b[4] = 0xA2
	_, err = keymethod_decode(b[:n], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, got.flags, 0xA)

	for method in ([]u8{0, 1, 3, 15}) {
		b = buf
		b[4] = method
		_, err = keymethod_decode(b[:n], .Client, &got)
		testing.expectf(t, err == .Bad_Key_Method, "method %d: %v", method, err)
	}
	// The method byte is checked as soon as it is there.
	_, err = keymethod_decode(unhex("00000000 01"), .Client, &got)
	testing.expect_value(t, err, Error.Bad_Key_Method)

	// Options over 512 bytes: fatal, even before the bytes have arrived.
	b = buf
	b[117], b[118] = 0x02, 0x01 // 513
	_, err = keymethod_decode(b[:130], .Client, &got)
	testing.expect_value(t, err, Error.Oversize)
	// 512 exactly is fine.
	long := make([]u8, 511, context.temp_allocator)
	for &c in long {
		c = 'a'
	}
	km2 := client_msg()
	km2.options = string(long)
	n2, err2 := keymethod_encode(buf[:], &km2)
	testing.expect_value(t, err2, Error.None)
	_, err = keymethod_decode(buf[:n2], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(got.options), 511)
	// One more byte is refused by the encoder.
	km2.options = string(make([]u8, 512, context.temp_allocator))
	_, err2 = keymethod_encode(buf[:], &km2)
	testing.expect(t, err2 == .Oversize || err2 == .Bad_Argument)

	// The message may not run past 2048 bytes.
	n, _ = keymethod_encode(buf[:], &km)
	b = buf
	// peer-info length field at the end of the message: claim 60000 bytes.
	pi_off := n - (2 + len(stock_peer_info_277) + 1)
	b[pi_off], b[pi_off + 1] = 0xEA, 0x60
	_, err = keymethod_decode(b[:n], .Client, &got)
	testing.expect_value(t, err, Error.Oversize)
}

@(test)
keymethod_string_rules :: proc(t: ^testing.T) {
	buf: [KEY_METHOD_MAX_LEN]u8
	got: Key_Method

	// An empty string may also be written as length 1 and a NUL.
	km := client_msg()
	n, _ := keymethod_encode(buf[:], &km)
	opt_end := 117 + 2 + len(stock_options_client) + 1
	// Rebuild: options, then username as 00 01 00, password as 00 00, peer-info 00 00.
	tail := unhex("0001 00  0000  0000")
	copy(buf[opt_end:], tail)
	used, err := keymethod_decode(buf[:opt_end + len(tail)], .Client, &got, final = true)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, used, opt_end + len(tail))
	testing.expect_value(t, got.username, "")
	testing.expect(t, !got.has_peer_info)

	// The reader forces the last byte to NUL: a sender that forgot it loses
	// one character.
	n, _ = keymethod_encode(buf[:], &km)
	buf[opt_end - 1] = 'X' // the options NUL replaced
	_, err = keymethod_decode(buf[:n], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(got.options), len(stock_options_client))

	// An embedded NUL ends the text there (C string).
	buf[117 + 2 + 3] = 0
	_, err = keymethod_decode(buf[:n], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, got.options, "V4,")
}

@(test)
keymethod_long_login_keeps_parsing :: proc(t: ^testing.T) {
	// an over-long username or password does not stop the
	// parse, so the peer-info can still be read; the login is then refused.
	long := make([]u8, 150, context.temp_allocator)
	for &c in long {
		c = 'u'
	}
	buf: [KEY_METHOD_MAX_LEN]u8
	km := client_msg()
	n, _ := keymethod_encode(buf[:], &km)
	// Hand-build: insert a 151-byte username and a 130-byte password.
	opt_end := 117 + 2 + len(stock_options_client) + 1
	out := make([dynamic]u8, context.temp_allocator)
	append(&out, ..buf[:opt_end])
	append(&out, 0x00, 151)
	append(&out, ..long)
	append(&out, 0)
	append(&out, 0x00, 130)
	for _ in 0 ..< 129 {
		append(&out, 'p')
	}
	append(&out, 0)
	append(&out, ..buf[n - (2 + len(stock_peer_info_277) + 1):n])
	got: Key_Method
	used, err := keymethod_decode(out[:], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, used, len(out))
	testing.expect(t, got.username_too_long)
	testing.expect(t, got.password_too_long)
	testing.expect_value(t, got.username, "")
	testing.expect_value(t, got.password, "")
	testing.expect_value(t, got.peer_info, stock_peer_info_277)

	// 128 declared (127 characters) is the limit and is fine.
	km.username = string(long[:127])
	n, err = keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.None)
	_, err = keymethod_decode(buf[:n], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, !got.username_too_long)
	testing.expect_value(t, len(got.username), 127)
	km.username = string(long[:128])
	_, err = keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.Oversize)
}

@(test)
keymethod_encoder_rejects :: proc(t: ^testing.T) {
	buf: [KEY_METHOD_MAX_LEN]u8
	small: [10]u8
	km := client_msg()
	_, err := keymethod_encode(small[:], &km)
	testing.expect_value(t, err, Error.Buffer_Too_Small)

	km = client_msg()
	km.random = fake_random(64)
	_, err = keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.Bad_Argument)

	km = client_msg()
	km.random = make([]u8, KEY_METHOD_RANDOM_CLIENT, context.temp_allocator)
	_, err = keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.Zero_Random)

	km = client_msg("al\x00ice", "x")
	_, err = keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.Bad_Argument)

	srv := Key_Method {
		sender   = .Server,
		random   = fake_random(KEY_METHOD_RANDOM_SERVER),
		options  = stock_options_server,
		username = "alice",
	}
	_, err = keymethod_encode(buf[:], &srv)
	testing.expect_value(t, err, Error.Bad_Argument)

	// The whole message may not pass 2048 bytes.
	big := make([]u8, 2000, context.temp_allocator)
	for &c in big {
		c = 'v'
	}
	km = client_msg(peer_info = string(big))
	_, err = keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.Oversize)
}

@(test)
keymethod_message_without_peer_info :: proc(t: ^testing.T) {
	// Peer-info absent: the message ends after the password.
	km := client_msg(peer_info = "")
	buf: [KEY_METHOD_MAX_LEN]u8
	n, _ := keymethod_encode(buf[:], &km)
	got: Key_Method
	// The encoder writes 00 00; the decoder sees length 0 as absent.
	used, err := keymethod_decode(buf[:n], .Client, &got)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, used, n)
	testing.expect(t, !got.has_peer_info)
	// Cut before those two bytes: needs more, unless final.
	_, err = keymethod_decode(buf[:n - 2], .Client, &got)
	testing.expect_value(t, err, Error.Need_More)
	used, err = keymethod_decode(buf[:n - 2], .Client, &got, final = true)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, used, n - 2)
}

@(test)
keymethod_login_empty_user :: proc(t: ^testing.T) {
	// A token with no user: the stock client writes the empty username as
	// 00 01 00 (ssl.c write_string). Length 0 causes the server to drop the token.
	km := client_msg("", "tok")
	km.login = true
	buf: [KEY_METHOD_MAX_LEN]u8
	n, err := keymethod_encode(buf[:], &km)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, keymethod_encoded_len(&km), n)
	i := 117 + 2 + len(stock_options_client) + 1
	expect_bytes(t, buf[i:][:9], unhex("0001 00 0004 746f6b 00"), "login")
	got: Key_Method
	used, derr := keymethod_decode(buf[:n], .Client, &got, final = true)
	testing.expect_value(t, derr, Error.None)
	testing.expect_value(t, used, n)
	testing.expect_value(t, got.password, "tok")
	srv := Key_Method {
		sender = .Server,
		random = fake_random(KEY_METHOD_RANDOM_SERVER),
		login  = true,
	}
	_, err = keymethod_encode(buf[:], &srv)
	testing.expect_value(t, err, Error.Bad_Argument)
}
