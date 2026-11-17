// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:strings"
import "core:testing"

// A fixed "random" source for the tests: counts up from the seed.
@(private = "file")
test_rand_seed: u8

@(private = "file")
test_rand :: proc "contextless" (buf: []u8) -> bool {
	for i in 0 ..< len(buf) {
		buf[i] = test_rand_seed
		test_rand_seed += 1
	}
	return true
}

@(private = "file")
test_rand_fail :: proc "contextless" (buf: []u8) -> bool {
	return false
}

@(test)
ws_accept_key_rfc_example :: proc(t: ^testing.T) {
	// RFC 6455 section 1.3.
	got := ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==")
	testing.expect_value(t, string(got[:]), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
}

@(test)
ws_new_key_is_base64_of_16_bytes :: proc(t: ^testing.T) {
	test_rand_seed = 0
	key, ok := ws_new_key(test_rand)
	testing.expect(t, ok)
	testing.expect_value(t, string(key[:]), "AAECAwQFBgcICQoLDA0ODw==")
	_, ok = ws_new_key(test_rand_fail)
	testing.expect(t, !ok)
}

@(test)
ws_header_length_forms :: proc(t: ^testing.T) {
	h: [WS_HEADER_LEN_MAX]u8
	// 7-bit
	n := ws_header(h[:], WS_OP_BINARY, 5, nil)
	testing.expect_value(t, n, 2)
	testing.expect_value(t, h[0], u8(0x82))
	testing.expect_value(t, h[1], u8(5))
	n = ws_header(h[:], WS_OP_BINARY, 125, nil)
	testing.expect_value(t, n, 2)
	testing.expect_value(t, h[1], u8(125))
	// 16-bit
	n = ws_header(h[:], WS_OP_BINARY, 126, nil)
	testing.expect_value(t, n, 4)
	testing.expect_value(t, h[1], u8(126))
	testing.expect_value(t, int(h[2]) << 8 | int(h[3]), 126)
	n = ws_header(h[:], WS_OP_BINARY, 16368, [4]u8{1, 2, 3, 4})
	testing.expect_value(t, n, 8)
	testing.expect_value(t, h[1], u8(0x80 | 126))
	testing.expect_value(t, int(h[2]) << 8 | int(h[3]), 16368)
	testing.expect_value(t, [4]u8{h[4], h[5], h[6], h[7]}, [4]u8{1, 2, 3, 4})
	// 64-bit
	n = ws_header(h[:], WS_OP_BINARY, 70000, nil)
	testing.expect_value(t, n, 10)
	testing.expect_value(t, h[1], u8(127))
	v := 0
	for i in 0 ..< 8 {
		v = v << 8 | int(h[2 + i])
	}
	testing.expect_value(t, v, 70000)
	n = ws_header(h[:], WS_OP_PING, 3, [4]u8{9, 9, 9, 9})
	testing.expect_value(t, n, 6)
	testing.expect_value(t, h[0], u8(0x89))
}

@(test)
ws_mask_round_trip_and_offsets :: proc(t: ^testing.T) {
	key := [4]u8{0x37, 0xfa, 0x21, 0x3d}
	src: [37]u8
	for i in 0 ..< len(src) {
		src[i] = u8(i * 7 + 1)
	}
	a := src
	ws_mask(a[:], key)
	for i in 0 ..< len(src) {
		testing.expect_value(t, a[i], src[i] ~ key[i & 3])
	}
	ws_mask(a[:], key)
	testing.expect_value(t, a, src)
	// In pieces with an offset: same as in one pass.
	b := src
	ws_mask(b[:5], key, 0)
	ws_mask(b[5:19], key, 5)
	ws_mask(b[19:], key, 19)
	c := src
	ws_mask(c[:], key)
	testing.expect_value(t, b, c)
	// The copying form.
	d: [37]u8
	ws_mask_copy(d[:], src[:], key)
	testing.expect_value(t, d, c)
}

// Runs `bytes` through the receiver in pieces of `step` bytes. The data payloads are joined into `stream`; the
// other events are listed as text.
@(private = "file")
rx_run :: proc(r: ^Ws_Rx, bytes: []u8, step: int, stream: ^[dynamic]u8) -> string {
	events := strings.builder_make(context.temp_allocator)
	buf := make([]u8, len(bytes), context.temp_allocator)
	copy(buf, bytes)
	for off := 0; off < len(buf); off += step {
		rest := buf[off:min(off + step, len(buf))]
		for len(rest) > 0 {
			ev := ws_rx_next(r, rest)
			if ev.used == 0 {
				strings.write_string(&events, "STUCK;")
				return strings.to_string(events)
			}
			rest = rest[ev.used:]
			switch ev.kind {
			case .More:
			case .Data:
				append(stream, ..ev.data)
			case .Ping:
				strings.write_string(&events, "ping:")
				strings.write_string(&events, string(ev.data))
				strings.write_string(&events, ";")
			case .Pong:
				strings.write_string(&events, "pong;")
			case .Close:
				strings.write_string(&events, "close;")
			case .Error:
				strings.write_string(&events, "error:")
				strings.write_string(&events, ev.text)
				strings.write_string(&events, ";")
				return strings.to_string(events)
			}
		}
	}
	return strings.to_string(events)
}

// A frame as bytes: the header (masked with `key` if given), then the payload.
@(private = "file")
frame_bytes :: proc(op: u8, fin: bool, payload: []u8, key: Maybe([4]u8)) -> []u8 {
	h: [WS_HEADER_LEN_MAX]u8
	n := ws_header(h[:], op, len(payload), key)
	if !fin {
		h[0] &= 0x7f
	}
	out := make([]u8, n + len(payload), context.temp_allocator)
	copy(out, h[:n])
	copy(out[n:], payload)
	if k, ok := key.?; ok {
		ws_mask(out[n:], k)
	}
	return out
}

@(private = "file")
cat :: proc(parts: ..[]u8) -> []u8 {
	out := make([dynamic]u8, context.temp_allocator)
	for p in parts {
		append(&out, ..p)
	}
	return out[:]
}

@(test)
ws_rx_stream_split_across_frames :: proc(t: ^testing.T) {
	// One OpenVPN stream cut at odd places into frames, then delivered in pieces of every size.
	stream := make([]u8, 40000, context.temp_allocator)
	for i in 0 ..< len(stream) {
		stream[i] = u8(i * 31 + 7)
	}
	f1 := frame_bytes(WS_OP_BINARY, true, stream[:3], [4]u8{1, 2, 3, 4})
	f2 := frame_bytes(WS_OP_BINARY, true, stream[3:16000], [4]u8{9, 8, 7, 6})
	f3 := frame_bytes(WS_OP_BINARY, true, stream[16000:32000], [4]u8{5, 5, 5, 5})
	f4 := frame_bytes(WS_OP_BINARY, true, stream[32000:], [4]u8{0, 0, 0, 0})
	all := cat(f1, f2, f3, f4)
	for step in ([]int{1, 2, 3, 5, 7, 100, 4096, 100000}) {
		r := Ws_Rx {
			want_mask = true,
		}
		got: [dynamic]u8
		got.allocator = context.temp_allocator
		ev := rx_run(&r, all, step, &got)
		testing.expectf(t, ev == "", "step %d: events %s", step, ev)
		testing.expectf(t, string(got[:]) == string(stream), "step %d: stream differs (%d bytes)", step, len(got))
	}
}

@(test)
ws_rx_unmasked_from_server_and_fragments :: proc(t: ^testing.T) {
	// The client side: unmasked frames, a message in three fragments, and a 64-bit length form.
	f1 := frame_bytes(WS_OP_BINARY, false, []u8{1, 2, 3}, nil)
	f2 := frame_bytes(WS_OP_CONT, false, []u8{4, 5}, nil)
	f3 := frame_bytes(WS_OP_CONT, true, []u8{6}, nil)
	// A 64-bit length for 4 payload bytes (legal, if not minimal).
	f4 := cat([]u8{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 4, 7, 8, 9, 10})
	r := Ws_Rx{}
	got: [dynamic]u8
	got.allocator = context.temp_allocator
	ev := rx_run(&r, cat(f1, f2, f3, f4), 3, &got)
	testing.expect_value(t, ev, "")
	testing.expect_value(t, len(got), 10)
	testing.expect(t, got[0] == 1 && got[5] == 6 && got[9] == 10)
}

@(test)
ws_rx_control_frame_in_the_middle :: proc(t: ^testing.T) {
	// A ping between two data frames, and one inside a fragmented message; a pong; a close at the end.
	key := [4]u8{0xde, 0xad, 0xbe, 0xef}
	all := cat(
		frame_bytes(WS_OP_BINARY, false, []u8{'a', 'b'}, key),
		frame_bytes(WS_OP_PING, true, transmute([]u8)string("hello"), key),
		frame_bytes(WS_OP_CONT, true, []u8{'c'}, key),
		frame_bytes(WS_OP_PONG, true, nil, key),
		frame_bytes(WS_OP_PING, true, nil, key),
		frame_bytes(WS_OP_CLOSE, true, []u8{0x03, 0xe8}, key),
	)
	for step in ([]int{1, 2, 4, 1000}) {
		r := Ws_Rx {
			want_mask = true,
		}
		got: [dynamic]u8
		got.allocator = context.temp_allocator
		ev := rx_run(&r, all, step, &got)
		testing.expectf(t, ev == "ping:hello;pong;ping:;close;", "step %d: %s", step, ev)
		testing.expectf(t, string(got[:]) == "abc", "step %d: %s", step, string(got[:]))
	}
}

@(test)
ws_rx_protocol_errors :: proc(t: ^testing.T) {
	key := [4]u8{1, 2, 3, 4}
	check :: proc(t: ^testing.T, want_mask: bool, bytes: []u8, part: string, loc := #caller_location) {
		r := Ws_Rx {
			want_mask = want_mask,
		}
		got: [dynamic]u8
		got.allocator = context.temp_allocator
		ev := rx_run(&r, bytes, 1000, &got)
		testing.expectf(t, strings.contains(ev, "error:") && strings.contains(ev, part), "wanted an error with '%s', got '%s'", part, ev, loc = loc)
	}
	// The server needs a masked frame, the client an unmasked one.
	check(t, true, frame_bytes(WS_OP_BINARY, true, []u8{1}, nil), "not masked")
	check(t, false, frame_bytes(WS_OP_BINARY, true, []u8{1}, key), "is masked")
	// Text and reserved opcodes, RSV bits.
	check(t, false, frame_bytes(WS_OP_TEXT, true, []u8{1}, nil), "text frame")
	check(t, false, frame_bytes(3, true, []u8{1}, nil), "reserved opcode 3")
	check(t, false, frame_bytes(11, true, nil, nil), "reserved opcode 11")
	rsv := frame_bytes(WS_OP_BINARY, true, []u8{1}, nil)
	rsv[0] |= 0x40
	check(t, false, rsv, "reserved bits")
	// Control frames: fragmented, too long (7-bit and 16-bit length forms).
	check(t, false, frame_bytes(WS_OP_PING, false, []u8{1}, nil), "fragmented control")
	check(t, false, frame_bytes(WS_OP_PING, true, make([]u8, 126, context.temp_allocator), nil), "more than 125")
	// Messages: a continuation with nothing open, a new message inside a fragmented one.
	check(t, false, frame_bytes(WS_OP_CONT, true, []u8{1}, nil), "no message to continue")
	check(t, false, cat(frame_bytes(WS_OP_BINARY, false, []u8{1}, nil), frame_bytes(WS_OP_BINARY, true, []u8{1}, nil)), "inside a fragmented")
	// Lengths: above the limit, and with the top bit set.
	big := cat([]u8{0x82, 127, 0, 0, 0, 0, 0, 0, 0x40, 0x01})
	check(t, false, big, "limit")
	huge := cat([]u8{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1})
	check(t, false, huge, "top bit")
	// The limit itself is fine.
	ok := cat([]u8{0x82, 126, 0x40, 0x00})
	r := Ws_Rx{}
	ev := ws_rx_next(&r, ok)
	testing.expect(t, ev.kind != .Error)
}

@(test)
ws_out_frames_the_stream :: proc(t: ^testing.T) {
	// The server does not mask, the client does; a frame has at most WS_FRAME_MAX bytes; the receiver gets the stream back.
	src := make([]u8, 40000, context.temp_allocator)
	for i in 0 ..< len(src) {
		src[i] = u8(i * 13 + 3)
	}
	for masked in ([]bool{false, true}) {
		o: Ws_Out
		testing.expect(t, ws_out_init(&o, masked))
		defer ws_out_destroy(&o)
		test_rand_seed = 1
		o.rand = test_rand
		wire := make([dynamic]u8, context.temp_allocator)
		rest := src
		frames := 0
		for len(rest) > 0 {
			used, ok := ws_out_next(&o, rest)
			testing.expect(t, ok)
			testing.expect(t, used > 0 && used <= WS_FRAME_MAX)
			testing.expect(t, ws_out_pending(&o) <= WS_OUT_SIZE)
			append(&wire, ..o.buf[o.head:o.tail])
			o.head = o.tail
			rest = rest[used:]
			frames += 1
		}
		testing.expect_value(t, frames, 3)
		// The header of the first frame: binary, FIN, masked or not.
		testing.expect_value(t, wire[0], u8(0x82))
		testing.expect_value(t, wire[1] & 0x80 != 0, masked)
		r := Ws_Rx {
			want_mask = masked,
		}
		got: [dynamic]u8
		got.allocator = context.temp_allocator
		ev := rx_run(&r, wire[:], 1000, &got)
		testing.expect_value(t, ev, "")
		testing.expect(t, string(got[:]) == string(src))
		if masked {
			// Each frame has its own key: the second frame's key differs from the first's.
			k1 := [4]u8{wire[4], wire[5], wire[6], wire[7]}
			off := 8 + WS_FRAME_MAX
			k2 := [4]u8{wire[off + 4], wire[off + 5], wire[off + 6], wire[off + 7]}
			testing.expect(t, k1 != k2)
		}
	}
}

@(test)
ws_out_control_frames_go_between_frames :: proc(t: ^testing.T) {
	o: Ws_Out
	testing.expect(t, ws_out_init(&o, true))
	defer ws_out_destroy(&o)
	test_rand_seed = 0x10
	o.rand = test_rand
	// A pong waits; the next frame staged is the pong.
	testing.expect(t, ws_out_ctl(&o, WS_OP_PONG, transmute([]u8)string("hi")))
	testing.expect(t, ws_out_has_ctl(&o))
	used, ok := ws_out_next(&o, []u8{1, 2, 3})
	testing.expect(t, ok)
	testing.expect_value(t, used, 0)
	staged := o.buf[o.head:o.tail]
	r := Ws_Rx {
		want_mask = true,
	}
	ev := ws_rx_next(&r, staged)
	testing.expect_value(t, ev.kind, Ws_Kind.Pong)
	testing.expect(t, !ws_out_has_ctl(&o))
	// The ping's payload comes back in a ping: check a close and the payload of a pong.
	o.head = o.tail
	pl := ws_close_payload()
	testing.expect(t, ws_out_ctl(&o, WS_OP_CLOSE, pl[:]))
	used, ok = ws_out_next(&o, nil)
	testing.expect(t, ok && used == 0)
	r2 := Ws_Rx {
		want_mask = true,
	}
	ev = ws_rx_next(&r2, o.buf[o.head:o.tail])
	testing.expect_value(t, ev.kind, Ws_Kind.Close)
	testing.expect_value(t, ev.data[0], u8(0x03))
	testing.expect_value(t, ev.data[1], u8(0xe8))
	// A key that cannot be generated is reported.
	o.head = o.tail
	o.rand = test_rand_fail
	_, ok = ws_out_next(&o, []u8{1})
	testing.expect(t, !ok)
	testing.expect(t, !ws_out_ctl(&o, WS_OP_PONG, nil))
}

@(test)
ws_request_build_exact :: proc(t: ^testing.T) {
	key := transmute([]u8)string("dGhlIHNhbXBsZSBub25jZQ==")
	out, ok := ws_request_build("/vpn", "vpn.example", key, context.temp_allocator)
	testing.expect(t, ok)
	want := "GET /vpn HTTP/1.1\r\nHost: vpn.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	testing.expect_value(t, string(out), want)
	// Bad input.
	_, ok = ws_request_build("vpn", "h", key, context.temp_allocator)
	testing.expect(t, !ok)
	_, ok = ws_request_build("/v pn", "h", key, context.temp_allocator)
	testing.expect(t, !ok)
	_, ok = ws_request_build("/vpn", "h\r\nX: y", key, context.temp_allocator)
	testing.expect(t, !ok)
	_, ok = ws_request_build("/vpn", "", key, context.temp_allocator)
	testing.expect(t, !ok)
}

@(test)
ws_request_build_chrome_headers_and_order :: proc(t: ^testing.T) {
	key := transmute([]u8)string("dGhlIHNhbXBsZSBub25jZQ==")
	out, ok := ws_request_build("/vpn", "vpn.example", key, context.temp_allocator, .Chrome)
	testing.expect(t, ok)
	want := strings.concatenate(
		{
			"GET /vpn HTTP/1.1\r\n",
			"Host: vpn.example\r\n",
			"Connection: Upgrade\r\n",
			"Pragma: no-cache\r\n",
			"Cache-Control: no-cache\r\n",
			"User-Agent: ", WS_CHROME_USER_AGENT, "\r\n",
			"Upgrade: websocket\r\n",
			"Origin: https://vpn.example\r\n",
			"Sec-WebSocket-Version: 13\r\n",
			"Accept-Encoding: gzip, deflate, br, zstd\r\n",
			"Accept-Language: en-US,en;q=0.9\r\n",
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
			"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
			"\r\n",
		},
		context.temp_allocator,
	)
	testing.expect_value(t, string(out), want)
	testing.expect(t, strings.contains(string(out), "Chrome/142.0.0.0 Safari/537.36\r\n"))
	// The server accepts it as it accepts the plain one, and the client takes the plain reply.
	end, st := http_head_end(out)
	testing.expect_value(t, st, Http_Head.Done)
	testing.expect_value(t, end, len(out))
	r := ws_request_check(out[:end], "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Accept)
	testing.expect_value(t, r.key, "dGhlIHNhbXBsZSBub25jZQ==")
	reply := ws_reply_build(r.key, context.temp_allocator)
	res, _ := ws_reply_check(reply, key)
	testing.expect_value(t, res, Ws_Reply.Ok)
	// The same bad input is refused under the profile.
	_, ok = ws_request_build("vpn", "h", key, context.temp_allocator, .Chrome)
	testing.expect(t, !ok)
	_, ok = ws_request_build("/vpn", "h\r\nX: y", key, context.temp_allocator, .Chrome)
	testing.expect(t, !ok)
	// The default profile is the plain request.
	plain, _ := ws_request_build("/vpn", "vpn.example", key, context.temp_allocator, .Default)
	testing.expect(t, !strings.contains(string(plain), "User-Agent"))
}

@(test)
ws_host_header_port_and_brackets :: proc(t: ^testing.T) {
	testing.expect_value(t, ws_host_header("vpn.example", 443, context.temp_allocator), "vpn.example")
	testing.expect_value(t, ws_host_header("vpn.example", 8443, context.temp_allocator), "vpn.example:8443")
	testing.expect_value(t, ws_host_header("2001:db8::1", 443, context.temp_allocator), "[2001:db8::1]")
	testing.expect_value(t, ws_host_header("2001:db8::1", 8443, context.temp_allocator), "[2001:db8::1]:8443")
	testing.expect_value(t, ws_host_header("192.0.2.7", 1194, context.temp_allocator), "192.0.2.7:1194")
}

@(test)
ws_path_syntax :: proc(t: ^testing.T) {
	testing.expect(t, ws_path_ok("/"))
	testing.expect(t, ws_path_ok("/vpn"))
	testing.expect(t, !ws_path_ok(""))
	testing.expect(t, !ws_path_ok("vpn"))
	testing.expect(t, !ws_path_ok("/a b"))
	testing.expect(t, !ws_path_ok("/a\tb"))
	testing.expect(t, !ws_path_ok(strings.concatenate({"/", strings.repeat("a", 255, context.temp_allocator)}, context.temp_allocator)))
	testing.expect(t, ws_path_ok(strings.concatenate({"/", strings.repeat("a", 254, context.temp_allocator)}, context.temp_allocator)))
}

@(private = "file")
reply_for :: proc(extra: string, key: string) -> string {
	acc := ws_accept_key(key)
	return strings.concatenate({"HTTP/1.1 101 Switching Protocols\r\n", extra, "Sec-WebSocket-Accept: ", string(acc[:]), "\r\n\r\n"}, context.temp_allocator)
}

@(test)
ws_reply_accepted :: proc(t: ^testing.T) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	text := reply_for("Upgrade: websocket\r\nConnection: Upgrade\r\n", key)
	end, st := http_head_end(transmute([]u8)text)
	testing.expect_value(t, st, Http_Head.Done)
	testing.expect_value(t, end, len(text))
	res, line := ws_reply_check(transmute([]u8)text, transmute([]u8)key)
	testing.expect_value(t, res, Ws_Reply.Ok)
	testing.expect_value(t, line, "HTTP/1.1 101 Switching Protocols")
	// Case does not matter for names and values, and Connection is a list.
	text = reply_for("upgrade: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\n", key)
	res, _ = ws_reply_check(transmute([]u8)text, transmute([]u8)key)
	testing.expect_value(t, res, Ws_Reply.Ok)
	// The RFC example: the accept key of the RFC's key.
	rfc := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
	res, _ = ws_reply_check(transmute([]u8)rfc, transmute([]u8)key)
	testing.expect_value(t, res, Ws_Reply.Ok)
}

@(test)
ws_reply_refusals :: proc(t: ^testing.T) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	k := transmute([]u8)key
	res, line := ws_reply_check(transmute([]u8)string("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"), k)
	testing.expect_value(t, res, Ws_Reply.Refused)
	testing.expect_value(t, line, "HTTP/1.1 404 Not Found")
	res, _ = ws_reply_check(transmute([]u8)string("HTTP/1.1 200 OK\r\n\r\n"), k)
	testing.expect_value(t, res, Ws_Reply.Refused)
	res, _ = ws_reply_check(transmute([]u8)string("SSH-2.0-OpenSSH\r\n\r\n"), k)
	testing.expect_value(t, res, Ws_Reply.Not_Http)
	// 101 without the upgrade headers.
	res, _ = ws_reply_check(transmute([]u8)reply_for("Connection: Upgrade\r\n", key), k)
	testing.expect_value(t, res, Ws_Reply.Not_Upgrade)
	res, _ = ws_reply_check(transmute([]u8)reply_for("Upgrade: websocket\r\n", key), k)
	testing.expect_value(t, res, Ws_Reply.Not_Upgrade)
	res, _ = ws_reply_check(transmute([]u8)reply_for("Upgrade: h2c\r\nConnection: Upgrade\r\n", key), k)
	testing.expect_value(t, res, Ws_Reply.Not_Upgrade)
	// A wrong or missing accept key.
	res, _ = ws_reply_check(transmute([]u8)string("HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"), k)
	testing.expect_value(t, res, Ws_Reply.Bad_Accept)
	res, _ = ws_reply_check(transmute([]u8)string("HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), k)
	testing.expect_value(t, res, Ws_Reply.Bad_Accept)
}

@(test)
http_head_end_cases :: proc(t: ^testing.T) {
	end, st := http_head_end(transmute([]u8)string("GET / HTTP/1.1\r\nHost: x"))
	testing.expect_value(t, st, Http_Head.Need_More)
	end, st = http_head_end(transmute([]u8)string("GET / HTTP/1.1\r\nHost: x\r\n\r\nmore"))
	testing.expect_value(t, st, Http_Head.Done)
	testing.expect_value(t, end, 27)
	// Bare line feeds work too.
	end, st = http_head_end(transmute([]u8)string("GET / HTTP/1.1\nHost: x\n\nrest"))
	testing.expect_value(t, st, Http_Head.Done)
	testing.expect_value(t, end, 24)
	// A header that never ends.
	big := strings.repeat("X: y\r\n", 2000, context.temp_allocator)
	_, st = http_head_end(transmute([]u8)big)
	testing.expect_value(t, st, Http_Head.Too_Long)
	// A blank line after 8 KiB is too late.
	pad := strings.repeat("a", WS_HEADER_MAX, context.temp_allocator)
	_, st = http_head_end(transmute([]u8)strings.concatenate({"GET / HTTP/1.1\r\nX: ", pad, "\r\n\r\n"}, context.temp_allocator))
	testing.expect_value(t, st, Http_Head.Too_Long)
}

@(private = "file")
request_with :: proc(first: string, headers: string) -> string {
	return strings.concatenate({first, "\r\n", headers, "\r\n"}, context.temp_allocator)
}

@(test)
ws_request_verdicts :: proc(t: ^testing.T) {
	good := "Host: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
	r := ws_request_check(transmute([]u8)request_with("GET /vpn HTTP/1.1", good), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Accept)
	testing.expect_value(t, r.key, "dGhlIHNhbXBsZSBub25jZQ==")
	// Browsers and proxies: other case, an extra token in Connection.
	odd := "host: h\r\nupgrade: WebSocket\r\nconnection: keep-alive, Upgrade\r\nsec-websocket-key: abc\r\nsec-websocket-version: 13\r\n"
	r = ws_request_check(transmute([]u8)request_with("GET /vpn HTTP/1.1", odd), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Accept)
	// Wrong path wins over other faults.
	r = ws_request_check(transmute([]u8)request_with("GET /other HTTP/1.1", good), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Bad_Path)
	r = ws_request_check(transmute([]u8)request_with("GET /vpn/ HTTP/1.1", "Host: h\r\n"), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Bad_Path)
	// Not an upgrade, no key, no version.
	r = ws_request_check(transmute([]u8)request_with("GET /vpn HTTP/1.1", "Host: h\r\n"), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Not_Upgrade)
	nokey := "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
	r = ws_request_check(transmute([]u8)request_with("GET /vpn HTTP/1.1", nokey), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Not_Upgrade)
	nover := "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\n"
	r = ws_request_check(transmute([]u8)request_with("GET /vpn HTTP/1.1", nover), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Not_Upgrade)
	noconn := "Upgrade: websocket\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n"
	r = ws_request_check(transmute([]u8)request_with("GET /vpn HTTP/1.1", noconn), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Not_Upgrade)
	// A wrong version.
	v8 := "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 8\r\n"
	r = ws_request_check(transmute([]u8)request_with("GET /vpn HTTP/1.1", v8), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Bad_Version)
	testing.expect_value(t, r.version, "8")
	// A request line that is not one.
	r = ws_request_check(transmute([]u8)request_with("GET /vpn", good), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Not_Upgrade)
	r = ws_request_check(transmute([]u8)request_with("GET /vpn SPDY/3", good), "/vpn")
	testing.expect_value(t, r.verdict, Ws_Verdict.Not_Upgrade)
	// The refusal texts.
	testing.expect(t, strings.has_prefix(ws_refusal(.Bad_Path), "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
	testing.expect(t, strings.has_prefix(ws_refusal(.Not_Upgrade), "HTTP/1.1 400 Bad Request\r\n"))
	testing.expect(t, strings.contains(ws_refusal(.Bad_Version), "426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\n"))
}

@(test)
ws_server_reply_matches_client_check :: proc(t: ^testing.T) {
	key, _ := ws_new_key(test_rand)
	reply := ws_reply_build(string(key[:]), context.temp_allocator)
	testing.expect(t, strings.has_prefix(string(reply), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "))
	end, st := http_head_end(reply)
	testing.expect_value(t, st, Http_Head.Done)
	res, _ := ws_reply_check(reply[:end], key[:])
	testing.expect_value(t, res, Ws_Reply.Ok)
}

@(test)
ws_classify_plain_bytes :: proc(t: ^testing.T) {
	testing.expect_value(t, classify_plain(nil), Plain_Bytes.Need_More)
	testing.expect_value(t, classify_plain([]u8{'G'}), Plain_Bytes.Need_More)
	testing.expect_value(t, classify_plain([]u8{'G', 'E', 'T'}), Plain_Bytes.Need_More)
	testing.expect_value(t, classify_plain([]u8{'G', 'E', 'T', ' '}), Plain_Bytes.Http)
	testing.expect_value(t, classify_plain([]u8{'G', 'E', 'T', ' ', '/'}), Plain_Bytes.Http)
	// A raw OpenVPN stream: the length of the first packet, then the opcode byte.
	testing.expect_value(t, classify_plain([]u8{0x00, 0x0e, 0x38}), Plain_Bytes.Raw)
	testing.expect_value(t, classify_plain([]u8{'P'}), Plain_Bytes.Raw)
	testing.expect_value(t, classify_plain([]u8{'G', 'X'}), Plain_Bytes.Raw)
	// The framing cannot start with "GE": that length is 18245.
	testing.expect_value(t, int('G') << 8 | int('E'), 18245)
}
