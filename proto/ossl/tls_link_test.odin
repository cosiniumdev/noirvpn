// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package ossl

import "core:sys/linux"
import "core:testing"

// --- link sessions: the custom BIO over a socket pair ---
//
// The hooks play the part of `platform/tlslink`. They keep the bytes the library
// writes in a small buffer, and read from fed bytes first, then from a socket.
// The test moves the buffer to the socket by hand.

@(private = "file")
Hook :: struct {
	fd:      linux.Fd, // our end of the socket pair
	out:     [4096]u8,
	out_n:   int,
	room:    int, // the most `out` takes (a small value causes the library to retry)
	full:    int, // times `write` found no room
	fed:     []u8, // read before the socket
	fed_at:  int,
	retries: int, // times `read` found nothing
	end:     bool, // the socket said end of stream
	reads:   int, // successful socket reads
}

@(private = "file")
hook_write :: proc "c" (user: rawptr, data: [^]u8, n: int) -> int {
	h := (^Hook)(user)
	m := min(n, h.room - h.out_n)
	if m <= 0 {
		h.full += 1
		return 0
	}
	copy(h.out[h.out_n:][:m], data[:m])
	h.out_n += m
	return m
}

@(private = "file")
hook_read :: proc "c" (user: rawptr, buf: [^]u8, n: int) -> int {
	h := (^Hook)(user)
	if h.fed_at < len(h.fed) {
		m := min(n, len(h.fed) - h.fed_at)
		copy(buf[:m], h.fed[h.fed_at:][:m])
		h.fed_at += m
		return m
	}
	got, e := linux.recv(h.fd, buf[:n], {.DONTWAIT})
	if e == .EAGAIN {
		h.retries += 1
		return IO_RETRY
	}
	if e != .NONE {
		return IO_ERROR
	}
	if got == 0 {
		h.end = true
		return IO_END
	}
	h.reads += 1
	return got
}

@(private = "file")
hook_pending_in :: proc "c" (user: rawptr) -> int {
	h := (^Hook)(user)
	return len(h.fed) - h.fed_at
}

@(private = "file")
hook_pending_out :: proc "c" (user: rawptr) -> int {
	return (^Hook)(user).out_n
}

@(private = "file")
hook_io :: proc(h: ^Hook) -> Link_Io {
	return {user = h, write = hook_write, read = hook_read, pending_in = hook_pending_in, pending_out = hook_pending_out}
}

// Sends what the library wrote to the socket (all of it: the socket pair has room).
@(private = "file")
hook_send :: proc(h: ^Hook) {
	sent := 0
	for sent < h.out_n {
		n, e := linux.send(h.fd, h.out[sent:h.out_n], {.DONTWAIT, .NOSIGNAL})
		if e != .NONE {
			break
		}
		sent += n
	}
	copy(h.out[:], h.out[sent:h.out_n])
	h.out_n -= sent
}

@(private = "file")
Lpair :: struct {
	cctx, sctx: Tls_Ctx,
	c, s:       Tls_Session,
	ch, sh:     Hook, // the hooks of the client and of the server
	fds:        [2]linux.Fd,
}

// Sets up two link sessions in place (they must not move).
@(private = "file")
lpair_init :: proc(t: ^testing.T, p: ^Lpair, room := 4096, max_version := Tls_Version.Any) -> bool {
	if e := linux.socketpair(.UNIX, .STREAM, {}, &p.fds); !testing.expect_value(t, e, linux.Errno.NONE) {
		return false
	}
	p.ch.fd, p.sh.fd = p.fds[0], p.fds[1]
	p.ch.room, p.sh.room = room, room
	ccfg := outer(.Client, {})
	scfg := outer(.Server, P256_SERVER)
	ccfg.max_version, scfg.max_version = max_version, max_version
	err: Error
	p.cctx, err = tls_ctx_create(ccfg)
	if !testing.expect_value(t, err, Error.None) {
		return false
	}
	p.sctx, err = tls_ctx_create(scfg)
	if !testing.expect_value(t, err, Error.None) {
		return false
	}
	if !testing.expect_value(t, tls_session_init_link(&p.c, &p.cctx, hook_io(&p.ch)), Error.None) {
		return false
	}
	return testing.expect_value(t, tls_session_init_link(&p.s, &p.sctx, hook_io(&p.sh)), Error.None)
}

@(private = "file")
lpair_destroy :: proc(p: ^Lpair) {
	tls_session_destroy(&p.c)
	tls_session_destroy(&p.s)
	tls_ctx_destroy(&p.cctx)
	tls_ctx_destroy(&p.sctx)
	linux.close(p.fds[0])
	linux.close(p.fds[1])
}

@(private = "file")
lpair_handshake :: proc(t: ^testing.T, p: ^Lpair) -> bool {
	cs, ss := Handshake_Status.Want_More, Handshake_Status.Want_More
	for _ in 0 ..< 1000 {
		if cs == .Want_More {
			cs = tls_handshake_step(&p.c)
		}
		hook_send(&p.ch)
		if ss == .Want_More {
			ss = tls_handshake_step(&p.s)
		}
		hook_send(&p.sh)
		if cs != .Want_More && ss != .Want_More {
			break
		}
	}
	ok := cs == .Done && ss == .Done
	testing.expectf(t, ok, "link handshake: client %v (%s), server %v (%s)", cs, tls_last_error(&p.c), ss, tls_last_error(&p.s))
	return ok
}

// Writes `data` on `s`, moving the output to the socket until the library
// has taken all of it (a small `room` causes it to ask again with the same data).
@(private = "file")
lpair_write :: proc(t: ^testing.T, s: ^Tls_Session, h: ^Hook, data: []u8) -> bool {
	for _ in 0 ..< 1000 {
		switch tls_write_app(s, data) {
		case .Ok:
			hook_send(h)
			return true
		case .Want_More:
			hook_send(h) // frees room
		case .Failed, .Not_Ready, .Closed:
			testing.expectf(t, false, "link write failed: %s", tls_last_error(s))
			return false
		}
	}
	testing.expect(t, false, "link write did not finish")
	return false
}

// Reads exactly `want` bytes from `s` (they must be on their way already).
@(private = "file")
lpair_read :: proc(t: ^testing.T, s: ^Tls_Session, want: int) -> []u8 {
	out := make([]u8, want, context.temp_allocator)
	have := 0
	for have < want {
		n, st := tls_read_app(s, out[have:])
		if st != .Ok {
			testing.expectf(t, false, "link read stopped after %d of %d bytes: %v %s", have, want, st, tls_last_error(s))
			break
		}
		have += n
	}
	return out[:have]
}

@(test)
link_session_handshake_and_data_over_a_socket_pair :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	// Room for 700 bytes only: every handshake flight is cut and retried.
	if !lpair_init(t, &p, 700) || !lpair_handshake(t, &p) {
		return
	}
	testing.expect(t, p.ch.full > 0 || p.sh.full > 0, "the write hook ran out of room (retry-write)")
	testing.expect_value(t, tls_version_name(&p.c), "TLSv1.3")
	testing.expect_value(t, tls_state(&p.c), Tls_State.Established)
	// A link session takes nothing by `tls_feed` and gives nothing to `tls_take`.
	testing.expect(t, !tls_feed(&p.s, transmute([]u8)string("x")))
	small: [8]u8
	testing.expect_value(t, tls_take(&p.s, small[:]), 0)
	// A record of 3000 bytes does not fit the 700 byte room: the write waits for
	// room (`.Want_More`), is called again with the same data, and ends.
	data := make([]u8, 3000, context.temp_allocator)
	for &b, i in data {
		b = u8(i * 5)
	}
	full_before := p.ch.full
	testing.expect(t, lpair_write(t, &p.c, &p.ch, data))
	testing.expect(t, p.ch.full > full_before, "the record was cut")
	got := lpair_read(t, &p.s, len(data))
	expect_bytes(t, got, data, "client to server")
	// And back.
	testing.expect(t, lpair_write(t, &p.s, &p.sh, data[:1000]))
	got = lpair_read(t, &p.c, 1000)
	expect_bytes(t, got, data[:1000], "server to client")
	// Nothing more: the socket has nothing, the read waits.
	buf: [16]u8
	_, st := tls_read_app(&p.c, buf[:])
	testing.expect_value(t, st, Io_Status.Want_More)
	testing.expect(t, p.ch.retries > 0)
	testing.expect(t, !tls_has_input(&p.c))
}

@(test)
link_session_pending_counts_follow_the_hooks :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	if !lpair_init(t, &p) {
		return
	}
	testing.expect_value(t, tls_pending_out(&p.c), 0)
	tls_handshake_step(&p.c)
	testing.expect(t, p.ch.out_n > 0, "the ClientHello is in the output")
	testing.expect_value(t, tls_pending_out(&p.c), p.ch.out_n)
	p.sh.fed = make([]u8, 40, context.temp_allocator)
	testing.expect_value(t, bio_pending(p.s.rbio), 40)
	testing.expect(t, tls_has_input(&p.s), "fed bytes count as input")
}

@(test)
link_session_reads_fed_bytes_first :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	if !lpair_init(t, &p) {
		return
	}
	// The client's first flight: the first 100 bytes are fed to the server
	// hook, the rest goes through the socket. The server must see one stream.
	tls_handshake_step(&p.c)
	hello := make([]u8, p.ch.out_n, context.temp_allocator)
	copy(hello, p.ch.out[:p.ch.out_n])
	p.ch.out_n = 0
	testing.expect(t, len(hello) > 100)
	p.sh.fed = hello[:100]
	_, e := linux.send(p.ch.fd, hello[100:], {.NOSIGNAL})
	testing.expect_value(t, e, linux.Errno.NONE)
	if !lpair_handshake(t, &p) {
		return
	}
	testing.expect_value(t, p.sh.fed_at, 100)
	testing.expect(t, p.sh.reads > 0)
}

@(test)
link_session_end_of_stream_is_seen :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	if !lpair_init(t, &p) || !lpair_handshake(t, &p) {
		return
	}
	// The client's end goes away without a close_notify.
	linux.shutdown(p.ch.fd, .WR)
	buf: [16]u8
	_, st := tls_read_app(&p.s, buf[:])
	testing.expect(t, st != .Ok && st != .Want_More, "an end of stream without close_notify is no data and no wait")
	testing.expect(t, p.sh.end, "the hook saw the end")
}

@(test)
link_session_close_notify :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	if !lpair_init(t, &p) || !lpair_handshake(t, &p) {
		return
	}
	testing.expect(t, tls_shutdown(&p.c))
	hook_send(&p.ch)
	buf: [16]u8
	_, st := tls_read_app(&p.s, buf[:])
	testing.expect_value(t, st, Io_Status.Closed)
	testing.expect(t, !p.sh.end, "a close_notify is no end of stream")
}

@(test)
link_session_key_update_both_ways :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	if !lpair_init(t, &p, 700) || !lpair_handshake(t, &p) {
		return
	}
	testing.expect(t, tls_is_tls13(&p.c))
	msg := make([]u8, 500, context.temp_allocator)
	for round in 0 ..< 3 {
		for &b, i in msg {
			b = u8(i + round)
		}
		// Our update: the message goes out ahead of the next data.
		testing.expect(t, tls_key_update(&p.c))
		testing.expect(t, lpair_write(t, &p.c, &p.ch, msg))
		expect_bytes(t, lpair_read(t, &p.s, len(msg)), msg, "after a client key update")
		testing.expect(t, tls_key_update(&p.s))
		testing.expect(t, lpair_write(t, &p.s, &p.sh, msg))
		expect_bytes(t, lpair_read(t, &p.c, len(msg)), msg, "after a server key update")
	}
}

@(test)
link_session_answers_a_requested_key_update :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	if !lpair_init(t, &p) || !lpair_handshake(t, &p) {
		return
	}
	// The client updates and asks the server to do the same (type 1).
	testing.expect_value(t, SSL_key_update(p.c.ssl, 1), cint(1))
	msg := transmute([]u8)string("please answer")
	testing.expect(t, lpair_write(t, &p.c, &p.ch, msg))
	testing.expect_value(t, p.sh.out_n, 0)
	expect_bytes(t, lpair_read(t, &p.s, len(msg)), msg, "the data behind the request")
	// The server takes the request in. When its response leaves differs between
	// the libraries (at once, at its next read, or with its next write). The
	// test only needs it to leave with the next data at the latest.
	buf: [16]u8
	_, st := tls_read_app(&p.s, buf[:])
	testing.expect_value(t, st, Io_Status.Want_More)
	hook_send(&p.sh)
	// Both directions work with the new keys.
	testing.expect(t, lpair_write(t, &p.s, &p.sh, msg))
	expect_bytes(t, lpair_read(t, &p.c, len(msg)), msg, "server to client after the update")
	testing.expect(t, lpair_write(t, &p.c, &p.ch, msg))
	expect_bytes(t, lpair_read(t, &p.s, len(msg)), msg, "client to server after the update")
}

@(test)
link_session_has_no_key_update_on_tls12 :: proc(t: ^testing.T) {
	p: Lpair
	defer lpair_destroy(&p)
	if !lpair_init(t, &p, 4096, .TLS_1_2) || !lpair_handshake(t, &p) {
		return
	}
	testing.expect_value(t, tls_version_name(&p.c), "TLSv1.2")
	testing.expect(t, !tls_is_tls13(&p.c))
	testing.expect(t, !tls_key_update(&p.c))
	msg := transmute([]u8)string("tls 1.2 data")
	testing.expect(t, lpair_write(t, &p.c, &p.ch, msg))
	expect_bytes(t, lpair_read(t, &p.s, len(msg)), msg, "tls 1.2 data")
}

@(test)
link_session_init_checks_its_arguments :: proc(t: ^testing.T) {
	ctx, err := tls_ctx_create(outer(.Client, {}))
	testing.expect_value(t, err, Error.None)
	defer tls_ctx_destroy(&ctx)
	s: Tls_Session
	testing.expect_value(t, tls_session_init_link(&s, &ctx, {}), Error.Bad_Argument)
	h: Hook
	testing.expect_value(t, tls_session_init_link(&s, &ctx, hook_io(&h)), Error.None)
	tls_session_destroy(&s)
}

// --- the ClientHello profile `.Chrome` ---

// What a ClientHello holds, for the tests below.
@(private = "file")
Hello_Info :: struct {
	ciphers: [dynamic]u16,
	exts:    [dynamic]u16,
	sigalgs: [dynamic]u16,
	alpn:    [dynamic]string,
}

// A `Hello_Info` whose lists live in the temporary allocator.
@(private = "file")
hello_info :: proc() -> Hello_Info {
	a := context.temp_allocator
	return {ciphers = make([dynamic]u16, a), exts = make([dynamic]u16, a), sigalgs = make([dynamic]u16, a), alpn = make([dynamic]string, a)}
}

@(private = "file")
be16 :: proc(b: []u8) -> u16 {
	return u16(b[0]) << 8 | u16(b[1])
}

// Takes a ClientHello (the first record) apart. False if it is not one.
@(private = "file")
hello_parse :: proc(rec: []u8, h: ^Hello_Info) -> bool {
	if len(rec) < 9 + 34 || rec[0] != 0x16 || rec[5] != 1 {
		return false
	}
	b := rec[9:] // after the handshake header
	p := 2 + 32
	p += 1 + int(b[p]) // session id
	n := int(be16(b[p:]))
	p += 2
	for i := 0; i < n; i += 2 {
		append(&h.ciphers, be16(b[p + i:]))
	}
	p += n
	p += 1 + int(b[p]) // compression
	end := p + 2 + int(be16(b[p:]))
	p += 2
	for p + 4 <= end && p + 4 <= len(b) {
		typ, l := be16(b[p:]), int(be16(b[p + 2:]))
		p += 4
		append(&h.exts, typ)
		body := b[p:p + l]
		switch typ {
		case 13:
			for i := 2; i + 2 <= len(body); i += 2 {
				append(&h.sigalgs, be16(body[i:]))
			}
		case 16:
			for i := 2; i < len(body); {
				m := int(body[i])
				append(&h.alpn, string(body[i + 1:i + 1 + m]))
				i += 1 + m
			}
		}
		p += l
	}
	return true
}

@(private = "file")
chrome_pair :: proc(t: ^testing.T, p: ^Pair, hello: Hello_Profile) -> bool {
	cfg := outer(.Client, {}, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
	cfg.groups = "X25519MLKEM768:X25519:P-256:P-384"
	cfg.hello = hello
	return pair_init(t, p, cfg, outer(.Server, P256_SERVER, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"))
}

@(test)
chrome_profile_handshakes_with_the_default_server :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !chrome_pair(t, &p, .Chrome) {
		return
	}
	testing.expect_value(t, p.cctx.hello, Hello_Profile.Chrome)
	testing.expect_value(t, p.sctx.hello, Hello_Profile.Default)
	testing.expect(t, tls_session_set_sni(&p.c, "vpn.example"))
	testing.expect(t, tls_session_set_alpn(&p.c, {"h2", "http/1.1"}))
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect_value(t, tls_version_name(&p.c), "TLSv1.3")
	// Our server never selects an ALPN protocol.
	testing.expect_value(t, tls_alpn_selected(&p.c), "")
	c := tls_cipher_name(&p.c)
	testing.expectf(t, c == "TLS_AES_128_GCM_SHA256" || c == "TLS_AES_256_GCM_SHA384" || c == "TLS_CHACHA20_POLY1305_SHA256", "cipher %s", c)
	msg := transmute([]u8)string("hello through the chrome profile")
	testing.expect_value(t, tls_write_app(&p.c, msg), Io_Status.Ok)
	tls_move(&p.c, &p.s)
	got: [64]u8
	n, st := tls_read_app(&p.s, got[:])
	testing.expect_value(t, st, Io_Status.Ok)
	testing.expect_value(t, string(got[:n]), string(msg))
}

@(test)
chrome_profile_client_hello :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !chrome_pair(t, &p, .Chrome) {
		return
	}
	testing.expect(t, tls_session_set_alpn(&p.c, {"h2", "http/1.1"}))
	tls_handshake_step(&p.c)
	rec := make([]u8, tls_pending_out(&p.c), context.temp_allocator)
	tls_take(&p.c, rec)
	h := hello_info()
	if !testing.expect(t, hello_parse(rec, &h), "a ClientHello") {
		return
	}
	// 15 suites, in Chrome's order (a GREASE value may come first on AWS-LC).
	want := [?]u16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	got := make([dynamic]u16, context.temp_allocator)
	for c in h.ciphers {
		if c & 0x0f0f != 0x0a0a { // not GREASE
			append(&got, c)
		}
	}
	testing.expect_value(t, len(got), len(want))
	for w, i in want {
		if i < len(got) {
			testing.expectf(t, got[i] == w, "suite %d is 0x%04x, want 0x%04x", i, got[i], w)
		}
	}
	// The eight signature algorithms, in order.
	sw := [?]u16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	sgot := make([dynamic]u16, context.temp_allocator)
	for s in h.sigalgs {
		if s & 0x0f0f != 0x0a0a {
			append(&sgot, s)
		}
	}
	testing.expect_value(t, len(sgot), len(sw))
	for w, i in sw {
		if i < len(sgot) {
			testing.expectf(t, sgot[i] == w, "signature algorithm %d is 0x%04x, want 0x%04x", i, sgot[i], w)
		}
	}
	has :: proc(h: ^Hello_Info, e: u16) -> bool {
		for x in h.exts {
			if x == e {
				return true
			}
		}
		return false
	}
	testing.expect(t, has(&h, 35), "the session ticket extension is there")
	testing.expect(t, has(&h, 5), "status_request is there")
	testing.expect(t, !has(&h, 22), "no encrypt_then_mac") // AWS-LC never sends it
	testing.expect_value(t, len(h.alpn), 2)
	if len(h.alpn) == 2 {
		testing.expect_value(t, h.alpn[0], "h2")
		testing.expect_value(t, h.alpn[1], "http/1.1")
	}
	when NOIR_CRYPTO == "awslc" {
		testing.expect(t, has(&h, 17613), "ALPS, new codepoint")
		testing.expect(t, has(&h, 65037), "ECH GREASE")
		testing.expect(t, has(&h, 27), "compress_certificate")
		testing.expect(t, has(&h, 18), "signed_certificate_timestamp")
	}
}

@(test)
chrome_profile_http11_alone_has_no_alps :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !chrome_pair(t, &p, .Chrome) {
		return
	}
	testing.expect(t, tls_session_set_alpn(&p.c, {"http/1.1"}))
	tls_handshake_step(&p.c)
	rec := make([]u8, tls_pending_out(&p.c), context.temp_allocator)
	tls_take(&p.c, rec)
	h := hello_info()
	if !testing.expect(t, hello_parse(rec, &h), "a ClientHello") {
		return
	}
	testing.expect_value(t, len(h.alpn), 1)
	for x in h.exts {
		testing.expectf(t, x != 17613 && x != 17513, "no ALPS extension, got %d", x)
	}
}

@(test)
default_profile_has_no_ticket_extension :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !chrome_pair(t, &p, .Default) {
		return
	}
	tls_handshake_step(&p.c)
	rec := make([]u8, tls_pending_out(&p.c), context.temp_allocator)
	tls_take(&p.c, rec)
	h := hello_info()
	if !testing.expect(t, hello_parse(rec, &h), "a ClientHello") {
		return
	}
	for x in h.exts {
		testing.expect(t, x != 35, "no session ticket extension under the default profile")
	}
}

@(test)
chrome_profile_is_for_clients_only :: proc(t: ^testing.T) {
	cfg := outer(.Server, P256_SERVER)
	cfg.hello = .Chrome
	ctx, err := tls_ctx_create(cfg)
	testing.expect_value(t, err, Error.None)
	defer tls_ctx_destroy(&ctx)
	testing.expect_value(t, ctx.hello, Hello_Profile.Default)
}
