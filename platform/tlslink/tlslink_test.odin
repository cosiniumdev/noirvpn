// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package tlslink

import cnet "core:net"
import "core:testing"
import "core:time"
import net "noir:platform/net"
import "noir:proto/ossl"

// The outer TLS link over loopback TCP: the handshake from both ends, reads
// that arrive a byte at a time, a write larger than the socket buffers, close
// notices, and a peer that does not speak TLS.

CERT_PEM := #load("../../proto/ossl/testdata/p256_server.crt.pem")
KEY_PEM := #load("../../proto/ossl/testdata/p256_server.key.pem")
SPKI_DER := #load("../../proto/ossl/testdata/p256_server.spki.der")

@(private = "file")
LO4 :: cnet.Endpoint {
	address = cnet.IP4_Address{127, 0, 0, 1},
	port    = 0,
}

@(private = "file")
Pair :: struct {
	cctx, sctx: ossl.Tls_Ctx,
	c, s:       Link,
	cout, sout: [OUT_BUF_SIZE]u8,
	csock:      net.Socket,
	ssock:      net.Socket,
}

// Two connected TCP sockets. `client_opts` are for the connecting side.
@(private = "file")
sockets :: proc(t: ^testing.T, client_opts: net.TCP_Options = {}) -> (c, s: net.Socket, ok: bool) {
	l, lerr := net.tcp_listen(LO4)
	if !testing.expect_value(t, lerr, net.Error.None) {
		return {}, {}, false
	}
	defer net.close(l)
	lep, _ := net.local_endpoint(l)
	cs, _, cerr := net.tcp_connect(lep, client_opts)
	if !testing.expect_value(t, cerr, net.Error.None) {
		return {}, {}, false
	}
	for _ in 0 ..< 500 {
		if net.tcp_connect_finish(cs) != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	for _ in 0 ..< 500 {
		ss, _, aerr := net.tcp_accept(l)
		if aerr == .None {
			return cs, ss, true
		}
		time.sleep(time.Millisecond)
	}
	net.close(cs)
	testing.expect(t, false, "no connection accepted")
	return {}, {}, false
}

@(private = "file")
pair_init :: proc(t: ^testing.T, p: ^Pair, client_opts: net.TCP_Options = {}, sni := "", max_version := ossl.Tls_Version.Any) -> bool {
	ok: bool
	p.csock, p.ssock, ok = sockets(t, client_opts)
	if !ok {
		return false
	}
	err: ossl.Error
	p.cctx, err = ossl.tls_ctx_create({role = .Client, min_version = .TLS_1_2, max_version = max_version, verify = .None})
	testing.expect_value(t, err, ossl.Error.None)
	p.sctx, err = ossl.tls_ctx_create({role = .Server, min_version = .TLS_1_2, max_version = max_version, verify = .None, cert_pem = CERT_PEM, key_pem = KEY_PEM})
	testing.expect_value(t, err, ossl.Error.None)
	testing.expect_value(t, link_init(&p.c, &p.cctx, p.csock, p.cout[:], sni, {"http/1.1"}), Error.None)
	testing.expect_value(t, link_init(&p.s, &p.sctx, p.ssock, p.sout[:]), Error.None)
	return true
}

@(private = "file")
pair_destroy :: proc(p: ^Pair) {
	link_destroy(&p.c)
	link_destroy(&p.s)
	ossl.tls_ctx_destroy(&p.cctx)
	ossl.tls_ctx_destroy(&p.sctx)
	net.close(p.csock)
	net.close(p.ssock)
}

// Runs both handshakes until each is `.Done` or `.Failed`.
@(private = "file")
handshake :: proc(p: ^Pair) -> (cs, ss: Hs_Status) {
	start := time.tick_now()
	cs, ss = .Want_Read, .Want_Read
	for time.tick_since(start) < 5 * time.Second {
		if cs != .Done && cs != .Failed {
			cs = link_handshake(&p.c)
		}
		if ss != .Done && ss != .Failed {
			ss = link_handshake(&p.s)
		}
		if (cs == .Done || cs == .Failed) && (ss == .Done || ss == .Failed) {
			return
		}
		time.sleep(time.Millisecond)
	}
	return
}

@(private = "file")
flush_all :: proc(l: ^Link) {
	start := time.tick_now()
	for time.tick_since(start) < 5 * time.Second {
		pending, err := link_flush(l)
		if pending == 0 || err != .None {
			return
		}
		time.sleep(time.Millisecond)
	}
}

// Reads exactly `want` bytes (or stops at an error or 5 s).
@(private = "file")
read_exactly :: proc(l: ^Link, want: int) -> (got: []u8, err: Error) {
	out := make([]u8, want, context.temp_allocator)
	have := 0
	start := time.tick_now()
	for have < want && time.tick_since(start) < 10 * time.Second {
		n, rerr := link_read(l, out[have:])
		if rerr == .Would_Block {
			time.sleep(time.Millisecond)
			continue
		}
		if rerr != .None {
			return out[:have], rerr
		}
		have += n
	}
	return out[:have], .None
}

@(test)
handshake_and_data_both_ways :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, sni = "vpn.example.org") {
		return
	}
	cs, ss := handshake(&p)
	testing.expect_value(t, cs, Hs_Status.Done)
	testing.expect_value(t, ss, Hs_Status.Done)
	if cs != .Done || ss != .Done {
		return
	}
	// The client knows the server's key; the server asked for no certificate.
	testing.expect(t, p.c.peer_ok)
	want := ossl.sha256(SPKI_DER)
	testing.expect_value(t, p.c.peer.spki_sha256, want)
	testing.expect(t, !p.s.peer_ok)
	testing.expect_value(t, ossl.tls_server_name(&p.s.s), "vpn.example.org")
	// A second call after Done changes nothing.
	testing.expect_value(t, link_handshake(&p.c), Hs_Status.Done)

	msg := "hello over TLS"
	testing.expect_value(t, link_write(&p.c, transmute([]u8)msg), Error.None)
	testing.expect(t, link_pending(&p.c) > len(msg))
	_, ferr := link_flush(&p.c)
	testing.expect_value(t, ferr, Error.None)
	got, rerr := read_exactly(&p.s, len(msg))
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, string(got), msg)

	reply := "and back"
	testing.expect_value(t, link_write(&p.s, transmute([]u8)reply), Error.None)
	flush_all(&p.s)
	got, rerr = read_exactly(&p.c, len(reply))
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, string(got), reply)

	// Nothing more to read.
	buf: [16]u8
	_, rerr = link_read(&p.c, buf[:])
	testing.expect_value(t, rerr, Error.Would_Block)
	testing.expect_value(t, link_pending(&p.c), 0)
}

@(test)
reads_may_arrive_a_byte_at_a_time :: proc(t: ^testing.T) {
	// A relay between the two links passes one byte at a time each way, so the
	// TLS library gets the handshake and records in one-byte pieces.
	p: Pair
	defer pair_destroy(&p)
	ok: bool
	relay_a, relay_b: net.Socket
	p.csock, relay_a, ok = sockets(t)
	if !ok {
		return
	}
	defer net.close(relay_a)
	relay_b, p.ssock, ok = sockets(t)
	if !ok {
		net.close(p.csock)
		return
	}
	defer net.close(relay_b)
	err: ossl.Error
	p.cctx, err = ossl.tls_ctx_create({role = .Client, min_version = .TLS_1_2, verify = .None})
	testing.expect_value(t, err, ossl.Error.None)
	p.sctx, err = ossl.tls_ctx_create({role = .Server, min_version = .TLS_1_2, verify = .None, cert_pem = CERT_PEM, key_pem = KEY_PEM})
	testing.expect_value(t, err, ossl.Error.None)
	testing.expect_value(t, link_init(&p.c, &p.cctx, p.csock, p.cout[:]), Error.None)
	testing.expect_value(t, link_init(&p.s, &p.sctx, p.ssock, p.sout[:]), Error.None)

	cs, ss := Hs_Status.Want_Read, Hs_Status.Want_Read
	big := make([]u8, 5000, context.temp_allocator)
	for &b, i in big {
		b = u8(i * 7)
	}
	sent := false
	got: [dynamic]u8
	got.allocator = context.temp_allocator
	one: [1]u8
	start := time.tick_now()
	for time.tick_since(start) < 20 * time.Second && len(got) < len(big) {
		// The relay: one byte each way.
		if n, rerr := net.stream_recv(relay_a, one[:]); rerr == .None && n == 1 {
			net.stream_send(relay_b, one[:])
		}
		if n, rerr := net.stream_recv(relay_b, one[:]); rerr == .None && n == 1 {
			net.stream_send(relay_a, one[:])
		}
		if cs != .Done && cs != .Failed {
			cs = link_handshake(&p.c)
		} else if cs == .Done && !sent {
			testing.expect_value(t, link_write(&p.c, big[:1000]), Error.None)
			link_flush(&p.c)
			testing.expect_value(t, link_write(&p.c, big[1000:2000]), Error.None)
			link_flush(&p.c)
			testing.expect_value(t, link_write(&p.c, big[2000:]), Error.None)
			sent = true
		}
		link_flush(&p.c)
		if ss != .Done && ss != .Failed {
			ss = link_handshake(&p.s)
		}
		link_flush(&p.s)
		if ss == .Done {
			buf: [700]u8
			n, rerr := link_read(&p.s, buf[:])
			if rerr == .None {
				append(&got, ..buf[:n])
			} else if rerr != .Would_Block {
				testing.expect_value(t, rerr, Error.None)
				break
			}
		}
		if cs == .Failed || ss == .Failed {
			break
		}
	}
	testing.expect_value(t, cs, Hs_Status.Done)
	testing.expect_value(t, ss, Hs_Status.Done)
	testing.expect_value(t, len(got), len(big))
	for i in 0 ..< min(len(got), len(big)) {
		if got[i] != big[i] {
			testing.expectf(t, false, "byte %d differs", i)
			break
		}
	}
}

@(test)
large_write_through_small_socket_buffers :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, {send_buffer = 4096, recv_buffer = 4096}) {
		return
	}
	cs, ss := handshake(&p)
	if cs != .Done || ss != .Done {
		testing.expect_value(t, cs, Hs_Status.Done)
		testing.expect_value(t, ss, Hs_Status.Done)
		return
	}
	N :: 1024 * 1024
	data := make([]u8, N, context.temp_allocator)
	for &b, i in data {
		b = u8(i * 31 + i >> 8)
	}
	got := make([]u8, N, context.temp_allocator)
	have, sent := 0, 0
	blocked_flushes := 0
	start := time.tick_now()
	for have < N && time.tick_since(start) < 20 * time.Second {
		// One record at a time, when the buffer is empty: the way the daemon writes.
		if sent < N && link_pending(&p.c) == 0 {
			n := min(RECORD_PLAINTEXT, N - sent)
			if !testing.expect_value(t, link_write(&p.c, data[sent:][:n]), Error.None) {
				break
			}
			sent += n
		}
		if link_pending(&p.c) > 0 {
			pending, ferr := link_flush(&p.c)
			testing.expect_value(t, ferr, Error.None)
			if pending > 0 {
				blocked_flushes += 1
			}
		}
		// The reader reads only when the writer is blocked or done, so the socket
		// buffers fill up on every system (Windows loopback drains them fast).
		if link_pending(&p.c) == 0 && sent < N {
			continue
		}
		n, rerr := link_read(&p.s, got[have:])
		if rerr == .Would_Block {
			time.sleep(100 * time.Microsecond)
			continue
		}
		if !testing.expect_value(t, rerr, Error.None) {
			break
		}
		have += n
	}
	testing.expect_value(t, have, N)
	testing.expect(t, blocked_flushes > 0, "the socket took everything at once: the would-block path did not run")
	for i in 0 ..< min(have, N) {
		if got[i] != data[i] {
			testing.expectf(t, false, "byte %d differs", i)
			break
		}
	}
	testing.expect_value(t, link_pending(&p.c), 0)
}

@(test)
write_without_room_waits_for_the_socket :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, {send_buffer = 4096, recv_buffer = 4096}) {
		return
	}
	cs, ss := handshake(&p)
	if cs != .Done || ss != .Done {
		testing.expect_value(t, cs, Hs_Status.Done)
		return
	}
	rec: [RECORD_PLAINTEXT]u8
	for &b, i in rec {
		b = u8(i)
	}
	// Nobody reads: the kernel buffers fill, then the output buffer, then
	// `link_write` says it has no room and takes nothing.
	taken := 0
	err := Error.None
	for _ in 0 ..< 100_000 {
		err = link_write(&p.c, rec[:])
		if err != .None {
			break
		}
		taken += 1
	}
	testing.expect_value(t, err, Error.Would_Block)
	testing.expect(t, taken > 0)
	before := link_pending(&p.c)
	testing.expect(t, before > 0)
	// Data that could never fit is refused for good.
	over := make([]u8, len(p.cout), context.temp_allocator)
	testing.expect_value(t, link_write(&p.c, over), Error.Invalid)
	// The server reads everything that was taken; then the writer has room again.
	have := 0
	buf: [RECORD_PLAINTEXT]u8
	start := time.tick_now()
	for have < taken * RECORD_PLAINTEXT && time.tick_since(start) < 20 * time.Second {
		link_flush(&p.c)
		n, rerr := link_read(&p.s, buf[:])
		if rerr == .Would_Block {
			time.sleep(100 * time.Microsecond)
			continue
		}
		if !testing.expect_value(t, rerr, Error.None) {
			break
		}
		have += n
	}
	testing.expect_value(t, have, taken * RECORD_PLAINTEXT)
	flush_all(&p.c)
	testing.expect_value(t, link_write(&p.c, rec[:]), Error.None)
}

@(test)
handshake_and_data_through_a_small_output_buffer :: proc(t: ^testing.T) {
	// The output buffer is smaller than a handshake flight: the library's
	// writes are cut and retried, and the handshake still ends.
	p: Pair
	defer pair_destroy(&p)
	ok: bool
	p.csock, p.ssock, ok = sockets(t)
	if !ok {
		return
	}
	err: ossl.Error
	p.cctx, err = ossl.tls_ctx_create({role = .Client, min_version = .TLS_1_2, verify = .None})
	testing.expect_value(t, err, ossl.Error.None)
	p.sctx, err = ossl.tls_ctx_create({role = .Server, min_version = .TLS_1_2, verify = .None, cert_pem = CERT_PEM, key_pem = KEY_PEM})
	testing.expect_value(t, err, ossl.Error.None)
	testing.expect_value(t, link_init(&p.c, &p.cctx, p.csock, p.cout[:300]), Error.None)
	testing.expect_value(t, link_init(&p.s, &p.sctx, p.ssock, p.sout[:300]), Error.None)
	cs, ss := handshake(&p)
	testing.expect_value(t, cs, Hs_Status.Done)
	testing.expect_value(t, ss, Hs_Status.Done)
	if cs != .Done || ss != .Done {
		return
	}
	msg: [200]u8
	for &b, i in msg {
		b = u8(i + 3)
	}
	for _ in 0 ..< 20 {
		testing.expect_value(t, link_write(&p.c, msg[:]), Error.None)
		flush_all(&p.c)
		got, rerr := read_exactly(&p.s, len(msg))
		testing.expect_value(t, rerr, Error.None)
		testing.expect(t, string(got) == string(msg[:]), "the bytes differ")
	}
	// More than the buffer holds, with its overhead: refused.
	testing.expect_value(t, link_write(&p.c, make([]u8, 300, context.temp_allocator)), Error.Invalid)
}

@(test)
fed_bytes_come_before_the_socket :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p) {
		return
	}
	// The client's first flight goes to the server's socket. Take it out by hand
	// and feed the first part to the server link: the rest of the handshake must
	// run on the fed bytes plus what the socket still holds, in order.
	testing.expect_value(t, link_handshake(&p.c), Hs_Status.Want_Read)
	raw: [4096]u8
	n: int
	for _ in 0 ..< 500 {
		rn, rerr := net.stream_recv(p.ssock, raw[:])
		if rerr == .None {
			n = rn
			break
		}
		time.sleep(time.Millisecond)
	}
	if !testing.expect(t, n > 100, "the ClientHello is there") {
		return
	}
	testing.expect(t, link_feed(&p.s, raw[:60]))
	testing.expect(t, link_feed(&p.s, raw[60:100]))
	testing.expect(t, link_feed(&p.s, nil))
	// The rest goes to the server's socket again, from the client's end.
	_, serr := net.stream_send(p.csock, raw[100:n])
	testing.expect_value(t, serr, net.Error.None)
	cs, ss := handshake(&p)
	testing.expect_value(t, cs, Hs_Status.Done)
	testing.expect_value(t, ss, Hs_Status.Done)
	testing.expect_value(t, len(p.s.fed), 0)
	if cs != .Done || ss != .Done {
		return
	}
	msg := "after fed bytes"
	testing.expect_value(t, link_write(&p.c, transmute([]u8)msg), Error.None)
	flush_all(&p.c)
	got, rerr := read_exactly(&p.s, len(msg))
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, string(got), msg)
}

// A round: both sides write `rec` and read what the other wrote.
@(private = "file")
round_trip :: proc(t: ^testing.T, p: ^Pair, rec: []u8) -> bool {
	testing.expect_value(t, link_write(&p.c, rec), Error.None)
	flush_all(&p.c)
	got, rerr := read_exactly(&p.s, len(rec))
	if !testing.expect_value(t, rerr, Error.None) || string(got) != string(rec) {
		testing.expect(t, false, "client to server: wrong bytes")
		return false
	}
	testing.expect_value(t, link_write(&p.s, rec), Error.None)
	flush_all(&p.s)
	got, rerr = read_exactly(&p.c, len(rec))
	if !testing.expect_value(t, rerr, Error.None) || string(got) != string(rec) {
		testing.expect(t, false, "server to client: wrong bytes")
		return false
	}
	return true
}

@(test)
keys_are_updated_after_the_byte_count :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p) {
		return
	}
	cs, ss := handshake(&p)
	if cs != .Done || ss != .Done {
		testing.expect_value(t, cs, Hs_Status.Done)
		return
	}
	testing.expect(t, p.c.tls13 && p.s.tls13)
	testing.expect_value(t, p.c.rekey_after, REKEY_BYTES)
	// 20 rounds of 500 bytes each way: 3000 bytes cause a key update on each side.
	p.c.rekey_after = 3000
	p.s.rekey_after = 3000
	rec: [500]u8
	for i in 0 ..< 20 {
		for &b, j in rec {
			b = u8(i * 13 + j)
		}
		if !round_trip(t, &p, rec[:]) {
			return
		}
	}
	testing.expect(t, p.c.rekeys >= 3, "the client updated its keys")
	testing.expect(t, p.s.rekeys >= 3, "the server updated its keys")
	bytes, rekeyed := link_rekey_note(&p.c)
	testing.expect(t, rekeyed)
	testing.expect_value(t, bytes, u64(3000))
	// Each update is told once.
	_, again := link_rekey_note(&p.c)
	testing.expect(t, !again)
	// The count starts again after an update.
	testing.expect(t, p.c.written < 3000)
}

@(test)
no_key_update_on_tls12 :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, max_version = .TLS_1_2) {
		return
	}
	cs, ss := handshake(&p)
	if cs != .Done || ss != .Done {
		testing.expect_value(t, cs, Hs_Status.Done)
		return
	}
	testing.expect_value(t, ossl.tls_version_name(&p.c.s), "TLSv1.2")
	testing.expect(t, !p.c.tls13 && !p.s.tls13)
	p.c.rekey_after = 100
	rec: [500]u8
	for i in 0 ..< 5 {
		rec[0] = u8(i)
		if !round_trip(t, &p, rec[:]) {
			return
		}
	}
	testing.expect_value(t, p.c.rekeys, u64(0))
	_, rekeyed := link_rekey_note(&p.c)
	testing.expect(t, !rekeyed)
}

@(test)
close_notify_is_a_clean_end :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p) {
		return
	}
	cs, ss := handshake(&p)
	if cs != .Done || ss != .Done {
		testing.expect_value(t, cs, Hs_Status.Done)
		return
	}
	link_close(&p.c)
	buf: [16]u8
	err: Error
	for _ in 0 ..< 1000 {
		_, err = link_read(&p.s, buf[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.Closed)
	testing.expect(t, !p.s.eof, "close_notify arrived: not a truncated stream")
}

@(test)
closing_the_socket_without_close_notify_is_closed_too :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p) {
		return
	}
	cs, ss := handshake(&p)
	if cs != .Done || ss != .Done {
		testing.expect_value(t, cs, Hs_Status.Done)
		return
	}
	net.close(p.csock)
	p.csock = net.INVALID_SOCKET
	buf: [16]u8
	err: Error
	for _ in 0 ..< 1000 {
		_, err = link_read(&p.s, buf[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.Closed)
	testing.expect(t, p.s.eof)
}

@(test)
a_peer_that_is_not_tls_fails_the_handshake :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p) {
		return
	}
	// What a stock OpenVPN client sends first over TCP: a length, then a reset packet.
	raw := [?]u8{0x00, 0x0e, 0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0}
	_, serr := net.stream_send(p.csock, raw[:])
	testing.expect_value(t, serr, net.Error.None)
	st := Hs_Status.Want_Read
	for _ in 0 ..< 1000 {
		st = link_handshake(&p.s)
		if st != .Want_Read {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, st, Hs_Status.Failed)
	testing.expect(t, len(link_error_text(&p.s)) > 0, "an error text")
	// It stays failed.
	testing.expect_value(t, link_handshake(&p.s), Hs_Status.Failed)
	buf: [8]u8
	_, rerr := link_read(&p.s, buf[:])
	testing.expect_value(t, rerr, Error.Invalid)
}

@(test)
the_peer_hangs_up_during_the_handshake :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p) {
		return
	}
	// The client starts and the server end vanishes.
	testing.expect_value(t, link_handshake(&p.c), Hs_Status.Want_Read)
	net.close(p.ssock)
	p.ssock = net.INVALID_SOCKET
	st := Hs_Status.Want_Read
	for _ in 0 ..< 1000 {
		st = link_handshake(&p.c)
		if st != .Want_Read {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, st, Hs_Status.Failed)
}

@(test)
data_that_follows_the_last_handshake_flight_is_not_lost :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p) {
		return
	}
	// Client: run until done, then send data at once (TLS 1.3 allows it after
	// Finished). The server's handshake call then also reads the data, and the
	// socket has nothing more to say about it.
	cs, ss := Hs_Status.Want_Read, Hs_Status.Want_Read
	for _ in 0 ..< 200 {
		cs = link_handshake(&p.c)
		if cs == .Done {
			break
		}
		ss = link_handshake(&p.s)
		time.sleep(time.Millisecond)
	}
	if !testing.expect_value(t, cs, Hs_Status.Done) {
		return
	}
	msg := "first packet"
	testing.expect_value(t, link_write(&p.c, transmute([]u8)msg), Error.None)
	flush_all(&p.c)
	time.sleep(20 * time.Millisecond)
	for _ in 0 ..< 200 {
		if ss == .Done {
			break
		}
		ss = link_handshake(&p.s)
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, ss, Hs_Status.Done)
	// The library may have read the message ahead with the last flight (then
	// `link_has_input` says so), or it is still in the socket (the socket stays
	// readable). It must be in one of the two places.
	peek: [64]u8
	in_socket, _ := net.stream_peek(p.ssock, peek[:])
	testing.expectf(t, link_has_input(&p.s) || in_socket > 0, "the message is nowhere (has_input %v, socket %d)", link_has_input(&p.s), in_socket)
	got, rerr := read_exactly(&p.s, len(msg))
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, string(got), msg)
	testing.expect(t, !link_has_input(&p.s))
}

@(test)
init_checks_its_arguments :: proc(t: ^testing.T) {
	ctx, err := ossl.tls_ctx_create({role = .Client, verify = .None})
	testing.expect_value(t, err, ossl.Error.None)
	defer ossl.tls_ctx_destroy(&ctx)
	l: Link
	testing.expect_value(t, link_init(&l, &ctx, net.INVALID_SOCKET, nil), Error.Invalid)
	buf: [64]u8
	testing.expect_value(t, link_init(&l, &ctx, net.INVALID_SOCKET, buf[:], "a\x00b"), Error.Invalid)
	testing.expect_value(t, link_init(&l, &ctx, net.INVALID_SOCKET, buf[:], "host.example"), Error.None)
	// Not established: no data calls.
	b: [8]u8
	testing.expect_value(t, link_write(&l, b[:]), Error.Invalid)
	_, rerr := link_read(&l, b[:])
	testing.expect_value(t, rerr, Error.Invalid)
	link_destroy(&l)
}
