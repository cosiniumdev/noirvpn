// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package noirnet

import win "core:sys/windows"
import "core:testing"
import "core:time"

// The UDP tests of net_test.odin that do not depend on Linux, and the
// Windows differences. Loopback and ephemeral ports only.

LO4 :: Endpoint{address = IP4_Address{127, 0, 0, 1}, port = 0}
LO6 :: Endpoint{address = IP6_Address{0, 0, 0, 0, 0, 0, 0, 1}, port = 0}

// An open socket bound to loopback with a kernel-chosen port, and the
// endpoint that reaches it.
@(private)
Bound :: struct {
	sock: Socket,
	ep:   Endpoint,
}

@(private)
udp_bound :: proc(t: ^testing.T, family: Family, opts: UDP_Options = {}) -> (b: Bound, ok: bool) {
	s, err := udp_open(family, opts)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return {}, false
	}
	bind_ep := LO4 if family == .V4 else LO6
	if berr := bind(s, bind_ep); berr != .None {
		close(s)
		testing.expect_value(t, berr, Error.None)
		return {}, false
	}
	ep, lerr := local_endpoint(s)
	testing.expect_value(t, lerr, Error.None)
	return {s, ep}, true
}

// ---- UDP ----

@(test)
udp_single_packet :: proc(t: ^testing.T) {
	a, ok := udp_bound(t, .V4)
	if !ok {
		return
	}
	defer close(a.sock)
	b, ok2 := udp_bound(t, .V4)
	if !ok2 {
		return
	}
	defer close(b.sock)
	testing.expect(t, a.ep.port != 0)
	testing.expect(t, a.ep.port != b.ep.port)

	buf: [64]u8
	// Nothing yet.
	_, _, err := recv_from(a.sock, buf[:])
	testing.expect_value(t, err, Error.Would_Block)

	msg := "hello over udp"
	testing.expect_value(t, send_to(b.sock, transmute([]u8)msg, a.ep), Error.None)
	// Loopback delivers before sendto returns, but allow a moment anyway.
	n: int
	from: Endpoint
	for _ in 0 ..< 100 {
		n, from, err = recv_from(a.sock, buf[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, string(buf[:n]), msg)
	testing.expect_value(t, from, b.ep)
}

@(test)
udp_connected_send_recv :: proc(t: ^testing.T) {
	a, ok := udp_bound(t, .V4)
	if !ok {
		return
	}
	defer close(a.sock)
	b, ok2 := udp_bound(t, .V4)
	if !ok2 {
		return
	}
	defer close(b.sock)

	testing.expect_value(t, connect(b.sock, a.ep), Error.None)
	peer, perr := peer_endpoint(b.sock)
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, peer, a.ep)

	data := [3]u8{1, 2, 3}
	testing.expect_value(t, send(b.sock, data[:]), Error.None)
	buf: [16]u8
	n: int
	err: Error
	for _ in 0 ..< 100 {
		n, err = recv(a.sock, buf[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 3)
}

@(test)
udp_batch_64_packets :: proc(t: ^testing.T) {
	rx, ok := udp_bound(t, .V4)
	if !ok {
		return
	}
	defer close(rx.sock)
	tx, ok2 := udp_bound(t, .V4)
	if !ok2 {
		return
	}
	defer close(tx.sock)

	N :: 64
	SLOT :: 256

	// Send: 64 packets of different lengths, in one call.
	sendb: Batch
	testing.expect_value(t, batch_init(&sendb, .V4, N), Error.None)
	defer batch_destroy(&sendb)
	out: [N][SLOT]u8
	lens: [N]int
	for i in 0 ..< N {
		lens[i] = 1 + (i * 7) % 200
		for j in 0 ..< lens[i] {
			out[i][j] = u8(i + j)
		}
		testing.expect_value(t, batch_set_send(&sendb, i, out[i][:lens[i]], rx.ep), Error.None)
	}
	sent, serr := send_batch(tx.sock, &sendb, N)
	testing.expect_value(t, serr, Error.None)
	testing.expect_value(t, sent, N)

	// Receive in two calls of 32 slots.
	recvb: Batch
	testing.expect_value(t, batch_init(&recvb, .V4, 32), Error.None)
	defer batch_destroy(&recvb)
	pool: [32][SLOT]u8
	for i in 0 ..< 32 {
		batch_set_recv(&recvb, i, pool[i][:])
	}

	got := 0
	deadline := time.tick_now()
	for got < N {
		n, rerr := recv_batch(rx.sock, &recvb)
		if rerr == .Would_Block {
			if time.tick_since(deadline) > 2 * time.Second {
				break
			}
			time.sleep(time.Millisecond)
			continue
		}
		testing.expect_value(t, rerr, Error.None)
		if rerr != .None {
			break
		}
		testing.expect(t, n >= 1 && n <= 32)
		for i in 0 ..< n {
			idx := got + i
			testing.expect_value(t, batch_len(&recvb, i), lens[idx])
			testing.expect(t, !batch_truncated(&recvb, i))
			testing.expect_value(t, batch_from(&recvb, i), tx.ep)
			want := out[idx][:lens[idx]]
			have := pool[i][:batch_len(&recvb, i)]
			testing.expect(t, string(want) == string(have), "payload differs")
		}
		got += n
	}
	testing.expect_value(t, got, N)

	// Drained: the next call would block.
	_, rerr := recv_batch(rx.sock, &recvb)
	testing.expect_value(t, rerr, Error.Would_Block)
}

@(test)
udp_batch_connected_send_and_partial_count :: proc(t: ^testing.T) {
	rx, ok := udp_bound(t, .V4)
	if !ok {
		return
	}
	defer close(rx.sock)
	tx, ok2 := udp_bound(t, .V4)
	if !ok2 {
		return
	}
	defer close(tx.sock)
	testing.expect_value(t, connect(tx.sock, rx.ep), Error.None)

	sendb: Batch
	batch_init(&sendb, .V4, 8)
	defer batch_destroy(&sendb)
	data := [?]u8{0xa0, 0xa1, 0xa2}
	for i in 0 ..< 8 {
		testing.expect_value(t, batch_set_send(&sendb, i, data[:i % 3 + 1]), Error.None) // no address
	}
	// Ask to send only 5 of the 8.
	sent, serr := send_batch(tx.sock, &sendb, 5)
	testing.expect_value(t, serr, Error.None)
	testing.expect_value(t, sent, 5)

	recvb: Batch
	batch_init(&recvb, .V4, 8)
	defer batch_destroy(&recvb)
	pool: [8][16]u8
	for i in 0 ..< 8 {
		batch_set_recv(&recvb, i, pool[i][:])
	}
	n, rerr := recv_batch(rx.sock, &recvb, 3) // take at most 3
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, n, 3)
	n, rerr = recv_batch(rx.sock, &recvb)
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, n, 2)
}

@(test)
udp_batch_truncated :: proc(t: ^testing.T) {
	rx, ok := udp_bound(t, .V4)
	if !ok {
		return
	}
	defer close(rx.sock)
	tx, ok2 := udp_bound(t, .V4)
	if !ok2 {
		return
	}
	defer close(tx.sock)

	big: [100]u8
	testing.expect_value(t, send_to(tx.sock, big[:], rx.ep), Error.None)

	recvb: Batch
	batch_init(&recvb, .V4, 1)
	defer batch_destroy(&recvb)
	small: [10]u8
	batch_set_recv(&recvb, 0, small[:])
	n: int
	err: Error
	for _ in 0 ..< 100 {
		n, err = recv_batch(rx.sock, &recvb)
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, batch_len(&recvb, 0), 10)
	testing.expect(t, batch_truncated(&recvb, 0))
}

@(test)
udp_batch_init_errors :: proc(t: ^testing.T) {
	b: Batch
	testing.expect_value(t, batch_init(&b, .V4, 0), Error.Invalid)

	// A v6 destination cannot be set on a v4 batch.
	testing.expect_value(t, batch_init(&b, .V4, 2), Error.None)
	defer batch_destroy(&b)
	data := [1]u8{1}
	err := batch_set_send(&b, 0, data[:], LO6)
	testing.expect_value(t, err, Error.Invalid)
}

@(test)
udp_buffer_sizes :: proc(t: ^testing.T) {
	s, err := udp_open(.V4, {recv_buffer = 64 * 1024, send_buffer = 64 * 1024})
	testing.expect_value(t, err, Error.None)
	defer close(s)
	r, w, serr := set_buffer_sizes(s, 0, 0) // only reads back
	testing.expect_value(t, serr, Error.None)
	testing.expect(t, r >= 64 * 1024, "receive buffer smaller than asked")
	testing.expect(t, w >= 64 * 1024, "send buffer smaller than asked")
}

@(test)
udp_v6_loopback_and_dual_stack :: proc(t: ^testing.T) {
	// A dual-stack socket on `::` accepts IPv4 senders, and shows them as IPv4.
	rx, err := udp_open(.V6, {v6_mode = .Dual_Stack})
	if err != .None {
		return // no IPv6 on this host
	}
	defer close(rx)
	if bind(rx, Endpoint{address = IP6_Address{}, port = 0}) != .None {
		return
	}
	v, _ := get_int_opt(rx, win.IPPROTO_IPV6, win.IPV6_V6ONLY)
	testing.expect_value(t, v, 0)
	local, _ := local_endpoint(rx)
	testing.expect(t, local.port != 0)

	// An IPv4 sender.
	tx4, e4 := udp_open(.V4)
	testing.expect_value(t, e4, Error.None)
	defer close(tx4)
	dest4 := Endpoint{address = IP4_Address{127, 0, 0, 1}, port = local.port}
	data := [2]u8{7, 8}
	testing.expect_value(t, send_to(tx4, data[:], dest4), Error.None)
	buf: [8]u8
	n: int
	from: Endpoint
	rerr: Error
	for _ in 0 ..< 100 {
		n, from, rerr = recv_from(rx, buf[:])
		if rerr != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, n, 2)
	_, is_v4 := from.address.(IP4_Address)
	testing.expect(t, is_v4, "a mapped source should read as IPv4")

	// Reply through the v6 socket to that IPv4 endpoint: the mapping is applied.
	testing.expect_value(t, send_to(rx, data[:], from), Error.None)

	// An IPv6 sender.
	tx6, e6 := udp_open(.V6)
	testing.expect_value(t, e6, Error.None)
	defer close(tx6)
	dest6 := Endpoint{address = IP6_Address{0, 0, 0, 0, 0, 0, 0, 1}, port = local.port}
	testing.expect_value(t, send_to(tx6, data[:], dest6), Error.None)
	for _ in 0 ..< 100 {
		n, from, rerr = recv_from(rx, buf[:])
		if rerr != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, rerr, Error.None)
	_, is_v6 := from.address.(IP6_Address)
	testing.expect(t, is_v6)
}

@(test)
udp_v6_only_mode :: proc(t: ^testing.T) {
	s, err := udp_open(.V6, {v6_mode = .V6_Only})
	if err != .None {
		return // no IPv6 on this host
	}
	defer close(s)
	v, _ := get_int_opt(s, win.IPPROTO_IPV6, win.IPV6_V6ONLY)
	testing.expect_value(t, v, 1)
}

@(test)
v4_endpoint_on_v4_socket_only :: proc(t: ^testing.T) {
	s, err := udp_open(.V4)
	testing.expect_value(t, err, Error.None)
	defer close(s)
	testing.expect_value(t, bind(s, LO6), Error.Invalid)
	data := [1]u8{0}
	testing.expect_value(t, send_to(s, data[:], LO6), Error.Invalid)
}


@(test)
wsa_error_mapping :: proc(t: ^testing.T) {
	testing.expect_value(t, map_wsa(win.WSAEWOULDBLOCK), Error.Would_Block)
	testing.expect_value(t, map_wsa(win.WSAECONNREFUSED), Error.Connection_Refused)
	testing.expect_value(t, map_wsa(win.WSAECONNRESET), Error.Connection_Reset)
	testing.expect_value(t, map_wsa(win.WSAEADDRINUSE), Error.Address_In_Use)
	testing.expect_value(t, map_wsa(win.WSAEMSGSIZE), Error.Message_Too_Long)
	testing.expect_value(t, map_wsa(win.WSAENETUNREACH), Error.Network_Unreachable)
	testing.expect_value(t, map_wsa(12345), Error.Other)
}

@(test)
linux_only_features_report_unsupported :: proc(t: ^testing.T) {
	_, err := udp_open(.V4, {reuse_port = true})
	testing.expect_value(t, err, Error.Unsupported)

	s, err2 := udp_open(.V4, {offload = true, pktinfo = true})
	testing.expect_value(t, err2, Error.None)
	defer close(s)
	testing.expect(t, !s.gso && !s.gro && !s.pktinfo)

	data := [1]u8{0}
	local := local_of_address(IP4_Address{127, 0, 0, 1})
	testing.expect_value(t, send_to(s, data[:], Endpoint{address = IP4_Address{127, 0, 0, 1}, port = 9}, local), Error.Unsupported)
	b: Batch
	testing.expect_value(t, batch_init(&b, .V4, 2), Error.None)
	defer batch_destroy(&b)
	testing.expect(t, !batch_push(&b, data[:], LO4, local))
	testing.expect(t, !batch_gso_active(s, &b))
}

@(test)
udp_port_unreachable_is_not_a_read_error :: proc(t: ^testing.T) {
	// A port nobody uses: bind, note the port, close.
	gone, ok := udp_bound(t, .V4)
	if !ok {
		return
	}
	close(gone.sock)
	s, ok2 := udp_bound(t, .V4)
	if !ok2 {
		return
	}
	defer close(s.sock)
	data := [4]u8{1, 2, 3, 4}
	testing.expect_value(t, send_to(s.sock, data[:], gone.ep), Error.None)
	time.sleep(50 * time.Millisecond)
	buf: [16]u8
	_, _, err := recv_from(s.sock, buf[:])
	testing.expect_value(t, err, Error.Would_Block)
}

@(test)
udp_pushed_batch_round_trip :: proc(t: ^testing.T) {
	rx, ok := udp_bound(t, .V4)
	if !ok {
		return
	}
	defer close(rx.sock)
	tx, ok2 := udp_bound(t, .V4)
	if !ok2 {
		return
	}
	defer close(tx.sock)
	b: Batch
	batch_init(&b, .V4, 4)
	defer batch_destroy(&b)
	data := [3]u8{9, 8, 7}
	for i in 0 ..< 4 {
		testing.expect(t, batch_push(&b, data[:i % 3 + 1], rx.ep))
	}
	testing.expect(t, batch_full(&b))
	testing.expect(t, !batch_push(&b, data[:], rx.ep))
	sent, err := send_pushed(tx.sock, &b)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, 4)
	testing.expect_value(t, b.tx_dgrams, 4)
	batch_reset(&b)
	testing.expect_value(t, batch_pending(&b), 0)

	r: Batch
	batch_init(&r, .V4, 8)
	defer batch_destroy(&r)
	pool: [8][16]u8
	for i in 0 ..< 8 {
		batch_set_recv(&r, i, pool[i][:])
	}
	got := 0
	for _ in 0 ..< 100 {
		n, rerr := recv_batch(rx.sock, &r)
		if rerr == .None {
			for i in 0 ..< n {
				testing.expect_value(t, batch_gro_size(&r, i), 0)
				testing.expect_value(t, batch_segments(&r, i), 1)
				testing.expect_value(t, batch_local(&r, i).len, 0)
			}
			got += n
		}
		if got >= 4 {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, got, 4)
}
