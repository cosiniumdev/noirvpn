// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package noirnet

import "core:strings"
import "core:sys/linux"
import "core:testing"
import "core:time"

// Everything here uses loopback and ephemeral ports, so tests can run in
// parallel and need no privileges.

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

// ---- addresses ----

@(test)
sockaddr_v4_bytes :: proc(t: ^testing.T) {
	sa, size, ok := to_sockaddr(Endpoint{address = IP4_Address{192, 0, 2, 7}, port = 0x1234}, .V4)
	testing.expect(t, ok)
	testing.expect_value(t, size, 16)
	raw := (^[16]u8)(&sa)^
	// family AF_INET (2, little-endian u16), port big-endian, address, zeros
	want := [16]u8{2, 0, 0x12, 0x34, 192, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0}
	testing.expect_value(t, raw, want)
}

@(test)
sockaddr_v6_bytes :: proc(t: ^testing.T) {
	addr := IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 2}
	sa, size, ok := to_sockaddr(Endpoint{address = addr, port = 1194}, .V6)
	testing.expect(t, ok)
	testing.expect_value(t, size, 28)
	raw := (^[28]u8)(&sa)^
	want := [28]u8 {
		10, 0, // AF_INET6
		0x04, 0xaa, // port 1194
		0, 0, 0, 0, // flow info
		0xfd, 0x00, 0x01, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0, 0, 0, 0, // scope id
	}
	testing.expect_value(t, raw, want)
}

@(test)
sockaddr_v4_on_v6_socket_is_mapped :: proc(t: ^testing.T) {
	sa, size, ok := to_sockaddr(Endpoint{address = IP4_Address{10, 1, 2, 3}, port = 80}, .V6)
	testing.expect(t, ok)
	testing.expect_value(t, size, 28)
	testing.expect_value(t, sa.sin6_addr, [16]u8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3})

	// And back: the mapped address reads as IPv4 again.
	ep, ok2 := from_sockaddr(&sa)
	testing.expect(t, ok2)
	testing.expect_value(t, ep.address, Address(IP4_Address{10, 1, 2, 3}))
	testing.expect_value(t, ep.port, 80)
}

@(test)
sockaddr_v6_on_v4_socket_is_refused :: proc(t: ^testing.T) {
	_, _, ok := to_sockaddr(Endpoint{address = IP6_Address{0, 0, 0, 0, 0, 0, 0, 1}, port = 80}, .V4)
	testing.expect(t, !ok)
}

@(test)
sockaddr_round_trip :: proc(t: ^testing.T) {
	eps := [?]Endpoint {
		{address = IP4_Address{1, 2, 3, 4}, port = 1},
		{address = IP4_Address{255, 255, 255, 255}, port = 65535},
		{address = IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}, port = 443},
		{address = IP6_Address{0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff}, port = 0},
	}
	for ep in eps {
		fam := family_of(ep)
		sa, _, ok := to_sockaddr(ep, fam)
		testing.expect(t, ok)
		back, ok2 := from_sockaddr(&sa)
		testing.expect(t, ok2)
		testing.expect_value(t, back, ep)
	}
	// A family we do not handle.
	sa: linux.Sock_Addr_Any
	sa.family = .UNIX
	_, ok := from_sockaddr(&sa)
	testing.expect(t, !ok)
}

@(test)
errno_mapping :: proc(t: ^testing.T) {
	testing.expect_value(t, map_errno(.NONE), Error.None)
	testing.expect_value(t, map_errno(.EAGAIN), Error.Would_Block)
	testing.expect_value(t, map_errno(.EWOULDBLOCK), Error.Would_Block)
	testing.expect_value(t, map_errno(.ECONNREFUSED), Error.Connection_Refused)
	testing.expect_value(t, map_errno(.EADDRINUSE), Error.Address_In_Use)
	testing.expect_value(t, map_errno(.ENETUNREACH), Error.Network_Unreachable)
	testing.expect_value(t, map_errno(.EPIPE), Error.Closed)
	testing.expect_value(t, map_errno(.EXDEV), Error.Other)
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
udp_reuse_port :: proc(t: ^testing.T) {
	a, ok := udp_bound(t, .V4, {reuse_port = true})
	if !ok {
		return
	}
	defer close(a.sock)

	// A second socket with SO_REUSEPORT can share the port.
	b, err := udp_open(.V4, {reuse_port = true})
	testing.expect_value(t, err, Error.None)
	defer close(b)
	testing.expect_value(t, bind(b, a.ep), Error.None)

	// One without it cannot.
	c, err2 := udp_open(.V4)
	testing.expect_value(t, err2, Error.None)
	defer close(c)
	testing.expect_value(t, bind(c, a.ep), Error.Address_In_Use)
}

@(test)
udp_buffer_sizes :: proc(t: ^testing.T) {
	s, err := udp_open(.V4, {recv_buffer = 64 * 1024, send_buffer = 64 * 1024})
	testing.expect_value(t, err, Error.None)
	defer close(s)
	r, w, serr := set_buffer_sizes(s, 0, 0) // only reads back
	testing.expect_value(t, serr, Error.None)
	// The kernel reports twice what was asked (bookkeeping overhead).
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
	v, _ := get_int_opt(rx.fd, IPPROTO_IPV6, IPV6_V6ONLY)
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
	v, _ := get_int_opt(s.fd, IPPROTO_IPV6, IPV6_V6ONLY)
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

// `keepalive` sets SO_KEEPALIVE and the probe timing, on a connecting socket
// and on an accepted one.
@(test)
test_tcp_keepalive_options :: proc(t: ^testing.T) {
	l, lerr := tcp_listen(LO4)
	if !testing.expect_value(t, lerr, Error.None) {
		return
	}
	defer close(l)
	lep, _ := local_endpoint(l)
	c, _, cerr := tcp_connect(lep, {keepalive = true})
	if !testing.expect_value(t, cerr, Error.None) {
		return
	}
	defer close(c)
	plain, _, perr := tcp_connect(lep)
	if !testing.expect_value(t, perr, Error.None) {
		return
	}
	defer close(plain)
	acc: [2]Socket
	for i in 0 ..< 2 {
		// The first connection of the queue is the keepalive one.
		for _ in 0 ..< 200 {
			s, _, aerr := tcp_accept(l, {keepalive = i == 0})
			if aerr == .None {
				acc[i] = s
				break
			}
			time.sleep(5 * time.Millisecond)
		}
		if !testing.expect(t, is_valid(acc[i])) {
			return
		}
	}
	defer close(acc[0])
	defer close(acc[1])
	want := [?]i32{1, KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, KEEPALIVE_PROBES}
	opts := [?][2]int{{SOL_SOCKET, int(linux.Socket_Option.KEEPALIVE)}, {IPPROTO_TCP, TCP_KEEPIDLE}, {IPPROTO_TCP, TCP_KEEPINTVL}, {IPPROTO_TCP, TCP_KEEPCNT}}
	for o, i in opts {
		v, _ := get_int_opt(c.fd, o[0], o[1])
		testing.expect_value(t, v, want[i])
		v, _ = get_int_opt(acc[0].fd, o[0], o[1])
		testing.expect_value(t, v, want[i])
	}
	v, _ := get_int_opt(plain.fd, SOL_SOCKET, int(linux.Socket_Option.KEEPALIVE))
	testing.expect_value(t, v, 0)
	v, _ = get_int_opt(acc[1].fd, SOL_SOCKET, int(linux.Socket_Option.KEEPALIVE))
	testing.expect_value(t, v, 0)
}

// The name of the device that a socket is limited to, "" for none.
@(private = "file")
device_of :: proc(s: Socket) -> string {
	name: [16]u8
	size := u32(len(name))
	if linux.syscall(linux.SYS_getsockopt, s.fd, SOL_SOCKET, int(linux.Socket_Option.BINDTODEVICE), &name, &size) < 0 {
		return "?"
	}
	n := int(size)
	for n > 0 && name[n - 1] == 0 {
		n -= 1
	}
	return strings.clone(string(name[:n]), context.temp_allocator)
}

// A listener and a UDP socket limited to the loopback device: connections
// over loopback arrive, and the accepted socket has the same limit.
@(test)
test_bind_device :: proc(t: ^testing.T) {
	l, lerr := tcp_listen(LO4, 16, .Dual_Stack, "lo")
	if !testing.expect_value(t, lerr, Error.None) {
		return
	}
	defer close(l)
	testing.expect_value(t, device_of(l), "lo")
	lep, _ := local_endpoint(l)
	c, _, cerr := tcp_connect(lep)
	if !testing.expect_value(t, cerr, Error.None) {
		return
	}
	defer close(c)
	acc := INVALID_SOCKET
	for _ in 0 ..< 200 {
		s, _, aerr := tcp_accept(l)
		if aerr == .None {
			acc = s
			break
		}
		time.sleep(5 * time.Millisecond)
	}
	if !testing.expect(t, is_valid(acc), "no connection arrived on the loopback device") {
		return
	}
	defer close(acc)
	testing.expect_value(t, device_of(acc), "lo")

	plain, perr := tcp_listen(LO4)
	if testing.expect_value(t, perr, Error.None) {
		testing.expect_value(t, device_of(plain), "")
		close(plain)
	}

	u, uerr := udp_open(.V4)
	if testing.expect_value(t, uerr, Error.None) {
		testing.expect_value(t, bind_device(u, "lo"), Error.None)
		testing.expect_value(t, bind(u, LO4), Error.None)
		testing.expect_value(t, device_of(u), "lo")
		close(u)
	}
}

// A device that does not exist, and a name that is too long.
@(test)
test_bind_device_errors :: proc(t: ^testing.T) {
	_, err := tcp_listen(LO4, 16, .Dual_Stack, "nodev-noir0")
	testing.expect(t, err != .None, "a listener on a device that does not exist opened")
	_, err = tcp_listen(LO4, 16, .Dual_Stack, "a-name-of-16-chr")
	testing.expect_value(t, err, Error.Invalid)
	u, uerr := udp_open(.V4)
	if testing.expect_value(t, uerr, Error.None) {
		testing.expect_value(t, bind_device(u, ""), Error.Invalid)
		close(u)
	}
}
