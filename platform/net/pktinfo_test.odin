// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package noirnet

import "core:testing"
import "core:time"

// Tests of the local address of a datagram (IP_PKTINFO, IPV6_PKTINFO). All of
// 127.0.0.0/8 is local on Linux, so a wildcard server socket and a client
// connected to 127.0.0.2 model a multi-address host without privilege.

// ---- control messages ----

@(test)
cmsg_pktinfo_v4_layout :: proc(t: ^testing.T) {
	c: Ctrl
	l := Local {
		len     = 4,
		addr    = {0 = 192, 2 = 2, 3 = 9},
		ifindex = 7,
	}
	used := cmsg_put_pktinfo(&c, 0, .V4, l)
	raw := ([^]u8)(&c)
	testing.expect_value(t, used, CMSG_HDR_SIZE + cmsg_align(12))
	h := (^Cmsg_Hdr)(raw)^
	testing.expect_value(t, h.len, uint(CMSG_HDR_SIZE + 12))
	testing.expect_value(t, h.level, i32(0)) // SOL_IP
	testing.expect_value(t, h.type, i32(8)) // IP_PKTINFO
	d := raw[CMSG_HDR_SIZE:]
	// struct in_pktinfo: ifindex, ipi_spec_dst (the source), ipi_addr (unused).
	want := [12]u8{7, 0, 0, 0, 192, 0, 2, 9, 0, 0, 0, 0}
	for i in 0 ..< 12 {
		testing.expect_value(t, d[i], want[i])
	}
	// An IPv6 local cannot be sent from an IPv4 socket.
	l6 := Local {
		len = 16,
	}
	testing.expect_value(t, cmsg_put_pktinfo(&c, 0, .V4, l6), 0)
	testing.expect_value(t, cmsg_put_pktinfo(&c, 0, .V4, Local{}), 0)
}

@(test)
cmsg_pktinfo_v6_layout :: proc(t: ^testing.T) {
	c: Ctrl
	raw := ([^]u8)(&c)
	l := Local {
		len     = 16,
		addr    = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
		ifindex = 3,
	}
	used := cmsg_put_pktinfo(&c, 0, .V6, l)
	testing.expect_value(t, used, CMSG_HDR_SIZE + cmsg_align(20))
	h := (^Cmsg_Hdr)(raw)^
	testing.expect_value(t, h.level, i32(41)) // SOL_IPV6
	testing.expect_value(t, h.type, i32(50)) // IPV6_PKTINFO
	d := raw[CMSG_HDR_SIZE:]
	testing.expect_value(t, d[0], u8(0xfd))
	testing.expect_value(t, d[15], u8(5))
	testing.expect_value(t, d[16], u8(3))

	// An IPv4 local is sent in its mapped form.
	l4 := Local {
		len  = 4,
		addr = {0 = 10, 1 = 1, 2 = 2, 3 = 3},
	}
	used = cmsg_put_pktinfo(&c, 0, .V6, l4)
	testing.expect_value(t, used, CMSG_HDR_SIZE + cmsg_align(20))
	want := [20]u8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3, 0, 0, 0, 0}
	for i in 0 ..< 20 {
		testing.expect_value(t, d[i], want[i])
	}
}

@(test)
cmsg_find_local_cases :: proc(t: ^testing.T) {
	buf: [CTRL_SIZE]u8
	// IPv4: the address to reply from (ipi_spec_dst), and the interface. The
	// destination of the packet (ipi_addr) is a broadcast address here.
	n := make_cmsg(buf[:], 0, 8, {5, 0, 0, 0, 10, 0, 0, 1, 10, 0, 0, 255})
	l := cmsg_find_local(buf[:n])
	testing.expect_value(t, l.len, u8(4))
	testing.expect_value(t, l.addr[0], u8(10))
	testing.expect_value(t, l.addr[3], u8(1))
	testing.expect_value(t, l.ifindex, u32(5))
	// IPv4 with an empty ipi_spec_dst: the destination of the packet.
	n = make_cmsg(buf[:], 0, 8, {5, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2})
	l = cmsg_find_local(buf[:n])
	testing.expect_value(t, l.addr[3], u8(2))
	// IPv6, native.
	d6 := [20]u8{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 4, 0, 0, 0}
	n = make_cmsg(buf[:], 41, 50, d6[:])
	l = cmsg_find_local(buf[:n])
	testing.expect_value(t, l.len, u8(16))
	testing.expect_value(t, l.addr[15], u8(9))
	testing.expect_value(t, l.ifindex, u32(4))
	// IPv6, mapped: an IPv4 local.
	m6 := [20]u8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3, 2, 0, 0, 0}
	n = make_cmsg(buf[:], 41, 50, m6[:])
	l = cmsg_find_local(buf[:n])
	testing.expect_value(t, l.len, u8(4))
	testing.expect_value(t, l.addr[0], u8(10))
	testing.expect_value(t, l.addr[3], u8(3))
	testing.expect_value(t, l.addr[4], u8(0))
	testing.expect_value(t, l.addr[15], u8(0))
	// Other messages, too short a message, nothing.
	n = make_cmsg(buf[:], 17, 104, {0x78, 0x05, 0, 0})
	testing.expect_value(t, cmsg_find_local(buf[:n]).len, u8(0))
	n = make_cmsg(buf[:], 0, 8, {5, 0, 0, 0, 10, 0, 0, 1})
	testing.expect_value(t, cmsg_find_local(buf[:n]).len, u8(0))
	testing.expect_value(t, cmsg_find_local(nil).len, u8(0))
}

@(test)
cmsg_find_local_never_reads_outside :: proc(t: ^testing.T) {
	buf: [CTRL_SIZE]u8
	d6 := [20]u8{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 4, 0, 0, 0}
	make_cmsg(buf[:], 41, 50, d6[:])
	for cut in 0 ..< CMSG_HDR_SIZE + 20 { // the message is that long without its padding
		testing.expect_value(t, cmsg_find_local(buf[:cut]).len, u8(0))
	}
	(^Cmsg_Hdr)(&buf[0])^ = {
		len   = max(uint),
		level = 41,
		type  = 50,
	}
	testing.expect_value(t, cmsg_find_local(buf[:]).len, u8(0))
	seed := u64(0x9e3779b97f4a7c15)
	for _ in 0 ..< 2000 {
		for &b in buf {
			seed = seed * 6364136223846793005 + 1442695040888963407
			b = u8(seed >> 56)
		}
		_ = cmsg_find_local(buf[:])
	}
}

@(test)
local_address_round_trip :: proc(t: ^testing.T) {
	a4 := Address(IP4_Address{192, 0, 2, 1})
	l := local_of_address(a4)
	testing.expect_value(t, l.len, u8(4))
	got, ok := local_address(l)
	testing.expect(t, ok)
	testing.expect_value(t, got, a4)
	a6 := Address(IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 7})
	l = local_of_address(a6)
	testing.expect_value(t, l.len, u8(16))
	got, ok = local_address(l)
	testing.expect(t, ok)
	testing.expect_value(t, got, a6)
	_, ok = local_address(Local{})
	testing.expect(t, !ok)
}

// ---- GSO runs ----

@(test)
pack_keeps_locals_apart :: proc(t: ^testing.T) {
	b: Batch
	testing.expect_value(t, batch_init(&b, .V4, 8), Error.None)
	defer batch_destroy(&b)
	data: [8][1200]u8
	to := Endpoint {
		address = IP4_Address{10, 0, 0, 1},
		port    = 5000,
	}
	la := Local {
		len  = 4,
		addr = {0 = 10, 3 = 2},
	}
	lb := Local {
		len  = 4,
		addr = {0 = 10, 3 = 3},
	}
	lc := la
	lc.ifindex = 2
	// a a b b: two runs. a a (same address, other interface) c: three.
	locals := [?]Local{la, la, lb, lb, la, la, lc, Local{}}
	for l, i in locals {
		testing.expect(t, batch_push(&b, data[i][:1200], to, l))
	}
	pack_pushed(&b, true)
	testing.expect_value(t, b.n_msg, 5)
	want := [?]int{2, 2, 2, 1, 1}
	for w, m in want {
		testing.expect_value(t, int(b.spans[m].n), w)
	}
	// The control data of each message holds its packet info, then UDP_SEGMENT.
	for m in 0 ..< 4 {
		ctrl := b.hdrs[m].hdr.control
		l := cmsg_find_local(ctrl)
		testing.expect_value(t, l.len, u8(4))
		testing.expect_value(t, l.addr, b.locals[b.spans[m].first].addr)
		if b.spans[m].n > 1 {
			testing.expect_value(t, len(ctrl), CMSG_HDR_SIZE + cmsg_align(12) + CMSG_HDR_SIZE + cmsg_align(2))
		} else {
			testing.expect_value(t, len(ctrl), CMSG_HDR_SIZE + cmsg_align(12))
		}
	}
	// No local: no control data for a single datagram.
	testing.expect_value(t, len(b.hdrs[4].hdr.control), 0)
}

// ---- the kernel ----

@(private = "file")
Rx :: struct {
	b:   Batch,
	buf: [8][2048]u8,
}

@(private = "file")
rx_init :: proc(t: ^testing.T, r: ^Rx, family: Family) -> bool {
	if batch_init(&r.b, family, 8) != .None {
		testing.fail_now(t, "batch_init")
	}
	for i in 0 ..< 8 {
		batch_set_recv(&r.b, i, r.buf[i][:])
	}
	return true
}

// A socket bound to the wildcard address with a kernel-chosen port.
@(private = "file")
wild_server :: proc(t: ^testing.T, family: Family, opts: UDP_Options) -> (s: Socket, port: int, ok: bool) {
	err: Error
	s, err = udp_open(family, opts)
	if err != .None {
		return {}, 0, false // no IPv6 here
	}
	ep := Endpoint {
		address = IP6_Address{} if family == .V6 else IP4_Address{},
	}
	if berr := bind(s, ep); berr != .None {
		close(s)
		return {}, 0, false
	}
	lep, lerr := local_endpoint(s)
	testing.expect_value(t, lerr, Error.None)
	return s, lep.port, true
}

// A client socket connected to `to`.
@(private = "file")
connected_client :: proc(t: ^testing.T, to: Endpoint) -> (s: Socket, ok: bool) {
	family := family_of(to)
	err: Error
	s, err = udp_open(family)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return {}, false
	}
	if cerr := connect(s, to); cerr != .None {
		close(s)
		testing.expect_value(t, cerr, Error.None)
		return {}, false
	}
	return s, true
}

@(private = "file")
LO4_2 :: IP4_Address{127, 0, 0, 2}

@(private = "file")
recv_one :: proc(t: ^testing.T, s: Socket, r: ^Rx) -> (n: int, from: Endpoint, l: Local) {
	got, err := recv_batch(s, &r.b, 1)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, got, 1)
	if got != 1 {
		return
	}
	return batch_len(&r.b, 0), batch_from(&r.b, 0), batch_local(&r.b, 0)
}

// The client reads the reply, or not. Loopback delivers inside the send call;
// the short wait is a safety margin.
@(private = "file")
client_gets :: proc(s: Socket, buf: []u8) -> (n: int, err: Error) {
	for _ in 0 ..< 5 {
		n, err = recv(s, buf)
		if err != .Would_Block {
			return
		}
		time.sleep(2 * time.Millisecond)
	}
	return
}

// A client that talks to 127.0.0.2: the server sees that address as local. The
// client is connected, so it only takes datagrams from 127.0.0.2.
@(private = "file")
round_trip :: proc(t: ^testing.T, family: Family, to: Endpoint, use_local: bool) {
	srv, port, ok := wild_server(t, family, {pktinfo = true})
	if !ok {
		return
	}
	defer close(srv)
	if !srv.pktinfo {
		return // this kernel cannot report it
	}
	dest := to
	dest.port = port
	cl, cok := connected_client(t, dest)
	if !cok {
		return
	}
	defer close(cl)
	testing.expect_value(t, send(cl, transmute([]u8)string("ping")), Error.None)

	rx := new(Rx)
	defer free(rx)
	rx_init(t, rx, family)
	defer batch_destroy(&rx.b)
	n, from, l := recv_one(t, srv, rx)
	testing.expect_value(t, n, 4)
	got, has := local_address(l)
	testing.expect(t, has)
	testing.expect_value(t, got, dest.address)
	testing.expect_value(t, l.len, u8(4 if family_of(dest) == .V4 else 16))

	reply := transmute([]u8)string("pong")
	if use_local {
		testing.expect_value(t, send_to(srv, reply, from, l), Error.None)
	} else {
		testing.expect_value(t, send_to(srv, reply, from), Error.None)
	}
	buf: [64]u8
	rn, rerr := client_gets(cl, buf[:])
	if use_local {
		testing.expect_value(t, rerr, Error.None)
		testing.expect_value(t, rn, 4)
	} else if family_of(dest) == .V4 {
		// The reply left from 127.0.0.1, which the connected client drops.
		testing.expect_value(t, rerr, Error.Would_Block)
	}
}

@(test)
pktinfo_answer_from_local_v4 :: proc(t: ^testing.T) {
	round_trip(t, .V4, Endpoint{address = LO4_2}, true)
}

@(test)
pktinfo_answer_without_local_is_lost_v4 :: proc(t: ^testing.T) {
	round_trip(t, .V4, Endpoint{address = LO4_2}, false)
}

// A dual-stack IPv6 socket reports an IPv4 arrival as an IPv4-mapped address in
// IPV6_PKTINFO and takes the same form on send.
@(test)
pktinfo_answer_from_local_dual_stack :: proc(t: ^testing.T) {
	round_trip(t, .V6, Endpoint{address = LO4_2}, true)
}

@(test)
pktinfo_answer_without_local_is_lost_dual_stack :: proc(t: ^testing.T) {
	round_trip(t, .V6, Endpoint{address = LO4_2}, false)
}

@(test)
pktinfo_round_trip_v6 :: proc(t: ^testing.T) {
	round_trip(t, .V6, Endpoint{address = IP6_Address{0, 0, 0, 0, 0, 0, 0, 1}}, true)
}

// The interface that the kernel reports can be sent back (it is loopback here).
@(test)
pktinfo_ifindex_round_trip :: proc(t: ^testing.T) {
	srv, port, ok := wild_server(t, .V4, {pktinfo = true})
	if !ok {
		return
	}
	defer close(srv)
	cl, cok := connected_client(t, Endpoint{address = LO4_2, port = port})
	if !cok {
		return
	}
	defer close(cl)
	testing.expect_value(t, send(cl, transmute([]u8)string("ping")), Error.None)
	rx := new(Rx)
	defer free(rx)
	rx_init(t, rx, .V4)
	defer batch_destroy(&rx.b)
	_, from, l := recv_one(t, srv, rx)
	testing.expect(t, l.ifindex != 0)
	testing.expect_value(t, send_to(srv, transmute([]u8)string("pong"), from, l), Error.None)
	buf: [64]u8
	n, rerr := client_gets(cl, buf[:])
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, n, 4)
}

// A socket that did not ask for packet info has no local, and nothing changes
// for it.
@(test)
pktinfo_off_gives_no_local :: proc(t: ^testing.T) {
	srv, port, ok := wild_server(t, .V4, {})
	if !ok {
		return
	}
	defer close(srv)
	testing.expect(t, !srv.pktinfo)
	cl, cok := connected_client(t, Endpoint{address = LO4_2, port = port})
	if !cok {
		return
	}
	defer close(cl)
	testing.expect_value(t, send(cl, transmute([]u8)string("ping")), Error.None)
	rx := new(Rx)
	defer free(rx)
	rx_init(t, rx, .V4)
	defer batch_destroy(&rx.b)
	_, _, l := recv_one(t, srv, rx)
	testing.expect_value(t, l.len, u8(0))
}

// With GRO on, the packet info and the GRO size are both in the control data.
@(test)
pktinfo_with_gro :: proc(t: ^testing.T) {
	srv, port, ok := wild_server(t, .V4, {pktinfo = true, offload = true})
	if !ok {
		return
	}
	defer close(srv)
	cl, cok := connected_client(t, Endpoint{address = LO4_2, port = port})
	if !cok {
		return
	}
	defer close(cl)
	for _ in 0 ..< 3 {
		testing.expect_value(t, send(cl, transmute([]u8)string("ping")), Error.None)
	}
	rx := new(Rx)
	defer free(rx)
	rx_init(t, rx, .V4)
	defer batch_destroy(&rx.b)
	total := 0
	for total < 3 {
		got, err := recv_batch(srv, &rx.b)
		if err != .None {
			testing.expect_value(t, err, Error.None)
			break
		}
		for i in 0 ..< got {
			total += batch_segments(&rx.b, i)
			l := batch_local(&rx.b, i)
			a, has := local_address(l)
			testing.expect(t, has)
			testing.expect_value(t, a, Address(LO4_2))
		}
	}
	testing.expect_value(t, total, 3)
}

// Pushed datagrams with a local leave from it, in one GSO message when they
// can. The receiver is not connected and shows the source address of each.
@(private = "file")
batch_from_local :: proc(t: ^testing.T, family: Family) {
	srv, _, ok := wild_server(t, family, {pktinfo = true, offload = true})
	if !ok {
		return
	}
	defer close(srv)
	// The receiver: plain, bound to 127.0.0.1 (so that the sources show).
	cl, cerr := udp_open(.V4)
	testing.expect_value(t, cerr, Error.None)
	if cerr != .None {
		return
	}
	defer close(cl)
	testing.expect_value(t, bind(cl, Endpoint{address = IP4_Address{127, 0, 0, 1}}), Error.None)
	cep, _ := local_endpoint(cl)

	tx: Batch
	testing.expect_value(t, batch_init(&tx, family, 16), Error.None)
	defer batch_destroy(&tx)
	data: [16][1000]u8
	l2 := local_of_address(LO4_2)
	l3 := local_of_address(IP4_Address{127, 0, 0, 3})
	// Four datagrams from .2, then three from .3.
	for i in 0 ..< 7 {
		for j in 0 ..< len(data[i]) {
			data[i][j] = u8(i)
		}
		testing.expect(t, batch_push(&tx, data[i][:], cep, l2 if i < 4 else l3))
	}
	sent, err := send_pushed(srv, &tx)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, 7)
	if srv.gso && tx.gso_off == false {
		testing.expect_value(t, tx.tx_msgs, 2)
		testing.expect_value(t, tx.gso_msgs, 2)
	}

	rx := new(Rx)
	defer free(rx)
	rx_init(t, rx, .V4)
	defer batch_destroy(&rx.b)
	seen := 0
	for _ in 0 ..< 5 {
		got, rerr := recv_batch(cl, &rx.b)
		if rerr == .Would_Block {
			time.sleep(2 * time.Millisecond)
			continue
		}
		testing.expect_value(t, rerr, Error.None)
		for i in 0 ..< got {
			testing.expect_value(t, batch_len(&rx.b, i), 1000)
			k := int(rx.buf[i][0])
			from := batch_from(&rx.b, i)
			want := Address(LO4_2) if k < 4 else Address(IP4_Address{127, 0, 0, 3})
			testing.expect_value(t, from.address, want)
			seen += 1
		}
		if seen == 7 {
			break
		}
	}
	testing.expect_value(t, seen, 7)
}

@(test)
pktinfo_batch_send_v4 :: proc(t: ^testing.T) {
	batch_from_local(t, .V4)
}

@(test)
pktinfo_batch_send_dual_stack :: proc(t: ^testing.T) {
	batch_from_local(t, .V6)
}

// The slots set by hand take a local too.
@(test)
pktinfo_batch_set_send :: proc(t: ^testing.T) {
	srv, _, ok := wild_server(t, .V4, {pktinfo = true})
	if !ok {
		return
	}
	defer close(srv)
	cl, cerr := udp_open(.V4)
	testing.expect_value(t, cerr, Error.None)
	if cerr != .None {
		return
	}
	defer close(cl)
	testing.expect_value(t, bind(cl, Endpoint{address = IP4_Address{127, 0, 0, 1}}), Error.None)
	cep, _ := local_endpoint(cl)
	tx: Batch
	testing.expect_value(t, batch_init(&tx, .V4, 2), Error.None)
	defer batch_destroy(&tx)
	d := [?]u8{1, 2, 3}
	testing.expect_value(t, batch_set_send(&tx, 0, d[:], cep, local_of_address(LO4_2)), Error.None)
	testing.expect_value(t, batch_set_send(&tx, 1, d[:], cep), Error.None)
	sent, err := send_batch(srv, &tx, 2)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, 2)
	rx := new(Rx)
	defer free(rx)
	rx_init(t, rx, .V4)
	defer batch_destroy(&rx.b)
	got, rerr := recv_batch(cl, &rx.b)
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, got, 2)
	if got == 2 {
		testing.expect_value(t, batch_from(&rx.b, 0).address, Address(LO4_2))
		testing.expect_value(t, batch_from(&rx.b, 1).address, Address(IP4_Address{127, 0, 0, 1}))
	}
}

// A local that the host does not have is refused by the kernel and is an
// error of that send, nothing else.
@(test)
pktinfo_send_from_a_foreign_address :: proc(t: ^testing.T) {
	srv, _, ok := wild_server(t, .V4, {pktinfo = true})
	if !ok {
		return
	}
	defer close(srv)
	to := Endpoint {
		address = IP4_Address{127, 0, 0, 1},
		port    = 9,
	}
	l := local_of_address(IP4_Address{192, 0, 2, 55})
	err := send_to(srv, transmute([]u8)string("x"), to, l)
	testing.expect(t, err != .None && err != .Would_Block)
}
