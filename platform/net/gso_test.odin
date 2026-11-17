// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package noirnet

import "core:sys/linux"
import "core:testing"
import "core:time"

// Tests of UDP GSO (send) and UDP GRO (receive). Unit tests build message
// layouts without a socket. Loopback tests use the real kernel and skip what
// it lacks (never fail for a missing feature).

// ---- control messages ----

@(test)
cmsg_gso_layout :: proc(t: ^testing.T) {
	c: Ctrl
	used := cmsg_put_gso(&c, 0, 1400)
	raw := ([^]u8)(&c)
	when size_of(uint) == 8 {
		// cmsg_len = 16 + 2, level SOL_UDP (17), type UDP_SEGMENT (103), u16 data.
		want := [18]u8{18, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 103, 0, 0, 0, 0x78, 0x05}
		testing.expect_value(t, used, 24)
		for i in 0 ..< len(want) {
			testing.expect_value(t, raw[i], want[i])
		}
	} else {
		testing.expect_value(t, used, 12 + 4)
	}
	testing.expect_value(t, CMSG_HDR_SIZE, 16 if size_of(uint) == 8 else 12)
}

// A control buffer holding one message: `data` bytes of data after a header.
@(private)
make_cmsg :: proc(buf: []u8, level, typ: i32, data: []u8) -> int {
	for &b in buf {
		b = 0
	}
	h := Cmsg_Hdr {
		len   = uint(CMSG_HDR_SIZE + len(data)),
		level = level,
		type  = typ,
	}
	(^Cmsg_Hdr)(&buf[0])^ = h
	copy(buf[CMSG_HDR_SIZE:], data)
	return CMSG_HDR_SIZE + cmsg_align(len(data))
}

@(test)
cmsg_find_gro_cases :: proc(t: ^testing.T) {
	buf: [CTRL_SIZE]u8
	// The kernel's form: an int.
	n := make_cmsg(buf[:], SOL_UDP, UDP_GRO, {0x78, 0x05, 0, 0})
	testing.expect_value(t, cmsg_find_gro(buf[:n]), 1400)
	// A u16 is understood too.
	n = make_cmsg(buf[:], SOL_UDP, UDP_GRO, {0x78, 0x05})
	testing.expect_value(t, cmsg_find_gro(buf[:n]), 1400)
	// Other messages: ignored.
	n = make_cmsg(buf[:], SOL_UDP, UDP_SEGMENT, {0x78, 0x05, 0, 0})
	testing.expect_value(t, cmsg_find_gro(buf[:n]), 0)
	n = make_cmsg(buf[:], 1, UDP_GRO, {0x78, 0x05, 0, 0})
	testing.expect_value(t, cmsg_find_gro(buf[:n]), 0)
	// A negative size and an empty message are not sizes.
	n = make_cmsg(buf[:], SOL_UDP, UDP_GRO, {0xff, 0xff, 0xff, 0xff})
	testing.expect_value(t, cmsg_find_gro(buf[:n]), 0)
	n = make_cmsg(buf[:], SOL_UDP, UDP_GRO, {})
	testing.expect_value(t, cmsg_find_gro(buf[:n]), 0)
	// Nothing at all.
	testing.expect_value(t, cmsg_find_gro(nil), 0)
	testing.expect_value(t, cmsg_find_gro(buf[:0]), 0)
}

@(test)
cmsg_find_gro_second_message :: proc(t: ^testing.T) {
	buf: [64]u8
	n1 := make_cmsg(buf[:], 0, 8, {1, 2, 3, 4, 5, 6, 7, 8}) // some other message first
	n2 := make_cmsg(buf[n1:], SOL_UDP, UDP_GRO, {0x00, 0x04, 0, 0})
	testing.expect_value(t, cmsg_find_gro(buf[:n1 + n2]), 1024)
}

@(test)
cmsg_find_gro_never_reads_outside :: proc(t: ^testing.T) {
	// Every truncation of a valid buffer, and headers that lie about their
	// length: no crash, no result unless the whole message is inside.
	buf: [CTRL_SIZE]u8
	make_cmsg(buf[:], SOL_UDP, UDP_GRO, {0x78, 0x05, 0, 0})
	for cut in 0 ..< CMSG_HDR_SIZE + 4 { // the message is CMSG_HDR_SIZE + 4 bytes long (without padding)
		got := cmsg_find_gro(buf[:cut])
		testing.expect_value(t, got, 0)
	}
	for lie in 0 ..< 70 {
		for &b in buf {
			b = 0
		}
		(^Cmsg_Hdr)(&buf[0])^ = {
			len   = uint(lie),
			level = SOL_UDP,
			type  = UDP_GRO,
		}
		_ = cmsg_find_gro(buf[:])
		_ = cmsg_find_gro(buf[:lie % (len(buf) + 1)])
	}
	// A huge length.
	(^Cmsg_Hdr)(&buf[0])^ = {
		len   = max(uint),
		level = SOL_UDP,
		type  = UDP_GRO,
	}
	testing.expect_value(t, cmsg_find_gro(buf[:]), 0)
	// Random bytes.
	seed := u64(0x9e3779b97f4a7c15)
	for _ in 0 ..< 2000 {
		for &b in buf {
			seed = seed * 6364136223846793005 + 1442695040888963407
			b = u8(seed >> 56)
		}
		_ = cmsg_find_gro(buf[:])
	}
}

// ---- how datagrams are packed ----

@(private = "file")
Pack_Env :: struct {
	b:    Batch,
	data: [200][]u8,
	mem:  [200][1500]u8,
}

@(private = "file")
pack_setup :: proc(t: ^testing.T, e: ^Pack_Env, sizes: []int, dests: []u16 = nil) -> bool {
	if batch_init(&e.b, .V4, len(sizes)) != .None {
		testing.fail_now(t, "batch_init")
	}
	for sz, i in sizes {
		e.data[i] = e.mem[i][:sz]
		to: Maybe(Endpoint)
		if dests != nil {
			to = Endpoint {
				address = IP4_Address{10, 0, 0, 1},
				port    = int(dests[i]),
			}
		}
		if !batch_push(&e.b, e.data[i], to) {
			return false
		}
	}
	return true
}

@(private = "file")
span :: proc(b: ^Batch, m: int) -> (first, n: int) {
	return int(b.spans[m].first), int(b.spans[m].n)
}

@(test)
pack_equal_sizes_one_run :: proc(t: ^testing.T) {
	e := new(Pack_Env)
	defer free(e)
	sizes: [10]int
	for &s in sizes {
		s = 1200
	}
	testing.expect(t, pack_setup(t, e, sizes[:]))
	defer batch_destroy(&e.b)
	pack_pushed(&e.b, true)
	testing.expect_value(t, e.b.n_msg, 1)
	f, n := span(&e.b, 0)
	testing.expect_value(t, f, 0)
	testing.expect_value(t, n, 10)
	testing.expect_value(t, len(e.b.hdrs[0].hdr.iov), 10)
	testing.expect_value(t, len(e.b.hdrs[0].hdr.control), 24 if size_of(uint) == 8 else 16)
	// The segment size in the control message is the size of the first datagram.
	testing.expect_value(t, (^u16)(&([^]u8)(&e.b.ctrl[0])[CMSG_HDR_SIZE])^, 1200)
	testing.expect(t, e.b.hdrs[0].hdr.name == nil)
}

@(test)
pack_last_may_be_shorter :: proc(t: ^testing.T) {
	e := new(Pack_Env)
	defer free(e)
	sizes := [?]int{1200, 1200, 1200, 700}
	testing.expect(t, pack_setup(t, e, sizes[:]))
	defer batch_destroy(&e.b)
	pack_pushed(&e.b, true)
	testing.expect_value(t, e.b.n_msg, 1)
	_, n := span(&e.b, 0)
	testing.expect_value(t, n, 4)
}

@(test)
pack_runs_break_where_they_must :: proc(t: ^testing.T) {
	e := new(Pack_Env)
	defer free(e)
	// 1200 x3, then a short one closes the run, then a new run starts with
	// a longer one (1300 > 1200), then a datagram longer than its run's size.
	sizes := [?]int{1200, 1200, 1200, 500, 1300, 1300, 1301, 100}
	testing.expect(t, pack_setup(t, e, sizes[:]))
	defer batch_destroy(&e.b)
	pack_pushed(&e.b, true)
	// [1200 1200 1200 500] [1300 1300] [1301 100]
	testing.expect_value(t, e.b.n_msg, 3)
	f, n := span(&e.b, 0)
	testing.expect_value(t, f, 0)
	testing.expect_value(t, n, 4)
	f, n = span(&e.b, 1)
	testing.expect_value(t, f, 4)
	testing.expect_value(t, n, 2)
	f, n = span(&e.b, 2)
	testing.expect_value(t, f, 6)
	testing.expect_value(t, n, 2)
	// A message with one datagram has no control message.
	one := [?]int{100, 200}
	batch_reset(&e.b)
	for sz, i in one {
		e.data[i] = e.mem[i][:sz]
		batch_push(&e.b, e.data[i])
	}
	pack_pushed(&e.b, true)
	// 100 then 200: the second is longer, so two entries.
	testing.expect_value(t, e.b.n_msg, 2)
	testing.expect_value(t, len(e.b.hdrs[0].hdr.control), 0)
	testing.expect_value(t, len(e.b.hdrs[1].hdr.control), 0)
}

@(test)
pack_stops_at_64_datagrams_and_65507_bytes :: proc(t: ^testing.T) {
	e := new(Pack_Env)
	defer free(e)
	small: [100]int
	for &s in small {
		s = 100
	}
	testing.expect(t, pack_setup(t, e, small[:]))
	pack_pushed(&e.b, true)
	testing.expect_value(t, e.b.n_msg, 2)
	_, n := span(&e.b, 0)
	testing.expect_value(t, n, GSO_MAX_SEGS)
	_, n = span(&e.b, 1)
	testing.expect_value(t, n, 36)
	batch_destroy(&e.b)

	// 1500 bytes each: 65507 / 1500 = 43 fit.
	e2 := new(Pack_Env)
	defer free(e2)
	big: [60]int
	for &s in big {
		s = 1500
	}
	testing.expect(t, pack_setup(t, e2, big[:]))
	defer batch_destroy(&e2.b)
	pack_pushed(&e2.b, true)
	_, n = span(&e2.b, 0)
	testing.expect_value(t, n, 43)
	testing.expect(t, n * 1500 <= GSO_MAX_BYTES)
	_, n = span(&e2.b, 1)
	testing.expect_value(t, n, 17)
}

@(test)
pack_keeps_destinations_apart :: proc(t: ^testing.T) {
	e := new(Pack_Env)
	defer free(e)
	sizes := [?]int{1000, 1000, 1000, 1000, 1000, 1000}
	ports := [?]u16{1, 1, 2, 2, 2, 1}
	testing.expect(t, pack_setup(t, e, sizes[:], ports[:]))
	defer batch_destroy(&e.b)
	pack_pushed(&e.b, true)
	testing.expect_value(t, e.b.n_msg, 3)
	_, n := span(&e.b, 0)
	testing.expect_value(t, n, 2)
	_, n = span(&e.b, 1)
	testing.expect_value(t, n, 3)
	_, n = span(&e.b, 2)
	testing.expect_value(t, n, 1)
	// Every entry names its own destination: the one of its first datagram.
	testing.expect(t, e.b.hdrs[0].hdr.name == &e.b.addrs[0])
	testing.expect(t, e.b.hdrs[1].hdr.name == &e.b.addrs[2])
	testing.expect(t, e.b.hdrs[2].hdr.name == &e.b.addrs[5])
}

@(test)
pack_without_gso_is_one_entry_per_datagram :: proc(t: ^testing.T) {
	e := new(Pack_Env)
	defer free(e)
	sizes := [?]int{1000, 1000, 1000, 400}
	testing.expect(t, pack_setup(t, e, sizes[:]))
	defer batch_destroy(&e.b)
	pack_pushed(&e.b, false)
	testing.expect_value(t, e.b.n_msg, 4)
	for m in 0 ..< 4 {
		_, n := span(&e.b, m)
		testing.expect_value(t, n, 1)
		testing.expect_value(t, len(e.b.hdrs[m].hdr.iov), 1)
		testing.expect_value(t, len(e.b.hdrs[m].hdr.control), 0)
	}
}

@(test)
pack_zero_length_and_full_batch :: proc(t: ^testing.T) {
	e := new(Pack_Env)
	defer free(e)
	sizes := [?]int{100, 0, 100}
	testing.expect(t, pack_setup(t, e, sizes[:]))
	defer batch_destroy(&e.b)
	pack_pushed(&e.b, true)
	// An empty datagram is never part of a run.
	testing.expect_value(t, e.b.n_msg, 3)

	// A full batch refuses another push.
	testing.expect(t, batch_full(&e.b))
	testing.expect(t, !batch_push(&e.b, e.mem[0][:10]))
	testing.expect_value(t, batch_pending(&e.b), 3)
	batch_reset(&e.b)
	testing.expect_value(t, batch_pending(&e.b), 0)
	testing.expect(t, batch_push(&e.b, e.mem[0][:10]))
}

@(test)
push_refuses_a_v6_destination_on_a_v4_batch :: proc(t: ^testing.T) {
	b: Batch
	testing.expect_value(t, batch_init(&b, .V4, 2), Error.None)
	defer batch_destroy(&b)
	data: [10]u8
	testing.expect(t, !batch_push(&b, data[:], LO6))
	testing.expect_value(t, batch_pending(&b), 0)
	testing.expect(t, batch_push(&b, data[:], LO4))
}

// ---- the kernel ----

@(private = "file")
udp_pair :: proc(t: ^testing.T, family: Family, tx_off, rx_off: bool) -> (tx, rx: Bound, ok: bool) {
	rx = udp_bound(t, family, {offload = rx_off}) or_return
	tx, ok = udp_bound(t, family, {offload = tx_off})
	if !ok {
		close(rx.sock)
		return
	}
	return tx, rx, true
}

// Fills `data` with a pattern of the datagram number.
@(private = "file")
fill_dgram :: proc(buf: []u8, k: int) {
	for j in 0 ..< len(buf) {
		buf[j] = u8(k * 7 + j)
	}
}

// Receives until `want` bytes arrived (or 2 s pass), splitting coalesced
// blocks. Calls `each` per datagram. Returns the datagram count and the
// number of coalesced blocks.
@(private = "file")
Rx_Result :: struct {
	dgrams:    int,
	coalesced: int,
	blocks:    int,
	bad:       int,
}

@(private = "file")
receive_all :: proc(t: ^testing.T, s: Socket, want: int, sizes: []int) -> Rx_Result {
	rb: Batch
	testing.expect_value(t, batch_init(&rb, .V4 if s.family == .V4 else .V6, 8), Error.None)
	defer batch_destroy(&rb)
	pool := make([]u8, 8 * 65536)
	defer delete(pool)
	for i in 0 ..< 8 {
		batch_set_recv(&rb, i, pool[i * 65536:][:65536])
	}
	r: Rx_Result
	start := time.tick_now()
	for r.dgrams < want {
		n, err := recv_batch(s, &rb)
		if err == .Would_Block {
			if time.tick_since(start) > 2 * time.Second {
				break
			}
			time.sleep(time.Millisecond)
			continue
		}
		testing.expect_value(t, err, Error.None)
		if err != .None {
			break
		}
		for i in 0 ..< n {
			block := pool[i * 65536:][:batch_len(&rb, i)]
			seg := batch_gro_size(&rb, i)
			r.blocks += 1
			if seg == 0 {
				seg = len(block)
			} else {
				r.coalesced += 1
			}
			for off := 0; off < len(block); off += seg {
				d := block[off:min(off + seg, len(block))]
				k := r.dgrams
				if k >= len(sizes) || len(d) != sizes[k] {
					r.bad += 1
				} else {
					for j in 0 ..< len(d) {
						if d[j] != u8(k * 7 + j) {
							r.bad += 1
							break
						}
					}
				}
				r.dgrams += 1
			}
		}
	}
	return r
}

@(private = "file")
gso_gro_round_trip :: proc(t: ^testing.T, family: Family) {
	tx, rx, ok := udp_pair(t, family, true, true)
	if !ok {
		return
	}
	defer close(tx.sock)
	defer close(rx.sock)
	if !tx.sock.gso || !rx.sock.gro {
		return // this kernel has no UDP GSO or GRO
	}
	sb: Batch
	testing.expect_value(t, batch_init(&sb, family, 64), Error.None)
	defer batch_destroy(&sb)

	N :: 40
	mem: [N][1200]u8
	sizes: [N]int
	for k in 0 ..< N {
		sizes[k] = 1200
	}
	sizes[N - 1] = 700 // the last one is shorter
	for k in 0 ..< N {
		fill_dgram(mem[k][:sizes[k]], k)
		testing.expect(t, batch_push(&sb, mem[k][:sizes[k]], rx.ep))
	}
	sent, err := send_pushed(tx.sock, &sb)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, N)
	testing.expect_value(t, sb.tx_calls, 1)
	testing.expect_value(t, sb.gso_msgs, 1)
	testing.expect_value(t, sb.gso_dgrams, N)
	_, fresh := batch_take_gso_failure(&sb)
	testing.expect(t, !fresh)

	r := receive_all(t, rx.sock, N, sizes[:])
	testing.expect_value(t, r.dgrams, N)
	testing.expect_value(t, r.bad, 0)
	// On loopback the kernel hands the GSO packet to a GRO socket as it is.
	testing.expect(t, r.coalesced >= 1, "no coalesced block arrived: UDP GRO did not take effect")
	testing.expect(t, r.blocks < N)
}

@(test)
gso_to_gro_loopback_v4 :: proc(t: ^testing.T) {
	gso_gro_round_trip(t, .V4)
}

@(test)
gso_to_gro_loopback_v6 :: proc(t: ^testing.T) {
	gso_gro_round_trip(t, .V6)
}

@(test)
gso_to_plain_receiver :: proc(t: ^testing.T) {
	// The receiver has no GRO: the kernel cuts the GSO packet into datagrams.
	tx, rx, ok := udp_pair(t, .V4, true, false)
	if !ok {
		return
	}
	defer close(tx.sock)
	defer close(rx.sock)
	if !tx.sock.gso {
		return
	}
	testing.expect(t, !rx.sock.gro)
	sb: Batch
	batch_init(&sb, .V4, 64)
	defer batch_destroy(&sb)
	N :: 30
	mem: [N][900]u8
	sizes: [N]int
	for k in 0 ..< N {
		sizes[k] = 900 - (k / 29) * 400
		fill_dgram(mem[k][:sizes[k]], k)
		batch_push(&sb, mem[k][:sizes[k]], rx.ep)
	}
	sent, err := send_pushed(tx.sock, &sb)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, N)
	testing.expect(t, sb.gso_msgs >= 1)
	r := receive_all(t, rx.sock, N, sizes[:])
	testing.expect_value(t, r.dgrams, N)
	testing.expect_value(t, r.coalesced, 0)
	testing.expect_value(t, r.bad, 0)
}

@(test)
send_pushed_without_gso_socket :: proc(t: ^testing.T) {
	// A socket without `gso`: plain entries, same result.
	tx, rx, ok := udp_pair(t, .V4, false, false)
	if !ok {
		return
	}
	defer close(tx.sock)
	defer close(rx.sock)
	sb: Batch
	batch_init(&sb, .V4, 16)
	defer batch_destroy(&sb)
	N :: 10
	mem: [N][300]u8
	sizes: [N]int
	for k in 0 ..< N {
		sizes[k] = 300
		fill_dgram(mem[k][:], k)
		batch_push(&sb, mem[k][:], rx.ep)
	}
	sent, err := send_pushed(tx.sock, &sb)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, N)
	testing.expect_value(t, sb.gso_msgs, 0)
	testing.expect_value(t, sb.tx_msgs, N)
	r := receive_all(t, rx.sock, N, sizes[:])
	testing.expect_value(t, r.dgrams, N)
	testing.expect_value(t, r.bad, 0)
}

@(test)
gso_refused_falls_back_and_reports_once :: proc(t: ^testing.T) {
	tx, rx, ok := udp_pair(t, .V4, true, false)
	if !ok {
		return
	}
	defer close(tx.sock)
	defer close(rx.sock)
	if !tx.sock.gso {
		return
	}
	// SO_NO_CHECK (11) turns the UDP checksum off, and the kernel does not
	// segment such a packet: it returns EINVAL to a GSO message.
	SO_NO_CHECK :: 11
	if set_int_opt(tx.sock.fd, SOL_SOCKET, SO_NO_CHECK, 1) != .NONE {
		return
	}
	sb: Batch
	batch_init(&sb, .V4, 16)
	defer batch_destroy(&sb)
	N :: 6
	mem: [N][500]u8
	sizes: [N]int
	for k in 0 ..< N {
		sizes[k] = 500
		fill_dgram(mem[k][:], k)
		batch_push(&sb, mem[k][:], rx.ep)
	}
	sent, err := send_pushed(tx.sock, &sb)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, N)
	testing.expect(t, sb.gso_off)
	testing.expect_value(t, sb.gso_msgs, 0)
	testing.expect_value(t, sb.tx_msgs, N)
	errno, fresh := batch_take_gso_failure(&sb)
	testing.expect(t, fresh)
	testing.expect_value(t, linux.Errno(errno), linux.Errno.EINVAL)
	_, fresh = batch_take_gso_failure(&sb)
	testing.expect(t, !fresh, "the failure is reported once")
	testing.expect(t, !batch_gso_active(tx.sock, &sb))
	r := receive_all(t, rx.sock, N, sizes[:])
	testing.expect_value(t, r.dgrams, N)
	testing.expect_value(t, r.bad, 0)

	// Later sends stay plain.
	batch_reset(&sb)
	for k in 0 ..< N {
		batch_push(&sb, mem[k][:], rx.ep)
	}
	sent, err = send_pushed(tx.sock, &sb)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, sent, N)
	testing.expect_value(t, sb.tx_msgs, 2 * N)
}

@(test)
gro_socket_with_plain_traffic :: proc(t: ^testing.T) {
	// A GRO socket that gets ordinary datagrams reports no coalescing.
	tx, rx, ok := udp_pair(t, .V4, false, true)
	if !ok {
		return
	}
	defer close(tx.sock)
	defer close(rx.sock)
	if !rx.sock.gro {
		return
	}
	for k in 0 ..< 3 {
		d: [100]u8
		fill_dgram(d[:], k)
		testing.expect_value(t, send_to(tx.sock, d[:], rx.ep), Error.None)
	}
	sizes := [?]int{100, 100, 100}
	r := receive_all(t, rx.sock, 3, sizes[:])
	testing.expect_value(t, r.dgrams, 3)
	testing.expect_value(t, r.coalesced, 0)
	testing.expect_value(t, r.bad, 0)
}

@(test)
udp_open_offload_flags :: proc(t: ^testing.T) {
	s, err := udp_open(.V4, {offload = true})
	testing.expect_value(t, err, Error.None)
	defer close(s)
	// Whatever the kernel says, a plain open stays plain.
	p, perr := udp_open(.V4)
	testing.expect_value(t, perr, Error.None)
	defer close(p)
	testing.expect(t, !p.gso && !p.gro)
	// Switching GRO off again.
	if s.gro {
		s2 := udp_gro_disable(s)
		testing.expect(t, !s2.gro)
	}
}
