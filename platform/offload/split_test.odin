// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package offload

import "core:fmt"
import "core:testing"
import "core:time"

MAX_OUT :: 2000

// Checks that cutting the super-packet of `sp` gives exactly the packets built
// one by one, and that every output has right checksums.
check_split :: proc(t: ^testing.T, sp: ^Spec, mss: int, label: string) -> bool {
	buf := make([]u8, len(sp.payload) + 300, context.temp_allocator)
	h, pkt := make_super(sp, mss, buf)
	got, err := split_all(h, pkt, MAX_OUT)
	if !testing.expectf(t, err == .None, "%s: split_init: %v", label, err) {
		return false
	}
	want := expected_segments(sp, mss)
	if !testing.expectf(t, len(got) == len(want), "%s: %d packets, want %d", label, len(got), len(want)) {
		return false
	}
	ok := true
	// The size of all the packets is known before the first is cut.
	total := 0
	for g in got {
		total += len(g)
	}
	probe: Split
	testing.expect_value(t, split_init(&probe, h, pkt, MAX_OUT), Error.None)
	if !testing.expectf(t, split_bytes_left(&probe) == total, "%s: bytes left %d, packets have %d", label, split_bytes_left(&probe), total) {
		ok = false
	}
	// ... and after some of them are given out.
	if split_count(&probe) > 2 {
		scratch := make([]u8, MAX_OUT, context.temp_allocator)
		first, _ := split_next(&probe, scratch)
		second, _ := split_next(&probe, scratch)
		if !testing.expectf(t, split_bytes_left(&probe) == total - first - second, "%s: bytes left after two packets", label) {
			ok = false
		}
	}
	for i in 0 ..< len(got) {
		v, why := verify(got[i])
		if !testing.expectf(t, v, "%s: packet %d: %s", label, i, why) {
			ok = false
		}
		same := len(got[i]) == len(want[i])
		if same {
			for k in 0 ..< len(got[i]) {
				if got[i][k] != want[i][k] {
					same = false
					break
				}
			}
		}
		if !testing.expectf(t, same, "%s: packet %d differs from the expected one", label, i) {
			ok = false
		}
	}
	return ok
}

@(test)
split_tcp4_basic :: proc(t: ^testing.T) {
	sp := default_spec(false)
	sp.payload = fill_payload(1360 * 3 + 500)
	check_split(t, &sp, 1360, "v4 basic")
}

@(test)
split_tcp6_basic :: proc(t: ^testing.T) {
	sp := default_spec(true)
	sp.payload = fill_payload(1340 * 4 + 1)
	check_split(t, &sp, 1340, "v6 basic")
}

@(test)
split_matrix :: proc(t: ^testing.T) {
	ts := ts_options(0x01020304, 0x0a0b0c0d)
	flag_sets := [?]u8{0x10, 0x18, 0x11, 0x19, 0x90, 0xd8, 0x50, 0x10 | 0x20}
	sizes := [?]int{1, 99, 100, 101, 200, 201, 1000, 4501}
	mss := 100
	for v6 in ([2]bool{false, true}) {
		for with_opts in ([2]bool{false, true}) {
			for fl in flag_sets {
				for size in sizes {
					sp := default_spec(v6)
					sp.flags = fl
					sp.payload = fill_payload(size, size)
					sp.id = 0xfffd // the id wraps
					sp.seq = 0xffffff00 // and so does the sequence number
					if with_opts {
						sp.topts = ts[:]
					}
					label := fmt.tprintf("v6=%v opts=%v flags=%#x size=%d", v6, with_opts, fl, size)
					ok := check_split(t, &sp, mss, label)
					free_all(context.temp_allocator)
					if !ok {
						return
					}
				}
			}
		}
	}
}

@(test)
split_flags_rules :: proc(t: ^testing.T) {
	sp := default_spec(false)
	sp.flags = TCP_ACK | TCP_PSH | TCP_FIN | TCP_CWR | TCP_ECE
	sp.payload = fill_payload(1000)
	buf := make([]u8, 70000, context.temp_allocator)
	h, pkt := make_super(&sp, 400, buf)
	got, err := split_all(h, pkt, MAX_OUT)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(got), 3)
	for p, i in got {
		fl := p[20 + 13]
		testing.expectf(t, fl & TCP_ECE != 0, "packet %d lost ECE", i)
		testing.expectf(t, fl & TCP_ACK != 0, "packet %d lost ACK", i)
		testing.expectf(t, (fl & TCP_CWR != 0) == (i == 0), "CWR on packet %d", i)
		testing.expectf(t, (fl & TCP_PSH != 0) == (i == 2), "PSH on packet %d", i)
		testing.expectf(t, (fl & TCP_FIN != 0) == (i == 2), "FIN on packet %d", i)
	}
}

@(test)
split_single_segment :: proc(t: ^testing.T) {
	sp := default_spec(false)
	sp.flags = TCP_ACK | TCP_PSH | TCP_FIN | TCP_CWR
	sp.payload = fill_payload(300)
	check_split(t, &sp, 1360, "one segment")
	sp.payload = nil
	check_split(t, &sp, 1360, "no payload")
	sp.payload = fill_payload(1360)
	check_split(t, &sp, 1360, "exactly mss")
	sp.payload = fill_payload(2720)
	check_split(t, &sp, 1360, "exactly two mss")
}

@(test)
split_ip_options :: proc(t: ^testing.T) {
	sp := default_spec(false)
	sp.ip_opts = {1, 1, 1, 0, 1, 1, 1, 0} // NOPs and an end of list
	sp.payload = fill_payload(900)
	check_split(t, &sp, 400, "ipv4 options")
	ts := ts_options(5, 6)
	sp.topts = ts[:]
	check_split(t, &sp, 400, "ipv4 options and tcp options")
}

@(test)
split_v6_extension_headers :: proc(t: ^testing.T) {
	sp := default_spec(true)
	h1 := hbh_header(PROTO_TCP)
	sp.ext = h1[:]
	sp.ext_nh = 0
	sp.payload = fill_payload(1000)
	check_split(t, &sp, 300, "one hop-by-hop")
	// Two headers: hop-by-hop, then destination options of 16 bytes.
	ext: [24]u8
	hb := hbh_header(60)
	copy(ext[:8], hb[:])
	ext[8] = PROTO_TCP
	ext[9] = 1 // 16 bytes
	ext[10], ext[11] = 1, 12
	sp.ext = ext[:]
	check_split(t, &sp, 300, "two extension headers")
	sp.udp = true
	ext[8] = PROTO_UDP
	check_split(t, &sp, 300, "udp after extension headers")
}

@(test)
split_uso :: proc(t: ^testing.T) {
	for v6 in ([2]bool{false, true}) {
		sp := default_spec(v6)
		sp.udp = true
		sp.payload = fill_payload(1200 * 5 + 77)
		check_split(t, &sp, 1200, "uso")
		sp.payload = fill_payload(100)
		check_split(t, &sp, 1200, "uso one packet")
	}
}

// A UDP checksum that comes out as 0 is sent as 0xFFFF.
@(test)
split_udp_zero_checksum :: proc(t: ^testing.T) {
	buf := make([]u8, 200, context.temp_allocator)
	big := make([]u8, 200, context.temp_allocator)
	for v6 in ([2]bool{false, true}) {
		found := false
		sp := default_spec(v6)
		sp.udp = true
		field := (40 if v6 else 20) + 6
		pay: [2]u8
		for w in 0 ..< 65536 {
			pay[0], pay[1] = u8(w >> 8), u8(w)
			sp.payload = pay[:]
			p := build(&sp, buf)
			// `build` applies the rule too: look for a field of 0xFFFF.
			if be16(p[field:]) != 0xffff {
				continue
			}
			found = true
			// The packet as a tun gives it, with a partial checksum and no GSO.
			h, sup := make_super(&sp, 1000, big)
			h.gso_type = GSO_NONE
			got, err := split_all(h, sup, MAX_OUT)
			testing.expect_value(t, err, Error.None)
			if err == .None {
				testing.expect_value(t, len(got), 1)
				v, why := verify(got[0])
				testing.expectf(t, v, "%s", why)
				testing.expect_value(t, be16(got[0][field:]), u16(0xffff))
			}
			// The same through USO.
			h2, sup2 := make_super(&sp, 1000, big)
			got2, err2 := split_all(h2, sup2, MAX_OUT)
			testing.expect_value(t, err2, Error.None)
			if err2 == .None {
				testing.expect_value(t, be16(got2[0][field:]), u16(0xffff))
			}
			break
		}
		testing.expectf(t, found, "v6=%v: no payload gave a zero checksum", v6)
	}
}

// A packet without a GSO type.
@(test)
split_plain :: proc(t: ^testing.T) {
	for v6 in ([2]bool{false, true}) {
		for udp in ([2]bool{false, true}) {
			sp := default_spec(v6)
			sp.udp = udp
			sp.payload = fill_payload(777)
			buf := make([]u8, 3000, context.temp_allocator)
			want := build(&sp, buf)

			// No flags: a plain copy, checksum left alone (even a wrong one).
			got, err := split_all(Vnet_Hdr{}, want, MAX_OUT)
			testing.expect_value(t, err, Error.None)
			testing.expect_value(t, len(got), 1)
			one: Split
			testing.expect_value(t, split_init(&one, Vnet_Hdr{}, want, MAX_OUT), Error.None)
			testing.expect_value(t, split_bytes_left(&one), len(want))
			if len(got) == 1 {
				testing.expect(t, string(got[0]) == string(want), "plain copy differs")
			}

			// A partial checksum is completed.
			buf2 := make([]u8, 3000, context.temp_allocator)
			h, part := make_super(&sp, 1000, buf2)
			h.gso_type = GSO_NONE
			got, err = split_all(h, part, MAX_OUT)
			testing.expect_value(t, err, Error.None)
			if len(got) == 1 {
				testing.expect(t, string(got[0]) == string(want), "completed checksum differs")
				v, why := verify(got[0])
				testing.expectf(t, v, "%s", why)
			}
		}
	}
}

// An ICMPv6 echo request, with the checksum at offset 2 of the transport header.
@(test)
split_plain_icmp6 :: proc(t: ^testing.T) {
	sp := default_spec(true)
	pay := fill_payload(40)
	p := make([]u8, 40 + 8 + len(pay), context.temp_allocator)
	p[0] = 0x60
	put_be16(p[4:], u16(8 + len(pay)))
	p[6] = 58
	p[7] = 255
	copy(p[8:24], sp.src[:])
	copy(p[24:40], sp.dst[:])
	p[40] = 128
	put_be16(p[44:], 0x1234)
	put_be16(p[46:], 1)
	copy(p[48:], pay)
	// The full checksum, by the naive code.
	ck := ~naive_fold(naive_sum(p[40:], naive_pseudo(p, 40, true, 58)))
	want := make([]u8, len(p), context.temp_allocator)
	copy(want, p)
	put_be16(want[42:], ck)
	// The tun's view: the field holds the pseudo-header sum.
	put_be16(p[42:], naive_fold(naive_pseudo(p, 40, true, 58)))
	h := Vnet_Hdr {
		flags       = F_NEEDS_CSUM,
		csum_start  = 40,
		csum_offset = 2,
	}
	got, err := split_all(h, p, MAX_OUT)
	testing.expect_value(t, err, Error.None)
	if len(got) == 1 {
		testing.expect(t, string(got[0]) == string(want), "icmpv6 differs")
		v, why := verify(got[0])
		testing.expectf(t, v, "%s", why)
	}
}

@(test)
split_too_big :: proc(t: ^testing.T) {
	sp := default_spec(false)
	sp.payload = fill_payload(5000)
	buf := make([]u8, 70000, context.temp_allocator)
	h, pkt := make_super(&sp, 1400, buf)
	s: Split
	// Header 40 bytes + 1400: fits in 1440, not in 1439.
	testing.expect_value(t, split_init(&s, h, pkt, 1439), Error.Too_Big)
	testing.expect_value(t, split_count(&s), 0)
	out: [2000]u8
	_, ok := split_next(&s, out[:])
	testing.expect(t, !ok, "split_next after a failed init")
	testing.expect_value(t, split_init(&s, h, pkt, 1440), Error.None)
	testing.expect_value(t, split_max_out(&s), 1440)
	// A buffer that is too small takes nothing.
	small: [1439]u8
	n, ok2 := split_next(&s, small[:])
	testing.expect(t, !ok2 && n == 0, "short buffer must fail")
	testing.expect_value(t, split_count(&s), 4)
	// A plain packet larger than max_out.
	testing.expect_value(t, split_init(&s, Vnet_Hdr{}, pkt, 1000), Error.Too_Big)
	// Fewer bytes than gso_size: the real size counts, not gso_size.
	sp.payload = fill_payload(100)
	h, pkt = make_super(&sp, 1400, buf)
	testing.expect_value(t, split_init(&s, h, pkt, 140), Error.None)
	testing.expect_value(t, split_init(&s, h, pkt, 139), Error.Too_Big)
	// All packets, then nothing more.
	sp.payload = fill_payload(5000)
	h, pkt = make_super(&sp, 1400, buf)
	testing.expect_value(t, split_init(&s, h, pkt, 1440), Error.None)
	for _ in 0 ..< 4 {
		_, ok = split_next(&s, out[:])
		testing.expect(t, ok, "packet")
	}
	_, ok = split_next(&s, out[:])
	testing.expect(t, !ok, "one packet too many")
	testing.expect_value(t, split_count(&s), 0)
}

@(test)
split_too_many_segments :: proc(t: ^testing.T) {
	sp := default_spec(false)
	sp.payload = fill_payload(1025 * 20)
	buf := make([]u8, 70000, context.temp_allocator)
	h, pkt := make_super(&sp, 20, buf)
	s: Split
	testing.expect_value(t, split_init(&s, h, pkt, MAX_OUT), Error.Too_Big)
	h.gso_size = 21
	testing.expect_value(t, split_init(&s, h, pkt, MAX_OUT), Error.None)
	testing.expect_value(t, split_count(&s), 977)
}

@(test)
split_errors :: proc(t: ^testing.T) {
	buf := make([]u8, 70000, context.temp_allocator)
	sp4 := default_spec(false)
	sp4.payload = fill_payload(3000)
	h4, p4 := make_super(&sp4, 1000, buf)
	p4c := make([]u8, len(p4), context.temp_allocator)
	copy(p4c, p4)
	sp6 := default_spec(true)
	sp6.payload = fill_payload(3000)
	buf6 := make([]u8, 70000, context.temp_allocator)
	h6, p6 := make_super(&sp6, 1000, buf6)
	s: Split

	testing.expect_value(t, split_init(&s, h4, nil, MAX_OUT), Error.Short)
	testing.expect_value(t, split_init(&s, Vnet_Hdr{}, nil, MAX_OUT), Error.Short)

	h := h4
	h.gso_type = GSO_UDP
	testing.expect_value(t, split_init(&s, h, p4c, MAX_OUT), Error.Unsupported)
	h.gso_type = 2
	testing.expect_value(t, split_init(&s, h, p4c, MAX_OUT), Error.Unsupported)
	h.gso_type = 0x7f
	testing.expect_value(t, split_init(&s, h, p4c, MAX_OUT), Error.Unsupported)

	h = h4
	h.gso_size = 0
	testing.expect_value(t, split_init(&s, h, p4c, MAX_OUT), Error.Bad_Header)

	h = h4
	h.csum_start = 21
	testing.expect_value(t, split_init(&s, h, p4c, MAX_OUT), Error.Bad_Header)
	h = h4
	h.csum_offset = 6
	testing.expect_value(t, split_init(&s, h, p4c, MAX_OUT), Error.Bad_Header)

	// TCPv4 type on an IPv6 packet, and the other way round.
	testing.expect_value(t, split_init(&s, h4, p6, MAX_OUT), Error.Bad_Header)
	testing.expect_value(t, split_init(&s, h6, p4c, MAX_OUT), Error.Bad_Header)
	// A TCP type on a UDP packet.
	spu := default_spec(false)
	spu.udp = true
	spu.payload = fill_payload(3000)
	bu := make([]u8, 70000, context.temp_allocator)
	hu, pu := make_super(&spu, 1000, bu)
	h = hu
	h.gso_type = GSO_TCPV4
	h.csum_offset = 16
	testing.expect_value(t, split_init(&s, h, pu, MAX_OUT), Error.Bad_Header)
	// And the other way.
	h = h4
	h.gso_type = GSO_UDP_L4
	h.csum_offset = 6
	testing.expect_value(t, split_init(&s, h, p4c, MAX_OUT), Error.Bad_Header)

	// Not IP.
	bad := make([]u8, 100, context.temp_allocator)
	bad[0] = 0x90
	testing.expect_value(t, split_init(&s, h4, bad, MAX_OUT), Error.Not_Ip)

	// Lengths that lie.
	for delta in ([]int{-1, 1, -100, 1000}) {
		lie := make([]u8, len(p4c), context.temp_allocator)
		copy(lie, p4c)
		put_be16(lie[2:], u16(len(p4c) + delta))
		testing.expect_value(t, split_init(&s, h4, lie, MAX_OUT), Error.Bad_Length)
	}
	lie6 := make([]u8, len(p6), context.temp_allocator)
	copy(lie6, p6)
	put_be16(lie6[4:], u16(len(p6) - 41))
	testing.expect_value(t, split_init(&s, h6, lie6, MAX_OUT), Error.Bad_Length)
	// A packet longer than its length field (trailing bytes).
	testing.expect_value(t, split_init(&s, h4, p4c[:len(p4c) - 1], MAX_OUT), Error.Bad_Length)

	// IPv4: header length below 20, above the packet, and a fragment.
	hdrbad := make([]u8, len(p4c), context.temp_allocator)
	copy(hdrbad, p4c)
	hdrbad[0] = 0x44
	testing.expect_value(t, split_init(&s, h4, hdrbad, MAX_OUT), Error.Bad_Header)
	copy(hdrbad, p4c)
	hdrbad[6] = 0x20 // more fragments
	testing.expect_value(t, split_init(&s, h4, hdrbad, MAX_OUT), Error.Unsupported)
	copy(hdrbad, p4c)
	put_be16(hdrbad[6:], 0x0008) // fragment offset
	testing.expect_value(t, split_init(&s, h4, hdrbad, MAX_OUT), Error.Unsupported)

	// TCP header length: below 20, and past the end.
	copy(hdrbad, p4c)
	hdrbad[20 + 12] = 0x40
	testing.expect_value(t, split_init(&s, h4, hdrbad, MAX_OUT), Error.Bad_Header)
	tiny := make([]u8, 20 + 20 + 4, context.temp_allocator)
	tsp := default_spec(false)
	tsp.payload = fill_payload(4)
	tb := make([]u8, 200, context.temp_allocator)
	th, tp := make_super(&tsp, 4, tb)
	copy(tiny, tp)
	tiny[20 + 12] = 0xf0 // 60 bytes, but only 24 are there
	testing.expect_value(t, split_init(&s, th, tiny, MAX_OUT), Error.Short)

	// Short packets of both kinds.
	for n in 1 ..< 45 {
		hh := h4
		hh.flags = 0
		e := split_init(&s, hh, p4c[:n], MAX_OUT)
		testing.expectf(t, e != .None, "length %d must fail", n)
		hh = h6
		hh.flags = 0
		e = split_init(&s, hh, p6[:n], MAX_OUT)
		testing.expectf(t, e != .None, "v6 length %d must fail", n)
	}

	// IPv6 extension headers: a fragment header and ESP are refused, and so is
	// a chain that runs past the end or never ends.
	for nh in ([]u8{44, 50, 51, 59, 200}) {
		x := make([]u8, len(p6), context.temp_allocator)
		copy(x, p6)
		x[6] = nh
		testing.expect_value(t, split_init(&s, h6, x, MAX_OUT), Error.Unsupported)
	}
	{
		x := make([]u8, 40 + 8 * 20 + 40, context.temp_allocator)
		x[0] = 0x60
		put_be16(x[4:], u16(len(x) - 40))
		x[6] = 0
		for i in 0 ..< 20 {
			x[40 + i * 8] = 0 // hop-by-hop after hop-by-hop, never TCP
		}
		hh := h6
		hh.flags = 0
		testing.expect_value(t, split_init(&s, hh, x, MAX_OUT), Error.Unsupported)
		// A length that points past the end.
		x[40] = 0
		x[41] = 255
		testing.expect_value(t, split_init(&s, hh, x, MAX_OUT), Error.Short)
	}

	// A plain packet with csum_start or csum_offset outside the packet.
	hh := Vnet_Hdr {
		flags       = F_NEEDS_CSUM,
		csum_start  = 60,
		csum_offset = 16,
	}
	pp := p4c[:70]
	testing.expect_value(t, split_init(&s, hh, pp, MAX_OUT), Error.Bad_Header) // 60 + 16 + 2 > 70
	hh.csum_start = 52
	testing.expect_value(t, split_init(&s, hh, pp, MAX_OUT), Error.None) // 52 + 16 + 2 = 70
	hh.csum_start = 53
	testing.expect_value(t, split_init(&s, hh, pp, MAX_OUT), Error.Bad_Header)
	hh.csum_start = 0xffff
	hh.csum_offset = 0xffff
	testing.expect_value(t, split_init(&s, hh, pp, MAX_OUT), Error.Bad_Header)
}

// Writes into a buffer that has guard bytes around it, and checks the guards.
@(test)
split_never_writes_outside :: proc(t: ^testing.T) {
	sp := default_spec(true)
	ts := ts_options(1, 2)
	sp.topts = ts[:]
	sp.payload = fill_payload(5000)
	buf := make([]u8, 70000, context.temp_allocator)
	h, pkt := make_super(&sp, 1000, buf)
	s: Split
	testing.expect_value(t, split_init(&s, h, pkt, MAX_OUT), Error.None)
	guard := make([]u8, 3000, context.temp_allocator)
	for i in 0 ..< len(guard) {
		guard[i] = 0xa5
	}
	for split_count(&s) > 0 {
		// The buffer is exactly as long as needed.
		need := split_max_out(&s)
		n, ok := split_next(&s, guard[100:][:need])
		testing.expect(t, ok, "split_next")
		testing.expect(t, n <= need, "n > need")
		for i in 0 ..< 100 {
			testing.expect(t, guard[i] == 0xa5, "write before the buffer")
		}
		for i in 100 + need ..< len(guard) {
			testing.expect(t, guard[i] == 0xa5, "write after the buffer")
		}
	}
}

mutation_check :: proc(t: ^testing.T, h: Vnet_Hdr, pkt: []u8, out: []u8, kind: int, count: ^int) {
	s: Split
	if split_init(&s, h, pkt, len(out)) != .None {
		return
	}
	count^ += 1
	for split_count(&s) > 0 {
		n, ok := split_next(&s, out)
		if !testing.expectf(t, ok, "kind %d: split_next failed", kind) {
			return
		}
		// A plain packet with a partial checksum is only completed: if the
		// test changed an address, the old pseudo-header sum is wrong.
		if h.gso_type &~ GSO_ECN != GSO_NONE {
			v, why := verify(out[:n])
			testing.expectf(t, v, "kind %d: %s", kind, why)
		}
	}
}

// Every byte of the headers of a good packet set to several values, and the
// virtio header too. Never a crash. What is accepted gives right packets.
@(test)
split_mutations :: proc(t: ^testing.T) {
	r := Rng {
		s = 0x1234567,
	}
	ts := ts_options(9, 9)
	count := 0
	for kind in 0 ..< 6 {
		sp := default_spec(kind % 2 == 1)
		sp.payload = fill_payload(700)
		switch kind {
		case 2, 3:
			sp.udp = true
		case 4:
			sp.topts = ts[:]
			sp.ip_opts = {1, 1, 1, 0}
		case 5:
			h1 := hbh_header(PROTO_TCP)
			sp.ext = h1[:]
			sp.ext_nh = 0
			sp.topts = ts[:]
		}
		buf := make([]u8, 70000, context.temp_allocator)
		h0, p0 := make_super(&sp, 200, buf)
		work := make([]u8, len(p0), context.temp_allocator)
		out := make([]u8, MAX_OUT, context.temp_allocator)
		for pos in 0 ..< min(len(p0), 90) {
			vals := [?]u8{0, 1, 0x0f, 0x10, 0x40, 0x45, 0x60, 0x7f, 0x80, 0xff, u8(rng_next(&r)), p0[pos] + 1, p0[pos] ~ 0x04}
			for v in vals {
				copy(work, p0)
				work[pos] = v
				mutation_check(t, h0, work, out, kind, &count)
			}
		}
		// Truncations.
		for n in 0 ..= len(p0) {
			mutation_check(t, h0, p0[:n], out, kind, &count)
			hh := h0
			hh.flags = 0
			mutation_check(t, hh, p0[:n], out, kind, &count)
		}
		// The virtio header.
		for field in 0 ..< 5 {
			for k in 0 ..< 40 {
				hh := h0
				v := u16(rng_next(&r))
				if k < 8 {
					v = u16(k)
				} else if k < 16 {
					v = 0xffff - u16(k)
				}
				switch field {
				case 0:
					hh.flags = u8(v)
				case 1:
					hh.gso_type = u8(v)
				case 2:
					hh.gso_size = v
				case 3:
					hh.csum_start = v
				case 4:
					hh.csum_offset = v
				}
				mutation_check(t, hh, p0, out, kind, &count)
			}
		}
	}
	testing.expect(t, count > 100, "too few accepted packets: the test does nothing")
}

// Random bytes: no crash, whatever the virtio header says.
@(test)
split_random_garbage :: proc(t: ^testing.T) {
	r := Rng {
		s = 0xdeadbeef,
	}
	out := make([]u8, 70000, context.temp_allocator)
	buf := make([]u8, 3000, context.temp_allocator)
	accepted := 0
	for _ in 0 ..< 60000 {
		n := rng_n(&r, 300)
		pkt := buf[:n]
		for i in 0 ..< n {
			pkt[i] = u8(rng_next(&r))
		}
		// Make the start look like IP most of the time.
		if n > 0 {
			switch rng_n(&r, 4) {
			case 0:
				pkt[0] = 0x45
			case 1:
				pkt[0] = 0x60
			case 2:
				pkt[0] = 0x40 | u8(rng_n(&r, 16))
			}
		}
		if n > 9 && rng_n(&r, 2) == 0 {
			pkt[9] = PROTO_TCP if rng_n(&r, 2) == 0 else PROTO_UDP
			if n > 6 {
				pkt[6] = PROTO_TCP if rng_n(&r, 2) == 0 else PROTO_UDP
			}
			if rng_n(&r, 2) == 0 {
				pkt[6] &= 0x1f
			}
			if rng_n(&r, 2) == 0 {
				put_be16(pkt[2:], u16(n))
			}
			if n > 5 && rng_n(&r, 2) == 0 {
				put_be16(pkt[4:], u16(n - 40))
			}
		}
		types := [8]u8{0, 1, 4, 5, 0x81, 0x84, 3, 9}
		offsets := [4]u16{6, 16, 2, u16(rng_next(&r))}
		h := Vnet_Hdr {
			flags       = u8(rng_n(&r, 4)),
			gso_type    = types[rng_n(&r, 8)],
			gso_size    = u16(rng_next(&r)),
			csum_start  = u16(rng_n(&r, 80)),
			csum_offset = offsets[rng_n(&r, 4)],
		}
		if rng_n(&r, 2) == 0 {
			h.gso_size = u16(1 + rng_n(&r, 200))
		}
		s: Split
		if split_init(&s, h, pkt, len(out)) != .None {
			continue
		}
		accepted += 1
		for split_count(&s) > 0 {
			_, ok := split_next(&s, out)
			testing.expect(t, ok, "split_next failed after a good init")
			if !ok {
				break
			}
		}
	}
	fmt.printfln("split_random_garbage: accepted %d of 60000 random packets", accepted)
}

// How fast is it? Only prints; no assertion.
@(test)
split_speed :: proc(t: ^testing.T) {
	sp := default_spec(false)
	ts := ts_options(1, 2)
	sp.topts = ts[:]
	mss := 1360 - 12
	sp.payload = fill_payload(mss * 45)
	buf := make([]u8, 70000, context.temp_allocator)
	h, pkt := make_super(&sp, mss, buf)
	out := make([]u8, MAX_OUT, context.temp_allocator)
	rounds := 3000
	start := time.tick_now()
	segs := 0
	for _ in 0 ..< rounds {
		s: Split
		if split_init(&s, h, pkt, MAX_OUT) != .None {
			return
		}
		for split_count(&s) > 0 {
			split_next(&s, out)
			segs += 1
		}
	}
	d := time.tick_since(start)
	ns := f64(d) / f64(segs)
	fmt.printfln("split: %.1f ns per packet of %d bytes, %.0f ns per 45-packet super-packet", ns, mss + 52, ns * 45)
	// Same with a plain copy, to see what the checksum costs.
	start = time.tick_now()
	for _ in 0 ..< rounds * 45 {
		copy(out, pkt[:1400])
	}
	d = time.tick_since(start)
	fmt.printfln("copy only: %.1f ns per 1400 bytes", f64(d) / f64(rounds * 45))
}
