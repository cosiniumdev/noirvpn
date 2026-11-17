// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package mss

import "core:testing"

// A packet builder and a slow checksum of our own, independent of the code under test.

// The one's complement sum of `b` as 16-bit words, folded, not inverted.
sum16 :: proc(b: []u8, seed: u32 = 0) -> u32 {
	s := seed
	for i := 0; i + 1 < len(b); i += 2 {
		s += u32(b[i]) << 8 | u32(b[i + 1])
	}
	if len(b) % 2 == 1 {
		s += u32(b[len(b) - 1]) << 8
	}
	for s >> 16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return s
}

// The TCP checksum of an IP packet computed from scratch (the field is skipped
// by zeroing a copy).
tcp_checksum :: proc(pkt: []u8) -> u16 {
	t, v6 := 20, false
	if pkt[0] >> 4 == 6 {
		t, v6 = 40, true
	} else {
		t = int(pkt[0] & 0x0f) * 4
	}
	seg := make([]u8, len(pkt) - t)
	defer delete(seg)
	copy(seg, pkt[t:])
	seg[16], seg[17] = 0, 0
	seed: u32
	if v6 {
		seed = sum16(pkt[8:40]) + u32(len(seg)) + 6
	} else {
		seed = sum16(pkt[12:20]) + u32(len(seg)) + 6
	}
	return ~u16(sum16(seg, seed))
}

// Is the TCP checksum of the packet right?
checksum_ok :: proc(pkt: []u8) -> bool {
	t := 40 if pkt[0] >> 4 == 6 else int(pkt[0] & 0x0f) * 4
	have := u16(pkt[t + 16]) << 8 | u16(pkt[t + 17])
	return have == tcp_checksum(pkt)
}

// An IP packet with a TCP header of `flags` and these options (padded with
// zeros to a multiple of 4), `payload` bytes of data, and a good checksum.
make_pkt :: proc(v6: bool, flags: u8, opts: []u8, payload := 0) -> []u8 {
	olen := (len(opts) + 3) / 4 * 4
	tcp_len := 20 + olen + payload
	ip := 40 if v6 else 20
	pkt := make([]u8, ip + tcp_len)
	if v6 {
		pkt[0] = 0x60
		pkt[4], pkt[5] = u8(tcp_len >> 8), u8(tcp_len)
		pkt[6] = 6
		pkt[7] = 64
		for i in 8 ..< 40 {
			pkt[i] = u8(i * 7)
		}
	} else {
		pkt[0] = 0x45
		total := ip + tcp_len
		pkt[2], pkt[3] = u8(total >> 8), u8(total)
		pkt[8] = 64
		pkt[9] = 6
		pkt[12], pkt[13], pkt[14], pkt[15] = 10, 8, 0, 2
		pkt[16], pkt[17], pkt[18], pkt[19] = 10, 8, 0, 1
	}
	t := pkt[ip:]
	t[0], t[1], t[2], t[3] = 0x9c, 0x40, 0x01, 0xbb
	t[4], t[5], t[6], t[7] = 0x12, 0x34, 0x56, 0x78
	t[12] = u8((20 + olen) / 4 << 4)
	t[13] = flags
	t[14], t[15] = 0xff, 0xff
	copy(t[20:], opts)
	for i in 0 ..< payload {
		t[20 + olen + i] = u8(i * 13 + 1)
	}
	ck := tcp_checksum(pkt)
	t[16], t[17] = u8(ck >> 8), u8(ck)
	return pkt
}

// A typical client SYN: MSS, SACK permitted, timestamps, NOP, window scale.
syn_opts :: proc(mss: u16) -> []u8 {
	o := make([]u8, 20, context.temp_allocator)
	copy(o, []u8{2, 4, u8(mss >> 8), u8(mss), 4, 2, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 1, 3, 3, 7})
	return o
}

mss_of :: proc(pkt: []u8, t: int) -> int {
	return int(pkt[t + 22]) << 8 | int(pkt[t + 23])
}

SYN :: 0x02
ACK :: 0x10

@(test)
test_clamp_ipv4_syn :: proc(t: ^testing.T) {
	pkt := make_pkt(false, SYN, syn_opts(1460))
	defer delete(pkt)
	testing.expect(t, checksum_ok(pkt))
	testing.expect(t, clamp_syn(pkt, 1360))
	testing.expect_value(t, mss_of(pkt, 20), 1360)
	testing.expect(t, checksum_ok(pkt))
	// The other options are untouched.
	testing.expect_value(t, pkt[20 + 20 + 4], 4)
	testing.expect_value(t, pkt[20 + 20 + 16], 1)
}

@(test)
test_clamp_ipv6_syn :: proc(t: ^testing.T) {
	pkt := make_pkt(true, SYN, syn_opts(1440))
	defer delete(pkt)
	testing.expect(t, checksum_ok(pkt))
	testing.expect(t, clamp_syn(pkt, 1360))
	// IPv6: 20 less.
	testing.expect_value(t, mss_of(pkt, 40), 1340)
	testing.expect(t, checksum_ok(pkt))
}

@(test)
test_clamp_syn_ack :: proc(t: ^testing.T) {
	for v6 in ([2]bool{false, true}) {
		pkt := make_pkt(v6, SYN | ACK, syn_opts(1460))
		defer delete(pkt)
		testing.expect(t, clamp_syn(pkt, 1300))
		ip := 40 if v6 else 20
		want := 1280 if v6 else 1300
		testing.expect_value(t, mss_of(pkt, ip), want)
		testing.expect(t, checksum_ok(pkt))
	}
}

@(test)
test_clamp_mss_only_option_and_not_first :: proc(t: ^testing.T) {
	// MSS as the only option.
	a := make_pkt(false, SYN, {2, 4, 0x05, 0xb4})
	defer delete(a)
	testing.expect(t, clamp_syn(a, 1000))
	testing.expect_value(t, mss_of(a, 20), 1000)
	testing.expect(t, checksum_ok(a))
	// After NOPs and another option.
	b := make_pkt(true, SYN, {1, 1, 4, 2, 2, 4, 0x05, 0xb4})
	defer delete(b)
	testing.expect(t, clamp_syn(b, 1000))
	testing.expect_value(t, int(b[40 + 20 + 6]) << 8 | int(b[40 + 20 + 7]), 980)
	testing.expect(t, checksum_ok(b))
}

@(test)
test_clamp_leaves_what_it_should :: proc(t: ^testing.T) {
	for v6 in ([2]bool{false, true}) {
		// Not a SYN: the same options, but an ACK with data, and a FIN, RST.
		for flags in ([]u8{ACK, ACK | 0x08, 0x01 | ACK, 0x04}) {
			pkt := make_pkt(v6, flags, syn_opts(1460), 100)
			defer delete(pkt)
			orig := make([]u8, len(pkt))
			defer delete(orig)
			copy(orig, pkt)
			testing.expect(t, !clamp_syn(pkt, 1300))
			testing.expect(t, string(pkt) == string(orig))
		}
		// The MSS is below the limit already, or equal to it.
		for mss in ([]u16{1200, 1300, 1280, 1000}) {
			pkt := make_pkt(v6, SYN, syn_opts(mss))
			defer delete(pkt)
			orig := make([]u8, len(pkt))
			defer delete(orig)
			copy(orig, pkt)
			limit := 1300
			if v6 {
				limit = 1280
			}
			testing.expect_value(t, clamp_syn(pkt, 1300), int(mss) > limit)
			if int(mss) <= limit {
				testing.expect(t, string(pkt) == string(orig))
			}
		}
		// No MSS option.
		pkt := make_pkt(v6, SYN, {4, 2, 1, 1, 3, 3, 7, 1})
		defer delete(pkt)
		testing.expect(t, !clamp_syn(pkt, 1000))
		// No options at all.
		pkt2 := make_pkt(v6, SYN, {})
		defer delete(pkt2)
		testing.expect(t, !clamp_syn(pkt2, 1000))
		// Limit 0 is off.
		pkt3 := make_pkt(v6, SYN, syn_opts(1460))
		defer delete(pkt3)
		testing.expect(t, !clamp_syn(pkt3, 0))
		testing.expect(t, checksum_ok(pkt3))
	}
}

@(test)
test_clamp_malformed_options :: proc(t: ^testing.T) {
	cases := [][]u8 {
		{1, 1, 1, 1, 1, 1, 2, 4}, // an MSS option that runs past the header end
		{4, 0, 2, 4, 0x05, 0xb4, 0, 0}, // length 0
		{4, 1, 2, 4, 0x05, 0xb4, 0, 0}, // length 1
		{4, 20, 2, 4, 0x05, 0xb4, 0, 0}, // runs past the header
		{1, 1, 1, 2}, // the option kind is the last byte
		{0, 2, 4, 0x05, 0xb4}, // EOL before the MSS option
		{2, 3, 0x05, 0xb4}, // MSS with a wrong length
		{2, 6, 0x05, 0xb4, 0, 0}, // MSS with a wrong length
		{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, // NOPs only
		{8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 2, 4, 5, 0xb4}, // fine: timestamps then MSS (control)
	}
	for opts, k in cases {
		for v6 in ([2]bool{false, true}) {
			pkt := make_pkt(v6, SYN, opts)
			defer delete(pkt)
			orig := make([]u8, len(pkt))
			defer delete(orig)
			copy(orig, pkt)
			changed := clamp_syn(pkt, 1000)
			if k == len(cases) - 1 {
				testing.expect(t, changed)
				testing.expect(t, checksum_ok(pkt))
			} else {
				testing.expectf(t, !changed, "case %d v6=%v changed", k, v6)
				testing.expectf(t, string(pkt) == string(orig), "case %d v6=%v modified", k, v6)
			}
		}
	}
}

@(test)
test_clamp_short_and_odd_packets :: proc(t: ^testing.T) {
	pkt := make_pkt(false, SYN, syn_opts(1460))
	defer delete(pkt)
	// Every prefix of a SYN: nothing crashes, and the packet is not changed
	// unless the whole header is there.
	for n in 0 ..< len(pkt) {
		cut := make([]u8, n)
		defer delete(cut)
		copy(cut, pkt[:n])
		testing.expect(t, !clamp_syn(cut, 1000))
	}
	pkt6 := make_pkt(true, SYN, syn_opts(1460))
	defer delete(pkt6)
	for n in 0 ..< len(pkt6) {
		cut := make([]u8, n)
		defer delete(cut)
		copy(cut, pkt6[:n])
		testing.expect(t, !clamp_syn(cut, 1000))
	}
	// The data offset says the header is longer than the packet.
	bad := make_pkt(false, SYN, syn_opts(1460))
	defer delete(bad)
	bad[20 + 12] = 15 << 4
	testing.expect(t, !clamp_syn(bad[:60], 1000))
	// The data offset is below 5.
	bad[20 + 12] = 4 << 4
	testing.expect(t, !clamp_syn(bad, 1000))
	// A version that is neither 4 nor 6.
	v := make_pkt(false, SYN, syn_opts(1460))
	defer delete(v)
	v[0] = 0x55
	testing.expect(t, !clamp_syn(v, 1000))
	// An IPv4 header length below 20.
	v[0] = 0x44
	testing.expect(t, !clamp_syn(v, 1000))
}

@(test)
test_clamp_ipv4_header_options_and_fragments :: proc(t: ^testing.T) {
	// An IPv4 header with options (IHL 6): TCP starts at 24.
	base := make_pkt(false, SYN, syn_opts(1460))
	defer delete(base)
	pkt := make([]u8, len(base) + 4)
	defer delete(pkt)
	copy(pkt, base[:20])
	copy(pkt[24:], base[20:])
	pkt[0] = 0x46
	testing.expect(t, clamp_syn(pkt, 1360))
	testing.expect_value(t, mss_of(pkt, 24), 1360)
	testing.expect(t, checksum_ok(pkt))

	// Fragment with an offset: not touched.
	// First fragment (offset 0, more fragments set): has the header, so it is
	// clamped, with the right checksum difference.
	frag := make_pkt(false, SYN, syn_opts(1460))
	defer delete(frag)
	frag[6], frag[7] = 0x00, 0x10 // offset 16 * 8
	testing.expect(t, !clamp_syn(frag, 1360))
	testing.expect_value(t, mss_of(frag, 20), 1460)
	frag[6], frag[7] = 0x20, 0x00 // MF, offset 0
	testing.expect(t, clamp_syn(frag, 1360))
	testing.expect(t, checksum_ok(frag))
	// The don't fragment flag is not a fragment.
	frag[6], frag[7] = 0x40, 0x00
	frag[20 + 22], frag[20 + 23] = 0x05, 0xb4
	testing.expect(t, clamp_syn(frag, 1360))
}

@(test)
test_clamp_not_tcp_and_extension_headers :: proc(t: ^testing.T) {
	// UDP, ICMP.
	for p in ([]u8{17, 1, 47}) {
		pkt := make_pkt(false, SYN, syn_opts(1460))
		defer delete(pkt)
		pkt[9] = p
		testing.expect(t, !clamp_syn(pkt, 1000))
		pkt6 := make_pkt(true, SYN, syn_opts(1460))
		defer delete(pkt6)
		pkt6[6] = p
		testing.expect(t, !clamp_syn(pkt6, 1000))
	}
	// IPv6 with a hop-by-hop header before TCP: not looked at.
	pkt6 := make_pkt(true, SYN, syn_opts(1460))
	defer delete(pkt6)
	ext := make([]u8, len(pkt6) + 8)
	defer delete(ext)
	copy(ext, pkt6[:40])
	ext[6] = 0
	ext[40] = 6
	copy(ext[48:], pkt6[40:])
	testing.expect(t, !clamp_syn(ext, 1000))
}

@(test)
test_clamp_checksum_many_values :: proc(t: ^testing.T) {
	// The incremental checksum equals the full one for many values, with data
	// behind the header and an odd length.
	for mss in 1000 ..= 1460 {
		for v6 in ([2]bool{false, true}) {
			pkt := make_pkt(v6, SYN | ACK, syn_opts(u16(mss) + 1000), mss % 3)
			defer delete(pkt)
			testing.expect(t, clamp_syn(pkt, mss))
			testing.expect(t, checksum_ok(pkt))
			ip := 40 if v6 else 20
			testing.expect_value(t, mss_of(pkt, ip), mss - (20 if v6 else 0))
		}
	}
}

@(test)
test_clamp_without_checksum_fix :: proc(t: ^testing.T) {
	// A packet with a partial checksum: only the option changes.
	pkt := make_pkt(false, SYN, syn_opts(1460))
	defer delete(pkt)
	before := u16(pkt[20 + 16]) << 8 | u16(pkt[20 + 17])
	testing.expect(t, clamp_syn(pkt, 1360, false))
	testing.expect_value(t, mss_of(pkt, 20), 1360)
	testing.expect_value(t, u16(pkt[20 + 16]) << 8 | u16(pkt[20 + 17]), before)
}
