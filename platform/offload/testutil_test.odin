// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package offload

// Test helpers: a slow byte by byte checksum, a packet builder and a packet
// checker. They use nothing from the code under test (except constants), so
// a mistake in one cannot hide a mistake in the other.

// ---- the naive checksum (RFC 1071, one 16 bit word at a time) ----

naive_sum :: proc(data: []u8, init: u32 = 0) -> u32 {
	s := init
	i := 0
	for ; i + 1 < len(data); i += 2 {
		s += u32(data[i]) << 8 | u32(data[i + 1])
	}
	if i < len(data) {
		s += u32(data[i]) << 8
	}
	return s
}

naive_fold :: proc(s: u32) -> u16 {
	x := s
	for x >> 16 != 0 {
		x = (x & 0xffff) + (x >> 16)
	}
	return u16(x)
}

// ---- a packet builder ----

Spec :: struct {
	v6:       bool,
	udp:      bool,
	proto:    u8, // not 0: use this protocol number (a transport header of 8 bytes, checksum at 6, like UDP)
	src:      [16]u8,
	dst:      [16]u8,
	sport:    u16,
	dport:    u16,
	seq:      u32,
	ack:      u32,
	flags:    u8,
	window:   u16,
	topts:    []u8, // TCP options, a multiple of 4 bytes
	id:       u16,
	df:       bool,
	ttl:      u8,
	tos:      u8, // IPv6: the traffic class
	flow:     u32, // IPv6 flow label
	ip_opts:  []u8, // IPv4 options, a multiple of 4 bytes
	ext:      []u8, // IPv6 extension headers, as they are on the wire
	ext_nh:   u8, // IPv6: the next header of the fixed header when `ext` is used
	urg_ptr:  u16,
	payload:  []u8,
	// Trailing bytes after the IP length (not counted in it).
	trailing: int,
	// Corrupt the IPv4 header checksum or the TCP/UDP checksum wrong (one bit).
	bad_ip_csum:  bool,
	bad_csum:     bool,
}

default_spec :: proc(v6: bool) -> Spec {
	sp: Spec
	sp.v6 = v6
	if v6 {
		sp.src = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		sp.dst = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	} else {
		sp.src = {0 = 10, 1 = 8, 2 = 0, 3 = 2}
		sp.dst = {0 = 10, 1 = 8, 2 = 0, 3 = 1}
	}
	sp.sport = 40000
	sp.dport = 5201
	sp.seq = 1000
	sp.ack = 777
	sp.flags = 0x10 // ACK
	sp.window = 502
	sp.id = 100
	sp.df = true
	sp.ttl = 64
	return sp
}

// A hop-by-hop header of 8 bytes: the next header, length 0, a PadN of 4.
hbh_header :: proc(next: u8) -> [8]u8 {
	return {next, 0, 1, 4, 0, 0, 0, 0}
}

// 12 bytes of options: NOP NOP timestamps.
ts_options :: proc(tsval, tsecr: u32) -> [12]u8 {
	o: [12]u8
	o[0], o[1], o[2], o[3] = 1, 1, 8, 10
	put_be32(o[4:], tsval)
	put_be32(o[8:], tsecr)
	return o
}

spec_proto :: proc(sp: ^Spec) -> u8 {
	if sp.proto != 0 {
		return sp.proto
	}
	return PROTO_UDP if sp.udp else PROTO_TCP
}

spec_is_tcp :: proc(sp: ^Spec) -> bool {
	return spec_proto(sp) == PROTO_TCP
}

// Builds the packet with all checksums right. Returns a slice of `buf`.
build :: proc(sp: ^Spec, buf: []u8) -> []u8 {
	proto := spec_proto(sp)
	tcp := proto == PROTO_TCP
	iphl := 40 + len(sp.ext) if sp.v6 else 20 + len(sp.ip_opts)
	tl := 20 + len(sp.topts) if tcp else 8
	total := iphl + tl + len(sp.payload)
	p := buf[:total + sp.trailing]
	for i in 0 ..< len(p) {
		p[i] = 0
	}
	if sp.v6 {
		p[0] = 0x60 | sp.tos >> 4
		p[1] = (sp.tos & 0x0f) << 4 | u8(sp.flow >> 16 & 0x0f)
		p[2] = u8(sp.flow >> 8)
		p[3] = u8(sp.flow)
		put_be16(p[4:], u16(total - 40))
		p[6] = proto
		if len(sp.ext) > 0 {
			p[6] = sp.ext_nh
		}
		p[7] = sp.ttl
		copy(p[8:24], sp.src[:])
		copy(p[24:40], sp.dst[:])
		copy(p[40:], sp.ext)
	} else {
		p[0] = 0x40 | u8(iphl / 4)
		p[1] = sp.tos
		put_be16(p[2:], u16(total))
		put_be16(p[4:], sp.id)
		if sp.df {
			p[6] = 0x40
		}
		p[8] = sp.ttl
		p[9] = proto
		copy(p[12:16], sp.src[:4])
		copy(p[16:20], sp.dst[:4])
		copy(p[20:], sp.ip_opts)
		put_be16(p[10:], ~naive_fold(naive_sum(p[:iphl])))
	}
	t := p[iphl:]
	put_be16(t[0:], sp.sport)
	put_be16(t[2:], sp.dport)
	if tcp {
		put_be32(t[4:], sp.seq)
		put_be32(t[8:], sp.ack)
		t[12] = u8(tl / 4) << 4
		t[13] = sp.flags
		put_be16(t[14:], sp.window)
		put_be16(t[18:], sp.urg_ptr)
		copy(t[20:], sp.topts)
		copy(t[tl:], sp.payload)
	} else {
		put_be16(t[4:], u16(tl + len(sp.payload)))
		copy(t[8:], sp.payload)
	}
	ck := ~naive_fold(naive_sum(t[:tl + len(sp.payload)], naive_pseudo(p[:total], iphl, sp.v6, proto)))
	if ck == 0 && !tcp {
		ck = 0xffff
	}
	put_be16(t[16:] if tcp else t[6:], ck)
	if sp.bad_csum {
		t[17 if tcp else 7] ~= 0x01
	}
	if sp.bad_ip_csum && !sp.v6 {
		p[11] ~= 0x01
	}
	return p
}

// The sum of the pseudo header, one word at a time.
naive_pseudo :: proc(p: []u8, iphl: int, v6: bool, proto: u8) -> u32 {
	tlen := len(p) - iphl
	ph: [40]u8
	n := 0
	if v6 {
		copy(ph[0:32], p[8:40])
		put_be32(ph[32:], u32(tlen))
		ph[39] = proto
		n = 40
	} else {
		copy(ph[0:8], p[12:20])
		ph[9] = proto
		put_be16(ph[10:], u16(tlen))
		n = 12
	}
	return naive_sum(ph[:n])
}

// ---- a packet checker ----

// Checks lengths and all checksums. `why` says what is wrong.
verify :: proc(pkt: []u8) -> (ok: bool, why: string) {
	if len(pkt) < 20 {
		return false, "short"
	}
	v6 := false
	iphl := 0
	proto: u8
	switch pkt[0] >> 4 {
	case 4:
		iphl = int(pkt[0] & 0xf) * 4
		if iphl < 20 || iphl > len(pkt) {
			return false, "bad ihl"
		}
		if int(be16(pkt[2:])) != len(pkt) {
			return false, "bad total length"
		}
		if naive_fold(naive_sum(pkt[:iphl])) != 0xffff {
			return false, "bad ip header checksum"
		}
		proto = pkt[9]
	case 6:
		v6 = true
		if len(pkt) < 40 {
			return false, "short v6"
		}
		if int(be16(pkt[4:])) != len(pkt) - 40 {
			return false, "bad payload length"
		}
		iphl = 40
		nh := pkt[6]
		for nh == 0 || nh == 43 || nh == 60 {
			if iphl + 8 > len(pkt) {
				return false, "ext past end"
			}
			next := pkt[iphl]
			iphl += (int(pkt[iphl + 1]) + 1) * 8
			nh = next
		}
		if iphl > len(pkt) {
			return false, "ext past end"
		}
		proto = nh
	case:
		return false, "not ip"
	}
	t := pkt[iphl:]
	if proto == PROTO_TCP {
		if len(t) < 20 {
			return false, "short tcp"
		}
	} else if len(t) < 8 {
		return false, "short transport"
	}
	sum := naive_fold(naive_sum(t, naive_pseudo(pkt, iphl, v6, proto)))
	if sum != 0xffff {
		return false, "bad transport checksum"
	}
	if proto == PROTO_UDP && int(be16(t[4:])) != len(t) {
		return false, "bad udp length"
	}
	return true, ""
}

// ---- helpers for the tests ----

// Payload bytes that tell where they are.
fill_payload :: proc(n: int, salt: int = 0) -> []u8 {
	p := make([]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		p[i] = u8(i * 7 + i / 251 + salt * 13 + 3)
	}
	return p
}

// A tiny random number generator (xorshift64*), so the tests are repeatable.
Rng :: struct {
	s: u64,
}

rng_next :: proc(r: ^Rng) -> u64 {
	r.s ~= r.s >> 12
	r.s ~= r.s << 25
	r.s ~= r.s >> 27
	return r.s * 0x2545F4914F6CDD1D
}

rng_n :: proc(r: ^Rng, n: int) -> int {
	return int(rng_next(r) % u64(n))
}

// The packet a tun gives for a TSO or USO packet: all data in one packet,
// partial checksum. The checksum field holds the pseudo-header sum, not
// inverted.
make_super :: proc(sp: ^Spec, mss: int, buf: []u8) -> (h: Vnet_Hdr, pkt: []u8) {
	pkt = build(sp, buf)
	tcp := spec_is_tcp(sp)
	iphl := 40 + len(sp.ext) if sp.v6 else 20 + len(sp.ip_opts)
	tl := 20 + len(sp.topts) if tcp else 8
	total := iphl + tl + len(sp.payload)
	ps := naive_fold(naive_pseudo(pkt[:total], iphl, sp.v6, spec_proto(sp)))
	field := iphl + (16 if tcp else 6)
	put_be16(pkt[field:], ps)
	h.flags = F_NEEDS_CSUM
	if tcp {
		h.gso_type = GSO_TCPV6 if sp.v6 else GSO_TCPV4
		if sp.flags & TCP_CWR != 0 {
			h.gso_type |= GSO_ECN
		}
	} else {
		h.gso_type = GSO_UDP_L4
	}
	h.hdr_len = u16(iphl + tl)
	h.gso_size = u16(mss)
	h.csum_start = u16(iphl)
	h.csum_offset = 16 if tcp else 6
	return
}

// The packets a super-packet of `sp` must become, built from scratch one by
// one (same rules as the splitter, but written without it).
expected_segments :: proc(sp: ^Spec, mss: int) -> [][]u8 {
	n := max(1, (len(sp.payload) + mss - 1) / mss)
	out := make([][]u8, n, context.temp_allocator)
	for k in 0 ..< n {
		s := sp^
		lo := k * mss
		hi := min(lo + mss, len(sp.payload))
		s.payload = sp.payload[lo:hi]
		s.seq = sp.seq + u32(lo)
		s.id = sp.id + u16(k)
		if k > 0 {
			s.flags &= ~u8(TCP_CWR)
		}
		if k < n - 1 {
			s.flags &= ~u8(TCP_FIN | TCP_PSH)
		}
		buf := make([]u8, mss + 300, context.temp_allocator)
		out[k] = build(&s, buf)
	}
	return out
}

// Cuts a packet with the splitter and gives the packets.
split_all :: proc(h: Vnet_Hdr, pkt: []u8, max_out: int) -> (pkts: [][]u8, err: Error) {
	s: Split
	err = split_init(&s, h, pkt, max_out)
	if err != .None {
		return nil, err
	}
	n := split_count(&s)
	pkts = make([][]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		buf := make([]u8, max_out, context.temp_allocator)
		k, ok := split_next(&s, buf)
		if !ok {
			return nil, .Too_Big
		}
		pkts[i] = buf[:k]
	}
	if split_count(&s) != 0 {
		return nil, .Too_Big
	}
	return
}

// All pieces of an output packet after the header, joined.
flatten :: proc(o: ^Out_Packet) -> []u8 {
	total := 0
	for i in 1 ..< o.n {
		total += len(o.pieces[i])
	}
	b := make([]u8, total, context.temp_allocator)
	at := 0
	for i in 1 ..< o.n {
		copy(b[at:], o.pieces[i])
		at += len(o.pieces[i])
	}
	return b
}
