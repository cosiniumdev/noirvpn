// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package offload

// Cutting a packet from the tun into ordinary packets.
//
//	h, _ := offload.vnet_decode(buf)
//	sp: offload.Split
//	if offload.split_init(&sp, h, buf[offload.VNET_HDR_LEN:n], MAX_OUT) == .None {
//		for offload.split_count(&sp) > 0 {
//			k, _ := offload.split_next(&sp, slot[:])
//			// slot[:k] is one packet
//		}
//	}
//
// `split_init` checks the whole packet. After `.None`, `split_next` can fail
// only for a buffer that is too small. The input slice must stay unchanged
// until the last `split_next`.
//
// A GSO packet (TSO or USO) becomes `ceil(payload / gso_size)` packets. For
// each one the headers are copied from the first and then fixed:
//
//	IPv4   total length, id (first id + k), header checksum
//	IPv6   payload length
//	TCP    sequence number (first + k * gso_size), FIN and PSH only on the last
//	       packet, CWR only on the first, checksum
//	UDP    length, checksum (a result of 0 is sent as 0xFFFF)
//
// The checksum is always computed again in full, with the pseudo header. The
// old value (partial or not) does not matter. Other TCP flags are kept on
// every packet.
//
// A packet with no GSO type is copied as it is. If its header says the
// checksum is partial (F_NEEDS_CSUM), the copy gets the completed checksum.

// Most packets one `split_init` accepts. A peer sets the segment size, and a
// tiny size on a 64 KiB packet would produce thousands of packets.
MAX_SPLIT_SEGS :: 1024

@(private)
Split_Mode :: enum u8 {
	Done, // not initialised, or nothing is left
	Copy, // one packet, copied
	Complete, // one packet, copied, with its partial checksum completed
	Gso, // several packets
}

Split :: struct {
	pkt:      []u8,
	mode:     Split_Mode,
	v6:       bool,
	proto:    u8, // TCP or UDP (Gso), or the UDP rule for a completed packet
	ip_len:   int, // bytes before the transport header (IP header and extension headers)
	tp_len:   int, // bytes of the transport header
	payload:  int,
	gso_size: int,
	segs:     int,
	next:     int, // the number of packets given out so far
	need:     int, // the largest packet `split_next` writes
	field:    int, // Complete: offset of the checksum field
	start:    int, // Complete: where the checksum starts
}

// Packets that `split_next` still gives.
split_count :: proc "contextless" (s: ^Split) -> int {
	if s.mode == .Done {
		return 0
	}
	return s.segs - s.next
}

// The bytes of all packets that `split_next` still gives (IP and transport
// headers included).
split_bytes_left :: proc "contextless" (s: ^Split) -> int {
	switch s.mode {
	case .Done:
		return 0
	case .Copy, .Complete:
		return len(s.pkt)
	case .Gso:
		return split_count(s) * (s.ip_len + s.tp_len) + s.payload - s.next * s.gso_size
	}
	return 0
}

// Largest packet that `split_next` writes. A buffer of this size always works.
split_max_out :: proc "contextless" (s: ^Split) -> int {
	return s.need
}

// Looks at the IP packet `pkt` and its virtio header `h` and prepares to cut
// it. `max_out` is the largest packet the caller can take.
//
//	.Short        empty packet, or a header that runs past the end
//	.Not_Ip       a GSO packet that is neither IPv4 nor IPv6
//	.Bad_Header   the header does not fit the GSO type, or csum_start/csum_offset
//	.Bad_Length   the IP length field is not the packet length (GSO only)
//	.Unsupported  UFO, an unknown GSO type, a fragment or other extension header
//	.Too_Big      a packet would be larger than `max_out`, or more than
//	              MAX_SPLIT_SEGS packets
split_init :: proc "contextless" (s: ^Split, h: Vnet_Hdr, pkt: []u8, max_out: int) -> Error {
	s^ = {}
	if len(pkt) == 0 {
		return .Short
	}
	gso := h.gso_type &~ GSO_ECN
	switch gso {
	case GSO_NONE:
		return split_init_plain(s, h, pkt, max_out)
	case GSO_TCPV4, GSO_TCPV6, GSO_UDP_L4:
	case:
		return .Unsupported
	}

	// A GSO packet. Find the IP and transport headers.
	v6: bool
	ip_len: int
	proto: u8
	switch pkt[0] >> 4 {
	case 4:
		if gso == GSO_TCPV6 {
			return .Bad_Header
		}
		if len(pkt) < 20 {
			return .Short
		}
		ip_len = int(pkt[0] & 0x0f) * 4
		if ip_len < 20 || ip_len > len(pkt) {
			return .Bad_Header
		}
		if int(be16(pkt[2:])) != len(pkt) {
			return .Bad_Length
		}
		// More fragments, or not the first fragment.
		if be16(pkt[6:]) & 0x3fff != 0 {
			return .Unsupported
		}
		proto = pkt[9]
	case 6:
		if gso == GSO_TCPV4 {
			return .Bad_Header
		}
		if len(pkt) < 40 {
			return .Short
		}
		v6 = true
		if int(be16(pkt[4:])) != len(pkt) - 40 {
			return .Bad_Length
		}
		err: Error
		ip_len, proto, err = v6_find_transport(pkt)
		if err != .None {
			return err
		}
	case:
		return .Not_Ip
	}
	want: u8 = PROTO_UDP if gso == GSO_UDP_L4 else PROTO_TCP
	if proto != want {
		return .Bad_Header
	}
	tp_len := 8
	csum_field := 6
	if want == PROTO_TCP {
		if ip_len + 20 > len(pkt) {
			return .Short
		}
		tp_len = int(pkt[ip_len + 12] >> 4) * 4
		if tp_len < 20 {
			return .Bad_Header
		}
		csum_field = 16
	}
	if ip_len + tp_len > len(pkt) {
		return .Short
	}
	if h.flags & F_NEEDS_CSUM != 0 {
		if int(h.csum_start) != ip_len || int(h.csum_offset) != csum_field {
			return .Bad_Header
		}
	}
	if h.gso_size == 0 {
		return .Bad_Header
	}
	hdr := ip_len + tp_len
	payload := len(pkt) - hdr
	gso_size := int(h.gso_size)
	segs := max(1, (payload + gso_size - 1) / gso_size)
	if segs > MAX_SPLIT_SEGS {
		return .Too_Big
	}
	need := hdr + min(gso_size, payload)
	if need > max_out {
		return .Too_Big
	}
	s.pkt = pkt
	s.mode = .Gso
	s.v6 = v6
	s.proto = want
	s.ip_len = ip_len
	s.tp_len = tp_len
	s.payload = payload
	s.gso_size = gso_size
	s.segs = segs
	s.need = need
	return .None
}

@(private)
split_init_plain :: proc "contextless" (s: ^Split, h: Vnet_Hdr, pkt: []u8, max_out: int) -> Error {
	if len(pkt) > max_out {
		return .Too_Big
	}
	s.pkt = pkt
	s.segs = 1
	s.need = len(pkt)
	s.mode = .Copy
	if h.flags & F_NEEDS_CSUM == 0 {
		return .None
	}
	start := int(h.csum_start)
	field := start + int(h.csum_offset)
	if field + 2 > len(pkt) {
		s^ = {}
		return .Bad_Header
	}
	s.mode = .Complete
	s.start = start
	s.field = field
	// A UDP checksum is never sent as 0. Say so only for a plain IPv4 header or
	// an IPv6 header without extension headers; other packets are left alone.
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) >= 20 && pkt[9] == PROTO_UDP {
			s.proto = PROTO_UDP
		}
	case 6:
		if len(pkt) >= 40 && pkt[6] == PROTO_UDP {
			s.proto = PROTO_UDP
		}
	}
	return .None
}

// Walks the extension headers of an IPv6 packet of at least 40 bytes. Gives the
// offset and the protocol of the transport header (TCP or UDP).
@(private)
v6_find_transport :: proc "contextless" (pkt: []u8) -> (off: int, proto: u8, err: Error) {
	off = 40
	nh := pkt[6]
	// More than a few extension headers is not a real packet.
	for _ in 0 ..< 8 {
		switch nh {
		case PROTO_TCP, PROTO_UDP:
			return off, nh, .None
		case 0, 43, 60:
			// Hop-by-hop, routing, destination options: next header, length in
			// units of 8 bytes not counting the first 8.
			if off + 8 > len(pkt) {
				return 0, 0, .Short
			}
			next := pkt[off]
			off += (int(pkt[off + 1]) + 1) * 8
			if off > len(pkt) {
				return 0, 0, .Short
			}
			nh = next
		case:
			return 0, 0, .Unsupported
		}
	}
	return 0, 0, .Unsupported
}

// Writes the next packet to the start of `out` and returns its length. `ok`
// is false when no packets remain, or when `out` is shorter than
// `split_max_out` (nothing is used up then).
split_next :: proc "contextless" (s: ^Split, out: []u8) -> (n: int, ok: bool) {
	if s.mode == .Done || s.next >= s.segs || len(out) < s.need {
		return 0, false
	}
	pkt := s.pkt
	switch s.mode {
	case .Done:
		return 0, false
	case .Copy:
		copy(out, pkt)
		n = len(pkt)
	case .Complete:
		n = len(pkt)
		copy(out[:s.start], pkt[:s.start])
		sum := csum_copy(out[s.start:n], pkt[s.start:])
		ck := ~sum
		if ck == 0 && s.proto == PROTO_UDP {
			ck = 0xffff
		}
		put_be16(out[s.field:], ck)
	case .Gso:
		n = split_gso_packet(s, out)
	}
	s.next += 1
	if s.next >= s.segs {
		s.mode = .Done
	}
	return n, true
}

// Packet number `s.next` of a GSO packet. `out` is long enough (checked).
@(private)
split_gso_packet :: proc "contextless" (s: ^Split, out: []u8) -> int {
	pkt := s.pkt
	k := s.next
	off := k * s.gso_size
	seg := min(s.gso_size, s.payload - off)
	ip_len := s.ip_len
	hdr := ip_len + s.tp_len
	total := hdr + seg
	last := k + 1 == s.segs

	copy(out[:hdr], pkt[:hdr])
	pay := csum_copy(out[hdr:total], pkt[hdr + off:][:seg])

	if s.v6 {
		put_be16(out[4:], u16(total - 40))
	} else {
		put_be16(out[2:], u16(total))
		put_be16(out[4:], be16(pkt[4:]) + u16(k))
		put_be16(out[10:], ip4_checksum(out, ip_len)) // also clears the field first
	}

	tp := out[ip_len:hdr]
	tlen := total - ip_len
	if s.proto == PROTO_TCP {
		put_be32(tp[4:], be32(pkt[ip_len + 4:]) + u32(off))
		flags := tp[13]
		if !last {
			flags &= ~u8(TCP_FIN | TCP_PSH)
		}
		if k > 0 {
			flags &= ~u8(TCP_CWR)
		}
		tp[13] = flags
		tp[16], tp[17] = 0, 0
		sum := csum_add(csum_add(pseudo_sum(out, s.v6, PROTO_TCP, tlen), csum_sum(tp)), pay)
		put_be16(tp[16:], ~sum)
	} else {
		put_be16(tp[4:], u16(tlen))
		tp[6], tp[7] = 0, 0
		sum := csum_add(csum_add(pseudo_sum(out, s.v6, PROTO_UDP, tlen), csum_sum(tp)), pay)
		ck := ~sum
		if ck == 0 {
			ck = 0xffff
		}
		put_be16(tp[6:], ck)
	}
	return total
}
