// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

import "base:intrinsics"

// One parse of an IP packet (no link header) for the flow table and the rules.
// No allocation. Never reads outside the packet.

PROTO_ICMP :: 1
PROTO_TCP :: 6
PROTO_UDP :: 17
PROTO_ICMP6 :: 58

TCP_FIN :: 0x01
TCP_SYN :: 0x02
TCP_RST :: 0x04
TCP_ACK :: 0x10

// IPv4 addresses are stored IPv4-mapped (::ffff:a.b.c.d).
Addr :: [16]u8

// IPv6 extension headers that the parse walks before the transport header.
MAX_EXT_HEADERS :: 6

Frag :: enum u8 {
	None,
	First, // offset 0, more fragments follow: has the transport header
	Later, // offset > 0: no transport header
}

Icmp :: enum u8 {
	None,
	Echo_Request,
	Echo_Reply,
	Error, // has the start of the packet that caused it
	Other,
}

Packet :: struct {
	af:         u8, // 4 or 6
	proto:      u8, // IP protocol of the transport header
	src, dst:   Addr,
	// TCP and UDP: the ports. ICMP echo: the identifier on the side that sent
	// the request (`sport` of a request, `dport` of a reply), 0 on the other.
	sport:      u16,
	dport:      u16,
	ports:      bool, // the transport header was read (TCP, UDP, ICMP echo)
	tcp_flags:  u8,
	frag:       Frag,
	frag_id:    u32,
	// The protocol field that all fragments of one packet share: the IPv4
	// protocol, or the next header of the IPv6 fragment header.
	frag_proto: u8,
	icmp:       Icmp,
	// For `Icmp.Error`: the packet inside, as the side that sent it saw it.
	inner:     Inner,
}

Inner :: struct {
	ok:       bool,
	proto:    u8,
	src, dst: Addr,
	sport:    u16,
	dport:    u16,
}

map4 :: #force_inline proc "contextless" (b: []u8) -> (a: Addr) {
	a[10] = 0xff
	a[11] = 0xff
	a[12], a[13], a[14], a[15] = b[0], b[1], b[2], b[3]
	return
}

be16 :: #force_inline proc "contextless" (b: []u8, i: int) -> u16 {
	return u16(b[i]) << 8 | u16(b[i + 1])
}

// The two halves of an address as integers in network order.
words :: #force_inline proc "contextless" (a: ^Addr) -> (hi, lo: u64) {
	hi = u64(intrinsics.unaligned_load((^u64be)(&a[0])))
	lo = u64(intrinsics.unaligned_load((^u64be)(&a[8])))
	return
}

is_mapped4 :: #force_inline proc "contextless" (a: ^Addr) -> bool {
	hi, lo := words(a)
	return hi == 0 && lo >> 32 == 0xffff
}

// A plain packet is IPv4 with a header of 20 bytes or IPv6 with no extension
// header, TCP or UDP, no fragment, and long enough for the TCP flags. Most
// packets of a tunnel are plain.
PLAIN4_MIN :: 20 + 14
PLAIN6_MIN :: 40 + 14

@(private)
load32 :: #force_inline proc "contextless" (b: [^]u8, i: int) -> u32 {
	return intrinsics.unaligned_load((^u32)(&b[i]))
}

@(private)
load64 :: #force_inline proc "contextless" (b: [^]u8, i: int) -> u64 {
	return intrinsics.unaligned_load((^u64)(&b[i]))
}

// Writes the flow key of a plain packet into `k`, from the bytes of the packet
// and with no `Packet`. Returns the TCP flags (0 for UDP). `out`: the client
// sent the packet. False: the packet is not plain and `k` is not set; use
// `parse`. The key is the key that `parse` and `key_make` give.
@(private)
plain_key :: #force_inline proc "contextless" (pkt: []u8, $out: bool, k: ^Flow_Key) -> (flags: u8, ok: bool) #no_bounds_check {
	if len(pkt) < PLAIN4_MIN {
		return
	}
	b := raw_data(pkt)
	head := load64(b, 0)
	proto: u8
	l4: int
	s0, s1, d0, d1: u64
	af: u64
	if u8(head) == 0x45 {
		// Bytes 6 and 7: no more fragments, and offset 0.
		if head & 0xff3f_0000_0000_0000 != 0 {
			return
		}
		proto = b[9]
		// Both addresses in one word: the source is the low half.
		ad := load64(b, 12)
		s1 = MAPPED4 | ad << 32
		d1 = MAPPED4 | ad & 0xffff_ffff_0000_0000
		l4 = 20
		af = 4
	} else if u8(head) >> 4 == 6 {
		if len(pkt) < PLAIN6_MIN {
			return
		}
		proto = u8(head >> 48)
		s0, s1 = load64(b, 8), load64(b, 16)
		d0, d1 = load64(b, 24), load64(b, 32)
		// An IPv4-mapped address makes the header broken: `parse` finds that.
		if (s0 == 0 && u32(s1) == MAPPED4) || (d0 == 0 && u32(d1) == MAPPED4) {
			return
		}
		l4 = 40
		af = 6
	} else {
		return
	}
	if proto != PROTO_TCP && proto != PROTO_UDP {
		return
	}
	// The ports as dport | sport << 16.
	ports := intrinsics.byte_swap(load32(b, l4))
	w := (^[5]u64)(k)
	when out {
		ports = ports >> 16 | ports << 16
		w[0], w[1], w[2], w[3] = s0, s1, d0, d1
	} else {
		w[0], w[1], w[2], w[3] = d0, d1, s0, s1
	}
	w[4] = u64(ports) | af << 32 | u64(proto) << 40
	flags = b[l4 + 13] if proto == PROTO_TCP else 0
	return flags, true
}

// Bytes 8 to 11 of an IPv4-mapped address, as the low half of a word.
@(private)
MAPPED4 :: 0xffff_0000

// The packet info of a plain inbound packet, from its key.
@(private)
plain_packet :: proc "contextless" (k: ^Flow_Key, flags: u8) -> (p: Packet) {
	p.af = u8(k.meta >> 32)
	p.proto = key_proto(k)
	p.src, p.dst = k.raddr, k.laddr
	p.sport, p.dport = u16(k.meta >> 16), u16(k.meta)
	p.ports = true
	p.tcp_flags = flags
	return
}

// False: the header is short or broken.
parse :: proc "contextless" (pkt: []u8, p: ^Packet) -> bool {
	p^ = {}
	l4, nh, ok := parse_ip(pkt, p)
	if !ok {
		return false
	}
	p.proto = nh
	if l4 < 0 || p.frag == .Later {
		return true
	}
	parse_l4(pkt[l4:], p, false)
	return true
}

// Returns the offset of the transport header (-1: not reached) and its protocol.
@(private)
parse_ip :: proc "contextless" (pkt: []u8, p: ^Packet) -> (l4: int, nh: u8, ok: bool) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return
		}
		ihl := int(pkt[0] & 0x0f) * 4
		if ihl < 20 || ihl > len(pkt) {
			return
		}
		p.af = 4
		p.src = map4(pkt[12:16])
		p.dst = map4(pkt[16:20])
		off := be16(pkt, 6) & 0x1fff
		more := pkt[6] & 0x20 != 0
		if off != 0 {
			p.frag = .Later
		} else if more {
			p.frag = .First
		}
		if p.frag != .None {
			p.frag_id = u32(be16(pkt, 4))
			p.frag_proto = pkt[9]
		}
		return ihl, pkt[9], true
	case 6:
		if len(pkt) < 40 {
			return
		}
		p.af = 6
		copy(p.src[:], pkt[8:24])
		copy(p.dst[:], pkt[24:40])
		if is_mapped4(&p.src) || is_mapped4(&p.dst) {
			// An IPv4-mapped address is not valid in a packet. It would be equal
			// to the stored form of an IPv4 address.
			return
		}
		nh = pkt[6]
		off := 40
		for hops in 0 ..= MAX_EXT_HEADERS {
			size: int
			switch nh {
			case 0, 43, 60:
				// Hop-by-hop, routing, destination options.
				if off + 2 > len(pkt) {
					return -1, nh, true
				}
				size = (int(pkt[off + 1]) + 1) * 8
			case 51:
				// Authentication header.
				if off + 2 > len(pkt) {
					return -1, nh, true
				}
				size = (int(pkt[off + 1]) + 2) * 4
			case 44:
				if off + 8 > len(pkt) {
					return -1, nh, true
				}
				fo := be16(pkt, off + 2)
				p.frag_id = u32(pkt[off + 4]) << 24 | u32(pkt[off + 5]) << 16 | u32(pkt[off + 6]) << 8 | u32(pkt[off + 7])
				p.frag_proto = pkt[off]
				if fo >> 3 != 0 {
					// What follows is the middle of the packet: no header to read.
					p.frag = .Later
					return -1, pkt[off], true
				}
				if fo & 1 != 0 {
					p.frag = .First
				}
				size = 8
			case:
				return off if off <= len(pkt) else -1, nh, true
			}
			if hops == MAX_EXT_HEADERS {
				break
			}
			nh = pkt[off]
			off += size
		}
		// More extension headers than the walk reads: no transport header.
		return -1, nh, true
	}
	return
}

// Reads ports, TCP flags and ICMP fields. `inner`: the header inside an ICMP
// error, where only the first 8 bytes of the transport header are sure.
@(private)
parse_l4 :: proc "contextless" (b: []u8, p: ^Packet, inner: bool) {
	switch p.proto {
	case PROTO_TCP:
		if len(b) < 4 {
			return
		}
		p.sport, p.dport = be16(b, 0), be16(b, 2)
		p.ports = true
		if len(b) >= 14 {
			p.tcp_flags = b[13]
		}
	case PROTO_UDP:
		if len(b) < 4 {
			return
		}
		p.sport, p.dport = be16(b, 0), be16(b, 2)
		p.ports = true
	case PROTO_ICMP, PROTO_ICMP6:
		if len(b) < 8 {
			return
		}
		if (p.proto == PROTO_ICMP) != (p.af == 4) {
			return
		}
		t := b[0]
		v4 := p.af == 4
		switch {
		case (v4 && t == 8) || (!v4 && t == 128):
			p.icmp = .Echo_Request
		case (v4 && t == 0) || (!v4 && t == 129):
			p.icmp = .Echo_Reply
		case v4 && (t == 3 || t == 11 || t == 12), !v4 && t >= 1 && t <= 4:
			p.icmp = .Error
		case:
			p.icmp = .Other
		}
		if p.icmp == .Echo_Request {
			p.sport = be16(b, 4)
			p.ports = true
		} else if p.icmp == .Echo_Reply {
			p.dport = be16(b, 4)
			p.ports = true
		} else if p.icmp == .Error && !inner {
			parse_inner(b[8:], p)
		}
	}
}

@(private)
parse_inner :: proc "contextless" (b: []u8, p: ^Packet) {
	q: Packet
	l4, nh, ok := parse_ip(b, &q)
	if !ok || q.af != p.af || l4 < 0 || q.frag == .Later {
		return
	}
	q.proto = nh
	parse_l4(b[l4:], &q, true)
	if !q.ports {
		return
	}
	p.inner = {
		ok    = true,
		proto = q.proto,
		src   = q.src,
		dst   = q.dst,
		sport = q.sport,
		dport = q.dport,
	}
}
