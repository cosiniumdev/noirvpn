// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package mss

// Lowers the MSS option of a TCP SYN inside the tunnel.
//
// `clamp_syn` reads one IP packet (IPv4 or IPv6, no link header).
// - TCP SYN with an MSS option above the limit: set it to the limit, fix the
//   TCP checksum with the difference (RFC 1624).
// - Anything else is left as it is.
// - No allocation. Never reads outside the packet.
//
// Not handled on purpose (only not clamped, never broken):
// - IPv4 fragment that is not the first (no TCP header)
// - IPv6 extension header before TCP (no header walk)

@(private)
PROTO_TCP :: 6
@(private)
TCP_SYN :: 0x02
@(private)
OPT_END :: 0
@(private)
OPT_NOP :: 1
@(private)
OPT_MSS :: 2

// `mss4` is the IPv4 value (see `mss_ipv4`). IPv6 uses `mss_ipv6` of it.
// 0 does nothing.
// `fix_csum` false: leave the TCP checksum. For a packet whose checksum field
// is only the start of a sum finished later (tun packet with NEEDS_CSUM).
//
// Returns true if the packet changed. The first lines exit quickly for
// non-SYN packets: they read at most 4 bytes.
clamp_syn :: proc "contextless" (pkt: []u8, mss4: int, fix_csum := true) -> bool {
	if mss4 <= 0 || len(pkt) < 40 {
		return false
	}
	t: int // where the TCP header starts
	limit := mss4
	switch pkt[0] >> 4 {
	case 4:
		if pkt[9] != PROTO_TCP {
			return false
		}
		t = int(pkt[0] & 0x0f) * 4
		// A fragment with an offset has no TCP header.
		if t < 20 || len(pkt) < t + 20 || (u16(pkt[6]) << 8 | u16(pkt[7])) & 0x1fff != 0 {
			return false
		}
	case 6:
		if pkt[6] != PROTO_TCP || len(pkt) < 60 {
			return false
		}
		t = 40
		limit = mss_ipv6(mss4)
	case:
		return false
	}
	if pkt[t + 13] & TCP_SYN == 0 {
		return false
	}
	end := t + int(pkt[t + 12] >> 4) * 4
	if end < t + 20 || end > len(pkt) {
		return false
	}
	i := t + 20
	for i < end {
		switch pkt[i] {
		case OPT_END:
			return false
		case OPT_NOP:
			i += 1
			continue
		}
		// Kind and length. A length below 2, or an option that runs past the
		// header, ends the walk: the packet is not ours to fix.
		if i + 1 >= end {
			return false
		}
		n := int(pkt[i + 1])
		if n < 2 || i + n > end {
			return false
		}
		if pkt[i] == OPT_MSS {
			if n != 4 {
				return false
			}
			old := u16(pkt[i + 2]) << 8 | u16(pkt[i + 3])
			if int(old) <= limit {
				return false
			}
			now := u16(limit)
			pkt[i + 2], pkt[i + 3] = u8(now >> 8), u8(now)
			if fix_csum {
				c := t + 16
				ck := csum_update(u16(pkt[c]) << 8 | u16(pkt[c + 1]), old, now)
				pkt[c], pkt[c + 1] = u8(ck >> 8), u8(ck)
			}
			return true
		}
		i += n
	}
	return false
}

// RFC 1624, equation 3: HC' = ~(~HC + ~m + m') for one 16-bit word that changed
// from `old` to `now`.
@(private)
csum_update :: proc "contextless" (ck, old, now: u16) -> u16 {
	sum := u32(~ck) + u32(~old) + u32(now)
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ~u16(sum)
}
