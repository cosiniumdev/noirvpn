// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

// Small parsers for the value types used in options. All are strict: no
// signs where none belong, no white space, no overflow.

// Parses a decimal number. A leading "-" is accepted only if `allow_neg`.
parse_decimal :: proc(s: string, allow_neg := false) -> (v: i64, ok: bool) {
	if len(s) == 0 {
		return 0, false
	}
	i := 0
	neg := false
	if s[0] == '-' {
		if !allow_neg {
			return 0, false
		}
		neg = true
		i = 1
		if len(s) == 1 {
			return 0, false
		}
	}
	for ; i < len(s); i += 1 {
		d := s[i]
		if d < '0' || d > '9' {
			return 0, false
		}
		// Stay far below overflow: no option needs more than 18 digits.
		if v > (max(i64) - 9) / 10 {
			return 0, false
		}
		v = v * 10 + i64(d - '0')
	}
	if neg {
		v = -v
	}
	return v, true
}

// Parses a decimal number and checks the range.
parse_range :: proc(s: string, lo, hi: i64, allow_neg := false) -> (v: i64, ok: bool) {
	v, ok = parse_decimal(s, allow_neg)
	if !ok || v < lo || v > hi {
		return 0, false
	}
	return v, true
}

// Parses a dotted-quad IPv4 address: four decimal parts, no leading plus,
// no more than three digits per part.
ipv4_parse :: proc(s: string) -> (a: [4]u8, ok: bool) {
	part, digits, n := 0, 0, 0
	for i in 0 ..< len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			part = part * 10 + int(c - '0')
			digits += 1
			if digits > 3 || part > 255 {
				return {}, false
			}
		case c == '.':
			if digits == 0 || n >= 3 {
				return {}, false
			}
			a[n] = u8(part)
			n += 1
			part, digits = 0, 0
		case:
			return {}, false
		}
	}
	if digits == 0 || n != 3 {
		return {}, false
	}
	a[3] = u8(part)
	return a, true
}

ipv4_to_u32 :: proc "contextless" (a: [4]u8) -> u32 {
	return u32(a[0]) << 24 | u32(a[1]) << 16 | u32(a[2]) << 8 | u32(a[3])
}

ipv4_from_u32 :: proc "contextless" (v: u32) -> [4]u8 {
	return {u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v)}
}

// Number of leading one bits if `mask` is a valid netmask (ones, then zeros).
ipv4_mask_prefix :: proc(mask: [4]u8) -> (prefix: int, ok: bool) {
	m := ipv4_to_u32(mask)
	ones := 0
	for ones < 32 && (m >> u32(31 - ones)) & 1 == 1 {
		ones += 1
	}
	// Everything after the ones must be zero.
	rest := m << u32(ones) if ones < 32 else 0
	if rest != 0 {
		return 0, false
	}
	return ones, true
}

ipv4_prefix_mask :: proc "contextless" (prefix: int) -> [4]u8 {
	if prefix <= 0 {
		return {}
	}
	if prefix >= 32 {
		return {255, 255, 255, 255}
	}
	return ipv4_from_u32(~u32(0) << u32(32 - prefix))
}

// Parses "a.b.c.d/len" or "a.b.c.d/mask".
ipv4_parse_cidr :: proc(s: string) -> (addr: [4]u8, prefix: int, ok: bool) {
	slash := -1
	for i in 0 ..< len(s) {
		if s[i] == '/' {
			slash = i
			break
		}
	}
	if slash < 0 {
		return {}, 0, false
	}
	addr = ipv4_parse(s[:slash]) or_return
	tail := s[slash + 1:]
	if len(tail) > 0 && !(tail[0] >= '0' && tail[0] <= '9') {
		return {}, 0, false
	}
	// A length has at most two digits; anything longer must be a dotted mask.
	if len(tail) <= 2 {
		p, pok := parse_range(tail, 0, 32)
		if !pok {
			return {}, 0, false
		}
		return addr, int(p), true
	}
	mask, mok := ipv4_parse(tail)
	if !mok {
		return {}, 0, false
	}
	p, pok := ipv4_mask_prefix(mask)
	if !pok {
		return {}, 0, false
	}
	return addr, p, true
}

@(private)
hex_digit :: proc "contextless" (c: u8) -> int {
	switch c {
	case '0' ..= '9':
		return int(c - '0')
	case 'a' ..= 'f':
		return int(c - 'a') + 10
	case 'A' ..= 'F':
		return int(c - 'A') + 10
	}
	return -1
}

// Reads colon-separated hex groups (the last may be an IPv4 address) into
// `out` and returns how many were read. An empty string has no groups.
@(private)
ipv6_groups :: proc(part: string, out: []u16) -> (n: int, ok: bool) {
	if part == "" {
		return 0, true
	}
	rest := part
	for {
		colon := -1
		for i in 0 ..< len(rest) {
			if rest[i] == ':' {
				colon = i
				break
			}
		}
		piece := rest if colon < 0 else rest[:colon]
		has_dot := false
		for c in transmute([]u8)piece {
			if c == '.' {
				has_dot = true
			}
		}
		if has_dot {
			if colon >= 0 || n + 2 > len(out) {
				return 0, false // an IPv4 tail must come last
			}
			v4 := ipv4_parse(piece) or_return
			out[n] = u16(v4[0]) << 8 | u16(v4[1])
			out[n + 1] = u16(v4[2]) << 8 | u16(v4[3])
			return n + 2, true
		}
		if len(piece) == 0 || len(piece) > 4 || n >= len(out) {
			return 0, false
		}
		v := 0
		for c in transmute([]u8)piece {
			d := hex_digit(c)
			if d < 0 {
				return 0, false
			}
			v = v * 16 + d
		}
		out[n] = u16(v)
		n += 1
		if colon < 0 {
			return n, true
		}
		rest = rest[colon + 1:]
	}
}

// Parses an IPv6 address: hex groups, one "::" at most, and an IPv4 tail
// (::ffff:1.2.3.4). Zone ids are not accepted.
ipv6_parse :: proc(s: string) -> (a: [16]u8, ok: bool) {
	if len(s) < 2 || len(s) > 45 {
		return {}, false
	}
	gap := -1
	for i in 0 ..< len(s) - 1 {
		if s[i] == ':' && s[i + 1] == ':' {
			if gap >= 0 {
				return {}, false
			}
			gap = i
			// ":::" is not valid
			if i + 2 < len(s) && s[i + 2] == ':' {
				return {}, false
			}
		}
	}
	groups: [8]u16
	if gap < 0 {
		n := ipv6_groups(s, groups[:]) or_return
		if n != 8 {
			return {}, false
		}
	} else {
		left, right: [8]u16
		nl := ipv6_groups(s[:gap], left[:]) or_return
		nr := ipv6_groups(s[gap + 2:], right[:]) or_return
		if nl + nr > 7 {
			return {}, false
		}
		for k in 0 ..< nl {
			groups[k] = left[k]
		}
		for k in 0 ..< nr {
			groups[8 - nr + k] = right[k]
		}
	}
	for k in 0 ..< 8 {
		a[2 * k] = u8(groups[k] >> 8)
		a[2 * k + 1] = u8(groups[k])
	}
	return a, true
}

// Parses "ipv6/bits".
ipv6_parse_cidr :: proc(s: string) -> (addr: [16]u8, bits: int, ok: bool) {
	slash := -1
	for i in 0 ..< len(s) {
		if s[i] == '/' {
			slash = i
			break
		}
	}
	if slash < 0 {
		return {}, 0, false
	}
	addr = ipv6_parse(s[:slash]) or_return
	b, bok := parse_range(s[slash + 1:], 0, 128)
	if !bok {
		return {}, 0, false
	}
	return addr, int(b), true
}

// True if all bits after the first `bits` are zero.
ipv6_host_part_is_zero :: proc "contextless" (a: [16]u8, bits: int) -> bool {
	for i in 0 ..< 16 {
		keep := clamp(bits - 8 * i, 0, 8)
		mask := u8(0xff) << u8(8 - keep) if keep < 8 else u8(0xff)
		if a[i] & ~mask != 0 {
			return false
		}
	}
	return true
}

// Adds `n` to an IPv6 address (wraps at 2^128).
ipv6_add :: proc "contextless" (a: [16]u8, n: u64) -> [16]u8 {
	out := a
	carry := n
	for i := 15; i >= 0 && carry != 0; i -= 1 {
		sum := u64(out[i]) + (carry & 0xff)
		out[i] = u8(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	return out
}

// Decodes standard base64 (RFC 4648, "+" and "/") into `out`. Padding is
// optional. These are errors: characters outside the alphabet, an input that
// does not fit in `out`, and non-zero leftover bits.
base64_decode :: proc(s: string, out: []u8) -> (n: int, ok: bool) {
	end := len(s)
	for end > 0 && s[end - 1] == '=' {
		end -= 1
	}
	if len(s) - end > 2 {
		return 0, false
	}
	acc, bits := u32(0), 0
	for i in 0 ..< end {
		c := s[i]
		v: u32
		switch c {
		case 'A' ..= 'Z':
			v = u32(c - 'A')
		case 'a' ..= 'z':
			v = u32(c - 'a') + 26
		case '0' ..= '9':
			v = u32(c - '0') + 52
		case '+':
			v = 62
		case '/':
			v = 63
		case:
			return 0, false
		}
		acc = acc << 6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			if n >= len(out) {
				return 0, false
			}
			out[n] = u8(acc >> u32(bits))
			n += 1
			acc &= (1 << u32(bits)) - 1
		}
	}
	// A single leftover character (6 bits) cannot encode a byte; and the unused
	// bits must be zero.
	if acc != 0 || bits >= 6 {
		return 0, false
	}
	return n, true
}

// Parses a SHA-256 fingerprint: 32 hex bytes, either all separated by ":" or
// with no separators at all.
parse_fingerprint :: proc(s: string) -> (fp: [32]u8, ok: bool) {
	step := 0
	switch len(s) {
	case 64:
		step = 2
	case 95:
		step = 3
	case:
		return {}, false
	}
	for n in 0 ..< 32 {
		i := n * step
		if n > 0 && step == 3 && s[i - 1] != ':' {
			return {}, false
		}
		hi, lo := hex_digit(s[i]), hex_digit(s[i + 1])
		if hi < 0 || lo < 0 {
			return {}, false
		}
		fp[n] = u8(hi << 4 | lo)
	}
	return fp, true
}
