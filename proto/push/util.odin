// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:strings"

// Small helpers: strict number parsing, IP text, a fixed-buffer writer.

// Digits only, no sign, no spaces, at most 18 digits. For option arguments.
parse_uint :: proc "contextless" (s: string) -> (v: u64, ok: bool) {
	if len(s) == 0 || len(s) > 18 {
		return 0, false
	}
	for c in transmute([]u8)s {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v * 10 + u64(c - '0')
	}
	return v, true
}

// Like `parse_uint` but the value must be at most `max`.
parse_uint_max :: proc "contextless" (s: string, max: u64) -> (v: u64, ok: bool) {
	v, ok = parse_uint(s)
	if ok && v > max {
		return 0, false
	}
	return v, ok
}

// Number as a peer-info reader takes it: leading spaces
// and one optional `+` are skipped, then digits. Anything after the digits is
// ignored. Garbage before the digits means "absent". `hex` reads base 16.
scan_uint_prefix :: proc "contextless" (s: string, hex := false) -> (v: u64, ok: bool) {
	b := transmute([]u8)s
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i += 1
	}
	if i < len(b) && b[i] == '+' {
		i += 1
	}
	digits := 0
	for i < len(b) {
		d: u64
		c := b[i]
		switch {
		case c >= '0' && c <= '9':
			d = u64(c - '0')
		case hex && c >= 'a' && c <= 'f':
			d = u64(c - 'a') + 10
		case hex && c >= 'A' && c <= 'F':
			d = u64(c - 'A') + 10
		case:
			d = 99
		}
		if d >= (16 if hex else 10) {
			break
		}
		base: u64 = 16 if hex else 10
		// Stop at 15 digits of hex or 18 of decimal: far beyond any field.
		if digits >= (15 if hex else 18) {
			return 0, false
		}
		v = v * base + d
		digits += 1
		i += 1
	}
	return v, digits > 0
}

// Dotted quad. Each part is 1 to 3 decimal digits, at most 255, no leading
// zeros (so "010" is refused).
parse_ipv4 :: proc "contextless" (s: string) -> (a: [4]u8, ok: bool) {
	b := transmute([]u8)s
	part := 0
	i := 0
	for part < 4 {
		start := i
		v := 0
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			v = v * 10 + int(b[i] - '0')
			i += 1
			if i - start > 3 {
				return {}, false
			}
		}
		n := i - start
		if n == 0 || v > 255 || (n > 1 && b[start] == '0') {
			return {}, false
		}
		a[part] = u8(v)
		part += 1
		if part < 4 {
			if i >= len(b) || b[i] != '.' {
				return {}, false
			}
			i += 1
		}
	}
	return a, i == len(b)
}

// IPv6 text: eight groups of 1 to 4 hex digits, one `::` allowed, an IPv4
// tail allowed. No zone id, no brackets.
parse_ipv6 :: proc "contextless" (s: string) -> (a: [16]u8, ok: bool) {
	if len(s) < 2 || len(s) > 45 {
		return {}, false
	}
	gap := -1
	for i in 0 ..< len(s) - 1 {
		if s[i] == ':' && s[i + 1] == ':' {
			if gap >= 0 {
				return {}, false // second "::" (also catches ":::")
			}
			gap = i
		}
	}
	head, tail: string
	if gap >= 0 {
		head, tail = s[:gap], s[gap + 2:]
	} else {
		head = s
	}
	hg, tg: [8]u16
	nh, nt: int
	hok, tok: bool
	nh, hok = parse_ipv6_groups(head, &hg, gap < 0)
	if !hok {
		return {}, false
	}
	if gap < 0 {
		if nh != 8 {
			return {}, false
		}
	} else {
		nt, tok = parse_ipv6_groups(tail, &tg, true)
		if !tok || nh + nt > 7 {
			return {}, false
		}
	}
	for g in 0 ..< nh {
		a[2 * g] = u8(hg[g] >> 8)
		a[2 * g + 1] = u8(hg[g])
	}
	for g in 0 ..< nt {
		p := 8 - nt + g
		a[2 * p] = u8(tg[g] >> 8)
		a[2 * p + 1] = u8(tg[g])
	}
	return a, true
}

// Colon separated groups. An IPv4 tail (the last piece) counts as two groups.
@(private)
parse_ipv6_groups :: proc "contextless" (part: string, out: ^[8]u16, allow_v4: bool) -> (n: int, ok: bool) {
	if len(part) == 0 {
		return 0, true
	}
	b := transmute([]u8)part
	i := 0
	for {
		start := i
		for i < len(b) && b[i] != ':' {
			i += 1
		}
		piece := part[start:i]
		last := i == len(b)
		if len(piece) == 0 {
			return 0, false
		}
		dot := false
		for c in transmute([]u8)piece {
			if c == '.' {
				dot = true
			}
		}
		if dot {
			if !last || !allow_v4 || n + 2 > 8 {
				return 0, false
			}
			v4, v4ok := parse_ipv4(piece)
			if !v4ok {
				return 0, false
			}
			out[n] = u16(v4[0]) << 8 | u16(v4[1])
			out[n + 1] = u16(v4[2]) << 8 | u16(v4[3])
			n += 2
			return n, true
		}
		if len(piece) > 4 || n >= 8 {
			return 0, false
		}
		v: u16
		for c in transmute([]u8)piece {
			d: u16
			switch {
			case c >= '0' && c <= '9':
				d = u16(c - '0')
			case c >= 'a' && c <= 'f':
				d = u16(c - 'a') + 10
			case c >= 'A' && c <= 'F':
				d = u16(c - 'A') + 10
			case:
				return 0, false
			}
			v = v << 4 | d
		}
		out[n] = v
		n += 1
		if last {
			return n, true
		}
		i += 1 // the ':'
		if i == len(b) {
			return 0, false // trailing ':'
		}
	}
}

// True if the netmask is a run of ones followed by zeros.
netmask_is_contiguous :: proc "contextless" (m: [4]u8) -> bool {
	v := u32(m[0]) << 24 | u32(m[1]) << 16 | u32(m[2]) << 8 | u32(m[3])
	inv := ~v
	return inv & (inv + 1) == 0
}

// Number of one bits of a contiguous netmask.
netmask_bits :: proc "contextless" (m: [4]u8) -> int {
	n := 0
	for x in m {
		for k in 0 ..< 8 {
			if x >> u32(7 - k) & 1 == 1 {
				n += 1
			}
		}
	}
	return n
}

// ASCII case-insensitive equality.
eq_fold :: proc "contextless" (a, b: string) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

// A writer over a fixed buffer. Once it runs out of room it stays failed.
Wr :: struct {
	buf:  []u8,
	n:    int,
	over: bool,
}

wr_str :: proc "contextless" (w: ^Wr, s: string) {
	if w.over || len(w.buf) - w.n < len(s) {
		w.over = true
		return
	}
	copy(w.buf[w.n:], s)
	w.n += len(s)
}

wr_byte :: proc "contextless" (w: ^Wr, c: u8) {
	if w.over || len(w.buf) - w.n < 1 {
		w.over = true
		return
	}
	w.buf[w.n] = c
	w.n += 1
}

wr_uint :: proc "contextless" (w: ^Wr, v: u64) {
	tmp: [20]u8
	i := len(tmp)
	x := v
	for {
		i -= 1
		tmp[i] = u8('0' + x % 10)
		x /= 10
		if x == 0 {
			break
		}
	}
	wr_str(w, string(tmp[i:]))
}

// Dotted quad.
wr_ipv4 :: proc "contextless" (w: ^Wr, a: [4]u8) {
	for i in 0 ..< 4 {
		if i > 0 {
			wr_byte(w, '.')
		}
		wr_uint(w, u64(a[i]))
	}
}

// Shortest form: the longest run of zero groups (two or more) becomes "::".
wr_ipv6 :: proc "contextless" (w: ^Wr, a: [16]u8) {
	g: [8]u16
	for i in 0 ..< 8 {
		g[i] = u16(a[2 * i]) << 8 | u16(a[2 * i + 1])
	}
	best_start, best_len := -1, 0
	i := 0
	for i < 8 {
		if g[i] != 0 {
			i += 1
			continue
		}
		j := i
		for j < 8 && g[j] == 0 {
			j += 1
		}
		if j - i > best_len {
			best_start, best_len = i, j - i
		}
		i = j
	}
	if best_len < 2 {
		best_start = -1
	}
	hexd := "0123456789abcdef"
	k := 0
	for k < 8 {
		if k == best_start {
			wr_str(w, "::")
			k += best_len
			continue
		}
		if k > 0 && k != best_start + best_len {
			wr_byte(w, ':')
		}
		v := g[k]
		started := false
		for sh := 12; sh >= 0; sh -= 4 {
			d := (v >> u32(sh)) & 0xF
			if d != 0 || started || sh == 0 {
				wr_byte(w, hexd[d])
				started = true
			}
		}
		k += 1
	}
}

// Copies `s` with the allocator. Empty stays empty without an allocation.
clone_str :: proc(s: string, allocator := context.allocator) -> (string, bool) {
	if len(s) == 0 {
		return "", true
	}
	r, err := strings.clone(s, allocator)
	return r, err == nil
}

// Takes the text up to the first `sep` off the front of `rest`. `more` is
// false when no separator was left; `item` is then the whole rest.
next_item :: proc "contextless" (rest: ^string, sep: u8) -> (item: string, more: bool) {
	for c, i in transmute([]u8)rest^ {
		if c == sep {
			item = rest^[:i]
			rest^ = rest^[i + 1:]
			return item, true
		}
	}
	item = rest^
	rest^ = ""
	return item, false
}
