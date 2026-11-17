// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package offload

import "base:intrinsics"

// The Internet checksum (RFC 1071): one's complement sum of 16 bit words.
//
// All procedures return the sum as a folded 16 bit value in network order
// terms ("logical" value), not inverted. Add two sums with `csum_add`. The
// checksum to put in a header is `~sum`.
//
// The loops read 8 bytes at a time in machine byte order. The sum does not
// depend on byte order (RFC 1071, section 2) if the result is swapped at the
// end. A piece summed on its own and added to another sum must start at an
// even offset of the whole data. All pieces here do: headers are a multiple
// of 4 bytes, and the payload is the last piece.

@(private)
load64 :: #force_inline proc "contextless" (p: [^]u8, i: int) -> u64 {
	return intrinsics.unaligned_load((^u64)(&p[i]))
}

@(private)
store64 :: #force_inline proc "contextless" (p: [^]u8, i: int, v: u64) {
	intrinsics.unaligned_store((^u64)(&p[i]), v)
}

// Adds the two 32 bit halves of `w`. Each add is below 2^33, so a 64 bit
// accumulator cannot overflow on data of up to 64 KiB (it holds 2^30 words).
@(private)
halves :: #force_inline proc "contextless" (w: u64) -> u64 {
	return (w & 0xffff_ffff) + (w >> 32)
}

// The last 0 to 7 bytes, as one machine order word padded with zero bytes.
@(private)
tail_word :: proc "contextless" (data: []u8) -> u64 {
	w: u64
	for b, k in data {
		w |= u64(b) << (uint(k) * 8)
	}
	return w
}

// Folds a wide sum of machine order words to 16 bits and swaps it to the
// logical order.
@(private)
fold_le :: #force_inline proc "contextless" (acc: u64) -> u16 {
	x := acc
	for x >> 16 != 0 {
		x = (x & 0xffff) + (x >> 16)
	}
	return u16(x) << 8 | u16(x) >> 8
}

// The sum of the 16 bit words of `data`. A last odd byte counts as the high
// byte of a word.
csum_sum :: proc "contextless" (data: []u8) -> u16 {
	n := len(data)
	p := raw_data(data)
	acc: u64
	i := 0
	for ; i + 32 <= n; i += 32 {
		acc += halves(load64(p, i)) + halves(load64(p, i + 8)) + halves(load64(p, i + 16)) + halves(load64(p, i + 24))
	}
	for ; i + 8 <= n; i += 8 {
		acc += halves(load64(p, i))
	}
	if i < n {
		acc += halves(tail_word(data[i:]))
	}
	return fold_le(acc)
}

// Copies `src` to the start of `dst` and returns the sum of the data, in one
// pass. `dst` must be at least as long as `src`. They must not overlap (they
// may be equal). If `dst` is too short: copies nothing, returns 0.
csum_copy :: proc "contextless" (dst, src: []u8) -> u16 {
	n := len(src)
	if len(dst) < n {
		return 0
	}
	sp := raw_data(src)
	dp := raw_data(dst)
	acc: u64
	i := 0
	for ; i + 32 <= n; i += 32 {
		a := load64(sp, i)
		b := load64(sp, i + 8)
		c := load64(sp, i + 16)
		d := load64(sp, i + 24)
		store64(dp, i, a)
		store64(dp, i + 8, b)
		store64(dp, i + 16, c)
		store64(dp, i + 24, d)
		acc += halves(a) + halves(b) + halves(c) + halves(d)
	}
	for ; i + 8 <= n; i += 8 {
		a := load64(sp, i)
		store64(dp, i, a)
		acc += halves(a)
	}
	if i < n {
		for k in i ..< n {
			dst[k] = src[k]
		}
		acc += halves(tail_word(src[i:]))
	}
	return fold_le(acc)
}

// One's complement addition of two sums.
csum_add :: #force_inline proc "contextless" (a, b: u16) -> u16 {
	s := u32(a) + u32(b)
	return u16(s & 0xffff) + u16(s >> 16)
}

// Folds a sum of several 16 bit values (up to 2^16 of them) to 16 bits.
@(private)
fold32 :: #force_inline proc "contextless" (s: u32) -> u16 {
	x := (s & 0xffff) + (s >> 16)
	x = (x & 0xffff) + (x >> 16)
	return u16(x)
}

// The sum of the TCP or UDP pseudo header over `ip` (starts at the IP header;
// needs the 8 or 32 address bytes). `proto` is the transport protocol (for
// IPv6 the last next-header value, not an extension header). `tlen` is the
// length of the transport header and its data.
@(private)
pseudo_sum :: proc "contextless" (ip: []u8, v6: bool, proto: u8, tlen: int) -> u16 {
	s: u32
	if v6 {
		s = u32(csum_sum(ip[8:40]))
	} else {
		s = u32(csum_sum(ip[12:20]))
	}
	s += u32(proto) + u32(tlen)
	return fold32(s)
}

// The checksum of an IPv4 header of `n` bytes at the start of `h`, with the
// checksum field (bytes 10 and 11) taken as zero.
@(private)
ip4_checksum :: proc "contextless" (h: []u8, n: int) -> u16 {
	h[10], h[11] = 0, 0
	return ~csum_sum(h[:n])
}
