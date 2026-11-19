// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

// The AES form of the hash (see hash.odin) in plain code, with no AES
// instructions. It is slow, and its table lookups depend on secret bytes, so
// the flow table never uses it. It is the reference for the tests and for the
// check in the benchmark.

key_hash_soft :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	sbox := soft_sbox()
	if key_is_v4(k) {
		return u32(soft_enc(&sbox, block_v4(k), &t.rk.v4)[0])
	}
	w := (^[5]u64)(k)
	a := soft_enc(&sbox, {w[0], w[1]}, &t.rk.l)
	b := soft_enc(&sbox, {w[2], w[3]}, &t.rk.r)
	c := soft_enc(&sbox, {w[4], 0}, &t.rk.m)
	return u32(a[0] ~ b[0] ~ c[0])
}

// `x` xor the first key, then one AES round for each of the other keys.
@(private)
soft_enc :: proc "contextless" (sbox: ^[256]u8, x: Block, keys: ^Key_Set) -> Block {
	s := Block{x[0] ~ keys[0][0], x[1] ~ keys[0][1]}
	for i in 1 ..= AES_ROUNDS {
		s = soft_round(sbox, s, keys[i])
	}
	return s
}

// One AES round: SubBytes, ShiftRows, MixColumns, then xor the round key.
// Byte 4*c + r of the block is row r of column c.
@(private)
soft_round :: proc "contextless" (sbox: ^[256]u8, state, key: Block) -> Block {
	s := transmute([16]u8)state
	t: [16]u8
	for c in 0 ..< 4 {
		col: [4]u8
		for r in 0 ..< 4 {
			col[r] = sbox[s[4 * ((c + r) % 4) + r]]
		}
		col = soft_mix_column(col)
		for r in 0 ..< 4 {
			t[4 * c + r] = col[r]
		}
	}
	out := transmute(Block)t
	return {out[0] ~ key[0], out[1] ~ key[1]}
}

@(private)
soft_mix_column :: proc "contextless" (a: [4]u8) -> [4]u8 {
	// Times 2 in the field of AES.
	x2 :: proc "contextless" (v: u8) -> u8 {
		return v << 1 ~ (0x1b if v & 0x80 != 0 else 0)
	}
	return {
		x2(a[0]) ~ x2(a[1]) ~ a[1] ~ a[2] ~ a[3],
		a[0] ~ x2(a[1]) ~ x2(a[2]) ~ a[2] ~ a[3],
		a[0] ~ a[1] ~ x2(a[2]) ~ x2(a[3]) ~ a[3],
		x2(a[0]) ~ a[0] ~ a[1] ~ a[2] ~ x2(a[3]),
	}
}

// The S-box of AES: the inverse in the field, then the affine step.
@(private)
soft_sbox :: proc "contextless" () -> (s: [256]u8) {
	rotl :: proc "contextless" (v: u8, n: uint) -> u8 {
		return v << n | v >> (8 - n)
	}
	p, q := u8(1), u8(1)
	for {
		// p times 3, q divided by 3: q stays the inverse of p.
		p = p ~ p << 1 ~ (0x1b if p & 0x80 != 0 else 0)
		q ~= q << 1
		q ~= q << 2
		q ~= q << 4
		if q & 0x80 != 0 {
			q ~= 0x09
		}
		s[p] = q ~ rotl(q, 1) ~ rotl(q, 2) ~ rotl(q, 3) ~ rotl(q, 4) ~ 0x63
		if p == 1 {
			break
		}
	}
	s[0] = 0x63
	return
}
