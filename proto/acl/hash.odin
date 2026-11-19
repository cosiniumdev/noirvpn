// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

// The hash of the flow table, keyed with the random key of the table. Without
// the key, a peer cannot find flows that go to one slot. Only the low 32 bits
// are kept.
//
// Two forms. A table uses one of them for all of its life:
//
//	AES form      CPUs with AES instructions (hash_amd64.odin, hash_arm64.odin)
//	SipHash-1-3   other CPUs (this file)
//
// AES form. `E(x, K)` is x xor K[0], then 4 AES rounds with K[1] to K[4]:
//
//	IPv4 flow:  block = last 4 bytes of laddr | last 4 bytes of raddr | meta
//	            hash  = E(block, v4)
//	IPv6 flow:  hash  = E(laddr, l) xor E(raddr, r) xor E(meta | 8 zero bytes, m)
//
// Each input byte goes through 4 AES rounds with secret round keys. After 4
// rounds every byte of a block depends on every input byte, and no difference
// between two inputs has a good chance of a chosen difference in the output
// (at least 25 active S-boxes). The blocks of an IPv6 flow have keys of their
// own, so the CPU runs them at the same time. hash_soft.odin has the same
// function in plain code.
//
// SipHash form. The message is the flow key without its constant bytes:
//
//	IPv6 flow: laddr, raddr, lport, rport, af, proto, one zero byte   39 bytes
//	IPv4 flow: the last 4 bytes of laddr and of raddr, then the same  15 bytes
//
// Both end one byte before a word boundary, so the length byte of SipHash
// fills the last word: 5 words (8 rounds) and 2 words (5 rounds). The rounds
// use plain 64-bit registers: a vector form of one key is slower.

#assert(ODIN_ENDIAN == .Little)

AES_ROUNDS :: 4

// 16 bytes in memory order.
Block :: [2]u64

// A first key and one key for each round.
Key_Set :: [AES_ROUNDS + 1]Block

Round_Keys :: struct {
	v4: Key_Set, // the block of an IPv4 flow
	l:  Key_Set, // IPv6: laddr
	r:  Key_Set, // IPv6: raddr
	m:  Key_Set, // IPv6: ports, family and protocol
}

// One build of the hash, for the tests and the benchmark.
Hash_Variant :: struct {
	name: string,
	aes:  bool, // the AES form
	hash: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32,
}

// The round keys of a table: SipHash-2-4 of a counter with the table key.
round_keys_make :: proc "contextless" (k0, k1: u64) -> (rk: Round_Keys) {
	words := (^[size_of(Round_Keys) / 8]u64)(&rk)
	for &w, i in words {
		w = sip24_word(k0, k1, u64(i))
	}
	return
}

// The block of an IPv4 flow.
@(private)
block_v4 :: #force_inline proc "contextless" (k: ^Flow_Key) -> Block {
	w := (^[5]u64)(k)
	return {w[1] >> 32 | w[3] & 0xffff_ffff_0000_0000, w[4]}
}

@(private)
key_is_v4 :: #force_inline proc "contextless" (k: ^Flow_Key) -> bool {
	return u8(k.meta >> 32) == 4
}

@(private)
sip_round :: #force_inline proc "contextless" (v0, v1, v2, v3: ^u64) {
	rotl :: #force_inline proc "contextless" (x: u64, b: u64) -> u64 {
		return (x << b) | (x >> (64 - b))
	}
	v0^ += v1^
	v1^ = rotl(v1^, 13)
	v1^ ~= v0^
	v0^ = rotl(v0^, 32)
	v2^ += v3^
	v3^ = rotl(v3^, 16)
	v3^ ~= v2^
	v0^ += v3^
	v3^ = rotl(v3^, 21)
	v3^ ~= v0^
	v2^ += v1^
	v1^ = rotl(v1^, 17)
	v1^ ~= v2^
	v2^ = rotl(v2^, 32)
}

// The SipHash form of one key. Inline, so that each caller compiles it for
// its own CPU features.
@(private)
sip13_key :: #force_inline proc "contextless" (k0, k1: u64, k: ^Flow_Key) -> u32 {
	w := (^[5]u64)(k)
	v0 := k0 ~ 0x736f6d6570736575
	v1 := k1 ~ 0x646f72616e646f6d
	v2 := k0 ~ 0x6c7967656e657261
	v3 := k1 ~ 0x7465646279746573
	last := w[4]
	if key_is_v4(k) {
		m := block_v4(k)[0]
		v3 ~= m
		sip_round(&v0, &v1, &v2, &v3)
		v0 ~= m
		last |= 15 << 56
	} else {
		for i in 0 ..< 4 {
			m := w[i]
			v3 ~= m
			sip_round(&v0, &v1, &v2, &v3)
			v0 ~= m
		}
		last |= 39 << 56
	}
	v3 ~= last
	sip_round(&v0, &v1, &v2, &v3)
	v0 ~= last
	v2 ~= 0xff
	sip_round(&v0, &v1, &v2, &v3)
	sip_round(&v0, &v1, &v2, &v3)
	sip_round(&v0, &v1, &v2, &v3)
	return u32(v0 ~ v1 ~ v2 ~ v3)
}

// SipHash-2-4 of the 8 bytes of `m`.
@(private)
sip24_word :: proc "contextless" (k0, k1: u64, m: u64) -> u64 {
	v0 := k0 ~ 0x736f6d6570736575
	v1 := k1 ~ 0x646f72616e646f6d
	v2 := k0 ~ 0x6c7967656e657261
	v3 := k1 ~ 0x7465646279746573
	for b in ([2]u64{m, 8 << 56}) {
		v3 ~= b
		sip_round(&v0, &v1, &v2, &v3)
		sip_round(&v0, &v1, &v2, &v3)
		v0 ~= b
	}
	v2 ~= 0xff
	for _ in 0 ..< 4 {
		sip_round(&v0, &v1, &v2, &v3)
	}
	return v0 ~ v1 ~ v2 ~ v3
}
