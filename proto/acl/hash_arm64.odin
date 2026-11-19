// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

import "base:intrinsics"
import "core:simd"
import "core:simd/arm"

// arm64: the builds of the hash, one chosen at start.
//
//	aes    the AES form with the AES instructions of ARMv8
//	plain  SipHash-1-3
//
// The AES instructions are an option of ARMv8-A: some boards do not have
// them. Linux and Android report them in the hardware capabilities of the
// process. Every arm64 CPU of Apple has them.
//
// AESE is xor key, SubBytes, ShiftRows, and AESMC is MixColumns. So `E` of
// hash.odin is 4 times AESMC(AESE(s, K[i])) and then xor K[4].

@(private = "file")
have_aes: bool = ODIN_OS == .Darwin

when ODIN_OS == .Linux {
	foreign import libc "system:c"

	@(private = "file")
	foreign libc {
		getauxval :: proc "c" (type: uint) -> uint ---
	}

	@(private = "file")
	AT_HWCAP :: 16
	@(private = "file")
	HWCAP_AES :: 1 << 3

	@(init, private)
	hash_init_arm64 :: proc "contextless" () {
		have_aes = getauxval(AT_HWCAP) & HWCAP_AES != 0
	}
}

key_hash :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	if have_aes {
		return key_hash_aes(t, k)
	}
	return key_hash_plain(t, k)
}

@(private = "file", enable_target_feature = "aes")
key_hash_aes :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	if key_is_v4(k) {
		return low32(enc(transmute(arm.uint8x16_t)block_v4(k), &t.rk.v4))
	}
	x := enc(intrinsics.unaligned_load((^arm.uint8x16_t)(&k.laddr)), &t.rk.l)
	y := enc(intrinsics.unaligned_load((^arm.uint8x16_t)(&k.raddr)), &t.rk.r)
	z := enc(transmute(arm.uint8x16_t)Block{k.meta, 0}, &t.rk.m)
	return low32(simd.bit_xor(simd.bit_xor(x, y), z))
}

@(private = "file", enable_target_feature = "aes")
enc :: #force_inline proc "contextless" (x: arm.uint8x16_t, keys: ^Key_Set) -> arm.uint8x16_t {
	s := x
	for i in 0 ..< AES_ROUNDS {
		s = arm.vaesmcq_u8(arm.vaeseq_u8(s, intrinsics.unaligned_load((^arm.uint8x16_t)(&keys[i]))))
	}
	return simd.bit_xor(s, intrinsics.unaligned_load((^arm.uint8x16_t)(&keys[AES_ROUNDS])))
}

@(private = "file")
low32 :: #force_inline proc "contextless" (x: arm.uint8x16_t) -> u32 {
	return simd.extract(transmute(#simd[4]u32)x, 0)
}

@(private = "file")
key_hash_plain :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	return sip13_key(t.k0, t.k1, k)
}

// The builds that this CPU can run. The first one is the build in use.
hash_variants :: proc "contextless" () -> (v: [3]Hash_Variant, n: int) {
	if have_aes {
		v[n] = {"aes", true, key_hash_aes}
		n += 1
	}
	v[n] = {"plain", false, key_hash_plain}
	n += 1
	return
}
