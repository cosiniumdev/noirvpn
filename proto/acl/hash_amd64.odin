// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

import "base:intrinsics"
import "core:simd/x86"

// amd64: the builds of the hash, one chosen at start with CPUID.
//
//	aes    the AES form with AES-NI
//	bmi2   SipHash-1-3 with RORX rotates
//	plain  SipHash-1-3 for the default CPU target
//
// For the default CPU target the compiler writes a rotate as SHLD. That is
// quick on Intel CPUs and slow on AMD ones, so a CPU with no AES-NI but with
// BMI2 gets the RORX build. AES-NI and BMI2 need no support from the OS.

@(private = "file")
have_aes, have_bmi2: bool

@(init, private)
hash_init_amd64 :: proc "contextless" () {
	max_leaf, _, _, _ := intrinsics.x86_cpuid(0, 0)
	if max_leaf >= 1 {
		_, _, ecx, _ := intrinsics.x86_cpuid(1, 0)
		have_aes = ecx & (1 << 25) != 0
	}
	if max_leaf >= 7 {
		_, ebx, _, _ := intrinsics.x86_cpuid(7, 0)
		have_bmi2 = ebx & (1 << 8) != 0
	}
}

key_hash :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	if have_aes {
		return key_hash_aes(t, k)
	}
	if have_bmi2 {
		return key_hash_bmi2(t, k)
	}
	return key_hash_plain(t, k)
}

@(private = "file", enable_target_feature = "sse2,aes")
key_hash_aes :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	if key_is_v4(k) {
		b := block_v4(k)
		return u32(x86._mm_cvtsi128_si32(enc(x86._mm_set_epi64x(i64(b[1]), i64(b[0])), &t.rk.v4)))
	}
	x := enc(x86._mm_loadu_si128((^x86.__m128i)(&k.laddr)), &t.rk.l)
	y := enc(x86._mm_loadu_si128((^x86.__m128i)(&k.raddr)), &t.rk.r)
	z := enc(x86._mm_set_epi64x(0, i64(k.meta)), &t.rk.m)
	return u32(x86._mm_cvtsi128_si32(x86._mm_xor_si128(x86._mm_xor_si128(x, y), z)))
}

@(private = "file", enable_target_feature = "sse2,aes")
enc :: #force_inline proc "contextless" (x: x86.__m128i, keys: ^Key_Set) -> x86.__m128i {
	s := x86._mm_xor_si128(x, x86._mm_loadu_si128((^x86.__m128i)(&keys[0])))
	for i in 1 ..= AES_ROUNDS {
		s = x86._mm_aesenc_si128(s, x86._mm_loadu_si128((^x86.__m128i)(&keys[i])))
	}
	return s
}

@(private = "file", enable_target_feature = "bmi2")
key_hash_bmi2 :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	return sip13_key(t.k0, t.k1, k)
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
	if have_bmi2 {
		v[n] = {"bmi2", false, key_hash_bmi2}
		n += 1
	}
	v[n] = {"plain", false, key_hash_plain}
	n += 1
	return
}
