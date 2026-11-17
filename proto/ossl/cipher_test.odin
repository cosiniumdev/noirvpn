// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:testing"

// NIST SP 800-38A, F.5.5 (CTR-AES256.Encrypt), all four blocks.
@(test)
aes256_ctr_nist_vector :: proc(t: ^testing.T) {
	key := unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt := unhex(
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
	)
	want := unhex(
		"601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
	)
	ct := make([]u8, len(pt), context.temp_allocator)
	testing.expect(t, aes256_ctr_xor(key, iv, ct, pt))
	expect_bytes(t, ct, want, "ciphertext")

	// CTR is its own inverse, and may run in place.
	testing.expect(t, aes256_ctr_xor(key, iv, ct, ct))
	expect_bytes(t, ct, pt, "decrypted")

	// Not a whole number of blocks.
	part := make([]u8, 21, context.temp_allocator)
	testing.expect(t, aes256_ctr_xor(key, iv, part, pt[:21]))
	expect_bytes(t, part, want[:21], "partial block")

	// Argument checks.
	testing.expect(t, !aes256_ctr_xor(key[:31], iv, ct, pt))
	testing.expect(t, !aes256_ctr_xor(key, iv[:15], ct, pt))
	testing.expect(t, !aes256_ctr_xor(key, iv, ct[:10], pt))
	testing.expect(t, aes256_ctr_xor(key, iv, nil, nil))
}

@(test)
random_bytes_work :: proc(t: ^testing.T) {
	a, b: [64]u8
	testing.expect(t, random_bytes(a[:]))
	testing.expect(t, random_bytes(b[:]))
	zero: [64]u8
	testing.expect(t, a != zero, "all zero")
	testing.expect(t, a != b, "two draws are equal")
	testing.expect(t, random_bytes(nil), "empty request must succeed")
}

@(test)
backend_is_recent_enough :: proc(t: ^testing.T) {
	// OpenSSL: 3.5.0 is the minimum; 4.x is fine. AWS-LC: 5.0.0, the release
	// we tested (its number is in the same layout, see `backend_version_num`).
	when NOIR_CRYPTO == "openssl" {
		testing.expectf(t, backend_version_num() >= 0x30500000, "library too old: %s", backend_version())
	} else {
		testing.expectf(t, backend_version_num() >= 0x50000000, "library too old: %s", backend_version())
	}
	testing.expect(t, len(backend_version()) > 0)
}
