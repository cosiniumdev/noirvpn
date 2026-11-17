// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:mem"

// Most iterations `pbkdf2_sha256` takes. A larger count is refused.
PBKDF2_MAX_ITERATIONS :: 10_000_000

// PBKDF2-HMAC-SHA-256 (RFC 8018). Fills `out` (1 to 1024 bytes). It is slow on
// purpose: call it on a worker thread, never on the event loop. Thread-safe.
pbkdf2_sha256 :: proc "contextless" (password, salt: []u8, iterations: int, out: []u8) -> bool {
	if iterations < 1 || iterations > PBKDF2_MAX_ITERATIONS || len(out) < 1 || len(out) > 1024 || len(password) > 1 << 20 || len(salt) > 1 << 20 {
		return false
	}
	// A zero length still needs a non-null pointer for the C library.
	dummy: u8
	pp := rawptr(raw_data(password)) if len(password) > 0 else rawptr(&dummy)
	sp := rawptr(raw_data(salt)) if len(salt) > 0 else rawptr(&dummy)
	if PKCS5_PBKDF2_HMAC(pp, cint(len(password)), sp, cint(len(salt)), cint(iterations), EVP_sha256(), cint(len(out)), raw_data(out)) != 1 {
		ERR_clear_error()
		mem.zero_explicit(raw_data(out), len(out))
		return false
	}
	return true
}

// True when `a` and `b` have the same length and bytes. The time does not
// depend on where they differ.
ct_equal :: proc "contextless" (a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return CRYPTO_memcmp(raw_data(a), raw_data(b), csize(len(a))) == 0
}
