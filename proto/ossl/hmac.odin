// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:mem"

// Hash used by HMAC and HKDF. tls-auth may use any of these. New values go at
// the end: other packages use the enum.
Hmac_Alg :: enum {
	SHA1,
	SHA256,
	SHA512,
	SHA224,
	SHA384,
}

// Size of the HMAC output (= the hash output) in bytes.
hmac_size :: proc "contextless" (alg: Hmac_Alg) -> int {
	switch alg {
	case .SHA1:
		return SHA1_LEN
	case .SHA256:
		return SHA256_LEN
	case .SHA512:
		return SHA512_LEN
	case .SHA224:
		return SHA224_LEN
	case .SHA384:
		return SHA384_LEN
	}
	return 0
}

// The digest of `alg` as a C handle (the AWS-LC backend needs it).
@(private = "package")
hmac_md :: proc "contextless" (alg: Hmac_Alg) -> EVP_MD {
	switch alg {
	case .SHA1:
		return EVP_sha1()
	case .SHA256:
		return EVP_sha256()
	case .SHA512:
		return EVP_sha512()
	case .SHA224:
		return EVP_sha224()
	case .SHA384:
		return EVP_sha384()
	}
	return nil
}

// One-shot HMAC of `data`. `out` must hold at least hmac_size(alg) bytes.
// For many messages under one key use `Hmac_Ctx`.
hmac :: proc "contextless" (alg: Hmac_Alg, key, data: []u8, out: []u8) -> bool {
	if len(out) < hmac_size(alg) || len(key) > 1 << 30 {
		return false
	}
	// An empty key or message still needs a non-null pointer for the C library.
	dummy: u8
	kp := rawptr(raw_data(key)) if len(key) > 0 else rawptr(&dummy)
	dp := rawptr(raw_data(data)) if len(data) > 0 else rawptr(&dummy)
	n: cuint
	if HMAC(hmac_md(alg), kp, cint(len(key)), dp, csize(len(data)), raw_data(out), &n) == nil {
		ERR_clear_error()
		return false
	}
	return true
}

// HKDF-Extract (RFC 5869 section 2.2). `prk` must hold hmac_size(alg) bytes.
// An empty salt means a string of zero bytes, as the RFC says.
hkdf_extract :: proc "contextless" (alg: Hmac_Alg, salt, ikm: []u8, prk: []u8) -> bool {
	zeros: [SHA512_LEN]u8
	s := salt
	if len(s) == 0 {
		s = zeros[:hmac_size(alg)]
	}
	return hmac(alg, s, ikm, prk)
}

// HKDF-Expand (RFC 5869 section 2.3). Fills `okm` completely. It is built on
// HMAC, so it works the same on every backend.
// Fails if len(okm) > 255 * hash size.
hkdf_expand :: proc "contextless" (alg: Hmac_Alg, prk, info: []u8, okm: []u8) -> bool {
	hlen := hmac_size(alg)
	if len(okm) > 255 * hlen {
		return false
	}
	h: Hmac_Ctx
	if hmac_ctx_init(&h, alg, prk) != .None {
		return false
	}
	defer hmac_ctx_destroy(&h)

	t: [SHA512_LEN]u8
	defer mem.zero_explicit(&t, size_of(t))
	done := 0
	for counter := 1; done < len(okm); counter += 1 {
		ctr := [1]u8{u8(counter)}
		ok := true
		if counter > 1 {
			ok = hmac_ctx_update(&h, t[:hlen])
		}
		ok = ok && hmac_ctx_update(&h, info) && hmac_ctx_update(&h, ctr[:]) && hmac_ctx_final(&h, t[:])
		if !ok {
			return false
		}
		n := min(hlen, len(okm) - done)
		copy(okm[done:done + n], t[:n])
		done += n
	}
	return true
}
