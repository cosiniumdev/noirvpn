// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// Key generation on OpenSSL 3 (see identity.odin).

when NOIR_CRYPTO == "openssl" {

	// A key generation context for `kind`, ready for EVP_PKEY_keygen, or nil.
	// OpenSSL 3 finds the algorithms by name in its default provider.
	backend_keygen_ctx :: proc(kind: Identity_Kind) -> EVP_PKEY_CTX {
		name: cstring
		switch kind {
		case .Ed25519:
			name = "ED25519"
		case .Mldsa65:
			name = "ML-DSA-65"
		case .P256:
			name = "EC"
		}
		ctx := EVP_PKEY_CTX_new_from_name(nil, name, nil)
		if ctx == nil {
			return nil
		}
		ok := EVP_PKEY_keygen_init(ctx) == 1
		// The curve is a parameter of the key generation, set after the init.
		if ok && kind == .P256 {
			ok = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_P256) == 1
		}
		if !ok {
			EVP_PKEY_CTX_free(ctx)
			return nil
		}
		return ctx
	}
}
