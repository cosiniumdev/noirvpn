// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// Key generation on AWS-LC (see identity.odin).

when NOIR_CRYPTO == "awslc" {

	@(private = "file")
	NID_PQDSA :: 993
	@(private = "file")
	NID_MLDSA65 :: 995

	// A key generation context for `kind`, ready for EVP_PKEY_keygen, or nil.
	// AWS-LC has one key type for all ML-DSA sets (EVP_PKEY_PQDSA); the set is
	// a parameter of the context.
	backend_keygen_ctx :: proc(kind: Identity_Kind) -> EVP_PKEY_CTX {
		id: cint
		switch kind {
		case .Ed25519:
			id = NID_ED25519
		case .Mldsa65:
			id = NID_PQDSA
		case .P256:
			id = EVP_PKEY_EC
		}
		ctx := EVP_PKEY_CTX_new_id(id, nil)
		if ctx == nil {
			return nil
		}
		ok := true
		if kind == .Mldsa65 {
			ok = EVP_PKEY_CTX_pqdsa_set_params(ctx, NID_MLDSA65) == 1
		}
		ok = ok && EVP_PKEY_keygen_init(ctx) == 1
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
