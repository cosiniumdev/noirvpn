// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// Incremental HMAC on OpenSSL, through EVP_MAC (HMAC_CTX is deprecated).

when NOIR_CRYPTO == "openssl" {

	// An HMAC with a fixed key that can sign many messages one after another.
	// The key is set once in `hmac_ctx_init`. Not thread-safe: use one per thread.
	Hmac_Ctx :: struct {
		ctx: EVP_MAC_CTX,
		alg: Hmac_Alg,
	}

	hmac_ctx_init :: proc "contextless" (h: ^Hmac_Ctx, alg: Hmac_Alg, key: []u8) -> Error {
		h^ = {}
		if len(key) > 1 << 30 {
			return .Bad_Argument
		}
		mac := EVP_MAC_fetch(nil, "HMAC", nil)
		if mac == nil {
			ERR_clear_error()
			return .Lib
		}
		defer EVP_MAC_free(mac) // the context keeps its own reference
		ctx := EVP_MAC_CTX_new(mac)
		if ctx == nil {
			ERR_clear_error()
			return .Alloc
		}

		digest := cstring("SHA256")
		switch alg {
		case .SHA1:
			digest = "SHA1"
		case .SHA256:
			digest = "SHA256"
		case .SHA512:
			digest = "SHA512"
		case .SHA224:
			digest = "SHA224"
		case .SHA384:
			digest = "SHA384"
		}
		params := [2]OSSL_PARAM {
			{
				key = "digest",
				data_type = OSSL_PARAM_UTF8_STRING,
				data = rawptr(digest),
				data_size = csize(len(digest)),
				return_size = OSSL_PARAM_UNMODIFIED,
			},
			{}, // an all-zero entry ends the list
		}
		// An empty key still needs a non-null pointer.
		dummy: u8
		kp := rawptr(raw_data(key)) if len(key) > 0 else rawptr(&dummy)
		if EVP_MAC_init(ctx, kp, csize(len(key)), &params[0]) != 1 {
			ERR_clear_error()
			EVP_MAC_CTX_free(ctx)
			return .Lib
		}
		h.ctx = ctx
		h.alg = alg
		return .None
	}

	hmac_ctx_destroy :: proc "contextless" (h: ^Hmac_Ctx) {
		if h.ctx != nil {
			EVP_MAC_CTX_free(h.ctx) // also wipes the key
		}
		h^ = {}
	}

	// Adds data to the message being signed.
	hmac_ctx_update :: proc "contextless" (h: ^Hmac_Ctx, data: []u8) -> bool {
		if len(data) == 0 {
			return true
		}
		return EVP_MAC_update(h.ctx, raw_data(data), csize(len(data))) == 1
	}

	// Writes the MAC to `out` (at least hmac_size bytes) and gets the context
	// ready for the next message with the same key. (For HMAC, EVP_MAC_init
	// with no key keeps the key that is already set.)
	hmac_ctx_final :: proc "contextless" (h: ^Hmac_Ctx, out: []u8) -> bool {
		size := hmac_size(h.alg)
		if len(out) < size {
			return false
		}
		n: csize
		ok := EVP_MAC_final(h.ctx, raw_data(out), &n, csize(len(out))) == 1 && int(n) == size
		ok = ok && EVP_MAC_init(h.ctx, nil, 0, nil) == 1
		if !ok {
			ERR_clear_error()
		}
		return ok
	}
}
