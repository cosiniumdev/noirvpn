// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// Incremental HMAC on AWS-LC, through HMAC_CTX (not deprecated there).

when NOIR_CRYPTO == "awslc" {

	// An HMAC with a fixed key that can sign many messages one after another.
	// The key is set once in `hmac_ctx_init`. Not thread-safe: use one per thread.
	Hmac_Ctx :: struct {
		ctx: HMAC_CTX,
		alg: Hmac_Alg,
	}

	hmac_ctx_init :: proc "contextless" (h: ^Hmac_Ctx, alg: Hmac_Alg, key: []u8) -> Error {
		h^ = {}
		if len(key) > 1 << 30 {
			return .Bad_Argument
		}
		ctx := HMAC_CTX_new()
		if ctx == nil {
			ERR_clear_error()
			return .Alloc
		}
		// An empty key still needs a non-null pointer: NULL means "keep the old key".
		dummy: u8
		kp := rawptr(raw_data(key)) if len(key) > 0 else rawptr(&dummy)
		if HMAC_Init_ex(ctx, kp, csize(len(key)), hmac_md(alg), nil) != 1 {
			ERR_clear_error()
			HMAC_CTX_free(ctx)
			return .Lib
		}
		h.ctx = ctx
		h.alg = alg
		return .None
	}

	hmac_ctx_destroy :: proc "contextless" (h: ^Hmac_Ctx) {
		if h.ctx != nil {
			HMAC_CTX_free(h.ctx) // also wipes the key
		}
		h^ = {}
	}

	// Adds data to the message being signed.
	hmac_ctx_update :: proc "contextless" (h: ^Hmac_Ctx, data: []u8) -> bool {
		if len(data) == 0 {
			return true
		}
		return HMAC_Update(h.ctx, raw_data(data), csize(len(data))) == 1
	}

	// Writes the MAC to `out` (at least hmac_size bytes) and gets the context
	// ready for the next message with the same key. (HMAC_Init_ex with no key
	// and no hash keeps both and resets the running state.)
	hmac_ctx_final :: proc "contextless" (h: ^Hmac_Ctx, out: []u8) -> bool {
		size := hmac_size(h.alg)
		if len(out) < size {
			return false
		}
		// The library writes exactly `size` bytes, however long `out` is.
		n: cuint
		ok := HMAC_Final(h.ctx, raw_data(out), &n) == 1 && int(n) == size
		ok = ok && HMAC_Init_ex(h.ctx, nil, 0, nil, nil) == 1
		if !ok {
			ERR_clear_error()
		}
		return ok
	}
}
