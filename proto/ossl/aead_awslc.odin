// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// AEAD on AWS-LC: one EVP_AEAD_CTX per key direction, set up once. The key
// schedule is never rewritten, so threads may share one `Aead` (aead.h says seal
// and open "may be called concurrently"). The nonce goes into every call; the
// context has no per-packet state. aead.odin checks arguments before these procs.

when NOIR_CRYPTO == "awslc" {

	@(private)
	Aead_Lib :: EVP_AEAD_CTX // read only after lib_aead_new

	@(private)
	lib_aead_new :: proc(cipher: Aead_Cipher, key: []u8, dir: Aead_Dir) -> (Aead_Lib, Error) {
		alg: EVP_AEAD
		switch cipher {
		case .AES_128_GCM:
			alg = EVP_aead_aes_128_gcm()
		case .AES_256_GCM:
			alg = EVP_aead_aes_256_gcm()
		case .CHACHA20_POLY1305:
			alg = EVP_aead_chacha20_poly1305()
		}
		// The context is allocated by the library, so we need not know the
		// size of the C struct.
		ctx := EVP_AEAD_CTX_new(alg, raw_data(key), csize(len(key)), AEAD_TAG_LEN)
		if ctx == nil {
			ERR_clear_error()
			return nil, .Lib
		}
		return ctx, .None
	}

	@(private)
	lib_aead_free :: proc "contextless" (ctx: Aead_Lib) {
		EVP_AEAD_CTX_free(ctx) // also wipes the key schedule
	}

	@(private)
	lib_aead_seal :: proc "contextless" (ctx: Aead_Lib, nonce, aad, plaintext, ciphertext, tag: []u8) -> bool {
		// With an empty message the library still wants non-null pointers.
		dummy: [1]u8
		in_p, out_p := raw_data(plaintext), raw_data(ciphertext)
		if len(plaintext) == 0 {
			in_p, out_p = &dummy[0], &dummy[0]
		}
		tag_len: csize
		ok :=
			EVP_AEAD_CTX_seal_scatter(
				ctx,
				out_p,
				raw_data(tag),
				&tag_len,
				AEAD_TAG_LEN,
				raw_data(nonce),
				AEAD_NONCE_LEN,
				in_p,
				csize(len(plaintext)),
				nil,
				0,
				raw_data(aad),
				csize(len(aad)),
			) ==
			1 &&
			tag_len == AEAD_TAG_LEN
		if !ok {
			ERR_clear_error()
		}
		return ok
	}

	// A failed open zeroes `plaintext` (AWS-LC does that).
	@(private)
	lib_aead_open :: proc "contextless" (ctx: Aead_Lib, nonce, aad, ciphertext, tag, plaintext: []u8) -> bool {
		dummy: [1]u8
		in_p, out_p := raw_data(ciphertext), raw_data(plaintext)
		if len(ciphertext) == 0 {
			in_p, out_p = &dummy[0], &dummy[0]
		}
		ok :=
			EVP_AEAD_CTX_open_gather(
				ctx,
				out_p,
				raw_data(nonce),
				AEAD_NONCE_LEN,
				in_p,
				csize(len(ciphertext)),
				raw_data(tag),
				AEAD_TAG_LEN,
				raw_data(aad),
				csize(len(aad)),
			) ==
			1
		if !ok {
			ERR_clear_error() // a bad tag leaves an entry in the error queue
		}
		return ok
	}
}
