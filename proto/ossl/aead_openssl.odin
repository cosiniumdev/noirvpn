// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// AEAD on OpenSSL: one EVP_CIPHER_CTX per key direction. The key is set once.
// Only the IV (nonce) is set again for each packet.
// aead.odin checks the arguments before it calls these procs.

when NOIR_CRYPTO == "openssl" {

	@(private)
	Aead_Lib :: EVP_CIPHER_CTX

	@(private)
	lib_aead_new :: proc(cipher: Aead_Cipher, key: []u8, dir: Aead_Dir) -> (Aead_Lib, Error) {
		// Fetch once. The context keeps its own reference, so ours can go
		// right after init.
		name := cstring("AES-128-GCM")
		switch cipher {
		case .AES_128_GCM:
			name = "AES-128-GCM"
		case .AES_256_GCM:
			name = "AES-256-GCM"
		case .CHACHA20_POLY1305:
			name = "ChaCha20-Poly1305"
		}
		evp := EVP_CIPHER_fetch(nil, name, nil)
		if evp == nil {
			ERR_clear_error()
			return nil, .Lib
		}
		defer EVP_CIPHER_free(evp)

		ctx := EVP_CIPHER_CTX_new()
		if ctx == nil {
			return nil, .Alloc
		}
		ok: bool
		switch dir {
		case .Seal:
			ok = EVP_EncryptInit_ex(ctx, evp, nil, raw_data(key), nil) == 1
		case .Open:
			ok = EVP_DecryptInit_ex(ctx, evp, nil, raw_data(key), nil) == 1
		}
		// Both ciphers default to a 12-byte nonce; set it explicitly.
		ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_NONCE_LEN, nil) == 1
		if !ok {
			ERR_clear_error()
			EVP_CIPHER_CTX_free(ctx)
			return nil, .Lib
		}
		return ctx, .None
	}

	@(private)
	lib_aead_free :: proc "contextless" (ctx: Aead_Lib) {
		EVP_CIPHER_CTX_free(ctx) // also wipes the key schedule
	}

	@(private)
	lib_aead_seal :: proc "contextless" (ctx: Aead_Lib, nonce, aad, plaintext, ciphertext, tag: []u8) -> bool {
		n: cint
		ok := EVP_EncryptInit_ex(ctx, nil, nil, nil, raw_data(nonce)) == 1
		if ok && len(aad) > 0 {
			ok = EVP_EncryptUpdate(ctx, nil, &n, raw_data(aad), cint(len(aad))) == 1
		}
		if ok && len(plaintext) > 0 {
			ok = EVP_EncryptUpdate(ctx, raw_data(ciphertext), &n, raw_data(plaintext), cint(len(plaintext))) == 1
		}
		// Final writes no bytes for these ciphers; it only finishes the tag.
		scratch: [16]u8
		ok = ok && EVP_EncryptFinal_ex(ctx, &scratch[0], &n) == 1
		ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, raw_data(tag)) == 1
		if !ok {
			ERR_clear_error()
		}
		return ok
	}

	// A failed open leaves garbage in `plaintext`.
	@(private)
	lib_aead_open :: proc "contextless" (ctx: Aead_Lib, nonce, aad, ciphertext, tag, plaintext: []u8) -> bool {
		n: cint
		ok := EVP_DecryptInit_ex(ctx, nil, nil, nil, raw_data(nonce)) == 1
		if ok && len(aad) > 0 {
			ok = EVP_DecryptUpdate(ctx, nil, &n, raw_data(aad), cint(len(aad))) == 1
		}
		if ok && len(ciphertext) > 0 {
			ok = EVP_DecryptUpdate(ctx, raw_data(plaintext), &n, raw_data(ciphertext), cint(len(ciphertext))) == 1
		}
		// The tag must be set before Final. OpenSSL takes a non-const pointer.
		ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN, raw_data(tag)) == 1
		scratch: [16]u8
		ok = ok && EVP_DecryptFinal_ex(ctx, &scratch[0], &n) == 1
		if !ok {
			ERR_clear_error() // a bad tag leaves an entry in the error queue
		}
		return ok
	}
}
