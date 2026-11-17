// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// AES-256-CTR (used by tls-crypt for control packets).
//
// One-shot: allocates a cipher context inside the C library on every call. Fine
// for the control channel; the data channel uses `aead_*`. `key` is 32 bytes,
// `iv` is 16 bytes (the initial counter block). `dst` must be at least as long as
// `src` and may be the same slice.
AES256_KEY_LEN :: 32
AES_BLOCK_LEN :: 16

aes256_ctr_xor :: proc "contextless" (key, iv: []u8, dst, src: []u8) -> bool {
	if len(key) != AES256_KEY_LEN || len(iv) != AES_BLOCK_LEN || len(dst) < len(src) || len(src) > 1 << 30 {
		return false
	}
	ctx := EVP_CIPHER_CTX_new()
	if ctx == nil {
		return false
	}
	defer EVP_CIPHER_CTX_free(ctx)

	ok := EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nil, raw_data(key), raw_data(iv)) == 1
	if ok && len(src) > 0 {
		n: cint
		ok = EVP_EncryptUpdate(ctx, raw_data(dst), &n, raw_data(src), cint(len(src))) == 1 && int(n) == len(src)
	}
	if !ok {
		ERR_clear_error()
	}
	return ok
}
