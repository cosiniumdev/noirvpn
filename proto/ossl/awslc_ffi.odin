// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+private
package ossl

// Raw AWS-LC bindings not shared with OpenSSL (see `ffi_common.odin`).
// Package-private: other packages use the API in the other files, never these
// names. Checked against the AWS-LC 5.0.0 headers. Where AWS-LC takes a different
// argument size than OpenSSL (`size_t` or `uint16_t` for `int`), the C function
// is declared here with a `c_` prefix and a small wrapper has the OpenSSL name,
// so the shared files compile unchanged.

when NOIR_CRYPTO == "awslc" {

	foreign import lib {"system:ssl", "system:crypto"}

	// AWS-LC takes 32 bits here (OpenSSL: 64).
	SSL_OP_NO_TICKET :: u32(1) << 14

	// Signature algorithms for TLS (ssl.h, SSL_SIGN_*).
	SSL_SIGN_RSA_PKCS1_SHA256 :: 0x0401
	SSL_SIGN_RSA_PKCS1_SHA384 :: 0x0501
	SSL_SIGN_RSA_PKCS1_SHA512 :: 0x0601
	SSL_SIGN_ECDSA_SECP256R1_SHA256 :: 0x0403
	SSL_SIGN_ECDSA_SECP384R1_SHA384 :: 0x0503
	SSL_SIGN_ECDSA_SECP521R1_SHA512 :: 0x0603
	SSL_SIGN_RSA_PSS_RSAE_SHA256 :: 0x0804
	SSL_SIGN_RSA_PSS_RSAE_SHA384 :: 0x0805
	SSL_SIGN_RSA_PSS_RSAE_SHA512 :: 0x0806
	SSL_SIGN_ED25519 :: 0x0807
	SSL_SIGN_MLDSA44 :: 0x0904
	SSL_SIGN_MLDSA65 :: 0x0905
	SSL_SIGN_MLDSA87 :: 0x0906

	// The decompression callback of `SSL_CTX_add_cert_compression_alg` (ssl.h).
	// `out` is a `CRYPTO_BUFFER **`.
	cert_decompress_fn :: #type proc "c" (ssl: SSL, out: ^rawptr, uncompressed_len: csize, inp: [^]u8, in_len: csize) -> cint

	// Handle types that only this backend has.
	EVP_AEAD :: distinct rawptr
	EVP_AEAD_CTX :: distinct rawptr
	HMAC_CTX :: distinct rawptr

	@(default_calling_convention = "c")
	foreign lib {
		// --- libcrypto: same name as in OpenSSL, but other argument types ---
		ERR_get_error :: proc() -> u32 ---
		ERR_error_string_n :: proc(e: u32, buf: [^]u8, len: csize) ---
		@(link_name = "RAND_bytes")
		c_RAND_bytes :: proc(buf: [^]u8, num: csize) -> cint ---
		@(link_name = "BIO_new_mem_buf")
		c_BIO_new_mem_buf :: proc(buf: rawptr, len: int) -> BIO ---
		BIO_pending :: proc(bio: BIO) -> csize ---
		// The generic stack (X509_STORE_CTX_get0_chain gives one). `size_t` here, `int` in OpenSSL.
		OPENSSL_sk_num :: proc(sk: STACK) -> csize ---
		OPENSSL_sk_value :: proc(sk: STACK, i: csize) -> rawptr ---
		@(link_name = "HMAC")
		c_HMAC :: proc(md: EVP_MD, key: rawptr, key_len: csize, data: rawptr, n: csize, out: [^]u8, out_len: ^cuint) -> [^]u8 ---

		@(link_name = "PKCS5_PBKDF2_HMAC")
		c_PKCS5_PBKDF2_HMAC :: proc(pass: rawptr, passlen: csize, salt: rawptr, saltlen: csize, iter: cuint, md: EVP_MD, keylen: csize, out: [^]u8) -> cint ---

		// --- libcrypto: AWS-LC only ---
		// AEAD. `EVP_AEAD_CTX` is immutable after `EVP_AEAD_CTX_new`. The seal and
		// open calls may run on many threads at once (aead.h).
		EVP_aead_aes_128_gcm :: proc() -> EVP_AEAD ---
		EVP_aead_aes_256_gcm :: proc() -> EVP_AEAD ---
		EVP_aead_chacha20_poly1305 :: proc() -> EVP_AEAD ---
		EVP_AEAD_CTX_new :: proc(aead: EVP_AEAD, key: [^]u8, key_len: csize, tag_len: csize) -> EVP_AEAD_CTX ---
		EVP_AEAD_CTX_free :: proc(ctx: EVP_AEAD_CTX) ---
		EVP_AEAD_CTX_seal_scatter :: proc(ctx: EVP_AEAD_CTX, out: [^]u8, out_tag: [^]u8, out_tag_len: ^csize, max_out_tag_len: csize, nonce: [^]u8, nonce_len: csize, inp: [^]u8, in_len: csize, extra_in: [^]u8, extra_in_len: csize, ad: [^]u8, ad_len: csize) -> cint ---
		EVP_AEAD_CTX_open_gather :: proc(ctx: EVP_AEAD_CTX, out: [^]u8, nonce: [^]u8, nonce_len: csize, inp: [^]u8, in_len: csize, in_tag: [^]u8, in_tag_len: csize, ad: [^]u8, ad_len: csize) -> cint ---

		// Incremental HMAC (not deprecated in AWS-LC).
		HMAC_CTX_new :: proc() -> HMAC_CTX ---
		HMAC_CTX_free :: proc(ctx: HMAC_CTX) ---
		HMAC_Init_ex :: proc(ctx: HMAC_CTX, key: rawptr, key_len: csize, md: EVP_MD, engine: rawptr) -> cint ---
		HMAC_Update :: proc(ctx: HMAC_CTX, data: rawptr, len: csize) -> cint ---
		HMAC_Final :: proc(ctx: HMAC_CTX, out: [^]u8, out_len: ^cuint) -> cint ---

		// --- libssl: same name as in OpenSSL, but other argument types ---
		SSL_CTX_set_options :: proc(ctx: SSL_CTX, options: u32) -> u32 ---
		@(link_name = "SSL_CTX_set_min_proto_version")
		c_SSL_CTX_set_min_proto_version :: proc(ctx: SSL_CTX, version: u16) -> cint ---
		@(link_name = "SSL_CTX_set_max_proto_version")
		c_SSL_CTX_set_max_proto_version :: proc(ctx: SSL_CTX, version: u16) -> cint ---

		// --- libssl: real functions here, macros over SSL_CTX_ctrl in OpenSSL ---
		SSL_CTX_set1_groups_list :: proc(ctx: SSL_CTX, groups: cstring) -> cint ---
		SSL_CTX_set_session_cache_mode :: proc(ctx: SSL_CTX, mode: cint) -> cint ---
		SSL_CTX_add_extra_chain_cert :: proc(ctx: SSL_CTX, x: X509) -> cint --- // takes ownership on success
		SSL_set_tlsext_host_name :: proc(ssl: SSL, name: cstring) -> cint ---
		SSL_set_read_ahead :: proc(ssl: SSL, yes: cint) -> cint --- // OpenSSL: no result

		@(link_name = "SSL_set_alpn_protos")
		c_SSL_set_alpn_protos :: proc(ssl: SSL, protos: [^]u8, len: csize) -> cint --- // 0 on success

		// --- libssl: AWS-LC only ---
		SSL_CTX_set_signing_algorithm_prefs :: proc(ctx: SSL_CTX, prefs: [^]u16, num: csize) -> cint ---
		SSL_CTX_set_verify_algorithm_prefs :: proc(ctx: SSL_CTX, prefs: [^]u16, num: csize) -> cint ---

		// The ClientHello profile (see tls_awslc.odin, `backend_hello_ctx`).
		SSL_CTX_set_strict_cipher_list :: proc(ctx: SSL_CTX, list: cstring) -> cint --- // OpenSSL: SSL_CTX_set_cipher_list
		SSL_CTX_set_grease_enabled :: proc(ctx: SSL_CTX, enabled: cint) ---
		SSL_CTX_set_permute_extensions :: proc(ctx: SSL_CTX, enabled: cint) ---
		SSL_CTX_enable_ocsp_stapling :: proc(ctx: SSL_CTX) --- // OpenSSL: SSL_CTX_set_tlsext_status_type
		SSL_CTX_enable_signed_cert_timestamps :: proc(ctx: SSL_CTX) ---
		SSL_CTX_add_cert_compression_alg :: proc(ctx: SSL_CTX, alg_id: u16, compress: rawptr, decompress: cert_decompress_fn) -> cint ---
		SSL_add_application_settings :: proc(ssl: SSL, proto: [^]u8, proto_len: csize, settings: [^]u8, settings_len: csize) -> cint ---
		SSL_set_alps_use_new_codepoint :: proc(ssl: SSL, use_new: cint) ---
		SSL_set_enable_ech_grease :: proc(ssl: SSL, enable: cint) ---

		EVP_PKEY_base_id :: proc(pkey: EVP_PKEY) -> cint --- // OpenSSL 3: EVP_PKEY_get_base_id

		// --- libssl: AWS-LC names for what OpenSSL 3 calls differently ---
		SSL_get_peer_certificate :: proc(ssl: SSL) -> X509 --- // new reference
		SSL_get_group_id :: proc(ssl: SSL) -> u16 --- // 0 if there is no handshake yet
		SSL_get_group_name :: proc(group_id: u16) -> cstring --- // nil for an unknown id

		// --- key generation (identity_awslc.odin) ---
		// OpenSSL 3: EVP_PKEY_CTX_new_from_name with the algorithm name.
		EVP_PKEY_CTX_new_id :: proc(id: cint, engine: rawptr) -> EVP_PKEY_CTX ---
		EVP_PKEY_CTX_pqdsa_set_params :: proc(ctx: EVP_PKEY_CTX, nid: cint) -> cint ---
		@(link_name = "X509_NAME_add_entry_by_NID")
		c_X509_NAME_add_entry_by_NID :: proc(name: X509_NAME, nid: cint, type: cint, bytes: [^]u8, len: int, loc: cint, set: cint) -> cint --- // `len` is an ossl_ssize_t
	}

	X509_NAME_add_entry_by_NID :: proc "contextless" (name: X509_NAME, nid: cint, type: cint, bytes: [^]u8, len: cint, loc: cint, set: cint) -> cint {
		return c_X509_NAME_add_entry_by_NID(name, nid, type, bytes, int(len), loc, set)
	}

	// Wrappers: the shared files call these with OpenSSL's argument types.

	chain_len :: proc "contextless" (sk: STACK) -> int {
		return int(OPENSSL_sk_num(sk)) if sk != nil else 0
	}

	chain_get :: proc "contextless" (sk: STACK, i: int) -> X509 {
		return X509(OPENSSL_sk_value(sk, csize(i)))
	}

	bio_pending :: proc "contextless" (bio: BIO) -> int {
		return int(BIO_pending(bio))
	}

	RAND_bytes :: proc "contextless" (buf: [^]u8, num: cint) -> cint {
		return c_RAND_bytes(buf, csize(num))
	}

	BIO_new_mem_buf :: proc "contextless" (buf: rawptr, len: cint) -> BIO {
		return c_BIO_new_mem_buf(buf, int(len))
	}

	HMAC :: proc "contextless" (md: EVP_MD, key: rawptr, key_len: cint, data: rawptr, n: csize, out: [^]u8, out_len: ^cuint) -> [^]u8 {
		return c_HMAC(md, key, csize(key_len), data, n, out, out_len)
	}

	PKCS5_PBKDF2_HMAC :: proc "contextless" (pass: rawptr, passlen: cint, salt: rawptr, saltlen: cint, iter: cint, md: EVP_MD, keylen: cint, out: [^]u8) -> cint {
		return c_PKCS5_PBKDF2_HMAC(pass, csize(passlen), salt, csize(saltlen), cuint(iter), md, csize(keylen), out)
	}

	SSL_CTX_set_min_proto_version :: proc "contextless" (ctx: SSL_CTX, version: int) -> cint {
		return c_SSL_CTX_set_min_proto_version(ctx, u16(version))
	}

	SSL_CTX_set_max_proto_version :: proc "contextless" (ctx: SSL_CTX, version: int) -> cint {
		return c_SSL_CTX_set_max_proto_version(ctx, u16(version))
	}

	// Returns 0 on success (the C library breaks the usual rule); we turn it around.
	SSL_set_alpn_protos :: proc "contextless" (ssl: SSL, protos: [^]u8, len: int) -> cint {
		return 1 if c_SSL_set_alpn_protos(ssl, protos, csize(len)) == 0 else 0
	}
}
