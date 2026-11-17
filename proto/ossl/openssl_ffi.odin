// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+private
package ossl

// Raw OpenSSL bindings that are not shared with AWS-LC (see `ffi_common.odin`
// for the ones that are). Package-private: other packages use the API in the
// other files of this package, never these names.
//
// Names follow the C library. Where OpenSSL has a macro but AWS-LC has a real
// function of the same name (SSL_CTX_set_min_proto_version, ...), a small
// wrapper below has the C name, so the shared files can call it either way.

when NOIR_CRYPTO == "openssl" {

	when ODIN_OS == .Windows {
		foreign import lib {"system:ssl.lib", "system:crypto.lib"}
	} else {
		foreign import lib {"system:ssl", "system:crypto"}
	}

	// Values of C macros that we need.
	SSL_CTRL_EXTRA_CHAIN_CERT :: 14
	SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
	TLSEXT_NAMETYPE_host_name :: 0
	SSL_CTRL_SET_SESS_CACHE_MODE :: 44
	SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE :: 65
	TLSEXT_STATUSTYPE_ocsp :: 1
	SSL_CTRL_SET_GROUPS_LIST :: 92
	SSL_CTRL_SET_SIGALGS_LIST :: 98
	SSL_CTRL_SET_MIN_PROTO_VERSION :: 123
	SSL_CTRL_SET_MAX_PROTO_VERSION :: 124
	SSL_OP_NO_TICKET :: u64(1) << 14
	SSL_OP_CLEANSE_PLAINTEXT :: u64(1) << 1
	SSL_OP_NO_ENCRYPT_THEN_MAC :: u64(1) << 19
	EVP_CTRL_AEAD_SET_IVLEN :: 0x9
	EVP_CTRL_AEAD_GET_TAG :: 0x10
	EVP_CTRL_AEAD_SET_TAG :: 0x11

	// OpenSSL-only handle types and the parameter record of the OSSL_PARAM API.
	EVP_MAC :: distinct rawptr
	EVP_MAC_CTX :: distinct rawptr

	OSSL_PARAM :: struct {
		key:         cstring,
		data_type:   cuint,
		data:        rawptr,
		data_size:   csize,
		return_size: csize,
	}
	OSSL_PARAM_UTF8_STRING :: 4
	OSSL_PARAM_UNMODIFIED :: ~csize(0) // (size_t)-1

	@(default_calling_convention = "c")
	foreign lib {
		// --- libcrypto: same name as in AWS-LC, but other argument types ---
		ERR_get_error :: proc() -> culong ---
		ERR_error_string_n :: proc(e: culong, buf: [^]u8, len: csize) ---
		RAND_bytes :: proc(buf: [^]u8, num: cint) -> cint ---
		BIO_new_mem_buf :: proc(buf: rawptr, len: cint) -> BIO ---
		BIO_ctrl :: proc(bio: BIO, cmd: cint, larg: clong, parg: rawptr) -> clong ---

		// One-shot HMAC. Not deprecated in 3.x or 4.x (HMAC_CTX_* is, so we do not use it).
		HMAC :: proc(md: EVP_MD, key: rawptr, key_len: cint, data: rawptr, n: csize, out: [^]u8, out_len: ^cuint) -> [^]u8 ---

		// `int` lengths and count here, `size_t` and `uint32_t` in AWS-LC.
		PKCS5_PBKDF2_HMAC :: proc(pass: rawptr, passlen: cint, salt: rawptr, saltlen: cint, iter: cint, md: EVP_MD, keylen: cint, out: [^]u8) -> cint ---

		// The generic stack (X509_STORE_CTX_get0_chain gives one). `int` here, `size_t` in AWS-LC.
		OPENSSL_sk_num :: proc(sk: STACK) -> cint ---
		OPENSSL_sk_value :: proc(sk: STACK, i: cint) -> rawptr ---

		// --- libcrypto: used by the AEAD code only ---
		EVP_CIPHER_CTX_ctrl :: proc(ctx: EVP_CIPHER_CTX, type: cint, arg: cint, ptr: rawptr) -> cint ---
		EVP_EncryptFinal_ex :: proc(ctx: EVP_CIPHER_CTX, out: [^]u8, out_len: ^cint) -> cint ---
		EVP_DecryptInit_ex :: proc(ctx: EVP_CIPHER_CTX, cipher: EVP_CIPHER, engine: rawptr, key: [^]u8, iv: [^]u8) -> cint ---
		EVP_DecryptUpdate :: proc(ctx: EVP_CIPHER_CTX, out: [^]u8, out_len: ^cint, inp: [^]u8, in_len: cint) -> cint ---
		EVP_DecryptFinal_ex :: proc(ctx: EVP_CIPHER_CTX, out: [^]u8, out_len: ^cint) -> cint ---

		// --- libcrypto: OpenSSL 3 only (see README, "Where the backends differ") ---
		EVP_CIPHER_fetch :: proc(libctx: rawptr, algorithm: cstring, properties: cstring) -> EVP_CIPHER ---
		EVP_CIPHER_free :: proc(cipher: EVP_CIPHER) ---
		// AWS-LC: HMAC_CTX_* instead.
		EVP_MAC_fetch :: proc(libctx: rawptr, algorithm: cstring, properties: cstring) -> EVP_MAC ---
		EVP_MAC_free :: proc(mac: EVP_MAC) ---
		EVP_MAC_CTX_new :: proc(mac: EVP_MAC) -> EVP_MAC_CTX ---
		EVP_MAC_CTX_free :: proc(ctx: EVP_MAC_CTX) ---
		EVP_MAC_init :: proc(ctx: EVP_MAC_CTX, key: rawptr, key_len: csize, params: [^]OSSL_PARAM) -> cint ---
		EVP_MAC_update :: proc(ctx: EVP_MAC_CTX, data: rawptr, len: csize) -> cint ---
		EVP_MAC_final :: proc(ctx: EVP_MAC_CTX, out: [^]u8, out_len: ^csize, out_size: csize) -> cint ---

		// --- libssl: same name as in AWS-LC, but other argument types ---
		SSL_CTX_ctrl :: proc(ctx: SSL_CTX, cmd: cint, larg: clong, parg: rawptr) -> clong ---
		SSL_CTX_set_options :: proc(ctx: SSL_CTX, options: u64) -> u64 ---
		SSL_ctrl :: proc(ssl: SSL, cmd: cint, larg: clong, parg: rawptr) -> clong ---
		// AWS-LC: SSL_CTX_set_strict_cipher_list. This one keeps the order of the list.
		SSL_CTX_set_cipher_list :: proc(ctx: SSL_CTX, list: cstring) -> cint ---
		SSL_set_read_ahead :: proc(ssl: SSL, yes: cint) --- // AWS-LC returns an int
		@(link_name = "SSL_set_alpn_protos")
		c_SSL_set_alpn_protos :: proc(ssl: SSL, protos: [^]u8, len: cuint) -> cint --- // 0 on success

		// --- libssl: OpenSSL 3 only ---
		SSL_get1_peer_certificate :: proc(ssl: SSL) -> X509 --- // new reference. AWS-LC: SSL_get_peer_certificate
		EVP_PKEY_get_base_id :: proc(pkey: EVP_PKEY) -> cint --- // AWS-LC: EVP_PKEY_base_id
		SSL_get0_group_name :: proc(ssl: SSL) -> cstring --- // OpenSSL >= 3.2. AWS-LC: SSL_get_group_id + SSL_get_group_name

		// --- key generation (identity_openssl.odin) ---
		// AWS-LC: EVP_PKEY_CTX_new_id, and EVP_PKEY_CTX_pqdsa_set_params for ML-DSA.
		EVP_PKEY_CTX_new_from_name :: proc(libctx: rawptr, name: cstring, propq: cstring) -> EVP_PKEY_CTX ---
		// `len` is an int here and an ossl_ssize_t in AWS-LC.
		X509_NAME_add_entry_by_NID :: proc(name: X509_NAME, nid: cint, type: cint, bytes: [^]u8, len: cint, loc: cint, set: cint) -> cint ---
	}

	chain_len :: proc "contextless" (sk: STACK) -> int {
		return int(OPENSSL_sk_num(sk)) if sk != nil else 0
	}

	chain_get :: proc "contextless" (sk: STACK, i: int) -> X509 {
		return X509(OPENSSL_sk_value(sk, cint(i)))
	}

	// Wrappers for OpenSSL macros that are real functions in AWS-LC.

	bio_pending :: proc "contextless" (bio: BIO) -> int {
		return int(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil))
	}

	SSL_CTX_set_min_proto_version :: proc "contextless" (ctx: SSL_CTX, version: int) -> cint {
		return cint(SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, clong(version), nil))
	}

	SSL_CTX_set_max_proto_version :: proc "contextless" (ctx: SSL_CTX, version: int) -> cint {
		return cint(SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, clong(version), nil))
	}

	SSL_CTX_set1_groups_list :: proc "contextless" (ctx: SSL_CTX, groups: cstring) -> cint {
		return cint(SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, rawptr(groups)))
	}

	// The signature algorithms the ClientHello offers, in OpenSSL's list syntax
	// ("ECDSA+SHA256:RSA-PSS+SHA256"). A macro over SSL_CTX_ctrl. AWS-LC takes
	// code points (SSL_CTX_set_verify_algorithm_prefs).
	SSL_CTX_set1_sigalgs_list :: proc "contextless" (ctx: SSL_CTX, list: cstring) -> cint {
		return cint(SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, rawptr(list)))
	}

	// Tells a client to send the status_request extension (OCSP). A macro over
	// SSL_CTX_ctrl; AWS-LC has SSL_CTX_enable_ocsp_stapling.
	SSL_CTX_set_tlsext_status_type :: proc "contextless" (ctx: SSL_CTX, type: int) -> cint {
		return cint(SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE, clong(type), nil))
	}

	SSL_CTX_set_session_cache_mode :: proc "contextless" (ctx: SSL_CTX, mode: int) {
		SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, clong(mode), nil)
	}

	// Takes ownership of `x` on success.
	SSL_CTX_add_extra_chain_cert :: proc "contextless" (ctx: SSL_CTX, x: X509) -> cint {
		return cint(SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, rawptr(x)))
	}

	// A macro over SSL_ctrl in OpenSSL; a real function in AWS-LC.
	SSL_set_tlsext_host_name :: proc "contextless" (ssl: SSL, name: cstring) -> cint {
		return cint(SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(name)))
	}

	// Returns 0 on success (the C library breaks the usual rule); we turn it around.
	SSL_set_alpn_protos :: proc "contextless" (ssl: SSL, protos: [^]u8, len: int) -> cint {
		return 1 if c_SSL_set_alpn_protos(ssl, protos, cuint(len)) == 0 else 0
	}
}
