// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+private
package ossl

// Raw C bindings that are the same in OpenSSL and AWS-LC. Package-private: other
// packages use the API in the other files, never these names. Declarations that
// differ are in `openssl_ffi.odin` and `awslc_ffi.odin` (one is compiled, see
// NOIR_CRYPTO). A name lives in exactly one of the three files. A name is
// "common" only if its C argument and result types have the same size in both
// libraries. Example: `RAND_bytes` takes an `int` length in OpenSSL and a
// `size_t` in AWS-LC, so it is not here.

// Windows needs the file names of the import libraries (build/windows-openssl.sh).
when ODIN_OS == .Windows {
	foreign import lib {"system:ssl.lib", "system:crypto.lib"}
} else {
	foreign import lib {"system:ssl", "system:crypto"}
}

// Values of C macros that we need. They are equal in both libraries.
SSL_SESS_CACHE_OFF :: 0
SSL_VERIFY_NONE :: 0
SSL_VERIFY_PEER :: 1
SSL_VERIFY_FAIL_IF_NO_PEER_CERT :: 2
SSL_ERROR_NONE :: 0
SSL_ERROR_SSL :: 1
SSL_ERROR_WANT_READ :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_ZERO_RETURN :: 6
TLS1_2_VERSION :: 0x0303
TLS1_3_VERSION :: 0x0304
OPENSSL_VERSION :: 0
X509_V_OK :: 0
X509_V_ERR_UNABLE_TO_GET_CRL :: 3
X509_V_ERR_CRL_HAS_EXPIRED :: 12
X509_V_ERR_CERT_REVOKED :: 23
X509_V_ERR_CERT_UNTRUSTED :: 27
X509_V_ERR_CERT_REJECTED :: 28
X509_V_FLAG_CRL_CHECK :: 0x4
X509_V_FLAG_CRL_CHECK_ALL :: 0x8
NID_COMMON_NAME :: 13
NID_KEY_USAGE :: 83
NID_EXT_KEY_USAGE :: 126
// X509_NAME_print_ex flags: XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN | ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_UTF8_CONVERT.
SUBJECT_TEXT_FLAGS :: culong(0x20011)
BIO_CTRL_PENDING :: 10
BIO_CTRL_FLUSH :: 11
BIO_CTRL_WPENDING :: 13
BIO_FLAGS_READ :: 0x01
BIO_FLAGS_WRITE :: 0x02
BIO_FLAGS_IO_SPECIAL :: 0x04
BIO_FLAGS_SHOULD_RETRY :: 0x08
BIO_TYPE_SOURCE_SINK :: 0x0400
SSL_KEY_UPDATE_NOT_REQUESTED :: 0
X509_VERSION_3 :: 2
MBSTRING_UTF8 :: 0x1000
NID_BASIC_CONSTRAINTS :: 87
NID_EXT_REQ :: 172 // pkcs-9-at-extensionRequest
NID_P256 :: 415 // NID_X9_62_prime256v1
EVP_PKEY_EC :: 408 // NID_X9_62_id_ecPublicKey
V_ASN1_SEQUENCE :: 16
// X509_NAME_print_ex flags: XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DN_REV | XN_FLAG_FN_SN |
// ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_UTF8_CONVERT.
// Gives RFC 2253 order (most specific name first), ", " between names.
NAME_RFC2253_FLAGS :: culong(0x120013)

pem_password_cb :: #type proc "c" (buf: [^]u8, size: cint, rwflag: cint, userdata: rawptr) -> cint
cert_verify_cb :: #type proc "c" (store_ctx: X509_STORE_CTX, arg: rawptr) -> cint
verify_cb :: #type proc "c" (preverify_ok: cint, store_ctx: X509_STORE_CTX) -> cint

// The callbacks of a custom BIO (BIO_meth_set_*): same definitions in both libraries.
bio_write_fn :: #type proc "c" (bio: BIO, data: [^]u8, n: cint) -> cint
bio_read_fn :: #type proc "c" (bio: BIO, buf: [^]u8, n: cint) -> cint
bio_ctrl_fn :: #type proc "c" (bio: BIO, cmd: cint, larg: clong, parg: rawptr) -> clong
bio_life_fn :: #type proc "c" (bio: BIO) -> cint

@(default_calling_convention = "c")
foreign lib {
	// --- libcrypto ---
	OpenSSL_version :: proc(which: cint) -> cstring ---
	OpenSSL_version_num :: proc() -> culong ---

	ERR_clear_error :: proc() ---
	CRYPTO_memcmp :: proc(a: rawptr, b: rawptr, n: csize) -> cint --- // 0 when equal, in constant time

	BIO_s_mem :: proc() -> BIO_METHOD ---
	BIO_new :: proc(method: BIO_METHOD) -> BIO ---
	BIO_free :: proc(bio: BIO) -> cint ---
	BIO_read :: proc(bio: BIO, data: rawptr, dlen: cint) -> cint ---
	BIO_write :: proc(bio: BIO, data: rawptr, dlen: cint) -> cint ---

	// A custom BIO. OpenSSL has BIO_set_retry_read and the like as macros over
	// BIO_set_flags, so the helpers `bio_retry_read`, `bio_retry_write` and
	// `bio_clear_retry` below use the flags (same result in both libraries).
	BIO_meth_new :: proc(type: cint, name: cstring) -> BIO_METHOD ---
	BIO_meth_free :: proc(method: BIO_METHOD) ---
	BIO_meth_set_write :: proc(method: BIO_METHOD, f: bio_write_fn) -> cint ---
	BIO_meth_set_read :: proc(method: BIO_METHOD, f: bio_read_fn) -> cint ---
	BIO_meth_set_ctrl :: proc(method: BIO_METHOD, f: bio_ctrl_fn) -> cint ---
	BIO_meth_set_create :: proc(method: BIO_METHOD, f: bio_life_fn) -> cint ---
	BIO_meth_set_destroy :: proc(method: BIO_METHOD, f: bio_life_fn) -> cint ---
	BIO_set_data :: proc(bio: BIO, ptr: rawptr) ---
	BIO_get_data :: proc(bio: BIO) -> rawptr ---
	BIO_set_init :: proc(bio: BIO, init: cint) ---
	BIO_set_flags :: proc(bio: BIO, flags: cint) ---
	BIO_clear_flags :: proc(bio: BIO, flags: cint) ---

	PEM_read_bio_X509 :: proc(bio: BIO, x: ^X509, cb: pem_password_cb, u: rawptr) -> X509 ---
	PEM_read_bio_PrivateKey :: proc(bio: BIO, x: ^EVP_PKEY, cb: pem_password_cb, u: rawptr) -> EVP_PKEY ---
	X509_free :: proc(x: X509) ---
	X509_get0_pubkey :: proc(x: X509) -> EVP_PKEY --- // borrowed: valid while `x` is
	X509_digest :: proc(x: X509, md: EVP_MD, out: [^]u8, out_len: ^cuint) -> cint ---
	X509_get_subject_name :: proc(x: X509) -> X509_NAME --- // borrowed: valid while `x` is
	X509_get_ext_d2i :: proc(x: X509, nid: cint, crit: ^cint, idx: ^cint) -> rawptr --- // a new object, or nil; free it with its own function
	ASN1_BIT_STRING_get_bit :: proc(s: ASN1_STRING, n: cint) -> cint ---
	ASN1_BIT_STRING_free :: proc(s: ASN1_STRING) ---
	EXTENDED_KEY_USAGE_free :: proc(eku: STACK) ---
	OBJ_txt2obj :: proc(s: cstring, no_name: cint) -> ASN1_OBJECT --- // a new object; no_name 0 also looks names up
	OBJ_obj2txt :: proc(buf: [^]u8, buf_len: cint, obj: ASN1_OBJECT, no_name: cint) -> cint --- // no_name 1: the dotted OID
	ASN1_OBJECT_free :: proc(obj: ASN1_OBJECT) ---
	X509_NAME_print_ex :: proc(bio: BIO, name: X509_NAME, indent: cint, flags: culong) -> cint ---
	ASN1_STRING_to_UTF8 :: proc(out: ^[^]u8, s: ASN1_STRING) -> cint --- // allocates *out: free it with CRYPTO_free
	CRYPTO_free :: proc(p: rawptr, file: cstring, line: cint) --- // AWS-LC ignores file and line
	X509_NAME_get_index_by_NID :: proc(name: X509_NAME, nid: cint, lastpos: cint) -> cint ---
	X509_NAME_get_entry :: proc(name: X509_NAME, loc: cint) -> X509_NAME_ENTRY --- // borrowed
	X509_NAME_ENTRY_get_data :: proc(ne: X509_NAME_ENTRY) -> ASN1_STRING --- // borrowed
	ASN1_STRING_get0_data :: proc(s: ASN1_STRING) -> [^]u8 --- // borrowed
	ASN1_STRING_length :: proc(s: ASN1_STRING) -> cint ---
	ASN1_STRING_type :: proc(s: ASN1_STRING) -> cint ---
	X509_STORE_new :: proc() -> X509_STORE ---
	X509_STORE_free :: proc(store: X509_STORE) ---
	X509_STORE_add_cert :: proc(store: X509_STORE, x: X509) -> cint ---
	X509_STORE_add_crl :: proc(store: X509_STORE, crl: X509_CRL) -> cint --- // the store takes its own reference
	X509_STORE_set_flags :: proc(store: X509_STORE, flags: culong) -> cint ---
	PEM_read_bio_X509_CRL :: proc(bio: BIO, x: ^X509_CRL, cb: pem_password_cb, u: rawptr) -> X509_CRL ---
	X509_CRL_free :: proc(crl: X509_CRL) ---
	X509_CRL_get0_nextUpdate :: proc(crl: X509_CRL) -> ASN1_STRING --- // borrowed; nil if the CRL has none
	X509_CRL_get_issuer :: proc(crl: X509_CRL) -> X509_NAME --- // borrowed
	X509_NAME_oneline :: proc(name: X509_NAME, buf: [^]u8, size: cint) -> cstring --- // with a buffer: no allocation
	X509_get0_serialNumber :: proc(x: X509) -> ASN1_STRING --- // borrowed; an ASN1_INTEGER
	X509_verify_cert :: proc(ctx: X509_STORE_CTX) -> cint ---
	X509_verify_cert_error_string :: proc(err: clong) -> cstring ---
	X509_STORE_CTX_get_error :: proc(ctx: X509_STORE_CTX) -> cint ---
	X509_STORE_CTX_get_error_depth :: proc(ctx: X509_STORE_CTX) -> cint ---
	X509_STORE_CTX_get_current_cert :: proc(ctx: X509_STORE_CTX) -> X509 --- // borrowed
	X509_STORE_CTX_get0_chain :: proc(ctx: X509_STORE_CTX) -> STACK --- // borrowed; the verified chain
	X509_STORE_CTX_get0_cert :: proc(ctx: X509_STORE_CTX) -> X509 --- // borrowed
	X509_STORE_CTX_set_error :: proc(ctx: X509_STORE_CTX, err: cint) ---
	EVP_PKEY_free :: proc(pkey: EVP_PKEY) ---
	i2d_PUBKEY :: proc(pkey: EVP_PKEY, pp: ^[^]u8) -> cint ---

	// Key generation and a self-signed certificate (identity.odin). The
	// context comes from `backend_keygen_ctx`.
	EVP_PKEY_CTX_free :: proc(ctx: EVP_PKEY_CTX) ---
	EVP_PKEY_keygen_init :: proc(ctx: EVP_PKEY_CTX) -> cint ---
	EVP_PKEY_keygen :: proc(ctx: EVP_PKEY_CTX, out: ^EVP_PKEY) -> cint ---
	X509_new :: proc() -> X509 ---
	X509_set_version :: proc(x: X509, version: clong) -> cint ---
	X509_get_serialNumber :: proc(x: X509) -> ASN1_STRING --- // borrowed and mutable; an ASN1_INTEGER
	ASN1_INTEGER_set_uint64 :: proc(a: ASN1_STRING, v: u64) -> cint ---
	X509_getm_notBefore :: proc(x: X509) -> ASN1_STRING --- // borrowed and mutable; an ASN1_TIME
	X509_getm_notAfter :: proc(x: X509) -> ASN1_STRING ---
	X509_gmtime_adj :: proc(s: ASN1_STRING, offset_sec: clong) -> ASN1_STRING --- // sets s to now plus the offset
	X509_set_issuer_name :: proc(x: X509, name: X509_NAME) -> cint --- // copies the name
	X509_set_pubkey :: proc(x: X509, pkey: EVP_PKEY) -> cint ---
	X509_sign :: proc(x: X509, pkey: EVP_PKEY, md: EVP_MD) -> cint --- // md nil: the default of the key; > 0 on success
	X509_add_ext :: proc(x: X509, ext: X509_EXTENSION, loc: cint) -> cint --- // copies the extension
	X509_EXTENSION_create_by_NID :: proc(ex: ^X509_EXTENSION, nid: cint, crit: cint, data: ASN1_STRING) -> X509_EXTENSION ---
	X509_EXTENSION_free :: proc(ext: X509_EXTENSION) ---
	ASN1_OCTET_STRING_new :: proc() -> ASN1_STRING ---
	ASN1_OCTET_STRING_set :: proc(s: ASN1_STRING, data: [^]u8, len: cint) -> cint ---
	ASN1_OCTET_STRING_free :: proc(s: ASN1_STRING) ---
	PEM_write_bio_X509 :: proc(bio: BIO, x: X509) -> cint ---
	PEM_write_bio_PrivateKey :: proc(bio: BIO, pkey: EVP_PKEY, enc: EVP_CIPHER, kstr: [^]u8, klen: cint, cb: pem_password_cb, u: rawptr) -> cint --- // enc nil: no encryption
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid :: proc(ctx: EVP_PKEY_CTX, nid: cint) -> cint --- // after EVP_PKEY_keygen_init

	// A certificate request (csr.odin).
	X509_REQ_new :: proc() -> X509_REQ ---
	X509_REQ_free :: proc(req: X509_REQ) ---
	X509_REQ_set_version :: proc(req: X509_REQ, version: clong) -> cint ---
	X509_REQ_get_subject_name :: proc(req: X509_REQ) -> X509_NAME --- // borrowed and mutable
	X509_REQ_set_pubkey :: proc(req: X509_REQ, pkey: EVP_PKEY) -> cint ---
	// `type` V_ASN1_SEQUENCE: `bytes` is the whole DER element (tag and length too).
	X509_REQ_add1_attr_by_NID :: proc(req: X509_REQ, nid: cint, type: cint, bytes: [^]u8, len: cint) -> cint ---
	X509_REQ_sign :: proc(req: X509_REQ, pkey: EVP_PKEY, md: EVP_MD) -> cint --- // md nil: the default of the key; > 0 on success
	X509_REQ_verify :: proc(req: X509_REQ, pkey: EVP_PKEY) -> cint --- // 1: the signature is good
	X509_REQ_get0_pubkey :: proc(req: X509_REQ) -> EVP_PKEY --- // borrowed
	PEM_write_bio_X509_REQ :: proc(bio: BIO, req: X509_REQ) -> cint ---
	PEM_read_bio_X509_REQ :: proc(bio: BIO, x: ^X509_REQ, cb: pem_password_cb, u: rawptr) -> X509_REQ ---
	i2d_X509_REQ :: proc(req: X509_REQ, pp: ^[^]u8) -> cint ---

	// Reading a certificate (csr.odin).
	d2i_X509 :: proc(x: ^X509, inp: ^[^]u8, len: clong) -> X509 --- // moves *inp past the certificate
	X509_get_issuer_name :: proc(x: X509) -> X509_NAME --- // borrowed: valid while `x` is
	X509_get0_notBefore :: proc(x: X509) -> ASN1_STRING --- // borrowed; an ASN1_TIME
	X509_get0_notAfter :: proc(x: X509) -> ASN1_STRING ---
	X509_get_X509_PUBKEY :: proc(x: X509) -> X509_PUBKEY --- // borrowed; any key algorithm
	i2d_X509_PUBKEY :: proc(key: X509_PUBKEY, pp: ^[^]u8) -> cint ---
	X509_verify :: proc(x: X509, pkey: EVP_PKEY) -> cint --- // 1: the signature is good
	X509_NAME_cmp :: proc(a: X509_NAME, b: X509_NAME) -> cint --- // 0 when equal

	EVP_sha1 :: proc() -> EVP_MD ---
	EVP_sha224 :: proc() -> EVP_MD ---
	EVP_sha256 :: proc() -> EVP_MD ---
	EVP_sha384 :: proc() -> EVP_MD ---
	EVP_sha512 :: proc() -> EVP_MD ---
	SHA1 :: proc(data: rawptr, n: csize, out: [^]u8) -> [^]u8 ---
	SHA256 :: proc(data: rawptr, n: csize, out: [^]u8) -> [^]u8 ---
	SHA512 :: proc(data: rawptr, n: csize, out: [^]u8) -> [^]u8 ---

	EVP_CIPHER_CTX_new :: proc() -> EVP_CIPHER_CTX ---
	EVP_CIPHER_CTX_free :: proc(ctx: EVP_CIPHER_CTX) ---
	EVP_aes_256_ctr :: proc() -> EVP_CIPHER ---
	EVP_EncryptInit_ex :: proc(ctx: EVP_CIPHER_CTX, cipher: EVP_CIPHER, engine: rawptr, key: [^]u8, iv: [^]u8) -> cint ---
	EVP_EncryptUpdate :: proc(ctx: EVP_CIPHER_CTX, out: [^]u8, out_len: ^cint, inp: [^]u8, in_len: cint) -> cint ---

	// --- libssl ---
	TLS_method :: proc() -> SSL_METHOD ---
	SSL_CTX_new :: proc(method: SSL_METHOD) -> SSL_CTX ---
	SSL_CTX_free :: proc(ctx: SSL_CTX) ---
	SSL_CTX_set_verify :: proc(ctx: SSL_CTX, mode: cint, cb: verify_cb) ---
	SSL_CTX_set_cert_verify_callback :: proc(ctx: SSL_CTX, cb: cert_verify_cb, arg: rawptr) ---
	SSL_CTX_set_num_tickets :: proc(ctx: SSL_CTX, num: csize) -> cint ---
	SSL_CTX_get_cert_store :: proc(ctx: SSL_CTX) -> X509_STORE ---
	SSL_CTX_set_cert_store :: proc(ctx: SSL_CTX, store: X509_STORE) --- // takes ownership; frees the old store
	SSL_get_verify_result :: proc(ssl: SSL) -> clong ---
	SSL_CTX_use_certificate :: proc(ctx: SSL_CTX, x: X509) -> cint ---
	SSL_CTX_use_PrivateKey :: proc(ctx: SSL_CTX, pkey: EVP_PKEY) -> cint ---
	SSL_CTX_check_private_key :: proc(ctx: SSL_CTX) -> cint ---
	SSL_CTX_set_ciphersuites :: proc(ctx: SSL_CTX, list: cstring) -> cint --- // the TLS 1.3 suites

	SSL_new :: proc(ctx: SSL_CTX) -> SSL ---
	SSL_free :: proc(ssl: SSL) ---
	SSL_set_bio :: proc(ssl: SSL, rbio: BIO, wbio: BIO) --- // takes ownership of both
	SSL_set_connect_state :: proc(ssl: SSL) ---
	SSL_set_accept_state :: proc(ssl: SSL) ---
	SSL_do_handshake :: proc(ssl: SSL) -> cint ---
	SSL_read :: proc(ssl: SSL, buf: rawptr, num: cint) -> cint ---
	SSL_write :: proc(ssl: SSL, buf: rawptr, num: cint) -> cint ---
	SSL_get_error :: proc(ssl: SSL, ret: cint) -> cint ---
	SSL_get_version :: proc(ssl: SSL) -> cstring ---
	SSL_get_current_cipher :: proc(ssl: SSL) -> SSL_CIPHER --- // borrowed; nil before the handshake
	SSL_CIPHER_get_name :: proc(c: SSL_CIPHER) -> cstring ---
	SSL_get0_alpn_selected :: proc(ssl: SSL, data: ^[^]u8, len: ^cuint) --- // the protocol the server chose, or len 0
	SSL_get_servername :: proc(ssl: SSL, type: cint) -> cstring --- // the SNI the client sent (server side), or nil
	SSL_pending :: proc(ssl: SSL) -> cint ---
	SSL_has_pending :: proc(ssl: SSL) -> cint --- // decrypted bytes, or bytes received and not decrypted yet
	SSL_key_update :: proc(ssl: SSL, request_type: cint) -> cint --- // TLS 1.3 only; the message goes out with the next SSL_write
	SSL_shutdown :: proc(ssl: SSL) -> cint ---
	SSL_export_keying_material :: proc(ssl: SSL, out: [^]u8, olen: csize, label: [^]u8, llen: csize, context_: rawptr, context_len: csize, use_context: cint) -> cint ---
}

// Flag helpers for a custom BIO (see the note at BIO_meth_new).
bio_retry_read :: proc "contextless" (bio: BIO) {
	BIO_set_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY)
}

bio_retry_write :: proc "contextless" (bio: BIO) {
	BIO_set_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY)
}

bio_clear_retry :: proc "contextless" (bio: BIO) {
	BIO_clear_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY)
}
