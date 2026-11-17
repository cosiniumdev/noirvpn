// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package ossl is the only place in noirvpn that talks to the C crypto/TLS
// library (OpenSSL >= 3.5 or AWS-LC, chosen at build time).
//
// Callers use a small API of our own:
//
//	TLS over memory BIOs   tls.odin       tls_ctx_*, tls_session_*, tls_feed, tls_take, ... (or a custom BIO: tls_session_init_link)
//	data-channel AEAD      aead.odin      aead_init, aead_seal, aead_open
//	HMAC, HKDF             hmac.odin      hmac, Hmac_Ctx, hkdf_expand
//	digests                digest.odin    sha1, sha256, sha512
//	AES-256-CTR            cipher.odin    aes256_ctr_xor
//	random                 random.odin    random_bytes
//
// Backend selection: see README.md. `*_openssl.odin` and `*_awslc.odin` files hold
// the code specific to each library. They wrap their whole body in
// `when NOIR_CRYPTO == "..."`, so only one set compiles. Both sets have the same
// names and signatures.
package ossl

// Crypto backend, set at build time with `-define:NOIR_CRYPTO=openssl` (default)
// or `-define:NOIR_CRYPTO=awslc`. The link step must match. Static builds with
// build/musl.sh need both `NOIR_CRYPTO=awslc` in the environment (library path)
// and `-define:NOIR_CRYPTO=awslc` as an extra flag (bindings).
NOIR_CRYPTO :: #config(NOIR_CRYPTO, "openssl")

#assert(NOIR_CRYPTO == "openssl" || NOIR_CRYPTO == "awslc", "NOIR_CRYPTO must be \"openssl\" or \"awslc\"")

// Errors returned by our own procedures. For TLS handshake and I/O problems
// see `tls_last_error`, which has the text from the C library.
Error :: enum {
	None,
	Alloc, // the C library returned null
	Bad_Argument, // wrong key length, empty input, and similar
	Bad_Cert, // certificate PEM could not be parsed
	Bad_Key, // private key PEM could not be parsed, or does not match the certificate
	Key_Encrypted, // the private key is encrypted and no passphrase was given
	Bad_Passphrase, // the passphrase does not open the encrypted private key
	Bad_Crl, // CRL PEM has no CRL, or one that could not be parsed
	Bad_Config, // a TLS setting was refused by the library (groups, version, CA list)
	Lib, // any other failure inside the C library
}

// Digest sizes. SHA512_LEN is the largest, so use it for scratch buffers.
SHA1_LEN :: 20
SHA224_LEN :: 28
SHA256_LEN :: 32
SHA384_LEN :: 48
SHA512_LEN :: 64
