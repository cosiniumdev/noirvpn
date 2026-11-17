// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// The TLS calls that exist only in OpenSSL 3 (see README, "Where the backends differ").

when NOIR_CRYPTO == "openssl" {

	// Backend settings on a new context, called by `tls_ctx_create`. The defaults
	// already cover Ed25519, ECDSA, RSA and ML-DSA. One option is set. Why: OpenSSL
	// keeps the plaintext of the last record in its read buffer until the next
	// record overwrites it, so a login message (user name, password) would stay in
	// daemon memory for the whole session. With the option the buffer is wiped on read.
	backend_ctx_setup :: proc(sc: SSL_CTX) -> bool {
		SSL_CTX_set_options(sc, SSL_OP_CLEANSE_PLAINTEXT)
		return true
	}

	// What OpenSSL sends as signature algorithms under `.Chrome`: Chrome's eight, in
	// its order (0403 0804 0401 0503 0805 0501 0806 0601), in OpenSSL's syntax.
	@(private = "file")
	CHROME_SIGALGS :: "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512"

	// The `.Chrome` profile on a client context. OpenSSL 3.5 lets us set the TLS 1.2
	// cipher list and signature algorithms, take out encrypt_then_mac, and ask for
	// status_request. It has no GREASE, extension shuffle, compress_certificate,
	// ALPS or ECH GREASE, and sends extensions in a fixed order, so the fingerprint
	// stays its own. (4.0 adds GREASE.)
	backend_hello_ctx :: proc(sc: SSL_CTX) -> bool {
		ok :=
			SSL_CTX_set_cipher_list(sc, CHROME_CIPHERS) == 1 &&
			SSL_CTX_set1_sigalgs_list(sc, CHROME_SIGALGS) == 1 &&
			SSL_CTX_set_tlsext_status_type(sc, TLSEXT_STATUSTYPE_ocsp) == 1
		if !ok {
			ERR_clear_error()
			return false
		}
		SSL_CTX_set_options(sc, SSL_OP_NO_ENCRYPT_THEN_MAC)
		return true
	}

	// Per session settings of the `.Chrome` profile: none on OpenSSL.
	backend_hello_session :: proc(ssl: SSL) {
	}

	// The ALPN list is set: nothing more to do on OpenSSL.
	backend_hello_alpn :: proc(ssl: SSL, protos: []string) -> bool {
		return true
	}

	backend_hello_note :: proc() -> string {
		return "outer TLS ClientHello: profile chrome on OpenSSL: cipher list, groups, signature algorithms, ALPN and session ticket only (no GREASE, fixed extension order)"
	}

	// Rewrites a NUL-terminated groups list for the library, in place.
	// OpenSSL takes the syntax of `Tls_Config.groups` as it is.
	backend_groups_list :: proc(buf: []u8) {
	}

	// The NID of a public key's algorithm (6 RSA, 408 EC, ...). OpenSSL 3 has
	// `EVP_PKEY_get_base_id` as a function and `EVP_PKEY_base_id` as a macro.
	pkey_nid :: proc(pkey: EVP_PKEY) -> cint {
		return EVP_PKEY_get_base_id(pkey)
	}

	NID_ED25519 :: 1087

	// The peer certificate with a new reference (free it with X509_free),
	// or nil if the peer sent none.
	peer_cert :: proc(s: ^Tls_Session) -> X509 {
		return SSL_get1_peer_certificate(s.ssl)
	}

	// Negotiated key exchange group: "X25519MLKEM768" (hybrid), "x25519",
	// "secp256r1" (P-256). The spelling is the library's: compare
	// case-insensitively. Empty until the handshake is done. The library owns the
	// string; it lives as long as the context.
	tls_negotiated_group_name :: proc(s: ^Tls_Session) -> string {
		// OpenSSL 3.5 crashes in this call when there is no session yet.
		if s.state != .Established {
			return ""
		}
		name := SSL_get0_group_name(s.ssl)
		return string(name) if name != nil else ""
	}

	// Version text of the linked library, e.g. "OpenSSL 3.5.7 9 Jun 2026".
	backend_version :: proc() -> string {
		return string(OpenSSL_version(OPENSSL_VERSION))
	}

	// Version of the linked library as a number: 0xMNN00PP0 (3.5.7 is 0x30500070).
	backend_version_num :: proc() -> u64 {
		return u64(OpenSSL_version_num())
	}
}
