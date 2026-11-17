// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// The TLS calls that differ in AWS-LC (see README, "Where the backends differ").

when NOIR_CRYPTO == "awslc" {

	// Signature algorithms we sign with and accept (same list both ways). AWS-LC
	// 5.0.0 leaves Ed25519 out of its TLS defaults (OpenSSL has it), so an Ed25519
	// handshake fails with NO_COMMON_SIGNATURE_ALGORITHMS. We list everything to
	// keep the policy in one place.
	@(private = "file")
	SIGALGS := [?]u16 {
		SSL_SIGN_MLDSA65,
		SSL_SIGN_MLDSA87,
		SSL_SIGN_MLDSA44,
		SSL_SIGN_ED25519,
		SSL_SIGN_ECDSA_SECP256R1_SHA256,
		SSL_SIGN_ECDSA_SECP384R1_SHA384,
		SSL_SIGN_ECDSA_SECP521R1_SHA512,
		SSL_SIGN_RSA_PSS_RSAE_SHA256,
		SSL_SIGN_RSA_PSS_RSAE_SHA384,
		SSL_SIGN_RSA_PSS_RSAE_SHA512,
		SSL_SIGN_RSA_PKCS1_SHA256,
		SSL_SIGN_RSA_PKCS1_SHA384,
		SSL_SIGN_RSA_PKCS1_SHA512,
	}

	// Backend settings on a new context. Called by `tls_ctx_create`.
	backend_ctx_setup :: proc(sc: SSL_CTX) -> bool {
		ok :=
			SSL_CTX_set_signing_algorithm_prefs(sc, &SIGALGS[0], len(SIGALGS)) == 1 &&
			SSL_CTX_set_verify_algorithm_prefs(sc, &SIGALGS[0], len(SIGALGS)) == 1
		if !ok {
			ERR_clear_error()
		}
		return ok
	}

	// Chrome's signature algorithms, in its order, for the ClientHello of the
	// `.Chrome` profile (it also decides what we accept from the server).
	@(private = "file")
	CHROME_SIGALGS := [?]u16 {
		SSL_SIGN_ECDSA_SECP256R1_SHA256,
		SSL_SIGN_RSA_PSS_RSAE_SHA256,
		SSL_SIGN_RSA_PKCS1_SHA256,
		SSL_SIGN_ECDSA_SECP384R1_SHA384,
		SSL_SIGN_RSA_PSS_RSAE_SHA384,
		SSL_SIGN_RSA_PKCS1_SHA384,
		SSL_SIGN_RSA_PSS_RSAE_SHA512,
		SSL_SIGN_RSA_PKCS1_SHA512,
	}

	// The IANA number of brotli in the certificate compression extension.
	@(private = "file")
	CERT_COMPRESSION_BROTLI :: 2

	// Brotli decompressor. It always fails. We register it only so the ClientHello
	// lists compress_certificate, as Chrome's does. Our server never sends a
	// compressed certificate. A peer that does (a CDN) fails the handshake.
	@(private = "file")
	no_decompress :: proc "c" (ssl: SSL, out: ^rawptr, uncompressed_len: csize, inp: [^]u8, in_len: csize) -> cint {
		return 0
	}

	// The `.Chrome` profile on a client context. AWS-LC (BoringSSL's sibling) can
	// send Chrome's ClientHello: cipher list, signature algorithms, GREASE, random
	// extension order, status_request, signed_certificate_timestamp,
	// compress_certificate. The ticket extension stays on: `tls_ctx_create` does
	// not set SSL_OP_NO_TICKET for this profile.
	backend_hello_ctx :: proc(sc: SSL_CTX) -> bool {
		ok :=
			SSL_CTX_set_strict_cipher_list(sc, CHROME_CIPHERS) == 1 &&
			SSL_CTX_set_verify_algorithm_prefs(sc, &CHROME_SIGALGS[0], len(CHROME_SIGALGS)) == 1 &&
			SSL_CTX_add_cert_compression_alg(sc, CERT_COMPRESSION_BROTLI, nil, no_decompress) == 1
		if !ok {
			ERR_clear_error()
			return false
		}
		SSL_CTX_set_grease_enabled(sc, 1)
		SSL_CTX_set_permute_extensions(sc, 1)
		SSL_CTX_enable_ocsp_stapling(sc)
		SSL_CTX_enable_signed_cert_timestamps(sc)
		return true
	}

	// Per session settings of the `.Chrome` profile: ECH GREASE (a fake
	// encrypted_client_hello extension, as Chrome sends when it has no ECH config).
	backend_hello_session :: proc(ssl: SSL) {
		SSL_set_enable_ech_grease(ssl, 1)
	}

	// After the ALPN list: if it offers h2, set ALPS for h2 with no settings on the
	// new codepoint (extension 17613, Chrome 133 and later). ALPS needs its protocol
	// in the ALPN list, so `http/1.1` alone gets none.
	backend_hello_alpn :: proc(ssl: SSL, protos: []string) -> bool {
		for p in protos {
			if p == "h2" {
				SSL_set_alps_use_new_codepoint(ssl, 1)
				h2 := "h2"
				return SSL_add_application_settings(ssl, raw_data(transmute([]u8)h2), 2, nil, 0) == 1
			}
		}
		return true
	}

	backend_hello_note :: proc() -> string {
		return "outer TLS ClientHello: profile chrome (GREASE, random extension order, status_request, sct, compress_certificate, ALPS, ECH GREASE)"
	}

	// Rewrites a NUL-terminated groups list (`Tls_Config.groups`) in place so
	// AWS-LC accepts what OpenSSL accepts:
	//   - A leading `*` ("send this key share at once") is dropped. AWS-LC has no
	//     such mark; it sends hybrid and X25519 shares anyway if both are listed.
	//   - NIST curves become P-256, P-384, P-521 (AWS-LC does not know secp256r1
	//     and the like, which OpenSSL and upstream OpenVPN use).
	// Every change shortens the text, so it fits the buffer. Groups AWS-LC lacks
	// (X448, FFDHE) stay, and the library refuses the list.
	backend_groups_list :: proc(buf: []u8) {
		out := 0
		i := 0
		for i < len(buf) && buf[i] != 0 {
			// One name, up to the next ':' or the end.
			j := i
			for j < len(buf) && buf[j] != 0 && buf[j] != ':' {
				j += 1
			}
			name := string(buf[i:j])
			if len(name) > 0 && name[0] == '*' {
				name = name[1:]
			}
			switch name {
			case "secp256r1", "prime256v1":
				name = "P-256"
			case "secp384r1":
				name = "P-384"
			case "secp521r1":
				name = "P-521"
			}
			for c in transmute([]u8)name {
				buf[out] = c
				out += 1
			}
			if j < len(buf) && buf[j] == ':' {
				buf[out] = ':'
				out += 1
				j += 1
			}
			i = j
		}
		if out < len(buf) {
			buf[out] = 0
		}
	}

	// The NID of a public key's algorithm (6 RSA, 408 EC, ...).
	pkey_nid :: proc(pkey: EVP_PKEY) -> cint {
		return EVP_PKEY_base_id(pkey)
	}

	NID_ED25519 :: 949

	// The peer certificate with a new reference (free it with X509_free),
	// or nil if the peer sent none.
	peer_cert :: proc(s: ^Tls_Session) -> X509 {
		return SSL_get_peer_certificate(s.ssl)
	}

	// Negotiated key exchange group: "X25519MLKEM768" (hybrid), "X25519",
	// "secp256r1" (P-256). The library says "P-256" and so on; we change it to
	// OpenSSL's spelling. Compare case-insensitively (OpenSSL writes x25519).
	// Empty until the handshake is done. The string is a library constant.
	tls_negotiated_group_name :: proc(s: ^Tls_Session) -> string {
		if s.state != .Established {
			return ""
		}
		id := SSL_get_group_id(s.ssl)
		if id == 0 {
			return ""
		}
		name := string(SSL_get_group_name(id))
		// Use OpenSSL's spelling for the NIST curves, so logs agree.
		switch name {
		case "P-256":
			return "secp256r1"
		case "P-384":
			return "secp384r1"
		case "P-521":
			return "secp521r1"
		}
		return name
	}

	// Version text of the linked library, e.g. "AWS-LC 5.0.0".
	backend_version :: proc() -> string {
		return string(OpenSSL_version(OPENSSL_VERSION))
	}

	// Library version in OpenSSL's layout, 0xMNN00PP0: AWS-LC 5.0.0 is 0x50000000.
	// (The C library's own number is a fixed 0x1010107f, so it says nothing.)
	// Meaningful only with the backend: check `NOIR_CRYPTO` first. 0 if the
	// version text cannot be read.
	backend_version_num :: proc() -> u64 {
		text := string(OpenSSL_version(OPENSSL_VERSION))
		// Find the first digit after "AWS-LC ".
		marker := "AWS-LC "
		start := -1
		for i in 0 ..= len(text) - len(marker) {
			if text[i:i + len(marker)] == marker {
				start = i + len(marker)
				break
			}
		}
		if start < 0 {
			return 0
		}
		parts: [3]u64
		idx := 0
		seen_digit := false
		for i := start; i < len(text) && idx < 3; i += 1 {
			c := text[i]
			switch {
			case c >= '0' && c <= '9':
				parts[idx] = parts[idx] * 10 + u64(c - '0')
				seen_digit = true
			case c == '.' && seen_digit:
				idx += 1
				seen_digit = false
			case:
				i = len(text) // stop at the first other character
			}
		}
		return parts[0] << 28 | parts[1] << 20 | parts[2] << 4
	}
}
