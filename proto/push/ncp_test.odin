// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

@(test)
cipher_helpers :: proc(t: ^testing.T) {
	testing.expect_value(t, cipher_name(.Aes_256_Gcm), "AES-256-GCM")
	testing.expect_value(t, cipher_name(.Aes_128_Gcm), "AES-128-GCM")
	testing.expect_value(t, cipher_name(.Chacha20_Poly1305), "CHACHA20-POLY1305")
	testing.expect_value(t, cipher_name(.None), "")
	testing.expect_value(t, cipher_key_bits(.Aes_128_Gcm), 128)
	testing.expect_value(t, cipher_key_bits(.Aes_256_Gcm), 256)
	testing.expect_value(t, cipher_key_bits(.Chacha20_Poly1305), 256)
	testing.expect_value(t, cipher_key_bits(.None), 0)
	testing.expect_value(t, cipher_from_name("aes-256-gcm"), Cipher.Aes_256_Gcm)
	testing.expect_value(t, cipher_from_name("ChaCha20-Poly1305"), Cipher.Chacha20_Poly1305)
	testing.expect_value(t, cipher_from_name("AES-256-CBC"), Cipher.None)
	testing.expect_value(t, cipher_from_name(""), Cipher.None)
	testing.expect_value(t, cipher_from_name("AES-256-GC"), Cipher.None)
	testing.expect_value(t, cipher_from_name("AES-256-GCMX"), Cipher.None)
	for c in Cipher.Aes_128_Gcm ..= Cipher.Chacha20_Poly1305 {
		testing.expect_value(t, cipher_from_name(cipher_name(c)), c)
	}
	for f in Protocol_Flag {
		back, ok := protocol_flag_from_name(protocol_flag_name(f))
		testing.expect(t, ok && back == f)
	}
	_, ok := protocol_flag_from_name("something-new")
	testing.expect(t, !ok)
}

@(test)
ncp_select_server_order_wins :: proc(t: ^testing.T) {
	server := []Cipher{.Aes_256_Gcm, .Aes_128_Gcm, .Chacha20_Poly1305}
	c, push, f := ncp_select({"AES-128-GCM", "AES-256-GCM"}, 0, "", server)
	testing.expect_value(t, c, Cipher.Aes_256_Gcm)
	testing.expect(t, push)
	testing.expect_value(t, f, Negotiation_Failure.None)

	// The client's order does not matter, the server's does.
	c, _, _ = ncp_select({"CHACHA20-POLY1305", "AES-128-GCM"}, 0, "", server)
	testing.expect_value(t, c, Cipher.Aes_128_Gcm)
	c, _, _ = ncp_select({"CHACHA20-POLY1305"}, 0, "", server)
	testing.expect_value(t, c, Cipher.Chacha20_Poly1305)
	// A server that prefers ChaCha.
	c, _, _ = ncp_select({"AES-256-GCM", "CHACHA20-POLY1305"}, 0, "", {.Chacha20_Poly1305, .Aes_256_Gcm})
	testing.expect_value(t, c, Cipher.Chacha20_Poly1305)
	// Names the server does not run are ignored; case does not matter.
	c, _, f = ncp_select({"BF-CBC", "aes-128-gcm", "AES-256-CBC"}, 0, "", server)
	testing.expect_value(t, c, Cipher.Aes_128_Gcm)
	testing.expect_value(t, f, Negotiation_Failure.None)
	// IV_CIPHERS wins over IV_NCP and the options-string cipher.
	c, push, f = ncp_select({"CHACHA20-POLY1305"}, 2, "AES-256-GCM", server)
	testing.expect_value(t, c, Cipher.Chacha20_Poly1305)
	testing.expect(t, push)
}

@(test)
ncp_select_fallbacks :: proc(t: ^testing.T) {
	server := []Cipher{.Chacha20_Poly1305, .Aes_256_Gcm, .Aes_128_Gcm}
	// IV_NCP >= 2 and no list: AES-256-GCM and AES-128-GCM only.
	c, push, f := ncp_select(nil, 2, "", server)
	testing.expect_value(t, c, Cipher.Aes_256_Gcm)
	testing.expect(t, push)
	testing.expect_value(t, f, Negotiation_Failure.None)
	c, _, f = ncp_select(nil, 2, "", {.Chacha20_Poly1305})
	testing.expect_value(t, c, Cipher.None)
	testing.expect_value(t, f, Negotiation_Failure.No_Shared_Cipher)

	// Poor man's NCP: the options-string cipher, no `cipher` pushed.
	c, push, f = ncp_select(nil, 0, "AES-128-GCM", server)
	testing.expect_value(t, c, Cipher.Aes_128_Gcm)
	testing.expect(t, !push)
	testing.expect_value(t, f, Negotiation_Failure.None)
	c, push, f = ncp_select(nil, 1, "aes-256-gcm", server)
	testing.expect_value(t, c, Cipher.Aes_256_Gcm)
	testing.expect(t, !push)
	// A cipher the server does not allow, an unknown one, none at all.
	_, _, f = ncp_select(nil, 0, "AES-128-GCM", {.Aes_256_Gcm})
	testing.expect_value(t, f, Negotiation_Failure.No_Shared_Cipher)
	_, _, f = ncp_select(nil, 0, "BF-CBC", server)
	testing.expect_value(t, f, Negotiation_Failure.No_Shared_Cipher)
	_, _, f = ncp_select(nil, 0, "", server)
	testing.expect_value(t, f, Negotiation_Failure.No_Shared_Cipher)
	_, _, f = ncp_select({"AES-256-CBC"}, 0, "AES-256-GCM", server)
	testing.expect_value(t, f, Negotiation_Failure.No_Shared_Cipher)
	_, _, f = ncp_select({"AES-128-GCM"}, 0, "", nil)
	testing.expect_value(t, f, Negotiation_Failure.No_Shared_Cipher)
}

@(test)
negotiate_server_flags :: proc(t: ^testing.T) {
	all := Server_Offer {
		ciphers = {.Aes_256_Gcm, .Aes_128_Gcm, .Chacha20_Poly1305},
		allow   = {.Cc_Exit, .Dyn_Tls_Crypt, .Aead_Epoch},
	}
	// The same flags a stock server pushed to these clients (captured).
	pi: Peer_Info
	testing.expect_value(t, peer_info_parse(stock_peer_info_277, &pi), Error.None)
	n := negotiate_server(&pi, "AES-256-GCM", &all)
	testing.expect_value(t, n.failure, Negotiation_Failure.None)
	testing.expect_value(t, n.cipher, Cipher.Aes_256_Gcm)
	testing.expect(t, n.push_cipher)
	testing.expect_value(t, n.flags, Protocol_Flags{.Cc_Exit, .Tls_Ekm, .Dyn_Tls_Crypt, .Aead_Epoch})
	testing.expect(t, !n.legacy_key_derivation)

	testing.expect_value(t, peer_info_parse("IV_VER=2.6.23\nIV_CIPHERS=AES-256-GCM\nIV_PROTO=990\n", &pi), Error.None)
	n = negotiate_server(&pi, "AES-256-GCM", &all)
	testing.expect_value(t, n.failure, Negotiation_Failure.None)
	testing.expect_value(t, n.flags, Protocol_Flags{.Cc_Exit, .Tls_Ekm, .Dyn_Tls_Crypt})

	// The server only enables what it offers.
	none := Server_Offer {
		ciphers = {.Aes_256_Gcm},
	}
	testing.expect_value(t, peer_info_parse(stock_peer_info_277, &pi), Error.None)
	n = negotiate_server(&pi, "AES-256-GCM", &none)
	testing.expect_value(t, n.flags, Protocol_Flags{.Tls_Ekm})

	// Without bit 7: key-derivation instead of protocol-flags.
	old := Iv_Proto{.Data_V2, .Tls_Key_Export}
	buf: [64]u8
	line := make([dynamic]u8, context.temp_allocator)
	append(&line, "IV_CIPHERS=AES-256-GCM\nIV_PROTO=")
	append(&line, ..transmute([]u8)uint_text(buf[:], u64(iv_proto_value(old))))
	append(&line, '\n')
	testing.expect_value(t, peer_info_parse(string(line[:]), &pi), Error.None)
	n = negotiate_server(&pi, "AES-256-GCM", &all)
	testing.expect_value(t, n.failure, Negotiation_Failure.None)
	testing.expect(t, n.legacy_key_derivation)
	testing.expect_value(t, n.flags, Protocol_Flags{.Tls_Ekm})
}

uint_text :: proc(buf: []u8, v: u64) -> string {
	w := Wr{buf = buf}
	wr_uint(&w, v)
	return string(buf[:w.n])
}

@(test)
negotiate_server_failures :: proc(t: ^testing.T) {
	offer := Server_Offer {
		ciphers = {.Aes_256_Gcm},
	}
	pi: Peer_Info
	// No IV_PROTO at all: no DATA_V2.
	_ = peer_info_parse("IV_VER=2.5.0\nIV_CIPHERS=AES-256-GCM\n", &pi)
	n := negotiate_server(&pi, "AES-256-GCM", &offer)
	testing.expect_value(t, n.failure, Negotiation_Failure.Missing_Data_V2)
	testing.expect_value(t, negotiation_failure_text(n.failure), "Data channel negotiation failed (missing DATA_V2)")
	// DATA_V2 but no key export (bit 3).
	_ = peer_info_parse("IV_CIPHERS=AES-256-GCM\nIV_PROTO=2\n", &pi)
	n = negotiate_server(&pi, "AES-256-GCM", &offer)
	testing.expect_value(t, n.failure, Negotiation_Failure.Missing_Key_Export)
	// No shared cipher.
	_ = peer_info_parse("IV_CIPHERS=AES-128-GCM\nIV_PROTO=8094\n", &pi)
	n = negotiate_server(&pi, "AES-128-GCM", &offer)
	testing.expect_value(t, n.failure, Negotiation_Failure.No_Shared_Cipher)
	testing.expect_value(t, negotiation_failure_text(n.failure), "Data channel cipher negotiation failed (no shared cipher)")
	testing.expect_value(t, negotiation_failure_text(.None), "")
	// The texts go through the AUTH_FAILED formatter within its limit.
	buf: [MAX_COMMAND_LEN]u8
	for f in ([]Negotiation_Failure{.No_Shared_Cipher, .Missing_Data_V2, .Missing_Key_Export}) {
		_, err := format_auth_failed(buf[:], negotiation_failure_text(f))
		testing.expect_value(t, err, Error.None)
	}
}

@(test)
ncp_client_check_cases :: proc(t: ^testing.T) {
	own := []Cipher{.Aes_256_Gcm, .Aes_128_Gcm}
	c, err := ncp_client_check("AES-128-GCM", "AES-256-GCM", own)
	testing.expect_value(t, err, Ncp_Client_Error.None)
	testing.expect_value(t, c, Cipher.Aes_128_Gcm)
	c, err = ncp_client_check("aes-256-gcm", "", own)
	testing.expect_value(t, err, Ncp_Client_Error.None)
	testing.expect_value(t, c, Cipher.Aes_256_Gcm)
	// Pushed but not in the list.
	_, err = ncp_client_check("CHACHA20-POLY1305", "AES-256-GCM", own)
	testing.expect_value(t, err, Ncp_Client_Error.Cipher_Not_Allowed)
	_, err = ncp_client_check("BF-CBC", "AES-256-GCM", own)
	testing.expect_value(t, err, Ncp_Client_Error.Cipher_Not_Allowed)
	// Nothing pushed: the server's options-string cipher.
	c, err = ncp_client_check("", "AES-256-GCM", own)
	testing.expect_value(t, err, Ncp_Client_Error.None)
	testing.expect_value(t, c, Cipher.Aes_256_Gcm)
	_, err = ncp_client_check("", "CHACHA20-POLY1305", own)
	testing.expect_value(t, err, Ncp_Client_Error.No_Usable_Cipher)
	_, err = ncp_client_check("", "", own)
	testing.expect_value(t, err, Ncp_Client_Error.No_Usable_Cipher)
	_, err = ncp_client_check("AES-256-GCM", "AES-256-GCM", nil)
	testing.expect_value(t, err, Ncp_Client_Error.Cipher_Not_Allowed)
}
