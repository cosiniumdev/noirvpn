// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

// Cipher negotiation and the protocol flags of
// the PUSH_REPLY (4.4). Also the server-side decision of what to enable for a
// given client, from its IV_PROTO bits.

// The data ciphers noirvpn can run.
Cipher :: enum u8 {
	None,
	Aes_128_Gcm,
	Aes_256_Gcm,
	Chacha20_Poly1305,
}

// The name as it goes on the wire. Empty for `.None`.
cipher_name :: proc "contextless" (c: Cipher) -> string {
	switch c {
	case .None:
		return ""
	case .Aes_128_Gcm:
		return "AES-128-GCM"
	case .Aes_256_Gcm:
		return "AES-256-GCM"
	case .Chacha20_Poly1305:
		return "CHACHA20-POLY1305"
	}
	return ""
}

// Key size in bits, 0 for `.None`.
cipher_key_bits :: proc "contextless" (c: Cipher) -> int {
	switch c {
	case .None:
		return 0
	case .Aes_128_Gcm:
		return 128
	case .Aes_256_Gcm, .Chacha20_Poly1305:
		return 256
	}
	return 0
}

// Case-insensitive, like the crypto library's own name lookup. A name noirvpn
// does not run gives `.None`.
cipher_from_name :: proc "contextless" (s: string) -> Cipher {
	for c in Cipher.Aes_128_Gcm ..= Cipher.Chacha20_Poly1305 {
		if eq_fold(s, cipher_name(c)) {
			return c
		}
	}
	return .None
}

// The server's default `data-ciphers` list.
DEFAULT_DATA_CIPHERS :: [3]Cipher{.Aes_256_Gcm, .Aes_128_Gcm, .Chacha20_Poly1305}

// What a server sends when nothing matches.
NCP_FAIL_NO_SHARED_CIPHER :: "Data channel cipher negotiation failed (no shared cipher)"
NCP_FAIL_MISSING_DATA_V2 :: "Data channel negotiation failed (missing DATA_V2)"
// SPEC-GAP: the spec says a server that forces EKM fails a client without
// bit 3 but gives no text. This one is ours.
NCP_FAIL_MISSING_KEY_EXPORT :: "Data channel negotiation failed (missing TLS key export)"

// ------------------------------------------------------------ protocol flags

Protocol_Flag :: enum u8 {
	Cc_Exit, // `cc-exit`: EXIT over the control channel
	Tls_Ekm, // `tls-ekm`: data keys from the exporter
	Dyn_Tls_Crypt, // `dyn-tls-crypt`
	Aead_Epoch, // `aead-epoch`: epoch data key format
}

Protocol_Flags :: bit_set[Protocol_Flag;u8]

// The word of a flag, as it is written in `protocol-flags`.
protocol_flag_name :: proc "contextless" (f: Protocol_Flag) -> string {
	switch f {
	case .Cc_Exit:
		return "cc-exit"
	case .Tls_Ekm:
		return "tls-ekm"
	case .Dyn_Tls_Crypt:
		return "dyn-tls-crypt"
	case .Aead_Epoch:
		return "aead-epoch"
	}
	return ""
}

// Flag for a word, or ok = false for a word this version does not know.
protocol_flag_from_name :: proc "contextless" (s: string) -> (f: Protocol_Flag, ok: bool) {
	for x in Protocol_Flag {
		if protocol_flag_name(x) == s {
			return x, true
		}
	}
	return {}, false
}

// ------------------------------------------------------------- server side

// What the server is willing to do.
Server_Offer :: struct {
	// `data-ciphers`, in the server's order of preference.
	ciphers: []Cipher,
	// Protocol flags the server enables when the client supports them.
	// `.Tls_Ekm` is always used; the others only if listed here.
	allow:   Protocol_Flags,
}

Negotiation_Failure :: enum u8 {
	None,
	No_Shared_Cipher,
	Missing_Data_V2,
	Missing_Key_Export,
}

// The reason text for AUTH_FAILED.
negotiation_failure_text :: proc "contextless" (f: Negotiation_Failure) -> string {
	switch f {
	case .None:
		return ""
	case .No_Shared_Cipher:
		return NCP_FAIL_NO_SHARED_CIPHER
	case .Missing_Data_V2:
		return NCP_FAIL_MISSING_DATA_V2
	case .Missing_Key_Export:
		return NCP_FAIL_MISSING_KEY_EXPORT
	}
	return ""
}

Negotiation :: struct {
	failure:               Negotiation_Failure,
	cipher:                Cipher,
	// Push `cipher <name>`. False for a client that announced no list (an
	// old client keeps the cipher of its options string).
	push_cipher:           bool,
	// What to push in `protocol-flags`.
	flags:                 Protocol_Flags,
	// Push `key-derivation tls-ekm` instead of `protocol-flags` (a client
	// without IV_PROTO bit 7).
	legacy_key_derivation: bool,
}

// Server's pick. `list`: the client's names
// (IV_CIPHERS) or empty. `ncp`: its IV_NCP. `options_cipher`: the cipher item of
// its options string ("" if none).
//
// Order:
// 1. the client's list, or AES-256-GCM:AES-128-GCM when only IV_NCP >= 2 is
//    there, or the options-string cipher alone ("poor man's NCP")
// 2. the first of the server's own list that the client has
// Nothing in common: `.No_Shared_Cipher`. noirvpn has no
// `data-ciphers-fallback`, so a client that announced nothing usable fails too.
ncp_select :: proc(list: []string, ncp: int, options_cipher: string, server: []Cipher) -> (cipher: Cipher, push: bool, failure: Negotiation_Failure) {
	announced := len(list) > 0 || ncp >= 2
	has :: proc(list: []string, c: Cipher) -> bool {
		if len(list) > 0 {
			for name in list {
				if cipher_from_name(name) == c {
					return true
				}
			}
			return false
		}
		return c == .Aes_256_Gcm || c == .Aes_128_Gcm
	}
	if announced {
		for c in server {
			if c != .None && has(list, c) {
				return c, true, .None
			}
		}
		return .None, false, .No_Shared_Cipher
	}
	// Poor man's NCP.
	oc := cipher_from_name(options_cipher)
	if oc != .None {
		for c in server {
			if c == oc {
				return c, false, .None
			}
		}
	}
	return .None, false, .No_Shared_Cipher
}

// Everything the server decides from the client's peer-info and options
// string: cipher, protocol flags, and whether the client can run noirvpn's
// baseline at all (DATA_V2, key export).
negotiate_server :: proc(peer: ^Peer_Info, options_cipher: string, offer: ^Server_Offer) -> (n: Negotiation) {
	if .Data_V2 not_in peer.proto {
		n.failure = .Missing_Data_V2
		return
	}
	if .Tls_Key_Export not_in peer.proto {
		n.failure = .Missing_Key_Export
		return
	}
	c, push, f := ncp_select(peer_info_ciphers(peer), peer.ncp, options_cipher, offer.ciphers)
	if f != .None {
		n.failure = f
		return
	}
	n.cipher = c
	n.push_cipher = push
	n.flags = {.Tls_Ekm}
	if .Cc_Exit_Notify not_in peer.proto {
		// Without bit 7 the client does not read `protocol-flags`.
		n.legacy_key_derivation = true
		return
	}
	if .Cc_Exit in offer.allow {
		n.flags += {.Cc_Exit}
	}
	if .Dyn_Tls_Crypt in offer.allow && .Dyn_Tls_Crypt in peer.proto {
		n.flags += {.Dyn_Tls_Crypt}
	}
	if .Aead_Epoch in offer.allow && .Data_Epoch in peer.proto {
		n.flags += {.Aead_Epoch}
	}
	return
}

// ------------------------------------------------------------- client side

Ncp_Client_Error :: enum u8 {
	None,
	// The pushed cipher is not in the client's list (or not one noirvpn runs).
	Cipher_Not_Allowed,
	// Nothing was pushed and the server's options-string cipher is not in
	// the client's list.
	No_Usable_Cipher,
}

// Client check of the pushed cipher. `pushed`: value of
// the last `cipher` option, "" if none. `server_options_cipher`: cipher item of
// the server's options string. `own`: the client's data-ciphers list.
// `data-ciphers-fallback` is not supported.
ncp_client_check :: proc(pushed: string, server_options_cipher: string, own: []Cipher) -> (cipher: Cipher, err: Ncp_Client_Error) {
	in_list :: proc(c: Cipher, own: []Cipher) -> bool {
		if c == .None {
			return false
		}
		for o in own {
			if o == c {
				return true
			}
		}
		return false
	}
	if len(pushed) > 0 {
		c := cipher_from_name(pushed)
		if !in_list(c, own) {
			return .None, .Cipher_Not_Allowed
		}
		return c, .None
	}
	c := cipher_from_name(server_options_cipher)
	if !in_list(c, own) {
		return .None, .No_Usable_Cipher
	}
	return c, .None
}
