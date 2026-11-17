// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:mem"
import "noir:proto/wire"

// Dynamic tls-crypt: a wrap key derived from the TLS
// session of key id 0, used for control packets of key ids 1 to 7.
// The caller exports the keying material from TLS and passes it in; this
// package never touches TLS.

// Exporter label. Call the exporter with this label, NO context (not even an
// empty one), and 256 bytes of output.
DYNAMIC_TLS_CRYPT_LABEL :: "EXPORTER-OpenVPN-dynamic-tls-crypt"
DYNAMIC_EXPORT_LEN :: 256

// Derives the dynamic key: the 256 exported bytes XOR the original wrap key, if
// any (key file bytes for tls-auth and tls-crypt, Kc for tls-crypt-v2). Pass
// `original = nil` when no static wrap was used. No zero-slot check on the result.
dynamic_key_derive :: proc "contextless" (exported: []u8, original: ^Static_Key, out: ^Static_Key) -> Error {
	out^ = {}
	if len(exported) != DYNAMIC_EXPORT_LEN {
		return .Bad_Argument
	}
	copy(out.bytes[:], exported)
	if original != nil {
		for i in 0 ..< STATIC_KEY_LEN {
			out.bytes[i] ~= original.bytes[i]
		}
	}
	return .None
}

// Sets up the dynamic wrap context: a tls-crypt context from the derived key,
// own counter starting at 0 (first wire id 1) and a fresh replay window. The
// direction comes from the role only.
dynamic_tls_crypt_init :: proc "contextless" (c: ^Tls_Crypt, exported: []u8, original: ^Static_Key, role: wire.Role) -> Error {
	c^ = {}
	key: Static_Key
	defer mem.zero_explicit(&key, size_of(key))
	if err := dynamic_key_derive(exported, original, &key); err != .None {
		return err
	}
	tls_crypt_init(c, &key, role)
	return .None
}

// Which wrap protects a packet: the dynamic one for key ids above 0 once it
// exists, else the original wrap.
wrap_uses_dynamic :: proc "contextless" (key_id: u8, have_dynamic: bool) -> bool {
	return key_id != 0 && have_dynamic
}
