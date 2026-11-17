// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:mem"
import "noir:proto/ossl"
import "noir:proto/wire"

// The exporter call: label, no context, 256 bytes.
// The TLS layer issues the call; this package only splits the result.
EXPORT_LABEL :: "EXPORTER-OpenVPN-datakeys"
EXPORT_LEN :: 256

// Size of the implicit IV in the baseline format.
IMPLICIT_IV_LEN :: 8
// Size of the epoch root key E1 (and of every later epoch key).
EPOCH_KEY_LEN :: 32
// Largest cipher key (AES-256, ChaCha20).
MAX_KEY_LEN :: 32

// Each direction has 4 parts of this many bytes in the export: cipher key
// area, "hmac" area (implicit IV), and the same two for the other direction.
@(private)
PART_LEN :: 64
@(private)
HALF_LEN :: 128
@(private)
ZERO_CHECK_LEN :: 16

// Key bytes of one direction.
Dir_Material :: struct {
	key:     [MAX_KEY_LEN]u8, // the first `key_len` bytes are the cipher key
	key_len: int,
	iv:      [IMPLICIT_IV_LEN]u8, // baseline format: implicit IV
	e1:      [EPOCH_KEY_LEN]u8, // epoch format: root key of the chain
}

// What a peer needs for one key id.
Key_Material :: struct {
	send: Dir_Material,
	recv: Dir_Material,
}

// Splits the 256 exporter bytes for a peer in `role`.
// A client sends with the first half and receives with the second; a server the
// other way round. All three ranges (key, implicit IV, E1) are filled; the
// connection's format picks one.
derive_material :: proc(export: []u8, role: wire.Role, cipher: ossl.Aead_Cipher) -> (m: Key_Material, err: Error) {
	if len(export) != EXPORT_LEN {
		return {}, .Bad_Export_Length
	}
	// Reject an all-zero part. Test all four, even those the cipher does not use.
	for part in 0 ..< 4 {
		if all_zero(export[part * PART_LEN:][:ZERO_CHECK_LEN]) {
			return {}, .Zero_Material
		}
	}
	key_len := ossl.aead_key_len(cipher)
	if key_len == 0 {
		return {}, .Bad_Argument
	}
	send_half, recv_half := 0, HALF_LEN
	if role == .Server {
		send_half, recv_half = HALF_LEN, 0
	}
	fill_dir(&m.send, export[send_half:][:HALF_LEN], key_len)
	fill_dir(&m.recv, export[recv_half:][:HALF_LEN], key_len)
	return m, .None
}

@(private)
fill_dir :: proc(d: ^Dir_Material, half: []u8, key_len: int) {
	d.key_len = key_len
	copy(d.key[:key_len], half[:key_len])
	copy(d.iv[:], half[PART_LEN:][:IMPLICIT_IV_LEN])
	copy(d.e1[:], half[:EPOCH_KEY_LEN])
}

@(private)
all_zero :: proc "contextless" (b: []u8) -> bool {
	acc: u8
	for x in b {
		acc |= x
	}
	return acc == 0
}

// Overwrites the key bytes in a way the compiler may not remove.
material_wipe :: proc "contextless" (m: ^Key_Material) {
	mem.zero_explicit(m, size_of(Key_Material))
}

// Same for the 256 exporter bytes, once they are split.
export_wipe :: proc "contextless" (export: []u8) {
	mem.zero_explicit(raw_data(export), len(export))
}
