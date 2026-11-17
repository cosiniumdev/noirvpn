// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package wrap protects the OpenVPN control channel before and around TLS: tls-auth
// (HMAC only), tls-crypt and tls-crypt-v2 (HMAC-SHA256 plus AES-256-CTR), dynamic
// tls-crypt (key derived from the TLS session).
//
// Turns the inner control packet `op | sid | body` into the wire packet and back.
// No I/O, no clock (caller passes `now` in whole unix seconds), no TLS (caller
// passes exporter bytes for dynamic tls-crypt).
//
// Layers:
//
//   key files      keyfile.odin    Static_Key, Server_Key, Client_Key and their parsers
//   replay         replay.odin     Send_Counter, Replay_Window (caller owns them)
//   tls-auth       auth.odin       Auth_Keys / Tls_Auth
//   tls-crypt      crypt.odin      Crypt_Keys / Tls_Crypt (also the type for v2 and dynamic)
//   tls-crypt-v2   crypt_v2.odin   WKc, metadata, client and server helpers
//   dynamic        dynamic.odin    key derivation from exporter output
//
// Per mode, `*_seal` / `*_open` are pure functions of keys and wrap id.
// `*_wrap` / `*_unwrap` on the context type add the send counter and replay window.
// The caller supplies all packet buffers; they must not overlap.
package wrap

import "core:mem"
import "noir:proto/ossl"

Error :: enum {
	None,
	// Packet shorter than the minimum for the mode.
	Truncated,
	// Output buffer too small.
	Buffer_Too_Small,
	// Input and output slices overlap.
	Buffer_Overlap,
	// HMAC or tag does not match. The packet is dropped without a reply.
	Bad_Mac,
	// Wrap packet id rejected by the replay window.
	Replay,
	// The send counter cannot advance (id exhausted within one second).
	Counter_Exhausted,
	// The crypto library failed (not a property of the packet).
	Crypto,
	// Argument has the wrong size or value.
	Bad_Argument,

	// Key files.
	Missing_Header, // no BEGIN line
	Missing_Footer, // no END line
	Bad_Hex, // static key: a character that is not hex or white space
	Bad_Base64, // PEM body is not valid base64
	Wrong_Label, // PEM block has another label than expected
	Wrong_Size, // key material has the wrong number of bytes
	Zero_Slot, // static key: the first 16 bytes of a slot are all zero

	// tls-crypt-v2.
	Wrong_Opcode, // only opcodes 10 and 11 carry a WKc
	Bad_Wkc_Len, // WKc length field out of range
	Bad_Wkc, // WKc failed authentication
	Metadata_Too_Long,
	Metadata_Not_Timestamp, // age check needs a type-1 metadata of at least 9 bytes
	Metadata_Too_Old,
}

// Whole unix seconds as the u32 on the wire. Negative becomes 0; a value past
// 2106 saturates.
//
// SPEC-GAP: the spec says the wrap time is "seconds since 1970, sender's clock"
// but not how to treat a clock outside the u32 range. Clamping is safest: the
// value only has to be ordered, never compared with a clock.
wrap_time :: proc "contextless" (now: i64) -> u32 {
	if now <= 0 {
		return 0
	}
	if now > i64(max(u32)) {
		return max(u32)
	}
	return u32(now)
}

@(private)
put_u32 :: #force_inline proc "contextless" (b: []u8, v: u32) {
	b[0] = u8(v >> 24)
	b[1] = u8(v >> 16)
	b[2] = u8(v >> 8)
	b[3] = u8(v)
}

@(private)
get_u32 :: #force_inline proc "contextless" (b: []u8) -> u32 {
	return u32(b[0]) << 24 | u32(b[1]) << 16 | u32(b[2]) << 8 | u32(b[3])
}

@(private)
get_u16 :: #force_inline proc "contextless" (b: []u8) -> u16 {
	return u16(b[0]) << 8 | u16(b[1])
}

// Compares in constant time (for equal lengths).
@(private)
ct_equal :: proc "contextless" (a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	diff: u8
	for i in 0 ..< len(a) {
		diff |= a[i] ~ b[i]
	}
	return diff == 0
}

// True if the two non-empty slices share memory.
@(private)
overlaps :: proc "contextless" (a, b: []u8) -> bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	a0 := uintptr(raw_data(a))
	b0 := uintptr(raw_data(b))
	return a0 < b0 + uintptr(len(b)) && b0 < a0 + uintptr(len(a))
}

@(private)
wipe :: proc "contextless" (b: []u8) {
	if len(b) > 0 {
		mem.zero_explicit(raw_data(b), len(b))
	}
}

// HMAC over the concatenation of up to three parts, without copying them.
// `out` must hold hmac_size(alg) bytes.
@(private)
mac_parts :: proc "contextless" (alg: ossl.Hmac_Alg, key, p1, p2, p3: []u8, out: []u8) -> bool {
	h: ossl.Hmac_Ctx
	if ossl.hmac_ctx_init(&h, alg, key) != .None {
		return false
	}
	defer ossl.hmac_ctx_destroy(&h)
	return ossl.hmac_ctx_update(&h, p1) && ossl.hmac_ctx_update(&h, p2) && ossl.hmac_ctx_update(&h, p3) && ossl.hmac_ctx_final(&h, out)
}

// AES-256-CTR with a 16-byte IV. `dst` may be the same slice as `src`.
@(private)
aes_ctr :: proc "contextless" (key, iv: []u8, dst, src: []u8) -> bool {
	return ossl.aes256_ctr_xor(key, iv, dst, src)
}
