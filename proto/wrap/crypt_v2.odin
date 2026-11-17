// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:mem"
import "noir:proto/wire"

// tls-crypt-v2.
//
// Client: wraps with its own key Kc like tls-crypt, and appends the wrapped key
// WKc to packets with opcode 10 and 11.
// Server: finds WKc at the end of the datagram, decrypts it with the server key
// (gets Kc and metadata), unwraps the rest as tls-crypt.

// A client starts its wrap id counter here, so its first wire id is
// 0x0f000001. A server reads "bits 24..27 all set" as "this client supports
// early negotiation" (section 5.6).
EARLY_NEG_START :: 0x0f000000
EARLY_NEG_MASK :: 0x0f000000

// WKc layout: T(32) | AES-CTR(Kc || metadata) | net_len(2).
WKC_TAG_LEN :: 32
WKC_LEN_FIELD :: 2
// Smallest WKc this package accepts: no metadata at all (a noirvpn rule, the
// spec lets the parser go lower; a generator always writes a type byte).
WKC_MIN_LEN :: WKC_TAG_LEN + STATIC_KEY_LEN + WKC_LEN_FIELD
// WKC_MAX_LEN is WKC_MAX_LEN in keyfile.odin (1024).
MAX_METADATA_LEN :: WKC_MAX_LEN - WKC_MIN_LEN // 734, type byte included

METADATA_TYPE_USER :: 0x00
METADATA_TYPE_TIMESTAMP :: 0x01

// Metadata carried in WKc: a type byte, then data. `len` counts both.
Metadata :: struct {
	data: [MAX_METADATA_LEN]u8,
	len:  int,
}

metadata_bytes :: proc "contextless" (m: ^Metadata) -> []u8 {
	return m.data[:m.len]
}

// The type byte; `ok` is false when the metadata is empty.
metadata_type :: proc "contextless" (m: ^Metadata) -> (typ: u8, ok: bool) {
	if m.len < 1 {
		return 0, false
	}
	return m.data[0], true
}

// The bytes after the type byte (what a verify hook receives as data).
metadata_data :: proc "contextless" (m: ^Metadata) -> []u8 {
	if m.len < 1 {
		return nil
	}
	return m.data[1:m.len]
}

// Decodes a timestamp metadata: type 1 and at least 9 bytes in total; the
// 8 bytes after the type are a signed 64-bit unix time, network order.
metadata_timestamp :: proc "contextless" (m: ^Metadata) -> (ts: i64, ok: bool) {
	if m.len < 9 || m.data[0] != METADATA_TYPE_TIMESTAMP {
		return 0, false
	}
	v: u64
	for i in 1 ..= 8 {
		v = v << 8 | u64(m.data[i])
	}
	return i64(v), true
}

// Builds a timestamp metadata block (9 bytes).
metadata_make_timestamp :: proc "contextless" (m: ^Metadata, ts: i64) {
	m^ = {}
	m.data[0] = METADATA_TYPE_TIMESTAMP
	v := u64(ts)
	for i in 0 ..< 8 {
		m.data[8 - i] = u8(v >> (8 * u32(i)))
	}
	m.len = 9
}

// The `tls-crypt-v2-max-age` rule: the metadata must be a timestamp, and
// `now - timestamp` must not exceed `max_age_days * 86400` seconds. Call it only
// when the option is set. Future timestamps pass.
//
// SPEC-GAP: the spec is silent on `max-age 0` and on future timestamps. This
// follows the formula literally: 0 days allows age 0 s; a future timestamp passes.
metadata_check_age :: proc "contextless" (m: ^Metadata, now: i64, max_age_days: i64) -> Error {
	ts, ok := metadata_timestamp(m)
	if !ok {
		return .Metadata_Not_Timestamp
	}
	if max_age_days < 0 {
		return .Bad_Argument
	}
	// Compare as differences in i128 so that nothing overflows.
	age := i128(now) - i128(ts)
	if age > i128(max_age_days) * 86400 {
		return .Metadata_Too_Old
	}
	return .None
}

// Builds a WKc (the offline key generator's job; also useful in tests and in
// a `noirvpnctl key` tool). `metadata` is the type byte plus data, at most
// 734 bytes. Returns the length: `290 + len(metadata)`.
tls_crypt_v2_wkc_build :: proc "contextless" (sk: ^Server_Key, kc: ^Static_Key, metadata: []u8, out: []u8) -> (n: int, err: Error) {
	if len(metadata) > MAX_METADATA_LEN {
		return 0, .Metadata_Too_Long
	}
	n = WKC_MIN_LEN + len(metadata)
	if len(out) < n {
		return 0, .Buffer_Too_Small
	}
	net_len: [2]u8
	net_len[0] = u8(n >> 8)
	net_len[1] = u8(n)

	plain: [STATIC_KEY_LEN + MAX_METADATA_LEN]u8
	defer wipe(plain[:])
	pt := plain[:STATIC_KEY_LEN + len(metadata)]
	copy(pt, kc.bytes[:])
	copy(pt[STATIC_KEY_LEN:], metadata)

	tag: [WKC_TAG_LEN]u8
	if !mac_parts(.SHA256, sk.ka[:], net_len[:], pt, nil, tag[:]) {
		return 0, .Crypto
	}
	if !aes_ctr(sk.ke[:], tag[:16], out[WKC_TAG_LEN:WKC_TAG_LEN + len(pt)], pt) {
		return 0, .Crypto
	}
	copy(out[:WKC_TAG_LEN], tag[:])
	copy(out[n - WKC_LEN_FIELD:n], net_len[:])
	return n, .None
}

// Decrypts and authenticates a WKc with the server key (steps 4 to 6 of
// section 5.5). On success `kc` and `meta` are filled in. The length field in
// the last two bytes of `wkc` must equal `len(wkc)`.
tls_crypt_v2_wkc_open :: proc "contextless" (sk: ^Server_Key, wkc: []u8, kc: ^Static_Key, meta: ^Metadata) -> Error {
	kc^ = {}
	meta^ = {}
	if len(wkc) < WKC_MIN_LEN || len(wkc) > WKC_MAX_LEN {
		return .Bad_Wkc_Len
	}
	if int(get_u16(wkc[len(wkc) - WKC_LEN_FIELD:])) != len(wkc) {
		return .Bad_Wkc_Len
	}
	ct := wkc[WKC_TAG_LEN:len(wkc) - WKC_LEN_FIELD]
	plain: [WKC_MAX_LEN]u8
	defer wipe(plain[:])
	pt := plain[:len(ct)]
	if !aes_ctr(sk.ke[:], wkc[:16], pt, ct) {
		return .Crypto
	}
	tag: [WKC_TAG_LEN]u8
	if !mac_parts(.SHA256, sk.ka[:], wkc[len(wkc) - WKC_LEN_FIELD:], pt, nil, tag[:]) {
		return .Crypto
	}
	if !ct_equal(tag[:], wkc[:WKC_TAG_LEN]) {
		return .Bad_Wkc
	}
	copy(kc.bytes[:], pt[:STATIC_KEY_LEN])
	meta.len = len(pt) - STATIC_KEY_LEN
	copy(meta.data[:meta.len], pt[STATIC_KEY_LEN:])
	return .None
}

// Splits a datagram into the tls-crypt part and the WKc at its end (steps 2 and
// 3 of section 5.5). The first byte must be opcode 10 or 11.
//
// Checks:
// - at least 3 bytes after the opcode byte
// - last two bytes are a length of 290 to 1024 (290 is a noirvpn rule) that fits
//   in the packet
// - the rest is long enough for a tls-crypt packet
// Both results point into `packet`.
tls_crypt_v2_split_wkc :: proc "contextless" (packet: []u8) -> (body, wkc: []u8, err: Error) {
	if len(packet) < 1 {
		return nil, nil, .Truncated
	}
	op, _ := wire.split_first_byte(packet[0])
	if op != .Hard_Reset_Client_V3 && op != .Control_Wkc_V1 {
		return nil, nil, .Wrong_Opcode
	}
	if len(packet) < 1 + 3 {
		return nil, nil, .Truncated
	}
	l := int(get_u16(packet[len(packet) - WKC_LEN_FIELD:]))
	if l > WKC_MAX_LEN || l > len(packet) - 1 || l < WKC_MIN_LEN {
		return nil, nil, .Bad_Wkc_Len
	}
	if len(packet) - l < CRYPT_MIN_PACKET {
		return nil, nil, .Truncated
	}
	return packet[:len(packet) - l], packet[len(packet) - l:], .None
}

// True if the wrap id of a client packet signals early negotiation
// (bits 24..27 all set). Read the id with `crypt_peek_wrap_id`.
tls_crypt_v2_signals_early_negotiation :: proc "contextless" (wrap_id: u32) -> bool {
	return wrap_id & EARLY_NEG_MASK == EARLY_NEG_MASK
}

// ---- client ----

// Sets up the wrap context of a tls-crypt-v2 client: a tls-crypt client built
// from Kc, with the send counter at 0x0f000000.
tls_crypt_v2_client_init :: proc "contextless" (c: ^Tls_Crypt, ck: ^Client_Key) {
	tls_crypt_init(c, &ck.kc, .Client, EARLY_NEG_START)
}

// Wraps `inner` as tls-crypt and appends `wkc`. Only for opcodes 10 and 11
// (`.Wrong_Opcode` otherwise); other packets use `tls_crypt_wrap`. The tag does
// not cover the WKc. Returns the wire length `len(inner) + 40 + len(wkc)`.
tls_crypt_v2_client_wrap :: proc "contextless" (c: ^Tls_Crypt, wkc: []u8, now: i64, inner, out: []u8) -> (n: int, err: Error) {
	if len(inner) < 1 {
		return 0, .Truncated
	}
	op, _ := wire.split_first_byte(inner[0])
	if op != .Hard_Reset_Client_V3 && op != .Control_Wkc_V1 {
		return 0, .Wrong_Opcode
	}
	if len(wkc) < 1 || len(wkc) > WKC_MAX_LEN {
		return 0, .Bad_Wkc_Len
	}
	if len(out) < len(inner) + CRYPT_OVERHEAD + len(wkc) {
		return 0, .Buffer_Too_Small
	}
	m, werr := tls_crypt_wrap(c, now, inner, out)
	if werr != .None {
		return 0, werr
	}
	copy(out[m:], wkc)
	return m + len(wkc), .None
}

// ---- server ----

// Server side of a client's first packet (opcode 10 or 11). Opens the WKc,
// builds a server-role wrap context from Kc in `ctx`, unwraps the rest with it.
//
// On success:
// - `out[:n]` is the inner packet
// - `ctx` holds the client's wrap state (first wrap id already in its replay
//   window)
// - `meta` is the WKc metadata
// The metadata checks of section 5.3 (age, verify callback) are NOT run here:
// call `metadata_check_age` and your hook.
// A stateless server discards `ctx` afterwards.
//
// If the peer already has a context, do not call this again: use
// `tls_crypt_v2_split_wkc` and unwrap `body` with `tls_crypt_unwrap`.
tls_crypt_v2_server_unwrap :: proc "contextless" (
	sk: ^Server_Key,
	packet, out: []u8,
	ctx: ^Tls_Crypt,
	meta: ^Metadata,
) -> (
	n: int,
	err: Error,
) {
	ctx^ = {}
	meta^ = {}
	body, wkc, serr := tls_crypt_v2_split_wkc(packet)
	if serr != .None {
		return 0, serr
	}
	kc: Static_Key
	defer static_key_wipe(&kc)
	if oerr := tls_crypt_v2_wkc_open(sk, wkc, &kc, meta); oerr != .None {
		return 0, oerr
	}
	tls_crypt_init(ctx, &kc, .Server)
	m, uerr := tls_crypt_unwrap(ctx, body, out)
	if uerr != .None {
		mem.zero_explicit(ctx, size_of(ctx^))
		meta^ = {}
		return 0, uerr
	}
	return m, .None
}
