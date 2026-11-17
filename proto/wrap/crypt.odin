// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:mem"
import "noir:proto/wire"

// tls-crypt. Also used, with other keys, for
// tls-crypt-v2 and dynamic tls-crypt.
//
//   | op:1 | sid:8 | id:4 | time:4 | tag:32 | CIPHERTEXT(body) |
//   tag = HMAC-SHA256(Ka, op | sid | id | time | body)
//   ciphertext = AES-256-CTR(Ke, iv = tag[0..16], body)

CRYPT_HEADER_LEN :: 17 // op, sid, id, time
CRYPT_TAG_LEN :: 32
// Bytes added to the inner packet.
CRYPT_OVERHEAD :: 40
// Smallest wire packet (an inner packet of 9 bytes: op and sid only).
CRYPT_MIN_PACKET :: CRYPT_HEADER_LEN + CRYPT_TAG_LEN
// Offset of the wrap id in the wire packet.
CRYPT_ID_OFFSET :: 9

// Keys of one tls-crypt setup. Plain bytes: safe to copy.
Crypt_Keys :: struct {
	send_ke: [32]u8, // AES-256 key
	send_ka: [32]u8, // HMAC-SHA256 key
	recv_ke: [32]u8,
	recv_ka: [32]u8,
}

// Picks the slots by role: server sends with slot 0 and receives with slot 1;
// the client is the mirror image.
crypt_keys_init :: proc "contextless" (k: ^Crypt_Keys, key: ^Static_Key, role: wire.Role) {
	send_slot, recv_slot := 0, 1
	if role == .Client {
		send_slot, recv_slot = 1, 0
	}
	copy(k.send_ke[:], static_key_cipher(key, send_slot)[:32])
	copy(k.send_ka[:], static_key_hmac(key, send_slot)[:32])
	copy(k.recv_ke[:], static_key_cipher(key, recv_slot)[:32])
	copy(k.recv_ka[:], static_key_hmac(key, recv_slot)[:32])
}

crypt_keys_wipe :: proc "contextless" (k: ^Crypt_Keys) {
	mem.zero_explicit(k, size_of(k^))
}

// Reads the wrap id and time from the clear header of a tls-crypt, v2 or
// dynamic packet, without authenticating. Needs at least 17 bytes.
crypt_peek_wrap_id :: proc "contextless" (packet: []u8) -> (id, time: u32, ok: bool) {
	if len(packet) < CRYPT_HEADER_LEN {
		return 0, 0, false
	}
	return get_u32(packet[CRYPT_ID_OFFSET:]), get_u32(packet[CRYPT_ID_OFFSET + 4:]), true
}

// Wraps `inner` (`op | sid | body`) with an explicit wrap id and time. Returns
// the wire length, `len(inner) + 40`.
tls_crypt_seal :: proc "contextless" (k: ^Crypt_Keys, id, time: u32, inner, out: []u8) -> (n: int, err: Error) {
	if len(inner) < 9 {
		return 0, .Truncated
	}
	n = len(inner) + CRYPT_OVERHEAD
	if len(out) < n {
		return 0, .Buffer_Too_Small
	}
	if overlaps(inner, out[:n]) {
		return 0, .Buffer_Overlap
	}
	copy(out[0:9], inner[0:9])
	put_u32(out[9:13], id)
	put_u32(out[13:17], time)

	body := inner[9:]
	tag: [CRYPT_TAG_LEN]u8
	if !mac_parts(.SHA256, k.send_ka[:], out[:CRYPT_HEADER_LEN], body, nil, tag[:]) {
		return 0, .Crypto
	}
	copy(out[CRYPT_HEADER_LEN:CRYPT_MIN_PACKET], tag[:])
	if !aes_ctr(k.send_ke[:], tag[:16], out[CRYPT_MIN_PACKET:n], body) {
		return 0, .Crypto
	}
	return n, .None
}

// Verifies the tag. Returns the inner packet `op | sid | body` in `out`, with the
// wrap id and time. Does NOT look at the replay window: use `tls_crypt_unwrap`,
// or call `replay_accept` afterwards. On a bad tag the plaintext is wiped from
// `out`.
tls_crypt_open :: proc "contextless" (k: ^Crypt_Keys, packet, out: []u8) -> (n: int, id, time: u32, err: Error) {
	if len(packet) < CRYPT_MIN_PACKET {
		return 0, 0, 0, .Truncated
	}
	n = len(packet) - CRYPT_OVERHEAD
	if len(out) < n {
		return 0, 0, 0, .Buffer_Too_Small
	}
	if overlaps(packet, out[:n]) {
		return 0, 0, 0, .Buffer_Overlap
	}
	tag := packet[CRYPT_HEADER_LEN:CRYPT_MIN_PACKET]
	// Decrypt first (CTR has no padding), then check the tag over the
	// plaintext, as the spec describes.
	if !aes_ctr(k.recv_ke[:], tag[:16], out[9:n], packet[CRYPT_MIN_PACKET:]) {
		wipe(out[:n])
		return 0, 0, 0, .Crypto
	}
	expect: [CRYPT_TAG_LEN]u8
	if !mac_parts(.SHA256, k.recv_ka[:], packet[:CRYPT_HEADER_LEN], out[9:n], nil, expect[:]) {
		wipe(out[:n])
		return 0, 0, 0, .Crypto
	}
	if !ct_equal(expect[:], tag) {
		wipe(out[:n])
		return 0, 0, 0, .Bad_Mac
	}
	copy(out[0:9], packet[0:9])
	return n, get_u32(packet[9:]), get_u32(packet[13:]), .None
}

// tls-crypt wrap context: keys, send counter, receive window. The caller owns
// it, one per control session (the dynamic tls-crypt wrap has its own).
// Plain data: safe to copy. Wipe when done.
Tls_Crypt :: struct {
	keys:    Crypt_Keys,
	counter: Send_Counter,
	replay:  Replay_Window,
}

// `first_id` is the counter before the first packet; leave it 0 except for a
// tls-crypt-v2 client (see tls_crypt_v2_client_init).
tls_crypt_init :: proc "contextless" (c: ^Tls_Crypt, key: ^Static_Key, role: wire.Role, first_id: u32 = 0) {
	c^ = {}
	crypt_keys_init(&c.keys, key, role)
	send_counter_init(&c.counter, first_id)
}

tls_crypt_wipe :: proc "contextless" (c: ^Tls_Crypt) {
	mem.zero_explicit(c, size_of(c^))
}

// Wraps with the next wrap id of the context's counter.
tls_crypt_wrap :: proc "contextless" (c: ^Tls_Crypt, now: i64, inner, out: []u8) -> (n: int, err: Error) {
	id, time, cerr := send_counter_next(&c.counter, now)
	if cerr != .None {
		return 0, cerr
	}
	return tls_crypt_seal(&c.keys, id, time, inner, out)
}

// Authenticates, then runs the replay test and commits it.
// On any error `out` must not be used.
tls_crypt_unwrap :: proc "contextless" (c: ^Tls_Crypt, packet, out: []u8) -> (n: int, err: Error) {
	m, id, time, oerr := tls_crypt_open(&c.keys, packet, out)
	if oerr != .None {
		return 0, oerr
	}
	if !replay_accept(&c.replay, id, time) {
		wipe(out[:m])
		return 0, .Replay
	}
	return m, .None
}
