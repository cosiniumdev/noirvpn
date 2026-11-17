// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:mem"
import "noir:proto/ossl"

// tls-auth: packet sent in clear, authenticated with HMAC.
//
//   wire order:       | op:1 | sid:8 | HMAC:N | id:4 | time:4 | rest |
//   HMAC input order: | id:4 | time:4 | op:1 | sid:8 | rest |
//
// `rest` is the inner packet after the session id (ACK array, message id,
// payload). Digests: SHA-1, SHA-256, SHA-512 (what proto/ossl offers).

// Which half of the key file each direction uses.
Key_Direction :: enum {
	Bidirectional, // no key-direction option: slot 0 both ways
	Zero, // key-direction 0: send slot 0, receive slot 1 (server convention)
	One, // key-direction 1: send slot 1, receive slot 0 (client convention)
}

// Keys of one tls-auth setup. Plain bytes: safe to copy.
Auth_Keys :: struct {
	alg:      ossl.Hmac_Alg,
	mac_len:  int, // digest size N
	send_key: [ossl.SHA512_LEN]u8, // first mac_len bytes used
	recv_key: [ossl.SHA512_LEN]u8,
}

auth_keys_init :: proc "contextless" (k: ^Auth_Keys, key: ^Static_Key, alg: ossl.Hmac_Alg, dir: Key_Direction) {
	k^ = {}
	k.alg = alg
	k.mac_len = ossl.hmac_size(alg)
	send_slot, recv_slot: int
	switch dir {
	case .Bidirectional:
		send_slot, recv_slot = 0, 0
	case .Zero:
		send_slot, recv_slot = 0, 1
	case .One:
		send_slot, recv_slot = 1, 0
	}
	copy(k.send_key[:k.mac_len], static_key_hmac(key, send_slot)[:k.mac_len])
	copy(k.recv_key[:k.mac_len], static_key_hmac(key, recv_slot)[:k.mac_len])
}

auth_keys_wipe :: proc "contextless" (k: ^Auth_Keys) {
	mem.zero_explicit(k, size_of(k^))
}

// Bytes tls-auth adds to a packet: HMAC plus the 8-byte wrap id.
tls_auth_overhead :: proc "contextless" (alg: ossl.Hmac_Alg) -> int {
	return ossl.hmac_size(alg) + 8
}

// Wraps `inner` (`op | sid | rest`) with an explicit wrap id and time.
// Returns the wire length, `len(inner) + N + 8`.
tls_auth_seal :: proc "contextless" (k: ^Auth_Keys, id, time: u32, inner, out: []u8) -> (n: int, err: Error) {
	if len(inner) < 9 {
		return 0, .Truncated
	}
	nmac := k.mac_len
	n = len(inner) + nmac + 8
	if len(out) < n {
		return 0, .Buffer_Too_Small
	}
	if overlaps(inner, out[:n]) {
		return 0, .Buffer_Overlap
	}
	idt: [8]u8
	put_u32(idt[0:4], id)
	put_u32(idt[4:8], time)

	mac: [ossl.SHA512_LEN]u8
	if !mac_parts(k.alg, k.send_key[:nmac], idt[:], inner[:9], inner[9:], mac[:]) {
		return 0, .Crypto
	}
	copy(out[0:9], inner[0:9])
	copy(out[9:9 + nmac], mac[:nmac])
	copy(out[9 + nmac:9 + nmac + 8], idt[:])
	copy(out[9 + nmac + 8:n], inner[9:])
	return n, .None
}

// Checks the HMAC. Returns the inner packet `op | sid | rest` in `out`, with the
// wrap id and time. Does NOT look at the replay window: use `tls_auth_unwrap`,
// or call `replay_accept` afterwards. A stateless server uses this alone
//.
tls_auth_open :: proc "contextless" (k: ^Auth_Keys, packet, out: []u8) -> (n: int, id, time: u32, err: Error) {
	nmac := k.mac_len
	if len(packet) < 9 + nmac + 8 {
		return 0, 0, 0, .Truncated
	}
	n = len(packet) - nmac - 8
	if len(out) < n {
		return 0, 0, 0, .Buffer_Too_Small
	}
	if overlaps(packet, out[:n]) {
		return 0, 0, 0, .Buffer_Overlap
	}
	idt := packet[9 + nmac:][:8]
	mac: [ossl.SHA512_LEN]u8
	if !mac_parts(k.alg, k.recv_key[:nmac], idt, packet[0:9], packet[9 + nmac + 8:], mac[:]) {
		return 0, 0, 0, .Crypto
	}
	if !ct_equal(mac[:nmac], packet[9:9 + nmac]) {
		return 0, 0, 0, .Bad_Mac
	}
	copy(out[0:9], packet[0:9])
	copy(out[9:n], packet[9 + nmac + 8:])
	return n, get_u32(idt[0:4]), get_u32(idt[4:8]), .None
}

// tls-auth wrap context: keys, send counter, receive window. Owned by the
// caller, one per control session. Plain data: safe to copy, wipe when done.
Tls_Auth :: struct {
	keys:    Auth_Keys,
	counter: Send_Counter,
	replay:  Replay_Window,
}

tls_auth_init :: proc "contextless" (a: ^Tls_Auth, key: ^Static_Key, alg: ossl.Hmac_Alg, dir: Key_Direction) {
	a^ = {}
	auth_keys_init(&a.keys, key, alg, dir)
	send_counter_init(&a.counter)
}

tls_auth_wipe :: proc "contextless" (a: ^Tls_Auth) {
	mem.zero_explicit(a, size_of(a^))
}

// Wraps with the next wrap id of the context's counter.
tls_auth_wrap :: proc "contextless" (a: ^Tls_Auth, now: i64, inner, out: []u8) -> (n: int, err: Error) {
	id, time, cerr := send_counter_next(&a.counter, now)
	if cerr != .None {
		return 0, cerr
	}
	return tls_auth_seal(&a.keys, id, time, inner, out)
}

// Authenticates, then runs the replay test, then commits it.
// On `.Replay` or any failure, `out` must not be used.
tls_auth_unwrap :: proc "contextless" (a: ^Tls_Auth, packet, out: []u8) -> (n: int, err: Error) {
	m, id, time, oerr := tls_auth_open(&a.keys, packet, out)
	if oerr != .None {
		return 0, oerr
	}
	if !replay_accept(&a.replay, id, time) {
		return 0, .Replay
	}
	return m, .None
}
