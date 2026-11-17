// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "noir:proto/ossl"

// The baseline AEAD packet:
//
//   | op/kid:1 | peer-id:3 | packet-id:4 | tag:16 | ciphertext:n |
//   \____________ AD (8 bytes) __________/
//
// nonce = packet-id(4, big endian) || implicit-iv(8)
//
// These procs are plain functions of the key context and packet id. Counting,
// replay checks and key rules are in key.odin.

// The 12-byte nonce of the baseline format.
@(private)
baseline_nonce :: #force_inline proc "contextless" (kc: ^Key_Ctx, pid: u32) -> (n: [12]u8) {
	put_u32(n[0:4], pid)
	copy(n[4:], kc.iv[4:])
	return
}

// Seals `plain` as packet `pid` of key `key_id` for `peer_id`. Writes
// `BASELINE_HEADROOM + len(plain)` bytes to `out`, returns that length.
// `plain` may be `out[BASELINE_HEADROOM:][:len(plain)]` (in place).
// `pid` must never repeat for one key (`Tx_Key` ensures it).
baseline_seal :: proc "contextless" (
	kc: ^Key_Ctx,
	key_id: u8,
	peer_id: u32,
	pid: u32,
	plain: []u8,
	out: []u8,
) -> (
	n: int,
	err: Error,
) {
	n = BASELINE_HEADROOM + len(plain)
	if len(out) < n {
		return 0, .Buffer_Too_Small
	}
	body := out[BASELINE_HEADROOM:n]
	if !same_or_apart(plain, body) || overlaps(plain, out[:BASELINE_HEADROOM]) {
		return 0, .Buffer_Overlap
	}
	if err = put_header(out, key_id, peer_id); err != .None {
		return 0, err
	}
	put_u32(out[4:8], pid)
	nonce := baseline_nonce(kc, pid)
	if !ossl.aead_seal(&kc.aead, nonce[:], out[:BASELINE_AD_LEN], plain, body, out[8:BASELINE_HEADROOM]) {
		return 0, .Crypto
	}
	return n, .None
}

// The packet id of a baseline packet, if it is long enough.
baseline_peek_pid :: proc "contextless" (pkt: []u8) -> (pid: u32, ok: bool) {
	if len(pkt) < BASELINE_AD_LEN {
		return 0, false
	}
	return get_u32(pkt[4:8]), true
}

// Checks the tag and decrypts. Returns the packet id and the plaintext length.
// The plaintext goes to `out[:n]`; `out` may be `pkt[BASELINE_HEADROOM:]` (in
// place). Ignores the replay window (see `Rx_Key`). On `.Bad_Tag` `out` is
// garbage.
baseline_open :: proc "contextless" (kc: ^Key_Ctx, pkt: []u8, out: []u8) -> (pid: u32, n: int, err: Error) {
	if len(pkt) < BASELINE_HEADROOM {
		return 0, 0, .Too_Short
	}
	if _, herr := get_header(pkt); herr != .None {
		return 0, 0, herr
	}
	pid = get_u32(pkt[4:8])
	if pid == 0 {
		return 0, 0, .Bad_Packet_Id
	}
	body := pkt[BASELINE_HEADROOM:]
	n = len(body)
	if len(out) < n {
		return 0, 0, .Buffer_Too_Small
	}
	// The plaintext may overwrite the ciphertext exactly, nothing else.
	if !same_or_apart(body, out[:n]) || overlaps(pkt[:BASELINE_HEADROOM], out[:n]) {
		return 0, 0, .Buffer_Overlap
	}
	nonce := baseline_nonce(kc, pid)
	if !ossl.aead_open(&kc.aead, nonce[:], pkt[:BASELINE_AD_LEN], body, pkt[8:BASELINE_HEADROOM], out[:n]) {
		return 0, 0, .Bad_Tag
	}
	return pid, n, .None
}
