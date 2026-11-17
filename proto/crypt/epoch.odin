// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "base:intrinsics"
import "noir:proto/ossl"

// The epoch packet:
//
//   | op/kid:1 | peer-id:3 | epoch:2 | counter:6 | ciphertext:n | tag:16 |
//   \____________________ AD (12 bytes) __________/
//
// nonce = (epoch(2) || counter(6) || 00 00 00 00) XOR implicit-iv(12)
//
// The tag follows the ciphertext (it precedes it in the baseline format).
// `epoch` and `counter` are never 0.

// The 8 bytes after the 4-byte header: the epoch (2 bytes) and the counter (6
// bytes) as one big-endian number. `counter` is below 2^48.
@(private)
epoch_word :: #force_inline proc "contextless" (epoch: u16, counter: u64) -> u64 {
	return u64(epoch) << 48 | counter
}

// The 12-byte nonce of the epoch format: the packet word (8 bytes) plus 4 zero
// bytes, XOR the IV. Done in words: the bytes of the word are big endian in
// the packet and in the nonce, so the IV is read the same way.
@(private)
epoch_nonce :: #force_inline proc "contextless" (kc: ^Key_Ctx, word: u64) -> (n: [12]u8) {
	iv_hi := intrinsics.unaligned_load((^u64be)(&kc.iv[0]))
	iv_lo := intrinsics.unaligned_load((^u32)(&kc.iv[8]))
	intrinsics.unaligned_store((^u64be)(&n[0]), u64be(word) ~ iv_hi)
	intrinsics.unaligned_store((^u32)(&n[8]), iv_lo)
	return
}

// Seals `plain` as packet `counter` of `epoch`. Writes
// `EPOCH_HEADROOM + len(plain) + EPOCH_TAILROOM` bytes to `out`, returns that
// length. `plain` may be `out[EPOCH_HEADROOM:][:len(plain)]` (in place).
// `kc` must hold the key and IV of `epoch`; `counter` must never repeat within
// it (`Tx_Key` ensures both).
epoch_seal :: proc "contextless" (
	kc: ^Key_Ctx,
	key_id: u8,
	peer_id: u32,
	epoch: u16,
	counter: u64,
	plain: []u8,
	out: []u8,
) -> (
	n: int,
	err: Error,
) {
	if epoch == 0 || counter == 0 || counter > EPOCH_COUNTER_MAX {
		return 0, .Bad_Packet_Id
	}
	n = EPOCH_HEADROOM + len(plain) + EPOCH_TAILROOM
	if len(out) < n {
		return 0, .Buffer_Too_Small
	}
	body := out[EPOCH_HEADROOM:][:len(plain)]
	tag := out[EPOCH_HEADROOM + len(plain):n]
	// `plain` is the body itself (in place) or does not touch the packet at all.
	if raw_data(plain) != raw_data(body) && overlaps(plain, out[:n]) {
		return 0, .Buffer_Overlap
	}
	if err = put_header(out, key_id, peer_id); err != .None {
		return 0, err
	}
	word := epoch_word(epoch, counter)
	intrinsics.unaligned_store((^u64be)(&out[4]), u64be(word))
	nonce := epoch_nonce(kc, word)
	if !ossl.aead_seal(&kc.aead, nonce[:], out[:EPOCH_AD_LEN], plain, body, tag) {
		return 0, .Crypto
	}
	return n, .None
}

// The epoch and counter of an epoch packet, if it is long enough to have them.
epoch_peek :: proc "contextless" (pkt: []u8) -> (epoch: u16, counter: u64, ok: bool) {
	if len(pkt) < EPOCH_AD_LEN {
		return 0, 0, false
	}
	word := u64(intrinsics.unaligned_load((^u64be)(&pkt[4])))
	return u16(word >> 48), word & EPOCH_COUNTER_MAX, true
}

// Checks the tag and decrypts. `kc` must hold the key of the packet's epoch.
// Returns the plaintext length; plaintext goes to `out[:n]`, which may be
// `pkt[EPOCH_HEADROOM:]` (in place). Ignores the replay and epoch windows (see
// `Rx_Key`). On `.Bad_Tag` `out` is garbage.
epoch_open :: proc "contextless" (kc: ^Key_Ctx, pkt: []u8, out: []u8) -> (n: int, err: Error) {
	if len(pkt) < EPOCH_HEADROOM + EPOCH_TAILROOM {
		return 0, .Too_Short
	}
	if _, herr := get_header(pkt); herr != .None {
		return 0, herr
	}
	epoch, counter, _ := epoch_peek(pkt)
	if epoch == 0 {
		return 0, .Unknown_Epoch
	}
	if counter == 0 {
		return 0, .Bad_Packet_Id
	}
	return epoch_open_checked(kc, pkt, out)
}

// `epoch_open` for a caller that has already checked the length, header, epoch
// and counter (`Rx_Key` does). It does the tag, the buffers and the decryption.
@(private)
epoch_open_checked :: #force_inline proc "contextless" (kc: ^Key_Ctx, pkt: []u8, out: []u8) -> (n: int, err: Error) {
	word := u64(intrinsics.unaligned_load((^u64be)(&pkt[4])))
	n = len(pkt) - EPOCH_HEADROOM - EPOCH_TAILROOM
	if len(out) < n {
		return 0, .Buffer_Too_Small
	}
	body := pkt[EPOCH_HEADROOM:][:n]
	tag := pkt[EPOCH_HEADROOM + n:]
	// `out` is the body itself (in place) or does not touch the packet at all.
	if raw_data(out) != raw_data(body) && overlaps(pkt, out[:n]) {
		return 0, .Buffer_Overlap
	}
	nonce := epoch_nonce(kc, word)
	if !ossl.aead_open(&kc.aead, nonce[:], pkt[:EPOCH_AD_LEN], body, tag, out[:n]) {
		return 0, .Bad_Tag
	}
	return n, .None
}
