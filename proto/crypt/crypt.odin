// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package crypt: seals and opens P_DATA_V2 data packets (baseline AEAD and epoch
// formats), with replay
// window, usage counters, keepalive and OCC payloads. Key bytes come from package
// keys.
//
// Layers, from the bottom:
//
//	replay.odin    Replay_Window: sliding window by packet id
//	baseline.odin  byte-exact seal and open of the baseline format
//	epoch.odin     byte-exact seal and open of the epoch format
//	key.odin       Tx_Key, Rx_Key, Data_Key: keys plus counters and rules
//	payload.odin   keepalive ping, OCC messages, payload classification
//
// Package rules:
//   - No allocation on the packet path (the caller gives every buffer). Setting up
//     or replacing a key allocates inside the C library (AEAD contexts).
//   - Packet procs are "contextless": no Odin context needed.
//   - Open checks the tag first. Replay state and counters change only for an
//     authenticated packet, so forged packets move nothing.
//   - Errors are values. Never panics on packet bytes.
//
// Buffers:
// - Sealed baseline packet: `header(4) pid(4) tag(16) ciphertext`
// - Sealed epoch packet: `header(4) epoch(2) counter(6) ciphertext tag(16)`
// - In place: pass `plain` as exactly the slice of `out` where the payload goes
//   (`out[BASELINE_HEADROOM:]`, `out[EPOCH_HEADROOM:]`), so a packet can be read
//   from the tun device straight into place.
// - Any other overlap of two buffers is an error.
//
// Threads: three kinds of data, kept apart so a threaded data path shares what is
// safe and gives the rest to one owner:
//
//   Key_Ctx    AEAD context and implicit IV. Never written after init.
//              AWS-LC: one Key_Ctx may serve many threads at once.
//              OpenSSL: context holds per-call state, so each worker needs its own
//              Key_Ctx of the same key (ossl README).
//   Tx_State   send counter and usage counters of one key direction.
//   Rx_State   replay window and usage counters of one key direction.
//
// Ownership:
// - A Tx_State or Rx_State belongs to one worker at a time.
// - Today they sit in Tx_Key and Rx_Key beside the Key_Ctx. A Data_Key (both
//   directions of a key id) belongs to one worker.
// - Splitting directions across workers, or an atomic send counter for several
//   sealing workers, touches only `tx_seal` / `rx_open`.
// - Epoch format: the send epoch follows the receive epoch (6.6). Keep both
//   directions of a key id with one owner, or pass the `epoch_advanced` result of
//   `rx_open` to `tx_follow_epoch`. `Data_Key` does it itself.
package crypt

import "core:mem"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/wire"

Error :: enum {
	None,
	// Packet shorter than the format's minimum.
	Too_Short,
	// Not a P_DATA_V2 packet (another opcode, or an opcode noirvpn rejects).
	Not_Data_Packet,
	// The key id in the packet is not the id of this key.
	Wrong_Key_Id,
	// An output buffer is too small.
	Buffer_Too_Small,
	// Two buffers overlap in a way that is not the allowed in-place form.
	Buffer_Overlap,
	// Packet id 0 (baseline) or counter 0 (epoch): never valid.
	Bad_Packet_Id,
	// Epoch format: the epoch is 0 or outside the receive window.
	Unknown_Epoch,
	// The tag check failed. Drop the packet and count it.
	Bad_Tag,
	// Authentic, but the packet id was seen already or is too old.
	Replay,
	// More than 2^36 failed tag checks on this key: it refuses all packets.
	Key_Disabled,
	// The send packet ids of this key are used up (baseline: 2^32 - 1; epoch:
	// counter 2^48 - 1 at epoch 65535). The session layer starts a rekey and
	// sends nothing with this key.
	Packet_Id_Exhausted,
	// A wrong argument: peer id above 24 bits, key size, ...
	Bad_Argument,
	// The crypto library failed (not a property of the packet). The key is
	// no longer usable.
	Crypto,
}

// Sizes.
BASELINE_HEADROOM :: 24 // header(4) + packet id(4) + tag(16) before the payload
BASELINE_AD_LEN :: 8
EPOCH_HEADROOM :: 12 // header(4) + epoch(2) + counter(6) before the payload
EPOCH_TAILROOM :: 16 // the tag after the payload
EPOCH_AD_LEN :: 12
TAG_LEN :: ossl.AEAD_TAG_LEN
// Largest counter of the epoch format (48 bits).
EPOCH_COUNTER_MAX :: (u64(1) << 48) - 1
// Largest packet id of the baseline format (32 bits).
BASELINE_PID_MAX :: u64(max(u32))

// Extra bytes a sealed packet has over its payload.
packet_overhead :: proc "contextless" (format: keys.Format) -> int {
	if format == .Epoch {
		return EPOCH_HEADROOM + EPOCH_TAILROOM
	}
	return BASELINE_HEADROOM
}

// The AEAD context and implicit IV of one key and direction. Written once by
// `key_ctx_init_*`, then only read (see the thread notes above).
Key_Ctx :: struct {
	aead: ossl.Aead,
	iv:   [12]u8, // baseline: bytes 4 to 11 hold the 8-byte implicit IV; epoch: all 12 bytes
}

// Baseline format: `key` is the cipher key, `iv8` the 8-byte implicit IV.
key_ctx_init_baseline :: proc(kc: ^Key_Ctx, cipher: ossl.Aead_Cipher, key, iv8: []u8, dir: ossl.Aead_Dir) -> Error {
	kc^ = {}
	if len(iv8) != keys.IMPLICIT_IV_LEN {
		return .Bad_Argument
	}
	copy(kc.iv[4:], iv8)
	return aead_init(kc, cipher, key, dir)
}

// Epoch format: `key` is K(epoch), `iv12` is IV(epoch).
key_ctx_init_epoch :: proc(kc: ^Key_Ctx, cipher: ossl.Aead_Cipher, key, iv12: []u8, dir: ossl.Aead_Dir) -> Error {
	kc^ = {}
	if len(iv12) != keys.EPOCH_IV_LEN {
		return .Bad_Argument
	}
	copy(kc.iv[:], iv12)
	return aead_init(kc, cipher, key, dir)
}

@(private)
aead_init :: proc(kc: ^Key_Ctx, cipher: ossl.Aead_Cipher, key: []u8, dir: ossl.Aead_Dir) -> Error {
	#partial switch ossl.aead_init(&kc.aead, cipher, key, dir) {
	case .None:
		return .None
	case .Bad_Argument:
		return .Bad_Argument
	}
	return .Crypto
}

// Frees the AEAD context (this also wipes its key schedule) and the IV.
key_ctx_destroy :: proc "contextless" (kc: ^Key_Ctx) {
	ossl.aead_destroy(&kc.aead)
	mem.zero_explicit(&kc.iv, size_of(kc.iv))
}

// --- Buffer helpers ---

@(private)
overlaps :: #force_inline proc "contextless" (a, b: []u8) -> bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	a0 := uintptr(raw_data(a))
	b0 := uintptr(raw_data(b))
	return a0 < b0 + uintptr(len(b)) && b0 < a0 + uintptr(len(a))
}

// True if `a` and `b` are the same memory or do not touch each other.
@(private)
same_or_apart :: #force_inline proc "contextless" (a, b: []u8) -> bool {
	return raw_data(a) == raw_data(b) || !overlaps(a, b)
}

// Writes the 4-byte P_DATA_V2 header.
@(private)
put_header :: #force_inline proc "contextless" (out: []u8, key_id: u8, peer_id: u32) -> Error {
	_, err := wire.data_v2_encode(out, key_id, peer_id)
	#partial switch err {
	case .None:
		return .None
	case .Buffer_Too_Small:
		return .Buffer_Too_Small
	}
	return .Bad_Argument
}

// Reads the 4-byte header and checks that this is a P_DATA_V2 packet.
@(private)
get_header :: #force_inline proc "contextless" (pkt: []u8) -> (hdr: wire.Data_V2_Header, err: Error) {
	h, _, werr := wire.data_v2_decode(pkt)
	if werr != .None {
		return {}, .Not_Data_Packet
	}
	return h, .None
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
