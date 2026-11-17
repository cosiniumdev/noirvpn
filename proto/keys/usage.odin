// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:time"
import "noir:proto/ossl"

// AEAD usage limits and rekey triggers.
// Data and pure functions: package crypt counts, the session layer asks
// `rekey_check`.

// SPEC-GAP: the spec gives the limit, "blocks plus the
// highest packet id", compared after each packet. It leaves open:
// - `>` or `>=`: we use `>=` ("reached")
// - how stock counts blocks: we count ceil((payload + 24) / 16) per packet, both
//   directions (the conservative form)
// - the packet id in the epoch format: ids are 64 bits with the epoch on top
//   (6.1), which would reach any limit at once, so we use the 48-bit counter of
//   the current epoch key
// Epoch key usage restarts with the epoch. `reneg-bytes` and `reneg-pkts` count
// over all epochs of a key id.
//
// AES-GCM may protect at most 2^36 - 1 "blocks + packets" per key.
USAGE_LIMIT_FULL :: (u64(1) << 36) - 1
// Baseline format: a renegotiation starts at 7/8 of the limit.
USAGE_LIMIT_BASELINE :: USAGE_LIMIT_FULL / 8 * 7
// Failed tag checks on one receive key (per epoch key in the epoch format):
// - above this: renegotiation (baseline) or epoch move (epoch format) is due
// - above the second limit: drop packets without trying them
// Only failed AEAD checks count (not a wrong key id, unknown epoch or short
// packet). Both rules say "more than", so the test is `>`.
TAG_FAIL_REKEY :: u64(1) << 35
TAG_FAIL_REFUSE :: u64(1) << 36
// Baseline send packet id at which a renegotiation is due (32-bit wrap guard).
PACKET_ID_REKEY_AT :: 0xFF00_0000
// Overhead assumed per packet when counting blocks: 4 (header) + 4 (packet id)
// + 16 (tag). A bit more than stock counts, which is the safe side.
BLOCK_COUNT_OVERHEAD :: 24

// Usage limit in blocks plus packets for a cipher and format. 0 means no limit
// (ChaCha20-Poly1305).
usage_limit :: proc "contextless" (cipher: ossl.Aead_Cipher, format: Format) -> u64 {
	switch cipher {
	case .AES_128_GCM, .AES_256_GCM:
		if format == .Epoch {
			return USAGE_LIMIT_FULL
		}
		return USAGE_LIMIT_BASELINE
	case .CHACHA20_POLY1305:
		return 0
	}
	return 0
}

// AEAD blocks that one packet with `payload_len` plaintext bytes counts for.
blocks_for :: #force_inline proc "contextless" (payload_len: int) -> u64 {
	return (u64(payload_len) + BLOCK_COUNT_OVERHEAD + 15) / 16
}

// Usage of one direction of one key (of one epoch key in the epoch format).
Usage :: struct {
	blocks:   u64, // AEAD blocks processed
	pid:      u64, // highest packet id sent, or accepted (the counter in the epoch format)
	tag_fail: u64, // failed tag checks (receive side)
}

// Counts one authenticated or sent packet.
usage_count :: #force_inline proc "contextless" (u: ^Usage, pid: u64, payload_len: int) {
	u.blocks += blocks_for(payload_len)
	if pid > u.pid {
		u.pid = pid
	}
}

// True once blocks plus the highest packet id reach `limit` (0: no limit).
usage_reached :: #force_inline proc "contextless" (limit: u64, u: Usage) -> bool {
	return limit != 0 && u.blocks + u.pid >= limit
}

// Everything `rekey_check` needs to know about one key id.
Key_Usage :: struct {
	tx, rx:             Usage, // current key; in the epoch format, the current epoch key
	tx_pkts, rx_pkts:   u64, // all epochs of this key id
	tx_bytes, rx_bytes: u64, // payload bytes, all epochs of this key id
	tx_epoch:           u16, // epoch format only
}

// Settings that decide when a key is replaced.
Rekey_Policy :: struct {
	cipher:         ossl.Aead_Cipher,
	format:         Format,
	reneg_sec:      i64, // seconds since the key became active; 0 = off. A server: see `reneg_sec_jitter`
	reneg_bytes:    u64, // bytes in plus out on this key; 0 = off
	reneg_pkts:     u64, // packets in plus out on this key; 0 = off
	limit_override: u64, // replaces the AEAD usage limit when not 0 (for tests; stock has a hidden option for it)
}

// Why a renegotiation is due, otherwise `None`.
Rekey_Reason :: enum {
	None,
	Age, // reneg-sec
	Bytes, // reneg-bytes
	Packets, // reneg-pkts
	Epoch_Limit, // epoch format: send epoch reached 0xF000
	Packet_Id, // baseline: send packet id is close to wrapping
	Aead_Usage, // baseline: usage limit (7/8 value) on the send or the receive key
	Tag_Failures, // more than 2^35 failed tag checks on the receive key
}

// The AEAD limit that applies to this policy.
policy_limit :: proc "contextless" (p: ^Rekey_Policy) -> u64 {
	if p.limit_override != 0 {
		return p.limit_override
	}
	return usage_limit(p.cipher, p.format)
}

// Should the peer start a renegotiation now? Checks the
// triggers in table order, returns the first that holds. `established` is when
// the key state became active (see `Key_Slots`). The epoch format skips the
// 32-bit packet id and AEAD usage rules (the sender moves to the next epoch;
// see package crypt).
rekey_check :: proc "contextless" (p: ^Rekey_Policy, established, now: time.Duration, u: ^Key_Usage) -> Rekey_Reason {
	if p.reneg_sec > 0 && now - established >= time.Duration(p.reneg_sec) * time.Second {
		return .Age
	}
	if p.reneg_bytes > 0 && u.tx_bytes + u.rx_bytes >= p.reneg_bytes {
		return .Bytes
	}
	if p.reneg_pkts > 0 && u.tx_pkts + u.rx_pkts >= p.reneg_pkts {
		return .Packets
	}
	switch p.format {
	case .Epoch:
		if u.tx_epoch >= EPOCH_REKEY_AT {
			return .Epoch_Limit
		}
	case .Baseline:
		if u.tx.pid >= PACKET_ID_REKEY_AT {
			return .Packet_Id
		}
		limit := policy_limit(p)
		if usage_reached(limit, u.tx) || usage_reached(limit, u.rx) {
			return .Aead_Usage
		}
	}
	if u.rx.tag_fail > TAG_FAIL_REKEY {
		return .Tag_Failures
	}
	return .None
}

// The effective `reneg-sec` of a server: the configured value minus a random
// amount up to 10 percent, so clients do not all rekey at once. `rand` is a
// random u32 from the caller. A value of 0 or less returns unchanged.
reneg_sec_jitter :: proc "contextless" (reneg_sec: i64, rand: u32) -> i64 {
	if reneg_sec <= 0 {
		return reneg_sec
	}
	span := max(reneg_sec / 10, 1)
	return reneg_sec - i64(rand) % span
}
