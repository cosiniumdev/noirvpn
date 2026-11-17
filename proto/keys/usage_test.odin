// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:testing"
import "core:time"
import "noir:proto/ossl"

@(test)
usage_limit_constants :: proc(t: ^testing.T) {
	// 2^36 - 1 and 7/8 of it (integer division).
	testing.expect_value(t, USAGE_LIMIT_FULL, 68_719_476_735)
	testing.expect_value(t, USAGE_LIMIT_BASELINE, 60_129_542_137)
	testing.expect_value(t, usage_limit(.AES_128_GCM, .Baseline), 60_129_542_137)
	testing.expect_value(t, usage_limit(.AES_256_GCM, .Baseline), 60_129_542_137)
	testing.expect_value(t, usage_limit(.AES_128_GCM, .Epoch), 68_719_476_735)
	testing.expect_value(t, usage_limit(.AES_256_GCM, .Epoch), 68_719_476_735)
	// ChaCha20-Poly1305 has none, in either format.
	testing.expect_value(t, usage_limit(.CHACHA20_POLY1305, .Baseline), 0)
	testing.expect_value(t, usage_limit(.CHACHA20_POLY1305, .Epoch), 0)
}

@(test)
blocks_counted_per_packet :: proc(t: ^testing.T) {
	// ceil((payload + 24) / 16)
	testing.expect_value(t, blocks_for(0), 2)
	testing.expect_value(t, blocks_for(1), 2)
	testing.expect_value(t, blocks_for(8), 2)
	testing.expect_value(t, blocks_for(9), 3)
	testing.expect_value(t, blocks_for(64), 6)
	testing.expect_value(t, blocks_for(1400), 89)
}

@(test)
usage_counting_and_limit :: proc(t: ^testing.T) {
	u: Usage
	usage_count(&u, 1, 64)
	usage_count(&u, 2, 64)
	// Out of order: the highest id counts.
	usage_count(&u, 5, 64)
	usage_count(&u, 3, 64)
	testing.expect_value(t, u.pid, 5)
	testing.expect_value(t, u.blocks, 24)

	// blocks + highest id, compared with >=.
	limit := u64(100)
	u = {
		blocks = 60,
		pid    = 39,
	}
	testing.expect(t, !usage_reached(limit, u), "99 < 100")
	u.pid = 40
	testing.expect(t, usage_reached(limit, u), "100 reached")
	u.pid = 41
	testing.expect(t, usage_reached(limit, u), "101")
	testing.expect(t, !usage_reached(0, u), "no limit")
}

@(private = "file")
policy :: proc(cipher := ossl.Aead_Cipher.AES_256_GCM, format := Format.Baseline) -> Rekey_Policy {
	return {cipher = cipher, format = format}
}

@(test)
rekey_none_by_default :: proc(t: ^testing.T) {
	p := policy()
	u: Key_Usage
	testing.expect_value(t, rekey_check(&p, 0, 1000 * time.Hour, &u), Rekey_Reason.None)
	// All thresholds off, so nothing fires however large the counters are.
	u.tx_bytes, u.rx_bytes, u.tx_pkts, u.rx_pkts = 1 << 50, 1 << 50, 1 << 50, 1 << 50
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None)
}

@(test)
rekey_by_age :: proc(t: ^testing.T) {
	p := policy()
	p.reneg_sec = 3600
	u: Key_Usage
	est := 100 * time.Second
	testing.expect_value(t, rekey_check(&p, est, est + 3599 * time.Second, &u), Rekey_Reason.None)
	testing.expect_value(t, rekey_check(&p, est, est + 3600 * time.Second, &u), Rekey_Reason.Age)
	testing.expect_value(t, rekey_check(&p, est, est + 7200 * time.Second, &u), Rekey_Reason.Age)
	// 0 disables it.
	p.reneg_sec = 0
	testing.expect_value(t, rekey_check(&p, est, est + 99999 * time.Second, &u), Rekey_Reason.None)
}

@(test)
rekey_by_bytes_and_packets :: proc(t: ^testing.T) {
	p := policy()
	p.reneg_bytes = 1000
	p.reneg_pkts = 50
	u: Key_Usage
	// Both directions count together.
	u.tx_bytes, u.rx_bytes = 600, 399
	u.tx_pkts, u.rx_pkts = 25, 24
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None)
	u.rx_pkts = 25
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.Packets)
	u.rx_pkts = 0
	u.rx_bytes = 400
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.Bytes)
}

@(test)
rekey_baseline_limits :: proc(t: ^testing.T) {
	p := policy()
	u: Key_Usage
	// Packet id close to wrapping.
	u.tx.pid = PACKET_ID_REKEY_AT - 1
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None)
	u.tx.pid = PACKET_ID_REKEY_AT
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.Packet_Id)
	// The receive packet id does not count for that rule.
	u = {}
	u.rx.pid = 0xFFFF_FFFF
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None)
}

@(test)
rekey_baseline_aead_usage :: proc(t: ^testing.T) {
	p := policy()
	u: Key_Usage
	limit := USAGE_LIMIT_BASELINE
	// Send side: blocks + highest id.
	u.tx.blocks, u.tx.pid = limit - 1000 - 1, 1000
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None)
	u.tx.blocks += 1
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.Aead_Usage)
	// Receive side the same.
	u = {}
	u.rx.blocks, u.rx.pid = limit - 5, 5
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.Aead_Usage)
	// ChaCha20-Poly1305: no limit.
	pc := policy(.CHACHA20_POLY1305)
	testing.expect_value(t, rekey_check(&pc, 0, 0, &u), Rekey_Reason.None)
	// An override replaces the limit.
	pc.limit_override = 10
	u = {}
	u.tx.blocks, u.tx.pid = 9, 1
	testing.expect_value(t, rekey_check(&pc, 0, 0, &u), Rekey_Reason.Aead_Usage)
}

@(test)
rekey_epoch_format :: proc(t: ^testing.T) {
	p := policy(.AES_256_GCM, .Epoch)
	u: Key_Usage
	// The 32-bit id rule and the usage rule do not apply: the sender moves to
	// the next epoch instead.
	u.tx.pid = 0xFFFF_FFFF_FFFF
	u.tx.blocks = USAGE_LIMIT_FULL
	u.rx.blocks = USAGE_LIMIT_FULL
	u.tx_epoch = 3
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None)
	// Send epoch 0xF000 asks for a renegotiation.
	u.tx_epoch = EPOCH_REKEY_AT - 1
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None)
	u.tx_epoch = EPOCH_REKEY_AT
	testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.Epoch_Limit)
	// Time, bytes and packets still apply.
	u.tx_epoch = 1
	p.reneg_sec = 10
	testing.expect_value(t, rekey_check(&p, 0, 10 * time.Second, &u), Rekey_Reason.Age)
}

@(test)
rekey_tag_failures :: proc(t: ^testing.T) {
	for format in Format {
		p := policy(.AES_128_GCM, format)
		u: Key_Usage
		u.rx.tag_fail = TAG_FAIL_REKEY
		testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.None) // "more than 2^35"
		u.rx.tag_fail = TAG_FAIL_REKEY + 1
		testing.expect_value(t, rekey_check(&p, 0, 0, &u), Rekey_Reason.Tag_Failures)
	}
}

@(test)
rekey_order_of_reasons :: proc(t: ^testing.T) {
	// Several triggers at once: the first row of the rekey table wins.
	p := policy()
	p.reneg_sec, p.reneg_bytes = 10, 1
	u: Key_Usage
	u.tx_bytes = 5
	u.tx.pid = PACKET_ID_REKEY_AT
	u.rx.tag_fail = TAG_FAIL_REKEY + 1
	testing.expect_value(t, rekey_check(&p, 0, 11 * time.Second, &u), Rekey_Reason.Age)
	testing.expect_value(t, rekey_check(&p, 0, 5 * time.Second, &u), Rekey_Reason.Bytes)
	p.reneg_bytes = 0
	testing.expect_value(t, rekey_check(&p, 0, 5 * time.Second, &u), Rekey_Reason.Packet_Id)
	u.tx.pid = 0
	testing.expect_value(t, rekey_check(&p, 0, 5 * time.Second, &u), Rekey_Reason.Tag_Failures)
}

@(test)
reneg_jitter_range :: proc(t: ^testing.T) {
	// reneg - (rand mod max(reneg / 10, 1)): at most 10 percent less.
	for r in ([?]u32{0, 1, 359, 360, 361, 0xFFFF_FFFF, 123456789}) {
		got := reneg_sec_jitter(3600, r)
		testing.expectf(t, got > 3240 && got <= 3600, "rand %d: %d", r, got)
	}
	testing.expect_value(t, reneg_sec_jitter(3600, 7), 3593)
	// Small values: reneg / 10 is 0, so the divisor is 1 and nothing is taken off.
	testing.expect_value(t, reneg_sec_jitter(15, 12345), 15)
	testing.expect_value(t, reneg_sec_jitter(100, 7), 93) // 7 mod 10
	testing.expect_value(t, reneg_sec_jitter(0, 7), 0)
	testing.expect_value(t, reneg_sec_jitter(-1, 7), -1)
}
