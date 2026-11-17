// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "core:testing"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/wire"

@(private = "file")
payload :: proc(n: int, seed: u8 = 0) -> []u8 {
	p := make([]u8, n, context.temp_allocator)
	for &b, i in p {
		b = u8(i) ~ seed
	}
	// Look like an IPv4 packet so classification says tunnel.
	if n > 0 {
		p[0] = 0x45
	}
	return p
}

// Every cipher and format, sizes from 1 byte up to a full MTU, out of place
// and in place, in both directions.
@(test)
roundtrip_all_ciphers_and_formats :: proc(t: ^testing.T) {
	rng := Rng {
		s = 12345,
	}
	sizes := [?]int{1, 2, 15, 16, 17, 63, 64, 65, 255, 512, 1399, 1400, 1500, 9000}
	for format in keys.Format {
		for cipher in ossl.Aead_Cipher {
			client, server, ok := make_pair(t, format, cipher)
			if !ok {
				continue
			}
			defer data_key_destroy(&client)
			defer data_key_destroy(&server)
			headroom := packet_overhead(format) - (EPOCH_TAILROOM if format == .Epoch else 0)
			for size in sizes {
				pt := payload(size, u8(size))
				// Out of place, client to server.
				pkt := make([]u8, size + packet_overhead(format), context.temp_allocator)
				n, err := data_key_seal(&client, 7, pt, pkt)
				testing.expect_value(t, err, Error.None)
				testing.expect_value(t, n, size + packet_overhead(format))
				out := make([]u8, size, context.temp_allocator)
				res, oerr := data_key_open(&server, pkt[:n], out)
				testing.expect_value(t, oerr, Error.None)
				testing.expect_value(t, res.peer_id, 7)
				expect_bytes(t, out[:res.n], pt, "plaintext")

				// In place, server to client: read the payload into its final
				// place, seal, then open where it lies.
				buf := make([]u8, size + packet_overhead(format), context.temp_allocator)
				body := buf[headroom:][:size]
				copy(body, pt)
				n, err = data_key_seal(&server, 7, body, buf)
				testing.expect_value(t, err, Error.None)
				if format == .Baseline {
					// Ciphertext differs from plaintext (a 1-byte one could match by chance).
					if size > 8 {
						testing.expect(t, !bytes_same(buf[headroom:][:size], pt), "payload was not encrypted")
					}
				}
				res, oerr = data_key_open(&client, buf[:n], buf[headroom:])
				testing.expect_value(t, oerr, Error.None)
				expect_bytes(t, buf[headroom:][:res.n], pt, "in-place plaintext")
			}
			// Random sizes and contents.
			for _ in 0 ..< 200 {
				size := 1 + rng_below(&rng, 1500)
				pt := make([]u8, size, context.temp_allocator)
				rng_fill(&rng, pt)
				pkt := make([]u8, size + packet_overhead(format), context.temp_allocator)
				n, err := data_key_seal(&client, 0xFFFFFF, pt, pkt)
				testing.expect_value(t, err, Error.None)
				out := make([]u8, size, context.temp_allocator)
				res, oerr := data_key_open(&server, pkt[:n], out)
				testing.expect_value(t, oerr, Error.None)
				expect_bytes(t, out[:res.n], pt, "random plaintext")
			}
		}
	}
}

@(private = "file")
bytes_same :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

@(test)
packet_layout_is_as_specified :: proc(t: ^testing.T) {
	// Baseline: header, packet id, tag, ciphertext. Epoch: header, epoch,
	// counter, ciphertext, tag.
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .AES_256_GCM, 5)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := payload(40)
		pkt := make([]u8, 40 + packet_overhead(format), context.temp_allocator)
		n, _ := data_key_seal(&client, 0x010203, pt, pkt)
		testing.expect_value(t, pkt[0], 0x48 | 5)
		expect_bytes(t, pkt[1:4], []u8{1, 2, 3}, "peer id")
		if format == .Baseline {
			testing.expect_value(t, n, 24 + 40)
			expect_bytes(t, pkt[4:8], []u8{0, 0, 0, 1}, "packet id")
		} else {
			testing.expect_value(t, n, 12 + 40 + 16)
			expect_bytes(t, pkt[4:12], []u8{0, 1, 0, 0, 0, 0, 0, 1}, "epoch 1, counter 1")
		}
		_, _ = data_key_seal(&client, 0x010203, pt, pkt)
		if format == .Baseline {
			expect_bytes(t, pkt[4:8], []u8{0, 0, 0, 2}, "second packet id")
		} else {
			expect_bytes(t, pkt[4:12], []u8{0, 1, 0, 0, 0, 0, 0, 2}, "second counter")
		}
	}
}

@(test)
seal_argument_errors :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .AES_128_GCM)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := payload(32)
		oh := packet_overhead(format)
		pkt := make([]u8, 32 + oh, context.temp_allocator)

		// A buffer that is one byte short, and nothing was counted for it.
		_, err := data_key_seal(&client, 0, pt, pkt[:32 + oh - 1])
		testing.expect_value(t, err, Error.Buffer_Too_Small)
		testing.expect_value(t, client.tx.st.last_id, 0)
		// Peer id above 24 bits.
		_, err = data_key_seal(&client, 0x1000000, pt, pkt)
		testing.expect_value(t, err, Error.Bad_Argument)
		testing.expect_value(t, client.tx.st.last_id, 0)
		// An empty payload is refused.
		_, err = data_key_seal(&client, 0, nil, pkt)
		testing.expect_value(t, err, Error.Bad_Argument)
		// The largest peer id and the "no peer id" value are fine.
		for pid in ([?]u32{0, 1, wire.PEER_ID_MAX, wire.PEER_ID_UNDEFINED}) {
			n, serr := data_key_seal(&client, pid, pt, pkt)
			testing.expect_value(t, serr, Error.None)
			hdr, _, _ := wire.data_v2_decode(pkt[:n])
			testing.expect_value(t, hdr.peer_id, pid)
		}
		testing.expect_value(t, client.tx.st.last_id, 4) // only the good ones counted

		// Overlap that is not the exact in-place form.
		buf := make([]u8, 64 + oh, context.temp_allocator)
		copy(buf[oh:], pt)
		_, err = data_key_seal(&client, 0, buf[oh - 1:][:32], buf)
		testing.expect_value(t, err, Error.Buffer_Overlap)
		_, err = data_key_seal(&client, 0, buf[:32], buf)
		testing.expect_value(t, err, Error.Buffer_Overlap)
		testing.expect_value(t, client.tx.st.last_id, 4)

		// Open: output too small, and bad overlap.
		n, _ := data_key_seal(&client, 0, pt, pkt)
		_, err = data_key_open(&server, pkt[:n], make([]u8, 31, context.temp_allocator))
		testing.expect_value(t, err, Error.Buffer_Too_Small)
		_, err = data_key_open(&server, pkt[:n], pkt[:32])
		testing.expect_value(t, err, Error.Buffer_Overlap)
		// Nothing of that touched the replay window or the counters.
		testing.expect_value(t, server.rx.pkts, 0)
	}
}

@(test)
open_rejects_other_packets :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .CHACHA20_POLY1305, 3)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := payload(20)
		pkt := make([]u8, 20 + packet_overhead(format), context.temp_allocator)
		n, _ := data_key_seal(&client, 0, pt, pkt)
		out := make([]u8, 64, context.temp_allocator)
		min_len := packet_overhead(format) // header and tag, no payload

		// Too short: every length below the minimum.
		for l in 0 ..< min_len {
			_, err := data_key_open(&server, pkt[:l], out)
			testing.expectf(t, err == .Too_Short, "length %d: %v", l, err)
		}
		// Other opcodes: control packets and P_DATA_V1.
		for first in ([?]u8{0x20 | 3, 0x28 | 3, 0x38 | 3, 0x30 | 3, 0x00, 0x58 | 3, 0xF8 | 3}) {
			bad := make([]u8, n, context.temp_allocator)
			copy(bad, pkt[:n])
			bad[0] = first
			_, err := data_key_open(&server, bad, out)
			testing.expectf(t, err == .Not_Data_Packet, "first byte %02x: %v", first, err)
		}
		// Another key id.
		for kid in u8(0) ..< 8 {
			if kid == 3 {
				continue
			}
			bad := make([]u8, n, context.temp_allocator)
			copy(bad, pkt[:n])
			bad[0] = 0x48 | kid
			_, err := data_key_open(&server, bad, out)
			testing.expectf(t, err == .Wrong_Key_Id, "key id %d: %v", kid, err)
		}
		// None of the above counted as a failed tag check.
		testing.expect_value(t, rx_usage(&server.rx).tag_fail, 0)
		// A good one still works.
		_, err := data_key_open(&server, pkt[:n], out)
		testing.expect_value(t, err, Error.None)
	}
}

// Baseline: the packet id counts up; at 2^32 - 1 the key is used up.
@(test)
baseline_packet_id_exhaustion :: proc(t: ^testing.T) {
	client, server, ok := make_pair(t, .Baseline, .AES_256_GCM)
	if !ok {
		return
	}
	defer data_key_destroy(&client)
	defer data_key_destroy(&server)
	pt := payload(10)
	pkt := make([]u8, 10 + BASELINE_HEADROOM, context.temp_allocator)
	out := make([]u8, 10, context.temp_allocator)

	// Jump the counter close to the end.
	client.tx.st.last_id = 0xFFFF_FFFD
	n, err := data_key_seal(&client, 0, pt, pkt)
	testing.expect_value(t, err, Error.None)
	pid, _ := baseline_peek_pid(pkt[:n])
	testing.expect_value(t, pid, 0xFFFF_FFFE)
	// The rekey trigger fires long before this (0xFF000000).
	p := keys.Rekey_Policy {
		cipher = .AES_256_GCM,
		format = .Baseline,
	}
	u := data_key_usage(&client)
	testing.expect_value(t, keys.rekey_check(&p, 0, 0, &u), keys.Rekey_Reason.Packet_Id)

	// The last usable id is 2^32 - 1, and it opens.
	n, err = data_key_seal(&client, 0, pt, pkt)
	testing.expect_value(t, err, Error.None)
	pid, _ = baseline_peek_pid(pkt[:n])
	testing.expect_value(t, pid, 0xFFFF_FFFF)
	res, oerr := data_key_open(&server, pkt[:n], out)
	testing.expect_value(t, oerr, Error.None)
	testing.expect_value(t, res.id, 0xFFFF_FFFF)

	// Then nothing: the id would wrap. It stays an error however often it is tried.
	for _ in 0 ..< 3 {
		_, err = data_key_seal(&client, 0, pt, pkt)
		testing.expect_value(t, err, Error.Packet_Id_Exhausted)
		testing.expect_value(t, client.tx.st.last_id, 0xFFFF_FFFF)
	}
	// The key table can stop using this key for sending.
	slots: keys.Key_Slots
	keys.slots_init(&slots)
	_, _ = keys.slots_install(&slots, 0, 0)
	keys.slots_block_tx(&slots, 0)
	_, can := keys.slots_tx_key(&slots, 1)
	testing.expect(t, !can, "blocked key must not be chosen")
}

// Epoch: the counter limit moves the sender to the next epoch; at the last
// epoch there is nowhere to go.
@(test)
epoch_counter_exhaustion :: proc(t: ^testing.T) {
	client, server, ok := make_pair(t, .Epoch, .AES_128_GCM)
	if !ok {
		return
	}
	defer data_key_destroy(&client)
	defer data_key_destroy(&server)
	pt := payload(10)
	pkt := make([]u8, 10 + packet_overhead(.Epoch), context.temp_allocator)
	out := make([]u8, 10, context.temp_allocator)

	client.tx.st.last_id = EPOCH_COUNTER_MAX - 1
	n, err := data_key_seal(&client, 0, pt, pkt)
	testing.expect_value(t, err, Error.None)
	epoch, counter, _ := epoch_peek(pkt[:n])
	testing.expect_value(t, epoch, 1)
	testing.expect_value(t, counter, EPOCH_COUNTER_MAX) // the last usable counter
	res, oerr := data_key_open(&server, pkt[:n], out)
	testing.expect_value(t, oerr, Error.None)
	testing.expect_value(t, res.id, EPOCH_COUNTER_MAX)

	// Next packet: a new epoch, counter 1.
	n, err = data_key_seal(&client, 0, pt, pkt)
	testing.expect_value(t, err, Error.None)
	epoch, counter, _ = epoch_peek(pkt[:n])
	testing.expect_value(t, epoch, 2)
	testing.expect_value(t, counter, 1)
	res, oerr = data_key_open(&server, pkt[:n], out)
	testing.expect_value(t, oerr, Error.None)
	testing.expect(t, res.epoch_advanced, "epoch 2 is a future epoch for the server")
	testing.expect_value(t, rx_epoch(&server.rx), 2)

	// At the last epoch: used up.
	testing.expect_value(t, tx_follow_epoch(&client.tx, keys.EPOCH_MAX), Error.None)
	testing.expect_value(t, tx_epoch(&client.tx), keys.EPOCH_MAX)
	testing.expect_value(t, client.tx.st.last_id, 0) // fresh counter in the new epoch
	client.tx.st.last_id = EPOCH_COUNTER_MAX
	_, err = data_key_seal(&client, 0, pt, pkt)
	testing.expect_value(t, err, Error.Packet_Id_Exhausted)
	// One packet before the end still works.
	client.tx.st.last_id = EPOCH_COUNTER_MAX - 1
	n, err = data_key_seal(&client, 0, pt, pkt)
	testing.expect_value(t, err, Error.None)
	_, counter, _ = epoch_peek(pkt[:n])
	testing.expect_value(t, counter, EPOCH_COUNTER_MAX)
	// The usage limit does not move it past 65535 either.
	client.tx.st.usage.blocks = keys.USAGE_LIMIT_FULL
	client.tx.st.last_id = 5
	n, err = data_key_seal(&client, 0, pt, pkt)
	testing.expect_value(t, err, Error.None)
	epoch, counter, _ = epoch_peek(pkt[:n])
	testing.expect_value(t, epoch, keys.EPOCH_MAX)
	testing.expect_value(t, counter, 6)
}

@(test)
usage_counters_and_rekey_decision :: proc(t: ^testing.T) {
	// A small usage limit so the baseline rule fires quickly.
	opts := Key_Options {
		limit_override = 100,
	}
	client, server, ok := make_pair(t, .Baseline, .AES_256_GCM, 0, 1, opts)
	if !ok {
		return
	}
	defer data_key_destroy(&client)
	defer data_key_destroy(&server)
	pol := keys.Rekey_Policy {
		cipher         = .AES_256_GCM,
		format         = .Baseline,
		limit_override = 100,
		reneg_pkts     = 1000,
	}
	pt := payload(40) // (40 + 24 + 15) / 16 = 4 blocks
	pkt := make([]u8, 40 + BASELINE_HEADROOM, context.temp_allocator)
	out := make([]u8, 40, context.temp_allocator)
	fired_at := 0
	for i in 1 ..= 40 {
		n, err := data_key_seal(&client, 0, pt, pkt)
		testing.expect_value(t, err, Error.None)
		_, oerr := data_key_open(&server, pkt[:n], out)
		testing.expect_value(t, oerr, Error.None)
		u := data_key_usage(&client)
		testing.expect_value(t, u.tx.pid, u64(i))
		testing.expect_value(t, u.tx.blocks, u64(4 * i))
		testing.expect_value(t, u.tx_pkts, u64(i))
		testing.expect_value(t, u.tx_bytes, u64(40 * i))
		su := data_key_usage(&server)
		testing.expect_value(t, su.rx.pid, u64(i))
		testing.expect_value(t, su.rx.blocks, u64(4 * i))
		testing.expect_value(t, su.rx_pkts, u64(i))
		if fired_at == 0 && keys.rekey_check(&pol, 0, 0, &u) == .Aead_Usage {
			fired_at = i
		}
	}
	// blocks + highest id = 4i + i = 5i >= 100 at i = 20.
	testing.expect_value(t, fired_at, 20)
	// The receiver sees the same numbers.
	su := data_key_usage(&server)
	testing.expect_value(t, keys.rekey_check(&pol, 0, 0, &su), keys.Rekey_Reason.Aead_Usage)

	// The packet counts feed reneg-pkts (both directions together).
	pol.limit_override = 0
	pol.cipher = .CHACHA20_POLY1305
	pol.reneg_pkts = 80
	testing.expect_value(t, keys.rekey_check(&pol, 0, 0, &su), keys.Rekey_Reason.None)
	pol.reneg_pkts = 40
	testing.expect_value(t, keys.rekey_check(&pol, 0, 0, &su), keys.Rekey_Reason.Packets)
}

@(test)
failed_tag_checks_are_counted_and_the_key_gives_up :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .AES_256_GCM)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := payload(30)
		pkt := make([]u8, 30 + packet_overhead(format), context.temp_allocator)
		out := make([]u8, 30, context.temp_allocator)
		n, _ := data_key_seal(&client, 0, pt, pkt)
		forged := make([]u8, n, context.temp_allocator)
		copy(forged, pkt[:n])
		forged[n - 1] ~= 1 // last byte: ciphertext (baseline) or tag (epoch)
		for i in 1 ..= 5 {
			_, err := data_key_open(&server, forged, out)
			testing.expect_value(t, err, Error.Bad_Tag)
			testing.expect_value(t, rx_usage(&server.rx).tag_fail, u64(i))
		}
		// The rekey rule needs more than 2^35.
		su := data_key_usage(&server)
		p := keys.Rekey_Policy {
			cipher = .AES_256_GCM,
			format = format,
		}
		testing.expect_value(t, keys.rekey_check(&p, 0, 0, &su), keys.Rekey_Reason.None)
		set_tag_fail(&server.rx, keys.TAG_FAIL_REKEY + 1)
		su = data_key_usage(&server)
		testing.expect_value(t, keys.rekey_check(&p, 0, 0, &su), keys.Rekey_Reason.Tag_Failures)
		// Still opens genuine packets between 2^35 and 2^36.
		_, err := data_key_open(&server, pkt[:n], out)
		testing.expect_value(t, err, Error.None)
		// Above 2^36 the key refuses everything without trying.
		set_tag_fail(&server.rx, keys.TAG_FAIL_REFUSE + 1)
		n, _ = data_key_seal(&client, 0, pt, pkt)
		_, err = data_key_open(&server, pkt[:n], out)
		testing.expect_value(t, err, Error.Key_Disabled)
	}
}

set_tag_fail :: proc(rx: ^Rx_Key, v: u64) {
	switch &b in rx.body {
	case Baseline_Rx:
		b.st.usage.tag_fail = v
	case Epoch_Rx:
		b.slot[b.chain.current].st.usage.tag_fail = v
	}
}

// Forged packets must not move the replay window or any counter. The hard case
// is a high packet id with a bad tag: if it advanced the window, the genuine
// packets after it would be lost.
@(test)
forged_packets_do_not_advance_the_window :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .AES_128_GCM)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := payload(50)
		oh := packet_overhead(format)
		pkts: [5][]u8
		for i in 0 ..< 5 {
			buf := make([]u8, 50 + oh, context.temp_allocator)
			n, _ := data_key_seal(&client, 0, pt, buf)
			pkts[i] = buf[:n]
		}
		out := make([]u8, 50, context.temp_allocator)
		// A forgery with a huge id and a random tag.
		forged := make([]u8, len(pkts[0]), context.temp_allocator)
		copy(forged, pkts[0])
		if format == .Baseline {
			forged[4], forged[5], forged[6], forged[7] = 0x7F, 0xFF, 0xFF, 0xFF
		} else {
			forged[8] = 0x7F // counter 2^31 + 1
		}
		for _ in 0 ..< 10 {
			_, err := data_key_open(&server, forged, out)
			testing.expect_value(t, err, Error.Bad_Tag)
		}
		testing.expect_value(t, rx_usage(&server.rx).pid, 0)
		testing.expect_value(t, server.rx.pkts, 0)
		// All genuine packets still open, in any order.
		for i in ([?]int{2, 0, 4, 1, 3}) {
			_, err := data_key_open(&server, pkts[i], out)
			testing.expectf(t, err == .None, "packet %d: %v", i, err)
		}
		// And now they are replays.
		for i in 0 ..< 5 {
			_, err := data_key_open(&server, pkts[i], out)
			testing.expectf(t, err == .Replay, "packet %d again: %v", i, err)
		}
		testing.expect_value(t, rx_usage(&server.rx).pid, 5)
		testing.expect_value(t, server.rx.pkts, 5)
	}
}

// A window of 64: ids older than 64 behind the newest are refused even though
// they are genuine; with a larger window they pass.
@(test)
reordering_depth_follows_the_window_size :: proc(t: ^testing.T) {
	for bits in ([?]int{64, 256}) {
		client, server, ok := make_pair(t, .Baseline, .AES_256_GCM, 0, 1, {replay_bits = bits})
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := payload(20)
		all: [100][]u8
		for i in 0 ..< len(all) {
			buf := make([]u8, 20 + BASELINE_HEADROOM, context.temp_allocator)
			n, _ := data_key_seal(&client, 0, pt, buf)
			all[i] = buf[:n]
		}
		out := make([]u8, 20, context.temp_allocator)
		_, err := data_key_open(&server, all[99], out) // id 100 first
		testing.expect_value(t, err, Error.None)
		_, err = data_key_open(&server, all[36], out) // id 37: 100 - 37 = 63
		testing.expect_value(t, err, Error.None)
		_, err = data_key_open(&server, all[35], out) // id 36: 64 behind
		testing.expect_value(t, err, bits == 64 ? Error.Replay : Error.None)
	}
}

@(test)
destroy_is_safe_and_wipes :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .AES_256_GCM)
		if !ok {
			continue
		}
		data_key_destroy(&client)
		data_key_destroy(&server)
		// A destroyed key refuses to work and may be destroyed again.
		pkt := make([]u8, 100, context.temp_allocator)
		_, err := data_key_seal(&client, 0, payload(10), pkt)
		testing.expect(t, err != .None, "sealing with a destroyed key")
		_, err = data_key_open(&server, pkt, pkt)
		testing.expect(t, err != .None, "opening with a destroyed key")
		data_key_destroy(&client)
		data_key_destroy(&server)
	}
}

// The override only lowers the limit: a higher value cannot weaken a key.
@(test)
limit_override_only_lowers :: proc(t: ^testing.T) {
	testing.expect_value(t, effective_limit(0, 1000), u64(1000))
	testing.expect_value(t, effective_limit(100, 1000), u64(100))
	testing.expect_value(t, effective_limit(5000, 1000), u64(1000))
	testing.expect_value(t, effective_limit(100, 0), u64(100))
	testing.expect_value(t, effective_limit(0, 0), u64(0))
}
