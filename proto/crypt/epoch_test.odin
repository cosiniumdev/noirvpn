// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "core:testing"
import "noir:proto/keys"
import "noir:proto/ossl"

@(private = "file")
payload :: proc(n: int) -> []u8 {
	p := make([]u8, n, context.temp_allocator)
	for &b, i in p {
		b = u8(i)
	}
	p[0] = 0x45
	return p
}

@(private = "file")
seal_one :: proc(t: ^testing.T, dk: ^Data_Key, n: int = 64) -> []u8 {
	pkt := make([]u8, n + packet_overhead(.Epoch), context.temp_allocator)
	len_, err := data_key_seal(dk, 0, payload(n), pkt)
	testing.expect_value(t, err, Error.None)
	return pkt[:len_]
}

@(private = "file")
open_one :: proc(dk: ^Data_Key, pkt: []u8) -> (Open_Result, Error) {
	out := make([]u8, len(pkt), context.temp_allocator)
	return data_key_open(dk, pkt, out)
}

// With a tiny usage limit the sender moves to the next epoch every few
// packets. Both peers talk in turn, so each follows the other epoch by epoch.
@(test)
epoch_iteration_under_a_small_limit :: proc(t: ^testing.T) {
	for cipher in ossl.Aead_Cipher {
		// 64-byte packets are 6 blocks. blocks + id = 7 per packet: the limit
		// of 30 is reached after the 5th packet of an epoch.
		client, server, ok := make_pair(t, .Epoch, cipher, 0, 3, {limit_override = 30})
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		advanced := 0
		for i in 1 ..= 100 {
			pkt := seal_one(t, &client)
			epoch, counter, _ := epoch_peek(pkt)
			// Epoch changes after the 5th packet; each epoch's counter starts at 1.
			testing.expect_value(t, epoch, u16(1 + (i - 1) / 5))
			testing.expect_value(t, counter, u64(1 + (i - 1) % 5))
			res, err := open_one(&server, pkt)
			if !testing.expectf(t, err == .None, "%v packet %d: %v", cipher, i, err) {
				return
			}
			if res.epoch_advanced {
				advanced += 1
			}
			// The server's own send epoch follows what it received.
			testing.expect_value(t, tx_epoch(&server.tx), epoch)
			// Its response is in the same epoch, except after the 5th packet of an
			// epoch. That packet fills the server's receive key, so by rule 2 the
			// server moves on and the client follows.
			reply_epoch := epoch + 1 if counter == 5 else epoch
			reply := seal_one(t, &server, 10)
			res2, err2 := open_one(&client, reply)
			if !testing.expectf(t, err2 == .None, "%v reply %d: %v", cipher, i, err2) {
				return
			}
			testing.expect_value(t, res2.epoch, reply_epoch)
			testing.expect_value(t, rx_epoch(&client.rx), reply_epoch)
			testing.expect_value(t, tx_epoch(&client.tx), reply_epoch)
		}
		// The last packet was the 5th of epoch 20, so both senders ended in 21.
		testing.expect_value(t, tx_epoch(&client.tx), 21)
		testing.expect_value(t, rx_epoch(&server.rx), 20)
		testing.expect_value(t, tx_epoch(&server.tx), 21)
		testing.expect_value(t, advanced, 19) // the server went from epoch 1 to 20
		// The epoch the sender is in is the epoch for the rekey rule too.
		u := data_key_usage(&client)
		testing.expect_value(t, u.tx_epoch, 21)
		// Counters of the key id cover all epochs.
		testing.expect_value(t, u.tx_pkts, 100)
		testing.expect_value(t, u.tx_bytes, 6400)
	}
}

// Rule 2: a sender in the same epoch as its receive key
// moves on when the receive key hits the limit, which causes the peer to follow.
@(test)
epoch_sender_pushes_when_receive_key_is_full :: proc(t: ^testing.T) {
	client, server, ok := make_pair(t, .Epoch, .AES_256_GCM, 0, 9, {limit_override = 30})
	if !ok {
		return
	}
	defer data_key_destroy(&client)
	defer data_key_destroy(&server)
	// The server only sends for a while; the client only receives and its
	// receive key fills up (7 per packet: 30 is reached at packet 5).
	for i in 1 ..= 4 {
		_, err := open_one(&client, seal_one(t, &server))
		testing.expectf(t, err == .None, "packet %d: %v", i, err)
		testing.expect_value(t, tx_epoch(&client.tx), 1)
	}
	// The server's own limit moved its sender on only at its 5th packet; the
	// client's receive key is full after the 5th it received.
	pkt5 := seal_one(t, &server)
	_, err := open_one(&client, pkt5)
	testing.expect_value(t, err, Error.None)
	u := rx_usage(&client.rx)
	testing.expect(t, keys.usage_reached(client.rx.limit, u), "receive key at its limit")
	testing.expect_value(t, tx_epoch(&client.tx), 1)

	// The client sends: it moves to epoch 2 first.
	pkt := seal_one(t, &client)
	epoch, counter, _ := epoch_peek(pkt)
	testing.expect_value(t, epoch, 2)
	testing.expect_value(t, counter, 1)
	// The server follows (a future epoch), and its response comes in epoch 2.
	res, err2 := open_one(&server, pkt)
	testing.expect_value(t, err2, Error.None)
	testing.expect(t, res.epoch_advanced, "server moved to epoch 2")
	reply := seal_one(t, &server)
	epoch, _, _ = epoch_peek(reply)
	testing.expect_value(t, epoch, 2)
	// The client's receive key is a fresh one: nothing is left of the pressure.
	_, err = open_one(&client, reply)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, rx_epoch(&client.rx), 2)
	pkt2 := seal_one(t, &client)
	epoch, _, _ = epoch_peek(pkt2)
	testing.expect_value(t, epoch, 2) // no further move
	// Too many failed tag checks on the receive key push the same way.
	set_tag_fail(&client.rx, keys.TAG_FAIL_REKEY + 1)
	pkt3 := seal_one(t, &client)
	epoch, _, _ = epoch_peek(pkt3)
	testing.expect_value(t, epoch, 3)
}

// A peer that is more than one epoch ahead (here 2): the receiver takes it
// at once; the epoch it skipped is gone; the old one is kept as retiring.
@(test)
epoch_future_key_window :: proc(t: ^testing.T) {
	client, server, ok := make_pair(t, .Epoch, .AES_256_GCM)
	if !ok {
		return
	}
	defer data_key_destroy(&client)
	defer data_key_destroy(&server)
	// Packets of epoch 1, created before the jump. Hold them back for later.
	old1 := seal_one(t, &client)
	old2 := seal_one(t, &client)
	old3 := seal_one(t, &client)
	testing.expect_value(t, tx_follow_epoch(&client.tx, 3), Error.None)
	e3a := seal_one(t, &client)
	e3b := seal_one(t, &client)
	epoch, counter, _ := epoch_peek(e3a)
	testing.expect_value(t, epoch, 3)
	testing.expect_value(t, counter, 1)

	// A forged epoch-3 packet (bad tag) changes nothing.
	forged := make([]u8, len(e3a), context.temp_allocator)
	copy(forged, e3a)
	forged[len(forged) - 1] ~= 0x80
	_, err := open_one(&server, forged)
	testing.expect_value(t, err, Error.Bad_Tag)
	testing.expect_value(t, rx_epoch(&server.rx), 1)
	testing.expect_value(t, tx_epoch(&server.tx), 1)
	// Forged: valid length, a fake epoch inside the window.
	forged[4], forged[5] = 0, 2
	_, err = open_one(&server, forged)
	testing.expect_value(t, err, Error.Bad_Tag)
	testing.expect_value(t, rx_epoch(&server.rx), 1)

	// Epoch 1 still opens.
	_, err = open_one(&server, old1)
	testing.expect_value(t, err, Error.None)
	// The real epoch-3 packet: authenticated, the window moves.
	res, err2 := open_one(&server, e3a)
	testing.expect_value(t, err2, Error.None)
	testing.expect(t, res.epoch_advanced, "advanced")
	testing.expect_value(t, res.epoch, 3)
	testing.expect_value(t, rx_epoch(&server.rx), 3)
	// The server's sender is not lower than its receiver (6.6 step 3).
	testing.expect_value(t, tx_epoch(&server.tx), 3)
	// Next in the same epoch: the epoch stays. Duplicates are refused.
	res, err2 = open_one(&server, e3b)
	testing.expect_value(t, err2, Error.None)
	testing.expect(t, !res.epoch_advanced, "same epoch")
	_, err2 = open_one(&server, e3b)
	testing.expect_value(t, err2, Error.Replay)
	// Epoch 1 is the retiring key now: late packets still open, with their own
	// replay window.
	_, err2 = open_one(&server, old2)
	testing.expect_value(t, err2, Error.None)
	_, err2 = open_one(&server, old2)
	testing.expect_value(t, err2, Error.Replay)
	// Epoch 2 was skipped: no key for it any more.
	other, other_server, ok2 := make_pair(t, .Epoch, .AES_256_GCM)
	if !ok2 {
		return
	}
	defer data_key_destroy(&other)
	defer data_key_destroy(&other_server)
	testing.expect_value(t, tx_follow_epoch(&other.tx, 2), Error.None)
	_, err2 = open_one(&server, seal_one(t, &other))
	testing.expect_value(t, err2, Error.Unknown_Epoch)

	// The peer moves on to epoch 4: epoch 3 is retiring, epoch 1 is dropped.
	testing.expect_value(t, tx_next_epoch(&client.tx), Error.None)
	e4 := seal_one(t, &client)
	res, err2 = open_one(&server, e4)
	testing.expect_value(t, err2, Error.None)
	testing.expect(t, res.epoch_advanced, "advanced to 4")
	_, err2 = open_one(&server, old3)
	testing.expect_value(t, err2, Error.Unknown_Epoch)
}

@(test)
epoch_window_limits :: proc(t: ^testing.T) {
	client, server, ok := make_pair(t, .Epoch, .AES_128_GCM)
	if !ok {
		return
	}
	defer data_key_destroy(&client)
	defer data_key_destroy(&server)
	// Receive epoch 1: epochs 2 to 5 are inside the window, 6 is not.
	for to in 2 ..= 6 {
		c, c_server, c_ok := make_pair(t, .Epoch, .AES_128_GCM) // same export, fresh counters
		if !c_ok {
			return
		}
		defer data_key_destroy(&c)
		defer data_key_destroy(&c_server)
		testing.expect_value(t, tx_follow_epoch(&c.tx, u16(to)), Error.None)
		pkt := seal_one(t, &c)
		res, err := open_one(&server, pkt)
		if to <= 5 {
			testing.expectf(t, err == .None, "epoch %d: %v", to, err)
			testing.expect(t, res.epoch_advanced, "advanced")
			// A fresh server for the next round.
			data_key_destroy(&server)
			_, server, ok = make_pair(t, .Epoch, .AES_128_GCM)
			if !ok {
				return
			}
		} else {
			testing.expect_value(t, err, Error.Unknown_Epoch)
			testing.expect_value(t, rx_epoch(&server.rx), 1)
		}
	}

	// Epoch 0 in the packet is dropped before anything else, and so is counter 0.
	pkt := seal_one(t, &client)
	zero_epoch := make([]u8, len(pkt), context.temp_allocator)
	copy(zero_epoch, pkt)
	zero_epoch[4], zero_epoch[5] = 0, 0
	_, err := open_one(&server, zero_epoch)
	testing.expect_value(t, err, Error.Unknown_Epoch)
	zero_counter := make([]u8, len(pkt), context.temp_allocator)
	copy(zero_counter, pkt)
	for i in 6 ..< 12 {
		zero_counter[i] = 0
	}
	_, err = open_one(&server, zero_counter)
	testing.expect_value(t, err, Error.Bad_Packet_Id)
	testing.expect_value(t, rx_usage(&server.rx).tag_fail, 0)
	// The genuine packet is fine.
	_, err = open_one(&server, pkt)
	testing.expect_value(t, err, Error.None)
}

// The same counter value in two epochs is two different packets, each once.
@(test)
epoch_replay_is_per_epoch :: proc(t: ^testing.T) {
	client, server, ok := make_pair(t, .Epoch, .CHACHA20_POLY1305)
	if !ok {
		return
	}
	defer data_key_destroy(&client)
	defer data_key_destroy(&server)
	e1 := seal_one(t, &client)
	testing.expect_value(t, tx_next_epoch(&client.tx), Error.None)
	e2 := seal_one(t, &client)
	_, c1, _ := epoch_peek(e1)
	_, c2, _ := epoch_peek(e2)
	testing.expect_value(t, c1, c2) // both counter 1
	_, err := open_one(&server, e1)
	testing.expect_value(t, err, Error.None)
	_, err = open_one(&server, e2)
	testing.expect_value(t, err, Error.None)
	_, err = open_one(&server, e1)
	testing.expect_value(t, err, Error.Replay)
	_, err = open_one(&server, e2)
	testing.expect_value(t, err, Error.Replay)
}

// Walks the sender through many epochs and compares each packet with one generated
// directly from the key schedule in package keys.
@(test)
epoch_packets_match_the_key_schedule :: proc(t: ^testing.T) {
	export := fake_export(11)
	cm, _ := keys.derive_material(export[:], .Client, .AES_256_GCM)
	defer keys.material_wipe(&cm)
	tx: Tx_Key
	testing.expect_value(t, tx_init(&tx, .Epoch, .AES_256_GCM, 2, &cm.send), Error.None)
	defer tx_destroy(&tx)

	chain: keys.Epoch_Key
	_ = keys.epoch_send_init(&chain, cm.send.e1[:], 32)
	pt := payload(100)
	for epoch in 1 ..= 8 {
		if epoch > 1 {
			testing.expect_value(t, tx_next_epoch(&tx), Error.None)
			testing.expect_value(t, keys.epoch_send_advance(&chain, u16(epoch)), keys.Error.None)
		}
		kc: Key_Ctx
		testing.expect_value(t, key_ctx_init_epoch(&kc, .AES_256_GCM, chain.key[:32], chain.iv[:], .Seal), Error.None)
		defer key_ctx_destroy(&kc)
		for ctr in 1 ..= 3 {
			got := make([]u8, 100 + packet_overhead(.Epoch), context.temp_allocator)
			want := make([]u8, 100 + packet_overhead(.Epoch), context.temp_allocator)
			n, err := tx_seal(&tx, 1, pt, got)
			testing.expect_value(t, err, Error.None)
			m, err2 := epoch_seal(&kc, 2, 1, u16(epoch), u64(ctr), pt, want)
			testing.expect_value(t, err2, Error.None)
			expect_bytes(t, got[:n], want[:m], "epoch packet")
		}
	}
}
