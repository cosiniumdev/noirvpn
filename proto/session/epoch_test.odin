// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:testing"
import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"

// The epoch data format in the session. Tests:
// - format follows the pushed `aead-epoch`
// - send epoch moves by the usage limit and by the peer
// - a future epoch of the peer opens a window
// - keys of different key ids keep their own chains
// - the limits of 6.4 and 6.7
//
// The client runs against the fake server (a spec-strict peer built from the
// crypt package) and the real server session (`Duo`). The fake hands out packets
// of its own keys, so a test can build any order of epochs.

// ------------------------------------------------------------------ helpers

// A small usage limit for a test: with 100-byte payloads (8 blocks) it moves the
// epoch about every 10 packets.
SMALL_LIMIT :: 90

limit_small :: proc(m: ^Sim) {
	m.cfg.limit_override = SMALL_LIMIT
}

// Echoes of `total` packets (the bench keeps 32 at a time). Returns how many
// came back unchanged.
echo_many :: proc(m: ^Sim, total, payload: int) -> (ok: int) {
	for left := total; left > 0; left -= 30 {
		ok += sim_echo(m, min(left, 30), payload)
	}
	return
}

duo_echo_many :: proc(d: ^Duo, total, payload: int) -> (ok: int) {
	for left := total; left > 0; left -= 30 {
		ok += duo_echo(d, 0, min(left, 30), payload)
	}
	return
}

// The data key of key id `kid` in the client session.
client_dk :: proc(m: ^Sim, kid: u8 = 0) -> ^crypt.Data_Key {
	return &m.s.dp.dk[m.s.dp.dk_of[kid]]
}

// One packet of the fake server for the client, created with the fake's own send
// key (its counters and epoch). `seq` is the tunnel packet number.
fake_packet :: proc(m: ^Sim, seq: u16) -> (pkt: [LINK_BUF_SIZE]u8, n: int) {
	head, _ := format_room(.Epoch)
	ip: [256]u8
	plen := make_ip_packet(ip[:], 60, seq)
	copy(pkt[head:], ip[:plen])
	f := &m.f
	err: crypt.Error
	n, err = crypt.data_key_seal(&f.dk[f.tx_kid], u32(f.o.peer_id), pkt[head:][:plen], pkt[:])
	if err != .None {
		panic("the fake could not seal")
	}
	return
}

// Hands one packet to the client (a UDP datagram). Returns whether a tunnel packet came out and
// which one it was (its sequence number).
feed_pkt :: proc(m: ^Sim, pkt: [LINK_BUF_SIZE]u8, n: int) -> (got: bool, seq: u16) {
	p := pkt
	r := session_receive(&m.s, p[:n], m.now)
	if len(r.tunnel) < 28 {
		return false, 0
	}
	return true, u16(r.tunnel[26]) << 8 | u16(r.tunnel[27])
}

// The fake moves its send epoch one step (as a sender that reached its limit).
fake_next_epoch :: proc(m: ^Sim) {
	if crypt.tx_next_epoch(&m.f.dk[m.f.tx_kid].tx) != .None {
		panic("the fake could not move on")
	}
}

epoch_connect :: proc(t: ^testing.T, o: Fake_Opts, tweak: proc(m: ^Sim) = nil, loc := #caller_location) -> ^Sim {
	opts := o
	opts.epoch = true
	m := connect(t, opts, 0, tweak, loc)
	if m == nil {
		return nil
	}
	testing.expect_value(t, session_data_format(&m.s), keys.Format.Epoch, loc = loc)
	tx, rx := session_epochs(&m.s)
	testing.expect_value(t, tx, 1, loc = loc)
	testing.expect_value(t, rx, 1, loc = loc)
	return m
}

// ----------------------------------------------------------- negotiation

@(test)
test_epoch_udp_none :: proc(t: ^testing.T) {
	check_basic(t, {epoch = true})
}

@(test)
test_epoch_udp_tls_auth :: proc(t: ^testing.T) {
	check_basic(t, {epoch = true, mode = .Tls_Auth, key_direction = .One})
}

@(test)
test_epoch_udp_tls_crypt_dyn :: proc(t: ^testing.T) {
	check_basic(t, {epoch = true, mode = .Tls_Crypt, dyn = true, cc_exit = true})
}

@(test)
test_epoch_udp_tls_crypt_v2_aes128 :: proc(t: ^testing.T) {
	check_basic(t, {epoch = true, mode = .Tls_Crypt_V2, cipher = .Aes_128_Gcm})
}

@(test)
test_epoch_udp_chacha :: proc(t: ^testing.T) {
	check_basic(t, {epoch = true, mode = .Tls_Crypt, cipher = .Chacha20_Poly1305})
}

@(test)
test_epoch_tcp :: proc(t: ^testing.T) {
	check_basic(t, {epoch = true, mode = .Tls_Crypt, transport = .Tcp})
	// Frames cut in odd places: the epoch packet has its length prefix in front
	// of a header that starts earlier in the buffer than the baseline one.
	check_basic(t, {epoch = true, mode = .Tls_Crypt, transport = .Tcp}, chunk = 7)
}

// `aead-epoch` needs a peer id (the push check of the client).
@(test)
test_epoch_without_peer_id_refused :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, epoch = true, no_peer_id = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Push)
}

// The packet the client sends is exactly the epoch layout, also with the
// header placed in front of the payload.
@(test)
test_epoch_client_packet_layout :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	buf: [LINK_BUF_SIZE]u8
	n := make_ip_packet(buf[TUNNEL_HEADROOM:], 100, 7)
	pkt, err := session_encap(&m.s, buf[:], n, m.now)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(pkt), crypt.EPOCH_HEADROOM + n + crypt.EPOCH_TAILROOM)
	testing.expect_value(t, len(pkt), n + session_seal_overhead(&m.s))
	testing.expect_value(t, pkt[0], u8(0x48))
	// The payload did not move.
	testing.expect_value(t, uintptr(raw_data(pkt)) + uintptr(crypt.EPOCH_HEADROOM), uintptr(raw_data(buf[TUNNEL_HEADROOM:])))
	epoch, counter, ok := crypt.epoch_peek(pkt)
	testing.expect(t, ok, "no epoch in the packet")
	testing.expect_value(t, epoch, u16(1))
	testing.expect(t, counter >= 1, "counter 0")
	// A buffer without the 16 bytes for the tag is refused.
	short: [TUNNEL_HEADROOM + 100]u8
	_, serr := session_encap(&m.s, short[:], 100, m.now)
	testing.expect_value(t, serr, Error.Buffer_Too_Small)
}

// ----------------------------------------------------------------- advance

// The client's usage limit moves its send epoch; the fake follows it (6.6) and
// its replies cause the client's receive epoch to follow in turn.
@(test)
test_epoch_client_advances :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt}, limit_small)
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, echo_many(m, 60, 100), 60)
	tx, _ := session_epochs(&m.s)
	testing.expectf(t, tx >= 5, "the send epoch did not move (%d)", tx)
	c := session_counters(&m.s)
	testing.expect(t, c.epoch_adv_tx >= 1 && c.epoch_adv_tx <= u64(tx - 1), "send advances not counted")
	testing.expect(t, c.epoch_adv_rx >= 1, "the receive epoch did not follow the fake")
	// The fake's receive window moved with the client's send epoch.
	frx := crypt.rx_epoch(&m.f.dk[0].rx)
	testing.expect(t, frx >= tx - 1 && frx <= tx, "fake receive epoch out of step")
	testing.expect_value(t, m.f.data_bad, 0)
	testing.expect_value(t, c.drop_data_tag, 0)
	testing.expect_value(t, c.drop_data_epoch, 0)
	testing.expect_value(t, c.drop_data_replay, 0)
	testing.expect_value(t, c.drop_data_no_key, 0)
}

// The fake runs into its limit: the client receives a higher epoch, and its own
// send epoch follows (6.6 step 3).
@(test)
test_epoch_server_advances :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt, limit = SMALL_LIMIT})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, echo_many(m, 60, 100), 60)
	tx, rx := session_epochs(&m.s)
	testing.expectf(t, rx >= 5, "the receive epoch did not move (%d)", rx)
	testing.expect(t, tx >= rx, "the send epoch is below the receive epoch")
	c := session_counters(&m.s)
	testing.expect(t, c.epoch_adv_rx >= 4, "receive advances not counted")
	testing.expect(t, c.epoch_adv_tx >= 1, "the send epoch did not follow")
	testing.expect_value(t, m.f.data_bad, 0)
	testing.expect_value(t, c.drop_data_tag, 0)
	testing.expect_value(t, c.drop_data_epoch, 0)
}

// Limits on both sides, over TCP: the epochs go up in step.
@(test)
test_epoch_advances_both_tcp :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt, transport = .Tcp, limit = SMALL_LIMIT}, limit_small)
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, echo_many(m, 80, 100), 80)
	tx, rx := session_epochs(&m.s)
	testing.expect(t, tx >= 5 && rx >= 5, "epochs did not move")
	testing.expect_value(t, m.f.data_bad, 0)
	testing.expect_value(t, m.s.state, State.Up)
}

// ------------------------------------------------------------ future window

// A packet from an epoch ahead of the current one opens it (6.6): the old
// current epoch is retiring and still takes late packets, skipped epochs are
// gone, the send epoch follows.
@(test)
test_epoch_future_window :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	late1, n1 := fake_packet(m, 1) // epoch 1
	late2, n2 := fake_packet(m, 2) // epoch 1
	fake_next_epoch(m)
	skipped, ns := fake_packet(m, 3) // epoch 2
	fake_next_epoch(m)
	fake_next_epoch(m)
	ahead, na := fake_packet(m, 4) // epoch 4: three ahead

	// A forged packet of epoch 4 changes nothing.
	bad := ahead
	bad[na - 1] ~= 0x01
	got := false
	got, _ = feed_pkt(m, bad, na)
	testing.expect(t, !got, "a forged packet was taken")
	tx, rx := session_epochs(&m.s)
	testing.expect_value(t, rx, 1)
	testing.expect_value(t, tx, 1)
	testing.expect_value(t, m.s.counters.drop_data_tag, 1)

	// The real one opens epoch 4.
	seq: u16
	got, seq = feed_pkt(m, ahead, na)
	testing.expect(t, got && seq == 4, "the future packet was not taken")
	tx, rx = session_epochs(&m.s)
	testing.expect_value(t, rx, 4)
	testing.expect_value(t, tx, 4) // the send epoch is never below the receive epoch
	c := session_counters(&m.s)
	testing.expect_value(t, c.epoch_adv_rx, 1)
	testing.expect_value(t, c.epoch_adv_tx, 1) // one move of the send chain, over three epochs

	// Epoch 1 is retiring: its late packets are still taken, once.
	got, seq = feed_pkt(m, late2, n2)
	testing.expect(t, got && seq == 2, "a late packet of the retiring epoch was dropped")
	got, _ = feed_pkt(m, late2, n2)
	testing.expect(t, !got, "a replay in the retiring epoch was taken")
	got, seq = feed_pkt(m, late1, n1)
	testing.expect(t, got && seq == 1, "the older late packet was dropped")
	testing.expect_value(t, m.s.counters.drop_data_replay, 1)

	// Epoch 2 was skipped for good.
	got, _ = feed_pkt(m, skipped, ns)
	testing.expect(t, !got, "a packet of a skipped epoch was taken")
	testing.expect_value(t, m.s.counters.drop_data_epoch, 1)

	// A replay of the new epoch.
	got, _ = feed_pkt(m, ahead, na)
	testing.expect(t, !got, "a replay in the current epoch was taken")
	testing.expect_value(t, m.s.counters.drop_data_replay, 2)

	// And the link still works: the client now sends in epoch 4, which the fake
	// has in its window.
	testing.expect_value(t, sim_echo(m, 4, 80), 4)
	testing.expect_value(t, m.f.data_bad, 0)
}

// The window is four epochs: the fifth is not taken and changes nothing. A
// packet of epoch 0 is never taken.
@(test)
test_epoch_window_limits :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	for _ in 0 ..< 4 {
		fake_next_epoch(m)
	}
	edge, ne := fake_packet(m, 1) // epoch 5 = 1 + 4
	fake_next_epoch(m)
	far, nf := fake_packet(m, 2) // epoch 6 = 1 + 5

	got := false
	got, _ = feed_pkt(m, far, nf)
	testing.expect(t, !got, "epoch r + 5 was taken")
	testing.expect_value(t, m.s.counters.drop_data_epoch, 1)
	_, rx := session_epochs(&m.s)
	testing.expect_value(t, rx, 1)

	// Epoch 0 (here: the epoch field of a good packet set to 0).
	zero := edge
	zero[4], zero[5] = 0, 0
	got, _ = feed_pkt(m, zero, ne)
	testing.expect(t, !got, "epoch 0 was taken")
	testing.expect_value(t, m.s.counters.drop_data_epoch, 2)

	seq: u16
	got, seq = feed_pkt(m, edge, ne)
	testing.expect(t, got && seq == 1, "epoch r + 4 was not taken")
	_, rx = session_epochs(&m.s)
	testing.expect_value(t, rx, 5)
	// Now epoch 6 is the next one, and so on: the window moved.
	got, seq = feed_pkt(m, far, nf)
	testing.expect(t, got && seq == 2, "the next epoch was not taken after the move")
	_, rx = session_epochs(&m.s)
	testing.expect_value(t, rx, 6)
}

// Replay state is per epoch key: an id that was used in epoch 1 is new in epoch
// 2, and the replay window of the retiring epoch keeps what it has seen.
@(test)
test_epoch_replay_across_the_change :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	a1, na1 := fake_packet(m, 11)
	a2, na2 := fake_packet(m, 12)
	a3, na3 := fake_packet(m, 13)
	fake_next_epoch(m)
	b1, nb1 := fake_packet(m, 21) // counter 1 of epoch 2

	got := false
	got, _ = feed_pkt(m, a1, na1)
	testing.expect(t, got, "a1")
	got, _ = feed_pkt(m, a3, na3)
	testing.expect(t, got, "a3 (a gap)")
	got, _ = feed_pkt(m, b1, nb1) // epoch 2 opens
	testing.expect(t, got, "b1")
	_, rx := session_epochs(&m.s)
	testing.expect_value(t, rx, 2)
	// Seen before the change: replays stay replays.
	got, _ = feed_pkt(m, a1, na1)
	testing.expect(t, !got, "a1 replayed after the change")
	got, _ = feed_pkt(m, a3, na3)
	testing.expect(t, !got, "a3 replayed after the change")
	got, _ = feed_pkt(m, b1, nb1)
	testing.expect(t, !got, "b1 replayed")
	// The gap is still open in the retiring window.
	seq: u16
	got, seq = feed_pkt(m, a2, na2)
	testing.expect(t, got && seq == 12, "a2 (late, in the gap) was dropped")
	got, _ = feed_pkt(m, a2, na2)
	testing.expect(t, !got, "a2 replayed")
	testing.expect_value(t, m.s.counters.drop_data_replay, 4)
	testing.expect_value(t, m.s.counters.drop_data_tag, 0)

	// Next epoch: epoch 1 is gone now (only the previous one is kept).
	fake_next_epoch(m)
	c1, nc1 := fake_packet(m, 31)
	got, _ = feed_pkt(m, c1, nc1)
	testing.expect(t, got, "c1")
	got, _ = feed_pkt(m, a2, na2)
	testing.expect(t, !got, "a packet of epoch 1 after two moves")
	testing.expect_value(t, m.s.counters.drop_data_epoch, 1)
}

// ------------------------------------------------------------------ rekey

// A rekey without the echo traffic of `rekey_cycle`, so the new key is still
// at epoch 1 afterwards.
rekey_quiet :: proc(t: ^testing.T, m: ^Sim, by_client: bool, loc := #caller_location) {
	if by_client {
		testing.expect(t, session_rekey(&m.s, m.now), "session_rekey refused", loc = loc)
	} else {
		fake_rekey(&m.f, m.now)
	}
	ok := sim_run(m, proc(m: ^Sim) -> bool {
		return m.s.state == .Up && m.s.ks.state == .Generated_Keys && !m.s.rekeying && m.f.installed
	}, 60 * time.Second)
	testing.expect(t, ok, "rekey did not finish", loc = loc)
}

// A new key id has its own chain, back at epoch 1; the old key keeps its chain
// while it is the lame key.
@(test)
test_epoch_rekey_chains :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt, dyn = true}, limit_small)
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, echo_many(m, 40, 100), 40)
	tx0, _ := session_epochs(&m.s)
	testing.expect(t, tx0 >= 3, "the first key did not advance")
	rekey_quiet(t, m, true)
	tx1, rx1 := session_epochs(&m.s)
	testing.expect_value(t, tx1, 1)
	testing.expect_value(t, rx1, 1)
	// Key 0 is the lame key: its chain is where it was. The fake still sends on it.
	k0 := client_dk(m, 0)
	testing.expect(t, crypt.tx_epoch(&k0.tx) >= tx0, "the lame key lost its epoch")
	testing.expect_value(t, session_data_format(&m.s), keys.Format.Epoch)
	m.f.tx_kid = 0
	testing.expect_value(t, sim_echo(m, 5, 100), 5)
	testing.expect_value(t, m.s.counters.drop_data_no_key, 0)
	m.f.tx_kid = 1
	// More traffic on the new key moves its epochs again, independent of key 0.
	testing.expect_value(t, echo_many(m, 60, 100), 60)
	tx1b, _ := session_epochs(&m.s)
	testing.expect(t, tx1b > tx1, "the new key did not advance")
	// The totals of the session count both keys, also after key 0 is freed.
	adv := session_counters(&m.s).epoch_adv_tx
	rekey_cycle(t, m, false)
	rekey_cycle(t, m, true)
	testing.expect(t, session_counters(&m.s).epoch_adv_tx >= adv, "advances lost with a freed key")
	testing.expect_value(t, m.f.data_bad, 0)
	testing.expect_value(t, m.s.counters.drop_data_tag, 0)
}

@(test)
test_epoch_rekey_by_client :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt, dyn = true, epoch = true}, true)
}

@(test)
test_epoch_rekey_by_server :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt, dyn = true, epoch = true}, false)
}

@(test)
test_epoch_rekey_tcp :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt, dyn = true, epoch = true, transport = .Tcp}, true, rounds = 2)
}

// ------------------------------------------------------------------ limits

// A send epoch of 0xF000 asks for a renegotiation (6.4, 6.7). The jump is done
// by moving the chain. The fake cannot read those packets, which does not
// matter here.
@(test)
test_epoch_rekey_at_0xf000 :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	// Just below the line: nothing starts.
	testing.expect_value(t, crypt.tx_follow_epoch(&client_dk(m, 0).tx, keys.EPOCH_REKEY_AT - 1), crypt.Error.None)
	for _ in 0 ..< 600 {
		m.tunnel_n = 0
		sim_send_ip(m, 50, 1)
	}
	testing.expect(t, !m.s.rekeying, "a rekey started below 0xF000")
	// On the line.
	testing.expect_value(t, crypt.tx_next_epoch(&client_dk(m, 0).tx), crypt.Error.None)
	for _ in 0 ..< 600 {
		sim_send_ip(m, 50, 1)
	}
	testing.expect(t, m.s.rekeying || m.s.ks.id == 1, "no rekey at epoch 0xF000")
	ok := sim_run(m, proc(m: ^Sim) -> bool {
		return m.s.state == .Up && m.s.ks.id == 1 && m.s.ks.state == .Generated_Keys && !m.s.rekeying
	}, 60 * time.Second)
	testing.expect(t, ok, "the rekey did not finish")
	tx, rx := session_epochs(&m.s)
	testing.expect_value(t, tx, 1)
	testing.expect_value(t, rx, 1)
	expect_echo(t, m)
}

// The last epoch with the last counter: the key cannot send any more. The
// session sends nothing with it, starts a rekey, and the new key works.
@(test)
test_epoch_exhausted_key_rekeys :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	dk := client_dk(m, 0)
	testing.expect_value(t, crypt.tx_follow_epoch(&dk.tx, keys.EPOCH_MAX), crypt.Error.None)
	dk.tx.st.last_id = crypt.EPOCH_COUNTER_MAX
	buf: [LINK_BUF_SIZE]u8
	n := make_ip_packet(buf[TUNNEL_HEADROOM:], 50, 1)
	_, err := session_encap(&m.s, buf[:], n, m.now)
	testing.expect_value(t, err, Error.No_Key)
	testing.expect(t, m.s.rekeying, "no rekey after the key was used up")
	ok := sim_run(m, proc(m: ^Sim) -> bool {
		return m.s.state == .Up && m.s.ks.id == 1 && m.s.ks.state == .Generated_Keys && !m.s.rekeying
	}, 60 * time.Second)
	testing.expect(t, ok, "the rekey did not finish")
	expect_echo(t, m)
}

// ------------------------------------------------------- the real server

epoch_duo_pair :: proc(t: ^testing.T, o: Duo_Opts, tweak: proc(d: ^Duo) = nil, loc := #caller_location) -> ^Duo {
	d := duo_connect(t, o, tweak, loc)
	if d == nil {
		return nil
	}
	return d
}

@(test)
duo_epoch_is_negotiated :: proc(t: ^testing.T) {
	for transport in ([]Transport{.Udp, .Tcp}) {
		d := epoch_duo_pair(t, {mode = .Tls_Crypt, transport = transport})
		if d == nil {
			return
		}
		defer duo_free(d)
		c, s := &d.peers[0].c, duo_srv(d)
		testing.expect_value(t, session_data_format(c), keys.Format.Epoch)
		testing.expect_value(t, session_data_format(s), keys.Format.Epoch)
		testing.expect(t, .Aead_Epoch in session_protocol_flags(c), "client: no aead-epoch")
		testing.expect(t, .Aead_Epoch in session_protocol_flags(s), "server: no aead-epoch")
		duo_expect_echo(t, d)
		tx, rx := session_epochs(c)
		testing.expect_value(t, tx, 1)
		testing.expect_value(t, rx, 1)
	}
}

// A client without bit 10 gets the baseline format; so does a client of a
// server that does not offer the flag. Each session decides for itself.
@(test)
duo_epoch_fallback_to_baseline :: proc(t: ^testing.T) {
	// The client does not offer it.
	d := epoch_duo_pair(t, {mode = .Tls_Crypt, n = 2}, proc(d: ^Duo) {
		d.peers[0].cfg.iv_proto = DEFAULT_IV_PROTO - {.Data_Epoch}
	})
	if d == nil {
		return
	}
	// Client 0 is baseline, client 1 epoch, on the same server.
	testing.expect_value(t, session_data_format(&d.peers[0].c), keys.Format.Baseline)
	testing.expect_value(t, session_data_format(duo_srv(d, 0)), keys.Format.Baseline)
	testing.expect(t, .Aead_Epoch not_in session_protocol_flags(duo_srv(d, 0)), "pushed to a client that did not offer it")
	testing.expect_value(t, session_data_format(&d.peers[1].c), keys.Format.Epoch)
	testing.expect_value(t, session_data_format(duo_srv(d, 1)), keys.Format.Epoch)
	duo_expect_echo(t, d, 0)
	duo_expect_echo(t, d, 1)
	// A rekey keeps each session's format.
	testing.expect(t, session_rekey(&d.peers[0].c, d.now), "rekey")
	testing.expect(t, session_rekey(&d.peers[1].c, d.now), "rekey")
	duo_idle(d, 5 * time.Second)
	testing.expect_value(t, session_data_format(&d.peers[0].c), keys.Format.Baseline)
	testing.expect_value(t, session_data_format(&d.peers[1].c), keys.Format.Epoch)
	duo_expect_echo(t, d, 0)
	duo_expect_echo(t, d, 1)
	duo_free(d)

	// The server does not offer it.
	d = epoch_duo_pair(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.flags = {.Cc_Exit, .Dyn_Tls_Crypt}
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, session_data_format(&d.peers[0].c), keys.Format.Baseline)
	testing.expect_value(t, session_data_format(duo_srv(d)), keys.Format.Baseline)
	duo_expect_echo(t, d)
}

// Both our sessions move epochs, by their own limits, in both directions, and a
// rekey in the middle starts the chains again.
@(test)
duo_epoch_advances_and_rekeys :: proc(t: ^testing.T) {
	d := epoch_duo_pair(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.limit_override = SMALL_LIMIT
		d.peers[0].cfg.limit_override = SMALL_LIMIT
		d.peers[0].cfg.reneg_sec = -1
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	c, s := &d.peers[0].c, duo_srv(d)
	testing.expect_value(t, duo_echo_many(d, 50, 100), 50)
	ctx, crx := session_epochs(c)
	stx, srx := session_epochs(s)
	testing.expect(t, ctx >= 4 && crx >= 4 && stx >= 4 && srx >= 4, "epochs did not move")
	testing.expect(t, ctx >= crx && stx >= srx, "a send epoch is below the receive epoch")
	// Epochs of the two ends stay close: each side's send epoch is the other's
	// receive epoch, at most one ahead (the packet in flight).
	testing.expect(t, ctx >= srx - 1 && ctx <= srx + 1, "client send and server receive epochs apart")
	testing.expect(t, stx >= crx - 1 && stx <= crx + 1, "server send and client receive epochs apart")
	cc, sc := session_counters(c), session_counters(s)
	testing.expect(t, cc.epoch_adv_tx >= 3 && cc.epoch_adv_rx >= 3, "client counters")
	testing.expect(t, sc.epoch_adv_tx >= 3 && sc.epoch_adv_rx >= 3, "server counters")
	// A rekey started by the server: a fresh chain on both ends.
	testing.expect(t, session_rekey(s, d.now), "server rekey")
	duo_idle(d, 5 * time.Second)
	testing.expect_value(t, c.ks.id, u8(1))
	testing.expect_value(t, s.ks.id, u8(1))
	ctx, crx = session_epochs(c)
	testing.expect(t, ctx <= 2 && crx <= 2, "the new key did not start at epoch 1")
	testing.expect_value(t, duo_echo_many(d, 50, 100), 50)
	ctx2, _ := session_epochs(c)
	testing.expect(t, ctx2 > ctx, "the new key did not advance")
	cc = session_counters(c)
	testing.expect(t, cc.epoch_adv_tx >= 3, "client advances lost at the rekey")
	for x in ([]^Session{c, s}) {
		k := session_counters(x)
		testing.expect_value(t, k.drop_data_tag, 0)
		testing.expect_value(t, k.drop_data_epoch, 0)
		testing.expect_value(t, k.drop_data_no_key, 0)
	}
	testing.expect_value(t, c.state, State.Up)
	testing.expect_value(t, s.state, State.Up)
}

// Reordered and duplicated packets across epoch changes, both ends ours.
@(test)
duo_epoch_reorder_and_duplicates :: proc(t: ^testing.T) {
	d := epoch_duo_pair(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.limit_override = SMALL_LIMIT
		d.peers[0].cfg.limit_override = SMALL_LIMIT
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	p := &d.peers[0]
	p.swap_c2s, p.swap_s2c = true, true
	testing.expect(t, duo_echo_many(d, 60, 100) >= 60, "reordered data lost across epochs")
	p.swap_c2s, p.swap_s2c = false, false
	p.dup_c2s, p.dup_s2c = true, true
	testing.expect_value(t, duo_echo_many(d, 60, 100), 60)
	testing.expect(t, duo_srv(d).counters.drop_data_replay >= 60, "duplicates not counted")
	testing.expect_value(t, duo_srv(d).counters.drop_data_tag, 0)
	testing.expect_value(t, p.c.counters.drop_data_tag, 0)
}

// ------------------------------------------------------------ the grace key

// A stock peer keeps sending on its old key for a while after a rekey. If a
// second rekey follows soon, those packets arrive on the key before the lame key.
// They still open for `DEFAULT_LAME_GRACE` after the new key is installed, also
// through the handshake of the next soft reset; the key is gone when that time ends.
grace_case :: proc(t: ^testing.T, epoch: bool) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true, epoch = epoch}, 0)
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, echo_many(m, 10, 100), 10)
	rekey_quiet(t, m, true) // key 1; key 0 is the lame key
	m.f.tx_kid = 0 // the fake keeps sending on its old key
	testing.expect_value(t, sim_echo(m, 5, 100), 5)

	// The second soft reset begins: key 0 is the lame key and stays through the handshake.
	testing.expect(t, session_rekey(&m.s, m.now), "session_rekey refused")
	testing.expect(t, keys.slots_rx_ok(&m.s.slots, 0, m.now), "key 0 dropped when the soft reset began")
	ok := sim_run(m, proc(m: ^Sim) -> bool {
		return m.s.state == .Up && m.s.ks.state == .Generated_Keys && !m.s.rekeying && m.f.installed
	}, 60 * time.Second)
	testing.expect(t, ok, "second rekey did not finish")
	m.f.tx_kid = 0
	// Key 2 is the primary, key 1 the lame key, key 0 the grace key: all three are in use.
	testing.expect_value(t, keys.slots_in_use(&m.s.slots), keys.Key_Id_Set{0, 1, 2})
	testing.expect_value(t, sim_echo(m, 5, 100), 5)
	testing.expect_value(t, m.s.counters.drop_data_no_key, 0)
	testing.expect_value(t, m.f.data_bad, 0)

	// After the grace time the key is gone. Traffic on the new key keeps the session alive
	// (the ping timeout is 60 s).
	for _ in 0 ..< 7 {
		m.f.tx_kid = 2
		testing.expect_value(t, sim_echo(m, 2, 100), 2)
		sim_idle(m, 10 * time.Second)
	}
	testing.expect_value(t, m.s.state, State.Up)
	testing.expect(t, !keys.slots_rx_ok(&m.s.slots, 0, m.now), "key 0 still there after the grace time")
	testing.expect_value(t, m.s.dp.dk_of[0], i8(-1))
	m.f.tx_kid = 0
	testing.expect_value(t, sim_echo(m, 3, 100), 0)
	testing.expect(t, m.s.counters.drop_data_no_key >= 3, "packets on the freed key were not counted")
	m.f.tx_kid = 2
	testing.expect_value(t, sim_echo(m, 3, 100), 3)
}

@(test)
test_lame_key_grace_baseline :: proc(t: ^testing.T) {
	grace_case(t, false)
}

@(test)
test_lame_key_grace_epoch :: proc(t: ^testing.T) {
	grace_case(t, true)
}

// The next soft reset drops the grace key at once; the lame key stays, and there are
// never more than three keys with crypto state.
@(test)
test_lame_key_grace_next_rekey :: proc(t: ^testing.T) {
	m := epoch_connect(t, {mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	rekey_quiet(t, m, true) // key 1
	rekey_quiet(t, m, false) // key 2 (by the server): key 0 is the grace key
	testing.expect_value(t, keys.slots_in_use(&m.s.slots), keys.Key_Id_Set{0, 1, 2})
	rekey_quiet(t, m, true) // key 3: the soft reset drops key 0, the install sets key 1 as the grace key
	testing.expect_value(t, keys.slots_in_use(&m.s.slots), keys.Key_Id_Set{1, 2, 3})
	testing.expect_value(t, m.s.dp.dk_of[0], i8(-1))
	used := 0
	for u in m.s.dp.dk_used {
		if u {
			used += 1
		}
	}
	testing.expect_value(t, used, 3)
	m.f.tx_kid = 1
	testing.expect_value(t, sim_echo(m, 3, 100), 3)
	m.f.tx_kid = 0
	testing.expect_value(t, sim_echo(m, 3, 100), 0)
	// Ten more rekeys: the key ids wrap and nothing runs out of key slots.
	for i in 0 ..< 10 {
		rekey_quiet(t, m, i % 2 == 0)
	}
	testing.expect_value(t, m.s.state, State.Up)
	testing.expect_value(t, session_counters(&m.s).rekeys, u64(13))
}
