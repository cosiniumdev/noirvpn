// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:testing"
import "core:time"
import "noir:proto/keys"

// The data channel behind an owner (dataplane.odin). The loopback owner runs on
// the same thread: the session sends commands and packets through `Dp_Remote` to
// its own `Data_Plane`, as with crypto workers. Flows of the other tests must give
// the same results this way.

loop_attach :: proc(s: ^Session) {
	session_set_remote(s, Dp_Remote{submit = loop_submit, seal = loop_seal, open = loop_open})
}

loop_submit :: proc(user: rawptr, dp: ^Data_Plane, cmd: ^Dp_Cmd) {
	if cmd.kind == .Destroy {
		dp_destroy(dp)
		free(dp)
		return
	}
	dp_apply(dp, cmd)
}

loop_seal :: proc(user: rawptr, dp: ^Data_Plane, buf: []u8, n: int, counted: bool, now: Time) -> Dp_Seal {
	return dp_seal(dp, buf, n, counted, now)
}

loop_open :: proc(user: rawptr, dp: ^Data_Plane, pkt: []u8, now: Time) -> Dp_Open {
	return dp_open(dp, pkt, now)
}

remote_sim :: proc(m: ^Sim) {
	m.remote = true
}

remote_rekey_sim :: proc(t: ^testing.T, o: Fake_Opts, by_client: bool, chunk := 0, loc := #caller_location) {
	m := connect(t, o, chunk, remote_sim, loc)
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect(t, session_is_remote(&m.s), "the session is not remote", loc = loc)
	expect_echo(t, m, loc)
	for _ in 0 ..< 3 {
		rekey_cycle(t, m, by_client, loc)
	}
	testing.expect_value(t, m.s.state, State.Up)
	testing.expect_value(t, m.f.data_bad, 0)
	testing.expect_value(t, m.s.counters.drop_data_tag, 0)
	testing.expect_value(t, m.s.counters.drop_data_no_key, 0)
}

@(test)
test_remote_sim_rekey_baseline :: proc(t: ^testing.T) {
	remote_rekey_sim(t, {mode = .Tls_Crypt, dyn = true}, true)
	remote_rekey_sim(t, {mode = .Tls_Crypt, dyn = true}, false)
	remote_rekey_sim(t, {transport = .Tcp}, true, chunk = 700)
}

@(test)
test_remote_sim_rekey_epoch :: proc(t: ^testing.T) {
	remote_rekey_sim(t, {mode = .Tls_Crypt, dyn = true, epoch = true}, true)
	remote_rekey_sim(t, {mode = .Tls_Crypt, dyn = true, epoch = true}, false)
}

// The epoch numbers and the epoch moves are read from the owner's public copy.
@(test)
test_remote_epoch_numbers :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true, epoch = true}, 0, proc(m: ^Sim) {
		m.remote = true
		limit_small(m)
	})
	if m == nil {
		return
	}
	defer sim_free(m)
	tx, rx := session_epochs(&m.s)
	testing.expect_value(t, tx, 1)
	testing.expect_value(t, rx, 1)
	testing.expect_value(t, echo_many(m, 40, 100), 40)
	dp_publish(m.s.rdp)
	tx, _ = session_epochs(&m.s)
	testing.expect(t, tx >= 3, "the send epoch did not move")
	testing.expect(t, session_counters(&m.s).epoch_adv_tx >= 2, "no epoch moves counted")
}

remote_duo :: proc(t: ^testing.T, o: Duo_Opts, who: Who) {
	opts := o
	opts.remote = true
	rekey_duo(t, opts, who, rounds = 2)
}

@(test)
test_remote_duo_rekey :: proc(t: ^testing.T) {
	remote_duo(t, {mode = .Tls_Crypt}, .Client)
	remote_duo(t, {mode = .Tls_Crypt}, .Server)
	remote_duo(t, {mode = .None, transport = .Tcp}, .Client)
}

// A sink that keeps what the session takes.
Taken :: struct {
	pkts:    [8][LINK_BUF_SIZE]u8,
	lens:    [8]int,
	n:       int,
	barrier: int,
}

taken_take :: proc(host: rawptr, s: ^Session, pkt: []u8, now: Time) -> bool {
	k := (^Taken)(host)
	if k.n >= len(k.pkts) {
		return false
	}
	// A real owner opens the packet where it is; the test copies it.
	copy(k.pkts[k.n][:], pkt)
	k.lens[k.n] = len(pkt)
	k.n += 1
	return true
}

taken_barrier :: proc(host: rawptr) {
	(^Taken)(host).barrier += 1
}

// Packets the session keeps for a batch come out in order when the owner has
// opened them; a control packet calls the barrier first.
@(test)
test_remote_take_and_finish :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true, epoch = true}, 0, remote_sim)
	if m == nil {
		return
	}
	defer sim_free(m)
	k: Taken
	m.s.remote.host = &k
	m.s.remote.take = taken_take
	m.s.remote.barrier = taken_barrier
	for i in 0 ..< 5 {
		pkt, n := fake_packet(m, u16(i))
		p := pkt
		r := session_receive(&m.s, p[:n], m.now)
		testing.expect_value(t, len(r.tunnel), 0)
	}
	testing.expect_value(t, k.n, 5)
	testing.expect_value(t, m.s.counters.tunnel_rx, 0)
	// A control packet (a garbage ack) calls the barrier before anything else.
	junk := [?]u8{0x28, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	session_receive(&m.s, junk[:], m.now)
	testing.expect_value(t, k.barrier, 1)
	saved := k.pkts[2]
	// The owner opens the batch; the session finishes it in order.
	for i in 0 ..< k.n {
		pkt := k.pkts[i][:k.lens[i]]
		res := dp_open(m.s.rdp, pkt, m.now)
		testing.expect_value(t, res.code, Dp_Open_Code.Tunnel)
		plain := session_rx_finish(&m.s, pkt, res, m.now)
		testing.expect(t, len(plain) >= 28, "no tunnel packet")
		testing.expect_value(t, u16(plain[26]) << 8 | u16(plain[27]), u16(i))
	}
	testing.expect_value(t, m.s.counters.tunnel_rx, 5)
	// A packet that is opened twice is a replay.
	pkt := k.pkts[2][:k.lens[2]]
	copy(pkt, saved[:k.lens[2]])
	res := dp_open(m.s.rdp, pkt, m.now)
	testing.expect_value(t, res.code, Dp_Open_Code.Replay)
	testing.expect_value(t, len(session_rx_finish(&m.s, pkt, res, m.now)), 0)
	testing.expect_value(t, m.s.counters.drop_data_replay, 1)
}

// The slot tables of the session and of the data plane get the same calls and
// agree: after a rekey and the grace time both have the same keys.
@(test)
test_remote_tables_agree :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true}, 0, remote_sim)
	if m == nil {
		return
	}
	defer sim_free(m)
	rekey_cycle(t, m, true)
	rekey_cycle(t, m, false)
	testing.expect_value(t, keys.slots_in_use(&m.s.slots), keys.slots_in_use(&m.s.rdp.slots))
	// Past the grace time the oldest key goes from both.
	sim_idle(m, 70 * time.Second)
	testing.expect_value(t, keys.slots_in_use(&m.s.slots), keys.slots_in_use(&m.s.rdp.slots))
	testing.expect_value(t, card(keys.slots_in_use(&m.s.slots)), 2)
}

// A result about a key that is no longer the newest (the packet was on the
// worker while the next key was installed) starts no rekey. One about the newest
// key does.
@(test)
test_remote_due_of_an_old_key_is_ignored :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true}, 0, remote_sim)
	if m == nil {
		return
	}
	defer sim_free(m)
	old, _, _ := keys.slots_primary(&m.s.slots)
	rekey_cycle(t, m, true)
	cur, _, ok := keys.slots_primary(&m.s.slots)
	testing.expect(t, ok && cur != old, "the rekey did not install a new key")
	testing.expect(t, !m.s.rekeying, "a rekey still runs")
	n := m.s.counters.rekeys
	now := m.now
	pkt: [16]u8
	session_rx_finish(&m.s, pkt[:], Dp_Open{code = .Ping, due = true, key = old}, now)
	seal_done(&m.s, Dp_Seal{due = true, key = old}, now)
	seal_done(&m.s, Dp_Seal{exhausted = true, key = old}, now)
	testing.expect_value(t, m.s.counters.rekeys, n)
	testing.expect(t, !m.s.rekeying, "a result about the old key started a rekey")
	seal_done(&m.s, Dp_Seal{exhausted = true, key = cur}, now)
	testing.expect_value(t, m.s.counters.rekeys, n + 1)
	testing.expect(t, m.s.rekeying, "a used-up newest key started no rekey")
}
