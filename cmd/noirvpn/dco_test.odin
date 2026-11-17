// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:platform/dco"
import "noir:proto/config"
import "noir:proto/keys"
import "noir:proto/session"

// Tests of the owner of a data channel on a DCO service, against a backend that
// records its calls. No socket, no session: session commands are built by hand.

Call :: struct {
	what:    string,
	slot:    u32,
	key_id:  u32,
	has_fd:  bool,
	peer_id: u32,
	enc0:    u8, // first byte of the send key
}

Fake_Be :: struct {
	calls:    [dynamic]Call,
	fail:     map[string]int, // call name -> status to return
	set_last: dco.Set_Peer,
	addr_last: dco.Set_Peer_Addr,
	stats:    dco.Peer_Stats, // what STATS returns; zero: a fixed set of numbers
	open_idx: u32, // the interface index that OPEN returns
	// TCP: the records of CTRL_TX in order, the read-ahead of the last NEW_PEER, the record that
	// `ctrl_record` returns.
	sent:     [dynamic][]u8,
	ahead:    [dynamic]u8,
	rx:       []u8,
	etext:    string, // what `err_text` returns (a kernel fake)
	filter:   dco.Filter_Stats, // the counters that SET_FILTER returns
	filter_flags: u32, // the flags of the last SET_FILTER
}

fake_be :: proc(f: ^Fake_Be) -> dco.Backend {
	rec :: proc(f: ^Fake_Be, c: Call) -> int {
		append(&f.calls, c)
		return f.fail[c.what] or_else 0
	}
	return dco.Backend {
		user = f,
		open = proc(user: rawptr, name: string, mode: dco.Mode, flags: u32) -> (u32, int) {
			f := (^Fake_Be)(user)
			append(&f.calls, Call{what = "OPEN"})
			if st := f.fail["OPEN"] or_else 0; st != 0 {
				return 0, st
			}
			return f.open_idx, 0
		},
		new_peer = proc(user: rawptr, p: ^dco.New_Peer, fd: i32) -> int {
			f := (^Fake_Be)(user)
			return rec(f, Call{what = "NEW_PEER", peer_id = p.peer_id, has_fd = fd >= 0})
		},
		attach = proc(user: rawptr, fd: i32) -> int {
			return rec((^Fake_Be)(user), Call{what = "ATTACH", has_fd = fd >= 0, peer_id = u32(fd)})
		},
		new_peer_stream = proc(user: rawptr, p: ^dco.New_Peer, fd: i32, ahead: []u8) -> int {
			f := (^Fake_Be)(user)
			clear(&f.ahead)
			append(&f.ahead, ..ahead)
			return rec(f, Call{what = "NEW_PEER_STREAM", peer_id = p.peer_id, has_fd = fd >= 0})
		},
		ctrl_tx = proc(user: rawptr, peer_id: u32, r: []u8) -> int {
			f := (^Fake_Be)(user)
			append(&f.sent, clone_bytes(r))
			return rec(f, Call{what = "CTRL_TX", peer_id = peer_id})
		},
		ctrl_record = proc(user: rawptr) -> []u8 {
			return (^Fake_Be)(user).rx
		},
		set_peer_id = proc(user: rawptr, peer_id, new_id: u32) -> int {
			return rec((^Fake_Be)(user), Call{what = "SET_PEER_ID", peer_id = peer_id, key_id = new_id})
		},
		set_peer_addr = proc(user: rawptr, a: ^dco.Set_Peer_Addr) -> int {
			f := (^Fake_Be)(user)
			f.addr_last = a^
			return rec(f, Call{what = "SET_PEER_ADDR", peer_id = a.peer_id})
		},
		set_filter = proc(user: rawptr, flags: u32, out: ^dco.Filter_Stats) -> int {
			f := (^Fake_Be)(user)
			f.filter_flags = flags
			out^ = f.filter
			return rec(f, Call{what = "SET_FILTER", key_id = flags})
		},
		set_peer = proc(user: rawptr, p: ^dco.Set_Peer) -> int {
			f := (^Fake_Be)(user)
			f.set_last = p^
			return rec(f, Call{what = "SET_PEER", peer_id = p.peer_id})
		},
		del_peer = proc(user: rawptr, peer_id: u32) -> int {
			return rec((^Fake_Be)(user), Call{what = "DEL_PEER", peer_id = peer_id})
		},
		new_key = proc(user: rawptr, k: ^dco.New_Key) -> int {
			return rec((^Fake_Be)(user), Call{what = "NEW_KEY", slot = k.slot, key_id = k.key_id, peer_id = k.peer_id, enc0 = k.enc_key[0]})
		},
		swap_keys = proc(user: rawptr, peer_id: u32) -> int {
			return rec((^Fake_Be)(user), Call{what = "SWAP_KEYS", peer_id = peer_id})
		},
		del_key = proc(user: rawptr, peer_id: u32, slot: dco.Key_Slot) -> int {
			return rec((^Fake_Be)(user), Call{what = "DEL_KEY", slot = u32(slot), peer_id = peer_id})
		},
		key_add = proc(user: rawptr, k: ^dco.Key) -> int {
			return rec((^Fake_Be)(user), Call{what = "KEY_ADD", key_id = k.key_id, peer_id = k.peer_id, enc0 = k.enc_key[0]})
		},
		key_tx = proc(user: rawptr, peer_id, key_id: u32) -> int {
			return rec((^Fake_Be)(user), Call{what = "KEY_TX", key_id = key_id, peer_id = peer_id})
		},
		key_drop = proc(user: rawptr, peer_id, key_id: u32) -> int {
			return rec((^Fake_Be)(user), Call{what = "KEY_DROP", key_id = key_id, peer_id = peer_id})
		},
		stats = proc(user: rawptr, peer_id: u32, out: ^dco.Peer_Stats) -> int {
			f := (^Fake_Be)(user)
			out^ = f.stats
			if out^ == {} {
				out^ = dco.Peer_Stats {
					vpn_rx_bytes   = 100,
					vpn_tx_bytes   = 200,
					vpn_rx_packets = 3,
					vpn_tx_packets = 4,
					link_tx_packets = 5,
				}
			}
			return rec(f, Call{what = "STATS", peer_id = peer_id})
		},
	}
}

Rig :: struct {
	be:   Fake_Be,
	link: Dco_Link,
	o:    Dco_Owner,
	now:  time.Duration,
}

// A link that is up with no descriptor of its own. In the zero value the service
// and kernel descriptors are 0, and `dco_link_close` would close descriptor 0,
// which another test may own.
fake_link_up :: proc(l: ^Dco_Link) {
	l^ = {}
	l.up = true
	l.c.fd = -1
	l.k.ep = -1
	l.k.udp = -1
	l.k.gen.fd = -1
	l.k.ntf.fd = -1
}

rig_init :: proc(r: ^Rig, caps: u32 = 0) {
	fake_link_up(&r.link)
	r.link.be = fake_be(&r.be)
	r.link.be.caps = caps
	r.be.fail = make(map[string]int)
	r.now = time.Second
	dco_owner_init(&r.o, &r.link, keys.Slots_Config{tran_window = 3600 * time.Second, lame_grace = keys.DEFAULT_LAME_GRACE})
}

rig_free :: proc(r: ^Rig) {
	delete(r.be.calls)
	delete(r.be.fail)
	for x in r.be.sent {
		delete(x)
	}
	delete(r.be.sent)
	delete(r.be.ahead)
}

clone_bytes :: proc(b: []u8) -> []u8 {
	c := make([]u8, len(b))
	copy(c, b)
	return c
}

// The names of the calls so far, as "NEW_KEY/0/P DEL_KEY/S ...".
rig_text :: proc(r: ^Rig, from := 0) -> string {
	b: [dynamic]u8
	defer delete(b)
	text := ""
	for c, i in r.be.calls {
		if i < from {
			continue
		}
		part := ""
		switch c.what {
		case "NEW_KEY":
			part = fmt.tprintf("NEW_KEY/%d/%s", c.key_id, "P" if c.slot == 0 else "S")
		case "DEL_KEY":
			part = fmt.tprintf("DEL_KEY/%s", "P" if c.slot == 0 else "S")
		case "KEY_ADD", "KEY_TX", "KEY_DROP":
			part = fmt.tprintf("%s/%d", c.what, c.key_id)
		case "SET_PEER_ID":
			part = fmt.tprintf("SET_PEER_ID/%d>%d", c.peer_id, c.key_id)
		case:
			part = c.what
		}
		text = part if text == "" else fmt.tprintf("%s %s", text, part)
	}
	return text
}

make_install :: proc(id: u8, now: time.Duration, first_byte: u8) -> (cmd: session.Dp_Cmd, m: ^keys.Key_Material) {
	m = new(keys.Key_Material)
	m.send.key_len = 32
	m.recv.key_len = 32
	for i in 0 ..< 32 {
		m.send.key[i] = first_byte + u8(i)
		m.recv.key[i] = 100 + first_byte + u8(i)
	}
	m.send.iv = {1, 2, 3, 4, 5, 6, 7, 8}
	m.recv.iv = {8, 7, 6, 5, 4, 3, 2, 1}
	cmd = session.Dp_Cmd {
		kind     = .Install,
		key_id   = id,
		now      = now,
		material = m,
		cipher   = .AES_256_GCM,
	}
	return
}

submit :: proc(r: ^Rig, cmd: ^session.Dp_Cmd) {
	dco_submit(&r.o, nil, cmd)
}

install :: proc(r: ^Rig, id: u8, first_byte: u8) {
	cmd, m := make_install(id, r.now, first_byte)
	defer free(m)
	submit(r, &cmd)
}

kind :: proc(r: ^Rig, k: session.Dp_Cmd_Kind) {
	cmd := session.Dp_Cmd {
		kind = k,
		now  = r.now,
	}
	submit(r, &cmd)
}

new_peer :: proc(r: ^Rig, id: u32) -> int {
	p := dco.New_Peer {
		peer_id = id,
		flags   = dco.PEER_REMOTE,
	}
	return dco_peer_create(&r.o, &p, 7)
}

@(test)
test_dco_keys_wait_for_the_peer :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	install(&r, 0, 10)
	// Nothing is sent before the peer exists.
	testing.expect_value(t, len(r.be.calls), 0)
	testing.expect_value(t, r.o.n_ops, 1)
	dco_peer_set(&r.o, 10, 60, 1300)
	testing.expect_value(t, len(r.be.calls), 0)
	testing.expect_value(t, new_peer(&r, 77), 0)
	testing.expect_value(t, rig_text(&r), "NEW_PEER NEW_KEY/0/P SET_PEER")
	// The key carries the peer id and the send key as the encryption key.
	testing.expect_value(t, r.be.calls[0].has_fd, true)
	testing.expect_value(t, r.be.calls[1].peer_id, 77)
	testing.expect_value(t, r.be.calls[1].enc0, 10)
	testing.expect_value(t, r.be.set_last.peer_id, 77)
	testing.expect_value(t, r.be.set_last.keepalive_interval, 10)
	testing.expect_value(t, r.be.set_last.keepalive_timeout, 60)
	testing.expect_value(t, r.be.set_last.mss, 1300)
	// The secret is wiped from the queue after it went out.
	testing.expect_value(t, r.o.n_ops, 0)
	for op in r.o.ops {
		testing.expect_value(t, op.key.enc_key[0], 0)
		testing.expect_value(t, op.key.dec_key[0], 0)
	}
	// Later commands go out at once.
	n := len(r.be.calls)
	kind(&r, .Rekey_Started)
	testing.expect_value(t, len(r.be.calls), n)
	install(&r, 1, 20)
	testing.expect_value(t, rig_text(&r, n), "NEW_KEY/1/S SWAP_KEYS")
}

@(test)
test_dco_keys_two_before_the_peer :: proc(t: ^testing.T) {
	// A second key before the peer exists (the first rekey is unlikely, but the
	// order must hold): primary, then secondary and swap.
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	install(&r, 0, 10)
	kind(&r, .Rekey_Started)
	install(&r, 1, 20)
	testing.expect_value(t, new_peer(&r, 5), 0)
	testing.expect_value(t, rig_text(&r), "NEW_PEER NEW_KEY/0/P NEW_KEY/1/S SWAP_KEYS")
}

@(test)
test_dco_rekey_cycles :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	install(&r, 0, 10)
	testing.expect_value(t, new_peer(&r, 9), 0)
	n := len(r.be.calls)

	// First rekey: the secondary slot is free, the new key goes there and sends.
	r.now += 10 * time.Second
	kind(&r, .Rekey_Started)
	install(&r, 1, 20)
	testing.expect_value(t, rig_text(&r, n), "NEW_KEY/1/S SWAP_KEYS")
	testing.expect_value(t, r.o.held, [2]int{1, 0})
	n = len(r.be.calls)

	// Second rekey: key 0 (lame) is in the secondary slot; it goes first.
	r.now += 10 * time.Second
	kind(&r, .Rekey_Started)
	testing.expect_value(t, len(r.be.calls), n) // the grace key is not in the service
	install(&r, 2, 30)
	testing.expect_value(t, rig_text(&r, n), "DEL_KEY/S NEW_KEY/2/S SWAP_KEYS")
	testing.expect_value(t, r.o.held, [2]int{2, 1})
	n = len(r.be.calls)

	// The grace time and the transition window: the old key leaves the
	// session's table, and the service's secondary slot with it.
	r.now += 7200 * time.Second
	kind(&r, .Expire)
	testing.expect_value(t, rig_text(&r, n), "DEL_KEY/S")
	testing.expect_value(t, r.o.held, [2]int{2, -1})
	// Another Expire has nothing more to do.
	n = len(r.be.calls)
	kind(&r, .Expire)
	testing.expect_value(t, len(r.be.calls), n)
	testing.expect_value(t, r.o.err, 0)

	// The key ids wrap: 7 then 1 (0 is for the first key of a session).
	for id in ([]u8{3, 4, 5, 6, 7, 1}) {
		r.now += 100 * time.Second
		kind(&r, .Rekey_Started)
		install(&r, id, 40 + id)
	}
	testing.expect_value(t, r.o.err, 0)
	testing.expect_value(t, r.o.held[0], 1)
}

@(test)
test_dco_mapping_follows_the_session_table :: proc(t: ^testing.T) {
	// The owner's table and the session's table get the same calls: after any number
	// of rekeys the service's two slots hold the two newest keys the table still has.
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	mirror: keys.Key_Slots
	keys.slots_init(&mirror, keys.Slots_Config{tran_window = 3600 * time.Second, lame_grace = keys.DEFAULT_LAME_GRACE})
	id := u8(0)
	install(&r, id, 10)
	keys.slots_install(&mirror, id, r.now)
	testing.expect_value(t, new_peer(&r, 3), 0)
	for _ in 0 ..< 20 {
		r.now += 5 * time.Second
		kind(&r, .Rekey_Started)
		keys.slots_rekey_started(&mirror, r.now)
		id = keys.key_id_next(id)
		install(&r, id, 10 + id)
		keys.slots_install(&mirror, id, r.now)
		primary, _, _ := keys.slots_primary(&mirror)
		testing.expect_value(t, r.o.held[0], int(primary))
		if mirror.lame >= 0 {
			testing.expect_value(t, r.o.held[1], mirror.lame)
		}
	}
	testing.expect_value(t, r.o.err, 0)
}

// ------------------------------------------------------ with the key table

@(test)
test_dco_table_keys_wait_for_the_peer :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_KEY_TABLE)
	defer rig_free(&r)
	testing.expect(t, r.o.table)
	install(&r, 0, 10)
	testing.expect_value(t, len(r.be.calls), 0)
	// The key and the choice of the key that sends: two queued commands.
	testing.expect_value(t, r.o.n_ops, 2)
	testing.expect_value(t, new_peer(&r, 77), 0)
	testing.expect_value(t, rig_text(&r), "NEW_PEER KEY_ADD/0 KEY_TX/0")
	testing.expect_value(t, r.be.calls[1].peer_id, 77)
	testing.expect_value(t, r.be.calls[1].enc0, 10)
	testing.expect_value(t, r.be.calls[2].peer_id, 77)
	testing.expect_value(t, r.o.n_ops, 0)
	for op in r.o.ops {
		testing.expect_value(t, op.key.enc_key[0], 0)
		testing.expect_value(t, op.key.dec_key[0], 0)
	}
	// A rekey before the peer exists keeps the order too.
	r2: Rig
	rig_init(&r2, dco.CAP_KEY_TABLE)
	defer rig_free(&r2)
	install(&r2, 0, 10)
	kind(&r2, .Rekey_Started)
	install(&r2, 1, 20)
	testing.expect_value(t, new_peer(&r2, 5), 0)
	testing.expect_value(t, rig_text(&r2), "NEW_PEER KEY_ADD/0 KEY_TX/0 KEY_ADD/1 KEY_TX/1")
}

@(test)
test_dco_table_rekey_cycles :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_KEY_TABLE)
	defer rig_free(&r)
	install(&r, 0, 10)
	testing.expect_value(t, new_peer(&r, 9), 0)
	n := len(r.be.calls)

	// First rekey: the new key is added and sends; the old one stays (it receives).
	r.now += 10 * time.Second
	kind(&r, .Rekey_Started)
	testing.expect_value(t, len(r.be.calls), n)
	install(&r, 1, 20)
	testing.expect_value(t, rig_text(&r, n), "KEY_ADD/1 KEY_TX/1")
	testing.expect_value(t, r.o.tx_id, 1)
	n = len(r.be.calls)

	// Second rekey: key 0 is the grace key now, and stays in the service.
	r.now += 10 * time.Second
	kind(&r, .Rekey_Started)
	testing.expect_value(t, len(r.be.calls), n)
	install(&r, 2, 30)
	testing.expect_value(t, rig_text(&r, n), "KEY_ADD/2 KEY_TX/2")
	testing.expect_value(t, r.o.have, keys.Key_Id_Set{0, 1, 2})
	n = len(r.be.calls)

	// The third soft reset drops the grace key (0), and the install sets key 1 as the
	// grace key: three keys stay, as in the session.
	r.now += 10 * time.Second
	kind(&r, .Rekey_Started)
	testing.expect_value(t, rig_text(&r, n), "KEY_DROP/0")
	install(&r, 3, 40)
	testing.expect_value(t, rig_text(&r, n), "KEY_DROP/0 KEY_ADD/3 KEY_TX/3")
	testing.expect_value(t, r.o.have, keys.Key_Id_Set{1, 2, 3})
	n = len(r.be.calls)

	// The grace time and the transition window end: the old keys leave the table.
	r.now += 7200 * time.Second
	kind(&r, .Expire)
	testing.expect_value(t, rig_text(&r, n), "KEY_DROP/1 KEY_DROP/2")
	testing.expect_value(t, r.o.have, keys.Key_Id_Set{3})
	testing.expect_value(t, r.o.tx_id, 3)
	n = len(r.be.calls)
	kind(&r, .Expire)
	testing.expect_value(t, len(r.be.calls), n)
	testing.expect_value(t, r.o.err, 0)

	// An empty slot at the service is not a failure.
	r.be.fail["KEY_DROP"] = dco.ENOENT
	r.now += 100 * time.Second
	kind(&r, .Rekey_Started)
	install(&r, 4, 50)
	r.now += 100 * time.Second
	kind(&r, .Rekey_Started)
	install(&r, 5, 60)
	r.now += 100 * time.Second
	kind(&r, .Rekey_Started)
	testing.expect_value(t, r.o.err, 0)
}

@(test)
test_dco_table_mirrors_the_session_table :: proc(t: ^testing.T) {
	// The service holds the keys that the session's table holds, and sends with the
	// key the table sends with, after any number of rekeys and expiries.
	r: Rig
	rig_init(&r, dco.CAP_KEY_TABLE)
	defer rig_free(&r)
	mirror: keys.Key_Slots
	keys.slots_init(&mirror, keys.Slots_Config{tran_window = 3600 * time.Second, lame_grace = keys.DEFAULT_LAME_GRACE})
	id := u8(0)
	install(&r, id, 10)
	keys.slots_install(&mirror, id, r.now)
	testing.expect_value(t, new_peer(&r, 3), 0)
	for i in 0 ..< 30 {
		r.now += 5 * time.Second
		kind(&r, .Rekey_Started)
		keys.slots_rekey_started(&mirror, r.now)
		id = keys.key_id_next(id)
		install(&r, id, 10 + id)
		keys.slots_install(&mirror, id, r.now)
		if i % 7 == 6 {
			r.now += 100 * time.Second
			kind(&r, .Expire)
			keys.slots_expire(&mirror, r.now)
		}
		in_use := keys.slots_in_use(&mirror)
		for k in 0 ..< keys.KEY_ID_COUNT {
			testing.expect_value(t, k in r.o.have, k in in_use)
		}
		tx, _ := keys.slots_tx_key(&mirror, r.now)
		testing.expect_value(t, r.o.tx_id, int(tx))
	}
	testing.expect_value(t, r.o.err, 0)
	// The service never got more than the table allows.
	testing.expect(t, card(r.o.have) <= 3)
}

@(test)
test_dco_table_failures_and_fallback :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_KEY_TABLE)
	defer rig_free(&r)
	install(&r, 0, 10)
	testing.expect_value(t, new_peer(&r, 4), 0)
	r.be.fail["KEY_ADD"] = dco.EINVAL
	kind(&r, .Rekey_Started)
	install(&r, 1, 20)
	testing.expect_value(t, r.o.err, dco.EINVAL)
	testing.expect_value(t, r.o.err_op, "KEY_ADD")

	// A service with only the statistics reasons has no key table: the two slots.
	r2: Rig
	rig_init(&r2, dco.CAP_STATS_REASONS)
	defer rig_free(&r2)
	testing.expect(t, !r2.o.table)
	install(&r2, 0, 10)
	testing.expect_value(t, new_peer(&r2, 4), 0)
	testing.expect_value(t, rig_text(&r2), "NEW_PEER NEW_KEY/0/P")
}

@(test)
test_dco_stats_reasons :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_STATS_REASONS)
	defer rig_free(&r)
	r.be.stats = dco.Peer_Stats {
		vpn_rx_packets = 10,
		rx_drops       = 7,
		tx_drops       = 2,
		rx_no_key      = 1,
		rx_replay      = 2,
		rx_auth        = 3,
		rx_bad         = 1,
		tx_no_key      = 2,
		rx_src         = 4,
	}
	testing.expect_value(t, new_peer(&r, 2), 0)
	delta, ok := dco_stats(&r.o, nil, r.now)
	testing.expect(t, ok)
	testing.expect_value(t, delta.rx_drops, 7)
	testing.expect_value(t, delta.rx_no_key, 1)
	testing.expect_value(t, delta.rx_replay, 2)
	testing.expect_value(t, delta.rx_auth, 3)
	testing.expect_value(t, delta.rx_bad, 1)
	testing.expect_value(t, delta.tx_no_key, 2)
	testing.expect_value(t, delta.rx_src, 4)
	r.be.stats.rx_auth = 5
	delta, ok = dco_stats(&r.o, nil, r.now)
	testing.expect_value(t, delta.rx_auth, 2)
	testing.expect_value(t, delta.rx_replay, 0)
}

@(test)
test_dco_failures :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	install(&r, 0, 10)
	testing.expect_value(t, new_peer(&r, 4), 0)
	// An empty slot is not a failure.
	r.be.fail["DEL_KEY"] = dco.ENOENT
	kind(&r, .Rekey_Started)
	install(&r, 1, 20)
	kind(&r, .Rekey_Started)
	install(&r, 2, 30)
	testing.expect_value(t, r.o.err, 0)
	// Any other error stops the rest and is kept for the daemon.
	r.be.fail["NEW_KEY"] = dco.EINVAL
	n := len(r.be.calls)
	kind(&r, .Rekey_Started)
	install(&r, 3, 40)
	testing.expect_value(t, r.o.err, dco.EINVAL)
	testing.expect_value(t, r.o.err_op, "NEW_KEY")
	m := len(r.be.calls)
	testing.expect(t, m > n)
	install(&r, 4, 50)
	testing.expect_value(t, len(r.be.calls), m)
	// A failing NEW_PEER is returned.
	r2: Rig
	rig_init(&r2)
	defer rig_free(&r2)
	r2.be.fail["NEW_PEER"] = -17
	install(&r2, 0, 1)
	testing.expect_value(t, new_peer(&r2, 4), -17)
	testing.expect(t, !r2.o.created)
	testing.expect_value(t, len(r2.be.calls), 1)
	// A key without material is refused.
	r3: Rig
	rig_init(&r3)
	defer rig_free(&r3)
	bad := session.Dp_Cmd {
		kind   = .Install,
		key_id = 0,
		now    = r3.now,
	}
	submit(&r3, &bad)
	testing.expect_value(t, r3.o.err, dco.EINVAL)
}

@(test)
test_dco_destroy :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	install(&r, 0, 10)
	testing.expect_value(t, new_peer(&r, 6), 0)
	n := len(r.be.calls)
	kind(&r, .Destroy)
	testing.expect_value(t, rig_text(&r, n), "DEL_PEER")
	kind(&r, .Destroy)
	testing.expect_value(t, len(r.be.calls), n + 1)
	// After the end nothing goes out.
	install(&r, 1, 20)
	testing.expect_value(t, len(r.be.calls), n + 1)

	// The service dropped the peer by itself: no DEL_PEER.
	r2: Rig
	rig_init(&r2)
	defer rig_free(&r2)
	testing.expect_value(t, new_peer(&r2, 6), 0)
	dco_peer_dropped(&r2.o)
	n = len(r2.be.calls)
	kind(&r2, .Destroy)
	testing.expect_value(t, len(r2.be.calls), n)

	// A peer that was never created: the keys that waited are wiped, nothing is sent.
	r3: Rig
	rig_init(&r3)
	defer rig_free(&r3)
	install(&r3, 0, 10)
	kind(&r3, .Destroy)
	testing.expect_value(t, len(r3.be.calls), 0)
	testing.expect_value(t, r3.o.ops[0].key.enc_key[0], 0)
}

@(test)
test_dco_stats_deltas :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	// Not before the peer exists.
	_, ok := dco_stats(&r.o, nil, r.now)
	testing.expect(t, !ok)
	testing.expect_value(t, new_peer(&r, 2), 0)
	delta, ok2 := dco_stats(&r.o, nil, r.now)
	testing.expect(t, ok2)
	testing.expect_value(t, delta.vpn_rx_pkts, 3)
	testing.expect_value(t, delta.vpn_tx_bytes, 200)
	testing.expect_value(t, delta.link_tx_pkts, 5)
	// The fake service reports the same totals again: nothing new.
	delta, ok2 = dco_stats(&r.o, nil, r.now)
	testing.expect(t, ok2)
	testing.expect_value(t, delta.vpn_rx_pkts, 0)
	testing.expect_value(t, delta.vpn_tx_bytes, 0)
}

@(test)
test_dco_classify :: proc(t: ^testing.T) {
	ev := dco.Event {
		kind   = .Peer_Del,
		reason = .Expired,
	}
	testing.expect_value(t, dco_classify(&ev), Dco_Act.Expired)
	ev.reason = .Transport_Error
	testing.expect_value(t, dco_classify(&ev), Dco_Act.Link_Error)
	ev.reason = .Transport_Disconnect
	testing.expect_value(t, dco_classify(&ev), Dco_Act.Link_Error)
	ev.reason = .Userspace
	testing.expect_value(t, dco_classify(&ev), Dco_Act.None)
	ev.reason = .Teardown
	testing.expect_value(t, dco_classify(&ev), Dco_Act.None)
	ev.kind = .Peer_Float
	testing.expect_value(t, dco_classify(&ev), Dco_Act.Float)
	ev.kind = .Key_Swap
	testing.expect_value(t, dco_classify(&ev), Dco_Act.Key_Swap)
}

@(test)
test_dco_conversions :: proc(t: ^testing.T) {
	a := session.peer_addr_v4({192, 0, 2, 9}, 1194)
	ss, ok := dco_sockaddr(session.peer_addr_bytes(&a))
	testing.expect(t, ok)
	back, bok := dco_peer_addr(&ss)
	testing.expect(t, bok)
	testing.expect_value(t, back, a)

	ip: [16]u8
	ip[0], ip[1], ip[15] = 0x20, 0x01, 1
	a6 := session.peer_addr_v6(ip, 443)
	ss6, ok6 := dco_sockaddr(session.peer_addr_bytes(&a6))
	testing.expect(t, ok6)
	back6, bok6 := dco_peer_addr(&ss6)
	testing.expect(t, bok6)
	testing.expect_value(t, back6, a6)

	// An IPv4 peer seen on a dual-stack socket comes back as IPv4.
	mapped: [16]u8
	mapped[10], mapped[11] = 0xff, 0xff
	mapped[12], mapped[13], mapped[14], mapped[15] = 192, 0, 2, 9
	sm := dco.sockaddr_v6(mapped, 1194)
	bm, mok := dco_peer_addr(&sm)
	testing.expect(t, mok)
	testing.expect_value(t, bm, a)

	junk := [?]u8{9, 1, 2}
	_, jok := dco_sockaddr(junk[:])
	testing.expect(t, !jok)
	empty: dco.Sockaddr_Storage
	_, vok := dco_peer_addr(&empty)
	testing.expect(t, !vok)
}

@(test)
test_dco_open_flags :: proc(t: ^testing.T) {
	// Nothing switched off: no flags.
	testing.expect_value(t, dco_open_flags(off_parse_config("")), 0)
	testing.expect_value(t, dco_open_flags(off_parse_config("tun")), dco.OPT_NO_TUN_OFFLOAD)
	testing.expect_value(t, dco_open_flags(off_parse_config("gso")), dco.OPT_NO_GSO)
	testing.expect_value(t, dco_open_flags(off_parse_config("gro")), dco.OPT_NO_GRO)
	testing.expect_value(t, dco_open_flags(off_parse_config("gso,gro")), dco.OPT_NO_GSO | dco.OPT_NO_GRO)
	testing.expect_value(t, dco_open_flags(off_parse_config("all")), dco.OPT_NO_GSO | dco.OPT_NO_GRO | dco.OPT_NO_TUN_OFFLOAD)
}

// ------------------------------------------------------------- TCP peers

@(test)
test_dco_stream_peer_and_control_records :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_TCP | dco.CAP_KEY_TABLE)
	defer rig_free(&r)
	install(&r, 0, 10)
	dco_peer_set(&r.o, 10, 60, 0)
	// Nothing goes out before the peer exists, and the owner does not own a stream yet.
	framed := [7]u8{0, 5, 0x20, 1, 2, 3, 4}
	dco_ctrl_send(&r.o, framed[:])
	testing.expect_value(t, len(r.be.sent), 0)
	p := dco.New_Peer {
		peer_id = 9,
		flags   = dco.PEER_REMOTE,
	}
	ahead := [3]u8{0, 9, 0x38}
	testing.expect_value(t, dco_peer_create_stream(&r.o, &p, 7, ahead[:]), 0)
	testing.expect(t, r.o.stream && r.o.created)
	// The stream first, then the keys that waited, then SET_PEER: as for UDP.
	testing.expect_value(t, rig_text(&r), "NEW_PEER_STREAM KEY_ADD/0 KEY_TX/0 SET_PEER")
	testing.expect_value(t, r.be.calls[0].has_fd, true)
	testing.expect_value(t, string(r.be.ahead[:]), string(ahead[:]))
	// The session's framed output goes out without its 2-byte length.
	dco_ctrl_send(&r.o, framed[:])
	testing.expect_value(t, len(r.be.sent), 1)
	testing.expect_value(t, string(r.be.sent[0]), string(framed[2:]))
	testing.expect_value(t, r.be.calls[len(r.be.calls) - 1].peer_id, 9)
	// A frame whose length does not match is a failure of the owner; an empty frame is nothing.
	bad := [5]u8{0, 9, 1, 2, 3}
	dco_ctrl_send(&r.o, bad[:])
	testing.expect_value(t, r.o.err, dco.EINVAL)
	testing.expect_value(t, len(r.be.sent), 1)
	r.o.err = 0
	dco_ctrl_send(&r.o, framed[:2])
	testing.expect_value(t, len(r.be.sent), 1)
	// The stream is gone or the peer is unknown: not a failure, the event follows.
	r.be.fail["CTRL_TX"] = dco.ENOTCONN
	dco_ctrl_send(&r.o, framed[:])
	testing.expect_value(t, r.o.err, 0)
	r.be.fail["CTRL_TX"] = dco.ENOENT
	dco_ctrl_send(&r.o, framed[:])
	testing.expect_value(t, r.o.err, 0)
	// 1 MB of records waits: the owner failed, the session ends.
	r.be.fail["CTRL_TX"] = dco.ENOBUFS
	dco_ctrl_send(&r.o, framed[:])
	testing.expect_value(t, r.o.err, dco.ENOBUFS)
	testing.expect_value(t, r.o.err_op, "CTRL_TX")
	// After the service dropped the peer nothing is sent.
	r.o.err = 0
	r.be.fail["CTRL_TX"] = 0
	dco_peer_dropped(&r.o)
	n := len(r.be.sent)
	dco_ctrl_send(&r.o, framed[:])
	testing.expect_value(t, len(r.be.sent), n)
}

@(test)
test_dco_stream_refused :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_TCP | dco.CAP_KEY_TABLE)
	defer rig_free(&r)
	p := dco.New_Peer {
		peer_id = 3,
	}
	// The service refuses the stream: the owner has none, and the caller keeps its socket.
	r.be.fail["NEW_PEER_STREAM"] = dco.EPROTONOSUPPORT
	testing.expect_value(t, dco_peer_create_stream(&r.o, &p, 7, nil), dco.EPROTONOSUPPORT)
	testing.expect(t, !r.o.stream && !r.o.created)
	// A failure after the handover (a key the service refuses): the stream is the service's already.
	r.be.fail["NEW_PEER_STREAM"] = 0
	r.be.fail["KEY_ADD"] = dco.EINVAL
	install(&r, 0, 10)
	st := dco_peer_create_stream(&r.o, &p, 7, nil)
	testing.expect_value(t, st, dco.EINVAL)
	testing.expect(t, r.o.stream, "the caller must close its socket after a failure past the handover")
}

@(test)
test_dco_tcp_capability :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	testing.expect(t, !dco_tcp_ok(&r.link))
	r.link.be.caps = dco.CAP_KEY_TABLE | dco.CAP_TCP
	testing.expect(t, dco_tcp_ok(&r.link))
	r.link.up = false
	testing.expect(t, !dco_tcp_ok(&r.link))
}

@(test)
test_dco_classify_stream_ends :: proc(t: ^testing.T) {
	for reason in ([]dco.Del_Reason{.Transport_Error, .Transport_Disconnect}) {
		ev := dco.Event {
			kind   = .Peer_Del,
			reason = reason,
		}
		testing.expect_value(t, dco_classify(&ev), Dco_Act.Link_Error)
	}
	// A control record is not an event for the daemon's switch.
	ev := dco.Event {
		kind = .Ctrl_Rx,
	}
	testing.expect_value(t, dco_classify(&ev), Dco_Act.None)
}

// -------------------------------------------------- the early handover (rename)

@(test)
test_dco_early_capability :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	r.link.be.caps = dco.CAP_KEY_TABLE | dco.CAP_TCP
	testing.expect(t, !dco_early_ok(&r.link), "a service without CAP_PEER_ID gets the late handover")
	r.link.be.caps = dco.CAP_PEER_ID
	testing.expect(t, !dco_early_ok(&r.link), "the early handover needs the TCP capability too")
	r.link.be.caps = dco.CAP_TCP | dco.CAP_PEER_ID
	testing.expect(t, dco_early_ok(&r.link))
	r.link.up = false
	testing.expect(t, !dco_early_ok(&r.link))
}

@(test)
test_dco_early_peer_rename :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_TCP | dco.CAP_KEY_TABLE | dco.CAP_PEER_ID)
	defer rig_free(&r)
	// The stream goes first, with no read-ahead, under the provisional id.
	p := dco.New_Peer {
		peer_id = 0xfffffe,
		flags   = dco.PEER_REMOTE,
	}
	testing.expect_value(t, dco_peer_create_stream(&r.o, &p, 7, nil), 0)
	testing.expect_value(t, len(r.be.ahead), 0)
	testing.expect_value(t, r.o.peer_id, 0xfffffe)
	testing.expect(t, dco_owns_id(&r.o, 0xfffffe) && !dco_owns_id(&r.o, 5))
	// The handshake runs through CTRL_TX under the provisional id, the key goes in under it too.
	framed := [7]u8{0, 5, 0x20, 1, 2, 3, 4}
	dco_ctrl_send(&r.o, framed[:])
	install(&r, 0, 10)
	testing.expect_value(t, rig_text(&r), "NEW_PEER_STREAM CTRL_TX KEY_ADD/0 KEY_TX/0")
	for c in r.be.calls[1:] {
		testing.expect_value(t, c.peer_id, 0xfffffe)
	}
	// The push reply: the peer takes the pushed id, then SET_PEER goes out with the new id.
	n := len(r.be.calls)
	testing.expect_value(t, dco_peer_rename(&r.o, 5), 0)
	testing.expect_value(t, dco_peer_set(&r.o, 10, 60, 1300), 0)
	testing.expect_value(t, rig_text(&r, n), "SET_PEER_ID/16777214>5 SET_PEER")
	testing.expect_value(t, r.be.calls[n].peer_id, 0xfffffe)
	testing.expect_value(t, r.be.calls[n + 1].peer_id, 5)
	testing.expect_value(t, r.be.set_last.peer_id, 5)
	testing.expect_value(t, r.o.peer_id, 5)
	// Both ids are the peer's: events and records queued before the rename carry the old one.
	testing.expect(t, dco_owns_id(&r.o, 5) && dco_owns_id(&r.o, 0xfffffe) && !dco_owns_id(&r.o, 6))
	// Everything after goes under the new id: control records, keys, the end.
	dco_ctrl_send(&r.o, framed[:])
	kind(&r, .Rekey_Started)
	install(&r, 1, 20)
	dco_peer_delete(&r.o)
	for c in r.be.calls[n + 2:] {
		testing.expect_value(t, c.peer_id, 5)
	}
	testing.expect_value(t, r.be.calls[len(r.be.calls) - 1].what, "DEL_PEER")
}

@(test)
test_dco_rename_failures :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_TCP | dco.CAP_PEER_ID)
	defer rig_free(&r)
	// No peer yet: nothing to rename.
	testing.expect_value(t, dco_peer_rename(&r.o, 5), dco.ENOENT)
	p := dco.New_Peer {
		peer_id = 0xfffffe,
	}
	testing.expect_value(t, dco_peer_create_stream(&r.o, &p, 7, nil), 0)
	// The id is another peer's, or too large: the peer keeps its id, and no old id is kept.
	r.be.fail["SET_PEER_ID"] = dco.EEXIST
	testing.expect_value(t, dco_peer_rename(&r.o, 5), dco.EEXIST)
	r.be.fail["SET_PEER_ID"] = dco.EINVAL
	testing.expect_value(t, dco_peer_rename(&r.o, 0x1000000), dco.EINVAL)
	testing.expect_value(t, r.o.peer_id, 0xfffffe)
	testing.expect(t, !r.o.has_old && !dco_owns_id(&r.o, 5))
	// The same id is nothing to do: no call, no old id.
	r.be.fail["SET_PEER_ID"] = 0
	n := len(r.be.calls)
	testing.expect_value(t, dco_peer_rename(&r.o, 0xfffffe), 0)
	testing.expect_value(t, len(r.be.calls), n)
	testing.expect(t, !r.o.has_old)
	// After the service dropped the peer there is nothing to rename.
	dco_peer_dropped(&r.o)
	testing.expect_value(t, dco_peer_rename(&r.o, 5), dco.ENOENT)
}

@(test)
test_dco_provisional_ids :: proc(t: ^testing.T) {
	// The client rotates through 256 ids at the top, below the 'no peer' id 0xffffff.
	c: Dco_Client
	seen: [DCO_PROV_CLIENT]bool
	for _ in 0 ..< DCO_PROV_CLIENT {
		id := dco_prov_id(&c)
		testing.expect(t, id < 0xffffff && id >= 0xffffff - DCO_PROV_CLIENT, "inside the reserved range")
		testing.expect(t, !seen[0xfffffe - id], "no id twice in a round")
		seen[0xfffffe - id] = true
	}
	testing.expect_value(t, dco_prov_id(&c), 0xfffffe)
	// The server's ids and the registry's do not overlap: max-clients plus the conn table fits in 24 bits.
	testing.expect(t, srv_dco_early_fits(1024))
	testing.expect(t, srv_dco_early_fits(5_000_000))
	testing.expect(t, !srv_dco_early_fits(0xfffffe))
}

@(test)
test_dco_server_early_and_peer_addr :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_TCP | dco.CAP_PEER_ID)
	defer rig_free(&r)
	testing.expect(t, dco_early_ok(&r.link) && !dco_server_early_ok(&r.link), "the server also needs CAP_PEER_ADDR")
	r.link.be.caps |= dco.CAP_PEER_ADDR
	testing.expect(t, dco_server_early_ok(&r.link))
	r.link.be.caps = dco.CAP_TCP | dco.CAP_PEER_ADDR
	testing.expect(t, !dco_server_early_ok(&r.link))

	// The server's order at the login: rename, the addresses, then SET_PEER; all under the new id.
	r.link.be.caps = dco.CAP_TCP | dco.CAP_PEER_ID | dco.CAP_PEER_ADDR
	testing.expect_value(t, dco_peer_set_addr(&r.o, dco.PEER_VPN4, {10, 8, 0, 2}, {}), dco.ENOENT)
	p := dco.New_Peer {
		peer_id = 0xfffffd,
		flags   = dco.PEER_REMOTE,
	}
	testing.expect_value(t, dco_peer_create_stream(&r.o, &p, 7, nil), 0)
	testing.expect_value(t, dco_peer_rename(&r.o, 3), 0)
	vpn6 := [16]u8{0 = 0xfd, 15 = 2}
	testing.expect_value(t, dco_peer_set_addr(&r.o, dco.PEER_VPN4 | dco.PEER_VPN6 | 0x100, {10, 8, 0, 2}, vpn6), 0)
	dco_peer_set(&r.o, 10, 60, 0)
	testing.expect_value(t, rig_text(&r), "NEW_PEER_STREAM SET_PEER_ID/16777213>3 SET_PEER_ADDR SET_PEER")
	testing.expect_value(t, r.be.addr_last.peer_id, 3)
	testing.expect_value(t, r.be.addr_last.flags, dco.PEER_VPN4 | dco.PEER_VPN6)
	testing.expect_value(t, r.be.addr_last.vpn4, [4]u8{10, 8, 0, 2})
	// The address is another peer's: the error is the caller's.
	r.be.fail["SET_PEER_ADDR"] = dco.EEXIST
	testing.expect_value(t, dco_peer_set_addr(&r.o, dco.PEER_VPN4, {10, 8, 0, 2}, {}), dco.EEXIST)
}

// --------------------------------------------- the data path of an attempt

// The client's choice between the service and this process. `dial` stands in for
// the connect to the service: it replies with `dial_status` and, on success,
// gives a link with `dial_caps`.
@(thread_local)
dial_status: int
@(thread_local)
dial_caps: u32
@(thread_local)
dial_calls: int

fake_dial :: proc(d: ^Daemon) -> int {
	dial_calls += 1
	if dial_status != 0 {
		return dial_status
	}
	fake_link_up(&d.dco.link)
	d.dco.link.be.caps = dial_caps
	return 0
}

// A client that wants the service, with the link down and a dial that fails.
choice_init :: proc(d: ^Daemon, cfg: ^config.Client_Config, mode: config.Datapath) {
	cfg.datapath = mode
	cfg.dco_socket = "/nonexistent/dco.sock"
	d.cfg = cfg
	d.dco.want = mode != .Userspace
	d.dco.dial = fake_dial
	dial_status = dco.ENOENT
	dial_caps = dco.CAP_TCP
	dial_calls = 0
}

@(test)
test_dco_attempt_service_down_and_back :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	choice_init(&d, &cfg, .Udco)
	// The service is not there: the attempt runs here, and each attempt asks again.
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, d.dco.lost)
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, !dco_for_attempt(&d, .Tcp, false))
	testing.expect_value(t, dial_calls, 3)
	// The service is back: the attempt uses it, and the "lost" state is over.
	dial_status = 0
	d.dco.dev = true // a device of the old link is gone with it
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	testing.expect(t, !d.dco.lost)
	testing.expect(t, !d.dco.dev)
	testing.expect(t, d.dco.link.up)
	// It stays; no new dial while the link is up.
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	testing.expect_value(t, dial_calls, 4)
	// It goes away again (the link is closed by `dco_client_lost`): back to this process.
	d.dco.link = {}
	dial_status = DCO_ECONNREFUSED
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, d.dco.lost)
}

@(test)
test_dco_attempt_service_without_tcp :: proc(t: ^testing.T) {
	for mode in ([]config.Datapath{.Udco, .Auto}) {
		cfg: config.Client_Config
		d: Daemon
		choice_init(&d, &cfg, mode)
		dial_status = 0
		dial_caps = 0 // a service of before the TCP capability
		// UDP goes to the service; TCP runs here, and the log says so once.
		testing.expect(t, dco_for_attempt(&d, .Udp, false))
		testing.expect(t, !dco_for_attempt(&d, .Tcp, false))
		testing.expect(t, d.dco.tcp_warned)
		testing.expect(t, !dco_for_attempt(&d, .Tcp, false))
		testing.expect(t, dco_for_attempt(&d, .Udp, false))
		// A service with the capability takes TCP.
		d.dco.link.be.caps = dco.CAP_TCP
		testing.expect(t, dco_for_attempt(&d, .Tcp, false))
		// A tls remote always runs here.
		testing.expect(t, !dco_for_attempt(&d, .Tcp, true))
	}
}

@(test)
test_dco_attempt_not_wanted :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	choice_init(&d, &cfg, .Userspace)
	dial_status = 0
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect_value(t, dial_calls, 0)
	// `auto` that found no service at the start does not look again.
	choice_init(&d, &cfg, .Auto)
	d.dco.want = false
	dial_status = 0
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect_value(t, dial_calls, 0)
}

@(test)
test_dco_setup_failure_retries_here_at_once :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	choice_init(&d, &cfg, .Auto)
	dial_status = 0
	testing.expect(t, dco_for_attempt(&d, .Udp, false))

	// The service refuses NEW_PEER.
	r: Rig
	rig_init(&r, dco.CAP_TCP)
	defer rig_free(&r)
	r.be.fail["NEW_PEER"] = dco.EINVAL
	d.dco.link = r.link
	p := dco.New_Peer {
		peer_id = 3,
		flags   = dco.PEER_REMOTE,
	}
	testing.expect_value(t, dco_peer_create(&r.o, &p, 5), dco.EINVAL)

	// The attempt ends with a reason of its own, which the bus reports...
	outcome := close_outcome(.Datapath)
	testing.expect_value(t, outcome, client.Outcome.Datapath_Failed)
	testing.expect_value(t, state_reason(outcome, .None, .Ok), "udco_failed")
	testing.expect_value(t, state_reason(.Local_Stop, .Datapath, .Ok), "udco_failed")
	testing.expect(t, !close_reason_stops(.Datapath))
	dco_attempt_ended(&d, outcome)
	testing.expect(t, d.dco.skip)
	// ... the next attempt runs in this process, and the one after it asks the service again.
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, !d.dco.skip)
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	// Any other end of an attempt leaves the choice alone.
	dco_attempt_ended(&d, .Connect_Failed)
	testing.expect(t, !d.dco.skip)
	dco_attempt_ended(&d, .Datapath_Failed)
	d.dco.want = false
	dco_attempt_ended(&d, .Datapath_Failed)
	testing.expect(t, !d.dco.skip)
}

@(test)
test_client_state_has_the_datapath :: proc(t: ^testing.T) {
	d: Daemon
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)
	d.stats.attempts = 3

	// No attempt yet: null.
	_, has := client_datapath(&d)
	testing.expect(t, !has)
	bus.begin_obj(&w)
	client_state_write(&w, &d, "waiting", "waiting", "")
	text := bus.writer_string(&w)
	testing.expect(t, strings.contains(text, `"attempt":3,"datapath":null`), text)

	d.dco.path = .Udco
	bus.writer_reset(&w)
	bus.begin_obj(&w)
	client_state_write(&w, &d, "handshake", "connecting", "")
	text = bus.writer_string(&w)
	testing.expect(t, strings.contains(text, `"attempt":3,"datapath":"udco"`), text)

	// The service failed: the attempt after it is in this process, and the move to
	// waiting says why.
	d.dco.path = .Userspace
	bus.writer_reset(&w)
	bus.begin_obj(&w)
	client_state_write(&w, &d, "waiting", "closing", state_reason(.Datapath_Failed, .None, .Ok))
	text = bus.writer_string(&w)
	testing.expect(t, strings.contains(text, `"reason":"udco_failed"`), text)
	testing.expect(t, strings.contains(text, `"attempt":3,"datapath":"userspace"`), text)
}

// ------------------------------------------------- the server falls back

@(test)
test_dco_try_open :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	r.be.open_idx = 7
	idx, ok, why := dco_try_open(&r.link, "tun3", .Mp)
	testing.expect(t, ok)
	testing.expect_value(t, idx, 7)
	testing.expect_value(t, why, "")
	testing.expect(t, r.link.dev)
	testing.expect_value(t, r.link.ifindex, 7)

	// The service refuses: the text is the status, and nothing is logged by the caller.
	r.link.dev = false
	r.be.fail["OPEN"] = dco.EINVAL
	_, ok, why = dco_try_open(&r.link, "", .Mp)
	testing.expect(t, !ok)
	testing.expect_value(t, why, dco_status_text(dco.EINVAL))

	// A device without an index is no device.
	delete_key(&r.be.fail, "OPEN")
	r.be.open_idx = 0
	_, ok, why = dco_try_open(&r.link, "", .Mp)
	testing.expect(t, !ok)
	testing.expect_value(t, why, "it gave no interface index")
}

@(test)
test_dco_owner_after_the_connection_is_lost :: proc(t: ^testing.T) {
	// The server marks every owner gone when the service is lost: a session that ends,
	// a key, the counters and a control record lead to no call to the service then.
	r: Rig
	rig_init(&r, dco.CAP_TCP)
	defer rig_free(&r)
	p := dco.New_Peer {
		peer_id = 5,
		flags   = dco.PEER_REMOTE,
	}
	testing.expect_value(t, dco_peer_create(&r.o, &p, 9), 0)
	calls := len(r.be.calls)
	r.o.gone = true
	r.link = {} // what `dco_link_close` leaves
	r.o.link = &r.link
	dco_peer_delete(&r.o)
	_, ok := dco_stats(&r.o, nil, 0)
	testing.expect(t, !ok)
	testing.expect_value(t, dco_peer_set(&r.o, 10, 60, 1360), 0)
	testing.expect_value(t, dco_peer_rename(&r.o, 6), dco.ENOENT)
	dco_ctrl_send(&r.o, []u8{0, 2, 1, 2})
	testing.expect_value(t, len(r.be.calls), calls)
	testing.expect_value(t, r.o.err, 0)
}

@(test)
test_srv_dco_init_falls_back :: proc(t: ^testing.T) {
	listens := []config.Listen{{port = 1194, proto = .Udp}}
	cfg: config.Server_Config
	cfg.listens = listens
	cfg.dco_socket = "/nonexistent/dco.sock"

	// No kernel module on this machine, whatever the machine has.
	probe_begin(dco.ENO_OVPN, dco.ENOENT)
	defer probe_end()
	// `userspace` does not look for the service.
	d: Srv
	d.cfg = &cfg
	cfg.datapath = .Userspace
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on && !d.dco.link.up)

	// `auto` and `udco` with no service: the server goes on in this process.
	for mode in ([]config.Datapath{.Auto, .Udco}) {
		d = {}
		d.cfg = &cfg
		d.dco.wait_secs = 1
		cfg.datapath = mode
		testing.expect(t, srv_dco_init(&d))
		testing.expect(t, !d.dco.on)
		testing.expect(t, !d.dco.link.up)
		testing.expect(t, !d.dco.mixed && !d.dco.tcp)
	}

	// Two listeners are too many for the service: `auto` runs here, `udco` is a config error.
	two := []config.Listen{{port = 1194, proto = .Udp}, {port = 1195, proto = .Udp}}
	cfg.listens = two
	d = {}
	d.cfg = &cfg
	cfg.datapath = .Auto
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on)
	d = {}
	d.cfg = &cfg
	cfg.datapath = .Udco
	testing.expect(t, !srv_dco_init(&d))
	testing.expect_value(t, d.exit_code, Exit.Config)
}

// What the fake `key_install` saw last.
@(private = "file")
Install_Seen :: struct {
	n:      int,
	key_id: u32,
	format: keys.Format,
	send0:  u8,
	e1_0:   u8,
}

@(private = "file")
install_seen: Install_Seen

@(test)
test_dco_key_install_from_material :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_KEY_TABLE)
	defer rig_free(&r)
	testing.expect(t, !dco_epoch_ok(&r.link), "no epoch keys without key_install and the flag")
	r.link.be.key_install = proc(user: rawptr, k: ^dco.Key_Install) -> int {
		install_seen = {
			n      = install_seen.n + 1,
			key_id = k.key_id,
			format = k.format,
			send0  = k.material.send.key[0],
			e1_0   = k.material.send.e1[0],
		}
		append(&(^Fake_Be)(user).calls, Call{what = "KEY_ADD", key_id = k.key_id, peer_id = k.peer_id, enc0 = k.material.send.key[0]})
		return 0
	}
	testing.expect(t, !dco_epoch_ok(&r.link))
	r.link.be.epoch_keys = true
	testing.expect(t, dco_epoch_ok(&r.link))
	dco_owner_init(&r.o, &r.link, keys.Slots_Config{tran_window = 3600 * time.Second, lame_grace = keys.DEFAULT_LAME_GRACE})
	testing.expect(t, r.o.install)
	install_seen = {}
	cmd, m := make_install(0, r.now, 10)
	m.send.e1[0] = 77
	cmd.format = .Epoch
	submit(&r, &cmd)
	free(m)
	testing.expect_value(t, new_peer(&r, 8), 0)
	testing.expect_value(t, rig_text(&r), "NEW_PEER KEY_ADD/0 KEY_TX/0")
	testing.expect_value(t, install_seen.n, 1)
	testing.expect(t, install_seen.format == .Epoch)
	testing.expect_value(t, install_seen.send0, 10)
	testing.expect_value(t, install_seen.e1_0, 77)
	for op in r.o.ops {
		testing.expect_value(t, op.mat.send.key[0], 0)
		testing.expect_value(t, op.mat.send.e1[0], 0)
	}

	// Without key_install an epoch key is refused: the backend cannot build it.
	r2: Rig
	rig_init(&r2, dco.CAP_KEY_TABLE)
	defer rig_free(&r2)
	testing.expect_value(t, new_peer(&r2, 8), 0)
	cmd2, m2 := make_install(0, r2.now, 10)
	cmd2.format = .Epoch
	submit(&r2, &cmd2)
	free(m2)
	testing.expect_value(t, rig_text(&r2), "NEW_PEER")
	testing.expect_value(t, r2.o.err, dco.EINVAL)
}

@(test)
test_srv_dco_peer_release_removes_the_backend_peer :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	d := new(Srv)
	defer free(d)
	d.dco.on = true
	c := new(Conn)
	defer free(c)
	testing.expect_value(t, new_peer(&r, 5), 0)
	c.dco = r.o
	from := len(r.be.calls)
	srv_dco_peer_release(d, c)
	testing.expect_value(t, rig_text(&r, from), "DEL_PEER")
	testing.expect(t, c.dco.gone)
	// Once only: the later destroy of the session finds the peer gone.
	srv_dco_peer_release(d, c)
	dco_peer_delete(&c.dco)
	testing.expect_value(t, rig_text(&r, from), "DEL_PEER")

	// A client that the process runs (a tls client of a mixed server) has no backend peer.
	c2 := new(Conn)
	defer free(c2)
	c2.dco = r.o
	c2.dco.gone = false
	c2.tls = true
	from = len(r.be.calls)
	srv_dco_peer_release(d, c2)
	testing.expect_value(t, rig_text(&r, from), "")
}

// A profile of the client service with `disable-dco`: its attempts run in this
// process and the backend is not asked; without it, the backend is used.
@(test)
test_dco_attempt_profile_without_dco :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	choice_init(&d, &cfg, .Udco)
	dial_status = 0
	cfg.disable_dco = true
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, !dco_for_attempt(&d, .Tcp, false))
	testing.expect_value(t, dial_calls, 0)
	testing.expect_value(t, daemon_datapath(&d), "userspace")
	cfg.disable_dco = false
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	testing.expect_value(t, daemon_datapath(&d), "udco")
}
