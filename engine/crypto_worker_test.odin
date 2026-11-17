// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "base:intrinsics"
import "core:testing"
import "core:thread"
import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/session"
import "noir:proto/wire"

// ------------------------------------------------------------------ the ring

@(test)
test_spsc_order_and_full :: proc(t: ^testing.T) {
	r := new(Spsc(int, 8))
	defer free(r)
	_, ok := spsc_pop(r)
	testing.expect(t, !ok, "an empty ring gave a value")
	for i in 0 ..< 8 {
		testing.expect(t, spsc_push(r, i), "push failed")
	}
	testing.expect(t, !spsc_push(r, 99), "push into a full ring")
	testing.expect_value(t, spsc_len(r), 8)
	// Wrap around many times.
	next := 0
	for round in 0 ..< 100 {
		for _ in 0 ..< 3 {
			v, vok := spsc_pop(r)
			testing.expect(t, vok, "pop failed")
			testing.expect_value(t, v, next)
			next += 1
		}
		for k in 0 ..< 3 {
			testing.expect(t, spsc_push(r, 8 + round * 3 + k), "push failed")
		}
	}
}

Spsc_Fixture :: struct {
	r:     Spsc(int, 64),
	total: int,
	got:   int,
	order: bool,
}

spsc_producer :: proc(th: ^thread.Thread) {
	f := (^Spsc_Fixture)(th.data)
	for i in 0 ..< f.total {
		for !spsc_push(&f.r, i) {
			thread.yield()
		}
	}
}

@(test)
test_spsc_two_threads :: proc(t: ^testing.T) {
	f := new(Spsc_Fixture)
	defer free(f)
	f.total = 200_000
	f.order = true
	th := thread.create(spsc_producer)
	th.data = f
	thread.start(th)
	for f.got < f.total {
		v, ok := spsc_pop(&f.r)
		if !ok {
			thread.yield()
			continue
		}
		if v != f.got {
			f.order = false
		}
		f.got += 1
	}
	thread.join(th)
	thread.destroy(th)
	testing.expect(t, f.order, "values came out of order")
	testing.expect_value(t, f.got, f.total)
}

// ------------------------------------------------------------------ helpers

TEST_PEER_ID :: 5
TEST_SLOT :: 2048

Test_Slot :: struct {
	buf: [TEST_SLOT]u8,
}

// A pair of data planes for one tunnel: `tx` seals for the peer, `rx` opens.
// Keys come from the same export, the way the two ends of a session get them.
Pair :: struct {
	pool: ^Wk_Pool,
	tx:   ^session.Data_Plane,
	rx:   ^session.Data_Plane,
	wtx:  ^Wk_Worker,
	wrx:  ^Wk_Worker,
}

pair_export :: proc(seed: u8) -> (e: [keys.EXPORT_LEN]u8) {
	for i in 0 ..< len(e) {
		e[i] = u8(i * 7 + 1) ~ seed
		if e[i] == 0 {
			e[i] = 1
		}
	}
	return
}

pair_new :: proc(workers: int, rx_worker: int, format: keys.Format) -> (p: Pair) {
	p.pool = pool_start(workers)
	p.wtx = &p.pool.workers[0]
	p.wrx = &p.pool.workers[rx_worker]
	cfg := keys.Slots_Config {
		tran_window = 3600 * time.Second,
		lame_grace  = keys.DEFAULT_LAME_GRACE,
	}
	p.tx = new(session.Data_Plane)
	p.rx = new(session.Data_Plane)
	session.dp_init(p.tx, .Client, .Udp, cfg)
	session.dp_init(p.rx, .Server, .Udp, cfg)
	p.wtx.peers += 1
	p.wrx.peers += 1
	return
}

pair_stop :: proc(p: ^Pair) {
	d := session.Dp_Cmd {
		kind = .Destroy,
	}
	remote_submit(p.wtx, p.tx, &d)
	remote_submit(p.wrx, p.rx, &d)
	pool_stop(p.pool)
}

// Generates the key `id` of this export for both ends and installs it at `now`.
pair_install :: proc(p: ^Pair, id: u8, seed: u8, format: keys.Format, now: time.Duration, sides := 3) {
	exp := pair_export(seed)
	for side in 0 ..< 2 {
		if sides & (1 << uint(side)) == 0 {
			continue
		}
		role := wire.Role.Client if side == 0 else wire.Role.Server
		m, merr := keys.derive_material(exp[:], role, .AES_256_GCM)
		assert(merr == .None)
		dk: crypt.Data_Key
		assert(crypt.data_key_init(&dk, format, .AES_256_GCM, id, &m, {}) == .None)
		keys.material_wipe(&m)
		cmd := session.Dp_Cmd {
			kind    = .Install,
			key_id  = id,
			now     = now,
			key     = (^crypt.Data_Key)(rawptr(&dk)),
			format  = format,
			peer_id = TEST_PEER_ID,
			policy  = {cipher = .AES_256_GCM, format = format},
		}
		if side == 0 {
			remote_submit(p.wtx, p.tx, &cmd)
		} else {
			remote_submit(p.wrx, p.rx, &cmd)
		}
	}
}

// An IPv4-looking payload with a sequence number at 20.
fill_payload :: proc(s: ^Test_Slot, seq: int, n: int) {
	b := s.buf[session.TUNNEL_HEADROOM:][:n]
	for i in 0 ..< n {
		b[i] = u8(i + seq)
	}
	b[0] = 0x45
	b[20], b[21], b[22], b[23] = u8(seq >> 24), u8(seq >> 16), u8(seq >> 8), u8(seq)
}

payload_seq :: proc(b: []u8) -> int {
	return int(b[20]) << 24 | int(b[21]) << 16 | int(b[22]) << 8 | int(b[23])
}

// Seals `count` packets in one go (sequence numbers from `first`), lane by lane.
// Returns the slots and how many were sealed.
seal_many :: proc(p: ^Pair, slots: []Test_Slot, first, count: int, now: time.Duration) -> (jobs: [dynamic]^Wk_Job) {
	for i in 0 ..< count {
		fill_payload(&slots[i], first + i, 100)
		j := job_add(p.wtx, .Tx, p.tx, slots[i].buf[:], 100, now)
		assert(j != nil)
		append(&jobs, j)
	}
	lane_run(p.pool, .Tx)
	return
}

// ------------------------------------------------------------------ the tests

@(test)
test_workers_seal_and_open_in_order :: proc(t: ^testing.T) {
	for format in keys.Format {
		p := pair_new(2, 1, format)
		defer pair_stop(&p)
		pair_install(&p, 0, 1, format, time.Second)
		slots := make([]Test_Slot, 300)
		defer delete(slots)
		now := 2 * time.Second
		// 300 packets: five batches of the lane.
		jobs := seal_many(&p, slots, 0, 300, now)
		defer delete(jobs)
		for j in jobs {
			testing.expect_value(t, j.seal.err, session.Error.None)
		}
		// Open them on the other worker, in the same order.
		ojobs: [dynamic]^Wk_Job
		defer delete(ojobs)
		for i in 0 ..< 300 {
			j := jobs[i]
			o := job_add(p.wrx, .Rx, p.rx, slots[i].buf[j.seal.start:j.seal.end], 0, now)
			testing.expect(t, o != nil, "no room")
			append(&ojobs, o)
		}
		lane_run(p.pool, .Rx)
		for o, i in ojobs {
			testing.expect_value(t, o.open.code, session.Dp_Open_Code.Tunnel)
			plain := o.buf[o.open.off:][:o.open.len]
			testing.expect_value(t, payload_seq(plain), i)
		}
		lane_recycle(p.pool, .Rx)
		lane_recycle(p.pool, .Tx)
	}
}

// A key installed between two batches applies from the second one on.
// The send side and the receive side.
@(test)
test_key_install_is_ordered_with_batches :: proc(t: ^testing.T) {
	p := pair_new(2, 1, .Baseline)
	defer pair_stop(&p)
	slots := make([]Test_Slot, 64)
	defer delete(slots)
	now := 2 * time.Second
	// Send side. Batch 1 runs before the key is there.
	j1 := seal_many(&p, slots, 0, 8, now)
	for j in j1 {
		testing.expect_value(t, j.seal.err, session.Error.No_Key)
	}
	delete(j1)
	lane_recycle(p.pool, .Tx)
	// The key goes to the send side only; batch 2 uses it.
	pair_install(&p, 0, 3, .Baseline, time.Second, sides = 1)
	j2 := seal_many(&p, slots, 100, 8, now)
	for j in j2 {
		testing.expect_value(t, j.seal.err, session.Error.None)
	}
	// Receive side: add a packet, install the key (that posts the open batch
	// first), then add another packet. The first one ran with no key; the second
	// one opens.
	a := job_add(p.wrx, .Rx, p.rx, slots[0].buf[j2[0].seal.start:j2[0].seal.end], 0, now)
	pair_install(&p, 0, 3, .Baseline, time.Second, sides = 2)
	b := job_add(p.wrx, .Rx, p.rx, slots[1].buf[j2[1].seal.start:j2[1].seal.end], 0, now)
	lane_run(p.pool, .Rx)
	testing.expect_value(t, a.open.code, session.Dp_Open_Code.No_Key)
	testing.expect_value(t, b.open.code, session.Dp_Open_Code.Tunnel)
	delete(j2)
	lane_recycle(p.pool, .Rx)
	lane_recycle(p.pool, .Tx)
}

// A rekey in the middle of a stream: every packet opens, in order, also the ones
// sealed with the old key that arrive after the new key is installed.
@(test)
test_rekey_during_traffic :: proc(t: ^testing.T) {
	for format in keys.Format {
		p := pair_new(2, 1, format)
		defer pair_stop(&p)
		pair_install(&p, 0, 5, format, time.Second)
		slots := make([]Test_Slot, 1024)
		defer delete(slots)
		now := 2 * time.Second
		seq := 0
		next_key: u8 = 1
		expect_seq := 0
		// Packets sealed with key 0 that are held back until key 1 is in.
		held: [8]int
		held_start, held_end: [8]int
		for round in 0 ..< 6 {
			jobs := seal_many(&p, slots[seq:], seq, 40, now)
			first := seq
			seq += 40
			lane_recycle(p.pool, .Tx)
			// Hold the last 8 of round 1 back; the rekey happens before they go.
			cut := 40
			if round == 1 {
				cut = 32
				for k in 0 ..< 8 {
					held[k] = first + 32 + k
					held_start[k], held_end[k] = jobs[32 + k].seal.start, jobs[32 + k].seal.end
				}
			}
			ojobs: [dynamic]^Wk_Job
			for i in 0 ..< cut {
				j := jobs[i]
				o := job_add(p.wrx, .Rx, p.rx, slots[first + i].buf[j.seal.start:j.seal.end], 0, now)
				append(&ojobs, o)
			}
			lane_run(p.pool, .Rx)
			for o in ojobs {
				testing.expect_value(t, o.open.code, session.Dp_Open_Code.Tunnel)
				if o.open.code == .Tunnel {
					testing.expect_value(t, payload_seq(o.buf[o.open.off:][:o.open.len]), expect_seq)
				}
				expect_seq += 1
			}
			delete(ojobs)
			delete(jobs)
			lane_recycle(p.pool, .Rx)
			if round == 1 {
				// The rekey: both ends see the soft reset, then the new key.
				for side in 0 ..< 2 {
					cmd := session.Dp_Cmd {
						kind = .Rekey_Started,
						now  = now,
					}
					if side == 0 {
						remote_submit(p.wtx, p.tx, &cmd)
					} else {
						remote_submit(p.wrx, p.rx, &cmd)
					}
				}
				pair_install(&p, next_key, 9, format, now)
				next_key += 1
				// The held packets arrive now, after the new key is installed.
				hj: [dynamic]^Wk_Job
				for k in 0 ..< 8 {
					idx := held[k]
					o := job_add(p.wrx, .Rx, p.rx, slots[idx].buf[held_start[k]:held_end[k]], 0, now)
					append(&hj, o)
				}
				lane_run(p.pool, .Rx)
				for o in hj {
					testing.expect_value(t, o.open.code, session.Dp_Open_Code.Tunnel)
					if o.open.code == .Tunnel {
						testing.expect_value(t, payload_seq(o.buf[o.open.off:][:o.open.len]), expect_seq)
					}
					expect_seq += 1
				}
				delete(hj)
				lane_recycle(p.pool, .Rx)
			}
		}
		testing.expect_value(t, expect_seq, seq)
	}
}

// A packet the session creates itself is sealed after the packets that were added
// before it.
@(test)
test_one_packet_waits_for_the_batch :: proc(t: ^testing.T) {
	p := pair_new(1, 0, .Baseline)
	defer pair_stop(&p)
	pair_install(&p, 0, 7, .Baseline, time.Second)
	slots := make([]Test_Slot, 4)
	defer delete(slots)
	now := 2 * time.Second
	for i in 0 ..< 3 {
		fill_payload(&slots[i], i, 100)
		job_add(p.wtx, .Tx, p.tx, slots[i].buf[:], 100, now)
	}
	fill_payload(&slots[3], 3, 100)
	r := remote_seal(p.wtx, p.tx, slots[3].buf[:], 100, true, now)
	testing.expect_value(t, r.err, session.Error.None)
	lane_run(p.pool, .Tx)
	// The one packet has the fourth packet id: the three before it were sealed first.
	pid := int(slots[3].buf[r.start + 4]) << 24 | int(slots[3].buf[r.start + 5]) << 16 | int(slots[3].buf[r.start + 6]) << 8 | int(slots[3].buf[r.start + 7])
	testing.expect_value(t, pid, 4)
	lane_recycle(p.pool, .Tx)
}

// The semaphore wakes a worker that sleeps: a batch added a while after the
// last one still runs.
@(test)
test_idle_worker_wakes :: proc(t: ^testing.T) {
	p := pair_new(1, 0, .Epoch)
	defer pair_stop(&p)
	pair_install(&p, 0, 2, .Epoch, time.Second)
	slots := make([]Test_Slot, 4)
	defer delete(slots)
	for round in 0 ..< 3 {
		time.sleep(20 * time.Millisecond)
		jobs := seal_many(&p, slots, round, 2, 2 * time.Second)
		for j in jobs {
			testing.expect_value(t, j.seal.err, session.Error.None)
		}
		delete(jobs)
		lane_recycle(p.pool, .Tx)
	}
	// The workers' counters.
	testing.expect_value(t, intrinsics.atomic_load(&p.wtx.batches_run), 3)
	testing.expect_value(t, intrinsics.atomic_load(&p.wtx.jobs_run), 6)
}
