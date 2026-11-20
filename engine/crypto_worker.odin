// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "base:intrinsics"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "noir:bus"
import "noir:platform/event"
import "noir:proto/crypt"
import "noir:proto/session"

// Crypto worker threads (`workers N`). The data channel of a peer (keys, send
// counters, replay windows: `session.Data_Plane`) lives on one worker while the
// peer exists; the worker seals and opens. The main thread keeps sockets, tun,
// routing, control channel and queues, and never waits for a worker.
//
//	main thread                                  worker k
//	  job_add          copy the packet into a batch
//	  pool_post        post the open batches ---->  work ring  ---->  seal or open each packet
//	  (back to the event loop)                                         (in order)
//	  pool_next        take a finished batch <----  done ring  <----  wake the loop
//	  batch_free       the batch is free again
//
// A packet that finds no free batch is dropped (counted in `Wk_Worker.drops`).

WK_JOBS :: 64 // packets in one batch
WK_BATCHES :: 32 // batches in one lane of one worker
WK_RING :: 256 // messages in a ring (a power of two)
// Packet memory of one job: a ring slot (headroom, packet, tag) or a datagram.
WK_SLOT :: SLOT_SIZE
#assert(RX_SLOT <= WK_SLOT)
// Send room a tun read needs: a large read is cut into this many packets at an
// ordinary MSS. With less room the daemon stops reading the tun for a while.
WK_TUN_ROOM :: 64
// All batches of a worker together use less than half of the work ring.
#assert(2 * WK_BATCHES < WK_RING / 2)

// ------------------------------------------------------------------ the ring

// A single producer, single consumer queue of `N` slots (a power of two).
Spsc :: struct($T: typeid, $N: int) where N > 0 && (N & (N - 1)) == 0 {
	buf:  [N]T,
	// Written by the consumer.
	head: u64,
	_pad: [56]u8,
	// Written by the producer.
	tail: u64,
}

spsc_push :: proc "contextless" (r: ^Spsc($T, $N), v: T) -> bool {
	tail := r.tail
	if tail - intrinsics.atomic_load_explicit(&r.head, .Acquire) >= u64(N) {
		return false
	}
	r.buf[tail & u64(N - 1)] = v
	intrinsics.atomic_store_explicit(&r.tail, tail + 1, .Release)
	return true
}

spsc_pop :: proc "contextless" (r: ^Spsc($T, $N)) -> (v: T, ok: bool) {
	head := r.head
	if head == intrinsics.atomic_load_explicit(&r.tail, .Acquire) {
		return {}, false
	}
	v = r.buf[head & u64(N - 1)]
	intrinsics.atomic_store_explicit(&r.head, head + 1, .Release)
	return v, true
}

spsc_len :: proc "contextless" (r: ^Spsc($T, $N)) -> int {
	return int(intrinsics.atomic_load_explicit(&r.tail, .Acquire) - intrinsics.atomic_load_explicit(&r.head, .Acquire))
}


// ------------------------------------------------------------------ the jobs

Wk_Kind :: enum u8 {
	Seal, // a batch of packets to seal
	Open, // a batch of packets to open
	One_Seal, // one packet the session itself created (in `Wk_Worker.one`)
	One_Open,
	Cmd, // a command for a data plane
	Stop,
}

// One packet.
Wk_Job :: struct {
	dp:      ^session.Data_Plane,
	// Seal: the slot (the payload at TUNNEL_HEADROOM, `n` bytes). Open: the
	// packet, opened in place. Memory of the batch, except for a `One_*` job.
	buf:     []u8,
	n:       int,
	now:     time.Duration,
	// Seal: it is a tunnel packet (not a keepalive or an exit notice).
	counted: bool,
	// The results.
	seal:    session.Dp_Seal,
	open:    session.Dp_Open,
}

Wk_Batch :: struct {
	lane:  ^Wk_Lane,
	kind:  Wk_Kind,
	count: int,
	// Job `i` of the batch has the number `first + i`, unique in the pool (see
	// `pool_jobs`): daemons keep their records of a job at that index.
	first: int,
	jobs:  [WK_JOBS]Wk_Job,
	mem:   []u8, // WK_JOBS slots of WK_SLOT bytes
}

// What goes through the work ring.
Wk_Msg :: struct {
	kind:  Wk_Kind,
	batch: ^Wk_Batch,
	dp:    ^session.Data_Plane,
	cmd:   session.Dp_Cmd,
}

// The batches of one direction on one worker.
Wk_Lane :: struct {
	batches: []Wk_Batch,
	free:    [WK_BATCHES]^Wk_Batch,
	nfree:   int,
	open:    ^Wk_Batch, // being filled, or nil
	posted:  int, // posted, not taken with `pool_next` yet
}

Lane :: enum u8 {
	Rx, // packets to open
	Tx, // packets to seal
}

Wk_Worker :: struct {
	index:       int,
	pool:        ^Wk_Pool,
	thread:      ^thread.Thread,
	work:        Spsc(Wk_Msg, WK_RING),
	done:        Spsc(^Wk_Batch, WK_RING),
	// Guards the flags below; `work_cv` wakes the worker, `room_cv` and `one_cv`
	// the main thread.
	work_mu:     sync.Mutex,
	work_cv:     sync.Cond,
	room_cv:     sync.Cond,
	one_cv:      sync.Cond,
	work_idle:   bool,
	room_wait:   bool,
	one_done:    bool,
	lanes:       [Lane]Wk_Lane,
	mem:         []u8,
	// The packet of a `One_*` message and its result.
	one:         Wk_Job,
	// Peers pinned to this worker.
	peers:       int,
	// Packets that found no free batch, by lane (main thread).
	drops:       [Lane]u64,
	// Written by the worker, read for the status text.
	batches_run: u64,
	jobs_run:    u64,
}

Wk_Pool :: struct {
	workers:   []Wk_Worker,
	allocator: mem.Allocator,
	// The loop of the main thread: a worker wakes it when a batch is done.
	loop:      ^event.Loop,
	// The worker `pool_next` looks at first.
	next:      int,
}

// ------------------------------------------------------------------ start, stop

// Starts `n` workers. They wake `loop` (nil: nothing to wake, for tests) when a
// batch is done. Nil if a thread or memory is not available (what was started
// is stopped).
pool_start :: proc(n: int, loop: ^event.Loop) -> ^Wk_Pool {
	p := new(Wk_Pool)
	if p == nil {
		return nil
	}
	p.allocator = context.allocator
	p.loop = loop
	p.workers = make([]Wk_Worker, n)
	for &w, i in p.workers {
		w.index = i
		w.pool = p
		w.mem = make([]u8, len(Lane) * WK_BATCHES * WK_JOBS * WK_SLOT)
		for &l in w.lanes {
			l.batches = make([]Wk_Batch, WK_BATCHES)
		}
		if w.mem == nil || w.lanes[.Rx].batches == nil || w.lanes[.Tx].batches == nil {
			pool_stop(p)
			return nil
		}
		for lane in Lane {
			l := &w.lanes[lane]
			for &b, k in l.batches {
				nb := (int(lane) * WK_BATCHES + k)
				b.lane = l
				b.kind = .Open if lane == .Rx else .Seal
				b.first = (i * len(Lane) * WK_BATCHES + nb) * WK_JOBS
				b.mem = w.mem[nb * WK_JOBS * WK_SLOT:][:WK_JOBS * WK_SLOT]
				l.free[k] = &b
			}
			l.nfree = WK_BATCHES
		}
	}
	for &w in p.workers {
		t := thread.create(worker_main)
		if t == nil {
			pool_stop(p)
			return nil
		}
		t.data = &w
		w.thread = t
		thread.start(t)
	}
	return p
}

// Stops the workers and frees everything. Call it after the last session is
// destroyed.
pool_stop :: proc(p: ^Wk_Pool) {
	if p == nil {
		return
	}
	for &w in p.workers {
		if w.thread != nil {
			post(&w, Wk_Msg{kind = .Stop})
			thread.join(w.thread)
			thread.destroy(w.thread)
			w.thread = nil
		}
	}
	for &w in p.workers {
		for &l in w.lanes {
			delete(l.batches)
		}
		delete(w.mem)
	}
	delete(p.workers)
	free(p)
}

// The number of jobs in the pool: job numbers (`Wk_Batch.first`) are below it.
pool_jobs :: proc(p: ^Wk_Pool) -> int {
	return len(p.workers) * len(Lane) * WK_BATCHES * WK_JOBS
}

// The worker with the fewest peers; the first one when they are equal.
pool_pick :: proc(p: ^Wk_Pool) -> ^Wk_Worker {
	best := &p.workers[0]
	for &w in p.workers[1:] {
		if w.peers < best.peers {
			best = &w
		}
	}
	return best
}

// ------------------------------------------------------------------ the worker

@(private = "file")
worker_main :: proc(t: ^thread.Thread) {
	w := (^Wk_Worker)(t.data)
	context.allocator = w.pool.allocator
	for {
		m := take(w)
		switch m.kind {
		case .Stop:
			return
		case .Cmd:
			worker_cmd(&m)
		case .Seal, .Open:
			b := m.batch
			last: ^session.Data_Plane
			for i in 0 ..< b.count {
				j := &b.jobs[i]
				if b.kind == .Seal {
					j.seal = session.dp_seal(j.dp, j.buf, j.n, true, j.now)
				} else {
					j.open = session.dp_open(j.dp, j.buf, j.now)
				}
				if j.dp != last {
					if last != nil {
						session.dp_publish(last)
					}
					last = j.dp
				}
			}
			if last != nil {
				session.dp_publish(last)
			}
			intrinsics.atomic_add_explicit(&w.batches_run, 1, .Relaxed)
			intrinsics.atomic_add_explicit(&w.jobs_run, u64(b.count), .Relaxed)
			worker_done(w, b)
		case .One_Seal:
			j := &w.one
			j.seal = session.dp_seal(j.dp, j.buf, j.n, j.counted, j.now)
			session.dp_publish(j.dp)
			one_done(w)
		case .One_Open:
			j := &w.one
			j.open = session.dp_open(j.dp, j.buf, j.now)
			session.dp_publish(j.dp)
			one_done(w)
		}
	}
}

// Takes the next message of the work ring; waits while it is empty.
@(private = "file")
take :: proc(w: ^Wk_Worker) -> Wk_Msg {
	sync.mutex_lock(&w.work_mu)
	defer sync.mutex_unlock(&w.work_mu)
	for {
		if m, ok := spsc_pop(&w.work); ok {
			if w.room_wait {
				w.room_wait = false
				sync.cond_signal(&w.room_cv)
			}
			return m
		}
		w.work_idle = true
		sync.cond_wait(&w.work_cv, &w.work_mu)
		w.work_idle = false
	}
}

// Hands a finished batch to the main thread.
@(private = "file")
worker_done :: proc(w: ^Wk_Worker, b: ^Wk_Batch) {
	for !spsc_push(&w.done, b) {
		thread.yield()
	}
	if spsc_len(&w.done) == 1 && w.pool.loop != nil {
		event.wake(w.pool.loop)
	}
}

@(private = "file")
one_done :: proc(w: ^Wk_Worker) {
	sync.mutex_lock(&w.work_mu)
	w.one_done = true
	sync.cond_signal(&w.one_cv)
	sync.mutex_unlock(&w.work_mu)
}

// A command for a data plane. An Install takes over the key that the main
// thread boxed; the box is wiped and freed.
@(private = "file")
worker_cmd :: proc(m: ^Wk_Msg) {
	cmd := &m.cmd
	switch cmd.kind {
	case .Install:
		box := cmd.key
		if !session.dp_apply(m.dp, cmd) {
			crypt.data_key_destroy(box)
		}
		mem.zero_explicit(box, size_of(crypt.Data_Key))
		free(box)
	case .Rekey_Started, .Expire:
		session.dp_apply(m.dp, cmd)
	case .Destroy:
		session.dp_apply(m.dp, cmd)
		free(m.dp)
	}
}

// ------------------------------------------------------------------ the main thread

// Puts a message in the work ring and wakes the worker. The batches of a worker
// use a small part of the ring (see WK_RING); only a burst of commands can fill
// it. A full ring is waited out until the worker takes a message.
@(private = "file")
post :: proc(w: ^Wk_Worker, m: Wk_Msg) {
	sync.mutex_lock(&w.work_mu)
	for !spsc_push(&w.work, m) {
		w.room_wait = true
		sync.cond_wait(&w.room_cv, &w.work_mu)
	}
	if w.work_idle {
		sync.cond_signal(&w.work_cv)
	}
	sync.mutex_unlock(&w.work_mu)
}

// Posts the batch that is being filled.
@(private = "file")
lane_post :: proc(w: ^Wk_Worker, l: ^Wk_Lane) {
	b := l.open
	if b == nil {
		return
	}
	l.open = nil
	l.posted += 1
	post(w, Wk_Msg{kind = b.kind, batch = b})
}

// Adds a packet to the open batch of a lane (a new batch if none or full) and
// copies it into the batch. Seal: `src` is a slot with the payload at
// TUNNEL_HEADROOM, `n` bytes. Open: `src` is the packet. Nil: no free batch, or
// the packet does not fit a slot; the caller drops it. `id` is the job number
// (see `pool_jobs`). The job is valid until `batch_free` of its batch.
job_add :: proc(w: ^Wk_Worker, lane: Lane, dp: ^session.Data_Plane, src: []u8, n: int, now: time.Duration) -> (j: ^Wk_Job, id: int) {
	size := len(src) if lane == .Rx else session.TUNNEL_HEADROOM + n
	if size > WK_SLOT {
		return nil, -1
	}
	l := &w.lanes[lane]
	b := l.open
	if b != nil && b.count == WK_JOBS {
		lane_post(w, l)
		b = nil
	}
	if b == nil {
		if l.nfree == 0 {
			w.drops[lane] += 1
			return nil, -1
		}
		l.nfree -= 1
		b = l.free[l.nfree]
		b.count = 0
		l.open = b
	}
	k := b.count
	b.count += 1
	slot := b.mem[k * WK_SLOT:][:WK_SLOT]
	j = &b.jobs[k]
	j^ = {
		dp      = dp,
		n       = n,
		now     = now,
		counted = true,
	}
	if lane == .Rx {
		copy(slot, src)
		j.buf = slot[:len(src)]
	} else {
		copy(slot[session.TUNNEL_HEADROOM:], src[session.TUNNEL_HEADROOM:][:n])
		j.buf = slot
	}
	return j, b.first + k
}

// Posts the open batches of every worker. Call it at the end of a round of
// reading: the workers start at once, the main thread goes on.
pool_post :: proc(p: ^Wk_Pool) {
	for &w in p.workers {
		post_open(&w)
	}
}

// A finished batch, or nil. Never waits. Batches of one worker come in the order
// they were posted. Give each one back with `batch_free` when its results are used.
pool_next :: proc(p: ^Wk_Pool) -> ^Wk_Batch {
	n := len(p.workers)
	for k in 0 ..< n {
		i := (p.next + k) % n
		if b, ok := spsc_pop(&p.workers[i].done); ok {
			b.lane.posted -= 1
			p.next = (i + 1) % n
			return b
		}
	}
	return nil
}

// Packets a lane of `w` can take before `job_add` drops.
lane_room :: proc(w: ^Wk_Worker, lane: Lane) -> int {
	l := &w.lanes[lane]
	r := l.nfree * WK_JOBS
	if l.open != nil {
		r += WK_JOBS - l.open.count
	}
	return r
}

// The smallest room of a lane over all workers: a read may hold packets for any of them.
pool_room :: proc(p: ^Wk_Pool, lane: Lane) -> int {
	r := max(int)
	for &w in p.workers {
		r = min(r, lane_room(&w, lane))
	}
	return r
}

// The batch can be filled again. Its jobs and memory are not valid after this.
batch_free :: proc(b: ^Wk_Batch) {
	l := b.lane
	l.free[l.nfree] = b
	l.nfree += 1
}

// Posts the open batches of every lane of one worker, so that what comes next
// in the ring comes after the packets added so far.
@(private = "file")
post_open :: proc(w: ^Wk_Worker) {
	for &l in w.lanes {
		lane_post(w, &l)
	}
}

// ------------------------------------------------------------------ sessions

// Gives the data channel of a session to the least loaded worker. `take` is the
// daemon hook (`session.Dp_Remote`); `host` goes with it. Call after the session
// is created, before it starts.
pool_attach :: proc(p: ^Wk_Pool, s: ^session.Session, host: rawptr, take: proc(host: rawptr, s: ^session.Session, pkt: []u8, now: time.Duration) -> bool) -> (w: ^Wk_Worker, ok: bool) {
	w = pool_pick(p)
	remote := session.Dp_Remote {
		user   = w,
		host   = host,
		submit = remote_submit,
		seal   = remote_seal,
		open   = remote_open,
		take   = take,
	}
	dp := session.session_set_remote(s, remote)
	if dp == nil {
		return nil, false
	}
	w.peers += 1
	return w, true
}

remote_submit :: proc(user: rawptr, dp: ^session.Data_Plane, cmd: ^session.Dp_Cmd) {
	w := (^Wk_Worker)(user)
	post_open(w)
	m := Wk_Msg {
		kind = .Cmd,
		dp   = dp,
		cmd  = cmd^,
	}
	if cmd.kind == .Install {
		box := new(crypt.Data_Key, w.pool.allocator)
		box^ = cmd.key^
		m.cmd.key = box
	}
	if cmd.kind == .Destroy {
		w.peers -= 1
	}
	post(w, m)
}

// Runs the `One_*` job in `w.one` after what the worker has, and waits for it.
@(private = "file")
run_one :: proc(w: ^Wk_Worker, kind: Wk_Kind) {
	post_open(w)
	w.one_done = false
	post(w, Wk_Msg{kind = kind})
	sync.mutex_lock(&w.work_mu)
	for !w.one_done {
		sync.cond_wait(&w.one_cv, &w.work_mu)
	}
	sync.mutex_unlock(&w.work_mu)
}

// One packet the session created, sealed now (a keepalive, an exit notice).
remote_seal :: proc(user: rawptr, dp: ^session.Data_Plane, buf: []u8, n: int, counted: bool, now: time.Duration) -> session.Dp_Seal {
	w := (^Wk_Worker)(user)
	w.one = {
		dp      = dp,
		buf     = buf,
		n       = n,
		now     = now,
		counted = counted,
	}
	run_one(w, .One_Seal)
	return w.one.seal
}

remote_open :: proc(user: rawptr, dp: ^session.Data_Plane, pkt: []u8, now: time.Duration) -> session.Dp_Open {
	w := (^Wk_Worker)(user)
	w.one = {
		dp  = dp,
		buf = pkt,
		now = now,
	}
	run_one(w, .One_Open)
	return w.one.open
}

// ------------------------------------------------------------------ status

// How many workers there are (0: none).
pool_count :: proc(p: ^Wk_Pool) -> int {
	if p == nil {
		return 0
	}
	return len(p.workers)
}

// "workers=2 peers=3,4 drops=0/0,0/0" (receive/send of each worker), or "workers=0".
pool_text :: proc(p: ^Wk_Pool) -> string {
	if p == nil {
		return "workers=0"
	}
	b: strings.Builder
	strings.builder_init(&b, context.temp_allocator)
	fmt.sbprintf(&b, "workers=%d peers=", len(p.workers))
	for &w, i in p.workers {
		if i > 0 {
			strings.write_byte(&b, ',')
		}
		fmt.sbprintf(&b, "%d", w.peers)
	}
	strings.write_string(&b, " drops=")
	for &w, i in p.workers {
		if i > 0 {
			strings.write_byte(&b, ',')
		}
		fmt.sbprintf(&b, "%d/%d", w.drops[.Rx], w.drops[.Tx])
	}
	return strings.to_string(b)
}

// `workers` (number) and `worker_peers` (the peers of each worker) for the bus.
pool_write_bus :: proc(w: ^bus.Writer, p: ^Wk_Pool) {
	bus.kv_int(w, "workers", i64(pool_count(p)))
	bus.kv_arr(w, "worker_peers")
	if p != nil {
		for &wk in p.workers {
			bus.val_int(w, i64(wk.peers))
		}
	}
	bus.end(w)
}
