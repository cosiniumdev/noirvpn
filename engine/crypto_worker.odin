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
import "noir:proto/crypt"
import "noir:proto/session"

// Crypto worker threads (`workers N`). The data channel of a peer (keys, send
// counters, replay windows: `session.Data_Plane`) lives on one worker while the
// peer exists; the worker seals and opens in place. The main thread
// keeps sockets, tun, routing, control channel and queues.
//
//	main thread                                  worker k
//	  job_add          fill a batch
//	  lanes_run        post the batch  ---->  work ring  ---->  seal or open each packet
//	                   wait for it     <----  done ring  <----  (in place, in order)
//	  read the results, use the buffers again
//
// A batch: up to WK_JOBS packets of one kind, any peers of that worker. Buffers
// belong to the daemon (receive buffer, send slots); a job holds a slice and the
// result, no copy. The main thread must not touch a buffer from `job_add` to the
// end of `lanes_run`.
//
// Commands for a data plane (new key, soft reset, end of a peer) use the same
// work ring and post the open batches first. So a command applies after earlier
// packets and before later ones: a key installed between two batches applies to
// the second. AEAD contexts of the key are created on the main thread and belong to
// the worker from the command on.
//
// Rings: single producer, single consumer, fixed size, one semaphore each. An
// idle worker sleeps; the main thread sleeps while it waits for a result (bounded:
// a worker never stops on its own). `pool_stop` sends a stop message and joins.
//
// Two lanes, receive (open) and send (seal), with separate batches: the daemon
// can read results of one direction while adding jobs to the other.

WK_JOBS :: 64 // packets in one batch
WK_BATCHES :: 32 // batches in one lane of one worker
WK_RING :: 256 // messages in a ring (a power of two)
// Packets one lane of one worker holds before `job_add` says no.
WK_LANE_JOBS :: WK_JOBS * WK_BATCHES

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
	// packet, opened in place.
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
	lane:  ^Wk_Lane, // nil for the batch that stands for a `One_*` message
	kind:  Wk_Kind,
	count: int,
	jobs:  [WK_JOBS]Wk_Job,
}

// What goes through the work ring.
Wk_Msg :: struct {
	kind:  Wk_Kind,
	batch: ^Wk_Batch,
	dp:    ^session.Data_Plane,
	cmd:   session.Dp_Cmd,
}

// The batches of one direction on one worker. They are taken in order and all
// given back together (`lanes_recycle`) when the results are read.
Wk_Lane :: struct {
	batches: []Wk_Batch,
	used:    int, // batches taken since the last recycle
	posted:  int, // of them posted
	waited:  int, // of them that came back
	open:    ^Wk_Batch, // being filled, or nil
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
	work_sem:    sync.Sema,
	done_sem:    sync.Sema,
	lanes:       [Lane]Wk_Lane,
	// The packet of a `One_*` message, its result, and the batch that stands for
	// it in the done ring.
	one:         Wk_Job,
	one_batch:   Wk_Batch,
	one_back:    bool,
	// Peers pinned to this worker.
	peers:       int,
	// Written by the worker, read for the status text.
	batches_run: u64,
	jobs_run:    u64,
}

Wk_Pool :: struct {
	workers:   []Wk_Worker,
	allocator: mem.Allocator,
	// Set when `pool_stop` begins: no more jobs.
	stopping:  bool,
}

// ------------------------------------------------------------------ start, stop

// Starts `n` workers. Nil if a thread or memory is not available (what was
// started is stopped).
pool_start :: proc(n: int) -> ^Wk_Pool {
	p := new(Wk_Pool)
	p.allocator = context.allocator
	p.workers = make([]Wk_Worker, n)
	for &w, i in p.workers {
		w.index = i
		w.pool = p
		w.one_batch.kind = .One_Seal
		for &l in w.lanes {
			l.batches = make([]Wk_Batch, WK_BATCHES)
		}
		for lane in Lane {
			for &b in w.lanes[lane].batches {
				b.lane = &w.lanes[lane]
				b.kind = .Open if lane == .Rx else .Seal
			}
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

// Stops the workers (each finishes the messages it has) and frees everything.
// Nothing may be in flight: the caller has read all results.
pool_stop :: proc(p: ^Wk_Pool) {
	if p == nil {
		return
	}
	p.stopping = true
	// Batches that were posted and never read must not fill the done ring.
	for lane in Lane {
		lane_run(p, lane)
		lane_recycle(p, lane)
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
	}
	delete(p.workers)
	free(p)
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
		sync.sema_wait(&w.work_sem)
		m, ok := spsc_pop(&w.work)
		if !ok {
			continue
		}
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
			worker_done(w, &w.one_batch)
		case .One_Open:
			j := &w.one
			j.open = session.dp_open(j.dp, j.buf, j.now)
			session.dp_publish(j.dp)
			worker_done(w, &w.one_batch)
		}
	}
}

@(private = "file")
worker_done :: proc(w: ^Wk_Worker, b: ^Wk_Batch) {
	// The ring holds more than the batches that can be out.
	for !spsc_push(&w.done, b) {
		time.sleep(20 * time.Microsecond)
	}
	sync.sema_post(&w.done_sem)
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

// Puts a message in the work ring and wakes the worker. A full ring (a burst of
// commands) is waited out: the worker takes a message every few microseconds.
@(private = "file")
post :: proc(w: ^Wk_Worker, m: Wk_Msg) {
	for !spsc_push(&w.work, m) {
		time.sleep(20 * time.Microsecond)
	}
	sync.sema_post(&w.work_sem)
}

// Waits for one entry of the done ring and credits it to its lane.
@(private = "file")
collect_one :: proc(w: ^Wk_Worker) {
	sync.sema_wait(&w.done_sem)
	b, ok := spsc_pop(&w.done)
	for !ok {
		b, ok = spsc_pop(&w.done)
	}
	if b.lane == nil {
		w.one_back = true
	} else {
		b.lane.waited += 1
	}
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

// Adds a packet to the open batch of a lane (new batch if none or full). Nil:
// no room - run the lane, read the results, recycle it. The job stays valid
// until `lanes_recycle`.
job_add :: proc(w: ^Wk_Worker, lane: Lane, dp: ^session.Data_Plane, buf: []u8, n: int, now: time.Duration) -> ^Wk_Job {
	l := &w.lanes[lane]
	b := l.open
	if b != nil && b.count == WK_JOBS {
		lane_post(w, l)
		b = nil
	}
	if b == nil {
		if l.used == len(l.batches) {
			return nil
		}
		b = &l.batches[l.used]
		l.used += 1
		b.count = 0
		l.open = b
	}
	j := &b.jobs[b.count]
	b.count += 1
	j^ = {
		dp      = dp,
		buf     = buf,
		n       = n,
		now     = now,
		counted = true,
	}
	return j
}

// Posts what is open on every worker, then waits until every batch of the lane
// is back. After this the results of the lane's jobs can be read.
lane_run :: proc(p: ^Wk_Pool, lane: Lane) {
	for &w in p.workers {
		lane_post(&w, &w.lanes[lane])
	}
	for &w in p.workers {
		l := &w.lanes[lane]
		for l.waited < l.posted {
			collect_one(&w)
		}
	}
}

// Gives the batches of a lane back. The results are not valid after this.
lane_recycle :: proc(p: ^Wk_Pool, lane: Lane) {
	for &w in p.workers {
		l := &w.lanes[lane]
		l.used, l.posted, l.waited = 0, 0, 0
		l.open = nil
	}
}

// Is any job waiting in a lane (added, results not read yet)?
lane_busy :: proc(p: ^Wk_Pool, lane: Lane) -> bool {
	for &w in p.workers {
		if w.lanes[lane].used > 0 {
			return true
		}
	}
	return false
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

// Gives the data channel of a session to the least loaded worker. `take` and
// `barrier` are the daemon hooks (`session.Dp_Remote`); `host` goes with them.
// Call after the session is created, before it starts.
pool_attach :: proc(p: ^Wk_Pool, s: ^session.Session, host: rawptr, take: proc(host: rawptr, s: ^session.Session, pkt: []u8, now: time.Duration) -> bool, barrier: proc(host: rawptr)) -> (w: ^Wk_Worker, ok: bool) {
	w = pool_pick(p)
	remote := session.Dp_Remote {
		user    = w,
		host    = host,
		submit  = remote_submit,
		seal    = remote_seal,
		open    = remote_open,
		take    = take,
		barrier = barrier,
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

// One packet the session created, sealed now (a keepalive, an exit notice).
remote_seal :: proc(user: rawptr, dp: ^session.Data_Plane, buf: []u8, n: int, counted: bool, now: time.Duration) -> session.Dp_Seal {
	w := (^Wk_Worker)(user)
	post_open(w)
	w.one = {
		dp      = dp,
		buf     = buf,
		n       = n,
		now     = now,
		counted = counted,
	}
	w.one_back = false
	post(w, Wk_Msg{kind = .One_Seal})
	for !w.one_back {
		collect_one(w)
	}
	return w.one.seal
}

remote_open :: proc(user: rawptr, dp: ^session.Data_Plane, pkt: []u8, now: time.Duration) -> session.Dp_Open {
	w := (^Wk_Worker)(user)
	post_open(w)
	w.one = {
		dp  = dp,
		buf = pkt,
		now = now,
	}
	w.one_back = false
	post(w, Wk_Msg{kind = .One_Open})
	for !w.one_back {
		collect_one(w)
	}
	return w.one.open
}

// ------------------------------------------------------------------ status

// How many workers there are (0: none) and how many peers each one has.
pool_count :: proc(p: ^Wk_Pool) -> int {
	if p == nil {
		return 0
	}
	return len(p.workers)
}

// "workers=2 peers=3,4", or "workers=0".
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
