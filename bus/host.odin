// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Daemon side of the bus: the events stream and the control channel.
//
// Threads:
//   loop thread     The daemon's single event-loop thread. Calls `publish`,
//                   `next_request`, `next_notice`, `reply_*`, `host_close`.
//                   None blocks on the transport or on another thread (short
//                   lock only).
//   worker threads  `workers` Odin threads. A worker:
//                   1. receives a request with its sender identity
//                   2. checks size, syntax, role, mode; replies with errors itself
//                   3. queues a valid request for the loop
//                   4. sleeps until the loop replies (or timeout), then sends
//
// The transport is behind a seam (transport_nng.odin on Unix: nng PUB and REP;
// transport_pipe.odin on Windows: two named pipes):
//   transport_prepare          directories (Unix)
//   transport_listen_events    start the events endpoint, a queue per subscriber
//   transport_listen_control   start the control endpoint
//   transport_recv             a worker waits for one request and its sender
//   peer_identity              credentials and roles of the sender
//   transport_send             the reply to that request
//   transport_publish          one event to every subscriber, never blocks
//   transport_stop             wake the workers in transport_recv
//   transport_close            close the endpoints
// The loop never calls the transport for a reply: `reply_ok` stores the bytes
// and wakes the worker.
//
// Wake-up: the wake object (`host_wake_fd` Unix, `host_wake_handle` Windows) is
// ready while the queue holds a request or notice. Register it with the event
// loop. When it fires, call `next_request` and `next_notice` until each returns
// false. It goes quiet when both are empty.
//
// Limit: at most `max_pending` requests are queued or in the loop; the next
// gets `busy`. `max_pending` is below `workers`, so a worker is always free to
// say `busy` and a flood cannot starve the socket.

import "base:intrinsics"
import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

Request_State :: enum u8 {
	// In the queue, not yet taken by the loop.
	Queued,
	// The loop has it and has not replied.
	Active,
	Replied,
	// The worker gave up (timeout or shutdown) before the loop replied.
	Abandoned,
}

// A request handed to the loop. The loop reads the public fields and replies
// with `reply_ok` or `reply_error`, once.
// - After the reply the pointer is invalid.
// - A reply may come later than the handler returns. Keep the pointer until
//   then.
// - Do not use the pointer after `host_close`.
Request :: struct {
	// The request id, the operation and its args. `args` is empty when the
	// request had none. All of it lives until the reply.
	id:         string,
	op:         string,
	info:       ^Op_Info,
	args:       json.Object,
	// Who sent it, and what roles that gives them (for audit logs).
	creds:      Peer_Creds,
	roles:      Roles,

	// Private.
	root:       json.Value,
	state:      Request_State,
	reply:      []byte,
	reply_code: Maybe(Error_Code),
	loop_ref:   bool,
	worker_ref: bool,
	linked:     bool,
	prev, next: ^Request,
}

Notice_Kind :: enum u8 {
	// A request was refused for lack of a role, or credentials could not be read.
	Denied,
	// Malformed request: bad JSON, too big, unknown op, wrong mode.
	Bad_Request,
	// A request was turned away because the queue was full.
	Busy,
	// The loop did not reply to a request in time.
	Reply_Timeout,
}

NOTICE_TEXT_MAX :: 64

// Something the daemon should log. The bus never logs by itself.
Notice :: struct {
	kind:      Notice_Kind,
	// The sender. Only valid when `has_creds`. On Windows `sid` is the user.
	uid, gid:  u32,
	sid:       Sid,
	pid:       u32,
	has_pid:   bool,
	has_creds: bool,
	op:        [MAX_OP_LEN]u8,
	op_len:    u8,
	text:      [NOTICE_TEXT_MAX]u8,
	text_len:  u8,
}

notice_op :: proc(n: ^Notice) -> string {
	return string(n.op[:n.op_len])
}

notice_text :: proc(n: ^Notice) -> string {
	return string(n.text[:n.text_len])
}

NOTICE_QUEUE :: 32

Host_Stats :: struct {
	// Events handed to the transport, and events that could not be (bad
	// topic, transport error). nng drops events for a slow subscriber without
	// telling us. The pipe transport disconnects that subscriber. Subscribers
	// see the loss as a gap in `seq`.
	published:       u64,
	publish_errors:  u64,
	// Requests received on the control socket.
	requests:        u64,
	// Replies the loop sent, by outcome.
	replied_ok:      u64,
	replied_error:   u64,
	denied:          u64,
	bad_requests:    u64,
	busy:            u64,
	// Repeats replied to from the cache.
	deduped:         u64,
	reply_timeouts:  u64,
	notices_dropped: u64,
}

Host_Options :: struct {
	mode:          Daemon_Mode,
	// nil turns the socket off.
	events:        Maybe(Endpoint),
	control:       Maybe(Endpoint),
	// The host keeps its own copy.
	policy:        Policy,
	// Says if a user is a member of a group, for the `gid` rules. nil: the
	// group database of the system.
	member:        Member_Check,
	// Control worker threads. Default 8, at least 2.
	workers:       int,
	// Most requests queued or in the loop's hands. Default 6; at most
	// workers - 1.
	max_pending:   int,
	// How long a worker waits for the loop's reply. Default 30 s.
	reply_timeout: time.Duration,
	// How long a state-changing request's reply is kept. Default 120 s.
	dedupe_window: time.Duration,
	// Most cached replies. Default 256.
	dedupe_max:    int,
	// Messages queued for each subscriber. Default 256. When the queue is
	// full, nng drops the event; the pipe transport disconnects the subscriber.
	events_buffer: int,
	// Default context.allocator. It must be safe to use from several threads.
	allocator:     mem.Allocator,
}

Open_Error :: enum u8 {
	None,
	No_Memory,
	Wake_Failed,
	Bad_Group,
	// The directory exists but is not safe (wrong owner or writable by others),
	// or could not be created.
	Dir_Not_Safe,
	Dir_Create_Failed,
	Socket_Open_Failed,
	Events_In_Use,
	Events_Listen_Failed,
	Events_Chown_Failed,
	Control_In_Use,
	Control_Listen_Failed,
	Control_Chown_Failed,
	Thread_Failed,
}

open_error_string :: proc(e: Open_Error) -> string {
	switch e {
	case .None:
		return "ok"
	case .No_Memory:
		return "out of memory"
	case .Wake_Failed:
		return "cannot create the wake-up descriptor"
	case .Bad_Group:
		return "the group set for a bus socket does not exist"
	case .Dir_Not_Safe:
		return "the socket directory is not safe (it has the wrong owner, or other users can write to it)"
	case .Dir_Create_Failed:
		return "cannot create the socket directory"
	case .Socket_Open_Failed:
		return "cannot open a bus socket"
	case .Events_In_Use:
		return "another process is already using the events socket (choose a different name)"
	case .Events_Listen_Failed:
		return "cannot listen on the events socket"
	case .Events_Chown_Failed:
		return "cannot set the group of the events socket"
	case .Control_In_Use:
		return "another process is already using the control socket (choose a different name)"
	case .Control_Listen_Failed:
		return "cannot listen on the control socket"
	case .Control_Chown_Failed:
		return "cannot set the group of the control socket"
	case .Thread_Failed:
		return "cannot start a control worker thread"
	}
	return "?"
}

@(private)
Worker :: struct {
	host:   ^Host,
	tw:     Transport_Worker,
	thread: ^thread.Thread,
	out:    Writer,
	// The `gid` rules to ask the group database about, for the request in work.
	groups: [dynamic]Rule,
}

Host :: struct {
	allocator:     mem.Allocator,
	mode:          Daemon_Mode,
	t0:            time.Duration, // mono_now() at open

	tr:            Transport,

	// Events.
	pub_on:        bool,
	pub_mu:        sync.Mutex,
	pub_buf:       Writer,
	run:           [RUN_ID_LEN]u8,
	seq:           u64,
	events_path:   string,

	// Control.
	rep_on:        bool,
	control_path:  string,
	workers:       []Worker,
	max_pending:   int,
	reply_timeout: time.Duration,

	// Everything below is guarded by `mu`; `cond` signals any change.
	mu:            sync.Mutex,
	cond:          sync.Cond,
	closing:       bool,
	policy:        Policy,
	member:        Member_Check,
	queue:         [dynamic]^Request,
	live:          ^Request,
	pending:       int,
	busy_workers:  int,
	signaled:      bool,
	notices:       [NOTICE_QUEUE]Notice,
	n_head:        int,
	n_count:       int,
	dedupe:        Dedupe,

	wake:          Wake,
	// Monotonic nanoseconds of the last send, for the linger in host_close.
	last_send:     i64,
	stats:         Host_Stats,
}

@(private)
now_ns :: proc(h: ^Host) -> i64 {
	return i64(mono_now() - h.t0)
}

// Open the endpoints and start the workers. On Unix the directory of each
// socket is created if missing (mode 0750) or checked if it exists. Free with
// `host_close`.
host_open :: proc(opts: Host_Options) -> (h: ^Host, err: Open_Error, nng_err: Transport_Error) {
	allocator := opts.allocator
	if allocator.procedure == nil {
		allocator = context.allocator
	}
	context.allocator = allocator

	h = new(Host, allocator)
	if h == nil {
		return nil, .No_Memory, .None
	}
	h.allocator = allocator
	h.mode = opts.mode
	h.t0 = mono_now()
	h.reply_timeout = opts.reply_timeout if opts.reply_timeout > 0 else 30 * time.Second

	n_workers := max(opts.workers if opts.workers > 0 else 8, 2)
	h.max_pending = opts.max_pending if opts.max_pending > 0 else 6
	h.max_pending = min(h.max_pending, n_workers - 1)
	h.max_pending = max(h.max_pending, 1)
	window := opts.dedupe_window if opts.dedupe_window > 0 else 120 * time.Second
	dedupe_max := opts.dedupe_max if opts.dedupe_max > 0 else 256
	dedupe_init(&h.dedupe, i64(window), dedupe_max, allocator)
	h.queue = make([dynamic]^Request, allocator)
	h.policy = policy_clone(opts.policy, allocator)
	h.member = opts.member if opts.member != nil else default_member
	writer_init(&h.pub_buf, allocator)

	run := random_hex(RUN_ID_LEN / 2, context.temp_allocator)
	copy(h.run[:], run)

	if !wake_open(&h.wake) {
		host_close(h, 0)
		return nil, .Wake_Failed, .None
	}

	ev, has_events := opts.events.?
	ctl, has_control := opts.control.?
	if e := transport_prepare(h, opts); e != .None {
		host_close(h, 0)
		return nil, e, .None
	}

	if has_events {
		e, ne := open_events(h, ev, opts.events_buffer if opts.events_buffer > 0 else 256)
		if e != .None {
			host_close(h, 0)
			return nil, e, ne
		}
	}
	if has_control {
		e, ne := open_control(h, ctl, n_workers)
		if e != .None {
			host_close(h, 0)
			return nil, e, ne
		}
	}
	return h, .None, .None
}

@(private)
open_events :: proc(h: ^Host, ep: Endpoint, buffer: int) -> (Open_Error, Transport_Error) {
	h.pub_on = true
	h.events_path = strings.clone(ep.path, h.allocator)
	return transport_listen_events(h, ep, buffer)
}

@(private)
open_control :: proc(h: ^Host, ep: Endpoint, n_workers: int) -> (Open_Error, Transport_Error) {
	h.rep_on = true
	h.control_path = strings.clone(ep.path, h.allocator)
	h.workers = make([]Worker, n_workers, h.allocator)
	for i in 0 ..< n_workers {
		w := &h.workers[i]
		w.host = h
		writer_init(&w.out, h.allocator)
		w.groups = make([dynamic]Rule, h.allocator)
	}
	if e, ne := transport_listen_control(h, ep, n_workers); e != .None {
		return e, ne
	}
	for i in 0 ..< n_workers {
		w := &h.workers[i]
		t := thread.create(worker_main)
		if t == nil {
			return .Thread_Failed, .None
		}
		t.data = w
		w.thread = t
		thread.start(t)
	}
	return .None, .None
}

// The start id and the sequence number of the last event published. A client
// that just subscribed compares them with the events it sees, to find out if
// it missed any (put them in the `status` result).
host_position :: proc(h: ^Host) -> (run: string, seq: u64) {
	sync.mutex_lock(&h.pub_mu)
	defer sync.mutex_unlock(&h.pub_mu)
	return string(h.run[:]), h.seq
}

host_stats :: proc(h: ^Host) -> (s: Host_Stats) {
	s.published = intrinsics.atomic_load(&h.stats.published)
	s.publish_errors = intrinsics.atomic_load(&h.stats.publish_errors)
	s.requests = intrinsics.atomic_load(&h.stats.requests)
	s.replied_ok = intrinsics.atomic_load(&h.stats.replied_ok)
	s.replied_error = intrinsics.atomic_load(&h.stats.replied_error)
	s.denied = intrinsics.atomic_load(&h.stats.denied)
	s.bad_requests = intrinsics.atomic_load(&h.stats.bad_requests)
	s.busy = intrinsics.atomic_load(&h.stats.busy)
	s.deduped = intrinsics.atomic_load(&h.stats.deduped)
	s.reply_timeouts = intrinsics.atomic_load(&h.stats.reply_timeouts)
	s.notices_dropped = intrinsics.atomic_load(&h.stats.notices_dropped)
	return
}

// Replace the authorisation policy (config reload). The host keeps a copy.
host_set_policy :: proc(h: ^Host, p: ^Policy) {
	fresh := policy_clone(p^, h.allocator)
	sync.mutex_lock(&h.mu)
	old := h.policy
	h.policy = fresh
	sync.mutex_unlock(&h.mu)
	policy_destroy(&old)
}

// Publish one event: `topic` (like "peer.connect") and `data`, a JSON object
// text (nil means {}). Adds the envelope with the next sequence number and the
// time. Never blocks.
// Returns false if the event could not be handed to the transport (counted in
// `publish_errors`). It still uses a sequence number then, so subscribers see
// a gap.
// Safe from any thread.
publish :: proc(h: ^Host, topic: string, data: []byte = nil) -> bool {
	if h == nil || !h.pub_on {
		return false
	}
	if !valid_name(topic, MAX_TOPIC_LEN) {
		intrinsics.atomic_add(&h.stats.publish_errors, 1)
		return false
	}
	sync.mutex_lock(&h.pub_mu)
	defer sync.mutex_unlock(&h.pub_mu)
	h.seq += 1
	ts_buf: [24]u8
	ts := format_ts(time.now(), &ts_buf)
	writer_reset(&h.pub_buf)
	write_event(&h.pub_buf, string(h.run[:]), h.seq, ts, topic, data)
	if h.pub_buf.failed || len(h.pub_buf.buf) > MAX_EVENT_SIZE {
		intrinsics.atomic_add(&h.stats.publish_errors, 1)
		return false
	}
	if !transport_publish(h, topic, writer_bytes(&h.pub_buf)) {
		intrinsics.atomic_add(&h.stats.publish_errors, 1)
		return false
	}
	intrinsics.atomic_store(&h.last_send, now_ns(h))
	intrinsics.atomic_add(&h.stats.published, 1)
	return true
}

// ---- the loop's side of the queue ----

// Set the wake fd readable, once, until the queues are empty. Lock held.
@(private)
signal_locked :: proc(h: ^Host) {
	if !h.signaled {
		h.signaled = true
		wake_signal(&h.wake)
	}
}

@(private)
clear_wake_locked :: proc(h: ^Host) {
	if h.signaled && len(h.queue) == 0 && h.n_count == 0 {
		h.signaled = false
		wake_clear(&h.wake)
	}
}

// Take the next request, or false if none is waiting. Loop thread only.
next_request :: proc(h: ^Host) -> (req: ^Request, ok: bool) {
	sync.mutex_lock(&h.mu)
	defer sync.mutex_unlock(&h.mu)
	for len(h.queue) > 0 {
		r := h.queue[0]
		ordered_remove(&h.queue, 0)
		if r.state == .Abandoned {
			release_loop_locked(h, r)
			continue
		}
		r.state = .Active
		clear_wake_locked(h)
		return r, true
	}
	clear_wake_locked(h)
	return nil, false
}

// Take the next thing to log, or false if none. Loop thread only.
next_notice :: proc(h: ^Host) -> (n: Notice, ok: bool) {
	sync.mutex_lock(&h.mu)
	defer sync.mutex_unlock(&h.mu)
	if h.n_count == 0 {
		clear_wake_locked(h)
		return {}, false
	}
	n = h.notices[h.n_head]
	h.n_head = (h.n_head + 1) % NOTICE_QUEUE
	h.n_count -= 1
	clear_wake_locked(h)
	return n, true
}

// Reply with a result. `result` is a JSON value (usually an object), nil
// means {}. Returns false if nobody waits for the reply any more (the worker
// timed out, or the host is closing). The request is then released.
reply_ok :: proc(h: ^Host, req: ^Request, result: []byte = nil) -> bool {
	w: Writer
	writer_init(&w, h.allocator)
	write_reply_ok(&w, req.id, result)
	return complete(h, req, &w, nil)
}

reply_error :: proc(h: ^Host, req: ^Request, code: Error_Code, message: string) -> bool {
	return reply_error_details(h, req, code, message, nil)
}

// Like `reply_error`, with a `details` array in the error object. `details` is
// JSON text of an array (for example a list of objects). Anything else is left
// out.
reply_error_details :: proc(h: ^Host, req: ^Request, code: Error_Code, message: string, details: []byte) -> bool {
	w: Writer
	writer_init(&w, h.allocator)
	d := details if len(details) > 0 && details[0] == '[' else nil
	write_reply_error_details(&w, req.id, code, message, d)
	return complete(h, req, &w, code)
}

// `bad_request` for an argument that `arg_*` rejected.
reply_bad_arg :: proc(h: ^Host, req: ^Request, name: string, e: Arg_Error) -> bool {
	buf: [160]byte
	return reply_error(h, req, .Bad_Request, arg_message(name, e, buf[:]))
}

@(private)
complete :: proc(h: ^Host, req: ^Request, w: ^Writer, code: Maybe(Error_Code)) -> bool {
	sync.mutex_lock(&h.mu)
	defer sync.mutex_unlock(&h.mu)
	if req.state != .Active || w.failed {
		if req.state == .Abandoned && req.loop_ref {
			release_loop_locked(h, req)
		}
		writer_destroy(w)
		return false
	}
	req.reply = writer_bytes(w)
	req.reply_code = code
	req.state = .Replied
	h.pending -= 1
	if code == nil {
		intrinsics.atomic_add(&h.stats.replied_ok, 1)
	} else {
		intrinsics.atomic_add(&h.stats.replied_error, 1)
	}
	release_loop_locked(h, req)
	sync.cond_broadcast(&h.cond)
	return true
}

// The loop is done with the request (or the queue dropped it).
@(private)
release_loop_locked :: proc(h: ^Host, r: ^Request) {
	r.loop_ref = false
	if !r.worker_ref {
		request_free_locked(h, r)
	}
}

@(private)
request_free_locked :: proc(h: ^Host, r: ^Request) {
	if r.linked {
		if r.prev != nil {
			r.prev.next = r.next
		} else {
			h.live = r.next
		}
		if r.next != nil {
			r.next.prev = r.prev
		}
	}
	if r.info != nil && r.info.secret {
		wipe_args_of(r.root)
	}
	json.destroy_value(r.root, h.allocator)
	// A reply may carry a password (`auth.credentials`): overwrite it.
	if len(r.reply) > 0 {
		mem.zero_explicit(raw_data(r.reply), len(r.reply))
	}
	delete(r.reply, h.allocator)
	free(r, h.allocator)
}

@(private)
push_notice_locked :: proc(
	h: ^Host,
	kind: Notice_Kind,
	creds: Peer_Creds,
	has_creds: bool,
	op, text: string,
) {
	if h.n_count == NOTICE_QUEUE {
		intrinsics.atomic_add(&h.stats.notices_dropped, 1)
		return
	}
	n := &h.notices[(h.n_head + h.n_count) % NOTICE_QUEUE]
	n^ = {
		kind      = kind,
		uid       = creds.uid,
		gid       = creds.gid,
		sid       = creds.sid,
		pid       = creds.pid,
		has_pid   = creds.has_pid,
		has_creds = has_creds,
	}
	n.op_len = u8(copy(n.op[:], op))
	n.text_len = u8(copy(n.text[:], text))
	h.n_count += 1
	signal_locked(h)
}

@(private)
push_notice :: proc(h: ^Host, kind: Notice_Kind, creds: Peer_Creds, has_creds: bool, op, text: string) {
	sync.mutex_lock(&h.mu)
	push_notice_locked(h, kind, creds, has_creds, op, text)
	sync.mutex_unlock(&h.mu)
}

// ---- worker threads ----

@(private)
worker_main :: proc(t: ^thread.Thread) {
	w := (^Worker)(t.data)
	h := w.host
	context.allocator = h.allocator
	for {
		m, st := transport_recv(h, w)
		if st != .Ok {
			if st == .Closed || host_closing(h) {
				return
			}
			// Do not spin on a persistent error.
			time.sleep(10 * time.Millisecond)
			continue
		}
		sync.mutex_lock(&h.mu)
		h.busy_workers += 1
		sync.mutex_unlock(&h.mu)

		serve(h, w, &m)

		sync.mutex_lock(&h.mu)
		h.busy_workers -= 1
		sync.cond_broadcast(&h.cond)
		sync.mutex_unlock(&h.mu)
	}
}

@(private)
host_closing :: proc(h: ^Host) -> bool {
	sync.mutex_lock(&h.mu)
	defer sync.mutex_unlock(&h.mu)
	return h.closing
}

// Handle one received message and send the reply.
@(private)
serve :: proc(h: ^Host, w: ^Worker, m: ^Incoming) {
	intrinsics.atomic_add(&h.stats.requests, 1)
	creds, roles, have := peer_identity(h, w, m)
	body := incoming_body(m)
	process(h, w, creds, roles, have, body)
	// The request may hold a secret, and the transport frees a message
	// without zeroing it.
	if len(body) > 0 {
		mem.zero_explicit(raw_data(body), len(body))
	}
	transport_release(h, w, m)

	// The worker's buffer held a copy of the reply (maybe a password): wipe it.
	defer if len(w.out.buf) > 0 {
		mem.zero_explicit(raw_data(w.out.buf), len(w.out.buf))
	}
	if transport_send(h, w, m, writer_bytes(&w.out)) {
		intrinsics.atomic_store(&h.last_send, now_ns(h))
	}
}

@(private)
role_message :: proc(r: Role) -> string {
	switch r {
	case .Read:
		return "this operation requires the read role"
	case .Operator:
		return "this operation requires the operator role"
	case .Auth:
		return "this operation requires the auth role"
	case .Admin:
		return "this operation requires the admin role"
	}
	return "not allowed"
}

// Decide what to do with one request body and write the reply into `w.out`.
// Order: credentials, any role at all, size, syntax, op name, role for the
// op, mode, then the queue.
@(private)
process :: proc(h: ^Host, w: ^Worker, creds: Peer_Creds, roles: Roles, have_creds: bool, body: []byte) {
	out := &w.out
	writer_reset(out)

	deny :: proc(h: ^Host, out: ^Writer, creds: Peer_Creds, have: bool, id, op, text: string) {
		intrinsics.atomic_add(&h.stats.denied, 1)
		push_notice(h, .Denied, creds, have, op, text)
		write_reply_error(out, id, .Denied, text)
	}

	if !have_creds {
		deny(h, out, creds, false, "", "", "the peer credentials of the caller are not available")
		return
	}
	if roles == {} {
		deny(h, out, creds, true, "", "", "the caller has no role on this bus")
		return
	}

	bad :: proc(h: ^Host, out: ^Writer, creds: Peer_Creds, id, op: string, code: Error_Code, text: string) {
		intrinsics.atomic_add(&h.stats.bad_requests, 1)
		push_notice(h, .Bad_Request, creds, true, op, text)
		write_reply_error(out, id, code, text)
	}

	// The operation is not known yet: allow the largest size for now.
	if len(body) > MAX_PROFILE_REQUEST_SIZE {
		bad(h, out, creds, "", "", .Bad_Request, "the request is too large")
		return
	}
	hash := hash_bytes(body)
	p, code, msg, ok := parse_request(body, h.allocator)
	if !ok {
		bad(h, out, creds, p.id, "", code, msg)
		parsed_destroy(&p, h.allocator)
		return
	}
	info, known := op_lookup(p.op)
	if !known {
		bad(h, out, creds, p.id, p.op, .Unknown_Op, "unknown operation")
		parsed_destroy(&p, h.allocator)
		return
	}
	if info.secret {
		// The parse created copies of the strings. Overwrite the raw request now,
		// before the wait for the loop.
		mem.zero_explicit(raw_data(body), len(body))
	}
	if len(body) > MAX_REQUEST_SIZE && !info.big_request {
		bad(h, out, creds, p.id, p.op, .Bad_Request, "the request is too large")
		parsed_drop(h, &p, info)
		return
	}
	if !roles_allow(roles, info.role) {
		deny(h, out, creds, true, p.id, p.op, role_message(info.role))
		parsed_drop(h, &p, info)
		return
	}
	if !op_in_mode(info, h.mode) {
		text := "this operation is only available on a server daemon" if h.mode == .Client else "this operation is only available on a client daemon"
		bad(h, out, creds, p.id, p.op, .Unsupported, text)
		parsed_drop(h, &p, info)
		return
	}
	dispatch(h, w, &p, info, creds, roles, hash)
}

// Frees a parsed request that does not go to the loop. The strings of a
// request with a secret are overwritten first.
@(private)
parsed_drop :: proc(h: ^Host, p: ^Parsed_Request, info: ^Op_Info) {
	if info.secret {
		wipe_args_of(p.root)
	}
	parsed_destroy(p, h.allocator)
}

// Queue a checked request for the loop and wait for the reply.
@(private)
dispatch :: proc(
	h: ^Host,
	w: ^Worker,
	p: ^Parsed_Request,
	info: ^Op_Info,
	creds: Peer_Creds,
	roles: Roles,
	hash: u64,
) {
	out := &w.out
	req, aerr := new(Request, h.allocator)
	if aerr != nil {
		write_reply_error(out, p.id, .Internal, "out of memory")
		parsed_drop(h, p, info)
		return
	}
	req^ = Request {
		id         = p.id,
		op         = p.op,
		info       = info,
		args       = p.args,
		creds      = creds,
		roles      = roles,
		root       = p.root,
		state      = .Queued,
		loop_ref   = true,
		worker_ref = true,
	}
	p^ = {} // the request owns the parsed value now

	key := dedupe_key(creds.uid, req.id)
	track := info.mutating
	deadline := now_ns(h) + i64(h.reply_timeout)

	sync.mutex_lock(&h.mu)
	defer sync.mutex_unlock(&h.mu)

	// Shorthand for the exits that never reach the loop.
	refuse :: proc(h: ^Host, out: ^Writer, req: ^Request, key: Dedupe_Key, forget: bool, code: Error_Code, text: string) {
		if forget {
			dedupe_forget(&h.dedupe, key)
			sync.cond_broadcast(&h.cond)
		}
		write_reply_error(out, req.id, code, text)
		request_free_locked(h, req)
	}

	if h.closing {
		refuse(h, out, req, key, false, .Busy, "the daemon is shutting down")
		return
	}

	if track {
		for {
			res, cached := dedupe_check(&h.dedupe, key, hash, now_ns(h))
			if res == .New {
				break
			}
			if res == .Done {
				put(out, cached)
				intrinsics.atomic_add(&h.stats.deduped, 1)
				request_free_locked(h, req)
				return
			}
			if res == .Conflict {
				refuse(h, out, req, key, false, .Conflict, "this request id was already used for a different request")
				return
			}
			// Pending: the first copy is still running. Wait for it.
			remaining := deadline - now_ns(h)
			if remaining <= 0 || h.closing {
				refuse(h, out, req, key, false, .Timeout, "an earlier copy of this request is still running")
				return
			}
			sync.cond_wait_with_timeout(&h.cond, &h.mu, time.Duration(remaining))
		}
	}

	// `pending` counts the requests someone still waits for. Requests the
	// worker gave up on stay in the queue until the loop looks at them. Do not
	// let those pile up if the loop is stuck.
	if h.pending >= h.max_pending || len(h.queue) >= 4 * h.max_pending {
		intrinsics.atomic_add(&h.stats.busy, 1)
		push_notice_locked(h, .Busy, creds, true, req.op, "the request queue is full")
		refuse(h, out, req, key, track, .Busy, "the daemon is busy right now, so try again later")
		return
	}

	// Queue it.
	h.pending += 1
	req.linked = true
	req.next = h.live
	if h.live != nil {
		h.live.prev = req
	}
	h.live = req
	append(&h.queue, req)
	signal_locked(h)

	for (req.state == .Queued || req.state == .Active) && !h.closing {
		remaining := deadline - now_ns(h)
		if remaining <= 0 {
			break
		}
		sync.cond_wait_with_timeout(&h.cond, &h.mu, time.Duration(remaining))
	}

	code: Maybe(Error_Code)
	switch req.state {
	case .Replied:
		put(out, req.reply)
		code = req.reply_code
	case .Queued, .Active:
		req.state = .Abandoned
		h.pending -= 1
		if h.closing {
			write_reply_error(out, req.id, .Busy, "the daemon is shutting down")
			code = .Busy
		} else {
			intrinsics.atomic_add(&h.stats.reply_timeouts, 1)
			push_notice_locked(h, .Reply_Timeout, creds, true, req.op, "the daemon did not respond in time")
			write_reply_error(out, req.id, .Timeout, "the daemon did not respond in time")
			code = .Timeout
		}
	case .Abandoned:
		// Not possible: only this worker abandons.
		write_reply_error(out, req.id, .Internal, "internal error")
	}

	if track {
		// A busy or timeout reply means the request may not have run: keep no
		// record, so a retry with the same id runs it.
		if c, is_err := code.?; is_err && (c == .Busy || c == .Timeout) {
			dedupe_forget(&h.dedupe, key)
		} else {
			dedupe_finish(&h.dedupe, key, writer_bytes(out), now_ns(h))
		}
		sync.cond_broadcast(&h.cond)
	}

	req.worker_ref = false
	if !req.loop_ref {
		request_free_locked(h, req)
	}
}

// ---- shutdown ----

// Stop the bus and free it. Unanswered requests get an error reply (daemon
// shutting down) if their worker can still send it.
// To reply and then shut down (`daemon.shutdown`): `reply_ok` first, then
// `host_close`. It waits up to `grace` for the workers, then a few ms more for
// the transport to write out the last messages.
// All `^Request` pointers are invalid after this. Safe on a partly opened host.
host_close :: proc(h: ^Host, grace := 500 * time.Millisecond) {
	if h == nil {
		return
	}
	context.allocator = h.allocator

	sync.mutex_lock(&h.mu)
	h.closing = true
	sync.cond_broadcast(&h.cond)
	if grace > 0 {
		deadline := now_ns(h) + i64(grace)
		for h.busy_workers > 0 {
			remaining := deadline - now_ns(h)
			if remaining <= 0 {
				break
			}
			sync.cond_wait_with_timeout(&h.cond, &h.mu, time.Duration(remaining))
		}
	}
	sync.mutex_unlock(&h.mu)

	// The transport writes messages on its own threads after a send returns.
	// Give the last ones a moment before the endpoints go away.
	if grace > 0 {
		LINGER :: i64(30 * time.Millisecond)
		if last := intrinsics.atomic_load(&h.last_send); last > 0 {
			if wait := LINGER - (now_ns(h) - last); wait > 0 {
				time.sleep(time.Duration(wait))
			}
		}
	}

	// Wake the workers that sit in a receive, then wait for them.
	transport_stop(h)
	for &w in h.workers {
		if w.thread != nil {
			thread.join(w.thread)
			thread.destroy(w.thread)
			w.thread = nil
		}
		writer_destroy(&w.out)
		delete(w.groups)
	}
	// transport_close reads the workers (nng: their contexts), so they go after it.
	transport_close(h)
	delete(h.workers)
	h.workers = nil

	delete(h.events_path)
	delete(h.control_path)

	// Requests the loop never replied to.
	for r := h.live; r != nil; {
		next := r.next
		r.linked = false
		request_free_locked(h, r)
		r = next
	}
	h.live = nil
	delete(h.queue)
	dedupe_destroy(&h.dedupe)
	policy_destroy(&h.policy)
	writer_destroy(&h.pub_buf)
	wake_close(&h.wake)
	free(h)
}
