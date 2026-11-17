// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package bus

// Windows transport of the host: two named pipes in byte mode, framed as in
// frame.odin.
// Threads:
//   I/O thread      One thread with an I/O completion port. It accepts
//                   connections, reads each client identity and the request
//                   frames, writes replies and events. All I/O is overlapped:
//                   it never waits for one client.
//   worker threads  `transport_recv` waits for a whole request read by the I/O
//                   thread. `transport_send` hands it the reply.
//   loop thread     `transport_publish` queues the event for each subscriber
//                   and wakes the I/O thread. Never waits.
// Access: each pipe instance has an explicit access list. LocalSystem and
// Administrators: full control. SIDs of `sid` rules: PIPE_CONTROL_RIGHTS or
// PIPE_EVENTS_RIGHTS.
// Instances: the first of each pipe uses FILE_FLAG_FIRST_PIPE_INSTANCE. A new
// instance is created before an old one closes, so the name is never free while
// the host runs. A subscriber with a full queue is disconnected.

import "core:mem"
import "core:sync"
import win "core:sys/windows"
import "core:thread"
import "core:time"

Transport_Error :: enum u32 {
	None = 0,
}

// The most connections of each pipe at one time.
PIPE_MAX_CONNECTIONS :: 64
@(private)
PIPE_BUFFER :: 64 * 1024

@(private)
Pipe_Kind :: enum u8 {
	Control,
	Events,
}

@(private)
Conn_State :: enum u8 {
	Listening,
	Reading,
	// A worker has the request.
	Working,
	Writing,
	Subscribed,
}

// One events frame, shared by the queues of all subscribers.
@(private)
Event_Frame :: struct {
	refs: int,
	data: []u8,
}

@(private)
Pipe_Conn :: struct {
	kind:       Pipe_Kind,
	handle:     win.HANDLE,
	state:      Conn_State,
	ov_read:    win.OVERLAPPED,
	ov_write:   win.OVERLAPPED,
	// Overlapped operations that have not completed.
	pending:    int,
	closed:     bool,
	// A worker holds a request of this connection.
	held:       bool,
	reader:     Frame_Reader,
	identified: bool,
	creds:      Peer_Creds,
	groups:     [dynamic]Sid,
	reply:      []u8,
	reply_off:  int,
	queue:      [dynamic]^Event_Frame,
	writing:    ^Event_Frame,
	write_off:  int,
	// Events: a read that completes when the client leaves.
	probe:      [1]u8,
	prev, next: ^Pipe_Conn,
}

@(private)
Pipe_Listener :: struct {
	on:        bool,
	name:      win.wstring,
	kind:      Pipe_Kind,
	// Open connections, the listening one included.
	live:      int,
	listening: bool,
	made:      bool,
}

@(private)
Transport :: struct {
	mu:        sync.Mutex,
	cond:      sync.Cond,
	port:      win.HANDLE,
	io:        ^thread.Thread,
	stopping:  bool,
	io_stop:   bool,
	conns:     ^Pipe_Conn,
	work:      [dynamic]Incoming,
	ready:     [dynamic]^Pipe_Conn,
	ctl:       Pipe_Listener,
	ev:        Pipe_Listener,
	queue_max: int,
	// Subscribers disconnected because their queue was full.
	dropped:   u64,
	// The owner of new pipe instances (service_owner), or nil for the
	// default owner.
	owner:     Maybe(Sid),
}

@(private)
Transport_Worker :: struct {}

@(private)
Incoming :: struct {
	conn: ^Pipe_Conn,
	body: []u8,
}

@(private)
Recv_Status :: enum u8 {
	Ok,
	Closed,
	Failed,
}

@(private)
incoming_body :: proc(m: ^Incoming) -> []byte {
	return m.body
}

// Named pipes have no folder.
prepare_dirs :: proc(opts: Host_Options) -> Open_Error {
	return .None
}

@(private)
transport_prepare :: proc(h: ^Host, opts: Host_Options) -> Open_Error {
	h.tr.work = make([dynamic]Incoming, h.allocator)
	h.tr.ready = make([dynamic]^Pipe_Conn, h.allocator)
	if owner, set := service_owner(); set {
		h.tr.owner = owner
	}
	h.tr.port = win.CreateIoCompletionPort(win.INVALID_HANDLE_VALUE, nil, 0, 1)
	if h.tr.port == nil {
		return .Socket_Open_Failed
	}
	t := thread.create(io_main)
	if t == nil {
		return .Thread_Failed
	}
	t.data = h
	h.tr.io = t
	thread.start(t)
	return .None
}

@(private)
transport_listen_events :: proc(h: ^Host, ep: Endpoint, queue: int) -> (Open_Error, Transport_Error) {
	h.tr.queue_max = max(queue, 1)
	return listen_pipe(h, &h.tr.ev, .Events, ep, .Events_In_Use, .Events_Listen_Failed)
}

@(private)
transport_listen_control :: proc(h: ^Host, ep: Endpoint, n_workers: int) -> (Open_Error, Transport_Error) {
	return listen_pipe(h, &h.tr.ctl, .Control, ep, .Control_In_Use, .Control_Listen_Failed)
}

@(private)
listen_pipe :: proc(
	h: ^Host,
	l: ^Pipe_Listener,
	kind: Pipe_Kind,
	ep: Endpoint,
	in_use, failed: Open_Error,
) -> (
	Open_Error,
	Transport_Error,
) {
	name := win.utf8_to_wstring(ep.path, h.allocator)
	if name == nil {
		return failed, .None
	}
	l.name = name
	l.kind = kind
	l.on = true
	sync.mutex_lock(&h.tr.mu)
	defer sync.mutex_unlock(&h.tr.mu)
	if e := listener_spawn(h, l); e != 0 {
		if e == win.ERROR_ACCESS_DENIED || e == ERROR_PIPE_BUSY {
			return in_use, Transport_Error(e)
		}
		return failed, Transport_Error(e)
	}
	return .None, .None
}

// Create a listening instance if there is none and the limit allows. Lock held.
// Returns the Windows error, or 0.
@(private)
listener_spawn :: proc(h: ^Host, l: ^Pipe_Listener) -> u32 {
	tr := &h.tr
	if !l.on || l.listening || l.live >= PIPE_MAX_CONNECTIONS || tr.io_stop {
		return 0
	}
	sync.mutex_lock(&h.mu)
	sids := policy_sids(&h.policy, h.allocator)
	sync.mutex_unlock(&h.mu)
	defer delete(sids)
	ps: Pipe_Security
	defer pipe_security_destroy(&ps, h.allocator)
	rights := PIPE_CONTROL_RIGHTS if l.kind == .Control else PIPE_EVENTS_RIGHTS
	owner, has_owner := tr.owner.?
	if !pipe_security_make(&ps, sids[:], rights, &owner if has_owner else nil, h.allocator) {
		return win.GetLastError()
	}
	open_mode := win.PIPE_ACCESS_DUPLEX | win.FILE_FLAG_OVERLAPPED
	if !l.made {
		open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	pipe_mode := win.PIPE_TYPE_BYTE | win.PIPE_READMODE_BYTE | win.PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS
	// One more than the limit: a new instance is created before an old one closes.
	hp := win.CreateNamedPipeW(l.name, open_mode, pipe_mode, PIPE_MAX_CONNECTIONS + 1, PIPE_BUFFER, PIPE_BUFFER, 0, &ps.sa)
	if hp == win.INVALID_HANDLE_VALUE {
		return win.GetLastError()
	}
	l.made = true
	c := new(Pipe_Conn, h.allocator)
	if c == nil {
		win.CloseHandle(hp)
		return win.ERROR_NOT_ENOUGH_MEMORY
	}
	c.kind = l.kind
	c.handle = hp
	c.state = .Listening
	c.groups = make([dynamic]Sid, h.allocator)
	c.queue = make([dynamic]^Event_Frame, h.allocator)
	frame_reader_init(&c.reader, FRAME_MAX_REQUEST, h.allocator)
	c.next = tr.conns
	if tr.conns != nil {
		tr.conns.prev = c
	}
	tr.conns = c
	l.listening = true
	l.live += 1
	if win.CreateIoCompletionPort(hp, tr.port, uint(uintptr(rawptr(c))), 0) == nil {
		e := win.GetLastError()
		close_conn(h, c)
		return e
	}
	if win.ConnectNamedPipe(hp, &c.ov_read) != win.FALSE {
		c.pending += 1
		return 0
	}
	switch e := win.GetLastError(); e {
	case ERROR_IO_PENDING:
		c.pending += 1
	case ERROR_PIPE_CONNECTED:
		on_connected(h, c)
	case:
		close_conn(h, c)
	}
	return 0
}

@(private)
listener_of :: proc(h: ^Host, c: ^Pipe_Conn) -> ^Pipe_Listener {
	return &h.tr.ctl if c.kind == .Control else &h.tr.ev
}

// A client connected: read who it is before anything else, then create the
// next listening instance.
@(private)
on_connected :: proc(h: ^Host, c: ^Pipe_Conn) {
	l := listener_of(h, c)
	l.listening = false
	creds, ok := pipe_client_identity(c.handle, &c.groups)
	c.creds = creds
	c.identified = ok
	listener_spawn(h, l)
	switch c.kind {
	case .Control:
		// Without an identity the request still gets a reply: denied.
		c.state = .Reading
		start_read(h, c)
	case .Events:
		if !ok {
			close_conn(h, c)
			return
		}
		sync.mutex_lock(&h.mu)
		roles := roles_for_sids(&h.policy, c.creds.sid, c.groups[:])
		sync.mutex_unlock(&h.mu)
		if roles == {} {
			close_conn(h, c)
			return
		}
		c.state = .Subscribed
		if win.ReadFile(c.handle, &c.probe, 1, nil, &c.ov_read) != win.FALSE || win.GetLastError() == ERROR_IO_PENDING {
			c.pending += 1
		} else {
			close_conn(h, c)
		}
	}
}

@(private)
start_read :: proc(h: ^Host, c: ^Pipe_Conn) {
	buf := frame_want(&c.reader)
	if win.ReadFile(c.handle, raw_data(buf), u32(len(buf)), nil, &c.ov_read) != win.FALSE || win.GetLastError() == ERROR_IO_PENDING {
		c.pending += 1
		return
	}
	close_conn(h, c)
}

@(private)
start_write :: proc(h: ^Host, c: ^Pipe_Conn, buf: []u8) {
	if win.WriteFile(c.handle, raw_data(buf), u32(len(buf)), nil, &c.ov_write) != win.FALSE || win.GetLastError() == ERROR_IO_PENDING {
		c.pending += 1
		return
	}
	close_conn(h, c)
}

@(private)
on_read :: proc(h: ^Host, c: ^Pipe_Conn, ok: bool, n: int) {
	c.pending -= 1
	if c.closed {
		maybe_free(h, c)
		return
	}
	if c.state == .Listening {
		if ok {
			on_connected(h, c)
		} else {
			close_conn(h, c)
		}
		return
	}
	if c.kind == .Events || !ok {
		// An events client never writes: the read ends when it leaves.
		close_conn(h, c)
		return
	}
	switch frame_got(&c.reader, n) {
	case .More:
		start_read(h, c)
	case .Done:
		body := frame_take(&c.reader)
		c.held = true
		c.state = .Working
		append(&h.tr.work, Incoming{conn = c, body = body})
		sync.cond_signal(&h.tr.cond)
	case .Bad_Length, .No_Memory:
		close_conn(h, c)
	}
}

@(private)
on_write :: proc(h: ^Host, c: ^Pipe_Conn, ok: bool, n: int) {
	c.pending -= 1
	if c.closed {
		maybe_free(h, c)
		return
	}
	if !ok {
		close_conn(h, c)
		return
	}
	if c.kind == .Control {
		c.reply_off += n
		if c.reply_off < len(c.reply) {
			start_write(h, c, c.reply[c.reply_off:])
			return
		}
		drop_reply(h, c)
		c.state = .Reading
		start_read(h, c)
		return
	}
	c.write_off += n
	if c.write_off < len(c.writing.data) {
		start_write(h, c, c.writing.data[c.write_off:])
		return
	}
	frame_unref(h, c.writing)
	c.writing = nil
	next_event_write(h, c)
}

@(private)
next_event_write :: proc(h: ^Host, c: ^Pipe_Conn) {
	if c.writing != nil || len(c.queue) == 0 || c.closed {
		return
	}
	c.writing = c.queue[0]
	ordered_remove(&c.queue, 0)
	c.write_off = 0
	start_write(h, c, c.writing.data)
}

@(private)
drop_reply :: proc(h: ^Host, c: ^Pipe_Conn) {
	if c.reply != nil {
		// A reply may hold a password (`auth.credentials`).
		mem.zero_explicit(raw_data(c.reply), len(c.reply))
		delete(c.reply, h.allocator)
	}
	c.reply = nil
	c.reply_off = 0
}

@(private)
frame_unref :: proc(h: ^Host, f: ^Event_Frame) {
	f.refs -= 1
	if f.refs == 0 {
		delete(f.data, h.allocator)
		free(f, h.allocator)
	}
}

// Stop all I/O of a connection. The memory goes when the cancelled
// operations have completed and no worker holds it. Lock held.
@(private)
close_conn :: proc(h: ^Host, c: ^Pipe_Conn) {
	if c.closed {
		return
	}
	c.closed = true
	l := listener_of(h, c)
	if c.state == .Listening {
		l.listening = false
	}
	l.live -= 1
	for f in c.queue {
		frame_unref(h, f)
	}
	clear(&c.queue)
	if c.writing != nil && c.pending == 0 {
		frame_unref(h, c.writing)
		c.writing = nil
	}
	if c.pending > 0 {
		win.CancelIoEx(c.handle, nil)
	}
	maybe_free(h, c)
}

@(private)
maybe_free :: proc(h: ^Host, c: ^Pipe_Conn) {
	if !c.closed || c.pending > 0 {
		return
	}
	if c.writing != nil {
		frame_unref(h, c.writing)
		c.writing = nil
	}
	drop_reply(h, c)
	frame_reader_destroy(&c.reader)
	if c.handle != nil {
		// The replacement first: the name of the pipe must not become free.
		listener_spawn(h, listener_of(h, c))
		win.CloseHandle(c.handle)
		c.handle = nil
	}
	if c.held {
		return
	}
	if c.prev != nil {
		c.prev.next = c.next
	} else {
		h.tr.conns = c.next
	}
	if c.next != nil {
		c.next.prev = c.prev
	}
	delete(c.groups)
	delete(c.queue)
	free(c, h.allocator)
}

@(private)
io_wake :: proc(h: ^Host) {
	win.PostQueuedCompletionStatus(h.tr.port, 0, 0, nil)
}

@(private)
io_main :: proc(t: ^thread.Thread) {
	h := (^Host)(t.data)
	context.allocator = h.allocator
	tr := &h.tr
	deadline: time.Duration
	for {
		n: u32
		key: uint
		ov: ^win.OVERLAPPED
		wait := win.INFINITE if deadline == 0 else 50
		ok := win.GetQueuedCompletionStatus(tr.port, &n, &key, &ov, wait) != win.FALSE
		sync.mutex_lock(&tr.mu)
		if ov != nil {
			c := (^Pipe_Conn)(rawptr(uintptr(key)))
			if ov == &c.ov_read {
				on_read(h, c, ok, int(n))
			} else {
				on_write(h, c, ok, int(n))
			}
		}
		if tr.io_stop && deadline == 0 {
			deadline = mono_now() + 2 * time.Second
			for c := tr.conns; c != nil; {
				next := c.next
				close_conn(h, c)
				c = next
			}
		}
		if deadline != 0 {
			done := tr.conns == nil || mono_now() > deadline
			sync.mutex_unlock(&tr.mu)
			if done {
				return
			}
			continue
		}
		for c in tr.ready {
			if c.closed {
				drop_reply(h, c)
				maybe_free(h, c)
			} else {
				start_write(h, c, c.reply)
			}
		}
		clear(&tr.ready)
		for c := tr.conns; c != nil; {
			next := c.next
			if c.kind == .Events && c.state == .Subscribed {
				next_event_write(h, c)
			}
			c = next
		}
		listener_spawn(h, &tr.ctl)
		listener_spawn(h, &tr.ev)
		sync.mutex_unlock(&tr.mu)
		free_all(context.temp_allocator)
	}
}

@(private)
transport_recv :: proc(h: ^Host, w: ^Worker) -> (m: Incoming, st: Recv_Status) {
	tr := &h.tr
	sync.mutex_lock(&tr.mu)
	defer sync.mutex_unlock(&tr.mu)
	for len(tr.work) == 0 && !tr.stopping {
		sync.cond_wait(&tr.cond, &tr.mu)
	}
	if tr.stopping {
		return {}, .Closed
	}
	m = tr.work[0]
	ordered_remove(&tr.work, 0)
	return m, .Ok
}

// The SID of the client token and the roles of its user and enabled groups.
@(private)
peer_identity :: proc(h: ^Host, w: ^Worker, m: ^Incoming) -> (creds: Peer_Creds, roles: Roles, ok: bool) {
	c := m.conn
	if !c.identified {
		return {}, {}, false
	}
	sync.mutex_lock(&h.mu)
	roles = roles_for_sids(&h.policy, c.creds.sid, c.groups[:])
	sync.mutex_unlock(&h.mu)
	return c.creds, roles, true
}

@(private)
transport_release :: proc(h: ^Host, w: ^Worker, m: ^Incoming) {
	delete(m.body, h.allocator)
	m.body = nil
}

@(private)
transport_send :: proc(h: ^Host, w: ^Worker, m: ^Incoming, reply: []byte) -> bool {
	tr := &h.tr
	c := m.conn
	m.conn = nil
	sync.mutex_lock(&tr.mu)
	defer sync.mutex_unlock(&tr.mu)
	c.held = false
	if c.closed {
		maybe_free(h, c)
		return false
	}
	if len(reply) == 0 {
		close_conn(h, c)
		return false
	}
	buf, err := make([]u8, FRAME_HEADER + len(reply), h.allocator)
	if err != nil {
		close_conn(h, c)
		return false
	}
	hdr := frame_header(len(reply))
	copy(buf, hdr[:])
	copy(buf[FRAME_HEADER:], reply)
	c.reply = buf
	c.reply_off = 0
	c.state = .Writing
	append(&tr.ready, c)
	io_wake(h)
	return true
}

@(private)
transport_publish :: proc(h: ^Host, topic: string, envelope: []byte) -> bool {
	tr := &h.tr
	sync.mutex_lock(&tr.mu)
	defer sync.mutex_unlock(&tr.mu)
	if !tr.ev.on {
		return false
	}
	f: ^Event_Frame
	for c := tr.conns; c != nil; {
		next := c.next
		if c.kind == .Events && c.state == .Subscribed && !c.closed {
			if f == nil {
				f = new_event_frame(h, topic, envelope)
				if f == nil {
					return false
				}
			}
			queued := len(c.queue) + (1 if c.writing != nil else 0)
			if queued >= tr.queue_max {
				tr.dropped += 1
				close_conn(h, c)
			} else {
				f.refs += 1
				append(&c.queue, f)
			}
		}
		c = next
	}
	if f == nil {
		return true
	}
	if f.refs == 0 {
		f.refs = 1
		frame_unref(h, f)
	}
	io_wake(h)
	return true
}

@(private)
new_event_frame :: proc(h: ^Host, topic: string, envelope: []byte) -> ^Event_Frame {
	size := len(topic) + 1 + len(envelope)
	data, err := make([]u8, FRAME_HEADER + size, h.allocator)
	if err != nil {
		return nil
	}
	f := new(Event_Frame, h.allocator)
	if f == nil {
		delete(data, h.allocator)
		return nil
	}
	hdr := frame_header(size)
	copy(data, hdr[:])
	copy(data[FRAME_HEADER:], topic)
	data[FRAME_HEADER + len(topic)] = ' '
	copy(data[FRAME_HEADER + len(topic) + 1:], envelope)
	f.data = data
	return f
}

@(private)
transport_stop :: proc(h: ^Host) {
	tr := &h.tr
	sync.mutex_lock(&tr.mu)
	tr.stopping = true
	sync.cond_broadcast(&tr.cond)
	sync.mutex_unlock(&tr.mu)
}

// The workers have ended. Requests that no worker took are dropped, then the
// I/O thread closes every connection and waits for the cancelled operations.
@(private)
transport_close :: proc(h: ^Host) {
	tr := &h.tr
	transport_stop(h)
	sync.mutex_lock(&tr.mu)
	for &m in tr.work {
		mem.zero_explicit(raw_data(m.body), len(m.body))
		delete(m.body, h.allocator)
		m.conn.held = false
		maybe_free(h, m.conn)
	}
	clear(&tr.work)
	tr.io_stop = true
	sync.mutex_unlock(&tr.mu)
	if tr.io != nil {
		io_wake(h)
		thread.join(tr.io)
		thread.destroy(tr.io)
		tr.io = nil
	}
	if tr.port != nil {
		win.CloseHandle(tr.port)
		tr.port = nil
	}
	delete(tr.work)
	delete(tr.ready)
	free(rawptr(tr.ctl.name), h.allocator)
	free(rawptr(tr.ev.name), h.allocator)
	tr.ctl.name, tr.ev.name = nil, nil
}

// Tests: subscribers dropped for a full queue.
@(private)
transport_dropped :: proc(h: ^Host) -> u64 {
	sync.mutex_lock(&h.tr.mu)
	defer sync.mutex_unlock(&h.tr.mu)
	return h.tr.dropped
}
