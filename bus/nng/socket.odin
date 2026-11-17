// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package nng

// Thin wrapper over the raw binding. Synchronous calls only: call from
// ordinary Odin threads. nng sockets can be shared between threads.
// nng does its I/O on its own threads and nothing here runs Odin code there.
// If aio is bound later, its completion callbacks run on nng threads: they
// must be `proc "c"` and set up a context first:
//
//	on_done :: proc "c" (arg: rawptr) {
//		context = runtime.default_context()
//		...
//	}
//
// Keep them short: queue the work to an Odin thread and return.

import "base:runtime"
import "core:c"
import "core:time"

Socket   :: nng_socket
Listener :: nng_listener
Pipe     :: nng_pipe
Ctx      :: nng_ctx
Msg      :: nng_msg

Protocol :: enum {
	Pub,
	Sub,
	Req,
	Rep,
}

// Call once at program start, before any other call. nng 1.x needs nothing (it
// starts itself on first use). nng 2.0 needs nng_init here. Keep calling this
// now, so the upgrade is a one-line change.
init :: proc() {
}

// Library version, for example "1.10.1".
version :: proc() -> string {
	return string(nng_version())
}

// Open a socket. It is not connected to anything yet.
open :: proc(protocol: Protocol) -> (s: Socket, err: Error) {
	rc: c.int
	switch protocol {
	case .Pub: rc = nng_pub0_open(&s)
	case .Sub: rc = nng_sub0_open(&s)
	case .Req: rc = nng_req0_open(&s)
	case .Rep: rc = nng_rep0_open(&s)
	}
	err = to_error(rc)
	if err != .None {
		s = {}
	}
	return
}

// Close the socket. This also closes its listeners, dialers and pipes, and
// wakes any thread blocked in recv on it with the error .Closed.
close :: proc(s: Socket) -> Error {
	return to_error(nng_socket_close(s))
}

// Start listening on a URL such as "ipc:///run/noirvpn/events".
// For IPC, ipc_permissions sets the mode of the socket file (for example
// 0o660). It is applied before the listener starts, and the umask is not
// applied to it. Leave it nil to keep the default of nng.
listen :: proc(s: Socket, url: cstring, ipc_permissions: Maybe(int) = nil) -> (l: Listener, err: Error) {
	err = to_error(nng_listener_create(&l, s, url))
	if err != .None {
		return {}, err
	}
	if mode, ok := ipc_permissions.?; ok {
		err = to_error(nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, c.int(mode)))
		if err != .None {
			nng_listener_close(l)
			return {}, err
		}
	}
	err = to_error(nng_listener_start(l, 0))
	if err != .None {
		nng_listener_close(l)
		return {}, err
	}
	return
}

// Connect to a URL. The first attempt is done before dial returns, unless
// nonblock is true: then it is done in the background. Either way, nng
// reconnects by itself if the link drops later.
dial :: proc(s: Socket, url: cstring, nonblock := false) -> Error {
	flags := NNG_FLAG_NONBLOCK if nonblock else 0
	return to_error(nng_dial(s, url, nil, flags))
}

// Subscribe a SUB socket to messages that start with prefix. An empty prefix
// matches everything. A new SUB socket receives nothing until it subscribes.
subscribe :: proc(s: Socket, prefix: string) -> Error {
	return to_error(nng_sub0_socket_subscribe(s, raw_data(prefix), c.size_t(len(prefix))))
}

unsubscribe :: proc(s: Socket, prefix: string) -> Error {
	return to_error(nng_sub0_socket_unsubscribe(s, raw_data(prefix), c.size_t(len(prefix))))
}

@(private)
to_ms :: proc "contextless" (d: time.Duration) -> nng_duration {
	if d < 0 {
		return NNG_DURATION_INFINITE
	}
	return nng_duration(d / time.Millisecond)
}

// Set how long a receive may block. A negative duration means no limit.
// When it expires, recv and recv_msg return .Timed_Out.
set_recv_timeout :: proc(s: Socket, d: time.Duration) -> Error {
	return to_error(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, to_ms(d)))
}

// Set how long a send may block. A negative duration means no limit.
set_send_timeout :: proc(s: Socket, d: time.Duration) -> Error {
	return to_error(nng_socket_set_ms(s, NNG_OPT_SENDTIMEO, to_ms(d)))
}

// REQ only. A request is sent again if no reply arrives within this time
// (default 60 s), or if the connection drops. So the server can see the same
// request twice: handlers should be safe to repeat. A negative duration means
// never resend on a timer.
set_req_resend_time :: proc(s: Socket, d: time.Duration) -> Error {
	return to_error(nng_socket_set_ms(s, NNG_OPT_REQ_RESENDTIME, to_ms(d)))
}

// Number of messages a socket may queue in each direction. For PUB this is the
// queue for each subscriber: messages past it are dropped for that subscriber.
set_send_buffer :: proc(s: Socket, messages: int) -> Error {
	return to_error(nng_socket_set_int(s, NNG_OPT_SENDBUF, c.int(messages)))
}

set_recv_buffer :: proc(s: Socket, messages: int) -> Error {
	return to_error(nng_socket_set_int(s, NNG_OPT_RECVBUF, c.int(messages)))
}

// Largest message the socket accepts, in bytes. 0 means no limit. A larger
// message is dropped by the transport.
set_recv_max_size :: proc(s: Socket, bytes: int) -> Error {
	return to_error(nng_socket_set_size(s, NNG_OPT_RECVMAXSZ, c.size_t(bytes)))
}

// Messages.

// Create a message holding a copy of data.
msg_new :: proc(data: []byte = nil) -> (m: ^Msg, err: Error) {
	err = to_error(nng_msg_alloc(&m, 0))
	if err != .None {
		return nil, err
	}
	err = msg_append(m, data)
	if err != .None {
		nng_msg_free(m)
		return nil, err
	}
	return
}

// Add a copy of data to the end of the message body.
msg_append :: proc(m: ^Msg, data: []byte) -> Error {
	if len(data) == 0 {
		return .None
	}
	return to_error(nng_msg_append(m, raw_data(data), c.size_t(len(data))))
}

// Free a message you still own: one from msg_new that was not sent, or one
// from recv_msg.
msg_free :: proc(m: ^Msg) {
	nng_msg_free(m)
}

// The message body. The slice points into the message: it is valid until the
// message is freed or sent.
msg_body :: proc(m: ^Msg) -> []byte {
	n := int(nng_msg_len(m))
	if n == 0 {
		return nil
	}
	return ([^]byte)(nng_msg_body(m))[:n]
}

// The pipe (connection) a received message came from.
msg_pipe :: proc(m: ^Msg) -> Pipe {
	return nng_msg_get_pipe(m)
}

// Send a message. On success nng owns it: do not touch it again. On failure
// you still own it and must free it.
send_msg :: proc(s: Socket, m: ^Msg, nonblock := false) -> Error {
	flags := NNG_FLAG_NONBLOCK if nonblock else 0
	return to_error(nng_sendmsg(s, m, flags))
}

// Receive one message. The caller owns it and must free it with msg_free.
recv_msg :: proc(s: Socket, nonblock := false) -> (m: ^Msg, err: Error) {
	flags := NNG_FLAG_NONBLOCK if nonblock else 0
	err = to_error(nng_recvmsg(s, &m, flags))
	if err != .None {
		m = nil
	}
	return
}

// Send a copy of data as one message.
send :: proc(s: Socket, data: []byte, nonblock := false) -> Error {
	m, err := msg_new(data)
	if err != .None {
		return err
	}
	err = send_msg(s, m, nonblock)
	if err != .None {
		nng_msg_free(m)
	}
	return err
}

// Receive one message and return a copy of its body. Free it with delete.
recv :: proc(s: Socket, nonblock := false, allocator := context.allocator) -> (data: []byte, err: Error) {
	m: ^Msg
	m, err = recv_msg(s, nonblock)
	if err != .None {
		return nil, err
	}
	defer nng_msg_free(m)
	alloc_err: runtime.Allocator_Error
	data, alloc_err = make([]byte, int(nng_msg_len(m)), allocator)
	if alloc_err != nil {
		return nil, .No_Memory
	}
	copy(data, msg_body(m))
	return
}

// Send a request and wait for the reply (REQ socket). Set a receive timeout
// first, or this blocks until a reply arrives.
call :: proc(s: Socket, request: []byte, allocator := context.allocator) -> (reply: []byte, err: Error) {
	err = send(s, request)
	if err != .None {
		return nil, err
	}
	return recv(s, false, allocator)
}

// Contexts. A REP socket handles one request at a time: it must send the
// reply before it takes the next request. To serve several requests at once,
// give each worker thread its own context. A context has its own request
// state. All contexts share the connections of the socket.

ctx_open :: proc(s: Socket) -> (cx: Ctx, err: Error) {
	err = to_error(nng_ctx_open(&cx, s))
	if err != .None {
		cx = {}
	}
	return
}

// Close a context. A thread blocked in ctx_recv_msg gets the error .Closed.
ctx_close :: proc(cx: Ctx) -> Error {
	return to_error(nng_ctx_close(cx))
}

ctx_recv_msg :: proc(cx: Ctx, nonblock := false) -> (m: ^Msg, err: Error) {
	flags := NNG_FLAG_NONBLOCK if nonblock else 0
	err = to_error(nng_ctx_recvmsg(cx, &m, flags))
	if err != .None {
		m = nil
	}
	return
}

// Same ownership rule as send_msg.
ctx_send_msg :: proc(cx: Ctx, m: ^Msg, nonblock := false) -> Error {
	flags := NNG_FLAG_NONBLOCK if nonblock else 0
	return to_error(nng_ctx_sendmsg(cx, m, flags))
}

// Peer credentials of an IPC connection. The kernel supplies them, so the
// peer cannot forge them.
Peer_Creds :: struct {
	uid, gid: u32,
	pid:      u32,
	has_pid:  bool, // pid is not available on every platform
}

// Read the credentials of the process at the other end of a pipe. Get the pipe
// from msg_pipe and read it right after the receive: if the peer already
// disconnected, the pipe is gone and the call fails. Treat any error as "not
// authorised".
// Errors:
//   .Not_Found     - pipe gone (nng can also say .Closed)
//   .Not_Supported - transport or platform has no uid and gid (TCP, inproc)
//   .Bad_Type      - option type differs
pipe_peer_creds :: proc(p: Pipe) -> (creds: Peer_Creds, err: Error) {
	uid, gid: u32
	uid, err = pipe_peer_id(p, NNG_OPT_PEER_UID)
	if err != .None {
		return
	}
	gid, err = pipe_peer_id(p, NNG_OPT_PEER_GID)
	if err != .None {
		return
	}
	creds.uid = uid
	creds.gid = gid

	pid, pid_err := pipe_peer_id(p, NNG_OPT_PEER_PID)
	#partial switch pid_err {
	case .None:
		creds.pid = pid
		creds.has_pid = true
	case .Not_Supported:
		// Fine: some platforms cannot report the pid.
	case:
		return {}, pid_err
	}
	return
}

// Read one credential option. 2.0: the options become int, so this is the only
// place to change.
// nng reports a value it cannot get (the pid on macOS, for example) as
// (uint64_t)-1 with no error. This maps it to .Not_Supported.
@(private)
pipe_peer_id :: proc(p: Pipe, opt: cstring) -> (id: u32, err: Error) {
	v: u64
	err = to_error(nng_pipe_get_uint64(p, opt, &v))
	if err != .None {
		return
	}
	if v == max(u64) {
		return 0, .Not_Supported
	}
	if v > u64(max(u32)) {
		return 0, .Invalid
	}
	return u32(v), .None
}

// Close one connection. The peer can reconnect (a dialer does by itself).
pipe_close :: proc(p: Pipe) -> Error {
	return to_error(nng_pipe_close(p))
}
