// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package dco

import "core:mem"
import "core:sys/linux"

// Blocking request/reply client of the userspace DCO socket protocol
//: AF_UNIX, SOCK_SEQPACKET, one message
// per datagram. One connection controls one device; closing it tears the
// device down.
//
// `call` sends a request and reads until its reply comes. Meanwhile:
// - log lines go to the `log` proc
// - events are queued
// - replies of other requests are dropped
// - if events were queued, `call` ends with a PING. The service responds at
//   once, so the socket turns readable and a poll loop checks the queue.
// `next_event` returns queued events first, then reads the socket without
// blocking.
//
// Control records of TCP peers (CTRL_RX, `CAP_TCP`):
// - A record joins the event queue in sequence, as a `Ctrl_Rx` event. Its
//   bytes wait in a second queue.
// - A record is never passed to a callback inside `call`: the caller may be
//   in the middle of a call into its session.
// - After such an event, `ctrl_record` has the bytes in a client buffer. They
//   stay valid until the next `next_event`, whatever calls come between.
//
// Uses system calls directly (`core:sys/linux`), like the rest of
// the platform code.

// How long a request may wait for its reply.
REPLY_TIMEOUT_SECS :: 10
// The most events kept for a daemon that is slow to read them.
EVENT_QUEUE_MAX :: 16384
// The most bytes of control records kept for the same daemon. A record that does
// not fit is lost (the stream then fails its TLS, so the peer ends).
CTRL_QUEUE_MAX :: 16 << 20
// `peer_id` of a queued record that `ctrl_forget` took out.
CTRL_DEAD :: 0xffff_ffff

SOL_SOCKET :: 1
SCM_RIGHTS :: 1
SO_RCVTIMEO :: 20
ETIMEDOUT :: -110
EAGAIN :: -11
ENAMETOOLONG :: -36

Log_Proc :: #type proc(user: rawptr, level: Log_Level, text: string)

Conn :: struct {
	fd:       i32,
	hello:    Hello_Reply,
	log:      Log_Proc,
	log_user: rawptr,
	// Events that came while a request waited, oldest first from `head`.
	events:   [dynamic]Event,
	head:     int,
	// Events thrown away because the queue was full.
	dropped:  int,
	// The bytes of the `Ctrl_Rx` events in the queue, in the same order, from
	// `ctrl_off`; `ctrl_cur` is the record of the event that `next_event` gave last.
	ctrl:     [dynamic]u8,
	ctrl_off: int,
	ctrl_cur: []u8, // in `cur`
	cur:      []u8, // STREAM_REC_MAX bytes, allocated on first use
	ctrl_lost: int,
	// Receive buffer for the largest message (`MSG_MAX_STREAM`), allocated on first use.
	rx:       []u8,
	// The connection failed or was closed by the service.
	lost:     bool,
}

@(private)
Cmsg_Hdr :: struct {
	len:   uint,
	level: i32,
	type:  i32,
}

@(private)
CMSG_HDR_SIZE :: ((size_of(Cmsg_Hdr) + size_of(uint) - 1) / size_of(uint)) * size_of(uint)

@(private)
HDR_SIZE :: size_of(Hdr)

// ----------------------------------------------------------------- connect

// Connects to the service at `path` and says HELLO. Returns 0 or a negative
// errno: ENOENT (no socket), ECONNREFUSED, EPROTONOSUPPORT (other version).
connect :: proc(c: ^Conn, path: string, log: Log_Proc = nil, log_user: rawptr = nil) -> int {
	c^ = {}
	c.fd = -1
	c.log = log
	c.log_user = log_user
	addr: linux.Sock_Addr_Un
	if len(path) == 0 || len(path) >= len(addr.sun_path) {
		return ENAMETOOLONG
	}
	addr.sun_family = .UNIX
	copy(addr.sun_path[:], path)
	fd, e := linux.socket(.UNIX, .SEQPACKET, {.CLOEXEC}, .UNSPECIFIED)
	if e != .NONE {
		return -int(e)
	}
	if ce := linux.connect(fd, &addr); ce != .NONE {
		linux.close(fd)
		return -int(ce)
	}
	return attach(c, i32(fd))
}

// Takes over a connected SEQPACKET socket (a test passes one end of a
// socketpair) and says HELLO. `disconnect` closes the fd, also after a failure.
attach :: proc(c: ^Conn, fd: i32) -> int {
	c.fd = fd
	tv: [2]i64 = {REPLY_TIMEOUT_SECS, 0}
	linux.syscall(linux.SYS_setsockopt, linux.Fd(fd), SOL_SOCKET, SO_RCVTIMEO, &tv, size_of(tv))
	req := Hello {
		version = PROTO_VERSION,
	}
	rep: Hello_Reply
	st := call(c, .Hello, &req, size_of(req), &rep, size_of(rep))
	if st == 0 && rep.version != PROTO_VERSION {
		st = EPROTONOSUPPORT
	}
	if st < 0 {
		disconnect(c)
		return st
	}
	c.hello = rep
	c.hello.daemon[len(c.hello.daemon) - 1] = 0
	return 0
}

// Closes the socket (the service then removes the device) and frees the queue.
disconnect :: proc(c: ^Conn) {
	if c.fd >= 0 {
		linux.close(linux.Fd(c.fd))
	}
	c.fd = -1
	c.lost = true
	delete(c.events)
	c.events = nil
	c.head = 0
	delete(c.ctrl)
	c.ctrl = nil
	c.ctrl_off = 0
	c.ctrl_cur = nil
	delete(c.cur)
	c.cur = nil
	delete(c.rx)
	c.rx = nil
}

// The name the service gave in its HELLO reply.
daemon_name :: proc(c: ^Conn) -> string {
	n := 0
	for n < len(c.hello.daemon) && c.hello.daemon[n] != 0 {
		n += 1
	}
	return string(c.hello.daemon[:n])
}

// ------------------------------------------------------------------- wire

// Only the messages that carry a TCP record may be longer than MSG_MAX.
@(private)
msg_limit :: proc "contextless" (type: Msg) -> int {
	#partial switch type {
	case .New_Peer, .Ctrl_Tx:
		return MSG_MAX_STREAM
	}
	return MSG_MAX
}

// `tail` follows the body in the same message (the read-ahead bytes of a stream
// peer, the record of a `Ctrl_Tx`).
@(private)
send_msg :: proc(c: ^Conn, type: Msg, body: rawptr, body_len: int, pass_fd: i32, tail: []u8 = nil) -> int {
	if HDR_SIZE + body_len + len(tail) > msg_limit(type) {
		return EMSGSIZE
	}
	buf: [MSG_MAX]u8
	h := Hdr {
		type  = u16(type),
		flags = F_FD if pass_fd >= 0 else 0,
	}
	mem.copy(&buf[0], &h, HDR_SIZE)
	if body_len > 0 {
		mem.copy(&buf[HDR_SIZE], body, body_len)
	}
	iov := [2]linux.IO_Vec{{base = &buf[0], len = uint(HDR_SIZE + body_len)}, {base = raw_data(tail), len = uint(len(tail))}}
	ctl: [3]u64 // room for one SCM_RIGHTS message with one fd, aligned
	msg := linux.Msg_Hdr {
		iov = iov[:2] if len(tail) > 0 else iov[:1],
	}
	if pass_fd >= 0 {
		base := ([^]u8)(&ctl)
		hdr := Cmsg_Hdr {
			len   = CMSG_HDR_SIZE + size_of(i32),
			level = SOL_SOCKET,
			type  = SCM_RIGHTS,
		}
		mem.copy(base, &hdr, size_of(hdr))
		fd := pass_fd
		mem.copy(base[CMSG_HDR_SIZE:], &fd, size_of(fd))
		msg.control = base[:CMSG_HDR_SIZE + 8]
	}
	for {
		_, e := linux.sendmsg(linux.Fd(c.fd), &msg, {.NOSIGNAL})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			c.lost = true
			return -int(e)
		}
		return 0
	}
}

// The receive buffer, allocated on first use. Nil when memory is short.
@(private)
rx_buf :: proc(c: ^Conn) -> []u8 {
	if c.rx == nil {
		c.rx = make([]u8, MSG_MAX_STREAM)
	}
	return c.rx
}

// One message into `buf`. Returns its length or a negative errno:
//   ECONNRESET  service closed the connection
//   EPROTO      message too short or too long
//   EAGAIN      `nonblock` and nothing waiting
//   ETIMEDOUT   blocking read waited too long
@(private)
recv_msg :: proc(c: ^Conn, buf: []u8, nonblock: bool) -> int {
	flags := linux.Socket_Msg{.TRUNC}
	if nonblock {
		flags += {.DONTWAIT}
	}
	for {
		iov := [1]linux.IO_Vec{{base = raw_data(buf), len = uint(len(buf))}}
		msg := linux.Msg_Hdr {
			iov = iov[:],
		}
		n, e := linux.recvmsg(linux.Fd(c.fd), &msg, flags)
		if e == .EINTR {
			continue
		}
		if e == .EAGAIN {
			return EAGAIN if nonblock else ETIMEDOUT
		}
		if e != .NONE {
			c.lost = true
			return -int(e)
		}
		if n == 0 {
			c.lost = true
			return ECONNRESET
		}
		if n > len(buf) || n < HDR_SIZE {
			return EPROTO
		}
		return n
	}
}

// Handles a message that is not a reply to the request in progress: a log
// line goes to the log proc, an event is queued. True: an event was queued.
@(private)
handle_async :: proc(c: ^Conn, buf: []u8) -> bool {
	h: Hdr
	mem.copy(&h, raw_data(buf), HDR_SIZE)
	if h.flags & F_REPLY != 0 {
		return false
	}
	body := buf[HDR_SIZE:]
	switch Msg(h.type) {
	case .Event:
		if len(body) < size_of(Event) || len(buf) > MSG_MAX {
			return false
		}
		ev: Event
		mem.copy(&ev, raw_data(body), size_of(Event))
		if ev.kind == .Ctrl_Rx {
			return false // not a wire event
		}
		if len(c.events) - c.head >= EVENT_QUEUE_MAX {
			if c.dropped == 0 && c.log != nil {
				c.log(c.log_user, .Error, "the event queue is full, so events are being dropped")
			}
			c.dropped += 1
			return false
		}
		append(&c.events, ev)
		return true
	case .Ctrl_Rx:
		// The peer id, then the record: an empty record is nothing.
		if len(body) <= size_of(Ctrl) {
			return false
		}
		ev := Event {
			kind    = .Ctrl_Rx,
			key_id  = u32(len(body) - size_of(Ctrl)),
		}
		mem.copy(&ev.peer_id, raw_data(body), size_of(Ctrl))
		if len(c.events) - c.head >= EVENT_QUEUE_MAX || len(c.ctrl) - c.ctrl_off + int(ev.key_id) > CTRL_QUEUE_MAX {
			if c.ctrl_lost == 0 && c.log != nil {
				c.log(c.log_user, .Error, "the control record queue is full, so records are being dropped")
			}
			c.ctrl_lost += 1
			return false
		}
		append(&c.events, ev)
		append(&c.ctrl, ..body[size_of(Ctrl):])
		return true
	case .Log:
		if len(body) <= 4 || c.log == nil {
			return false
		}
		level: u32
		mem.copy(&level, raw_data(body), 4)
		text := body[4:]
		n := 0
		for n < len(text) && text[n] != 0 {
			n += 1
		}
		c.log(c.log_user, Log_Level(level), string(text[:n]))
	case .Hello, .Open, .Close, .New_Peer, .Set_Peer, .Del_Peer, .Detach, .New_Key, .Del_Key, .Swap_Keys,
	     .Peer_Stats, .Link_Set, .Addr_Add, .Addr_Del, .Route_Add, .Route_Del, .Ping, .Key_Add, .Key_Tx, .Key_Drop,
	     .Ctrl_Tx, .Set_Peer_Id, .Set_Peer_Addr, .Set_Filter:
		// A request type sent to us: not part of the protocol, ignored.
	}
	return false
}

@(private)
pop_event :: proc(c: ^Conn, ev: ^Event) {
	ev^ = c.events[c.head]
	c.head += 1
	if ev.kind == .Ctrl_Rx {
		n := int(ev.key_id)
		if c.cur == nil {
			c.cur = make([]u8, STREAM_REC_MAX)
		}
		if c.cur != nil {
			// A copy: a call issued while the record is in use may grow the queue.
			copy(c.cur, c.ctrl[c.ctrl_off:][:n])
			c.ctrl_cur = c.cur[:n]
		} else {
			c.ctrl_cur = nil
		}
		c.ctrl_off += n
	}
	if c.head == len(c.events) {
		clear(&c.events)
		c.head = 0
		clear(&c.ctrl)
		c.ctrl_off = 0
	}
}

// The bytes of the `Ctrl_Rx` event that `next_event` returned last: the control
// record without its length prefix. Valid until the next `next_event`.
ctrl_record :: proc(c: ^Conn) -> []u8 {
	return c.ctrl_cur
}

// Takes the queued records of a peer out of the sequence (the peer is gone: a new
// peer with the same id must not get them). The bytes stay until their turn.
ctrl_forget :: proc(c: ^Conn, peer_id: u32) {
	for i in c.head ..< len(c.events) {
		if c.events[i].kind == .Ctrl_Rx && c.events[i].peer_id == peer_id {
			c.events[i].peer_id = CTRL_DEAD
		}
	}
}

// Sends one request and waits for its reply. `rep` gets the reply body when
// the status is 0 (`rep_len` bytes; a body of another length is cut or padded
// with zeros, see the protocol notes). `pass_fd` >= 0 goes along with
// SCM_RIGHTS. Returns the reply status (0 or -errno), or the connection error.
call :: proc(c: ^Conn, type: Msg, req: rawptr, req_len: int, rep: rawptr, rep_len: int, pass_fd: i32 = -1, tail: []u8 = nil) -> int {
	if c.fd < 0 {
		return ENOTCONN
	}
	buf := rx_buf(c)
	if buf == nil {
		return -12
	}
	if r := send_msg(c, type, req, req_len, pass_fd, tail); r < 0 {
		return r
	}
	stashed := 0
	status := 0
	for {
		n := recv_msg(c, buf, false)
		if n == EPROTO {
			// A message of a bad size: skip it, the reply may still come.
			continue
		}
		if n < 0 {
			return n
		}
		h: Hdr
		mem.copy(&h, &buf[0], HDR_SIZE)
		if h.flags & F_REPLY == 0 {
			if handle_async(c, buf[:n]) {
				stashed += 1
			}
			continue
		}
		if Msg(h.type) != type {
			continue
		}
		status = int(h.status)
		if status == 0 && rep_len > 0 {
			// A service of another version may send a shorter body (an older one)
			// or a longer one (a newer one): copy what fits, a missing field is 0.
			mem.zero(rep, rep_len)
			mem.copy(rep, &buf[HDR_SIZE], min(rep_len, n - HDR_SIZE))
		}
		break
	}
	if stashed > 0 {
		send_msg(c, .Ping, nil, 0, -1)
	}
	return status
}

// The next event: queued ones first, then what the socket has now. Returns 1
// with `ev` filled, 0 if none, or a negative errno if the connection is gone.
// A `Ctrl_Rx` event has its record in `ctrl_record`.
next_event :: proc(c: ^Conn, ev: ^Event) -> int {
	for {
		if c.head < len(c.events) {
			pop_event(c, ev)
			if ev.kind == .Ctrl_Rx && ev.peer_id == CTRL_DEAD {
				continue
			}
			return 1
		}
		if c.dropped > 0 && c.log != nil {
			c.log(c.log_user, .Error, "events were dropped because the queue was full")
			c.dropped = 0
		}
		if c.ctrl_lost > 0 && c.log != nil {
			c.log(c.log_user, .Error, "control records were dropped because the queue was full")
			c.ctrl_lost = 0
		}
		if c.fd < 0 {
			return ENOTCONN
		}
		buf := rx_buf(c)
		if buf == nil {
			return -12
		}
		for {
			n := recv_msg(c, buf, true)
			if n == EAGAIN {
				return 0
			}
			if n == EPROTO {
				continue
			}
			if n < 0 {
				return n
			}
			if handle_async(c, buf[:n]) {
				break
			}
		}
	}
}

// ---------------------------------------------------------------- requests

open_device :: proc(c: ^Conn, name: string, mode: Mode, flags: u32) -> (ifindex: u32, status: int) {
	if len(name) == 0 || len(name) >= IFNAME_MAX {
		return 0, EINVAL
	}
	req := Open {
		dataplane = u32(Dataplane.Openvpn),
		mode      = u32(mode),
		flags     = flags,
	}
	copy(req.ifname[:], name)
	rep: Open_Reply
	status = call(c, .Open, &req, size_of(req), &rep, size_of(rep))
	return rep.ifindex, status
}

close_device :: proc(c: ^Conn) -> int {
	return call(c, .Close, nil, 0, nil, 0)
}

new_peer :: proc(c: ^Conn, p: ^New_Peer, fd: i32 = -1) -> int {
	return call(c, .New_Peer, p, size_of(New_Peer), nil, 0, fd)
}

// A TCP peer (`CAP_TCP`): `fd` is the connected stream socket. The service
// owns the stream from the reply on; the caller closes its copy and never
// uses it again. `ahead`: bytes read from the stream and unused (a partial
// record is fine, at most STREAM_REC_MAX).
new_peer_stream :: proc(c: ^Conn, p: ^New_Peer, fd: i32, ahead: []u8 = nil) -> int {
	if fd < 0 {
		return EINVAL
	}
	return call(c, .New_Peer, p, size_of(New_Peer), nil, 0, fd, ahead)
}

// Sends one control record (no length prefix, 1 to STREAM_REC_MAX bytes) on
// the stream of a TCP peer. The service writes it after its queued records
// and before any data packet.
// ENOENT: no such peer. ENOTCONN: stream closed. ENOBUFS: 1 MB of records
// already waits.
ctrl_tx :: proc(c: ^Conn, peer_id: u32, rec: []u8) -> int {
	if len(rec) == 0 || len(rec) > STREAM_REC_MAX {
		return EMSGSIZE
	}
	req := Ctrl {
		peer_id = peer_id,
	}
	return call(c, .Ctrl_Tx, &req, size_of(req), nil, 0, -1, rec)
}

// The peer `peer_id` takes the id `new_id` (`CAP_PEER_ID`). A control record or an
// event that was queued before the call carries the old id and may be read after it.
set_peer_id :: proc(c: ^Conn, peer_id, new_id: u32) -> int {
	req := Set_Peer_Id {
		peer_id = peer_id,
		new_id  = new_id,
	}
	return call(c, .Set_Peer_Id, &req, size_of(req), nil, 0)
}

// The VPN addresses of a peer (`CAP_PEER_ADDR`), as `New_Peer` sets them.
set_peer_addr :: proc(c: ^Conn, a: ^Set_Peer_Addr) -> int {
	return call(c, .Set_Peer_Addr, a, size_of(Set_Peer_Addr), nil, 0)
}

// The packet filter of the device (`CAP_BLOCK_IPV6`). `out` gets the counters of the
// device since `open_device`; a service that sends less than 16 bytes leaves the rest 0.
set_filter :: proc(c: ^Conn, flags: u32, out: ^Filter_Stats) -> int {
	req := Set_Filter {
		flags = flags,
	}
	out^ = {}
	return call(c, .Set_Filter, &req, size_of(req), out, size_of(Filter_Stats))
}

set_peer :: proc(c: ^Conn, p: ^Set_Peer) -> int {
	return call(c, .Set_Peer, p, size_of(Set_Peer), nil, 0)
}

del_peer :: proc(c: ^Conn, peer_id: u32) -> int {
	req := Peer_Id {
		peer_id = peer_id,
	}
	// Records of this peer that are still queued are not for a later peer of the same id.
	ctrl_forget(c, peer_id)
	return call(c, .Del_Peer, &req, size_of(req), nil, 0)
}

new_key :: proc(c: ^Conn, k: ^New_Key) -> int {
	return call(c, .New_Key, k, size_of(New_Key), nil, 0)
}

swap_keys :: proc(c: ^Conn, peer_id: u32) -> int {
	req := Peer_Id {
		peer_id = peer_id,
	}
	return call(c, .Swap_Keys, &req, size_of(req), nil, 0)
}

del_key :: proc(c: ^Conn, peer_id: u32, slot: Key_Slot) -> int {
	req := Del_Key {
		peer_id = peer_id,
		slot    = u32(slot),
	}
	return call(c, .Del_Key, &req, size_of(req), nil, 0)
}

key_add :: proc(c: ^Conn, k: ^Key) -> int {
	return call(c, .Key_Add, k, size_of(Key), nil, 0)
}

key_tx :: proc(c: ^Conn, peer_id, key_id: u32) -> int {
	req := Key_Id {
		peer_id = peer_id,
		key_id  = key_id,
	}
	return call(c, .Key_Tx, &req, size_of(req), nil, 0)
}

key_drop :: proc(c: ^Conn, peer_id, key_id: u32) -> int {
	req := Key_Id {
		peer_id = peer_id,
		key_id  = key_id,
	}
	return call(c, .Key_Drop, &req, size_of(req), nil, 0)
}

peer_stats :: proc(c: ^Conn, peer_id: u32, out: ^Peer_Stats) -> int {
	req := Peer_Id {
		peer_id = peer_id,
	}
	return call(c, .Peer_Stats, &req, size_of(req), out, size_of(Peer_Stats))
}

detach :: proc(c: ^Conn) -> int {
	return call(c, .Detach, nil, 0, nil, 0)
}

// ----------------------------------------------------------------- backend

// The socket client as a `Backend`. `c` must stay where it is for as long as
// the backend is used.
socket_backend :: proc(c: ^Conn) -> Backend {
	return Backend {
		user = c,
		kind = .Service,
		fd = c.fd,
		mss_clamp = true,
		err_text = proc(user: rawptr) -> string {
			return ""
		},
		caps = c.hello.caps,
		open = proc(user: rawptr, name: string, mode: Mode, flags: u32) -> (u32, int) {
			return open_device((^Conn)(user), name, mode, flags)
		},
		close = proc(user: rawptr) -> int {
			return close_device((^Conn)(user))
		},
		new_peer = proc(user: rawptr, p: ^New_Peer, fd: i32) -> int {
			return new_peer((^Conn)(user), p, fd)
		},
		new_peer_stream = proc(user: rawptr, p: ^New_Peer, fd: i32, ahead: []u8) -> int {
			return new_peer_stream((^Conn)(user), p, fd, ahead)
		},
		ctrl_tx = proc(user: rawptr, peer_id: u32, rec: []u8) -> int {
			return ctrl_tx((^Conn)(user), peer_id, rec)
		},
		ctrl_record = proc(user: rawptr) -> []u8 {
			return ctrl_record((^Conn)(user))
		},
		set_peer_id = proc(user: rawptr, peer_id, new_id: u32) -> int {
			return set_peer_id((^Conn)(user), peer_id, new_id)
		},
		set_peer_addr = proc(user: rawptr, a: ^Set_Peer_Addr) -> int {
			return set_peer_addr((^Conn)(user), a)
		},
		set_filter = proc(user: rawptr, flags: u32, out: ^Filter_Stats) -> int {
			return set_filter((^Conn)(user), flags, out)
		},
		set_peer = proc(user: rawptr, p: ^Set_Peer) -> int {
			return set_peer((^Conn)(user), p)
		},
		del_peer = proc(user: rawptr, peer_id: u32) -> int {
			return del_peer((^Conn)(user), peer_id)
		},
		new_key = proc(user: rawptr, k: ^New_Key) -> int {
			return new_key((^Conn)(user), k)
		},
		swap_keys = proc(user: rawptr, peer_id: u32) -> int {
			return swap_keys((^Conn)(user), peer_id)
		},
		del_key = proc(user: rawptr, peer_id: u32, slot: Key_Slot) -> int {
			return del_key((^Conn)(user), peer_id, slot)
		},
		key_add = proc(user: rawptr, k: ^Key) -> int {
			return key_add((^Conn)(user), k)
		},
		key_tx = proc(user: rawptr, peer_id, key_id: u32) -> int {
			return key_tx((^Conn)(user), peer_id, key_id)
		},
		key_drop = proc(user: rawptr, peer_id, key_id: u32) -> int {
			return key_drop((^Conn)(user), peer_id, key_id)
		},
		stats = proc(user: rawptr, peer_id: u32, out: ^Peer_Stats) -> int {
			return peer_stats((^Conn)(user), peer_id, out)
		},
		detach = proc(user: rawptr) -> int {
			return detach((^Conn)(user))
		},
		next_event = proc(user: rawptr, ev: ^Event) -> int {
			return next_event((^Conn)(user), ev)
		},
	}
}
