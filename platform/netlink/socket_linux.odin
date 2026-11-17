// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package netlink

import "core:sys/linux"
import "core:time"

// Netlink socket with blocking request/reply helpers. Not thread safe: use one
// per thread. The receive timeout keeps a lost reply from hanging the caller.

// Socket level for netlink options (not in core:sys/linux).
SOL_NETLINK :: 270

NETLINK_ADD_MEMBERSHIP  :: 1
NETLINK_DROP_MEMBERSHIP :: 2
NETLINK_CAP_ACK         :: 10
NETLINK_EXT_ACK         :: 11
NETLINK_GET_STRICT_CHK  :: 12

@(private)
SOL_SOCKET :: 1

EXT_MSG_MAX :: 128

Socket :: struct {
	fd:      linux.Fd,
	seq:     u32, // last sequence number handed out
	port:    u32, // our port id (nl_pid), assigned by the kernel
	errno:   linux.Errno, // errno behind the last `.Kernel` or `.Io` error
	ext_msg: [EXT_MSG_MAX]u8, // the kernel's text for the last `.Kernel` error, if any
	ext_len: int,
}

// A reply handler. `msg.payload` points into the receive buffer and is valid
// only during the call.
Handler :: proc(user: rawptr, msg: Msg)

// The kernel's explanation of the last `.Kernel` error, or "".
ext_message :: proc(s: ^Socket) -> string {
	return string(s.ext_msg[:s.ext_len])
}

// Opens and binds a netlink socket. `groups`: bit mask of legacy multicast
// groups to join at bind (0 none; use `subscribe` for group numbers above 31).
// `timeout` bounds each wait for a reply.
open :: proc(protocol: int, groups: u32 = 0, timeout := 5 * time.Second) -> (s: Socket, err: Error) {
	fd, e := linux.socket(.NETLINK, .RAW, {.CLOEXEC}, linux.Protocol(protocol))
	if e != .NONE {
		s.errno = e
		return s, .Io
	}
	s.fd = fd

	// bind(2) with port 0: the kernel picks a free port id.
	addr := Sock_Addr_Nl{family = u16(linux.Address_Family.NETLINK), groups = groups}
	if ret := linux.syscall(linux.SYS_bind, fd, &addr, size_of(addr)); ret < 0 {
		err = open_failed(&s, linux.Errno(-ret))
		return s, err
	}
	addr_len := u32(size_of(addr))
	if ret := linux.syscall(linux.SYS_getsockname, fd, &addr, &addr_len); ret < 0 {
		err = open_failed(&s, linux.Errno(-ret))
		return s, err
	}
	s.port = addr.pid

	// Optional kernel features; old kernels may refuse them.
	one: i32 = 1
	linux.setsockopt_base(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one)
	linux.setsockopt_base(fd, SOL_NETLINK, NETLINK_CAP_ACK, &one)
	if protocol == NETLINK_ROUTE {
		linux.setsockopt_base(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &one)
	}

	if timeout > 0 {
		tv := Timeval {
			sec  = i64(timeout / time.Second),
			usec = i64((timeout % time.Second) / time.Microsecond),
		}
		// 64-bit fields are right for both SO_RCVTIMEO_OLD (64-bit hosts) and
		// SO_RCVTIMEO_NEW (32-bit hosts).
		opt := int(linux.Socket_Option.RCVTIMEO)
		if ret := linux.setsockopt_base(fd, SOL_SOCKET, opt, &tv); ret != .NONE {
			err = open_failed(&s, ret)
			return s, err
		}
	}
	return s, .None
}

// A deferred close cannot change the returned socket. So each failure in
// `open` closes by hand and returns a socket with no descriptor (call it
// before the `return`: the returned values are copied first).
@(private)
open_failed :: proc(s: ^Socket, e: linux.Errno) -> Error {
	linux.close(s.fd)
	s.fd = -1
	s.errno = e
	return .Io
}

close :: proc(s: ^Socket) {
	if s.fd > 0 {
		linux.close(s.fd)
	}
	s.fd = -1
}

// Join a multicast group (group number, not a bit mask).
subscribe :: proc(s: ^Socket, group: u32) -> Error {
	g := group
	if e := linux.setsockopt_base(s.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &g); e != .NONE {
		s.errno = e
		return .Io
	}
	return .None
}

// The next sequence number for a request.
next_seq :: proc(s: ^Socket) -> u32 {
	s.seq += 1
	return s.seq
}

// Send one finished message (or several) to the kernel.
send :: proc(s: ^Socket, msg: []u8) -> Error {
	for {
		_, e := linux.send(s.fd, msg, {})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			s.errno = e
			return .Io
		}
		return .None
	}
}

// Receive one datagram (one or more messages). `.Timeout`: nothing came in
// time. `.Buffer_Too_Small`: the datagram did not fit and is lost (use 32 KiB
// or more for dumps).
recv :: proc(s: ^Socket, buf: []u8) -> (n: int, err: Error) {
	for {
		// MSG_TRUNC causes the kernel to return the real size even when cut.
		got, e := linux.recv(s.fd, buf, {.TRUNC})
		#partial switch e {
		case .NONE:
			if got > len(buf) {
				return 0, .Buffer_Too_Small
			}
			return got, .None
		case .EINTR:
			continue
		case .EAGAIN:
			return 0, .Timeout
		case:
			s.errno = e
			return 0, .Io
		}
	}
}

// Like `recv`, but never waits: `.Timeout` when nothing is queued. For poll
// loops (notifications). A queue overflow gives `.Io` with errno ENOBUFS:
// messages were lost.
recv_nowait :: proc(s: ^Socket, buf: []u8) -> (n: int, err: Error) {
	for {
		got, e := linux.recv(s.fd, buf, {.TRUNC, .DONTWAIT})
		#partial switch e {
		case .NONE:
			if got > len(buf) {
				return 0, .Buffer_Too_Small
			}
			return got, .None
		case .EINTR:
			continue
		case .EAGAIN:
			return 0, .Timeout
		case:
			s.errno = e
			return 0, .Io
		}
	}
}

// Send `msg` (one message) and wait for the response to its sequence number.
// Each data message in the response goes to `handler`. The call ends at:
// - an ACK or error (request with NLM_F_ACK)
// - the end of a dump (NLM_F_DUMP)
// A request with neither flag gets no end marker and waits until the timeout.
//
// `rx` is the receive buffer. For dumps use 32 KiB or more.
request :: proc(s: ^Socket, msg: []u8, rx: []u8, handler: Handler = nil, user: rawptr = nil) -> Error {
	if len(msg) < NLMSG_HDRLEN {
		return .Truncated
	}
	hdr := (^Msg_Hdr)(raw_data(msg))^
	s.ext_len = 0
	send(s, msg) or_return

	interrupted := false
	for {
		n := recv(s, rx) or_return
		it := msg_iter(rx[:n])
		for m in msg_next(&it) {
			if m.hdr.seq != hdr.seq {
				continue // a notification, or a response to something else
			}
			switch m.hdr.type {
			case NLMSG_NOOP:
				continue
			case NLMSG_OVERRUN:
				return .Unexpected
			case NLMSG_DONE:
				return .Dump_Interrupted if interrupted else .None
			case NLMSG_ERROR:
				errno, text, ok := parse_error(m.hdr.flags, m.payload)
				if !ok {
					return .Truncated
				}
				if errno == 0 {
					return .Dump_Interrupted if interrupted else .None
				}
				s.errno = linux.Errno(errno)
				s.ext_len = min(len(text), EXT_MSG_MAX)
				copy(s.ext_msg[:], text[:s.ext_len])
				return .Kernel
			case:
				if m.hdr.flags & NLM_F_DUMP_INTR != 0 {
					interrupted = true
				}
				if handler != nil {
					handler(user, m)
				}
			}
		}
		if it.err != .None {
			return it.err
		}
	}
}

// `request` for a message that only needs an ACK.
transact :: proc(s: ^Socket, msg: []u8, rx: []u8) -> Error {
	return request(s, msg, rx)
}

@(private)
Sock_Addr_Nl :: struct #packed {
	family: u16,
	_pad:   u16,
	pid:    u32,
	groups: u32,
}

@(private)
Timeval :: struct {
	sec:  i64,
	usec: i64,
}

// Resolve a generic netlink family by name. `s` must be a NETLINK_GENERIC
// socket. A family that is not loaded gives `.Kernel` with errno ENOENT.
genl_resolve :: proc(s: ^Socket, name: string, rx: []u8) -> (info: Family_Info, err: Error) {
	buf: [128]u8
	b: Builder
	builder_init(&b, buf[:])
	put_genl_header(&b, GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, next_seq(s), CTRL_CMD_GETFAMILY, 1)
	put_str(&b, CTRL_ATTR_FAMILY_NAME, name)
	msg := finish(&b) or_return

	Result :: struct {
		info:  Family_Info,
		found: bool,
	}
	res: Result
	handler :: proc(user: rawptr, m: Msg) {
		r := (^Result)(user)
		if m.hdr.type == GENL_ID_CTRL && !r.found {
			r.info, r.found = parse_family_info(m.payload)
		}
	}
	request(s, msg, rx, handler, &res) or_return
	if !res.found {
		return {}, .Unexpected
	}
	return res.info, .None
}
