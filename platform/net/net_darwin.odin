// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import "core:c"
import "core:sys/posix"

// The sockets on macOS, with core:sys/posix. Same names and rules as
// net_linux.odin. Differences:
//   - No MSG_NOSIGNAL: every socket gets SO_NOSIGPIPE, so a write to a closed
//     peer returns EPIPE and raises no signal.
//   - Non-blocking and close-on-exec are set with `fcntl` after `socket` (no
//     SOCK_NONBLOCK or SOCK_CLOEXEC flags).
//   - No UDP GSO, GRO or packet info: `Socket.gso`, `gro` and `pktinfo` stay
//     false, and a `Local` is `.Unsupported`.
//   - No SO_RCVBUFFORCE: kern.ipc.maxsockbuf caps the buffer sizes.
//   - The socket address starts with a length byte (`sin_len`).

// Socket levels and options, from <sys/socket.h>, <netinet/in.h>, <netinet/tcp.h>.
@(private)
SOL_SOCKET :: 0xffff
@(private)
SO_REUSEADDR :: 0x0004
@(private)
SO_REUSEPORT :: 0x0200
@(private)
SO_SNDBUF :: 0x1001
@(private)
SO_RCVBUF :: 0x1002
@(private)
SO_ERROR :: 0x1007
@(private)
SO_NOSIGPIPE :: 0x1022
@(private)
IPPROTO_TCP :: 6
@(private)
IPPROTO_IPV6 :: 41
@(private)
TCP_NODELAY :: 1
// Odin's posix package has no name for these two.
TCP_NOTSENT_LOWAT :: 0x201
@(private)
IPV6_V6ONLY :: 27

foreign import libsystem "system:System"

@(default_calling_convention = "c")
foreign libsystem {
	// The posix package takes an enum for the option name, which has no value
	// for the protocol level options.
	setsockopt :: proc(fd: c.int, level, name: c.int, value: rawptr, len: u32) -> c.int ---
	getsockopt :: proc(fd: c.int, level, name: c.int, value: rawptr, len: ^u32) -> c.int ---
}

// A socket address of any family, as the system calls take it.
@(private)
Sock_Addr :: struct #raw_union {
	base:    posix.sockaddr,
	v4:      posix.sockaddr_in,
	v6:      posix.sockaddr_in6,
	storage: posix.sockaddr_storage,
}

map_errno :: proc "contextless" (e: posix.Errno) -> Error {
	#partial switch e {
	case .NONE:
		return .None
	case .EAGAIN:
		return .Would_Block
	case .EINTR:
		return .Interrupted
	case .EPIPE:
		return .Closed
	case .ECONNREFUSED:
		return .Connection_Refused
	case .ECONNRESET, .ECONNABORTED:
		return .Connection_Reset
	case .ETIMEDOUT:
		return .Timed_Out
	case .EHOSTUNREACH:
		return .Host_Unreachable
	case .ENETUNREACH:
		return .Network_Unreachable
	case .ENETDOWN:
		return .Network_Down
	case .ENOTCONN:
		return .Not_Connected
	case .EADDRINUSE:
		return .Address_In_Use
	case .EADDRNOTAVAIL:
		return .Address_Not_Available
	case .EMSGSIZE:
		return .Message_Too_Long
	case .ENOBUFS, .ENOMEM:
		return .No_Buffers
	case .EMFILE, .ENFILE:
		return .Too_Many_Files
	case .EACCES, .EPERM:
		return .Permission
	case .EINVAL, .EBADF, .EFAULT, .ENOTSOCK, .EISCONN, .EDESTADDRREQ:
		return .Invalid
	case .EAFNOSUPPORT, .EPROTONOSUPPORT, .EOPNOTSUPP, .ENOPROTOOPT, .EPROTOTYPE:
		return .Unsupported
	}
	return .Other
}

// ---- options ----

@(private)
set_int_opt :: proc "contextless" (fd: i32, level, opt: c.int, v: i32) -> posix.Errno {
	val := v
	if setsockopt(fd, level, opt, &val, size_of(i32)) < 0 {
		return posix.errno()
	}
	return .NONE
}

@(private)
get_int_opt :: proc "contextless" (fd: i32, level, opt: c.int) -> (v: i32, e: posix.Errno) {
	n := u32(size_of(i32))
	if getsockopt(fd, level, opt, &v, &n) < 0 {
		return 0, posix.errno()
	}
	return v, .NONE
}

// Set the socket buffer sizes. Returns what the system ended up with. A size
// above kern.ipc.maxsockbuf is refused (ENOBUFS); half the size is tried until
// the system takes it.
set_buffer_sizes :: proc(s: Socket, recv_size, send_size: int) -> (recv_actual, send_actual: int, err: Error) {
	try_set :: proc(fd: i32, opt: c.int, size: int) -> Error {
		v := i32(min(size, int(max(i32))))
		for v >= 4096 {
			e := set_int_opt(fd, SOL_SOCKET, opt, v)
			if e == .NONE {
				return .None
			}
			if e != .ENOBUFS && e != .EINVAL {
				return map_errno(e)
			}
			v /= 2
		}
		return .No_Buffers
	}
	if recv_size > 0 {
		try_set(s.fd, SO_RCVBUF, recv_size) or_return
	}
	if send_size > 0 {
		try_set(s.fd, SO_SNDBUF, send_size) or_return
	}
	r, _ := get_int_opt(s.fd, SOL_SOCKET, SO_RCVBUF)
	w, _ := get_int_opt(s.fd, SOL_SOCKET, SO_SNDBUF)
	return int(r), int(w), .None
}

@(private)
apply_v6_mode :: proc(fd: i32, mode: V6_Mode) -> Error {
	switch mode {
	case .Dual_Stack:
		return map_errno(set_int_opt(fd, IPPROTO_IPV6, IPV6_V6ONLY, 0))
	case .V6_Only:
		return map_errno(set_int_opt(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1))
	case .System_Default:
	}
	return .None
}

// Non-blocking, close-on-exec, and SO_NOSIGPIPE set.
@(private)
prepare_fd :: proc(fd: posix.FD) -> Error {
	fl := posix.fcntl(fd, .GETFL)
	if fl < 0 || posix.fcntl(fd, .SETFL, fl | posix.O_NONBLOCK) < 0 {
		return map_errno(posix.errno())
	}
	if posix.fcntl(fd, .SETFD, posix.FD_CLOEXEC) < 0 {
		return map_errno(posix.errno())
	}
	if e := set_int_opt(i32(fd), SOL_SOCKET, SO_NOSIGPIPE, 1); e != .NONE {
		return map_errno(e)
	}
	return .None
}

@(private)
open_socket :: proc(family: Family, kind: posix.Sock, protocol: posix.Protocol) -> (s: Socket, err: Error) {
	af: posix.AF = .INET if family == .V4 else .INET6
	fd := posix.socket(af, kind, protocol)
	if fd < 0 {
		return INVALID_SOCKET, map_errno(posix.errno())
	}
	if perr := prepare_fd(fd); perr != .None {
		posix.close(fd)
		return INVALID_SOCKET, perr
	}
	return Socket{fd = i32(fd), family = family}, .None
}

// ---- addresses ----

// Fills a socket address for `ep` as seen through a socket of `family`. A v4
// endpoint on a v6 socket becomes a mapped address. False if `ep` is v6 and
// the socket is v4.
@(private)
to_sockaddr :: proc "contextless" (ep: Endpoint, family: Family) -> (sa: Sock_Addr, size: u32, ok: bool) {
	switch a in ep.address {
	case IP4_Address:
		switch family {
		case .V4:
			sa.v4.sin_len = size_of(posix.sockaddr_in)
			sa.v4.sin_family = .INET
			sa.v4.sin_port = posix.in_port_t(ep.port)
			(^[4]u8)(&sa.v4.sin_addr)^ = cast([4]u8)a
			return sa, size_of(posix.sockaddr_in), true
		case .V6:
			mapped: [16]u8
			mapped[10] = 0xff
			mapped[11] = 0xff
			mapped[12], mapped[13], mapped[14], mapped[15] = a[0], a[1], a[2], a[3]
			sa.v6.sin6_len = size_of(posix.sockaddr_in6)
			sa.v6.sin6_family = .INET6
			sa.v6.sin6_port = posix.in_port_t(ep.port)
			(^[16]u8)(&sa.v6.sin6_addr)^ = mapped
			return sa, size_of(posix.sockaddr_in6), true
		}
	case IP6_Address:
		if family == .V4 {
			return {}, 0, false
		}
		sa.v6.sin6_len = size_of(posix.sockaddr_in6)
		sa.v6.sin6_family = .INET6
		sa.v6.sin6_port = posix.in_port_t(ep.port)
		(^[16]u8)(&sa.v6.sin6_addr)^ = transmute([16]u8)a
		return sa, size_of(posix.sockaddr_in6), true
	}
	return {}, 0, false
}

// Is this IPv6 address an IPv4 address in the mapped form (::ffff:a.b.c.d)?
@(private)
addr_is_mapped :: proc "contextless" (b: [16]u8) -> bool {
	for i in 0 ..< 10 {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// Reads a socket address back into an endpoint. Mapped IPv4 addresses become
// IPv4 endpoints.
@(private)
from_sockaddr :: proc "contextless" (sa: ^Sock_Addr) -> (ep: Endpoint, ok: bool) {
	#partial switch sa.base.sa_family {
	case .INET:
		return Endpoint{address = IP4_Address((^[4]u8)(&sa.v4.sin_addr)^), port = int(sa.v4.sin_port)}, true
	case .INET6:
		b := (^[16]u8)(&sa.v6.sin6_addr)^
		if addr_is_mapped(b) {
			return Endpoint{address = IP4_Address{b[12], b[13], b[14], b[15]}, port = int(sa.v6.sin6_port)}, true
		}
		return Endpoint{address = IP6_Address(transmute([8]u16be)b), port = int(sa.v6.sin6_port)}, true
	}
	return {}, false
}

// ---- common socket calls ----

close :: proc "contextless" (s: Socket) {
	if s.fd >= 0 {
		posix.close(posix.FD(s.fd))
	}
}

// Bind to a local address. Use port 0 for any free port.
bind :: proc(s: Socket, ep: Endpoint) -> Error {
	sa, size, ok := to_sockaddr(ep, s.family)
	if !ok {
		return .Invalid
	}
	if posix.bind(posix.FD(s.fd), &sa.base, posix.socklen_t(size)) != .OK {
		return map_errno(posix.errno())
	}
	return .None
}

// Set the default peer. For UDP this also filters incoming packets to that
// peer and lets `send`/`recv` work without an address.
connect :: proc(s: Socket, ep: Endpoint) -> Error {
	sa, size, ok := to_sockaddr(ep, s.family)
	if !ok {
		return .Invalid
	}
	if posix.connect(posix.FD(s.fd), &sa.base, posix.socklen_t(size)) != .OK {
		return map_errno(posix.errno())
	}
	return .None
}

// The local address the socket is bound to (after `bind` with port 0, this
// shows the port the system chose).
local_endpoint :: proc(s: Socket) -> (ep: Endpoint, err: Error) {
	sa: Sock_Addr
	n := posix.socklen_t(size_of(Sock_Addr))
	if posix.getsockname(posix.FD(s.fd), &sa.base, &n) != .OK {
		return {}, map_errno(posix.errno())
	}
	ok: bool
	ep, ok = from_sockaddr(&sa)
	return ep, .None if ok else .Unsupported
}

peer_endpoint :: proc(s: Socket) -> (ep: Endpoint, err: Error) {
	sa: Sock_Addr
	n := posix.socklen_t(size_of(Sock_Addr))
	if posix.getpeername(posix.FD(s.fd), &sa.base, &n) != .OK {
		return {}, map_errno(posix.errno())
	}
	ok: bool
	ep, ok = from_sockaddr(&sa)
	return ep, .None if ok else .Unsupported
}

// ---- UDP ----

// Create a non-blocking UDP socket. It is not bound yet.
udp_open :: proc(family: Family, opts: UDP_Options = {}) -> (s: Socket, err: Error) {
	sock := open_socket(family, .DGRAM, .UDP) or_return
	if serr := udp_setup(sock, opts); serr != .None {
		close(sock)
		return INVALID_SOCKET, serr
	}
	return sock, .None
}

@(private)
udp_setup :: proc(s: Socket, opts: UDP_Options) -> Error {
	if s.family == .V6 {
		apply_v6_mode(s.fd, opts.v6_mode) or_return
	}
	if opts.reuse_addr {
		if oe := set_int_opt(s.fd, SOL_SOCKET, SO_REUSEADDR, 1); oe != .NONE {
			return map_errno(oe)
		}
	}
	if opts.reuse_port {
		if oe := set_int_opt(s.fd, SOL_SOCKET, SO_REUSEPORT, 1); oe != .NONE {
			return map_errno(oe)
		}
	}
	if opts.recv_buffer > 0 || opts.send_buffer > 0 {
		_, _ = set_buffer_sizes(s, opts.recv_buffer, opts.send_buffer) or_return
	}
	return .None
}

// macOS has no UDP GSO or GRO: the socket is returned with both off.
udp_offload_enable :: proc(s: Socket) -> Socket {
	r := s
	r.gso, r.gro = false, false
	return r
}

// macOS has no packet info in this package: the socket is returned with it off.
udp_pktinfo_enable :: proc(s: Socket) -> Socket {
	r := s
	r.pktinfo = false
	return r
}

// Nothing to switch off.
udp_gro_disable :: proc(s: Socket) -> Socket {
	r := s
	r.gro = false
	return r
}

// Receive one datagram from a connected socket.
recv :: proc(s: Socket, buf: []u8) -> (n: int, err: Error) {
	for {
		got := posix.recv(posix.FD(s.fd), raw_data(buf), uint(len(buf)), {})
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return 0, map_errno(e)
		}
		return int(got), .None
	}
}

// Receive one datagram and its source address.
recv_from :: proc(s: Socket, buf: []u8) -> (n: int, from: Endpoint, err: Error) {
	sa: Sock_Addr
	for {
		size := posix.socklen_t(size_of(Sock_Addr))
		got := posix.recvfrom(posix.FD(s.fd), raw_data(buf), uint(len(buf)), {}, &sa.base, &size)
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return 0, {}, map_errno(e)
		}
		ep, ok := from_sockaddr(&sa)
		if !ok {
			return int(got), {}, .Unsupported
		}
		return int(got), ep, .None
	}
}

// Send one datagram on a connected socket.
send :: proc(s: Socket, data: []u8) -> Error {
	for {
		if posix.send(posix.FD(s.fd), raw_data(data), uint(len(data)), {}) < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return map_errno(e)
		}
		return .None
	}
}

// Send one datagram to an address. A `local` is `.Unsupported` on macOS: the
// datagram leaves from the address the route picks.
send_to :: proc(s: Socket, data: []u8, to: Endpoint, local := Local{}) -> Error {
	if local.len > 0 {
		return .Unsupported
	}
	sa, size, ok := to_sockaddr(to, s.family)
	if !ok {
		return .Invalid
	}
	for {
		if posix.sendto(posix.FD(s.fd), raw_data(data), uint(len(data)), {}, &sa.base, posix.socklen_t(size)) < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return map_errno(e)
		}
		return .None
	}
}

// ---- TCP ----

// Start a non-blocking TCP connection. `in_progress` true: add the socket to
// the event loop for `.Write`; when it fires call `tcp_connect_finish`. False:
// already connected (loopback can do this). On error the socket is closed and
// `s` is `INVALID_SOCKET`.
tcp_connect :: proc(ep: Endpoint, opts: TCP_Options = {}) -> (s: Socket, in_progress: bool, err: Error) {
	sock, oerr := open_socket(family_of(ep), .STREAM, .TCP)
	if oerr != .None {
		return INVALID_SOCKET, false, oerr
	}
	pending, serr := tcp_connect_setup(sock, ep, opts)
	if serr != .None {
		close(sock)
		return INVALID_SOCKET, false, serr
	}
	return sock, pending, .None
}

@(private)
tcp_connect_setup :: proc(s: Socket, ep: Endpoint, opts: TCP_Options) -> (in_progress: bool, err: Error) {
	if s.family == .V6 {
		apply_v6_mode(s.fd, opts.v6_mode) or_return
	}
	if !opts.nagle {
		if oe := set_int_opt(s.fd, IPPROTO_TCP, TCP_NODELAY, 1); oe != .NONE {
			return false, map_errno(oe)
		}
	}
	if opts.notsent_lowat {
		tcp_set_notsent_lowat(s)
	}
	if opts.recv_buffer > 0 || opts.send_buffer > 0 {
		_, _ = set_buffer_sizes(s, opts.recv_buffer, opts.send_buffer) or_return
	}
	if local, has := opts.local.?; has {
		bind(s, local) or_return
	}
	sa, size, ok := to_sockaddr(ep, s.family)
	if !ok {
		return false, .Invalid
	}
	if posix.connect(posix.FD(s.fd), &sa.base, posix.socklen_t(size)) == .OK {
		return false, .None
	}
	ce := posix.errno()
	if ce == .EINPROGRESS {
		return true, .None
	}
	return false, map_errno(ce)
}

// Call after the socket became writable. `.None`: connected. `.Would_Block`:
// not yet, wait again. Other: why the connect failed (close the socket).
tcp_connect_finish :: proc(s: Socket) -> Error {
	v, e := get_int_opt(s.fd, SOL_SOCKET, SO_ERROR)
	if e != .NONE {
		return map_errno(e)
	}
	if v != 0 {
		return map_errno(posix.Errno(v))
	}
	sa: Sock_Addr
	n := posix.socklen_t(size_of(Sock_Addr))
	if posix.getpeername(posix.FD(s.fd), &sa.base, &n) != .OK {
		pe := posix.errno()
		if pe == .ENOTCONN {
			return .Would_Block
		}
		return map_errno(pe)
	}
	return .None
}

// A listening TCP socket (for tests, and for a server).
tcp_listen :: proc(ep: Endpoint, backlog: i32 = 128, v6_mode := V6_Mode.Dual_Stack) -> (s: Socket, err: Error) {
	sock := open_socket(family_of(ep), .STREAM, .TCP) or_return
	if serr := tcp_listen_setup(sock, ep, backlog, v6_mode); serr != .None {
		close(sock)
		return INVALID_SOCKET, serr
	}
	return sock, .None
}

@(private)
tcp_listen_setup :: proc(s: Socket, ep: Endpoint, backlog: i32, v6_mode: V6_Mode) -> Error {
	if s.family == .V6 {
		apply_v6_mode(s.fd, v6_mode) or_return
	}
	if oe := set_int_opt(s.fd, SOL_SOCKET, SO_REUSEADDR, 1); oe != .NONE {
		return map_errno(oe)
	}
	bind(s, ep) or_return
	if posix.listen(posix.FD(s.fd), backlog) != .OK {
		return map_errno(posix.errno())
	}
	return .None
}

// Limits the bytes the system holds unsent in a TCP socket (see the Linux file
// for why). A system that refuses it is not an error.
tcp_set_notsent_lowat :: proc "contextless" (s: Socket) {
	set_int_opt(s.fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, NOTSENT_LOWAT)
}

// Accept one connection. The new socket is non-blocking, with TCP_NODELAY
// (unless `opts.nagle`) and TCP_NOTSENT_LOWAT (if `opts.notsent_lowat`). Other
// `opts` fields do not apply.
tcp_accept :: proc(listener: Socket, opts: TCP_Options = {}) -> (s: Socket, from: Endpoint, err: Error) {
	sa: Sock_Addr
	for {
		size := posix.socklen_t(size_of(Sock_Addr))
		fd := posix.accept(posix.FD(listener.fd), &sa.base, &size)
		if fd < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return INVALID_SOCKET, {}, map_errno(e)
		}
		if perr := prepare_fd(fd); perr != .None {
			posix.close(fd)
			return INVALID_SOCKET, {}, perr
		}
		s = {
			fd     = i32(fd),
			family = listener.family,
		}
		if !opts.nagle {
			set_int_opt(s.fd, IPPROTO_TCP, TCP_NODELAY, 1)
		}
		if opts.notsent_lowat {
			tcp_set_notsent_lowat(s)
		}
		from, _ = from_sockaddr(&sa)
		return s, from, .None
	}
}

// Read from a stream socket. `.Closed` when the peer closed its side. It needs
// no Odin context, so a C callback (the BIO of `platform/tlslink`) may call it.
stream_recv :: proc "contextless" (s: Socket, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	for {
		got := posix.recv(posix.FD(s.fd), raw_data(buf), uint(len(buf)), {})
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return 0, map_errno(e)
		}
		if got == 0 {
			return 0, .Closed
		}
		return int(got), .None
	}
}

// Look at the next bytes of a stream socket without taking them out.
stream_peek :: proc(s: Socket, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	for {
		got := posix.recv(posix.FD(s.fd), raw_data(buf), uint(len(buf)), {.PEEK})
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return 0, map_errno(e)
		}
		if got == 0 {
			return 0, .Closed
		}
		return int(got), .None
	}
}

// Write to a stream socket without raising SIGPIPE (SO_NOSIGPIPE). May write
// less than asked.
stream_send :: proc(s: Socket, data: []u8) -> (n: int, err: Error) {
	if len(data) == 0 {
		return 0, .None
	}
	for {
		got := posix.send(posix.FD(s.fd), raw_data(data), uint(len(data)), {})
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return 0, map_errno(e)
		}
		return int(got), .None
	}
}

// Close our sending side after the queued data (a clean end of stream).
shutdown_write :: proc(s: Socket) -> Error {
	if posix.shutdown(posix.FD(s.fd), .WR) != .OK {
		return map_errno(posix.errno())
	}
	return .None
}
