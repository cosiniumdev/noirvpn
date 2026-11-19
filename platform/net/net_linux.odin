// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import "core:sys/linux"

// Socket levels and options that core:sys/linux does not name (or names
// without the IPv6 ones).
@(private)
SOL_SOCKET :: 1
@(private)
IPPROTO_IP :: 0
@(private)
IPPROTO_TCP :: 6
@(private)
IPPROTO_IPV6 :: 41
@(private)
TCP_NODELAY :: 1
TCP_NOTSENT_LOWAT :: 25
@(private)
IPV6_V6ONLY :: 26
@(private)
TCP_KEEPIDLE :: 4
@(private)
TCP_KEEPINTVL :: 5
@(private)
TCP_KEEPCNT :: 6
// Packet info (ip(7), ipv6(7)): the option on an IPv4 socket, the options and
// the control message type on an IPv6 socket.
@(private)
IP_PKTINFO :: 8
@(private)
IPV6_RECVPKTINFO :: 49
@(private)
IPV6_PKTINFO :: 50
// UDP socket options (<linux/udp.h>), at level SOL_UDP (= IPPROTO_UDP).
SOL_UDP :: 17
UDP_SEGMENT :: 103
UDP_GRO :: 104

map_errno :: proc "contextless" (e: linux.Errno) -> Error {
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
set_int_opt :: proc "contextless" (fd: i32, level, opt: int, v: i32) -> linux.Errno {
	val := v
	return linux.setsockopt_base(linux.Fd(fd), level, opt, &val)
}

// core:sys/linux's getsockopt passes the size of the pointer as the length,
// so do it by hand with the right size.
@(private)
get_int_opt :: proc "contextless" (fd: i32, level, opt: int) -> (v: i32, e: linux.Errno) {
	n := u32(size_of(i32))
	ret := linux.syscall(linux.SYS_getsockopt, linux.Fd(fd), level, opt, &v, &n)
	if ret < 0 {
		return 0, linux.Errno(-ret)
	}
	return v, .NONE
}

// Set the socket buffer sizes. Tries SO_RCVBUFFORCE first (ignores the system
// maximum, needs CAP_NET_ADMIN), then SO_RCVBUF. Returns what the kernel ended
// up with (it reports double the request, for bookkeeping).
set_buffer_sizes :: proc(s: Socket, recv_size, send_size: int) -> (recv_actual, send_actual: int, err: Error) {
	if recv_size > 0 {
		v := i32(min(recv_size, int(max(i32))))
		if set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.RCVBUFFORCE), v) != .NONE {
			if e := set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.RCVBUF), v); e != .NONE {
				return 0, 0, map_errno(e)
			}
		}
	}
	if send_size > 0 {
		v := i32(min(send_size, int(max(i32))))
		if set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.SNDBUFFORCE), v) != .NONE {
			if e := set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.SNDBUF), v); e != .NONE {
				return 0, 0, map_errno(e)
			}
		}
	}
	r, _ := get_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.RCVBUF))
	w, _ := get_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.SNDBUF))
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

// ---- addresses ----

// Fills a socket address for `ep` as seen through a socket of `family`. A v4
// endpoint on a v6 socket becomes a mapped address. False if `ep` is v6 and
// the socket is v4.
@(private)
to_sockaddr :: proc "contextless" (ep: Endpoint, family: Family) -> (sa: linux.Sock_Addr_Any, size: u32, ok: bool) {
	switch a in ep.address {
	case IP4_Address:
		switch family {
		case .V4:
			octets := cast([4]u8)a
			sa.ipv4 = {
				sin_family = .INET,
				sin_port   = u16be(ep.port),
				sin_addr   = octets,
			}
			return sa, size_of(linux.Sock_Addr_In), true
		case .V6:
			mapped: [16]u8
			mapped[10] = 0xff
			mapped[11] = 0xff
			mapped[12], mapped[13], mapped[14], mapped[15] = a[0], a[1], a[2], a[3]
			sa.ipv6 = {
				sin6_family = .INET6,
				sin6_port   = u16be(ep.port),
				sin6_addr   = mapped,
			}
			return sa, size_of(linux.Sock_Addr_In6), true
		}
	case IP6_Address:
		if family == .V4 {
			return {}, 0, false
		}
		sa.ipv6 = {
			sin6_family = .INET6,
			sin6_port   = u16be(ep.port),
			sin6_addr   = transmute([16]u8)a,
		}
		return sa, size_of(linux.Sock_Addr_In6), true
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
from_sockaddr :: proc "contextless" (sa: ^linux.Sock_Addr_Any) -> (ep: Endpoint, ok: bool) {
	#partial switch sa.family {
	case .INET:
		return Endpoint{address = IP4_Address(sa.sin_addr), port = int(sa.sin_port)}, true
	case .INET6:
		b := sa.sin6_addr
		if addr_is_mapped(b) {
			return Endpoint{address = IP4_Address{b[12], b[13], b[14], b[15]}, port = int(sa.sin6_port)}, true
		}
		return Endpoint{address = IP6_Address(transmute([8]u16be)b), port = int(sa.sin6_port)}, true
	}
	return {}, false
}

@(private)
sys_bind :: proc "contextless" (fd: i32, sa: ^linux.Sock_Addr_Any, size: u32) -> linux.Errno {
	ret := linux.syscall(linux.SYS_bind, linux.Fd(fd), sa, size)
	return linux.Errno(-ret) if ret < 0 else .NONE
}

@(private)
sys_connect :: proc "contextless" (fd: i32, sa: ^linux.Sock_Addr_Any, size: u32) -> linux.Errno {
	ret := linux.syscall(linux.SYS_connect, linux.Fd(fd), sa, size)
	return linux.Errno(-ret) if ret < 0 else .NONE
}

// ---- common socket calls ----

close :: proc "contextless" (s: Socket) {
	if s.fd >= 0 {
		linux.close(linux.Fd(s.fd))
	}
}

// Bind to a local address. Use port 0 for any free port.
bind :: proc(s: Socket, ep: Endpoint) -> Error {
	sa, size, ok := to_sockaddr(ep, s.family)
	if !ok {
		return .Invalid
	}
	return map_errno(sys_bind(s.fd, &sa, size))
}

// Set the default peer. For UDP this also filters incoming packets to that
// peer and lets `send`/`recv` work without an address.
connect :: proc(s: Socket, ep: Endpoint) -> Error {
	sa, size, ok := to_sockaddr(ep, s.family)
	if !ok {
		return .Invalid
	}
	return map_errno(sys_connect(s.fd, &sa, size))
}

// The local address the socket is bound to (after `bind` with port 0, this
// shows the port the kernel chose).
local_endpoint :: proc(s: Socket) -> (ep: Endpoint, err: Error) {
	sa: linux.Sock_Addr_Any
	if e := linux.getsockname(linux.Fd(s.fd), &sa); e != .NONE {
		return {}, map_errno(e)
	}
	ok: bool
	ep, ok = from_sockaddr(&sa)
	return ep, .None if ok else .Unsupported
}

peer_endpoint :: proc(s: Socket) -> (ep: Endpoint, err: Error) {
	sa: linux.Sock_Addr_Any
	if e := linux.getpeername(linux.Fd(s.fd), &sa); e != .NONE {
		return {}, map_errno(e)
	}
	ok: bool
	ep, ok = from_sockaddr(&sa)
	return ep, .None if ok else .Unsupported
}

// ---- UDP ----

// Create a non-blocking UDP socket. It is not bound yet.
udp_open :: proc(family: Family, opts: UDP_Options = {}) -> (s: Socket, err: Error) {
	af: linux.Address_Family = .INET if family == .V4 else .INET6
	fd, e := linux.socket(af, .DGRAM, {.NONBLOCK, .CLOEXEC}, .UDP)
	if e != .NONE {
		return INVALID_SOCKET, map_errno(e)
	}
	sock := Socket {
		fd     = i32(fd),
		family = family,
	}
	// A deferred cleanup cannot change the returned value, so close in the
	// error path by hand and never hand back a closed descriptor.
	if serr := udp_setup(sock, opts); serr != .None {
		close(sock)
		return INVALID_SOCKET, serr
	}
	if opts.offload {
		sock = udp_offload_enable(sock)
	}
	if opts.pktinfo {
		sock = udp_pktinfo_enable(sock)
	}
	return sock, .None
}

@(private)
udp_setup :: proc(s: Socket, opts: UDP_Options) -> Error {
	if s.family == .V6 {
		apply_v6_mode(s.fd, opts.v6_mode) or_return
	}
	if opts.reuse_addr {
		if oe := set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.REUSEADDR), 1); oe != .NONE {
			return map_errno(oe)
		}
	}
	if opts.reuse_port {
		if oe := set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.REUSEPORT), 1); oe != .NONE {
			return map_errno(oe)
		}
	}
	if opts.recv_buffer > 0 || opts.send_buffer > 0 {
		_, _ = set_buffer_sizes(s, opts.recv_buffer, opts.send_buffer) or_return
	}
	return .None
}

// Switches on the UDP offloads the kernel has. Returns the socket with `gso`
// and `gro` set to what worked. Never fails: without them the socket works as
// before.
// - GSO: detected by reading UDP_SEGMENT (a kernel before 4.18 lacks it). If
//   the device under the route takes it shows only at the first send:
//   `send_pushed` falls back by itself (see batch_linux.odin).
// - GRO: the UDP_GRO option (5.0 and later).
udp_offload_enable :: proc(s: Socket) -> Socket {
	r := s
	r.gso, r.gro = false, false
	if _, e := get_int_opt(s.fd, SOL_UDP, UDP_SEGMENT); e == .NONE {
		r.gso = true
	}
	if set_int_opt(s.fd, SOL_UDP, UDP_GRO, 1) == .NONE {
		r.gro = true
	}
	return r
}

// Asks for the local address of every datagram. Returns the socket with
// `pktinfo` set to whether it worked. Never fails: without it, replies leave
// from the address the route picks.
// - IPv4 socket: IP_PKTINFO.
// - IPv6 socket: IPV6_RECVPKTINFO. A dual-stack socket reports an IPv4
//   datagram in IPV6_PKTINFO with an IPv4-mapped address (ipv6(7));
//   `batch_local` turns it back into an IPv4 local.
udp_pktinfo_enable :: proc(s: Socket) -> Socket {
	r := s
	level, opt := IPPROTO_IP, IP_PKTINFO
	if s.family == .V6 {
		level, opt = IPPROTO_IPV6, IPV6_RECVPKTINFO
	}
	r.pktinfo = set_int_opt(s.fd, level, opt, 1) == .NONE
	return r
}

// Switches UDP_GRO off again (for tests, and for a fallback).
udp_gro_disable :: proc(s: Socket) -> Socket {
	r := s
	if r.gro {
		set_int_opt(s.fd, SOL_UDP, UDP_GRO, 0)
		r.gro = false
	}
	return r
}

// Receive one datagram from a connected socket.
recv :: proc(s: Socket, buf: []u8) -> (n: int, err: Error) {
	for {
		got, e := linux.recv(linux.Fd(s.fd), buf, {.DONTWAIT})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return 0, map_errno(e)
		}
		return got, .None
	}
}

// Receive one datagram and its source address.
recv_from :: proc(s: Socket, buf: []u8) -> (n: int, from: Endpoint, err: Error) {
	sa: linux.Sock_Addr_Any
	for {
		got, e := linux.recvfrom(linux.Fd(s.fd), buf, {.DONTWAIT}, &sa)
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return 0, {}, map_errno(e)
		}
		ep, ok := from_sockaddr(&sa)
		if !ok {
			return got, {}, .Unsupported
		}
		return got, ep, .None
	}
}

// Send one datagram on a connected socket.
send :: proc(s: Socket, data: []u8) -> Error {
	for {
		_, e := linux.send(linux.Fd(s.fd), data, {.NOSIGNAL, .DONTWAIT})
		if e == .EINTR {
			continue
		}
		return map_errno(e)
	}
}

// Send one datagram. With a `local` it leaves from that address (and
// interface, if the local names one): see `Local`. A local the host no longer
// has causes the kernel to refuse the send (`.Invalid`).
send_to :: proc(s: Socket, data: []u8, to: Endpoint, local := Local{}) -> Error {
	sa, size, ok := to_sockaddr(to, s.family)
	if !ok {
		return .Invalid
	}
	if local.len > 0 {
		return send_to_local(s, data, &sa, size, local)
	}
	for {
		ret := linux.syscall(
			linux.SYS_sendto,
			linux.Fd(s.fd),
			raw_data(data),
			len(data),
			transmute(i32)linux.Socket_Msg{.NOSIGNAL, .DONTWAIT},
			&sa,
			size,
		)
		if ret == -int(linux.Errno.EINTR) {
			continue
		}
		if ret < 0 {
			return map_errno(linux.Errno(-ret))
		}
		return .None
	}
}

// sendmsg with the packet info of `local`.
@(private)
send_to_local :: proc(s: Socket, data: []u8, sa: ^linux.Sock_Addr_Any, size: u32, local: Local) -> Error {
	ctrl: Ctrl
	used := cmsg_put_pktinfo(&ctrl, 0, s.family, local)
	iov := linux.IO_Vec {
		base = raw_data(data),
		len  = uint(len(data)),
	}
	hdr := linux.Msg_Hdr {
		name    = sa,
		namelen = i32(size),
		iov     = ([^]linux.IO_Vec)(&iov)[:1],
	}
	if used > 0 {
		hdr.control = ([^]u8)(&ctrl)[:used]
	}
	for {
		_, e := linux.sendmsg(linux.Fd(s.fd), &hdr, {.NOSIGNAL, .DONTWAIT})
		if e == .EINTR {
			continue
		}
		return map_errno(e)
	}
}

// ---- TCP ----

// Start a non-blocking TCP connection. `in_progress` true: add the socket to
// the event loop for `.Write`; when it fires call `tcp_connect_finish`. False:
// already connected (loopback can do this). On error the socket is closed and
// `s` is `INVALID_SOCKET`.
tcp_connect :: proc(ep: Endpoint, opts: TCP_Options = {}) -> (s: Socket, in_progress: bool, err: Error) {
	family := family_of(ep)
	af: linux.Address_Family = .INET if family == .V4 else .INET6
	fd, e := linux.socket(af, .STREAM, {.NONBLOCK, .CLOEXEC}, .TCP)
	if e != .NONE {
		return INVALID_SOCKET, false, map_errno(e)
	}
	sock := Socket {
		fd     = i32(fd),
		family = family,
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
	if opts.keepalive {
		tcp_set_keepalive(s)
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
	ce := sys_connect(s.fd, &sa, size)
	#partial switch ce {
	case .NONE:
		return false, .None
	case .EINPROGRESS:
		return true, .None
	}
	return false, map_errno(ce)
}

// Call after the socket became writable. `.None`: connected. `.Would_Block`:
// not yet, wait again. Other: why the connect failed (close the socket).
tcp_connect_finish :: proc(s: Socket) -> Error {
	v, e := get_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.ERROR))
	if e != .NONE {
		return map_errno(e)
	}
	if v != 0 {
		return map_errno(linux.Errno(v))
	}
	sa: linux.Sock_Addr_Any
	if pe := linux.getpeername(linux.Fd(s.fd), &sa); pe != .NONE {
		if pe == .ENOTCONN {
			return .Would_Block
		}
		return map_errno(pe)
	}
	return .None
}

// A listening TCP socket (for a server, and for tests).
tcp_listen :: proc(ep: Endpoint, backlog: i32 = 128, v6_mode := V6_Mode.Dual_Stack, device := "") -> (s: Socket, err: Error) {
	family := family_of(ep)
	af: linux.Address_Family = .INET if family == .V4 else .INET6
	fd, e := linux.socket(af, .STREAM, {.NONBLOCK, .CLOEXEC}, .TCP)
	if e != .NONE {
		return INVALID_SOCKET, map_errno(e)
	}
	sock := Socket {
		fd     = i32(fd),
		family = family,
	}
	if serr := tcp_listen_setup(sock, ep, backlog, v6_mode, device); serr != .None {
		close(sock)
		return INVALID_SOCKET, serr
	}
	return sock, .None
}

@(private)
tcp_listen_setup :: proc(s: Socket, ep: Endpoint, backlog: i32, v6_mode: V6_Mode, device: string) -> Error {
	if s.family == .V6 {
		apply_v6_mode(s.fd, v6_mode) or_return
	}
	if oe := set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.REUSEADDR), 1); oe != .NONE {
		return map_errno(oe)
	}
	if device != "" {
		bind_device(s, device) or_return
	}
	bind(s, ep) or_return
	if le := linux.listen(linux.Fd(s.fd), backlog); le != .NONE {
		return map_errno(le)
	}
	return .None
}

// Limits the bytes the kernel holds unsent in a TCP socket: `send` and `epoll`
// call the socket full above `NOTSENT_LOWAT` bytes. The kernel queue stays
// short, a slow path shows itself to the sender, and the inner TCP of a tunnel
// sees loss. A kernel that refuses it is not an error.
// Set on `tls` link sockets (at connect, or after the server tells TLS from
// raw). The raw TCP transport and sockets to the DCO service keep the kernel
// default.
// Limits a socket to one network device (SO_BINDTODEVICE): it takes only
// packets that arrive on `device` and sends only through it. Connections
// that a listener accepts have the same limit. Call it before `bind`. Since
// Linux 5.7 a process with no capability can set it once for a socket; an
// older kernel needs CAP_NET_RAW.
bind_device :: proc "contextless" (s: Socket, device: string) -> Error {
	name: [16]u8 // IFNAMSIZ, with the 0 at the end
	if len(device) == 0 || len(device) >= len(name) {
		return .Invalid
	}
	copy(name[:], device)
	if e := linux.setsockopt_base(linux.Fd(s.fd), SOL_SOCKET, int(linux.Socket_Option.BINDTODEVICE), &name); e != .NONE {
		return map_errno(e)
	}
	return .None
}

tcp_set_notsent_lowat :: proc "contextless" (s: Socket) {
	set_int_opt(s.fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, NOTSENT_LOWAT)
}

// Switches on TCP keepalive probes with the `KEEPALIVE_*` timing. The probe
// timing is best effort: a system that refuses it keeps its own timing.
tcp_set_keepalive :: proc "contextless" (s: Socket) {
	set_int_opt(s.fd, SOL_SOCKET, int(linux.Socket_Option.KEEPALIVE), 1)
	set_int_opt(s.fd, IPPROTO_TCP, TCP_KEEPIDLE, KEEPALIVE_IDLE)
	set_int_opt(s.fd, IPPROTO_TCP, TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
	set_int_opt(s.fd, IPPROTO_TCP, TCP_KEEPCNT, KEEPALIVE_PROBES)
}

// Accept one connection. The new socket is non-blocking, with TCP_NODELAY
// (unless `opts.nagle`), TCP_NOTSENT_LOWAT (if `opts.notsent_lowat`) and
// keepalive (if `opts.keepalive`). Other `opts` fields do not apply.
tcp_accept :: proc(listener: Socket, opts: TCP_Options = {}) -> (s: Socket, from: Endpoint, err: Error) {
	sa: linux.Sock_Addr_Any
	for {
		fd, e := linux.accept(linux.Fd(listener.fd), &sa, {.NONBLOCK, .CLOEXEC})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return INVALID_SOCKET, {}, map_errno(e)
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
		if opts.keepalive {
			tcp_set_keepalive(s)
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
		got, e := linux.recv(linux.Fd(s.fd), buf, {.DONTWAIT})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return 0, map_errno(e)
		}
		if got == 0 {
			return 0, .Closed
		}
		return got, .None
	}
}

// Look at the next bytes of a stream socket without taking them out: the next
// read gets them again. Returns what is there, up to `len(buf)` (maybe less,
// or `.Would_Block` if nothing yet). `.Closed`: peer closed, no bytes left.
stream_peek :: proc(s: Socket, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	for {
		got, e := linux.recv(linux.Fd(s.fd), buf, {.DONTWAIT, .PEEK})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return 0, map_errno(e)
		}
		if got == 0 {
			return 0, .Closed
		}
		return got, .None
	}
}

// Write to a stream socket without raising SIGPIPE. May write less than asked.
stream_send :: proc(s: Socket, data: []u8) -> (n: int, err: Error) {
	if len(data) == 0 {
		return 0, .None
	}
	for {
		got, e := linux.send(linux.Fd(s.fd), data, {.NOSIGNAL, .DONTWAIT})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return 0, map_errno(e)
		}
		return got, .None
	}
}

// Close our sending side after the queued data (a clean end of stream).
shutdown_write :: proc(s: Socket) -> Error {
	return map_errno(linux.shutdown(linux.Fd(s.fd), .WR))
}
