// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import win "core:sys/windows"

// Winsock version of net_linux.odin. Same names and rules (non-blocking
// sockets, `.Would_Block`, no allocation on the data path). `Socket.fd` holds
// the SOCKET value; Windows socket handles fit in 32 bits.
//
// Differences from Linux:
//   - No UDP GSO, GRO or packet info: `offload` and `pktinfo` leave the socket
//     flags false, and `send_to` with a `Local` is `.Unsupported`.
//   - No SO_REUSEPORT (`reuse_port` is `.Unsupported`). A TCP listener uses
//     SO_EXCLUSIVEADDRUSE, because SO_REUSEADDR on Windows lets another socket
//     take the port.
//   - No TCP_NOTSENT_LOWAT: `tcp_set_notsent_lowat` does nothing.
//   - SIO_UDP_CONNRESET is off: an ICMP "port unreachable" gives no error on
//     the next read of a UDP socket.
//   - Child processes do not inherit sockets.

@(private)
SIO_UDP_CONNRESET :: 0x9800000C

@(private)
WSAEDESTADDRREQ :: 10039

@(init, private)
winsock_init :: proc "contextless" () {
	win.ensure_winsock_initialized()
}

@(private)
sock :: proc "contextless" (s: Socket) -> win.SOCKET {
	return win.SOCKET(uintptr(u32(s.fd)))
}

@(private)
map_wsa :: proc "contextless" (e: i32) -> Error {
	switch e {
	case 0:
		return .None
	case win.WSAEWOULDBLOCK, win.WSAEINPROGRESS, win.WSAEALREADY:
		return .Would_Block
	case win.WSAEINTR:
		return .Interrupted
	case win.WSAESHUTDOWN:
		return .Closed
	case win.WSAECONNREFUSED:
		return .Connection_Refused
	case win.WSAECONNRESET, win.WSAECONNABORTED, win.WSAENETRESET:
		return .Connection_Reset
	case win.WSAETIMEDOUT:
		return .Timed_Out
	case win.WSAEHOSTUNREACH, win.WSAEHOSTDOWN:
		return .Host_Unreachable
	case win.WSAENETUNREACH:
		return .Network_Unreachable
	case win.WSAENETDOWN:
		return .Network_Down
	case win.WSAENOTCONN:
		return .Not_Connected
	case win.WSAEADDRINUSE:
		return .Address_In_Use
	case win.WSAEADDRNOTAVAIL:
		return .Address_Not_Available
	case win.WSAEMSGSIZE:
		return .Message_Too_Long
	case win.WSAENOBUFS, win.WSA_NOT_ENOUGH_MEMORY:
		return .No_Buffers
	case win.WSAEMFILE:
		return .Too_Many_Files
	case win.WSAEACCES:
		return .Permission
	case win.WSAEINVAL, win.WSAEFAULT, win.WSAENOTSOCK, win.WSAEISCONN, WSAEDESTADDRREQ, win.WSA_INVALID_HANDLE:
		return .Invalid
	case win.WSAEAFNOSUPPORT, win.WSAEPROTONOSUPPORT, win.WSAEOPNOTSUPP, win.WSAENOPROTOOPT, win.WSAEPROTOTYPE:
		return .Unsupported
	}
	return .Other
}

@(private)
last_error :: proc "contextless" () -> Error {
	return map_wsa(win.WSAGetLastError())
}

// ---- options ----

@(private)
set_int_opt :: proc "contextless" (s: Socket, level, opt: i32, v: i32) -> Error {
	val := v
	if win.setsockopt(sock(s), level, opt, &val, size_of(i32)) != 0 {
		return last_error()
	}
	return .None
}

@(private)
get_int_opt :: proc "contextless" (s: Socket, level, opt: i32) -> (v: i32, err: Error) {
	n := i32(size_of(i32))
	if win.getsockopt(sock(s), level, opt, ([^]u8)(&v), &n) != 0 {
		return 0, last_error()
	}
	return v, .None
}

// Set the socket buffer sizes (SO_RCVBUF, SO_SNDBUF). Returns what the system
// reports afterwards.
set_buffer_sizes :: proc(s: Socket, recv_size, send_size: int) -> (recv_actual, send_actual: int, err: Error) {
	if recv_size > 0 {
		set_int_opt(s, win.SOL_SOCKET, win.SO_RCVBUF, i32(min(recv_size, int(max(i32))))) or_return
	}
	if send_size > 0 {
		set_int_opt(s, win.SOL_SOCKET, win.SO_SNDBUF, i32(min(send_size, int(max(i32))))) or_return
	}
	r, _ := get_int_opt(s, win.SOL_SOCKET, win.SO_RCVBUF)
	w, _ := get_int_opt(s, win.SOL_SOCKET, win.SO_SNDBUF)
	return int(r), int(w), .None
}

@(private)
apply_v6_mode :: proc(s: Socket, mode: V6_Mode) -> Error {
	switch mode {
	case .Dual_Stack:
		return set_int_opt(s, win.IPPROTO_IPV6, win.IPV6_V6ONLY, 0)
	case .V6_Only:
		return set_int_opt(s, win.IPPROTO_IPV6, win.IPV6_V6ONLY, 1)
	case .System_Default:
	}
	return .None
}

// ---- addresses ----

// Fills a socket address for `ep` as seen through a socket of `family`. A v4
// endpoint on a v6 socket becomes a mapped address. False if `ep` is v6 and
// the socket is v4.
@(private)
to_sockaddr :: proc "contextless" (ep: Endpoint, family: Family) -> (sa: win.SOCKADDR_STORAGE_LH, size: i32, ok: bool) {
	switch a in ep.address {
	case IP4_Address:
		switch family {
		case .V4:
			sin := (^win.sockaddr_in)(&sa)
			sin.sin_family = u16(win.AF_INET)
			sin.sin_port = u16be(ep.port)
			sin.sin_addr = transmute(win.in_addr)a
			return sa, size_of(win.sockaddr_in), true
		case .V6:
			sin6 := (^win.sockaddr_in6)(&sa)
			sin6.sin6_family = u16(win.AF_INET6)
			sin6.sin6_port = u16be(ep.port)
			sin6.sin6_addr.s6_addr[10] = 0xff
			sin6.sin6_addr.s6_addr[11] = 0xff
			sin6.sin6_addr.s6_addr[12] = a[0]
			sin6.sin6_addr.s6_addr[13] = a[1]
			sin6.sin6_addr.s6_addr[14] = a[2]
			sin6.sin6_addr.s6_addr[15] = a[3]
			return sa, size_of(win.sockaddr_in6), true
		}
	case IP6_Address:
		if family == .V4 {
			return {}, 0, false
		}
		sin6 := (^win.sockaddr_in6)(&sa)
		sin6.sin6_family = u16(win.AF_INET6)
		sin6.sin6_port = u16be(ep.port)
		sin6.sin6_addr.s6_addr = transmute([16]u8)a
		return sa, size_of(win.sockaddr_in6), true
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
from_sockaddr :: proc "contextless" (sa: ^win.SOCKADDR_STORAGE_LH) -> (ep: Endpoint, ok: bool) {
	switch i32(sa.ss_family) {
	case win.AF_INET:
		sin := (^win.sockaddr_in)(sa)
		return Endpoint{address = transmute(IP4_Address)sin.sin_addr, port = int(sin.sin_port)}, true
	case win.AF_INET6:
		sin6 := (^win.sockaddr_in6)(sa)
		b := sin6.sin6_addr.s6_addr
		if addr_is_mapped(b) {
			return Endpoint{address = IP4_Address{b[12], b[13], b[14], b[15]}, port = int(sin6.sin6_port)}, true
		}
		return Endpoint{address = IP6_Address(transmute([8]u16be)b), port = int(sin6.sin6_port)}, true
	}
	return {}, false
}

// ---- common socket calls ----

// A new non-blocking socket that child processes do not inherit.
@(private)
open_socket :: proc "contextless" (family: Family, kind, protocol: i32) -> (s: Socket, err: Error) {
	af := win.AF_INET if family == .V4 else win.AF_INET6
	h := win.WSASocketW(af, kind, protocol, nil, 0, win.WSA_FLAG_NO_HANDLE_INHERIT)
	if h == win.INVALID_SOCKET {
		return INVALID_SOCKET, last_error()
	}
	s = Socket {
		fd     = i32(u32(uintptr(h))),
		family = family,
	}
	on := u32(1)
	if win.ioctlsocket(h, transmute(i32)u32(win.FIONBIO), &on) != 0 {
		err = last_error()
		win.closesocket(h)
		return INVALID_SOCKET, err
	}
	return s, .None
}

close :: proc "contextless" (s: Socket) {
	if s.fd >= 0 {
		win.closesocket(sock(s))
	}
}

// Bind to a local address. Use port 0 for any free port.
bind :: proc(s: Socket, ep: Endpoint) -> Error {
	sa, size, ok := to_sockaddr(ep, s.family)
	if !ok {
		return .Invalid
	}
	if win.bind(sock(s), &sa, size) != 0 {
		return last_error()
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
	if win.connect(sock(s), &sa, size) != 0 {
		return last_error()
	}
	return .None
}

// The local address the socket is bound to (after `bind` with port 0, this
// shows the port the system chose).
local_endpoint :: proc(s: Socket) -> (ep: Endpoint, err: Error) {
	sa: win.SOCKADDR_STORAGE_LH
	n := i32(size_of(sa))
	if win.getsockname(sock(s), &sa, &n) != 0 {
		return {}, last_error()
	}
	ok: bool
	ep, ok = from_sockaddr(&sa)
	return ep, .None if ok else .Unsupported
}

peer_endpoint :: proc(s: Socket) -> (ep: Endpoint, err: Error) {
	sa: win.SOCKADDR_STORAGE_LH
	n := i32(size_of(sa))
	if win.getpeername(sock(s), &sa, &n) != 0 {
		return {}, last_error()
	}
	ok: bool
	ep, ok = from_sockaddr(&sa)
	return ep, .None if ok else .Unsupported
}

// ---- UDP ----

// Create a non-blocking UDP socket. It is not bound yet.
udp_open :: proc(family: Family, opts: UDP_Options = {}) -> (s: Socket, err: Error) {
	s = open_socket(family, win.SOCK_DGRAM, win.IPPROTO_UDP) or_return
	if serr := udp_setup(s, opts); serr != .None {
		close(s)
		return INVALID_SOCKET, serr
	}
	return s, .None
}

@(private)
udp_setup :: proc(s: Socket, opts: UDP_Options) -> Error {
	if s.family == .V6 {
		apply_v6_mode(s, opts.v6_mode) or_return
	}
	if opts.reuse_port {
		return .Unsupported
	}
	if opts.reuse_addr {
		set_int_opt(s, win.SOL_SOCKET, win.SO_REUSEADDR, 1) or_return
	}
	off := u32(0)
	ret: u32
	win.WSAIoctl(sock(s), SIO_UDP_CONNRESET, &off, size_of(off), nil, 0, &ret, nil, nil)
	if opts.recv_buffer > 0 || opts.send_buffer > 0 {
		_, _ = set_buffer_sizes(s, opts.recv_buffer, opts.send_buffer) or_return
	}
	return .None
}

// Windows has no UDP GSO or GRO here: the socket is returned with both off.
udp_offload_enable :: proc(s: Socket) -> Socket {
	r := s
	r.gso, r.gro = false, false
	return r
}

// No packet info on Windows: the socket is returned with `pktinfo` false.
udp_pktinfo_enable :: proc(s: Socket) -> Socket {
	r := s
	r.pktinfo = false
	return r
}

udp_gro_disable :: proc(s: Socket) -> Socket {
	r := s
	r.gro = false
	return r
}

// Receive one datagram from a connected socket. A datagram longer than `buf`
// is cut, as on Linux.
recv :: proc(s: Socket, buf: []u8) -> (n: int, err: Error) {
	got := win.recv(sock(s), raw_data(buf), i32(len(buf)), 0)
	if got < 0 {
		e := win.WSAGetLastError()
		if e == win.WSAEMSGSIZE {
			return len(buf), .None
		}
		return 0, map_wsa(e)
	}
	return int(got), .None
}

// Receive one datagram and its source address.
recv_from :: proc(s: Socket, buf: []u8) -> (n: int, from: Endpoint, err: Error) {
	sa: win.SOCKADDR_STORAGE_LH
	size := i32(size_of(sa))
	got := win.recvfrom(sock(s), raw_data(buf), i32(len(buf)), 0, &sa, &size)
	if got < 0 {
		e := win.WSAGetLastError()
		if e != win.WSAEMSGSIZE {
			return 0, {}, map_wsa(e)
		}
		got = i32(len(buf))
	}
	ep, ok := from_sockaddr(&sa)
	if !ok {
		return int(got), {}, .Unsupported
	}
	return int(got), ep, .None
}

// Send one datagram on a connected socket.
send :: proc(s: Socket, data: []u8) -> Error {
	if win.send(sock(s), raw_data(data), i32(len(data)), 0) < 0 {
		return last_error()
	}
	return .None
}

// Send one datagram to an address. A `local` is `.Unsupported` on Windows.
send_to :: proc(s: Socket, data: []u8, to: Endpoint, local := Local{}) -> Error {
	if local.len > 0 {
		return .Unsupported
	}
	sa, size, ok := to_sockaddr(to, s.family)
	if !ok {
		return .Invalid
	}
	if win.sendto(sock(s), raw_data(data), i32(len(data)), 0, &sa, size) < 0 {
		return last_error()
	}
	return .None
}

// ---- TCP ----

// Start a non-blocking TCP connection. `in_progress` true: add the socket to
// the event loop for `.Write`; when it fires call `tcp_connect_finish`. On
// error the socket is closed and `s` is `INVALID_SOCKET`.
tcp_connect :: proc(ep: Endpoint, opts: TCP_Options = {}) -> (s: Socket, in_progress: bool, err: Error) {
	family := family_of(ep)
	s = open_socket(family, win.SOCK_STREAM, win.IPPROTO_TCP) or_return
	pending, serr := tcp_connect_setup(s, ep, opts)
	if serr != .None {
		close(s)
		return INVALID_SOCKET, false, serr
	}
	return s, pending, .None
}

@(private)
tcp_connect_setup :: proc(s: Socket, ep: Endpoint, opts: TCP_Options) -> (in_progress: bool, err: Error) {
	if s.family == .V6 {
		apply_v6_mode(s, opts.v6_mode) or_return
	}
	if !opts.nagle {
		set_int_opt(s, win.IPPROTO_TCP, win.TCP_NODELAY, 1) or_return
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
	if win.connect(sock(s), &sa, size) == 0 {
		return false, .None
	}
	e := win.WSAGetLastError()
	if e == win.WSAEWOULDBLOCK || e == win.WSAEINPROGRESS {
		return true, .None
	}
	return false, map_wsa(e)
}

// Call after the socket became writable (or reported an error). `.None`:
// connected. `.Would_Block`: not yet, wait again. Other: why the connect
// failed (close the socket).
tcp_connect_finish :: proc(s: Socket) -> Error {
	v := get_int_opt(s, win.SOL_SOCKET, win.SO_ERROR) or_return
	if v != 0 {
		return map_wsa(v)
	}
	sa: win.SOCKADDR_STORAGE_LH
	n := i32(size_of(sa))
	if win.getpeername(sock(s), &sa, &n) != 0 {
		e := win.WSAGetLastError()
		if e == win.WSAENOTCONN {
			return .Would_Block
		}
		return map_wsa(e)
	}
	return .None
}

// A listening TCP socket (for tests, and for a local service).
tcp_listen :: proc(ep: Endpoint, backlog: i32 = 128, v6_mode := V6_Mode.Dual_Stack) -> (s: Socket, err: Error) {
	s = open_socket(family_of(ep), win.SOCK_STREAM, win.IPPROTO_TCP) or_return
	if serr := tcp_listen_setup(s, ep, backlog, v6_mode); serr != .None {
		close(s)
		return INVALID_SOCKET, serr
	}
	return s, .None
}

@(private)
tcp_listen_setup :: proc(s: Socket, ep: Endpoint, backlog: i32, v6_mode: V6_Mode) -> Error {
	if s.family == .V6 {
		apply_v6_mode(s, v6_mode) or_return
	}
	set_int_opt(s, win.SOL_SOCKET, win.SO_EXCLUSIVEADDRUSE, 1) or_return
	bind(s, ep) or_return
	if win.listen(sock(s), backlog) != 0 {
		return last_error()
	}
	return .None
}

// Windows has no TCP_NOTSENT_LOWAT. The socket works as before.
tcp_set_notsent_lowat :: proc "contextless" (s: Socket) {
}

// Accept one connection. The new socket is non-blocking, with TCP_NODELAY
// (unless `opts.nagle`). The other fields of `opts` do not apply here.
tcp_accept :: proc(listener: Socket, opts: TCP_Options = {}) -> (s: Socket, from: Endpoint, err: Error) {
	sa: win.SOCKADDR_STORAGE_LH
	n := i32(size_of(sa))
	h := win.accept(sock(listener), &sa, &n)
	if h == win.INVALID_SOCKET {
		return INVALID_SOCKET, {}, last_error()
	}
	s = {
		fd     = i32(u32(uintptr(h))),
		family = listener.family,
	}
	// An accepted socket takes the listener's WSAEventSelect state; clear it,
	// so a loop can register the new socket on its own.
	win.WSAEventSelect(h, nil, 0)
	on := u32(1)
	win.ioctlsocket(h, transmute(i32)u32(win.FIONBIO), &on)
	if !opts.nagle {
		set_int_opt(s, win.IPPROTO_TCP, win.TCP_NODELAY, 1)
	}
	from, _ = from_sockaddr(&sa)
	return s, from, .None
}

// Read from a stream socket. `.Closed` when the peer closed its side. It needs
// no Odin context, so a C callback (the BIO of `platform/tlslink`) may call it.
stream_recv :: proc "contextless" (s: Socket, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	got := win.recv(sock(s), raw_data(buf), i32(min(len(buf), int(max(i32)))), 0)
	if got < 0 {
		return 0, last_error()
	}
	if got == 0 {
		return 0, .Closed
	}
	return int(got), .None
}

// Look at the next bytes of a stream socket without taking them out.
// `.Closed` when the peer closed its side and no bytes are left.
stream_peek :: proc(s: Socket, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	got := win.recv(sock(s), raw_data(buf), i32(min(len(buf), int(max(i32)))), win.MSG_PEEK)
	if got < 0 {
		return 0, last_error()
	}
	if got == 0 {
		return 0, .Closed
	}
	return int(got), .None
}

// Write to a stream socket. May write less than asked.
stream_send :: proc(s: Socket, data: []u8) -> (n: int, err: Error) {
	if len(data) == 0 {
		return 0, .None
	}
	got := win.send(sock(s), raw_data(data), i32(min(len(data), int(max(i32)))), 0)
	if got < 0 {
		return 0, last_error()
	}
	return int(got), .None
}

// Close our sending side after the queued data (a clean end of stream).
shutdown_write :: proc(s: Socket) -> Error {
	if win.shutdown(sock(s), win.SD_SEND) != 0 {
		return last_error()
	}
	return .None
}
