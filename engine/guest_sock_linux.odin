// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import cnet "core:net"
import "core:sys/linux"
import net "noir:platform/net"

// TCP connection of the engine. A guest with `protect` (Android) must call
// `protect` before the connect, so the socket is created here. The daemon and a
// guest without `protect` use `net.tcp_connect`.
engine_tcp_connect :: proc(d: ^Daemon, ep: cnet.Endpoint, opts: net.TCP_Options) -> (s: net.Socket, in_progress: bool, err: net.Error) {
	if d.guest == nil || d.guest.h.protect == nil {
		return net.tcp_connect(ep, opts)
	}
	_, v6 := ep.address.(cnet.IP6_Address)
	af: linux.Address_Family = .INET6 if v6 else .INET
	fd, e := linux.socket(af, .STREAM, {.NONBLOCK, .CLOEXEC}, .TCP)
	if e != .NONE {
		return net.INVALID_SOCKET, false, .Invalid
	}
	one: i32 = 1
	_ = linux.setsockopt_tcp(fd, .TCP, .NODELAY, &one)
	if !guest_protect(d, i32(fd)) {
		linux.close(fd)
		return net.INVALID_SOCKET, false, .Invalid
	}
	sock := net.Socket {
		fd     = i32(fd),
		family = .V6 if v6 else .V4,
	}
	if local, has := opts.local.?; has {
		if berr := net.bind(sock, local); berr != .None {
			net.close(sock)
			return net.INVALID_SOCKET, false, berr
		}
	}
	if v6 {
		sa := linux.Sock_Addr_In6 {
			sin6_family = .INET6,
			sin6_port   = u16be(ep.port),
			sin6_addr   = transmute([16]u8)ep.address.(cnet.IP6_Address),
		}
		e = linux.connect(fd, &sa)
	} else {
		sa := linux.Sock_Addr_In {
			sin_family = .INET,
			sin_port   = u16be(ep.port),
			sin_addr   = cast([4]u8)ep.address.(cnet.IP4_Address),
		}
		e = linux.connect(fd, &sa)
	}
	if e == .EINPROGRESS {
		return sock, true, .None
	}
	if e != .NONE {
		net.close(sock)
		return net.INVALID_SOCKET, false, .Connection_Refused if e == .ECONNREFUSED else .Invalid
	}
	return sock, false, .None
}
