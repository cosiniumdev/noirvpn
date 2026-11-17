// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package noirnet (directory platform/net) is the socket layer: UDP and TCP
// sockets, batched UDP, TCP length framing, host name lookup. It uses raw
// system calls (core:sys/linux) and builds static.
//
// Sources: socket(7), udp(7), tcp(7), ip(7), ipv6(7), recvmmsg(2), connect(2).
//
// Rules:
//   - Sockets are non-blocking. Errors are a small enum; `.Would_Block` means
//     "try again when the event loop says ready".
//   - Hot-path calls (`recv_batch`, `send_batch`, `tcp_recv`, `tcp_flush`) do
//     not allocate. Buffers belong to the caller.
//   - IPv6 sockets are dual stack by default: an IPv4 `Endpoint` is mapped to
//     `::ffff:a.b.c.d` on send; mapped sources show as IPv4 again. `.V6_Only`
//     turns that off.
//
// OS-specific names are in *_linux.odin, *_windows.odin and *_darwin.odin,
// with the same names. macOS has one system call per datagram and no UDP
//
// Import name: the directory is `net`, so `import "noir:platform/net"` gives
// the name `net`. The package is declared `noirnet` because Odin allows no two
// packages named `net` in one program, and core:net is one. A file that also
// imports core:net must alias one of them:
//
//	import "core:net"
//	import noirnet "noir:platform/net"
package noirnet

import cnet "core:net"

// Addresses and endpoints are core:net's types, so the config parser, the
// client and this package share one representation.
Address :: cnet.Address
IP4_Address :: cnet.IP4_Address
IP6_Address :: cnet.IP6_Address
Endpoint :: cnet.Endpoint

Family :: enum {
	V4,
	V6,
}

// What an IPv6 socket does with IPv4 traffic (IPV6_V6ONLY).
V6_Mode :: enum {
	// Accept and send IPv4 too, through mapped addresses. The usual choice for
	// a server bound to `::`. The default.
	Dual_Stack,
	// IPv6 only.
	V6_Only,
	// Whatever the net.ipv6.bindv6only sysctl says.
	System_Default,
}

// A socket handle. `family` is the address family of the socket; endpoint
// conversion needs it.
//
// `gso` and `gro` show which UDP offloads `udp_open` switched on
// (`opts.offload`). With `gro`, the kernel may hand over several datagrams in
// one `recvmmsg` message. Read such a socket only with `recv_batch`, which
// splits them (`recv` and `recv_from` return the coalesced block as one
// datagram).
Socket :: struct {
	fd:      i32,
	family:  Family,
	gso:     bool, // sends may use UDP_SEGMENT (one syscall entry, many datagrams)
	gro:     bool, // UDP_GRO is on: reads may return coalesced datagrams
	pktinfo: bool, // reads report the local address of each datagram (`batch_local`)
}

// The local side of a datagram: the address it was sent to (receive) or is
// sent from (send), and the interface. `len` is 4 (IPv4, in `addr[0:4]`), 16
// (IPv6) or 0 (none). `ifindex` 0: any interface.
Local :: struct {
	len:     u8,
	addr:    [16]u8,
	ifindex: u32,
}

// The address of a local, if it has one.
local_address :: proc "contextless" (l: Local) -> (a: Address, ok: bool) {
	switch l.len {
	case 4:
		return IP4_Address{l.addr[0], l.addr[1], l.addr[2], l.addr[3]}, true
	case 16:
		return IP6_Address(transmute([8]u16be)l.addr), true
	}
	return nil, false
}

// A local with the address `a` and no interface.
local_of_address :: proc "contextless" (a: Address) -> (l: Local) {
	switch v in a {
	case IP4_Address:
		l.len = 4
		l.addr[0], l.addr[1], l.addr[2], l.addr[3] = v[0], v[1], v[2], v[3]
	case IP6_Address:
		l.len = 16
		l.addr = transmute([16]u8)v
	}
	return
}

INVALID_SOCKET :: Socket{fd = -1}

is_valid :: proc "contextless" (s: Socket) -> bool {
	return s.fd >= 0
}

Error :: enum {
	None,
	// Nothing to do now: retry when the event loop reports the socket ready.
	// From `tcp_connect_finish`: the connection is still being set up.
	Would_Block,
	// A signal interrupted the call. Retrying is safe.
	Interrupted,
	// The peer closed the connection (a read of 0 bytes, or EPIPE).
	Closed,
	Connection_Refused,
	Connection_Reset,
	Timed_Out,
	Host_Unreachable,
	Network_Unreachable,
	Network_Down,
	Not_Connected,
	Address_In_Use,
	Address_Not_Available,
	Message_Too_Long,
	No_Buffers,
	Too_Many_Files,
	Permission,
	// A bad argument: wrong address family for the socket, a bad descriptor.
	Invalid,
	// The system does not support this (IPv6 disabled, option not known).
	Unsupported,
	// A TCP stream broke the framing rules (zero or oversize length). Close it.
	Bad_Frame,
	// The caller's buffer cannot hold the data.
	Buffer_Too_Small,
	// The TCP receive buffer holds whole packets that were not taken yet.
	// Call `tcp_next` until it has none, then read again.
	Buffer_Full,
	// A name did not resolve.
	Resolve_Failed,
	// A system error with no case above.
	Other,
}

UDP_Options :: struct {
	// Socket buffer sizes in bytes. 0 keeps the system default. The kernel caps
	// the value at net.core.rmem_max / wmem_max unless the process has
	// CAP_NET_ADMIN (tried first).
	recv_buffer: int,
	send_buffer: int,
	// SO_REUSEPORT: several sockets on one port, one per worker thread.
	reuse_port:  bool,
	// SO_REUSEADDR.
	reuse_addr:  bool,
	// Only for IPv6 sockets.
	v6_mode:     V6_Mode,
	// Try UDP GSO (send) and UDP GRO (receive). `Socket.gso` and `Socket.gro`
	// show what the kernel accepts. A kernel without them is not an error.
	offload:     bool,
	// Ask the kernel for the local address of each datagram (IP_PKTINFO on IPv4,
	// IPV6_RECVPKTINFO on IPv6), for a server that replies from the address the
	// client used. A client socket leaves it off. `Socket.pktinfo` shows if it
	// worked.
	pktinfo:     bool,
}

// The most unsent bytes a TCP socket may hold in the kernel (TCP_NOTSENT_LOWAT).
NOTSENT_LOWAT :: 128 * 1024

TCP_Options :: struct {
	// Leave Nagle's algorithm on. Off by default (TCP_NODELAY is set): tunnel
	// packets must not wait for more data.
	nagle:            bool,
	// Set TCP_NOTSENT_LOWAT (`NOTSENT_LOWAT` bytes): the kernel keeps a short
	// send queue. Off by default; the outer TLS stream of a `tls` link sets it.
	notsent_lowat:    bool,
	// Bind to this local address (and port) before connecting.
	local:            Maybe(Endpoint),
	recv_buffer:      int,
	send_buffer:      int,
	v6_mode:          V6_Mode,
}

// Which address families `resolve` may return.
Resolve_Pref :: enum {
	Any, // IPv4 first, then IPv6
	V4_Only,
	V6_Only,
}

// The family of an endpoint's address.
family_of :: proc "contextless" (ep: Endpoint) -> Family {
	_, is_v6 := ep.address.(IP6_Address)
	return .V6 if is_v6 else .V4
}
