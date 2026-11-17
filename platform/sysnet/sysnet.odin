// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package sysnet applies network settings to the OS: link state and MTU,
// addresses, routes, DNS.
//   Linux    rtnetlink through noir:platform/netlink (no libnl, no `ip`)
//   Windows  IP Helper API (sysnet_windows.odin, dns_windows.odin)
//   macOS    starts ifconfig(8), route(8), scutil(8) and reads their output
//            (sysnet_darwin.odin, sysnet_darwin_parse.odin, dns_darwin.odin)
// The names are the same on all three.
//
// Sources: rtnetlink(7), netlink(7), <linux/rtnetlink.h>, <linux/if_addr.h>,
// <linux/if_link.h>.
//
// A `Conn` is one netlink socket. Not thread safe. It acts on the network
// namespace the process was in when the Conn was opened.
//
// The usual client sequence after the tunnel is up:
//
//	c, _ := sysnet.open()
//	link, _ := sysnet.link_get(&c, tun.name(&dev))
//	sysnet.link_set_mtu(&c, link.index, 1400)
//	sysnet.addr_add(&c, link.index, ip, 24)
//	sysnet.link_set_up(&c, link.index)
//	sysnet.route_add(&c, {dst = net, dst_len = 24, gateway = gw, ifindex = link.index})
//
// For `redirect-gateway`: `route_lookup` the server's address first, add a
// host route for it through that gateway, then add the two half-default
// routes (or replace the default route).
package sysnet

import cnet "core:net"

Address :: cnet.Address
IP4_Address :: cnet.IP4_Address
IP6_Address :: cnet.IP6_Address

Family :: enum {
	V4,
	V6,
}

Error :: enum {
	None,
	// The address or route is already there (EEXIST).
	Exists,
	// No such link, address or route (ENODEV, ENOENT, ESRCH, EADDRNOTAVAIL).
	Not_Found,
	// Needs CAP_NET_ADMIN.
	Permission,
	// The kernel does not support it (EOPNOTSUPP, EAFNOSUPPORT, IPv6 disabled).
	Unsupported,
	// A bad argument: prefix too long, mixed IPv4 and IPv6, EINVAL.
	Invalid,
	// The gateway cannot be reached (ENETUNREACH): add the route on-link, or
	// add the address first.
	Network_Unreachable,
	No_Buffer,
	Busy,
	// No reply from the kernel in time.
	Timeout,
	// The netlink socket failed.
	Io,
	// The kernel's reply was not understood, or did not fit the buffer.
	Protocol,
	// A kernel error with no case above. See `Conn.nl.errno`.
	Other,
}

// Link flags (IFF_*), as bit numbers in a bit set.
Link_Flag :: enum u32 {
	Up             = 0,
	Broadcast      = 1,
	Loopback       = 3,
	Point_To_Point = 4,
	Running        = 6,
	No_ARP         = 7,
	Multicast      = 12,
	Lower_Up       = 16,
}
Link_Flags :: bit_set[Link_Flag; u32]

// Longest link name in bytes, including a terminating NUL. Windows names
// (interface aliases) are longer; a longer one is cut.
when ODIN_OS == .Windows {
	IFNAMSIZ :: 128
} else {
	IFNAMSIZ :: 16
}

Link_Info :: struct {
	index:    u32,
	// The NET_LUID of the interface (Windows only).
	luid:     u64,
	name_buf: [IFNAMSIZ]u8,
	name_len: int,
	mtu:      u32,
	flags:    Link_Flags,
	// The link kind ("tun", "veth", "ovpn" ...), empty for a plain device.
	kind_buf: [IFNAMSIZ]u8,
	kind_len: int,
}

link_name :: proc "contextless" (l: ^Link_Info) -> string {
	return string(l.name_buf[:l.name_len])
}

link_kind :: proc "contextless" (l: ^Link_Info) -> string {
	return string(l.kind_buf[:l.kind_len])
}

// An address on a link.
Addr_Info :: struct {
	index:      u32,
	address:    Address, // the local address
	peer:       Maybe(Address), // set on a point-to-point address
	prefix_len: u8,
	flags:      u32, // IFA_F_*
	scope:      u8,
}

Addr_Options :: struct {
	// Set the address to point-to-point: `peer` is the other end. For
	// `topology p2p` the prefix is usually the full length (32 or 128).
	peer:            Maybe(Address),
	// Do not let the kernel add the connected route for the prefix
	// (IFA_F_NOPREFIXROUTE). The caller then adds routes itself.
	no_prefix_route: bool,
}

Route_Kind :: enum u8 {
	Unicast, // a normal route
	Blackhole, // drop silently
	Unreachable, // drop and reply with "host unreachable"
	Prohibit, // drop and reply with "administratively prohibited"
	Local, // the destination is this host (the kernel creates these itself)
	Other, // read back only: broadcast, multicast, anycast, throw, ...
}

// One route. Used to add, delete, and (filled by the kernel) to list.
Route :: struct {
	// The destination network. The address type (IPv4 or IPv6) sets the
	// family. `dst_len` 0 is a default route: `dst` may be nil or the zero
	// address, but a nil `dst` needs `family`.
	dst:      Address,
	family:   Family, // only read when `dst` is nil
	dst_len:  u8,
	// The next hop. Must be the same family as `dst`. Nil for a route
	// that is on-link through `ifindex`.
	gateway:  Maybe(Address),
	// Output interface. 0 lets the kernel pick from the gateway.
	ifindex:  u32,
	// Lower is preferred. Nil leaves it to the kernel's default.
	metric:   Maybe(u32),
	// Routing table. 0 is the main table (254).
	table:    u32,
	// Who added it (RTPROT_*). 0 means RTPROT_STATIC on add. Pick a private
	// number (for example 201) to find leftover routes after a crash.
	protocol: u8,
	// The gateway is on-link even if no connected route says so
	// (RTNH_F_ONLINK).
	onlink:   bool,
	kind:     Route_Kind,
	// Read back only:
	scope:    u8,
	prefsrc:  Maybe(Address), // preferred source address
}

// The IPv4 or IPv6 default route destination, for a `Route` literal.
default_dst :: proc "contextless" (family: Family) -> Address {
	return IP4_Address{} if family == .V4 else IP6_Address{}
}
