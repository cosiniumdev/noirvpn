// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package netlink: a small allocation-free netlink toolkit. It has a message
// builder, a message and attribute parser, and (on Linux) a socket with
// request/reply helpers. No libnl, no other noirvpn packages.
//
// Sources: netlink(7), rtnetlink(7), <linux/genetlink.h>, <linux/netlink.h>,
// <linux/rtnetlink.h>.
//
// Layout of the package:
//
//   builder.odin       write messages into a caller-owned buffer
//   parser.odin        walk messages and attributes in a received buffer
//   rtnl.odin          rtnetlink numbers and fixed headers (links, addresses, routes)
//   genl.odin          generic netlink: family lookup (the Linux DCO backend uses it)
//   socket_linux.odin  socket, request/reply, dump
//
// The builder and parser are pure byte work and build on every OS.
package netlink

// Netlink protocols (socket(2) third argument).
NETLINK_ROUTE   :: 0
NETLINK_GENERIC :: 16

// nlmsghdr.flags
NLM_F_REQUEST      :: 0x0001
NLM_F_MULTI        :: 0x0002
NLM_F_ACK          :: 0x0004
NLM_F_ECHO         :: 0x0008
NLM_F_DUMP_INTR    :: 0x0010
NLM_F_DUMP_FILTERED :: 0x0020

// Modifiers for GET requests.
NLM_F_ROOT   :: 0x0100
NLM_F_MATCH  :: 0x0200
NLM_F_ATOMIC :: 0x0400
NLM_F_DUMP   :: NLM_F_ROOT | NLM_F_MATCH

// Modifiers for NEW requests.
NLM_F_REPLACE :: 0x0100
NLM_F_EXCL    :: 0x0200
NLM_F_CREATE  :: 0x0400
NLM_F_APPEND  :: 0x0800

// Flags on an NLMSG_ERROR reply.
NLM_F_CAPPED   :: 0x0100
NLM_F_ACK_TLVS :: 0x0200

// Control message types (below NLMSG_MIN_TYPE).
NLMSG_NOOP     :: 0x1
NLMSG_ERROR    :: 0x2
NLMSG_DONE     :: 0x3
NLMSG_OVERRUN  :: 0x4
NLMSG_MIN_TYPE :: 0x10

// Attribute type bits.
NLA_F_NESTED        :: 1 << 15
NLA_F_NET_BYTEORDER :: 1 << 14
NLA_TYPE_MASK       :: ~u16(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

// Extended ACK attributes (the kernel's error text).
NLMSGERR_ATTR_MSG :: 1

// Everything is aligned to 4 bytes.
ALIGNTO :: 4

NLMSG_HDRLEN :: 16
NLA_HDRLEN   :: 4

// The 16-byte header in front of every message. Fields are in host byte order.
Msg_Hdr :: struct {
	len:   u32, // header plus payload, without the padding after it
	type:  u16,
	flags: u16,
	seq:   u32,
	pid:   u32, // sender port id; 0 when the kernel sent it
}
#assert(size_of(Msg_Hdr) == NLMSG_HDRLEN)

// Payload of an NLMSG_ERROR message: an errno (negative) and the header of the
// request it replies to. Error 0 is an ACK.
Err_Msg :: struct {
	error: i32,
	msg:   Msg_Hdr,
}

Error :: enum {
	None,
	// The builder's buffer is full, or the receive buffer is smaller than the
	// message the kernel sent.
	Buffer_Too_Small,
	// An attribute is longer than 65531 bytes.
	Oversize,
	// A length field points past the data, or is shorter than its header.
	Truncated,
	// An NLMSG_OVERRUN reply, or a reply of a type the caller did not expect.
	Unexpected,
	// The kernel returned an error. The errno is in `Socket.errno`.
	Kernel,
	// A system call failed. The errno is in `Socket.errno`.
	Io,
	// No reply within the receive timeout.
	Timeout,
	// A dump ended with NLM_F_DUMP_INTR: the data changed while it was being
	// read. Ask again.
	Dump_Interrupted,
}

// Rounds up to a multiple of 4.
align :: #force_inline proc "contextless" (n: int) -> int {
	return (n + ALIGNTO - 1) &~ (ALIGNTO - 1)
}
