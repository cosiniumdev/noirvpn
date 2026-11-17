// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package netlink

import "base:intrinsics"
import "core:mem"

// Writes netlink messages into a caller-owned buffer. The first failure (full
// buffer, attribute too long) is kept and later calls do nothing. So a caller
// writes a whole message and checks once in `finish`.
//
//	buf: [256]u8
//	b: Builder
//	builder_init(&b, buf[:])
//	msg_begin(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq)
//	put_struct(&b, Ifinfomsg{index = 3})
//	put_u32(&b, IFLA_MTU, 1400)
//	out, err := finish(&b)
Builder :: struct {
	buf: []u8,
	n:   int, // bytes written
	msg: int, // offset of the open message header, or -1
	err: Error,
}

builder_init :: proc(b: ^Builder, buf: []u8) {
	b^ = {
		buf = buf,
		msg = -1,
	}
}

// Start a message: writes the 16-byte header. `msg_end` (or `finish`) fills
// in the length. A builder can hold several messages in a row. End one before
// starting the next.
msg_begin :: proc(b: ^Builder, type: u16, flags: u16, seq: u32, pid: u32 = 0) {
	if b.err != .None {
		return
	}
	if b.msg >= 0 {
		msg_end(b)
	}
	off := reserve(b, NLMSG_HDRLEN)
	if b.err != .None {
		return
	}
	b.msg = off
	hdr := Msg_Hdr{len = 0, type = type, flags = flags, seq = seq, pid = pid}
	store(b.buf[off:], hdr)
}

// Close the open message: sets its length field.
msg_end :: proc(b: ^Builder) {
	if b.err != .None || b.msg < 0 {
		return
	}
	set_u32(b.buf, b.msg, u32(b.n - b.msg))
	b.msg = -1
}

// End the open message and return everything written so far.
finish :: proc(b: ^Builder) -> (msg: []u8, err: Error) {
	msg_end(b)
	if b.err != .None {
		return nil, b.err
	}
	return b.buf[:b.n], .None
}

// Add a fixed header struct (ifinfomsg, ifaddrmsg, rtmsg, genlmsghdr ...)
// right after the message header, padded to 4 bytes. Natural struct layout,
// host byte order.
put_struct :: proc(b: ^Builder, v: $T) {
	if b.err != .None {
		return
	}
	size := align(size_of(T))
	off := reserve(b, size)
	if b.err != .None {
		return
	}
	mem.zero(raw_data(b.buf[off:]), size)
	store(b.buf[off:], v)
}

// Add an attribute with raw bytes.
put_attr :: proc(b: ^Builder, type: u16, data: []u8) {
	if b.err != .None {
		return
	}
	if len(data) > 0xffff - NLA_HDRLEN {
		b.err = .Oversize
		return
	}
	size := align(NLA_HDRLEN + len(data))
	off := reserve(b, size)
	if b.err != .None {
		return
	}
	mem.zero(raw_data(b.buf[off:]), size)
	set_u16(b.buf, off, u16(NLA_HDRLEN + len(data)))
	set_u16(b.buf, off + 2, type)
	copy(b.buf[off + NLA_HDRLEN:], data)
}

// An attribute with no payload (a flag).
put_flag :: proc(b: ^Builder, type: u16) {
	put_attr(b, type, nil)
}

put_u8 :: proc(b: ^Builder, type: u16, v: u8) {
	x := v
	put_attr(b, type, ([^]u8)(&x)[:1])
}

// u16, u32 and u64 attributes are in host byte order, like the kernel reads
// them. The `_be` forms are for the few attributes that are in network order.
put_u16 :: proc(b: ^Builder, type: u16, v: u16) {
	x := v
	put_attr(b, type, ([^]u8)(&x)[:2])
}

put_u32 :: proc(b: ^Builder, type: u16, v: u32) {
	x := v
	put_attr(b, type, ([^]u8)(&x)[:4])
}

put_u64 :: proc(b: ^Builder, type: u16, v: u64) {
	x := v
	put_attr(b, type, ([^]u8)(&x)[:8])
}

put_u16_be :: proc(b: ^Builder, type: u16, v: u16) {
	x := u16be(v)
	put_attr(b, type, ([^]u8)(&x)[:2])
}

put_u32_be :: proc(b: ^Builder, type: u16, v: u32) {
	x := u32be(v)
	put_attr(b, type, ([^]u8)(&x)[:4])
}

// A string attribute, with the terminating NUL the kernel expects.
put_str :: proc(b: ^Builder, type: u16, s: string) {
	if b.err != .None {
		return
	}
	if len(s) + 1 > 0xffff - NLA_HDRLEN {
		b.err = .Oversize
		return
	}
	size := align(NLA_HDRLEN + len(s) + 1)
	off := reserve(b, size)
	if b.err != .None {
		return
	}
	mem.zero(raw_data(b.buf[off:]), size)
	set_u16(b.buf, off, u16(NLA_HDRLEN + len(s) + 1))
	set_u16(b.buf, off + 2, type)
	copy(b.buf[off + NLA_HDRLEN:], s)
}

// Start a nested attribute (sets NLA_F_NESTED). Returns a mark for
// `nest_end`. Nests may contain nests.
nest_begin :: proc(b: ^Builder, type: u16) -> (mark: int) {
	if b.err != .None {
		return -1
	}
	off := reserve(b, NLA_HDRLEN)
	if b.err != .None {
		return -1
	}
	set_u16(b.buf, off, 0)
	set_u16(b.buf, off + 2, type | NLA_F_NESTED)
	return off
}

nest_end :: proc(b: ^Builder, mark: int) {
	if b.err != .None || mark < 0 {
		return
	}
	size := b.n - mark
	if size > 0xffff {
		b.err = .Oversize
		return
	}
	set_u16(b.buf, mark, u16(size))
}

// Claims `size` bytes at the end. Sets the error and returns 0 when full.
@(private)
reserve :: proc(b: ^Builder, size: int) -> int {
	if b.n + size > len(b.buf) {
		b.err = .Buffer_Too_Small
		return 0
	}
	off := b.n
	b.n += size
	return off
}

@(private)
store :: #force_inline proc(dst: []u8, v: $T) {
	intrinsics.unaligned_store((^T)(raw_data(dst)), v)
}

@(private)
set_u16 :: #force_inline proc(buf: []u8, off: int, v: u16) {
	intrinsics.unaligned_store((^u16)(raw_data(buf[off:])), v)
}

@(private)
set_u32 :: #force_inline proc(buf: []u8, off: int, v: u32) {
	intrinsics.unaligned_store((^u32)(raw_data(buf[off:])), v)
}
