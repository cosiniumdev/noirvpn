// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package netlink

import "base:intrinsics"

// Walks the messages in one receive buffer. Payloads are slices into the
// buffer. Malformed data ends the walk and sets `err`.
//
//	it := msg_iter(buf[:n])
//	for msg in msg_next(&it) {
//		...
//	}
//	if it.err != .None { /* the buffer was cut or corrupt */ }
Msg :: struct {
	hdr:     Msg_Hdr,
	payload: []u8, // after the 16-byte header, without trailing padding
}

Msg_Iter :: struct {
	data: []u8,
	off:  int,
	err:  Error,
}

msg_iter :: proc "contextless" (data: []u8) -> Msg_Iter {
	return {data = data}
}

msg_next :: proc "contextless" (it: ^Msg_Iter) -> (msg: Msg, ok: bool) {
	if it.err != .None || it.off >= len(it.data) {
		return {}, false
	}
	rest := it.data[it.off:]
	if len(rest) < NLMSG_HDRLEN {
		it.err = .Truncated
		return {}, false
	}
	hdr := intrinsics.unaligned_load((^Msg_Hdr)(raw_data(rest)))
	if int(hdr.len) < NLMSG_HDRLEN || int(hdr.len) > len(rest) {
		it.err = .Truncated
		return {}, false
	}
	it.off += min(align(int(hdr.len)), len(rest))
	return {hdr = hdr, payload = rest[NLMSG_HDRLEN:hdr.len]}, true
}

// One attribute. `data` excludes the 4-byte header and the padding.
Attr :: struct {
	type:      u16, // with the flag bits removed
	nested:    bool, // NLA_F_NESTED was set
	net_order: bool, // NLA_F_NET_BYTEORDER was set
	data:      []u8,
}

Attr_Iter :: struct {
	data: []u8,
	off:  int,
	err:  Error,
}

attr_iter :: proc "contextless" (data: []u8) -> Attr_Iter {
	return {data = data}
}

attr_next :: proc "contextless" (it: ^Attr_Iter) -> (a: Attr, ok: bool) {
	if it.err != .None || it.off >= len(it.data) {
		return {}, false
	}
	rest := it.data[it.off:]
	if len(rest) < NLA_HDRLEN {
		it.err = .Truncated
		return {}, false
	}
	alen := int(intrinsics.unaligned_load((^u16)(raw_data(rest))))
	atype := intrinsics.unaligned_load((^u16)(raw_data(rest[2:])))
	if alen < NLA_HDRLEN || alen > len(rest) {
		it.err = .Truncated
		return {}, false
	}
	it.off += min(align(alen), len(rest))
	return {
			type = atype & NLA_TYPE_MASK,
			nested = atype & NLA_F_NESTED != 0,
			net_order = atype & NLA_F_NET_BYTEORDER != 0,
			data = rest[NLA_HDRLEN:alen],
		},
		true
}

// First attribute of the given type in `data`. Stops quietly at malformed
// data.
attr_find :: proc "contextless" (data: []u8, type: u16) -> (a: Attr, found: bool) {
	it := attr_iter(data)
	for x in attr_next(&it) {
		if x.type == type {
			return x, true
		}
	}
	return {}, false
}

// Split a fixed header struct off the front of a payload. `rest` starts after
// the padding.
read_struct :: proc "contextless" (payload: []u8, $T: typeid) -> (v: T, rest: []u8, ok: bool) {
	size := align(size_of(T))
	if len(payload) < size {
		return {}, nil, false
	}
	v = intrinsics.unaligned_load((^T)(raw_data(payload)))
	return v, payload[size:], true
}

// Attribute value readers. They fail on a wrong length. Integers are in host
// byte order unless the name says `_be`.
attr_u8 :: proc "contextless" (a: Attr) -> (v: u8, ok: bool) {
	if len(a.data) != 1 {
		return 0, false
	}
	return a.data[0], true
}

attr_u16 :: proc "contextless" (a: Attr) -> (v: u16, ok: bool) {
	if len(a.data) != 2 {
		return 0, false
	}
	return intrinsics.unaligned_load((^u16)(raw_data(a.data))), true
}

attr_u32 :: proc "contextless" (a: Attr) -> (v: u32, ok: bool) {
	if len(a.data) != 4 {
		return 0, false
	}
	return intrinsics.unaligned_load((^u32)(raw_data(a.data))), true
}

attr_u64 :: proc "contextless" (a: Attr) -> (v: u64, ok: bool) {
	if len(a.data) != 8 {
		return 0, false
	}
	return intrinsics.unaligned_load((^u64)(raw_data(a.data))), true
}

// An unsigned integer that the kernel wrote with `nla_put_uint`: 4 or 8 bytes
// (it picks the short form when the value fits). Also accepts 1 and 2 bytes.
attr_uint :: proc "contextless" (a: Attr) -> (v: u64, ok: bool) {
	switch len(a.data) {
	case 1:
		return u64(a.data[0]), true
	case 2:
		x, _ := attr_u16(a)
		return u64(x), true
	case 4:
		x, _ := attr_u32(a)
		return u64(x), true
	case 8:
		return attr_u64(a)
	}
	return 0, false
}

attr_u16_be :: proc "contextless" (a: Attr) -> (v: u16, ok: bool) {
	if len(a.data) != 2 {
		return 0, false
	}
	return u16(a.data[0]) << 8 | u16(a.data[1]), true
}

attr_u32_be :: proc "contextless" (a: Attr) -> (v: u32, ok: bool) {
	if len(a.data) != 4 {
		return 0, false
	}
	return u32(a.data[0]) << 24 | u32(a.data[1]) << 16 | u32(a.data[2]) << 8 | u32(a.data[3]), true
}

// The text up to the first NUL. The result points into the message.
attr_str :: proc "contextless" (a: Attr) -> string {
	n := 0
	for n < len(a.data) && a.data[n] != 0 {
		n += 1
	}
	return string(a.data[:n])
}

// Reads the errno and the original header from an NLMSG_ERROR payload.
// `errno` is positive (0 means ACK). `ext_msg` is the kernel error text if the
// socket asked for extended ACKs, else empty.
parse_error :: proc "contextless" (flags: u16, payload: []u8) -> (errno: i32, ext_msg: string, ok: bool) {
	if len(payload) < size_of(i32) + NLMSG_HDRLEN {
		return 0, "", false
	}
	e := intrinsics.unaligned_load((^Err_Msg)(raw_data(payload)))
	errno = -e.error
	if flags & NLM_F_ACK_TLVS == 0 {
		return errno, "", true
	}
	// After the header comes the original payload (unless capped), then TLVs.
	off := size_of(i32) + NLMSG_HDRLEN
	if flags & NLM_F_CAPPED == 0 {
		off = size_of(i32) + align(int(e.msg.len))
	}
	if off > len(payload) {
		return errno, "", true
	}
	it := attr_iter(payload[off:])
	for a in attr_next(&it) {
		if a.type == NLMSGERR_ATTR_MSG {
			return errno, attr_str(a), true
		}
	}
	return errno, "", true
}
