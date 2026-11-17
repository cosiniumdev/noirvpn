// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package netlink

import "core:testing"

// Expected bytes were worked out by hand from netlink(7) and
// <linux/rtnetlink.h>. Netlink fields are host byte order, so they are
// written for little-endian hosts (every target noirvpn builds for).

@(test)
build_set_mtu :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf: [64]u8
		b: Builder
		builder_init(&b, buf[:])
		msg_begin(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 0x01020304)
		put_struct(&b, Ifinfomsg{index = 7, flags = IFF_UP, change = IFF_UP})
		put_u32(&b, IFLA_MTU, 1400)
		out, err := finish(&b)
		testing.expect_value(t, err, Error.None)

		want := [?]u8 {
			// nlmsghdr: len 40, type 16, flags REQUEST|ACK, seq, pid 0
			0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x00,
			0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
			// ifinfomsg: family 0, pad, type 0, index 7, flags 1, change 1
			0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			// IFLA_MTU = 1400 (0x578)
			0x08, 0x00, 0x04, 0x00, 0x78, 0x05, 0x00, 0x00,
		}
		testing.expect_value(t, len(out), len(want))
		testing.expect(t, len(out) == len(want) && string(out) == string(want[:]), "bytes differ")
	}
}

// The kernel layout: a nest inside a nest,
// strings with padding, a one-byte attribute.
@(test)
build_nested_link_create :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf: [128]u8
		b: Builder
		builder_init(&b, buf[:])
		msg_begin(&b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 1)
		put_struct(&b, Ifinfomsg{family = AF_PACKET})
		put_str(&b, IFLA_IFNAME, "ovpn0")
		linkinfo := nest_begin(&b, IFLA_LINKINFO)
		put_str(&b, IFLA_INFO_KIND, "ovpn")
		data := nest_begin(&b, IFLA_INFO_DATA)
		put_u8(&b, 1, 0)
		nest_end(&b, data)
		nest_end(&b, linkinfo)
		out, err := finish(&b)
		testing.expect_value(t, err, Error.None)

		want := [?]u8 {
			// nlmsghdr: len 72, type 16, flags 0x605, seq 1
			0x48, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x06,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// ifinfomsg with family AF_PACKET (17)
			0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// IFLA_IFNAME "ovpn0": len 10, padded to 12
			0x0a, 0x00, 0x03, 0x00, 'o', 'v', 'p', 'n',
			'0', 0x00, 0x00, 0x00,
			// IFLA_LINKINFO | NESTED: len 28
			0x1c, 0x00, 0x12, 0x80,
			// IFLA_INFO_KIND "ovpn": len 9, padded to 12
			0x09, 0x00, 0x01, 0x00, 'o', 'v', 'p', 'n',
			0x00, 0x00, 0x00, 0x00,
			// IFLA_INFO_DATA | NESTED: len 12
			0x0c, 0x00, 0x02, 0x80,
			// attribute 1, one byte, value 0: len 5, padded to 8
			0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		testing.expect_value(t, len(out), len(want))
		testing.expect(t, len(out) == len(want) && string(out) == string(want[:]), "bytes differ")
	}
}

@(test)
build_stale_buffer_is_cleared :: proc(t: ^testing.T) {
	// Padding bytes must be zero even when the buffer held old data.
	buf: [64]u8
	for &x in buf {
		x = 0xaa
	}
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, 1, 0, 1)
	put_struct(&b, Genlmsghdr{cmd = 1})
	put_u8(&b, 9, 0x55)
	put_str(&b, 10, "ab")
	out, err := finish(&b)
	testing.expect_value(t, err, Error.None)
	// header 16, genl 4, u8 attr 8, str attr 8
	testing.expect_value(t, len(out), 36)
	for x in out[20:] {
		testing.expect(t, x != 0xaa)
	}
	// The u8 attribute: bytes 5..7 of it are padding.
	testing.expect_value(t, out[25], 0)
	testing.expect_value(t, out[26], 0)
	testing.expect_value(t, out[27], 0)
}

@(test)
build_overflow_is_sticky :: proc(t: ^testing.T) {
	buf: [24]u8
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, 1, 0, 1)
	put_u32(&b, 1, 5) // 16 + 8 = 24: fits exactly
	_, err := finish(&b)
	testing.expect_value(t, err, Error.None)

	builder_init(&b, buf[:])
	msg_begin(&b, 1, 0, 1)
	put_u32(&b, 1, 5)
	put_u32(&b, 2, 6) // no room
	put_u8(&b, 3, 1) // ignored
	_, err = finish(&b)
	testing.expect_value(t, err, Error.Buffer_Too_Small)
}

@(test)
build_oversize_attr :: proc(t: ^testing.T) {
	buf: [80000]u8
	data: [70000]u8
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, 1, 0, 1)
	put_attr(&b, 1, data[:])
	_, err := finish(&b)
	testing.expect_value(t, err, Error.Oversize)

	// The largest attribute that fits: 65535 - 4.
	builder_init(&b, buf[:])
	msg_begin(&b, 1, 0, 1)
	put_attr(&b, 1, data[:65531])
	out, err2 := finish(&b)
	testing.expect_value(t, err2, Error.None)
	testing.expect_value(t, len(out), 16 + 65536)
}

@(test)
build_big_endian_attrs :: proc(t: ^testing.T) {
	buf: [64]u8
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, 1, 0, 1)
	put_u16_be(&b, 1, 0x1234)
	put_u32_be(&b, 2, 0xdeadbeef)
	out, err := finish(&b)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(out), 16 + 8 + 8)
	testing.expect_value(t, out[20], 0x12)
	testing.expect_value(t, out[21], 0x34)
	testing.expect_value(t, out[28], 0xde)
	testing.expect_value(t, out[31], 0xef)
}

@(test)
build_two_messages :: proc(t: ^testing.T) {
	buf: [128]u8
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, 20, NLM_F_REQUEST, 1)
	put_u32(&b, 1, 11)
	msg_begin(&b, 21, NLM_F_REQUEST, 2) // ends the first one
	put_str(&b, 1, "x")
	out, err := finish(&b)
	testing.expect_value(t, err, Error.None)

	it := msg_iter(out)
	m1, ok1 := msg_next(&it)
	testing.expect(t, ok1)
	testing.expect_value(t, m1.hdr.type, 20)
	testing.expect_value(t, m1.hdr.seq, 1)
	testing.expect_value(t, m1.hdr.len, 24)
	testing.expect_value(t, len(m1.payload), 8)
	m2, ok2 := msg_next(&it)
	testing.expect(t, ok2)
	testing.expect_value(t, m2.hdr.type, 21)
	testing.expect_value(t, m2.hdr.seq, 2)
	_, ok3 := msg_next(&it)
	testing.expect(t, !ok3)
	testing.expect_value(t, it.err, Error.None)
}

// ---- parser ----

@(test)
parse_round_trip :: proc(t: ^testing.T) {
	buf: [128]u8
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, RTM_NEWLINK, 0, 9)
	put_struct(&b, Ifinfomsg{index = 3, flags = 0x1043})
	put_str(&b, IFLA_IFNAME, "tun7")
	put_u32(&b, IFLA_MTU, 1500)
	put_u8(&b, IFLA_OPERSTATE, 6)
	put_u64(&b, 99, 0x0102030405060708)
	nest := nest_begin(&b, IFLA_LINKINFO)
	put_str(&b, IFLA_INFO_KIND, "tun")
	nest_end(&b, nest)
	out, err := finish(&b)
	testing.expect_value(t, err, Error.None)

	// Parse from an odd offset to prove nothing needs alignment.
	shifted: [160]u8
	copy(shifted[1:], out)
	it := msg_iter(shifted[1:][:len(out)])
	m, ok := msg_next(&it)
	testing.expect(t, ok)
	testing.expect_value(t, m.hdr.type, RTM_NEWLINK)
	testing.expect_value(t, m.hdr.seq, 9)

	ifi, rest, ok2 := read_struct(m.payload, Ifinfomsg)
	testing.expect(t, ok2)
	testing.expect_value(t, ifi.index, 3)
	testing.expect_value(t, ifi.flags, 0x1043)

	seen := 0
	ai := attr_iter(rest)
	for a in attr_next(&ai) {
		switch a.type {
		case IFLA_IFNAME:
			testing.expect_value(t, attr_str(a), "tun7")
			seen += 1
		case IFLA_MTU:
			v, vok := attr_u32(a)
			testing.expect(t, vok)
			testing.expect_value(t, v, 1500)
			seen += 1
		case IFLA_OPERSTATE:
			v, vok := attr_u8(a)
			testing.expect(t, vok)
			testing.expect_value(t, v, 6)
			seen += 1
		case 99:
			v, vok := attr_u64(a)
			testing.expect(t, vok)
			testing.expect_value(t, v, 0x0102030405060708)
			seen += 1
		case IFLA_LINKINFO:
			testing.expect(t, a.nested)
			kind, kok := attr_find(a.data, IFLA_INFO_KIND)
			testing.expect(t, kok)
			testing.expect_value(t, attr_str(kind), "tun")
			seen += 1
		}
	}
	testing.expect_value(t, ai.err, Error.None)
	testing.expect_value(t, seen, 5)

	_, found := attr_find(rest, 77)
	testing.expect(t, !found)
}

@(test)
parse_attr_length_mismatch :: proc(t: ^testing.T) {
	// A u32 reader refuses a 2-byte attribute.
	a := Attr{type = 1, data = {1, 2}}
	_, ok := attr_u32(a)
	testing.expect(t, !ok)
	_, ok = attr_u16_be(a)
	testing.expect(t, ok)
	_, ok = attr_u8(a)
	testing.expect(t, !ok)
}

@(test)
parse_truncated_messages :: proc(t: ^testing.T) {
	// Shorter than a header.
	it := msg_iter([]u8{1, 2, 3})
	_, ok := msg_next(&it)
	testing.expect(t, !ok)
	testing.expect_value(t, it.err, Error.Truncated)

	// Length field below the header size.
	short: [16]u8
	short[0] = 8
	it = msg_iter(short[:])
	_, ok = msg_next(&it)
	testing.expect(t, !ok)
	testing.expect_value(t, it.err, Error.Truncated)

	// Length field past the end of the data.
	long: [16]u8
	long[0] = 32
	it = msg_iter(long[:])
	_, ok = msg_next(&it)
	testing.expect(t, !ok)
	testing.expect_value(t, it.err, Error.Truncated)

	// A good message followed by cut data: the first is returned, then an error.
	two: [20]u8
	two[0] = 16
	it = msg_iter(two[:])
	_, ok = msg_next(&it)
	testing.expect(t, ok)
	_, ok = msg_next(&it)
	testing.expect(t, !ok)
	testing.expect_value(t, it.err, Error.Truncated)

	// Empty input is simply the end.
	it = msg_iter(nil)
	_, ok = msg_next(&it)
	testing.expect(t, !ok)
	testing.expect_value(t, it.err, Error.None)
}

@(test)
parse_truncated_attrs :: proc(t: ^testing.T) {
	// Attribute length below 4.
	ai := attr_iter([]u8{3, 0, 1, 0})
	_, ok := attr_next(&ai)
	testing.expect(t, !ok)
	testing.expect_value(t, ai.err, Error.Truncated)

	// Attribute length past the end.
	ai = attr_iter([]u8{12, 0, 1, 0, 0, 0, 0, 0})
	_, ok = attr_next(&ai)
	testing.expect(t, !ok)
	testing.expect_value(t, ai.err, Error.Truncated)

	// Fewer than 4 bytes left over.
	ai = attr_iter([]u8{4, 0, 1, 0, 9, 9})
	_, ok = attr_next(&ai)
	testing.expect(t, ok)
	_, ok = attr_next(&ai)
	testing.expect(t, !ok)
	testing.expect_value(t, ai.err, Error.Truncated)

	// An empty attribute (flag) is valid.
	ai = attr_iter([]u8{4, 0, 5, 0})
	a, ok2 := attr_next(&ai)
	testing.expect(t, ok2)
	testing.expect_value(t, a.type, 5)
	testing.expect_value(t, len(a.data), 0)

	// A last attribute without its padding is accepted.
	ai = attr_iter([]u8{5, 0, 6, 0, 0xee})
	a, ok2 = attr_next(&ai)
	testing.expect(t, ok2)
	testing.expect_value(t, len(a.data), 1)
	_, ok2 = attr_next(&ai)
	testing.expect(t, !ok2)
	testing.expect_value(t, ai.err, Error.None)
}

@(test)
parse_attr_flag_bits :: proc(t: ^testing.T) {
	// type 0xc005 = NESTED | NET_BYTEORDER | 5
	ai := attr_iter([]u8{4, 0, 0x05, 0xc0})
	a, ok := attr_next(&ai)
	testing.expect(t, ok)
	testing.expect_value(t, a.type, 5)
	testing.expect(t, a.nested)
	testing.expect(t, a.net_order)
}

@(test)
parse_error_messages :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		// ACK: error 0, then the original header.
		ack: [20]u8
		e, text, ok := parse_error(0, ack[:])
		testing.expect(t, ok)
		testing.expect_value(t, e, 0)
		testing.expect_value(t, text, "")

		// -EEXIST (17) without extended ACK.
		exist: [20]u8
		exist[0], exist[1], exist[2], exist[3] = 0xef, 0xff, 0xff, 0xff
		e, text, ok = parse_error(0, exist[:])
		testing.expect(t, ok)
		testing.expect_value(t, e, 17)

		// Capped, with ACK_TLVS: -ENODEV (19), the 16-byte original header,
		// then the message attribute "no dev" (type 1, len 11, padded to 12).
		capped := [?]u8 {
			0xed, 0xff, 0xff, 0xff,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			11, 0, 1, 0, 'n', 'o', ' ', 'd', 'e', 'v', 0, 0,
		}
		e, text, ok = parse_error(NLM_F_CAPPED | NLM_F_ACK_TLVS, capped[:])
		testing.expect(t, ok)
		testing.expect_value(t, e, 19)
		testing.expect_value(t, text, "no dev")

		// Not capped: the original message (length 20) comes first, then the
		// TLVs. -EINVAL (22), message "bad".
		full := [?]u8 {
			0xea, 0xff, 0xff, 0xff,
			20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0xde, 0xad, 0xbe, 0xef,
			8, 0, 1, 0, 'b', 'a', 'd', 0,
		}
		e, text, ok = parse_error(NLM_F_ACK_TLVS, full[:])
		testing.expect(t, ok)
		testing.expect_value(t, e, 22)
		testing.expect_value(t, text, "bad")

		// Too short.
		_, _, ok = parse_error(0, ack[:10])
		testing.expect(t, !ok)
	}
}

@(test)
genl_family_info_parse :: proc(t: ^testing.T) {
	// Build a reply like the controller's, then parse it.
	buf: [256]u8
	b: Builder
	builder_init(&b, buf[:])
	put_genl_header(&b, GENL_ID_CTRL, 0, 1, 1, 2)
	put_u16(&b, CTRL_ATTR_FAMILY_ID, 33)
	put_str(&b, CTRL_ATTR_FAMILY_NAME, "ovpn")
	put_u32(&b, CTRL_ATTR_VERSION, 1)
	put_u32(&b, CTRL_ATTR_HDRSIZE, 0)
	put_u32(&b, CTRL_ATTR_MAXATTR, 12)
	groups := nest_begin(&b, CTRL_ATTR_MCAST_GROUPS)
	g1 := nest_begin(&b, 1)
	put_str(&b, CTRL_ATTR_MCAST_GRP_NAME, "peers")
	put_u32(&b, CTRL_ATTR_MCAST_GRP_ID, 7)
	nest_end(&b, g1)
	nest_end(&b, groups)
	out, err := finish(&b)
	testing.expect_value(t, err, Error.None)

	it := msg_iter(out)
	m, ok := msg_next(&it)
	testing.expect(t, ok)
	info, ok2 := parse_family_info(m.payload)
	testing.expect(t, ok2)
	testing.expect_value(t, info.id, 33)
	testing.expect_value(t, info.version, 1)
	testing.expect_value(t, info.max_attr, 12)
	testing.expect_value(t, info.n_groups, 1)
	testing.expect_value(t, group_name(&info, 0), "peers")
	testing.expect_value(t, info.groups[0].id, 7)
}

@(test)
align_rounds_to_four :: proc(t: ^testing.T) {
	testing.expect_value(t, align(0), 0)
	testing.expect_value(t, align(1), 4)
	testing.expect_value(t, align(4), 4)
	testing.expect_value(t, align(5), 8)
	testing.expect_value(t, align(17), 20)
}

// These numbers were printed by a C program that includes the kernel headers.
// They catch typos in the constants.
@(test)
constants_match_headers :: proc(t: ^testing.T) {
	testing.expect_value(t, NLM_F_DUMP, 0x300)
	testing.expect_value(t, NLMSG_MIN_TYPE, 0x10)
	testing.expect_value(t, RTM_NEWADDR, 20)
	testing.expect_value(t, RTM_GETROUTE, 26)
	testing.expect_value(t, IFLA_LINKINFO, 18)
	testing.expect_value(t, IFLA_EXT_MASK, 29)
	testing.expect_value(t, IFA_FLAGS, 8)
	testing.expect_value(t, RTA_TABLE, 15)
	testing.expect_value(t, RTA_PRIORITY, 6)
	testing.expect_value(t, RT_SCOPE_LINK, 253)
	testing.expect_value(t, GENL_ID_CTRL, 0x10)
	testing.expect_value(t, CTRL_ATTR_MCAST_GROUPS, 7)
	testing.expect_value(t, NLA_TYPE_MASK, 0x3fff)
}

@(test)
attr_uint_takes_every_width :: proc(t: ^testing.T) {
	v, ok := attr_uint(Attr{data = []u8{7}})
	testing.expect(t, ok)
	testing.expect_value(t, v, u64(7))
	b2: [2]u8
	b4: [4]u8
	b8: [8]u8
	b2[0] = 1
	b4[1] = 1
	b8[7] = 1
	v, ok = attr_uint(Attr{data = b2[:]})
	testing.expect(t, ok)
	testing.expect_value(t, v, u64(1))
	v, ok = attr_uint(Attr{data = b4[:]})
	testing.expect(t, ok)
	testing.expect_value(t, v, u64(256))
	v, ok = attr_uint(Attr{data = b8[:]})
	testing.expect(t, ok)
	testing.expect_value(t, v, u64(1) << 56)
	_, ok = attr_uint(Attr{data = []u8{1, 2, 3}})
	testing.expect(t, !ok)
}
