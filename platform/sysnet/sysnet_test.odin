// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package sysnet

import "core:fmt"
import "core:sys/linux"
import "core:testing"
import "noir:platform/netlink"

// Pure tests. Expected messages were worked out by hand from
// <linux/rtnetlink.h> and <linux/if_addr.h>. Netlink fields are host byte
// order, so the tests assume little-endian hosts. The kernel-facing tests at
// the end only read.

@(private = "file")
expect_bytes :: proc(t: ^testing.T, got: []u8, want: []u8, loc := #caller_location) {
	if len(got) == len(want) && string(got) == string(want) {
		return
	}
	testing.expectf(t, false, "bytes differ\n  got  %02x\n  want %02x", got, want, loc = loc)
}

@(private = "file")
buf_for :: proc() -> [256]u8 {
	return {}
}

// ---- addresses ----

@(test)
build_addr_add_v4 :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_addr(buf[:], true, 7, 5, IP4_Address{10, 199, 0, 2}, 24, {})
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// len 40, RTM_NEWADDR (20), REQUEST|ACK|CREATE|EXCL = 0x605, seq 7
			0x28, 0x00, 0x00, 0x00, 0x14, 0x00, 0x05, 0x06,
			0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// ifaddrmsg: AF_INET, /24, flags 0, scope 0, index 5
			0x02, 0x18, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
			// IFA_LOCAL, IFA_ADDRESS: 10.199.0.2
			0x08, 0x00, 0x02, 0x00, 0x0a, 0xc7, 0x00, 0x02,
			0x08, 0x00, 0x01, 0x00, 0x0a, 0xc7, 0x00, 0x02,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_addr_add_v6 :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_addr(buf[:], true, 8, 5, IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 2}, 64, {})
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// len 64, RTM_NEWADDR, flags 0x605, seq 8
			0x40, 0x00, 0x00, 0x00, 0x14, 0x00, 0x05, 0x06,
			0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// ifaddrmsg: AF_INET6 (10), /64, index 5
			0x0a, 0x40, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
			// IFA_LOCAL fd00:199::2
			0x14, 0x00, 0x02, 0x00,
			0xfd, 0x00, 0x01, 0x99, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			// IFA_ADDRESS fd00:199::2
			0x14, 0x00, 0x01, 0x00,
			0xfd, 0x00, 0x01, 0x99, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_addr_point_to_point :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_addr(buf[:], true, 1, 3, IP4_Address{10, 8, 0, 2}, 32, {peer = IP4_Address{10, 8, 0, 1}})
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			0x28, 0x00, 0x00, 0x00, 0x14, 0x00, 0x05, 0x06,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x20, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
			// local 10.8.0.2
			0x08, 0x00, 0x02, 0x00, 0x0a, 0x08, 0x00, 0x02,
			// peer 10.8.0.1
			0x08, 0x00, 0x01, 0x00, 0x0a, 0x08, 0x00, 0x01,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_addr_no_prefix_route_uses_ifa_flags :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_addr(buf[:], true, 1, 3, IP4_Address{10, 8, 0, 2}, 24, {no_prefix_route = true})
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, len(msg), 48)
		// IFA_FLAGS (8) = 0x200 at the end
		expect_bytes(t, msg[40:], []u8{0x08, 0x00, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00})
	}
}

@(test)
build_addr_del :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_addr(buf[:], false, 2, 5, IP4_Address{10, 199, 0, 2}, 24, {})
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// RTM_DELADDR (21), flags REQUEST|ACK
			0x28, 0x00, 0x00, 0x00, 0x15, 0x00, 0x05, 0x00,
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x18, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
			0x08, 0x00, 0x02, 0x00, 0x0a, 0xc7, 0x00, 0x02,
			0x08, 0x00, 0x01, 0x00, 0x0a, 0xc7, 0x00, 0x02,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_addr_rejects_bad_input :: proc(t: ^testing.T) {
	buf := buf_for()
	_, err := build_addr(buf[:], true, 1, 3, IP4_Address{10, 8, 0, 2}, 33, {})
	testing.expect_value(t, err, Error.Invalid)
	_, err = build_addr(buf[:], true, 1, 3, IP6_Address{1, 0, 0, 0, 0, 0, 0, 2}, 129, {})
	testing.expect_value(t, err, Error.Invalid)
	_, err = build_addr(buf[:], true, 1, 3, nil, 24, {})
	testing.expect_value(t, err, Error.Invalid)
	// A peer of the other family.
	_, err = build_addr(buf[:], true, 1, 3, IP4_Address{10, 8, 0, 2}, 32, {peer = IP6_Address{1, 0, 0, 0, 0, 0, 0, 1}})
	testing.expect_value(t, err, Error.Invalid)
	// A buffer that is too small.
	small: [20]u8
	_, err = build_addr(small[:], true, 1, 3, IP4_Address{10, 8, 0, 2}, 24, {})
	testing.expect_value(t, err, Error.Protocol)
}

@(test)
build_addr_dump_message :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_addr_dump(buf[:], 4, 0, nil)
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// RTM_GETADDR (22), REQUEST|ROOT|MATCH = 0x301
			0x18, 0x00, 0x00, 0x00, 0x16, 0x00, 0x01, 0x03,
			0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		expect_bytes(t, msg, want[:])

		msg, err = build_addr_dump(buf[:], 4, 9, Family.V6)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, msg[16], 10) // AF_INET6
		testing.expect_value(t, msg[20], 9) // index
	}
}

// ---- links ----

@(test)
build_link_up_and_mtu :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_link_set(buf[:], 1, 5, {.Up}, {.Up}, nil)
		testing.expect_value(t, err, Error.None)
		up := [?]u8 {
			// RTM_NEWLINK (16), REQUEST|ACK
			0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// ifinfomsg: index 5, flags IFF_UP, change IFF_UP
			0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		}
		expect_bytes(t, msg, up[:])

		msg, err = build_link_set(buf[:], 2, 5, {}, {.Up}, nil) // down
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, msg[24], 0) // flags 0
		testing.expect_value(t, msg[28], 1) // change IFF_UP

		msg, err = build_link_set(buf[:], 3, 5, {}, {}, u32(1400))
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, len(msg), 40)
		expect_bytes(t, msg[32:], []u8{0x08, 0x00, 0x04, 0x00, 0x78, 0x05, 0x00, 0x00})

		msg, err = build_link_set(buf[:], 4, 5, {}, {}, nil, u32(2048))
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, len(msg), 40)
		// IFLA_TXQLEN (13), 2048
		expect_bytes(t, msg[32:], []u8{0x08, 0x00, 0x0d, 0x00, 0x00, 0x08, 0x00, 0x00})
	}
}

@(test)
build_link_dump_message :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_link_dump(buf[:], 3)
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// RTM_GETLINK (18), REQUEST|ROOT|MATCH
			0x20, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x03,
			0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_link_get_by_name_and_index :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_link_get(buf[:], 1, 0, "tun0")
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// RTM_GETLINK (18), REQUEST|ACK
			0x28, 0x00, 0x00, 0x00, 0x12, 0x00, 0x05, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// IFLA_IFNAME "tun0\0" (len 9, padded to 12)
			0x09, 0x00, 0x03, 0x00, 't', 'u', 'n', '0',
			0x00, 0x00, 0x00, 0x00,
		}
		// 16 + 16 + 12 = 44 = 0x2c
		testing.expect_value(t, len(msg), 44)
		expect_bytes(t, msg[:16], []u8{0x2c, 0x00, 0x00, 0x00, 0x12, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0})
		expect_bytes(t, msg[32:], want[32:])

		msg, err = build_link_get(buf[:], 2, 7, "")
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, len(msg), 32)
		testing.expect_value(t, msg[20], 7)
	}
	buf2 := buf_for()
	_, err2 := build_link_get(buf2[:], 1, 0, "")
	testing.expect_value(t, err2, Error.Invalid)
	_, err2 = build_link_get(buf2[:], 1, 0, "this-name-is-too-long")
	testing.expect_value(t, err2, Error.Invalid)
}

@(test)
build_link_add_ovpn_and_parse_kind :: proc(t: ^testing.T) {
	buf := buf_for()
	msg, err := build_link_add_ovpn(buf[:], 3, "nvk0", netlink.OVPN_MODE_MP)
	testing.expect_value(t, err, Error.None)
	// 16 header + 16 ifinfomsg + 12 name + 4 + 12 kind + 4 + 8 mode
	testing.expect_value(t, len(msg), 72)
	// The message must parse back: kind and mode.
	it := netlink.msg_iter(msg)
	m, ok := netlink.msg_next(&it)
	testing.expect(t, ok)
	testing.expect_value(t, m.hdr.type, u16(netlink.RTM_NEWLINK))
	l, lok := parse_link(m.payload)
	testing.expect(t, lok)
	testing.expect_value(t, link_name(&l), "nvk0")
	testing.expect_value(t, link_kind(&l), "ovpn")
	_, rest, _ := netlink.read_struct(m.payload, netlink.Ifinfomsg)
	li, _ := netlink.attr_find(rest, netlink.IFLA_LINKINFO)
	testing.expect(t, li.nested)
	data, _ := netlink.attr_find(li.data, netlink.IFLA_INFO_DATA)
	testing.expect(t, data.nested)
	mode, _ := netlink.attr_find(data.data, netlink.IFLA_OVPN_MODE)
	v, vok := netlink.attr_u8(mode)
	testing.expect(t, vok)
	testing.expect_value(t, v, u8(netlink.OVPN_MODE_MP))

	_, err2 := build_link_add_ovpn(buf[:], 1, "", 0)
	testing.expect_value(t, err2, Error.Invalid)
}

// ---- routes ----

@(test)
build_route_default_via_gateway :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_route(
			buf[:],
			true,
			false,
			9,
			Route{dst = IP4_Address{}, dst_len = 0, gateway = IP4_Address{10, 199, 0, 1}, ifindex = 5, metric = u32(100)},
		)
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// len 52, RTM_NEWROUTE (24), REQUEST|ACK|CREATE|EXCL, seq 9
			0x34, 0x00, 0x00, 0x00, 0x18, 0x00, 0x05, 0x06,
			0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// rtmsg: AF_INET, dst_len 0, src_len 0, tos 0,
			//        table 254, protocol static (4), scope universe, type unicast
			0x02, 0x00, 0x00, 0x00, 0xfe, 0x04, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, // flags
			// RTA_GATEWAY 10.199.0.1
			0x08, 0x00, 0x05, 0x00, 0x0a, 0xc7, 0x00, 0x01,
			// RTA_OIF 5
			0x08, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00,
			// RTA_PRIORITY 100
			0x08, 0x00, 0x06, 0x00, 0x64, 0x00, 0x00, 0x00,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_route_device_only_in_table_100 :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_route(
			buf[:],
			true,
			false,
			1,
			Route{dst = IP4_Address{192, 168, 77, 0}, dst_len = 24, ifindex = 5, table = 100},
		)
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			0x2c, 0x00, 0x00, 0x00, 0x18, 0x00, 0x05, 0x06,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// table 100 (0x64), scope link (253), type unicast
			0x02, 0x18, 0x00, 0x00, 0x64, 0x04, 0xfd, 0x01,
			0x00, 0x00, 0x00, 0x00,
			// RTA_DST 192.168.77.0
			0x08, 0x00, 0x01, 0x00, 0xc0, 0xa8, 0x4d, 0x00,
			// RTA_OIF 5
			0x08, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_route_big_table_uses_attribute :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_route(
			buf[:],
			true,
			false,
			1,
			Route{dst = IP4_Address{192, 168, 77, 0}, dst_len = 24, ifindex = 5, table = 1000},
		)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, msg[20], 252) // RT_TABLE_COMPAT in the header
		// RTA_TABLE (15) = 1000 (0x3e8) at the end
		expect_bytes(t, msg[len(msg) - 8:], []u8{0x08, 0x00, 0x0f, 0x00, 0xe8, 0x03, 0x00, 0x00})
	}
}

@(test)
build_route_v6_onlink :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_route(
			buf[:],
			true,
			false,
			3,
			Route {
				dst = IP6_Address{0x2001, 0x0db8, 0x0077, 0, 0, 0, 0, 0},
				dst_len = 48,
				gateway = IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 1},
				onlink = true,
			},
		)
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// len 16 + 12 + 20 + 20 = 68
			0x44, 0x00, 0x00, 0x00, 0x18, 0x00, 0x05, 0x06,
			0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// AF_INET6, /48, table 254, static, universe, unicast, flags ONLINK (4)
			0x0a, 0x30, 0x00, 0x00, 0xfe, 0x04, 0x00, 0x01,
			0x04, 0x00, 0x00, 0x00,
			// RTA_DST 2001:db8:77::
			0x14, 0x00, 0x01, 0x00,
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x77, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// RTA_GATEWAY fd00:199::1
			0x14, 0x00, 0x05, 0x00,
			0xfd, 0x00, 0x01, 0x99, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_route_v6_default_by_family_field :: proc(t: ^testing.T) {
	// No destination at all: the family field says which default route.
	buf := buf_for()
	msg, err := build_route(
		buf[:],
		true,
		false,
		1,
		Route{family = .V6, dst_len = 0, gateway = IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 1}},
	)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, msg[16], 10) // AF_INET6
	testing.expect_value(t, msg[17], 0) // dst_len 0
	testing.expect_value(t, len(msg), 16 + 12 + 20) // no RTA_DST
}

@(test)
build_route_replace_flag :: proc(t: ^testing.T) {
	buf := buf_for()
	msg, _ := build_route(buf[:], true, true, 1, Route{dst = IP4_Address{1, 2, 3, 0}, dst_len = 24, ifindex = 2})
	// flags: REQUEST|ACK|CREATE|REPLACE = 1|4|0x400|0x100 = 0x505
	testing.expect_value(t, msg[6], 0x05)
	testing.expect_value(t, msg[7], 0x05)
}

@(test)
build_route_delete_message :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_route(
			buf[:],
			false,
			false,
			6,
			Route{dst = IP4_Address{10, 199, 0, 0}, dst_len = 24, ifindex = 5},
		)
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// RTM_DELROUTE (25), REQUEST|ACK
			0x2c, 0x00, 0x00, 0x00, 0x19, 0x00, 0x05, 0x00,
			0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// table 254, protocol 0 (any), scope NOWHERE (255), type 0
			0x02, 0x18, 0x00, 0x00, 0xfe, 0x00, 0xff, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x08, 0x00, 0x01, 0x00, 0x0a, 0xc7, 0x00, 0x00,
			0x08, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00,
		}
		expect_bytes(t, msg, want[:])
	}
}

@(test)
build_route_blackhole :: proc(t: ^testing.T) {
	buf := buf_for()
	msg, err := build_route(buf[:], true, false, 1, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8, kind = .Blackhole})
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, msg[23], 6) // RTN_BLACKHOLE
	testing.expect_value(t, msg[22], 0) // scope universe
}

@(test)
build_route_local_kind_and_read_only_kind :: proc(t: ^testing.T) {
	buf := buf_for()
	msg, err := build_route(buf[:], true, false, 1, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8, kind = .Local})
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, msg[23], 2) // RTN_LOCAL
	_, err = build_route(buf[:], true, false, 1, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8, kind = .Other})
	testing.expect_value(t, err, Error.Invalid)
}

@(test)
build_route_rejects_bad_input :: proc(t: ^testing.T) {
	buf := buf_for()
	_, err := build_route(buf[:], true, false, 1, Route{dst = IP4_Address{1, 2, 3, 0}, dst_len = 33})
	testing.expect_value(t, err, Error.Invalid)
	// IPv6 gateway on an IPv4 route
	_, err = build_route(
		buf[:],
		true,
		false,
		1,
		Route{dst = IP4_Address{1, 2, 3, 0}, dst_len = 24, gateway = IP6_Address{1, 0, 0, 0, 0, 0, 0, 1}},
	)
	testing.expect_value(t, err, Error.Invalid)
	// A destination of a different family than the first one cannot happen
	// (the type decides), but a gateway of nil with a non-zero length is fine.
	_, err = build_route(buf[:], true, false, 1, Route{dst = IP6_Address{1, 0, 0, 0, 0, 0, 0, 0}, dst_len = 129})
	testing.expect_value(t, err, Error.Invalid)
}

@(test)
build_route_lookup_message :: proc(t: ^testing.T) {
	when ODIN_ENDIAN == .Little {
		buf := buf_for()
		msg, err := build_route_lookup(buf[:], 5, IP4_Address{8, 8, 8, 8})
		testing.expect_value(t, err, Error.None)
		want := [?]u8 {
			// RTM_GETROUTE (26), REQUEST|ACK; dst_len 32
			0x24, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x05, 0x00,
			0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x08, 0x00, 0x01, 0x00, 0x08, 0x08, 0x08, 0x08,
		}
		expect_bytes(t, msg, want[:])
	}
	buf2 := buf_for()
	_, err2 := build_route_lookup(buf2[:], 1, nil)
	testing.expect_value(t, err2, Error.Invalid)
}

@(test)
build_route_dump_message :: proc(t: ^testing.T) {
	buf := buf_for()
	msg, err := build_route_dump(buf[:], 1, .V6)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(msg), 28)
	testing.expect_value(t, msg[6], 0x01) // REQUEST
	testing.expect_value(t, msg[7], 0x03) // ROOT|MATCH
	testing.expect_value(t, msg[16], 10)
}

// ---- parsers ----

@(test)
parse_route_reply :: proc(t: ^testing.T) {
	buf: [256]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.msg_begin(&b, netlink.RTM_NEWROUTE, 0, 1)
	netlink.put_struct(
		&b,
		netlink.Rtmsg {
			family = netlink.AF_INET,
			dst_len = 24,
			table = netlink.RT_TABLE_COMPAT,
			protocol = netlink.RTPROT_KERNEL,
			scope = netlink.RT_SCOPE_LINK,
			type = netlink.RTN_UNICAST,
		},
	)
	netlink.put_attr(&b, netlink.RTA_DST, []u8{10, 199, 0, 0})
	netlink.put_attr(&b, netlink.RTA_GATEWAY, []u8{10, 199, 0, 1})
	netlink.put_attr(&b, netlink.RTA_PREFSRC, []u8{10, 199, 0, 2})
	netlink.put_u32(&b, netlink.RTA_OIF, 5)
	netlink.put_u32(&b, netlink.RTA_PRIORITY, 50)
	netlink.put_u32(&b, netlink.RTA_TABLE, 1000)
	out, _ := netlink.finish(&b)

	it := netlink.msg_iter(out)
	m, _ := netlink.msg_next(&it)
	r, ok := parse_route(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, r.dst, Address(IP4_Address{10, 199, 0, 0}))
	testing.expect_value(t, r.dst_len, 24)
	testing.expect_value(t, r.gateway, Maybe(Address)(Address(IP4_Address{10, 199, 0, 1})))
	testing.expect_value(t, r.prefsrc, Maybe(Address)(Address(IP4_Address{10, 199, 0, 2})))
	testing.expect_value(t, r.ifindex, 5)
	testing.expect_value(t, r.metric, Maybe(u32)(50))
	testing.expect_value(t, r.table, 1000) // RTA_TABLE wins over the header
	testing.expect_value(t, r.protocol, netlink.RTPROT_KERNEL)
	testing.expect_value(t, r.scope, netlink.RT_SCOPE_LINK)
	testing.expect_value(t, r.kind, Route_Kind.Unicast)
}

@(test)
parse_route_default_has_no_dst_attribute :: proc(t: ^testing.T) {
	buf: [128]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.msg_begin(&b, netlink.RTM_NEWROUTE, 0, 1)
	netlink.put_struct(&b, netlink.Rtmsg{family = netlink.AF_INET6, table = netlink.RT_TABLE_MAIN, type = netlink.RTN_UNICAST})
	gw := [16]u8{0xfd, 0, 1, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	netlink.put_attr(&b, netlink.RTA_GATEWAY, gw[:])
	out, _ := netlink.finish(&b)
	it := netlink.msg_iter(out)
	m, _ := netlink.msg_next(&it)
	r, ok := parse_route(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, r.dst, Address(IP6_Address{}))
	testing.expect_value(t, r.dst_len, 0)
	testing.expect_value(t, r.family, Family.V6)
	testing.expect_value(t, r.gateway, Maybe(Address)(Address(IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 1})))
	testing.expect_value(t, r.table, 254)
}

@(test)
parse_route_kinds :: proc(t: ^testing.T) {
	kinds := [?]struct {
		rtn:  u8,
		want: Route_Kind,
	}{{netlink.RTN_UNICAST, .Unicast}, {netlink.RTN_LOCAL, .Local}, {netlink.RTN_BLACKHOLE, .Blackhole}, {netlink.RTN_BROADCAST, .Other}, {netlink.RTN_THROW, .Other}}
	for k in kinds {
		buf: [64]u8
		b: netlink.Builder
		netlink.builder_init(&b, buf[:])
		netlink.msg_begin(&b, netlink.RTM_NEWROUTE, 0, 1)
		netlink.put_struct(&b, netlink.Rtmsg{family = netlink.AF_INET, type = k.rtn})
		out, _ := netlink.finish(&b)
		it := netlink.msg_iter(out)
		m, _ := netlink.msg_next(&it)
		r, ok := parse_route(m.payload)
		testing.expect(t, ok)
		testing.expect_value(t, r.kind, k.want)
	}
}

@(test)
parse_route_rejects_unknown_family :: proc(t: ^testing.T) {
	buf: [64]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.msg_begin(&b, netlink.RTM_NEWROUTE, 0, 1)
	netlink.put_struct(&b, netlink.Rtmsg{family = 128})
	out, _ := netlink.finish(&b)
	it := netlink.msg_iter(out)
	m, _ := netlink.msg_next(&it)
	_, ok := parse_route(m.payload)
	testing.expect(t, !ok)
	// And a payload shorter than the header.
	_, ok = parse_route(m.payload[:5])
	testing.expect(t, !ok)
}

@(test)
parse_addr_reply :: proc(t: ^testing.T) {
	buf: [128]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.msg_begin(&b, netlink.RTM_NEWADDR, 0, 1)
	netlink.put_struct(&b, netlink.Ifaddrmsg{family = netlink.AF_INET, prefixlen = 24, flags = 0x80, index = 5})
	netlink.put_attr(&b, netlink.IFA_ADDRESS, []u8{10, 199, 0, 2})
	netlink.put_attr(&b, netlink.IFA_LOCAL, []u8{10, 199, 0, 2})
	netlink.put_u32(&b, netlink.IFA_FLAGS, 0x280)
	out, _ := netlink.finish(&b)
	it := netlink.msg_iter(out)
	m, _ := netlink.msg_next(&it)
	a, ok := parse_addr(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, a.address, Address(IP4_Address{10, 199, 0, 2}))
	testing.expect(t, a.peer == nil, "same address twice is not a peer")
	testing.expect_value(t, a.prefix_len, 24)
	testing.expect_value(t, a.index, 5)
	testing.expect_value(t, a.flags, 0x280) // IFA_FLAGS wins over the 8-bit field
}

@(test)
parse_addr_point_to_point :: proc(t: ^testing.T) {
	buf: [128]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.msg_begin(&b, netlink.RTM_NEWADDR, 0, 1)
	netlink.put_struct(&b, netlink.Ifaddrmsg{family = netlink.AF_INET, prefixlen = 32, index = 3})
	netlink.put_attr(&b, netlink.IFA_ADDRESS, []u8{10, 8, 0, 1})
	netlink.put_attr(&b, netlink.IFA_LOCAL, []u8{10, 8, 0, 2})
	out, _ := netlink.finish(&b)
	it := netlink.msg_iter(out)
	m, _ := netlink.msg_next(&it)
	a, ok := parse_addr(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, a.address, Address(IP4_Address{10, 8, 0, 2}))
	testing.expect_value(t, a.peer, Maybe(Address)(Address(IP4_Address{10, 8, 0, 1})))
}

@(test)
parse_addr_with_only_address_attribute :: proc(t: ^testing.T) {
	buf: [128]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.msg_begin(&b, netlink.RTM_NEWADDR, 0, 1)
	netlink.put_struct(&b, netlink.Ifaddrmsg{family = netlink.AF_INET6, prefixlen = 64, index = 3})
	a6 := [16]u8{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	netlink.put_attr(&b, netlink.IFA_ADDRESS, a6[:])
	out, _ := netlink.finish(&b)
	it := netlink.msg_iter(out)
	m, _ := netlink.msg_next(&it)
	a, ok := parse_addr(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, a.address, Address(IP6_Address{0xfe80, 0, 0, 0, 0, 0, 0, 1}))
	testing.expect(t, a.peer == nil)
}

@(test)
parse_link_reply :: proc(t: ^testing.T) {
	buf: [128]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.msg_begin(&b, netlink.RTM_NEWLINK, 0, 1)
	netlink.put_struct(&b, netlink.Ifinfomsg{index = 12, flags = netlink.IFF_UP | netlink.IFF_POINTOPOINT | netlink.IFF_LOWER_UP})
	netlink.put_str(&b, netlink.IFLA_IFNAME, "tun7")
	netlink.put_u32(&b, netlink.IFLA_MTU, 1400)
	out, _ := netlink.finish(&b)
	it := netlink.msg_iter(out)
	m, _ := netlink.msg_next(&it)
	l, ok := parse_link(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, l.index, 12)
	testing.expect_value(t, link_name(&l), "tun7")
	testing.expect_value(t, l.mtu, 1400)
	testing.expect(t, .Up in l.flags)
	testing.expect(t, .Point_To_Point in l.flags)
	testing.expect(t, .Lower_Up in l.flags)
	testing.expect(t, .Loopback not_in l.flags)
}

@(test)
link_flag_bits_match_if_h :: proc(t: ^testing.T) {
	testing.expect_value(t, transmute(u32)Link_Flags{.Up}, 0x1)
	testing.expect_value(t, transmute(u32)Link_Flags{.Loopback}, 0x8)
	testing.expect_value(t, transmute(u32)Link_Flags{.Point_To_Point}, 0x10)
	testing.expect_value(t, transmute(u32)Link_Flags{.Running}, 0x40)
	testing.expect_value(t, transmute(u32)Link_Flags{.Lower_Up}, 0x10000)
}

@(test)
error_mapping :: proc(t: ^testing.T) {
	testing.expect_value(t, map_errno(.EEXIST), Error.Exists)
	testing.expect_value(t, map_errno(.ESRCH), Error.Not_Found)
	testing.expect_value(t, map_errno(.ENODEV), Error.Not_Found)
	testing.expect_value(t, map_errno(.EADDRNOTAVAIL), Error.Not_Found)
	testing.expect_value(t, map_errno(.EPERM), Error.Permission)
	testing.expect_value(t, map_errno(.ENETUNREACH), Error.Network_Unreachable)
	testing.expect_value(t, map_errno(.EXDEV), Error.Other)
	testing.expect_value(t, map_nl_error(.NONE, .Timeout), Error.Timeout)
	testing.expect_value(t, map_nl_error(.NONE, .Truncated), Error.Protocol)
	testing.expect_value(t, map_nl_error(.EEXIST, .Kernel), Error.Exists)
	// A kernel failure never maps to "no error".
	testing.expect_value(t, map_nl_error(.NONE, .Kernel), Error.Other)
}

// ---- the kernel, read only ----

@(test)
kernel_link_get_loopback :: proc(t: ^testing.T) {
	c, err := open()
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&c)

	l, gerr := link_get(&c, "lo")
	testing.expect_value(t, gerr, Error.None)
	testing.expect_value(t, link_name(&l), "lo")
	testing.expect(t, l.index > 0)
	testing.expect(t, .Loopback in l.flags)
	testing.expect_value(t, l.mtu, 65536)

	// By index gives the same link.
	l2, gerr2 := link_get_by_index(&c, l.index)
	testing.expect_value(t, gerr2, Error.None)
	testing.expect_value(t, link_name(&l2), "lo")

	// A link that does not exist.
	_, gerr3 := link_get(&c, "noir-nosuch0")
	testing.expect_value(t, gerr3, Error.Not_Found)
	testing.expect_value(t, last_errno(&c), linux.Errno.ENODEV)
	_, gerr4 := link_get_by_index(&c, 0x7fff_fff0)
	testing.expect_value(t, gerr4, Error.Not_Found)
}

@(test)
kernel_lists_succeed :: proc(t: ^testing.T) {
	c, err := open()
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&c)

	links := make([dynamic]Link_Info)
	defer delete(links)
	testing.expect_value(t, link_list(&c, &links), Error.None)
	have_lo := false
	for &l in links {
		testing.expect(t, l.index > 0)
		if link_name(&l) == "lo" {
			have_lo = true
		}
	}
	testing.expect(t, have_lo, "lo is in the link list")

	addrs := make([dynamic]Addr_Info)
	defer delete(addrs)
	testing.expect_value(t, addr_list(&c, 0, nil, &addrs), Error.None)
	// Every link listed has an index and an address.
	for a in addrs {
		testing.expect(t, a.index > 0)
		testing.expect(t, a.address != nil)
	}
	testing.expect_value(t, addr_list(&c, 0, Family.V4, &addrs), Error.None)
	for a in addrs {
		_, is_v4 := a.address.(IP4_Address)
		testing.expect(t, is_v4)
	}

	routes := make([dynamic]Route)
	defer delete(routes)
	testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
	for r in routes {
		testing.expect_value(t, r.table, netlink.RT_TABLE_MAIN)
		_, is_v4 := r.dst.(IP4_Address)
		testing.expect(t, is_v4)
	}
	testing.expect_value(t, route_list(&c, .V6, 0, 0, &routes), Error.None)
	// The default route may or may not exist. If it does, it has an interface.
	d, derr := route_get_default(&c, .V4)
	if derr == .None {
		testing.expect_value(t, d.dst_len, 0)
		testing.expect(t, d.ifindex != 0 || d.gateway != nil)
	} else {
		testing.expect_value(t, derr, Error.Not_Found)
	}
}

@(test)
kernel_changes_need_privileges :: proc(t: ^testing.T) {
	// An unprivileged process must get a clean `.Permission`, not a crash.
	// (In a namespace where we are root, this succeeds or fails with
	// .Not_Found: no error here is unexpected.) The index cannot exist, so
	// nothing real is touched even with privileges.
	c, err := open()
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&c)
	e := link_set_up(&c, 0x7fff_fff0)
	testing.expect(t, e == .Permission || e == .Not_Found, fmt.tprintf("got %v", e))
}
