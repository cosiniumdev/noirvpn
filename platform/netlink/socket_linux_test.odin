// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package netlink

import "core:sys/linux"
import "core:testing"
import "core:time"

// These talk to the real kernel but only read: they work without privileges
// and change nothing.

@(test)
dump_links_finds_loopback :: proc(t: ^testing.T) {
	s, err := open(NETLINK_ROUTE)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&s)
	testing.expect(t, s.port != 0)

	buf: [64]u8
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, next_seq(&s))
	put_struct(&b, Ifinfomsg{})
	msg, berr := finish(&b)
	testing.expect_value(t, berr, Error.None)

	Found :: struct {
		count:    int,
		lo_index: i32,
	}
	found: Found
	handler :: proc(user: rawptr, m: Msg) {
		f := (^Found)(user)
		if m.hdr.type != RTM_NEWLINK {
			return
		}
		ifi, rest, ok := read_struct(m.payload, Ifinfomsg)
		if !ok {
			return
		}
		f.count += 1
		if name, nok := attr_find(rest, IFLA_IFNAME); nok && attr_str(name) == "lo" {
			f.lo_index = ifi.index
			if ifi.flags & IFF_LOOPBACK == 0 {
				f.lo_index = -1
			}
		}
	}
	rx := make([]u8, 32768)
	defer delete(rx)
	rerr := request(&s, msg, rx, handler, &found)
	testing.expect_value(t, rerr, Error.None)
	testing.expect(t, found.count >= 1, "no links in the dump")
	testing.expect(t, found.lo_index > 0, "no loopback device found")
}

@(test)
get_missing_link_is_kernel_error :: proc(t: ^testing.T) {
	s, err := open(NETLINK_ROUTE)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&s)

	buf: [128]u8
	b: Builder
	builder_init(&b, buf[:])
	msg_begin(&b, RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, next_seq(&s))
	put_struct(&b, Ifinfomsg{})
	put_str(&b, IFLA_IFNAME, "noir-nosuch0")
	msg, _ := finish(&b)

	rx: [4096]u8
	rerr := transact(&s, msg, rx[:])
	testing.expect_value(t, rerr, Error.Kernel)
	testing.expect_value(t, s.errno, linux.Errno.ENODEV)
}

@(test)
recv_times_out :: proc(t: ^testing.T) {
	s, err := open(NETLINK_ROUTE, 0, 50 * time.Millisecond)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&s)
	rx: [256]u8
	start := time.tick_now()
	_, rerr := recv(&s, rx[:])
	testing.expect_value(t, rerr, Error.Timeout)
	elapsed := time.tick_since(start)
	testing.expect(t, elapsed >= 40 * time.Millisecond, "returned too early")
	testing.expect(t, elapsed < 2 * time.Second, "returned too late")
}

@(test)
genl_resolves_controller :: proc(t: ^testing.T) {
	s, err := open(NETLINK_GENERIC)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&s)
	rx: [8192]u8

	info, rerr := genl_resolve(&s, "nlctrl", rx[:])
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, info.id, GENL_ID_CTRL)

	// An unknown family is a kernel error, ENOENT. (Names are 15 bytes at
	// most; a longer one is EINVAL.)
	_, rerr = genl_resolve(&s, "noir_nosuch", rx[:])
	testing.expect_value(t, rerr, Error.Kernel)
	testing.expect_value(t, s.errno, linux.Errno.ENOENT)
}

@(test)
recv_nowait_does_not_wait :: proc(t: ^testing.T) {
	s, err := open(NETLINK_ROUTE, 0, 0)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&s)
	rx: [256]u8
	start := time.tick_now()
	_, rerr := recv_nowait(&s, rx[:])
	testing.expect_value(t, rerr, Error.Timeout)
	testing.expect(t, time.tick_since(start) < 500 * time.Millisecond, "waited")
}

@(test)
genl_group_of_a_family :: proc(t: ^testing.T) {
	s, err := open(NETLINK_GENERIC)
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&s)
	rx: [8192]u8
	// The controller has the group "notify".
	info, rerr := genl_resolve(&s, "nlctrl", rx[:])
	testing.expect_value(t, rerr, Error.None)
	id, ok := group_id(&info, "notify")
	testing.expect(t, ok)
	testing.expect(t, id != 0)
	_, ok = group_id(&info, "noir_nosuch")
	testing.expect(t, !ok)
}
