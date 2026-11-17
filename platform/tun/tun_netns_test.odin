// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package tun

import "core:sys/linux"
import "core:testing"

// Tests that create real tun devices. They change network state, so they run
// only with -define:NOIR_NETNS_TESTS=true, and only inside a throwaway
// network namespace owned by a user namespace. Use platform/run-netns-tests.sh
// (it runs `unshare -rn`). Without the define the file still compiles (the
// helpers) but registers no tests.
NETNS :: #config(NOIR_NETNS_TESTS, false)

// True when this process is in a user namespace that is not the initial one.
// Then a network namespace we hold is private, and root here is not root on
// the host. The initial namespace maps the whole uid range ("0 0 4294967295").
in_private_userns :: proc() -> bool {
	fd, e := linux.open("/proc/self/uid_map", {.CLOEXEC})
	if e != .NONE {
		return false
	}
	defer linux.close(fd)
	buf: [128]u8
	n, re := linux.read(fd, buf[:])
	if re != .NONE || n <= 0 {
		return false
	}
	text := string(buf[:n])
	for i in 0 ..< len(text) - 9 {
		if text[i:i + 10] == "4294967295" {
			return false
		}
	}
	return true
}

// Fails the test, with a hint, when we are not in a private namespace.
require_private_netns :: proc(t: ^testing.T) -> bool {
	ok := in_private_userns()
	testing.expect(t, ok, "not in a private user namespace: run platform/run-netns-tests.sh")
	return ok
}

SIOCSIFFLAGS :: 0x8914
IFF_UP :: 0x1

// Bring the interface up or down with the classic ioctls (the sysnet package
// does this over netlink; tun tests must not depend on it).
set_link :: proc(dev: ^Device, up: bool) -> Error {
	ifr: Ifreq
	copy(ifr.name[:], name(dev))
	if e := if_ioctl(SIOCGIFFLAGS, &ifr); e != .None {
		return e
	}
	if up {
		ifr.flags |= IFF_UP
	} else {
		ifr.flags &= ~i16(IFF_UP)
	}
	return if_ioctl(SIOCSIFFLAGS, &ifr)
}

// An IPv4 header of 20 bytes with a correct checksum, protocol 253
// (experimental). `payload_len` only sets the total length field.
ipv4_header :: proc(src_addr, dst_addr: [4]u8, payload_len: int) -> (h: [20]u8) {
	src, dst := src_addr, dst_addr
	total := 20 + payload_len
	h[0] = 0x45
	h[2] = u8(total >> 8)
	h[3] = u8(total)
	h[8] = 64 // ttl
	h[9] = 253
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	sum: u32
	for i := 0; i < 20; i += 2 {
		sum += u32(h[i]) << 8 | u32(h[i + 1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ~u16(sum)
	h[10] = u8(c >> 8)
	h[11] = u8(c)
	return
}

when NETNS {

	@(test)
	netns_open_creates_the_named_device :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirtun0"})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)
		testing.expect_value(t, name(&dev), "noirtun0")
		testing.expect(t, is_open(&dev))

		flags, ferr := get_flags(&dev)
		testing.expect_value(t, ferr, Error.None)
		testing.expect_value(t, flags & (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE), IFF_TUN | IFF_NO_PI)

		// The descriptor is non-blocking.
		fl, _ := linux.fcntl_getfl(linux.Fd(dev.fd), .GETFL)
		testing.expect(t, .NONBLOCK in fl)
	}

	@(test)
	netns_name_pattern_and_default :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		a, aerr := open({name = "noirp%d"})
		testing.expect_value(t, aerr, Error.None)
		defer close(&a)
		testing.expect_value(t, name(&a), "noirp0")
		b, berr := open({name = "noirp%d"})
		testing.expect_value(t, berr, Error.None)
		defer close(&b)
		testing.expect_value(t, name(&b), "noirp1")

		// No name at all: the kernel's default pattern.
		c, cerr := open({})
		testing.expect_value(t, cerr, Error.None)
		defer close(&c)
		n := name(&c)
		testing.expect(t, len(n) > 3 && n[:3] == "tun", "default name starts with tun")
	}

	@(test)
	netns_device_goes_away_with_its_descriptor :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirgone0"})
		testing.expect_value(t, err, Error.None)
		close(&dev)
		// The name is free again at once.
		again, err2 := open({name = "noirgone0"})
		testing.expect_value(t, err2, Error.None)
		close(&again)
	}

	@(test)
	netns_mtu_round_trip :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirmtu0"})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)

		mtu, merr := get_mtu(&dev)
		testing.expect_value(t, merr, Error.None)
		testing.expect_value(t, mtu, 1500)

		testing.expect_value(t, set_mtu(&dev, 1400), Error.None)
		mtu, merr = get_mtu(&dev)
		testing.expect_value(t, merr, Error.None)
		testing.expect_value(t, mtu, 1400)

		// Below the IPv4 minimum (68) and above the 16 bit limit: refused.
		testing.expect_value(t, set_mtu(&dev, 10), Error.Invalid)
		testing.expect_value(t, set_mtu(&dev, 200000), Error.Invalid)
		mtu, _ = get_mtu(&dev)
		testing.expect_value(t, mtu, 1400)
	}

	@(test)
	netns_second_open_of_a_single_queue_device_is_busy :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		a, aerr := open({name = "noirbusy0"})
		testing.expect_value(t, aerr, Error.None)
		defer close(&a)
		b, berr := open({name = "noirbusy0"})
		testing.expect_value(t, berr, Error.Busy)
		testing.expect(t, !is_open(&b), "a failed open leaves no descriptor")
	}

	@(test)
	netns_multi_queue :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		q0, e0 := open({name = "noirmq0", multi_queue = true})
		testing.expect_value(t, e0, Error.None)
		defer close(&q0)
		flags, _ := get_flags(&q0)
		testing.expect(t, flags & IFF_MULTI_QUEUE != 0)

		q1, e1 := open_queue(&q0)
		testing.expect_value(t, e1, Error.None)
		defer close(&q1)
		q2, e2 := open_queue(&q0)
		testing.expect_value(t, e2, Error.None)
		defer close(&q2)
		testing.expect_value(t, name(&q1), "noirmq0")
		testing.expect_value(t, name(&q2), "noirmq0")
		testing.expect(t, q0.fd != q1.fd && q1.fd != q2.fd)

		// All queues see the same interface.
		testing.expect_value(t, set_mtu(&q2, 1300), Error.None)
		mtu, merr := get_mtu(&q0)
		testing.expect_value(t, merr, Error.None)
		testing.expect_value(t, mtu, 1300)

		// The interface stays while any queue is open.
		close(&q0)
		q3, e3 := open_queue(&q1)
		testing.expect_value(t, e3, Error.None)
		close(&q3)
		mtu, merr = get_mtu(&q2)
		testing.expect_value(t, merr, Error.None)
		testing.expect_value(t, mtu, 1300)

		// A plain (single queue) open of a multi-queue device is refused.
		_, perr := open({name = "noirmq0"})
		testing.expect_value(t, perr, Error.Invalid)
	}

	@(test)
	netns_read_is_would_block_when_idle :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirrd0"})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)
		buf: [2048]u8
		_, rerr := read(&dev, buf[:])
		testing.expect_value(t, rerr, Error.Would_Block)
	}

	@(test)
	netns_write_needs_the_link_up :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirwr0"})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)

		pkt := ipv4_header({10, 199, 0, 1}, {10, 199, 0, 2}, 0)
		// Down: the kernel refuses with EIO.
		testing.expect_value(t, write(&dev, pkt[:]), Error.Io)

		testing.expect_value(t, set_link(&dev, true), Error.None)
		testing.expect_value(t, write(&dev, pkt[:]), Error.None)

		// Not an IP packet (version nibble 0): refused.
		junk := [?]u8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
		testing.expect_value(t, write(&dev, junk[:]), Error.Invalid)

		testing.expect_value(t, set_link(&dev, false), Error.None)
		testing.expect_value(t, write(&dev, pkt[:]), Error.Io)
	}

	// Packets the stack sends to the tunnel are read by `read`. Here we send
	// from the device's own address by way of a UDP socket bound to it.
	@(test)
	netns_host_sends_into_the_tunnel :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirtx0"})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)
		testing.expect_value(t, set_link(&dev, true), Error.None)
		// Address and route come from sysnet (its tests cover the whole path:
		// sysnet_netns_test.odin). Here we check only an idle but up interface.
		// IPv6 sends router solicitations or neighbor discovery only after an
		// address exists, so nothing waits.
		buf: [2048]u8
		_, rerr := read(&dev, buf[:])
		testing.expect(t, rerr == .Would_Block || rerr == .None)
	}
}
