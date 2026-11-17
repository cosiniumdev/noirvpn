// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package tun

import "core:sys/linux"
import "core:testing"

// Tests that need no privileges. The ones that create a real tun device are
// in tun_netns_test.odin and run only inside a throwaway network namespace.

@(test)
ioctl_numbers_match_the_headers :: proc(t: ^testing.T) {
	// Printed by a C program that includes <linux/if_tun.h>.
	testing.expect_value(t, TUNSETIFF, 0x400454ca)
	testing.expect_value(t, TUNGETIFF, 0x800454d2)
	testing.expect_value(t, TUNSETQUEUE, 0x400454d9)
	testing.expect_value(t, IFF_TUN, 0x1)
	testing.expect_value(t, IFF_NO_PI, 0x1000)
	testing.expect_value(t, IFF_MULTI_QUEUE, 0x100)
	testing.expect_value(t, SIOCSIFMTU, 0x8922)
}

@(test)
ifreq_layout :: proc(t: ^testing.T) {
	ifr: Ifreq
	copy(ifr.name[:], "tun0")
	ifr.flags = IFF_TUN | IFF_NO_PI
	raw := (^[40]u8)(&ifr)^
	testing.expect_value(t, raw[0], 't')
	testing.expect_value(t, raw[4], 0)
	// flags are at offset 16, host byte order (little-endian here)
	when ODIN_ENDIAN == .Little {
		testing.expect_value(t, raw[16], 0x01)
		testing.expect_value(t, raw[17], 0x10)
	}
	// mtu shares the same bytes
	ifr.value = 1400
	raw = (^[40]u8)(&ifr)^
	when ODIN_ENDIAN == .Little {
		testing.expect_value(t, raw[16], 0x78)
		testing.expect_value(t, raw[17], 0x05)
	}
}

@(test)
open_rejects_bad_names_before_touching_the_system :: proc(t: ^testing.T) {
	dev, err := open({name = "this-name-is-too-long"})
	testing.expect_value(t, err, Error.Invalid)
	testing.expect(t, !is_open(&dev))
	_, err = open({name = "a/b"})
	testing.expect_value(t, err, Error.Invalid)
	_, err = open({name = "a b"})
	testing.expect_value(t, err, Error.Invalid)
}

@(test)
open_without_privileges_reports_why :: proc(t: ^testing.T) {
	if linux.geteuid() == 0 {
		return // a privileged run would really create an interface
	}
	dev, err := open({name = "noirtst%d"})
	defer close(&dev)
	// No CAP_NET_ADMIN: EPERM, or the device node is missing (a container).
	// If this machine lets us create tun devices, that is fine too.
	testing.expect(t, err == .Permission || err == .No_Device || err == .None, "unexpected error")
}

@(test)
open_queue_needs_multi_queue :: proc(t: ^testing.T) {
	d := Device {
		fd = -1,
	}
	_, err := open_queue(&d)
	testing.expect_value(t, err, Error.Unsupported)
}

// A pipe stands in for the tun descriptor: read and write move whole chunks.
// This also shows a host-supplied descriptor being wrapped.
@(test)
from_fd_read_write_on_a_pipe :: proc(t: ^testing.T) {
	fds: [2]linux.Fd
	testing.expect_value(t, linux.pipe2(&fds, {.CLOEXEC}), linux.Errno.NONE)
	defer linux.close(fds[0])
	defer linux.close(fds[1])

	// Blocking pipe ends: from_fd switches them to non-blocking.
	rd, rerr := from_fd(i32(fds[0]))
	testing.expect_value(t, rerr, Error.None)
	wr, werr := from_fd(i32(fds[1]))
	testing.expect_value(t, werr, Error.None)
	testing.expect_value(t, name(&rd), "") // not a tun device: no name
	testing.expect(t, !rd.owned)

	buf: [64]u8
	_, err := read(&rd, buf[:])
	testing.expect_value(t, err, Error.Would_Block)

	pkt := [?]u8{0x45, 0, 0, 20, 1, 2, 3, 4}
	testing.expect_value(t, write(&wr, pkt[:]), Error.None)
	n: int
	n, err = read(&rd, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, len(pkt))
	testing.expect_value(t, buf[0], 0x45)

	// `close` of a descriptor we do not own leaves it open.
	close(&rd)
	testing.expect(t, !is_open(&rd))
	n2, e2 := linux.write(fds[1], pkt[:1])
	_ = n2
	testing.expect_value(t, e2, linux.Errno.NONE)
}

@(test)
from_fd_owned_is_closed :: proc(t: ^testing.T) {
	fds: [2]linux.Fd
	linux.pipe2(&fds, {.CLOEXEC})
	defer linux.close(fds[1])
	dev, err := from_fd(i32(fds[0]), true, true)
	testing.expect_value(t, err, Error.None)
	// One byte waits in the pipe: a read on the open descriptor would give it.
	marker := [1]u8{0x5a}
	_, we := linux.write(fds[1], marker[:])
	testing.expect_value(t, we, linux.Errno.NONE)
	close(&dev)
	testing.expect(t, !is_open(&dev))
	// The descriptor is gone: reading its number gives EBADF, or, if another
	// test thread already got the same number for a new file, anything but our
	// byte. (Tests run on several threads and the number may be reused at
	// once. Only the byte tells our pipe from a new file.)
	buf: [4]u8
	n, e := linux.read(fds[0], buf[:])
	testing.expect(t, e == .EBADF || n != 1 || buf[0] != 0x5a, "the owned descriptor is still open")
}

@(test)
from_fd_blocking_mode_is_kept :: proc(t: ^testing.T) {
	fds: [2]linux.Fd
	linux.pipe2(&fds, {.CLOEXEC})
	defer linux.close(fds[0])
	defer linux.close(fds[1])
	dev, err := from_fd(i32(fds[0]), false)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, dev.blocking)
	flags, _ := linux.fcntl_getfl(fds[0], .GETFL)
	testing.expect(t, .NONBLOCK not_in flags)

	_, err = from_fd(-1)
	testing.expect_value(t, err, Error.Closed)
}

@(test)
errno_mapping :: proc(t: ^testing.T) {
	testing.expect_value(t, map_errno(.EPERM), Error.Permission)
	testing.expect_value(t, map_errno(.ENOENT), Error.No_Device)
	testing.expect_value(t, map_errno(.EBUSY), Error.Busy)
	testing.expect_value(t, map_errno(.EAGAIN), Error.Would_Block)
	testing.expect_value(t, map_errno(.EIO), Error.Io)
	testing.expect_value(t, map_errno(.ENOTTY), Error.Unsupported)
	testing.expect_value(t, map_errno(.EXDEV), Error.Other)
}

@(test)
mtu_needs_a_name :: proc(t: ^testing.T) {
	d := Device {
		fd = 5,
	}
	testing.expect_value(t, set_mtu(&d, 1400), Error.Unsupported)
	_, err := get_mtu(&d)
	testing.expect_value(t, err, Error.Unsupported)
}
