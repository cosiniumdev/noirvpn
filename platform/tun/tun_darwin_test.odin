// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package tun

import "core:log"
import "core:sys/posix"
import "core:testing"

// Tests that need no privileges, and one that creates a real utun interface
// when the tests run as root (it logs and passes otherwise).

@(test)
constants_match_the_headers :: proc(t: ^testing.T) {
	// Printed by a C program that includes <sys/kern_control.h> and <net/if_utun.h>.
	testing.expect_value(t, CTLIOCGINFO, 0xc0644e03)
	testing.expect_value(t, PF_SYSTEM, 32)
	testing.expect_value(t, AF_SYSTEM, 32)
	testing.expect_value(t, SYSPROTO_CONTROL, 2)
	testing.expect_value(t, AF_SYS_CONTROL, 2)
	testing.expect_value(t, UTUN_OPT_IFNAME, 2)
	testing.expect_value(t, AF_INET6, 30)
	testing.expect_value(t, size_of(Ctl_Info), 100)
	testing.expect_value(t, size_of(Sockaddr_Ctl), 32)
}

@(test)
names_give_units :: proc(t: ^testing.T) {
	u, ok := unit_of_name("")
	testing.expect(t, ok)
	testing.expect_value(t, u, 0)
	u, ok = unit_of_name("utun0")
	testing.expect(t, ok)
	testing.expect_value(t, u, 1)
	u, ok = unit_of_name("utun12")
	testing.expect(t, ok)
	testing.expect_value(t, u, 13)
	for bad in ([]string{"utun", "utun01", "utunx", "tun0", "utun1x", "utun1234567", "noir0", "utun-1"}) {
		_, ok = unit_of_name(bad)
		testing.expectf(t, !ok, "%q should be refused", bad)
	}
	testing.expect(t, is_utun_name("utun3"))
	testing.expect(t, !is_utun_name(""))
	testing.expect(t, !is_utun_name("tun"))
}

@(test)
open_refuses_what_utun_cannot_do :: proc(t: ^testing.T) {
	_, err := open({name = "noir0"})
	testing.expect_value(t, err, Error.Invalid)
	_, err = open({name = "utun0", multi_queue = true})
	testing.expect_value(t, err, Error.Unsupported)
}

@(test)
family_header_follows_the_ip_version :: proc(t: ^testing.T) {
	h, ok := af_header({0x45, 0, 0, 20})
	testing.expect(t, ok)
	testing.expect_value(t, h, [4]u8{0, 0, 0, 2})
	h, ok = af_header({0x60, 0, 0, 0})
	testing.expect(t, ok)
	testing.expect_value(t, h, [4]u8{0, 0, 0, 30})
	_, ok = af_header({0x20})
	testing.expect(t, !ok)
	_, ok = af_header({})
	testing.expect(t, !ok)
}

@(test)
write_checks_the_packet_before_the_system :: proc(t: ^testing.T) {
	dev := Device {
		fd = -1,
	}
	testing.expect_value(t, write(&dev, {0x45}), Error.Closed)
	dev.fd = 0 // not touched: the packet is refused first
	testing.expect_value(t, write(&dev, {0x20, 1, 2}), Error.Invalid)
	testing.expect_value(t, write(&dev, {}), Error.Invalid)
	testing.expect_value(t, write_v(&dev, nil), Error.Invalid)
}

@(test)
open_without_root_reports_why :: proc(t: ^testing.T) {
	if posix.geteuid() == 0 {
		return // a privileged run creates an interface: see the next test
	}
	dev, err := open()
	testing.expect_value(t, err, Error.Permission)
	testing.expect(t, !is_open(&dev))
}

@(test)
real_utun_round_trip :: proc(t: ^testing.T) {
	if posix.geteuid() != 0 {
		log.info("skipped: creating a utun interface needs root")
		return
	}
	dev, err := open()
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(&dev)
	testing.expect(t, is_open(&dev))
	testing.expect(t, is_utun_name(name(&dev)), "the kernel gave a name that is not utunN")

	// Nothing waits yet.
	buf: [2048]u8
	_, rerr := read(&dev, buf[:])
	testing.expect_value(t, rerr, Error.Would_Block)

	// A second device with the same unit is busy.
	_, berr := open({name = name(&dev)})
	testing.expect_value(t, berr, Error.Busy)

	// A packet for the host's stack: a UDP datagram to an address nobody
	// replies for. The header is added and the whole packet is taken. Not run
	// as root yet: if the system refuses a packet on an interface with no
	// address, the error is logged and the test goes on.
	pkt := [28]u8 {
		0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 99, 0, 1, 10, 99, 0, 2,
		0, 9, 0, 9, 0, 8, 0, 0,
	}
	if werr := write(&dev, pkt[:]); werr != .None {
		log.infof("write on an interface with no address: %v", werr)
	}
}
