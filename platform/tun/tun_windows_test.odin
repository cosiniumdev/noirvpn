// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package tun

import "core:log"
import "core:testing"

// These tests create a wintun adapter: they need an administrator token and
// wintun.dll next to the test program. Without them they log and pass.

@(private = "file")
open_or_skip :: proc(t: ^testing.T, name: string) -> (dev: Device, ok: bool) {
	err: Error
	dev, err = open({name = name})
	#partial switch err {
	case .None:
		return dev, true
	case .No_Device, .Permission:
		log.infof("skipped: no wintun.dll or no administrator token (%v)", err)
		return dev, false
	}
	testing.expect_value(t, err, Error.None)
	return dev, false
}

@(test)
adapter_guid_is_stable_and_marked :: proc(t: ^testing.T) {
	a := adapter_guid("noirvpn")
	b := adapter_guid("noirvpn")
	c := adapter_guid("noirvpn1")
	testing.expect(t, a == b, "the same name gives another GUID")
	testing.expect(t, a != c, "two names give the same GUID")
	testing.expect_value(t, a.Data3 >> 12, 5)
	testing.expect_value(t, a.Data4[0] & 0xC0, 0x80)
}

@(test)
bad_options_are_refused :: proc(t: ^testing.T) {
	_, err := open({multi_queue = true})
	testing.expect_value(t, err, Error.Unsupported)
	long: [IFNAMSIZ]u8
	for &c in long {
		c = 'a'
	}
	_, err = open({name = string(long[:])})
	testing.expect_value(t, err, Error.Invalid)
	_, err = open({name = "bad\nname"})
	testing.expect_value(t, err, Error.Invalid)
}

@(test)
closed_device_reports_closed :: proc(t: ^testing.T) {
	dev: Device
	buf: [64]u8
	_, err := read(&dev, buf[:])
	testing.expect_value(t, err, Error.Closed)
	testing.expect_value(t, write(&dev, buf[:]), Error.Closed)
	testing.expect(t, !is_open(&dev), "a zero Device is open")
	close(&dev)
}

@(test)
adapter_opens_with_luid_and_event :: proc(t: ^testing.T) {
	dev, ok := open_or_skip(t, "noirtest-tun0")
	if !ok {
		return
	}
	defer close(&dev)
	testing.expect(t, is_open(&dev), "not open")
	testing.expect_value(t, name(&dev), "noirtest-tun0")
	testing.expect(t, dev.luid != 0 && dev.ifindex != 0, "no LUID or index")
	testing.expect(t, dev.read_event != nil, "no read event")
	testing.expect(t, driver_version() != 0, "no driver version")

	// A second adapter with the same name is refused while the first lives.
	dup, derr := open({name = "noirtest-tun0"})
	if derr == .None {
		close(&dup)
	}
	testing.expect_value(t, derr, Error.Busy)

	big := make([]u8, MAX_PACKET + 1)
	defer delete(big)
	testing.expect_value(t, write(&dev, big), Error.Message_Too_Long)
	testing.expect_value(t, write(&dev, nil), Error.Invalid)
	buf: [256]u8
	_, rerr := read(&dev, buf[:])
	testing.expect(t, rerr == .Would_Block || rerr == .None, "read on a new adapter")
}
