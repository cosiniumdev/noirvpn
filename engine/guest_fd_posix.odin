// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin
package engine

import "core:sys/posix"
import "noir:platform/tun"

// The tun descriptor of the host. The engine owns it from here and closes it.
tun_from_fd :: proc(fd: i32) -> (dev: tun.Device, ok: bool) {
	d, err := tun.from_fd(fd, true, true)
	if err != .None || d.vnet {
		// A descriptor with the virtio header is not what the host promised.
		if err == .None {
			tun.close(&d)
		}
		return {}, false
	}
	return d, true
}

tun_close_dev :: proc(dev: ^tun.Device) {
	tun.close(dev)
}

guest_close_fd :: proc(fd: i32) {
	if fd >= 0 {
		posix.close(posix.FD(fd))
	}
}
