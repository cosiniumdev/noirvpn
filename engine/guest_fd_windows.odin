// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "noir:platform/tun"

// TODO(engine): a tun descriptor of the host is not supported on Windows. The
// guest has no use there: the library is for phones and the Linux test host.
tun_from_fd :: proc(fd: i32) -> (dev: tun.Device, ok: bool) {
	return {}, false
}

tun_close_dev :: proc(dev: ^tun.Device) {
}

guest_close_fd :: proc(fd: i32) {
}
