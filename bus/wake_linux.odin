// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// The wake-up fd: readable when the control server has something for the
// daemon's loop. On Linux it is an eventfd.

import "core:sys/linux"

Wake :: struct {
	fd: linux.Fd,
}

wake_open :: proc(w: ^Wake) -> bool {
	fd, err := linux.eventfd(0, {.NONBLOCK, .CLOEXEC})
	if err != .NONE {
		w.fd = -1
		return false
	}
	w.fd = fd
	return true
}

wake_close :: proc(w: ^Wake) {
	if w.fd >= 0 {
		linux.close(w.fd)
		w.fd = -1
	}
}

// Set the fd readable. Any thread.
wake_signal :: proc(w: ^Wake) {
	one := u64(1)
	linux.write(w.fd, (cast([^]u8)&one)[:size_of(u64)])
}

// Set the fd not readable again.
wake_clear :: proc(w: ^Wake) {
	v: u64
	linux.read(w.fd, (cast([^]u8)&v)[:size_of(u64)])
}

// The descriptor to register with the event loop.
wake_fd :: proc(w: ^Wake) -> i32 {
	return i32(w.fd)
}

// The descriptor to watch for readability in the daemon's event loop.
host_wake_fd :: proc(h: ^Host) -> i32 {
	return wake_fd(&h.wake)
}
