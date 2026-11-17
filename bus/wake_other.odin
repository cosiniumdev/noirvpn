// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin, freebsd, openbsd, netbsd
package bus

// The wake-up fd on systems without eventfd: the read end of a pipe. Tested on
// macOS (the daemon's kqueue loop watches it).

import "core:sys/posix"

Wake :: struct {
	rd, wr: posix.FD,
}

wake_open :: proc(w: ^Wake) -> bool {
	fds: [2]posix.FD
	if posix.pipe(&fds) != .OK {
		return false
	}
	for fd in fds {
		fl := posix.fcntl(fd, .GETFL)
		posix.fcntl(fd, .SETFL, fl | posix.O_NONBLOCK)
		posix.fcntl(fd, .SETFD, posix.FD_CLOEXEC)
	}
	w.rd, w.wr = fds[0], fds[1]
	return true
}

wake_close :: proc(w: ^Wake) {
	posix.close(w.rd)
	posix.close(w.wr)
	w^ = {-1, -1}
}

wake_signal :: proc(w: ^Wake) {
	b := [1]u8{1}
	posix.write(w.wr, raw_data(b[:]), 1)
}

wake_clear :: proc(w: ^Wake) {
	buf: [64]u8
	for posix.read(w.rd, raw_data(buf[:]), len(buf)) == len(buf) {
	}
}

wake_fd :: proc(w: ^Wake) -> i32 {
	return i32(w.rd)
}

// The descriptor to watch for readability in the daemon's event loop.
host_wake_fd :: proc(h: ^Host) -> i32 {
	return wake_fd(&h.wake)
}
