// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:intrinsics"
import "core:sys/linux"

// Stopping `events` with SIGINT or SIGTERM. The signals are blocked and read
// from a signalfd, so no handler runs. Call `stop_open` before any other
// thread starts (the nng threads inherit the blocked set).

SIGINT :: 2
SIGTERM :: 15

@(private = "file")
SFD_NONBLOCK :: 0o4000
@(private = "file")
SFD_CLOEXEC :: 0o2000000

Stop :: struct {
	// Set by anyone to ask the loop to end (a test uses this).
	flag:   bool,
	// The signal descriptor, or -1.
	sig_fd: i32,
}

stop_init :: proc() -> Stop {
	return Stop{sig_fd = -1}
}

// Block SIGINT and SIGTERM and open the descriptor. The kernel's signal set is
// 8 bytes (the libc one is 128), so this calls the system calls directly.
stop_open :: proc(s: ^Stop) -> bool {
	mask: u64
	for sig in ([]int{SIGINT, SIGTERM}) {
		mask |= u64(1) << u64(sig - 1)
	}
	SIG_BLOCK :: 0
	if linux.syscall(linux.SYS_rt_sigprocmask, int(SIG_BLOCK), &mask, rawptr(nil), 8) < 0 {
		return false
	}
	r := linux.syscall(linux.SYS_signalfd4, int(-1), &mask, 8, int(SFD_NONBLOCK | SFD_CLOEXEC))
	if r < 0 {
		return false
	}
	s.sig_fd = i32(r)
	return true
}

stop_close :: proc(s: ^Stop) {
	if s.sig_fd >= 0 {
		linux.close(linux.Fd(s.sig_fd))
		s.sig_fd = -1
	}
}

stop_requested :: proc(s: ^Stop) -> bool {
	if intrinsics.atomic_load(&s.flag) {
		return true
	}
	if s.sig_fd >= 0 {
		fds := [1]linux.Poll_Fd{{fd = linux.Fd(s.sig_fd), events = {.IN}}}
		n, _ := linux.poll(fds[:], 0)
		return n > 0
	}
	return false
}
