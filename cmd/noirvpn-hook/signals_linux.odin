// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:intrinsics"
import "core:sys/linux"

// Stopping the runner with SIGINT or SIGTERM. The signals are blocked and
// read from a signalfd, so no handler runs. Call `stop_open` in `main`
// before any other thread starts: the nng threads inherit the blocked set.
// Only the reader thread calls these procs.

SIGINT :: 2
SIGTERM :: 15

@(private = "file")
SFD_NONBLOCK :: 0o4000
@(private = "file")
SFD_CLOEXEC :: 0o2000000

Stop :: struct {
	// Set by anyone to ask for a stop (a test uses this).
	flag:   bool,
	// Set by anyone to ask for the quick stop: kill the commands now.
	force:  bool,
	// The signal descriptor, or -1.
	sig_fd: i32,
	// How many signals were read.
	count:  int,
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

// Read the signals that arrived.
@(private = "file")
stop_poll :: proc(s: ^Stop) {
	if s.sig_fd < 0 {
		return
	}
	info: [128]u8 // struct signalfd_siginfo
	for {
		n, e := linux.read(linux.Fd(s.sig_fd), info[:])
		if e != .NONE || n != len(info) {
			return
		}
		s.count += 1
	}
}

// A stop was asked for: a signal, or the flag.
stop_requested :: proc(s: ^Stop) -> bool {
	stop_poll(s)
	return s.count >= 1 || intrinsics.atomic_load(&s.flag) || intrinsics.atomic_load(&s.force)
}

// A second signal, or the force flag: do not wait for the commands.
stop_forced :: proc(s: ^Stop) -> bool {
	stop_poll(s)
	return s.count >= 2 || intrinsics.atomic_load(&s.force)
}
