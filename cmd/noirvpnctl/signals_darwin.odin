// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:intrinsics"
import "core:c"
import "core:sys/posix"

// Stopping `events` with SIGINT or SIGTERM. A handler (it does nothing else)
// writes to a pipe, and `stop_requested` polls the other end. macOS has no
// signalfd. Call `stop_open` once, before the loop starts.

SIGINT :: 2
SIGTERM :: 15

foreign import libsystem "system:System"

@(default_calling_convention = "c")
foreign libsystem {
	// The address of the calling thread's errno.
	__error :: proc() -> ^c.int ---
}

// The write end of the pipe, for the handler. -1 until `stop_open`.
@(private = "file")
stop_wr: posix.FD = -1

Stop :: struct {
	// Set by anyone to ask the loop to end (a test uses this).
	flag:   bool,
	// The read end of the signal pipe, or -1.
	sig_fd: i32,
}

stop_init :: proc() -> Stop {
	return Stop{sig_fd = -1}
}

// Runs in signal context: nothing but write(2).
@(private = "file")
stop_handler :: proc "c" (sig: posix.Signal) {
	b := [1]u8{u8(sig)}
	saved := __error()^
	_ = posix.write(stop_wr, raw_data(b[:]), 1)
	__error()^ = saved
}

// Open the pipe and install the handlers.
stop_open :: proc(s: ^Stop) -> bool {
	fds: [2]posix.FD
	if posix.pipe(&fds) != .OK {
		return false
	}
	for pfd in fds {
		fl := posix.fcntl(pfd, .GETFL)
		posix.fcntl(pfd, .SETFL, fl | posix.O_NONBLOCK)
		posix.fcntl(pfd, .SETFD, posix.FD_CLOEXEC)
	}
	stop_wr = fds[1]
	for sig in ([]int{SIGINT, SIGTERM}) {
		act: posix.sigaction_t
		act.sa_handler = stop_handler
		act.sa_flags = {.RESTART}
		posix.sigemptyset(&act.sa_mask)
		if posix.sigaction(posix.Signal(sig), &act, nil) != .OK {
			posix.close(fds[0])
			posix.close(fds[1])
			stop_wr = -1
			return false
		}
	}
	s.sig_fd = i32(fds[0])
	return true
}

stop_close :: proc(s: ^Stop) {
	if s.sig_fd >= 0 {
		posix.close(posix.FD(s.sig_fd))
		s.sig_fd = -1
	}
	if stop_wr >= 0 {
		posix.close(stop_wr)
		stop_wr = -1
	}
}

stop_requested :: proc(s: ^Stop) -> bool {
	if intrinsics.atomic_load(&s.flag) {
		return true
	}
	if s.sig_fd >= 0 {
		fds := [1]posix.pollfd{{fd = posix.FD(s.sig_fd), events = {.IN}}}
		return posix.poll(raw_data(fds[:]), 1, 0) > 0
	}
	return false
}
