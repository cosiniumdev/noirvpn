// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:c"
import "core:sys/posix"
import "noir:platform/event"

foreign import libsystem "system:System"

@(default_calling_convention = "c")
foreign libsystem {
	// The address of the calling thread's errno.
	__error :: proc() -> ^c.int ---
}

// Signals reach the event loop through a pipe: a handler (nothing else) writes
// the signal number to the pipe, and the loop reads the numbers from the other
// end. macOS has no signalfd. kqueue could watch signals with EVFILT_SIGNAL, but
// the default action would still need turning off for each signal; a pipe works
// the same way as on the other systems.
//
// The numbers are those of <sys/signal.h> on macOS.

SIGHUP :: 1
SIGINT :: 2
SIGPIPE :: 13
SIGTERM :: 15
SIGUSR1 :: 30
SIGUSR2 :: 31

// The write end of the pipe, for the handler. -1 until `sig_open`.
@(private = "file")
sig_wr: posix.FD = -1

// Runs in signal context: no allocation, no Odin runtime, nothing but write(2).
@(private = "file")
sig_handler :: proc "c" (sig: posix.Signal) {
	b := [1]u8{u8(sig)}
	// The interrupted code may be about to read errno: put it back.
	saved := __error()^
	_ = posix.write(sig_wr, raw_data(b[:]), 1)
	__error()^ = saved
}

// Installs the handlers and returns the read end of the pipe. A write to a
// closed socket (SIGPIPE) is ignored: the call that failed reports it.
sig_open :: proc() -> (fd: i32, ok: bool) {
	fds: [2]posix.FD
	if posix.pipe(&fds) != .OK {
		return -1, false
	}
	for pfd in fds {
		fl := posix.fcntl(pfd, .GETFL)
		posix.fcntl(pfd, .SETFL, fl | posix.O_NONBLOCK)
		posix.fcntl(pfd, .SETFD, posix.FD_CLOEXEC)
	}
	sig_wr = fds[1]
	for sig in ([]int{SIGHUP, SIGINT, SIGUSR1, SIGUSR2, SIGTERM}) {
		act: posix.sigaction_t
		act.sa_handler = sig_handler
		act.sa_flags = {.RESTART}
		posix.sigemptyset(&act.sa_mask)
		if posix.sigaction(posix.Signal(sig), &act, nil) != .OK {
			posix.close(fds[0])
			posix.close(fds[1])
			sig_wr = -1
			return -1, false
		}
	}
	posix.signal(posix.Signal(SIGPIPE), auto_cast posix.SIG_IGN)
	return i32(fds[0]), true
}

// Puts the signal descriptor into the loop.
sig_watch :: proc(loop: ^event.Loop, fd: i32, handler: event.Fd_Handler, user: rawptr) -> event.Error {
	return event.add_fd(loop, fd, {.Read}, handler, user)
}

// The next pending signal number, or 0 if there is none.
sig_read :: proc(fd: i32) -> int {
	b: [1]u8
	for {
		n := posix.read(posix.FD(fd), raw_data(b[:]), 1)
		if n < 0 && posix.errno() == .EINTR {
			continue
		}
		if n != 1 {
			return 0
		}
		return int(b[0])
	}
}

// What the daemon says when `has_net_admin` is false.
PRIV_TEXT :: "root privileges are needed to create the utun interface and set routes (run noirvpn with sudo)"

// True if the process runs as root: a utun interface, ifconfig and route all
// need it.
has_net_admin :: proc() -> bool {
	return posix.geteuid() == 0
}
