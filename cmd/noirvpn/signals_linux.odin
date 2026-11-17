// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:sys/linux"
import "noir:platform/event"

// Signals come through a signalfd in the event loop. They are blocked for the
// whole process, so no handler ever runs. (A child process started later, such
// as `resolvectl`, inherits the blocked set; that is harmless for it.)

SIGHUP :: 1
SIGINT :: 2
SIGUSR1 :: 10
SIGUSR2 :: 12
SIGPIPE :: 13
SIGTERM :: 15

@(private = "file")
SFD_NONBLOCK :: 0o4000
@(private = "file")
SFD_CLOEXEC :: 0o2000000

// `struct signalfd_siginfo` is 128 bytes; the first field is the number.
Sig_Info :: struct {
	signo: u32,
	rest:  [124]u8,
}
#assert(size_of(Sig_Info) == 128)

// Blocks the signals and returns the descriptor. The kernel's signal set is
// 8 bytes (the libc one is 128), so this calls the system calls directly.
sig_open :: proc() -> (fd: i32, ok: bool) {
	mask: u64
	for sig in ([]int{SIGHUP, SIGINT, SIGUSR1, SIGUSR2, SIGPIPE, SIGTERM}) {
		mask |= u64(1) << u64(sig - 1)
	}
	SIG_BLOCK :: 0
	if linux.syscall(linux.SYS_rt_sigprocmask, int(SIG_BLOCK), &mask, rawptr(nil), 8) < 0 {
		return -1, false
	}
	r := linux.syscall(linux.SYS_signalfd4, int(-1), &mask, 8, int(SFD_NONBLOCK | SFD_CLOEXEC))
	if r < 0 {
		return -1, false
	}
	return i32(r), true
}

// Puts the signal descriptor into the loop.
sig_watch :: proc(loop: ^event.Loop, fd: i32, handler: event.Fd_Handler, user: rawptr) -> event.Error {
	return event.add_fd(loop, fd, {.Read}, handler, user)
}

// The next pending signal number, or 0 if there is none.
sig_read :: proc(fd: i32) -> int {
	info: Sig_Info
	n, e := linux.read(linux.Fd(fd), (cast([^]u8)&info)[:size_of(Sig_Info)])
	if e != .NONE || n != size_of(Sig_Info) {
		return 0
	}
	return int(info.signo)
}

// What the daemon says when `has_net_admin` is false.
PRIV_TEXT :: "CAP_NET_ADMIN is needed to create the tunnel and set routes (run noirvpn as root, or grant it the capability)"

// True if the process holds CAP_NET_ADMIN (effective). If the kernel cannot
// say, assume yes: the real calls report the error.
has_net_admin :: proc() -> bool {
	Header :: struct {
		version: u32,
		pid:     i32,
	}
	Data :: struct {
		effective:   u32,
		permitted:   u32,
		inheritable: u32,
	}
	CAP_V3 :: 0x20080522
	CAP_NET_ADMIN :: 12
	hdr := Header {
		version = CAP_V3,
	}
	data: [2]Data
	if linux.syscall(linux.SYS_capget, &hdr, &data) < 0 {
		return true
	}
	return data[0].effective & (1 << CAP_NET_ADMIN) != 0
}
