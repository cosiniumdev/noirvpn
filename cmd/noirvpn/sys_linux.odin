// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:sys/linux"
import "noir:bus"
import "noir:platform/event"

// The parts of the daemon that differ between Linux and Windows: log output, the
// terminal and what the event loop watches for the bus. Client engine parts:
// engine/sys_linux.odin. sys_windows.odin has the same procedures.

// Writes one log line to stderr.
log_write :: proc(line: []u8) {
	_, _ = linux.write(2, line)
}

// The daemon is up. A service manager on Windows hears of it (winsvc_windows.odin).
svc_note_running :: proc() {}

// ------------------------------------------------------------- event sources

// Watches the wake descriptor of the bus host.
bus_watch :: proc(loop: ^event.Loop, h: ^bus.Host, handler: event.Fd_Handler) -> event.Error {
	return event.add_fd(loop, bus.host_wake_fd(h), {.Read}, handler, nil)
}

// ------------------------------------------------------------------ terminal

// The kernel's `struct termios` (what TCGETS and TCSETS use).
@(private = "file")
Termios :: struct {
	iflag: u32,
	oflag: u32,
	cflag: u32,
	lflag: u32,
	line:  u8,
	cc:    [19]u8,
}

@(private = "file")
TCGETS :: 0x5401
@(private = "file")
TCSETS :: 0x5402
@(private = "file")
ECHO :: 0o10

tty_is :: proc(fd: i32) -> bool {
	t: Termios
	return linux.syscall(linux.SYS_ioctl, linux.Fd(fd), uint(TCGETS), &t) >= 0
}

// Writes `label` to stderr and reads one line from stdin into `out` (without the
// newline). With `echo` false the terminal does not show what is typed. Returns
// the length. `out` should be one byte longer than the longest value.
tty_prompt :: proc(label: string, echo: bool, out: []u8, abort_fd: i32) -> (n: int, ok: bool) {
	_, _ = linux.write(2, transmute([]u8)label)
	saved: Termios
	changed := false
	if !echo {
		if linux.syscall(linux.SYS_ioctl, linux.Fd(0), uint(TCGETS), &saved) >= 0 {
			t := saved
			t.lflag &~= ECHO
			if linux.syscall(linux.SYS_ioctl, linux.Fd(0), uint(TCSETS), &t) >= 0 {
				changed = true
			}
		}
	}
	line: [1]u8
	got_any := false
	for {
		if abort_fd >= 0 {
			fds := [2]linux.Poll_Fd{{fd = 0, events = {.IN}}, {fd = linux.Fd(abort_fd), events = {.IN}}}
			if _, perr := linux.poll(fds[:], -1); perr == .NONE && .IN in fds[1].revents {
				got_any = false
				break
			}
		}
		r, e := linux.read(0, line[:])
		if e == .EINTR {
			continue
		}
		if e != .NONE || r == 0 {
			break
		}
		got_any = true
		if line[0] == '\n' {
			break
		}
		if n < len(out) {
			out[n] = line[0]
			n += 1
		}
	}
	if changed {
		_ = linux.syscall(linux.SYS_ioctl, linux.Fd(0), uint(TCSETS), &saved)
		_, _ = linux.write(2, {'\n'})
	}
	if n > 0 && out[n - 1] == '\r' {
		n -= 1
	}
	return n, got_any
}
