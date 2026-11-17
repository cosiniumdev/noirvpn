// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:sys/posix"
import "noir:bus"
import "noir:platform/event"

// The parts of the daemon that differ between systems: log output, the terminal
// and what the event loop watches for the bus. Client engine parts:
// engine/sys_darwin.odin. sys_linux.odin and sys_windows.odin have the same
// procedures. This is the macOS version (descriptors watched with kqueue).

// Writes one log line to stderr.
log_write :: proc(line: []u8) {
	_ = posix.write(2, raw_data(line), uint(len(line)))
}

// The daemon is up. A service manager on Windows hears of it (winsvc_windows.odin).
svc_note_running :: proc() {}

// ------------------------------------------------------------- event sources

// Watches the wake descriptor of the bus host (the read end of a pipe).
bus_watch :: proc(loop: ^event.Loop, h: ^bus.Host, handler: event.Fd_Handler) -> event.Error {
	return event.add_fd(loop, bus.host_wake_fd(h), {.Read}, handler, nil)
}

// ------------------------------------------------------------------ terminal

tty_is :: proc(fd: i32) -> bool {
	return bool(posix.isatty(posix.FD(fd)))
}

// Writes `label` to stderr and reads one line from stdin into `out` (without the
// newline). With `echo` false the terminal does not show what is typed. Returns
// the length. `out` should be one byte longer than the longest value.
// `abort_fd` becomes readable when the question must stop (a stop signal): the
// call then returns with `ok` false.
tty_prompt :: proc(label: string, echo: bool, out: []u8, abort_fd: i32) -> (n: int, ok: bool) {
	_ = posix.write(2, raw_data(transmute([]u8)label), uint(len(label)))
	saved: posix.termios
	changed := false
	if !echo {
		if posix.tcgetattr(0, &saved) == .OK {
			t := saved
			t.c_lflag -= {.ECHO}
			if posix.tcsetattr(0, .TCSANOW, &t) == .OK {
				changed = true
			}
		}
	}
	line: [1]u8
	got_any := false
	for {
		if abort_fd >= 0 {
			fds := [2]posix.pollfd{{fd = 0, events = {.IN}}, {fd = posix.FD(abort_fd), events = {.IN}}}
			if posix.poll(raw_data(fds[:]), 2, -1) > 0 && .IN in fds[1].revents {
				got_any = false
				break
			}
		}
		r := posix.read(0, raw_data(line[:]), 1)
		if r < 0 && posix.errno() == .EINTR {
			continue
		}
		if r <= 0 {
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
		_ = posix.tcsetattr(0, .TCSANOW, &saved)
		nl := [1]u8{'\n'}
		_ = posix.write(2, raw_data(nl[:]), 1)
	}
	if n > 0 && out[n - 1] == '\r' {
		n -= 1
	}
	return n, got_any
}
