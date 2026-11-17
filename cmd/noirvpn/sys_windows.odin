// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import "core:os"
import win "core:sys/windows"
import "noir:bus"
import "noir:platform/event"

// The Windows forms of the procedures in sys_linux.odin. The parts of the
// client engine are in engine/sys_windows.odin.

// Writes one log line to stderr: the console, or the log file of the service
// (`svc_open_log` puts it in place of stderr).
log_write :: proc(line: []u8) {
	_, _ = os.write(os.stderr, line)
}

// ------------------------------------------------------------- event sources

@(private = "file")
bus_handler: event.Fd_Handler

// Watches the wake event of the bus host. It stays signaled while requests
// wait, so the loop comes back to them.
bus_watch :: proc(loop: ^event.Loop, h: ^bus.Host, handler: event.Fd_Handler) -> event.Error {
	bus_handler = handler
	return event.add_handle(loop, bus.host_wake_handle(h), on_bus_event, nil)
}

@(private = "file")
on_bus_event :: proc(loop: ^event.Loop, h: win.HANDLE, user: rawptr) {
	bus_handler(loop, -1, {.Read}, nil)
}

// ------------------------------------------------------------------ terminal

// True when the standard handle `fd` (0, 1 or 2) is a console.
tty_is :: proc(fd: i32) -> bool {
	which := [3]win.DWORD{win.STD_INPUT_HANDLE, win.STD_OUTPUT_HANDLE, win.STD_ERROR_HANDLE}
	if fd < 0 || fd > 2 || svc_mode {
		return false
	}
	mode: win.DWORD
	return bool(win.GetConsoleMode(win.GetStdHandle(which[fd]), &mode))
}

// Writes `label` to stderr and reads one line from the console into `out`
// (without the line end). With `echo` false the console does not show what is
// typed. Ctrl+C cancels the question. `abort_fd` has no use on Windows.
tty_prompt :: proc(label: string, echo: bool, out: []u8, abort_fd: i32) -> (n: int, ok: bool) {
	log_write(transmute([]u8)label)
	h := win.GetStdHandle(win.STD_INPUT_HANDLE)
	saved: win.DWORD
	changed := false
	if !echo && win.GetConsoleMode(h, &saved) {
		if win.SetConsoleMode(h, saved & ~win.ENABLE_ECHO_INPUT) {
			changed = true
		}
	}
	// Both buffers can hold a password: wiped at the end.
	wide: [256]u16
	buf: [1024]u8
	defer mem.zero_explicit(&wide, size_of(wide))
	defer mem.zero_explicit(&buf, size_of(buf))
	got_any := false
	done := false
	for !done {
		r: win.DWORD
		if !win.ReadConsoleW(h, &wide[0], u32(len(wide)), &r, nil) || sig_pending() {
			got_any = false
			break
		}
		if r == 0 {
			continue
		}
		got_any = true
		text := win.utf16_to_utf8(buf[:], wide[:r])
		for c in transmute([]u8)text {
			if c == '\n' {
				done = true
				break
			}
			if n < len(out) {
				out[n] = c
				n += 1
			}
		}
	}
	if changed {
		win.SetConsoleMode(h, saved)
		log_write({'\r', '\n'})
	}
	if n > 0 && out[n - 1] == '\r' {
		n -= 1
	}
	return n, got_any
}
