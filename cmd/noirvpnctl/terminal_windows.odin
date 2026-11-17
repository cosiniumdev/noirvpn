// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import win "core:sys/windows"

// Reading a secret from the console without showing it, and the standard
// handles. A descriptor number is 0, 1 or 2 for standard input, output and error.

@(private = "file")
std_handle :: proc(fd: i32) -> win.HANDLE {
	switch fd {
	case 0:
		return win.GetStdHandle(win.STD_INPUT_HANDLE)
	case 1:
		return win.GetStdHandle(win.STD_OUTPUT_HANDLE)
	}
	return win.GetStdHandle(win.STD_ERROR_HANDLE)
}

fd_write :: proc(fd: i32, data: []u8) -> (n: int, ok: bool) {
	done: u32
	if win.WriteFile(std_handle(fd), raw_data(data), u32(min(len(data), 1 << 30)), &done, nil) == win.FALSE {
		return 0, false
	}
	return int(done), true
}

// 0 bytes is the end. A closed pipe on standard input is the end too.
fd_read :: proc(fd: i32, buf: []u8) -> (n: int, ok: bool) {
	got: u32
	if win.ReadFile(std_handle(fd), raw_data(buf), u32(len(buf)), &got, nil) == win.FALSE {
		e := win.GetLastError()
		return 0, e == win.ERROR_BROKEN_PIPE || e == win.ERROR_HANDLE_EOF
	}
	return int(got), true
}

tty_is :: proc(fd: i32) -> bool {
	mode: u32
	return win.GetConsoleMode(std_handle(fd), &mode) != win.FALSE
}

@(private = "file")
ENABLE_ECHO_INPUT :: 0x0004

// Ask for one line on the console. The label goes to standard error; typed text
// is not shown. The line is returned without its line end in `buf` (at most
// `len(buf)` bytes; `too_long` says more was typed).
tty_read_secret :: proc(label: string, buf: []u8) -> (n: int, too_long: bool, ok: bool) {
	fd_write(2, transmute([]u8)label)
	in_h := std_handle(0)
	saved: u32
	changed := false
	if win.GetConsoleMode(in_h, &saved) != win.FALSE {
		if win.SetConsoleMode(in_h, saved &~ ENABLE_ECHO_INPUT) != win.FALSE {
			changed = true
		}
	}
	one: [1]u8
	got_any := false
	for {
		r, rok := fd_read(0, one[:])
		if !rok || r == 0 {
			break
		}
		got_any = true
		if one[0] == '\n' {
			break
		}
		if n < len(buf) {
			buf[n] = one[0]
			n += 1
		} else {
			too_long = true
		}
	}
	mem.zero_explicit(&one, size_of(one))
	if changed {
		win.SetConsoleMode(in_h, saved)
		fd_write(2, {'\n'})
	}
	if n > 0 && buf[n - 1] == '\r' {
		n -= 1
	}
	return n, too_long, got_any
}
