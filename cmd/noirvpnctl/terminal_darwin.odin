// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import "core:sys/posix"

// Reading a secret from the terminal without showing it, and the standard
// descriptors. The macOS version of terminal_linux.odin.

// Write to a descriptor; an interrupted call is repeated. `ok` is false on an
// error.
fd_write :: proc(fd: i32, data: []u8) -> (n: int, ok: bool) {
	for {
		w := posix.write(posix.FD(fd), raw_data(data), uint(len(data)))
		if w < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			return 0, false
		}
		return int(w), true
	}
}

// Read from a descriptor; 0 bytes is the end. An interrupted call is repeated.
fd_read :: proc(fd: i32, buf: []u8) -> (n: int, ok: bool) {
	for {
		r := posix.read(posix.FD(fd), raw_data(buf), uint(len(buf)))
		if r < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			return 0, false
		}
		return int(r), true
	}
}

tty_is :: proc(fd: i32) -> bool {
	return bool(posix.isatty(posix.FD(fd)))
}

// Ask for one line on the terminal (stdin). The label goes to stderr and
// what is typed is not shown. The line is returned without its newline, in
// `buf` (it holds at most `len(buf)` bytes; `too_long` says more was typed).
tty_read_secret :: proc(label: string, buf: []u8) -> (n: int, too_long: bool, ok: bool) {
	_ = posix.write(2, raw_data(transmute([]u8)label), uint(len(label)))
	saved: posix.termios
	changed := false
	if posix.tcgetattr(0, &saved) == .OK {
		t := saved
		t.c_lflag -= {.ECHO}
		if posix.tcsetattr(0, .TCSANOW, &t) == .OK {
			changed = true
		}
	}
	one: [1]u8
	got_any := false
	for {
		r := posix.read(0, raw_data(one[:]), 1)
		if r < 0 && posix.errno() == .EINTR {
			continue
		}
		if r <= 0 {
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
		_ = posix.tcsetattr(0, .TCSANOW, &saved)
		nl := [1]u8{'\n'}
		_ = posix.write(2, raw_data(nl[:]), 1)
	}
	if n > 0 && buf[n - 1] == '\r' {
		n -= 1
	}
	return n, too_long, got_any
}
