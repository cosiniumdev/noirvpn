// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import "core:sys/linux"

// Reading a secret from the terminal without showing it, and the standard
// descriptors.

// Write to a descriptor; an interrupted call is repeated. `ok` is false on an
// error.
fd_write :: proc(fd: i32, data: []u8) -> (n: int, ok: bool) {
	for {
		w, e := linux.write(linux.Fd(fd), data)
		if e == .EINTR {
			continue
		}
		return w, e == .NONE
	}
}

// Read from a descriptor; 0 bytes is the end. An interrupted call is repeated.
fd_read :: proc(fd: i32, buf: []u8) -> (n: int, ok: bool) {
	for {
		r, e := linux.read(linux.Fd(fd), buf)
		if e == .EINTR {
			continue
		}
		return r, e == .NONE
	}
}

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

// Ask for one line on the terminal (stdin). The label goes to stderr and
// what is typed is not shown. The line is returned without its newline, in
// `buf` (it holds at most `len(buf)` bytes; `too_long` says more was typed).
tty_read_secret :: proc(label: string, buf: []u8) -> (n: int, too_long: bool, ok: bool) {
	_, _ = linux.write(2, transmute([]u8)label)
	saved: Termios
	changed := false
	if linux.syscall(linux.SYS_ioctl, linux.Fd(0), uint(TCGETS), &saved) >= 0 {
		t := saved
		t.lflag &~= ECHO
		if linux.syscall(linux.SYS_ioctl, linux.Fd(0), uint(TCSETS), &t) >= 0 {
			changed = true
		}
	}
	one: [1]u8
	got_any := false
	for {
		r, e := linux.read(0, one[:])
		if e == .EINTR {
			continue
		}
		if e != .NONE || r == 0 {
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
		_ = linux.syscall(linux.SYS_ioctl, linux.Fd(0), uint(TCSETS), &saved)
		_, _ = linux.write(2, {'\n'})
	}
	if n > 0 && buf[n - 1] == '\r' {
		n -= 1
	}
	return n, too_long, got_any
}
