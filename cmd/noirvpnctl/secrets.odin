// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"

// Read a secret for `auth-supply`: the first line of standard input (asked at the
// terminal, not shown, if it is one) or of a file. The text is allocated; wipe
// and free it with `secret_destroy`. `err` is "" on success. `bad_value` marks a
// bad secret (empty, too long: a usage error), not a source that could not be read.
read_secret :: proc(src: Secret_Source, path, what: string, io: ^Io) -> (text: string, err: string, bad_value: bool) {
	raw: []u8
	defer if raw != nil {
		mem.zero_explicit(raw_data(raw), len(raw))
		delete(raw)
	}
	switch src {
	case .None:
		return "", "", false
	case .Stdin:
		switch {
		case io.stdin_set:
			raw = make([]u8, len(io.stdin_text))
			copy(raw, io.stdin_text)
		case tty_is(0):
			buf: [SUPPLY_MAX + 2]u8
			defer mem.zero_explicit(&buf, size_of(buf))
			n, too_long, ok := tty_read_secret(strings.concatenate({what, ": "}, context.temp_allocator), buf[:SUPPLY_MAX])
			if !ok {
				return "", fmt.tprintf("could not read the %s from the terminal", what), false
			}
			if too_long {
				return "", too_long_text(what), true
			}
			raw = make([]u8, n)
			copy(raw, buf[:n])
		case:
			data, ok := read_fd(0, 4096)
			if !ok {
				return "", fmt.tprintf("could not read the %s from standard input", what), false
			}
			raw = data
		}
	case .File:
		data, rerr := os.read_entire_file(path, context.allocator)
		if rerr != nil {
			return "", fmt.tprintf("cannot read the %s file '%s'", what, path), false
		}
		raw = data
	}
	line := raw
	if i := index_byte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if len(line) > 0 && line[len(line) - 1] == '\r' {
		line = line[:len(line) - 1]
	}
	if len(line) == 0 {
		return "", fmt.tprintf("the %s is empty", what), true
	}
	if len(line) > SUPPLY_MAX {
		return "", too_long_text(what), true
	}
	out := make([]u8, len(line))
	copy(out, line)
	return string(out), "", false
}

@(private = "file")
too_long_text :: proc(what: string) -> string {
	return fmt.tprintf("the %s cannot be longer than %d bytes", what, SUPPLY_MAX)
}

@(private = "file")
index_byte :: proc(b: []u8, c: u8) -> int {
	for x, i in b {
		if x == c {
			return i
		}
	}
	return -1
}

// Read a descriptor to the end, but at most `limit` bytes.
@(private = "file")
read_fd :: proc(fd: i32, limit: int) -> (data: []u8, ok: bool) {
	buf := make([dynamic]u8)
	tmp: [512]u8
	defer mem.zero_explicit(&tmp, size_of(tmp))
	for len(buf) < limit {
		n, rok := fd_read(fd, tmp[:])
		if !rok {
			mem.zero_explicit(raw_data(buf[:]), len(buf))
			delete(buf)
			return nil, false
		}
		if n == 0 {
			break
		}
		append(&buf, ..tmp[:n])
	}
	return buf[:], true
}

secret_destroy :: proc(s: ^string) {
	if len(s^) > 0 {
		mem.zero_explicit(raw_data(s^), len(s^))
		delete(s^)
	}
	s^ = ""
}
