// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:strings"

// Where the output goes: a file descriptor, or (in tests) a builder.
Sink :: struct {
	fd:  i32,
	buf: ^strings.Builder,
}

// The streams of one run. A test sets `buf` on the sinks and `stdin_set`.
Io :: struct {
	out:        Sink,
	err:        Sink,
	// Standard input for --password-stdin and --response-stdin, when a test
	// supplies it. Otherwise the real standard input is read.
	stdin_text: string,
	stdin_set:  bool,
}

sink_write :: proc(s: Sink, text: string) {
	if s.buf != nil {
		strings.write_string(s.buf, text)
		return
	}
	data := transmute([]u8)text
	for len(data) > 0 {
		n, ok := fd_write(s.fd, data)
		if !ok {
			return
		}
		data = data[n:]
	}
}

out_text :: proc(io: ^Io, text: string) {
	sink_write(io.out, text)
}

// A line on stderr, `noirvpnctl: ...`.
err_line :: proc(io: ^Io, format: string, args: ..any) {
	sink_write(io.err, "noirvpnctl: ")
	sink_write(io.err, fmt.tprintf(format, ..args))
	sink_write(io.err, "\n")
}

// A note on stderr, `noirvpnctl: note: ...`.
note_line :: proc(io: ^Io, format: string, args: ..any) {
	sink_write(io.err, "noirvpnctl: note: ")
	sink_write(io.err, fmt.tprintf(format, ..args))
	sink_write(io.err, "\n")
}
