// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:testing"
import "core:time"

// One line per source and reason per hold time; the held packets show in the
// next line of that source.
@(test)
first_log_holds_repeats :: proc(t: ^testing.T) {
	fl: First_Log
	a := []u8{1, 2, 3, 4}
	b := []u8{5, 6, 7, 8}
	now := time.Duration(1000) * time.Second

	_, ok := first_log_take(&fl, now, a, .Drop, .Decode)
	testing.expect(t, ok, "first line not written")
	for i in 1 ..= 5 {
		_, ok = first_log_take(&fl, now + time.Duration(i) * time.Second, a, .Drop, .Decode)
		testing.expect(t, !ok, "a repeat inside the hold time was written")
	}
	// Another reason or another source is a line of its own.
	_, ok = first_log_take(&fl, now, a, .Odd_Reset, .None)
	testing.expect(t, ok, "another note was held")
	_, ok = first_log_take(&fl, now, b, .Drop, .Decode)
	testing.expect(t, ok, "another source was held")

	held: int
	held, ok = first_log_take(&fl, now + FIRST_LOG_HOLD, a, .Drop, .Decode)
	testing.expect(t, ok, "no line after the hold time")
	testing.expect_value(t, held, 5)
}

// At most FIRST_LOG_MAX lines in a hold time, whatever the sources.
@(test)
first_log_caps_all_sources :: proc(t: ^testing.T) {
	fl: First_Log
	now := time.Duration(1000) * time.Second
	written := 0
	for i in 0 ..< FIRST_LOG_MAX * 2 {
		src := []u8{10, 0, u8(i >> 8), u8(i)}
		if _, ok := first_log_take(&fl, now, src, .Drop, .Unwrap); ok {
			written += 1
		}
	}
	testing.expect_value(t, written, FIRST_LOG_MAX)
	testing.expect_value(t, fl.held, FIRST_LOG_MAX)
	_, ok := first_log_take(&fl, now + FIRST_LOG_HOLD, []u8{11, 0, 0, 1}, .Drop, .Unwrap)
	testing.expect(t, ok, "the cap did not reset after the hold time")
	testing.expect_value(t, fl.held, 0)
}
