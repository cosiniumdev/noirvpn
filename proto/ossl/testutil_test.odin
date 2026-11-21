// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:encoding/hex"
import "core:testing"

// Decodes a hex string into temp memory. Spaces and newlines are skipped.
unhex :: proc(s: string) -> []u8 {
	clean := make([dynamic]u8, 0, len(s), context.temp_allocator)
	for c in transmute([]u8)s {
		if c != ' ' && c != '\n' && c != '\t' {
			append(&clean, c)
		}
	}
	// A full length means the decode worked, on every Odin version.
	b, _ := hex.decode(clean[:], context.temp_allocator)
	assert(len(b) * 2 == len(clean), "bad hex in test")
	return b
}

// Checks two byte slices are equal and prints both as hex if not.
expect_bytes :: proc(t: ^testing.T, got, want: []u8, what: string, loc := #caller_location) -> bool {
	ok := len(got) == len(want)
	if ok {
		for i in 0 ..< len(got) {
			if got[i] != want[i] {
				ok = false
				break
			}
		}
	}
	if !ok {
		g := hex.encode(got, context.temp_allocator)
		w := hex.encode(want, context.temp_allocator)
		testing.expectf(t, false, "%s:\n  got  %s\n  want %s", what, string(g), string(w), loc = loc)
	}
	return ok
}
