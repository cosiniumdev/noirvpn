// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:encoding/hex"
import "core:encoding/json"
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

// Small deterministic PRNG (xorshift64*) so fuzz tests repeat exactly.
Rng :: struct {
	s: u64,
}

rng_next :: proc(r: ^Rng) -> u64 {
	r.s ~= r.s >> 12
	r.s ~= r.s << 25
	r.s ~= r.s >> 27
	return r.s * 0x2545F4914F6CDD1D
}

rng_below :: proc(r: ^Rng, n: int) -> int {
	return int(rng_next(r) % u64(n))
}

rng_fill :: proc(r: ^Rng, b: []u8) {
	for &x in b {
		x = u8(rng_next(r) >> 32)
	}
}

// Non-zero patterned random block for the encoder.
fake_random :: proc(n: int, seed: u8 = 1) -> []u8 {
	b := make([]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		b[i] = u8(i) * 7 + seed
		if b[i] == 0 {
			b[i] = 1
		}
	}
	return b
}

// ---- JSON access for the vector files ----

jget :: proc(v: json.Value, key: string) -> json.Value {
	o, ok := v.(json.Object)
	if !ok {
		return nil
	}
	return o[key] or_else nil
}

jstr :: proc(v: json.Value, key: string) -> string {
	s, _ := jget(v, key).(json.String)
	return string(s)
}

jint :: proc(v: json.Value, key: string) -> int {
	i, _ := jget(v, key).(json.Integer)
	return int(i)
}

jbool :: proc(v: json.Value, key: string) -> bool {
	b, _ := jget(v, key).(json.Boolean)
	return bool(b)
}

jarr :: proc(v: json.Value, key: string) -> json.Array {
	a, _ := jget(v, key).(json.Array)
	return a
}

// Parses a vector file. The caller destroys the value.
load_json :: proc(t: ^testing.T, data: []u8, loc := #caller_location) -> (root: json.Value, ok: bool) {
	v, err := json.parse(data, .JSON, true)
	if err != .None {
		testing.expectf(t, false, "vector file does not parse: %v", err, loc = loc)
		return nil, false
	}
	return v, true
}
