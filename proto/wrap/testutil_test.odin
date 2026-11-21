// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

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

// Key used by the spec's worked examples: byte i has the value i.
spec_key :: proc() -> Static_Key {
	k: Static_Key
	for i in 0 ..< STATIC_KEY_LEN {
		k.bytes[i] = u8(i)
	}
	return k
}

// Spec session id, wrap time and inner reset body.
SPEC_SID :: "0102030405060708"
SPEC_TIME :: 0x6553f100
SPEC_NOW :: 1700000000

// Static key file text for a key, as `--genkey` writes it.
static_key_text :: proc(k: ^Static_Key, upper := false) -> string {
	hexs := hex.encode(k.bytes[:], context.temp_allocator)
	b := make([dynamic]u8, context.temp_allocator)
	append(&b, "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(hexs); i += 32 {
		line := hexs[i:][:32]
		if upper {
			for c in line {
				append(&b, u8(c) - 32 if c >= 'a' && c <= 'f' else u8(c))
			}
		} else {
			append(&b, ..line)
		}
		append(&b, '\n')
	}
	append(&b, "-----END OpenVPN Static key V1-----\n")
	return string(b[:])
}
