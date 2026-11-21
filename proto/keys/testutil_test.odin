// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:encoding/hex"
import "core:encoding/json"
import "core:testing"
import "noir:proto/ossl"

// Real captures from stock OpenVPN 2.6.23 and 2.7.7 (proto/testdata/vectors/).
DATA_CHANNEL_JSON :: #load("../testdata/vectors/data-channel.json")
TLS_EXPORTER_JSON :: #load("../testdata/vectors/tls-exporter.json")

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

// Parses a vector file. The result lives in temp memory.
load_json :: proc(t: ^testing.T, data: []u8) -> json.Object {
	v, err := json.parse(data, allocator = context.temp_allocator)
	testing.expect_value(t, err, json.Error.None)
	obj, ok := v.(json.Object)
	testing.expect(t, ok, "vector file is not a JSON object")
	return obj
}

// The `cases` array of a vector file.
json_cases :: proc(t: ^testing.T, root: json.Object) -> json.Array {
	arr, ok := root["cases"].(json.Array)
	testing.expect(t, ok, "no cases array")
	return arr
}

// A string field, or "" if it is missing.
jstr :: proc(o: json.Object, key: string) -> string {
	s, _ := o[key].(json.String)
	return string(s)
}

// A nested object, or an empty one.
jobj :: proc(o: json.Object, key: string) -> json.Object {
	v, _ := o[key].(json.Object)
	return v
}

// A hex field, decoded.
jhex :: proc(o: json.Object, key: string) -> []u8 {
	return unhex(jstr(o, key))
}

// Cipher name as the vector files write it.
cipher_from_name :: proc(name: string) -> (c: ossl.Aead_Cipher, ok: bool) {
	switch name {
	case "AES-128-GCM":
		return .AES_128_GCM, true
	case "AES-256-GCM":
		return .AES_256_GCM, true
	case "CHACHA20-POLY1305":
		return .CHACHA20_POLY1305, true
	}
	return {}, false
}
