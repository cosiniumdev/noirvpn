// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "core:encoding/hex"
import "core:encoding/json"
import "core:testing"
import "noir:proto/keys"
import "noir:proto/ossl"

// Real captures from stock OpenVPN 2.6.23 and 2.7.7 (proto/testdata/vectors/).
DATA_CHANNEL_JSON :: #load("../testdata/vectors/data-channel.json")
DATA_CHANNEL_REKEY_JSON :: #load("../testdata/vectors/data-channel-rekey.json")

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

// Small deterministic PRNG (xorshift64*) so tests repeat exactly.
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

// Parses a vector file. The result lives in temp memory.
load_json :: proc(t: ^testing.T, data: []u8) -> json.Object {
	v, err := json.parse(data, parse_integers = true, allocator = context.temp_allocator)
	testing.expect_value(t, err, json.Error.None)
	obj, ok := v.(json.Object)
	testing.expect(t, ok, "vector file is not a JSON object")
	return obj
}

jstr :: proc(o: json.Object, key: string) -> string {
	s, _ := o[key].(json.String)
	return string(s)
}

jobj :: proc(o: json.Object, key: string) -> json.Object {
	v, _ := o[key].(json.Object)
	return v
}

jarr :: proc(o: json.Object, key: string) -> json.Array {
	v, _ := o[key].(json.Array)
	return v
}

jint :: proc(o: json.Object, key: string) -> i64 {
	v, _ := o[key].(json.Integer)
	return i64(v)
}

jhex :: proc(o: json.Object, key: string) -> []u8 {
	return unhex(jstr(o, key))
}

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

// A fake 256-byte export with no zero parts: byte i is a mix of the seed and i.
fake_export :: proc(seed: u8) -> (e: [keys.EXPORT_LEN]u8) {
	for i in 0 ..< keys.EXPORT_LEN {
		e[i] = u8(i * 7) ~ seed ~ u8(i >> 3) + 1
	}
	return
}

// A client and a server Data_Key for the same export, the way the session layer
// would set them up. Wipes the key material like the caller should.
make_pair :: proc(
	t: ^testing.T,
	format: keys.Format,
	cipher: ossl.Aead_Cipher,
	key_id: u8 = 0,
	seed: u8 = 1,
	opts: Key_Options = {},
) -> (
	client, server: Data_Key,
	ok: bool,
) {
	export := fake_export(seed)
	defer keys.export_wipe(export[:])
	cm, cerr := keys.derive_material(export[:], .Client, cipher)
	sm, serr := keys.derive_material(export[:], .Server, cipher)
	defer keys.material_wipe(&cm)
	defer keys.material_wipe(&sm)
	if !testing.expect_value(t, cerr, keys.Error.None) || !testing.expect_value(t, serr, keys.Error.None) {
		return
	}
	if !testing.expect_value(t, data_key_init(&client, format, cipher, key_id, &cm, opts), Error.None) {
		return
	}
	if !testing.expect_value(t, data_key_init(&server, format, cipher, key_id, &sm, opts), Error.None) {
		data_key_destroy(&client)
		return
	}
	return client, server, true
}
