// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:encoding/json"
import "core:testing"
import "noir:proto/ossl"

// Every case of data-channel.json: the 256 exporter bytes captured from stock
// peers, split for client and server. Compared with the key, implicit IV and
// E1 that the verifier derived from the spec.
@(test)
derive_from_captures :: proc(t: ^testing.T) {
	root := load_json(t, DATA_CHANNEL_JSON)
	cases := json_cases(t, root)
	testing.expect(t, len(cases) >= 6, "expected at least 6 captured cases")
	for c in cases {
		cs := c.(json.Object)
		cell := jstr(cs, "cell")
		cipher, ok := cipher_from_name(jstr(cs, "cipher"))
		testing.expectf(t, ok, "%s: unknown cipher", cell)
		export := jhex(jobj(cs, "exporter"), "output_hex")
		testing.expect_value(t, len(export), EXPORT_LEN)

		client, cerr := derive_material(export, .Client, cipher)
		server, serr := derive_material(export, .Server, cipher)
		testing.expect_value(t, cerr, Error.None)
		testing.expect_value(t, serr, Error.None)

		derived := jobj(cs, "derived")
		c2s, s2c := jobj(derived, "c2s"), jobj(derived, "s2c")
		key_len := ossl.aead_key_len(cipher)
		// The client sends with c2s and receives s2c; the server the other way.
		expect_bytes(t, client.send.key[:key_len], jhex(c2s, "key"), cell)
		expect_bytes(t, server.recv.key[:key_len], jhex(c2s, "key"), cell)
		expect_bytes(t, client.recv.key[:key_len], jhex(s2c, "key"), cell)
		expect_bytes(t, server.send.key[:key_len], jhex(s2c, "key"), cell)
		testing.expect_value(t, client.send.key_len, key_len)
		if "iv8" in c2s {
			expect_bytes(t, client.send.iv[:], jhex(c2s, "iv8"), cell)
			expect_bytes(t, server.recv.iv[:], jhex(c2s, "iv8"), cell)
			expect_bytes(t, client.recv.iv[:], jhex(s2c, "iv8"), cell)
			expect_bytes(t, server.send.iv[:], jhex(s2c, "iv8"), cell)
		}
		if "epoch_1_base_key_e1" in c2s {
			expect_bytes(t, client.send.e1[:], jhex(c2s, "epoch_1_base_key_e1"), cell)
			expect_bytes(t, server.recv.e1[:], jhex(c2s, "epoch_1_base_key_e1"), cell)
			expect_bytes(t, client.recv.e1[:], jhex(s2c, "epoch_1_base_key_e1"), cell)
			expect_bytes(t, server.send.e1[:], jhex(s2c, "epoch_1_base_key_e1"), cell)
		}
	}
}

// The exporter vectors: every datakeys export must split into mirror images
// for the two roles. For TLS 1.3 the export is also recomputed from the
// exporter secret (RFC 8446 7.5). This checks the vector itself, not only our
// split of it.
@(test)
derive_from_exporter_vectors :: proc(t: ^testing.T) {
	root := load_json(t, TLS_EXPORTER_JSON)
	checked_tls13 := 0
	for c in json_cases(t, root) {
		cs := c.(json.Object)
		cell := jstr(cs, "cell")
		exp: []u8
		for e in cs["exports"].(json.Array) {
			eo := e.(json.Object)
			if jstr(eo, "label") == EXPORT_LABEL {
				exp = jhex(eo, "output_hex")
			}
		}
		testing.expectf(t, len(exp) == EXPORT_LEN, "%s: no datakeys export", cell)
		client, cerr := derive_material(exp, .Client, .AES_256_GCM)
		server, serr := derive_material(exp, .Server, .AES_256_GCM)
		testing.expect_value(t, cerr, Error.None)
		testing.expect_value(t, serr, Error.None)
		testing.expectf(t, client.send == server.recv, "%s: client send != server recv", cell)
		testing.expectf(t, client.recv == server.send, "%s: client recv != server send", cell)
		testing.expectf(t, client.send != client.recv, "%s: both directions equal", cell)

		if jstr(cs, "hash") == "sha384" {
			secret := jhex(cs, "secret_hex")
			got := make([]u8, EXPORT_LEN, context.temp_allocator)
			testing.expect(t, tls13_export(secret, EXPORT_LABEL, got), "tls13_export failed")
			expect_bytes(t, got, exp, cell)
			checked_tls13 += 1
		}
	}
	testing.expect(t, checked_tls13 >= 2, "expected two TLS 1.3 exporter vectors")
}

// TLS 1.3 exporter with SHA-384 and an empty context (RFC 8446 7.5):
//   derived = HKDF-Expand-Label(secret, label, Hash(""), 48)
//   out     = HKDF-Expand-Label(derived, "exporter", Hash(""), len)
@(private = "file")
tls13_export :: proc(secret: []u8, label: string, out: []u8) -> bool {
	// SHA-384 of the empty string.
	empty_hash := unhex(
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
	)
	derived: [48]u8
	return(
		hkdf_expand_label_tls13(secret, label, empty_hash, derived[:]) &&
		hkdf_expand_label_tls13(derived[:], "exporter", empty_hash, out) \
	)
}

@(private = "file")
hkdf_expand_label_tls13 :: proc(secret: []u8, label: string, ctx, out: []u8) -> bool {
	info := make([dynamic]u8, context.temp_allocator)
	append(&info, u8(len(out) >> 8), u8(len(out)), u8(6 + len(label)))
	append(&info, "tls13 ")
	append(&info, label)
	append(&info, u8(len(ctx)))
	append(&info, ..ctx)
	return ossl.hkdf_expand(.SHA384, secret, info[:], out)
}

@(test)
derive_rejects_bad_input :: proc(t: ^testing.T) {
	export: [EXPORT_LEN]u8
	for &b, i in export {
		b = u8(i + 1)
	}
	_, err := derive_material(export[:255], .Client, .AES_256_GCM)
	testing.expect_value(t, err, Error.Bad_Export_Length)
	_, err = derive_material(export[:], .Client, .AES_256_GCM)
	testing.expect_value(t, err, Error.None)

	// Any of the four 64-byte parts with 16 zero bytes at its start is refused.
	for part in 0 ..< 4 {
		bad := export
		for i in 0 ..< 16 {
			bad[part * 64 + i] = 0
		}
		_, err = derive_material(bad[:], .Client, .AES_128_GCM)
		testing.expectf(t, err == .Zero_Material, "part %d all zero: got %v", part, err)
	}
	// 15 zero bytes are fine; bytes after the first 16 do not count.
	ok := export
	for i in 0 ..< 15 {
		ok[64 + i] = 0
	}
	for i in 16 ..< 64 {
		ok[128 + i] = 0
	}
	_, err = derive_material(ok[:], .Server, .CHACHA20_POLY1305)
	testing.expect_value(t, err, Error.None)
}

@(test)
derive_key_sizes_and_wipe :: proc(t: ^testing.T) {
	export: [EXPORT_LEN]u8
	for &b, i in export {
		b = u8(i + 1)
	}
	m128, _ := derive_material(export[:], .Client, .AES_128_GCM)
	m256, _ := derive_material(export[:], .Client, .AES_256_GCM)
	testing.expect_value(t, m128.send.key_len, 16)
	testing.expect_value(t, m256.send.key_len, 32)
	// Same bytes, the 128-bit key is the first half of the 256-bit one.
	expect_bytes(t, m128.send.key[:16], m256.send.key[:16], "key prefix")
	testing.expect_value(t, m128.send.key[16], 0)
	// The ranges for a client.
	expect_bytes(t, m256.send.key[:], export[0:32], "client send key")
	expect_bytes(t, m256.send.iv[:], export[64:72], "client send iv")
	expect_bytes(t, m256.recv.key[:], export[128:160], "client recv key")
	expect_bytes(t, m256.recv.iv[:], export[192:200], "client recv iv")

	material_wipe(&m256)
	zero: Key_Material
	testing.expect(t, m256 == zero, "wipe left bytes behind")
	export_wipe(export[:])
	testing.expect_value(t, export[0], 0)
	testing.expect_value(t, export[255], 0)
}
