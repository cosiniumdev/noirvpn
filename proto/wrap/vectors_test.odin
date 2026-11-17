// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:testing"
import "noir:proto/ossl"

// Every byte vector of the wrapping spec.

@(test)
spec_tls_auth_sha1_vectors :: proc(t: ^testing.T) {
	key := spec_key()
	inner := unhex("38 " + SPEC_SID + " 00 00000000")
	testing.expect_value(t, len(inner), 14)
	out: [128]u8

	// Client, key-direction 1.
	client: Auth_Keys
	auth_keys_init(&client, &key, .SHA1, .One)
	expect_bytes(t, client.send_key[:20], unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3"), "send key (file bytes 192..212)")
	expect_bytes(t, client.recv_key[:20], unhex("404142434445464748494a4b4c4d4e4f50515253"), "recv key (file bytes 64..84)")
	n, err := tls_auth_seal(&client, 1, SPEC_TIME, inner, out[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 42)
	want_client := unhex("38 " + SPEC_SID + " 3647902577839423b58b17ca6af3b0971e4f40a1 00000001 6553f100 00 00000000")
	expect_bytes(t, out[:n], want_client, "client wire, key-direction 1")

	// Same packet, no key direction (slot 0).
	bidir: Auth_Keys
	auth_keys_init(&bidir, &key, .SHA1, .Bidirectional)
	expect_bytes(t, bidir.send_key[:20], unhex("404142434445464748494a4b4c4d4e4f50515253"), "send key bidir")
	expect_bytes(t, bidir.recv_key[:20], unhex("404142434445464748494a4b4c4d4e4f50515253"), "recv key bidir")
	n, err = tls_auth_seal(&bidir, 1, SPEC_TIME, inner, out[:])
	testing.expect_value(t, err, Error.None)
	want_bidir := unhex("38 " + SPEC_SID + " a8ee943911816c5ed98bc04842a3ab3b2b5f4143 00000001 6553f100 00 00000000")
	expect_bytes(t, out[:n], want_bidir, "wire, no key direction")

	// Server with key-direction 0 receives the client packet (slot 1) ...
	server: Auth_Keys
	auth_keys_init(&server, &key, .SHA1, .Zero)
	expect_bytes(t, server.send_key[:20], unhex("404142434445464748494a4b4c4d4e4f50515253"), "server send key")
	expect_bytes(t, server.recv_key[:20], unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3"), "server recv key")
	back: [128]u8
	m, id, tm, oerr := tls_auth_open(&server, want_client, back[:])
	testing.expect_value(t, oerr, Error.None)
	testing.expect_value(t, id, 1)
	testing.expect_value(t, tm, SPEC_TIME)
	expect_bytes(t, back[:m], inner, "unwrapped by server")

	// ... but a bidirectional peer, or a client with the same direction, cannot.
	_, _, _, oerr = tls_auth_open(&bidir, want_client, back[:])
	testing.expect_value(t, oerr, Error.Bad_Mac)
	_, _, _, oerr = tls_auth_open(&client, want_client, back[:])
	testing.expect_value(t, oerr, Error.Bad_Mac)
	// The bidirectional packet opens only with bidirectional keys.
	_, _, _, oerr = tls_auth_open(&bidir, want_bidir, back[:])
	testing.expect_value(t, oerr, Error.None)
	_, _, _, oerr = tls_auth_open(&server, want_bidir, back[:])
	testing.expect_value(t, oerr, Error.Bad_Mac)

	testing.expect_value(t, tls_auth_overhead(.SHA1), 28)
}

@(test)
spec_tls_crypt_vectors :: proc(t: ^testing.T) {
	key := spec_key()
	inner := unhex("38 " + SPEC_SID + " 00 00000000")
	out: [128]u8

	client: Crypt_Keys
	crypt_keys_init(&client, &key, .Client)
	// Client sends with slot 1: Ke = bytes 128..160, Ka = bytes 192..224.
	testing.expect_value(t, client.send_ke[0], 128)
	testing.expect_value(t, client.send_ka[0], 192)
	testing.expect_value(t, client.recv_ke[0], 0)
	testing.expect_value(t, client.recv_ka[0], 64)
	n, err := tls_crypt_seal(&client, 1, SPEC_TIME, inner, out[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 54)
	want_client := unhex(`38 0102030405060708 00000001 6553f100
		e2fcfd945f4c4d4a65fe3f138b0c4bafa2f10f7a4e77594fca76f3a4cad2f5e6
		0bc4ff7777`)
	expect_bytes(t, out[:n], want_client, "client wire")

	// Server sends a HARD_RESET_SERVER_V2 (0x40) with slot 0.
	server: Crypt_Keys
	crypt_keys_init(&server, &key, .Server)
	testing.expect_value(t, server.send_ke[0], 0)
	testing.expect_value(t, server.send_ka[0], 64)
	server_inner := unhex("40 " + SPEC_SID + " 00 00000000")
	n, err = tls_crypt_seal(&server, 1, SPEC_TIME, server_inner, out[:])
	testing.expect_value(t, err, Error.None)
	want_server := unhex(`40 0102030405060708 00000001 6553f100
		98524624e46e5f774d7a674dd402021138a94a47f08d2a5b24300a6d1a77f668
		ad9b2fe42b`)
	expect_bytes(t, out[:n], want_server, "server wire")

	// Each side opens the other's packet, and not its own.
	back: [128]u8
	m, id, tm, oerr := tls_crypt_open(&server, want_client, back[:])
	testing.expect_value(t, oerr, Error.None)
	testing.expect_value(t, id, 1)
	testing.expect_value(t, tm, SPEC_TIME)
	expect_bytes(t, back[:m], inner, "server opens client packet")
	m, id, tm, oerr = tls_crypt_open(&client, want_server, back[:])
	testing.expect_value(t, oerr, Error.None)
	expect_bytes(t, back[:m], server_inner, "client opens server packet")
	_, _, _, oerr = tls_crypt_open(&client, want_client, back[:])
	testing.expect_value(t, oerr, Error.Bad_Mac)
	_, _, _, oerr = tls_crypt_open(&server, want_server, back[:])
	testing.expect_value(t, oerr, Error.Bad_Mac)

	// The wire id/time can be read before authentication.
	pid, ptime, pok := crypt_peek_wrap_id(want_client)
	testing.expect(t, pok)
	testing.expect_value(t, pid, 1)
	testing.expect_value(t, ptime, SPEC_TIME)
}

SPEC_WKC :: `f623ef77270b5568d0fb12d9609478a4c3ea1f8ab457d7eb829d9ff439abaf2a
b1625cf0ed0c2078ef736f9d5ccfdddb2ea49be1b3b4cb3cf718f0d849233d3a
1235fc2236e60ce5d512132cd5e143323084ba6c63dd0de3c994ab7126b20458
00ce9d873a1a17f4d8ec0c0a15baad3cdcf4631fcc2180914e684fddd3959af5
88e341c798bc58a489c85f5d427697f82ae0e363d2187b6bdb2d85184cd23973
266853d79a110ef4697d3efa7fe756490a4404a3d82b91469ad63ba52d173a52
c8b251c8030ab06858da94edf6e8da7a3d230c21b34713745b4665d23303f6e7
a9dd7377cc6509cebaf6f26635d9450bcfcb41fc703a284a80d3892d68170c02
25c6ff06effa302f4fb5897137ae41acb06f77e89d2180940d141563036dbc2a
fda72eec8f2096866d012b`

spec_v2_server_key :: proc() -> Server_Key {
	body: [128]u8
	for i in 0 ..< 128 {
		body[i] = u8(i)
	}
	sk: Server_Key
	err := server_key_from_bytes(body[:], &sk)
	assert(err == .None)
	return sk
}

spec_v2_kc :: proc() -> Static_Key {
	kc: Static_Key
	for i in 0 ..< 256 {
		kc.bytes[i] = u8((7 * i + 3) % 256)
	}
	return kc
}

@(test)
spec_tls_crypt_v2_vectors :: proc(t: ^testing.T) {
	sk := spec_v2_server_key()
	kc := spec_v2_kc()
	testing.expect_value(t, sk.ke[0], 0)
	testing.expect_value(t, sk.ke[31], 31)
	testing.expect_value(t, sk.ka[0], 0x40)
	testing.expect_value(t, sk.ka[31], 0x5f)

	// Metadata: timestamp 1700000000.
	meta_in: Metadata
	metadata_make_timestamp(&meta_in, SPEC_NOW)
	expect_bytes(t, metadata_bytes(&meta_in), unhex("01 000000006553f100"), "metadata")

	wkc: [WKC_MAX_LEN]u8
	n, err := tls_crypt_v2_wkc_build(&sk, &kc, metadata_bytes(&meta_in), wkc[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 299)
	want_wkc := unhex(SPEC_WKC)
	testing.expect_value(t, len(want_wkc), 299)
	expect_bytes(t, wkc[:n], want_wkc, "WKc")

	// The server opens it.
	got_kc: Static_Key
	meta: Metadata
	testing.expect_value(t, tls_crypt_v2_wkc_open(&sk, want_wkc, &got_kc, &meta), Error.None)
	expect_bytes(t, got_kc.bytes[:], kc.bytes[:], "Kc from WKc")
	expect_bytes(t, metadata_bytes(&meta), metadata_bytes(&meta_in), "metadata from WKc")
	ts, ts_ok := metadata_timestamp(&meta)
	testing.expect(t, ts_ok)
	testing.expect_value(t, ts, SPEC_NOW)
	typ, typ_ok := metadata_type(&meta)
	testing.expect(t, typ_ok)
	testing.expect_value(t, typ, METADATA_TYPE_TIMESTAMP)

	// Client V3 reset: session id 0102030405060708, wrap id 0x0f000001.
	inner := unhex("50 " + SPEC_SID + " 00 00000000")
	ck: Client_Key
	ck.kc = kc
	copy(ck.wkc[:], want_wkc)
	ck.wkc_len = len(want_wkc)
	ctx: Tls_Crypt
	tls_crypt_v2_client_init(&ctx, &ck)
	out: [512]u8
	m, werr := tls_crypt_v2_client_wrap(&ctx, client_key_wkc(&ck), SPEC_NOW, inner, out[:])
	testing.expect_value(t, werr, Error.None)
	testing.expect_value(t, m, 353)
	want_pkt := unhex(`50 0102030405060708 0f000001 6553f100
		12880fa5b64f800b9f5216d589329100690b208cd3a07dba129ef35ed0874657
		747a9a2a70`)
	testing.expect_value(t, len(want_pkt), 54)
	expect_bytes(t, out[:54], want_pkt, "client reset before WKc")
	expect_bytes(t, out[54:m], want_wkc, "WKc appended")

	// The server side: signals early negotiation, opens WKc, unwraps.
	wid, _, wok := crypt_peek_wrap_id(out[:m])
	testing.expect(t, wok)
	testing.expect_value(t, wid, 0x0f000001)
	testing.expect(t, tls_crypt_v2_signals_early_negotiation(wid))
	back: [512]u8
	srv: Tls_Crypt
	smeta: Metadata
	k, uerr := tls_crypt_v2_server_unwrap(&sk, out[:m], back[:], &srv, &smeta)
	testing.expect_value(t, uerr, Error.None)
	expect_bytes(t, back[:k], inner, "inner packet at the server")
	expect_bytes(t, metadata_bytes(&smeta), metadata_bytes(&meta_in), "metadata at the server")
	// The server can respond and the client can read it.
	reply := unhex("40 " + SPEC_SID + " 00 00000000")
	rn, rerr := tls_crypt_wrap(&srv, SPEC_NOW, reply, out[:])
	testing.expect_value(t, rerr, Error.None)
	cn, cerr := tls_crypt_unwrap(&ctx, out[:rn], back[:])
	testing.expect_value(t, cerr, Error.None)
	expect_bytes(t, back[:cn], reply, "reply at the client")

}

@(test)
tls_auth_extra_digest_vectors :: proc(t: ^testing.T) {
	// Computed by an independent script that follows the spec text (Python hmac).
	key := spec_key()
	rest := unhex("02 00000005 00000006 b1b2b3b4b5b6b7b8 00000007 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627")
	inner := make([]u8, 9 + len(rest), context.temp_allocator)
	copy(inner, unhex("20 " + SPEC_SID))
	copy(inner[9:], rest)

	Case :: struct {
		alg:  ossl.Hmac_Alg,
		dir:  Key_Direction,
		id:   u32,
		time: u32,
		wire: string,
	}
	cases := [?]Case {
		{
			.SHA256,
			.Zero,
			0x01020304,
			0x6553f101,
			"200102030405060708c015220a7443065ff7543a55be61d67acb31b17dddf217ba20f5ec7117d8e760010203046553f101020000000500000006b1b2b3b4b5b6b7b800000007000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
		},
		{
			.SHA512,
			.One,
			2,
			0x6553f102,
			"20010203040506070890d57f7231c3ec56b4a2d4abd837c80df6f214788236d5d0a4b333c28bf2a4afe72332c8e1c01343b40103af8103397dceae4b32c12594e19e0b03e0896a18bf000000026553f102020000000500000006b1b2b3b4b5b6b7b800000007000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
		},
	}
	for c in cases {
		k: Auth_Keys
		auth_keys_init(&k, &key, c.alg, c.dir)
		out: [256]u8
		n, err := tls_auth_seal(&k, c.id, c.time, inner, out[:])
		testing.expect_value(t, err, Error.None)
		want := unhex(c.wire)
		expect_bytes(t, out[:n], want, "wire")
		testing.expect_value(t, n, len(inner) + tls_auth_overhead(c.alg))

		// The opposite role opens it.
		peer_dir: Key_Direction = .One if c.dir == .Zero else .Zero
		peer: Auth_Keys
		auth_keys_init(&peer, &key, c.alg, peer_dir)
		back: [256]u8
		m, id, tm, oerr := tls_auth_open(&peer, want, back[:])
		testing.expect_value(t, oerr, Error.None)
		testing.expect_value(t, id, c.id)
		testing.expect_value(t, tm, c.time)
		expect_bytes(t, back[:m], inner, "unwrapped")
	}

	// SHA-256, no key direction, a packet that is only an ACK array.
	ack_inner := unhex("28 " + SPEC_SID + " 01 00000000 b1b2b3b4b5b6b7b8")[:]
	k: Auth_Keys
	auth_keys_init(&k, &key, .SHA256, .Bidirectional)
	out: [128]u8
	n, err := tls_auth_seal(&k, 9, 0x11223344, ack_inner, out[:])
	testing.expect_value(t, err, Error.None)
	back: [128]u8
	m, _, _, oerr := tls_auth_open(&k, out[:n], back[:])
	testing.expect_value(t, oerr, Error.None)
	expect_bytes(t, back[:m], ack_inner, "bidirectional round trip")
}

@(test)
tls_crypt_extra_vectors :: proc(t: ^testing.T) {
	// Computed by an independent script (Python hmac + cryptography) that
	// follows the spec text.
	key := spec_key()
	server: Crypt_Keys
	client: Crypt_Keys
	crypt_keys_init(&server, &key, .Server)
	crypt_keys_init(&client, &key, .Client)
	rest := unhex("02 00000005 00000006 b1b2b3b4b5b6b7b8 00000007 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627")
	inner := make([]u8, 9 + len(rest), context.temp_allocator)
	copy(inner, unhex("20 " + SPEC_SID))
	copy(inner[9:], rest)
	out: [256]u8
	n, err := tls_crypt_seal(&server, 0x01020304, 0x6553f101, inner, out[:])
	testing.expect_value(t, err, Error.None)
	want := unhex(
		"200102030405060708010203046553f101b98a029fb6f245d5c97451881b012386ff77c02f7e26a2c71c2a04c5074cc3d2c2f7aaa450a7e7f888fde4b2283cad7b3811ae9693a24b153d748f1739dcb307999bf45d24bf91968f9606f33a64f1f157a578bc9d88834e954ab7a571",
	)
	expect_bytes(t, out[:n], want, "server wire, long body")

	// A short body, and a packet with nothing after the sid.
	n, err = tls_crypt_seal(&client, 77, 0x6553f103, unhex("28 " + SPEC_SID + " 02 00000005 00000006 b1b2b3b4"), out[:])
	testing.expect_value(t, err, Error.None)
	expect_bytes(
		t,
		out[:n],
		unhex("2801020304050607080000004d6553f10363a5c2610c6d7094ce42f505ec23ea759700ad67818332ca99115e10919f279d9d4a6ba77c8e6f3a5a750f47b6"),
		"client wire, short body",
	)
	n, err = tls_crypt_seal(&client, 77, 0x6553f103, unhex("28 " + SPEC_SID), out[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 49)
	expect_bytes(t, out[:n], unhex("2801020304050607080000004d6553f1034f23e13ef925576083c19664364616b441673cfecc04a55f9d456aa9933c69e3"), "empty body")
	back: [256]u8
	m, _, _, oerr := tls_crypt_open(&server, out[:n], back[:])
	testing.expect_value(t, oerr, Error.None)
	expect_bytes(t, back[:m], unhex("28 " + SPEC_SID), "empty body round trip")
}

@(test)
dynamic_key_derivation :: proc(t: ^testing.T) {
	exported: [256]u8
	for i in 0 ..< 256 {
		exported[i] = u8(255 - i)
	}
	orig := spec_key()
	dyn: Static_Key
	testing.expect_value(t, dynamic_key_derive(exported[:], &orig, &dyn), Error.None)
	for i in 0 ..< 256 {
		testing.expect_value(t, dyn.bytes[i], exported[i] ~ orig.bytes[i])
	}
	// XOR of these two is 0xff everywhere.
	testing.expect_value(t, dyn.bytes[0], 0xff)
	testing.expect_value(t, dyn.bytes[255], 0xff)

	// No original: the export unchanged.
	testing.expect_value(t, dynamic_key_derive(exported[:], nil, &dyn), Error.None)
	expect_bytes(t, dyn.bytes[:], exported[:], "no original")

	testing.expect_value(t, dynamic_key_derive(exported[:255], nil, &dyn), Error.Bad_Argument)
	testing.expect_value(t, dynamic_key_derive(make([]u8, 257, context.temp_allocator), nil, &dyn), Error.Bad_Argument)

	// Contexts: server and client talk to each other; own counter from 0.
	srv, cli: Tls_Crypt
	testing.expect_value(t, dynamic_tls_crypt_init(&srv, exported[:], &orig, .Server), Error.None)
	testing.expect_value(t, dynamic_tls_crypt_init(&cli, exported[:], &orig, .Client), Error.None)
	inner := unhex("20 " + SPEC_SID + " 00 00000001 aabb")
	out, back: [128]u8
	n, err := tls_crypt_wrap(&cli, SPEC_NOW, inner, out[:])
	testing.expect_value(t, err, Error.None)
	pid, _, _ := crypt_peek_wrap_id(out[:n])
	testing.expect_value(t, pid, 1) // first wire id is 1
	m, uerr := tls_crypt_unwrap(&srv, out[:n], back[:])
	testing.expect_value(t, uerr, Error.None)
	expect_bytes(t, back[:m], inner, "dynamic round trip")

	// A context built without the original key cannot read it.
	other: Tls_Crypt
	testing.expect_value(t, dynamic_tls_crypt_init(&other, exported[:], nil, .Server), Error.None)
	_, uerr = tls_crypt_unwrap(&other, out[:n], back[:])
	testing.expect_value(t, uerr, Error.Bad_Mac)

	// which wrap applies.
	testing.expect(t, wrap_uses_dynamic(1, true))
	testing.expect(t, wrap_uses_dynamic(7, true))
	testing.expect(t, !wrap_uses_dynamic(0, true))
	testing.expect(t, !wrap_uses_dynamic(1, false))
}
