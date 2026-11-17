// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:testing"
import "noir:proto/ossl"

// A control packet body: ack array (2 acks), message id, payload.
@(private = "file")
sample_inner :: proc(op: u8, payload_len: int) -> []u8 {
	b := make([dynamic]u8, context.temp_allocator)
	append(&b, op)
	append(&b, ..unhex(SPEC_SID))
	append(&b, ..unhex("02 00000000 00000001 b1b2b3b4b5b6b7b8 00000002"))
	for i in 0 ..< payload_len {
		append(&b, u8(i * 7 + 1))
	}
	return b[:]
}

// ---- tls-auth ----

@(test)
tls_auth_context_round_trip_all_digests :: proc(t: ^testing.T) {
	key := spec_key()
	algs := [?]ossl.Hmac_Alg{.SHA1, .SHA256, .SHA512}
	for alg in algs {
		for dir in Key_Direction {
			// A pair of peers: for Zero the other side uses One and the
			// reverse; bidirectional talks to itself.
			peer_dir := dir
			if dir == .Zero {
				peer_dir = .One
			} else if dir == .One {
				peer_dir = .Zero
			}
			a, b: Tls_Auth
			tls_auth_init(&a, &key, alg, dir)
			tls_auth_init(&b, &key, alg, peer_dir)
			for size in ([?]int{0, 1, 100, 1200}) {
				inner := sample_inner(0x20, size)
				wire_buf := make([]u8, len(inner) + tls_auth_overhead(alg), context.temp_allocator)
				out := make([]u8, len(inner), context.temp_allocator)
				n, err := tls_auth_wrap(&a, SPEC_NOW, inner, wire_buf)
				testing.expect_value(t, err, Error.None)
				testing.expect_value(t, n, len(wire_buf))
				m, uerr := tls_auth_unwrap(&b, wire_buf[:n], out)
				testing.expect_value(t, uerr, Error.None)
				expect_bytes(t, out[:m], inner, "round trip")
				// The same packet again is a replay.
				_, uerr = tls_auth_unwrap(&b, wire_buf[:n], out)
				testing.expect_value(t, uerr, Error.Replay)
			}
			// Both directions work on the same pair.
			inner := sample_inner(0x40, 10)
			wire_buf := make([]u8, len(inner) + 100, context.temp_allocator)
			out := make([]u8, len(inner), context.temp_allocator)
			n, err := tls_auth_wrap(&b, SPEC_NOW, inner, wire_buf)
			testing.expect_value(t, err, Error.None)
			m, uerr := tls_auth_unwrap(&a, wire_buf[:n], out)
			testing.expect_value(t, uerr, Error.None)
			expect_bytes(t, out[:m], inner, "reverse direction")
		}
	}
}

@(test)
tls_auth_wrong_direction_and_key :: proc(t: ^testing.T) {
	key := spec_key()
	other := spec_key()
	other.bytes[200] ~= 1 // slot 1 hmac part differs
	inner := sample_inner(0x20, 20)
	out: [256]u8
	back: [256]u8

	// Same key direction on both sides fails. Opposite directions work.
	// (Bidirectional uses slot 0 both ways, so it can read a direction-0 sender
	// and be read by a direction-1 receiver, but not the reverse.)
	Dir_Case :: struct {
		tx, rx: Key_Direction,
		works:  bool,
	}
	cases := [?]Dir_Case {
		{.Zero, .Zero, false},
		{.One, .One, false},
		{.Bidirectional, .Bidirectional, true},
		{.Zero, .One, true},
		{.One, .Zero, true},
		{.Zero, .Bidirectional, true},
		{.Bidirectional, .One, true},
		{.Bidirectional, .Zero, false},
		{.One, .Bidirectional, false},
	}
	for c in cases {
		a, b: Tls_Auth
		tls_auth_init(&a, &key, .SHA1, c.tx)
		tls_auth_init(&b, &key, .SHA1, c.rx)
		n, _ := tls_auth_wrap(&a, SPEC_NOW, inner, out[:])
		_, err := tls_auth_unwrap(&b, out[:n], back[:])
		if c.works {
			testing.expectf(t, err == .None, "%v -> %v: %v", c.tx, c.rx, err)
		} else {
			testing.expectf(t, err == .Bad_Mac, "%v -> %v: %v", c.tx, c.rx, err)
		}
	}
	// Different key material.
	a, b: Tls_Auth
	tls_auth_init(&a, &key, .SHA256, .One)
	tls_auth_init(&b, &other, .SHA256, .Zero)
	n, _ := tls_auth_wrap(&a, SPEC_NOW, inner, out[:])
	_, err := tls_auth_unwrap(&b, out[:n], back[:])
	testing.expect_value(t, err, Error.Bad_Mac)
	// Different digest.
	tls_auth_init(&b, &key, .SHA1, .Zero)
	_, err = tls_auth_unwrap(&b, out[:n], back[:])
	testing.expect_value(t, err, Error.Bad_Mac)
}

// Every single-byte change and every truncation of a valid packet must fail.
@(test)
tls_auth_tamper_and_truncate :: proc(t: ^testing.T) {
	key := spec_key()
	for alg in ([?]ossl.Hmac_Alg{.SHA1, .SHA256, .SHA512}) {
		tx, rx: Tls_Auth
		tls_auth_init(&tx, &key, alg, .One)
		inner := sample_inner(0x20, 30)
		wire_buf := make([]u8, len(inner) + tls_auth_overhead(alg), context.temp_allocator)
		n, _ := tls_auth_wrap(&tx, SPEC_NOW, inner, wire_buf)
		out := make([]u8, n, context.temp_allocator)

		for i in 0 ..< n {
			for bit in ([?]u8{0x01, 0x80}) {
				wire_buf[i] ~= bit
				tls_auth_init(&rx, &key, alg, .Zero)
				_, err := tls_auth_unwrap(&rx, wire_buf[:n], out)
				testing.expectf(t, err == .Bad_Mac, "%v: flip bit %x of byte %d: %v", alg, bit, i, err)
				wire_buf[i] ~= bit
			}
		}
		// Failed attempts did not touch the replay window of a fresh context.
		tls_auth_init(&rx, &key, alg, .Zero)
		_, err := tls_auth_unwrap(&rx, wire_buf[:n], out)
		testing.expect_value(t, err, Error.None)

		min_len := 9 + ossl.hmac_size(alg) + 8
		for cut in 0 ..< n {
			tls_auth_init(&rx, &key, alg, .Zero)
			_, err = tls_auth_unwrap(&rx, wire_buf[:cut], out)
			if cut < min_len {
				testing.expectf(t, err == .Truncated, "cut %d: %v", cut, err)
			} else {
				testing.expectf(t, err == .Bad_Mac, "cut %d: %v", cut, err)
			}
		}
	}
}

@(test)
tls_auth_buffers_and_replay_state :: proc(t: ^testing.T) {
	key := spec_key()
	tx, rx: Tls_Auth
	tls_auth_init(&tx, &key, .SHA1, .One)
	tls_auth_init(&rx, &key, .SHA1, .Zero)
	inner := sample_inner(0x20, 8)
	out: [128]u8

	// Output too small by one byte.
	_, err := tls_auth_wrap(&tx, SPEC_NOW, inner, out[:len(inner) + 27])
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	// Inner packet shorter than op + sid.
	_, err = tls_auth_wrap(&tx, SPEC_NOW, inner[:8], out[:])
	testing.expect_value(t, err, Error.Truncated)
	// Overlapping buffers.
	buf: [128]u8
	copy(buf[:], inner)
	_, err = tls_auth_seal(&tx.keys, 1, 1, buf[:len(inner)], buf[:])
	testing.expect_value(t, err, Error.Buffer_Overlap)

	n, werr := tls_auth_wrap(&tx, SPEC_NOW, inner, out[:])
	testing.expect_value(t, werr, Error.None)
	small: [10]u8
	_, err = tls_auth_unwrap(&rx, out[:n], small[:])
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	// A failed unwrap committed nothing: the packet is still fresh.
	back: [128]u8
	_, err = tls_auth_unwrap(&rx, out[:n], back[:])
	testing.expect_value(t, err, Error.None)

	// `open` alone never commits (stateless server).
	n, _ = tls_auth_wrap(&tx, SPEC_NOW, inner, out[:])
	for _ in 0 ..< 3 {
		_, id, _, oerr := tls_auth_open(&rx.keys, out[:n], back[:])
		testing.expect_value(t, oerr, Error.None)
		testing.expect_value(t, id, tx.counter.id)
	}
	// Packets arriving out of order within the window are all accepted.
	pkts: [5][128]u8
	lens: [5]int
	for i in 0 ..< 5 {
		lens[i], _ = tls_auth_wrap(&tx, SPEC_NOW, inner, pkts[i][:])
	}
	for i in ([?]int{4, 2, 3, 0, 1}) {
		_, err = tls_auth_unwrap(&rx, pkts[i][:lens[i]], back[:])
		testing.expectf(t, err == .None, "packet %d: %v", i, err)
	}
	for i in 0 ..< 5 {
		_, err = tls_auth_unwrap(&rx, pkts[i][:lens[i]], back[:])
		testing.expectf(t, err == .Replay, "replayed packet %d: %v", i, err)
	}
}

// ---- tls-crypt ----

@(test)
tls_crypt_context_round_trip :: proc(t: ^testing.T) {
	key := spec_key()
	cli, srv: Tls_Crypt
	tls_crypt_init(&cli, &key, .Client)
	tls_crypt_init(&srv, &key, .Server)
	for size in ([?]int{0, 1, 15, 16, 17, 100, 1000, 1200}) {
		for dir in 0 ..< 2 {
			inner := sample_inner(0x20, size)
			wire_buf := make([]u8, len(inner) + CRYPT_OVERHEAD, context.temp_allocator)
			out := make([]u8, len(inner), context.temp_allocator)
			tx, rx := &cli, &srv
			if dir == 1 {
				tx, rx = &srv, &cli
			}
			n, err := tls_crypt_wrap(tx, SPEC_NOW, inner, wire_buf)
			testing.expect_value(t, err, Error.None)
			testing.expect_value(t, n, len(inner) + 40)
			// The plaintext is not visible on the wire.
			if size >= 16 {
				testing.expect(t, string(wire_buf[CRYPT_MIN_PACKET:]) != string(inner[9:]), "body is not encrypted")
			}
			m, uerr := tls_crypt_unwrap(rx, wire_buf[:n], out)
			testing.expect_value(t, uerr, Error.None)
			expect_bytes(t, out[:m], inner, "round trip")
			_, uerr = tls_crypt_unwrap(rx, wire_buf[:n], out)
			testing.expect_value(t, uerr, Error.Replay)
		}
	}
	// Wrap ids kept counting across packets (never reset per key id).
	testing.expect_value(t, cli.counter.id, 8)
}

@(test)
tls_crypt_tamper_and_truncate :: proc(t: ^testing.T) {
	key := spec_key()
	tx, rx: Tls_Crypt
	tls_crypt_init(&tx, &key, .Client)
	inner := sample_inner(0x20, 40)
	wire_buf := make([]u8, len(inner) + CRYPT_OVERHEAD, context.temp_allocator)
	n, _ := tls_crypt_wrap(&tx, SPEC_NOW, inner, wire_buf)
	out := make([]u8, n, context.temp_allocator)
	zeros := make([]u8, n, context.temp_allocator)

	for i in 0 ..< n {
		for bit in ([?]u8{0x01, 0x80}) {
			wire_buf[i] ~= bit
			tls_crypt_init(&rx, &key, .Server)
			_, err := tls_crypt_unwrap(&rx, wire_buf[:n], out)
			testing.expectf(t, err == .Bad_Mac, "flip bit %x of byte %d: %v", bit, i, err)
			// The decrypted garbage is wiped.
			expect_bytes(t, out[:n - 40], zeros[:n - 40], "output wiped after failure")
			wire_buf[i] ~= bit
		}
	}
	tls_crypt_init(&rx, &key, .Server)
	_, err := tls_crypt_unwrap(&rx, wire_buf[:n], out)
	testing.expect_value(t, err, Error.None)

	for cut in 0 ..< n {
		tls_crypt_init(&rx, &key, .Server)
		_, err = tls_crypt_unwrap(&rx, wire_buf[:cut], out)
		if cut < CRYPT_MIN_PACKET {
			testing.expectf(t, err == .Truncated, "cut %d: %v", cut, err)
		} else {
			testing.expectf(t, err == .Bad_Mac, "cut %d: %v", cut, err)
		}
	}

	// Wrong role (a client reading its own packets).
	same: Tls_Crypt
	tls_crypt_init(&same, &key, .Client)
	_, err = tls_crypt_unwrap(&same, wire_buf[:n], out)
	testing.expect_value(t, err, Error.Bad_Mac)

	// Buffers.
	_, err = tls_crypt_wrap(&tx, SPEC_NOW, inner, wire_buf[:len(inner) + 39])
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	_, err = tls_crypt_wrap(&tx, SPEC_NOW, inner[:8], wire_buf)
	testing.expect_value(t, err, Error.Truncated)
	tls_crypt_init(&rx, &key, .Server)
	_, err = tls_crypt_unwrap(&rx, wire_buf[:n], out[:n - 41])
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	_, err = tls_crypt_unwrap(&rx, wire_buf[:n], wire_buf[:n])
	testing.expect_value(t, err, Error.Buffer_Overlap)
}

@(test)
tls_crypt_replay_window_across_session :: proc(t: ^testing.T) {
	key := spec_key()
	tx, rx: Tls_Crypt
	tls_crypt_init(&tx, &key, .Client)
	tls_crypt_init(&rx, &key, .Server)
	inner := sample_inner(0x20, 5)
	back: [128]u8
	pkts: [70][128]u8
	lens: [70]int
	for i in 0 ..< 70 {
		lens[i], _ = tls_crypt_wrap(&tx, SPEC_NOW + i64(i), inner, pkts[i][:])
	}
	// All packets carry the time of the first one.
	_, tm, _ := crypt_peek_wrap_id(pkts[69][:lens[69]])
	testing.expect_value(t, tm, SPEC_TIME)
	// Newest first, then an old one that is outside the 64-window.
	_, err := tls_crypt_unwrap(&rx, pkts[69][:lens[69]], back[:])
	testing.expect_value(t, err, Error.None)
	_, err = tls_crypt_unwrap(&rx, pkts[0][:lens[0]], back[:]) // id 1, newest id 70: distance 69
	testing.expect_value(t, err, Error.Replay)
	_, err = tls_crypt_unwrap(&rx, pkts[5][:lens[5]], back[:]) // id 6: distance 64
	testing.expect_value(t, err, Error.Replay)
	_, err = tls_crypt_unwrap(&rx, pkts[6][:lens[6]], back[:]) // id 7: distance 63
	testing.expect_value(t, err, Error.None)
}

// ---- tls-crypt-v2 ----

@(private = "file")
V2 :: struct {
	sk: Server_Key,
	ck: Client_Key,
}

@(private = "file")
make_v2 :: proc(metadata: []u8) -> V2 {
	v: V2
	v.sk = spec_v2_server_key()
	v.ck.kc = spec_v2_kc()
	n, err := tls_crypt_v2_wkc_build(&v.sk, &v.ck.kc, metadata, v.ck.wkc[:])
	assert(err == .None)
	v.ck.wkc_len = n
	return v
}

@(test)
tls_crypt_v2_handshake_flow :: proc(t: ^testing.T) {
	meta_in: Metadata
	metadata_make_timestamp(&meta_in, SPEC_NOW)
	v := make_v2(metadata_bytes(&meta_in))
	cli: Tls_Crypt
	tls_crypt_v2_client_init(&cli, &v.ck)

	// 1. Client V3 reset with WKc (wrap id 0x0f000001).
	reset := unhex("50 " + SPEC_SID + " 00 00000000")
	pkt1: [1400]u8
	n1, err := tls_crypt_v2_client_wrap(&cli, client_key_wkc(&v.ck), SPEC_NOW, reset, pkt1[:])
	testing.expect_value(t, err, Error.None)
	id1, _, _ := crypt_peek_wrap_id(pkt1[:n1])
	testing.expect_value(t, id1, 0x0f000001)

	// Stateless server: unwrap, then throw the context away. A second call gives the same result.
	back: [1400]u8
	for _ in 0 ..< 2 {
		srv: Tls_Crypt
		meta: Metadata
		m, uerr := tls_crypt_v2_server_unwrap(&v.sk, pkt1[:n1], back[:], &srv, &meta)
		testing.expect_value(t, uerr, Error.None)
		expect_bytes(t, back[:m], reset, "reset at server")
		testing.expect_value(t, metadata_check_age(&meta, SPEC_NOW + 3600, 1), Error.None)
	}

	// 2. Server replies from a fresh counter: wrap id 1, time now.
	srv_fresh: Tls_Crypt
	tls_crypt_init(&srv_fresh, &v.ck.kc, .Server)
	reply := unhex("40 " + SPEC_SID + " 01 00000000 0102030405060708 00000000")
	rn, _ := tls_crypt_wrap(&srv_fresh, SPEC_NOW, reply, back[:])
	_, uerr := tls_crypt_unwrap(&cli, back[:rn], pkt1[:])
	testing.expect_value(t, uerr, Error.None)

	// 3. Client sends the third packet as opcode 11 with WKc (id 0x0f000002).
	third := sample_inner(0x58, 50)
	pkt3: [1400]u8
	n3, werr := tls_crypt_v2_client_wrap(&cli, client_key_wkc(&v.ck), SPEC_NOW, third, pkt3[:])
	testing.expect_value(t, werr, Error.None)
	testing.expect_value(t, n3, len(third) + 40 + 299)
	id3, _, _ := crypt_peek_wrap_id(pkt3[:n3])
	testing.expect_value(t, id3, 0x0f000002)

	// Server creates its session: unwrap with WKc.
	session: Tls_Crypt
	meta: Metadata
	m3, serr := tls_crypt_v2_server_unwrap(&v.sk, pkt3[:n3], back[:], &session, &meta)
	testing.expect_value(t, serr, Error.None)
	expect_bytes(t, back[:m3], third, "third packet")
	// Repeated copy (a retransmission) for a peer that has a context: strip the WKc and unwrap.
	body, wkc, perr := tls_crypt_v2_split_wkc(pkt3[:n3])
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, len(body), len(third) + 40)
	expect_bytes(t, wkc, client_key_wkc(&v.ck), "split WKc")
	_, uerr = tls_crypt_unwrap(&session, body, back[:])
	testing.expect_value(t, uerr, Error.Replay)

	// 4. Later packets are plain tls-crypt, no WKc; the server context reads them.
	later := sample_inner(0x20, 30)
	n4, e4 := tls_crypt_wrap(&cli, SPEC_NOW, later, pkt3[:])
	testing.expect_value(t, e4, Error.None)
	testing.expect_value(t, n4, len(later) + 40)
	m4, u4 := tls_crypt_unwrap(&session, pkt3[:n4], back[:])
	testing.expect_value(t, u4, Error.None)
	expect_bytes(t, back[:m4], later, "later packet")
}

@(test)
tls_crypt_v2_wkc_negative :: proc(t: ^testing.T) {
	v := make_v2({METADATA_TYPE_USER, 'h', 'i'})
	wkc := make([]u8, len(client_key_wkc(&v.ck)), context.temp_allocator)
	copy(wkc, client_key_wkc(&v.ck))
	testing.expect_value(t, len(wkc), 293)
	kc: Static_Key
	meta: Metadata

	testing.expect_value(t, tls_crypt_v2_wkc_open(&v.sk, wkc, &kc, &meta), Error.None)
	expect_bytes(t, kc.bytes[:], v.ck.kc.bytes[:], "Kc")
	expect_bytes(t, metadata_data(&meta), {'h', 'i'}, "user data")
	typ, _ := metadata_type(&meta)
	testing.expect_value(t, typ, METADATA_TYPE_USER)
	_, ts_ok := metadata_timestamp(&meta)
	testing.expect(t, !ts_ok, "user metadata is not a timestamp")

	// Every byte matters (tag, ciphertext, length field).
	for i in 0 ..< len(wkc) {
		wkc[i] ~= 0x01
		err := tls_crypt_v2_wkc_open(&v.sk, wkc, &kc, &meta)
		want := Error.Bad_Wkc
		if i >= len(wkc) - 2 {
			want = .Bad_Wkc_Len // the length field no longer matches
		}
		testing.expectf(t, err == want, "flip byte %d: %v", i, err)
		testing.expect_value(t, kc.bytes, [256]u8{})
		testing.expect_value(t, meta.len, 0)
		wkc[i] ~= 0x01
	}
	// Truncation and extension.
	for cut in 0 ..< len(wkc) {
		testing.expectf(t, tls_crypt_v2_wkc_open(&v.sk, wkc[:cut], &kc, &meta) != .None, "cut %d accepted", cut)
	}
	// Another server key.
	other := v.sk
	other.ka[3] ~= 1
	testing.expect_value(t, tls_crypt_v2_wkc_open(&other, wkc, &kc, &meta), Error.Bad_Wkc)
	other = v.sk
	other.ke[3] ~= 1
	testing.expect_value(t, tls_crypt_v2_wkc_open(&other, wkc, &kc, &meta), Error.Bad_Wkc)

	// Limits: metadata of 734 bytes is the largest.
	big := make([]u8, MAX_METADATA_LEN, context.temp_allocator)
	for i in 0 ..< len(big) {
		big[i] = u8(i)
	}
	big[0] = METADATA_TYPE_USER
	bw: [WKC_MAX_LEN]u8
	n, err := tls_crypt_v2_wkc_build(&v.sk, &v.ck.kc, big, bw[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 1024)
	testing.expect_value(t, tls_crypt_v2_wkc_open(&v.sk, bw[:n], &kc, &meta), Error.None)
	expect_bytes(t, metadata_bytes(&meta), big, "734-byte metadata")
	_, err = tls_crypt_v2_wkc_build(&v.sk, &v.ck.kc, make([]u8, 735, context.temp_allocator), bw[:])
	testing.expect_value(t, err, Error.Metadata_Too_Long)
	_, err = tls_crypt_v2_wkc_build(&v.sk, &v.ck.kc, big, bw[:1023])
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	// Empty metadata (M = 0): the shortest WKc (290).
	n, err = tls_crypt_v2_wkc_build(&v.sk, &v.ck.kc, nil, bw[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 290)
	testing.expect_value(t, tls_crypt_v2_wkc_open(&v.sk, bw[:n], &kc, &meta), Error.None)
	testing.expect_value(t, meta.len, 0)
	_, has_type := metadata_type(&meta)
	testing.expect(t, !has_type)
	testing.expect_value(t, metadata_check_age(&meta, SPEC_NOW, 10), Error.Metadata_Not_Timestamp)
}

@(test)
tls_crypt_v2_server_unwrap_negative :: proc(t: ^testing.T) {
	v := make_v2({METADATA_TYPE_USER, 'x'})
	cli: Tls_Crypt
	tls_crypt_v2_client_init(&cli, &v.ck)
	reset := unhex("50 " + SPEC_SID + " 00 00000000")
	pkt: [1400]u8
	n, err := tls_crypt_v2_client_wrap(&cli, client_key_wkc(&v.ck), SPEC_NOW, reset, pkt[:])
	testing.expect_value(t, err, Error.None)
	back: [1400]u8
	srv: Tls_Crypt
	meta: Metadata

	// Opcode: only 10 and 11.
	for op in 0 ..< 32 {
		mut := make([]u8, n, context.temp_allocator)
		copy(mut, pkt[:n])
		mut[0] = u8(op << 3)
		_, uerr := tls_crypt_v2_server_unwrap(&v.sk, mut, back[:], &srv, &meta)
		if op == 10 || op == 11 {
			// Changing 10 to 11 breaks the tag (opcode is authenticated).
			want := Error.None if op == 10 else Error.Bad_Mac
			testing.expectf(t, uerr == want, "opcode %d: %v", op, uerr)
		} else {
			testing.expectf(t, uerr == .Wrong_Opcode, "opcode %d: %v", op, uerr)
		}
	}

	// Truncation: nothing short of the full packet works.
	for cut in 0 ..< n {
		_, uerr := tls_crypt_v2_server_unwrap(&v.sk, pkt[:cut], back[:], &srv, &meta)
		testing.expectf(t, uerr != .None, "cut %d accepted", cut)
	}
	// Any single byte change fails (clear header, tag, ciphertext, WKc).
	for i in 1 ..< n {
		pkt[i] ~= 0x20
		_, uerr := tls_crypt_v2_server_unwrap(&v.sk, pkt[:n], back[:], &srv, &meta)
		testing.expectf(t, uerr != .None, "flip byte %d accepted", i)
		pkt[i] ~= 0x20
	}
	// After failures the context and metadata are cleared.
	testing.expect_value(t, srv.keys, Crypt_Keys{})
	testing.expect_value(t, meta.len, 0)

	// WKc length field: too big, too small, larger than the packet.
	for l in ([?]u16{0, 1, 2, 289, 1025, 0xffff, u16(n)}) {
		mut := make([]u8, n, context.temp_allocator)
		copy(mut, pkt[:n])
		mut[n - 2] = u8(l >> 8)
		mut[n - 1] = u8(l)
		_, _, serr := tls_crypt_v2_split_wkc(mut)
		testing.expectf(t, serr == .Bad_Wkc_Len, "length %d: %v", l, serr)
	}
	// Wrong server key.
	other := v.sk
	other.ka[0] ~= 0xff
	_, uerr := tls_crypt_v2_server_unwrap(&other, pkt[:n], back[:], &srv, &meta)
	testing.expect_value(t, uerr, Error.Bad_Wkc)
	// Plain tls-crypt wrapped with a different Kc but with a valid WKc appended.
	rogue: Tls_Crypt
	other_kc := spec_v2_kc()
	other_kc.bytes[130] ~= 1 // in the client send key
	tls_crypt_init(&rogue, &other_kc, .Client, EARLY_NEG_START)
	rn, _ := tls_crypt_wrap(&rogue, SPEC_NOW, reset, pkt[:])
	copy(pkt[rn:], client_key_wkc(&v.ck))
	_, uerr = tls_crypt_v2_server_unwrap(&v.sk, pkt[:rn + len(client_key_wkc(&v.ck))], back[:], &srv, &meta)
	testing.expect_value(t, uerr, Error.Bad_Mac)
}

@(test)
tls_crypt_v2_client_wrap_checks :: proc(t: ^testing.T) {
	v := make_v2({METADATA_TYPE_USER, 'x'})
	cli: Tls_Crypt
	tls_crypt_v2_client_init(&cli, &v.ck)
	out: [1400]u8
	// Only opcodes 10 and 11 take a WKc.
	for op in 0 ..< 32 {
		inner := sample_inner(u8(op << 3), 4)
		_, err := tls_crypt_v2_client_wrap(&cli, client_key_wkc(&v.ck), SPEC_NOW, inner, out[:])
		if op == 10 || op == 11 {
			testing.expectf(t, err == .None, "opcode %d: %v", op, err)
		} else {
			testing.expectf(t, err == .Wrong_Opcode, "opcode %d: %v", op, err)
		}
	}
	inner := sample_inner(0x50, 4)
	_, err := tls_crypt_v2_client_wrap(&cli, client_key_wkc(&v.ck), SPEC_NOW, inner, out[:len(inner) + 40 + len(client_key_wkc(&v.ck)) - 1])
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	_, err = tls_crypt_v2_client_wrap(&cli, nil, SPEC_NOW, inner, out[:])
	testing.expect_value(t, err, Error.Bad_Wkc_Len)
	_, err = tls_crypt_v2_client_wrap(&cli, make([]u8, 1025, context.temp_allocator), SPEC_NOW, inner, out[:])
	testing.expect_value(t, err, Error.Bad_Wkc_Len)
	_, err = tls_crypt_v2_client_wrap(&cli, client_key_wkc(&v.ck), SPEC_NOW, nil, out[:])
	testing.expect_value(t, err, Error.Truncated)
}

@(test)
tls_crypt_v2_early_negotiation_bits :: proc(t: ^testing.T) {
	testing.expect(t, tls_crypt_v2_signals_early_negotiation(0x0f000001))
	testing.expect(t, tls_crypt_v2_signals_early_negotiation(0x0f000000))
	testing.expect(t, tls_crypt_v2_signals_early_negotiation(0xffffffff))
	testing.expect(t, tls_crypt_v2_signals_early_negotiation(0x1f123456))
	testing.expect(t, !tls_crypt_v2_signals_early_negotiation(1))
	testing.expect(t, !tls_crypt_v2_signals_early_negotiation(0x0e000001))
	testing.expect(t, !tls_crypt_v2_signals_early_negotiation(0x07000001))
	testing.expect(t, !tls_crypt_v2_signals_early_negotiation(0))
}

@(test)
metadata_age_checks :: proc(t: ^testing.T) {
	m: Metadata
	metadata_make_timestamp(&m, 1_700_000_000)
	day := i64(86400)
	// Exactly at the limit passes; one second past fails.
	testing.expect_value(t, metadata_check_age(&m, 1_700_000_000 + 7 * day, 7), Error.None)
	testing.expect_value(t, metadata_check_age(&m, 1_700_000_000 + 7 * day + 1, 7), Error.Metadata_Too_Old)
	// A timestamp in the future passes.
	testing.expect_value(t, metadata_check_age(&m, 1_600_000_000, 1), Error.None)
	testing.expect_value(t, metadata_check_age(&m, 1_700_000_000, 0), Error.None)
	testing.expect_value(t, metadata_check_age(&m, 1_700_000_001, 0), Error.Metadata_Too_Old)
	testing.expect_value(t, metadata_check_age(&m, 1_700_000_000, -1), Error.Bad_Argument)
	// Huge values do not overflow.
	testing.expect_value(t, metadata_check_age(&m, max(i64), max(i64)), Error.None)
	testing.expect_value(t, metadata_check_age(&m, max(i64), 1), Error.Metadata_Too_Old)
	metadata_make_timestamp(&m, min(i64))
	testing.expect_value(t, metadata_check_age(&m, max(i64), 1), Error.Metadata_Too_Old)

	// Negative timestamps decode as signed.
	metadata_make_timestamp(&m, -5)
	ts, ok := metadata_timestamp(&m)
	testing.expect(t, ok)
	testing.expect_value(t, ts, -5)

	// Not a timestamp: user type, short, empty.
	m = {}
	m.data[0] = METADATA_TYPE_USER
	m.len = 9
	testing.expect_value(t, metadata_check_age(&m, 1, 1), Error.Metadata_Not_Timestamp)
	m.data[0] = METADATA_TYPE_TIMESTAMP
	m.len = 8
	testing.expect_value(t, metadata_check_age(&m, 1, 1), Error.Metadata_Not_Timestamp)
	m.len = 0
	testing.expect_value(t, metadata_check_age(&m, 1, 1), Error.Metadata_Not_Timestamp)
	// Extra data after the 8 bytes is allowed.
	m.len = 20
	testing.expect_value(t, metadata_check_age(&m, 1, 1), Error.None)
	testing.expect_value(t, wrap_time(-1), 0)
	testing.expect_value(t, wrap_time(SPEC_NOW), SPEC_TIME)
}

// ---- fuzz-style ----

@(private = "file")
exercise_all :: proc(t: ^testing.T, b: []u8) {
	key := spec_key()
	out: [2200]u8

	for alg in ([?]ossl.Hmac_Alg{.SHA1, .SHA256, .SHA512}) {
		a: Tls_Auth
		tls_auth_init(&a, &key, alg, .Zero)
		_, err := tls_auth_unwrap(&a, b, out[:])
		testing.expect(t, err != .None, "random packet accepted by tls-auth")
	}
	c: Tls_Crypt
	tls_crypt_init(&c, &key, .Server)
	_, err := tls_crypt_unwrap(&c, b, out[:])
	testing.expect(t, err != .None, "random packet accepted by tls-crypt")

	sk := spec_v2_server_key()
	srv: Tls_Crypt
	meta: Metadata
	_, err = tls_crypt_v2_server_unwrap(&sk, b, out[:], &srv, &meta)
	testing.expect(t, err != .None, "random packet accepted by tls-crypt-v2")
	_, _, _ = tls_crypt_v2_split_wkc(b)
	kc: Static_Key
	_ = tls_crypt_v2_wkc_open(&sk, b, &kc, &meta)
	_, _, _ = crypt_peek_wrap_id(b)

	var: Static_Key
	_ = static_key_parse(b, &var)
	ssk: Server_Key
	_ = server_key_parse(b, &ssk)
	ck: Client_Key
	_ = client_key_parse(b, &ck)
	_ = dynamic_key_derive(b, &key, &var)
}

@(test)
fuzz_random_buffers :: proc(t: ^testing.T) {
	rng := Rng{0xfeedface12345678}
	buf: [2200]u8
	for i in 0 ..< 3000 {
		n := rng_below(&rng, 200)
		if i % 100 == 0 {
			n = rng_below(&rng, len(buf))
		}
		rng_fill(&rng, buf[:n])
		if n > 4 && i % 4 == 0 {
			// Plausible opcode, plausible WKc length in the last two bytes.
			buf[0] = (10 + u8(i % 2)) << 3
			l := 290 + rng_below(&rng, 740)
			buf[n - 2] = u8(l >> 8)
			buf[n - 1] = u8(l)
		}
		exercise_all(t, buf[:n])
	}
}

@(test)
fuzz_text_inputs :: proc(t: ^testing.T) {
	rng := Rng{99}
	k := spec_key()
	text := transmute([]u8)static_key_text(&k)
	pem := transmute([]u8)string("-----BEGIN OpenVPN tls-crypt-v2 server key-----\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\n-----END OpenVPN tls-crypt-v2 server key-----\n")
	for src in ([2][]u8{text, pem}) {
		mut := make([]u8, len(src), context.temp_allocator)
		for cut in 0 ..= len(src) {
			var: Static_Key
			sk: Server_Key
			ck: Client_Key
			_ = static_key_parse(src[:cut], &var)
			_ = server_key_parse(src[:cut], &sk)
			_ = client_key_parse(src[:cut], &ck)
		}
		for _ in 0 ..< 1000 {
			copy(mut, src)
			for _ in 0 ..< 1 + rng_below(&rng, 4) {
				mut[rng_below(&rng, len(mut))] = u8(rng_next(&rng) >> 40)
			}
			var: Static_Key
			sk: Server_Key
			ck: Client_Key
			_ = static_key_parse(mut, &var)
			_ = server_key_parse(mut, &sk)
			_ = client_key_parse(mut, &ck)
		}
	}
}

// Mutated and truncated VALID packets, for every mode: nothing but the
// untouched packet may unwrap.
@(test)
fuzz_mutated_valid_packets :: proc(t: ^testing.T) {
	rng := Rng{31337}
	key := spec_key()
	v := make_v2({METADATA_TYPE_USER, 'x'})
	inner := sample_inner(0x50, 60)
	out: [1400]u8

	pkts: [4][]u8
	{
		a: Tls_Auth
		tls_auth_init(&a, &key, .SHA256, .One)
		buf: [512]u8
		n, _ := tls_auth_wrap(&a, SPEC_NOW, inner, buf[:])
		pkts[0] = make([]u8, n, context.temp_allocator)
		copy(pkts[0], buf[:n])

		c: Tls_Crypt
		tls_crypt_init(&c, &key, .Client)
		n, _ = tls_crypt_wrap(&c, SPEC_NOW, inner, buf[:])
		pkts[1] = make([]u8, n, context.temp_allocator)
		copy(pkts[1], buf[:n])

		cv2: Tls_Crypt
		tls_crypt_v2_client_init(&cv2, &v.ck)
		big: [1400]u8
		n, _ = tls_crypt_v2_client_wrap(&cv2, client_key_wkc(&v.ck), SPEC_NOW, inner, big[:])
		pkts[2] = make([]u8, n, context.temp_allocator)
		copy(pkts[2], big[:n])
		pkts[3] = pkts[1]
	}

	for p, mode in pkts {
		mut := make([]u8, len(p), context.temp_allocator)
		for iter in 0 ..< 600 {
			copy(mut, p)
			cut := len(mut)
			if iter % 3 == 0 {
				cut = rng_below(&rng, len(mut))
			} else {
				mut[rng_below(&rng, len(mut))] ~= u8(1 + rng_below(&rng, 255))
			}
			err: Error
			switch mode {
			case 0:
				a: Tls_Auth
				tls_auth_init(&a, &key, .SHA256, .Zero)
				_, err = tls_auth_unwrap(&a, mut[:cut], out[:])
			case 1, 3:
				c: Tls_Crypt
				tls_crypt_init(&c, &key, .Server)
				_, err = tls_crypt_unwrap(&c, mut[:cut], out[:])
			case 2:
				c: Tls_Crypt
				m: Metadata
				_, err = tls_crypt_v2_server_unwrap(&v.sk, mut[:cut], out[:], &c, &m)
			}
			testing.expectf(t, err != .None, "mode %d iter %d: mutated packet accepted", mode, iter)
		}
		// And the untouched packet still works.
		err: Error
		switch mode {
		case 0:
			a: Tls_Auth
			tls_auth_init(&a, &key, .SHA256, .Zero)
			_, err = tls_auth_unwrap(&a, p, out[:])
		case 1, 3:
			c: Tls_Crypt
			tls_crypt_init(&c, &key, .Server)
			_, err = tls_crypt_unwrap(&c, p, out[:])
		case 2:
			c: Tls_Crypt
			m: Metadata
			_, err = tls_crypt_v2_server_unwrap(&v.sk, p, out[:], &c, &m)
		}
		testing.expect_value(t, err, Error.None)
	}
}

// a stateless server builds each reply from a fresh
// counter, so two replies for the same input are byte-identical (and the
// second looks like a replay to the client).
@(test)
stateless_reply_uses_fresh_counter :: proc(t: ^testing.T) {
	v := make_v2({METADATA_TYPE_USER, 'x'})
	reply := unhex("40 " + SPEC_SID + " 01 00000000 0102030405060708 00000000")
	out1, out2: [128]u8
	n1, n2: int
	for i in 0 ..< 2 {
		ctx: Tls_Crypt
		tls_crypt_init(&ctx, &v.ck.kc, .Server)
		if i == 0 {
			n1, _ = tls_crypt_wrap(&ctx, SPEC_NOW, reply, out1[:])
		} else {
			n2, _ = tls_crypt_wrap(&ctx, SPEC_NOW, reply, out2[:])
		}
	}
	expect_bytes(t, out1[:n1], out2[:n2], "two stateless replies")
	id, tm, _ := crypt_peek_wrap_id(out1[:n1])
	testing.expect_value(t, id, 1)
	testing.expect_value(t, tm, SPEC_TIME)

	// A client that already took the first copy drops the second as a replay.
	cli: Tls_Crypt
	tls_crypt_v2_client_init(&cli, &v.ck)
	back: [128]u8
	_, err := tls_crypt_unwrap(&cli, out1[:n1], back[:])
	testing.expect_value(t, err, Error.None)
	_, err = tls_crypt_unwrap(&cli, out2[:n2], back[:])
	testing.expect_value(t, err, Error.Replay)
}
