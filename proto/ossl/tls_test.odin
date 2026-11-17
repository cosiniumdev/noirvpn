// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:fmt"
import "core:log"
import "core:strings"
import "core:testing"

// Test identities (see testdata/README.md). All are self-signed.
@(private = "file")
Identity :: struct {
	cert_pem: []u8,
	key_pem:  []u8,
	cert_der: []u8, // whole certificate, for the peer-fingerprint check
	spki_der: []u8, // SubjectPublicKeyInfo, for the key pin check
}

@(private = "file")
ED_SERVER := Identity {
	#load("testdata/ed25519_server.crt.pem"),
	#load("testdata/ed25519_server.key.pem"),
	#load("testdata/ed25519_server.crt.der"),
	#load("testdata/ed25519_server.spki.der"),
}
@(private = "file")
ED_CLIENT := Identity {
	#load("testdata/ed25519_client.crt.pem"),
	#load("testdata/ed25519_client.key.pem"),
	#load("testdata/ed25519_client.crt.der"),
	#load("testdata/ed25519_client.spki.der"),
}
@(private)
P256_SERVER := Identity {
	#load("testdata/p256_server.crt.pem"),
	#load("testdata/p256_server.key.pem"),
	#load("testdata/p256_server.crt.der"),
	#load("testdata/p256_server.spki.der"),
}
@(private = "file")
P256_CLIENT := Identity {
	#load("testdata/p256_client.crt.pem"),
	#load("testdata/p256_client.key.pem"),
	#load("testdata/p256_client.crt.der"),
	#load("testdata/p256_client.spki.der"),
}
@(private = "file")
MLDSA_SERVER := Identity {
	#load("testdata/mldsa65_server.crt.pem"),
	#load("testdata/mldsa65_server.key.pem"),
	#load("testdata/mldsa65_server.crt.der"),
	#load("testdata/mldsa65_server.spki.der"),
}
@(private = "file")
MLDSA_CLIENT := Identity {
	#load("testdata/mldsa65_client.crt.pem"),
	#load("testdata/mldsa65_client.key.pem"),
	#load("testdata/mldsa65_client.crt.der"),
	#load("testdata/mldsa65_client.spki.der"),
}
@(private = "file")
RSA_SERVER := Identity {
	#load("testdata/rsa_server.crt.pem"),
	#load("testdata/rsa_server.key.pem"),
	#load("testdata/rsa_server.crt.der"),
	#load("testdata/rsa_server.spki.der"),
}
@(private = "file")
CA_PEM := #load("testdata/ca.crt.pem")
@(private = "file")
OTHER_CA_PEM := #load("testdata/other_ca.crt.pem")
@(private = "file")
CHAIN_SERVER := Identity {
	#load("testdata/chain_server.crt.pem"),
	#load("testdata/chain_server.key.pem"),
	nil,
	nil,
}
@(private = "file")
CHAIN_CLIENT := Identity {
	#load("testdata/chain_client.crt.pem"),
	#load("testdata/chain_client.key.pem"),
	nil,
	nil,
}

@(private = "file")
pinned :: proc(role: Tls_Role, id: Identity, groups := "") -> Tls_Config {
	return Tls_Config {
		role = role,
		cert_pem = id.cert_pem,
		key_pem = id.key_pem,
		groups = groups,
		min_version = .TLS_1_3,
		verify = .Pinned,
		pin_check = test_pin_check,
	}
}

// Pins for one side of a test, plus what the check saw.
@(private = "file")
Pin_List :: struct {
	pins:  [4][SHA256_LEN]u8,
	n:     int,
	seen:  Peer_Key,
	calls: int,
}

// With `user` nil: accept the key of any test identity. Otherwise accept only
// the keys in the ^Pin_List, and record what was seen.
@(private = "file")
test_pin_check :: proc "contextless" (peer: Peer_Key, user: rawptr) -> bool {
	if user != nil {
		l := (^Pin_List)(user)
		l.seen = peer
		l.calls += 1
		for i in 0 ..< l.n {
			if l.pins[i] == peer.spki_sha256 {
				return true
			}
		}
		return false
	}
	known := [?]^Identity{&ED_SERVER, &ED_CLIENT, &P256_SERVER, &P256_CLIENT, &MLDSA_SERVER, &MLDSA_CLIENT}
	for id in known {
		if sha256(id.spki_der) == peer.spki_sha256 {
			return true
		}
	}
	return false
}

// Two contexts and two sessions.
@(private)
Pair :: struct {
	cctx, sctx: Tls_Ctx,
	c, s:       Tls_Session,
}

@(private)
pair_init :: proc(t: ^testing.T, p: ^Pair, ccfg, scfg: Tls_Config) -> bool {
	err: Error
	p.cctx, err = tls_ctx_create(ccfg)
	if !testing.expectf(t, err == .None, "client context: %v", err) {
		return false
	}
	p.sctx, err = tls_ctx_create(scfg)
	if !testing.expectf(t, err == .None, "server context: %v", err) {
		return false
	}
	p.c, err = tls_session_create(&p.cctx)
	if !testing.expectf(t, err == .None, "client session: %v", err) {
		return false
	}
	p.s, err = tls_session_create(&p.sctx)
	return testing.expectf(t, err == .None, "server session: %v", err)
}

@(private)
pair_destroy :: proc(p: ^Pair) {
	tls_session_destroy(&p.c)
	tls_session_destroy(&p.s)
	tls_ctx_destroy(&p.cctx)
	tls_ctx_destroy(&p.sctx)
}

// Runs the handshake and expects both sides to finish.
@(private)
handshake_ok :: proc(t: ^testing.T, p: ^Pair, loc := #caller_location) -> bool {
	cs, ss := tls_loopback(&p.c, &p.s)
	ok := cs == .Done && ss == .Done
	testing.expectf(
		t,
		ok,
		"handshake did not finish: client %v (%s), server %v (%s)",
		cs,
		tls_last_error(&p.c),
		ss,
		tls_last_error(&p.s),
		loc = loc,
	)
	return ok
}

// --- the handshake itself ---

@(test)
tls13_handshake_and_app_data :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT), pinned(.Server, ED_SERVER)) {
		return
	}

	// Nothing works before the handshake is done.
	buf: [64]u8
	_, st := tls_read_app(&p.c, buf[:])
	testing.expect_value(t, st, Io_Status.Not_Ready)
	testing.expect_value(t, tls_write_app(&p.c, buf[:4]), Io_Status.Not_Ready)
	testing.expect(t, !tls_export_keying_material(&p.c, "x", buf[:]))
	testing.expect_value(t, tls_negotiated_group_name(&p.c), "")

	if !handshake_ok(t, &p) {
		return
	}
	testing.expect_value(t, tls_version_name(&p.c), "TLSv1.3")
	testing.expect_value(t, tls_version_name(&p.s), "TLSv1.3")
	testing.expect_value(t, tls_state(&p.c), Tls_State.Established)
	// No session tickets: nothing is left to send after the handshake.
	testing.expect_value(t, tls_pending_out(&p.c), 0)
	testing.expect_value(t, tls_pending_out(&p.s), 0)

	// Client to server.
	msg := "PUSH_REQUEST"
	testing.expect_value(t, tls_write_app(&p.c, transmute([]u8)msg), Io_Status.Ok)
	testing.expect(t, tls_pending_out(&p.c) > len(msg), "ciphertext must be bigger than the text")
	tls_move(&p.c, &p.s)
	n, st2 := tls_read_app(&p.s, buf[:])
	testing.expect_value(t, st2, Io_Status.Ok)
	expect_bytes(t, buf[:n], transmute([]u8)msg, "server got")
	_, st3 := tls_read_app(&p.s, buf[:])
	testing.expect_value(t, st3, Io_Status.Want_More)

	// Server to client, 100 kB: many TLS records.
	big := make([]u8, 100_000, context.temp_allocator)
	for &b, i in big {
		b = u8(i * 13)
	}
	testing.expect_value(t, tls_write_app(&p.s, big), Io_Status.Ok)
	tls_move(&p.s, &p.c)
	got := make([dynamic]u8, 0, len(big), context.temp_allocator)
	chunk: [4096]u8
	for {
		m, st4 := tls_read_app(&p.c, chunk[:])
		if st4 != .Ok {
			testing.expect_value(t, st4, Io_Status.Want_More)
			break
		}
		append(&got, ..chunk[:m])
	}
	expect_bytes(t, got[:], big, "100 kB round trip")
}

// Moves the bytes in small pieces, as control-channel packets would.
@(test)
tls13_handshake_in_small_pieces :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT), pinned(.Server, ED_SERVER)) {
		return
	}
	// Each "packet" carries at most 100 bytes; every packet is fed alone
	// and followed by a handshake step.
	pkt: [100]u8
	cs, ss := Handshake_Status.Want_More, Handshake_Status.Want_More
	packets := 0
	for _ in 0 ..< 200 {
		if cs == .Want_More {
			cs = tls_handshake_step(&p.c)
		}
		for tls_pending_out(&p.c) > 0 {
			n := tls_take(&p.c, pkt[:])
			testing.expect(t, tls_feed(&p.s, pkt[:n]))
			if ss == .Want_More {
				ss = tls_handshake_step(&p.s)
			}
			packets += 1
		}
		for tls_pending_out(&p.s) > 0 {
			n := tls_take(&p.s, pkt[:])
			testing.expect(t, tls_feed(&p.c, pkt[:n]))
			if cs == .Want_More {
				cs = tls_handshake_step(&p.c)
			}
			packets += 1
		}
		if cs == .Done && ss == .Done {
			break
		}
	}
	testing.expect_value(t, cs, Handshake_Status.Done)
	testing.expect_value(t, ss, Handshake_Status.Done)
	testing.expectf(t, packets > 4, "expected the flights to span several packets, got %d", packets)
}

// --- key export ---

@(test)
exporter_keys_match :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT), pinned(.Server, ED_SERVER)) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}

	labels := [?]string{"EXPORTER-OpenVPN-datakeys", "EXPORTER-OpenVPN-dynamic-tls-crypt"}
	exported: [len(labels)][256]u8
	for label, i in labels {
		c, s: [256]u8
		testing.expectf(t, tls_export_keying_material(&p.c, label, c[:]), "client export %s", label)
		testing.expectf(t, tls_export_keying_material(&p.s, label, s[:]), "server export %s", label)
		expect_bytes(t, c[:], s[:], label)
		zero: [256]u8
		testing.expectf(t, c != zero, "%s: output is all zero", label)
		exported[i] = c
	}
	testing.expect(t, exported[0] != exported[1], "two labels must give different keys")

	// A second handshake gives other keys.
	p2: Pair
	defer pair_destroy(&p2)
	if !pair_init(t, &p2, pinned(.Client, ED_CLIENT), pinned(.Server, ED_SERVER)) {
		return
	}
	if !handshake_ok(t, &p2) {
		return
	}
	again: [256]u8
	testing.expect(t, tls_export_keying_material(&p2.c, labels[0], again[:]))
	testing.expect(t, again != exported[0], "a new session must export new keys")
}

// --- key exchange groups ---

@(private = "file")
negotiate :: proc(t: ^testing.T, client_groups, server_groups: string) -> (group: string, ok: bool) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT, client_groups), pinned(.Server, ED_SERVER, server_groups)) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	cg := tls_negotiated_group_name(&p.c)
	sg := tls_negotiated_group_name(&p.s)
	testing.expect_value(t, cg, sg)
	// Return constant strings: the name belongs to the library and `p` is
	// destroyed on return. The library writes "x25519" in lower case.
	for known in ([]string{"X25519MLKEM768", "X25519", "secp256r1"}) {
		if strings.equal_fold(cg, known) {
			return known, true
		}
	}
	testing.expectf(t, false, "unexpected group %q", cg)
	return
}

@(test)
group_hybrid_is_preferred :: proc(t: ^testing.T) {
	g, ok := negotiate(t, "X25519MLKEM768:X25519", "X25519MLKEM768:X25519")
	testing.expect(t, ok)
	testing.expect_value(t, g, "X25519MLKEM768")
}

@(test)
group_library_default_is_hybrid :: proc(t: ^testing.T) {
	g, ok := negotiate(t, "", "")
	testing.expect(t, ok)
	testing.expect_value(t, g, "X25519MLKEM768")
}

@(test)
group_client_x25519_only_falls_back :: proc(t: ^testing.T) {
	g, ok := negotiate(t, "X25519", "X25519MLKEM768:X25519")
	testing.expect(t, ok)
	testing.expect_value(t, g, "X25519")
}

@(test)
group_server_x25519_only_falls_back :: proc(t: ^testing.T) {
	// The client offers its hybrid key share first; the server cannot use it
	// and asks again (HelloRetryRequest). The result is still X25519.
	g, ok := negotiate(t, "X25519MLKEM768:X25519", "X25519")
	testing.expect(t, ok)
	testing.expect_value(t, g, "X25519")
}

@(test)
group_hybrid_only_server_refuses_classical_client :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT, "X25519"), pinned(.Server, ED_SERVER, "X25519MLKEM768")) {
		return
	}
	cs, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	testing.expect(t, len(tls_last_error(&p.s)) > 0, "server must say why")
	testing.expect(t, len(tls_last_error(&p.c)) > 0, "client must say why")
	log.infof("server: %s", tls_last_error(&p.s))
	log.infof("client: %s", tls_last_error(&p.c))
	// A failed session stays failed and does nothing else.
	testing.expect_value(t, tls_handshake_step(&p.s), Handshake_Status.Failed)
	buf: [16]u8
	_, st := tls_read_app(&p.s, buf[:])
	testing.expect_value(t, st, Io_Status.Failed)
	testing.expect(t, !tls_export_keying_material(&p.s, "x", buf[:]))
}

@(test)
group_hybrid_only_both_sides :: proc(t: ^testing.T) {
	g, ok := negotiate(t, "X25519MLKEM768", "X25519MLKEM768")
	testing.expect(t, ok)
	testing.expect_value(t, g, "X25519MLKEM768")
}

@(test)
group_list_errors :: proc(t: ^testing.T) {
	_, err := tls_ctx_create(pinned(.Client, ED_CLIENT, "NoSuchGroup"))
	testing.expect_value(t, err, Error.Bad_Config)
	long: [300]u8
	for &b in long {
		b = 'A'
	}
	_, err = tls_ctx_create(pinned(.Client, ED_CLIENT, string(long[:])))
	testing.expect_value(t, err, Error.Bad_Argument)
}

// Group list spellings that upstream OpenVPN users write (`tls-groups`).
// AWS-LC does not know some of them; the AWS-LC backend rewrites the list.
@(test)
group_list_spellings :: proc(t: ^testing.T) {
	// "*" means "send this key share at once" in OpenSSL; AWS-LC ignores it.
	g, ok := negotiate(t, "*X25519MLKEM768:*X25519", "X25519MLKEM768:X25519")
	testing.expect(t, ok)
	testing.expect_value(t, g, "X25519MLKEM768")
	// Upstream spellings of the NIST curves, and a list with several groups.
	g, ok = negotiate(t, "X25519:secp256r1:secp384r1", "secp256r1:X25519")
	testing.expect(t, ok)
	testing.expect_value(t, g, "X25519")
	g, ok = negotiate(t, "secp384r1:secp256r1", "secp256r1")
	testing.expect(t, ok)
	testing.expect_value(t, g, "secp256r1")
	g, ok = negotiate(t, "P-256", "secp256r1")
	testing.expect(t, ok)
	testing.expect_value(t, g, "secp256r1")
}

// The cost of the fallback to a classical peer, counted in flights from the
// client (1 = ClientHello alone, 3 = HelloRetryRequest happened). OpenSSL sends
// only the first key share unless "*" is used. AWS-LC sends the hybrid and
// X25519 shares when both are in the list. Only logged, plus a sanity bound.
@(test)
group_fallback_flights :: proc(t: ^testing.T) {
	count :: proc(t: ^testing.T, cgroups, sgroups: string) -> int {
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, pinned(.Client, ED_CLIENT, cgroups), pinned(.Server, ED_SERVER, sgroups)) {
			return -1
		}
		cs, ss := Handshake_Status.Want_More, Handshake_Status.Want_More
		flights := 0
		for _ in 0 ..< 16 {
			if cs == .Want_More {
				cs = tls_handshake_step(&p.c)
			}
			if tls_move(&p.c, &p.s) > 0 {
				flights += 1
			}
			if ss == .Want_More {
				ss = tls_handshake_step(&p.s)
			}
			tls_move(&p.s, &p.c)
			if cs == .Done && ss == .Done {
				return flights
			}
		}
		testing.expect(t, false, "handshake did not finish")
		return -1
	}
	plain := count(t, "X25519MLKEM768:X25519", "X25519")
	starred := count(t, "*X25519MLKEM768:*X25519", "X25519")
	both := count(t, "X25519MLKEM768:X25519", "X25519MLKEM768:X25519")
	log.infof("client flights: hybrid-first vs classical server %d, with '*' %d, vs hybrid server %d", plain, starred, both)
	testing.expect(t, plain >= 2 && plain <= 3)
	testing.expect(t, starred == 2, "with both shares sent there must be no retry")
	testing.expect_value(t, both, 2)
}

// The signature scheme of the certificate is independent of the key exchange.
@(test)
mldsa_with_classical_group :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, MLDSA_CLIENT, "X25519"), pinned(.Server, MLDSA_SERVER, "X25519")) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect(t, strings.equal_fold(tls_negotiated_group_name(&p.c), "X25519"))
}

// --- key pinning ---

// Handshake with `server` and `client` identities in pinned mode, then check
// that each side sees the other's key and certificate exactly as the files say.
@(private = "file")
check_pinning :: proc(t: ^testing.T, name: string, server, client: Identity) -> bool {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, client), pinned(.Server, server)) {
		return false
	}
	if !handshake_ok(t, &p) {
		return false
	}
	// The client sees the server's key, the server sees the client's.
	c_sees, ok1 := tls_peer_spki_sha256(&p.c)
	s_sees, ok2 := tls_peer_spki_sha256(&p.s)
	testing.expectf(t, ok1 && ok2, "%s: no peer certificate", name)
	want_srv := sha256(server.spki_der)
	want_cli := sha256(client.spki_der)
	expect_bytes(t, c_sees[:], want_srv[:], fmt.tprintf("%s: spki seen by client", name))
	expect_bytes(t, s_sees[:], want_cli[:], fmt.tprintf("%s: spki seen by server", name))
	testing.expect(t, want_srv != want_cli, "test identities must differ")

	c_cert, ok3 := tls_peer_cert_sha256(&p.c)
	s_cert, ok4 := tls_peer_cert_sha256(&p.s)
	testing.expectf(t, ok3 && ok4, "%s: no peer certificate", name)
	want_srv_cert := sha256(server.cert_der)
	want_cli_cert := sha256(client.cert_der)
	expect_bytes(t, c_cert[:], want_srv_cert[:], fmt.tprintf("%s: cert hash seen by client", name))
	expect_bytes(t, s_cert[:], want_cli_cert[:], fmt.tprintf("%s: cert hash seen by server", name))
	testing.expect(t, c_cert != c_sees, "cert hash and key hash are different things")
	return true
}

@(test)
pinning_ed25519 :: proc(t: ^testing.T) {
	check_pinning(t, "ed25519", ED_SERVER, ED_CLIENT)
}

@(test)
pinning_p256 :: proc(t: ^testing.T) {
	check_pinning(t, "p256", P256_SERVER, P256_CLIENT)
}

// ML-DSA-65 certificates in a TLS 1.3 handshake.
@(test)
pinning_mldsa65 :: proc(t: ^testing.T) {
	check_pinning(t, "mldsa65", MLDSA_SERVER, MLDSA_CLIENT)
}

// A client with an ML-DSA key and a server with an Ed25519 key, mixed.
@(test)
pinning_mixed_algorithms :: proc(t: ^testing.T) {
	check_pinning(t, "ed25519 server, mldsa65 client", ED_SERVER, MLDSA_CLIENT)
	check_pinning(t, "p256 server, ed25519 client", P256_SERVER, ED_CLIENT)
}

@(test)
pinned_mode_needs_a_client_certificate :: proc(t: ^testing.T) {
	ccfg := pinned(.Client, ED_CLIENT)
	ccfg.cert_pem = nil // the client has nothing to show
	ccfg.key_pem = nil
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, ccfg, pinned(.Server, ED_SERVER)) {
		return
	}
	cs, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	log.infof("server said: %s", tls_last_error(&p.s))
	// The client may have finished before the server's refusal reached it.
	// It must not be able to claim a peer identity for the server's side.
	_, ok := tls_peer_spki_sha256(&p.s)
	testing.expect(t, !ok, "server must have no peer key")
	_ = cs
}

@(test)
peer_identity_is_absent_before_handshake :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT), pinned(.Server, ED_SERVER)) {
		return
	}
	_, ok := tls_peer_spki_sha256(&p.c)
	testing.expect(t, !ok)
	_, ok = tls_peer_cert_sha256(&p.c)
	testing.expect(t, !ok)
}

// --- common name ---

@(private = "file")
accept_all :: proc "contextless" (peer: Peer_Key, user: rawptr) -> bool {
	return true
}

@(private = "file")
cn_of :: proc(s: ^Tls_Session, buf: []u8) -> (string, bool) {
	n, ok := tls_peer_common_name(s, buf)
	return string(buf[:n]), ok
}

@(test)
common_name_in_chain_mode :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), chain(.Server, CHAIN_SERVER, CA_PEM)) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	buf: [COMMON_NAME_MAX]u8
	cn, ok := cn_of(&p.s, buf[:])
	testing.expect(t, ok)
	testing.expect_value(t, cn, "noir-test-chain-client")
	cn, ok = cn_of(&p.c, buf[:])
	testing.expect(t, ok)
	testing.expect_value(t, cn, "noir-test-chain-server")
}

@(test)
peer_serial_of_a_chain_client :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), chain(.Server, CHAIN_SERVER, CA_PEM)) {
		return
	}
	out: [SERIAL_BYTES_MAX]u8
	_, ok := tls_peer_serial(&p.s, &out)
	testing.expect(t, !ok, "no certificate before the handshake")
	if !handshake_ok(t, &p) {
		return
	}
	// openssl x509 -serial: 06C12A11DF8FE0011827E66745B27F37FEB0C3EA
	want := [SERIAL_BYTES_MAX]u8{0x06, 0xC1, 0x2A, 0x11, 0xDF, 0x8F, 0xE0, 0x01, 0x18, 0x27, 0xE6, 0x67, 0x45, 0xB2, 0x7F, 0x37, 0xFE, 0xB0, 0xC3, 0xEA}
	n: int
	n, ok = tls_peer_serial(&p.s, &out)
	testing.expect(t, ok)
	testing.expect_value(t, n, SERIAL_BYTES_MAX)
	testing.expect(t, out == want)
}

@(test)
common_name_in_pinned_mode :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, P256_CLIENT), pinned(.Server, P256_SERVER)) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	buf: [COMMON_NAME_MAX]u8
	cn, ok := cn_of(&p.s, buf[:])
	testing.expect(t, ok)
	testing.expect_value(t, cn, "noir-test-p256-client")
}

@(test)
common_name_needs_room_and_a_handshake :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT), pinned(.Server, ED_SERVER)) {
		return
	}
	buf: [COMMON_NAME_MAX]u8
	_, ok := cn_of(&p.s, buf[:])
	testing.expect(t, !ok, "no certificate before the handshake")
	if !handshake_ok(t, &p) {
		return
	}
	small: [8]u8
	_, ok = cn_of(&p.s, small[:])
	testing.expect(t, !ok, "a CN that does not fit is refused, not cut")
	cn, ok2 := cn_of(&p.s, buf[:])
	testing.expect(t, ok2)
	testing.expect_value(t, cn, "noir-test-ed25519-client")
	_, ok = cn_of(&p.s, nil)
	testing.expect(t, !ok)
}

@(test)
common_name_refuses_odd_subjects :: proc(t: ^testing.T) {
	NO_CN := Identity{#load("testdata/nocn_client.crt.pem"), #load("testdata/nocn_client.key.pem"), nil, nil}
	TWO_CN := Identity{#load("testdata/twocn_client.crt.pem"), #load("testdata/twocn_client.key.pem"), nil, nil}
	for id, i in ([2]Identity{NO_CN, TWO_CN}) {
		p: Pair
		defer pair_destroy(&p)
		scfg := pinned(.Server, ED_SERVER)
		scfg.pin_check = accept_all
		ccfg := pinned(.Client, id)
		ccfg.pin_check = accept_all
		if !pair_init(t, &p, ccfg, scfg) {
			return
		}
		if !handshake_ok(t, &p) {
			return
		}
		buf: [COMMON_NAME_MAX]u8
		_, ok := cn_of(&p.s, buf[:])
		testing.expectf(t, !ok, "subject %d must give no CN", i)
		// The key pin still works for such a peer.
		_, ok = tls_peer_spki_sha256(&p.s)
		testing.expect(t, ok)
	}
}

// --- chain mode ---

@(private = "file")
chain :: proc(role: Tls_Role, id: Identity, ca: []u8) -> Tls_Config {
	cfg := pinned(role, id)
	cfg.verify = .Chain
	cfg.ca_pem = ca
	return cfg
}

@(test)
chain_mode_accepts_certificates_from_the_ca :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), chain(.Server, CHAIN_SERVER, CA_PEM)) {
		return
	}
	handshake_ok(t, &p)
}

@(test)
chain_mode_rejects_other_ca :: proc(t: ^testing.T) {
	// The client trusts a different CA than the one that signed the server.
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, OTHER_CA_PEM), chain(.Server, CHAIN_SERVER, CA_PEM)) {
		return
	}
	cs, _ := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	log.infof("client said: %s", tls_last_error(&p.c))
}

@(test)
chain_mode_rejects_self_signed :: proc(t: ^testing.T) {
	// Same self-signed certificate that pinned mode accepts.
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), pinned(.Server, ED_SERVER)) {
		return
	}
	cs, _ := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, cs, Handshake_Status.Failed)
}

// --- configuration errors ---

@(test)
config_errors_are_reported :: proc(t: ^testing.T) {
	garbage := transmute([]u8)string("this is not PEM")
	cfg := pinned(.Server, ED_SERVER)

	c1 := cfg
	c1.cert_pem = garbage
	_, err := tls_ctx_create(c1)
	testing.expect_value(t, err, Error.Bad_Cert)

	c2 := cfg
	c2.key_pem = garbage
	_, err = tls_ctx_create(c2)
	testing.expect_value(t, err, Error.Bad_Key)

	// A key that does not belong to the certificate.
	c3 := cfg
	c3.key_pem = ED_CLIENT.key_pem
	_, err = tls_ctx_create(c3)
	testing.expect_value(t, err, Error.Bad_Key)

	// A server needs a certificate.
	c4 := cfg
	c4.cert_pem = nil
	c4.key_pem = nil
	_, err = tls_ctx_create(c4)
	testing.expect_value(t, err, Error.Bad_Cert)

	// Chain mode needs trust anchors.
	c5 := chain(.Client, ED_CLIENT, nil)
	_, err = tls_ctx_create(c5)
	testing.expect_value(t, err, Error.Bad_Config)
	c5.ca_pem = garbage
	_, err = tls_ctx_create(c5)
	testing.expect_value(t, err, Error.Bad_Config)
}

// --- handshake sizes ---

// Bytes the handshake puts on the wire, per direction, and the size of the
// first flight (the ClientHello). These decide how many control packets a
// handshake needs.
@(private = "file")
Wire_Sizes :: struct {
	client_hello: int,
	c2s, s2c:     int,
}

@(private = "file")
wire_sizes :: proc(t: ^testing.T, ccfg, scfg: Tls_Config) -> (w: Wire_Sizes, ok: bool) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, ccfg, scfg) {
		return
	}
	cs, ss := Handshake_Status.Want_More, Handshake_Status.Want_More
	for round in 0 ..< 16 {
		if cs == .Want_More {
			cs = tls_handshake_step(&p.c)
		}
		n := tls_move(&p.c, &p.s)
		if round == 0 {
			w.client_hello = n
		}
		w.c2s += n
		if ss == .Want_More {
			ss = tls_handshake_step(&p.s)
		}
		w.s2c += tls_move(&p.s, &p.c)
		if cs == .Done && ss == .Done {
			return w, true
		}
	}
	return
}

@(test)
handshake_wire_sizes :: proc(t: ^testing.T) {
	classic, ok1 := wire_sizes(t, pinned(.Client, ED_CLIENT, "X25519"), pinned(.Server, ED_SERVER, "X25519"))
	hybrid, ok2 := wire_sizes(
		t,
		pinned(.Client, ED_CLIENT, "X25519MLKEM768:X25519"),
		pinned(.Server, ED_SERVER, "X25519MLKEM768:X25519"),
	)
	pq, ok3 := wire_sizes(
		t,
		pinned(.Client, MLDSA_CLIENT, "X25519MLKEM768:X25519"),
		pinned(.Server, MLDSA_SERVER, "X25519MLKEM768:X25519"),
	)
	dflt, ok4 := wire_sizes(t, pinned(.Client, ED_CLIENT), pinned(.Server, ED_SERVER))
	if !(ok1 && ok2 && ok3 && ok4) {
		return
	}
	log.infof("ed25519 + library default:   ClientHello %5d B, client->server %5d B, server->client %5d B", dflt.client_hello, dflt.c2s, dflt.s2c)
	log.infof("ed25519 + X25519:            ClientHello %5d B, client->server %5d B, server->client %5d B", classic.client_hello, classic.c2s, classic.s2c)
	log.infof("ed25519 + X25519MLKEM768:    ClientHello %5d B, client->server %5d B, server->client %5d B", hybrid.client_hello, hybrid.c2s, hybrid.s2c)
	log.infof("ML-DSA-65 + X25519MLKEM768:  ClientHello %5d B, client->server %5d B, server->client %5d B", pq.client_hello, pq.c2s, pq.s2c)
	// An ML-KEM-768 key share is 1184 bytes; an ML-DSA-65 certificate is
	// 5.5 kB and its signature 3.3 kB.
	testing.expect(t, hybrid.client_hello > 1184, "hybrid ClientHello must carry the ML-KEM key share")
	testing.expect(t, hybrid.client_hello > classic.client_hello + 1000)
	testing.expect(t, pq.s2c > 8000, "ML-DSA server flight must hold a 5.5 kB certificate and a 3.3 kB signature")
}

// --- TLS 1.2 ---

// Peers may be limited to TLS 1.2 (upstream `tls-version-max`). Handshake,
// key export, and pin hashes must work the same way there.
@(test)
tls12_works_too :: proc(t: ^testing.T) {
	scfg := pinned(.Server, ED_SERVER, "X25519MLKEM768:X25519")
	scfg.min_version = .TLS_1_2
	scfg.max_version = .TLS_1_2
	ccfg := pinned(.Client, ED_CLIENT, "X25519MLKEM768:X25519")
	ccfg.min_version = .TLS_1_2
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, ccfg, scfg) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect_value(t, tls_version_name(&p.c), "TLSv1.2")
	// TLS 1.2 has no hybrid group; it falls back to X25519.
	testing.expect(t, strings.equal_fold(tls_negotiated_group_name(&p.c), "X25519"))
	for label in ([]string{"EXPORTER-OpenVPN-datakeys", "EXPORTER-OpenVPN-dynamic-tls-crypt"}) {
		c, s: [256]u8
		testing.expect(t, tls_export_keying_material(&p.c, label, c[:]))
		testing.expect(t, tls_export_keying_material(&p.s, label, s[:]))
		expect_bytes(t, c[:], s[:], label)
	}
	got, ok := tls_peer_spki_sha256(&p.c)
	want := sha256(ED_SERVER.spki_der)
	testing.expect(t, ok)
	expect_bytes(t, got[:], want[:], "spki over TLS 1.2")
	// Application data too.
	msg := "hello over 1.2"
	buf: [32]u8
	testing.expect_value(t, tls_write_app(&p.s, transmute([]u8)msg), Io_Status.Ok)
	tls_move(&p.s, &p.c)
	n, st := tls_read_app(&p.c, buf[:])
	testing.expect_value(t, st, Io_Status.Ok)
	expect_bytes(t, buf[:n], transmute([]u8)msg, "app data")
}

@(test)
version_range_without_overlap_fails :: proc(t: ^testing.T) {
	scfg := pinned(.Server, ED_SERVER)
	scfg.min_version = .TLS_1_2
	scfg.max_version = .TLS_1_2
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT), scfg) { 	// client wants 1.3 at least
		return
	}
	cs, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	testing.expect_value(t, ss, Handshake_Status.Failed)
}

// --- fail-closed pin check ---

@(test)
pinned_mode_requires_a_pin_check :: proc(t: ^testing.T) {
	cfg := pinned(.Server, ED_SERVER)
	cfg.pin_check = nil
	_, err := tls_ctx_create(cfg)
	testing.expect_value(t, err, Error.Bad_Config)
}

// The server pins only the P-256 client key; an Ed25519 client is refused
// during the handshake, and the check saw both hashes of the real peer.
@(test)
server_refuses_unpinned_client_key :: proc(t: ^testing.T) {
	spins := Pin_List{n = 1}
	spins.pins[0] = sha256(P256_CLIENT.spki_der)
	scfg := pinned(.Server, ED_SERVER)
	scfg.pin_user = &spins
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, ED_CLIENT), scfg) {
		return
	}
	cs, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	log.infof("server said: %s", tls_last_error(&p.s))
	testing.expect_value(t, spins.calls, 1)
	want_spki := sha256(ED_CLIENT.spki_der)
	want_cert := sha256(ED_CLIENT.cert_der)
	expect_bytes(t, spins.seen.spki_sha256[:], want_spki[:], "spki seen by the pin check")
	expect_bytes(t, spins.seen.cert_sha256[:], want_cert[:], "cert hash seen by the pin check")
	// In TLS 1.3 the client finishes before the server checks the client
	// certificate, so the refusal reaches the client as an alert on its next
	// read. It must never yield application data.
	if cs == .Done {
		tls_move(&p.s, &p.c)
		buf: [64]u8
		n, st := tls_read_app(&p.c, buf[:])
		testing.expect_value(t, n, 0)
		testing.expect(t, st == .Failed || st == .Closed, "client must see the server's refusal")
	}
	log.infof("client said: %s", tls_last_error(&p.c))
}

// The client pins a different server key and refuses the real one.
@(test)
client_refuses_unpinned_server_key :: proc(t: ^testing.T) {
	cpins := Pin_List{n = 1}
	cpins.pins[0] = sha256(P256_SERVER.spki_der)
	ccfg := pinned(.Client, ED_CLIENT)
	ccfg.pin_user = &cpins
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, ccfg, pinned(.Server, ED_SERVER)) {
		return
	}
	cs, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	testing.expect_value(t, cpins.calls, 1)
	_ = ss // the server may finish its side first; the client refused
}

// Both sides pin exactly the other's key: the handshake completes and each
// check ran once.
@(test)
exact_pins_on_both_sides :: proc(t: ^testing.T) {
	spins := Pin_List{n = 1}
	spins.pins[0] = sha256(MLDSA_CLIENT.spki_der)
	cpins := Pin_List{n = 1}
	cpins.pins[0] = sha256(MLDSA_SERVER.spki_der)
	scfg := pinned(.Server, MLDSA_SERVER)
	scfg.pin_user = &spins
	ccfg := pinned(.Client, MLDSA_CLIENT)
	ccfg.pin_user = &cpins
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, ccfg, scfg) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect_value(t, spins.calls, 1)
	testing.expect_value(t, cpins.calls, 1)
}

// --- the outer TLS of the `tls` transport: no certificate checks, SNI, ALPN, suites ---

@(private)
outer :: proc(role: Tls_Role, id: Identity, suites := "") -> Tls_Config {
	cfg := Tls_Config {
		role               = role,
		// TLS 1.2 with an ECDSA P-256 certificate needs P-256 among the groups.
		groups             = "X25519MLKEM768:X25519:P-256",
		min_version        = .TLS_1_2,
		verify             = .None,
		tls13_ciphersuites = suites,
	}
	if role == .Server {
		cfg.cert_pem = id.cert_pem
		cfg.key_pem = id.key_pem
	}
	return cfg
}

// Does `hay` hold `needle`?
@(private = "file")
contains :: proc(hay: []u8, needle: string) -> bool {
	n := len(needle)
	for i in 0 ..< len(hay) - n + 1 {
		if string(hay[i:i + n]) == needle {
			return true
		}
	}
	return false
}

@(test)
none_mode_takes_any_server_and_asks_for_no_client_certificate :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	// The server certificate is signed by a CA nobody trusts here.
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, CHAIN_SERVER)) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect_value(t, tls_version_name(&p.c), "TLSv1.3")
	_, ok := tls_peer_key(&p.s)
	testing.expect(t, !ok, "the server must not have asked for a client certificate")
	key, kok := tls_peer_key(&p.c)
	testing.expect(t, kok, "the client has the server key")
	// Same value as the pin accessor.
	pin, _ := tls_peer_spki_sha256(&p.c)
	cert, _ := tls_peer_cert_sha256(&p.c)
	expect_bytes(t, key.spki_sha256[:], pin[:], "spki")
	expect_bytes(t, key.cert_sha256[:], cert[:], "cert hash")
}

@(test)
none_mode_reports_the_server_key :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	key, ok := tls_peer_key(&p.c)
	testing.expect(t, ok)
	want := sha256(P256_SERVER.spki_der)
	expect_bytes(t, key.spki_sha256[:], want[:], "the pin of the server key")
	wantc := sha256(P256_SERVER.cert_der)
	expect_bytes(t, key.cert_sha256[:], wantc[:], "the hash of the server certificate")
}

@(test)
none_mode_works_on_tls12 :: proc(t: ^testing.T) {
	ccfg := outer(.Client, {})
	scfg := outer(.Server, P256_SERVER)
	ccfg.max_version = .TLS_1_2
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, ccfg, scfg) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect_value(t, tls_version_name(&p.c), "TLSv1.2")
	_, ok := tls_peer_key(&p.c)
	testing.expect(t, ok)
	msg := "hello"
	testing.expect_value(t, tls_write_app(&p.s, transmute([]u8)msg), Io_Status.Ok)
	tls_move(&p.s, &p.c)
	buf: [16]u8
	n, st := tls_read_app(&p.c, buf[:])
	testing.expect_value(t, st, Io_Status.Ok)
	expect_bytes(t, buf[:n], transmute([]u8)msg, "payload")
}

@(test)
peer_key_needs_a_handshake :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		return
	}
	_, ok := tls_peer_key(&p.c)
	testing.expect(t, !ok)
}

@(test)
sni_and_alpn_are_in_the_client_hello :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		return
	}
	testing.expect(t, tls_session_set_sni(&p.c, "vpn.example.org"))
	testing.expect(t, tls_session_set_alpn(&p.c, {"http/1.1"}))
	testing.expect_value(t, tls_server_name(&p.s), "")
	tls_handshake_step(&p.c)
	hello := make([]u8, tls_pending_out(&p.c), context.temp_allocator)
	tls_take(&p.c, hello)
	testing.expect(t, len(hello) > 0)
	testing.expect(t, contains(hello, "vpn.example.org"), "SNI is in the ClientHello")
	testing.expect(t, contains(hello, "http/1.1"), "ALPN is in the ClientHello")
	// Carry on with the handshake: the server sees the name.
	tls_feed(&p.s, hello)
	cs, ss := tls_handshake_step(&p.c), tls_handshake_step(&p.s)
	_ = cs
	_ = ss
	testing.expect_value(t, tls_server_name(&p.s), "vpn.example.org")
	tls_move(&p.s, &p.c)
	cs2, ss2 := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, cs2, Handshake_Status.Done)
	testing.expect_value(t, ss2, Handshake_Status.Done)
}

@(test)
no_sni_when_none_is_set :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		return
	}
	tls_handshake_step(&p.c)
	hello := make([]u8, tls_pending_out(&p.c), context.temp_allocator)
	tls_take(&p.c, hello)
	testing.expect(t, !contains(hello, "http/1.1"), "no ALPN without a call")
	tls_feed(&p.s, hello)
	tls_handshake_step(&p.s)
	testing.expect_value(t, tls_server_name(&p.s), "")
}

@(test)
sni_and_alpn_refuse_bad_input :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		return
	}
	testing.expect(t, !tls_session_set_sni(&p.c, ""))
	testing.expect(t, !tls_session_set_sni(&p.c, "a\x00b"))
	long := strings.repeat("a", 300, context.temp_allocator)
	testing.expect(t, !tls_session_set_sni(&p.c, long))
	testing.expect(t, !tls_session_set_alpn(&p.c, {""}))
	testing.expect(t, !tls_session_set_alpn(&p.c, {long}))
	testing.expect(t, tls_session_set_alpn(&p.c, {"h2", "http/1.1"}))
}

@(test)
tls13_suite_preference_is_applied :: proc(t: ^testing.T) {
	for suites in ([?]string{"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"}) {
		p: Pair
		ok := pair_init(t, &p, outer(.Client, {}, suites), outer(.Server, P256_SERVER, suites))
		if ok && handshake_ok(t, &p) {
			first := suites[:strings.index_byte(suites, ':')]
			testing.expect_value(t, tls_cipher_name(&p.c), first)
			testing.expect_value(t, tls_cipher_name(&p.s), first)
		}
		pair_destroy(&p)
	}
	// The name is empty before the handshake.
	p: Pair
	defer pair_destroy(&p)
	if pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		testing.expect_value(t, tls_cipher_name(&p.c), "")
	}
}

@(test)
tls13_suite_list_errors :: proc(t: ^testing.T) {
	ctx, err := tls_ctx_create(outer(.Client, {}, "TLS_NO_SUCH_SUITE"))
	testing.expect_value(t, err, Error.Bad_Config)
	tls_ctx_destroy(&ctx)
	ctx, err = tls_ctx_create(outer(.Client, {}, strings.repeat("A", 300, context.temp_allocator)))
	testing.expect_value(t, err, Error.Bad_Argument)
	tls_ctx_destroy(&ctx)
}

@(test)
close_notify_reaches_the_peer :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		return
	}
	testing.expect(t, !tls_shutdown(&p.c), "no shutdown before the handshake")
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect(t, tls_shutdown(&p.c))
	testing.expect(t, tls_pending_out(&p.c) > 0, "the alert is queued")
	tls_move(&p.c, &p.s)
	buf: [16]u8
	_, st := tls_read_app(&p.s, buf[:])
	testing.expect_value(t, st, Io_Status.Closed)
}

@(test)
has_input_follows_the_buffers :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, outer(.Client, {}), outer(.Server, P256_SERVER)) {
		return
	}
	if !handshake_ok(t, &p) {
		return
	}
	testing.expect(t, !tls_has_input(&p.s))
	big := make([]u8, 40_000, context.temp_allocator)
	testing.expect_value(t, tls_write_app(&p.c, big), Io_Status.Ok)
	tls_move(&p.c, &p.s)
	testing.expect(t, tls_has_input(&p.s))
	// Read a little: the rest stays buffered.
	small: [100]u8
	_, st := tls_read_app(&p.s, small[:])
	testing.expect_value(t, st, Io_Status.Ok)
	testing.expect(t, tls_has_input(&p.s))
	chunk: [4096]u8
	for {
		_, st2 := tls_read_app(&p.s, chunk[:])
		if st2 != .Ok {
			break
		}
	}
	testing.expect(t, !tls_has_input(&p.s))
}

@(test)
certificate_key_kinds :: proc(t: ^testing.T) {
	testing.expect_value(t, cert_key_kind(P256_SERVER.cert_pem), Key_Kind.Ec)
	testing.expect_value(t, cert_key_kind(ED_SERVER.cert_pem), Key_Kind.Ed25519)
	testing.expect_value(t, cert_key_kind(RSA_SERVER.cert_pem), Key_Kind.Rsa)
	testing.expect_value(t, cert_key_kind(MLDSA_SERVER.cert_pem), Key_Kind.Other)
	// A chain: the first certificate counts.
	chain := strings.concatenate({string(P256_SERVER.cert_pem), string(RSA_SERVER.cert_pem)}, context.temp_allocator)
	testing.expect_value(t, cert_key_kind(transmute([]u8)chain), Key_Kind.Ec)
	testing.expect_value(t, cert_key_kind(transmute([]u8)string("not a certificate")), Key_Kind.Invalid)
	testing.expect_value(t, cert_key_kind(nil), Key_Kind.Invalid)
}

// ------------------------------------------------------------ Pin_Or_Chain

// What the lookup of a `.Pin_Or_Chain` test accepts and refuses.
@(private = "file")
Lookup_List :: struct {
	accept:     [4][SHA256_LEN]u8,
	n:          int,
	refuse_all: bool,
	calls:      int,
}

@(private = "file")
test_pin_lookup :: proc "contextless" (peer: Peer_Key, user: rawptr) -> Pin_Verdict {
	l := (^Lookup_List)(user)
	l.calls += 1
	if l.refuse_all {
		return .Refused
	}
	for i in 0 ..< l.n {
		if l.accept[i] == peer.spki_sha256 {
			return .Accepted
		}
	}
	return .Unknown
}

@(private = "file")
either :: proc(l: ^Lookup_List) -> Tls_Config {
	cfg := chain(.Server, CHAIN_SERVER, CA_PEM)
	cfg.verify = .Pin_Or_Chain
	cfg.pin_lookup = test_pin_lookup
	cfg.pin_user = l
	return cfg
}

@(test)
either_accepts_a_ca_client_without_a_pin :: proc(t: ^testing.T) {
	l: Lookup_List
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), either(&l)) {
		return
	}
	if handshake_ok(t, &p) {
		testing.expect(t, tls_chain_verified(&p.s), "the chain let the client in")
	}
	testing.expect_value(t, l.calls, 1)
}

@(test)
either_accepts_a_pinned_self_signed_client :: proc(t: ^testing.T) {
	l := Lookup_List{n = 1}
	l.accept[0] = sha256(ED_CLIENT.spki_der)
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, ED_CLIENT, CA_PEM), either(&l)) {
		return
	}
	if handshake_ok(t, &p) {
		testing.expect(t, !tls_chain_verified(&p.s), "the pin let the client in, not the chain")
	}
}

@(test)
either_refuses_an_unpinned_self_signed_client :: proc(t: ^testing.T) {
	l: Lookup_List
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, ED_CLIENT, CA_PEM), either(&l)) {
		return
	}
	_, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	log.infof("server said: %s", tls_last_error(&p.s))
}

// A refused pin (a disabled key) fails even with a good chain.
@(test)
either_refused_pin_does_not_fall_back_to_the_chain :: proc(t: ^testing.T) {
	l := Lookup_List{refuse_all = true}
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), either(&l)) {
		return
	}
	_, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect_value(t, l.calls, 1)
}

@(test)
either_needs_a_lookup_and_a_server :: proc(t: ^testing.T) {
	l: Lookup_List
	cfg := either(&l)
	cfg.pin_lookup = nil
	_, err := tls_ctx_create(cfg)
	testing.expect_value(t, err, Error.Bad_Config)
	cfg = either(&l)
	cfg.role = .Client
	_, err = tls_ctx_create(cfg)
	testing.expect_value(t, err, Error.Bad_Config)
}

// ------------------------------------------------------- client_cert_optional

@(private = "file")
no_cert :: proc(cfg: Tls_Config) -> Tls_Config {
	c := cfg
	c.cert_pem, c.key_pem = nil, nil
	return c
}

@(private = "file")
optional :: proc(cfg: Tls_Config) -> Tls_Config {
	c := cfg
	c.client_cert_optional = true
	return c
}

@(test)
a_server_refuses_a_client_without_a_certificate_by_default :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, no_cert(chain(.Client, CHAIN_CLIENT, CA_PEM)), chain(.Server, CHAIN_SERVER, CA_PEM)) {
		return
	}
	_, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
}

@(test)
optional_is_for_a_server_only :: proc(t: ^testing.T) {
	ctx, err := tls_ctx_create(optional(chain(.Client, CHAIN_CLIENT, CA_PEM)))
	testing.expect_value(t, err, Error.Bad_Config)
	if err == .None {
		tls_ctx_destroy(&ctx)
	}
}

@(test)
optional_chain_takes_no_certificate :: proc(t: ^testing.T) {
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, no_cert(chain(.Client, CHAIN_CLIENT, CA_PEM)), optional(chain(.Server, CHAIN_SERVER, CA_PEM))) {
		return
	}
	if handshake_ok(t, &p) {
		testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.None)
		_, has := tls_peer_key(&p.s)
		testing.expect(t, !has, "no certificate, so no key")
	}
}

// A server with no way to check a certificate (`.None`, as the daemon sets it
// for password logins only) does not ask for one. A client that has a
// certificate connects, and the server sees none.
@(private = "file")
no_verifier_server :: proc(id: Identity) -> Tls_Config {
	cfg := outer(.Server, id)
	cfg.client_cert_optional = true
	return cfg
}

@(test)
no_verifier_server_asks_for_no_certificate :: proc(t: ^testing.T) {
	// A certificate that no check would accept (another CA) is not a problem.
	for ccfg in ([]Tls_Config{chain(.Client, CHAIN_CLIENT, CA_PEM), chain(.Client, ED_CLIENT, CA_PEM), no_cert(chain(.Client, CHAIN_CLIENT, CA_PEM))}) {
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, ccfg, no_verifier_server(CHAIN_SERVER)) {
			return
		}
		if handshake_ok(t, &p) {
			testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.None)
			testing.expect(t, !tls_peer_has_cert(&p.s), "the server must not have a client certificate")
			_, has := tls_peer_key(&p.s)
			testing.expect(t, !has, "no certificate, so no key")
			_, has = tls_peer_spki_sha256(&p.s)
			testing.expect(t, !has, "no certificate, so no pin")
		}
	}
}

@(test)
optional_chain_judges_a_certificate_that_is_sent :: proc(t: ^testing.T) {
	{
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), optional(chain(.Server, CHAIN_SERVER, CA_PEM))) {
			return
		}
		if handshake_ok(t, &p) {
			testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.Chain)
		}
	}
	// A certificate without a chain to the CA ends the handshake.
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, ED_CLIENT, CA_PEM), optional(chain(.Server, CHAIN_SERVER, CA_PEM))) {
		return
	}
	_, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.None)
}

@(test)
optional_pinned_takes_no_certificate_and_judges_a_sent_one :: proc(t: ^testing.T) {
	l := Pin_List{n = 1}
	l.pins[0] = sha256(ED_CLIENT.spki_der)
	scfg := optional(pinned(.Server, ED_SERVER))
	scfg.pin_user = &l
	{
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, no_cert(pinned(.Client, ED_CLIENT)), scfg) {
			return
		}
		if handshake_ok(t, &p) {
			testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.None)
		}
		testing.expect_value(t, l.calls, 0)
	}
	{
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, pinned(.Client, ED_CLIENT), scfg) {
			return
		}
		if handshake_ok(t, &p) {
			testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.Pin)
		}
	}
	// A key that is not in the list ends the handshake.
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, pinned(.Client, P256_CLIENT), scfg) {
		return
	}
	_, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
}

@(test)
optional_either_says_which_proof_let_the_client_in :: proc(t: ^testing.T) {
	l := Lookup_List{n = 1}
	l.accept[0] = sha256(ED_CLIENT.spki_der)
	scfg := optional(either(&l))
	// No certificate.
	{
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, no_cert(chain(.Client, CHAIN_CLIENT, CA_PEM)), scfg) {
			return
		}
		if handshake_ok(t, &p) {
			testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.None)
		}
		testing.expect_value(t, l.calls, 0)
	}
	// A pinned self-signed key.
	{
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, chain(.Client, ED_CLIENT, CA_PEM), scfg) {
			return
		}
		if handshake_ok(t, &p) {
			testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.Pin)
		}
	}
	// A certificate with a chain.
	{
		p: Pair
		defer pair_destroy(&p)
		if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), scfg) {
			return
		}
		if handshake_ok(t, &p) {
			testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.Chain)
		}
	}
	// A key that is neither pinned nor chained ends the handshake.
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, P256_CLIENT, CA_PEM), scfg) {
		return
	}
	_, ss := tls_loopback(&p.c, &p.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	// A refused (disabled) pin never falls back to the chain.
	l2 := Lookup_List{refuse_all = true}
	p2: Pair
	defer pair_destroy(&p2)
	if !pair_init(t, &p2, chain(.Client, CHAIN_CLIENT, CA_PEM), optional(either(&l2))) {
		return
	}
	_, ss = tls_loopback(&p2.c, &p2.s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
}

@(test)
proof_is_none_before_the_handshake_ends :: proc(t: ^testing.T) {
	l: Lookup_List
	p: Pair
	defer pair_destroy(&p)
	if !pair_init(t, &p, chain(.Client, CHAIN_CLIENT, CA_PEM), either(&l)) {
		return
	}
	testing.expect_value(t, tls_peer_proof(&p.s), Peer_Proof.None)
}
