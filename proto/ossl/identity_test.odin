// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:strings"
import "core:testing"

@(private = "file")
SERVER_CERT := #load("testdata/ed25519_server.crt.pem")
@(private = "file")
SERVER_KEY := #load("testdata/ed25519_server.key.pem")
@(private = "file")
SERVER_SPKI := #load("testdata/ed25519_server.spki.der")
@(private = "file")
MLDSA_SERVER_CERT := #load("testdata/mldsa65_server.crt.pem")
@(private = "file")
MLDSA_SERVER_KEY := #load("testdata/mldsa65_server.key.pem")
@(private = "file")
MLDSA_SERVER_SPKI := #load("testdata/mldsa65_server.spki.der")

// The one key that a side accepts, and what it saw.
@(private = "file")
One_Pin :: struct {
	pin:  [SHA256_LEN]u8,
	seen: int,
}

@(private = "file")
one_pin_check :: proc "contextless" (peer: Peer_Key, user: rawptr) -> bool {
	p := (^One_Pin)(user)
	p.seen += 1
	return peer.spki_sha256 == p.pin
}

@(private = "file")
pinned_cfg :: proc(role: Tls_Role, cert, key: []u8, pin: ^One_Pin) -> Tls_Config {
	return Tls_Config {
		role = role,
		cert_pem = cert,
		key_pem = key,
		min_version = .TLS_1_3,
		verify = .Pinned,
		pin_check = one_pin_check,
		pin_user = pin,
	}
}

// A generated identity as the client of a pinned handshake: the server
// accepts only the generated pin, the client only the server's key.
@(private = "file")
handshake_with :: proc(t: ^testing.T, id: Identity, server_cert, server_key, server_spki: []u8) -> bool {
	spin := One_Pin{pin = id.spki_sha256}
	cpin := One_Pin{pin = sha256(server_spki)}
	cctx, cerr := tls_ctx_create(pinned_cfg(.Client, transmute([]u8)id.cert_pem, transmute([]u8)id.key_pem, &cpin))
	if !testing.expectf(t, cerr == .None, "client context with the generated identity: %v", cerr) {
		return false
	}
	defer tls_ctx_destroy(&cctx)
	sctx, serr := tls_ctx_create(pinned_cfg(.Server, server_cert, server_key, &spin))
	if !testing.expectf(t, serr == .None, "server context: %v", serr) {
		return false
	}
	defer tls_ctx_destroy(&sctx)
	c, _ := tls_session_create(&cctx)
	defer tls_session_destroy(&c)
	s, _ := tls_session_create(&sctx)
	defer tls_session_destroy(&s)
	cs, ss := tls_loopback(&c, &s)
	ok := testing.expectf(t, cs == .Done && ss == .Done, "handshake: client %v (%s), server %v (%s)", cs, tls_last_error(&c), ss, tls_last_error(&s))
	testing.expect_value(t, spin.seen, 1)
	seen, _ := tls_peer_spki_sha256(&s)
	testing.expect(t, seen == id.spki_sha256, "the server sees the generated pin")
	return ok
}

@(private = "file")
check_kind :: proc(t: ^testing.T, kind: Identity_Kind) {
	id, err := identity_generate(kind, "alice laptop")
	defer identity_destroy(&id)
	if !testing.expectf(t, err == .None, "%v: identity_generate: %v", kind, err) {
		return
	}
	testing.expect(t, strings.has_prefix(id.cert_pem, "-----BEGIN CERTIFICATE-----\n"), "certificate PEM")
	testing.expect(t, strings.has_prefix(id.key_pem, "-----BEGIN PRIVATE KEY-----\n"), "unencrypted PKCS#8 key PEM")
	want_kind := Key_Kind.Ed25519 if kind == .Ed25519 else Key_Kind.Other
	testing.expect_value(t, cert_key_kind(transmute([]u8)id.cert_pem), want_kind)
	got, ok := cert_identity_kind(transmute([]u8)id.cert_pem)
	testing.expectf(t, ok && got == kind, "%v: cert_identity_kind %v %v", kind, got, ok)
	pin, pok := cert_spki_sha256(transmute([]u8)id.cert_pem)
	testing.expect(t, pok && pin == id.spki_sha256, "cert_spki_sha256 gives the pin of identity_generate")

	other, err2 := identity_generate(kind, "alice laptop")
	defer identity_destroy(&other)
	testing.expect(t, err2 == .None && other.spki_sha256 != id.spki_sha256, "a second key differs")

	handshake_with(t, id, SERVER_CERT, SERVER_KEY, SERVER_SPKI)
	handshake_with(t, id, MLDSA_SERVER_CERT, MLDSA_SERVER_KEY, MLDSA_SERVER_SPKI)
}

@(test)
identity_ed25519 :: proc(t: ^testing.T) {
	check_kind(t, .Ed25519)
}

@(test)
identity_mldsa65 :: proc(t: ^testing.T) {
	check_kind(t, .Mldsa65)
}

// A server with a pin of another key refuses the generated identity.
@(test)
identity_other_pin_is_refused :: proc(t: ^testing.T) {
	id, err := identity_generate(.Ed25519, "bob")
	defer identity_destroy(&id)
	if !testing.expect(t, err == .None) {
		return
	}
	spin := One_Pin{pin = sha256(SERVER_SPKI)}
	cpin := One_Pin{pin = sha256(SERVER_SPKI)}
	cctx, _ := tls_ctx_create(pinned_cfg(.Client, transmute([]u8)id.cert_pem, transmute([]u8)id.key_pem, &cpin))
	defer tls_ctx_destroy(&cctx)
	sctx, _ := tls_ctx_create(pinned_cfg(.Server, SERVER_CERT, SERVER_KEY, &spin))
	defer tls_ctx_destroy(&sctx)
	c, _ := tls_session_create(&cctx)
	defer tls_session_destroy(&c)
	s, _ := tls_session_create(&sctx)
	defer tls_session_destroy(&s)
	_, ss := tls_loopback(&c, &s)
	testing.expect_value(t, ss, Handshake_Status.Failed)
}

@(test)
identity_common_name_limits :: proc(t: ^testing.T) {
	_, err := identity_generate(.Ed25519, "")
	testing.expect_value(t, err, Error.Bad_Argument)
	_, err = identity_generate(.Ed25519, strings.repeat("a", IDENTITY_CN_MAX + 1, context.temp_allocator))
	testing.expect_value(t, err, Error.Bad_Argument)
	id, err2 := identity_generate(.Ed25519, strings.repeat("é", IDENTITY_CN_MAX / 2, context.temp_allocator))
	defer identity_destroy(&id)
	testing.expect_value(t, err2, Error.None)
}

// The pin of the test certificates that the openssl CLI generated.
@(test)
identity_pin_of_cli_certificates :: proc(t: ^testing.T) {
	pin, ok := cert_spki_sha256(SERVER_CERT)
	testing.expect(t, ok && pin == sha256(SERVER_SPKI), "Ed25519 pin")
	pin, ok = cert_spki_sha256(MLDSA_SERVER_CERT)
	testing.expect(t, ok && pin == sha256(MLDSA_SERVER_SPKI), "ML-DSA-65 pin")
	k, kok := cert_identity_kind(MLDSA_SERVER_CERT)
	testing.expect(t, kok && k == .Mldsa65, "ML-DSA-65 kind")
	p256 := #load("testdata/p256_client.crt.pem")
	_, kok = cert_identity_kind(p256)
	testing.expect(t, !kok, "a P-256 key is neither kind")
	_, ok = cert_spki_sha256(transmute([]u8)string("not a certificate"))
	testing.expect(t, !ok, "no certificate, no pin")
}
