// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:testing"

// RFC 7914 section 11.
@(test)
test_pbkdf2_rfc7914 :: proc(t: ^testing.T) {
	out: [64]u8
	ok := pbkdf2_sha256(transmute([]u8)string("passwd"), transmute([]u8)string("salt"), 1, out[:])
	testing.expect(t, ok)
	expect_bytes(
		t,
		out[:],
		unhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
		"rfc7914 1",
	)
	ok = pbkdf2_sha256(transmute([]u8)string("Password"), transmute([]u8)string("NaCl"), 80000, out[:])
	testing.expect(t, ok)
	expect_bytes(
		t,
		out[:],
		unhex("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
		"rfc7914 2",
	)
}

// RFC 6070 style vector for SHA-256 (iterations 2), a short output.
@(test)
test_pbkdf2_short_output :: proc(t: ^testing.T) {
	out: [20]u8
	ok := pbkdf2_sha256(transmute([]u8)string("password"), transmute([]u8)string("salt"), 2, out[:])
	testing.expect(t, ok)
	expect_bytes(t, out[:], unhex("ae4d0c95af6b46d32d0adff928f06dd02a303f8e"), "2 iterations")
}

@(test)
test_pbkdf2_refuses_bad_arguments :: proc(t: ^testing.T) {
	out: [32]u8
	pw := transmute([]u8)string("x")
	testing.expect(t, !pbkdf2_sha256(pw, pw, 0, out[:]))
	testing.expect(t, !pbkdf2_sha256(pw, pw, PBKDF2_MAX_ITERATIONS + 1, out[:]))
	testing.expect(t, !pbkdf2_sha256(pw, pw, 1, nil))
	// An empty password and an empty salt work.
	testing.expect(t, pbkdf2_sha256(nil, nil, 1, out[:]))
}

@(test)
test_ct_equal :: proc(t: ^testing.T) {
	a := []u8{1, 2, 3}
	testing.expect(t, ct_equal(a, []u8{1, 2, 3}))
	testing.expect(t, !ct_equal(a, []u8{1, 2, 4}))
	testing.expect(t, !ct_equal(a, []u8{1, 2}))
	testing.expect(t, ct_equal(nil, nil))
}
