// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"
import "noir:proto/config"
import "noir:proto/ossl"

// The decision table of the proofs, row by row. Pins: alice (1), alice's second device (2), bob (3), carol disabled (4).
// A key with no pin and a chain: 50, named by the certificate.

PW_FILE :: "peer-passwords users.txt\n"
OPT_FILE :: "verify-client-cert optional\npeer-passwords users.txt\n"
OPT_EXT :: "verify-client-cert optional\nauth-external 9\n"

chain_in :: proc(name: string, username := "", has_password := false) -> Auth_Input {
	return Auth_Input {
		key = peer_key(50),
		has_key = true,
		cert_name = name,
		proof = .Chain,
		username = username,
		has_password = has_password,
	}
}

pin_in :: proc(n: u64, username := "", has_password := false) -> Auth_Input {
	in_ := pinned_in(n, username)
	in_.proof = .Pin
	in_.has_password = has_password
	return in_
}

nocert_in :: proc(username := "", has_password := false) -> Auth_Input {
	return Auth_Input{username = username, has_password = has_password}
}

@(private = "file")
decide :: proc(f: ^Auth_Fixture, in_: Auth_Input) -> Decision {
	return auth_decide(&f.auth, &f.pt, in_, 0)
}

@(private = "file")
expect_reject :: proc(t: ^testing.T, d: Decision, reason: Reject_Reason, loc := #caller_location) {
	testing.expect_value(t, d.kind, Decision_Kind.Reject, loc = loc)
	testing.expect_value(t, d.reject.reason, reason, loc = loc)
}

// ---- row 1: require, no password source

@(test)
test_proofs_row1_require_without_source_ignores_the_password :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// A pin: the certificate decides, a password is not looked at.
	d := decide(f, pin_in(1, "alice", true))
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.proofs, Proof_Set{.Pin})
	testing.expect_value(t, f.auth.stats.pending_password, u64(0))

	c, ok2 := auth_fixture(t, SERVER_BASE)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(c)
	// A chain: the same, and the username of the client is ignored.
	d = decide(c, chain_in("laptop-17", "someone", true))
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "laptop-17")
	testing.expect_value(t, d.source, Identity_Source.Cert_Name)
	testing.expect_value(t, d.proofs, Proof_Set{.Chain})
}

// ---- row 2: a certificate that passes, a user name and a password

@(test)
test_proofs_row2_require_with_hash_file_enforces_both :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + PW_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// A pinned key: the hash file must check the password.
	d := decide(f, pin_in(1, "alice", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.source, Identity_Source.Pin)
	testing.expect_value(t, d.proofs, Proof_Set{.Pin})
	testing.expect(t, d.pinned)
	testing.expect_value(t, d.n_kicks, 0)
	testing.expect_value(t, f.auth.stats.accepted, u64(0))
	// ... and the result of that check goes on to an accept.
	r := auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, r.proofs, Proof_Set{.Pin, .Password})
	testing.expect_value(t, identity_str(&r.identity), "alice")
	testing.expect_value(t, f.auth.stats.accepted, u64(1))

	// A chain certificate: the identity is the certificate name.
	d = decide(f, chain_in("laptop-17", "laptop-17", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, d.source, Identity_Source.Cert_Name)
	testing.expect_value(t, d.proofs, Proof_Set{.Chain})
	r = auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.proofs, Proof_Set{.Chain, .Password})
}

@(test)
test_proofs_user_name_must_be_the_certificate_identity :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + PW_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// Another user name, with a pin and with a chain.
	d := decide(f, pin_in(1, "bob", true))
	expect_reject(t, d, .Username_Mismatch)
	d = decide(f, chain_in("laptop-17", "bob", true))
	expect_reject(t, d, .Username_Mismatch)
	testing.expect_value(t, identity_str(&d.identity), "laptop-17") // who was refused
	// A password with no user name is not the identity either.
	d = decide(f, chain_in("laptop-17", "", true))
	expect_reject(t, d, .Username_Mismatch)
	d = decide(f, pin_in(1, "", true))
	expect_reject(t, d, .Username_Mismatch)
	// No regard to case.
	d = decide(f, chain_in("Laptop-17", "LAPTOP-17", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, identity_str(&d.identity), "Laptop-17") // keeps the form of the certificate
	d = decide(f, pin_in(1, "ALICE", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, identity_str(&d.identity), "alice") // keeps the form of the peers file
	// Only ASCII letters fold.
	d = decide(f, chain_in("\xc3\x89mile", "\xc3\xa9mile", true))
	expect_reject(t, d, .Username_Mismatch)
}

@(test)
test_proofs_row2_require_with_controller_only :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "auth-external 7\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// The controller checks the password: the daemon proved the chain only.
	d := decide(f, chain_in("laptop-17", "laptop-17", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, d.external_timeout, 7)
	testing.expect_value(t, d.proofs, Proof_Set{.Chain})
	testing.expect_value(t, identity_str(&d.identity), "laptop-17")
	// Both are enforced: another user name is refused before the controller.
	d = decide(f, chain_in("laptop-17", "jdoe", true))
	expect_reject(t, d, .Username_Mismatch)
}

// ---- row 3 and 4: a certificate that passes, no password

@(test)
test_proofs_row3_require_with_hash_file_refuses_no_password :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + PW_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, pin_in(1))
	expect_reject(t, d, .Password_Missing)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	d = decide(f, chain_in("laptop-17", "laptop-17", false))
	expect_reject(t, d, .Password_Missing)
	// The hash file goes first: a controller does not change this.
	g, ok2 := auth_fixture(t, SERVER_BASE, PW_FILE + "auth-external\n")
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(g)
	expect_reject(t, decide(g, chain_in("laptop-17")), .Password_Missing)
}

@(test)
test_proofs_row4_require_with_controller_only_takes_no_password :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "auth-external\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, chain_in("laptop-17"))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, identity_str(&d.identity), "laptop-17")
	testing.expect_value(t, d.proofs, Proof_Set{.Chain})
	// A user name with no password is not checked against the certificate.
	d = decide(f, chain_in("laptop-17", "jdoe"))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
}

// ---- row 5: require, no certificate or one that fails

@(test)
test_proofs_row5_require_refuses_without_a_good_certificate :: proc(t: ^testing.T) {
	// Pins.
	f, ok := auth_fixture(t, PINNED_BASE, PW_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	expect_reject(t, decide(f, nocert_in("alice", true)), .Key_Not_Pinned)
	expect_reject(t, decide(f, nocert_in()), .Key_Not_Pinned)
	expect_reject(t, decide(f, pin_in(99, "alice", true)), .Key_Not_Pinned)
	expect_reject(t, decide(f, pin_in(4, "carol", true)), .Key_Disabled)
	// Chain.
	c, ok2 := auth_fixture(t, SERVER_BASE, PW_FILE)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(c)
	expect_reject(t, decide(c, nocert_in("laptop-17", true)), .Chain_Not_Verified)
	in_ := chain_in("laptop-17", "laptop-17", true)
	in_.proof = .None // a certificate that nothing vouched for
	expect_reject(t, decide(c, in_), .Chain_Not_Verified)
	in_.proof = .Pin // a pin is not a chain
	expect_reject(t, decide(c, in_), .Chain_Not_Verified)
}

// ---- row 6: optional, a certificate that passes, no password

@(test)
test_proofs_row6_optional_accepts_a_certificate_alone :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, pin_in(1))
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.proofs, Proof_Set{.Pin})
	d = decide(f, chain_in("laptop-17"))
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.source, Identity_Source.Cert_Name)
	testing.expect_value(t, d.proofs, Proof_Set{.Chain})
	// A user name with no password does not change this.
	d = decide(f, chain_in("laptop-17", "jdoe"))
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	// With a controller it still decides, with an empty password.
	g, ok2 := auth_fixture(t, SERVER_BASE, OPT_EXT)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(g)
	d = decide(g, chain_in("laptop-17"))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, d.proofs, Proof_Set{.Chain})
}

// ---- row 7: optional, a certificate that passes, a user name and a password

@(test)
test_proofs_row7_optional_verifies_both :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, pin_in(3, "bob", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, identity_str(&d.identity), "bob")
	d = decide(f, chain_in("laptop-17", "laptop-17", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	expect_reject(t, decide(f, pin_in(3, "alice", true)), .Username_Mismatch)
	expect_reject(t, decide(f, chain_in("laptop-17", "bob", true)), .Username_Mismatch)

	// The controller alone checks the password.
	g, ok2 := auth_fixture(t, SERVER_BASE, OPT_EXT)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(g)
	d = decide(g, chain_in("laptop-17", "laptop-17", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, d.proofs, Proof_Set{.Chain})
	expect_reject(t, decide(g, chain_in("laptop-17", "bob", true)), .Username_Mismatch)
}

// ---- row 8: optional, a certificate that passes neither check

@(test)
test_proofs_row8_optional_refuses_a_failing_certificate :: proc(t: ^testing.T) {
	// TLS ends the handshake of such a client; the decision refuses it as well.
	f, ok := auth_fixture(t, PINNED_BASE, OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	expect_reject(t, decide(f, pin_in(99, "alice", true)), .Key_Not_Pinned)
	expect_reject(t, decide(f, pin_in(4, "carol", true)), .Key_Disabled)
	in_ := pin_in(1, "alice", true)
	in_.proof = .None
	expect_reject(t, decide(f, in_), .Key_Not_Pinned)
	// A certificate does not become a password login by failing.
	expect_reject(t, decide(f, pin_in(99)), .Key_Not_Pinned)
	c, ok2 := auth_fixture(t, SERVER_BASE, OPT_FILE)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(c)
	in_ = chain_in("laptop-17", "laptop-17", true)
	in_.proof = .None
	expect_reject(t, decide(c, in_), .Chain_Not_Verified)
}

// ---- row 9 and 10: optional, no certificate

@(test)
test_proofs_row9_optional_no_certificate_logs_in_by_password :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, nocert_in("dave", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, identity_str(&d.identity), "dave")
	testing.expect_value(t, d.source, Identity_Source.Username)
	testing.expect_value(t, d.proofs, Proof_Set{})
	// Never a certificate identity.
	testing.expect(t, !d.pinned && !d.by_chain)
	testing.expect_value(t, d.spki, [32]u8{})
	// The hash file says yes; the identity may take the form of the file.
	r := auth_password_passed(&f.auth, &f.pt, d, "Dave")
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&r.identity), "Dave")
	testing.expect_value(t, r.source, Identity_Source.Username)
	testing.expect_value(t, r.proofs, Proof_Set{.Password})
	// Without a form the user name stays as it came.
	r = auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, identity_str(&r.identity), "dave")
	// A form that is another name is a bug: refused.
	r = auth_password_passed(&f.auth, &f.pt, d, "erin")
	expect_reject(t, r, .Internal)
	// A decision that is not waiting for the hash file cannot be resumed.
	acc := decide(f, nocert_in("dave", true))
	acc.kind = .Accept
	expect_reject(t, auth_password_passed(&f.auth, &f.pt, acc), .Internal)

	// With only a controller: it checks the password.
	g, ok2 := auth_fixture(t, SERVER_BASE, OPT_EXT)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(g)
	d = decide(g, nocert_in("dave", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, identity_str(&d.identity), "dave")
	testing.expect_value(t, d.source, Identity_Source.Username)
	testing.expect_value(t, d.proofs, Proof_Set{})
}

@(test)
test_proofs_row9_hash_file_and_controller_in_order :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, OPT_FILE + "auth-external 4\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, nocert_in("dave", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password) // the hash file first
	testing.expect_value(t, f.auth.stats.pending, u64(0))
	r := auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Pending_External) // the controller second
	testing.expect_value(t, r.external_timeout, 4)
	testing.expect_value(t, r.proofs, Proof_Set{.Password})
	testing.expect_value(t, f.auth.stats.pending, u64(1))
	r = auth_resume(&f.auth, &f.pt, r)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, r.proofs, Proof_Set{.Password})
}

@(test)
test_proofs_row10_optional_needs_a_user_name_and_a_password :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// No user name: refused before a password source is asked.
	expect_reject(t, decide(f, nocert_in()), .No_Identity)
	expect_reject(t, decide(f, nocert_in("", true)), .No_Identity)
	// A user name with no password has neither proof.
	expect_reject(t, decide(f, nocert_in("dave")), .Password_Missing)
	expect_reject(t, decide(f, nocert_in("../x", true)), .Bad_Identity)
	testing.expect_value(t, f.auth.stats.pending_password, u64(0))
	// The same with a controller only: it never sees a client with neither proof.
	g, ok2 := auth_fixture(t, SERVER_BASE, OPT_EXT)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(g)
	expect_reject(t, decide(g, nocert_in()), .No_Identity)
	expect_reject(t, decide(g, nocert_in("dave")), .Password_Missing)
	testing.expect_value(t, g.auth.stats.pending, u64(0))
}

@(test)
test_proofs_a_certificate_result_must_match_the_key :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// A proof with no certificate is a bug in the caller: refused.
	in_ := nocert_in("dave", true)
	in_.proof = .Chain
	expect_reject(t, decide(f, in_), .Internal)
}

// A pin and a chain with `optional`: the mode is `either`.
@(test)
test_proofs_optional_with_pin_else_chain :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// A disabled pin never falls back to the chain.
	in_ := pin_in(4, "carol", true)
	in_.proof = .Chain
	in_.cert_name = "carol"
	expect_reject(t, decide(f, in_), .Key_Disabled)
	// A chain key that is not pinned.
	d := decide(f, chain_in("laptop-17", "laptop-17", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect(t, d.by_chain)
}

// A pin and a chain both needed, with a password.
@(test)
test_proofs_both_mode_adds_the_password :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\npeer-keys-mode both\n" + PW_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, pin_in(1, "alice", true))
	testing.expect_value(t, d.reject.reason, Reject_Reason.Chain_Not_Verified) // a pin proof is not a chain
	in_ := pinned_in(1, "alice")
	in_.has_password = true
	d = decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, d.proofs, Proof_Set{.Pin, .Chain})
	r := auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.proofs, Proof_Set{.Pin, .Chain, .Password})
}

// ---- limits and the password step

@(test)
test_proofs_limits_are_checked_before_and_after_the_password :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, OPT_FILE + "max-clients 2\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// A session of the same user is replaced: not listed while the password
	// is checked, listed after.
	old := connect_as(t, f, "Dave", 1)
	connect_as(t, f, "x", 2)
	d := decide(f, nocert_in("dave", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, d.n_kicks, 0)
	r := auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, r.n_kicks, 1)
	testing.expect_value(t, r.kicks[0], old)
	// A newcomer finds the server full before the password is checked.
	d = decide(f, nocert_in("erin", true))
	expect_reject(t, d, .Max_Clients)
	testing.expect_value(t, identity_str(&d.identity), "erin")
	testing.expect_value(t, d.source, Identity_Source.Username)
}

@(test)
test_proofs_rate_limit_is_charged_once :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, OPT_FILE + "connect-freq 1 100\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	src := addr_key_v4({198, 51, 100, 7}, 5000)
	in_ := nocert_in("dave", true)
	in_.src = src
	d := decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	r := auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	expect_reject(t, decide(f, in_), .Rate_Limited)
}

// ---- user names with no regard to case

@(test)
test_name_equal_folds_ascii_only :: proc(t: ^testing.T) {
	testing.expect(t, name_equal("alice", "ALICE"))
	testing.expect(t, name_equal("Alice-01", "aLICE-01"))
	testing.expect(t, name_equal("", ""))
	testing.expect(t, !name_equal("alice", "alic"))
	testing.expect(t, !name_equal("alice", "alicf"))
	// Other letters match byte for byte.
	testing.expect(t, name_equal("\xc3\xa9", "\xc3\xa9"))
	testing.expect(t, !name_equal("\xc3\xa9", "\xc3\x89"))
	// Characters next to the letters do not fold into them.
	testing.expect(t, !name_equal("@", "`"))
	testing.expect(t, !name_equal("[", "{"))
	testing.expect_value(t, hash_name("Alice"), hash_name("aLICE"))
}

@(test)
test_duplicate_identity_ignores_case :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	old := connect_pinned(t, f, "ALICE", 1)
	// A login of `alice` replaces the session of `ALICE`.
	d := decide(f, pinned_in(1))
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], old)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	// The lookup by name folds, and the peer keeps its own form.
	h, p := peers_by_identity(&f.pt, "Alice")
	testing.expect_value(t, h, old)
	testing.expect_value(t, p.identity, "ALICE")
	// With duplicate-cn a second one lives next to it in one chain.
	g, ok2 := auth_fixture(t, PINNED_BASE, "duplicate-cn\n")
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(g)
	connect_as(t, g, "alice", 1)
	connect_as(t, g, "Alice", 2)
	handles: [4]Peer_Handle
	testing.expect_value(t, peers_identity_handles(&g.pt, "aLiCe", handles[:]), 2)
}

@(test)
test_pinned_username_ignores_case :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, pinned_in(1, "ALICE"))
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	expect_reject(t, decide(f, pinned_in(1, "alicia")), .Username_Mismatch)
}

// ---- password logins only: `optional`, no `ca`, `peer-keys` or `peer-fingerprint`

@(private = "file")
NO_VERIFIER_BASE :: `server 10.8.0.0 255.255.255.0
dev tun
<cert>
CERT
</cert>
<key>
KEY
</key>
`

@(test)
test_password_only_policy_has_no_certificate_proof :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, NO_VERIFIER_BASE, OPT_FILE)
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	p := auth_policy_from_config(&cfg.server)
	testing.expect_value(t, p.proofs, Proof_Set{.Password})
	testing.expect(t, p.optional)

	// A controller alone: no proof of this package at all.
	cfg2, ok2 := make_cfg(t, NO_VERIFIER_BASE, OPT_EXT)
	if !ok2 {
		return
	}
	defer config.destroy(&cfg2)
	testing.expect_value(t, auth_policy_from_config(&cfg2.server).proofs, Proof_Set{})
}

@(test)
test_password_only_logins_use_the_user_name :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, NO_VERIFIER_BASE, OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, nocert_in("Alice", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect_value(t, identity_str(&d.identity), "Alice")
	testing.expect_value(t, d.source, Identity_Source.Username)
	testing.expect(t, !d.pinned && !d.by_chain)
	testing.expect_value(t, d.spki, [32]u8{})
	// The hash file gives its own spelling of the name; the proof is the password.
	d = auth_password_passed(&f.auth, &f.pt, d, "alice")
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.proofs, Proof_Set{.Password})
	// The rows for a client with no certificate.
	expect_reject(t, decide(f, nocert_in()), .No_Identity)
	expect_reject(t, decide(f, nocert_in("alice")), .Password_Missing)
}

@(test)
test_password_only_never_gives_a_certificate_identity :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, NO_VERIFIER_BASE, OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// TLS asks for no certificate, so none reaches the decision. A key that shows
	// up anyway is refused, whatever proof is claimed for it.
	for proof in ([]ossl.Peer_Proof{.None, .Pin, .Chain}) {
		in_ := chain_in("laptop-17", "laptop-17", true)
		in_.proof = proof
		d := decide(f, in_)
		testing.expectf(t, d.kind == .Reject, "proof %v was not refused", proof)
		in_.cert_name = ""
		d = decide(f, in_)
		testing.expectf(t, d.kind == .Reject, "proof %v with no name was not refused", proof)
	}
	// The same with a controller alone.
	g, ok2 := auth_fixture(t, NO_VERIFIER_BASE, OPT_EXT)
	if !ok2 {
		return
	}
	defer auth_fixture_destroy(g)
	d := decide(g, nocert_in("alice", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, d.proofs, Proof_Set{})
	for proof in ([]ossl.Peer_Proof{.None, .Pin, .Chain}) {
		in_ := chain_in("laptop-17", "laptop-17", true)
		in_.proof = proof
		testing.expectf(t, decide(g, in_).kind == .Reject, "proof %v was not refused", proof)
	}
}
