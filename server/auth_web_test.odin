// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:strings"
import "core:testing"

// Web sign-in (`auth-web`): the decision rows for a client that says
// IV_SSO=webauth, and the session token of the daemon.

WEB_CFG :: "verify-client-cert optional\nauth-external 90\nauth-web\n"
WEB_FILE_CFG :: "verify-client-cert optional\nauth-external 90\npeer-passwords users.txt\nauth-web\n"
NO_WEB_CFG :: "verify-client-cert optional\nauth-external 90\n"

@(private = "file")
web_in :: proc(username := "", has_password := false) -> Auth_Input {
	return Auth_Input{username = username, has_password = has_password, web_auth = true}
}

@(private = "file")
decide :: proc(f: ^Auth_Fixture, in_: Auth_Input) -> Decision {
	return auth_decide(&f.auth, &f.pt, in_, 0)
}

@(test)
test_web_login_waits_for_the_controller :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, web_in())
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect(t, d.web_login)
	testing.expect_value(t, d.identity.len, u8(0))
	testing.expect_value(t, d.source, Identity_Source.None)
	testing.expect_value(t, d.proofs, Proof_Set{})
	testing.expect_value(t, d.external_timeout, 90)
	testing.expect(t, !d.pinned && !d.by_chain)
	// A user name with no password does not turn it into a login by name.
	d = decide(f, web_in("mallory"))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect(t, d.web_login)
	testing.expect_value(t, d.identity.len, u8(0))
}

@(test)
test_web_login_is_refused_without_the_option :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, NO_WEB_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, web_in())
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.No_Identity)
	d = decide(f, web_in("mallory"))
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Password_Missing)
	// A token form means nothing without the option.
	in_ := web_in("dave", true)
	in_.token = .Valid
	in_.token_identity = "mallory"
	d = decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, identity_str(&d.identity), "dave")
	testing.expect(t, .Token not_in d.proofs)
}

@(test)
test_web_login_needs_the_client_to_say_so :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, Auth_Input{})
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.No_Identity)
	d = decide(f, Auth_Input{username = "mallory"})
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Password_Missing)
}

@(test)
test_web_login_with_a_password_still_goes_the_old_way :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_FILE_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// A web client that sends a password: the hash file checks it.
	d := decide(f, web_in("dave", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	testing.expect(t, !d.web_login)
	testing.expect_value(t, identity_str(&d.identity), "dave")
	testing.expect_value(t, d.source, Identity_Source.Username)
	// With no password it never reaches the hash file.
	d = decide(f, web_in())
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect(t, d.web_login)
	// A password with no user name is still refused.
	d = decide(f, web_in("", true))
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.No_Identity)
}

@(test)
test_web_login_names_and_limits :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := decide(f, web_in())
	// An allow with no name does not pass.
	r := auth_resume(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Reject)
	testing.expect_value(t, r.reject.reason, Reject_Reason.No_Identity)
	// A bad name.
	r = auth_name_web(&f.auth, d, "a/b")
	testing.expect_value(t, r.reject.reason, Reject_Reason.Bad_Identity)
	r = auth_name_web(&f.auth, d, "")
	testing.expect_value(t, r.reject.reason, Reject_Reason.Bad_Identity)
	// A good one: the controller is the source of the identity.
	n := auth_name_web(&f.auth, d, "erin@example.test")
	testing.expect_value(t, n.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, identity_str(&n.identity), "erin@example.test")
	testing.expect_value(t, n.source, Identity_Source.Controller)
	testing.expect(t, !n.web_login)
	r = auth_resume(&f.auth, &f.pt, n)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, r.n_kicks, 0)
	// The name takes part in duplicate-cn: the old session of the name is a kick.
	h := connect_as(t, f, "erin@example.test", 1)
	r = auth_resume(&f.auth, &f.pt, n)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, r.n_kicks, 1)
	testing.expect_value(t, r.kicks[0], h)
	// A name cannot replace an identity.
	has := auth_name_web(&f.auth, n, "someone-else")
	testing.expect_value(t, has.kind, Decision_Kind.Reject)
	cert := auth_decide(&f.auth, &f.pt, chain_in("bob"), 0)
	has = auth_name_web(&f.auth, cert, "someone-else")
	testing.expect_value(t, has.kind, Decision_Kind.Reject)
}

@(test)
test_web_login_counts_against_max_clients :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_CFG + "max-clients 2\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// Two parked logins fill the server, a third is refused at once.
	in_ := web_in()
	d := decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	in_.parked = 1
	d = decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	in_.parked = 2
	d = decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Max_Clients)
}

@(test)
test_token_gives_the_identity_of_the_token :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	in_ := web_in("whatever", true)
	in_.token, in_.token_identity = .Valid, "erin@example.test"
	d := decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, identity_str(&d.identity), "erin@example.test")
	testing.expect_value(t, d.source, Identity_Source.Controller)
	testing.expect_value(t, d.proofs, Proof_Set{.Token})
	testing.expect(t, !d.web_login)
	testing.expect(t, !d.pinned && !d.by_chain)
	// The token of a client that did not say IV_SSO works as well.
	in_.web_auth = false
	d = decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, d.proofs, Proof_Set{.Token})
}

@(test)
test_token_that_is_not_valid_is_a_session_failure :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_FILE_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	in_ := web_in("dave", true)
	in_.token = .Invalid
	d := decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Token_Invalid)
	testing.expect_value(t, d.reject.kind, Reject_Kind.Auth_Failed_Session)
	// Not a password of the hash file, whatever the user name is.
	testing.expect_value(t, f.auth.stats.pending_password, u64(0))
	// A valid token with a bad identity is refused the same way.
	in_.token, in_.token_identity = .Valid, "a/b"
	d = decide(f, in_)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Token_Invalid)
}

@(test)
test_token_form_with_a_certificate_is_refused :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_FILE_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	in_ := chain_in("bob", "bob", true)
	in_.token = .Valid
	in_.token_identity = "bob"
	d := decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Token_Invalid)
	in_.token = .Invalid
	d = decide(f, in_)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Token_Invalid)
	// A certificate with a plain password is as before.
	d = decide(f, chain_in("bob", "bob", true))
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
}

@(test)
test_token_reject_kinds :: proc(t: ^testing.T) {
	r := reject_make(.Token_Invalid)
	testing.expect_value(t, r.kind, Reject_Kind.Auth_Failed_Session)
	testing.expect(t, len(reject_text(.Token_Invalid)) > 0)
}

@(test)
test_web_login_and_token_with_the_longest_name :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, WEB_CFG)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	long := strings.repeat("n", MAX_IDENTITY_LEN, context.temp_allocator)
	// A web login named with 255 bytes.
	d := decide(f, web_in())
	n := auth_name_web(&f.auth, d, long)
	testing.expect_value(t, n.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, identity_str(&n.identity), long)
	r := auth_resume(&f.auth, &f.pt, n)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	// 256 bytes is not an identity.
	n = auth_name_web(&f.auth, d, strings.repeat("n", MAX_IDENTITY_LEN + 1, context.temp_allocator))
	testing.expect_value(t, n.reject.reason, Reject_Reason.Bad_Identity)
	// The token of that sign-in gives the same name back.
	in_ := web_in("whatever", true)
	in_.token, in_.token_identity = .Valid, long
	d = decide(f, in_)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, identity_str(&d.identity), long)
	testing.expect_value(t, d.proofs, Proof_Set{.Token})
}
