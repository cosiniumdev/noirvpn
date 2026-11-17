// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:reflect"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:proto/config"

// A server for auth tests: pins for alice (1), alice's second device (2), bob
// (3) and carol, who is disabled (4).
Auth_Fixture :: struct {
	cfg:    config.Config,
	pt:     Peer_Table,
	store:  Pin_Store,
	auth:   Auth_State,
}

auth_fixture :: proc(
	t: ^testing.T,
	base := PINNED_BASE,
	extra := "",
	max_peers := 16,
) -> (
	f: ^Auth_Fixture,
	ok: bool,
) {
	f = new(Auth_Fixture)
	f.cfg, ok = make_cfg(t, base, extra)
	if !ok {
		free(f)
		return nil, false
	}
	text := peers_text(
		strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator),
		strings.concatenate({"alice ", pin_text(2)}, context.temp_allocator),
		strings.concatenate({"bob ", pin_text(3)}, context.temp_allocator),
		strings.concatenate({"carol ", pin_text(4), " disabled"}, context.temp_allocator),
	)
	if strings.contains(base, "peer-keys") || strings.contains(extra, "peer-keys ") {
		pin_store_init(&f.store, make_pins(t, text))
	}
	testing.expect(t, peers_init(&f.pt, Peer_Table_Params{max_peers, 10 * SEC, 1}))
	testing.expect(t, auth_init(&f.auth, auth_policy_from_config(&f.cfg.server), &f.store))
	return f, true
}

auth_fixture_destroy :: proc(f: ^Auth_Fixture) {
	auth_destroy(&f.auth)
	peers_destroy(&f.pt)
	pin_table_destroy(pin_store_current(&f.store))
	config.destroy(&f.cfg)
	free(f)
}

// Connects an identity into the peer table, as a stand-in for a live session.
connect_as :: proc(t: ^testing.T, f: ^Auth_Fixture, name: string, n: int) -> Peer_Handle {
	return add_peer(t, &f.pt, name, n)
}

pinned_in :: proc(n: u64, username := "", src := Addr_Key{}) -> Auth_Input {
	return Auth_Input{key = peer_key(n), has_key = true, username = username, src = src, proof = .Chain}
}

@(test)
test_auth_policy_from_config :: proc(t: ^testing.T) {
	check :: proc(t: ^testing.T, base, extra: string, want: Proof_Set, both := false, loc := #caller_location) {
		cfg, ok := make_cfg(t, base, extra, loc)
		if !ok {
			return
		}
		defer config.destroy(&cfg)
		p := auth_policy_from_config(&cfg.server)
		testing.expect_value(t, p.proofs, want, loc = loc)
		testing.expect_value(t, p.both, both, loc = loc)
	}
	check(t, PINNED_BASE, "", {.Pin})
	check(t, SERVER_BASE, "", {.Chain})
	check(t, SERVER_BASE, "peer-keys peers.txt\npeer-keys-mode both\n", {.Pin, .Chain}, true)
	check(t, SERVER_BASE, "peer-keys peers.txt\npeer-keys-mode either\n", {.Pin, .Chain})
	// `ca` with `peer-keys` and no mode is `either`.
	check(t, SERVER_BASE, "peer-keys peers.txt\n", {.Pin, .Chain})
	check(t, SERVER_BASE, "peer-passwords users.txt\n", {.Chain, .Password})
	check(t, PINNED_BASE, "peer-passwords users.txt\n", {.Pin, .Password})
	// `auth-external` is not a proof of this package.
	check(t, SERVER_BASE, "auth-external\n", {.Chain})

	cfg, ok := make_cfg(t, "server 10.8.0.0 255.255.255.0\ndev tun\n<cert>\nC\n</cert>\n<key>\nK\n</key>\n", "peer-fingerprint DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74\n")
	if ok {
		p := auth_policy_from_config(&cfg.server)
		testing.expect_value(t, p.proofs, Proof_Set{.Pin})
		testing.expect(t, p.fingerprint)
		config.destroy(&cfg)
	}

	cfg, ok = make_cfg(t, SERVER_BASE, "verify-client-cert optional\nauth-external 5\n")
	if ok {
		p := auth_policy_from_config(&cfg.server)
		testing.expect(t, p.optional)
		testing.expect(t, p.external)
		config.destroy(&cfg)
	}
	cfg, ok = make_cfg(t, SERVER_BASE, "")
	if ok {
		testing.expect(t, !auth_policy_from_config(&cfg.server).optional)
		config.destroy(&cfg)
	}

	cfg, ok = make_cfg(
		t,
		SERVER_BASE,
		"duplicate-cn\nmax-clients 7\nconnect-freq 3 20\nauth-external 12\n",
	)
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	p := auth_policy_from_config(&cfg.server)
	testing.expect(t, p.duplicate_cn)
	testing.expect_value(t, p.max_clients, 7)
	testing.expect(t, p.connect_freq_set)
	testing.expect_value(t, p.connect_freq, config.Rate_Limit{3, 20})
	testing.expect(t, p.external)
	testing.expect_value(t, p.external_timeout, 12)
}

@(test)
test_auth_pinned_accepts_known_key :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.source, Identity_Source.Pin)
	testing.expect(t, d.pinned)
	testing.expect_value(t, d.spki, digest_of(1))
	testing.expect_value(t, d.n_kicks, 0)
	// Her second device is the same identity.
	d = auth_decide(&f.auth, &f.pt, pinned_in(2), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, f.auth.stats.accepted, u64(2))
}

@(test)
test_auth_pinned_rejects :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	expect_reject :: proc(t: ^testing.T, f: ^Auth_Fixture, in_: Auth_Input, reason: Reject_Reason, kind: Reject_Kind, loc := #caller_location) {
		d := auth_decide(&f.auth, &f.pt, in_, 0)
		testing.expect_value(t, d.kind, Decision_Kind.Reject, loc = loc)
		testing.expect_value(t, d.reject.reason, reason, loc = loc)
		testing.expect_value(t, d.reject.kind, kind, loc = loc)
	}
	expect_reject(t, f, pinned_in(99), .Key_Not_Pinned, .Auth_Failed)
	expect_reject(t, f, pinned_in(4), .Key_Disabled, .Auth_Failed)
	expect_reject(t, f, Auth_Input{}, .Key_Not_Pinned, .Auth_Failed) // no certificate at all
	expect_reject(t, f, pinned_in(1, "mallory"), .Username_Mismatch, .Auth_Failed)
	expect_reject(t, f, pinned_in(3, "alice"), .Username_Mismatch, .Auth_Failed) // bob's key, alice's name
	// The right username is fine, and so is none.
	d := auth_decide(&f.auth, &f.pt, pinned_in(3, "bob"), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	d = auth_decide(&f.auth, &f.pt, pinned_in(3), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, f.auth.stats.rejected[.Key_Not_Pinned], u64(2))
	testing.expect_value(t, f.auth.stats.rejected[.Username_Mismatch], u64(2))
}

@(test)
test_auth_pinned_ignores_cert_name :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	in_ := pinned_in(1)
	in_.cert_name = "someone-else"
	d := auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
}

@(test)
test_auth_pinned_without_a_table_refuses :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	old := pin_store_swap(&f.store, nil)
	defer pin_table_destroy(old)
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Key_Not_Pinned)
}

@(test)
test_auth_pin_reload_takes_effect :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(3), 0).kind, Decision_Kind.Accept)
	// A new file without bob.
	fresh := make_pins(t, strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator))
	old := pin_store_swap(&f.store, fresh)
	defer pin_table_destroy(old)
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(3), 0).kind, Decision_Kind.Reject)
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(1), 0).kind, Decision_Kind.Accept)
}

@(test)
test_auth_ca_mode :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	in_ := Auth_Input {
		key            = peer_key(50),
		has_key        = true,
		cert_name      = "laptop-17",
		proof = .Chain,
	}
	d := auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "laptop-17")
	testing.expect_value(t, d.source, Identity_Source.Cert_Name)
	testing.expect(t, !d.pinned)
	// A username from the client is ignored (no password check exists).
	in_.username = "someone"
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, identity_str(&d.identity), "laptop-17")
	// The chain must have been verified.
	in_.proof = .Pin
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Chain_Not_Verified)
	in_.proof = .Chain
	// No name, or a name that cannot be an identity.
	in_.cert_name = ""
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.No_Identity)
	for bad in ([?]string{"../etc/passwd", "a/b", "..", "tab\there", "x\x00y"}) {
		in_.cert_name = bad
		d = auth_decide(&f.auth, &f.pt, in_, 0)
		testing.expectf(t, d.reject.reason == .Bad_Identity, "name %q: %v", bad, d.reject.reason)
	}
}

@(test)
test_auth_both_mode :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\npeer-keys-mode both\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// Chain and pin: the identity is the pinned username, the CN is not compared.
	in_ := pinned_in(1)
	in_.cert_name = "alice-laptop-cn"
	d := auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect(t, d.pinned)
	// No chain: refused, even with a good pin.
	in_.proof = .Pin
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Chain_Not_Verified)
	// A good chain but an unknown key: refused.
	in2 := pinned_in(99)
	in2.cert_name = "anyone"
	d = auth_decide(&f.auth, &f.pt, in2, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Key_Not_Pinned)
	// Disabled and username rules as in pinned mode.
	d = auth_decide(&f.auth, &f.pt, pinned_in(4), 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Key_Disabled)
	d = auth_decide(&f.auth, &f.pt, pinned_in(1, "bob"), 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Username_Mismatch)
}

@(test)
test_auth_pending_external_and_resume :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "auth-external 7\nmax-clients 2\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	testing.expect_value(t, d.external_timeout, 7)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.n_kicks, 0)
	testing.expect_value(t, f.auth.stats.accepted, u64(0))
	// The controller takes a while; meanwhile two other clients connect and
	// fill the server. The limits are checked again at resume.
	connect_as(t, f, "x", 1)
	connect_as(t, f, "y", 2)
	r := auth_resume(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Reject)
	testing.expect_value(t, r.reject.reason, Reject_Reason.Max_Clients)
	// With room it is accepted.
	peers_remove(&f.pt, Peer_Handle{1, 1}, 0)
	r = auth_resume(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, f.auth.stats.accepted, u64(1))
	// A key that is not pinned never gets as far as the controller.
	d = auth_decide(&f.auth, &f.pt, pinned_in(99), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
}

@(test)
test_auth_parked_sessions_count_against_max_clients :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "auth-external 7\nmax-clients 2\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	connect_as(t, f, "x", 1)
	// One peer, one more session waits for a controller: the table is full for
	// a newcomer, and the reject still says who it was.
	in_ := pinned_in(1)
	in_.parked = 1
	d := auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Max_Clients)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.source, Identity_Source.Pin)
	testing.expect(t, d.pinned)
	testing.expect_value(t, d.spki, digest_of(1))
	// Without the parked one there is room.
	in_.parked = 0
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	// Resume: the session itself is not counted among the others.
	r := auth_resume(&f.auth, &f.pt, d, 0)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	r = auth_resume(&f.auth, &f.pt, d, 1)
	testing.expect_value(t, r.kind, Decision_Kind.Reject)
	testing.expect_value(t, identity_str(&r.identity), "alice")
}

@(test)
test_auth_max_clients :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "max-clients 2\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(1), 0).kind, Decision_Kind.Accept)
	connect_as(t, f, "x", 1)
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(3), 0).kind, Decision_Kind.Accept)
	h2 := connect_as(t, f, "y", 2)
	d := auth_decide(&f.auth, &f.pt, pinned_in(3), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Max_Clients)
	testing.expect_value(t, d.reject.kind, Reject_Kind.Auth_Failed_Temp)
	peers_remove(&f.pt, h2, 0)
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(3), 0).kind, Decision_Kind.Accept)
}

@(test)
test_auth_duplicate_identity_replaces_old_session :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "max-clients 2\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	old := connect_pinned(t, f, "alice", 1)
	connect_pinned(t, f, "bob", 3)
	// The server is full, but alice's new session replaces her old one, so it
	// is accepted and the old one is listed for removal.
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0) // alice's key again
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], old)
	// bob's key reconnects (a NAT rebind, say) and
	// replaces his own old session too.
	d = auth_decide(&f.auth, &f.pt, pinned_in(3), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 1)
	// A third identity is refused: the server is full.
	d = auth_decide(&f.auth, &f.pt, pinned_in(4), 0) // carol's key is disabled
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
}

// A live session of `name` that was admitted by the pin of key `n`.
connect_pinned :: proc(t: ^testing.T, f: ^Auth_Fixture, name: string, n: int) -> Peer_Handle {
	return add_peer(t, &f.pt, name, n, 0, Peer_Key{digest_of(u64(n)), true})
}

@(test)
test_auth_pinned_second_key_of_a_name_coexists :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	h1 := connect_pinned(t, f, "alice", 1)
	d := auth_decide(&f.auth, &f.pt, pinned_in(2), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 0)
	h2 := connect_pinned(t, f, "alice", 2)
	// Each key replaces only its own session.
	d = auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], h1)
	d = auth_decide(&f.auth, &f.pt, pinned_in(2), 0)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], h2)
}

@(test)
test_auth_pin_and_non_pin_sessions_of_a_name_coexist :: proc(t: ^testing.T) {
	// Two classes: pin sessions are unique by key, the other sessions (chain,
	// password, token, controller) are unique by name among themselves. A login
	// of one class never ends a session of the other class.
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	pinned := connect_pinned(t, f, "alice", 1)
	other := connect_as(t, f, "alice", 7)
	// A pin login ends only the session of its own key.
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], pinned)
	// Another key of the name: nothing ends.
	d = auth_decide(&f.auth, &f.pt, pinned_in(2), 0)
	testing.expect_value(t, d.n_kicks, 0)
	// A login with no pin proof ends only the session with no pin proof.
	d = auth_decide(&f.auth, &f.pt, chain_in("alice"), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], other)
	// With no session of the other class, nothing ends.
	peers_remove(&f.pt, other, 0)
	d = auth_decide(&f.auth, &f.pt, chain_in("alice"), 0)
	testing.expect_value(t, d.n_kicks, 0)
}

@(test)
test_auth_second_password_login_replaces_only_the_first :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + OPT_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	pinned := connect_pinned(t, f, "alice", 1)
	pw1 := connect_as(t, f, "alice", 7)
	// A login by user name and password (no certificate) is not a pin login.
	d := auth_decide(&f.auth, &f.pt, nocert_in("alice", true), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	r := auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, r.n_kicks, 1)
	testing.expect_value(t, r.kicks[0], pw1)
	testing.expect(t, r.kicks[0] != pinned)
}

@(test)
test_auth_pin_with_password_is_a_pin_session :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, "peer-keys peers.txt\n" + PW_FILE)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	other := connect_as(t, f, "alice", 7)
	// Pin proof and password proof: the login ends no session of the other class.
	d := auth_decide(&f.auth, &f.pt, pin_in(1, "alice", true), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_Password)
	r := auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
	testing.expect_value(t, r.n_kicks, 0)
	testing.expect_value(t, r.proofs, Proof_Set{.Pin, .Password})
	h := connect_pinned(t, f, "alice", 1)
	// ... and a login of the other class leaves it up.
	d = auth_decide(&f.auth, &f.pt, chain_in("alice", "alice", true), 0)
	r = auth_password_passed(&f.auth, &f.pt, d)
	testing.expect_value(t, r.n_kicks, 1)
	testing.expect_value(t, r.kicks[0], other)
	testing.expect(t, r.kicks[0] != h)
}

@(test)
test_auth_pinned_second_key_with_duplicate_cn :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "duplicate-cn\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	connect_pinned(t, f, "alice", 1)
	connect_pinned(t, f, "alice", 2)
	for n in 1 ..= 2 {
		d := auth_decide(&f.auth, &f.pt, pinned_in(u64(n)), 0)
		testing.expect_value(t, d.kind, Decision_Kind.Accept)
		testing.expect_value(t, d.n_kicks, 0)
	}
}

@(test)
test_auth_pinned_max_clients_counts_each_key :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "max-clients 2\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	h1 := connect_pinned(t, f, "alice", 1)
	connect_pinned(t, f, "alice", 2)
	// Full: a new name is refused, a key that is already up replaces itself.
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(3), 0).reject.reason, Reject_Reason.Max_Clients)
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.kicks[0], h1)
	peers_remove(&f.pt, h1, 0)
	// One place is free again: the second key fits.
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(3), 0).kind, Decision_Kind.Accept)
}

@(test)
test_auth_duplicate_cn_allows_several :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "duplicate-cn\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	connect_as(t, f, "alice", 1)
	connect_as(t, f, "alice", 2)
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 0)
}

@(test)
test_auth_too_many_old_sessions :: proc(t: ^testing.T) {
	// More old sessions of one identity than the daemon should have (it did not
	// kick them): refuse instead of guessing.
	f, ok := auth_fixture(t, PINNED_BASE, "", 32)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	for i in 0 ..< MAX_KICKS + 1 {
		add_peer(t, &f.pt, "alice", i + 1, 0, Peer_Key{digest_of(1), true})
	}
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Reject)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Internal)
}

@(test)
test_auth_connect_freq :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "connect-freq 3 10\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	a := addr_key_v4({198, 51, 100, 7}, 5000)
	b := addr_key_v4({198, 51, 100, 8}, 5000)
	for _ in 0 ..< 3 {
		testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(1, "", a), 0).kind, Decision_Kind.Accept)
	}
	d := auth_decide(&f.auth, &f.pt, pinned_in(1, "", a), 1 * SEC)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Rate_Limited)
	testing.expect_value(t, d.reject.kind, Reject_Kind.Auth_Failed_Temp)
	// Another source address is not affected; nor is another port of the same host.
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(1, "", b), 1 * SEC).kind, Decision_Kind.Accept)
	same_host := addr_key_v4({198, 51, 100, 7}, 6000)
	d = auth_decide(&f.auth, &f.pt, pinned_in(1, "", same_host), 1 * SEC)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Rate_Limited)
	// Failed attempts count too: a flood of bad keys uses up the bucket.
	c := addr_key_v4({198, 51, 100, 9}, 1)
	for _ in 0 ..< 3 {
		testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(99, "", c), 0).reject.reason, Reject_Reason.Key_Not_Pinned)
	}
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(1, "", c), 0).reject.reason, Reject_Reason.Rate_Limited)
	// After the window it works again.
	testing.expect_value(t, auth_decide(&f.auth, &f.pt, pinned_in(1, "", a), 30 * SEC).kind, Decision_Kind.Accept)
}

@(test)
test_auth_resume_does_not_charge_rate_limit_again :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "auth-external\nconnect-freq 1 100\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	src := addr_key_v4({198, 51, 100, 7}, 5000)
	d := auth_decide(&f.auth, &f.pt, pinned_in(1, "", src), 0)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	r := auth_resume(&f.auth, &f.pt, d)
	testing.expect_value(t, r.kind, Decision_Kind.Accept)
}

@(test)
test_auth_deny_external :: proc(t: ^testing.T) {
	// `server_deny_external` is part of the facade; check the reasons and kinds.
	r := reject_make(.External_Denied)
	testing.expect_value(t, r.kind, Reject_Kind.Auth_Failed)
	r = reject_make(.External_Timeout)
	testing.expect_value(t, r.kind, Reject_Kind.Auth_Failed_Temp)
}

@(test)
test_auth_no_password_field :: proc(t: ^testing.T) {
	// The input has no place for a password: only the fact that the client sent
	// one. Check that no other field name suggests a password, so adding one
	// needs a conscious change.
	names := reflect.struct_field_names(Auth_Input)
	types := reflect.struct_field_types(Auth_Input)
	for f, i in names {
		if strings.contains(strings.to_lower(f, context.temp_allocator), "pass") {
			testing.expect_value(t, f, "has_password")
			testing.expect(t, types[i].id == typeid_of(bool), "has_password is a bool")
		}
	}
}

@(test)
test_auth_identity_is_a_copy :: proc(t: ^testing.T) {
	// The identity survives a table reload that frees the entry it came from.
	f, ok := auth_fixture(t)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	d := auth_decide(&f.auth, &f.pt, pinned_in(1), 0)
	fresh := make_pins(t, strings.concatenate({"zed ", pin_text(7)}, context.temp_allocator))
	old := pin_store_swap(&f.store, fresh)
	pin_table_destroy(old)
	testing.expect_value(t, identity_str(&d.identity), "alice")
}

// Many random decisions: invariants only.
@(test)
test_auth_random_inputs :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, PINNED_BASE, "connect-freq 50 10\nmax-clients 5\n")
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	r := rng_make(7)
	names := [?]string{"", "alice", "bob", "carol", "mallory", "../x"}
	for i in 0 ..< 3000 {
		in_ := Auth_Input {
			key            = peer_key(u64(rng_below(&r, 7))),
			has_key        = rng_below(&r, 8) != 0,
			cert_name      = names[rng_below(&r, len(names))],
			username       = names[rng_below(&r, len(names))],
			proof          = .Chain if rng_below(&r, 2) == 0 else .Pin,
			src            = addr_key_v4({10, 0, 0, u8(rng_below(&r, 30))}, 1),
		}
		if !in_.has_key {
			in_.proof = .None
		}
		d := auth_decide(&f.auth, &f.pt, in_, time.Duration(i) * 100 * time.Millisecond)
		if d.kind == .Accept {
			// Anything accepted in pinned mode has a pin that is not disabled, and the
			// username, if given, equals the identity.
			e := pin_table_find(pin_store_current(&f.store), d.spki)
			testing.expect(t, e != nil && !e.disabled)
			testing.expect(t, in_.has_key)
			testing.expect(t, in_.username == "" || name_equal(in_.username, identity_str(&d.identity)))
			testing.expect(t, identity_check(identity_str(&d.identity)))
		} else {
			testing.expect_value(t, d.kind, Decision_Kind.Reject)
			testing.expect(t, d.reject.reason != .None)
		}
	}
}

EITHER_EXTRA :: "peer-keys peers.txt\npeer-keys-mode either\n"

@(test)
test_auth_either_pin_first :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, EITHER_EXTRA)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	// A pinned key needs no chain, and the pin names the session.
	in_ := pinned_in(1)
	in_.proof = .Pin
	in_.cert_name = "someone-else"
	d := auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "alice")
	testing.expect_value(t, d.source, Identity_Source.Pin)
	testing.expect(t, d.pinned && !d.by_chain)
	// The username rule of the pinned mode holds.
	in_.username = "bob"
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Username_Mismatch)
}

@(test)
test_auth_either_chain_when_not_pinned :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, EITHER_EXTRA)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	in_ := pinned_in(99)
	in_.cert_name = "dave"
	d := auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, identity_str(&d.identity), "dave")
	testing.expect_value(t, d.source, Identity_Source.Cert_Name)
	testing.expect(t, d.by_chain && !d.pinned)
	testing.expect_value(t, d.spki, digest_of(99))
	// Without a verified chain an unpinned key is refused.
	in_.proof = .Pin
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Chain_Not_Verified)
	// A verified chain without a name has no identity.
	in_ = pinned_in(99)
	d = auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.No_Identity)
}

// carol's key is pinned and disabled: a good chain does not let her in.
@(test)
test_auth_either_disabled_pin_never_uses_the_chain :: proc(t: ^testing.T) {
	f, ok := auth_fixture(t, SERVER_BASE, EITHER_EXTRA)
	if !ok {
		return
	}
	defer auth_fixture_destroy(f)
	in_ := pinned_in(4)
	in_.cert_name = "carol"
	d := auth_decide(&f.auth, &f.pt, in_, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Key_Disabled)
	d = auth_decide(&f.auth, &f.pt, Auth_Input{cert_name = "carol"}, 0)
	testing.expect_value(t, d.reject.reason, Reject_Reason.Key_Not_Pinned)
}
