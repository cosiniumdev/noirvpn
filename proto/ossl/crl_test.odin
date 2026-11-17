// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:strings"
import "core:testing"

// Tests of certificate revocation (crl.odin). The PKI is in testdata (see
// gen.sh): a root, an intermediate (serial 2001) and leaf certificates (good
// 3001, bad 3002).

@(private = "file")
ROOT_PEM := #load("testdata/crl_root.crt.pem")
@(private = "file")
SUB_PEM := #load("testdata/crl_sub.crt.pem")
@(private = "file")
GOOD_CRT := #load("testdata/crl_good.crt.pem")
@(private = "file")
GOOD_KEY := #load("testdata/crl_good.key.pem")
@(private = "file")
BAD_CRT := #load("testdata/crl_bad.crt.pem")
@(private = "file")
BAD_KEY := #load("testdata/crl_bad.key.pem")
@(private = "file")
LONG_CRT := #load("testdata/crl_long.crt.pem")
@(private = "file")
SUB_BAD_CRL := #load("testdata/crl_sub_bad.crl.pem")
@(private = "file")
SUB_EMPTY_CRL := #load("testdata/crl_sub_empty.crl.pem")
@(private = "file")
SUB_EXPIRED_CRL := #load("testdata/crl_sub_expired.crl.pem")
@(private = "file")
ROOT_SUB_CRL := #load("testdata/crl_root_sub.crl.pem")
@(private = "file")
ROOT_EMPTY_CRL := #load("testdata/crl_root_empty.crl.pem")

// A leaf certificate followed by the intermediate, as a peer sends it.
@(private = "file")
chain_pem :: proc(leaf: []u8) -> []u8 {
	b := make([dynamic]u8, 0, len(leaf) + len(SUB_PEM) + 1, context.temp_allocator)
	append(&b, ..leaf)
	append(&b, ..SUB_PEM)
	return b[:]
}

@(private = "file")
crl_cfg :: proc(role: Tls_Role, crt, key, crl: []u8) -> Tls_Config {
	return Tls_Config{role = role, cert_pem = chain_pem(crt), key_pem = key, min_version = .TLS_1_3, verify = .Chain, ca_pem = ROOT_PEM, crl_pem = crl}
}

@(private = "file")
Both :: struct {
	cctx, sctx: Tls_Ctx,
	c, s:       Tls_Session,
}

@(private = "file")
both_init :: proc(t: ^testing.T, b: ^Both, ccfg, scfg: Tls_Config) -> bool {
	err: Error
	b.cctx, err = tls_ctx_create(ccfg)
	if !testing.expectf(t, err == .None, "client context: %v", err) {
		return false
	}
	b.sctx, err = tls_ctx_create(scfg)
	if !testing.expectf(t, err == .None, "server context: %v", err) {
		return false
	}
	return both_sessions(t, b)
}

@(private = "file")
both_sessions :: proc(t: ^testing.T, b: ^Both) -> bool {
	tls_session_destroy(&b.c)
	tls_session_destroy(&b.s)
	err: Error
	b.c, err = tls_session_create(&b.cctx)
	if !testing.expectf(t, err == .None, "client session: %v", err) {
		return false
	}
	b.s, err = tls_session_create(&b.sctx)
	return testing.expectf(t, err == .None, "server session: %v", err)
}

@(private = "file")
both_destroy :: proc(b: ^Both) {
	tls_session_destroy(&b.c)
	tls_session_destroy(&b.s)
	tls_ctx_destroy(&b.cctx)
	tls_ctx_destroy(&b.sctx)
}

@(private = "file")
run :: proc(b: ^Both) -> (cs, ss: Handshake_Status) {
	return tls_loopback(&b.c, &b.s)
}

@(private = "file")
expect_done :: proc(t: ^testing.T, b: ^Both, loc := #caller_location) {
	cs, ss := run(b)
	testing.expectf(t, cs == .Done && ss == .Done, "client %v (%s), server %v (%s)", cs, tls_last_error(&b.c), ss, tls_last_error(&b.s), loc = loc)
}

@(test)
crl_good_client_passes_when_another_is_revoked :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, SUB_BAD_CRL)) {
		return
	}
	expect_done(t, &b)
}

@(test)
crl_revoked_client_is_refused :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, BAD_CRT, BAD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, SUB_BAD_CRL)) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect(t, tls_cert_revoked(&b.s))
	text := tls_last_error(&b.s)
	testing.expectf(t, strings.contains(text, "revoked") && strings.contains(text, "serial 3002") && strings.contains(text, "CN noir-test-crl-bad") && strings.contains(text, "depth 0"), "text: %s", text)
}

@(test)
crl_revoked_server_is_refused_by_the_client :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, SUB_BAD_CRL), crl_cfg(.Server, BAD_CRT, BAD_KEY, nil)) {
		return
	}
	cs, _ := run(&b)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	testing.expect(t, tls_cert_revoked(&b.c))
	testing.expect(t, strings.contains(tls_last_error(&b.c), "serial 3002"))
}

@(test)
crl_empty_crl_passes_everyone :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, BAD_CRT, BAD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, SUB_EMPTY_CRL)) {
		return
	}
	expect_done(t, &b)
}

@(test)
crl_issuer_without_a_crl_is_accepted :: proc(t: ^testing.T) {
	// The list has a CRL of the root only: the leaf's issuer (the intermediate) has none.
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, BAD_CRT, BAD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, ROOT_EMPTY_CRL)) {
		return
	}
	expect_done(t, &b)
	testing.expect(t, b.s.crl_skipped > 0, "the skipped certificates are counted")
}

@(test)
crl_revoked_intermediate_refuses_its_leaves :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, ROOT_SUB_CRL)) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect(t, tls_cert_revoked(&b.s))
	testing.expectf(t, strings.contains(tls_last_error(&b.s), "serial 2001") && strings.contains(tls_last_error(&b.s), "depth 1"), "text: %s", tls_last_error(&b.s))
}

@(test)
crl_expired_crl_refuses :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, SUB_EXPIRED_CRL)) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect(t, tls_crl_failed(&b.s))
	testing.expect(t, !tls_cert_revoked(&b.s))
	testing.expectf(t, strings.contains(tls_last_error(&b.s), "CRL has expired"), "text: %s", tls_last_error(&b.s))
}

@(test)
crl_unreadable_pem_is_an_error :: proc(t: ^testing.T) {
	cases := [?]string {
		"this is not PEM",
		"-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n",
		string(ROOT_PEM), // a certificate, no CRL
	}
	for c in cases {
		_, err := tls_ctx_create(crl_cfg(.Server, GOOD_CRT, GOOD_KEY, transmute([]u8)c))
		testing.expect_value(t, err, Error.Bad_Crl)
	}
	// A good CRL followed by a cut one: the cut one must not be dropped silently.
	cut := strings.concatenate({string(SUB_BAD_CRL), string(SUB_EMPTY_CRL)[:200]}, context.temp_allocator)
	_, err := tls_ctx_create(crl_cfg(.Server, GOOD_CRT, GOOD_KEY, transmute([]u8)cut))
	testing.expect_value(t, err, Error.Bad_Crl)
	// Two good CRLs in one text work.
	both := strings.concatenate({string(SUB_BAD_CRL), string(ROOT_EMPTY_CRL)}, context.temp_allocator)
	ctx, err2 := tls_ctx_create(crl_cfg(.Server, GOOD_CRT, GOOD_KEY, transmute([]u8)both))
	testing.expect_value(t, err2, Error.None)
	tls_ctx_destroy(&ctx)
}

// --- the serial callback ---

@(private = "file")
Revoke_Rule :: struct {
	serial: string,
	depth:  int, // -1: any
	calls:  int,
	seen:   [4]u8, // serials seen
}

@(private = "file")
rule_check :: proc "contextless" (serial_dec: string, depth: int, user: rawptr) -> bool {
	r := (^Revoke_Rule)(user)
	r.calls += 1
	return serial_dec == r.serial && (r.depth < 0 || r.depth == depth)
}

@(private = "file")
cb_cfg :: proc(role: Tls_Role, crt, key: []u8, rule: ^Revoke_Rule) -> Tls_Config {
	cfg := crl_cfg(role, crt, key, nil)
	cfg.revoked_check = rule_check
	cfg.revoked_user = rule
	return cfg
}

@(test)
crl_callback_revokes_a_leaf_by_serial :: proc(t: ^testing.T) {
	rule := Revoke_Rule{serial = "3002", depth = 0}
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, BAD_CRT, BAD_KEY, nil), cb_cfg(.Server, GOOD_CRT, GOOD_KEY, &rule)) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect(t, tls_cert_revoked(&b.s))
	testing.expectf(t, strings.contains(tls_last_error(&b.s), "serial 3002") && strings.contains(tls_last_error(&b.s), "CN noir-test-crl-bad"), "text: %s", tls_last_error(&b.s))
	testing.expect(t, rule.calls >= 1)
}

@(test)
crl_callback_passes_other_leaves_and_sees_the_whole_chain :: proc(t: ^testing.T) {
	rule := Revoke_Rule{serial = "3002", depth = 0}
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, nil), cb_cfg(.Server, GOOD_CRT, GOOD_KEY, &rule)) {
		return
	}
	expect_done(t, &b)
	// The leaf, the intermediate and the root are asked about.
	testing.expect_value(t, rule.calls, 3)
}

@(test)
crl_callback_revokes_an_intermediate :: proc(t: ^testing.T) {
	rule := Revoke_Rule{serial = "2001", depth = 1}
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, nil), cb_cfg(.Server, GOOD_CRT, GOOD_KEY, &rule)) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect(t, strings.contains(tls_last_error(&b.s), "depth 1"))
}

@(test)
crl_callback_works_in_the_client_role :: proc(t: ^testing.T) {
	rule := Revoke_Rule{serial = "3002", depth = -1}
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, cb_cfg(.Client, GOOD_CRT, GOOD_KEY, &rule), crl_cfg(.Server, BAD_CRT, BAD_KEY, nil)) {
		return
	}
	cs, _ := run(&b)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	testing.expect(t, tls_cert_revoked(&b.c))
}

@(test)
crl_callback_and_file_work_together :: proc(t: ^testing.T) {
	// The file revokes 3002, the callback 3001.
	rule := Revoke_Rule{serial = "3001", depth = 0}
	cfg := cb_cfg(.Server, GOOD_CRT, GOOD_KEY, &rule)
	cfg.crl_pem = SUB_BAD_CRL
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, nil), cfg) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	// A second client with the other certificate.
	both_destroy(&b)
	b = {}
	if !both_init(t, &b, crl_cfg(.Client, BAD_CRT, BAD_KEY, nil), cfg) {
		return
	}
	_, ss = run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
}

@(test)
crl_callback_is_not_asked_in_pinned_mode :: proc(t: ^testing.T) {
	rule := Revoke_Rule{serial = "3001", depth = -1}
	scfg := crl_cfg(.Server, GOOD_CRT, GOOD_KEY, SUB_BAD_CRL)
	scfg.verify = .Pinned
	scfg.pin_check = proc "contextless" (peer: Peer_Key, user: rawptr) -> bool {return true}
	scfg.revoked_check = rule_check
	scfg.revoked_user = &rule
	ccfg := crl_cfg(.Client, BAD_CRT, BAD_KEY, nil)
	ccfg.verify = .Pinned
	ccfg.pin_check = scfg.pin_check
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, ccfg, scfg) {
		return
	}
	// The revoked certificate (in the CRL) is accepted: there is no chain.
	expect_done(t, &b)
	testing.expect_value(t, rule.calls, 0)
}

@(test)
crl_serial_in_decimal :: proc(t: ^testing.T) {
	cases := [?]struct {
		pem:  []u8,
		want: string,
	}{{GOOD_CRT, "3001"}, {BAD_CRT, "3002"}, {SUB_PEM, "2001"}, {LONG_CRT, "5753854965885600108575829560559299546819203860"}}
	for c in cases {
		bio := pem_bio(c.pem)
		x := PEM_read_bio_X509(bio, nil, no_password, nil)
		BIO_free(bio)
		if !testing.expect(t, x != nil) {
			return
		}
		buf: [SERIAL_DEC_MAX]u8
		n, ok := serial_decimal(x, &buf)
		testing.expect(t, ok)
		testing.expect_value(t, string(buf[:n]), c.want)
		X509_free(x)
	}
}

// --- a lost list, and a new one ---

@(test)
crl_lost_list_refuses_everyone_until_a_good_reload :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, GOOD_CRT, GOOD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, SUB_EMPTY_CRL)) {
		return
	}
	expect_done(t, &b)

	tls_ctx_crl_lost(&b.sctx)
	testing.expect(t, tls_ctx_is_crl_lost(&b.sctx))
	if !both_sessions(t, &b) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect(t, tls_crl_failed(&b.s))
	testing.expectf(t, strings.contains(tls_last_error(&b.s), "the CRL is not loaded"), "text: %s", tls_last_error(&b.s))

	// A reload that fails keeps the list lost.
	testing.expect_value(t, tls_ctx_set_crl(&b.sctx, ROOT_PEM, transmute([]u8)string("garbage"), 2), Error.Bad_Crl)
	testing.expect(t, tls_ctx_is_crl_lost(&b.sctx))

	// A good reload brings the same certificate back.
	testing.expect_value(t, tls_ctx_set_crl(&b.sctx, ROOT_PEM, SUB_EMPTY_CRL, 3), Error.None)
	testing.expect(t, !tls_ctx_is_crl_lost(&b.sctx))
	testing.expect_value(t, b.sctx.revision, u64(3))
	if !both_sessions(t, &b) {
		return
	}
	expect_done(t, &b)
}

@(test)
crl_reload_replaces_the_list :: proc(t: ^testing.T) {
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, crl_cfg(.Client, BAD_CRT, BAD_KEY, nil), crl_cfg(.Server, GOOD_CRT, GOOD_KEY, SUB_EMPTY_CRL)) {
		return
	}
	expect_done(t, &b)
	// A session that is up stays up; the next handshake sees the new list.
	testing.expect_value(t, tls_ctx_set_crl(&b.sctx, ROOT_PEM, SUB_BAD_CRL, 2), Error.None)
	testing.expect_value(t, tls_state(&b.s), Tls_State.Established)
	msg := "still up"
	testing.expect_value(t, tls_write_app(&b.c, transmute([]u8)msg), Io_Status.Ok)
	if !both_sessions(t, &b) {
		return
	}
	_, ss := run(&b)
	testing.expect_value(t, ss, Handshake_Status.Failed)
	testing.expect(t, tls_cert_revoked(&b.s))
	// And back.
	testing.expect_value(t, tls_ctx_set_crl(&b.sctx, ROOT_PEM, SUB_EMPTY_CRL, 3), Error.None)
	if !both_sessions(t, &b) {
		return
	}
	expect_done(t, &b)
}

@(test)
crl_set_crl_needs_a_crl_context :: proc(t: ^testing.T) {
	ctx, err := tls_ctx_create(crl_cfg(.Server, GOOD_CRT, GOOD_KEY, nil))
	testing.expect_value(t, err, Error.None)
	defer tls_ctx_destroy(&ctx)
	testing.expect_value(t, tls_ctx_set_crl(&ctx, ROOT_PEM, SUB_EMPTY_CRL, 1), Error.Bad_Argument)
}

// --- crl_inspect ---

@(test)
crl_inspect_reports_issuer_and_dates :: proc(t: ^testing.T) {
	infos: [4]Crl_Info
	both := strings.concatenate({string(SUB_EXPIRED_CRL), string(SUB_BAD_CRL)}, context.temp_allocator)
	n, ok := crl_inspect(transmute([]u8)both, infos[:])
	testing.expect(t, ok)
	testing.expect_value(t, n, 2)
	testing.expect_value(t, string(infos[0].issuer[:infos[0].issuer_len]), "/CN=noir-test-crl-sub")
	testing.expect(t, infos[0].expired)
	testing.expect_value(t, infos[0].next_update, i64(1577923200)) // 2020-01-02
	testing.expect(t, !infos[1].expired)
	testing.expect(t, infos[1].next_update > 4_000_000_000)

	_, ok = crl_inspect(transmute([]u8)string("nothing"), infos[:])
	testing.expect(t, !ok)
	_, ok = crl_inspect(nil, infos[:])
	testing.expect(t, !ok)
}

@(test)
crl_asn1_time :: proc(t: ^testing.T) {
	v, ok := asn1_time_unix(transmute([]u8)string("200102000000Z"))
	testing.expect(t, ok)
	testing.expect_value(t, v, i64(1577923200))
	v, ok = asn1_time_unix(transmute([]u8)string("20260102000000Z"))
	testing.expect(t, ok)
	testing.expect_value(t, v, i64(1767312000))
	_, ok = asn1_time_unix(transmute([]u8)string("2001020000"))
	testing.expect(t, !ok)
	_, ok = asn1_time_unix(transmute([]u8)string("200102000000+"))
	testing.expect(t, !ok)
}
