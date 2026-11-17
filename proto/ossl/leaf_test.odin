// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:encoding/base64"
import "core:strings"
import "core:testing"

// Tests of the leaf rules (leaf.odin): key usage, extended key usage and name
// of the peer's own certificate. The PKI is in testdata (see gen.sh, `leaf`).

@(private = "file")
LEAF_CA := #load("testdata/leaf_ca.crt.pem")
@(private = "file")
SERVER_CRT := #load("testdata/leaf_server.crt.pem")
@(private = "file")
SERVER_KEY := #load("testdata/leaf_server.key.pem")
@(private = "file")
CLIENT_CRT := #load("testdata/leaf_client.crt.pem")
@(private = "file")
CLIENT_KEY := #load("testdata/leaf_client.key.pem")
@(private = "file")
BOTH_CRT := #load("testdata/leaf_both.crt.pem")
@(private = "file")
BOTH_KEY := #load("testdata/leaf_both.key.pem")
@(private = "file")
NOEKU_CRT := #load("testdata/leaf_noeku.crt.pem")
@(private = "file")
NOEKU_KEY := #load("testdata/leaf_noeku.key.pem")
@(private = "file")
NOKU_CRT := #load("testdata/leaf_noku.crt.pem")
@(private = "file")
NOKU_KEY := #load("testdata/leaf_noku.key.pem")
@(private = "file")
PLAIN_CRT := #load("testdata/leaf_plain.crt.pem")
@(private = "file")
DEC_CRT := #load("testdata/leaf_dec.crt.pem")
@(private = "file")
EKU3_CRT := #load("testdata/leaf_eku3.crt.pem")
@(private = "file")
ODD_CRT := #load("testdata/leaf_odd.crt.pem")
@(private = "file")
LONGCN_CRT := #load("testdata/leaf_longcn.crt.pem")
@(private = "file")
CTL_CRT := #load("testdata/leaf_ctl.crt.pem")
@(private = "file")
NUL_CRT := #load("testdata/leaf_nul.crt.pem")
@(private = "file")
NOCN_CRT := #load("testdata/nocn_client.crt.pem")
@(private = "file")
TWOCN_CRT := #load("testdata/twocn_client.crt.pem")
@(private = "file")
CRL_ROOT := #load("testdata/crl_root.crt.pem")
@(private = "file")
CRL_SUB := #load("testdata/crl_sub.crt.pem")
@(private = "file")
CRL_GOOD_CRT := #load("testdata/crl_good.crt.pem")
@(private = "file")
CRL_GOOD_KEY := #load("testdata/crl_good.key.pem")
@(private = "file")
CRL_BAD_CRT := #load("testdata/crl_bad.crt.pem")
@(private = "file")
CRL_BAD_KEY := #load("testdata/crl_bad.key.pem")
@(private = "file")
CRL_SUB_BAD := #load("testdata/crl_sub_bad.crl.pem")

// ----------------------------------------------------------- the judge itself

// Runs the judge on the first certificate of `pem`.
@(private = "file")
judge :: proc(t: ^testing.T, pem: []u8, r: Leaf_Rules, loc := #caller_location) -> (ok: bool, v: Leaf_Verdict) {
	h: Leaf_Hook
	if !testing.expect_value(t, leaf_hook_fill(&h, r), Error.None, loc = loc) {
		return false, {}
	}
	bio := pem_bio(pem)
	if !testing.expect(t, bio != nil, loc = loc) {
		return false, {}
	}
	defer BIO_free(bio)
	x := PEM_read_bio_X509(bio, nil, no_password, nil)
	if !testing.expect(t, x != nil, loc = loc) {
		return false, {}
	}
	defer X509_free(x)
	ok = leaf_check(x, &h, &v)
	return
}

@(private = "file")
expect_pass :: proc(t: ^testing.T, pem: []u8, r: Leaf_Rules, loc := #caller_location) {
	ok, v := judge(t, pem, r, loc)
	testing.expectf(t, ok, "should pass; failed with %v '%s'", v.fail, string(v.text[:v.text_len]), loc = loc)
}

@(private = "file")
expect_fail :: proc(t: ^testing.T, pem: []u8, r: Leaf_Rules, want: Rule_Fail, loc := #caller_location) -> Leaf_Verdict {
	ok, v := judge(t, pem, r, loc)
	testing.expect(t, !ok, "should fail", loc = loc)
	testing.expect_value(t, v.fail, want, loc = loc)
	return v
}

@(private = "file")
tls_rules :: proc(eku: string) -> Leaf_Rules {
	return Leaf_Rules{ku_required = true, eku = eku}
}

@(private = "file")
ku_rules :: proc(values: ..u8) -> Leaf_Rules {
	r: Leaf_Rules
	for v in values {
		r.ku_list[r.ku_count] = v
		r.ku_count += 1
	}
	return r
}

@(private = "file")
name_rule :: proc(kind: Leaf_Name_Kind, name: string) -> Leaf_Rules {
	return Leaf_Rules{name_kind = kind, name = name}
}

@(test)
leaf_no_rules_is_not_active :: proc(t: ^testing.T) {
	testing.expect(t, !leaf_rules_active({}))
	testing.expect(t, leaf_rules_active({ku_required = true}))
	testing.expect(t, leaf_rules_active(ku_rules(0x80)))
	testing.expect(t, leaf_rules_active({eku = "1.2.3"}))
	testing.expect(t, leaf_rules_active(name_rule(.Name, "x")))
	// A name with no kind is not a rule.
	testing.expect(t, !leaf_rules_active({name = "x"}))
}

@(test)
leaf_remote_cert_tls_server :: proc(t: ^testing.T) {
	r := tls_rules(EKU_SERVER_AUTH)
	expect_pass(t, SERVER_CRT, r)
	expect_pass(t, BOTH_CRT, r)
	v := expect_fail(t, CLIENT_CRT, r, .Eku_Mismatch)
	testing.expect_value(t, v.role, Eku_Role.Server)
	expect_fail(t, NOEKU_CRT, r, .Eku_Missing)
	expect_fail(t, NOKU_CRT, r, .Ku_Missing)
	expect_fail(t, PLAIN_CRT, r, .Ku_Missing)
}

@(test)
leaf_remote_cert_tls_client :: proc(t: ^testing.T) {
	r := tls_rules(EKU_CLIENT_AUTH)
	expect_pass(t, CLIENT_CRT, r)
	expect_pass(t, BOTH_CRT, r)
	v := expect_fail(t, SERVER_CRT, r, .Eku_Mismatch)
	testing.expect_value(t, v.role, Eku_Role.Client)
	expect_fail(t, NOEKU_CRT, r, .Eku_Missing)
}

@(test)
leaf_key_usage_required_only :: proc(t: ^testing.T) {
	// Any value passes, but the extension must be there.
	expect_pass(t, SERVER_CRT, {ku_required = true})
	expect_pass(t, DEC_CRT, {ku_required = true})
	expect_fail(t, NOKU_CRT, {ku_required = true}, .Ku_Missing)
	expect_fail(t, PLAIN_CRT, {ku_required = true}, .Ku_Missing)
}

@(test)
leaf_key_usage_lists :: proc(t: ^testing.T) {
	// leaf_server has digitalSignature and keyEncipherment: 0xa0.
	expect_pass(t, SERVER_CRT, ku_rules(0xa0))
	// At least the bits of one value: a subset passes.
	expect_pass(t, SERVER_CRT, ku_rules(0x80))
	expect_pass(t, SERVER_CRT, ku_rules(0x20))
	// One value of the list is enough.
	expect_pass(t, SERVER_CRT, ku_rules(0x40, 0x88, 0x20))
	// No value matches. The text gets the value of the certificate.
	v := expect_fail(t, SERVER_CRT, ku_rules(0x88), .Ku_Mismatch)
	testing.expect_value(t, v.ku, u8(0xa0))
	expect_fail(t, SERVER_CRT, ku_rules(0x40), .Ku_Mismatch)
	expect_fail(t, SERVER_CRT, ku_rules(0xa1), .Ku_Mismatch)
	expect_fail(t, SERVER_CRT, ku_rules(0x40, 0x04), .Ku_Mismatch)
	// A client certificate has only 0x80.
	expect_pass(t, CLIENT_CRT, ku_rules(0x80))
	expect_fail(t, CLIENT_CRT, ku_rules(0xa0), .Ku_Mismatch)
	// A value with a list needs the extension.
	expect_fail(t, NOKU_CRT, ku_rules(0x80), .Ku_Missing)
	expect_fail(t, PLAIN_CRT, ku_rules(0x80, 0xa0), .Ku_Missing)
}

@(test)
leaf_key_usage_ninth_bit :: proc(t: ^testing.T) {
	// leaf_dec: digitalSignature, keyAgreement and decipherOnly (bit 9). Only
	// the first eight bits count, so the value is 0x88.
	v := expect_fail(t, DEC_CRT, ku_rules(0x20), .Ku_Mismatch)
	testing.expect_value(t, v.ku, u8(0x88))
	expect_pass(t, DEC_CRT, ku_rules(0x88))
	expect_pass(t, DEC_CRT, ku_rules(0x08))
	expect_pass(t, DEC_CRT, ku_rules(0x80))
}

@(test)
leaf_extended_key_usage_forms :: proc(t: ^testing.T) {
	// The same OID as a dotted number, a short name and a long name.
	for form in ([]string{"1.3.6.1.5.5.7.3.1", "serverAuth", "TLS Web Server Authentication"}) {
		expect_pass(t, SERVER_CRT, {eku = form})
		expect_pass(t, EKU3_CRT, {eku = form})
		expect_fail(t, CLIENT_CRT, {eku = form}, .Eku_Mismatch)
	}
	for form in ([]string{"1.3.6.1.5.5.7.3.3", "codeSigning", "Code Signing"}) {
		expect_pass(t, EKU3_CRT, {eku = form})
		expect_fail(t, SERVER_CRT, {eku = form}, .Eku_Mismatch)
	}
	// An OID that the library has no name for.
	expect_pass(t, EKU3_CRT, {eku = "1.3.6.1.4.1.99999.1.2"})
	expect_fail(t, EKU3_CRT, {eku = "1.3.6.1.4.1.99999.1.3"}, .Eku_Mismatch)
	v := expect_fail(t, SERVER_CRT, {eku = "1.3.6.1.4.1.99999.1.2"}, .Eku_Mismatch)
	testing.expect_value(t, v.role, Eku_Role.Other)
	testing.expect_value(t, string(v.text[:v.text_len]), "1.3.6.1.4.1.99999.1.2")
	// No extension at all.
	expect_fail(t, NOEKU_CRT, {eku = "serverAuth"}, .Eku_Missing)
	expect_fail(t, PLAIN_CRT, {eku = "1.3.6.1.5.5.7.3.1"}, .Eku_Missing)
	// A name or OID that does not exist cannot be a rule.
	h: Leaf_Hook
	testing.expect_value(t, leaf_hook_fill(&h, {eku = "no such usage"}), Error.Bad_Config)
	testing.expect_value(t, leaf_hook_fill(&h, {eku = "1.2.x"}), Error.Bad_Config)
	testing.expect(t, leaf_eku_valid("serverAuth"))
	testing.expect(t, leaf_eku_valid("1.2.3.4"))
	testing.expect(t, !leaf_eku_valid(""))
	testing.expect(t, !leaf_eku_valid("no such usage"))
}

@(test)
leaf_bad_rules_are_refused :: proc(t: ^testing.T) {
	h: Leaf_Hook
	testing.expect_value(t, leaf_hook_fill(&h, ku_rules(0)), Error.Bad_Argument)
	testing.expect_value(t, leaf_hook_fill(&h, name_rule(.Name, "")), Error.Bad_Argument)
	testing.expect_value(t, leaf_hook_fill(&h, name_rule(.Name, "a\x00b")), Error.Bad_Argument)
	long := strings.repeat("x", LEAF_NAME_MAX + 1, context.temp_allocator)
	testing.expect_value(t, leaf_hook_fill(&h, name_rule(.Name, long)), Error.Bad_Argument)
	exact := strings.repeat("x", LEAF_NAME_MAX, context.temp_allocator)
	testing.expect_value(t, leaf_hook_fill(&h, name_rule(.Name, exact)), Error.None)
	many := Leaf_Rules {
		ku_count = KU_LIST_MAX + 1,
	}
	testing.expect_value(t, leaf_hook_fill(&h, many), Error.Bad_Argument)
}

@(test)
leaf_name_subject :: proc(t: ^testing.T) {
	const_subject := "C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=Server-1"
	expect_pass(t, SERVER_CRT, name_rule(.Subject, const_subject))
	// Near misses.
	for bad in ([]string {
			"C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=Server-2",
			"C=KG,ST=NA,L=Bishkek,O=Noir Test,CN=Server-1",
			"C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=Server-1 ",
			" C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=Server-1",
			"C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=server-1",
			"CN=Server-1, O=Noir Test, L=Bishkek, ST=NA, C=KG",
			"/C=KG/ST=NA/L=Bishkek/O=Noir Test/CN=Server-1",
			"C=KG, ST=NA, L=Bishkek, O=Noir Test",
			"CN=Server-1",
			"C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=Server-1, C=KG",
		}) {
		v := expect_fail(t, SERVER_CRT, name_rule(.Subject, bad), .Name_Mismatch)
		testing.expect_value(t, string(v.text[:v.text_len]), const_subject)
	}
	expect_pass(t, CLIENT_CRT, name_rule(.Subject, "C=KG, O=Noir Test, CN=Client-1"))
	expect_pass(t, BOTH_CRT, name_rule(.Subject, "CN=Both-1"))
	// The default type of the config is `subject`; the type of the rule is what counts.
	expect_pass(t, TWOCN_CRT, name_rule(.Subject, "CN=first-name, CN=second-name"))
	expect_pass(t, NOCN_CRT, name_rule(.Subject, "O=noir-test-no-common-name"))
}

@(test)
leaf_name_subject_escapes_and_utf8 :: proc(t: ^testing.T) {
	// RFC 2253 escapes for "," and "+", and the UTF-8 text as it is.
	want := "C=KG, O=Acme\\, Inc., OU=Café, CN=Odd \\+ Name"
	expect_pass(t, ODD_CRT, name_rule(.Subject, want))
	expect_fail(t, ODD_CRT, name_rule(.Subject, "C=KG, O=Acme, Inc., OU=Café, CN=Odd + Name"), .Name_Mismatch)
	// The common name is the value, with no escapes.
	expect_pass(t, ODD_CRT, name_rule(.Name, "Odd + Name"))
	expect_pass(t, ODD_CRT, name_rule(.Name_Prefix, "Odd +"))
	expect_fail(t, ODD_CRT, name_rule(.Name, "Odd \\+ Name"), .Name_Mismatch)
}

@(test)
leaf_name_common_name :: proc(t: ^testing.T) {
	expect_pass(t, SERVER_CRT, name_rule(.Name, "Server-1"))
	for bad in ([]string{"server-1", "Server-", "Server-12", "Server-1 ", " Server-1", "Server", "C=KG"}) {
		v := expect_fail(t, SERVER_CRT, name_rule(.Name, bad), .Name_Mismatch)
		testing.expect_value(t, string(v.text[:v.text_len]), "Server-1")
	}
	// The last common name counts.
	expect_pass(t, TWOCN_CRT, name_rule(.Name, "second-name"))
	expect_fail(t, TWOCN_CRT, name_rule(.Name, "first-name"), .Name_Mismatch)
	// No common name at all.
	expect_fail(t, NOCN_CRT, name_rule(.Name, "x"), .Name_Unreadable)
	expect_fail(t, NOCN_CRT, name_rule(.Name_Prefix, "x"), .Name_Unreadable)
}

@(test)
leaf_name_prefix :: proc(t: ^testing.T) {
	expect_pass(t, SERVER_CRT, name_rule(.Name_Prefix, "Server-"))
	expect_pass(t, SERVER_CRT, name_rule(.Name_Prefix, "S"))
	expect_pass(t, SERVER_CRT, name_rule(.Name_Prefix, "Server-1"))
	// A prefix that is longer than the name, or another case, does not match.
	expect_fail(t, SERVER_CRT, name_rule(.Name_Prefix, "Server-12"), .Name_Mismatch)
	expect_fail(t, SERVER_CRT, name_rule(.Name_Prefix, "server-"), .Name_Mismatch)
	expect_fail(t, SERVER_CRT, name_rule(.Name_Prefix, "erver-"), .Name_Mismatch)
	expect_fail(t, SERVER_CRT, name_rule(.Name_Prefix, "Client"), .Name_Mismatch)
}

// A certificate PEM with the text `from` in its DER replaced by `to` (same
// length). The signature does not hold after that: only for parsing.
@(private = "file")
patched :: proc(pem: []u8, from, to: []u8) -> []u8 {
	text := string(pem)
	a := strings.index(text, "-----BEGIN CERTIFICATE-----\n") + len("-----BEGIN CERTIFICATE-----\n")
	b := strings.index(text, "-----END CERTIFICATE-----")
	body, _ := strings.remove_all(text[a:b], "\n", context.temp_allocator)
	der, err := base64.decode(body, allocator = context.temp_allocator)
	assert(err == nil)
	assert(len(from) == len(to))
	hit := -1
	for i in 0 ..= len(der) - len(from) {
		if string(der[i:i + len(from)]) == string(from) {
			assert(hit < 0, "the text is not unique")
			hit = i
		}
	}
	assert(hit >= 0)
	copy(der[hit:], to)
	enc, _ := base64.encode(der, allocator = context.temp_allocator)
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "-----BEGIN CERTIFICATE-----\n")
	for i := 0; i < len(enc); i += 64 {
		strings.write_string(&sb, enc[i:min(i + 64, len(enc))])
		strings.write_string(&sb, "\n")
	}
	strings.write_string(&sb, "-----END CERTIFICATE-----\n")
	return transmute([]u8)strings.to_string(sb)
}

@(test)
leaf_name_control_bytes :: proc(t: ^testing.T) {
	// Control bytes and DEL become "_" (as upstream does) before the compare.
	pem := patched(CTL_CRT, transmute([]u8)string("Ctl-AAAA"), []u8{'C', 't', 'l', '-', 0x01, 0x0a, 0x7f, 0x1b})
	expect_pass(t, pem, name_rule(.Name, "Ctl-____"))
	expect_pass(t, pem, name_rule(.Name_Prefix, "Ctl-_"))
	expect_pass(t, pem, name_rule(.Subject, "CN=Ctl-____"))
	v := expect_fail(t, pem, name_rule(.Name, "Ctl-AAAA"), .Name_Mismatch)
	// The text for the log has no control bytes.
	for c in v.text[:v.text_len] {
		testing.expect(t, c >= 0x20 && c != 0x7f)
	}
	expect_fail(t, pem, name_rule(.Name, "Ctl-\x01\x0a\x7f\x1b"), .Name_Mismatch)
}

@(test)
leaf_name_nul_byte :: proc(t: ^testing.T) {
	// A NUL byte in the name: the certificate does not pass (no name could
	// match the part before it).
	pem := patched(NUL_CRT, transmute([]u8)string("Nul-AAAA"), []u8{'N', 'u', 'l', '-', 'x', 0x00, 'y', 'z'})
	expect_fail(t, pem, name_rule(.Name, "Nul-x"), .Name_Unreadable)
	expect_fail(t, pem, name_rule(.Name_Prefix, "Nul-x"), .Name_Unreadable)
	expect_fail(t, pem, name_rule(.Subject, "CN=Nul-x"), .Name_Unreadable)
}

@(test)
leaf_name_too_long :: proc(t: ^testing.T) {
	// 40 characters of 2 bytes: 80 bytes of UTF-8, over the 64 byte limit of
	// the common name.
	expect_fail(t, LONGCN_CRT, name_rule(.Name, "x"), .Name_Too_Long)
	expect_fail(t, LONGCN_CRT, name_rule(.Name_Prefix, "x"), .Name_Too_Long)
	// The subject fits its buffer.
	expect_fail(t, LONGCN_CRT, name_rule(.Subject, "CN=x"), .Name_Mismatch)
}

@(test)
leaf_rules_run_in_order :: proc(t: ^testing.T) {
	// Key usage first, then extended key usage, then name.
	all := Leaf_Rules {
		ku_required = true,
		eku         = EKU_SERVER_AUTH,
		name_kind   = .Name,
		name        = "Server-1",
	}
	expect_pass(t, SERVER_CRT, all)
	expect_fail(t, PLAIN_CRT, all, .Ku_Missing)
	expect_fail(t, NOEKU_CRT, all, .Eku_Missing)
	expect_fail(t, BOTH_CRT, all, .Name_Mismatch)
}

// ----------------------------------------------------------------- handshakes

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

// A client and a server of the leaf PKI: `.Chain` with the leaf CA.
@(private = "file")
chain_cfg :: proc(role: Tls_Role, crt, key: []u8, rules: Leaf_Rules) -> Tls_Config {
	return Tls_Config{role = role, cert_pem = crt, key_pem = key, min_version = .TLS_1_3, verify = .Chain, ca_pem = LEAF_CA, rules = rules}
}

@(private = "file")
accept_all :: proc "contextless" (peer: Peer_Key, user: rawptr) -> bool {
	return true
}

@(private = "file")
pinned_cfg :: proc(role: Tls_Role, crt, key: []u8, rules: Leaf_Rules) -> Tls_Config {
	return Tls_Config{role = role, cert_pem = crt, key_pem = key, min_version = .TLS_1_3, verify = .Pinned, pin_check = accept_all, rules = rules}
}

@(test)
leaf_chain_server_certificate_is_checked_by_a_client :: proc(t: ^testing.T) {
	rules := tls_rules(EKU_SERVER_AUTH)
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, chain_cfg(.Client, CLIENT_CRT, CLIENT_KEY, rules), chain_cfg(.Server, SERVER_CRT, SERVER_KEY, {})) {
		return
	}
	cs, ss := tls_loopback(&b.c, &b.s)
	testing.expectf(t, cs == .Done && ss == .Done, "client %v (%s), server %v (%s)", cs, tls_last_error(&b.c), ss, tls_last_error(&b.s))
	testing.expect(t, !tls_cert_rule_failed(&b.c))
}

@(test)
leaf_chain_certificate_with_no_extended_key_usage_is_refused :: proc(t: ^testing.T) {
	// leaf_noeku passes the library's own purpose check (no extension), so the
	// refusal is ours.
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, chain_cfg(.Client, CLIENT_CRT, CLIENT_KEY, tls_rules(EKU_SERVER_AUTH)), chain_cfg(.Server, NOEKU_CRT, NOEKU_KEY, {})) {
		return
	}
	cs, _ := tls_loopback(&b.c, &b.s)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	testing.expect(t, tls_cert_rule_failed(&b.c))
	text := tls_last_error(&b.c)
	testing.expectf(t, strings.has_prefix(text, "certificate verify failed: the certificate has no extended key usage"), "text: %s", text)
	testing.expectf(t, strings.contains(text, "CN Server-2") && strings.contains(text, "depth 0"), "text: %s", text)
}

@(test)
leaf_chain_client_certificate_is_checked_by_a_server :: proc(t: ^testing.T) {
	rules := tls_rules(EKU_CLIENT_AUTH)
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, chain_cfg(.Client, CLIENT_CRT, CLIENT_KEY, {}), chain_cfg(.Server, SERVER_CRT, SERVER_KEY, rules)) {
		return
	}
	cs, ss := tls_loopback(&b.c, &b.s)
	testing.expectf(t, cs == .Done && ss == .Done, "client %v (%s), server %v (%s)", cs, tls_last_error(&b.c), ss, tls_last_error(&b.s))

	// A certificate with no extended key usage fails the rule on the server.
	b2: Both
	defer both_destroy(&b2)
	if !both_init(t, &b2, chain_cfg(.Client, NOEKU_CRT, NOEKU_KEY, {}), chain_cfg(.Server, SERVER_CRT, SERVER_KEY, rules)) {
		return
	}
	_, ss2 := tls_loopback(&b2.c, &b2.s)
	testing.expect_value(t, ss2, Handshake_Status.Failed)
	testing.expect(t, tls_cert_rule_failed(&b2.s))
	testing.expect(t, strings.contains(tls_last_error(&b2.s), "no extended key usage"))

	// A server certificate (serverAuth only) as a client certificate fails too:
	// the library's purpose check or ours, either way it fails.
	b3: Both
	defer both_destroy(&b3)
	if !both_init(t, &b3, chain_cfg(.Client, SERVER_CRT, SERVER_KEY, {}), chain_cfg(.Server, SERVER_CRT, SERVER_KEY, rules)) {
		return
	}
	_, ss3 := tls_loopback(&b3.c, &b3.s)
	testing.expect_value(t, ss3, Handshake_Status.Failed)
}

@(test)
leaf_pinned_checks_the_rules_too :: proc(t: ^testing.T) {
	// `.Pinned` has no purpose check of the library: the refusal of a client
	// certificate is ours.
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, pinned_cfg(.Client, CLIENT_CRT, CLIENT_KEY, tls_rules(EKU_SERVER_AUTH)), pinned_cfg(.Server, CLIENT_CRT, CLIENT_KEY, {})) {
		return
	}
	cs, _ := tls_loopback(&b.c, &b.s)
	testing.expect_value(t, cs, Handshake_Status.Failed)
	testing.expect(t, tls_cert_rule_failed(&b.c))
	text := tls_last_error(&b.c)
	testing.expectf(t, strings.contains(text, "the certificate is not for a server (extended key usage)"), "text: %s", text)

	// The same pin with a server certificate: accepted.
	b2: Both
	defer both_destroy(&b2)
	if !both_init(t, &b2, pinned_cfg(.Client, CLIENT_CRT, CLIENT_KEY, tls_rules(EKU_SERVER_AUTH)), pinned_cfg(.Server, SERVER_CRT, SERVER_KEY, {})) {
		return
	}
	cs2, ss2 := tls_loopback(&b2.c, &b2.s)
	testing.expectf(t, cs2 == .Done && ss2 == .Done, "client %v (%s), server %v (%s)", cs2, tls_last_error(&b2.c), ss2, tls_last_error(&b2.s))

	// A server with a rule on the client certificate.
	b3: Both
	defer both_destroy(&b3)
	if !both_init(t, &b3, pinned_cfg(.Client, SERVER_CRT, SERVER_KEY, {}), pinned_cfg(.Server, SERVER_CRT, SERVER_KEY, tls_rules(EKU_CLIENT_AUTH))) {
		return
	}
	_, ss3 := tls_loopback(&b3.c, &b3.s)
	testing.expect_value(t, ss3, Handshake_Status.Failed)
	testing.expect(t, tls_cert_rule_failed(&b3.s))
	testing.expect(t, strings.contains(tls_last_error(&b3.s), "not for a client"))
}

@(test)
leaf_pinned_name_and_key_usage :: proc(t: ^testing.T) {
	good := Leaf_Rules {
		ku_required = true,
		name_kind   = .Name,
		name        = "Server-1",
	}
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, pinned_cfg(.Client, CLIENT_CRT, CLIENT_KEY, good), pinned_cfg(.Server, SERVER_CRT, SERVER_KEY, {})) {
		return
	}
	cs, ss := tls_loopback(&b.c, &b.s)
	testing.expectf(t, cs == .Done && ss == .Done, "client %v (%s), server %v (%s)", cs, tls_last_error(&b.c), ss, tls_last_error(&b.s))

	bad := good
	bad.name = "Server-2"
	b2: Both
	defer both_destroy(&b2)
	if !both_init(t, &b2, pinned_cfg(.Client, CLIENT_CRT, CLIENT_KEY, bad), pinned_cfg(.Server, SERVER_CRT, SERVER_KEY, {})) {
		return
	}
	cs2, _ := tls_loopback(&b2.c, &b2.s)
	testing.expect_value(t, cs2, Handshake_Status.Failed)
	testing.expect(t, strings.contains(tls_last_error(&b2.c), "the name 'Server-1' does not match verify-x509-name"))
	testing.expect_value(t, tls_cert_revoked(&b2.c), false)

	// No key usage extension.
	b3: Both
	defer both_destroy(&b3)
	if !both_init(t, &b3, pinned_cfg(.Client, CLIENT_CRT, CLIENT_KEY, {ku_required = true}), pinned_cfg(.Server, NOKU_CRT, NOKU_KEY, {})) {
		return
	}
	cs3, _ := tls_loopback(&b3.c, &b3.s)
	testing.expect_value(t, cs3, Handshake_Status.Failed)
	testing.expect(t, strings.contains(tls_last_error(&b3.c), "the certificate has no key usage"))
}

@(test)
leaf_name_rule_text_in_a_handshake :: proc(t: ^testing.T) {
	cases := [?]struct {
		rule: Leaf_Rules,
		text: string,
	} {
		{name_rule(.Name, "Other"), "the name 'Server-1' does not match verify-x509-name"},
		{name_rule(.Name_Prefix, "Other"), "the name 'Server-1' does not start with the verify-x509-name value"},
		{name_rule(.Subject, "CN=Server-1"), "the subject 'C=KG, ST=NA, L=Bishkek, O=Noir Test, CN=Server-1' does not match verify-x509-name"},
		{ku_rules(0x88), "key usage 0x00a0 is not in the accepted list"},
	}
	for c in cases {
		b: Both
		defer both_destroy(&b)
		if !both_init(t, &b, chain_cfg(.Client, CLIENT_CRT, CLIENT_KEY, c.rule), chain_cfg(.Server, SERVER_CRT, SERVER_KEY, {})) {
			return
		}
		cs, _ := tls_loopback(&b.c, &b.s)
		testing.expect_value(t, cs, Handshake_Status.Failed)
		text := tls_last_error(&b.c)
		testing.expectf(t, strings.has_prefix(text, "certificate verify failed: ") && strings.contains(text, c.text), "text: %s", text)
	}
}

@(test)
leaf_rules_with_a_crl_context :: proc(t: ^testing.T) {
	chain := proc(crt: []u8) -> []u8 {
		b := make([dynamic]u8, 0, len(crt) + len(CRL_SUB), context.temp_allocator)
		append(&b, ..crt)
		append(&b, ..CRL_SUB)
		return b[:]
	}
	cfg := proc(role: Tls_Role, crt, key: []u8, crl: []u8, rules: Leaf_Rules) -> Tls_Config {
		return Tls_Config{role = role, cert_pem = crt, key_pem = key, min_version = .TLS_1_3, verify = .Chain, ca_pem = CRL_ROOT, crl_pem = crl, rules = rules}
	}
	// The leaf of the CRL PKI has a key usage and no extended key usage.
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, cfg(.Client, chain(CRL_GOOD_CRT), CRL_GOOD_KEY, nil, {}), cfg(.Server, chain(CRL_GOOD_CRT), CRL_GOOD_KEY, CRL_SUB_BAD, {ku_required = true, ku_list = {0 = 0x80}, ku_count = 1})) {
		return
	}
	cs, ss := tls_loopback(&b.c, &b.s)
	testing.expectf(t, cs == .Done && ss == .Done, "client %v (%s), server %v (%s)", cs, tls_last_error(&b.c), ss, tls_last_error(&b.s))

	b2: Both
	defer both_destroy(&b2)
	if !both_init(t, &b2, cfg(.Client, chain(CRL_GOOD_CRT), CRL_GOOD_KEY, nil, {}), cfg(.Server, chain(CRL_GOOD_CRT), CRL_GOOD_KEY, CRL_SUB_BAD, tls_rules(EKU_CLIENT_AUTH))) {
		return
	}
	_, ss2 := tls_loopback(&b2.c, &b2.s)
	testing.expect_value(t, ss2, Handshake_Status.Failed)
	testing.expect(t, tls_cert_rule_failed(&b2.s))
	testing.expect(t, !tls_cert_revoked(&b2.s))

	// A revoked certificate is still refused as revoked: the CRL check runs first.
	b3: Both
	defer both_destroy(&b3)
	if !both_init(t, &b3, cfg(.Client, chain(CRL_BAD_CRT), CRL_BAD_KEY, nil, {}), cfg(.Server, chain(CRL_GOOD_CRT), CRL_GOOD_KEY, CRL_SUB_BAD, {ku_required = true})) {
		return
	}
	_, ss3 := tls_loopback(&b3.c, &b3.s)
	testing.expect_value(t, ss3, Handshake_Status.Failed)
	testing.expect(t, tls_cert_revoked(&b3.s))
	testing.expect(t, !tls_cert_rule_failed(&b3.s))

	// A lost list still refuses everyone.
	b4: Both
	defer both_destroy(&b4)
	if !both_init(t, &b4, cfg(.Client, chain(CRL_GOOD_CRT), CRL_GOOD_KEY, nil, {}), cfg(.Server, chain(CRL_GOOD_CRT), CRL_GOOD_KEY, CRL_SUB_BAD, {ku_required = true})) {
		return
	}
	tls_ctx_crl_lost(&b4.sctx)
	_, ss4 := tls_loopback(&b4.c, &b4.s)
	testing.expect_value(t, ss4, Handshake_Status.Failed)
	testing.expect(t, strings.contains(tls_last_error(&b4.s), "the CRL is not loaded"))
}

@(test)
leaf_rules_are_not_used_without_verification :: proc(t: ^testing.T) {
	// `.None` does not look at the certificate.
	ccfg := Tls_Config {
		role        = .Client,
		min_version = .TLS_1_3,
		verify      = .None,
		rules       = tls_rules(EKU_SERVER_AUTH),
	}
	scfg := Tls_Config {
		role        = .Server,
		cert_pem    = CLIENT_CRT,
		key_pem     = CLIENT_KEY,
		min_version = .TLS_1_3,
		verify      = .None,
	}
	b: Both
	defer both_destroy(&b)
	if !both_init(t, &b, ccfg, scfg) {
		return
	}
	cs, ss := tls_loopback(&b.c, &b.s)
	testing.expectf(t, cs == .Done && ss == .Done, "client %v, server %v", cs, ss)
}

@(test)
leaf_context_with_bad_rules_is_refused :: proc(t: ^testing.T) {
	cfg := chain_cfg(.Client, CLIENT_CRT, CLIENT_KEY, {eku = "no such usage"})
	_, err := tls_ctx_create(cfg)
	testing.expect_value(t, err, Error.Bad_Config)
	cfg = chain_cfg(.Client, CLIENT_CRT, CLIENT_KEY, name_rule(.Name, ""))
	_, err = tls_ctx_create(cfg)
	testing.expect_value(t, err, Error.Bad_Argument)
	cfg = pinned_cfg(.Client, CLIENT_CRT, CLIENT_KEY, {eku = "no such usage"})
	_, err = tls_ctx_create(cfg)
	testing.expect_value(t, err, Error.Bad_Config)
}

// --------------------------------------------------------------- TLS versions

@(private = "file")
version_cfg :: proc(role: Tls_Role, crt, key: []u8, min_v, max_v: Tls_Version) -> Tls_Config {
	return Tls_Config{role = role, cert_pem = crt, key_pem = key, min_version = min_v, max_version = max_v, verify = .Chain, ca_pem = LEAF_CA}
}

@(test)
tls_versions_both_ends :: proc(t: ^testing.T) {
	cases := [?]struct {
		cmin, cmax, smin, smax: Tls_Version,
		want:                   string, // "" means the handshake fails
	} {
		{.Any, .Any, .Any, .Any, "TLSv1.3"},
		{.TLS_1_3, .Any, .TLS_1_3, .Any, "TLSv1.3"},
		{.TLS_1_2, .TLS_1_2, .TLS_1_2, .TLS_1_2, "TLSv1.2"},
		{.Any, .TLS_1_2, .Any, .Any, "TLSv1.2"},
		{.Any, .Any, .Any, .TLS_1_2, "TLSv1.2"},
		// The client caps at 1.2, the server needs 1.3.
		{.Any, .TLS_1_2, .TLS_1_3, .Any, ""},
		// The client needs 1.3, the server caps at 1.2.
		{.TLS_1_3, .Any, .Any, .TLS_1_2, ""},
		{.TLS_1_3, .Any, .TLS_1_2, .Any, "TLSv1.3"},
	}
	for c in cases {
		b: Both
		defer both_destroy(&b)
		if !both_init(t, &b, version_cfg(.Client, CLIENT_CRT, CLIENT_KEY, c.cmin, c.cmax), version_cfg(.Server, SERVER_CRT, SERVER_KEY, c.smin, c.smax)) {
			return
		}
		cs, ss := tls_loopback(&b.c, &b.s)
		if c.want == "" {
			testing.expectf(t, cs == .Failed || ss == .Failed, "%v: should fail", c)
			continue
		}
		testing.expectf(t, cs == .Done && ss == .Done, "%v: client %v (%s), server %v (%s)", c, cs, tls_last_error(&b.c), ss, tls_last_error(&b.s))
		testing.expect_value(t, tls_version_name(&b.c), c.want)
		testing.expect_value(t, tls_version_name(&b.s), c.want)
	}
}

@(test)
tls_version_min_above_max_is_a_config_error :: proc(t: ^testing.T) {
	_, err := tls_ctx_create(version_cfg(.Client, CLIENT_CRT, CLIENT_KEY, .TLS_1_3, .TLS_1_2))
	testing.expect_value(t, err, Error.Bad_Config)
}
