// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:testing"

// `remote-cert-tls`, `remote-cert-ku`, `remote-cert-eku` and `verify-x509-name`:
// what the config keeps.

@(test)
test_remote_cert_tls_sets_key_usage_and_eku :: proc(t: ^testing.T) {
	cfg := load_client("remote-cert-tls server\n")
	if expect_clean(t, cfg.diags) {
		tls := cfg.client.tls
		testing.expect_value(t, tls.remote_cert_tls, Remote_Cert_Tls.Server)
		testing.expect(t, tls.remote_cert_ku_set)
		testing.expect_value(t, len(tls.remote_cert_ku), 0)
		testing.expect_value(t, tls.remote_cert_eku, REMOTE_EKU_SERVER)
	}
	destroy(&cfg)
	cfg = load_server("remote-cert-tls client\n")
	if expect_clean(t, cfg.diags) {
		tls := cfg.server.tls
		testing.expect_value(t, tls.remote_cert_tls, Remote_Cert_Tls.Client)
		testing.expect_value(t, tls.remote_cert_eku, REMOTE_EKU_CLIENT)
	}
	destroy(&cfg)
	cfg = load_client("remote-cert-tls both\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "must be server or client")
	destroy(&cfg)
}

@(test)
test_remote_cert_options_last_one_wins :: proc(t: ^testing.T) {
	// An explicit eku after remote-cert-tls replaces its eku, and the other way.
	cfg := load_client("remote-cert-tls server\nremote-cert-eku 1.3.6.1.5.5.7.3.3\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.remote_cert_eku, "1.3.6.1.5.5.7.3.3")
		testing.expect(t, cfg.client.tls.remote_cert_ku_set)
	}
	destroy(&cfg)
	cfg = load_client("remote-cert-eku codeSigning\nremote-cert-tls server\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.remote_cert_eku, REMOTE_EKU_SERVER)
	}
	destroy(&cfg)
	// A new key usage list replaces the earlier one.
	cfg = load_client("remote-cert-ku a0\nremote-cert-ku 88 04\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.tls.remote_cert_ku), 2)
		testing.expect_value(t, cfg.client.tls.remote_cert_ku[0], u16(0x88))
		testing.expect_value(t, cfg.client.tls.remote_cert_ku[1], u16(0x04))
	}
	destroy(&cfg)
	// With no values, the key usage is only required.
	cfg = load_client("remote-cert-ku a0\nremote-cert-ku\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.tls.remote_cert_ku), 0)
		testing.expect(t, cfg.client.tls.remote_cert_ku_set)
	}
	destroy(&cfg)
}

@(test)
test_remote_cert_ku_values :: proc(t: ^testing.T) {
	cfg := load_client("remote-cert-ku 0xA0 80\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.tls.remote_cert_ku), 2)
		testing.expect_value(t, cfg.client.tls.remote_cert_ku[0], u16(0xa0))
	}
	destroy(&cfg)
	for bad in ([]string{"remote-cert-ku zz\n", "remote-cert-ku 0\n", "remote-cert-ku 100\n", "remote-cert-ku a0 g\n", "remote-cert-ku 12345\n", "remote-cert-ku 1 2 3 4 5 6 7 8 9 a b c d e f 10 11\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_verify_x509_name_types :: proc(t: ^testing.T) {
	cases := [?]struct {
		text: string,
		name: string,
		kind: Verify_X509_Kind,
	} {
		{"verify-x509-name 'C=XX, CN=Server-1'\n", "C=XX, CN=Server-1", .Subject},
		{"verify-x509-name Server-1 subject\n", "Server-1", .Subject},
		{"verify-x509-name Server-1 name\n", "Server-1", .Name},
		{"verify-x509-name Server- name-prefix\n", "Server-", .Name_Prefix},
	}
	for c in cases {
		cfg := load_client(c.text)
		if expect_clean(t, cfg.diags) {
			x, ok := cfg.client.tls.verify_x509_name.?
			testing.expect(t, ok)
			testing.expect_value(t, x.name, c.name)
			testing.expect_value(t, x.kind, c.kind)
		}
		destroy(&cfg)
	}
	for bad in ([]string{"verify-x509-name Server-1 other\n", "verify-x509-name ''\n", "verify-x509-name a name extra\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}
