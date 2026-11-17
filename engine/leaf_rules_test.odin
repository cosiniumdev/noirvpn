// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:strings"
import "core:testing"
import "noir:proto/config"
import "noir:proto/ossl"

// The rules for the peer certificate and the TLS versions, as the settings of
// the daemon build them from a config.

// Builds the client config BASE plus `extra` and loads the settings.
@(private = "file")
settings_for :: proc(extra: string, s: ^Settings) -> (cfg: config.Config, ok: bool) {
	cfg = config.build(config.parse_text(strings.concatenate({BASE, extra}, context.temp_allocator), "test.conf"))
	if !config.ok(&cfg) {
		return cfg, false
	}
	return cfg, settings_load(s, &cfg)
}

@(test)
test_rules_off_by_default :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	cfg, _ := settings_for("", &s)
	defer config.destroy(&cfg)
	testing.expect(t, !ossl.leaf_rules_active(s.rules))
	testing.expect_value(t, s.tls_min, ossl.Tls_Version.Any)
	testing.expect_value(t, s.tls_max, ossl.Tls_Version.Any)
	for w in s.warnings {
		testing.expectf(t, !strings.has_prefix(w, "remote-cert") && !strings.has_prefix(w, "tls-version") && !strings.has_prefix(w, "verify-x509"), "warning: %s", w)
	}
}

@(test)
test_client_rules_from_remote_cert_tls :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	cfg, ok := settings_for("remote-cert-tls server\n", &s)
	defer config.destroy(&cfg)
	testing.expect(t, ok)
	testing.expect(t, s.rules.ku_required)
	testing.expect_value(t, s.rules.ku_count, 0)
	testing.expect_value(t, s.rules.eku, ossl.EKU_SERVER_AUTH)
	testing.expect_value(t, s.rules.name_kind, ossl.Leaf_Name_Kind.None)
	// The names that the config and the TLS layer use for the usage are the same.
	testing.expect_value(t, config.REMOTE_EKU_SERVER, ossl.EKU_SERVER_AUTH)
	testing.expect_value(t, config.REMOTE_EKU_CLIENT, ossl.EKU_CLIENT_AUTH)
	// No warning that the option is not applied.
	for w in s.warnings {
		testing.expectf(t, !strings.has_prefix(w, "remote-cert"), "warning: %s", w)
	}
}

@(test)
test_client_rules_all_options :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	extra := "remote-cert-tls server\nremote-cert-ku a0 88\nverify-x509-name Server- name-prefix\ntls-version-min 1.3\ntls-version-max 1.3\n"
	cfg, ok := settings_for(extra, &s)
	defer config.destroy(&cfg)
	testing.expect(t, ok)
	testing.expect(t, s.rules.ku_required)
	testing.expect_value(t, s.rules.ku_count, 2)
	testing.expect_value(t, s.rules.ku_list[0], u8(0xa0))
	testing.expect_value(t, s.rules.ku_list[1], u8(0x88))
	testing.expect_value(t, s.rules.eku, ossl.EKU_SERVER_AUTH)
	testing.expect_value(t, s.rules.name_kind, ossl.Leaf_Name_Kind.Name_Prefix)
	testing.expect_value(t, s.rules.name, "Server-")
	testing.expect_value(t, s.tls_min, ossl.Tls_Version.TLS_1_3)
	testing.expect_value(t, s.tls_max, ossl.Tls_Version.TLS_1_3)
}

@(test)
test_client_rules_name_types :: proc(t: ^testing.T) {
	cases := [?]struct {
		text: string,
		kind: ossl.Leaf_Name_Kind,
	} {
		{"verify-x509-name 'C=XX, CN=a'\n", .Subject},
		{"verify-x509-name a name\n", .Name},
		{"verify-x509-name a name-prefix\n", .Name_Prefix},
	}
	for c in cases {
		s: Settings
		defer settings_destroy(&s)
		cfg, ok := settings_for(c.text, &s)
		defer config.destroy(&cfg)
		testing.expect(t, ok)
		testing.expect_value(t, s.rules.name_kind, c.kind)
	}
}

@(test)
test_client_rules_with_a_fingerprint :: proc(t: ^testing.T) {
	// The rules apply with a pin as well as with a chain.
	fp := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	text := strings.concatenate({"client\nremote 192.0.2.1 1194 udp\n<cert>\nC\n</cert>\n<key>\nK\n</key>\npeer-fingerprint ", fp, "\nremote-cert-tls server\n"}, context.temp_allocator)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	s: Settings
	defer settings_destroy(&s)
	_ = settings_load(&s, &cfg)
	testing.expect_value(t, s.verify, ossl.Peer_Verify.Pinned)
	testing.expect(t, s.rules.ku_required)
	testing.expect_value(t, s.rules.eku, ossl.EKU_SERVER_AUTH)
}

@(test)
test_unknown_eku_is_an_error :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	cfg, ok := settings_for("remote-cert-eku no-such-usage\n", &s)
	defer config.destroy(&cfg)
	testing.expect(t, !ok)
	found := false
	for e in s.errors {
		found ||= strings.has_prefix(e, "remote-cert-eku: 'no-such-usage'")
	}
	testing.expectf(t, found, "errors: %v", s.errors)

	s2: Settings
	defer settings_destroy(&s2)
	cfg2, ok2 := settings_for("remote-cert-eku serverAuth\n", &s2)
	defer config.destroy(&cfg2)
	testing.expect(t, ok2)
	testing.expect_value(t, s2.rules.eku, "serverAuth")
}

