// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:os"
import "core:strings"
import "core:testing"
import "noir:proto/config"
import "noir:proto/ossl"

// The tests of crl.odin and leaf_rules.odin that need the server settings.

@(private = "file")
SERVER_BASE :: `mode server
server 10.8.0.0 255.255.255.0
<ca>
CA
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`

@(test)
test_crl_verify_with_pins_warns :: proc(t: ^testing.T) {
	// A server with a peers file checks keys: there is no chain.
	cfg := config.build(config.parse_text("mode server\nserver 10.8.0.0 255.255.255.0\ncert c.crt\nkey c.key\npeer-keys /nonexistent/peers\ncrl-verify /nonexistent/crl.pem\n", "test.conf"))
	defer config.destroy(&cfg)
	s: Server_Settings
	defer server_settings_destroy(&s)
	_ = server_settings_load(&s, &cfg)
	found := false
	for w in s.warnings {
		found ||= strings.has_prefix(w, "crl-verify has no effect")
	}
	testing.expectf(t, found, "warnings: %v", s.warnings)
	for e in s.errors {
		testing.expectf(t, !strings.has_prefix(e, "crl-verify"), "a file that is not used is not read: %s", e)
	}
}

@(test)
test_crl_verify_missing_file_is_a_server_error :: proc(t: ^testing.T) {
	cfg := config.build(config.parse_text("mode server\nserver 10.8.0.0 255.255.255.0\ncert c.crt\nkey c.key\nca ca.crt\ncrl-verify /nonexistent/crl.pem\n", "test.conf"))
	defer config.destroy(&cfg)
	s: Server_Settings
	defer server_settings_destroy(&s)
	testing.expect(t, !server_settings_load(&s, &cfg))
	found := false
	for e in s.errors {
		found ||= e == "crl-verify: cannot read /nonexistent/crl.pem"
	}
	testing.expectf(t, found, "errors: %v", s.errors)
}

@(test)
test_name_type_with_username_field_is_an_error :: proc(t: ^testing.T) {
	text := strings.concatenate({SERVER_BASE, "verify-x509-name a name\nx509-username-field emailAddress\n"}, context.temp_allocator)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	s: Server_Settings
	defer server_settings_destroy(&s)
	testing.expect(t, !server_settings_load(&s, &cfg))
	found := false
	for e in s.errors {
		found ||= strings.has_prefix(e, "verify-x509-name with the type name or name-prefix")
	}
	testing.expectf(t, found, "errors: %v", s.errors)

	// The whole subject is not read from that field: allowed.
	text2 := strings.concatenate({SERVER_BASE, "verify-x509-name 'CN=a' subject\nx509-username-field emailAddress\n"}, context.temp_allocator)
	cfg2 := config.build(config.parse_text(text2, "test.conf"))
	defer config.destroy(&cfg2)
	s2: Server_Settings
	defer server_settings_destroy(&s2)
	_ = server_settings_load(&s2, &cfg2)
	for e in s2.errors {
		testing.expectf(t, !strings.has_prefix(e, "verify-x509-name"), "error: %s", e)
	}
}

@(test)
test_server_rules_from_remote_cert_tls_client :: proc(t: ^testing.T) {
	text := strings.concatenate({SERVER_BASE, "remote-cert-tls client\nverify-x509-name Client- name-prefix\ntls-version-min 1.3\n"}, context.temp_allocator)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	s: Server_Settings
	defer server_settings_destroy(&s)
	_ = server_settings_load(&s, &cfg)
	testing.expect(t, s.rules.ku_required)
	testing.expect_value(t, s.rules.eku, ossl.EKU_CLIENT_AUTH)
	testing.expect_value(t, s.rules.name_kind, ossl.Leaf_Name_Kind.Name_Prefix)
	testing.expect_value(t, s.tls_min, ossl.Tls_Version.TLS_1_3)
	testing.expect_value(t, s.tls_max, ossl.Tls_Version.Any)
	for w in s.warnings {
		testing.expectf(t, !strings.has_prefix(w, "remote-cert") && !strings.has_prefix(w, "tls-version") && !strings.has_prefix(w, "verify-x509"), "warning: %s", w)
	}
}

@(test)
test_server_optional_certificate_is_supported :: proc(t: ^testing.T) {
	text := strings.concatenate({SERVER_BASE, "verify-client-cert optional\npeer-passwords /nonexistent/users\n"}, context.temp_allocator)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	s: Server_Settings
	defer server_settings_destroy(&s)
	_ = server_settings_load(&s, &cfg)
	testing.expect(t, s.cert_optional)
	testing.expect_value(t, s.verify, ossl.Peer_Verify.Chain)
	for e in s.errors {
		testing.expectf(t, !strings.contains(e, "verify-client-cert"), "error: %s", e)
	}
	// The default needs a certificate.
	cfg2 := config.build(config.parse_text(SERVER_BASE, "test.conf"))
	defer config.destroy(&cfg2)
	s2: Server_Settings
	defer server_settings_destroy(&s2)
	_ = server_settings_load(&s2, &cfg2)
	testing.expect(t, !s2.cert_optional)
}

@(test)
test_server_ca_with_peer_keys_is_pin_or_chain :: proc(t: ^testing.T) {
	text := strings.concatenate({SERVER_BASE, "peer-keys /nonexistent/peers\n"}, context.temp_allocator)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	s: Server_Settings
	defer server_settings_destroy(&s)
	_ = server_settings_load(&s, &cfg)
	testing.expect_value(t, s.verify, ossl.Peer_Verify.Pin_Or_Chain)
}

@(test)
test_server_check_passwords :: proc(t: ^testing.T) {
	cfg := config.build(config.parse_text(strings.concatenate({SERVER_BASE, "peer-passwords /nonexistent/users\n"}, context.temp_allocator), "test.conf"))
	defer config.destroy(&cfg)
	// A file that cannot be read is a warning: the daemon still starts.
	s: Server_Settings
	defer server_settings_destroy(&s)
	server_settings_check_passwords(&s, &cfg.server)
	testing.expect_value(t, len(s.errors), 0)
	testing.expect_value(t, len(s.warnings), 1)
	testing.expect_value(t, s.user_count, 0)

	// A file with one good line, one bad line and a repeated name.
	path := "/tmp/noirvpn-test-passwords"
	good := "pbkdf2-sha256:1000:AAECAwQFBgcICQoLDA0ODw==:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	text := strings.concatenate({"alice\t", good, "\nbroken\tline\nALICE\t", good, "\n"}, context.temp_allocator)
	testing.expect(t, os.write_entire_file(path, transmute([]u8)text) == nil)
	defer os.remove(path)
	cfg2 := config.build(config.parse_text(strings.concatenate({SERVER_BASE, "peer-passwords ", path, "\n"}, context.temp_allocator), "test.conf"))
	defer config.destroy(&cfg2)
	s2: Server_Settings
	defer server_settings_destroy(&s2)
	server_settings_check_passwords(&s2, &cfg2.server)
	testing.expect_value(t, len(s2.errors), 0)
	testing.expect_value(t, s2.user_count, 1)
	testing.expect_value(t, len(s2.warnings), 2)
}

@(test)
test_server_password_only :: proc(t: ^testing.T) {
	base := "mode server\nserver 10.8.0.0 255.255.255.0\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
	text := strings.concatenate({base, "verify-client-cert optional\npeer-passwords /nonexistent/users\ncrl-verify /nonexistent/crl.pem\nremote-cert-tls client\nverify-x509-name a name\n"}, context.temp_allocator)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	s: Server_Settings
	defer server_settings_destroy(&s)
	_ = server_settings_load(&s, &cfg)
	testing.expect(t, s.password_only)
	testing.expect(t, s.cert_optional)
	testing.expect_value(t, s.verify, ossl.Peer_Verify.None)
	// The certificate options have nothing to act on: a warning each, and the
	// CRL file is not read.
	for name in ([]string{"crl-verify", "remote-cert-tls", "verify-x509-name"}) {
		found := false
		for w in s.warnings {
			found ||= strings.has_prefix(w, name) && strings.contains(w, "no effect")
		}
		testing.expectf(t, found, "no warning for %s: %v", name, s.warnings)
	}
	for e in s.errors {
		testing.expectf(t, !strings.has_prefix(e, "crl-verify"), "error: %s", e)
	}

	// With a CA, or with a peers file, there is a verifier: not password only.
	cfg2 := config.build(config.parse_text(strings.concatenate({SERVER_BASE, "verify-client-cert optional\npeer-passwords /nonexistent/users\n"}, context.temp_allocator), "test.conf"))
	defer config.destroy(&cfg2)
	s2: Server_Settings
	defer server_settings_destroy(&s2)
	_ = server_settings_load(&s2, &cfg2)
	testing.expect(t, !s2.password_only)
	testing.expect_value(t, s2.verify, ossl.Peer_Verify.Chain)

	cfg3 := config.build(config.parse_text(strings.concatenate({base, "verify-client-cert optional\npeer-passwords /nonexistent/users\npeer-keys /nonexistent/peers\n"}, context.temp_allocator), "test.conf"))
	defer config.destroy(&cfg3)
	s3: Server_Settings
	defer server_settings_destroy(&s3)
	_ = server_settings_load(&s3, &cfg3)
	testing.expect(t, !s3.password_only)
	testing.expect_value(t, s3.verify, ossl.Peer_Verify.Pinned)
}
