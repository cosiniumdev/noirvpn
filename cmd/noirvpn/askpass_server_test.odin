// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"
import "noir:proto/config"
import "noir:proto/ossl"

@(private = "file")
LOCKED_KEY := #load("../../proto/ossl/testdata/keypass_legacy_p256.key.pem")
@(private = "file")
CERT := #load("../../proto/ossl/testdata/p256_server.crt.pem")
@(private = "file")
LOCKED_RSA_KEY := #load("../../proto/ossl/testdata/keypass_pkcs8_rsa.key.pem")
@(private = "file")
RSA_CERT := #load("../../proto/ossl/testdata/rsa_server.crt.pem")

@(private = "file")
server_text :: proc(pass_path, extra: string) -> string {
	return fmt.tprintf(
		"mode server\nserver 10.8.0.0 255.255.255.0\nproto tls-server\nca /nonexistent/ca.crt\n<cert>\n%s</cert>\n<key>\n%s</key>\naskpass %s\n%s",
		string(CERT),
		string(LOCKED_KEY),
		pass_path,
		extra,
	)
}

@(private = "file")
pass_path :: proc(name: string) -> string {
	dir, err := os.temp_directory(context.temp_allocator)
	if err != nil || dir == "" {
		dir = "/tmp"
	}
	path := fmt.tprintf("%s/noirvpn-askpass-srv-%d-%s", dir, os.get_pid(), name)
	_ = os.write_entire_file(path, transmute([]u8)string("noir-test-pass\n"), {.Read_User, .Write_User})
	return path
}

@(test)
test_server_settings_decrypt_key_and_outer_key :: proc(t: ^testing.T) {
	path := pass_path("shared")
	defer os.remove(path)

	// The outer TLS has no key of its own: it uses the decrypted `key`.
	cfg := config.build(config.parse_text(server_text(path, ""), "test.conf"))
	defer config.destroy(&cfg)
	s: Server_Settings
	defer server_settings_destroy(&s)
	_ = server_settings_load(&s, &cfg)
	for e in s.errors {
		testing.expectf(t, !strings.has_prefix(e, "key") && !strings.has_prefix(e, "askpass") && !strings.has_prefix(e, "tls-transport"), "error: %s", e)
	}
	testing.expect(t, len(s.key_pem) > 0 && !ossl.key_pem_encrypted(s.key_pem))
	testing.expect(t, raw_data(s.transport_key_pem) == raw_data(s.key_pem))

	// An outer key of its own is decrypted too.
	extra := fmt.tprintf("<tls-transport-cert>\n%s</tls-transport-cert>\n<tls-transport-key>\n%s</tls-transport-key>\n", string(RSA_CERT), string(LOCKED_RSA_KEY))
	cfg2 := config.build(config.parse_text(server_text(path, extra), "test.conf"))
	defer config.destroy(&cfg2)
	s2: Server_Settings
	defer server_settings_destroy(&s2)
	_ = server_settings_load(&s2, &cfg2)
	testing.expect(t, s2.transport_own)
	testing.expect(t, len(s2.transport_key_pem) > 0 && !ossl.key_pem_encrypted(s2.transport_key_pem))
	testing.expect(t, len(s2.key_pem) > 0 && !ossl.key_pem_encrypted(s2.key_pem))
	ctx, err := ossl.tls_ctx_create({role = .Server, verify = .None, cert_pem = s2.transport_cert_pem, key_pem = s2.transport_key_pem})
	testing.expect_value(t, err, ossl.Error.None)
	if err == .None {
		ossl.tls_ctx_destroy(&ctx)
	}
}
