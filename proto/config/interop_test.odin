// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:log"
import "core:os"
import "core:strings"
import "core:testing"

// Configs from the interop harness. The names are cell.role.conf.
IOP_TCP_V2_CLIENT :: #load("testdata/interop/s27c27-tcp-tlscryptv2-rekey.client.conf", string)
IOP_TCP_V2_SERVER :: #load("testdata/interop/s27c27-tcp-tlscryptv2-rekey.server.conf", string)
IOP_AUTH_CLIENT :: #load("testdata/interop/s27c27-udp-tlsauth-sha256-bidir.client.conf", string)
IOP_AUTH_SERVER :: #load("testdata/interop/s27c27-udp-tlsauth-sha256-bidir.server.conf", string)
IOP_PQ_CLIENT :: #load("testdata/interop/s27c27-udp-tlscryptv2-pq.client.conf", string)
IOP_PQ_SERVER :: #load("testdata/interop/s27c27-udp-tlscryptv2-pq.server.conf", string)
IOP_CA_CLIENT :: #load("testdata/interop/s27c26-udp-none-aes256-ca.client.conf", string)
IOP_CA_SERVER :: #load("testdata/interop/s27c26-udp-none-aes256-ca.server.conf", string)
IOP_USERPASS_CLIENT :: #load(
	"testdata/interop/s27c27-udp-tlscrypt-userpass-token.client.conf",
	string,
)
IOP_USERPASS_SERVER :: #load(
	"testdata/interop/s27c27-udp-tlscrypt-userpass-token.server.conf",
	string,
)
IOP_TLS12_CLIENT :: #load("testdata/interop/s26c26-udp-none-tls12.client.conf", string)
IOP_TLS12_SERVER :: #load("testdata/interop/s26c26-udp-none-tls12.server.conf", string)
IOP_TCP_CLIENT :: #load("testdata/interop/s26c26-tcp-none-rekey.client.conf", string)
IOP_TCP_SERVER :: #load("testdata/interop/s26c26-tcp-none-rekey.server.conf", string)
IOP_EXIT_SERVER :: #load("testdata/interop/s27c27-udp-tlscrypt-serverend.server.conf", string)

// Fingerprints used by the harness certificates.
IOP_SERVER_FP :: [32]u8 {
	0xDA,
	0xD1,
	0x56,
	0xB8,
	0xFA,
	0xCA,
	0x23,
	0x12,
	0x1E,
	0x77,
	0xFB,
	0xF8,
	0xA8,
	0x85,
	0x19,
	0xE1,
	0x7E,
	0xF1,
	0xA2,
	0xC5,
	0x83,
	0xB2,
	0x4E,
	0x55,
	0x1B,
	0x81,
	0x79,
	0x23,
	0xE1,
	0x67,
	0x2E,
	0x74,
}

// Warnings for options that stock configs always have and noirvpn ignores.
only_expected_warnings :: proc(t: ^testing.T, diags: []Diagnostic, loc := #caller_location) {
	for d in diags {
		if d.severity == .Error {
			testing.expectf(t, false, "unexpected error: %s", d.message, loc = loc)
			continue
		}
		ok :=
			strings.has_prefix(d.message, "cipher:") ||
			strings.has_prefix(d.message, "log:") ||
			strings.has_prefix(d.message, "dh:") ||
			strings.has_prefix(d.message, "script-security:") ||
			strings.has_prefix(d.message, "explicit-exit-notify:")
		testing.expectf(t, ok, "unexpected warning: %s", d.message, loc = loc)
	}
}

@(test)
test_interop_tcp_tls_crypt_v2 :: proc(t: ^testing.T) {
	c := load(IOP_TCP_V2_CLIENT)
	defer destroy(&c)
	only_expected_warnings(t, c.diags)
	testing.expect_value(t, c.role, Role.Client)
	testing.expect_value(t, len(c.client.connections), 1)
	conn := c.client.connections[0]
	testing.expect_value(t, conn.host, "10.89.6.129")
	testing.expect_value(t, conn.rport, u16(1194))
	testing.expect_value(t, conn.proto, Proto.Tcp)
	testing.expect(t, conn.nobind)
	v2, ok := conn.wrap.tls_crypt_v2.?
	testing.expect(t, ok)
	testing.expect_value(t, v2.key.path, "/keys/gen/tcv2-client.key")
	testing.expect_value(t, c.client.tls.cert.path, "/pki/ec/client.crt")
	testing.expect_value(t, len(c.client.tls.fingerprints), 1)
	testing.expect_value(t, c.client.tls.reneg_sec, 15)
	testing.expect_value(t, c.client.datapath, Datapath.Userspace) // disable-dco
	testing.expect_value(t, len(c.client.data_ciphers), 1)
	testing.expect_value(t, c.client.verb, 4)

	s := load(IOP_TCP_V2_SERVER)
	defer destroy(&s)
	only_expected_warnings(t, s.diags)
	testing.expect_value(t, s.role, Role.Server)
	testing.expect_value(t, len(s.server.listens), 1)
	testing.expect_value(t, s.server.listens[0].proto, Proto.Tcp)
	testing.expect_value(t, s.server.listens[0].port, u16(1194))
	testing.expect_value(t, s.server.net.server_addr, [4]u8{10, 8, 0, 1})
	testing.expect_value(t, s.server.ping, 5)
	testing.expect_value(t, s.server.ping_restart, 60)
	testing.expect(t, s.server.link.wrap.tls_crypt_v2 != nil)
	testing.expect_value(t, len(s.server.tls.fingerprints), 1)
	testing.expect_value(t, s.server.tls.fingerprints[0], IOP_SERVER_FP)
	testing.expect_value(t, s.server.verify_client_cert, Verify_Client_Cert.Require)
}

@(test)
test_interop_tls_auth_sha256 :: proc(t: ^testing.T) {
	c := load(IOP_AUTH_CLIENT)
	defer destroy(&c)
	only_expected_warnings(t, c.diags)
	ta, ok := c.client.connections[0].wrap.tls_auth.?
	testing.expect(t, ok)
	testing.expect_value(t, ta.key.path, "/keys/gen/ta.key")
	testing.expect_value(t, ta.digest, Auth_Digest.Sha256)
	testing.expect_value(t, ta.dir, Key_Dir.None)
	testing.expect_value(t, c.client.connections[0].explicit_exit_notify, 3)

	s := load(IOP_AUTH_SERVER)
	defer destroy(&s)
	only_expected_warnings(t, s.diags)
	sta, sok := s.server.link.wrap.tls_auth.?
	testing.expect(t, sok)
	testing.expect_value(t, sta.digest, Auth_Digest.Sha256)
	testing.expect_value(t, sta.dir, Key_Dir.None)
}

@(test)
test_interop_pq :: proc(t: ^testing.T) {
	c := load(IOP_PQ_CLIENT)
	defer destroy(&c)
	only_expected_warnings(t, c.diags)
	testing.expect_value(t, c.client.tls.tls_groups, "X25519MLKEM768")
	testing.expect_value(t, c.client.tls.cert.path, "/pki/mldsa/client.crt")
	s := load(IOP_PQ_SERVER)
	defer destroy(&s)
	only_expected_warnings(t, s.diags)
	testing.expect_value(t, s.server.tls.tls_groups, "X25519MLKEM768")
}

@(test)
test_interop_ca_and_remote_cert_tls :: proc(t: ^testing.T) {
	c := load(IOP_CA_CLIENT)
	defer destroy(&c)
	only_expected_warnings(t, c.diags)
	testing.expect_value(t, c.client.tls.ca.path, "/pki/rsa/ca.crt")
	testing.expect_value(t, c.client.tls.remote_cert_tls, Remote_Cert_Tls.Server)
	testing.expect_value(t, len(c.client.tls.fingerprints), 0)
	s := load(IOP_CA_SERVER)
	defer destroy(&s)
	only_expected_warnings(t, s.diags)
	testing.expect_value(t, s.server.tls.remote_cert_tls, Remote_Cert_Tls.Client)
	testing.expect_value(t, s.server.tls.ca.path, "/pki/rsa/ca.crt")
	testing.expect_value(t, s.server.peer_keys_mode, Peer_Keys_Mode.Pin)
}

@(test)
test_interop_user_pass :: proc(t: ^testing.T) {
	c := load(IOP_USERPASS_CLIENT)
	defer destroy(&c)
	only_expected_warnings(t, c.diags)
	a, ok := c.client.auth_user_pass.?
	testing.expect(t, ok)
	testing.expect_value(t, a.file, "/cell/userpass.txt")
	testing.expect_value(t, c.client.tls.hand_window, 7)

	// The server uses a script and auth tokens: both are rejected, with a
	// pointer to the control bus.
	s := load(IOP_USERPASS_SERVER)
	defer destroy(&s)
	expect_error(t, s.diags, 17, "auth-user-pass-verify: not supported")
	expect_error(t, s.diags, 17, "auth-external")
	expect_error(t, s.diags, 18, "auth-gen-token: not supported")
	expect_warning(t, s.diags, 16, "script-security: ignored")
	errors := 0
	for d in s.diags {
		if d.severity == .Error {
			errors += 1
		}
	}
	testing.expect_value(t, errors, 2)
	// Everything else in it is still understood.
	testing.expect_value(t, s.role, Role.Server)
	testing.expect_value(t, s.server.tls.hand_window, 7)
}

@(test)
test_interop_tls12 :: proc(t: ^testing.T) {
	c := load(IOP_TLS12_CLIENT)
	defer destroy(&c)
	only_expected_warnings(t, c.diags)
	testing.expect_value(t, c.client.tls.version_max, Tls_Version.V1_2)
	testing.expect_value(t, c.client.tls.version_min, Tls_Version.Default)
	s := load(IOP_TLS12_SERVER)
	defer destroy(&s)
	only_expected_warnings(t, s.diags)
	testing.expect_value(t, s.server.tls.version_max, Tls_Version.V1_2)
}

@(test)
test_interop_tcp_none :: proc(t: ^testing.T) {
	c := load(IOP_TCP_CLIENT)
	defer destroy(&c)
	only_expected_warnings(t, c.diags)
	testing.expect_value(t, c.client.connections[0].proto, Proto.Tcp)
	testing.expect(t, c.client.connections[0].wrap.tls_auth == nil)
	testing.expect(t, c.client.connections[0].wrap.tls_crypt == nil)
	testing.expect(t, c.client.connections[0].wrap.tls_crypt_v2 == nil)
	s := load(IOP_TCP_SERVER)
	defer destroy(&s)
	only_expected_warnings(t, s.diags)
	testing.expect_value(t, s.server.listens[0].proto, Proto.Tcp)
}

@(test)
test_interop_server_exit_notify_3 :: proc(t: ^testing.T) {
	// Stock configs give a server `explicit-exit-notify 3`. That is accepted;
	// the server uses 1 and says so.
	s := load(IOP_EXIT_SERVER)
	defer destroy(&s)
	only_expected_warnings(t, s.diags)
	expect_warning(t, s.diags, 10, "only 1 and 2 are defined")
	testing.expect_value(t, s.server.link.explicit_exit_notify, 1)
}

// Parses every generated config under out/interop/cells (if there are any).
// Each must read without parse errors, and each server or client file must
// have the role its file name says. Errors are allowed only for options that
// noirvpn rejects on purpose.
@(test)
test_interop_generated_configs :: proc(t: ^testing.T) {
	dir := #directory + "../../out/interop/cells"
	cells, err := os.read_all_directory_by_path(dir, context.temp_allocator)
	if err != nil {
		log.info("skipped: out/interop/cells does not exist")
		return
	}
	checked, with_errors := 0, 0
	for cell in cells {
		for name in ([]string{"client.conf", "server.conf"}) {
			path := strings.concatenate({dir, "/", cell.name, "/", name}, context.temp_allocator)
			if !os.exists(path) {
				continue
			}
			p := parse_file(path)
			testing.expectf(
				t,
				!diags_have_error(p.diags),
				"%s: parse errors:\n%s",
				path,
				diag_text(p.diags),
			)
			cfg := build(p)
			want := Role.Client if name == "client.conf" else Role.Server
			testing.expectf(t, cfg.role == want, "%s: role %v, want %v", path, cfg.role, want)
			checked += 1
			if diags_have_error(cfg.diags) {
				with_errors += 1
				for d in cfg.diags {
					if d.severity != .Error {
						continue
					}
					known :=
						strings.has_prefix(d.message, "auth-user-pass-verify: not supported") ||
						strings.has_prefix(d.message, "auth-gen-token: not supported") ||
					strings.has_prefix(d.message, "auth-user-pass-optional: not supported") ||
					strings.has_prefix(d.message, "management: not supported") ||
					strings.has_prefix(d.message, "management-client-auth: not supported") ||
						strings.has_prefix(d.message, "client-connect: not supported") ||
						strings.has_prefix(d.message, "client-disconnect: not supported") ||
						strings.has_prefix(d.message, "tls-verify: not supported") ||
						strings.has_prefix(d.message, "up: not supported")
					testing.expectf(t, known, "%s: unexpected error: %s", path, d.message)
				}
			}
			destroy(&cfg)
		}
	}
	log.infof(
		"parsed %d generated interop configs, %d with expected rejections",
		checked,
		with_errors,
	)
}
