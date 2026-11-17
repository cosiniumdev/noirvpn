// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

// CLIENT_BASE has 12 lines, so text added by `load_client` starts at line 13.
FIRST_EXTRA_LINE :: 13

@(test)
test_client_defaults :: proc(t: ^testing.T) {
	cfg := load_client("")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	c := &cfg.client
	testing.expect_value(t, cfg.role, Role.Client)
	testing.expect_value(t, len(cfg.diags), 0)
	testing.expect_value(t, c.verb, 1)
	testing.expect_value(t, c.dev, "tun")
	testing.expect_value(t, len(c.data_ciphers), 3)
	if len(c.data_ciphers) == 3 {
		testing.expect_value(t, c.data_ciphers[0], Cipher.Aes_256_Gcm)
		testing.expect_value(t, c.data_ciphers[1], Cipher.Aes_128_Gcm)
		testing.expect_value(t, c.data_ciphers[2], Cipher.Chacha20_Poly1305)
	}
	testing.expect_value(t, len(c.connections), 1)
	if len(c.connections) == 1 {
		conn := c.connections[0]
		testing.expect_value(t, conn.host, "vpn.example.com")
		testing.expect_value(t, conn.rport, u16(1194))
		testing.expect_value(t, conn.lport, u16(1194))
		testing.expect_value(t, conn.proto, Proto.Udp)
		testing.expect_value(t, conn.family, Family.Any)
		testing.expect(t, !conn.nobind)
		testing.expect_value(t, conn.connect_retry, 1)
		testing.expect_value(t, conn.connect_retry_max_wait, 300)
		testing.expect_value(t, conn.connect_timeout, 120)
		testing.expect(
			t,
			conn.wrap.tls_auth == nil &&
			conn.wrap.tls_crypt == nil &&
			conn.wrap.tls_crypt_v2 == nil,
		)
	}
	testing.expect_value(t, c.ping_restart, 120)
	testing.expect_value(t, c.ping, 0)
	testing.expect_value(t, c.tls.hand_window, 60)
	testing.expect_value(t, c.tls.tran_window, 3600)
	testing.expect_value(t, c.tls.reneg_sec, 3600)
	testing.expect_value(t, c.tls.pq_mode, Pq_Mode.Prefer)
	testing.expect_value(t, c.tls.version_min, Tls_Version.Default)
	testing.expect_value(t, c.resolv_retry, -1)
	testing.expect_value(t, c.datapath, Datapath.Userspace)
	testing.expect_value(t, c.dco_socket, "/run/udco/udco.sock")
	testing.expect_value(t, c.workers, 0)
	testing.expect(t, c.tls.ca.is_inline)
	testing.expect_value(t, c.tls.ca.data, "CA\n")
	testing.expect(t, c.tls.cert.is_inline && c.tls.key.is_inline)
	testing.expect_value(t, c.auth_user_pass == nil, true)
}

@(test)
test_client_remote_forms :: proc(t: ^testing.T) {
	cfg := load_client(
		"remote a.example\nremote b.example 443\nremote c.example 8443 tcp-client\nremote d.example 1195 udp6\nremote-random\n",
	)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	c := &cfg.client
	testing.expect_value(t, len(c.connections), 5)
	if len(c.connections) != 5 {
		return
	}
	testing.expect_value(t, c.connections[0].host, "vpn.example.com")
	testing.expect_value(t, c.connections[1].host, "a.example")
	testing.expect_value(t, c.connections[1].rport, u16(1194))
	testing.expect_value(t, c.connections[2].rport, u16(443))
	testing.expect_value(t, c.connections[2].proto, Proto.Udp)
	testing.expect_value(t, c.connections[3].rport, u16(8443))
	testing.expect_value(t, c.connections[3].proto, Proto.Tcp)
	testing.expect_value(t, c.connections[4].proto, Proto.Udp)
	testing.expect_value(t, c.connections[4].family, Family.V6)
	testing.expect(t, c.remote_random)
}

@(test)
test_client_remote_uses_final_global_defaults :: proc(t: ^testing.T) {
	// `port` and `proto` after a `remote` line still set that remote's defaults.
	cfg := load_client("remote h2\nproto tcp-client\nport 443\nlport 5000\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	conn := cfg.client.connections[1]
	testing.expect_value(t, conn.proto, Proto.Tcp)
	testing.expect_value(t, conn.rport, u16(443))
	testing.expect_value(t, conn.lport, u16(5000))
}

@(test)
test_client_proto_names :: proc(t: ^testing.T) {
	good := []struct {
		text:   string,
		proto:  Proto,
		family: Family,
	} {
		{"udp", .Udp, .Any},
		{"udp4", .Udp, .V4},
		{"udp6", .Udp, .V6},
		{"tcp", .Tcp, .Any},
		{"tcp-client", .Tcp, .Any},
		{"tcp4-client", .Tcp, .V4},
		{"tcp6-client", .Tcp, .V6},
		{"tcp4", .Tcp, .V4},
	}
	for g in good {
		cfg := load_client(strings.concatenate({"proto ", g.text, "\n"}, context.temp_allocator))
		if expect_clean(t, cfg.diags) {
			testing.expectf(
				t,
				cfg.client.connections[0].proto == g.proto &&
				cfg.client.connections[0].family == g.family,
				"proto %s: got %v %v",
				g.text,
				cfg.client.connections[0].proto,
				cfg.client.connections[0].family,
			)
		}
		destroy(&cfg)
	}
	for bad in ([]string{"tcp-server", "sctp", "udp5", "tcp-clientx", "UDP", "udp-client", "tcp4-server"}) {
		cfg := load_client(strings.concatenate({"proto ", bad, "\n"}, context.temp_allocator))
		testing.expectf(t, diags_have_error(cfg.diags), "proto %s should be an error", bad)
		destroy(&cfg)
	}
}

@(test)
test_client_remote_errors :: proc(t: ^testing.T) {
	for text in ([]string{"remote\n", "remote h 0\n", "remote h 65536\n", "remote h port\n", "remote h 443 sctp\n", "remote h 443 tcp-server\n", "remote h 443 udp x\n"}) {
		cfg := load_client(text)
		testing.expectf(t, diags_have_error(cfg.diags), "'%s' should be an error", text)
		destroy(&cfg)
	}
	cfg := load_client("remote h 99999\n")
	defer destroy(&cfg)
	expect_error(
		t,
		cfg.diags,
		FIRST_EXTRA_LINE,
		"port must be a number from 1 to 65535, but it is '99999'",
	)
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "remote:")
}

@(test)
test_client_no_remote :: proc(t: ^testing.T) {
	text, _ := strings.replace(
		CLIENT_BASE,
		"remote vpn.example.com 1194\n",
		"",
		1,
		context.temp_allocator,
	)
	cfg := load(text)
	defer destroy(&cfg)
	expect_error(t, cfg.diags, 0, "at least one `remote`")
}

@(test)
test_client_device :: proc(t: ^testing.T) {
	for dev in ([]string{"tun", "tun0", "tun7", "utun", "utun3"}) {
		cfg := load_client(strings.concatenate({"dev ", dev, "\n"}, context.temp_allocator))
		if expect_clean(t, cfg.diags) {
			testing.expect_value(t, cfg.client.dev, dev)
		}
		destroy(&cfg)
	}
	// A named device with an explicit type.
	cfg := load_client("dev vpn0\ndev-type tun\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	for text in ([]string{"dev tap\n", "dev tap0\n", "dev-type tap\n", "dev null\n", "dev vpn0\n", "dev-type ppp\n"}) {
		bad := load_client(text)
		testing.expectf(t, diags_have_error(bad.diags), "'%s' should be an error", text)
		destroy(&bad)
	}
	tap := load_client("dev tap\n")
	defer destroy(&tap)
	expect_error(t, tap.diags, FIRST_EXTRA_LINE, "TAP (layer 2) is not supported")
}

@(test)
test_client_topology :: proc(t: ^testing.T) {
	ok := load_client("topology subnet\n")
	defer destroy(&ok)
	expect_clean(t, ok.diags)
	testing.expect(t, ok.client.topology_subnet)
	for v in ([]string{"net30", "p2p", "foo"}) {
		cfg := load_client(strings.concatenate({"topology ", v, "\n"}, context.temp_allocator))
		expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "topology")
		destroy(&cfg)
	}
	n30 := load_client("topology net30\n")
	defer destroy(&n30)
	expect_error(t, n30.diags, FIRST_EXTRA_LINE, "topology subnet")
}

@(test)
test_client_connection_blocks :: proc(t: ^testing.T) {
	text := `client
proto tcp-client
port 443
<connection>
remote a.example
</connection>
proto udp
<connection>
remote b.example 1195
nobind
</connection>
<connection>
remote c.example 53 tcp-client
tls-crypt tc.key
</connection>
remote d.example
<ca>
CA
</ca>
<cert>
C
</cert>
<key>
K
</key>
`
	cfg := load(text)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	c := cfg.client.connections
	testing.expect_value(t, len(c), 4)
	if len(c) != 4 {
		return
	}
	// A block starts from the settings given before it.
	testing.expect_value(t, c[0].host, "a.example")
	testing.expect_value(t, c[0].proto, Proto.Tcp)
	testing.expect_value(t, c[0].rport, u16(443))
	testing.expect_value(t, c[1].proto, Proto.Udp)
	testing.expect_value(t, c[1].rport, u16(1195))
	testing.expect(t, c[1].nobind)
	testing.expect_value(t, c[2].proto, Proto.Tcp)
	testing.expect_value(t, c[2].rport, u16(53))
	if tc, ok := c[2].wrap.tls_crypt.?; ok {
		testing.expect_value(t, tc.path, "tc.key")
	} else {
		testing.expect(t, false, "the block's tls-crypt is missing")
	}
	testing.expect(t, c[0].wrap.tls_crypt == nil && c[1].wrap.tls_crypt == nil)
	// A plain remote uses the final global settings: the last `proto udp`.
	testing.expect_value(t, c[3].host, "d.example")
	testing.expect_value(t, c[3].proto, Proto.Udp)
	testing.expect_value(t, c[3].rport, u16(443))
	testing.expect(t, !c[3].nobind)
}

@(test)
test_client_connection_block_errors :: proc(t: ^testing.T) {
	cfg := load_client("<connection>\nnobind\n</connection>\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "needs a remote")
	destroy(&cfg)

	cfg = load_client("<connection>\nremote a\nverb 3\n</connection>\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 2, "cannot be used inside a <connection> block")
	destroy(&cfg)

	cfg = load_client("<connection>\nremote a\nremote b\n</connection>\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 2, "can only have one remote")
	destroy(&cfg)

	cfg = load_client("<connection>\nremote a\nproto tcp-server\n</connection>\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 2, "tcp-server")
	destroy(&cfg)

	// Only for a client.
	srv := load_server("<connection>\nremote a\n</connection>\n")
	defer destroy(&srv)
	testing.expect(t, diags_have_error(srv.diags))
}

@(test)
test_client_tls_auth :: proc(t: ^testing.T) {
	cfg := load_client("tls-auth ta.key 1\n")
	if expect_clean(t, cfg.diags) {
		ta, ok := cfg.client.connections[0].wrap.tls_auth.?
		testing.expect(t, ok)
		testing.expect_value(t, ta.key.path, "ta.key")
		testing.expect_value(t, ta.dir, Key_Dir.One)
		testing.expect_value(t, ta.digest, Auth_Digest.Sha1)
	}
	destroy(&cfg)

	cfg = load_client("tls-auth ta.key\nkey-direction 0\nauth SHA256\n")
	if expect_clean(t, cfg.diags) {
		ta, _ := cfg.client.connections[0].wrap.tls_auth.?
		testing.expect_value(t, ta.dir, Key_Dir.Zero)
		testing.expect_value(t, ta.digest, Auth_Digest.Sha256)
	}
	destroy(&cfg)

	// key-direction after the tls-auth line works too.
	cfg = load_client("key-direction 1\ntls-auth ta.key\nauth sha512\n")
	if expect_clean(t, cfg.diags) {
		ta, _ := cfg.client.connections[0].wrap.tls_auth.?
		testing.expect_value(t, ta.dir, Key_Dir.One)
		testing.expect_value(t, ta.digest, Auth_Digest.Sha512)
	}
	destroy(&cfg)

	// No direction at all: both sides share the key half.
	cfg = load_client("tls-auth ta.key\n")
	if expect_clean(t, cfg.diags) {
		ta, _ := cfg.client.connections[0].wrap.tls_auth.?
		testing.expect_value(t, ta.dir, Key_Dir.None)
	}
	destroy(&cfg)

	cfg = load_client("<tls-auth>\nKEY\n</tls-auth>\nkey-direction 1\n")
	if expect_clean(t, cfg.diags) {
		ta, _ := cfg.client.connections[0].wrap.tls_auth.?
		testing.expect(t, ta.key.is_inline)
		testing.expect_value(t, ta.key.data, "KEY\n")
		testing.expect_value(t, ta.dir, Key_Dir.One)
	}
	destroy(&cfg)

	cfg = load_client("tls-auth ta.key 2\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "direction must be 0 or 1")
	destroy(&cfg)

	cfg = load_client("key-direction 5\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "must be 0 or 1")
	destroy(&cfg)

	cfg = load_client("tls-auth ta.key\nauth MD5\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 1, "SHA1, SHA256 or SHA512")
	destroy(&cfg)

	cfg = load_client("auth SHA256\n")
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE, "no effect without tls-auth")
	testing.expect(t, !diags_have_error(cfg.diags))
	destroy(&cfg)
}

@(test)
test_client_wrap_combinations :: proc(t: ^testing.T) {
	cfg := load_client("tls-crypt tc.key\n")
	if expect_clean(t, cfg.diags) {
		w := cfg.client.connections[0].wrap
		testing.expect(t, w.tls_crypt != nil && w.tls_auth == nil && w.tls_crypt_v2 == nil)
	}
	destroy(&cfg)

	cfg = load_client("tls-crypt-v2 tcv2.key\n")
	if expect_clean(t, cfg.diags) {
		v2, ok := cfg.client.connections[0].wrap.tls_crypt_v2.?
		testing.expect(t, ok)
		testing.expect_value(t, v2.key.path, "tcv2.key")
		testing.expect_value(t, v2.cookie, Cookie_Mode.Force)
	}
	destroy(&cfg)

	cfg = load_client("tls-crypt-v2 tcv2.key allow-noncookie\n")
	if expect_clean(t, cfg.diags) {
		v2, _ := cfg.client.connections[0].wrap.tls_crypt_v2.?
		testing.expect_value(t, v2.cookie, Cookie_Mode.Allow_Noncookie)
	}
	destroy(&cfg)

	cfg = load_client("tls-crypt-v2 tcv2.key force-cookie\n")
	if expect_clean(t, cfg.diags) {
		v2, _ := cfg.client.connections[0].wrap.tls_crypt_v2.?
		testing.expect_value(t, v2.cookie, Cookie_Mode.Force)
	}
	destroy(&cfg)

	cfg = load_client("<tls-crypt-v2>\nKEYTEXT\n</tls-crypt-v2>\n")
	if expect_clean(t, cfg.diags) {
		v2, _ := cfg.client.connections[0].wrap.tls_crypt_v2.?
		testing.expect(t, v2.key.is_inline)
	}
	destroy(&cfg)

	cfg = load_client("tls-crypt-v2 tcv2.key sometimes\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "force-cookie or allow-noncookie")
	destroy(&cfg)

	cfg = load_client("<tls-crypt>\n</tls-crypt>\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "the inline block is empty")
	destroy(&cfg)

	// A client uses one wrapping mode.
	cfg = load_client("tls-crypt tc.key\ntls-auth ta.key 1\n")
	expect_error(t, cfg.diags, 0, "only one of tls-auth, tls-crypt and tls-crypt-v2")
	destroy(&cfg)
	cfg = load_client("tls-crypt tc.key\ntls-crypt-v2 v2.key\n")
	expect_error(t, cfg.diags, 0, "only one of")
	destroy(&cfg)
}

@(test)
test_client_data_ciphers :: proc(t: ^testing.T) {
	cfg := load_client("data-ciphers AES-128-GCM:CHACHA20-POLY1305\n")
	if expect_clean(t, cfg.diags) {
		c := cfg.client.data_ciphers
		testing.expect_value(t, len(c), 2)
		if len(c) == 2 {
			testing.expect_value(t, c[0], Cipher.Aes_128_Gcm)
			testing.expect_value(t, c[1], Cipher.Chacha20_Poly1305)
		}
	}
	destroy(&cfg)

	// Names are case-insensitive; duplicates collapse; DEFAULT expands.
	cfg = load_client("data-ciphers aes-256-gcm:AES-256-GCM:DEFAULT\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.data_ciphers), 3)
	}
	destroy(&cfg)

	// An optional cipher that noirvpn does not have is dropped with a warning.
	cfg = load_client("data-ciphers AES-256-GCM:?AES-256-CBC\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.data_ciphers), 1)
		expect_warning(t, cfg.diags, FIRST_EXTRA_LINE, "AES-256-CBC")
	}
	destroy(&cfg)

	// Old name.
	cfg = load_client("ncp-ciphers AES-128-GCM\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.data_ciphers), 1)
	}
	destroy(&cfg)

	for bad in ([]string{"AES-256-CBC", "AES-256-GCM:BF-CBC", "AES-256-GCM::AES-128-GCM", "?AES-256-CBC", "", ":"}) {
		line := strings.concatenate({"data-ciphers \"", bad, "\"\n"}, context.temp_allocator)
		c2 := load_client(line)
		testing.expectf(t, diags_have_error(c2.diags), "data-ciphers '%s' should be an error", bad)
		destroy(&c2)
	}
	cfg = load_client("data-ciphers AES-256-CBC\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "only uses AEAD ciphers")
	destroy(&cfg)

	cfg = load_client("data-ciphers-fallback AES-128-GCM\n")
	if expect_clean(t, cfg.diags) {
		c, ok := cfg.client.data_ciphers_fallback.?
		testing.expect(t, ok && c == .Aes_128_Gcm)
	}
	destroy(&cfg)
	cfg = load_client("data-ciphers-fallback BF-CBC\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "not supported")
	destroy(&cfg)
}

@(test)
test_client_cipher_option_ignored :: proc(t: ^testing.T) {
	// `cipher` is accepted and does nothing in TLS mode.
	cfg := load_client("cipher AES-256-GCM\ncipher BF-CBC\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE, "ignored")
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE + 1, "use data-ciphers")
	testing.expect_value(t, len(cfg.client.data_ciphers), 3)
}

@(test)
test_client_tls_versions :: proc(t: ^testing.T) {
	cfg := load_client("tls-version-min 1.3\ntls-version-max 1.3\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.version_min, Tls_Version.V1_3)
		testing.expect_value(t, cfg.client.tls.version_max, Tls_Version.V1_3)
	}
	destroy(&cfg)
	cfg = load_client("tls-version-min 1.2\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.version_min, Tls_Version.V1_2)
	}
	destroy(&cfg)
	cfg = load_client("tls-version-min 1.2 or-highest\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	// An unknown newer version with or-highest means the highest available.
	cfg = load_client("tls-version-min 1.9 or-highest\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.version_min, Tls_Version.V1_3)
	}
	destroy(&cfg)
	for bad in ([]string{"tls-version-min 2.0\n", "tls-version-max 1.1\n", "tls-version-max 1.0\n", "tls-version-max 2.0\n", "tls-version-min 1.2 maybe\n", "tls-version-min 1.3\ntls-version-max 1.2\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
	// A floor below 1.2 means 1.2, with a warning.
	for low in ([]string{"1.1", "1.0"}) {
		text := strings.concatenate({"tls-version-min ", low, "\n"}, context.temp_allocator)
		cfg = load_client(text)
		testing.expect_value(t, cfg.client.tls.version_min, Tls_Version.V1_2)
		expect_warning(t, cfg.diags, FIRST_EXTRA_LINE, "lowest supported version")
		testing.expect(t, !diags_have_error(cfg.diags))
		destroy(&cfg)
	}
	cfg = load_client("tls-version-min 1.0 or-highest\n")
	testing.expect_value(t, cfg.client.tls.version_min, Tls_Version.V1_2)
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE, "lowest supported version")
	destroy(&cfg)
	cfg = load_client("tls-version-max 1.2\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect_value(t, cfg.client.tls.version_max, Tls_Version.V1_2)
}

@(test)
test_client_timers_and_renegotiation :: proc(t: ^testing.T) {
	cfg := load_client(
		"reneg-sec 7200\nreneg-bytes 1000000\nreneg-pkts 5000\nhand-window 30\ntran-window 600\ntls-timeout 5\n",
	)
	if expect_clean(t, cfg.diags) {
		tls := cfg.client.tls
		testing.expect_value(t, tls.reneg_sec, 7200)
		testing.expect_value(t, tls.reneg_sec_min, -1)
		testing.expect_value(t, tls.reneg_bytes, i64(1000000))
		testing.expect_value(t, tls.reneg_pkts, i64(5000))
		testing.expect_value(t, tls.hand_window, 30)
		testing.expect_value(t, tls.tran_window, 600)
		testing.expect_value(t, tls.tls_timeout, 5)
	}
	destroy(&cfg)

	cfg = load_client("reneg-sec 3600 1800\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.reneg_sec, 3600)
		testing.expect_value(t, cfg.client.tls.reneg_sec_min, 1800)
	}
	destroy(&cfg)

	cfg = load_client("reneg-sec 0\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.reneg_sec, 0)
	}
	destroy(&cfg)

	for bad in ([]string{"reneg-sec -1\n", "reneg-sec abc\n", "reneg-sec 100 200\n", "reneg-bytes -5\n", "hand-window 0\n", "tran-window x\n", "reneg-sec 99999999999\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
	cfg = load_client("reneg-sec abc\n")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "reneg-sec: seconds must be a number from 0 to")
}

@(test)
test_client_keepalive_and_ping :: proc(t: ^testing.T) {
	cfg := load_client("keepalive 10 60\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.ping, 10)
		testing.expect_value(t, cfg.client.ping_restart, 60)
	}
	destroy(&cfg)

	cfg = load_client("ping 15\nping-exit 90\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.ping, 15)
		testing.expect_value(t, cfg.client.ping_exit, 90)
		// With ping-exit, the 120 s default restart does not apply.
		testing.expect_value(t, cfg.client.ping_restart, 0)
	}
	destroy(&cfg)

	cfg = load_client("ping-restart 0\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.ping_restart, 0)
	}
	destroy(&cfg)

	cfg = load_client("ping-exit 60\nping-restart 60\n")
	expect_error(t, cfg.diags, 0, "cannot be used together")
	destroy(&cfg)

	cfg = load_client("keepalive 10\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "needs 2 arguments, but the line has 1")
	destroy(&cfg)
}

@(test)
test_client_mtu_and_mss :: proc(t: ^testing.T) {
	cfg := load_client("tun-mtu 1400\nmssfix 1300\n")
	if expect_clean(t, cfg.diags) {
		l := cfg.client.connections[0]
		testing.expect_value(t, l.tun_mtu, 1400)
		testing.expect_value(t, l.mssfix.kind, Mssfix_Kind.Link)
		testing.expect_value(t, l.mssfix.value, 1300)
	}
	destroy(&cfg)

	cfg = load_client("mssfix 1400 mtu\n")
	if expect_clean(t, cfg.diags) {
		m := cfg.client.connections[0].mssfix
		testing.expect_value(t, m.kind, Mssfix_Kind.Mtu)
		testing.expect_value(t, m.value, 1400)
	}
	destroy(&cfg)

	cfg = load_client("mssfix 1200 fixed\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.connections[0].mssfix.kind, Mssfix_Kind.Fixed)
	}
	destroy(&cfg)

	cfg = load_client("mssfix 0\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.connections[0].mssfix.kind, Mssfix_Kind.Off)
	}
	destroy(&cfg)

	// A bare mssfix means the default.
	cfg = load_client("mssfix 1300\nmssfix\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.connections[0].mssfix.kind, Mssfix_Kind.Default)
	}
	destroy(&cfg)

	cfg = load_client("tun-mtu 1500 1600\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.connections[0].tun_mtu, 1500)
		testing.expect_value(t, cfg.client.connections[0].occ_mtu, 1600)
	}
	destroy(&cfg)

	for bad in ([]string{"mssfix 50\n", "mssfix 1300 weird\n", "mssfix abc\n", "tun-mtu 50\n", "tun-mtu 70000\n", "tun-mtu x\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}

	// max-packet-size sets mssfix only if none was given.
	cfg = load_client("max-packet-size 1400\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.max_packet_size, 1400)
		testing.expect_value(t, cfg.client.connections[0].mssfix.kind, Mssfix_Kind.Mtu)
	}
	destroy(&cfg)
	cfg = load_client("max-packet-size 100\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.max_packet_size, 154)
		expect_warning(t, cfg.diags, FIRST_EXTRA_LINE, "so 154 will be used")
	}
	destroy(&cfg)
}

@(test)
test_client_misc_link_options :: proc(t: ^testing.T) {
	cfg := load_client(
		"float\nexplicit-exit-notify\nnobind\nresolv-retry 60\nconnect-retry 5 60\nconnect-retry-max 3\nconnect-timeout 30\nmtu-disc yes\nlocal 192.0.2.5\nbind ipv6only\n",
	)
	if expect_clean(t, cfg.diags) {
		l := cfg.client.connections[0]
		testing.expect(t, l.float)
		testing.expect_value(t, l.explicit_exit_notify, 1)
		testing.expect(t, l.nobind)
		testing.expect_value(t, cfg.client.resolv_retry, 60)
		testing.expect_value(t, l.connect_retry, 5)
		testing.expect_value(t, l.connect_retry_max_wait, 60)
		testing.expect_value(t, l.connect_retry_max, 3)
		testing.expect_value(t, l.connect_timeout, 30)
		testing.expect_value(t, l.mtu_disc, Mtu_Disc.Yes)
		testing.expect_value(t, l.local_host, "192.0.2.5")
		testing.expect(t, l.bind_v6only)
	}
	destroy(&cfg)

	cfg = load_client("explicit-exit-notify 3\nresolv-retry infinite\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.connections[0].explicit_exit_notify, 3)
		testing.expect_value(t, cfg.client.resolv_retry, -1)
	}
	destroy(&cfg)

	for bad in ([]string{"explicit-exit-notify 0\n", "explicit-exit-notify 11\n", "resolv-retry soon\n", "connect-retry x\n", "mtu-disc sometimes\n", "bind weird\n", "connect-timeout 0\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_client_auth_user_pass :: proc(t: ^testing.T) {
	cfg := load_client("auth-user-pass\n")
	if expect_clean(t, cfg.diags) {
		a, ok := cfg.client.auth_user_pass.?
		testing.expect(t, ok)
		testing.expect_value(t, a.file, "")
		testing.expect(t, !a.is_inline && !a.username_only)
	}
	destroy(&cfg)

	cfg = load_client("auth-user-pass creds.txt\n")
	if expect_clean(t, cfg.diags) {
		a, _ := cfg.client.auth_user_pass.?
		testing.expect_value(t, a.file, "creds.txt")
	}
	destroy(&cfg)

	cfg = load_client("auth-user-pass username-only\n")
	if expect_clean(t, cfg.diags) {
		a, _ := cfg.client.auth_user_pass.?
		testing.expect(t, a.username_only)
	}
	destroy(&cfg)

	cfg = load_client("<auth-user-pass>\nuser\npass\n</auth-user-pass>\nauth-retry nointeract\n")
	if expect_clean(t, cfg.diags) {
		a, _ := cfg.client.auth_user_pass.?
		testing.expect(t, a.is_inline)
		testing.expect_value(t, a.data, "user\npass\n")
		testing.expect_value(t, cfg.client.auth_retry, Auth_Retry.Nointeract)
	}
	destroy(&cfg)

	// A client with a password and no certificate is fine.
	text, _ := strings.replace(
		CLIENT_BASE,
		"<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n",
		"",
		1,
		context.temp_allocator,
	)
	cfg = load(strings.concatenate({text, "auth-user-pass\n"}, context.temp_allocator))
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load(text)
	expect_error(t, cfg.diags, 0, "no identity")
	destroy(&cfg)
	// A client that says IV_SSO webauth is signed in by the server: no identity needed.
	cfg = load(strings.concatenate({text, "setenv IV_SSO webauth\n"}, context.temp_allocator))
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load(strings.concatenate({text, "setenv IV_SSO other\n"}, context.temp_allocator))
	expect_error(t, cfg.diags, 0, "no identity")
	destroy(&cfg)

	cfg = load_client("auth-retry maybe\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "must be none, nointeract or interact")
	destroy(&cfg)
}

@(test)
test_client_verification :: proc(t: ^testing.T) {
	fp := "DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74"
	// A pinned server needs no ca.
	base, _ := strings.replace(CLIENT_BASE, "<ca>\nCA\n</ca>\n", "", 1, context.temp_allocator)
	cfg := load(strings.concatenate({base, "peer-fingerprint ", fp, "\n"}, context.temp_allocator))
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.tls.fingerprints), 1)
		testing.expect_value(t, cfg.client.tls.fingerprints[0][0], u8(0xda))
		testing.expect_value(t, cfg.client.tls.fingerprints[0][31], u8(0x74))
	}
	destroy(&cfg)

	// Several fingerprints, inline.
	cfg = load(
		strings.concatenate(
			{
				base,
				"<peer-fingerprint>\n",
				fp,
				"\n# a comment\n",
				strings.to_lower(fp, context.temp_allocator),
				"\n</peer-fingerprint>\n",
			},
			context.temp_allocator,
		),
	)
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.tls.fingerprints), 2)
	}
	destroy(&cfg)

	cfg = load(
		strings.concatenate(
			{base, "peer-fingerprint ", fp, " ", fp, "\n"},
			context.temp_allocator,
		),
	)
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.client.tls.fingerprints), 2)
	}
	destroy(&cfg)

	cfg = load(strings.concatenate({base, "peer-fingerprint DA:D1:56\n"}, context.temp_allocator))
	expect_error(t, cfg.diags, 0, "not a SHA-256 fingerprint")
	destroy(&cfg)

	// Neither ca nor fingerprint.
	cfg = load(base)
	expect_error(t, cfg.diags, 0, "no way to verify the server")
	destroy(&cfg)

	// capath counts as a ca.
	cfg = load(strings.concatenate({base, "capath /etc/ssl/certs\n"}, context.temp_allocator))
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	cfg = load_client(
		"remote-cert-tls server\nverify-x509-name vpn.example.com name\nremote-cert-ku 80 a0\nremote-cert-eku \"TLS Web Server Authentication\"\ncrl-verify crl.pem\n",
	)
	if expect_clean(t, cfg.diags) {
		tls := cfg.client.tls
		testing.expect_value(t, tls.remote_cert_tls, Remote_Cert_Tls.Server)
		x, _ := tls.verify_x509_name.?
		testing.expect_value(t, x.name, "vpn.example.com")
		testing.expect_value(t, x.kind, Verify_X509_Kind.Name)
		testing.expect_value(t, len(tls.remote_cert_ku), 2)
		testing.expect_value(t, tls.remote_cert_eku, "TLS Web Server Authentication")
		crl, ok := tls.crl_verify.?
		testing.expect(t, ok)
		testing.expect_value(t, crl.src.path, "crl.pem")
	}
	destroy(&cfg)

	cfg = load_client("cert only.crt\n")
	defer destroy(&cfg)
	testing.expect(t, !diags_have_error(cfg.diags), "a later cert replaces the inline one")
}

@(test)
test_client_cert_key_pairing :: proc(t: ^testing.T) {
	text, _ := strings.replace(CLIENT_BASE, "<key>\nKEY\n</key>\n", "", 1, context.temp_allocator)
	cfg := load(text)
	defer destroy(&cfg)
	expect_error(t, cfg.diags, 0, "`cert` and `key` must be given together")
}

@(test)
test_client_files_vs_inline :: proc(t: ^testing.T) {
	text := `client
remote h
ca ca.crt
cert client.crt
key client.key
tls-groups X25519MLKEM768:X25519
`
	cfg := load(text)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	tls := cfg.client.tls
	testing.expect_value(t, tls.ca.path, "ca.crt")
	testing.expect(t, !tls.ca.is_inline)
	testing.expect_value(t, tls.cert.path, "client.crt")
	testing.expect_value(t, tls.key.path, "client.key")
	testing.expect_value(t, tls.tls_groups, "X25519MLKEM768:X25519")

	bad := load_client("tls-groups X25519::P-256\n")
	defer destroy(&bad)
	expect_error(t, bad.diags, FIRST_EXTRA_LINE, "empty entry")

	pk := load_client("cert pkcs11:id=%01\n")
	defer destroy(&pk)
	expect_error(t, pk.diags, FIRST_EXTRA_LINE, "PKCS#11")
}

@(test)
test_client_routes_and_redirect :: proc(t: ^testing.T) {
	cfg := load_client(
		"route 192.168.1.0 255.255.255.0\nroute 10.0.0.0 255.0.0.0 vpn_gateway 50\nroute 172.16.0.0 255.240.0.0 default\nroute vpn.example.org\nroute-ipv6 2001:db8::/32\nroute-ipv6 fd00::/8 ::1 20\nroute-metric 100\nroute-nopull\nroute-noexec\n",
	)
	if expect_clean(t, cfg.diags) {
		r := cfg.client.routes
		testing.expect_value(t, len(r), 4)
		if len(r) == 4 {
			testing.expect_value(t, r[0].network, "192.168.1.0")
			testing.expect_value(t, r[0].netmask, "255.255.255.0")
			testing.expect_value(t, r[0].gateway, "")
			testing.expect_value(t, r[0].metric, -1)
			testing.expect_value(t, r[1].gateway, "vpn_gateway")
			testing.expect_value(t, r[1].metric, 50)
			testing.expect_value(t, r[2].gateway, "")
			testing.expect_value(t, r[3].network, "vpn.example.org")
			testing.expect_value(t, r[3].netmask, "")
		}
		r6 := cfg.client.routes6
		testing.expect_value(t, len(r6), 2)
		if len(r6) == 2 {
			testing.expect_value(t, r6[0].prefix, "2001:db8::/32")
			testing.expect_value(t, r6[1].gateway, "::1")
			testing.expect_value(t, r6[1].metric, 20)
		}
		testing.expect_value(t, cfg.client.route_metric, 100)
		testing.expect(t, cfg.client.route_nopull)
		testing.expect(t, cfg.client.route_noexec)
	}
	destroy(&cfg)

	for bad in ([]string{"route 10.0.0.0 255.0.255.0\n", "route 10.0.0.0 abc\n", "route 10.0.0.0 255.0.0.0 gw 1 2\n", "route \"bad host!\"\n", "route-ipv6 2001:db8::\n", "route-ipv6 zzz/64\n", "route 10.0.0.0 255.0.0.0 gw -3\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}

	cfg = load_client("redirect-gateway def1 bypass-dhcp ipv6\nredirect-private local\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, cfg.client.redirect_gateway_set)
		testing.expect_value(
			t,
			cfg.client.redirect_gateway,
			Redirect_Flags{.Def1, .Bypass_Dhcp, .Ipv6},
		)
		testing.expect_value(t, cfg.client.redirect_private, Redirect_Flags{.Local})
	}
	destroy(&cfg)

	cfg = load_client("redirect-gateway\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, cfg.client.redirect_gateway_set)
		testing.expect_value(t, cfg.client.redirect_gateway, Redirect_Flags{})
	}
	destroy(&cfg)

	cfg = load_client("redirect-gateway def2\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "unknown flag 'def2'")
	destroy(&cfg)
}

@(test)
test_client_pull_filter_and_dns :: proc(t: ^testing.T) {
	cfg := load_client(
		"pull-filter ignore \"route \"\npull-filter accept dhcp-option\npull-filter reject \"redirect-gateway\"\ndns search-domains example.org corp.example\ndns server 0 address 10.8.0.1\ndhcp-option DNS 10.8.0.1\n",
	)
	if expect_clean(t, cfg.diags) {
		f := cfg.client.pull_filters
		testing.expect_value(t, len(f), 3)
		if len(f) == 3 {
			testing.expect_value(t, f[0].action, Pull_Action.Ignore)
			testing.expect_value(t, f[0].text, "route ")
			testing.expect_value(t, f[1].action, Pull_Action.Accept)
			testing.expect_value(t, f[2].action, Pull_Action.Reject)
		}
		testing.expect_value(t, len(cfg.client.dns_options), 3)
	}
	destroy(&cfg)

	for bad in ([]string{"pull-filter drop route\n", "dns frobnicate x\n", "dns server\n", "dns server abc address 1.1.1.1\n", "dns search-domains\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_client_process_options :: proc(t: ^testing.T) {
	cfg := load_client(
		"user nobody\ngroup nogroup\nverb 5\nwritepid /run/x.pid\nmlock\nsndbuf 65536\nrcvbuf 65536\nmark 5\nroute-table 100\nifconfig-noexec\n",
	)
	if expect_clean(t, cfg.diags) {
		c := cfg.client
		testing.expect_value(t, c.user, "nobody")
		testing.expect_value(t, c.group, "nogroup")
		testing.expect_value(t, c.verb, 5)
		testing.expect_value(t, c.writepid, "/run/x.pid")
		testing.expect(t, c.mlock)
		testing.expect_value(t, c.sndbuf, 65536)
		testing.expect_value(t, c.rcvbuf, 65536)
		testing.expect_value(t, c.mark, u32(5))
		testing.expect_value(t, c.route_table, 100)
		testing.expect(t, c.ifconfig_noexec)
	}
	destroy(&cfg)

	for bad in ([]string{"verb 12\n", "verb -1\n", "verb x\n", "sndbuf -1\n", "mark x\n", "cd relative/dir\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
	cfg = load_client("cd /etc/vpn\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.cd, "/etc/vpn")
	}
	destroy(&cfg)
}

@(test)
test_client_last_value_wins :: proc(t: ^testing.T) {
	cfg := load_client(
		"verb 3\nverb 7\nproto tcp-client\nproto udp\nreneg-sec 100\nreneg-sec 200\n",
	)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect_value(t, cfg.client.verb, 7)
	testing.expect_value(t, cfg.client.connections[0].proto, Proto.Udp)
	testing.expect_value(t, cfg.client.tls.reneg_sec, 200)
}

@(test)
test_stats_interval :: proc(t: ^testing.T) {
	cfg := load_client("verb 3\n")
	testing.expect_value(t, cfg.client.stats_interval, 0) // off by default
	destroy(&cfg)
	cfg = load_client("stats-interval 15\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.stats_interval, 15)
	}
	destroy(&cfg)
	cfg = load_client("stats-interval 0\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.stats_interval, 0)
	}
	destroy(&cfg)
	for bad in ([]string{"stats-interval\n", "stats-interval -1\n", "stats-interval soon\n", "stats-interval 1 2\n", "stats-interval 100000\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_client_bus_allow_sid :: proc(t: ^testing.T) {
	cfg := load_client("bus-allow sid S-1-5-32-545 read\nbus-allow sid \"BUILTIN\\\\Users\" operator\n")
	if expect_clean(t, cfg.diags) && len(cfg.client.bus_allow) == 2 {
		a := cfg.client.bus_allow
		testing.expect_value(t, a[0].kind, Bus_Id_Kind.Sid)
		testing.expect_value(t, a[0].name, "S-1-5-32-545")
		testing.expect_value(t, a[1].kind, Bus_Id_Kind.Sid)
		testing.expect_value(t, a[1].name, "BUILTIN\\Users")
		testing.expect_value(t, a[1].roles, Bus_Roles{.Operator})
	}
	destroy(&cfg)
	c := load_client("bus-allow sid \"bad\x01\" read\n")
	testing.expect(t, diags_have_error(c.diags))
	destroy(&c)
}

@(test)
test_client_new_options :: proc(t: ^testing.T) {
	cfg := load_client(
		"pq-mode require\nworkers 4\ndatapath userspace\nbus-events off\nbus-control /run/noirvpn/c.sock mode 660 group noirvpn\nbus-allow uid 1000 read,operator\nbus-allow gid admins admin\n",
	)
	if expect_clean(t, cfg.diags) {
		c := cfg.client
		testing.expect_value(t, c.tls.pq_mode, Pq_Mode.Require)
		testing.expect_value(t, c.workers, 4)
		testing.expect_value(t, c.datapath, Datapath.Userspace)
		testing.expect_value(t, c.bus_events.state, Bus_State.Off)
		testing.expect_value(t, c.bus_control.state, Bus_State.Custom)
		testing.expect_value(t, c.bus_control.path, "/run/noirvpn/c.sock")
		testing.expect_value(t, c.bus_control.mode, u32(0o660))
		testing.expect_value(t, c.bus_control.group, "noirvpn")
		testing.expect_value(t, len(c.bus_allow), 2)
		if len(c.bus_allow) == 2 {
			testing.expect_value(t, c.bus_allow[0].kind, Bus_Id_Kind.Uid)
			testing.expect_value(t, c.bus_allow[0].id, u32(1000))
			testing.expect_value(t, c.bus_allow[0].roles, Bus_Roles{.Read, .Operator})
			testing.expect_value(t, c.bus_allow[1].kind, Bus_Id_Kind.Gid)
			testing.expect_value(t, c.bus_allow[1].name, "admins")
			testing.expect_value(t, c.bus_allow[1].roles, Bus_Roles{.Admin})
		}
	}
	destroy(&cfg)

	cfg = load_client("workers 0\ndatapath udco\npq-mode off\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.workers, 0)
		testing.expect_value(t, cfg.client.datapath, Datapath.Udco)
		testing.expect_value(t, cfg.client.tls.pq_mode, Pq_Mode.Off)
	}
	destroy(&cfg)

	cfg = load_client("datapath dco\nproto tcp\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.datapath, Datapath.Dco)
	}
	destroy(&cfg)
	cfg = load_client("datapath dco\ndisable-dco\n")
	expect_error(t, cfg.diags, 0, "`disable-dco` conflicts with `datapath dco`")
	destroy(&cfg)
	cfg = load_client("datapath auto\ndisable-dco\n")
	expect_error(t, cfg.diags, 0, "`disable-dco` conflicts with `datapath auto`")
	destroy(&cfg)
	cfg = load_client("datapath auto\ndco-socket /run/x/y.sock\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.datapath, Datapath.Auto)
		testing.expect_value(t, cfg.client.dco_socket, "/run/x/y.sock")
	}
	destroy(&cfg)

	// The service carries TCP as well: no transport is refused at config time (the
	// daemon checks what the service can do when it connects).
	cfg = load_client("datapath udco\nproto tcp\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_client("datapath auto\nproto tcp\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_client("datapath udco\nproto udp\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	cfg = load_client("disable-dco\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.datapath, Datapath.Userspace)
	}
	destroy(&cfg)
	cfg = load_client("datapath udco\ndisable-dco\n")
	expect_error(t, cfg.diags, 0, "conflicts with")
	destroy(&cfg)

	for bad in ([]string{"pq-mode maybe\n", "workers auto\n", "workers -1\n", "workers 65\n", "workers 1000\n", "workers many\n", "datapath kernel\n", "dco-socket\n", "dco-socket a b\n", "bus-events\n", "bus-events off extra\n", "bus-control /p mode 999\n", "bus-control /p colour red\n", "bus-control /p mode\n", "bus-allow user 1 read\n", "bus-allow uid 1 root\n", "bus-allow uid \"bad name!\" read\n", "bus-allow uid 1\n"}) {
		c := load_client(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_client_pq_mode_with_tls_groups :: proc(t: ^testing.T) {
	// An explicit group list wins over pq-mode; a clash is reported.
	cfg := load_client("tls-groups X25519\npq-mode require\n")
	expect_error(
		t,
		cfg.diags,
		FIRST_EXTRA_LINE + 1,
		"pq-mode is require, but tls-groups 'X25519' does not include a hybrid group",
	)
	destroy(&cfg)

	cfg = load_client("tls-groups X25519MLKEM768:X25519\npq-mode off\n")
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE + 1, "the group list will be used")
	testing.expect(t, !diags_have_error(cfg.diags))
	destroy(&cfg)

	cfg = load_client("tls-groups X25519\npq-mode prefer\n")
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE + 1, "no hybrid key share will be sent")
	destroy(&cfg)

	// No clash, no message.
	cfg = load_client("tls-groups X25519MLKEM768\npq-mode require\n")
	testing.expect_value(t, len(cfg.diags), 0)
	destroy(&cfg)
	cfg = load_client("tls-groups X25519\npq-mode off\n")
	testing.expect_value(t, len(cfg.diags), 0)
	destroy(&cfg)
}

@(test)
test_client_rejected_options :: proc(t: ^testing.T) {
	for text in ([]string{"compress lz4\n", "comp-lzo\n", "management 127.0.0.1 7505\n", "up /etc/openvpn/up.sh\n", "down x\n", "client-connect x\n", "plugin foo.so\n", "fragment 1300\n", "secret static.key\n", "http-proxy proxy 8080\n", "socks-proxy proxy\n", "tap-sleep 1\n", "auth-nocache\nstatus /tmp/s\n"}) {
		cfg := load_client(text)
		testing.expectf(t, diags_have_error(cfg.diags), "'%s' should be rejected", text)
		destroy(&cfg)
	}
	cfg := load_client("compress lz4\n")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "compress: not supported")
	// The message names the reason and what to do.
	testing.expect(t, strings.contains(diag_text(cfg.diags), "compression"))
}

@(test)
test_client_ignored_options :: proc(t: ^testing.T) {
	cfg := load_client(
		"persist-key\nfast-io\nnice 5\nmute 20\nlog /tmp/x.log\nsuppress-timestamps\nscript-security 2\n",
	)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	for i in 0 ..< 7 {
		expect_warning(t, cfg.diags, FIRST_EXTRA_LINE + i, "ignored")
	}
	warnings := 0
	for d in cfg.diags {
		if d.severity == .Warning {
			warnings += 1
		}
	}
	testing.expect_value(t, warnings, 7)
}

@(test)
test_client_persist_tun :: proc(t: ^testing.T) {
	cfg := load_client("persist-tun\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	for d in cfg.diags {
		testing.expectf(t, d.severity != .Warning, "persist-tun warned: %s", d.message)
	}
	testing.expect(t, cfg.client.persist_tun)
}

@(test)
test_client_block_ipv6 :: proc(t: ^testing.T) {
	cfg := load_client("")
	testing.expect(t, !cfg.client.block_ipv6)
	destroy(&cfg)
	cfg = load_client("block-ipv6\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	for d in cfg.diags {
		testing.expectf(t, d.severity != .Warning, "block-ipv6 warned: %s", d.message)
	}
	testing.expect(t, cfg.client.block_ipv6)
	// No argument.
	bad := load_client("block-ipv6 yes\n")
	defer destroy(&bad)
	expect_error(t, bad.diags, FIRST_EXTRA_LINE, "block-ipv6")
}

@(test)
test_client_unknown_options :: proc(t: ^testing.T) {
	cfg := load_client("frobnicate 1\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "unknown option")
	destroy(&cfg)

	cfg = load_client("ignore-unknown-option frobnicate\nfrobnicate 1\nother 2\n")
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE + 1, "unknown option, which will be ignored")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 2, "unknown option")
	destroy(&cfg)

	cfg = load_client("setenv FORWARD_COMPATIBLE 1\nfrobnicate 1\n")
	expect_clean(t, cfg.diags)
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE + 1, "unknown option, which will be ignored")
	destroy(&cfg)

	cfg = load_client(
		"setenv opt frobnicate 1\nfrobnicate 1\nsetenv opt verb 9\nsetenv IV_GUI_VER x\n",
	)
	expect_clean(t, cfg.diags)
	testing.expect_value(t, cfg.client.verb, 9)
	testing.expect_value(t, cfg.client.iv_sso, "")
	destroy(&cfg)

	cfg = load_client("setenv IV_SSO webauth\n")
	expect_clean(t, cfg.diags)
	testing.expect_value(t, cfg.client.iv_sso, "webauth")
	destroy(&cfg)
}

@(test)
test_client_wrong_role_options :: proc(t: ^testing.T) {
	cfg := load_client("client-to-client\n")
	expect_error(
		t,
		cfg.diags,
		FIRST_EXTRA_LINE,
		"applies to servers only, but this is a client config",
	)
	destroy(&cfg)

	cfg = load_client("server 10.8.0.0 255.255.255.0\n")
	expect_error(t, cfg.diags, 0, "both client and server directives")
	destroy(&cfg)

	cfg = load_client("max-clients 5\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "servers only")
	destroy(&cfg)

	cfg = load_client("auth-token abc\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "can only be pushed")
	destroy(&cfg)

	cfg = load_client("iroute 10.0.0.0 255.0.0.0\n")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "client-config-dir")
	destroy(&cfg)
}

@(test)
test_arity_errors :: proc(t: ^testing.T) {
	cfg := load_client("remote\nverb 3 4\nverb\nclient extra\nkeepalive 1 2 3\nproto\n")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "needs 1 to 3 arguments, but the line has 0")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 1, "needs 1 argument, but the line has 2")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 2, "needs 1 argument, but the line has 0")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 3, "needs 0 arguments, but the line has 1")
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 4, "needs 2 arguments, but the line has 3")
}

@(test)
test_trailing_comment_hint :: proc(t: ^testing.T) {
	// Comments work only at the start of a line; say so when it looks like one.
	cfg := load_client("verb 3 # quiet\n")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE, "needs 1 argument, but the line has 3")
	expect_warning(
		t,
		cfg.diags,
		FIRST_EXTRA_LINE,
		"comments are only allowed at the start of a line",
	)
}

@(test)
test_role_detection :: proc(t: ^testing.T) {
	cfg := load("verb 3\nremote a 1\n")
	expect_error(t, cfg.diags, 0, "cannot tell whether this is a client or a server")
	testing.expect_value(t, cfg.role, Role.None)
	destroy(&cfg)

	cfg = load("")
	expect_error(t, cfg.diags, 0, "cannot tell")
	destroy(&cfg)

	// `pull` and `tls-client` also mark a client.
	cfg = load("pull\nremote a 1\nca ca.crt\ncert c.crt\nkey c.key\n")
	testing.expect_value(t, cfg.role, Role.Client)
	destroy(&cfg)

	cfg = load("tls-client\nremote a 1\nca ca.crt\n")
	testing.expect_value(t, cfg.role, Role.Client)
	expect_error(t, cfg.diags, 0, "needs `pull`")
	destroy(&cfg)

	// `mode server` marks a server.
	cfg = load("mode server\ntls-server\n")
	testing.expect_value(t, cfg.role, Role.Server)
	destroy(&cfg)
	cfg = load("mode p2p\nclient\n")
	expect_error(t, cfg.diags, 1, "mode 'p2p' is not supported")
	destroy(&cfg)
}

@(test)
test_allow_compression :: proc(t: ^testing.T) {
	cfg := load_client("allow-compression no\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	for v in ([]string{"yes", "asym"}) {
		c := load_client(
			strings.concatenate({"allow-compression ", v, "\n"}, context.temp_allocator),
		)
		expect_error(t, c.diags, FIRST_EXTRA_LINE, "compression has been removed")
		destroy(&c)
	}
}

@(test)
test_command_line_overrides_file :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["c.conf"] = strings.concatenate(
		{CLIENT_BASE, "verb 3\nremote second.example 443\n"},
		context.temp_allocator,
	)
	opts := Parse_Options {
		loader      = mem_loader,
		loader_data = &files,
	}
	cfg := build(
		parse_args(
			{
				"--config",
				"c.conf",
				"--verb",
				"9",
				"--remote",
				"third.example",
				"--reneg-sec",
				"60",
			},
			opts,
		),
	)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect_value(t, cfg.client.verb, 9)
	testing.expect_value(t, cfg.client.tls.reneg_sec, 60)
	// List options add up, in order.
	hosts: [dynamic]string
	defer delete(hosts)
	for c in cfg.client.connections {
		append(&hosts, c.host)
	}
	testing.expect_value(
		t,
		strings.join(hosts[:], ",", context.temp_allocator),
		"vpn.example.com,second.example,third.example",
	)
	// Errors on the command line name the argument.
	bad := build(parse_args({"--config", "c.conf", "--verb", "99"}, opts))
	defer destroy(&bad)
	testing.expect(t, has_diag(bad.diags, .Error, 0, "verb"))
	found := false
	for d in bad.diags {
		if d.file == COMMAND_LINE {
			found = true
		}
	}
	testing.expect(t, found, "the diagnostic should point at the command line")
}

@(test)
test_client_tls_proto :: proc(t: ^testing.T) {
	good := []struct {
		text:   string,
		family: Family,
	} {
		{"tls", .Any},
		{"tls-client", .Any},
		{"tls4-client", .V4},
		{"tls6-client", .V6},
		{"tls6", .V6},
	}
	for g in good {
		cfg := load_client(strings.concatenate({"proto ", g.text, "\n"}, context.temp_allocator))
		if expect_clean(t, cfg.diags) {
			c := cfg.client.connections[0]
			testing.expectf(t, c.proto == .Tcp && c.tls && c.family == g.family, "proto %s: got %v tls=%v %v", g.text, c.proto, c.tls, c.family)
		}
		destroy(&cfg)
	}
	// Plain tcp stays plain.
	plain := load_client("proto tcp-client\n")
	testing.expect(t, !plain.client.connections[0].tls)
	destroy(&plain)
	for bad in ([]string{"tls-server", "tls4-server", "tls-clientx", "tls5", "tlsclient", "TLS", "tls-server6"}) {
		cfg := load_client(strings.concatenate({"proto ", bad, "\n"}, context.temp_allocator))
		testing.expectf(t, diags_have_error(cfg.diags), "proto %s should be an error", bad)
		destroy(&cfg)
	}
	srv := load_client("proto tls-server\n")
	expect_error(t, srv.diags, 0, "a client cannot use 'tls-server'")
	destroy(&srv)
}

@(test)
test_client_tls_remotes_mix_with_udp_and_tcp :: proc(t: ^testing.T) {
	cfg := load_client("remote a.example 1194 udp\nremote b.example 8443 tcp-client\nremote c.example 443 tls-client\nremote d.example 443 tls6-client\n")
	if expect_clean(t, cfg.diags) {
		c := cfg.client.connections
		testing.expect_value(t, len(c), 5) // the base config has one remote too
		if len(c) == 5 {
			testing.expect(t, !c[1].tls && c[1].proto == .Udp)
			testing.expect(t, !c[2].tls && c[2].proto == .Tcp)
			testing.expect(t, c[3].tls && c[3].proto == .Tcp)
			testing.expect(t, c[4].tls && c[4].proto == .Tcp && c[4].family == .V6)
		}
	}
	destroy(&cfg)

	// The global proto is the default of a remote without one, and a <connection> block can say tls.
	cfg = load_client("proto tls-client\nremote e.example\n<connection>\nremote f.example 444\nproto tcp-client\n</connection>\n<connection>\nremote g.example 445 tls-client\n</connection>\n")
	if expect_clean(t, cfg.diags) {
		c := cfg.client.connections
		if testing.expect_value(t, len(c), 4) {
			testing.expect(t, c[0].tls) // the base remote: the final global proto
			testing.expect(t, c[1].tls)
			testing.expect(t, !c[2].tls && c[2].proto == .Tcp)
			testing.expect(t, c[3].tls)
		}
	}
	destroy(&cfg)
}

@(test)
test_client_proto_force_and_tls :: proc(t: ^testing.T) {
	// `proto-force tcp` keeps the tls remotes: they are TCP.
	cfg := load_client("remote t.example 443 tls-client\nproto-force tcp\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_client("proto-force tls-client\n")
	expect_error(t, cfg.diags, 0, "must be udp or tcp")
	destroy(&cfg)
}

@(test)
test_client_tls_transport_sni :: proc(t: ^testing.T) {
	cfg := load_client("tls-transport-sni front.example.net\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls_transport_sni, "front.example.net")
	}
	destroy(&cfg)
	cfg = load_client("")
	testing.expect_value(t, cfg.client.tls_transport_sni, "")
	destroy(&cfg)
	for bad in ([]string{"tls-transport-sni 192.0.2.1\n", "tls-transport-sni ::1\n", "tls-transport-sni\n", "tls-transport-sni a b\n"}) {
		cfg = load_client(bad)
		testing.expectf(t, diags_have_error(cfg.diags), "'%s' should be an error", bad)
		destroy(&cfg)
	}
	// Server options on a client.
	cfg = load_client("tls-transport-cert x.crt\n")
	expect_error(t, cfg.diags, 0, "applies to servers only")
	destroy(&cfg)
	cfg = load_client("tls-transport-key x.key\n")
	expect_error(t, cfg.diags, 0, "applies to servers only")
	destroy(&cfg)
}
