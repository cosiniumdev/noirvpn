// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

// SERVER_BASE has 11 lines, so text added by `load_server` starts at line 12.
S_FIRST_EXTRA_LINE :: 12

@(test)
test_server_defaults :: proc(t: ^testing.T) {
	cfg := load_server("")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	s := &cfg.server
	testing.expect_value(t, cfg.role, Role.Server)
	testing.expect_value(t, len(cfg.diags), 0)
	testing.expect_value(t, s.dev, "tun")
	testing.expect_value(t, s.net.network, [4]u8{10, 8, 0, 0})
	testing.expect_value(t, s.net.netmask, [4]u8{255, 255, 255, 0})
	testing.expect_value(t, s.net.prefix, u8(24))
	testing.expect_value(t, s.net.server_addr, [4]u8{10, 8, 0, 1})
	testing.expect(t, !s.net.nopool)
	pool, ok := s.pool.?
	testing.expect(t, ok)
	testing.expect_value(t, pool.start, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, pool.end, [4]u8{10, 8, 0, 253})
	testing.expect(t, s.topology_subnet)
	testing.expect_value(t, len(s.push), 2)
	if len(s.push) == 2 {
		testing.expect_value(t, s.push[0], "topology subnet")
		testing.expect_value(t, s.push[1], "route-gateway 10.8.0.1")
	}
	testing.expect_value(t, len(s.listens), 1)
	if len(s.listens) == 1 {
		testing.expect_value(t, s.listens[0].port, u16(1194))
		testing.expect_value(t, s.listens[0].proto, Proto.Udp)
		testing.expect_value(t, s.listens[0].host, "")
	}
	testing.expect_value(t, s.max_clients, 1024)
	testing.expect_value(t, s.verify_client_cert, Verify_Client_Cert.Require)
	testing.expect_value(t, s.peer_keys_mode, Peer_Keys_Mode.Pin)
	testing.expect_value(t, s.connect_freq_initial, Rate_Limit{100, 10})
	_, src_set := s.connect_freq_source.?
	testing.expect(t, !src_set)
	testing.expect_value(t, s.ping_restart, 0)
	testing.expect(t, s.net6 == nil)
	testing.expect(t, !s.client_to_client)
	testing.expect_value(t, s.tls.pq_mode, Pq_Mode.Prefer)
}

@(test)
test_server_net_expansion :: proc(t: ^testing.T) {
	Case :: struct {
		line:       string,
		server:     [4]u8,
		pool_start: [4]u8,
		pool_end:   [4]u8,
		prefix:     u8,
	}
	cases := []Case {
		{"server 10.8.0.0 255.255.255.0", {10, 8, 0, 1}, {10, 8, 0, 2}, {10, 8, 0, 253}, 24},
		{
			"server 192.168.100.0 255.255.255.128",
			{192, 168, 100, 1},
			{192, 168, 100, 2},
			{192, 168, 100, 125},
			25,
		},
		{"server 10.0.0.0 255.255.0.0", {10, 0, 0, 1}, {10, 0, 0, 2}, {10, 0, 255, 253}, 16},
		{
			"server 172.16.5.0 255.255.255.248",
			{172, 16, 5, 1},
			{172, 16, 5, 2},
			{172, 16, 5, 5},
			29,
		},
	}
	for c in cases {
		text, _ := strings.replace(
			SERVER_BASE,
			"server 10.8.0.0 255.255.255.0",
			c.line,
			1,
			context.temp_allocator,
		)
		cfg := load(text)
		if expect_clean(t, cfg.diags) {
			testing.expectf(
				t,
				cfg.server.net.server_addr == c.server,
				"%s: server addr %v",
				c.line,
				cfg.server.net.server_addr,
			)
			testing.expectf(
				t,
				cfg.server.net.prefix == c.prefix,
				"%s: prefix %d",
				c.line,
				cfg.server.net.prefix,
			)
			pool, ok := cfg.server.pool.?
			testing.expect(t, ok)
			testing.expectf(
				t,
				pool.start == c.pool_start && pool.end == c.pool_end,
				"%s: pool %v - %v",
				c.line,
				pool.start,
				pool.end,
			)
		}
		destroy(&cfg)
	}
}

@(test)
test_server_net_nopool :: proc(t: ^testing.T) {
	text, _ := strings.replace(
		SERVER_BASE,
		"255.255.255.0",
		"255.255.255.0 nopool",
		1,
		context.temp_allocator,
	)
	cfg := load(text)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect(t, cfg.server.net.nopool)
	testing.expect(t, cfg.server.pool == nil)
	// An explicit pool after it is used.
	cfg2 := load(
		strings.concatenate(
			{text, "ifconfig-pool 10.8.0.100 10.8.0.200\n"},
			context.temp_allocator,
		),
	)
	defer destroy(&cfg2)
	expect_clean(t, cfg2.diags)
	p, ok := cfg2.server.pool.?
	testing.expect(t, ok)
	testing.expect_value(t, p.start, [4]u8{10, 8, 0, 100})
}

@(test)
test_server_net_errors :: proc(t: ^testing.T) {
	cases := []struct {
		line: string,
		want: string,
	} {
		{"server 10.8.0.0 255.255.255.252", "between /1 and /29"},
		{"server 10.8.0.0 255.255.255.255", "between /1 and /29"},
		{"server 10.8.0.1 255.255.255.0", "host bits set"},
		{"server 10.8.0.0 255.0.255.0", "not valid (it must be ones followed by zeros)"},
		{"server 10.8.0 255.255.255.0", "not an IPv4 network address"},
		{"server 10.8.0.0 mask", "not a dotted IPv4 netmask"},
		{"server 10.8.0.0 255.255.255.0 nopools", "unknown flag 'nopools'"},
		{"server 10.8.0.0", "needs 2 to 3 arguments"},
	}
	for c in cases {
		text, _ := strings.replace(
			SERVER_BASE,
			"server 10.8.0.0 255.255.255.0",
			c.line,
			1,
			context.temp_allocator,
		)
		cfg := load(text)
		expect_error(t, cfg.diags, 1, c.want)
		destroy(&cfg)
	}
	// Given twice.
	cfg := load_server("server 10.9.0.0 255.255.255.0\n")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "given more than once")
}

@(test)
test_server_missing_server_directive :: proc(t: ^testing.T) {
	text, _ := strings.replace(
		SERVER_BASE,
		"server 10.8.0.0 255.255.255.0\n",
		"tls-server\n",
		1,
		context.temp_allocator,
	)
	cfg := load(text)
	defer destroy(&cfg)
	expect_error(t, cfg.diags, 1, "needs the `server` directive")
}

@(test)
test_server_ipv6 :: proc(t: ^testing.T) {
	cfg := load_server("server-ipv6 fd00:8::/64\n")
	if expect_clean(t, cfg.diags) {
		n, ok := cfg.server.net6.?
		testing.expect(t, ok)
		testing.expect_value(t, n.bits, u8(64))
		testing.expect_value(t, n.prefix[0], u8(0xfd))
		testing.expect_value(t, n.server_addr[15], u8(1))
		testing.expect_value(t, n.pool_base[15], u8(1))
		last := cfg.server.push[len(cfg.server.push) - 1]
		testing.expect_value(t, last, "tun-ipv6")
	}
	destroy(&cfg)

	// An address with a host part is the server's own address.
	cfg = load_server("server-ipv6 fd00:8::5/64\n")
	if expect_clean(t, cfg.diags) {
		n, _ := cfg.server.net6.?
		testing.expect_value(t, n.server_addr[15], u8(5))
	}
	destroy(&cfg)

	cfg = load_server("ifconfig-ipv6-pool fd00:8::100/64\nserver-ipv6 fd00:8::/64\n")
	if expect_clean(t, cfg.diags) {
		p, ok := cfg.server.pool6.?
		testing.expect(t, ok)
		testing.expect_value(t, p[15], u8(0))
		testing.expect_value(t, p[14], u8(1))
	}
	destroy(&cfg)

	for bad in ([]string{"server-ipv6 fd00::\n", "server-ipv6 fd00::/0\n", "server-ipv6 fd00::/120\n", "server-ipv6 xx::/64\n"}) {
		c := load_server(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_server_push :: proc(t: ^testing.T) {
	cfg := load_server(
		"push \"route 192.168.5.0 255.255.255.0\"\npush \"dhcp-option DNS 10.8.0.1\"\npush \"reneg-sec 1800\"\npush \"redirect-gateway def1\"\n",
	)
	if expect_clean(t, cfg.diags) {
		p := cfg.server.push
		testing.expect_value(t, len(p), 6)
		if len(p) == 6 {
			testing.expect_value(t, p[2], "route 192.168.5.0 255.255.255.0")
			testing.expect_value(t, p[3], "dhcp-option DNS 10.8.0.1")
			testing.expect_value(t, p[4], "reneg-sec 1800")
		}
		// Known pushable options give no warnings.
		testing.expect_value(t, len(cfg.diags), 0)
	}
	destroy(&cfg)

	cfg = load_server("push \"topology net30\"\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "topology net30 is not supported")
	destroy(&cfg)

	cfg = load_server("push \"\"\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "pushed option is empty")
	destroy(&cfg)

	cfg = load_server("push \"route \\\"unclosed\"\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "malformed")
	destroy(&cfg)

	cfg = load_server("push \"compress lz4\"\npush \"frobnicate 1\"\npush \"verb 4\"\n")
	testing.expect(t, !diags_have_error(cfg.diags))
	expect_warning(t, cfg.diags, S_FIRST_EXTRA_LINE, "rejected by noirvpn clients")
	expect_warning(t, cfg.diags, S_FIRST_EXTRA_LINE + 1, "not a known option")
	expect_warning(t, cfg.diags, S_FIRST_EXTRA_LINE + 2, "cannot be pushed, so clients will ignore it")
	destroy(&cfg)
}

@(test)
test_server_keepalive_expansion :: proc(t: ^testing.T) {
	cfg := load_server("keepalive 10 60\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.ping, 10)
		// The server waits twice as long as the clients are told.
		testing.expect_value(t, cfg.server.ping_restart, 120)
		p := cfg.server.push
		testing.expect_value(t, len(p), 4)
		if len(p) == 4 {
			testing.expect_value(t, p[2], "ping 10")
			testing.expect_value(t, p[3], "ping-restart 60")
		}
	}
	destroy(&cfg)
	cfg = load_server("keepalive 10 50000\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "43200")
	destroy(&cfg)
}

@(test)
test_server_connect_freq_source :: proc(t: ^testing.T) {
	cfg := load_server("connect-freq-source 5\n")
	if expect_clean(t, cfg.diags) {
		n, ok := cfg.server.connect_freq_source.?
		testing.expect(t, ok)
		testing.expect_value(t, n, 5)
	}
	destroy(&cfg)

	// 0 is a value: no limit per source.
	cfg = load_server("connect-freq-source 0\n")
	if expect_clean(t, cfg.diags) {
		n, ok := cfg.server.connect_freq_source.?
		testing.expect(t, ok)
		testing.expect_value(t, n, 0)
	}
	destroy(&cfg)

	for bad in ([]string{"connect-freq-source\n", "connect-freq-source -1\n", "connect-freq-source x\n", "connect-freq-source 1 2\n", "connect-freq-source 99999999999\n"}) {
		c := load_server(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_server_client_options :: proc(t: ^testing.T) {
	cfg := load_server(
		"client-to-client\nclient-config-dir /etc/noirvpn/ccd\nccd-exclusive\nduplicate-cn\nmax-clients 50\nmax-routes-per-client 10\nconnect-freq 5 10\nconnect-freq-initial 20 5\nifconfig-pool-persist ipp.txt 0\nmultihome\n",
	)
	if expect_clean(t, cfg.diags) {
		s := cfg.server
		testing.expect(t, s.client_to_client)
		testing.expect_value(t, s.client_config_dir, "/etc/noirvpn/ccd")
		testing.expect(t, s.ccd_exclusive)
		testing.expect(t, s.duplicate_cn)
		testing.expect_value(t, s.max_clients, 50)
		testing.expect_value(t, s.max_routes_per_client, 10)
		cf, ok := s.connect_freq.?
		testing.expect(t, ok)
		testing.expect_value(t, cf, Rate_Limit{5, 10})
		testing.expect_value(t, s.connect_freq_initial, Rate_Limit{20, 5})
		pp, pok := s.pool_persist.?
		testing.expect(t, pok)
		testing.expect_value(t, pp.file, "ipp.txt")
		testing.expect_value(t, pp.seconds, 0)
		testing.expect(t, s.multihome)
	}
	destroy(&cfg)

	cfg = load_server("ifconfig-pool-persist ipp.txt\n")
	if expect_clean(t, cfg.diags) {
		pp, _ := cfg.server.pool_persist.?
		testing.expect_value(t, pp.seconds, 600)
	}
	destroy(&cfg)

	for bad in ([]string{"max-clients 0\n", "max-clients x\n", "connect-freq 0 5\n", "ccd-exclusive\n", "ifconfig-pool 10.8.0.9 10.8.0.2\n", "ifconfig-pool 10.8.0.2\n", "ifconfig-pool 10.9.0.2 10.9.0.9\n", "multihome weird\n"}) {
		c := load_server(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_server_listen :: proc(t: ^testing.T) {
	cfg := load_server("proto tcp-server\nport 443\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.server.listens), 1)
		l := cfg.server.listens[0]
		testing.expect_value(t, l.proto, Proto.Tcp)
		testing.expect_value(t, l.port, u16(443))
	}
	destroy(&cfg)

	cfg = load_server("local 192.0.2.1\nlocal 2001:db8::1 1195 udp6\nlocal * 443 tcp-server\n")
	if expect_clean(t, cfg.diags) {
		ls := cfg.server.listens
		testing.expect_value(t, len(ls), 3)
		if len(ls) == 3 {
			testing.expect_value(t, ls[0].host, "192.0.2.1")
			testing.expect_value(t, ls[0].port, u16(1194))
			testing.expect_value(t, ls[0].proto, Proto.Udp)
			testing.expect_value(t, ls[1].host, "2001:db8::1")
			testing.expect_value(t, ls[1].port, u16(1195))
			testing.expect_value(t, ls[1].family, Family.V6)
			testing.expect_value(t, ls[2].host, "")
			testing.expect_value(t, ls[2].proto, Proto.Tcp)
		}
	}
	destroy(&cfg)

	// `local` without port or proto takes the final port and proto.
	cfg = load_server("local 192.0.2.1\nport 5000\nproto tcp-server\n")
	if expect_clean(t, cfg.diags) {
		l := cfg.server.listens[0]
		testing.expect_value(t, l.port, u16(5000))
		testing.expect_value(t, l.proto, Proto.Tcp)
	}
	destroy(&cfg)

	for bad in ([]string{"proto tcp-client\n", "local 1.2.3.4 0\n", "local 1.2.3.4 99999\n", "remote x 1\n", "nobind\n"}) {
		c := load_server(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
}

@(test)
test_server_wrapping :: proc(t: ^testing.T) {
	cfg := load_server("tls-crypt-v2 tcv2-server.key force-cookie\ntls-crypt-v2-max-age 30\n")
	if expect_clean(t, cfg.diags) {
		w := cfg.server.link.wrap
		v2, ok := w.tls_crypt_v2.?
		testing.expect(t, ok)
		testing.expect_value(t, v2.cookie, Cookie_Mode.Force)
		testing.expect_value(t, cfg.server.tls_crypt_v2_max_age, 30)
		// The listen settings share the same wrapping.
		testing.expect(t, cfg.server.listens[0].port != 0)
	}
	destroy(&cfg)

	// A server can accept tls-crypt-v2 together with another mode.
	cfg = load_server("tls-crypt-v2 v2.key allow-noncookie\ntls-crypt tc.key\n")
	if expect_clean(t, cfg.diags) {
		w := cfg.server.link.wrap
		testing.expect(t, w.tls_crypt_v2 != nil && w.tls_crypt != nil)
		v2, _ := w.tls_crypt_v2.?
		testing.expect_value(t, v2.cookie, Cookie_Mode.Allow_Noncookie)
	}
	destroy(&cfg)

	cfg = load_server("tls-auth ta.key 0\nauth SHA256\n")
	if expect_clean(t, cfg.diags) {
		ta, _ := cfg.server.link.wrap.tls_auth.?
		testing.expect_value(t, ta.dir, Key_Dir.Zero)
		testing.expect_value(t, ta.digest, Auth_Digest.Sha256)
	}
	destroy(&cfg)

	cfg = load_server("tls-auth ta.key 0\ntls-crypt tc.key\n")
	expect_error(t, cfg.diags, 0, "cannot be used together")
	destroy(&cfg)

	cfg = load_server("tls-crypt-v2-max-age 30\n")
	expect_warning(t, cfg.diags, S_FIRST_EXTRA_LINE, "no effect without tls-crypt-v2")
	destroy(&cfg)
}

@(test)
test_server_peer_keys :: proc(t: ^testing.T) {
	no_ca, _ := strings.replace(SERVER_BASE, "<ca>\nCA\n</ca>\n", "", 1, context.temp_allocator)

	// Pins only.
	cfg := load(
		strings.concatenate({no_ca, "peer-keys /etc/noirvpn/peers\n"}, context.temp_allocator),
	)
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.peer_keys, "/etc/noirvpn/peers")
		testing.expect_value(t, cfg.server.peer_keys_mode, Peer_Keys_Mode.Pin)
	}
	destroy(&cfg)

	// A ca with peer-keys and no mode means `either`.
	cfg = load_server("peer-keys /etc/noirvpn/peers\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.peer_keys_mode, Peer_Keys_Mode.Either)
	}
	destroy(&cfg)

	// `pin` is explicit and does not go with a ca.
	cfg = load_server("peer-keys /etc/noirvpn/peers\npeer-keys-mode pin\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE + 1, "`peer-keys-mode pin` cannot be used with `ca`")
	destroy(&cfg)

	cfg = load_server("peer-keys /etc/noirvpn/peers\npeer-keys-mode both\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.peer_keys_mode, Peer_Keys_Mode.Both)
	}
	destroy(&cfg)

	cfg = load(
		strings.concatenate(
			{no_ca, "peer-keys /p\npeer-keys-mode both\n"},
			context.temp_allocator,
		),
	)
	expect_error(t, cfg.diags, 0, "needs `ca` and `peer-keys`")
	destroy(&cfg)

	cfg = load_server("peer-keys-mode both\n")
	expect_error(t, cfg.diags, 0, "needs `ca` and `peer-keys`")
	destroy(&cfg)

	// A pin, else a chain: the same needs as `both`.
	cfg = load_server("peer-keys /etc/noirvpn/peers\npeer-keys-mode either\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.peer_keys_mode, Peer_Keys_Mode.Either)
	}
	destroy(&cfg)

	cfg = load(strings.concatenate({no_ca, "peer-keys /p\npeer-keys-mode either\n"}, context.temp_allocator))
	expect_error(t, cfg.diags, 0, "`peer-keys-mode either` needs `ca` and `peer-keys`")
	destroy(&cfg)

	cfg = load(strings.concatenate({no_ca, "peer-keys-mode pin\n"}, context.temp_allocator))
	expect_error(t, cfg.diags, 0, "needs `peer-keys`")
	destroy(&cfg)

	cfg = load_server("peer-keys-mode never\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "must be pin, both or either")
	destroy(&cfg)

	fp := "DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74"
	cfg = load(
		strings.concatenate(
			{no_ca, "peer-keys /p\npeer-fingerprint ", fp, "\n"},
			context.temp_allocator,
		),
	)
	expect_error(t, cfg.diags, 0, "cannot be combined")
	destroy(&cfg)

	// No way to verify clients at all.
	cfg = load(no_ca)
	expect_error(t, cfg.diags, 0, "no way to verify clients")
	destroy(&cfg)

	// A fingerprint is enough.
	cfg = load(strings.concatenate({no_ca, "peer-fingerprint ", fp, "\n"}, context.temp_allocator))
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	// peer-keys is a server option.
	cl := load_client("peer-keys /p\n")
	expect_error(t, cl.diags, CLIENT_FIRST, "servers only")
	destroy(&cl)
}

CLIENT_FIRST :: FIRST_EXTRA_LINE

@(test)
test_server_verify_client_cert_and_external_auth :: proc(t: ^testing.T) {
	// `none` is not supported, with or without a password source.
	cfg := load_server("verify-client-cert none\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "`verify-client-cert none` is not supported")
	destroy(&cfg)

	cfg = load_server("verify-client-cert none\nauth-external\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "`verify-client-cert none` is not supported")
	destroy(&cfg)

	cfg = load_server("verify-client-cert none\npeer-passwords /p\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "`verify-client-cert none` is not supported")
	destroy(&cfg)

	// `optional` needs a password source.
	cfg = load_server("verify-client-cert optional\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "needs a password source, either `peer-passwords` or `auth-external`")
	destroy(&cfg)

	cfg = load_server("verify-client-cert optional\nauth-external 10\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.verify_client_cert, Verify_Client_Cert.Optional)
		ae, _ := cfg.server.auth_external.?
		testing.expect_value(t, ae.timeout, 10)
	}
	destroy(&cfg)

	cfg = load_server("verify-client-cert optional\npeer-passwords /etc/noirvpn/users\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.verify_client_cert, Verify_Client_Cert.Optional)
		testing.expect_value(t, cfg.server.peer_passwords, "/etc/noirvpn/users")
		_, ext := cfg.server.auth_external.?
		testing.expect(t, !ext)
	}
	destroy(&cfg)

	cfg = load_server("verify-client-cert optional\npeer-passwords /p\nauth-external\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	// `optional` with a password source and no way to check a certificate is a
	// server for password logins only.
	no_ca, _ := strings.replace(SERVER_BASE, "<ca>\nCA\n</ca>\n", "", 1, context.temp_allocator)
	cfg = load(strings.concatenate({no_ca, "verify-client-cert optional\npeer-passwords /p\n"}, context.temp_allocator))
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	cfg = load(strings.concatenate({no_ca, "verify-client-cert optional\nauth-external\n"}, context.temp_allocator))
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	// Still errors: `optional` with no password source, `require` with no verifier, `none`.
	cfg = load(strings.concatenate({no_ca, "verify-client-cert optional\n"}, context.temp_allocator))
	expect_error(t, cfg.diags, 0, "needs a password source")
	destroy(&cfg)

	cfg = load(strings.concatenate({no_ca, "verify-client-cert require\npeer-passwords /p\n"}, context.temp_allocator))
	expect_error(t, cfg.diags, 0, "no way to verify clients")
	destroy(&cfg)

	cfg = load(strings.concatenate({no_ca, "verify-client-cert none\npeer-passwords /p\n"}, context.temp_allocator))
	expect_error(t, cfg.diags, 0, "`verify-client-cert none` is not supported")
	destroy(&cfg)

	cfg = load(strings.concatenate({no_ca, "verify-client-cert optional\npeer-passwords /p\npeer-keys /k\n"}, context.temp_allocator))
	expect_clean(t, cfg.diags)
	destroy(&cfg)

	// A pin and a chain with `optional`: the mode is `either` unless set.
	cfg = load_server("verify-client-cert optional\npeer-passwords /p\npeer-keys /k\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.peer_keys_mode, Peer_Keys_Mode.Either)
	}
	destroy(&cfg)

	cfg = load_server("verify-client-cert optional\npeer-passwords /p\npeer-keys /k\npeer-keys-mode both\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.peer_keys_mode, Peer_Keys_Mode.Both)
	}
	destroy(&cfg)

	cfg = load_server("auth-external 0\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "timeout seconds")
	destroy(&cfg)

	cfg = load_server("verify-client-cert sometimes\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "must be require, optional or none")
	destroy(&cfg)
}

@(test)
test_server_peer_passwords :: proc(t: ^testing.T) {
	// The default: no file.
	cfg := load_server("")
	testing.expect_value(t, cfg.server.peer_passwords, "")
	destroy(&cfg)

	// Legal with `require` (the default): the password of a client is checked as well.
	cfg = load_server("peer-passwords /etc/noirvpn/users\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.verify_client_cert, Verify_Client_Cert.Require)
		testing.expect_value(t, cfg.server.peer_passwords, "/etc/noirvpn/users")
	}
	destroy(&cfg)

	cfg = load_server("peer-passwords\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "")
	destroy(&cfg)

	// A server option.
	cl := load_client("peer-passwords /p\n")
	expect_error(t, cl.diags, CLIENT_FIRST, "servers only")
	destroy(&cl)
}

@(test)
test_server_cert_requirements :: proc(t: ^testing.T) {
	no_key, _ := strings.replace(
		SERVER_BASE,
		"<key>\nKEY\n</key>\n",
		"",
		1,
		context.temp_allocator,
	)
	cfg := load(no_key)
	expect_error(t, cfg.diags, 0, "needs `cert` and `key`")
	destroy(&cfg)
	cfg = load("server 10.8.0.0 255.255.255.0\nca ca.crt\n")
	expect_error(t, cfg.diags, 0, "needs `cert` and `key`")
	destroy(&cfg)
}

@(test)
test_server_device :: proc(t: ^testing.T) {
	cfg := load_server("dev tap\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "TAP")
	destroy(&cfg)
	cfg = load_server("topology net30\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "topology subnet")
	destroy(&cfg)
	cfg = load_server("topology subnet\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
}

@(test)
test_server_routes :: proc(t: ^testing.T) {
	cfg := load_server("route 192.168.20.0 255.255.255.0\nroute-ipv6 fd00:20::/64\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.server.routes), 1)
		testing.expect_value(t, len(cfg.server.routes6), 1)
	}
	destroy(&cfg)
}

@(test)
test_server_rejected :: proc(t: ^testing.T) {
	for text in ([]string{"client-connect x\n", "client-disconnect x\n", "learn-address x\n", "auth-user-pass-verify x via-env\n", "tls-verify x\n", "management 127.0.0.1 1\n", "status log\n", "script-security 2\nup x\n", "auth-gen-token\n", "username-as-common-name\n", "client-cert-not-required\n", "ifconfig-pool-linear\n"}) {
		cfg := load_server(text)
		testing.expectf(t, diags_have_error(cfg.diags), "'%s' should be rejected", text)
		destroy(&cfg)
	}
}

@(test)
test_server_new_options :: proc(t: ^testing.T) {
	cfg := load_server(
		"pq-mode require\nworkers 8\ndatapath userspace\nbus-events /run/noirvpn/events\nbus-allow uid 0 admin\n",
	)
	if expect_clean(t, cfg.diags) {
		s := cfg.server
		testing.expect_value(t, s.tls.pq_mode, Pq_Mode.Require)
		testing.expect_value(t, s.workers, 8)
		testing.expect_value(t, s.bus_events.state, Bus_State.Custom)
		testing.expect_value(t, len(s.bus_allow), 1)
		testing.expect_value(t, s.datapath, Datapath.Userspace)
		testing.expect_value(t, s.dco_socket, "/run/udco/udco.sock")
	}
	destroy(&cfg)

	cfg = load_server("datapath udco\ndco-socket /cell/dco.sock\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.datapath, Datapath.Udco)
		testing.expect_value(t, cfg.server.dco_socket, "/cell/dco.sock")
	}
	destroy(&cfg)
	// One socket only, UDP or TCP.
	cfg = load_server("datapath udco\nproto tcp-server\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_server("datapath udco\nlocal 192.0.2.1 1194 udp\nlocal 192.0.2.1 1195 tcp-server\n")
	expect_error(t, cfg.diags, 0, "one listening socket")
	destroy(&cfg)
	cfg = load_server("datapath auto\nproto tcp-server\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
}

@(test)
test_server_datapath_dco :: proc(t: ^testing.T) {
	cfg := load_server("datapath dco\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.datapath, Datapath.Dco)
	}
	destroy(&cfg)
	cfg = load_server("datapath dco\nproto tcp-server\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	// The kernel driver serves one listening socket, as the service does.
	cfg = load_server("datapath dco\nlocal 192.0.2.1 1194 udp\nlocal 192.0.2.1 1195 tcp-server\n")
	expect_error(t, cfg.diags, 0, "`datapath dco` supports only one listening socket")
	destroy(&cfg)
	// A mixed server.
	cfg = load_server("datapath dco\nlocal 192.0.2.1 1194 udp\nlocal 192.0.2.1 443 tls-server\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_server("datapath dco\nlocal 192.0.2.1 1194 udp\nlocal 192.0.2.1 443 tls-server\ntls-transport-accept-tcp\n")
	expect_error(t, cfg.diags, 0, "`datapath dco` handles either udp or tcp, not both")
	destroy(&cfg)
	cfg = load_server("datapath dco\nproto tcp-server\ntls-transport-ws /vpn\n")
	expect_error(t, cfg.diags, 0, "datapath dco can only serve WebSocket clients on a tls listener")
	destroy(&cfg)
	cfg = load_server("datapath dco\ndisable-dco\n")
	expect_error(t, cfg.diags, 0, "`disable-dco` conflicts with `datapath dco`")
	destroy(&cfg)
	cfg = load_server("disable-dco\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.datapath, Datapath.Userspace)
	}
	destroy(&cfg)
	cfg = load_server("datapath kernel\n")
	expect_error(t, cfg.diags, 0, "must be userspace, dco, udco or auto")
	destroy(&cfg)
	for d in ([]Datapath{.Userspace, .Auto, .Udco, .Dco}) {
		testing.expect_value(t, datapath_is_dco(d), d == .Udco || d == .Dco)
	}
	testing.expect_value(t, datapath_name(.Dco), "dco")
	testing.expect_value(t, datapath_name(.Udco), "udco")
	testing.expect_value(t, datapath_name(.Userspace), "userspace")
	testing.expect_value(t, datapath_name(.Auto), "auto")
}

@(test)
test_server_tls_listen :: proc(t: ^testing.T) {
	cfg := load_server("proto tls-server\nport 443\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.server.listens), 1)
		l := cfg.server.listens[0]
		testing.expect(t, l.proto == .Tcp && l.tls)
		testing.expect_value(t, l.port, u16(443))
	}
	destroy(&cfg)
	for text, want in ([]string{"tls", "tls-server", "tls4-server", "tls6-server"}) {
		_ = want
		cfg = load_server(strings.concatenate({"proto ", text, "\n"}, context.temp_allocator))
		if expect_clean(t, cfg.diags) {
			testing.expect(t, cfg.server.listens[0].tls, text)
		}
		destroy(&cfg)
	}
	cfg = load_server("proto tls4-server\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.listens[0].family, Family.V4)
	}
	destroy(&cfg)

	// A mix of listeners, each with its own transport.
	cfg = load_server("local * 1194 udp\nlocal * 443 tls-server\nlocal * 8443 tcp-server\n")
	if expect_clean(t, cfg.diags) {
		ls := cfg.server.listens
		if testing.expect_value(t, len(ls), 3) {
			testing.expect(t, ls[0].proto == .Udp && !ls[0].tls)
			testing.expect(t, ls[1].proto == .Tcp && ls[1].tls)
			testing.expect(t, ls[2].proto == .Tcp && !ls[2].tls)
		}
	}
	destroy(&cfg)
	// `local` without a proto takes the final one, tls included.
	cfg = load_server("local 192.0.2.1\nproto tls-server\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, cfg.server.listens[0].tls)
	}
	destroy(&cfg)
	// Plain tcp is not tls.
	cfg = load_server("proto tcp-server\n")
	testing.expect(t, !cfg.server.listens[0].tls)
	destroy(&cfg)

	for bad in ([]string{"proto tls-client\n", "proto tls4-client\n", "local * 443 tls-client\n", "proto tls-serverx\n"}) {
		c := load_server(bad)
		testing.expectf(t, diags_have_error(c.diags), "'%s' should be an error", bad)
		destroy(&c)
	}
	cfg = load_server("proto tls-client\n")
	expect_error(t, cfg.diags, 0, "a server cannot use 'tls-client'")
	destroy(&cfg)
}

@(test)
test_server_tls_transport_identity :: proc(t: ^testing.T) {
	cfg := load_server("proto tls-server\ntls-transport-cert outer.crt\ntls-transport-key outer.key\n")
	if expect_clean(t, cfg.diags) {
		tc := &cfg.server.tls
		testing.expect_value(t, tc.transport_cert.path, "outer.crt")
		testing.expect_value(t, tc.transport_key.path, "outer.key")
	}
	destroy(&cfg)
	// Inline blocks, as cert and key.
	cfg = load_server("proto tls-server\n<tls-transport-cert>\nOUTER CERT\n</tls-transport-cert>\n<tls-transport-key>\nOUTER KEY\n</tls-transport-key>\n")
	if expect_clean(t, cfg.diags) {
		tc := &cfg.server.tls
		testing.expect(t, tc.transport_cert.is_inline)
		testing.expect_value(t, tc.transport_cert.data, "OUTER CERT\n")
		testing.expect(t, tc.transport_key.is_inline)
		testing.expect_value(t, tc.transport_key.data, "OUTER KEY\n")
		// The inner identity is untouched.
		testing.expect_value(t, tc.cert.data, "CERT\n")
	}
	destroy(&cfg)
	// Not set: empty.
	cfg = load_server("proto tls-server\n")
	testing.expect(t, !key_source_is_set(cfg.server.tls.transport_cert))
	testing.expect(t, !key_source_is_set(cfg.server.tls.transport_key))
	destroy(&cfg)
	// One without the other.
	cfg = load_server("proto tls-server\ntls-transport-cert outer.crt\n")
	expect_error(t, cfg.diags, 0, "must be given together")
	destroy(&cfg)
	cfg = load_server("proto tls-server\ntls-transport-key outer.key\n")
	expect_error(t, cfg.diags, 0, "must be given together")
	destroy(&cfg)
	cfg = load_server("proto tls-server\n<tls-transport-cert>\n</tls-transport-cert>\n")
	expect_error(t, cfg.diags, 0, "the inline block is empty")
	destroy(&cfg)
	// No tls listener: a warning only.
	cfg = load_server("tls-transport-cert outer.crt\ntls-transport-key outer.key\n")
	expect_warning(t, cfg.diags, 0, "no effect")
	testing.expect(t, !diags_have_error(cfg.diags))
	destroy(&cfg)
	// SNI is a client option.
	cfg = load_server("proto tls-server\ntls-transport-sni vpn.example\n")
	expect_error(t, cfg.diags, 0, "applies to clients only")
	destroy(&cfg)
}

@(test)
test_server_tls_transport_accept_tcp :: proc(t: ^testing.T) {
	cfg := load_server("proto tls-server\ntls-transport-accept-tcp\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, cfg.server.tls.transport_accept_tcp)
	}
	destroy(&cfg)
	cfg = load_server("proto tls-server\n")
	testing.expect(t, !cfg.server.tls.transport_accept_tcp)
	destroy(&cfg)
	// No tls listener: a warning only.
	cfg = load_server("tls-transport-accept-tcp\n")
	expect_warning(t, cfg.diags, 0, "no effect")
	testing.expect(t, !diags_have_error(cfg.diags))
	destroy(&cfg)
	// No argument.
	cfg = load_server("proto tls-server\ntls-transport-accept-tcp yes\n")
	expect_error(t, cfg.diags, 0, "needs 0 arguments")
	destroy(&cfg)
	// A client config does not take it.
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-accept-tcp\n")
	expect_error(t, cfg.diags, 0, "applies to servers only")
	destroy(&cfg)
}

@(test)
test_server_tls_and_datapath :: proc(t: ^testing.T) {
	// A mixed server: the service for udp and tcp, the daemon for tls.
	cfg := load_server("datapath udco\nproto tls-server\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_server("datapath udco\nproto tls-server\ntls-transport-accept-tcp\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_server("datapath udco\nlocal 192.0.2.1 1194 udp\nlocal 192.0.2.1 443 tls-server\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	cfg = load_server("datapath udco\nlocal 192.0.2.1 1194 tcp-server\nlocal 192.0.2.1 443 tls-server\ntls-transport-accept-tcp\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	// The service serves one of udp and tcp.
	cfg = load_server("datapath udco\nlocal 192.0.2.1 1194 udp\nlocal 192.0.2.1 443 tls-server\ntls-transport-accept-tcp\n")
	expect_error(t, cfg.diags, 0, "udp or tcp, not both")
	destroy(&cfg)
	cfg = load_server("datapath udco\nlocal 192.0.2.1 1194 udp\nlocal 192.0.2.1 1195 udp\nlocal 192.0.2.1 443 tls-server\n")
	expect_error(t, cfg.diags, 0, "supports only one listening socket")
	destroy(&cfg)
	cfg = load_server("datapath udco\nlocal 192.0.2.1 1194 udp\n")
	expect_clean(t, cfg.diags)
	destroy(&cfg)
	for dp in ([]string{"auto", "userspace"}) {
		cfg = load_server(strings.concatenate({"datapath ", dp, "\nproto tls-server\n"}, context.temp_allocator))
		expect_clean(t, cfg.diags)
		destroy(&cfg)
	}
}

@(test)
test_tls_tun_name :: proc(t: ^testing.T) {
	testing.expect_value(t, tls_tun_name("tun0", "", context.temp_allocator), "tun0-tls")
	testing.expect_value(t, tls_tun_name("tun", "", context.temp_allocator), "tun-tls")
	testing.expect_value(t, tls_tun_name("tun7", "vpn-tls", context.temp_allocator), "vpn-tls")
	testing.expect(t, tun_name_ok("tun0-tls"))
	testing.expect(t, !tun_name_ok(""))
	testing.expect(t, !tun_name_ok("a/b"))
	testing.expect(t, !tun_name_ok("a b"))
}

@(test)
test_server_tls_transport_dev :: proc(t: ^testing.T) {
	// The default name fits.
	cfg := load_server("datapath udco\nproto tls-server\ndev tun0\ntls-transport-dev tlstun\n")
	expect_clean(t, cfg.diags)
	testing.expect_value(t, cfg.server.tls.transport_dev, "tlstun")
	destroy(&cfg)
	// A name longer than 15 bytes, given or derived.
	cfg = load_server("datapath udco\nproto tls-server\ntls-transport-dev abcdefghijklmnop\n")
	expect_error(t, cfg.diags, 0, "longer than 15 bytes")
	destroy(&cfg)
	cfg = load_server("datapath udco\nproto tls-server\ndev tunabcdefghi\n")
	expect_error(t, cfg.diags, 0, "longer than 15 bytes")
	destroy(&cfg)
	cfg = load_server("datapath udco\nproto tls-server\ndev tun0\ntls-transport-dev tun0\n")
	expect_error(t, cfg.diags, 0, "need different names")
	destroy(&cfg)
	// No effect without the mixed server.
	cfg = load_server("datapath userspace\nproto tls-server\ntls-transport-dev tlstun\n")
	expect_warning(t, cfg.diags, 0, "no effect")
	testing.expect(t, !diags_have_error(cfg.diags))
	destroy(&cfg)
	cfg = load_server("datapath udco\nlocal 192.0.2.1 1194 udp\ntls-transport-dev tlstun\n")
	expect_warning(t, cfg.diags, 0, "no effect")
	destroy(&cfg)
	// A client config does not take it.
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-dev x\n")
	expect_error(t, cfg.diags, 0, "applies to servers only")
	destroy(&cfg)
}

@(test)
test_server_tls_transport_ws :: proc(t: ^testing.T) {
	cfg := load_server("proto tls-server\ntls-transport-ws /vpn\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.tls.transport_ws, "/vpn")
	}
	destroy(&cfg)
	cfg = load_server("proto tcp-server\ntls-transport-ws /a/b?c=d\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.server.tls.transport_ws, "/a/b?c=d")
	}
	destroy(&cfg)
	cfg = load_server("proto tls-server\n")
	testing.expect_value(t, cfg.server.tls.transport_ws, "")
	destroy(&cfg)
	// A bad path.
	cfg = load_server("proto tls-server\ntls-transport-ws vpn\n")
	expect_error(t, cfg.diags, 0, "is not a valid path")
	destroy(&cfg)
	cfg = load_server("proto tls-server\ntls-transport-ws \"/a b\"\n")
	expect_error(t, cfg.diags, 0, "is not a valid path")
	destroy(&cfg)
	long := strings.concatenate({"proto tls-server\ntls-transport-ws /", strings.repeat("a", 255, context.temp_allocator), "\n"}, context.temp_allocator)
	cfg = load_server(long)
	expect_error(t, cfg.diags, 0, "is not a valid path")
	destroy(&cfg)
	// A udp listener: no effect.
	cfg = load_server("tls-transport-ws /vpn\n")
	expect_warning(t, cfg.diags, 0, "no effect")
	testing.expect(t, !diags_have_error(cfg.diags))
	destroy(&cfg)
	// The DCO service does not speak WebSocket: a tcp listener under `datapath udco` is an error, a tls one is fine.
	cfg = load_server("datapath udco\nproto tcp-server\ntls-transport-ws /vpn\n")
	expect_error(t, cfg.diags, 0, "datapath udco can only serve WebSocket clients on a tls listener")
	destroy(&cfg)
	cfg = load_server("datapath udco\nproto tls-server\ntls-transport-ws /vpn\n")
	testing.expect(t, !diags_have_error(cfg.diags))
	destroy(&cfg)
}

@(test)
test_server_block_ipv6 :: proc(t: ^testing.T) {
	cfg := load_server("")
	testing.expect(t, !cfg.server.block_ipv6)
	destroy(&cfg)
	cfg = load_server("block-ipv6\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect(t, cfg.server.block_ipv6)
	// A server may push it, and the push is no warning.
	pushed := load_server("push \"block-ipv6\"\n")
	defer destroy(&pushed)
	expect_clean(t, pushed.diags)
	for d in pushed.diags {
		testing.expectf(t, d.severity != .Warning, "push of block-ipv6 warned: %s", d.message)
	}
	testing.expect(t, !pushed.server.block_ipv6)
	found := false
	for line in pushed.server.push {
		found ||= line == "block-ipv6"
	}
	testing.expect(t, found)
}

@(test)
test_server_auth_web :: proc(t: ^testing.T) {
	cfg := load_server("verify-client-cert optional\nauth-external 120\nauth-web\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, cfg.server.auth_web)
	}
	destroy(&cfg)

	// With the hash file too: still fine.
	cfg = load_server("verify-client-cert optional\nauth-external\npeer-passwords /p\nauth-web\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, cfg.server.auth_web)
	}
	destroy(&cfg)

	cfg = load_server("verify-client-cert optional\nauth-external\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, !cfg.server.auth_web)
	}
	destroy(&cfg)

	// A controller is needed.
	cfg = load_server("verify-client-cert optional\npeer-passwords /p\nauth-web\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE + 2, "`auth-web` needs `auth-external`")
	destroy(&cfg)

	// A client that sends no certificate must be allowed.
	cfg = load_server("auth-external\nauth-web\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE + 1, "`auth-web` needs `verify-client-cert optional`")
	destroy(&cfg)

	cfg = load_server("verify-client-cert require\nauth-external\nauth-web\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE + 2, "`auth-web` needs `verify-client-cert optional`")
	destroy(&cfg)

	// No argument.
	cfg = load_server("verify-client-cert optional\nauth-external\nauth-web yes\n")
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE + 2, "auth-web")
	destroy(&cfg)
}
