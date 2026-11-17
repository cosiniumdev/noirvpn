// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:testing"

load_ccd :: proc(text: string) -> Config {
	return build_client_specific(parse_text(text, "ccd/alice"))
}

@(test)
test_ccd_basic :: proc(t: ^testing.T) {
	cfg := load_ccd(
		`# client-specific settings for alice
ifconfig-push 10.8.0.50 255.255.255.0
ifconfig-ipv6-push fd00:8::50/64 fd00:8::1
iroute 192.168.20.0 255.255.255.0
iroute 192.168.30.7
iroute-ipv6 fd00:30::/64
push "route 192.168.99.0 255.255.255.0"
push-remove "dhcp-option"
session-timeout 3600
max-routes-per-client 20
`,
	)
	defer destroy(&cfg)
	if !expect_clean(t, cfg.diags) {
		return
	}
	s := cfg.specific
	ip, ok := s.ifconfig_push.?
	testing.expect(t, ok)
	testing.expect_value(t, ip.local, "10.8.0.50")
	testing.expect_value(t, ip.remote_netmask, "255.255.255.0")
	testing.expect_value(t, ip.local_ip, [4]u8{10, 8, 0, 50})
	testing.expect(t, ip.local_is_ip)
	ip6, ok6 := s.ifconfig_ipv6_push.?
	testing.expect(t, ok6)
	testing.expect_value(t, ip6.bits, u8(64))
	testing.expect_value(t, ip6.remote, "fd00:8::1")
	testing.expect_value(t, len(s.iroutes), 2)
	if len(s.iroutes) == 2 {
		testing.expect_value(t, s.iroutes[0], Iroute{{192, 168, 20, 0}, 24})
		// No mask means one host.
		testing.expect_value(t, s.iroutes[1], Iroute{{192, 168, 30, 7}, 32})
	}
	testing.expect_value(t, len(s.iroutes6), 1)
	testing.expect_value(t, len(s.push), 1)
	testing.expect_value(t, len(s.push_remove), 1)
	testing.expect_value(t, s.session_timeout, 3600)
	testing.expect_value(t, s.max_routes, 20)
	testing.expect(t, !s.disable)
	testing.expect(t, !s.push_reset)
}

@(test)
test_ccd_disable_and_reset :: proc(t: ^testing.T) {
	cfg := load_ccd("disable\npush-reset\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect(t, cfg.specific.disable)
	testing.expect(t, cfg.specific.push_reset)
}

@(test)
test_ccd_empty :: proc(t: ^testing.T) {
	cfg := load_ccd("")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect(t, cfg.specific.ifconfig_push == nil)
	testing.expect_value(t, len(cfg.specific.iroutes), 0)
}

@(test)
test_ccd_errors :: proc(t: ^testing.T) {
	cfg := load_ccd(
		"iroute 10.0.0.1 255.255.255.0\nifconfig-push 10.8.0.5\nifconfig-push bad!host 255.255.255.0\niroute 10.0.0.0 255.0.255.0\niroute-ipv6 nonsense\npush \"topology net30\"\nifconfig-ipv6-push fd00::1\nsession-timeout x\n",
	)
	defer destroy(&cfg)
	expect_error(t, cfg.diags, 1, "host bits set")
	expect_error(t, cfg.diags, 2, "needs 2 to 3 arguments, but the line has 1")
	expect_error(t, cfg.diags, 3, "not an IPv4 address or host name")
	expect_error(t, cfg.diags, 4, "not valid")
	expect_error(t, cfg.diags, 5, "addr/bits")
	expect_error(t, cfg.diags, 6, "topology net30")
	expect_error(t, cfg.diags, 7, "addr/bits")
	expect_error(t, cfg.diags, 8, "seconds")
}

@(test)
test_ccd_only_ccd_options :: proc(t: ^testing.T) {
	// Global options do not belong in a per-client file.
	cfg := load_ccd("verb 3\nproto udp\nserver 10.9.0.0 255.255.255.0\nclient-to-client\n")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, 1, "cannot be used in a client config file")
	expect_error(t, cfg.diags, 2, "cannot be used in a client config file")
	expect_error(t, cfg.diags, 3, "cannot be used in a client config file")
	expect_error(t, cfg.diags, 4, "cannot be used in a client config file")

	// Unknown options and rejected options keep their usual errors.
	cfg2 := load_ccd("frobnicate\ncompress lz4\n")
	defer destroy(&cfg2)
	expect_error(t, cfg2.diags, 1, "unknown option")
	expect_error(t, cfg2.diags, 2, "not supported")

	// Ignored options still only warn.
	cfg3 := load_ccd("persist-key\n")
	defer destroy(&cfg3)
	expect_clean(t, cfg3.diags)
	expect_warning(t, cfg3.diags, 1, "ignored")
}

@(test)
test_ccd_options_not_valid_in_main_config :: proc(t: ^testing.T) {
	cfg := load_server("ifconfig-push 10.8.0.5 255.255.255.0\n")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, S_FIRST_EXTRA_LINE, "client-config-dir")
	cfg2 := load_server("disable\n")
	defer destroy(&cfg2)
	expect_error(t, cfg2.diags, S_FIRST_EXTRA_LINE, "client config file")
}
