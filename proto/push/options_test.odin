// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

@(test)
options_build_matches_stock_strings :: proc(t: ^testing.T) {
	// The captured strings of a stock peer.
	buf: [OPTIONS_MAX_LEN]u8
	Case :: struct {
		p:    Options_Params,
		want: string,
	}
	cases := []Case {
		{{role = .Client, transport = .Udp, cipher = .Aes_256_Gcm}, "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client"},
		{{role = .Server, transport = .Udp, cipher = .Aes_256_Gcm}, "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"},
		{{role = .Client, transport = .Udp, cipher = .Aes_128_Gcm}, "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth [null-digest],keysize 128,key-method 2,tls-client"},
		{{role = .Client, transport = .Udp, cipher = .Chacha20_Poly1305}, "V4,dev-type tun,link-mtu 1534,tun-mtu 1500,proto UDPv4,cipher CHACHA20-POLY1305,auth [null-digest],keysize 256,key-method 2,tls-client"},
		{{role = .Client, transport = .Tcp, cipher = .Aes_256_Gcm}, "V4,dev-type tun,link-mtu 1551,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client"},
		{{role = .Server, transport = .Tcp, cipher = .Aes_256_Gcm}, "V4,dev-type tun,link-mtu 1551,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"},
		{{role = .Client, transport = .Udp, cipher = .None}, "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-client"},
		{{role = .Client, transport = .Udp, cipher = .Aes_256_Gcm, tun_mtu = 1400}, "V4,dev-type tun,link-mtu 1449,tun-mtu 1400,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client"},
		{{role = .Client, transport = .Udp, cipher = .Aes_256_Gcm, link_mtu = 1600}, "V4,dev-type tun,link-mtu 1600,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client"},
	}
	for c in cases {
		p := c.p
		s, err := options_build(buf[:], &p)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, s, c.want)
	}
	small: [20]u8
	p := Options_Params {
		role   = .Client,
		cipher = .Aes_256_Gcm,
	}
	_, err := options_build(small[:], &p)
	testing.expect_value(t, err, Error.Buffer_Too_Small)
}

@(test)
options_link_mtu_values :: proc(t: ^testing.T) {
	testing.expect_value(t, options_link_mtu(1500, .Aes_128_Gcm, .Udp), 1549)
	testing.expect_value(t, options_link_mtu(1500, .Aes_256_Gcm, .Udp), 1549)
	testing.expect_value(t, options_link_mtu(1500, .Chacha20_Poly1305, .Udp), 1534)
	testing.expect_value(t, options_link_mtu(1500, .Aes_256_Gcm, .Tcp), 1551)
	testing.expect_value(t, options_link_mtu(1500, .None, .Udp), 1541)
}

@(test)
options_parse_stock_string :: proc(t: ^testing.T) {
	info: Options_Info
	err := options_parse(stock_options_client, &info)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, info.version, "V4")
	testing.expect_value(t, info.dev_type, "tun")
	testing.expect_value(t, info.link_mtu, 1549)
	testing.expect_value(t, info.tun_mtu, 1500)
	testing.expect_value(t, info.proto, "UDPv4")
	testing.expect_value(t, info.cipher, "AES-256-GCM")
	testing.expect_value(t, info.auth, "[null-digest]")
	testing.expect_value(t, info.keysize, 256)
	testing.expect_value(t, info.key_method, 2)
	testing.expect_value(t, info.role, Role.Client)
	testing.expect(t, !info.tls_auth)
	testing.expect(t, !info.comp_lzo)
	testing.expect_value(t, info.item_count, 10)
	testing.expect_value(t, info.unknown_count, 0)
	_, has_keydir := info.keydir.?
	testing.expect(t, !has_keydir)

	// tls-auth with a key direction.
	err = options_parse("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,keydir 1,cipher AES-128-GCM,auth [null-digest],keysize 128,tls-auth,key-method 2,tls-client", &info)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, info.keydir, 1)
	testing.expect(t, info.tls_auth)

	// No cipher item: the cipher stays empty.
	err = options_parse("V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server", &info)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, info.cipher, "")
	testing.expect_value(t, info.auth, "SHA1")
	testing.expect_value(t, info.role, Role.Server)

	// [null-cipher] means none.
	err = options_parse("V4,cipher [null-cipher],auth [null-digest]", &info)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, info.cipher, "none")
}

@(test)
options_parse_edge_cases :: proc(t: ^testing.T) {
	info: Options_Info
	// Empty string is accepted.
	testing.expect_value(t, options_parse("", &info), Error.None)
	testing.expect_value(t, info.item_count, 0)
	// Comp-lzo is noticed, unknown items counted, empty items skipped.
	err := options_parse("V4,,comp-lzo,mtu-dynamic,weird-item 5,tun-mtu notanumber,link-mtu 1500abc", &info)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, info.comp_lzo)
	testing.expect_value(t, info.unknown_count, 1)
	_, has := info.tun_mtu.?
	testing.expect(t, !has)
	testing.expect_value(t, info.link_mtu, 1500)
	// 511 characters is the longest allowed string (512 with the NUL).
	long := make([]u8, 511, context.temp_allocator)
	for &c in long {
		c = 'a'
	}
	testing.expect_value(t, options_parse(string(long), &info), Error.None)
	long2 := make([]u8, 512, context.temp_allocator)
	testing.expect_value(t, options_parse(string(long2), &info), Error.Oversize)
}

@(test)
options_compare_logs_differences :: proc(t: ^testing.T) {
	a, b: Options_Info
	_ = options_parse(stock_options_client, &a)
	_ = options_parse(stock_options_server, &b)
	// The role, and the items a stock peer does not compare, do not count.
	testing.expect_value(t, options_compare(&a, &b), Options_Diffs{})

	_ = options_parse("V4,dev-type tun,link-mtu 1541,tun-mtu 1400,proto TCPv4_SERVER,cipher CHACHA20-POLY1305,auth SHA1,keysize 128,comp-lzo,keydir 0,tls-auth,key-method 2,tls-server", &b)
	d := options_compare(&a, &b)
	testing.expect_value(t, d, Options_Diffs{.Link_Mtu, .Tun_Mtu, .Auth, .Keysize, .Comp_Lzo})
	testing.expect_value(t, options_diff_name(.Link_Mtu), "link-mtu")
	// A missing item against a present one counts.
	_ = options_parse("V4,dev-type tun", &b)
	d = options_compare(&a, &b)
	testing.expect(t, .Link_Mtu in d && .Tun_Mtu in d && .Auth in d)
	testing.expect(t, .Version not_in d && .Dev_Type not_in d)
}
