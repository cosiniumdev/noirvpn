// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

@(test)
iv_proto_values :: proc(t: ^testing.T) {
	// IV_PROTO values.
	testing.expect_value(t, iv_proto_value(IV_PROTO_USERSPACE), 8094)
	testing.expect_value(t, iv_proto_value(IV_PROTO_DCO), 2974)
	// 2.6.23 sends 990 = 2+4+8+16+64+128+256+512.
	v26 := Iv_Proto{.Data_V2, .Request_Push, .Tls_Key_Export, .Auth_Pending_Kw, .Dns_Option, .Cc_Exit_Notify, .Auth_Fail_Temp, .Dyn_Tls_Crypt}
	testing.expect_value(t, iv_proto_value(v26), 990)
	testing.expect_value(t, iv_proto_from_value(990), v26)
	testing.expect_value(t, iv_proto_from_value(8094), IV_PROTO_USERSPACE)
	// Bit values: bit n is 2^n.
	for b in Iv_Proto_Bit {
		testing.expect_value(t, iv_proto_value({b}), u32(1) << u32(b))
		testing.expect(t, len(iv_proto_bit_name(b)) > 3)
	}
	// Bit 0 and unknown high bits are dropped when decoding.
	testing.expect_value(t, iv_proto_from_value(1), Iv_Proto{})
	testing.expect_value(t, iv_proto_from_value(1 << 20 | 2), Iv_Proto{.Data_V2})
}

@(test)
peer_info_build_matches_stock :: proc(t: ^testing.T) {
	// The block a stock 2.7.7 pull client sends, built
	// from parameters. The three compression "stub" lines are passed as extra
	// lines (noirvpn does not send them).
	buf: [512]u8
	ciphers := []Cipher{.Aes_256_Gcm}
	p := Peer_Info_Params {
		version       = "2.7.7",
		platform      = "linux",
		tcp_nonlinear = true,
		mtu           = 1600,
		ciphers       = ciphers,
		proto         = IV_PROTO_USERSPACE,
		extra         = {"IV_LZO_STUB=1", "IV_COMP_STUB=1", "IV_COMP_STUBv2=1"},
	}
	s, err := peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, s, stock_peer_info_277)
	testing.expect_value(t, len(s) + 1, 134) // the declared length in the capture

	// 2.6.23: IV_PROTO=990.
	p.version = "2.6.23"
	p.proto = {.Data_V2, .Request_Push, .Tls_Key_Export, .Auth_Pending_Kw, .Dns_Option, .Cc_Exit_Notify, .Auth_Fail_Temp, .Dyn_Tls_Crypt}
	s, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, s, "IV_VER=2.6.23\nIV_PLAT=linux\nIV_TCPNL=1\nIV_MTU=1600\nIV_CIPHERS=AES-256-GCM\nIV_PROTO=990\nIV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\n")
}

@(test)
peer_info_build_noirvpn_client :: proc(t: ^testing.T) {
	buf: [512]u8
	p := Peer_Info_Params {
		id            = 0x1f2e3d,
		version       = "noirvpn-0.1.0",
		platform      = "linux",
		tcp_nonlinear = true,
		mtu           = 1600,
		ncp           = true,
		ciphers       = {.Aes_256_Gcm, .Aes_128_Gcm, .Chacha20_Poly1305},
		proto         = IV_PROTO_USERSPACE,
	}
	s, err := peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.None)
	// Order: ID, IV_VER, IV_PLAT, IV_TCPNL, IV_MTU, IV_NCP, IV_CIPHERS, IV_PROTO.
	testing.expect_value(
		t,
		s,
		"ID=1f2e3d\nIV_VER=noirvpn-0.1.0\nIV_PLAT=linux\nIV_TCPNL=1\nIV_MTU=1600\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nIV_PROTO=8094\n",
	)
	pi: Peer_Info
	testing.expect_value(t, peer_info_parse(s, &pi), Error.None)
	testing.expect_value(t, pi.id, 0x1f2e3d)
	testing.expect_value(t, pi.ver, "noirvpn-0.1.0")
	testing.expect_value(t, pi.plat, "linux")
	testing.expect(t, pi.tcp_nonlinear)
	testing.expect_value(t, pi.mtu, 1600)
	testing.expect_value(t, pi.ncp, 2)
	testing.expect_value(t, pi.cipher_count, 3)
	testing.expect_value(t, pi.ciphers[2], "CHACHA20-POLY1305")
	testing.expect(t, pi.has_proto)
	testing.expect_value(t, pi.proto, IV_PROTO_USERSPACE)
	testing.expect_value(t, pi.line_count, 8)

	// A line order the spec lets a reader accept in any order.
	p.id = nil
	p.mtu = 0
	p.ciphers = nil
	p.ncp = false
	p.proto = IV_PROTO_DCO
	s, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, s, "IV_VER=noirvpn-0.1.0\nIV_PLAT=linux\nIV_TCPNL=1\nIV_PROTO=2974\n")
}

@(test)
peer_info_build_rejects :: proc(t: ^testing.T) {
	buf: [512]u8
	p := Peer_Info_Params {
		version = "x",
	}
	_, err := peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.None)
	p.version = ""
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.version = "a\nb"
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.version = "x"
	p.platform = "li\x00nux"
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.platform = ""
	p.id = u32(0xFFFFFF)
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.id = nil
	p.extra = {"NOEQUALS"}
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.extra = {"=novalue"}
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.extra = {"A=b\nC=d"}
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.extra = nil
	p.ciphers = {.None}
	_, err = peer_info_build(buf[:], &p)
	testing.expect_value(t, err, Error.Bad_Argument)
	p.ciphers = nil
	small: [8]u8
	_, err = peer_info_build(small[:], &p)
	testing.expect_value(t, err, Error.Buffer_Too_Small)
}

@(test)
peer_info_parse_stock_blocks :: proc(t: ^testing.T) {
	pi: Peer_Info
	testing.expect_value(t, peer_info_parse(stock_peer_info_277, &pi), Error.None)
	testing.expect_value(t, pi.ver, "2.7.7")
	testing.expect_value(t, pi.plat, "linux")
	testing.expect(t, pi.tcp_nonlinear)
	testing.expect_value(t, pi.mtu, 1600)
	testing.expect_value(t, pi.ncp, 0)
	testing.expect_value(t, pi.ciphers_raw, "AES-256-GCM")
	testing.expect_value(t, pi.cipher_count, 1)
	testing.expect_value(t, pi.proto_raw, 8094)
	testing.expect_value(t, pi.proto, IV_PROTO_USERSPACE)
	_, has_id := pi.id.?
	testing.expect(t, !has_id)
	testing.expect_value(t, pi.line_count, 9)
	v, ok := peer_info_get(&pi, "IV_COMP_STUBv2")
	testing.expect(t, ok)
	testing.expect_value(t, v, "1")
	_, ok = peer_info_get(&pi, "IV_COMP_STUB2")
	testing.expect(t, !ok)

	// 2.6.23 sends IV_PROTO=990 and no bit 11 (it has bit 6 instead).
	testing.expect_value(t, peer_info_parse("IV_VER=2.6.23\nIV_PLAT=linux\nIV_PROTO=990\n", &pi), Error.None)
	testing.expect(t, .Dns_Option in pi.proto && .Dns_Option_V2 not_in pi.proto)
	testing.expect(t, .Data_Epoch not_in pi.proto)
}

@(test)
peer_info_parse_rules :: proc(t: ^testing.T) {
	pi: Peer_Info
	// Empty and absent.
	testing.expect_value(t, peer_info_parse("", &pi), Error.None)
	testing.expect(t, !pi.has_proto)
	testing.expect_value(t, pi.line_count, 0)

	// First occurrence wins for typed fields; every line stays in the raw map.
	testing.expect_value(t, peer_info_parse("IV_PROTO=2\nIV_PROTO=4\nFOO=bar\nUV_X=1\n", &pi), Error.None)
	testing.expect_value(t, pi.proto_raw, 2)
	testing.expect_value(t, pi.line_count, 4)
	v, _ := peer_info_get(&pi, "UV_X")
	testing.expect_value(t, v, "1")

	// Numbers: garbage after is ignored, garbage before means absent.
	_ = peer_info_parse("IV_PROTO=990x\nIV_MTU=zz1600\nIV_NCP= 2\n", &pi)
	testing.expect_value(t, pi.proto_raw, 990)
	testing.expect_value(t, pi.mtu, 0)
	testing.expect_value(t, pi.ncp, 2)

	// ID is hex.
	_ = peer_info_parse("ID=1F\n", &pi)
	testing.expect_value(t, pi.id, 0x1f)
	_ = peer_info_parse("ID=ffffff\n", &pi) // "undefined"
	_, has := pi.id.?
	testing.expect(t, !has)
	_ = peer_info_parse("ID=xyz\n", &pi)
	_, has = pi.id.?
	testing.expect(t, !has)

	// A name must start the line.
	_ = peer_info_parse("XIV_PROTO=2\n IV_PROTO=4\n", &pi)
	testing.expect(t, !pi.has_proto)

	// No trailing newline, empty lines, lines without '=' and with an empty name.
	_ = peer_info_parse("\n\nnoequals\n=empty\nIV_VER=1.0", &pi)
	testing.expect_value(t, pi.ver, "1.0")
	testing.expect_value(t, pi.line_count, 1)

	// IV_PROTO above 32 bits is absent.
	_ = peer_info_parse("IV_PROTO=99999999999\n", &pi)
	testing.expect(t, !pi.has_proto)

	// IV_TCPNL=0 is not set.
	_ = peer_info_parse("IV_TCPNL=0\n", &pi)
	testing.expect(t, !pi.tcp_nonlinear)
}

@(test)
peer_info_parse_is_bounded :: proc(t: ^testing.T) {
	pi: Peer_Info
	b := make([dynamic]u8, context.temp_allocator)
	for i in 0 ..< 100 {
		append(&b, "UV_")
		append(&b, u8('a' + i % 26), u8('a' + i / 26), '=', '1', '\n')
	}
	testing.expect_value(t, peer_info_parse(string(b[:]), &pi), Error.None)
	testing.expect_value(t, pi.line_count, MAX_PEER_INFO_LINES)
	testing.expect_value(t, pi.lines_dropped, 100 - MAX_PEER_INFO_LINES)

	// Ciphers: 40 names, 32 kept.
	c := make([dynamic]u8, context.temp_allocator)
	append(&c, "IV_CIPHERS=")
	for i in 0 ..< 40 {
		if i > 0 {
			append(&c, ':')
		}
		append(&c, 'C', u8('a' + i % 26))
	}
	append(&c, '\n')
	testing.expect_value(t, peer_info_parse(string(c[:]), &pi), Error.None)
	testing.expect_value(t, pi.cipher_count, MAX_PEER_CIPHERS)
	testing.expect_value(t, pi.ciphers_dropped, 8)

	// Empty cipher items are skipped.
	_ = peer_info_parse("IV_CIPHERS=::AES-128-GCM::\n", &pi)
	testing.expect_value(t, pi.cipher_count, 1)

	// Longer than the key-method message limit.
	big := make([]u8, KEY_METHOD_MAX_LEN + 1, context.temp_allocator)
	testing.expect_value(t, peer_info_parse(string(big), &pi), Error.Oversize)
}
