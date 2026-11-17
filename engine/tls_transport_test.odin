// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:testing"
import "noir:proto/config"
import "noir:proto/ossl"

@(test)
proto_name_covers_the_transports :: proc(t: ^testing.T) {
	testing.expect_value(t, proto_name(.Udp, false), "udp")
	testing.expect_value(t, proto_name(.Tcp, false), "tcp")
	testing.expect_value(t, proto_name(.Tcp, true), "tls")
}

@(test)
outer_sni_from_the_remote_or_the_option :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	name, explicit := outer_sni(&cfg, "vpn.example.org")
	testing.expect_value(t, name, "vpn.example.org")
	testing.expect_value(t, explicit, false)
	// an address has no server name
	name, explicit = outer_sni(&cfg, "192.0.2.7")
	testing.expect_value(t, name, "")
	testing.expect_value(t, explicit, false)
	name, _ = outer_sni(&cfg, "2001:db8::1")
	testing.expect_value(t, name, "")
	// the option wins
	cfg.tls_transport_sni = "front.example"
	name, explicit = outer_sni(&cfg, "192.0.2.7")
	testing.expect_value(t, name, "front.example")
	testing.expect_value(t, explicit, true)
}

@(test)
outer_alpn_follows_the_hello_profile :: proc(t: ^testing.T) {
	testing.expect_value(t, len(outer_alpn(.Default, false)), 1)
	testing.expect_value(t, len(outer_alpn(.Default, true)), 1)
	chrome := outer_alpn(.Chrome, false)
	testing.expect_value(t, len(chrome), 2)
	if len(chrome) == 2 {
		testing.expect_value(t, chrome[0], "h2")
		testing.expect_value(t, chrome[1], "http/1.1")
	}
	// In a WebSocket h2 would break the upgrade behind a proxy that chooses it.
	ws := outer_alpn(.Chrome, true)
	testing.expect_value(t, len(ws), 1)
	if len(ws) == 1 {
		testing.expect_value(t, ws[0], "http/1.1")
	}
}

@(test)
outer_client_ctx_takes_the_profile :: proc(t: ^testing.T) {
	ctx, err := outer_client_ctx("X25519", .Chrome)
	testing.expect_value(t, err, ossl.Error.None)
	testing.expect_value(t, ctx.hello, ossl.Hello_Profile.Chrome)
	ossl.tls_ctx_destroy(&ctx)
	ctx, err = outer_client_ctx("X25519")
	testing.expect_value(t, err, ossl.Error.None)
	testing.expect_value(t, ctx.hello, ossl.Hello_Profile.Default)
	ossl.tls_ctx_destroy(&ctx)
}

@(test)
outer_text_names :: proc(t: ^testing.T) {
	testing.expect_value(t, outer_text(.Direct), "direct")
	testing.expect_value(t, outer_text(.Terminated), "terminated")
	testing.expect_value(t, outer_text(.Pending), "pending")
}

@(test)
first_bytes_tell_tls_from_raw_openvpn :: proc(t: ^testing.T) {
	// A TLS record header: handshake, version 3.0 to 3.4.
	for minor in u8(0) ..= 4 {
		testing.expect_value(t, classify_first_bytes({0x16, 0x03, minor}), First_Bytes.Tls)
		testing.expect_value(t, classify_first_bytes({0x16, 0x03, minor, 0x01, 0x00}), First_Bytes.Tls)
	}
	// Past the known versions.
	testing.expect_value(t, classify_first_bytes({0x16, 0x03, 0x05}), First_Bytes.Raw)
	testing.expect_value(t, classify_first_bytes({0x16, 0x03, 0xff}), First_Bytes.Raw)
	// Not a handshake record, or not version 3.
	testing.expect_value(t, classify_first_bytes({0x17, 0x03, 0x03}), First_Bytes.Raw)
	testing.expect_value(t, classify_first_bytes({0x16, 0x02, 0x00}), First_Bytes.Raw)
	testing.expect_value(t, classify_first_bytes({0x16, 0x04, 0x01}), First_Bytes.Raw)
	// The start of a raw OpenVPN reset packet: length 0x0036, then the opcode byte.
	testing.expect_value(t, classify_first_bytes({0x00, 0x36, 0x38}), First_Bytes.Raw)
	testing.expect_value(t, classify_first_bytes({0x00, 0x0e, 0x40}), First_Bytes.Raw)
	// Plain text such as an HTTP request.
	testing.expect_value(t, classify_first_bytes(transmute([]u8)string("GET / HTTP/1.0\r\n\r\n")), First_Bytes.Raw)
	// A raw packet at the largest length this server takes is far below 0x1603.
	testing.expect_value(t, classify_first_bytes({0x05, 0xdc, 0x48}), First_Bytes.Raw)
	// Too few bytes: wait, as long as the bytes so far still fit TLS.
	testing.expect_value(t, classify_first_bytes({}), First_Bytes.Need_More)
	testing.expect_value(t, classify_first_bytes({0x16}), First_Bytes.Need_More)
	testing.expect_value(t, classify_first_bytes({0x16, 0x03}), First_Bytes.Need_More)
	// A short prefix that cannot be TLS is decided at once.
	testing.expect_value(t, classify_first_bytes({0x00}), First_Bytes.Raw)
	testing.expect_value(t, classify_first_bytes({0x16, 0x00}), First_Bytes.Raw)
}
