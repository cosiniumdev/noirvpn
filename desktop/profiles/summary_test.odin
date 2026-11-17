// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:testing"

expect_remote :: proc(t: ^testing.T, r: Remote, host: string, port: int, proto: string, loc := #caller_location) {
	testing.expect_value(t, r.host, host, loc)
	testing.expect_value(t, r.port, port, loc)
	testing.expect_value(t, r.proto, proto, loc)
}

@(test)
test_summarize_defaults :: proc(t: ^testing.T) {
	text := "client\ndev tun\nremote a.example\nremote b.example 443\nremote c.example 1195 tcp-client\nauth-user-pass\n"
	s, ok := summarize(text)
	defer summary_destroy(&s)
	testing.expect(t, ok)
	testing.expect_value(t, len(s.remotes), 3)
	expect_remote(t, s.remotes[0], "a.example", 1194, "udp")
	expect_remote(t, s.remotes[1], "b.example", 443, "udp")
	expect_remote(t, s.remotes[2], "c.example", 1195, "tcp")
	testing.expect_value(t, s.dev, "tun")
	testing.expect(t, s.user_pass)
	testing.expect(t, !s.has_ca && !s.has_cert && !s.has_key)
}

@(test)
test_summarize_globals :: proc(t: ^testing.T) {
	// The global proto and port apply to every remote, wherever they stand.
	text := "remote a.example\nproto TCP4\nport 443\nremote b.example 80 UDP6\nremote c.example x tls-client\nrport 8443\n"
	s, ok := summarize(text)
	defer summary_destroy(&s)
	testing.expect(t, ok)
	testing.expect_value(t, len(s.remotes), 3)
	expect_remote(t, s.remotes[0], "a.example", 8443, "tcp")
	expect_remote(t, s.remotes[1], "b.example", 80, "udp")
	expect_remote(t, s.remotes[2], "c.example", 8443, "tls")
}

@(test)
test_summarize_connections :: proc(t: ^testing.T) {
	text := `proto tcp
remote first.example
<connection>
remote one.example
</connection>
<connection>
remote two.example 993
proto udp4
</connection>
`
	s, ok := summarize(text)
	defer summary_destroy(&s)
	testing.expect(t, ok)
	testing.expect_value(t, len(s.remotes), 3)
	expect_remote(t, s.remotes[0], "first.example", 1194, "tcp")
	expect_remote(t, s.remotes[1], "one.example", 1194, "tcp")
	expect_remote(t, s.remotes[2], "two.example", 993, "udp")
}

@(test)
test_summarize_keys :: proc(t: ^testing.T) {
	text := "<ca>\nx\n</ca>\ncert c.crt\n<key>\nx\n</key>\n<tls-crypt>\nx\n</tls-crypt>\ntls-auth ta.key 1\n" +
		"<tls-crypt-v2>\nx\n</tls-crypt-v2>\n<peer-fingerprint>\nAA\n</peer-fingerprint>\n"
	s, ok := summarize(text)
	defer summary_destroy(&s)
	testing.expect(t, ok)
	testing.expect(t, s.has_ca && s.has_cert && s.has_key && s.has_tls_crypt && s.has_tls_auth)
	testing.expect(t, s.has_tls_crypt_v2 && s.has_peer_fingerprint && !s.user_pass)
	testing.expect_value(t, len(s.remotes), 0)
	testing.expect_value(t, s.dev, "")
}

@(test)
test_summarize_bad_text :: proc(t: ^testing.T) {
	s, ok := summarize("remote a.example\nremote \"b\n<ca>\nx\n")
	defer summary_destroy(&s)
	testing.expect(t, !ok)
	testing.expect_value(t, len(s.remotes), 1)

	e, eok := summarize("")
	defer summary_destroy(&e)
	testing.expect(t, eok)
	testing.expect_value(t, len(e.remotes), 0)
}
