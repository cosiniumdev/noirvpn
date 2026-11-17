// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:testing"

@(test)
test_build_keeps_parse_errors :: proc(t: ^testing.T) {
	// Syntax errors are reported first, and the good lines still count.
	text := "client\nremote \"broken 1194\nremote ok.example 1194\nca ca.crt\ncert c.crt\nkey c.key\n"
	cfg := build(parse_text(text, "p.conf"))
	defer destroy(&cfg)
	testing.expect(t, !ok(&cfg))
	testing.expect(t, len(cfg.diags) >= 1)
	if len(cfg.diags) >= 1 {
		testing.expect_value(t, cfg.diags[0].file, "p.conf")
		testing.expect_value(t, cfg.diags[0].line, 2)
	}
	testing.expect_value(t, len(cfg.client.connections), 1)
	testing.expect_value(t, cfg.client.connections[0].host, "ok.example")
}

@(test)
test_build_ok_and_destroy :: proc(t: ^testing.T) {
	cfg := load_client("")
	testing.expect(t, ok(&cfg))
	testing.expect(t, config_common(&cfg) == &cfg.client.common)
	destroy(&cfg)
	// A destroyed or zero Config can be destroyed again.
	destroy(&cfg)
	empty: Config
	destroy(&empty)

	srv := load_server("")
	testing.expect(t, config_common(&srv) == &srv.server.common)
	destroy(&srv)
}

@(test)
test_build_only_active_role_is_filled :: proc(t: ^testing.T) {
	cfg := load_client("")
	defer destroy(&cfg)
	testing.expect_value(t, len(cfg.server.listens), 0)
	testing.expect_value(t, len(cfg.server.push), 0)
	srv := load_server("")
	defer destroy(&srv)
	testing.expect_value(t, len(srv.client.connections), 0)
}

@(test)
test_build_does_not_alias_the_input_text :: proc(t: ^testing.T) {
	// The parser copies its input, so the caller may free it.
	text := make([]u8, len(CLIENT_BASE))
	copy(text, CLIENT_BASE)
	cfg := build(parse_text(string(text), "x.conf"))
	defer destroy(&cfg)
	for i in 0 ..< len(text) {
		text[i] = 'X'
	}
	delete(text)
	testing.expect_value(t, cfg.client.connections[0].host, "vpn.example.com")
	testing.expect_value(t, cfg.client.tls.ca.data, "CA\n")
}
