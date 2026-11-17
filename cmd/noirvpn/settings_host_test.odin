// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:testing"
import "noir:proto/config"

// `user` and `group` of the config are checked by the privilege code of the
// daemon: the engine asks it through `Sys_Hooks`.

@(private = "file")
BASE :: `client
dev tun
remote 192.0.2.1 1194 udp
<ca>
CA
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`

@(private = "file")
settings_for :: proc(extra: string, s: ^Settings) -> (cfg: config.Config, ok: bool) {
	text := concat(BASE, extra)
	cfg = config.build(config.parse_text(text, "test.conf"))
	if !config.ok(&cfg) {
		return cfg, false
	}
	return cfg, settings_load(s, &cfg)
}

@(private = "file")
concat :: proc(a, b: string) -> string {
	buf := make([]u8, len(a) + len(b), context.temp_allocator)
	copy(buf, a)
	copy(buf[len(a):], b)
	return string(buf)
}

@(test)
test_settings_user_group :: proc(t: ^testing.T) {
	// Windows refuses both options (privdrop_windows.odin).
	when ODIN_OS == .Linux {
		s1: Settings
		defer settings_destroy(&s1)
		cfg1, ok1 := settings_for("user root\ngroup 0\n", &s1)
		defer config.destroy(&cfg1)
		testing.expect(t, ok1)
		testing.expect_value(t, len(s1.errors), 0)
	}
	s: Settings
	defer settings_destroy(&s)
	cfg, ok := settings_for("user noirvpn-no-such-user-x\n", &s)
	defer config.destroy(&cfg)
	testing.expect(t, !ok)
	testing.expect(t, len(s.errors) > 0)
}
