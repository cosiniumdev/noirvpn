// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:strings"
import "core:testing"
import "noir:proto/config"

// A valid client config: the server is verified by `ca`, the identity is an
// inline `cert` and `key`. Inline blocks are not parsed, so any text does.
CLIENT_BASE :: `client
dev tun
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

// CLIENT_BASE plus `remotes` (`remote` lines or `<connection>` blocks) and
// `extra` options. The caller destroys the result with `config.destroy`.
load_client :: proc(remotes: string, extra := "") -> config.Config {
	text := strings.concatenate({CLIENT_BASE, remotes, "\n", extra, "\n"}, context.temp_allocator)
	return config.build(config.parse_text(text, "test.conf"))
}

expect_config_ok :: proc(t: ^testing.T, cfg: ^config.Config, loc := #caller_location) -> bool {
	if !config.ok(cfg) {
		testing.expectf(
			t,
			false,
			"config has errors:\n%s",
			config.format_diagnostics(cfg.diags, context.temp_allocator),
			loc = loc,
		)
		return false
	}
	return true
}
