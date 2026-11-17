// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:testing"

@(test)
test_build_askpass :: proc(t: ^testing.T) {
	none := load_client("")
	defer destroy(&none)
	_, set := none.client.tls.askpass.?
	testing.expect(t, !set)

	file := load_client("askpass /etc/noirvpn/key.pass\n")
	defer destroy(&file)
	expect_clean(t, file.diags)
	testing.expect_value(t, file.client.tls.askpass.? or_else "-", "/etc/noirvpn/key.pass")

	// No file, and the upstream spelling `stdin`: typed at the terminal.
	for text in ([]string{"askpass\n", "askpass stdin\n"}) {
		cfg := load_client(text)
		expect_clean(t, cfg.diags)
		testing.expect_value(t, cfg.client.tls.askpass.? or_else "-", "")
		destroy(&cfg)
	}

	srv := load_server("askpass /etc/noirvpn/key.pass\n")
	defer destroy(&srv)
	expect_clean(t, srv.diags)
	testing.expect_value(t, srv.server.tls.askpass.? or_else "-", "/etc/noirvpn/key.pass")

	// There is no inline form.
	inl := load_client("<askpass>\nsecret\n</askpass>\n")
	defer destroy(&inl)
	testing.expect(t, !ok(&inl))
}

@(test)
test_user_askpass :: proc(t: ^testing.T) {
	// Accepted: the service asks for the passphrase over the bus.
	p := user_profile_build("client\nremote a.example\nca /etc/ca.crt\naskpass\n")
	defer user_profile_destroy(&p)
	for pr in p.problems {
		testing.expectf(t, pr.option != "askpass", "askpass refused: %v", pr)
	}

	// A file: the desktop app reads it; the service accepts the line and never
	// opens the path. On mobile it is refused.
	d := user_profile_build("client\nremote a.example\naskpass /root/key.pass\n")
	defer user_profile_destroy(&d)
	for pr in d.problems {
		testing.expectf(t, pr.option != "askpass", "askpass refused: %v", pr)
	}
	q := user_profile_build_for("client\nremote a.example\naskpass /root/key.pass\n", true)
	defer user_profile_destroy(&q)
	found := false
	for pr in q.problems {
		if pr.option == "askpass" {
			found = true
			testing.expect_value(t, pr.class, "path")
		}
	}
	testing.expect(t, found)
}
