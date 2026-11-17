// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:testing"

// ---- the command line ----

@(test)
test_cli_flags :: proc(t: ^testing.T) {
	c := cli_split({"--check-config", "--config", "a.conf", "--verb", "3"})
	defer delete(c.args)
	testing.expect_value(t, c.mode, Mode.Check)
	testing.expect_value(t, len(c.args), 4)
	testing.expect_value(t, c.args[0], "--config")

	v := cli_split({"--version", "--help"})
	defer delete(v.args)
	testing.expect_value(t, v.mode, Mode.Version)

	h := cli_split({"-h"})
	defer delete(h.args)
	testing.expect_value(t, h.mode, Mode.Help)

	r := cli_split({"client.conf"})
	defer delete(r.args)
	testing.expect_value(t, r.mode, Mode.Run)
	testing.expect_value(t, len(r.args), 1)

	e := cli_split({})
	defer delete(e.args)
	testing.expect_value(t, e.mode, Mode.Run)
	testing.expect_value(t, len(e.args), 0)
}

@(test)
test_cli_name :: proc(t: ^testing.T) {
	// `--name` is the daemon's own flag: it and its value are not config arguments.
	c := cli_split({"--config", "a.conf", "--name", "vpn1", "--verb", "3"})
	defer delete(c.args)
	testing.expect_value(t, c.name, "vpn1")
	testing.expect(t, !c.name_missing)
	testing.expect_value(t, len(c.args), 4)
	testing.expect_value(t, c.args[2], "--verb")

	// The name comes before nothing: the end of the line, or another option, is "no value".
	m := cli_split({"a.conf", "--name"})
	defer delete(m.args)
	testing.expect(t, m.name_missing)
	testing.expect_value(t, len(m.args), 1)

	n := cli_split({"a.conf", "--name", "--verb", "3"})
	defer delete(n.args)
	testing.expect(t, n.name_missing)
	testing.expect_value(t, n.name, "")

	d := cli_split({"a.conf"})
	defer delete(d.args)
	testing.expect_value(t, d.name, "")
	testing.expect(t, !d.name_missing)
}
