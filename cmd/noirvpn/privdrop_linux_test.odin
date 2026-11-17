// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:strings"
import "core:testing"

// The lookups use the passwd and group databases of the host. Every Linux
// system has root with uid 0 and gid 0.

@(test)
priv_resolve_user_takes_its_primary_group :: proc(t: ^testing.T) {
	p, err := priv_resolve("root", "")
	testing.expect_value(t, err, "")
	testing.expect(t, p.on && p.change_uid)
	testing.expect_value(t, p.uid, u32(0))
	testing.expect_value(t, p.gid, u32(0))
}

@(test)
priv_resolve_numbers :: proc(t: ^testing.T) {
	p, err := priv_resolve("0", "0")
	testing.expect_value(t, err, "")
	testing.expect_value(t, p.uid, u32(0))
	testing.expect_value(t, p.gid, u32(0))
}

@(test)
priv_resolve_group_alone_keeps_the_uid :: proc(t: ^testing.T) {
	p, err := priv_resolve("", "root")
	testing.expect_value(t, err, "")
	testing.expect(t, p.on && !p.change_uid)
	testing.expect_value(t, p.gid, u32(0))
}

@(test)
priv_resolve_none :: proc(t: ^testing.T) {
	p, err := priv_resolve("", "")
	testing.expect_value(t, err, "")
	testing.expect(t, !p.on)
	testing.expect_value(t, priv_check_text("", ""), "")
}

@(test)
priv_resolve_errors :: proc(t: ^testing.T) {
	_, e1 := priv_resolve("noirvpn-no-such-user-x", "")
	testing.expect(t, strings.contains(e1, "this user does not exist"), e1)
	_, e2 := priv_resolve("root", "noirvpn-no-such-group-x")
	testing.expect(t, strings.contains(e2, "this group does not exist"), e2)
	// A uid with no passwd entry has no primary group.
	_, e3 := priv_resolve("4000000001", "")
	testing.expect(t, strings.contains(e3, "add the group option"), e3)
	_, e4 := priv_resolve("4294967295", "0")
	testing.expect(t, strings.contains(e4, "not a valid uid"), e4)
}
