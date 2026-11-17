// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:testing"

@(test)
instance_names :: proc(t: ^testing.T) {
	Case :: struct {
		in_, want: string,
	}
	cases := []Case {
		{"/etc/noirvpn/server.conf", "server"},
		{"work.ovpn", "work"},
		{"/etc/noirvpn/my vpn.conf", "my_vpn"},
		{"/etc/a.b.conf", "a.b"},
		{"noext", "noext"},
		{"/path/.hidden", ".hidden"},
		{"", "noirvpn"},
		{"/", "noirvpn"},
		{"/etc/..", "noirvpn"},
		{"/etc/ü.conf", "__"},
	}
	for c in cases {
		got := instance_name(c.in_)
		testing.expectf(t, got == c.want, "instance_name(%q) = %q, want %q", c.in_, got, c.want)
		delete(got)
	}
	long := instance_name("/etc/0123456789012345678901234567890123456789012345678901234567890123456789.conf")
	defer delete(long)
	testing.expect_value(t, len(long), 40)
}
