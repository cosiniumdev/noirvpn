// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:testing"

@(test)
test_acl_lines :: proc(t: ^testing.T) {
	text := "client\n# allow-inbound :80\n; forward 1 to a.lan:1\nallow-inbound :22 tcp\r\n<ca>\nallow-inbound :99\n</ca>\n" +
		"  forward 8080 to 127.0.0.1:80  \nremote vpn.example.com\nallow-inbound nas.lan:445 192.168.50.0/24\n"
	lines := acl_lines(text, context.temp_allocator)
	testing.expect_value(t, len(lines), 3)
	if len(lines) == 3 {
		testing.expect_value(t, lines[0], "allow-inbound :22 tcp")
		testing.expect_value(t, lines[1], "forward 8080 to 127.0.0.1:80")
		testing.expect_value(t, lines[2], "allow-inbound nas.lan:445 192.168.50.0/24")
	}
}

@(test)
test_acl_lines_none :: proc(t: ^testing.T) {
	testing.expect_value(t, len(acl_lines("", context.temp_allocator)), 0)
	testing.expect_value(t, len(acl_lines("client\nremote a.example\n<key>\nforward 1 to b:2\n</key>\n", context.temp_allocator)), 0)
}

@(test)
test_acl_line_count :: proc(t: ^testing.T) {
	lines := []string{"client", "allow-inbound :22 tcp", "  forward 8080 to 127.0.0.1:80", "forward-max-conns 9", "# allow-inbound :80", "allow-inbounds x", "forward\tudp"}
	testing.expect_value(t, acl_line_count(lines), 3)
	testing.expect_value(t, acl_line_count(nil), 0)
}
