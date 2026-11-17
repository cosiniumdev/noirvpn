// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:strings"
import "core:testing"

@(test)
test_controller_check_accepts_the_allowed_lines :: proc(t: ^testing.T) {
	lines := []string {
		"ifconfig-push 10.8.0.50 255.255.255.0",
		"route 192.168.5.0 255.255.255.0",
		"route-ipv6 fd00:99::/64",
		"dhcp-option DNS 10.8.0.1",
		"iroute 192.168.60.0 255.255.255.0",
		"session-timeout 600",
		"redirect-gateway def1",
	}
	text, bad, why := controller_check(lines)
	defer delete(text)
	testing.expect_value(t, bad, 0)
	testing.expect_value(t, why, "")
	// ccd syntax: the pushed options are wrapped in `push`.
	testing.expect(t, strings.contains(text, "ifconfig-push 10.8.0.50 255.255.255.0\n"))
	testing.expect(t, strings.contains(text, "push \"route 192.168.5.0 255.255.255.0\"\n"))
	testing.expect(t, strings.contains(text, "push \"dhcp-option DNS 10.8.0.1\"\n"))
	testing.expect(t, strings.contains(text, "session-timeout 600\n"))
}

@(test)
test_controller_check_names_the_bad_line :: proc(t: ^testing.T) {
	Case :: struct {
		lines: []string,
		bad:   int,
	}
	cases := []Case {
		{{"route 10.0.0.0 255.0.0.0", "ifconfig-push foo 255.255.255.0"}, 2},
		{{"ping 1"}, 1}, // keepalive is not the controller's
		{{"topology net30"}, 1},
		{{"ifconfig 10.8.0.2 255.255.255.0"}, 1},
		{{"up /bin/sh"}, 1},
		{{"route 10.0.0.0 255.0.0.0", "route 10.1.0.0 255.0.0.0", "cipher none"}, 3},
		{{"route not-an-address"}, 1},
		{{""}, 1},
		{{"route 10.0.0.0\nroute 10.1.0.0"}, 1}, // a line break would be a second line
		{{"route 10.0.0.0 255.0.0.0\" ; x"}, 1}, // a quote
		{{"dhcp-option DNS 1.1.1.1,route 0.0.0.0"}, 1}, // a comma starts another option
		{{"iroute 300.0.0.0 255.0.0.0"}, 1},
		{{"session-timeout many"}, 1},
		{{"route 10.0.0.0 255.0.0.0\x01"}, 1},
	}
	for c in cases {
		text, bad, why := controller_check(c.lines)
		testing.expectf(t, bad == c.bad && text == "" && why != "", "lines %v: bad %d, why '%s', text '%s'", c.lines, bad, why, text)
		delete(text)
	}
}

@(test)
test_controller_check_limits :: proc(t: ^testing.T) {
	many := make([]string, CONTROLLER_MAX_LINES + 1, context.temp_allocator)
	for &l in many {
		l = "route 10.0.0.0 255.0.0.0"
	}
	text, bad, why := controller_check(many)
	testing.expect_value(t, text, "")
	testing.expect_value(t, bad, 0)
	testing.expect(t, why != "")
	long := strings.concatenate({"dhcp-option DOMAIN ", strings.repeat("a", 300, context.temp_allocator)}, context.temp_allocator)
	_, bad, _ = controller_check([]string{long})
	testing.expect_value(t, bad, 1)
	// An empty list is fine and adds nothing.
	text, bad, why = controller_check(nil)
	testing.expect_value(t, text, "")
	testing.expect_value(t, bad, 0)
	testing.expect_value(t, why, "")
}

@(test)
test_controller_lines_reach_the_assignment :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	text, bad, _ := controller_check([]string{"ifconfig-push 10.8.0.50 255.255.255.0", "route 192.168.5.0 255.255.255.0", "session-timeout 90"})
	defer delete(text)
	testing.expect_value(t, bad, 0)
	// bob (key 3): a plain client. The controller gives an address and a route.
	d := server_authorize(&f.srv, Auth_Input{key = peer_key(3), has_key = true, proof = .Chain, src = tkey(3)}, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	a, h, rej, _ := server_connect(&f.srv, &d, tkey(3), 3, 0, extra = text)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect_value(t, a.addr4, [4]u8{10, 8, 0, 50})
	testing.expect_value(t, a.session_timeout, 90)
	found := false
	for l in a.push {
		found ||= l == "route 192.168.5.0 255.255.255.0"
	}
	testing.expect(t, found)
	// The static address is taken: a second client asking for it is refused.
	d2 := server_authorize(&f.srv, Auth_Input{key = peer_key(6), has_key = true, proof = .Chain, src = tkey(6)}, 0)
	_, _, rej2, _ := server_connect(&f.srv, &d2, tkey(6), 6, 0, extra = text)
	testing.expect_value(t, rej2.reason, Reject_Reason.Address_In_Use)
	assignment_destroy(&a)
	testing.expect(t, server_disconnect(&f.srv, h, 1 * SEC))
}

@(test)
test_controller_address_wins_over_the_peers_file :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	text, bad, _ := controller_check([]string{"ifconfig-push 10.8.0.60 255.255.255.0"})
	defer delete(text)
	testing.expect_value(t, bad, 0)
	// dave (key 5) has ifconfig-push=10.8.0.9 in the peers file.
	d := server_authorize(&f.srv, Auth_Input{key = peer_key(5), has_key = true, proof = .Chain, src = tkey(5)}, 0)
	a, h, rej, _ := server_connect(&f.srv, &d, tkey(5), 5, 0, extra = text)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect_value(t, a.addr4, [4]u8{10, 8, 0, 60})
	assignment_destroy(&a)
	testing.expect(t, server_disconnect(&f.srv, h, 1 * SEC))
}
