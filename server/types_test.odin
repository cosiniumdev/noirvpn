// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"

@(test)
test_addr_key_v4_v6 :: proc(t: ^testing.T) {
	k4 := addr_key_v4({192, 0, 2, 7}, 1194, 3)
	testing.expect(t, addr_key_is_v4(k4))
	testing.expect_value(t, k4[12], u8(192))
	testing.expect_value(t, k4[15], u8(7))
	testing.expect_value(t, k4[16], u8(1194 >> 8))
	testing.expect_value(t, k4[17], u8(1194 & 0xff))
	testing.expect_value(t, k4[18], u8(3))

	ip := v6("2001:db8:1:2:3:4:5:6")
	k6 := addr_key_v6(ip, 443)
	testing.expect(t, !addr_key_is_v4(k6))
	for i in 0 ..< 16 {
		testing.expect_value(t, k6[i], ip[i])
	}
	// Different port or socket, different key.
	testing.expect(t, addr_key_v4({1, 2, 3, 4}, 1) != addr_key_v4({1, 2, 3, 4}, 2))
	testing.expect(t, addr_key_v4({1, 2, 3, 4}, 1, 0) != addr_key_v4({1, 2, 3, 4}, 1, 1))
}

@(test)
test_rate_key :: proc(t: ^testing.T) {
	// IPv4: whole address, no port.
	a := rate_key(addr_key_v4({192, 0, 2, 7}, 1000))
	b := rate_key(addr_key_v4({192, 0, 2, 7}, 2000, 5))
	c := rate_key(addr_key_v4({192, 0, 2, 8}, 1000))
	testing.expect(t, a == b)
	testing.expect(t, a != c)
	// IPv6: the /64 only.
	x := rate_key(addr_key_v6(v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 1))
	y := rate_key(addr_key_v6(v6("2001:db8:1:2:1:2:3:4"), 2))
	z := rate_key(addr_key_v6(v6("2001:db8:1:3:1:2:3:4"), 1))
	testing.expect(t, x == y)
	testing.expect(t, x != z)
}

@(test)
test_identity_check :: proc(t: ^testing.T) {
	good := []string{"alice", "a", "bob smith", "carol@example.com", "x.y-z_1", "caf\xc3\xa9", "..a", "a..", "-flag"}
	for s in good {
		testing.expectf(t, identity_check(s), "%q should be valid", s)
	}
	long := make([]u8, 256, context.temp_allocator)
	for &c in long {
		c = 'a'
	}
	max_ok := string(long[:255])
	testing.expect(t, identity_check(max_ok))
	testing.expect(t, !identity_check(string(long)))
	bad := []string{"", ".", "..", "a/b", "../x", "a\\b", "a\x00b", "a\nb", "a\tb", "a\x7fb", "/"}
	for s in bad {
		testing.expectf(t, !identity_check(s), "%q should be invalid", s)
	}
	id, ok := identity_make("alice")
	testing.expect(t, ok)
	testing.expect_value(t, identity_str(&id), "alice")
	_, ok = identity_make("a/b")
	testing.expect(t, !ok)
}

@(test)
test_reject_kinds :: proc(t: ^testing.T) {
	temp := []Reject_Reason{.Password_Busy, .External_Timeout, .Rate_Limited, .Max_Clients, .Id_Exhausted, .Pool_Exhausted, .Address_In_Use}
	for r in Reject_Reason {
		if r == .None {
			continue
		}
		rj := reject_make(r)
		want_temp := false
		for x in temp {
			want_temp ||= x == r
		}
		testing.expectf(t, (rj.kind == .Auth_Failed_Temp) == want_temp, "kind of %v", r)
		testing.expectf(t, len(reject_text(r)) > 0 && reject_text(r) != "?", "text of %v", r)
		// The client text never names the reason.
		ct := reject_client_text(rj)
		testing.expect(t, len(ct) > 0)
		// Only a temporary reject has a back-off hint.
		testing.expectf(t, (reject_backoff(rj) > 0) == want_temp, "back-off of %v", r)
	}
	testing.expect_value(t, reject_backoff(reject_make(.Address_In_Use)), 30)
	testing.expect_value(t, reject_backoff(Reject{.Password_Failed, .Auth_Failed}), 0)
}
