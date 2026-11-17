// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

@(test)
parse_uint_cases :: proc(t: ^testing.T) {
	v, ok := parse_uint("0")
	testing.expect(t, ok && v == 0)
	v, ok = parse_uint("123456")
	testing.expect(t, ok && v == 123456)
	for bad in ([]string{"", "-1", "+1", " 1", "1 ", "1a", "0x10", "1234567890123456789"}) {
		_, ok = parse_uint(bad)
		testing.expectf(t, !ok, "%q must not parse", bad)
	}
	_, ok = parse_uint_max("256", 255)
	testing.expect(t, !ok)
	v, ok = parse_uint_max("255", 255)
	testing.expect(t, ok && v == 255)
}

@(test)
scan_uint_prefix_cases :: proc(t: ^testing.T) {
	// garbage after the number is ignored, garbage before it sets it absent.
	v, ok := scan_uint_prefix("8094")
	testing.expect(t, ok && v == 8094)
	v, ok = scan_uint_prefix("990 extra")
	testing.expect(t, ok && v == 990)
	v, ok = scan_uint_prefix("  12abc")
	testing.expect(t, ok && v == 12)
	_, ok = scan_uint_prefix("x12")
	testing.expect(t, !ok)
	_, ok = scan_uint_prefix("")
	testing.expect(t, !ok)
	_, ok = scan_uint_prefix("-5")
	testing.expect(t, !ok)
	v, ok = scan_uint_prefix("ff", hex = true)
	testing.expect(t, ok && v == 255)
	v, ok = scan_uint_prefix("1A2b", hex = true)
	testing.expect(t, ok && v == 0x1a2b)
	_, ok = scan_uint_prefix("zz", hex = true)
	testing.expect(t, !ok)
	// Far too many digits do not overflow.
	_, ok = scan_uint_prefix("99999999999999999999999999")
	testing.expect(t, !ok)
}

@(test)
ipv4_cases :: proc(t: ^testing.T) {
	a, ok := parse_ipv4("10.8.0.1")
	testing.expect(t, ok && a == [4]u8{10, 8, 0, 1})
	a, ok = parse_ipv4("255.255.255.255")
	testing.expect(t, ok && a == [4]u8{255, 255, 255, 255})
	a, ok = parse_ipv4("0.0.0.0")
	testing.expect(t, ok && a == [4]u8{})
	for bad in ([]string{"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.04", "1..2.3", ".1.2.3", "1.2.3.", "a.b.c.d", "1.2.3.4 ", " 1.2.3.4", "1.2.3.4/24", "1111.2.3.4"}) {
		_, ok = parse_ipv4(bad)
		testing.expectf(t, !ok, "%q must not parse", bad)
	}
}

@(test)
ipv6_cases :: proc(t: ^testing.T) {
	Case :: struct {
		text: string,
		want: [16]u8,
	}
	good := []Case {
		{"::", {}},
		{"::1", {15 = 1}},
		{"1::", {1 = 1}},
		{"fd00::1", {0 = 0xfd, 15 = 1}},
		{"2001:db8::ff00:42:8329", {0 = 0x20, 1 = 0x01, 2 = 0x0d, 3 = 0xb8, 10 = 0xff, 12 = 0x00, 13 = 0x42, 14 = 0x83, 15 = 0x29}},
		{"1:2:3:4:5:6:7:8", {1 = 1, 3 = 2, 5 = 3, 7 = 4, 9 = 5, 11 = 6, 13 = 7, 15 = 8}},
		{"::ffff:1.2.3.4", {10 = 0xff, 11 = 0xff, 12 = 1, 13 = 2, 14 = 3, 15 = 4}},
		{"FD00:0:0:0:0:0:0:1", {0 = 0xfd, 15 = 1}},
		{"1:2:3:4:5:6:1.2.3.4", {1 = 1, 3 = 2, 5 = 3, 7 = 4, 9 = 5, 11 = 6, 12 = 1, 13 = 2, 14 = 3, 15 = 4}},
	}
	for c in good {
		a, ok := parse_ipv6(c.text)
		testing.expectf(t, ok, "%q must parse", c.text)
		testing.expectf(t, a == c.want, "%q: got %v", c.text, a)
	}
	bad := []string {
		"",
		":",
		":::",
		"1:2:3:4:5:6:7",
		"1:2:3:4:5:6:7:8:9",
		"1::2::3",
		"12345::1",
		"g::1",
		"1:2:3:4:5:6:7:8::",
		"::1:2:3:4:5:6:7:8",
		"1:",
		":1",
		"1.2.3.4",
		"::1.2.3",
		"1.2.3.4::",
		"fe80::1%eth0",
		"[::1]",
		"1:2:3:4:5:6:7::8:9",
	}
	for s in bad {
		_, ok := parse_ipv6(s)
		testing.expectf(t, !ok, "%q must not parse", s)
	}
}

@(test)
ipv6_format_round_trip :: proc(t: ^testing.T) {
	buf: [64]u8
	for text in ([]string{"::", "::1", "fd00::1", "2001:db8::ff00:42:8329", "1:2:3:4:5:6:7:8", "1::", "fe80::1:0:0:1", "1:0:0:2:0:0:0:3"}) {
		a, ok := parse_ipv6(text)
		testing.expect(t, ok)
		w := Wr{buf = buf[:]}
		wr_ipv6(&w, a)
		got := string(buf[:w.n])
		back, ok2 := parse_ipv6(got)
		testing.expect(t, ok2 && back == a)
	}
	// The shortest form: the longest zero run, and a lone zero group stays.
	a, _ := parse_ipv6("1:0:0:2:0:0:0:3")
	w := Wr{buf = buf[:]}
	wr_ipv6(&w, a)
	testing.expect_value(t, string(buf[:w.n]), "1:0:0:2::3")
	a, _ = parse_ipv6("fd00:0:1:0:2:3:4:5")
	w = Wr{buf = buf[:]}
	wr_ipv6(&w, a)
	testing.expect_value(t, string(buf[:w.n]), "fd00:0:1:0:2:3:4:5")
	w = Wr{buf = buf[:]}
	wr_ipv6(&w, {})
	testing.expect_value(t, string(buf[:w.n]), "::")
}

@(test)
netmask_cases :: proc(t: ^testing.T) {
	testing.expect(t, netmask_is_contiguous({255, 255, 255, 0}))
	testing.expect(t, netmask_is_contiguous({255, 255, 255, 255}))
	testing.expect(t, netmask_is_contiguous({0, 0, 0, 0}))
	testing.expect(t, netmask_is_contiguous({255, 255, 128, 0}))
	testing.expect(t, !netmask_is_contiguous({255, 0, 255, 0}))
	testing.expect(t, !netmask_is_contiguous({0, 0, 0, 255}))
	testing.expect_value(t, netmask_bits({255, 255, 255, 0}), 24)
}

@(test)
writer_overflow_is_sticky :: proc(t: ^testing.T) {
	buf: [4]u8
	w := Wr{buf = buf[:]}
	wr_str(&w, "abc")
	testing.expect(t, !w.over)
	wr_str(&w, "de")
	testing.expect(t, w.over)
	wr_byte(&w, 'x')
	testing.expect_value(t, w.n, 3)
}
