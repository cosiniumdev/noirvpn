// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:testing"

@(test)
test_parse_decimal :: proc(t: ^testing.T) {
	v, ok := parse_decimal("0")
	testing.expect(t, ok && v == 0)
	v, ok = parse_decimal("1194")
	testing.expect(t, ok && v == 1194)
	v, ok = parse_decimal("-5", true)
	testing.expect(t, ok && v == -5)
	v, ok = parse_decimal("007")
	testing.expect(t, ok && v == 7)
	for bad in ([]string{"", "-", "+5", "5 ", " 5", "5a", "0x10", "1e3", "1.5", "99999999999999999999999"}) {
		_, ok = parse_decimal(bad, true)
		testing.expectf(t, !ok, "'%s' should not parse", bad)
	}
	_, ok = parse_decimal("-5")
	testing.expect(t, !ok, "a sign is refused unless allowed")
	_, ok = parse_range("70000", 1, 65535)
	testing.expect(t, !ok)
	_, ok = parse_range("0", 1, 65535)
	testing.expect(t, !ok)
	v, ok = parse_range("65535", 1, 65535)
	testing.expect(t, ok && v == 65535)
}

@(test)
test_ipv4 :: proc(t: ^testing.T) {
	a, ok := ipv4_parse("10.8.0.1")
	testing.expect(t, ok && a == [4]u8{10, 8, 0, 1})
	a, ok = ipv4_parse("255.255.255.255")
	testing.expect(t, ok && a == [4]u8{255, 255, 255, 255})
	for bad in ([]string{"", "1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3", "1..2.3", "256.1.1.1", "1.2.3.4 ", "a.b.c.d", "1.2.3.-4", "0001.2.3.4", "1.2.3.4/24"}) {
		_, ok = ipv4_parse(bad)
		testing.expectf(t, !ok, "'%s' should not parse", bad)
	}
	testing.expect_value(t, ipv4_to_u32({10, 8, 0, 1}), u32(0x0a080001))
	testing.expect_value(t, ipv4_from_u32(0x0a080001), [4]u8{10, 8, 0, 1})
}

@(test)
test_ipv4_masks :: proc(t: ^testing.T) {
	p, ok := ipv4_mask_prefix({255, 255, 255, 0})
	testing.expect(t, ok && p == 24)
	p, ok = ipv4_mask_prefix({255, 255, 255, 255})
	testing.expect(t, ok && p == 32)
	p, ok = ipv4_mask_prefix({0, 0, 0, 0})
	testing.expect(t, ok && p == 0)
	p, ok = ipv4_mask_prefix({255, 255, 254, 0})
	testing.expect(t, ok && p == 23)
	_, ok = ipv4_mask_prefix({255, 0, 255, 0})
	testing.expect(t, !ok)
	_, ok = ipv4_mask_prefix({0, 255, 255, 255})
	testing.expect(t, !ok)
	for n in 0 ..= 32 {
		m := ipv4_prefix_mask(n)
		got, mok := ipv4_mask_prefix(m)
		testing.expectf(t, mok && got == n, "prefix %d did not round-trip", n)
	}
}

@(test)
test_ipv4_cidr :: proc(t: ^testing.T) {
	a, p, ok := ipv4_parse_cidr("192.168.10.0/24")
	testing.expect(t, ok && a == [4]u8{192, 168, 10, 0} && p == 24)
	a, p, ok = ipv4_parse_cidr("10.0.0.0/255.0.0.0")
	testing.expect(t, ok && a == [4]u8{10, 0, 0, 0} && p == 8)
	a, p, ok = ipv4_parse_cidr("1.2.3.4/32")
	testing.expect(t, ok && p == 32)
	a, p, ok = ipv4_parse_cidr("0.0.0.0/0")
	testing.expect(t, ok && p == 0)
	for bad in ([]string{"10.0.0.0", "10.0.0.0/", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/255.0.255.0", "10.0.0/8", "10.0.0.0/8/8", "10.0.0.0/ 8"}) {
		_, _, ok = ipv4_parse_cidr(bad)
		testing.expectf(t, !ok, "'%s' should not parse", bad)
	}
}

@(test)
test_ipv6 :: proc(t: ^testing.T) {
	a, ok := ipv6_parse("::1")
	testing.expect(t, ok && a == [16]u8{15 = 1})
	a, ok = ipv6_parse("::")
	testing.expect(t, ok && a == [16]u8{})
	a, ok = ipv6_parse("fd00::1")
	testing.expect(t, ok && a[0] == 0xfd && a[1] == 0 && a[15] == 1)
	a, ok = ipv6_parse("2001:db8:0:0:0:0:0:1")
	testing.expect(
		t,
		ok && a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8 && a[15] == 1,
	)
	a, ok = ipv6_parse("2001:DB8::ff00:42:8329")
	testing.expect(
		t,
		ok && a[12] == 0x00 && a[13] == 0x42 && a[14] == 0x83 && a[15] == 0x29 && a[10] == 0xff,
	)
	a, ok = ipv6_parse("1:2:3:4:5:6:7:8")
	testing.expect(t, ok && a[15] == 8 && a[1] == 1)
	a, ok = ipv6_parse("fe80::")
	testing.expect(t, ok && a[0] == 0xfe && a[1] == 0x80 && a[2] == 0)
	for bad in ([]string{"", ":", ":::", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "12345::1", "g::1", "::1::", "1:2:3:4:5:6:7::8", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "fd00::1 ", "fd00::1/64"}) {
		_, ok = ipv6_parse(bad)
		testing.expectf(t, !ok, "'%s' should not parse", bad)
	}
}

@(test)
test_ipv6_cidr_and_math :: proc(t: ^testing.T) {
	a, bits, ok := ipv6_parse_cidr("fd00:1::/64")
	testing.expect(t, ok && bits == 64 && a[0] == 0xfd && a[3] == 1)
	_, _, ok = ipv6_parse_cidr("fd00::/129")
	testing.expect(t, !ok)
	_, _, ok = ipv6_parse_cidr("fd00::")
	testing.expect(t, !ok)
	_, _, ok = ipv6_parse_cidr("fd00::/")
	testing.expect(t, !ok)

	testing.expect(t, ipv6_host_part_is_zero(a, 64))
	testing.expect(t, ipv6_host_part_is_zero(a, 128) == true)
	one := ipv6_add(a, 1)
	testing.expect(t, !ipv6_host_part_is_zero(one, 64))
	testing.expect(t, one[15] == 1)
	testing.expect(t, ipv6_host_part_is_zero(one, 128))
	// A carry moves up through the bytes.
	x := [16]u8 {
		14 = 0,
		15 = 0xff,
	}
	y := ipv6_add(x, 1)
	testing.expect(t, y[14] == 1 && y[15] == 0)
	z := ipv6_add([16]u8{0 ..= 15 = 0xff}, 1)
	testing.expect(t, z == [16]u8{})
	big := ipv6_add({}, 0x0102030405060708)
	testing.expect(t, big[8] == 1 && big[15] == 8)
}

@(test)
test_base64 :: proc(t: ^testing.T) {
	buf: [64]u8
	n, ok := base64_decode("Zm9vYmFy", buf[:])
	testing.expect(t, ok && n == 6 && string(buf[:n]) == "foobar")
	n, ok = base64_decode("Zm9vYg==", buf[:])
	testing.expect(t, ok && n == 4 && string(buf[:n]) == "foob")
	// Padding is optional.
	n, ok = base64_decode("Zm9vYg", buf[:])
	testing.expect(t, ok && n == 4 && string(buf[:n]) == "foob")
	n, ok = base64_decode("Zm8=", buf[:])
	testing.expect(t, ok && n == 2 && string(buf[:n]) == "fo")
	n, ok = base64_decode("", buf[:])
	testing.expect(t, ok && n == 0)
	n, ok = base64_decode("+/+/", buf[:])
	testing.expect(t, ok && n == 3 && buf[0] == 0xfb && buf[1] == 0xff && buf[2] == 0xbf)
	for bad in ([]string{"Zm9v!mFy", "Zm9vY", "Zm9vYh==", "Zm9vYg===", "Zm 9v", "Zm9v\n", "-_-_"}) {
		_, ok = base64_decode(bad, buf[:])
		testing.expectf(t, !ok, "'%s' should not decode", bad)
	}
	// Output too small.
	small: [3]u8
	_, ok = base64_decode("Zm9vYmFy", small[:])
	testing.expect(t, !ok)
}

@(test)
test_fingerprint :: proc(t: ^testing.T) {
	fp, ok := parse_fingerprint(
		"DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74",
	)
	testing.expect(t, ok && fp[0] == 0xda && fp[1] == 0xd1 && fp[31] == 0x74)
	fp, ok = parse_fingerprint("dad156b8faca23121e77fbf8a88519e17ef1a2c583b24e551b817923e1672e74")
	testing.expect(t, ok && fp[0] == 0xda && fp[31] == 0x74)
	for bad in ([]string{"", "DA:D1", "DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E", "DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74:00", "DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:7G", "DAD1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74", "DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74:"}) {
		_, ok = parse_fingerprint(bad)
		testing.expectf(t, !ok, "'%s' should not parse", bad)
	}
}
