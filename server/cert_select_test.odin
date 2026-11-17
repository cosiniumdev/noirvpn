// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"
import "noir:proto/ossl"

@(private = "file")
parsed :: proc(text: string, buf: ^[ossl.SERIAL_BYTES_MAX]u8) -> ([]u8, bool) {
	n, ok := serial_parse(text, buf)
	return buf[:n], ok
}

@(test)
serial_parse_forms :: proc(t: ^testing.T) {
	buf: [ossl.SERIAL_BYTES_MAX]u8
	b, ok := parsed("0a1B", &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 2)
	testing.expect(t, b[0] == 0x0a && b[1] == 0x1b)

	// Colons and spaces are ignored; an odd digit count is padded on the left.
	b, ok = parsed("A:bc", &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 2)
	testing.expect(t, b[0] == 0x0a && b[1] == 0xbc)

	// Leading zeros are not significant.
	b, ok = parsed("000000ff", &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 1)
	testing.expect_value(t, b[0], 0xff)
	b, ok = parsed("00:0f", &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 1)
	testing.expect_value(t, b[0], 0x0f)

	// Zero is no bytes.
	b, ok = parsed("0", &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 0)
	b, ok = parsed("00:00", &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 0)
}

@(test)
serial_parse_limits :: proc(t: ^testing.T) {
	buf: [ossl.SERIAL_BYTES_MAX]u8
	_, ok := serial_parse("", &buf)
	testing.expect(t, !ok)
	_, ok = serial_parse(" : ", &buf)
	testing.expect(t, !ok)
	_, ok = serial_parse("0g", &buf)
	testing.expect(t, !ok)
	_, ok = serial_parse("0x10", &buf)
	testing.expect(t, !ok)
	_, ok = serial_parse("-1", &buf)
	testing.expect(t, !ok)

	// 20 bytes fit (also with leading zeros), 21 bytes do not.
	full :: "ffffffffffffffffffffffffffffffffffffffff"
	b: []u8
	b, ok = parsed(full, &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 20)
	b, ok = parsed("0000:" + full, &buf)
	testing.expect(t, ok)
	testing.expect_value(t, len(b), 20)
	_, ok = serial_parse("01" + full, &buf)
	testing.expect(t, !ok)
}

@(test)
cert_selected_rules :: proc(t: ^testing.T) {
	a := []u8{0x01, 0xab}
	testing.expect(t, cert_selected(a, "", "alice", []u8{0x01, 0xab}))
	testing.expect(t, !cert_selected(a, "", "alice", []u8{0x01, 0xac}))
	testing.expect(t, !cert_selected(a, "", "alice", []u8{0xab}))
	testing.expect(t, !cert_selected(a, "", "alice", []u8{0x01, 0xab, 0x00}))

	// With a name, the CN must match too (ASCII case ignored).
	testing.expect(t, cert_selected(a, "alice", "alice", a))
	testing.expect(t, cert_selected(a, "ALICE", "alice", a))
	testing.expect(t, !cert_selected(a, "bob", "alice", a))
	testing.expect(t, !cert_selected(a, "alice", "", a))

	// The serial 0 (no bytes) matches only the same.
	testing.expect(t, cert_selected(nil, "", "x", nil))
	testing.expect(t, !cert_selected(nil, "", "x", a))
}
