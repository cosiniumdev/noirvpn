// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "noir:proto/ossl"

// Choosing sessions by their client certificate (`peer.kick` with `serial`).

// A certificate serial number from text: hex digits (any case), colons and
// spaces ignored. Leading zeros do not count.
// - `out[:n]` is the number as big-endian bytes with no leading zero byte
//   (the serial 0 is 0 bytes).
// - False for no digit, any other character, or more than
//   `ossl.SERIAL_BYTES_MAX` bytes.
serial_parse :: proc(text: string, out: ^[ossl.SERIAL_BYTES_MAX]u8) -> (n: int, ok: bool) {
	out^ = {}
	nib: [ossl.SERIAL_BYTES_MAX * 2]u8
	m := 0 // digits kept, after the leading zeros
	any_digit := false
	for ch in transmute([]u8)text {
		v: u8
		switch ch {
		case '0' ..= '9':
			v = ch - '0'
		case 'a' ..= 'f':
			v = ch - 'a' + 10
		case 'A' ..= 'F':
			v = ch - 'A' + 10
		case ':', ' ':
			continue
		case:
			return 0, false
		}
		any_digit = true
		if m == 0 && v == 0 {
			continue
		}
		if m == len(nib) {
			return 0, false
		}
		nib[m] = v
		m += 1
	}
	if !any_digit {
		return 0, false
	}
	n = (m + 1) / 2
	// Fill from the right: the last digit is the low half of the last byte.
	for i in 0 ..< m {
		j := m - 1 - i // digit position from the right
		b := n - 1 - j / 2
		out[b] |= nib[i] if j % 2 == 0 else nib[i] << 4
	}
	return n, true
}

// Does a session with the client certificate (`cn`, `serial` as bytes from
// `serial_parse`) match the selector? `want_name` is "" if the selector has no
// name. Else the CN must be the same (ASCII case ignored).
cert_selected :: proc "contextless" (want_serial: []u8, want_name: string, cn: string, serial: []u8) -> bool {
	if len(want_serial) != len(serial) {
		return false
	}
	for i in 0 ..< len(serial) {
		if want_serial[i] != serial[i] {
			return false
		}
	}
	return want_name == "" || ascii_fold_equal(want_name, cn)
}

@(private = "file")
ascii_fold_equal :: proc "contextless" (a, b: string) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
