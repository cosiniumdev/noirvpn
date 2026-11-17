// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// Fills `buf` with cryptographically secure random bytes.
// Returns false if the library could not produce them. Then the caller must
// not use `buf`.
random_bytes :: proc "contextless" (buf: []u8) -> bool {
	p := raw_data(buf)
	left := len(buf)
	for left > 0 {
		n := min(left, 1 << 30)
		if RAND_bytes(p, cint(n)) != 1 {
			ERR_clear_error()
			return false
		}
		p = p[n:]
		left -= n
	}
	return true
}
