// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// One-shot digests.

sha1 :: proc "contextless" (data: []u8) -> (out: [SHA1_LEN]u8) {
	SHA1(raw_data(data), csize(len(data)), &out[0])
	return
}

sha256 :: proc "contextless" (data: []u8) -> (out: [SHA256_LEN]u8) {
	SHA256(raw_data(data), csize(len(data)), &out[0])
	return
}

sha512 :: proc "contextless" (data: []u8) -> (out: [SHA512_LEN]u8) {
	SHA512(raw_data(data), csize(len(data)), &out[0])
	return
}
