// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
#+build !darwin
#+build !freebsd
#+build !openbsd
#+build !netbsd
#+build !windows
package main

// No crypto library is linked, so the GUI cannot generate keys: no "New profile"
// in the plus menu outside the simulation, no key pin or key request in the
// profile view.

KEYGEN :: false

key_new :: proc(key_type, common_name: string) -> (cert, key, pin: string, ok: bool) {
	return
}

cert_pin :: proc(cert_pem: string, allocator := context.allocator) -> (pin, key_label, common_name: string, ok: bool) {
	return
}

request_new :: proc(key_type, common_name: string) -> (csr, key, pin: string, ok: bool) {
	return
}

cert_load :: proc(data: []u8, allocator := context.allocator) -> (c: Cert_Read, ok: bool) {
	return
}

key_spki :: proc(key_pem: string) -> (spki: [32]u8, ok: bool) {
	return
}

self_signed_cert :: proc(key_pem, common_name: string, allocator := context.allocator) -> (cert: string, ok: bool) {
	return
}
