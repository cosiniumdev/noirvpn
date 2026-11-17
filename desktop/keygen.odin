// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd, windows
package main

// Key generation, key requests and key pins with proto/ossl. keygen_none.odin
// is the form for systems where the GUI does not link the crypto library.

import "core:strings"
import "noir:proto/ossl"
import pf "profiles"

KEYGEN :: true

// key_new generates a key of the kind `key_type` (pf.KEY_*) and a self-signed
// certificate. The caller wipes `key` (pf.wipe_string).
key_new :: proc(key_type, common_name: string) -> (cert, key, pin: string, ok: bool) {
	kind := identity_kind(key_type)
	id, err := ossl.identity_generate(kind, common_name)
	if err != .None {
		return
	}
	cert, key = id.cert_pem, id.key_pem
	pin = pf.pin_text(kind == .Mldsa65, id.spki_sha256)
	return cert, key, pin, true
}

// cert_pin is the pin, the key type and the common name of the first
// certificate in a PEM text.
cert_pin :: proc(cert_pem: string, allocator := context.allocator) -> (pin, key_label, common_name: string, ok: bool) {
	info, err := ossl.cert_read(transmute([]u8)cert_pem, context.temp_allocator)
	if err != .None {
		return
	}
	return pf.pin_text(info.key_type == .Mldsa65, info.spki_sha256, allocator), strings.clone(key_type_label(info.key_type), allocator), strings.clone(info.common_name, allocator), true
}

// request_new generates a new key of the kind `key_type` and a certificate
// request for it. The caller wipes `key`.
request_new :: proc(key_type, common_name: string) -> (csr, key, pin: string, ok: bool) {
	kind := identity_kind(key_type)
	c, err := ossl.csr_new(kind, common_name)
	if err != .None {
		return
	}
	return c.csr_pem, c.key_pem, pf.pin_text(kind == .Mldsa65, c.spki_sha256), true
}

// cert_load reads a certificate file or a pasted text: PEM (the leaf and a
// chain) or one DER certificate.
cert_load :: proc(data: []u8, allocator := context.allocator) -> (c: Cert_Read, ok: bool) {
	info: ossl.Cert_Info
	err: ossl.Error
	if strings.contains(string(data), "-----BEGIN") {
		info, err = ossl.cert_read(data, context.temp_allocator)
	} else {
		info, err = ossl.cert_read_der(data, context.temp_allocator)
	}
	if err != .None {
		return
	}
	return Cert_Read {
			cert = strings.clone(info.cert_pem, allocator),
			chain = strings.clone(info.chain_pem, allocator),
			subject = strings.clone(info.subject, allocator),
			issuer = strings.clone(info.issuer, allocator),
			common_name = strings.clone(info.common_name, allocator),
			not_before = strings.clone(info.not_before, allocator),
			not_after = strings.clone(info.not_after, allocator),
			pin = pf.pin_text(info.key_type == .Mldsa65, info.spki_sha256, allocator),
			spki = info.spki_sha256,
		},
		true
}

// key_spki is the SHA-256 of the public key of a private key (PEM).
key_spki :: proc(key_pem: string) -> (spki: [32]u8, ok: bool) {
	h, err := ossl.key_spki_sha256(transmute([]u8)key_pem)
	return h, err == .None
}

// self_signed_cert generates a self-signed certificate for a private key (PEM).
self_signed_cert :: proc(key_pem, common_name: string, allocator := context.allocator) -> (cert: string, ok: bool) {
	c, err := ossl.identity_self_sign(transmute([]u8)key_pem, common_name, allocator)
	return c, err == .None
}

@(private = "file")
identity_kind :: proc(key_type: string) -> ossl.Identity_Kind {
	switch key_type {
	case pf.KEY_MLDSA65:
		return .Mldsa65
	case pf.KEY_P256:
		return .P256
	}
	return .Ed25519
}

@(private = "file")
key_type_label :: proc(t: ossl.Pub_Key_Type) -> string {
	switch t {
	case .Ed25519:
		return "Ed25519"
	case .P256:
		return "ECDSA P-256"
	case .Mldsa65:
		return "ML-DSA-65"
	case .Rsa:
		return "RSA"
	case .Ec:
		return "ECDSA"
	case .Other:
	}
	return "Other"
}
