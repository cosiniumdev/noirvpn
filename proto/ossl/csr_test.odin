// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:strings"
import "core:testing"

@(private = "file")
ED_CLIENT_CERT := #load("testdata/ed25519_client.crt.pem")
@(private = "file")
ED_CLIENT_DER := #load("testdata/ed25519_client.crt.der")
@(private = "file")
ED_CLIENT_KEY := #load("testdata/ed25519_client.key.pem")
@(private = "file")
ED_CLIENT_SPKI := #load("testdata/ed25519_client.spki.der")
@(private = "file")
P256_CLIENT_CERT := #load("testdata/p256_client.crt.pem")
@(private = "file")
P256_CLIENT_KEY := #load("testdata/p256_client.key.pem")
@(private = "file")
RSA_CLIENT_CERT := #load("testdata/rsa_client.crt.pem")
@(private = "file")
MLDSA_CLIENT_CERT := #load("testdata/mldsa65_client.crt.pem")
@(private = "file")
LEAF_CLIENT_CERT := #load("testdata/leaf_client.crt.pem")
@(private = "file")
CHAIN_CLIENT_CERT := #load("testdata/chain_client.crt.pem")
@(private = "file")
CA_CERT := #load("testdata/ca.crt.pem")
@(private = "file")
RSA_CLIENT_KEY_PKCS1 := #load("testdata/plain_rsa_client.key.pem")
@(private = "file")
P256_CLIENT_KEY_SEC1 := #load("testdata/plain_sec1_p256_client.key.pem")
@(private = "file")
ENCRYPTED_KEY := #load("testdata/keypass_pkcs8_p256.key.pem")

// The extensionRequest value that every request has (see csr.odin).
@(private = "file")
WANT_EXTENSIONS :: "30 25 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 07 80 30 13 06 03 55 1d 25 04 0c 30 0a 06 08 2b 06 01 05 05 07 03 02"

@(private = "file")
contains_bytes :: proc(hay, needle: []u8) -> bool {
	return strings.contains(string(hay), string(needle))
}

@(private = "file")
check_csr :: proc(t: ^testing.T, kind: Identity_Kind) {
	c, err := csr_new(kind, "alice phone")
	defer csr_destroy(&c)
	if !testing.expectf(t, err == .None, "%v: csr_new: %v", kind, err) {
		return
	}
	testing.expect(t, strings.has_prefix(c.csr_pem, "-----BEGIN CERTIFICATE REQUEST-----\n"))
	testing.expect(t, strings.has_prefix(c.key_pem, "-----BEGIN PRIVATE KEY-----\n"))

	// The library reads the request back, and its signature is good.
	bio := pem_bio(transmute([]u8)c.csr_pem)
	defer BIO_free(bio)
	req := PEM_read_bio_X509_REQ(bio, nil, no_password, nil)
	if !testing.expectf(t, req != nil, "%v: the request can be read", kind) {
		return
	}
	defer X509_REQ_free(req)
	pub := X509_REQ_get0_pubkey(req)
	testing.expectf(t, pub != nil && X509_REQ_verify(req, pub) == 1, "%v: the signature of the request is good", kind)
	ERR_clear_error()

	// The key of the request is the new key: same pin three ways.
	buf: [SPKI_MAX]u8
	der := pkey_spki_der(pub, buf[:])
	testing.expect(t, der != nil && sha256(der) == c.spki_sha256)
	kh, kerr := key_spki_sha256(transmute([]u8)c.key_pem)
	testing.expect(t, kerr == .None && kh == c.spki_sha256)

	// The DER has version 0, the name and the extensions.
	n := i2d_X509_REQ(req, nil)
	testing.expect(t, n > 0)
	out := make([]u8, n, context.temp_allocator)
	p := raw_data(out)
	testing.expect_value(t, i2d_X509_REQ(req, &p), n)
	testing.expect(t, contains_bytes(out, unhex("02 01 00")), "version 1 (0)")
	testing.expect(t, contains_bytes(out, transmute([]u8)string("alice phone")))
	testing.expect(t, contains_bytes(out, unhex(WANT_EXTENSIONS)), "the extensionRequest value")
	testing.expect(t, contains_bytes(out, unhex("06 09 2a 86 48 86 f7 0d 01 09 0e")), "the extensionRequest OID")
	switch kind {
	case .P256:
		testing.expect(t, contains_bytes(out, unhex("06 08 2a 86 48 ce 3d 04 03 02")), "ecdsa-with-SHA256")
	case .Ed25519:
		testing.expect(t, contains_bytes(out, unhex("30 05 06 03 2b 65 70")), "Ed25519 signature")
	case .Mldsa65:
		testing.expect(t, contains_bytes(out, unhex("06 09 60 86 48 01 65 03 04 03 12")), "ML-DSA-65 signature")
	}
}

@(test)
test_csr_new :: proc(t: ^testing.T) {
	check_csr(t, .Ed25519)
	check_csr(t, .P256)
	check_csr(t, .Mldsa65)
	// Two calls create two keys.
	a, _ := csr_new(.Ed25519, "x")
	defer csr_destroy(&a)
	b, _ := csr_new(.Ed25519, "x")
	defer csr_destroy(&b)
	testing.expect(t, a.spki_sha256 != b.spki_sha256)
}

@(test)
test_csr_new_bad_name :: proc(t: ^testing.T) {
	_, e1 := csr_new(.Ed25519, "")
	testing.expect_value(t, e1, Error.Bad_Argument)
	_, e2 := csr_new(.P256, strings.repeat("a", 65, context.temp_allocator))
	testing.expect_value(t, e2, Error.Bad_Argument)
	c, e3 := csr_new(.P256, strings.repeat("a", 64, context.temp_allocator))
	testing.expect_value(t, e3, Error.None)
	csr_destroy(&c)
	_, e4 := csr_new(.Ed25519, "bad \xff utf-8")
	testing.expect_value(t, e4, Error.Bad_Argument)
}

@(test)
test_identity_generate_p256 :: proc(t: ^testing.T) {
	id, err := identity_generate(.P256, "p256 laptop")
	defer identity_destroy(&id)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, cert_key_kind(transmute([]u8)id.cert_pem), Key_Kind.Ec)
	_, known := cert_identity_kind(transmute([]u8)id.cert_pem)
	testing.expect(t, !known, "cert_identity_kind knows Ed25519 and ML-DSA-65 only")
}

@(test)
test_cert_read_generated :: proc(t: ^testing.T) {
	for kind in Identity_Kind {
		id, err := identity_generate(kind, "alice laptop")
		defer identity_destroy(&id)
		if !testing.expectf(t, err == .None, "%v: identity_generate: %v", kind, err) {
			continue
		}
		info, rerr := cert_read(transmute([]u8)id.cert_pem)
		defer cert_info_destroy(&info)
		if !testing.expectf(t, rerr == .None, "%v: cert_read: %v", kind, rerr) {
			continue
		}
		want := [Identity_Kind]Pub_Key_Type {
			.Ed25519 = .Ed25519,
			.Mldsa65 = .Mldsa65,
			.P256    = .P256,
		}
		testing.expect_value(t, info.key_type, want[kind])
		testing.expect(t, info.spki_sha256 == id.spki_sha256)
		testing.expect_value(t, info.cert_pem, id.cert_pem)
		testing.expect_value(t, info.chain_pem, "")
		testing.expect_value(t, info.chain_count, 0)
		testing.expect_value(t, info.subject, "CN=alice laptop")
		testing.expect_value(t, info.issuer, "CN=alice laptop")
		testing.expect_value(t, info.common_name, "alice laptop")
		testing.expectf(t, info.self_signed, "%v: self-signed", kind)
		testing.expect(t, len(info.not_before) == 20 && strings.has_suffix(info.not_before, "Z") && info.not_before[10] == 'T')
		testing.expect(t, info.not_before < info.not_after)
		kh, kerr := key_spki_sha256(transmute([]u8)id.key_pem)
		testing.expect(t, kerr == .None && kh == info.spki_sha256)
	}
}

@(test)
test_cert_read_files :: proc(t: ^testing.T) {
	// A certificate that a CA signed: the order of RFC 2253.
	info, err := cert_read(LEAF_CLIENT_CERT)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, info.subject, "CN=Client-1, O=Noir Test, C=KG")
	testing.expect_value(t, info.issuer, "CN=noir-test-leaf-ca")
	testing.expect_value(t, info.common_name, "Client-1")
	testing.expect(t, !info.self_signed)
	cert_info_destroy(&info)

	// Times, pin, and the same facts from DER.
	pem, perr := cert_read(ED_CLIENT_CERT)
	defer cert_info_destroy(&pem)
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, pem.not_before, "2026-11-09T00:10:47Z")
	testing.expect_value(t, pem.not_after, "2126-10-16T00:10:47Z")
	testing.expect(t, pem.spki_sha256 == sha256(ED_CLIENT_SPKI))
	testing.expect(t, pem.self_signed)
	der, derr := cert_read_der(ED_CLIENT_DER)
	defer cert_info_destroy(&der)
	testing.expect_value(t, derr, Error.None)
	testing.expect_value(t, der.cert_pem, pem.cert_pem)
	testing.expect_value(t, der.subject, pem.subject)
	testing.expect_value(t, der.not_after, pem.not_after)
	testing.expect(t, der.spki_sha256 == pem.spki_sha256)
	// DER with a byte more, or cut short, is no certificate.
	longer := make([]u8, len(ED_CLIENT_DER) + 1, context.temp_allocator)
	copy(longer, ED_CLIENT_DER)
	_, e1 := cert_read_der(longer)
	testing.expect_value(t, e1, Error.Bad_Cert)
	_, e2 := cert_read_der(ED_CLIENT_DER[:len(ED_CLIENT_DER) - 1])
	testing.expect_value(t, e2, Error.Bad_Cert)

	// The key types.
	types := [?]struct {
		pem:  []u8,
		want: Pub_Key_Type,
	}{{P256_CLIENT_CERT, .P256}, {RSA_CLIENT_CERT, .Rsa}, {MLDSA_CLIENT_CERT, .Mldsa65}, {ED_CLIENT_CERT, .Ed25519}}
	for c in types {
		i, e := cert_read(c.pem)
		testing.expect_value(t, e, Error.None)
		testing.expect_value(t, i.key_type, c.want)
		cert_info_destroy(&i)
	}
}

@(test)
test_cert_read_chain :: proc(t: ^testing.T) {
	text := strings.concatenate({"some words before\r\n", string(CHAIN_CLIENT_CERT), "between\n", string(CA_CERT), "after"}, context.temp_allocator)
	info, err := cert_read(transmute([]u8)text)
	defer cert_info_destroy(&info)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, info.chain_count, 1)
	testing.expect_value(t, info.common_name, "noir-test-chain-client")
	ca, _ := cert_read(CA_CERT)
	defer cert_info_destroy(&ca)
	testing.expect_value(t, info.chain_pem, ca.cert_pem)
	testing.expect_value(t, info.cert_pem, string(CHAIN_CLIENT_CERT))

	// CRLF line ends.
	crlf, _ := strings.replace_all(string(CHAIN_CLIENT_CERT), "\n", "\r\n", context.temp_allocator)
	ci, ce := cert_read(transmute([]u8)crlf)
	testing.expect_value(t, ce, Error.None)
	testing.expect_value(t, ci.cert_pem, info.cert_pem)
	cert_info_destroy(&ci)

	// No certificate, or a broken second block.
	_, e1 := cert_read(transmute([]u8)string("hello"))
	testing.expect_value(t, e1, Error.Bad_Cert)
	_, e2 := cert_read(ED_CLIENT_KEY)
	testing.expect_value(t, e2, Error.Bad_Cert)
	broken := strings.concatenate({string(CHAIN_CLIENT_CERT), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}, context.temp_allocator)
	_, e3 := cert_read(transmute([]u8)broken)
	testing.expect_value(t, e3, Error.Bad_Cert)
	_, e4 := cert_read(nil)
	testing.expect_value(t, e4, Error.Bad_Cert)
}

@(test)
test_key_spki_sha256 :: proc(t: ^testing.T) {
	h, err := key_spki_sha256(ED_CLIENT_KEY)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, h == sha256(ED_CLIENT_SPKI))
	p, perr := key_spki_sha256(P256_CLIENT_KEY)
	testing.expect_value(t, perr, Error.None)
	cert_pin, _ := cert_spki_sha256(P256_CLIENT_CERT)
	testing.expect(t, p == cert_pin)
	testing.expect(t, p != h)
	// The traditional forms: SEC1 and PKCS#1.
	s, serr := key_spki_sha256(P256_CLIENT_KEY_SEC1)
	testing.expect(t, serr == .None && s == cert_pin)
	r, rerr := key_spki_sha256(RSA_CLIENT_KEY_PKCS1)
	rsa_pin, _ := cert_spki_sha256(RSA_CLIENT_CERT)
	testing.expect(t, rerr == .None && r == rsa_pin)
	_, e1 := key_spki_sha256(ENCRYPTED_KEY)
	testing.expect_value(t, e1, Error.Key_Encrypted)
	_, e2 := key_spki_sha256(ED_CLIENT_CERT)
	testing.expect_value(t, e2, Error.Bad_Key)
}

@(test)
test_identity_self_sign :: proc(t: ^testing.T) {
	keys := make([dynamic]string, context.temp_allocator)
	for kind in Identity_Kind {
		c, err := csr_new(kind, "k")
		testing.expect_value(t, err, Error.None)
		append(&keys, strings.clone(c.key_pem, context.temp_allocator))
		csr_destroy(&c)
	}
	append(&keys, string(P256_CLIENT_KEY_SEC1), string(RSA_CLIENT_KEY_PKCS1), string(ED_CLIENT_KEY))
	for key, i in keys {
		cert, err := identity_self_sign(transmute([]u8)key, "erin laptop")
		defer delete(cert)
		if !testing.expectf(t, err == .None, "key %d: identity_self_sign: %v", i, err) {
			continue
		}
		info, rerr := cert_read(transmute([]u8)cert)
		testing.expect_value(t, rerr, Error.None)
		kh, _ := key_spki_sha256(transmute([]u8)key)
		testing.expectf(t, info.spki_sha256 == kh, "key %d: the pin of the certificate is the pin of the key", i)
		testing.expectf(t, info.self_signed && info.subject == "CN=erin laptop", "key %d: self-signed for the name", i)
		cert_info_destroy(&info)
	}
	_, e1 := identity_self_sign(ENCRYPTED_KEY, "x")
	testing.expect_value(t, e1, Error.Key_Encrypted)
	_, e2 := identity_self_sign(ED_CLIENT_CERT, "x")
	testing.expect_value(t, e2, Error.Bad_Key)
	_, e3 := identity_self_sign(ED_CLIENT_KEY, "")
	testing.expect_value(t, e3, Error.Bad_Argument)
}
