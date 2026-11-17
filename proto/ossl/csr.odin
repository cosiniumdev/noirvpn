// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:mem"
import "core:strings"

// A new key with a certificate signing request, and the facts of a CA-signed
// certificate for it.
//
//	csr_new(kind, common_name) -> (Csr, Error)          new key (PKCS#8 PEM) and CSR (PEM)
//	csr_destroy(&c)                                     wipes and frees the key text
//	cert_read(pem) -> (Cert_Info, Error)                every CERTIFICATE block: the leaf and the chain
//	cert_read_der(der) -> (Cert_Info, Error)            one DER certificate
//	cert_info_destroy(&info)
//	key_spki_sha256(key_pem) -> (hash, Error)           the pin of an unencrypted private key
//
// The request (PKCS#10, RFC 2986): version 1, a subject with only the common
// name, and an extensionRequest attribute (RFC 2985) with the extensions that a
// server with `remote-cert-tls client` asks for: key usage digitalSignature
// (critical), extended key usage clientAuth. The key signs it: SHA-256 for P-256,
// no digest for Ed25519 and ML-DSA-65.

// A new key and its request. The key is PKCS#8 and not encrypted: a secret.
// Free both texts with `csr_destroy`, which wipes the key first.
Csr :: struct {
	key_pem:     string,
	csr_pem:     string,
	spki_sha256: [SHA256_LEN]u8, // the pin
}

// The kind of the public key of a certificate.
Pub_Key_Type :: enum u8 {
	Other,
	Ed25519,
	P256, // ECDSA on P-256
	Mldsa65, // ML-DSA-65
	Rsa,
	Ec, // ECDSA on another curve
}

// What `cert_read` tells about a certificate. The strings are allocated; free
// them with `cert_info_destroy`.
Cert_Info :: struct {
	cert_pem:    string, // the first certificate (the leaf), PEM
	chain_pem:   string, // the other certificates in order, PEM; "" when none
	chain_count: int,
	spki_sha256: [SHA256_LEN]u8, // the pin of the leaf
	key_type:    Pub_Key_Type,
	subject:     string, // one line in the order of RFC 2253: "CN=alice, O=Example"
	common_name: string, // the last common name in UTF-8; "" when none
	issuer:      string,
	self_signed: bool, // the issuer is the subject and the key of the certificate signed it
	not_before:  string, // ISO 8601 in UTC: "2026-11-16T10:00:00Z"
	not_after:   string,
}

// The value of the extensionRequest attribute, DER (RFC 5280):
// Extensions ::= SEQUENCE {
//   SEQUENCE { keyUsage, critical TRUE, OCTET STRING { BIT STRING digitalSignature } },
//   SEQUENCE { extKeyUsage, OCTET STRING { SEQUENCE { id-kp-clientAuth } } } }
@(private = "file")
CSR_EXTENSIONS := [?]u8 {
	0x30, 0x25,
	0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80,
	0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c,
	0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
}

// The algorithm identifiers in a SubjectPublicKeyInfo (RFC 3279, RFC 4055,
// RFC 5480, RFC 8410, FIPS 204), and the curve P-256 (a parameter of id-ecPublicKey).
@(private = "file")
OID_RSA := [?]u8{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
@(private = "file")
OID_RSA_PSS := [?]u8{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}
@(private = "file")
OID_EC := [?]u8{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
@(private = "file")
OID_P256 := [?]u8{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
@(private = "file")
OID_ED25519 := [?]u8{0x2b, 0x65, 0x70}
@(private = "file")
OID_MLDSA65 := [?]u8{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}

// Creates a new key of `kind` and a request for it. `common_name` is UTF-8, 1 to
// 64 bytes. The strings are allocated with `allocator`.
csr_new :: proc(kind: Identity_Kind, common_name: string, allocator := context.allocator) -> (c: Csr, err: Error) {
	if len(common_name) == 0 || len(common_name) > IDENTITY_CN_MAX {
		return {}, .Bad_Argument
	}
	pkey := new_key(kind)
	if pkey == nil {
		return {}, .Lib
	}
	defer EVP_PKEY_free(pkey)
	req := X509_REQ_new()
	if req == nil {
		ERR_clear_error()
		return {}, .Alloc
	}
	defer X509_REQ_free(req)
	if err = fill_request(req, pkey, sign_md(kind), common_name); err != .None {
		ERR_clear_error()
		return {}, err
	}
	buf: [SPKI_MAX]u8
	der := pkey_spki_der(pkey, buf[:])
	if der == nil {
		return {}, .Lib
	}
	spki := sha256(der)
	csr := pem_text(nil, nil, allocator, req)
	if csr == "" {
		return {}, .Lib
	}
	key := pem_text(nil, pkey, allocator)
	if key == "" {
		delete(csr, allocator)
		return {}, .Lib
	}
	return Csr{key_pem = key, csr_pem = csr, spki_sha256 = spki}, .None
}

// Wipes the key text and frees both texts.
csr_destroy :: proc(c: ^Csr, allocator := context.allocator) {
	wipe_free(c.key_pem, allocator)
	delete(c.csr_pem, allocator)
	c^ = {}
}

@(private = "file")
fill_request :: proc(req: X509_REQ, pkey: EVP_PKEY, md: EVP_MD, common_name: string) -> Error {
	if X509_REQ_set_version(req, 0) != 1 || X509_REQ_set_pubkey(req, pkey) != 1 {
		return .Lib
	}
	name := X509_REQ_get_subject_name(req) // borrowed
	if name == nil {
		return .Lib
	}
	if X509_NAME_add_entry_by_NID(name, NID_COMMON_NAME, MBSTRING_UTF8, raw_data(common_name), cint(len(common_name)), -1, 0) != 1 {
		return .Bad_Argument
	}
	if X509_REQ_add1_attr_by_NID(req, NID_EXT_REQ, V_ASN1_SEQUENCE, &CSR_EXTENSIONS[0], cint(len(CSR_EXTENSIONS))) != 1 {
		return .Lib
	}
	if X509_REQ_sign(req, pkey, md) <= 0 {
		return .Lib
	}
	return .None
}

// Reads every certificate of a PEM text: first is the leaf, the rest the chain.
// Text around the blocks is skipped.
//
// Errors:
//   .Bad_Cert      the text has no certificate, or a CERTIFICATE block that cannot be read
//   .Lib, .Alloc   the library fails
cert_read :: proc(pem: []u8, allocator := context.allocator) -> (info: Cert_Info, err: Error) {
	bio := pem_bio(pem)
	if bio == nil {
		ERR_clear_error()
		return {}, .Bad_Cert
	}
	defer BIO_free(bio)
	leaf := PEM_read_bio_X509(bio, nil, no_password, nil)
	if leaf == nil {
		ERR_clear_error()
		return {}, .Bad_Cert
	}
	defer X509_free(leaf)
	chain := strings.builder_make(allocator)
	count := 0
	for {
		x := PEM_read_bio_X509(bio, nil, no_password, nil)
		if x == nil {
			break
		}
		text := pem_text(x, nil, allocator)
		X509_free(x)
		if text == "" {
			strings.builder_destroy(&chain)
			return {}, .Lib
		}
		strings.write_string(&chain, text)
		delete(text, allocator)
		count += 1
	}
	ERR_clear_error() // the loop above ends with a "no start line" entry
	// A block that the library could not read ends the loop early.
	if 1 + count < strings.count(string(pem), "-----BEGIN CERTIFICATE-----") {
		strings.builder_destroy(&chain)
		return {}, .Bad_Cert
	}
	info, err = cert_info_of(leaf, allocator)
	if err != .None {
		strings.builder_destroy(&chain)
		return {}, err
	}
	if count > 0 {
		info.chain_pem = strings.to_string(chain)
	} else {
		strings.builder_destroy(&chain)
	}
	info.chain_count = count
	return info, .None
}

// Reads one DER certificate (a binary .cer or .der file). The whole input must
// be the certificate. Errors as `cert_read`.
cert_read_der :: proc(der: []u8, allocator := context.allocator) -> (info: Cert_Info, err: Error) {
	if len(der) == 0 || len(der) > 1 << 30 {
		return {}, .Bad_Cert
	}
	p := raw_data(der)
	x := d2i_X509(nil, &p, clong(len(der)))
	if x == nil {
		ERR_clear_error()
		return {}, .Bad_Cert
	}
	defer X509_free(x)
	if uintptr(p) - uintptr(raw_data(der)) != uintptr(len(der)) {
		return {}, .Bad_Cert
	}
	return cert_info_of(x, allocator)
}

cert_info_destroy :: proc(info: ^Cert_Info, allocator := context.allocator) {
	delete(info.cert_pem, allocator)
	delete(info.chain_pem, allocator)
	delete(info.subject, allocator)
	delete(info.common_name, allocator)
	delete(info.issuer, allocator)
	delete(info.not_before, allocator)
	delete(info.not_after, allocator)
	info^ = {}
}

// SHA-256 of the DER SubjectPublicKeyInfo of the private key in `key_pem` (its
// pin; a certificate for that key has the same pin). Errors: .Key_Encrypted for
// an encrypted key, .Bad_Key for a text with no readable key.
key_spki_sha256 :: proc(key_pem: []u8) -> (hash: [SHA256_LEN]u8, err: Error) {
	bio := pem_bio(key_pem)
	if bio == nil {
		ERR_clear_error()
		return {}, .Bad_Key
	}
	defer BIO_free(bio)
	pkey := PEM_read_bio_PrivateKey(bio, nil, no_password, nil)
	if pkey == nil {
		ERR_clear_error()
		return {}, .Key_Encrypted if key_pem_encrypted(key_pem) else .Bad_Key
	}
	defer EVP_PKEY_free(pkey)
	buf: [SPKI_MAX]u8
	der := pkey_spki_der(pkey, buf[:])
	if der == nil {
		return {}, .Lib
	}
	return sha256(der), .None
}

@(private = "file")
cert_info_of :: proc(x: X509, allocator: mem.Allocator) -> (info: Cert_Info, err: Error) {
	// The SubjectPublicKeyInfo as the certificate has it: this works for a key
	// type that the library cannot use, too.
	buf: [SPKI_MAX]u8
	pub := X509_get_X509_PUBKEY(x) // borrowed
	if pub == nil {
		ERR_clear_error()
		return {}, .Bad_Cert
	}
	n := i2d_X509_PUBKEY(pub, nil)
	if n <= 0 || int(n) > len(buf) {
		ERR_clear_error()
		return {}, .Bad_Cert
	}
	at := raw_data(buf[:])
	if i2d_X509_PUBKEY(pub, &at) != n {
		ERR_clear_error()
		return {}, .Bad_Cert
	}
	der := buf[:n]
	info.spki_sha256 = sha256(der)
	info.key_type = spki_key_type(der)

	nb: [ISO_TIME_LEN]u8
	na: [ISO_TIME_LEN]u8
	if !asn1_time_iso(X509_get0_notBefore(x), &nb) || !asn1_time_iso(X509_get0_notAfter(x), &na) {
		return {}, .Bad_Cert
	}
	subject := X509_get_subject_name(x) // borrowed
	issuer := X509_get_issuer_name(x) // borrowed
	if subject == nil || issuer == nil {
		ERR_clear_error()
		return {}, .Bad_Cert
	}
	if X509_NAME_cmp(subject, issuer) == 0 {
		if key := X509_get0_pubkey(x); key != nil {
			info.self_signed = X509_verify(x, key) == 1
		}
		ERR_clear_error()
	}
	cn: [256]u8
	cn_len, cn_fail := common_name_text(x, cn[:])
	if cn_fail != .None {
		cn_len = 0
	}

	info.cert_pem = pem_text(x, nil, allocator)
	info.subject = name_line(subject, allocator)
	info.issuer = name_line(issuer, allocator)
	info.common_name = strings.clone(string(cn[:cn_len]), allocator)
	info.not_before = strings.clone(string(nb[:]), allocator)
	info.not_after = strings.clone(string(na[:]), allocator)
	if info.cert_pem == "" {
		cert_info_destroy(&info, allocator)
		return {}, .Lib
	}
	return info, .None
}

// The kind of key of a DER SubjectPublicKeyInfo.
@(private = "file")
spki_key_type :: proc(der: []u8) -> Pub_Key_Type {
	outer, _ := der_take(der, 0x30)
	alg, _ := der_take(outer, 0x30)
	oid, params := der_take(alg, 0x06)
	switch {
	case bytes_equal(oid, OID_ED25519[:]):
		return .Ed25519
	case bytes_equal(oid, OID_MLDSA65[:]):
		return .Mldsa65
	case bytes_equal(oid, OID_RSA[:]), bytes_equal(oid, OID_RSA_PSS[:]):
		return .Rsa
	case bytes_equal(oid, OID_EC[:]):
		curve, _ := der_take(params, 0x06)
		return .P256 if bytes_equal(curve, OID_P256[:]) else .Ec
	}
	return .Other
}

// A name on one line (NAME_RFC2253_FLAGS), or "" when it cannot be printed.
@(private = "file")
name_line :: proc(name: X509_NAME, allocator: mem.Allocator) -> string {
	bio := BIO_new(BIO_s_mem())
	if bio == nil {
		ERR_clear_error()
		return ""
	}
	defer BIO_free(bio)
	if X509_NAME_print_ex(bio, name, 0, NAME_RFC2253_FLAGS) < 0 {
		ERR_clear_error()
		return ""
	}
	n := bio_pending(bio)
	if n <= 0 {
		return ""
	}
	out := make([]u8, n, allocator)
	if BIO_read(bio, raw_data(out), cint(n)) != cint(n) {
		ERR_clear_error()
		delete(out, allocator)
		return ""
	}
	return string(out)
}

@(private = "file")
ISO_TIME_LEN :: 20 // "YYYY-MM-DDTHH:MM:SSZ"

// An ASN.1 UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ") as
// ISO 8601 text. Only the Z form (UTC) is read, as RFC 5280 requires. Built from
// the digits, so a year after 2262 (9999 for "no end") is fine.
@(private = "file")
asn1_time_iso :: proc(t: ASN1_STRING, out: ^[ISO_TIME_LEN]u8) -> bool {
	if t == nil {
		return false
	}
	data := ASN1_STRING_get0_data(t)
	n := int(ASN1_STRING_length(t))
	if data == nil || (n != 13 && n != 15) {
		return false
	}
	s := data[:n]
	if s[n - 1] != 'Z' {
		return false
	}
	for c in s[:n - 1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	two :: proc(s: []u8) -> int {
		return int(s[0] - '0') * 10 + int(s[1] - '0')
	}
	year: [4]u8
	rest := s
	if n == 13 {
		// RFC 5280: YY of 50 and more is 19YY, else 20YY.
		yy := two(s)
		century: [2]u8 = {'1', '9'} if yy >= 50 else {'2', '0'}
		year = {century[0], century[1], s[0], s[1]}
		rest = s[2:]
	} else {
		year = {s[0], s[1], s[2], s[3]}
		rest = s[4:]
	}
	mo, d, h, mi, sec := two(rest[0:]), two(rest[2:]), two(rest[4:]), two(rest[6:]), two(rest[8:])
	if mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 60 {
		return false
	}
	o := out
	copy(o[0:4], year[:])
	o[4] = '-'
	copy(o[5:7], rest[0:2])
	o[7] = '-'
	copy(o[8:10], rest[2:4])
	o[10] = 'T'
	copy(o[11:13], rest[4:6])
	o[13] = ':'
	copy(o[14:16], rest[6:8])
	o[16] = ':'
	copy(o[17:19], rest[8:10])
	o[19] = 'Z'
	return true
}
