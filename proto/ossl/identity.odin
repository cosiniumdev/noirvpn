// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:mem"

// A client identity for key pinning: a new key and a self-signed certificate.
//
//	identity_generate(kind, common_name) -> (Identity, Error)
//	identity_destroy(&id)                  wipes and frees the key text
//	cert_spki_sha256(cert_pem) -> (hash, ok)          the pin of a certificate
//	cert_identity_kind(cert_pem) -> (kind, ok)        Ed25519 or ML-DSA-65, else ok is false
//	identity_self_sign(key_pem, common_name) -> (cert_pem, Error)   the same certificate for a key that exists
//
// A new key with a certificate request (not self-signed) is in csr.odin.
//
// The server judges the client by the SHA-256 of its public key (the pin).
// `.Pinned` mode checks no dates and no names, so the certificate is a frame for
// the key: random serial, 20 years validity, the common name, and the extensions
// that a server with `remote-cert-tls client` asks for (key usage
// digitalSignature, extended key usage clientAuth).

Identity_Kind :: enum u8 {
	Ed25519,
	Mldsa65, // ML-DSA-65 (FIPS 204), a post-quantum signature
	P256, // ECDSA on P-256, signed with SHA-256
}

// PEM texts. The key is PKCS#8 and not encrypted: the service needs it as it
// is. Free it with `identity_destroy`, which wipes it first.
Identity :: struct {
	key_pem:     string,
	cert_pem:    string,
	spki_sha256: [SHA256_LEN]u8, // the pin
}

IDENTITY_CN_MAX :: 64 // the upper bound of X.509 for a common name
IDENTITY_DAYS :: 7305 // 20 years

@(private = "file")
DAY :: 86400

// DER values of the extensions (RFC 5280).
@(private = "file")
EXT_BASIC_CONSTRAINTS := [?]u8{0x30, 0x00} // cA FALSE
@(private = "file")
EXT_KEY_USAGE := [?]u8{0x03, 0x02, 0x07, 0x80} // digitalSignature
@(private = "file")
EXT_CLIENT_AUTH := [?]u8{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02} // id-kp-clientAuth

// The algorithm identifiers in a SubjectPublicKeyInfo (RFC 8410, FIPS 204).
@(private = "file")
OID_ED25519 := [?]u8{0x2b, 0x65, 0x70}
@(private = "file")
OID_MLDSA65 := [?]u8{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
@(private = "file")
OID_ED448 := [?]u8{0x2b, 0x65, 0x71}
@(private = "file")
OID_RSA_ENCRYPTION := [?]u8{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
@(private = "file")
OID_EC_PUBLIC_KEY := [?]u8{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}

// Creates a new key of `kind` and a self-signed certificate for it.
// `common_name` is UTF-8, 1 to 64 bytes. The strings use `allocator`.
identity_generate :: proc(kind: Identity_Kind, common_name: string, allocator := context.allocator) -> (id: Identity, err: Error) {
	if len(common_name) == 0 || len(common_name) > IDENTITY_CN_MAX {
		return {}, .Bad_Argument
	}
	pkey := new_key(kind)
	if pkey == nil {
		return {}, .Lib
	}
	defer EVP_PKEY_free(pkey)

	x := X509_new()
	if x == nil {
		ERR_clear_error()
		return {}, .Alloc
	}
	defer X509_free(x)
	if err = self_sign(x, pkey, sign_md(kind), common_name); err != .None {
		ERR_clear_error()
		return {}, err
	}
	spki, ok := spki_hash(x)
	if !ok {
		return {}, .Lib
	}

	cert := pem_text(x, nil, allocator)
	if cert == "" {
		return {}, .Lib
	}
	key := pem_text(nil, pkey, allocator)
	if key == "" {
		delete(cert, allocator)
		return {}, .Lib
	}
	return Identity{key_pem = key, cert_pem = cert, spki_sha256 = spki}, .None
}

// Creates the certificate of `identity_generate` for the private key in `key_pem`
// (unencrypted PEM: PKCS#8, SEC1 or PKCS#1). The signature uses no digest for
// Ed25519, Ed448 and ML-DSA keys, SHA-256 for RSA and ECDSA. The text uses
// `allocator`. Errors: .Bad_Argument (bad common name), .Key_Encrypted,
// .Bad_Key (no key, or a key of another kind).
identity_self_sign :: proc(key_pem: []u8, common_name: string, allocator := context.allocator) -> (cert_pem: string, err: Error) {
	if len(common_name) == 0 || len(common_name) > IDENTITY_CN_MAX {
		return "", .Bad_Argument
	}
	bio := pem_bio(key_pem)
	if bio == nil {
		ERR_clear_error()
		return "", .Bad_Key
	}
	defer BIO_free(bio)
	pkey := PEM_read_bio_PrivateKey(bio, nil, no_password, nil)
	if pkey == nil {
		ERR_clear_error()
		return "", .Key_Encrypted if key_pem_encrypted(key_pem) else .Bad_Key
	}
	defer EVP_PKEY_free(pkey)
	buf: [SPKI_MAX]u8
	oid := spki_oid(pkey_spki_der(pkey, buf[:]))
	md: EVP_MD
	switch {
	case bytes_equal(oid, OID_ED25519[:]), bytes_equal(oid, OID_ED448[:]):
	case len(oid) == len(OID_MLDSA65) && bytes_equal(oid[:len(oid) - 1], OID_MLDSA65[:len(OID_MLDSA65) - 1]):
		// id-ml-dsa-44, -65, -87 differ in the last byte.
	case bytes_equal(oid, OID_RSA_ENCRYPTION[:]), bytes_equal(oid, OID_EC_PUBLIC_KEY[:]):
		md = EVP_sha256()
	case:
		return "", .Bad_Key
	}
	x := X509_new()
	if x == nil {
		ERR_clear_error()
		return "", .Alloc
	}
	defer X509_free(x)
	if err = self_sign(x, pkey, md, common_name); err != .None {
		ERR_clear_error()
		return "", err
	}
	cert_pem = pem_text(x, nil, allocator)
	if cert_pem == "" {
		return "", .Lib
	}
	return cert_pem, .None
}

// Wipes the key text and frees both texts.
identity_destroy :: proc(id: ^Identity, allocator := context.allocator) {
	wipe_free(id.key_pem, allocator)
	delete(id.cert_pem, allocator)
	id^ = {}
}

// The SHA-256 of the DER SubjectPublicKeyInfo of the first certificate in
// `cert_pem`: the pin of the peers file.
cert_spki_sha256 :: proc(cert_pem: []u8) -> (hash: [SHA256_LEN]u8, ok: bool) {
	x := first_cert(cert_pem)
	if x == nil {
		return
	}
	defer X509_free(x)
	return spki_hash(x)
}

// The kind of the key of the first certificate in `cert_pem`. `ok` is false
// for any other key, and for a text with no certificate.
cert_identity_kind :: proc(cert_pem: []u8) -> (kind: Identity_Kind, ok: bool) {
	x := first_cert(cert_pem)
	if x == nil {
		return
	}
	defer X509_free(x)
	buf: [SPKI_MAX]u8
	der := spki_der(x, buf[:])
	oid := spki_oid(der)
	switch {
	case bytes_equal(oid, OID_ED25519[:]):
		return .Ed25519, true
	case bytes_equal(oid, OID_MLDSA65[:]):
		return .Mldsa65, true
	}
	return
}

// Fills the certificate: version 3, serial, dates, names, key, extensions,
// signature.
@(private = "file")
self_sign :: proc(x: X509, pkey: EVP_PKEY, md: EVP_MD, common_name: string) -> Error {
	rnd: [8]u8
	if !random_bytes(rnd[:]) {
		return .Lib
	}
	serial: u64
	for b in rnd {
		serial = serial << 8 | u64(b)
	}
	serial = serial & 0x7fff_ffff_ffff_ffff | 1 // positive and not zero
	if X509_set_version(x, X509_VERSION_3) != 1 || ASN1_INTEGER_set_uint64(X509_get_serialNumber(x), serial) != 1 {
		return .Lib
	}
	// One hour back, for a peer with a clock that is a bit late.
	if X509_gmtime_adj(X509_getm_notBefore(x), -3600) == nil || X509_gmtime_adj(X509_getm_notAfter(x), IDENTITY_DAYS * DAY) == nil {
		return .Lib
	}
	name := X509_get_subject_name(x) // borrowed
	if X509_NAME_add_entry_by_NID(name, NID_COMMON_NAME, MBSTRING_UTF8, raw_data(common_name), cint(len(common_name)), -1, 0) != 1 {
		return .Bad_Argument
	}
	if X509_set_issuer_name(x, name) != 1 || X509_set_pubkey(x, pkey) != 1 {
		return .Lib
	}
	if !add_ext(x, NID_BASIC_CONSTRAINTS, false, EXT_BASIC_CONSTRAINTS[:]) ||
	   !add_ext(x, NID_KEY_USAGE, true, EXT_KEY_USAGE[:]) ||
	   !add_ext(x, NID_EXT_KEY_USAGE, false, EXT_CLIENT_AUTH[:]) {
		return .Lib
	}
	if X509_sign(x, pkey, md) <= 0 {
		return .Lib
	}
	return .None
}

// A new key of `kind`, or nil. Free it with EVP_PKEY_free.
@(private)
new_key :: proc(kind: Identity_Kind) -> EVP_PKEY {
	kctx := backend_keygen_ctx(kind)
	if kctx == nil {
		ERR_clear_error()
		return nil
	}
	pkey: EVP_PKEY
	made := EVP_PKEY_keygen(kctx, &pkey) == 1 && pkey != nil
	EVP_PKEY_CTX_free(kctx)
	if !made {
		ERR_clear_error()
		return nil
	}
	return pkey
}

// The digest of a signature with a key of `kind`: SHA-256 for ECDSA, none
// (nil) for Ed25519 and ML-DSA, which sign the message itself.
@(private)
sign_md :: proc(kind: Identity_Kind) -> EVP_MD {
	return EVP_sha256() if kind == .P256 else nil
}

@(private = "file")
add_ext :: proc(x: X509, nid: cint, critical: bool, der: []u8) -> bool {
	data := ASN1_OCTET_STRING_new()
	if data == nil {
		return false
	}
	defer ASN1_OCTET_STRING_free(data)
	if ASN1_OCTET_STRING_set(data, raw_data(der), cint(len(der))) != 1 {
		return false
	}
	ext := X509_EXTENSION_create_by_NID(nil, nid, critical ? 1 : 0, data)
	if ext == nil {
		return false
	}
	defer X509_EXTENSION_free(ext)
	return X509_add_ext(x, ext, -1) == 1
}

// The PEM text of a certificate (x), of a certificate request (req) or of an
// unencrypted private key (pkey), or "" on failure.
@(private)
pem_text :: proc(x: X509, pkey: EVP_PKEY, allocator: mem.Allocator, req: X509_REQ = nil) -> string {
	bio := BIO_new(BIO_s_mem())
	if bio == nil {
		ERR_clear_error()
		return ""
	}
	// The memory BIO wipes its buffer when it is freed (both libraries).
	defer BIO_free(bio)
	wrote: cint
	switch {
	case x != nil:
		wrote = PEM_write_bio_X509(bio, x)
	case req != nil:
		wrote = PEM_write_bio_X509_REQ(bio, req)
	case:
		wrote = PEM_write_bio_PrivateKey(bio, pkey, nil, nil, 0, nil, nil)
	}
	n := bio_pending(bio)
	if wrote != 1 || n <= 0 {
		ERR_clear_error()
		return ""
	}
	buf := make([]u8, n, allocator)
	if BIO_read(bio, raw_data(buf), cint(n)) != cint(n) {
		ERR_clear_error()
		wipe_free(string(buf), allocator)
		return ""
	}
	return string(buf)
}

@(private)
wipe_free :: proc(s: string, allocator: mem.Allocator) {
	if len(s) > 0 {
		mem.zero_explicit(raw_data(s), len(s))
	}
	delete(s, allocator)
}

@(private)
first_cert :: proc(cert_pem: []u8) -> X509 {
	bio := pem_bio(cert_pem)
	if bio == nil {
		ERR_clear_error()
		return nil
	}
	defer BIO_free(bio)
	x := PEM_read_bio_X509(bio, nil, no_password, nil)
	if x == nil {
		ERR_clear_error()
	}
	return x
}

// The DER SubjectPublicKeyInfo of `x` in `buf`, or nil.
@(private)
spki_der :: proc(x: X509, buf: []u8) -> []u8 {
	pkey := X509_get0_pubkey(x) // borrowed from `x`
	if pkey == nil {
		ERR_clear_error()
		return nil
	}
	return pkey_spki_der(pkey, buf)
}

// The DER SubjectPublicKeyInfo of the public part of `pkey` in `buf`, or nil.
@(private)
pkey_spki_der :: proc(pkey: EVP_PKEY, buf: []u8) -> []u8 {
	n := i2d_PUBKEY(pkey, nil) // size only
	if n <= 0 || int(n) > len(buf) {
		ERR_clear_error()
		return nil
	}
	p := raw_data(buf)
	if i2d_PUBKEY(pkey, &p) != n {
		ERR_clear_error()
		return nil
	}
	return buf[:n]
}

@(private)
spki_hash :: proc(x: X509) -> (hash: [SHA256_LEN]u8, ok: bool) {
	buf: [SPKI_MAX]u8
	der := spki_der(x, buf[:])
	if der == nil {
		return
	}
	return sha256(der), true
}

// The algorithm OID of a DER SubjectPublicKeyInfo:
// SEQUENCE { SEQUENCE { OBJECT IDENTIFIER, ... }, BIT STRING }.
@(private)
spki_oid :: proc(der: []u8) -> []u8 {
	outer, _ := der_take(der, 0x30)
	alg, _ := der_take(outer, 0x30)
	oid, _ := der_take(alg, 0x06)
	return oid
}

// Splits one DER element of tag `tag` off the front of `b`: its content and
// the rest. Both are nil when `b` does not start with such an element.
@(private)
der_take :: proc(b: []u8, tag: u8) -> (content, rest: []u8) {
	if len(b) < 2 || b[0] != tag {
		return
	}
	n := int(b[1])
	at := 2
	if n & 0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 || len(b) < 2 + count {
			return
		}
		n = 0
		for i in 0 ..< count {
			n = n << 8 | int(b[2 + i])
		}
		at += count
	}
	if len(b) - at < n {
		return
	}
	return b[at:at + n], b[at + n:]
}

@(private)
bytes_equal :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i in 0 ..< len(a) {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
