// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// Rules for the peer's own certificate (the leaf, depth 0): key usage, extended
// key usage and name. They are upstream's `remote-cert-tls`, `remote-cert-ku`,
// `remote-cert-eku` and `verify-x509-name`.
//
// The check is in the context's verify path (see `rules_cert_verify`). It runs
// after the chain check (`.Chain`, with or without CRLs) or pin check (`.Pinned`)
// accepted the certificate, and before the handshake can succeed, so no mode
// accepts a peer that fails a rule. `.None` does not look at the certificate:
// no rules there.
//
// Fail closed: these refuse the certificate: an unreadable certificate field, a
// name that does not fit the fixed buffers, a failed allocation inside the C
// library. Our code does not allocate in the check.

// Largest number of values in `Leaf_Rules.ku_list`.
KU_LIST_MAX :: 16
// Longest `name` of a rule, in bytes.
LEAF_NAME_MAX :: 512
// The one-line subject of a certificate must fit this many bytes.
LEAF_SUBJECT_MAX :: 1024
// The longest common name that `name` and `name-prefix` read, in UTF-8 bytes.
LEAF_CN_MAX :: 64
// Longest dotted OID of the extended key usage rule.
EKU_OID_MAX :: 96

// The extended key usage that `remote-cert-tls server` and `client` require
// (the long names of serverAuth and clientAuth).
EKU_SERVER_AUTH :: "TLS Web Server Authentication"
EKU_CLIENT_AUTH :: "TLS Web Client Authentication"

@(private)
OID_SERVER_AUTH :: "1.3.6.1.5.5.7.3.1"
@(private)
OID_CLIENT_AUTH :: "1.3.6.1.5.5.7.3.2"

Leaf_Name_Kind :: enum u8 {
	None,
	// The whole subject in OpenVPN's text form, e.g. "C=KG, ST=NA, CN=Server-1".
	Subject,
	// The common name (the last one, if there are several).
	Name,
	// The common name starts with `name`.
	Name_Prefix,
}

Leaf_Rules :: struct {
	// The key usage extension must be present (any value).
	ku_required: bool,
	// Accepted key usage values: bit sets in the order of the extension:
	//   0x80 digitalSignature   0x40 nonRepudiation   0x20 keyEncipherment
	//   0x10 dataEncipherment   0x08 keyAgreement     0x04 keyCertSign
	//   0x02 cRLSign            0x01 encipherOnly
	// The certificate passes if it has all the bits of at least one value. Bit 9
	// (decipherOnly) is ignored. With values, the extension is required. Each value
	// is 1 to 0xff.
	ku_list:     [KU_LIST_MAX]u8,
	ku_count:    int,
	// The extended key usage that the certificate must have: a dotted OID, a
	// short name or a long name. Empty: not checked. The extension is required.
	eku:         string,
	// The name rule. `name` is at most `LEAF_NAME_MAX` bytes.
	name_kind:   Leaf_Name_Kind,
	name:        string,
}

// True if the rules ask for any check.
leaf_rules_active :: proc(r: Leaf_Rules) -> bool {
	return r.ku_required || r.ku_count > 0 || r.eku != "" || r.name_kind != .None
}

// True if `text` is a dotted OID or a name that the library knows, so that
// `Leaf_Rules.eku` can take it. For a start-up check of a config.
leaf_eku_valid :: proc(text: string) -> bool {
	oid: [EKU_OID_MAX]u8
	_, ok := resolve_eku(text, &oid)
	return ok
}

@(private)
Eku_Role :: enum u8 {
	Other,
	Server,
	Client,
}

@(private)
Rule_Fail :: enum u8 {
	None,
	Ku_Missing,
	Ku_Mismatch,
	Eku_Missing,
	Eku_Mismatch,
	Name_Mismatch,
	Name_Unreadable,
	Name_Too_Long,
}

@(private)
RULE_TEXT_MAX :: 96

// Why a certificate failed. `text` is the name that was compared (the subject
// or the common name) or the OID that was missing, with control bytes gone.
@(private)
Leaf_Verdict :: struct {
	fail:     Rule_Fail,
	ku:       u8, // the key usage of the certificate (Ku_Mismatch)
	role:     Eku_Role, // Eku_Mismatch
	name:     Leaf_Name_Kind, // Name_Mismatch
	text:     [RULE_TEXT_MAX]u8,
	text_len: int,
}

// The rules in the form the check uses. The C library holds a pointer to this.
@(private)
Leaf_Hook :: struct {
	ku_required: bool,
	ku_list:     [KU_LIST_MAX]u8,
	ku_count:    int,
	eku_oid:     [EKU_OID_MAX]u8, // the dotted OID, or empty
	eku_len:     int,
	eku_role:    Eku_Role,
	name_kind:   Leaf_Name_Kind,
	name:        [LEAF_NAME_MAX]u8,
	name_len:    int,
}

// What a context with rules holds: the rules and the check that comes first
// (the pin check, the CRL verify, or the plain chain verify).
@(private)
Rules_Hook :: struct {
	using leaf: Leaf_Hook,
	pin:        ^Pin_Hook, // `.Pinned`
	crl:        ^Crl_Hook, // `.Chain` with CRLs
}

// Turns an OID or a name into the dotted OID.
@(private)
resolve_eku :: proc(text: string, out: ^[EKU_OID_MAX]u8) -> (n: int, ok: bool) {
	buf: [128]u8 // room for a NUL byte
	if len(text) == 0 || len(text) >= len(buf) {
		return 0, false
	}
	for c in transmute([]u8)text {
		if c == 0 {
			return 0, false
		}
	}
	copy(buf[:], text)
	ERR_clear_error()
	obj := OBJ_txt2obj(cstring(&buf[0]), 0)
	if obj == nil {
		ERR_clear_error()
		return 0, false
	}
	defer ASN1_OBJECT_free(obj)
	r := int(OBJ_obj2txt(&out[0], EKU_OID_MAX, obj, 1))
	if r <= 0 || r >= EKU_OID_MAX {
		ERR_clear_error()
		return 0, false
	}
	return r, true
}

@(private)
leaf_hook_fill :: proc(h: ^Leaf_Hook, r: Leaf_Rules) -> Error {
	h.ku_required = r.ku_required
	if r.ku_count < 0 || r.ku_count > KU_LIST_MAX {
		return .Bad_Argument
	}
	for i in 0 ..< r.ku_count {
		if r.ku_list[i] == 0 {
			return .Bad_Argument
		}
		h.ku_list[i] = r.ku_list[i]
	}
	h.ku_count = r.ku_count
	if r.eku != "" {
		n, ok := resolve_eku(r.eku, &h.eku_oid)
		if !ok {
			return .Bad_Config
		}
		h.eku_len = n
		switch string(h.eku_oid[:n]) {
		case OID_SERVER_AUTH:
			h.eku_role = .Server
		case OID_CLIENT_AUTH:
			h.eku_role = .Client
		}
	}
	if r.name_kind != .None {
		if r.name == "" || len(r.name) > LEAF_NAME_MAX {
			return .Bad_Argument
		}
		for c in transmute([]u8)r.name {
			if c == 0 {
				return .Bad_Argument
			}
		}
		h.name_kind = r.name_kind
		h.name_len = len(r.name)
		copy(h.name[:], r.name)
	}
	return .None
}

// Judges one certificate. Order as upstream: key usage, extended key usage,
// name. The first rule that fails is in `v`.
@(private)
leaf_check :: proc "contextless" (x: X509, h: ^Leaf_Hook, v: ^Leaf_Verdict) -> bool {
	v^ = {}
	return check_ku(x, h, v) && check_eku(x, h, v) && check_name(x, h, v)
}

@(private)
set_text :: proc "contextless" (v: ^Leaf_Verdict, text: []u8) {
	n := min(len(text), RULE_TEXT_MAX)
	copy(v.text[:n], text[:n])
	v.text_len = n
	for i in 0 ..< n {
		if v.text[i] < 0x20 || v.text[i] == 0x7f {
			v.text[i] = '?'
		}
	}
}

@(private)
check_ku :: proc "contextless" (x: X509, h: ^Leaf_Hook, v: ^Leaf_Verdict) -> bool {
	if !h.ku_required && h.ku_count == 0 {
		return true
	}
	ext := ASN1_STRING(X509_get_ext_d2i(x, NID_KEY_USAGE, nil, nil))
	if ext == nil {
		v.fail = .Ku_Missing
		return false
	}
	defer ASN1_BIT_STRING_free(ext)
	// Bit 0 of the extension (digitalSignature) is 0x80 in a value.
	nku: u8
	for i in 0 ..< 8 {
		if ASN1_BIT_STRING_get_bit(ext, cint(i)) == 1 {
			nku |= u8(1) << u8(7 - i)
		}
	}
	if h.ku_count == 0 {
		return true
	}
	for i in 0 ..< h.ku_count {
		want := h.ku_list[i]
		if want != 0 && nku & want == want {
			return true
		}
	}
	v.fail = .Ku_Mismatch
	v.ku = nku
	return false
}

@(private)
check_eku :: proc "contextless" (x: X509, h: ^Leaf_Hook, v: ^Leaf_Verdict) -> bool {
	if h.eku_len == 0 {
		return true
	}
	ext := STACK(X509_get_ext_d2i(x, NID_EXT_KEY_USAGE, nil, nil))
	if ext == nil {
		v.fail = .Eku_Missing
		return false
	}
	defer EXTENDED_KEY_USAGE_free(ext)
	want := string(h.eku_oid[:h.eku_len])
	for i in 0 ..< chain_len(ext) {
		obj := ASN1_OBJECT(chain_get(ext, i)) // borrowed from the stack
		buf: [EKU_OID_MAX]u8
		r := int(OBJ_obj2txt(&buf[0], EKU_OID_MAX, obj, 1))
		if r > 0 && r < EKU_OID_MAX && string(buf[:r]) == want {
			return true
		}
	}
	v.fail = .Eku_Mismatch
	v.role = h.eku_role
	set_text(v, h.eku_oid[:h.eku_len])
	return false
}

// OpenVPN compares text in which every byte below 0x20 and the byte 0x7f is
// an underscore.
@(private)
remap :: proc "contextless" (b: []u8) {
	for &c in b {
		if c < 0x20 || c == 0x7f {
			c = '_'
		}
	}
}

@(private)
check_name :: proc "contextless" (x: X509, h: ^Leaf_Hook, v: ^Leaf_Verdict) -> bool {
	if h.name_kind == .None {
		return true
	}
	buf: [LEAF_SUBJECT_MAX]u8
	n: int
	fail: Rule_Fail
	if h.name_kind == .Subject {
		n, fail = subject_text(x, buf[:])
	} else {
		n, fail = common_name_text(x, buf[:LEAF_CN_MAX])
	}
	if fail != .None {
		v.fail = fail
		v.name = h.name_kind
		return false
	}
	text := buf[:n]
	want := h.name[:h.name_len]
	ok: bool
	switch h.name_kind {
	case .Subject, .Name:
		ok = string(text) == string(want)
	case .Name_Prefix:
		ok = len(text) >= len(want) && string(text[:len(want)]) == string(want)
	case .None:
		ok = true
	}
	if !ok {
		v.fail = .Name_Mismatch
		v.name = h.name_kind
		set_text(v, text)
		return false
	}
	return true
}

// The subject as one line, in upstream's compare form: entries in certificate
// order, ", " between, short attribute names, "=" with no spaces, RFC 2253 escapes.
@(private)
subject_text :: proc "contextless" (x: X509, out: []u8) -> (n: int, fail: Rule_Fail) {
	name := X509_get_subject_name(x) // borrowed from `x`
	if name == nil {
		return 0, .Name_Unreadable
	}
	bio := BIO_new(BIO_s_mem())
	if bio == nil {
		ERR_clear_error()
		return 0, .Name_Unreadable
	}
	defer BIO_free(bio)
	if X509_NAME_print_ex(bio, name, 0, SUBJECT_TEXT_FLAGS) <= 0 {
		ERR_clear_error()
		return 0, .Name_Unreadable
	}
	have := bio_pending(bio)
	if have <= 0 {
		return 0, .Name_Unreadable
	}
	if have > len(out) {
		return 0, .Name_Too_Long
	}
	if int(BIO_read(bio, raw_data(out), cint(have))) != have {
		return 0, .Name_Unreadable
	}
	text := out[:have]
	for c in text {
		if c == 0 {
			return 0, .Name_Unreadable
		}
	}
	remap(text)
	for i := 0; i < len(text) && text[i] == '-'; i += 1 {
		text[i] = '_'
	}
	return have, .None
}

// The last common name of the subject, in UTF-8. A name with a NUL byte or one
// longer than `len(out)` bytes does not pass.
@(private)
common_name_text :: proc "contextless" (x: X509, out: []u8) -> (n: int, fail: Rule_Fail) {
	name := X509_get_subject_name(x) // borrowed from `x`
	if name == nil {
		return 0, .Name_Unreadable
	}
	last: cint = -1
	for {
		i := X509_NAME_get_index_by_NID(name, NID_COMMON_NAME, last)
		if i < 0 {
			break
		}
		last = i
	}
	if last < 0 {
		return 0, .Name_Unreadable
	}
	entry := X509_NAME_get_entry(name, last) // borrowed
	if entry == nil {
		return 0, .Name_Unreadable
	}
	str := X509_NAME_ENTRY_get_data(entry) // borrowed
	if str == nil {
		return 0, .Name_Unreadable
	}
	utf8: [^]u8
	l := int(ASN1_STRING_to_UTF8(&utf8, str))
	if l < 0 || utf8 == nil {
		ERR_clear_error()
		return 0, .Name_Unreadable
	}
	defer CRYPTO_free(utf8, nil, 0)
	if l == 0 {
		return 0, .Name_Unreadable
	}
	if l > len(out) {
		return 0, .Name_Too_Long
	}
	for i in 0 ..< l {
		if utf8[i] == 0 {
			return 0, .Name_Unreadable
		}
	}
	copy(out[:l], utf8[:l])
	remap(out[:l])
	return l, .None
}

// The verify of a context with rules: the check that the context would have
// without them, then the rules on the leaf.
@(private)
rules_cert_verify :: proc "c" (store_ctx: X509_STORE_CTX, arg: rawptr) -> cint {
	h := (^Rules_Hook)(arg)
	switch {
	case h.pin != nil && h.pin.lookup != nil:
		if either_cert_verify(store_ctx, h.pin) != 1 {
			return 0
		}
	case h.pin != nil:
		if check_pin(store_ctx, h.pin) != 1 {
			return 0
		}
	case h.crl != nil:
		if crl_cert_verify(store_ctx, h.crl) != 1 {
			return 0
		}
	case:
		if X509_verify_cert(store_ctx) <= 0 {
			return 0
		}
	}
	x := X509_STORE_CTX_get0_cert(store_ctx) // borrowed
	v: Leaf_Verdict
	if x != nil && leaf_check(x, &h.leaf, &v) {
		return 1
	}
	if x == nil {
		v.fail = .Name_Unreadable
	}
	verify_note = {
		set      = true,
		err      = X509_V_ERR_CERT_REJECTED,
		rule     = v.fail,
		ku       = v.ku,
		role     = v.role,
		name     = v.name,
		text     = v.text,
		text_len = v.text_len,
	}
	if x != nil {
		fill_note_cert(&verify_note, x)
	}
	X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REJECTED)
	return 0
}

// The text of a failed rule, for `tls_last_error`.
@(private)
rule_text :: proc(s: ^Tls_Session, note: ^Verify_Note) {
	text := string(note.text[:note.text_len])
	switch note.rule {
	case .None:
	case .Ku_Missing:
		err_put(s, "the certificate has no key usage (remote-cert-ku)")
	case .Ku_Mismatch:
		err_put(s, "key usage 0x")
		hex4(s, note.ku)
		err_put(s, " is not in the accepted list (remote-cert-ku)")
	case .Eku_Missing:
		err_put(s, "the certificate has no extended key usage (remote-cert-eku)")
	case .Eku_Mismatch:
		switch note.role {
		case .Server:
			err_put(s, "the certificate is not for a server (extended key usage)")
		case .Client:
			err_put(s, "the certificate is not for a client (extended key usage)")
		case .Other:
			err_put(s, "the extended key usage does not have the OID ")
			err_put(s, text)
		}
	case .Name_Mismatch:
		switch note.name {
		case .Subject:
			err_put(s, "the subject '")
		case .Name, .Name_Prefix, .None:
			err_put(s, "the name '")
		}
		err_put(s, text)
		if note.name == .Name_Prefix {
			err_put(s, "' does not start with the verify-x509-name value")
		} else {
			err_put(s, "' does not match verify-x509-name")
		}
	case .Name_Unreadable:
		err_put(s, "the name of the certificate cannot be read (verify-x509-name)")
	case .Name_Too_Long:
		err_put(s, "the name of the certificate is too long (verify-x509-name)")
	}
}

@(private)
hex4 :: proc(s: ^Tls_Session, b: u8) {
	digits := "0123456789abcdef"
	out := [4]u8{'0', '0', digits[b >> 4], digits[b & 15]}
	err_put(s, string(out[:]))
}

// True if the handshake failed because the certificate of the peer broke one
// of the `Leaf_Rules`.
tls_cert_rule_failed :: proc(s: ^Tls_Session) -> bool {
	return s.rule_failed
}
