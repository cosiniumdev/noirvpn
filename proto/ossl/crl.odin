// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:strings"
import "core:time"

// Certificate revocation for `.Chain` mode. Two ways to revoke:
//
//	crl_pem        PEM text with one or more CRLs. The library checks every chain
//	               certificate against them (CRL signature and dates included). An
//	               issuer with no CRL in the text is accepted.
//	revoked_check  callback asked about each verified chain certificate, by
//	               serial number in decimal.
//
// `tls_ctx_set_crl` replaces the list of a live context (new certificate store,
// swapped in). Safe only when no handshake runs on another thread: call it from
// the handshake thread of this context, between two handshake steps.
//
// A lost list (`tls_ctx_crl_lost`) fails every certificate until `tls_ctx_set_crl`
// gives a new one. The check is in the context's verify callback, so no
// handshake skips it.

// Asks whether a certificate is revoked. `serial_dec` is its serial in decimal
// (valid only during the call), `depth` its place in the chain (0 is the leaf).
// Return true to refuse it. Runs inside the TLS library on the
// `tls_handshake_step` thread: be quick, never block, never allocate.
Revoked_Check :: #type proc "contextless" (serial_dec: string, depth: int, user: rawptr) -> bool

// Largest serial number: 20 bytes (RFC 5280) is 49 decimal digits.
SERIAL_DEC_MAX :: 49
SERIAL_BYTES_MAX :: 20

CRL_ISSUER_MAX :: 160

// What `crl_inspect` tells about one CRL.
Crl_Info :: struct {
	issuer:      [CRL_ISSUER_MAX]u8, // one line, e.g. "/CN=Test CA"
	issuer_len:  int,
	next_update: i64, // unix seconds; 0 if the CRL has none
	expired:     bool, // next_update is in the past
}

@(private)
Crl_Hook :: struct {
	check: Revoked_Check, // may be nil
	user:  rawptr,
	lost:  bool, // the list is lost: refuse everything
}

NOTE_CN_MAX :: 32

// What the verify callbacks saw, for the error text. One per thread: a callback
// runs inside `SSL_do_handshake` on the calling thread; `tls_handshake_step`
// reads it right after.
@(private)
Verify_Note :: struct {
	set:        bool,
	lost:       bool,
	err:        cint,
	depth:      int,
	cn:         [NOTE_CN_MAX]u8,
	cn_len:     int,
	serial:     [SERIAL_DEC_MAX]u8,
	serial_len: int,
	// A failed leaf rule (leaf.odin): which one and what it saw.
	rule:       Rule_Fail,
	ku:         u8,
	role:       Eku_Role,
	name:       Leaf_Name_Kind,
	text:       [RULE_TEXT_MAX]u8,
	text_len:   int,
}

@(private)
CRL_MARKER :: "-----BEGIN X509 CRL-----"

@(private, thread_local)
verify_note: Verify_Note

// Certificates that were accepted because their issuer has no CRL.
@(private, thread_local)
crl_skipped: int

// Adds the CRLs of `pem` to `store`. The text must hold at least one, and
// every CRL block in it must be readable (a half-written file is an error).
@(private)
add_crls :: proc(store: X509_STORE, pem: []u8) -> (count: int, err: Error) {
	bio := pem_bio(pem)
	if bio == nil {
		ERR_clear_error()
		return 0, .Bad_Crl
	}
	defer BIO_free(bio)
	for {
		crl := PEM_read_bio_X509_CRL(bio, nil, no_password, nil)
		if crl == nil {
			break
		}
		ok := X509_STORE_add_crl(store, crl) == 1
		X509_CRL_free(crl)
		if !ok {
			ERR_clear_error()
			return count, .Bad_Crl
		}
		count += 1
	}
	ERR_clear_error()
	if count == 0 || count != strings.count(string(pem), CRL_MARKER) {
		return count, .Bad_Crl
	}
	return count, .None
}

// Reads the CRLs of `pem`. Fills `infos` with the first ones, returns how many
// CRLs the text has. `ok` is false if there is no CRL or one cannot be read.
crl_inspect :: proc(pem: []u8, infos: []Crl_Info) -> (total: int, ok: bool) {
	bio := pem_bio(pem)
	if bio == nil {
		ERR_clear_error()
		return 0, false
	}
	defer BIO_free(bio)
	now := time.to_unix_seconds(time.now())
	for {
		crl := PEM_read_bio_X509_CRL(bio, nil, no_password, nil)
		if crl == nil {
			break
		}
		if total < len(infos) {
			info := &infos[total]
			info^ = {}
			if name := X509_CRL_get_issuer(crl); name != nil {
				if X509_NAME_oneline(name, &info.issuer[0], CRL_ISSUER_MAX) != nil {
					for info.issuer_len < CRL_ISSUER_MAX && info.issuer[info.issuer_len] != 0 {
						info.issuer_len += 1
					}
				}
			}
			if t := X509_CRL_get0_nextUpdate(crl); t != nil {
				if data := ASN1_STRING_get0_data(t); data != nil {
					info.next_update, _ = asn1_time_unix(data[:max(int(ASN1_STRING_length(t)), 0)])
					info.expired = info.next_update != 0 && info.next_update < now
				}
			}
		}
		X509_CRL_free(crl)
		total += 1
	}
	ERR_clear_error()
	return total, total > 0 && total == strings.count(string(pem), CRL_MARKER)
}

// Unix seconds of an ASN.1 UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime
// ("YYYYMMDDHHMMSSZ"). Only the Z form (UTC) is accepted.
@(private)
asn1_time_unix :: proc(s: []u8) -> (secs: i64, ok: bool) {
	num :: proc(s: []u8) -> (n: int, ok: bool) {
		for c in s {
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n * 10 + int(c - '0')
		}
		return n, true
	}
	rest := s
	year: int
	switch len(s) {
	case 13:
		yy, y_ok := num(s[:2])
		if !y_ok {
			return 0, false
		}
		year = 1900 + yy if yy >= 50 else 2000 + yy
		rest = s[2:]
	case 15:
		y, y_ok := num(s[:4])
		if !y_ok {
			return 0, false
		}
		year = y
		rest = s[4:]
	case:
		return 0, false
	}
	if rest[10] != 'Z' {
		return 0, false
	}
	mo, o1 := num(rest[0:2])
	d, o2 := num(rest[2:4])
	h, o3 := num(rest[4:6])
	mi, o4 := num(rest[6:8])
	sec, o5 := num(rest[8:10])
	if !(o1 && o2 && o3 && o4 && o5) {
		return 0, false
	}
	t, t_ok := time.components_to_time(year, mo, d, h, mi, sec)
	if !t_ok {
		return 0, false
	}
	return time.to_unix_seconds(t), true
}

// Replaces the certificate store of a context created with a CRL list or a
// `revoked_check`: trust anchors `ca_pem`, CRLs `crl_pem`, CRL checks on. Nothing
// changes on failure. Clears the lost state. `revision` goes to `ctx.revision`
// (the caller's counter of which list the context has).
//
// Call it from the handshake thread of `ctx`, between two handshake steps (see
// the top of this file). Sessions that are up keep working: they do not use the
// store again.
tls_ctx_set_crl :: proc(ctx: ^Tls_Ctx, ca_pem, crl_pem: []u8, revision: u64) -> Error {
	if ctx.ctx == nil || ctx.crl == nil {
		return .Bad_Argument
	}
	ERR_clear_error()
	store := X509_STORE_new()
	if store == nil {
		ERR_clear_error()
		return .Alloc
	}
	if e := add_trust_anchors(store, ca_pem); e != .None {
		X509_STORE_free(store)
		return e
	}
	if _, e := add_crls(store, crl_pem); e != .None {
		X509_STORE_free(store)
		return e
	}
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)
	SSL_CTX_set_cert_store(ctx.ctx, store) // takes the store, frees the old one
	ctx.crl.lost = false
	ctx.revision = revision
	return .None
}

// The list of the context is lost (the file cannot be read): every
// certificate is refused until `tls_ctx_set_crl` succeeds.
tls_ctx_crl_lost :: proc(ctx: ^Tls_Ctx) {
	if ctx.crl != nil {
		ctx.crl.lost = true
	}
}

tls_ctx_is_crl_lost :: proc(ctx: ^Tls_Ctx) -> bool {
	return ctx.crl != nil && ctx.crl.lost
}

// ---------------------------------------------------------------- callbacks

// The verify callback of a context with CRLs. The library calls it for each error
// (`ok` 0) and each good certificate (`ok` 1). One error becomes success:
// "unable to get certificate CRL" (the issuer has no CRL in the list). All else
// keeps its result.
@(private)
crl_verify_cb :: proc "c" (ok: cint, store_ctx: X509_STORE_CTX) -> cint {
	if ok == 1 {
		return 1
	}
	err := X509_STORE_CTX_get_error(store_ctx)
	if err == X509_V_ERR_UNABLE_TO_GET_CRL {
		X509_STORE_CTX_set_error(store_ctx, X509_V_OK)
		crl_skipped += 1
		return 1
	}
	note_current(store_ctx, err)
	return 0
}

// The verify of a context with CRLs:
// 1. Refuse all if the list is lost.
// 2. Run the library's verification.
// 3. Ask `revoked_check` about each certificate of the chain.
@(private)
crl_cert_verify :: proc "c" (store_ctx: X509_STORE_CTX, arg: rawptr) -> cint {
	hook := (^Crl_Hook)(arg)
	if hook.lost {
		verify_note = {
			set  = true,
			lost = true,
			err  = X509_V_ERR_UNABLE_TO_GET_CRL,
		}
		X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_UNABLE_TO_GET_CRL)
		return 0
	}
	if X509_verify_cert(store_ctx) <= 0 {
		return 0
	}
	if hook.check == nil {
		return 1
	}
	chain := X509_STORE_CTX_get0_chain(store_ctx) // borrowed
	for i in 0 ..< chain_len(chain) {
		x := chain_get(chain, i)
		serial: [SERIAL_DEC_MAX]u8
		n, ok := serial_decimal(x, &serial)
		// A serial that does not fit is treated as revoked.
		if !ok || hook.check(string(serial[:n]), i, hook.user) {
			verify_note = {
				set   = true,
				err   = X509_V_ERR_CERT_REVOKED,
				depth = i,
			}
			fill_note_cert(&verify_note, x)
			X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REVOKED)
			return 0
		}
	}
	return 1
}

// Records the certificate that the library is judging.
@(private)
note_current :: proc "contextless" (store_ctx: X509_STORE_CTX, err: cint) {
	verify_note = {
		set   = true,
		err   = err,
		depth = int(X509_STORE_CTX_get_error_depth(store_ctx)),
	}
	if x := X509_STORE_CTX_get_current_cert(store_ctx); x != nil {
		fill_note_cert(&verify_note, x)
	}
}

@(private)
fill_note_cert :: proc "contextless" (n: ^Verify_Note, x: X509) {
	n.cn_len, _ = common_name_of(x, n.cn[:])
	// The name goes to the log, and the certificate may be one that failed
	// the check: control bytes become '?'.
	for i in 0 ..< n.cn_len {
		if n.cn[i] < 0x20 || n.cn[i] == 0x7f {
			n.cn[i] = '?'
		}
	}
	n.serial_len, _ = serial_decimal(x, &n.serial)
}

// The serial number of a certificate in decimal, with no leading zeros. False
// for a negative serial or one longer than 20 bytes.
@(private)
serial_decimal :: proc "contextless" (x: X509, out: ^[SERIAL_DEC_MAX]u8) -> (n: int, ok: bool) {
	s := X509_get0_serialNumber(x)
	if s == nil || ASN1_STRING_type(s) != 2 { // V_ASN1_INTEGER; 0x102 is a negative one
		return 0, false
	}
	data := ASN1_STRING_get0_data(s)
	l := int(ASN1_STRING_length(s))
	if data == nil || l < 0 {
		return 0, false
	}
	mag: [SERIAL_BYTES_MAX]u8
	start := 0
	for start < l && data[start] == 0 {
		start += 1
	}
	m := l - start
	if m > SERIAL_BYTES_MAX {
		return 0, false
	}
	for i in 0 ..< m {
		mag[i] = data[start + i]
	}
	// Divide the big-endian number by 10 until it is 0; the remainders are the
	// decimal digits, last one first.
	rev: [SERIAL_DEC_MAX]u8
	nd := 0
	lo := 0 // mag[lo:m] is what is left, with no leading zero
	for lo < m {
		rem := 0
		for i in lo ..< m {
			v := rem * 256 + int(mag[i])
			mag[i] = u8(v / 10)
			rem = v % 10
		}
		rev[nd] = u8('0' + rem)
		nd += 1
		for lo < m && mag[lo] == 0 {
			lo += 1
		}
	}
	if nd == 0 {
		out[0] = '0'
		return 1, true
	}
	for i in 0 ..< nd {
		out[i] = rev[nd - 1 - i]
	}
	return nd, true
}
