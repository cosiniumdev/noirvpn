// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:fmt"
import "core:strings"

@(private)
fmt_alloc :: proc(b: ^Build, format: string, args: ..any) -> string {
	return fmt.aprintf(format, ..args, allocator = b.alloc)
}

// Certificates, keys, verification, TLS versions, ciphers. Returns false if
// the option is not one of these.
@(private)
handle_tls :: proc(b: ^Build, d: ^Directive) -> bool {
	a := d.args
	t := &b.common.tls
	switch d.name {
	case "ca":
		if check_inline_nonempty(b, d) {
			t.ca = key_source_of(d, 0)
			note_first(b, d)
		}
	case "cert":
		if check_inline_nonempty(b, d) && check_cert_path(b, d) {
			t.cert = key_source_of(d, 0)
			note_first(b, d)
		}
	case "key":
		if check_inline_nonempty(b, d) && check_cert_path(b, d) {
			t.key = key_source_of(d, 0)
			note_first(b, d)
		}
	case "tls-transport-cert":
		if check_inline_nonempty(b, d) {
			t.transport_cert = key_source_of(d, 0)
			note_first(b, d)
		}
	case "tls-transport-accept-tcp":
		t.transport_accept_tcp = true
		note_first(b, d)
	case "tls-transport-dev":
		t.transport_dev = a[0]
		note_first(b, d)
	case "tls-transport-ws":
		if ws_path_ok(a[0]) {
			t.transport_ws = a[0]
			note_first(b, d)
		} else {
			berr(b, d, "'%s' is not a valid path; it must start with `/`, have at most %d bytes and contain no spaces", a[0], WS_PATH_MAX)
		}
	case "tls-transport-key":
		if check_inline_nonempty(b, d) {
			t.transport_key = key_source_of(d, 0)
			note_first(b, d)
		}
	case "extra-certs":
		if check_inline_nonempty(b, d) {
			t.extra_certs = key_source_of(d, 0)
		}
	case "askpass":
		// Upstream reads the passphrase from the terminal for `askpass stdin`.
		t.askpass = "" if len(a) == 0 || a[0] == "stdin" else a[0]
	case "capath":
		t.capath = a[0]
		note_first(b, d)
	case "crl-verify":
		handle_crl_verify(b, d)
	case "peer-fingerprint":
		handle_fingerprints(b, d)
	case "remote-cert-tls":
		// Same as `remote-cert-ku` with no values and `remote-cert-eku` with the
		// extended key usage of the role. The last of these options wins.
		switch a[0] {
		case "server":
			t.remote_cert_tls = .Server
			t.remote_cert_eku = REMOTE_EKU_SERVER
		case "client":
			t.remote_cert_tls = .Client
			t.remote_cert_eku = REMOTE_EKU_CLIENT
		case:
			berr(b, d, "must be server or client, not '%s'", a[0])
			return true
		}
		t.remote_cert_ku_set = true
		clear(&b.remote_cert_ku)
	case "remote-cert-ku":
		// A new option replaces the list of an earlier one.
		t.remote_cert_ku_set = true
		clear(&b.remote_cert_ku)
		for s in a {
			v, ok := parse_hex_u16(s)
			if !ok || v == 0 || v > 0xff {
				berr(b, d, "'%s' is not a key usage value; use a hex number from 1 to ff, for example a0", s)
				return true
			}
			if len(b.remote_cert_ku) == REMOTE_CERT_KU_MAX {
				berr(b, d, "you can give at most %d key usage values", REMOTE_CERT_KU_MAX)
				return true
			}
			append(&b.remote_cert_ku, v)
		}
	case "remote-cert-eku":
		t.remote_cert_eku = a[0]
	case "verify-x509-name":
		if a[0] == "" {
			berr(b, d, "the name is empty")
			return true
		}
		x := X509_Name {
			name = a[0],
		}
		if len(a) == 2 {
			switch a[1] {
			case "subject":
				x.kind = .Subject
			case "name":
				x.kind = .Name
			case "name-prefix":
				x.kind = .Name_Prefix
			case:
				berr(b, d, "unknown type '%s'; use subject, name or name-prefix", a[1])
				return true
			}
		}
		t.verify_x509_name = x
	case "x509-username-field":
		t.x509_username_field = a[0]
	case "tls-groups":
		handle_tls_groups(b, d)
	case "tls-version-min":
		handle_tls_version_min(b, d)
	case "tls-version-max":
		v, ok := parse_tls_version(b, d, a[0])
		if ok {
			t.version_max = v
		}
	case "data-ciphers", "ncp-ciphers":
		handle_data_ciphers(b, d)
	case "data-ciphers-fallback":
		if c, ok := parse_cipher(a[0]); ok {
			b.common.data_ciphers_fallback = c
		} else {
			berr(b, d, "'%s' is not supported; use %s", a[0], CIPHER_LIST)
		}
	case:
		return false
	}
	return true
}

@(private)
CIPHER_LIST :: "AES-256-GCM, AES-128-GCM or CHACHA20-POLY1305"

// Provider URIs (pkcs11:...) are not supported.
@(private)
check_cert_path :: proc(b: ^Build, d: ^Directive) -> bool {
	if !d.has_body && strings.has_prefix(d.args[0], "pkcs11:") {
		berr(b, d, "PKCS#11 URIs are not supported; use a PEM file")
		return false
	}
	return true
}

@(private)
parse_hex_u16 :: proc(s: string) -> (v: u16, ok: bool) {
	t := s
	if strings.has_prefix(t, "0x") || strings.has_prefix(t, "0X") {
		t = t[2:]
	}
	if len(t) == 0 || len(t) > 4 {
		return 0, false
	}
	n := 0
	for ch in transmute([]u8)t {
		d := hex_digit(ch)
		if d < 0 {
			return 0, false
		}
		n = n * 16 + d
	}
	return u16(n), true
}

// `crl-verify file [dir]`.
@(private)
handle_crl_verify :: proc(b: ^Build, d: ^Directive) {
	if !check_inline_nonempty(b, d) {
		return
	}
	crl := Crl_Verify {
		src = key_source_of(d, 0),
	}
	if !d.has_body && len(d.args) == 2 {
		if d.args[1] != "dir" {
			berr(b, d, "unknown flag '%s'; the only valid flag is dir", d.args[1])
			return
		}
		crl.dir = true
	}
	b.common.tls.crl_verify = crl
}

// `peer-fingerprint fp [fp...]` or an inline block with one per line.
@(private)
handle_fingerprints :: proc(b: ^Build, d: ^Directive) {
	add :: proc(b: ^Build, d: ^Directive, s: string) {
		fp, ok := parse_fingerprint(s)
		if !ok {
			berr(
				b,
				d,
				"'%s' is not a SHA-256 fingerprint (32 hex bytes, usually separated by ':')",
				s,
			)
			return
		}
		append(&b.fingerprints, fp)
	}
	if d.has_body {
		it := d.body
		n := 0
		for line in strings.split_lines_iterator(&it) {
			t := trim_space(line)
			if t == "" || t[0] == '#' || t[0] == ';' {
				continue
			}
			add(b, d, t)
			n += 1
		}
		if n == 0 {
			berr(b, d, "the inline block does not contain a fingerprint")
		}
		return
	}
	for s in d.args {
		add(b, d, s)
	}
	note_first(b, d)
}

@(private)
handle_tls_groups :: proc(b: ^Build, d: ^Directive) {
	s := d.args[0]
	it := s
	for g in strings.split_iterator(&it, ":") {
		if g == "" {
			berr(b, d, "the group list '%s' has an empty entry", s)
			return
		}
	}
	b.common.tls.tls_groups = s
	note_first(b, d)
}

@(private)
parse_tls_version :: proc(b: ^Build, d: ^Directive, s: string) -> (v: Tls_Version, ok: bool) {
	switch s {
	case "1.2":
		return .V1_2, true
	case "1.3":
		return .V1_3, true
	case "1.0", "1.1":
		berr(b, d, "TLS %s is not supported; the lowest supported version is 1.2", s)
	case:
		berr(b, d, "unknown TLS version '%s'; use 1.2 or 1.3", s)
	}
	return .Default, false
}

// `tls-version-min version [or-highest]`. TLS 1.2 is the lowest version we
// run: 1.0 and 1.1 are accepted with a warning and mean 1.2.
@(private)
handle_tls_version_min :: proc(b: ^Build, d: ^Directive) {
	a := d.args
	if len(a) == 2 && a[1] != "or-highest" {
		berr(b, d, "unknown flag '%s'; the only valid flag is or-highest", a[1])
		return
	}
	switch a[0] {
	case "1.0", "1.1":
		bwarn(b, d, "TLS %s is not supported, so the lowest supported version, 1.2, will be used instead", a[0])
		b.common.tls.version_min = .V1_2
	case "1.2":
		b.common.tls.version_min = .V1_2
	case "1.3":
		b.common.tls.version_min = .V1_3
	case:
		if len(a) == 2 {
			// A version that is not known, with or-highest: only the highest.
			b.common.tls.version_min = .V1_3
		} else {
			berr(b, d, "unknown TLS version '%s'; use 1.2 or 1.3", a[0])
		}
	}
}

// Case-insensitive cipher name.
@(private)
parse_cipher :: proc(s: string) -> (c: Cipher, ok: bool) {
	switch {
	case strings.equal_fold(s, "AES-256-GCM"):
		return .Aes_256_Gcm, true
	case strings.equal_fold(s, "AES-128-GCM"):
		return .Aes_128_Gcm, true
	case strings.equal_fold(s, "CHACHA20-POLY1305"):
		return .Chacha20_Poly1305, true
	}
	return {}, false
}

// `data-ciphers A:B:?C`. A `?` before a name marks it optional: if it is not
// a cipher noirvpn has, it is dropped. `DEFAULT` stands for the default list.
@(private)
handle_data_ciphers :: proc(b: ^Build, d: ^Directive) {
	list := make([dynamic]Cipher, b.alloc)
	add :: proc(list: ^[dynamic]Cipher, c: Cipher) {
		for e in list {
			if e == c {
				return
			}
		}
		append(list, c)
	}
	it := d.args[0]
	for name in strings.split_iterator(&it, ":") {
		optional := strings.has_prefix(name, "?")
		n := name[1:] if optional else name
		if n == "" {
			berr(b, d, "the cipher list '%s' has an empty entry", d.args[0])
			return
		}
		if n == "DEFAULT" {
			add(&list, .Aes_256_Gcm)
			add(&list, .Aes_128_Gcm)
			add(&list, .Chacha20_Poly1305)
			continue
		}
		if c, ok := parse_cipher(n); ok {
			add(&list, c)
		} else if optional {
			bwarn(b, d, "optional cipher '%s' is not available, so it will be skipped", n)
		} else {
			berr(
				b,
				d,
				"cipher '%s' is not supported because noirvpn only uses AEAD ciphers (%s); remove it, or write ?%s to mark it as optional",
				n,
				CIPHER_LIST,
				n,
			)
			return
		}
	}
	if len(list) == 0 {
		berr(b, d, "'%s' does not contain any usable cipher", d.args[0])
		return
	}
	b.common.data_ciphers = list[:]
}

// Parses the `auth` digest used by tls-auth.
@(private)
parse_digest :: proc(s: string) -> (dg: Auth_Digest, ok: bool) {
	switch {
	case strings.equal_fold(s, "SHA1"):
		return .Sha1, true
	case strings.equal_fold(s, "SHA256"):
		return .Sha256, true
	case strings.equal_fold(s, "SHA512"):
		return .Sha512, true
	}
	return {}, false
}

// The longest path of `tls-transport-ws`.
WS_PATH_MAX :: 255

// A path for `tls-transport-ws`: starts with `/`, at most `WS_PATH_MAX` bytes, no
// space or control character.
ws_path_ok :: proc(path: string) -> bool {
	if len(path) < 1 || len(path) > WS_PATH_MAX || path[0] != '/' {
		return false
	}
	for c in transmute([]u8)path {
		if c <= 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
