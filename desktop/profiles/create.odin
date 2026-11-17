// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Profiles that the GUI creates: the form, its checks, the profile text and
// the text of a key pin. The key itself comes from the caller (proto/ossl).
//
//	form_errors(f, s) -> [Form_Field]string     one message per field, "" when good
//	form_text(f, s, allocator) -> string        the profile text, keys inline
//	secrets_read(text, allocator) -> Secrets    the inline cert, key, ca and tls-crypt
//	secrets_destroy(s, allocator)               wipes the key material
//	pin_text(mldsa65, digest, allocator) -> string    "sha256:..." for the peers file
//	peers_name(name, allocator) -> string       a name for the peers file and the certificate
//	fingerprint_parse(s) -> (digest, ok)        fingerprint_text(digest, allocator) -> string
//	form_clone(f, allocator), form_destroy(f, allocator)
package profiles

import "core:encoding/base64"
import "core:fmt"
import "core:mem"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"

import "noir:proto/config"

// The form values of a created profile, as meta.json keeps them. The key, the
// tls-crypt key and the CA are in the profile text only.
Form :: struct {
	host:        string `json:"host"`,
	port:        int `json:"port"`,
	// "udp", "tcp" or "tls".
	transport:   string `json:"transport"`,
	// Hex with colons; "" when the profile has a CA.
	fingerprint: string `json:"fingerprint"`,
	// "ed25519" or "mldsa65".
	key_type:    string `json:"key_type"`,
	// Text of the fields; "" uses the default.
	mtu:         string `json:"mtu,omitempty"`,
	mss:         string `json:"mss,omitempty"`,
	user_pass:   bool `json:"user_pass"`,
	// "" (prefer), "off" or "require".
	pq_mode:     string `json:"pq_mode,omitempty"`,
	ciphers:     string `json:"ciphers,omitempty"`,
	sni:         string `json:"sni,omitempty"`,
	extra:       [dynamic]string `json:"extra,omitempty"`,
}

// Key material of a profile. Free it with secrets_destroy, which wipes it.
Secrets :: struct {
	cert:      string,
	key:       string,
	ca:        string,
	// A tls-crypt key or a tls-crypt-v2 client key (the header tells which).
	tls_crypt: string,
}

Form_Field :: enum u8 {
	Host,
	Port,
	Fingerprint,
	Mtu,
	Mss,
	Ca,
	Tls_Crypt,
	Ciphers,
	Sni,
	Extra,
}

KEY_ED25519 :: "ed25519"
KEY_MLDSA65 :: "mldsa65"

// tun-mtu: the parser takes 100 to 65535; the packet slots of the daemon hold
// at most 2246 bytes of payload, and IPv4 needs 576.
MTU_MIN :: 576
MTU_MAX :: 2246
// mssfix: 0 turns it off; else at least 100 (the parser's limits).
MSS_MIN :: 100
MSS_MAX :: 65535
PEM_MAX :: 65536
EXTRA_MAX :: 8
NAME_MAX :: 64

STATIC_KEY_BEGIN :: "-----BEGIN OpenVPN Static key V1-----"
CRYPT_V2_BEGIN :: "-----BEGIN OpenVPN tls-crypt-v2 client key-----"
CERT_BEGIN :: "-----BEGIN CERTIFICATE-----"

// Options that the form writes itself; an extra line cannot hold them.
@(private, rodata)
form_options := [?]string {
	"client",
	"dev",
	"nobind",
	"remote",
	"proto",
	"port",
	"rport",
	"cert",
	"key",
	"ca",
	"peer-fingerprint",
	"tls-crypt",
	"tls-crypt-v2",
	"tls-auth",
	"auth-user-pass",
	"tun-mtu",
	"mssfix",
	"pq-mode",
	"data-ciphers",
	"ncp-ciphers",
	"tls-transport-sni",
	"connection",
}

transport_default_port :: proc(transport: string) -> int {
	return 443 if transport == "tls" else DEFAULT_PORT
}

// The checks of the form. `s` gives the CA and the tls-crypt key.
form_errors :: proc(f: Form, s: Secrets) -> (errs: [Form_Field]string) {
	host := strings.trim_space(f.host)
	switch {
	case host == "":
		errs[.Host] = "Enter the name or address of the server."
	case !domain_valid(host) && !address_valid(host):
		errs[.Host] = "Use a host name or an IP address."
	}
	if f.port < 1 || f.port > 65535 {
		errs[.Port] = "Use a port from 1 to 65535."
	}
	fp := strings.trim_space(f.fingerprint)
	has_ca := strings.trim_space(s.ca) != ""
	switch {
	case fp != "" && has_ca:
		errs[.Fingerprint] = "Use either the fingerprint or the CA certificate, not both."
	case fp == "" && !has_ca:
		errs[.Fingerprint] = "Enter the fingerprint of the server certificate."
	case fp != "":
		if _, ok := fingerprint_parse(fp); !ok {
			errs[.Fingerprint] = "Use 64 hex digits (32 bytes), with or without colons."
		}
	}
	errs[.Mtu] = number_error(f.mtu, MTU_MIN, MTU_MAX, false)
	errs[.Mss] = number_error(f.mss, MSS_MIN, MSS_MAX, true)
	if has_ca && (!strings.contains(s.ca, CERT_BEGIN) || len(s.ca) > PEM_MAX) {
		errs[.Ca] = "This is not a PEM certificate."
	}
	tc := strings.trim_space(s.tls_crypt)
	if tc != "" && !strings.has_prefix(tc, STATIC_KEY_BEGIN) && !strings.has_prefix(tc, CRYPT_V2_BEGIN) {
		errs[.Tls_Crypt] = "This is not a tls-crypt key."
	}
	if c := strings.trim_space(f.ciphers); c != "" && !ciphers_valid(c) {
		errs[.Ciphers] = "Use AES-256-GCM, AES-128-GCM or CHACHA20-POLY1305, separated by colons."
	}
	if sni := strings.trim_space(f.sni); sni != "" && (!domain_valid(sni) || address_valid(sni)) {
		errs[.Sni] = "Use a host name."
	}
	for line in f.extra {
		if msg := extra_error(line); msg != "" {
			errs[.Extra] = msg
			break
		}
	}
	return
}

// A message for one extra option line, "" when it is good.
extra_error :: proc(line: string) -> string {
	l := strings.trim_space(line)
	if l == "" {
		return ""
	}
	if l[0] == '<' {
		return "Inline blocks cannot be used here."
	}
	p := config.parse_text(l, "extra", config.Parse_Options{loader = refuse_files})
	defer config.parsed_destroy(&p)
	if config.diags_have_error(p.diags) || len(p.directives) != 1 {
		return "Enter exactly one option on this line."
	}
	name := p.directives[0].name
	for o in form_options {
		if name == o {
			return fmt.tprintf("Set %s in the form above instead.", name)
		}
	}
	return ""
}

// The profile text. The caller checks the form first.
form_text :: proc(f: Form, s: Secrets, allocator := context.allocator) -> string {
	sb := strings.builder_make(allocator)
	w :: proc(sb: ^strings.Builder, format: string, args: ..any) {
		fmt.sbprintf(sb, format, ..args)
		strings.write_byte(sb, '\n')
	}
	block :: proc(sb: ^strings.Builder, name, body: string) {
		fmt.sbprintf(sb, "<%s>\n%s", name, body)
		if !strings.has_suffix(body, "\n") {
			strings.write_byte(sb, '\n')
		}
		fmt.sbprintf(sb, "</%s>\n", name)
	}
	proto := "udp"
	switch f.transport {
	case "tcp":
		proto = "tcp-client"
	case "tls":
		proto = "tls-client"
	}
	w(&sb, "client")
	w(&sb, "dev tun")
	w(&sb, "nobind")
	w(&sb, "remote %s %d %s", strings.trim_space(f.host), f.port, proto)
	if fp, ok := fingerprint_parse(strings.trim_space(f.fingerprint)); ok {
		w(&sb, "peer-fingerprint %s", fingerprint_text(fp, context.temp_allocator))
	} else if ca := strings.trim_space(s.ca); ca != "" {
		block(&sb, "ca", ca)
	}
	if f.pq_mode == "off" || f.pq_mode == "require" {
		w(&sb, "pq-mode %s", f.pq_mode)
	}
	if c := strings.trim_space(f.ciphers); c != "" {
		w(&sb, "data-ciphers %s", c)
	}
	if m := strings.trim_space(f.mtu); m != "" {
		w(&sb, "tun-mtu %s", m)
	}
	if m := strings.trim_space(f.mss); m != "" {
		w(&sb, "mssfix %s", m)
	}
	if sni := strings.trim_space(f.sni); sni != "" && f.transport == "tls" {
		w(&sb, "tls-transport-sni %s", sni)
	}
	if f.user_pass {
		w(&sb, "auth-user-pass")
	}
	if tc := strings.trim_space(s.tls_crypt); tc != "" {
		block(&sb, strings.has_prefix(tc, CRYPT_V2_BEGIN) ? "tls-crypt-v2" : "tls-crypt", tc)
	}
	for line in f.extra {
		if l := strings.trim_space(line); l != "" {
			w(&sb, "%s", l)
		}
	}
	block(&sb, "cert", s.cert)
	block(&sb, "key", s.key)
	return strings.to_string(sb)
}

// The inline blocks of a profile text: cert, key, ca and tls-crypt (or
// tls-crypt-v2). The parser copies are wiped.
secrets_read :: proc(text: string, allocator := context.allocator) -> (s: Secrets) {
	p := config.parse_text(text, "profile", config.Parse_Options{loader = refuse_files})
	defer {
		for d in p.directives {
			if d.has_body && len(d.body) > 0 {
				mem.zero_explicit(raw_data(d.body), len(d.body))
			}
		}
		config.parsed_destroy(&p)
	}
	for d in p.directives {
		if !d.has_body {
			continue
		}
		switch d.name {
		case "cert":
			replace(&s.cert, d.body, allocator)
		case "key":
			replace(&s.key, d.body, allocator)
		case "ca":
			replace(&s.ca, d.body, allocator)
		case "tls-crypt", "tls-crypt-v2":
			replace(&s.tls_crypt, d.body, allocator)
		}
	}
	return
}

secrets_destroy :: proc(s: ^Secrets, allocator := context.allocator) {
	for str in ([?]string{s.cert, s.key, s.ca, s.tls_crypt}) {
		wipe_string(str, allocator)
	}
	s^ = {}
}

// Overwrites a string and frees it.
wipe_string :: proc(str: string, allocator := context.allocator) {
	if len(str) > 0 {
		mem.zero_explicit(raw_data(str), len(str))
	}
	delete(str, allocator)
}

// The pin of the peers file: `sha256:` (`mldsa65-sha256:` for an ML-DSA-65
// key) and the digest in standard base64.
pin_text :: proc(mldsa65: bool, digest: [32]u8, allocator := context.allocator) -> string {
	d := digest
	b64, _ := base64.encode(d[:], allocator = context.temp_allocator)
	return strings.concatenate({mldsa65 ? "mldsa65-sha256:" : "sha256:", b64}, allocator)
}

// Name for the peers file (and certificate common name): no spaces, control
// characters, `/` or `\`, no leading `#`, at most 64 bytes. "user" if empty.
peers_name :: proc(name: string, allocator := context.allocator) -> string {
	sb := strings.builder_make(context.temp_allocator)
	for r in strings.trim_space(name) {
		c := r
		switch {
		case r == ' ' || r == '\t':
			c = '-'
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '/' || r == '\\' || r == utf8.RUNE_ERROR:
			continue
		case r == '#' && strings.builder_len(sb) == 0:
			continue
		}
		if strings.builder_len(sb) + utf8.rune_size(c) > NAME_MAX {
			break
		}
		strings.write_rune(&sb, c)
	}
	out := strings.to_string(sb)
	if out == "" || out == "." || out == ".." {
		out = "user"
	}
	return strings.clone(out, allocator)
}

// 32 bytes in hex; colons and spaces between the digits are allowed.
fingerprint_parse :: proc(s: string) -> (digest: [32]u8, ok: bool) {
	n := 0
	half := false
	for c in transmute([]u8)s {
		v: u8
		switch c {
		case '0' ..= '9':
			v = c - '0'
		case 'a' ..= 'f':
			v = c - 'a' + 10
		case 'A' ..= 'F':
			v = c - 'A' + 10
		case ':', ' ':
			if half {
				return {}, false
			}
			continue
		case:
			return {}, false
		}
		if n >= 32 {
			return {}, false
		}
		if half {
			digest[n] |= v
			n += 1
		} else {
			digest[n] = v << 4
		}
		half = !half
	}
	return digest, n == 32 && !half
}

// Upper-case hex with colons, as `openssl x509 -fingerprint` prints it.
fingerprint_text :: proc(digest: [32]u8, allocator := context.allocator) -> string {
	HEX := "0123456789ABCDEF"
	buf: [32 * 3 - 1]u8
	for b, i in digest {
		buf[i * 3] = HEX[b >> 4]
		buf[i * 3 + 1] = HEX[b & 15]
		if i < 31 {
			buf[i * 3 + 2] = ':'
		}
	}
	return strings.clone(string(buf[:]), allocator)
}

form_clone :: proc(f: Form, allocator := context.allocator) -> Form {
	c := f
	c.host = strings.clone(f.host, allocator)
	c.transport = strings.clone(f.transport, allocator)
	c.fingerprint = strings.clone(f.fingerprint, allocator)
	c.key_type = strings.clone(f.key_type, allocator)
	c.mtu = strings.clone(f.mtu, allocator)
	c.mss = strings.clone(f.mss, allocator)
	c.pq_mode = strings.clone(f.pq_mode, allocator)
	c.ciphers = strings.clone(f.ciphers, allocator)
	c.sni = strings.clone(f.sni, allocator)
	c.extra = make([dynamic]string, 0, len(f.extra), allocator)
	for l in f.extra {
		append(&c.extra, strings.clone(l, allocator))
	}
	return c
}

form_destroy :: proc(f: ^Form, allocator := context.allocator) {
	for s in ([?]string{f.host, f.transport, f.fingerprint, f.key_type, f.mtu, f.mss, f.pq_mode, f.ciphers, f.sni}) {
		delete(s, allocator)
	}
	for l in f.extra {
		delete(l, allocator)
	}
	delete(f.extra)
	f^ = {}
}

// "" for an empty text or a number in range; `zero` also allows 0.
@(private)
number_error :: proc(text: string, lo, hi: int, zero: bool) -> string {
	t := strings.trim_space(text)
	if t == "" {
		return ""
	}
	n, ok := strconv.parse_int(t, 10)
	if ok && (n >= lo && n <= hi || zero && n == 0) {
		return ""
	}
	if zero {
		return fmt.tprintf("Use 0 (off) or a number from %d to %d.", lo, hi)
	}
	return fmt.tprintf("Use a number from %d to %d.", lo, hi)
}

// Names of the data-channel ciphers, with `?` for an optional one, and
// DEFAULT; separated by colons.
@(private)
ciphers_valid :: proc(list: string) -> bool {
	l := list
	n := 0
	for item in strings.split_iterator(&l, ":") {
		name := strings.trim_prefix(item, "?")
		switch strings.to_upper(name, context.temp_allocator) {
		case "AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "DEFAULT":
			n += 1
		case:
			return false
		}
	}
	return n > 0
}

@(private)
replace :: proc(dst: ^string, src: string, allocator: mem.Allocator) {
	wipe_string(dst^, allocator)
	dst^ = strings.clone(src, allocator)
}

@(private)
refuse_files :: proc(_: rawptr, _: string, _: mem.Allocator) -> ([]u8, bool) {
	return nil, false
}
