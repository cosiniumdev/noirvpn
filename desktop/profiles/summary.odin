// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// The facts of a profile that the list and profile view show.
//
//	summarize(text, allocator) -> (s: Summary, ok: bool)
//	summary_destroy(s, allocator)
package profiles

import "core:mem"
import "core:strconv"
import "core:strings"

import "noir:proto/config"

DEFAULT_PORT :: 1194

Remote :: struct {
	host:  string,
	port:  int,
	// "udp", "tcp" or "tls"; another value is kept in lower case.
	proto: string,
}

Summary :: struct {
	remotes:              [dynamic]Remote,
	dev:                  string,
	has_ca:               bool,
	has_cert:             bool,
	has_key:              bool,
	has_tls_crypt:        bool,
	has_tls_auth:         bool,
	has_tls_crypt_v2:     bool,
	has_peer_fingerprint: bool,
	user_pass:            bool,
	// `auth-user-pass FILE` and `askpass FILE`: the files that the app reads
	// (secret_file.odin), or "".
	login_file:           string,
	pass_file:            string,
	// An `askpass` line: the passphrase of the key is asked for, or read
	// from `pass_file`.
	askpass:              bool,
	// An inline `<auth-user-pass>` block.
	login_inline:         bool,
	// A `disable-dco` line.
	disable_dco:          bool,
}

// ok is false when the text has syntax errors; the summary then has what
// could be read.
summarize :: proc(text: string, allocator := context.allocator) -> (s: Summary, ok: bool) {
	p := parse_profile(text)
	defer config.parsed_destroy(&p)
	s.remotes = make([dynamic]Remote, allocator)
	g := Link_Defaults{"udp", DEFAULT_PORT}
	link_defaults(p.directives, &g)
	for d in p.directives {
		switch d.name {
		case "connection":
			cg := g
			link_defaults(d.block, &cg)
			for c in d.block {
				add_remote(&s, c, cg, allocator)
			}
		case "remote":
			add_remote(&s, d, g, allocator)
		case "dev":
			if len(d.args) > 0 && s.dev == "" {
				s.dev = strings.clone(d.args[0], allocator)
			}
		case "ca":
			s.has_ca = true
		case "cert":
			s.has_cert = true
		case "key":
			s.has_key = true
		case "tls-crypt":
			s.has_tls_crypt = true
		case "tls-auth":
			s.has_tls_auth = true
		case "tls-crypt-v2":
			s.has_tls_crypt_v2 = true
		case "peer-fingerprint":
			s.has_peer_fingerprint = true
		case "auth-user-pass":
			s.user_pass = true
			s.login_inline = d.has_body
			delete(s.login_file, allocator)
			s.login_file = ""
			if !d.has_body && len(d.args) == 1 && d.args[0] != "username-only" {
				s.login_file = strings.clone(d.args[0], allocator)
			}
		case "disable-dco":
			s.disable_dco = true
		case "askpass":
			s.askpass = true
			delete(s.pass_file, allocator)
			s.pass_file = ""
			if len(d.args) == 1 && d.args[0] != "stdin" {
				s.pass_file = strings.clone(d.args[0], allocator)
			}
		}
	}
	return s, !config.diags_have_error(p.diags)
}

summary_destroy :: proc(s: ^Summary, allocator := context.allocator) {
	for r in s.remotes {
		delete(r.host, allocator)
		delete(r.proto, allocator)
	}
	delete(s.remotes)
	delete(s.dev, allocator)
	delete(s.login_file, allocator)
	delete(s.pass_file, allocator)
	s^ = {}
}

// "tcp-client" and "tcp4" give "tcp", "udp6" gives "udp", "tls-client" gives
// "tls". Another value is returned in lower case, in `buf`.
@(private)
proto_normalize :: proc(p: string, buf: []u8) -> string {
	lower := buf[:min(len(p), len(buf))]
	for i in 0 ..< len(lower) {
		c := p[i]
		lower[i] = c >= 'A' && c <= 'Z' ? c + 32 : c
	}
	l := string(lower)
	switch {
	case strings.has_prefix(l, "udp"):
		return "udp"
	case strings.has_prefix(l, "tcp"):
		return "tcp"
	case strings.has_prefix(l, "tls"):
		return "tls"
	}
	return l
}

@(private)
Link_Defaults :: struct {
	proto: string,
	port:  int,
}

// The last proto and port/rport of a list win, as upstream applies them after
// all options are read.
@(private)
link_defaults :: proc(ds: []config.Directive, g: ^Link_Defaults) {
	for d in ds {
		if len(d.args) == 0 {
			continue
		}
		switch d.name {
		case "proto":
			g.proto = d.args[0]
		case "port", "rport":
			if n, ok := port_parse(d.args[0]); ok {
				g.port = n
			}
		}
	}
}

@(private)
add_remote :: proc(s: ^Summary, d: config.Directive, g: Link_Defaults, allocator: mem.Allocator) {
	if d.name != "remote" || len(d.args) == 0 {
		return
	}
	r := Remote{port = g.port}
	if len(d.args) > 1 {
		if n, ok := port_parse(d.args[1]); ok {
			r.port = n
		}
	}
	proto := g.proto
	if len(d.args) > 2 {
		proto = d.args[2]
	}
	buf: [32]u8
	r.host = strings.clone(d.args[0], allocator)
	r.proto = strings.clone(proto_normalize(proto, buf[:]), allocator)
	append(&s.remotes, r)
}

@(private)
port_parse :: proc(s: string) -> (int, bool) {
	n, ok := strconv.parse_int(s, 10)
	if !ok || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// Parses with a loader that refuses every file, so `config` includes are
// reported and never read.
@(private)
parse_profile :: proc(text: string) -> config.Parsed {
	refuse :: proc(_: rawptr, _: string, _: mem.Allocator) -> ([]u8, bool) {
		return nil, false
	}
	return config.parse_text(text, "profile", config.Parse_Options{loader = refuse})
}
