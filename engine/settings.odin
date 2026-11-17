// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:mem"
import "core:os"
import "core:slice"
import "core:strings"
import "noir:proto/config"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/session"
import "noir:proto/wrap"

// Everything the daemon reads from files before it connects: keys and
// certificates (a reconnect needs no file access) and the checks of what the
// daemon can do with this config. Wiped at exit.

Conn_Keys :: struct {
	mode:       session.Wrap_Mode,
	static_key: wrap.Static_Key,
	client_key: wrap.Client_Key,
	digest:     ossl.Hmac_Alg,
	key_dir:    wrap.Key_Direction,
	// The login at the HTTP proxy of this remote (`http-proxy`), if it has credentials.
	proxy_creds: Creds,
}

Settings :: struct {
	conns:    []Conn_Keys,
	// Our certificate chain and key, and the trust anchors (PEM).
	cert_pem: []u8,
	key_pem:  []u8,
	// The key is encrypted and waits for the passphrase from the terminal
	// (`askpass` with no file): `keys_unlock_prompt` before the start.
	key_wait: bool,
	ca_pem:   []u8,
	verify:   ossl.Peer_Verify,
	crl:      Crl_State, // `crl-verify`
	// Rules for the server certificate and the TLS version range.
	rules:    ossl.Leaf_Rules,
	tls_min:  ossl.Tls_Version,
	tls_max:  ossl.Tls_Version,
	pins:     [][32]u8,
	ciphers:  []push.Cipher,
	groups:   string,
	// Things the daemon refuses (the config cannot be run) and things it
	// ignores although the option is accepted.
	errors:   [dynamic]string,
	warnings: [dynamic]string,
}

settings_destroy :: proc(s: ^Settings) {
	for &c in s.conns {
		wrap.static_key_wipe(&c.static_key)
		wrap.client_key_wipe(&c.client_key)
		cred_wipe(&c.proxy_creds)
	}
	if len(s.key_pem) > 0 {
		mem.zero_explicit(raw_data(s.key_pem), len(s.key_pem))
	}
	delete(s.conns)
	delete(s.cert_pem)
	delete(s.key_pem)
	delete(s.ca_pem)
	crl_destroy(&s.crl)
	leaf_rules_free(&s.rules)
	delete(s.ciphers)
	for e in s.errors {
		delete(e)
	}
	for w in s.warnings {
		delete(w)
	}
	delete(s.errors)
	delete(s.warnings)
	s^ = {}
}

@(private = "file")
add_error :: proc(s: ^Settings, format: string, args: ..any) {
	append(&s.errors, fmt.aprintf(format, ..args))
}

@(private = "file")
add_warning :: proc(s: ^Settings, format: string, args: ..any) {
	append(&s.warnings, fmt.aprintf(format, ..args))
}

// True if a directive with this name was given (also inside `<connection>` blocks).
has_directive :: proc(dirs: []config.Directive, name: string) -> bool {
	for &d in dirs {
		if d.name == name || has_directive(d.block, name) {
			return true
		}
	}
	return false
}

// The first argument of a directive, if given.
first_arg :: proc(dirs: []config.Directive, name: string) -> (arg: string, found: bool) {
	for &d in dirs {
		if d.name == name {
			return (d.args[0] if len(d.args) > 0 else ""), true
		}
		if a, ok := first_arg(d.block, name); ok {
			return a, true
		}
	}
	return "", false
}

@(private = "file")
Not_Done :: struct {
	name: string,
	why:  string,
}

// Options the config accepts but the daemon does not act on yet.
@(private = "file")
NOT_DONE := [?]Not_Done {
	{"float", "the UDP socket only accepts packets from the server address it connected to"},
	{"mtu-disc", "the path MTU discovery mode of the socket is not set"},
	{"mark", "the packet mark is not set on the socket"},
	{"mlock", "memory is not locked"},
	{"replay-window", "the default replay window of the data channel is used"},
	{"push-peer-info", "no extra peer info is sent"},
	{"ping-exit", "ping-exit is not applied"},
}

// Reads the key files and checks the config against what the daemon can do.
// Errors and warnings go to `s`. `ask`: who can type the passphrase of an
// encrypted key (`askpass` with no file).
settings_load :: proc(s: ^Settings, cfg: ^config.Config, ask := Key_Ask.Never) -> bool {
	c := &cfg.client
	dirs := cfg.parsed.directives

	if e := host_priv_error(c.user, c.group); e != "" {
		add_error(s, "%s", e)
	}
	when ODIN_OS == .Darwin {
		if w := utun_dev_warning(c.dev); w != "" {
			add_warning(s, "%s", w)
		}
	}
	for n in NOT_DONE {
		if has_directive(dirs, n.name) {
			add_warning(s, "%s: %s", n.name, n.why)
		}
	}
	if c.tls.capath != "" && !config.key_source_is_set(c.tls.ca) {
		add_error(s, "capath: a CA directory is not supported yet; use ca with one file")
	}
	if config.key_source_is_set(c.tls.ca) && len(c.tls.fingerprints) > 0 {
		add_error(s, "ca together with peer-fingerprint is not supported yet, so use only one of them")
	}
	// A guest lowers a large tun-mtu to `GUEST_MAX_MTU` (`guest_mtu`).
	if ask != .Guest {
		if c.link.tun_mtu > MAX_TUN_PACKET {
			add_error(s, "tun-mtu %d is too large (the limit is %d)", c.link.tun_mtu, MAX_TUN_PACKET)
		}
		for conn in c.connections {
			if conn.tun_mtu > MAX_TUN_PACKET {
				add_error(s, "tun-mtu %d is too large (the limit is %d)", conn.tun_mtu, MAX_TUN_PACKET)
			}
		}
	}

	// The ciphers we offer.
	list := make([dynamic]push.Cipher)
	for x in c.data_ciphers {
		switch x {
		case .Aes_256_Gcm:
			append(&list, push.Cipher.Aes_256_Gcm)
		case .Aes_128_Gcm:
			append(&list, push.Cipher.Aes_128_Gcm)
		case .Chacha20_Poly1305:
			append(&list, push.Cipher.Chacha20_Poly1305)
		}
	}
	s.ciphers = list[:]

	// TLS.
	s.rules = leaf_rules_of(&c.tls)
	s.tls_min, s.tls_max = tls_range_of(&c.tls)
	leaf_rules_problems(&c.tls, dirs, &s.errors)
	switch {
	case len(c.tls.fingerprints) > 0:
		s.verify = .Pinned
		s.pins = c.tls.fingerprints
	case:
		s.verify = .Chain
	}
	if config.key_source_is_set(c.tls.ca) {
		s.ca_pem = read_source(s, c.tls.ca, "ca")
	}
	if crl, ok := c.tls.crl_verify.?; ok {
		if s.verify == .Chain {
			crl_init(&s.crl, crl, s.ca_pem, false, &s.errors, &s.warnings)
		} else {
			add_warning(s, "crl-verify has no effect with peer-fingerprint because the server certificate is checked by its fingerprint, and there is no certificate chain to check against a revocation list")
		}
	}
	if config.key_source_is_set(c.tls.cert) {
		s.cert_pem = read_source(s, c.tls.cert, "cert")
		if config.key_source_is_set(c.tls.extra_certs) {
			extra := read_source(s, c.tls.extra_certs, "extra-certs")
			if len(extra) > 0 {
				joined := make([dynamic]u8)
				append(&joined, ..s.cert_pem)
				if len(joined) > 0 && joined[len(joined) - 1] != '\n' {
					append(&joined, '\n')
				}
				append(&joined, ..extra)
				delete(s.cert_pem)
				s.cert_pem = joined[:]
				delete(extra)
			}
		}
	}
	if config.key_source_is_set(c.tls.key) {
		s.key_pem = read_source(s, c.tls.key, "key")
	}
	slots := [1]Key_Slot{{&s.key_pem, "key"}}
	s.key_wait = keys_unlock(c.tls.askpass, ask, slots[:], &s.errors, &s.warnings)
	switch c.tls.pq_mode {
	case .Prefer:
		s.groups = c.tls.tls_groups
	case .Off:
		s.groups = c.tls.tls_groups if c.tls.tls_groups != "" else "X25519:P-256:P-384:P-521"
	case .Require:
		s.groups = c.tls.tls_groups if c.tls.tls_groups != "" else "X25519MLKEM768"
	}

	// The control wrapping of each remote.
	s.conns = make([]Conn_Keys, len(c.connections))
	for conn, i in c.connections {
		ck := &s.conns[i]
		w := conn.wrap
		switch {
		case w.tls_crypt_v2 != nil:
			v2, _ := w.tls_crypt_v2.?
			ck.mode = .Tls_Crypt_V2
			data := read_source(s, v2.key, "tls-crypt-v2")
			if len(data) > 0 {
				if wrap.client_key_parse(data, &ck.client_key) != .None {
					add_error(s, "tls-crypt-v2: not a tls-crypt-v2 client key file")
				}
				mem.zero_explicit(raw_data(data), len(data))
				delete(data)
			}
		case w.tls_crypt != nil:
			k, _ := w.tls_crypt.?
			ck.mode = .Tls_Crypt
			data := read_source(s, k, "tls-crypt")
			if len(data) > 0 {
				if wrap.static_key_parse(data, &ck.static_key) != .None {
					add_error(s, "tls-crypt: not a static key file")
				}
				mem.zero_explicit(raw_data(data), len(data))
				delete(data)
			}
		case w.tls_auth != nil:
			ta, _ := w.tls_auth.?
			ck.mode = .Tls_Auth
			data := read_source(s, ta.key, "tls-auth")
			if len(data) > 0 {
				if wrap.static_key_parse(data, &ck.static_key) != .None {
					add_error(s, "tls-auth: not a static key file")
				}
				mem.zero_explicit(raw_data(data), len(data))
				delete(data)
			}
			switch ta.digest {
			case .Sha1:
				ck.digest = .SHA1
			case .Sha256:
				ck.digest = .SHA256
			case .Sha512:
				ck.digest = .SHA512
			}
			switch ta.dir {
			case .None:
				ck.key_dir = .Bidirectional
			case .Zero:
				ck.key_dir = .Zero
			case .One:
				ck.key_dir = .One
			}
		case:
			ck.mode = .None
		}
		if px, ok := conn.proxy.?; ok && config.key_source_is_set(px.creds) {
			data := read_source(s, px.creds, "http-proxy credentials")
			if len(data) > 0 {
				if cerr := cred_parse(&ck.proxy_creds, string(data), false); cerr != .None {
					add_error(s, "http-proxy credentials: %s", proxy_cred_error_text(cerr))
				}
				mem.zero_explicit(raw_data(data), len(data))
			}
			delete(data)
		}
	}
	return len(s.errors) == 0
}

@(private = "file")
proxy_cred_error_text :: proc(e: Cred_Error) -> string {
	#partial switch e {
	case .Bad_Format:
		return "the file needs the user name on line 1 and the password on line 2"
	case .Empty_User:
		return "the user name is empty"
	case .Too_Long:
		return "the user name or password is longer than 127 bytes"
	}
	return "cannot use the credentials"
}

// The bytes of a key, certificate or key file. Empty (and an error noted) when
// the file cannot be read. The caller owns the result.
@(private = "file")
read_source :: proc(s: ^Settings, ks: config.Key_Source, what: string) -> []u8 {
	return read_key_source(&s.errors, ks, what)
}

// The same, with the error list given (the server settings use it too).
read_key_source :: proc(errors: ^[dynamic]string, ks: config.Key_Source, what: string) -> []u8 {
	if ks.is_inline {
		return slice.clone(transmute([]u8)ks.data)
	}
	data, err := os.read_entire_file(ks.path, context.allocator)
	if err != nil {
		append(errors, fmt.aprintf("%s: cannot read %s", what, ks.path))
		return nil
	}
	return data
}

// The name for the tun device: "" lets the kernel pick (`tun0`, ...).
tun_name_of :: proc(dev: string) -> string {
	when ODIN_OS == .Darwin {
		return utun_name_of(dev)
	}
	if dev == "tun" {
		when ODIN_OS == .Windows {
			return generic_tun_name()
		} else {
			return ""
		}
	}
	return dev
}

// For the check-config report: the daemon's own notes after the config's.
format_settings_notes :: proc(s: ^Settings) -> string {
	sb := strings.builder_make()
	for e in s.errors {
		fmt.sbprintfln(&sb, "daemon: error: %s", e)
	}
	for w in s.warnings {
		fmt.sbprintfln(&sb, "daemon: warning: %s", w)
	}
	return strings.to_string(sb)
}
