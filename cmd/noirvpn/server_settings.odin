// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:mem"
import "core:strings"
import "noir:proto/config"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/session"
import "noir:proto/wrap"
import "noir:server"

// Everything the server reads from files before it listens: certificate, key,
// trust anchors, control channel keys, and the checks of what the daemon can do
// with this config. Wiped at exit.

Server_Settings :: struct {
	cert_pem:     []u8,
	key_pem:      []u8,
	// Identity of the outer TLS of `tls-server` listeners: the same slices as
	// `cert_pem` and `key_pem` unless `tls-transport-cert` and `-key` are given.
	// Empty when no listener is `tls-server`.
	transport_cert_pem: []u8,
	transport_key_pem:  []u8,
	transport_own:      bool, // the two slices above are ours to free
	// A key is encrypted and waits for the passphrase from the terminal
	// (`askpass` with no file): `keys_unlock_prompt` before the start.
	key_wait:     bool,
	ca_pem:       []u8,
	verify:       ossl.Peer_Verify,
	// `verify-client-cert optional`: a client may send no certificate.
	cert_optional: bool,
	// `optional` with no `ca`, `peer-keys` or `peer-fingerprint`: the server asks
	// for no certificate and the clients log in by password only.
	password_only: bool,
	crl:          Crl_State, // `crl-verify`
	// Rules for client certificates and the TLS version range.
	rules:        ossl.Leaf_Rules,
	tls_min:      ossl.Tls_Version,
	tls_max:      ossl.Tls_Version,
	// `peer-fingerprint` (the whole-certificate hash), when the clients are
	// checked that way.
	fingerprints: [][32]u8,
	ciphers:      []push.Cipher,
	groups:       string,
	// Control channel wrapping.
	wrap_mode:    session.Wrap_Mode,
	static_key:   wrap.Static_Key,
	server_key:   wrap.Server_Key,
	have_v2:      bool,
	digest:       ossl.Hmac_Alg,
	key_dir:      wrap.Key_Direction,
	force_cookie: bool,
	max_age_days: int,
	// The number of keys in the peers file at the time of the check.
	peer_count:   int,
	// The number of users in the password file at the time of the check.
	user_count:   int,
	errors:       [dynamic]string,
	warnings:     [dynamic]string,
}

server_settings_destroy :: proc(s: ^Server_Settings) {
	wrap.static_key_wipe(&s.static_key)
	wipe(s.key_pem)
	mem.zero_explicit(&s.server_key, size_of(s.server_key))
	if s.transport_own {
		wipe(s.transport_key_pem)
		delete(s.transport_cert_pem)
		delete(s.transport_key_pem)
	}
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
add_error :: proc(s: ^Server_Settings, format: string, args: ..any) {
	append(&s.errors, fmt.aprintf(format, ..args))
}

@(private = "file")
add_warning :: proc(s: ^Server_Settings, format: string, args: ..any) {
	append(&s.warnings, fmt.aprintf(format, ..args))
}

// Options the config accepts but the server does not act on.
@(private = "file")
SERVER_NOT_DONE := [?]Not_Done {
	{"mtu-disc", "the server does not set the path MTU discovery mode of its sockets"},
	{"mark", "the server does not set the packet mark on its sockets"},
	{"mlock", "the server does not lock its memory"},
	{"replay-window", "the server uses the default replay window of the data channel"},
	{"ping-exit", "the server does not apply ping-exit"},
	{"inactive", "the server does not apply inactive (use session-timeout in a client-config-dir file instead)"},
	{"session-timeout", "the server does not apply a global session-timeout, so use it in a client-config-dir file instead"},
	{"learn-address", "the server does not run scripts"},
	{"client-connect", "the server does not run scripts"},
	{"client-disconnect", "the server does not run scripts"},
	{"up", "the server does not run scripts"},
	{"down", "the server does not run scripts"},
}

// Options that judge a client certificate. A server with password logins
// only asks for none, so they have nothing to act on.
PASSWORD_ONLY_IGNORED :: [?]string{"crl-verify", "remote-cert-tls", "remote-cert-ku", "remote-cert-eku", "verify-x509-name", "x509-username-field"}

Not_Done :: struct {
	name: string,
	why:  string,
}

// Reads the key files and checks the config against what the server can do.
// `ask` tells who can type the passphrase of an encrypted key (`askpass` with no file).
server_settings_load :: proc(s: ^Server_Settings, cfg: ^config.Config, ask := Key_Ask.Never) -> bool {
	c := &cfg.server
	dirs := cfg.parsed.directives

	if e := priv_settings_error(c.user, c.group); e != "" {
		add_error(s, "%s", e)
	}
	for n in SERVER_NOT_DONE {
		if has_directive(dirs, n.name) {
			add_warning(s, "%s: %s", n.name, n.why)
		}
	}
	if c.tls.capath != "" && !config.key_source_is_set(c.tls.ca) {
		add_error(s, "capath: a CA directory is not supported yet, so use ca with a single file")
	}
	if config.key_source_is_set(c.tls.ca) && len(c.tls.fingerprints) > 0 {
		add_error(s, "ca and peer-fingerprint cannot be used together yet, so use only one of them")
	}
	if c.auth_external != nil && c.bus_control.state == .Off {
		add_error(s, "auth-external needs the control bus, but bus-control is off, so no controller could respond and every login would time out")
	}
	if mtu := server_tun_mtu(c); mtu > MAX_TUN_PACKET {
		add_error(s, "tun-mtu %d is too large (the limit is %d)", mtu, MAX_TUN_PACKET)
	}
	if c.max_clients > 0xFFFF {
		add_error(s, "max-clients %d is too large (the limit is 65535)", c.max_clients)
	}
	if c.link.explicit_exit_notify > 0 && c.link.explicit_exit_notify != 1 {
		add_warning(s, "explicit-exit-notify %d: the server only sends one notice (RESTART or EXIT) to each client", c.link.explicit_exit_notify)
	}
	if c.ping > 0 && !has_directive(dirs, "keepalive") {
		add_warning(s, "ping without keepalive: the interval is also pushed to the clients, so they will ping at the same interval")
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

	// How clients are checked in TLS. A client with no certificate passes the
	// handshake only with `verify-client-cert optional`.
	s.cert_optional = c.verify_client_cert == .Optional
	s.rules = leaf_rules_of(&c.tls)
	s.tls_min, s.tls_max = tls_range_of(&c.tls)
	leaf_rules_problems(&c.tls, dirs, &s.errors)
	switch {
	case c.peer_keys != "" && c.peer_keys_mode == .Both:
		s.verify = .Chain
	case c.peer_keys != "" && c.peer_keys_mode == .Either:
		s.verify = .Pin_Or_Chain
	case c.peer_keys != "":
		s.verify = .Pinned
	case len(c.tls.fingerprints) > 0:
		s.verify = .Pinned
		s.fingerprints = c.tls.fingerprints
	case c.verify_client_cert == .Optional && !config.key_source_is_set(c.tls.ca) && c.tls.capath == "":
		s.verify = .None
		s.password_only = true
	case:
		s.verify = .Chain
	}
	if s.password_only {
		for name in PASSWORD_ONLY_IGNORED {
			if has_directive(dirs, name) {
				add_warning(s, "%s has no effect, because the server does not ask for a client certificate (there is no `ca`, `peer-keys` or `peer-fingerprint`), so clients log in by password only", name)
			}
		}
	}
	if config.key_source_is_set(c.tls.ca) {
		s.ca_pem = read_key_source(&s.errors, c.tls.ca, "ca")
	}
	if crl, ok := c.tls.crl_verify.?; ok {
		if s.verify == .Chain || s.verify == .Pin_Or_Chain {
			crl_init(&s.crl, crl, s.ca_pem, true, &s.errors, &s.warnings)
		} else if s.password_only {
			// Warned about with the other certificate options above.
		} else {
			add_warning(s, "crl-verify has no effect, because the clients are checked by their key (peers file or peer-fingerprint) and there is no certificate chain to check against a revocation list")
		}
	}
	if config.key_source_is_set(c.tls.cert) {
		s.cert_pem = read_key_source(&s.errors, c.tls.cert, "cert")
		if config.key_source_is_set(c.tls.extra_certs) {
			extra := read_key_source(&s.errors, c.tls.extra_certs, "extra-certs")
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
		s.key_pem = read_key_source(&s.errors, c.tls.key, "key")
	}
	load_transport_identity(s, c)
	slots: [2]Key_Slot
	s.key_wait = keys_unlock(c.tls.askpass, ask, server_key_slots(s, &slots), &s.errors, &s.warnings)
	server_transport_follow(s)
	switch c.tls.pq_mode {
	case .Prefer:
		s.groups = c.tls.tls_groups
	case .Off:
		s.groups = c.tls.tls_groups if c.tls.tls_groups != "" else "X25519:P-256:P-384:P-521"
	case .Require:
		s.groups = c.tls.tls_groups if c.tls.tls_groups != "" else "X25519MLKEM768"
	}

	// The control channel wrapping: one plain mode, and tls-crypt-v2 on top or
	// alone.
	w := c.link.wrap
	read_static :: proc(s: ^Server_Settings, ks: config.Key_Source, what: string) {
		data := read_key_source(&s.errors, ks, what)
		if len(data) > 0 {
			if wrap.static_key_parse(data, &s.static_key) != .None {
				add_error(s, "%s: not a static key file", what)
			}
			wipe(data)
			delete(data)
		}
	}
	switch {
	case w.tls_auth != nil:
		ta, _ := w.tls_auth.?
		s.wrap_mode = .Tls_Auth
		read_static(s, ta.key, "tls-auth")
		switch ta.digest {
		case .Sha1:
			s.digest = .SHA1
		case .Sha256:
			s.digest = .SHA256
		case .Sha512:
			s.digest = .SHA512
		}
		switch ta.dir {
		case .None:
			s.key_dir = .Bidirectional
		case .Zero:
			s.key_dir = .Zero
		case .One:
			s.key_dir = .One
		}
	case w.tls_crypt != nil:
		k, _ := w.tls_crypt.?
		s.wrap_mode = .Tls_Crypt
		read_static(s, k, "tls-crypt")
	case w.tls_crypt_v2 != nil:
		s.wrap_mode = .Tls_Crypt_V2
	case:
		s.wrap_mode = .None
	}
	if v2, ok := w.tls_crypt_v2.?; ok {
		data := read_key_source(&s.errors, v2.key, "tls-crypt-v2")
		if len(data) > 0 {
			if wrap.server_key_parse(data, &s.server_key) != .None {
				add_error(s, "tls-crypt-v2: not a tls-crypt-v2 server key file")
			} else {
				s.have_v2 = true
			}
			wipe(data)
			delete(data)
		}
		s.force_cookie = v2.cookie == .Force
		s.max_age_days = c.tls_crypt_v2_max_age
	}
	return len(s.errors) == 0
}

// The private keys of the settings: `key`, and `tls-transport-key` when the
// outer TLS has a key of its own.
server_key_slots :: proc(s: ^Server_Settings, buf: ^[2]Key_Slot) -> []Key_Slot {
	buf[0] = {&s.key_pem, "key"}
	if !s.transport_own {
		return buf[:1]
	}
	buf[1] = {&s.transport_key_pem, "tls-transport-key"}
	return buf[:]
}

// After `key` is decrypted: the outer TLS with no key of its own uses the new text.
server_transport_follow :: proc(s: ^Server_Settings) {
	if !s.transport_own && len(s.transport_cert_pem) > 0 {
		s.transport_key_pem = s.key_pem
	}
}

// Certificate and key of the outer TLS (`tls-server` listeners): those of
// `tls-transport-cert` and `-key`, or `cert` and `key`. The outer identity must
// be classical: a middlebox can refuse an unknown signature algorithm, so an
// ML-DSA certificate stays on the inner session.
@(private = "file")
load_transport_identity :: proc(s: ^Server_Settings, c: ^config.Server_Config) {
	any_tls := false
	for l in c.listens {
		any_tls ||= l.tls
	}
	if !any_tls {
		return
	}
	own := config.key_source_is_set(c.tls.transport_cert)
	if own {
		s.transport_own = true
		s.transport_cert_pem = read_key_source(&s.errors, c.tls.transport_cert, "tls-transport-cert")
		s.transport_key_pem = read_key_source(&s.errors, c.tls.transport_key, "tls-transport-key")
	} else {
		s.transport_cert_pem, s.transport_key_pem = s.cert_pem, s.key_pem
	}
	if len(s.transport_cert_pem) == 0 {
		return // read_key_source reported it, or `cert` is missing (reported by the config)
	}
	switch ossl.cert_key_kind(s.transport_cert_pem) {
	case .Rsa, .Ec, .Ed25519:
	case .Invalid:
		if own {
			add_error(s, "tls-transport-cert: cannot read a certificate from the file")
		}
	case .Other:
		if own {
			add_error(s, "tls-transport-cert: the outer TLS of `proto tls-server` needs a classical key (ECDSA or RSA), but this certificate has a different kind (ML-DSA?), and a middlebox can refuse an unknown signature algorithm")
		} else {
			add_error(s, "`proto tls-server` uses `cert` for the outer TLS, but its key is not a classical one (ECDSA or RSA; ML-DSA?), and a middlebox can refuse an unknown signature algorithm. Set an ECDSA or RSA certificate and key with tls-transport-cert and tls-transport-key")
		}
	}
}

// The peers file, read once for the check (the daemon loads it again when it
// starts). Adds to `s.errors` when the file cannot be used.
server_settings_check_peers :: proc(s: ^Server_Settings, cfg: ^config.Server_Config) {
	if cfg.peer_keys == "" {
		return
	}
	t, text := server.pin_table_load(cfg.peer_keys)
	if t == nil {
		for line in strings.split_lines(strings.trim_space(text), context.temp_allocator) {
			add_error(s, "peers file: %s", line)
		}
		delete(text)
		return
	}
	s.peer_count = server.pin_table_len(t)
	if t.shadowed > 0 {
		add_warning(s, "peers file: %d line(s) repeat a key from an earlier line, so only the first one is used", t.shadowed)
	}
	server.pin_table_destroy(t)
}

// The password file, read once for the check. A file that cannot be read is a
// warning: the daemon starts, and every password check fails until it loads.
server_settings_check_passwords :: proc(s: ^Server_Settings, cfg: ^config.Server_Config) {
	if cfg.peer_passwords == "" {
		return
	}
	t, why := pw_read_file(cfg.peer_passwords)
	if t == nil {
		add_warning(s, "peer-passwords %s: cannot read the file: %s, so every password check will fail until it can be loaded", cfg.peer_passwords, why)
		return
	}
	s.user_count = server.pw_len(t)
	for w in t.warnings {
		add_warning(s, "peer-passwords: %s", w)
	}
	if hidden := t.skipped + t.duplicates - len(t.warnings); hidden > 0 {
		add_warning(s, "peer-passwords: %d more line(s) were skipped and are not listed", hidden)
	}
	server.pw_destroy(t)
}

// For the check-config report: the daemon's own notes after the config's.
format_server_notes :: proc(s: ^Server_Settings) -> string {
	sb := strings.builder_make()
	for e in s.errors {
		fmt.sbprintfln(&sb, "daemon: error: %s", e)
	}
	for w in s.warnings {
		fmt.sbprintfln(&sb, "daemon: warning: %s", w)
	}
	return strings.to_string(sb)
}
