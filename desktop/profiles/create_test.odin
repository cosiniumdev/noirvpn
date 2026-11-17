// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:os"
import "core:strings"
import "core:testing"

import "noir:proto/config"

@(private = "file")
FP :: "28:61:7C:C6:BA:52:47:69:EA:9B:5A:7E:4C:C3:96:08:E7:D9:5F:FA:1F:40:69:F3:27:DF:70:D0:B9:FA:2A:F2"

@(private = "file")
good_form :: proc() -> Form {
	return Form{host = "vpn.example.com", port = 1194, transport = "udp", fingerprint = FP, key_type = KEY_ED25519}
}

@(private = "file")
good_secrets :: proc() -> Secrets {
	return Secrets{cert = PEM_CA, key = PEM_KEY}
}

@(private = "file")
no_errors :: proc(errs: [Form_Field]string) -> bool {
	for e in errs {
		if e != "" {
			return false
		}
	}
	return true
}

@(test)
test_form_errors :: proc(t: ^testing.T) {
	testing.expect(t, no_errors(form_errors(good_form(), good_secrets())))

	f := good_form()
	f.host = ""
	f.port = 0
	errs := form_errors(f, {})
	testing.expect(t, errs[.Host] != "" && errs[.Port] != "")
	f.host = "bad host"
	testing.expect(t, form_errors(f, {})[.Host] != "")
	f.host = "2001:db8::10"
	testing.expect(t, form_errors(f, {})[.Host] == "")

	f = good_form()
	f.fingerprint = ""
	testing.expect(t, strings.contains(form_errors(f, {})[.Fingerprint], "Enter"))
	testing.expect(t, form_errors(f, {ca = PEM_CA})[.Fingerprint] == "")
	f.fingerprint = FP
	testing.expect(t, strings.contains(form_errors(f, {ca = PEM_CA})[.Fingerprint], "not both"))
	f.fingerprint = "28617CC6BA524769EA9B5A7E4CC39608E7D95FFA1F4069F327DF70D0B9FA2AF2"
	testing.expect(t, form_errors(f, {})[.Fingerprint] == "")
	f.fingerprint = "28:61:7C"
	testing.expect(t, form_errors(f, {})[.Fingerprint] != "")
	f.fingerprint = strings.concatenate({FP, ":00"}, context.temp_allocator)
	testing.expect(t, form_errors(f, {})[.Fingerprint] != "")

	f = good_form()
	for m in ([]string{"576", "1400", "2246", " 1500 "}) {
		f.mtu = m
		testing.expectf(t, form_errors(f, {})[.Mtu] == "", "mtu %q", m)
	}
	for m in ([]string{"575", "2247", "x", "0", "-1"}) {
		f.mtu = m
		testing.expectf(t, form_errors(f, {})[.Mtu] != "", "mtu %q", m)
	}
	f.mtu = ""
	for m in ([]string{"0", "100", "1450", "65535"}) {
		f.mss = m
		testing.expectf(t, form_errors(f, {})[.Mss] == "", "mss %q", m)
	}
	for m in ([]string{"99", "65536", "1", "abc"}) {
		f.mss = m
		testing.expectf(t, form_errors(f, {})[.Mss] != "", "mss %q", m)
	}

	f = good_form()
	testing.expect(t, form_errors(f, {tls_crypt = "hello"})[.Tls_Crypt] != "")
	testing.expect(t, form_errors(f, {tls_crypt = STATIC_KEY})[.Tls_Crypt] == "")
	f.fingerprint = ""
	testing.expect(t, form_errors(f, {ca = "not a pem"})[.Ca] != "")
	f = good_form()
	f.ciphers = "AES-256-GCM:?chacha20-poly1305"
	testing.expect(t, form_errors(f, {})[.Ciphers] == "")
	f.ciphers = "AES-256-CBC"
	testing.expect(t, form_errors(f, {})[.Ciphers] != "")
	f = good_form()
	f.sni = "front.example.net"
	testing.expect(t, form_errors(f, {})[.Sni] == "")
	f.sni = "192.0.2.1"
	testing.expect(t, form_errors(f, {})[.Sni] != "")
	f = good_form()
	append(&f.extra, "verb 4", "")
	testing.expect(t, form_errors(f, {})[.Extra] == "")
	append(&f.extra, "remote other.example.com")
	testing.expect(t, strings.contains(form_errors(f, {})[.Extra], "remote"))
	delete(f.extra)
	f.extra = nil
	append(&f.extra, "<ca>")
	testing.expect(t, form_errors(f, {})[.Extra] != "")
	delete(f.extra)
}

@(private = "file")
directive_args :: proc(p: config.Parsed, name: string) -> (args: []string, body: string, found: bool) {
	for d in p.directives {
		if d.name == name {
			return d.args, d.body, true
		}
	}
	return
}

@(test)
test_form_text :: proc(t: ^testing.T) {
	s := good_secrets()
	for tr in ([]string{"udp", "tcp", "tls"}) {
		f := good_form()
		f.transport = tr
		f.port = transport_default_port(tr)
		text := form_text(f, s, context.temp_allocator)
		p := config.parse_text(text, "t")
		defer config.parsed_destroy(&p)
		testing.expectf(t, !config.diags_have_error(p.diags), "%s: parses", tr)
		args, _, ok := directive_args(p, "remote")
		want := tr == "udp" ? "udp" : tr == "tcp" ? "tcp-client" : "tls-client"
		testing.expectf(t, ok && len(args) == 3 && args[0] == "vpn.example.com" && args[2] == want, "%s: remote %v", tr, args)
		testing.expect(t, args[1] == (tr == "tls" ? "443" : "1194"))
		fp, _, has_fp := directive_args(p, "peer-fingerprint")
		testing.expect(t, has_fp && len(fp) == 1 && fp[0] == FP)
		_, cert, has_cert := directive_args(p, "cert")
		_, key, has_key := directive_args(p, "key")
		testing.expect(t, has_cert && cert == PEM_CA && has_key && key == PEM_KEY)
		for absent in ([]string{"tun-mtu", "mssfix", "pq-mode", "auth-user-pass", "ca", "tls-crypt", "tls-transport-sni"}) {
			_, _, has := directive_args(p, absent)
			testing.expectf(t, !has, "%s: no %s by default", tr, absent)
		}
		testing.expect(t, strings.has_prefix(text, "client\ndev tun\nnobind\nremote "))
	}

	// A CA in place of the fingerprint, and every option.
	f := good_form()
	f.transport = "tls"
	f.port = 8443
	f.fingerprint = ""
	f.mtu = "1380"
	f.mss = "1300"
	f.user_pass = true
	f.pq_mode = "require"
	f.ciphers = "CHACHA20-POLY1305"
	f.sni = "front.example.net"
	append(&f.extra, "verb 4")
	defer delete(f.extra)
	s.ca = strings.trim_space(PEM_CA)
	s.tls_crypt = STATIC_KEY
	text := form_text(f, s, context.temp_allocator)
	p := config.parse_text(text, "t")
	defer config.parsed_destroy(&p)
	testing.expect(t, !config.diags_have_error(p.diags))
	check :: proc(t: ^testing.T, p: config.Parsed, name, arg: string, loc := #caller_location) {
		args, _, ok := directive_args(p, name)
		testing.expectf(t, ok && (arg == "" && len(args) == 0 || len(args) == 1 && args[0] == arg), "%s %v", name, args, loc = loc)
	}
	check(t, p, "tun-mtu", "1380")
	check(t, p, "mssfix", "1300")
	check(t, p, "auth-user-pass", "")
	check(t, p, "pq-mode", "require")
	check(t, p, "data-ciphers", "CHACHA20-POLY1305")
	check(t, p, "tls-transport-sni", "front.example.net")
	check(t, p, "verb", "4")
	_, ca, has_ca := directive_args(p, "ca")
	_, tc, has_tc := directive_args(p, "tls-crypt")
	testing.expect(t, has_ca && ca == PEM_CA && has_tc && tc == STATIC_KEY)
	_, _, has_fp := directive_args(p, "peer-fingerprint")
	testing.expect(t, !has_fp)

	// The SNI goes only with the tls transport; a tls-crypt-v2 key has its own block.
	f.transport = "udp"
	s.tls_crypt = "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nabc\n-----END OpenVPN tls-crypt-v2 client key-----\n"
	text = form_text(f, s, context.temp_allocator)
	testing.expect(t, !strings.contains(text, "tls-transport-sni") && strings.contains(text, "<tls-crypt-v2>\n-----BEGIN OpenVPN tls-crypt-v2"))

	// The rules of the service for a user profile accept each form of the text.
	for tr in ([]string{"udp", "tcp", "tls"}) {
		g := f
		g.transport = tr
		g.fingerprint = tr == "tcp" ? FP : ""
		sec := s
		if tr == "tcp" {
			sec.ca = ""
		}
		up := config.user_profile_build(form_text(g, sec, context.temp_allocator))
		testing.expectf(t, up.ok, "%s: user profile rules: %v %v", tr, up.problems, up.cfg.diags)
		config.user_profile_destroy(&up)
	}

	text = form_text(good_form(), good_secrets(), context.temp_allocator)
	back := secrets_read(text)
	defer secrets_destroy(&back)
	testing.expect(t, back.cert == PEM_CA && back.key == PEM_KEY && back.ca == "" && back.tls_crypt == "")
}

@(test)
test_pin_text :: proc(t: ^testing.T) {
	d: [32]u8
	for i in 0 ..< 32 {
		d[i] = u8(i * 7 + 1)
	}
	ed := pin_text(false, d, context.temp_allocator)
	ml := pin_text(true, d, context.temp_allocator)
	testing.expect(t, strings.has_prefix(ed, "sha256:") && len(ed) == 7 + 44 && strings.has_suffix(ed, "="))
	testing.expect(t, strings.has_prefix(ml, "mldsa65-sha256:"))

	// The peers file parser takes the line that the GUI offers.
	name := peers_name("Alice's laptop")
	defer delete(name)
	testing.expect_value(t, name, "Alice's-laptop")
	line := strings.concatenate({name, " ", ed, "\n", "bob ", ml, "\n"}, context.temp_allocator)
	peers := config.peers_parse(line)
	defer config.peers_destroy(&peers)
	testing.expect(t, config.peers_ok(&peers) && len(peers.entries) == 2)
	if len(peers.entries) == 2 {
		testing.expect(t, peers.entries[0].user == "Alice's-laptop" && peers.entries[0].pin.kind == .Sha256 && peers.entries[0].pin.digest == d)
		testing.expect(t, peers.entries[1].pin.kind == .Mldsa65_Sha256 && peers.entries[1].pin.digest == d)
	}
}

@(test)
test_peers_name :: proc(t: ^testing.T) {
	cases := [?][2]string {
		{"Work VPN", "Work-VPN"},
		{"  a/b\\c  ", "abc"},
		{"#home", "home"},
		{"..", "user"},
		{"", "user"},
		{"a\tb\x01c", "a-bc"},
	}
	for c in cases {
		got := peers_name(c[0], context.temp_allocator)
		testing.expectf(t, got == c[1], "%q: got %q", c[0], got)
	}
	long := peers_name(strings.repeat("é", 40, context.temp_allocator), context.temp_allocator)
	testing.expect(t, len(long) == NAME_MAX)
}

@(test)
test_fingerprint :: proc(t: ^testing.T) {
	d, ok := fingerprint_parse("28617cc6ba524769ea9b5a7e4cc39608e7d95ffa1f4069f327df70d0b9fa2af2")
	testing.expect(t, ok)
	testing.expect_value(t, fingerprint_text(d, context.temp_allocator), FP)
	for bad in ([]string{"", "2", "28:6", "zz" + FP[2:], FP + "0"}) {
		_, ok = fingerprint_parse(bad)
		testing.expectf(t, !ok, "%q", bad)
	}
}

// A created profile keeps its form in meta.json; an imported one has none,
// and an old meta.json without the key still reads.
@(test)
test_store_form :: proc(t: ^testing.T) {
	base := test_dir(t)
	defer test_dir_remove(base)
	s := store_open(base)
	defer store_close(&s)
	f := good_form()
	f.mtu = "1380"
	append(&f.extra, "verb 4")
	defer delete(f.extra)
	id, ok := store_create_form(s, "Made", "client\n", f, context.temp_allocator)
	testing.expect(t, ok)
	plain, ok2 := store_create(s, "Plain", "client\n", context.temp_allocator)
	testing.expect(t, ok2)

	meta, _, found := store_load(s, id, context.temp_allocator)

	back, has := meta.form.?
	testing.expect(t, found && has && back.host == f.host && back.port == 1194 && back.fingerprint == FP && back.mtu == "1380" && back.key_type == KEY_ED25519 && len(back.extra) == 1)

	pm, _, pfound := store_load(s, plain, context.temp_allocator)

	_, phas := pm.form.?
	testing.expect(t, pfound && !phas)
	raw, _ := os.read_entire_file(strings.concatenate({base, "/", plain, "/meta.json"}, context.temp_allocator), context.temp_allocator)
	testing.expect(t, !strings.contains(string(raw), "\"form\""))

	old := strings.concatenate({base, "/", plain, "/meta.json"}, context.temp_allocator)
	testing.expect(t, os.write_entire_file(old, `{"id":"x","name":"Old","created":1,"overrides":{"ignore_server_dns":true}}`) == nil)
	om, _, ofound := store_load(s, plain, context.temp_allocator)

	_, ohas := om.form.?
	testing.expect(t, ofound && om.name == "Old" && !ohas && om.overrides.ignore_server_dns && om.overrides.tun_mtu == "")

	dup, dok := store_duplicate(s, id, "Made copy", context.temp_allocator)
	dm, _, _ := store_load(s, dup, context.temp_allocator)

	dform, dhas := dm.form.?
	testing.expect(t, dok && dhas && dform.host == f.host)
}

@(test)
test_override_mtu :: proc(t: ^testing.T) {
	o := Overrides{tun_mtu = "1380", mssfix = "0"}
	lines := override_lines(o, context.temp_allocator)
	testing.expect_value(t, lines, "tun-mtu 1380\nmssfix 0\n")
	ps := overrides_check(o)
	testing.expect(t, len(ps) == 0)
	problems_destroy(&ps)
	bad := Overrides{tun_mtu = "40", mssfix = "50"}
	testing.expect_value(t, override_lines(bad, context.temp_allocator), "")
	ps = overrides_check(bad)
	testing.expect(t, len(ps) == 2)
	problems_destroy(&ps)

	// The parser of the daemon takes the last tun-mtu and mssfix lines.
	f := good_form()
	f.mtu, f.mss = "1500", "1450"
	text := compose(form_text(f, good_secrets(), context.temp_allocator), o, context.temp_allocator)
	cfg := config.build(config.parse_text(text, "t"))
	defer config.destroy(&cfg)
	testing.expectf(t, config.ok(&cfg), "%v", cfg.diags)
	testing.expect_value(t, len(cfg.client.connections), 1)
	if len(cfg.client.connections) == 1 {
		conn := cfg.client.connections[0]
		testing.expect_value(t, conn.tun_mtu, 1380)
		testing.expect_value(t, conn.mssfix.kind, config.Mssfix_Kind.Off)
	}
}
