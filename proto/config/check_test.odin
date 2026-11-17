// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

LEGACY :: #load("testdata/legacy.conf", string)
CLIENT_INLINE :: #load("testdata/client-inline.conf", string)
SERVER_PEERKEYS :: #load("testdata/server-peerkeys.conf", string)

find_entry :: proc(r: ^Report, name: string, line := 0) -> (e: Check_Entry, ok: bool) {
	for x in r.entries {
		if x.name == name && (line == 0 || x.line == line) {
			return x, true
		}
	}
	return {}, false
}

@(test)
test_check_legacy_config :: proc(t: ^testing.T) {
	cfg := build(parse_text(LEGACY, "legacy.conf"))
	defer destroy(&cfg)
	r := check_config(&cfg)
	defer report_destroy(&r)

	testing.expect_value(t, r.role, Role.Server)
	testing.expect(t, !report_ok(&r))
	testing.expect_value(t, len(r.entries), 35)
	testing.expect_value(t, r.counts[.Supported], 20)
	testing.expect_value(t, r.counts[.Ignored], 7)
	testing.expect_value(t, r.counts[.Rejected], 7)
	testing.expect_value(t, r.counts[.New], 0)
	testing.expect_value(t, r.unknown, 1)
	testing.expect_value(t, r.errors, 9)
	testing.expect_value(t, r.warnings, 8)

	// Each rejected option has its reason.
	e, ok := find_entry(&r, "comp-lzo", 19)
	testing.expect(t, ok)
	testing.expect_value(t, e.disp, Disposition.Rejected)
	testing.expect(t, e.known)
	testing.expect_value(t, e.status, Check_Status.Error)
	testing.expect(t, strings.contains(e.note, "compression"))
	testing.expect_value(t, e.file, "legacy.conf")

	// A supported option with a bad value is an error too.
	e, ok = find_entry(&r, "topology")
	testing.expect(t, ok)
	testing.expect_value(t, e.disp, Disposition.Supported)
	testing.expect_value(t, e.status, Check_Status.Error)
	e, ok = find_entry(&r, "port")
	testing.expect(t, ok)
	testing.expect_value(t, e.status, Check_Status.Ok)

	e, ok = find_entry(&r, "persist-key")
	testing.expect(t, ok)
	testing.expect_value(t, e.disp, Disposition.Ignored)
	testing.expect_value(t, e.status, Check_Status.Warning)

	e, ok = find_entry(&r, "no-such-option")
	testing.expect(t, ok)
	testing.expect(t, !e.known)
	testing.expect_value(t, e.status, Check_Status.Error)

	// Entries are in file order with their line numbers.
	for i in 1 ..< len(r.entries) {
		testing.expect(t, r.entries[i - 1].line < r.entries[i].line)
	}
}

@(test)
test_check_legacy_report_text :: proc(t: ^testing.T) {
	cfg := build(parse_text(LEGACY, "legacy.conf"))
	defer destroy(&cfg)
	r := check_config(&cfg)
	defer report_destroy(&r)
	text := format_report(&r)
	defer delete(text)

	testing.expect(t, strings.has_prefix(text, "config check: server, 35 options\n"))
	testing.expect(
		t,
		strings.contains(
			text,
			"  rejected   legacy.conf:19  comp-lzo  [error]  -- compression has been removed",
		),
	)
	testing.expect(t, strings.contains(text, "  supported  legacy.conf:3  port\n"))
	testing.expect(
		t,
		strings.contains(text, "  unknown    legacy.conf:37  no-such-option  [error]\n"),
	)
	testing.expect(
		t,
		strings.contains(text, "legacy.conf:10: error: topology: topology net30 is not supported"),
	)
	testing.expect(t, strings.contains(text, "legacy.conf:23: warning: persist-key: ignored"))
	testing.expect(
		t,
		strings.contains(text, "summary: 20 supported, 0 new, 7 ignored, 7 rejected, 1 unknown\n"),
	)
	testing.expect(t, strings.has_suffix(text, "result: FAILED (9 errors, 8 warnings)\n"))
}

@(test)
test_check_good_configs :: proc(t: ^testing.T) {
	cfg := build(parse_text(CLIENT_INLINE, "client-inline.conf"))
	defer destroy(&cfg)
	r := check_config(&cfg)
	defer report_destroy(&r)
	testing.expect(t, report_ok(&r))
	testing.expect_value(t, r.errors, 0)
	testing.expect_value(t, r.warnings, 0)
	testing.expect_value(t, r.unknown, 0)
	testing.expect_value(t, r.counts[.Rejected], 0)
	text := format_report(&r)
	defer delete(text)
	testing.expect(t, strings.contains(text, "config check: client, "))
	testing.expect(t, strings.contains(text, "result: ok (0 errors, 0 warnings)\n"))
	testing.expect(t, !strings.contains(text, "problems:"))
}

@(test)
test_check_new_options_counted :: proc(t: ^testing.T) {
	cfg := build(parse_text(SERVER_PEERKEYS, "s.conf"))
	defer destroy(&cfg)
	r := check_config(&cfg)
	defer report_destroy(&r)
	testing.expect(t, report_ok(&r))
	// peer-keys, pq-mode, workers, datapath, bus-events, bus-control, bus-allow x2
	testing.expect_value(t, r.counts[.New], 8)
	e, ok := find_entry(&r, "peer-keys")
	testing.expect(t, ok)
	testing.expect_value(t, e.disp, Disposition.New)
}

@(test)
test_check_connection_block_entries :: proc(t: ^testing.T) {
	cfg := load_client("<connection>\nremote a\nverb 3\n</connection>\n")
	defer destroy(&cfg)
	r := check_config(&cfg)
	defer report_destroy(&r)
	e, ok := find_entry(&r, "verb")
	testing.expect(t, ok)
	testing.expect(t, e.in_block)
	testing.expect_value(t, e.status, Check_Status.Error)
	text := format_report(&r)
	defer delete(text)
	testing.expect(t, strings.contains(text, "    verb  [error]"))
}

@(test)
test_check_role_unknown_and_empty :: proc(t: ^testing.T) {
	cfg := load("")
	defer destroy(&cfg)
	r := check_config(&cfg)
	defer report_destroy(&r)
	testing.expect(t, !report_ok(&r))
	text := format_report(&r)
	defer delete(text)
	testing.expect(t, strings.has_prefix(text, "config check: unknown role, 0 options\n"))
	testing.expect(t, strings.contains(text, "cannot tell whether this is a client or a server"))
}

@(test)
test_format_diagnostics :: proc(t: ^testing.T) {
	diags := []Diagnostic {
		{.Error, "a.conf", 3, "bad"},
		{.Warning, "b.conf", 0, "careful"},
		{.Error, "", 0, "global"},
		{.Error, "", 7, "line only"},
	}
	text := format_diagnostics(diags)
	defer delete(text)
	testing.expect_value(
		t,
		text,
		"a.conf:3: error: bad\nb.conf: warning: careful\nerror: global\nline 7: error: line only\n",
	)
	empty := format_diagnostics(nil)
	defer delete(empty)
	testing.expect_value(t, empty, "")
}

@(test)
test_sample_client_inline :: proc(t: ^testing.T) {
	cfg := build(parse_text(CLIENT_INLINE, "client-inline.conf"))
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect_value(t, len(cfg.diags), 0)
	c := &cfg.client
	testing.expect_value(t, cfg.role, Role.Client)
	testing.expect_value(t, len(c.connections), 1)
	testing.expect_value(t, c.connections[0].host, "vpn.example.com")
	testing.expect(t, c.remote_random)
	testing.expect_value(t, c.resolv_retry, -1)
	testing.expect(t, c.connections[0].nobind)
	testing.expect_value(t, c.tls.remote_cert_tls, Remote_Cert_Tls.Server)
	testing.expect_value(t, c.tls.version_min, Tls_Version.V1_3)
	testing.expect_value(t, c.tls.reneg_sec, 0)
	testing.expect_value(t, len(c.data_ciphers), 2)
	testing.expect(t, c.tls.ca.is_inline && c.tls.cert.is_inline && c.tls.key.is_inline)
	testing.expect(t, strings.has_prefix(c.tls.ca.data, "-----BEGIN CERTIFICATE-----\n"))
	testing.expect(t, strings.has_suffix(c.tls.key.data, "-----END PRIVATE KEY-----\n"))
	v2, ok := c.connections[0].wrap.tls_crypt_v2.?
	testing.expect(t, ok)
	testing.expect(t, v2.key.is_inline)
	testing.expect(t, strings.contains(v2.key.data, "tls-crypt-v2 client key"))
	testing.expect_value(t, v2.cookie, Cookie_Mode.Force)
}

@(test)
test_sample_server_peerkeys :: proc(t: ^testing.T) {
	cfg := build(parse_text(SERVER_PEERKEYS, "server-peerkeys.conf"))
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	testing.expect_value(t, len(cfg.diags), 0)
	s := &cfg.server
	testing.expect_value(t, cfg.role, Role.Server)
	testing.expect_value(t, len(s.listens), 3)
	if len(s.listens) == 3 {
		testing.expect_value(t, s.listens[1].host, "::")
		testing.expect_value(t, s.listens[1].family, Family.V6)
		testing.expect_value(t, s.listens[2].proto, Proto.Tcp)
		testing.expect_value(t, s.listens[2].port, u16(443))
	}
	testing.expect_value(t, s.peer_keys, "/etc/noirvpn/peers")
	testing.expect_value(t, s.peer_keys_mode, Peer_Keys_Mode.Pin)
	testing.expect(t, !key_source_is_set(s.tls.ca))
	testing.expect_value(t, s.client_config_dir, "/etc/noirvpn/ccd")
	testing.expect(t, s.client_to_client)
	testing.expect_value(t, s.max_clients, 200)
	testing.expect_value(t, s.tls_crypt_v2_max_age, 365)
	testing.expect(t, s.net6 != nil)
	// server (2) + server-ipv6 (1) + keepalive (2) + three explicit pushes.
	testing.expect_value(t, len(s.push), 8)
	testing.expect_value(t, s.bus_events.path, "/run/noirvpn/events")
	testing.expect_value(t, s.bus_events.mode, u32(0o640))
	testing.expect_value(t, s.bus_control.group, "noirvpn")
	testing.expect_value(t, len(s.bus_allow), 2)
	testing.expect_value(t, s.workers, 0)
	testing.expect_value(t, s.ping, 10)
	testing.expect_value(t, s.ping_restart, 120)
}

@(test)
test_sample_legacy_config :: proc(t: ^testing.T) {
	cfg := build(parse_text(LEGACY, "legacy.conf"))
	defer destroy(&cfg)
	testing.expect(t, !ok(&cfg))
	expect_error(t, cfg.diags, 10, "topology net30")
	expect_error(t, cfg.diags, 19, "comp-lzo")
	expect_error(t, cfg.diags, 25, "status")
	expect_error(t, cfg.diags, 30, "up:")
	expect_error(t, cfg.diags, 31, "client-connect")
	expect_error(t, cfg.diags, 32, "management")
	expect_error(t, cfg.diags, 33, "plugin")
	expect_error(t, cfg.diags, 35, "fragment")
	expect_error(t, cfg.diags, 37, "unknown option")
	expect_warning(t, cfg.diags, 17, "use data-ciphers")
}

@(test)
test_check_counts_files :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["main.conf"] = CLIENT_BASE
	files["more.conf"] = "verb 4\n"
	files["top.conf"] = "config main.conf\nconfig more.conf\n"
	cfg := build(parse_file("top.conf", Parse_Options{loader = mem_loader, loader_data = &files}))
	defer destroy(&cfg)
	r := check_config(&cfg)
	defer report_destroy(&r)
	testing.expect(t, report_ok(&r))
	testing.expect_value(t, len(r.files), 3)
	text := format_report(&r)
	defer delete(text)
	testing.expect(t, strings.contains(text, " options in 3 files\n"), text)
	// Included options are marked with the included file.
	e, ok := find_entry(&r, "verb")
	testing.expect(t, ok)
	testing.expect_value(t, e.file, "more.conf")
	testing.expect_value(t, e.line, 1)
}
