// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:log"
import "core:os"
import "core:strings"
import "core:testing"

@(test)
test_table_sorted_and_unique :: proc(t: ^testing.T) {
	tbl := option_table()
	testing.expect(t, len(tbl) > 250, "the table looks too small")
	for i in 1 ..< len(tbl) {
		testing.expectf(
			t,
			strings.compare(tbl[i - 1].name, tbl[i].name) < 0,
			"rows %d and %d are not in order or are duplicates: '%s' then '%s'",
			i - 1,
			i,
			tbl[i - 1].name,
			tbl[i].name,
		)
	}
}

@(test)
test_table_rows_are_well_formed :: proc(t: ^testing.T) {
	for o in option_table() {
		testing.expectf(
			t,
			o.name != "" && !strings.has_prefix(o.name, "-"),
			"bad name '%s'",
			o.name,
		)
		testing.expectf(t, o.min_args >= 0, "'%s': negative min_args", o.name)
		testing.expectf(
			t,
			o.max_args == -1 || o.max_args >= o.min_args,
			"'%s': max_args below min_args",
			o.name,
		)
		testing.expectf(t, o.section != "", "'%s': no section", o.name)
		testing.expectf(t, len(o.note) >= 8, "'%s': note is missing or too short", o.name)
		if .Push_Only in o.flags {
			testing.expectf(
				t,
				o.applies != .Server,
				"'%s': push-only options are for clients",
				o.name,
			)
		}
		if o.disp == .Rejected {
			// The note gives the reason and what to use instead.
			testing.expectf(
				t,
				len(o.note) >= 20,
				"'%s': rejected option needs a reason and a replacement",
				o.name,
			)
		}
		for ch in transmute([]u8)o.name {
			ok := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-'
			testing.expectf(t, ok, "'%s': unexpected character in name", o.name)
		}
	}
}

@(test)
test_table_counts :: proc(t: ^testing.T) {
	c := option_counts()
	total := 0
	for d in Disposition {
		total += c[d]
	}
	testing.expect_value(t, total, len(option_table()))
	testing.expect_value(t, c[.New], 23)
	testing.expect(t, c[.Supported] > 100)
	testing.expect(t, c[.Rejected] > 80)
	testing.expect(t, c[.Ignored] > 30)
	log.infof(
		"options: %d supported, %d ignored, %d rejected, %d new (%d total)",
		c[.Supported],
		c[.Ignored],
		c[.Rejected],
		c[.New],
		total,
	)
}

@(test)
test_table_new_options :: proc(t: ^testing.T) {
	// The options that are New.
	names := []string {
		"peer-keys",
		"peer-keys-mode",
		"peer-passwords",
		"pq-mode",
		"workers",
		"datapath",
		"dco-socket",
		"auth-external",
		"auth-web",
		"bus-events",
		"bus-control",
		"bus-allow",
		"stats-interval",
		"connect-freq-source",
		"tls-transport-cert",
		"tls-transport-key",
		"tls-transport-accept-tcp",
		"tls-transport-dev",
		"tls-transport-hello",
		"tls-transport-sni",
		"tls-transport-strict",
		"tls-transport-ws",
		"client-service",
	}
	for n in names {
		o := option_find(n)
		testing.expectf(t, o != nil, "'%s' missing", n)
		if o != nil {
			testing.expectf(t, o.disp == .New, "'%s' should be New", n)
		}
	}
	for o in option_table() {
		if o.disp == .New {
			found := false
			for n in names {
				found ||= n == o.name
			}
			testing.expectf(t, found, "'%s' is New but not in the DESIGN list", o.name)
		}
	}
}

@(test)
test_table_dispositions :: proc(t: ^testing.T) {
	Want :: struct {
		name: string,
		disp: Disposition,
	}
	wants := []Want {
		// Supported.
		{"remote", .Supported},
		{"proto", .Supported},
		{"port", .Supported},
		{"local", .Supported},
		{"dev", .Supported},
		{"server", .Supported},
		{"server-ipv6", .Supported},
		{"topology", .Supported},
		{"push", .Supported},
		{"route", .Supported},
		{"route-ipv6", .Supported},
		{"iroute", .Supported},
		{"ifconfig-push", .Supported},
		{"client-config-dir", .Supported},
		{"client-to-client", .Supported},
		{"keepalive", .Supported},
		{"ping", .Supported},
		{"ping-restart", .Supported},
		{"data-ciphers", .Supported},
		{"data-ciphers-fallback", .Supported},
		{"tls-auth", .Supported},
		{"key-direction", .Supported},
		{"auth", .Supported},
		{"tls-crypt", .Supported},
		{"tls-crypt-v2", .Supported},
		{"tls-crypt-v2-max-age", .Supported},
		{"ca", .Supported},
		{"cert", .Supported},
		{"key", .Supported},
		{"peer-fingerprint", .Supported},
		{"tls-groups", .Supported},
		{"tls-version-min", .Supported},
		{"tls-version-max", .Supported},
		{"reneg-sec", .Supported},
		{"reneg-bytes", .Supported},
		{"reneg-pkts", .Supported},
		{"hand-window", .Supported},
		{"tran-window", .Supported},
		{"tun-mtu", .Supported},
		{"mssfix", .Supported},
		{"max-clients", .Supported},
		{"float", .Supported},
		{"explicit-exit-notify", .Supported},
		{"user", .Supported},
		{"group", .Supported},
		{"verb", .Supported},
		{"auth-user-pass", .Supported},
		{"pull", .Supported},
		{"client", .Supported},
		{"nobind", .Supported},
		{"resolv-retry", .Supported},
		{"connect-retry", .Supported},
		{"remote-random", .Supported},
		{"redirect-gateway", .Supported},
		{"pull-filter", .Supported},
		// Rejected: removed or replaced.
		{"compress", .Rejected},
		{"comp-lzo", .Rejected},
		{"management", .Rejected},
		{"up", .Rejected},
		{"down", .Rejected},
		{"script-security", .Ignored},
		{"client-connect", .Rejected},
		{"auth-user-pass-verify", .Rejected},
		{"plugin", .Rejected},
		{"status", .Rejected},
		{"dev-node", .Ignored},
		{"secret", .Rejected},
		{"tls-cipher", .Ignored},
		{"fragment", .Rejected},
		{"daemon", .Ignored},
		{"syslog", .Ignored},
		// Ignored with a warning.
		{"cipher", .Ignored},
		{"dh", .Ignored},
		{"log", .Ignored},
		{"persist-key", .Ignored},
		{"persist-tun", .Supported},
		{"block-ipv6", .Supported},
		{"nice", .Ignored},
	}
	for w in wants {
		o := option_find(w.name)
		if o == nil {
			testing.expectf(t, false, "'%s' is not in the table", w.name)
			continue
		}
		testing.expectf(t, o.disp == w.disp, "'%s': got %v, want %v", w.name, o.disp, w.disp)
	}
}

@(test)
test_table_flags_and_roles :: proc(t: ^testing.T) {
	// Inline-capable options.
	for n in ([]string{"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "peer-fingerprint", "extra-certs", "crl-verify", "auth-user-pass"}) {
		o := option_find(n)
		testing.expectf(t, o != nil && .Inline in o.flags, "'%s' should allow an inline block", n)
	}
	// Roles.
	o := option_find("server")
	testing.expect(t, o != nil && o.applies == .Server)
	o = option_find("remote")
	testing.expect(t, o != nil && o.applies == .Client)
	o = option_find("verb")
	testing.expect(t, o != nil && o.applies == .Both)
	// Pushable.
	for n in ([]string{"route", "route-ipv6", "ping", "ping-restart", "redirect-gateway", "dns", "topology", "ifconfig", "ifconfig-ipv6", "reneg-sec", "block-outside-dns", "block-ipv6"}) {
		o = option_find(n)
		testing.expectf(t, o != nil && .Pushable in o.flags, "'%s' should be pushable", n)
	}
	// Client-config-dir only.
	for n in ([]string{"iroute", "ifconfig-push", "push-reset", "disable"}) {
		o = option_find(n)
		testing.expectf(
			t,
			o != nil && (.Ccd in o.flags || .Ccd_Only in o.flags),
			"'%s' should be valid in a ccd file",
			n,
		)
	}
	// Connection-capable options: the ones the man page lists.
	for n in ([]string{"remote", "proto", "port", "rport", "lport", "local", "nobind", "float", "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "mssfix", "tun-mtu", "explicit-exit-notify", "connect-retry", "connect-timeout"}) {
		o = option_find(n)
		testing.expectf(
			t,
			o != nil && .Connection in o.flags,
			"'%s' should be allowed in <connection>",
			n,
		)
	}
}

@(test)
test_table_find :: proc(t: ^testing.T) {
	testing.expect(t, option_find("remote") != nil)
	testing.expect(t, option_find("") == nil)
	testing.expect(t, option_find("nope") == nil)
	testing.expect(t, option_find("--remote") == nil)
	testing.expect(t, option_find("Remote") == nil)
	// First and last rows are found (edges of the binary search).
	tbl := option_table()
	testing.expect(t, option_find(tbl[0].name) == &tbl[0])
	testing.expect(t, option_find(tbl[len(tbl) - 1].name) == &tbl[len(tbl) - 1])
	for &o in tbl {
		testing.expectf(t, option_find(o.name) == &o, "lookup of '%s' failed", o.name)
	}
}

@(test)
test_table_markdown :: proc(t: ^testing.T) {
	md := option_table_markdown()
	defer delete(md)
	testing.expect(t, strings.contains(md, "| `remote` |"))
	testing.expect(t, strings.contains(md, "| `compress` |"))
	testing.expect(t, strings.contains(md, "| `peer-keys` |"))
	for o in option_table() {
		testing.expectf(
			t,
			strings.contains(
				md,
				strings.concatenate({"| `", o.name, "` |"}, context.temp_allocator),
			),
			"'%s' missing from the Markdown",
			o.name,
		)
	}
}

// Finds the upstream man page sections. Returns "" if they are not there.
man_dir :: proc() -> string {
	if v, ok := os.lookup_env("OPENVPN_MAN_DIR", context.temp_allocator); ok && v != "" {
		return v
	}
	home, ok := os.lookup_env("HOME", context.temp_allocator)
	if !ok || home == "" {
		return ""
	}
	return strings.concatenate(
		{home, "/src/github/openvpn/doc/man-sections"},
		context.temp_allocator,
	)
}

// Every `--option` heading of the upstream man pages needs a row in the table.
// This is skipped when the man pages are not on this machine.
@(test)
test_table_covers_man_headings :: proc(t: ^testing.T) {
	dir := man_dir()
	if dir == "" {
		log.info("skipped: no man page directory")
		return
	}
	infos, err := os.read_all_directory_by_path(dir, context.temp_allocator)
	if err != nil {
		log.infof("skipped: cannot read %s", dir)
		return
	}
	headings := make(map[string]bool, 512, context.temp_allocator)
	files := 0
	for fi in infos {
		if !strings.has_suffix(fi.name, ".rst") {
			continue
		}
		path := strings.concatenate({dir, "/", fi.name}, context.temp_allocator)
		data, rerr := os.read_entire_file(path, context.temp_allocator)
		if rerr != nil {
			testing.expectf(t, false, "cannot read %s", path)
			continue
		}
		files += 1
		it := string(data)
		for line in strings.split_lines_iterator(&it) {
			// Option headings start in column 0 with `--` and a letter or digit.
			if len(line) < 3 || line[0] != '-' || line[1] != '-' {
				continue
			}
			c := line[2]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				continue
			}
			end := strings.index_any(line, " \t")
			name := line[2:] if end < 0 else line[2:end]
			headings[strings.clone(name, context.temp_allocator)] = true
		}
	}
	if files == 0 {
		log.infof("skipped: no .rst files in %s", dir)
		return
	}
	missing := 0
	for name in headings {
		if option_find(name) == nil {
			testing.expectf(t, false, "man page option '--%s' has no row in the table", name)
			missing += 1
		}
	}
	log.infof("%d man page options checked in %d files, %d missing", len(headings), files, missing)

	// The other way: a row that is not a man heading must be a known extra.
	for o in option_table() {
		if o.name in headings {
			continue
		}
		testing.expectf(
			t,
			o.section == "extra" || o.section == "noirvpn",
			"table row '%s' is not in the man pages and is not marked extra",
			o.name,
		)
	}
}
