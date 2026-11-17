// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package sysnet

import "core:os"
import "core:strings"
import "core:testing"

// ---- pure checks ----

@(test)
dns_valid_domain_table :: proc(t: ^testing.T) {
	good := []string{"example.com", "a", "a.b.c", "corp.example.", "x-y.z_w", "1.2.3.example", "."}
	for s in good {
		testing.expectf(t, dns_valid_domain(s), "%q should be valid", s)
	}
	bad := []string {
		"",
		"-bad.example",
		".leading",
		"a..b",
		"has space.example",
		"new\nline.example",
		"semi;colon",
		"~tilde.example",
		"slash/inside",
		"quote\".example",
		"ü.example",
	}
	for s in bad {
		testing.expectf(t, !dns_valid_domain(s), "%q should be refused", s)
	}
	long_label := strings.repeat("a", 64, context.temp_allocator)
	testing.expect(t, !dns_valid_domain(long_label))
	testing.expect(t, dns_valid_domain(strings.repeat("a", 63, context.temp_allocator)))
	too_long := strings.repeat("abcdefgh.", 29, context.temp_allocator) // 261 bytes
	testing.expect(t, !dns_valid_domain(too_long))
}

@(test)
dns_valid_ifname_table :: proc(t: ^testing.T) {
	for s in ([]string{"tun0", "noirvpn0", "a-b_c.d", "T"}) {
		testing.expectf(t, dns_valid_ifname(s), "%q should be valid", s)
	}
	for s in ([]string{"", "-tun", ".tun", "tun 0", "tun/0", "tun;0", "0123456789abcdef", "tun\n"}) {
		testing.expectf(t, !dns_valid_ifname(s), "%q should be refused", s)
	}
}

@(test)
dns_server_text_forms :: proc(t: ^testing.T) {
	cases := []struct {
		sv:   DNS_Server,
		want: string,
	} {
		{{IP4_Address{10, 8, 0, 1}, 0}, "10.8.0.1"},
		{{IP4_Address{10, 8, 0, 1}, 853}, "10.8.0.1:853"},
		{{IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}, 0}, "2001:db8::1"},
		{{IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}, 853}, "[2001:db8::1]:853"},
	}
	for c in cases {
		got := dns_server_text(c.sv, context.temp_allocator)
		testing.expect_value(t, got, c.want)
	}
}

@(test)
dns_resolved_domain_args :: proc(t: ^testing.T) {
	s := DNS_Settings {
		search_domains  = {"corp.example", "lan"},
		routing_domains = {"internal.example"},
		default_route   = true,
	}
	got := dns_resolved_domains(s, context.temp_allocator)
	want := []string{"corp.example", "lan", "~internal.example", "~."}
	testing.expect_value(t, len(got), len(want))
	for w, i in want {
		if i < len(got) {
			testing.expect_value(t, got[i], w)
		}
	}
	none := dns_resolved_domains({}, context.temp_allocator)
	testing.expect_value(t, len(none), 0)
}

@(test)
dns_resolv_conf_text :: proc(t: ^testing.T) {
	warnings := make([dynamic]string, context.temp_allocator)
	s := DNS_Settings {
		servers        = {{IP4_Address{10, 8, 0, 1}, 0}, {IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 1}, 0}},
		search_domains = {"corp.example", "lan"},
	}
	text, err := dns_resolv_conf("tun0", s, true, &warnings, context.temp_allocator)
	testing.expect_value(t, err, DNS_Error.None)
	want := "# noirvpn: DNS for tun0. The previous settings will be restored when the VPN disconnects.\n" + "nameserver 10.8.0.1\n" + "nameserver fd00::1\n" + "search corp.example lan\n"
	testing.expect_value(t, text, want)
	testing.expect_value(t, len(warnings), 0)
	testing.expect(t, strings.has_prefix(text, DNS_MARKER))

	// Without the marker line (resolvconf).
	plain, perr := dns_resolv_conf("tun0", s, false, &warnings, context.temp_allocator)
	testing.expect_value(t, perr, DNS_Error.None)
	testing.expect(t, !strings.has_prefix(plain, "#"))
}

@(test)
dns_resolv_conf_limits :: proc(t: ^testing.T) {
	warnings := make([dynamic]string, context.temp_allocator)
	// Five servers, one with a port: the port one is dropped, three are kept.
	s := DNS_Settings {
		servers = {
			{IP4_Address{10, 0, 0, 1}, 0},
			{IP4_Address{10, 0, 0, 2}, 5353},
			{IP4_Address{10, 0, 0, 3}, 0},
			{IP4_Address{10, 0, 0, 4}, 0},
			{IP4_Address{10, 0, 0, 5}, 0},
		},
		search_domains = {"a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example"},
		routing_domains = {"x.example"},
	}
	text, err := dns_resolv_conf("tun0", s, false, &warnings, context.temp_allocator)
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect_value(t, strings.count(text, "nameserver "), 3)
	testing.expect(t, strings.contains(text, "nameserver 10.0.0.1\n"))
	testing.expect(t, !strings.contains(text, "10.0.0.2"))
	testing.expect(t, !strings.contains(text, "10.0.0.5"))
	testing.expect(t, strings.contains(text, "search a.example b.example c.example d.example e.example f.example\n"))
	testing.expect(t, !strings.contains(text, "g.example"))
	// port, server limit, search limit, routing domains.
	testing.expect_value(t, len(warnings), 4)

	// Only servers with ports: nothing usable.
	only_port := DNS_Settings {
		servers = {{IP4_Address{10, 0, 0, 2}, 5353}},
	}
	_, perr := dns_resolv_conf("tun0", only_port, false, &warnings, context.temp_allocator)
	testing.expect_value(t, perr, DNS_Error.Invalid)
}

@(test)
dns_settings_check_cases :: proc(t: ^testing.T) {
	ok := DNS_Settings {
		servers = {{IP4_Address{10, 8, 0, 1}, 0}},
	}
	testing.expect_value(t, dns_settings_check(ok), DNS_Error.None)
	testing.expect_value(t, dns_settings_check({}), DNS_Error.Invalid)
	bad_search := ok
	bad_search.search_domains = {"has space"}
	testing.expect_value(t, dns_settings_check(bad_search), DNS_Error.Invalid)
	dot_search := ok
	dot_search.search_domains = {"."}
	testing.expect_value(t, dns_settings_check(dot_search), DNS_Error.Invalid)
	bad_route := ok
	bad_route.routing_domains = {"-x"}
	testing.expect_value(t, dns_settings_check(bad_route), DNS_Error.Invalid)
	nil_addr := DNS_Settings {
		servers = {{nil, 0}},
	}
	testing.expect_value(t, dns_settings_check(nil_addr), DNS_Error.Invalid)
}

@(test)
dns_settings_clone_is_deep :: proc(t: ^testing.T) {
	src := DNS_Settings {
		servers         = {{IP4_Address{10, 8, 0, 1}, 53}},
		search_domains  = {"corp.example"},
		routing_domains = {"x.example"},
		default_route   = true,
	}
	c, err := dns_settings_clone(src)
	testing.expect_value(t, err, nil)
	defer dns_settings_destroy(&c)
	testing.expect_value(t, len(c.servers), 1)
	testing.expect_value(t, c.search_domains[0], "corp.example")
	testing.expect_value(t, c.routing_domains[0], "x.example")
	testing.expect(t, c.default_route)
	testing.expect(t, raw_data(c.search_domains[0]) != raw_data(src.search_domains[0]))
}

// ---- a fake command runner and a temporary directory ----

Fake_Call :: struct {
	argv:  []string,
	stdin: string,
}

Fake_Runner :: struct {
	calls:    [dynamic]Fake_Call,
	// Exit code for call number i (0-based); missing = 0.
	codes:    map[int]int,
	// The process cannot be started for every call.
	no_start: bool,
}

fake_run :: proc(data: rawptr, argv: []string, stdin: string) -> (int, bool) {
	f := (^Fake_Runner)(data)
	cloned := make([]string, len(argv))
	for a, i in argv {
		cloned[i] = strings.clone(a)
	}
	append(&f.calls, Fake_Call{argv = cloned, stdin = strings.clone(stdin)})
	if f.no_start {
		return -1, false
	}
	return f.codes[len(f.calls) - 1], true
}

fake_destroy :: proc(f: ^Fake_Runner) {
	for c in f.calls {
		for a in c.argv {
			delete(a)
		}
		delete(c.argv)
		delete(c.stdin)
	}
	delete(f.calls)
	delete(f.codes)
}

// "a b c" for call i.
call_text :: proc(f: ^Fake_Runner, i: int) -> string {
	if i >= len(f.calls) {
		return "<no such call>"
	}
	return strings.join(f.calls[i].argv, " ", context.temp_allocator)
}

Test_Dir :: struct {
	root:     string,
	bin:      string,
	resolved: string,
	conf:     string,
	backup:   string,
	// Where the fake resolvconf keeps its records (not created until a test needs it).
	records:  [1]string,
}

// A temporary directory with `bin/` and an empty `resolved/` inside. Nothing
// outside it is touched.
test_dir_make :: proc(t: ^testing.T) -> (d: Test_Dir, ok: bool) {
	root, err := os.make_directory_temp("", "noirvpn-dns-test-*", context.allocator)
	if err != nil {
		testing.expectf(t, false, "cannot create a temp dir: %v", err)
		return {}, false
	}
	d.root = root
	d.bin = strings.concatenate({root, "/bin"})
	d.resolved = strings.concatenate({root, "/resolved"})
	d.conf = strings.concatenate({root, "/resolv.conf"})
	d.backup = strings.concatenate({root, "/resolv.conf.noirvpn-backup"})
	d.records[0] = strings.concatenate({root, "/records"})
	testing.expect_value(t, os.make_directory(d.bin), nil)
	return d, true
}

test_dir_destroy :: proc(d: ^Test_Dir) {
	_ = os.remove_all(d.root)
	delete(d.root)
	delete(d.bin)
	delete(d.resolved)
	delete(d.conf)
	delete(d.backup)
	delete(d.records[0])
}

// A file in `bin/` that looks like an installed command.
add_binary :: proc(t: ^testing.T, d: ^Test_Dir, name: string) {
	path := strings.concatenate({d.bin, "/", name}, context.temp_allocator)
	testing.expect_value(t, os.write_entire_file(path, "#!/bin/sh\n"), nil)
}

test_env :: proc(d: ^Test_Dir, f: ^Fake_Runner, bin_dirs: []string) -> DNS_Env {
	return DNS_Env {
		resolved_dir = d.resolved,
		bin_dirs = bin_dirs,
		resolv_conf = d.conf,
		backup = d.backup,
		record_dirs = d.records[:],
		runner = {data = f, run = fake_run},
	}
}

read_text :: proc(path: string) -> (string, bool) {
	data, err := os.read_entire_file(path, context.temp_allocator)
	if err != nil {
		return "", false
	}
	return string(data), true
}

SAMPLE :: DNS_Settings {
	servers         = {{IP4_Address{10, 8, 0, 1}, 0}, {IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 1}, 0}},
	search_domains  = {"corp.example"},
	routing_domains = {"internal.example"},
	default_route   = false,
}

// ---- detection ----

@(test)
dns_detect_order :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	bins := []string{d.bin}
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, bins)

	// Nothing installed: the file.
	testing.expect_value(t, dns_detect(env), DNS_Backend.Resolv_Conf)

	// resolvconf installed.
	add_binary(t, &d, "resolvconf")
	testing.expect_value(t, dns_detect(env), DNS_Backend.Resolvconf)

	// The resolved directory without resolvectl does not count.
	testing.expect_value(t, os.make_directory(d.resolved), nil)
	testing.expect_value(t, dns_detect(env), DNS_Backend.Resolvconf)

	// Both present: systemd-resolved wins.
	add_binary(t, &d, "resolvectl")
	testing.expect_value(t, dns_detect(env), DNS_Backend.Systemd_Resolved)

	// resolvectl without the directory (resolved not running): resolvconf.
	_ = os.remove(d.resolved)
	testing.expect_value(t, dns_detect(env), DNS_Backend.Resolvconf)

	// Forced.
	env.force = .Resolv_Conf
	testing.expect_value(t, dns_detect(env), DNS_Backend.Resolv_Conf)
}

// ---- systemd-resolved ----

@(test)
dns_resolved_apply_and_revert :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	add_binary(t, &d, "resolvectl")
	testing.expect_value(t, os.make_directory(d.resolved), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})

	st: DNS
	defer dns_destroy(&st)
	settings := SAMPLE
	settings.default_route = true
	testing.expect_value(t, dns_apply(&st, env, "tun0", settings), DNS_Error.None)
	testing.expect(t, st.active)
	testing.expect_value(t, st.backend, DNS_Backend.Systemd_Resolved)
	testing.expect_value(t, len(f.calls), 2)
	rc := strings.concatenate({d.bin, "/resolvectl"}, context.temp_allocator)
	testing.expect_value(t, call_text(&f, 0), strings.concatenate({rc, " dns tun0 10.8.0.1 fd00::1"}, context.temp_allocator))
	testing.expect_value(t, call_text(&f, 1), strings.concatenate({rc, " domain tun0 corp.example ~internal.example ~."}, context.temp_allocator))

	// A second apply while active is refused.
	testing.expect_value(t, dns_apply(&st, env, "tun0", settings), DNS_Error.Invalid)

	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
	testing.expect(t, !st.active)
	testing.expect_value(t, len(f.calls), 3)
	testing.expect_value(t, call_text(&f, 2), strings.concatenate({rc, " revert tun0"}, context.temp_allocator))
	// Revert twice: nothing to do.
	testing.expect_value(t, dns_revert(&st), DNS_Error.Not_Applied)
}

@(test)
dns_resolved_no_domains_skips_domain_call :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	add_binary(t, &d, "resolvectl")
	testing.expect_value(t, os.make_directory(d.resolved), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS
	defer dns_destroy(&st)
	only_servers := DNS_Settings {
		servers = {{IP4_Address{10, 8, 0, 1}, 5353}},
	}
	testing.expect_value(t, dns_apply(&st, env, "tun0", only_servers), DNS_Error.None)
	testing.expect_value(t, len(f.calls), 1) // only `dns`
	testing.expect(t, strings.has_suffix(call_text(&f, 0), " dns tun0 10.8.0.1:5353"))
	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
}

@(test)
dns_resolved_failures_leave_nothing :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	add_binary(t, &d, "resolvectl")
	testing.expect_value(t, os.make_directory(d.resolved), nil)

	// `dns` fails: no state, no further command.
	{
		f: Fake_Runner
		defer fake_destroy(&f)
		f.codes[0] = 1
		env := test_env(&d, &f, {d.bin})
		st: DNS
		testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.Command_Failed)
		testing.expect(t, !st.active)
		testing.expect_value(t, len(f.calls), 1)
	}
	// `domain` fails: the link is reverted.
	{
		f: Fake_Runner
		defer fake_destroy(&f)
		f.codes[1] = 1
		env := test_env(&d, &f, {d.bin})
		st: DNS
		testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.Command_Failed)
		testing.expect(t, !st.active)
		testing.expect_value(t, len(f.calls), 3)
		testing.expect(t, strings.has_suffix(call_text(&f, 2), " revert tun0"))
	}
	// The process does not start.
	{
		f: Fake_Runner
		defer fake_destroy(&f)
		f.no_start = true
		env := test_env(&d, &f, {d.bin})
		st: DNS
		testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.Command_Failed)
		testing.expect(t, !st.active)
	}
}

@(test)
dns_refuses_unsafe_input_before_any_command :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	add_binary(t, &d, "resolvectl")
	testing.expect_value(t, os.make_directory(d.resolved), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS

	evil_domain := SAMPLE
	evil_domain.search_domains = {"corp.example; rm -rf /"}
	testing.expect_value(t, dns_apply(&st, env, "tun0", evil_domain), DNS_Error.Invalid)
	dash_domain := SAMPLE
	dash_domain.search_domains = {"--help"}
	testing.expect_value(t, dns_apply(&st, env, "tun0", dash_domain), DNS_Error.Invalid)
	nl_domain := SAMPLE
	nl_domain.routing_domains = {"a.example\nnameserver 6.6.6.6"}
	testing.expect_value(t, dns_apply(&st, env, "tun0", nl_domain), DNS_Error.Invalid)
	testing.expect_value(t, dns_apply(&st, env, "tun0 --x", SAMPLE), DNS_Error.Invalid)
	testing.expect_value(t, dns_apply(&st, env, "-tun0", SAMPLE), DNS_Error.Invalid)
	testing.expect_value(t, dns_apply(&st, env, "tun0", {}), DNS_Error.Invalid)
	testing.expect_value(t, len(f.calls), 0)
}

// ---- resolvconf ----

@(test)
dns_resolvconf_apply_and_revert :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	add_binary(t, &d, "resolvconf")
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS
	defer dns_destroy(&st)
	testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
	testing.expect_value(t, st.backend, DNS_Backend.Resolvconf)
	testing.expect_value(t, len(f.calls), 1)
	rc := strings.concatenate({d.bin, "/resolvconf"}, context.temp_allocator)
	testing.expect_value(t, call_text(&f, 0), strings.concatenate({rc, " -a tun0.noirvpn"}, context.temp_allocator))
	testing.expect_value(t, f.calls[0].stdin, "nameserver 10.8.0.1\nnameserver fd00::1\nsearch corp.example\n")
	// resolvconf has no per-domain routing: that is reported.
	testing.expect_value(t, len(st.warnings), 1)

	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
	testing.expect_value(t, call_text(&f, 1), strings.concatenate({rc, " -d tun0.noirvpn"}, context.temp_allocator))
}

// ---- /etc/resolv.conf ----

ORIGINAL :: "nameserver 192.168.1.1\nsearch home.lan\n"

@(test)
dns_file_backend_regular_file :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	testing.expect_value(t, os.write_entire_file(d.conf, ORIGINAL), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS
	defer dns_destroy(&st)

	testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
	testing.expect_value(t, st.backend, DNS_Backend.Resolv_Conf)
	testing.expect_value(t, len(f.calls), 0) // no command for this backend
	now, _ := read_text(d.conf)
	testing.expect(t, strings.has_prefix(now, DNS_MARKER))
	testing.expect(t, strings.contains(now, "nameserver 10.8.0.1\n"))
	testing.expect(t, !strings.contains(now, "192.168.1.1"))
	saved, sok := read_text(d.backup)
	testing.expect(t, sok)
	testing.expect_value(t, saved, ORIGINAL)
	// No temporary file is left.
	testing.expect(t, !os.exists(strings.concatenate({d.conf, TMP_SUFFIX}, context.temp_allocator)))

	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
	back, _ := read_text(d.conf)
	testing.expect_value(t, back, ORIGINAL)
	testing.expect(t, !os.exists(d.backup))
}

@(test)
dns_file_backend_symlink_is_kept_as_a_symlink :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	stub := strings.concatenate({d.root, "/stub-resolv.conf"})
	defer delete(stub)
	testing.expect_value(t, os.write_entire_file(stub, ORIGINAL), nil)
	testing.expect_value(t, os.symlink(stub, d.conf), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS
	defer dns_destroy(&st)

	testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
	// Ours is a regular file, the stub is untouched.
	fi, _ := os.lstat(d.conf, context.temp_allocator)
	testing.expect_value(t, fi.type, os.File_Type.Regular)
	stub_text, _ := read_text(stub)
	testing.expect_value(t, stub_text, ORIGINAL)
	bi, _ := os.lstat(d.backup, context.temp_allocator)
	testing.expect_value(t, bi.type, os.File_Type.Symlink)

	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
	ri, _ := os.lstat(d.conf, context.temp_allocator)
	testing.expect_value(t, ri.type, os.File_Type.Symlink)
	target, _ := os.read_link(d.conf, context.temp_allocator)
	testing.expect_value(t, target, stub)
	testing.expect(t, !os.exists(d.backup))
}

@(test)
dns_file_backend_no_original :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS
	defer dns_destroy(&st)
	testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
	testing.expect(t, os.exists(d.conf))
	testing.expect(t, !os.exists(d.backup))
	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
	testing.expect(t, !os.exists(d.conf))
}

@(test)
dns_file_backend_does_not_clobber_a_changed_file :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	testing.expect_value(t, os.write_entire_file(d.conf, ORIGINAL), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS
	defer dns_destroy(&st)
	testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)

	// Somebody (a DHCP client, say) writes the file while we are up.
	theirs := "nameserver 9.9.9.9\n"
	testing.expect_value(t, os.write_entire_file(d.conf, theirs), nil)
	testing.expect_value(t, dns_revert(&st), DNS_Error.Modified_By_Other)
	now, _ := read_text(d.conf)
	testing.expect_value(t, now, theirs)
	// The saved file is kept for the administrator.
	testing.expect(t, os.exists(d.backup))
	testing.expect(t, !st.active)
}

@(test)
dns_file_backend_restores_when_file_vanished :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	testing.expect_value(t, os.write_entire_file(d.conf, ORIGINAL), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	st: DNS
	defer dns_destroy(&st)
	testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
	testing.expect_value(t, os.remove(d.conf), nil)
	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
	back, _ := read_text(d.conf)
	testing.expect_value(t, back, ORIGINAL)
}

@(test)
dns_cleanup_stale_restores_our_file_after_a_crash :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	testing.expect_value(t, os.write_entire_file(d.conf, ORIGINAL), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	{
		// "Crash": apply and forget the state.
		st: DNS
		testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
		dns_destroy(&st)
	}
	restored, err := dns_cleanup_stale(env, "tun0")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, restored)
	back, _ := read_text(d.conf)
	testing.expect_value(t, back, ORIGINAL)
	testing.expect(t, !os.exists(d.backup))

	// Nothing to do the second time.
	restored, err = dns_cleanup_stale(env, "tun0")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, !restored)
}

@(test)
dns_cleanup_stale_leaves_a_file_that_is_not_ours :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	// A leftover backup, and a resolv.conf somebody else wrote since.
	testing.expect_value(t, os.write_entire_file(d.backup, "nameserver 1.1.1.1\n"), nil)
	testing.expect_value(t, os.write_entire_file(d.conf, ORIGINAL), nil)
	restored, err := dns_cleanup_stale(env, "tun0")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, !restored)
	back, _ := read_text(d.conf)
	testing.expect_value(t, back, ORIGINAL)
	testing.expect(t, !os.exists(d.backup), "an old backup is dropped")
}

@(test)
dns_apply_after_a_crash_backs_up_the_real_file :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	testing.expect_value(t, os.write_entire_file(d.conf, ORIGINAL), nil)
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	{
		st: DNS
		testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
		dns_destroy(&st) // crash: file and backup stay
	}
	// The next run applies without a cleanup call. The backup must still be
	// the original, not our own earlier file.
	st: DNS
	defer dns_destroy(&st)
	testing.expect_value(t, dns_apply(&st, env, "tun0", SAMPLE), DNS_Error.None)
	saved, _ := read_text(d.backup)
	testing.expect_value(t, saved, ORIGINAL)
	testing.expect_value(t, dns_revert(&st), DNS_Error.None)
	back, _ := read_text(d.conf)
	testing.expect_value(t, back, ORIGINAL)
}

@(test)
dns_cleanup_stale_removes_a_resolvconf_record :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	add_binary(t, &d, "resolvconf")
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	// A record of ours is there: it is deleted.
	testing.expect_value(t, os.make_directory(d.records[0]), nil)
	record := strings.concatenate({d.records[0], "/tun0.noirvpn"}, context.temp_allocator)
	testing.expect_value(t, os.write_entire_file(record, "nameserver 10.8.0.1\n"), nil)
	_, err := dns_cleanup_stale(env, "tun0")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect_value(t, len(f.calls), 1)
	testing.expect(t, strings.has_suffix(call_text(&f, 0), " -d tun0.noirvpn"))
	_, bad := dns_cleanup_stale(env, "bad name")
	testing.expect_value(t, bad, DNS_Error.Invalid)
}

// Nothing of ours to clean: resolvconf is not even started (it is slow, and
// clients that start together would wait for each other).
@(test)
dns_cleanup_stale_skips_resolvconf_without_a_record :: proc(t: ^testing.T) {
	d, ok := test_dir_make(t)
	if !ok {
		return
	}
	defer test_dir_destroy(&d)
	add_binary(t, &d, "resolvconf")
	f: Fake_Runner
	defer fake_destroy(&f)
	env := test_env(&d, &f, {d.bin})
	// No record directory at all.
	_, err := dns_cleanup_stale(env, "tun0")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect_value(t, len(f.calls), 0)
	// A directory with records of other links, and of another name for this one.
	testing.expect_value(t, os.make_directory(d.records[0]), nil)
	for name in ([]string{"tun1.noirvpn", "tun0", "eth0.dhcp"}) {
		path := strings.concatenate({d.records[0], "/", name}, context.temp_allocator)
		testing.expect_value(t, os.write_entire_file(path, "nameserver 10.9.0.1\n"), nil)
	}
	_, err = dns_cleanup_stale(env, "tun0")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect_value(t, len(f.calls), 0)
	// The record of tun1 is found, and only it.
	_, err = dns_cleanup_stale(env, "tun1")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect_value(t, len(f.calls), 1)
	testing.expect(t, strings.has_suffix(call_text(&f, 0), " -d tun1.noirvpn"))
}

// ---- the real runner, on harmless commands ----

@(test)
dns_real_runner_exit_codes_and_stdin :: proc(t: ^testing.T) {
	env := dns_env_default()
	truth, tok := find_binary(env, "true", context.temp_allocator)
	falsy, fok := find_binary(env, "false", context.temp_allocator)
	grep, gok := find_binary(env, "grep", context.temp_allocator)
	if !tok || !fok || !gok {
		return // a very small system: nothing to test with
	}
	code, started := dns_run_command(nil, {truth}, "")
	testing.expect(t, started)
	testing.expect_value(t, code, 0)
	code, started = dns_run_command(nil, {falsy}, "")
	testing.expect(t, started)
	testing.expect_value(t, code, 1)
	// stdin reaches the child.
	code, started = dns_run_command(nil, {grep, "-q", "nameserver 10.8.0.1"}, "nameserver 10.8.0.1\n")
	testing.expect(t, started)
	testing.expect_value(t, code, 0)
	code, started = dns_run_command(nil, {grep, "-q", "nameserver 10.8.0.1"}, "nameserver 10.9.0.1\n")
	testing.expect(t, started)
	testing.expect_value(t, code, 1)
	// A command that does not exist.
	_, started = dns_run_command(nil, {"/nonexistent/noirvpn-test-binary"}, "")
	testing.expect(t, !started)
	_, started = dns_run_command(nil, {}, "")
	testing.expect(t, !started)
}
