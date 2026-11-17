// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package sysnet

import "core:strings"
import "core:testing"

// The DNS backend with a fake runner: nothing here touches the real system
// configuration.

@(private = "file")
Calls :: struct {
	argv:    [dynamic]string,
	stdin:   [dynamic]string,
	// What `scutil` prints for a `list` command.
	listing: string,
	// What `scutil` prints for any other script (it prints failures, and exits 0).
	printed: string,
	// The exit code of scutil.
	code:    int,
}

@(private = "file")
record_run :: proc(data: rawptr, argv: []string, stdin: string) -> (res: Command_Result, started: bool) {
	c := (^Calls)(data)
	append(&c.argv, strings.join(argv, " ", context.temp_allocator))
	append(&c.stdin, strings.clone(stdin, context.temp_allocator))
	if strings.has_suffix(argv[0], "scutil") {
		res.code = c.code
		if strings.contains(stdin, "\nlist ") {
			res.out = c.listing
		} else {
			res.out = c.printed
		}
	}
	return res, true
}

@(private = "file")
env_with :: proc(c: ^Calls) -> DNS_Env {
	c.argv.allocator = context.temp_allocator
	c.stdin.allocator = context.temp_allocator
	env := dns_env_default()
	env.runner = Command_Runner {
		data = c,
		run  = record_run,
	}
	return env
}

@(test)
set_script_for_all_queries :: proc(t: ^testing.T) {
	s := DNS_Settings {
		servers        = {{address = IP4_Address{10, 8, 0, 1}}, {address = IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 1}}},
		search_domains = {"corp.example", "example.org"},
	}
	warnings := make([dynamic]string, context.temp_allocator)
	script, err := dns_scutil_set_script("State:/Network/Service/noirvpn-utun3/DNS", s, &warnings, context.temp_allocator)
	testing.expect_value(t, err, DNS_Error.None)
	want := `open
d.init
d.add ServerAddresses * 10.8.0.1 fd00::1
d.add SearchDomains * corp.example example.org
d.add SupplementalMatchDomains * ""
set State:/Network/Service/noirvpn-utun3/DNS
quit
`
	testing.expect_value(t, script, want)
	testing.expect_value(t, len(warnings), 0)
}

@(test)
set_script_for_split_dns :: proc(t: ^testing.T) {
	s := DNS_Settings {
		servers         = {{address = IP4_Address{10, 8, 0, 1}, port = 5353}},
		routing_domains = {"corp.example", "internal"},
	}
	script, err := dns_scutil_set_script("K", s, nil, context.temp_allocator)
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, strings.contains(script, "d.add ServerPort # 5353\n"), script)
	testing.expect(t, strings.contains(script, "d.add SupplementalMatchDomains * corp.example internal\n"), script)
	testing.expect(t, !strings.contains(script, `""`), script)

	// With default_route the routing domains are not enough: every query goes.
	s.default_route = true
	script, err = dns_scutil_set_script("K", s, nil, context.temp_allocator)
	testing.expect(t, strings.contains(script, "d.add SupplementalMatchDomains * \"\"\n"), script)
}

@(test)
set_script_drops_a_server_with_another_port :: proc(t: ^testing.T) {
	s := DNS_Settings {
		servers = {{address = IP4_Address{10, 8, 0, 1}, port = 5353}, {address = IP4_Address{10, 8, 0, 2}, port = 853}, {address = IP4_Address{10, 8, 0, 3}, port = 5353}},
	}
	warnings := make([dynamic]string, 0, 4, context.temp_allocator)
	script, err := dns_scutil_set_script("K", s, &warnings, context.temp_allocator)
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, strings.contains(script, "d.add ServerAddresses * 10.8.0.1 10.8.0.3\n"), script)
	testing.expect_value(t, len(warnings), 1)
	testing.expect(t, strings.contains(warnings[0], "10.8.0.2"))
}

@(test)
apply_and_revert_run_scutil :: proc(t: ^testing.T) {
	calls: Calls
	env := env_with(&calls)
	s := DNS_Settings {
		servers = {{address = IP4_Address{10, 8, 0, 1}}},
	}
	d: DNS
	testing.expect_value(t, dns_apply(&d, env, "utun3", s), DNS_Error.None)
	defer dns_destroy(&d)
	testing.expect(t, d.active)
	testing.expect_value(t, d.backend, DNS_Backend.Scutil)
	testing.expect_value(t, d.key, "State:/Network/Service/noirvpn-utun3/DNS")

	// scutil first, then the cache is emptied.
	testing.expect_value(t, len(calls.argv), 3)
	testing.expect_value(t, calls.argv[0], "/usr/sbin/scutil")
	testing.expect(t, strings.contains(calls.stdin[0], "set State:/Network/Service/noirvpn-utun3/DNS\n"))
	testing.expect_value(t, calls.argv[1], "/usr/bin/dscacheutil -flushcache")
	testing.expect_value(t, calls.argv[2], "/usr/bin/killall -HUP mDNSResponder")

	// A second apply on the same value is refused.
	testing.expect_value(t, dns_apply(&d, env, "utun3", s), DNS_Error.Invalid)

	clear(&calls.argv)
	clear(&calls.stdin)
	testing.expect_value(t, dns_revert(&d), DNS_Error.None)
	testing.expect(t, !d.active)
	testing.expect_value(t, calls.stdin[0], "open\nremove State:/Network/Service/noirvpn-utun3/DNS\nquit\n")
	testing.expect_value(t, dns_revert(&d), DNS_Error.Not_Applied)
}

@(test)
apply_failure_leaves_nothing :: proc(t: ^testing.T) {
	calls: Calls
	calls.code = 1
	env := env_with(&calls)
	s := DNS_Settings {
		servers = {{address = IP4_Address{10, 8, 0, 1}}},
	}
	d: DNS
	testing.expect_value(t, dns_apply(&d, env, "utun3", s), DNS_Error.Command_Failed)
	testing.expect(t, !d.active)

	testing.expect_value(t, dns_apply(&d, env, "bad name", s), DNS_Error.Invalid)
	testing.expect_value(t, dns_apply(&d, env, "utun3", DNS_Settings{}), DNS_Error.Invalid)
	testing.expect_value(t, dns_apply(&d, env, "utun3", DNS_Settings{servers = {{address = IP4_Address{1, 1, 1, 1}}}, search_domains = {"bad domain"}}), DNS_Error.Invalid)
}

@(test)
cleanup_removes_only_an_existing_key :: proc(t: ^testing.T) {
	calls: Calls
	env := env_with(&calls)

	// No key: one `list`, no `remove`.
	restored, err := dns_cleanup_stale(env, "utun3")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, !restored)
	testing.expect_value(t, len(calls.argv), 1)

	clear(&calls.argv)
	clear(&calls.stdin)
	calls.listing = "  subKey [0] = State:/Network/Service/noirvpn-utun3/DNS\n"
	restored, err = dns_cleanup_stale(env, "utun3")
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, restored)
	testing.expect(t, strings.contains(calls.stdin[1], "remove State:/Network/Service/noirvpn-utun3/DNS"))

	// A dead record: the same, whether or not the interface is there.
	clear(&calls.argv)
	clear(&calls.stdin)
	restored, err = dns_cleanup_dead(env, .Scutil, "utun3", false)
	testing.expect(t, restored)
	_, err = dns_cleanup_dead(env, .None, "utun3", true)
	testing.expect_value(t, err, DNS_Error.Invalid)
	_, err = dns_cleanup_stale(env, "bad name")
	testing.expect_value(t, err, DNS_Error.Invalid)
}

@(test)
record_names :: proc(t: ^testing.T) {
	testing.expect_value(t, dns_backend_name(.Scutil), "scutil")
	b, ok := dns_backend_parse("scutil")
	testing.expect(t, ok)
	testing.expect_value(t, b, DNS_Backend.Scutil)
	_, ok = dns_backend_parse("resolvectl")
	testing.expect(t, !ok)
	testing.expect(t, !dns_backend_shared("scutil"))
	testing.expect_value(t, dns_record_detail(dns_env_default(), .Scutil, "utun3"), "key State:/Network/Service/noirvpn-utun3/DNS")
}

@(test)
scutil_failures_are_read_from_its_output :: proc(t: ^testing.T) {
	// scutil exits 0 whatever happens: the text says.
	testing.expect_value(t, scutil_failure(""), DNS_Error.None)
	testing.expect_value(t, scutil_failure("\n"), DNS_Error.None)
	testing.expect_value(t, scutil_failure("  Permission denied\n"), DNS_Error.Permission)
	testing.expect_value(t, scutil_failure("set: too few arguments\n"), DNS_Error.Command_Failed)
	testing.expect_value(t, scutil_failure("bogus: unknown, type \"help\" for command info\n"), DNS_Error.Command_Failed)
	testing.expect_value(t, scutil_failure("  No such key\n"), DNS_Error.Command_Failed)
	testing.expect_value(t, scutil_failure("  No such key\n", missing_ok = true), DNS_Error.None)
	testing.expect_value(t, scutil_failure("  No such key\n  Permission denied\n", missing_ok = true), DNS_Error.Permission)
}

@(test)
apply_without_root_reports_permission :: proc(t: ^testing.T) {
	calls: Calls
	calls.printed = "  Permission denied\n"
	env := env_with(&calls)
	d: DNS
	err := dns_apply(&d, env, "utun3", DNS_Settings{servers = {{address = IP4_Address{10, 8, 0, 1}}}})
	testing.expect_value(t, err, DNS_Error.Permission)
	testing.expect(t, !d.active)
	// The cache was not touched: nothing changed.
	testing.expect_value(t, len(calls.argv), 1)
}

@(test)
revert_of_a_key_that_is_gone_is_fine :: proc(t: ^testing.T) {
	calls: Calls
	env := env_with(&calls)
	d: DNS
	testing.expect_value(t, dns_apply(&d, env, "utun3", DNS_Settings{servers = {{address = IP4_Address{10, 8, 0, 1}}}}), DNS_Error.None)
	defer dns_destroy(&d)
	calls.printed = "  No such key\n"
	testing.expect_value(t, dns_revert(&d), DNS_Error.None)
}
