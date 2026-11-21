// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:strings"
import "core:testing"

@(private = "file")
DEFAULTS := []string{"--verb", "3", "--bus-control", "/run/x.control", "mode", "0660", "--bus-allow", "uid", "0", "admin"}

@(private = "file")
no_file :: proc(path: string) -> bool {
	return false
}

@(private = "file")
any_file :: proc(path: string) -> bool {
	return true
}

@(private = "file")
joined :: proc(a: []string) -> string {
	return strings.join(a, " ", context.temp_allocator)
}

@(test)
no_args_is_a_service_with_the_defaults :: proc(t: ^testing.T) {
	p := config_plan({}, DEFAULTS, no_file, true)
	testing.expect_value(t, joined(p.args), "--client-service --verb 3 --bus-control /run/x.control mode 0660 --bus-allow uid 0 admin")
	testing.expect(t, p.defaulted)
	testing.expect_value(t, p.create_path, "")
}

@(test)
given_options_replace_the_default_of_the_same_name :: proc(t: ^testing.T) {
	p := config_plan({"--verb", "5", "--bus-allow", "gid", "staff", "operator"}, DEFAULTS, no_file, true)
	testing.expect_value(t, joined(p.args), "--verb 5 --bus-allow gid staff operator --client-service --bus-control /run/x.control mode 0660")
	// An explicit --client-service is not added twice.
	p = config_plan({"--client-service"}, DEFAULTS, no_file, true)
	testing.expect_value(t, strings.count(joined(p.args), "--client-service"), 1)
}

@(test)
a_role_option_gets_no_service_defaults :: proc(t: ^testing.T) {
	p := config_plan({"--client", "--remote", "vpn.example.com", "1194"}, DEFAULTS, no_file, true)
	testing.expect_value(t, joined(p.args), "--client --remote vpn.example.com 1194")
}

@(test)
an_existing_file_is_left_alone :: proc(t: ^testing.T) {
	args := []string{"--config", "/etc/noirvpn/work.conf", "--verb", "4"}
	p := config_plan(args, DEFAULTS, any_file, true)
	testing.expect_value(t, joined(p.args), joined(args))
	testing.expect_value(t, p.create_path, "")
	testing.expect(t, !p.defaulted)
	p = config_plan({"work.conf"}, DEFAULTS, any_file, true)
	testing.expect_value(t, joined(p.args), "work.conf")
}

@(test)
a_missing_file_is_made_from_the_defaults_and_the_options :: proc(t: ^testing.T) {
	p := config_plan({"--config", "/etc/noirvpn/service.conf", "--verb", "2", "--workers", "2"}, DEFAULTS, no_file, true)
	testing.expect_value(t, p.create_path, "/etc/noirvpn/service.conf")
	want := `# Created by noirvpn from its defaults and the options on the command line.
verb 2
workers 2
client-service
bus-control /run/x.control mode 0660
bus-allow uid 0 admin
`
	testing.expect_value(t, p.create_text, want)
	// The file is read after it is created, and nothing else is: no option twice.
	testing.expect_value(t, joined(p.args), "--config /etc/noirvpn/service.conf")
	testing.expect(t, !p.defaulted)

	// A bare file name is a config file too.
	p = config_plan({"new.conf"}, DEFAULTS, no_file, true)
	testing.expect_value(t, p.create_path, "new.conf")
}

@(test)
check_config_makes_nothing :: proc(t: ^testing.T) {
	p := config_plan({"--config", "service.conf", "--verb", "2"}, DEFAULTS, no_file, false)
	testing.expect_value(t, p.create_path, "")
	testing.expect(t, strings.contains(joined(p.args), "--client-service"))
	testing.expect(t, !strings.contains(joined(p.args), "--config"))
}

@(test)
a_client_config_is_made_as_given :: proc(t: ^testing.T) {
	p := config_plan({"--config", "c.conf", "--client", "--remote", "vpn.example.com", "1194", "udp", "--auth-user-pass", "/tmp/my pass.txt"}, DEFAULTS, no_file, true)
	testing.expect_value(
		t,
		p.create_text,
		"# Created by noirvpn from its defaults and the options on the command line.\nclient\nremote vpn.example.com 1194 udp\nauth-user-pass \"/tmp/my pass.txt\"\n",
	)
}

@(test)
the_default_options_are_valid_config :: proc(t: ^testing.T) {
	// The real defaults of this system give a service that passes the config check.
	p := config_plan({}, service_default_args(), no_file, false)
	testing.expect(t, has_option(p.args, "client-service"))
	// On Windows, the control pipe name comes from the instance name
	// (defaults_windows.odin).
	when ODIN_OS != .Windows {
		testing.expect(t, has_option(p.args, "bus-control"))
	}
	testing.expect(t, has_option(p.args, "bus-allow"))
}
