// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package bus

import "core:fmt"
import "core:os"
import "core:testing"
import "noir:proto/config"

@(test)
setup_defaults_use_the_instance_name :: proc(t: ^testing.T) {
	c: config.Common_Config
	s, err := setup_from_config(&c, .Client, "work")
	defer setup_destroy(&s)
	testing.expect_value(t, err, Setup_Error.None)
	testing.expect_value(t, s.name, "work")
	testing.expect_value(t, s.opts.mode, Daemon_Mode.Client)
	ev, has_ev := s.opts.events.?
	ctl, has_ctl := s.opts.control.?
	testing.expect(t, has_ev && has_ctl)
	testing.expect(t, len(ev.path) > 0 && ev.path[len(ev.path) - len("/work.events"):] == "/work.events")
	testing.expect(t, ctl.path[len(ctl.path) - len("/work.control"):] == "/work.control")
	testing.expect_value(t, s.events, ev.path)
	testing.expect_value(t, s.control, ctl.path)
	// Default policy: root and ourselves.
	testing.expect(t, len(s.policy.rules) >= 1)
}

@(test)
setup_empty_name_is_noirvpn :: proc(t: ^testing.T) {
	c: config.Common_Config
	s, err := setup_from_config(&c, .Server, "")
	defer setup_destroy(&s)
	testing.expect_value(t, err, Setup_Error.None)
	testing.expect_value(t, s.name, DEFAULT_NAME)
}

@(test)
setup_follows_the_config :: proc(t: ^testing.T) {
	c := config.Common_Config {
		bus_events = {state = .Off},
		bus_control = {state = .Custom, path = "ipc:///run/x/ctl", mode = 0o660, group = "noirvpn"},
		bus_allow = {{kind = .Uid, id = 1000, roles = {.Operator}}, {kind = .Gid, id = 970, roles = {.Auth}}},
	}
	s, err := setup_from_config(&c, .Server, "srv")
	defer setup_destroy(&s)
	testing.expect_value(t, err, Setup_Error.None)
	_, has_ev := s.opts.events.?
	testing.expect(t, !has_ev)
	testing.expect_value(t, s.events, "")
	ctl, has_ctl := s.opts.control.?
	testing.expect(t, has_ctl)
	testing.expect_value(t, ctl.path, "/run/x/ctl")
	testing.expect_value(t, ctl.mode, 0o660)
	testing.expect_value(t, ctl.group, "noirvpn")
	testing.expect_value(t, len(s.policy.rules), 2)
	// The strings outlive the config.
	testing.expect_value(t, s.control, "/run/x/ctl")
}

@(test)
setup_reports_bad_paths_and_names :: proc(t: ^testing.T) {
	c := config.Common_Config {
		bus_events = {state = .Custom, path = "tcp://0.0.0.0:5555"},
	}
	s, err := setup_from_config(&c, .Server, "x")
	testing.expect_value(t, err, Setup_Error.Bad_Events_Path)
	setup_destroy(&s)

	c = config.Common_Config {
		bus_control = {state = .Custom, path = "relative"},
	}
	s, err = setup_from_config(&c, .Server, "x")
	testing.expect_value(t, err, Setup_Error.Bad_Control_Path)
	setup_destroy(&s)

	c = config.Common_Config {
		bus_allow = {{kind = .Uid, name = "no-such-user-xyz", roles = {.Read}}},
	}
	s, err = setup_from_config(&c, .Server, "x")
	testing.expect_value(t, err, Setup_Error.Unknown_Name)
	testing.expect_value(t, len(s.unresolved), 1)
	testing.expect_value(t, s.unresolved[0], "no-such-user-xyz")
	setup_destroy(&s)
}

// A daemon opened from a setup works end to end, and a tool finds it.
@(test)
setup_daemon_is_found_by_discover :: proc(t: ^testing.T) {
	if euid() == 0 {
		return // root would look in /run/noirvpn
	}
	dir := make_test_dir(t, "discover")
	defer remove_test_dir(dir)
	// XDG_RUNTIME_DIR is process wide; no other test reads it.
	old, had := os.lookup_env("XDG_RUNTIME_DIR", context.allocator)
	defer if had {
		delete(old)
	}
	os.set_env("XDG_RUNTIME_DIR", dir)
	defer {
		if had {
			os.set_env("XDG_RUNTIME_DIR", old)
		} else {
			os.unset_env("XDG_RUNTIME_DIR")
		}
	}

	c: config.Common_Config
	s, err := setup_from_config(&c, .Client, "lab")
	defer setup_destroy(&s)
	testing.expect_value(t, err, Setup_Error.None)
	testing.expect_value(t, s.control, fmt.tprintf("%s/noirvpn/lab.control", dir))

	h, oerr, _ := host_open(s.opts)
	testing.expect_value(t, oerr, Open_Error.None)
	if h == nil {
		return
	}
	defer host_close(h)

	found := discover()
	defer found_destroy(found)
	ok := false
	for f in found {
		if f.name == "lab" {
			ok = true
			testing.expect_value(t, f.url, fmt.tprintf("ipc://%s/noirvpn/lab.control", dir))
			testing.expect_value(t, f.events_url, fmt.tprintf("ipc://%s/noirvpn/lab.events", dir))
		}
	}
	testing.expect(t, ok, "daemon not found")
}
