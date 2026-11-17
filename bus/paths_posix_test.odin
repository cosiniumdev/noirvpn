// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !windows
package bus

import "core:testing"
import "noir:proto/config"

@(test)
dirs_by_user :: proc(t: ^testing.T) {
	d := default_dir(0, "/run/user/1000")
	defer delete(d)
	testing.expect(t, d == "/run/noirvpn" || d == "/var/run/noirvpn")

	d2 := default_dir(1000, "/run/user/1000")
	defer delete(d2)
	testing.expect_value(t, d2, "/run/user/1000/noirvpn")

	d3 := default_dir(1000, "/run/user/1000/")
	defer delete(d3)
	testing.expect_value(t, d3, "/run/user/1000/noirvpn")

	d4 := default_dir(1000, "")
	defer delete(d4)
	testing.expect_value(t, d4, "/tmp/noirvpn-1000")

	// A relative XDG value is not trusted.
	d5 := default_dir(1000, "relative/dir")
	defer delete(d5)
	testing.expect_value(t, d5, "/tmp/noirvpn-1000")
}

@(test)
socket_paths :: proc(t: ^testing.T) {
	p := default_socket_path("/run/noirvpn", "server", EVENTS_SUFFIX)
	defer delete(p)
	testing.expect_value(t, p, "/run/noirvpn/server.events")

	f, ok := socket_file_path("/run/x/control")
	testing.expect(t, ok)
	testing.expect_value(t, f, "/run/x/control")
	f, ok = socket_file_path("ipc:///run/x/control")
	testing.expect(t, ok)
	testing.expect_value(t, f, "/run/x/control")

	bad := []string{"", "relative/path", "ipc://relative", "tcp://127.0.0.1:5555", "abstract://x", "ipc://"}
	for b in bad {
		_, ok = socket_file_path(b)
		testing.expectf(t, !ok, "%q should be refused", b)
	}
	long := make([]byte, 120, context.temp_allocator)
	for &c in long {
		c = 'a'
	}
	long[0] = '/'
	_, ok = socket_file_path(string(long))
	testing.expect(t, !ok)

	u := socket_url("/run/x/control")
	defer delete(u)
	testing.expect_value(t, u, "ipc:///run/x/control")
}

@(test)
endpoint_resolution :: proc(t: ^testing.T) {
	e, enabled, ok := resolve_endpoint({state = .Off}, "/run/noirvpn/a.events")
	testing.expect(t, ok && !enabled)

	e, enabled, ok = resolve_endpoint({}, "/run/noirvpn/a.events")
	testing.expect(t, ok && enabled)
	testing.expect_value(t, e.path, "/run/noirvpn/a.events")
	testing.expect_value(t, e.mode, 0)

	e, enabled, ok = resolve_endpoint(
		config.Bus_Endpoint{state = .Custom, path = "ipc:///var/x/ev", mode = 0o640, group = "noirvpn"},
		"/run/noirvpn/a.events",
	)
	testing.expect(t, ok && enabled)
	testing.expect_value(t, e.path, "/var/x/ev")
	testing.expect_value(t, e.mode, 0o640)
	testing.expect_value(t, e.group, "noirvpn")

	_, _, ok = resolve_endpoint(config.Bus_Endpoint{state = .Custom, path = "tcp://0.0.0.0:1"}, "/x/y")
	testing.expect(t, !ok)
	_, _, ok = resolve_endpoint(config.Bus_Endpoint{state = .Custom, path = "rel"}, "/x/y")
	testing.expect(t, !ok)
}
