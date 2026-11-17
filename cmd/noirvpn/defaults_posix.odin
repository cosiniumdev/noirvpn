// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin
package main

import "core:strings"
import "core:sys/posix"

// Options of a client service when no config file gives them (defaults.odin).
// Control sockets: `desktop.control` and `desktop.events`, the names the desktop
// client looks for first. Root is the administrator. A group may load a profile
// and connect: `noirvpn` on Linux (the packages create it), `admin` on macOS (the
// users who may use sudo). A missing group is left out, so the service still
// starts; add users with `--bus-allow gid GROUP operator`.
service_default_args :: proc() -> []string {
	when ODIN_OS == .Darwin {
		dir :: "/var/run/noirvpn"
		group :: "admin"
	} else {
		dir :: "/run/noirvpn"
		group :: "noirvpn"
	}
	have_group := posix.getgrnam(group) != nil
	out := make([dynamic]string, context.temp_allocator)
	append(&out, "--verb", "3", "--datapath", "userspace")
	for kind in ([]string{"control", "events"}) {
		append(&out, strings.concatenate({"--bus-", kind}, context.temp_allocator))
		append(&out, strings.concatenate({dir, "/desktop.", kind}, context.temp_allocator), "mode", "0660")
		if have_group {
			append(&out, "group", group)
		}
	}
	append(&out, "--bus-allow", "uid", "0", "admin")
	if have_group {
		append(&out, "--bus-allow", "gid", group, "operator")
	}
	return out[:]
}
