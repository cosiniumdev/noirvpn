// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package bus

import "core:os"
import "core:strings"

@(private)
setup_euid :: proc() -> u32 {
	return euid()
}

// The directories where a daemon of this host may keep its sockets, in the
// order a tool looks: the system directory, then the directory of the user.
// Free the strings and the slice.
candidate_dirs :: proc(allocator := context.allocator) -> []string {
	xdg, _ := os.lookup_env("XDG_RUNTIME_DIR", context.temp_allocator)
	dirs := make([dynamic]string, allocator)
	append(&dirs, default_dir(0, "", allocator))
	if uid := euid(); uid != 0 {
		append(&dirs, default_dir(uid, xdg, allocator))
	}
	return dirs[:]
}

// The first default directory that this user may not look into, or "".
// `discover` finds nothing there. So if this is set, a tool that found no
// daemon should say "permission denied", not "not running".
hidden_dir :: proc(allocator := context.allocator) -> string {
	for dir in candidate_dirs(context.temp_allocator) {
		probe := default_socket_path(dir, DEFAULT_NAME, CONTROL_SUFFIX, context.temp_allocator)
		if socket_presence(probe) == .Permission_Denied {
			return strings.clone(dir, allocator)
		}
	}
	return ""
}

// List the daemons whose control socket file exists in the default
// directories. A listed daemon may still be dead (a stale file): `call` then
// says so.
discover :: proc(allocator := context.allocator) -> []Found {
	dirs := candidate_dirs(context.temp_allocator)
	out := make([dynamic]Found, allocator)
	for dir in dirs {
		infos, err := os.read_all_directory_by_path(dir, context.temp_allocator)
		if err != nil {
			continue
		}
		for info in infos {
			if !strings.has_suffix(info.name, CONTROL_SUFFIX) || len(info.name) == len(CONTROL_SUFFIX) {
				continue
			}
			name := info.name[:len(info.name) - len(CONTROL_SUFFIX)]
			f := Found {
				name       = strings.clone(name, allocator),
				url        = socket_url(strings.concatenate({dir, "/", info.name}, context.temp_allocator), allocator),
				events_url = socket_url(strings.concatenate({dir, "/", name, EVENTS_SUFFIX}, context.temp_allocator), allocator),
			}
			append(&out, f)
		}
	}
	return out[:]
}
