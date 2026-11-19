// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Where the sockets live, and how a config endpoint becomes a socket path.
//
// Name: each daemon has an instance name, so a server and a client daemon (or
// two client daemons) can share a host. It is `--name`, else the base name of
// the config file without extension (`server.conf` gives `server`), else
// `noirvpn`. Sockets:
//
//	<dir>/<name>.events      PUB
//	<dir>/<name>.control     REP
//
// `<dir>`: /run/noirvpn for root (/var/run/noirvpn on macOS); for another user
// $XDG_RUNTIME_DIR/noirvpn, else /tmp/noirvpn-<uid>. A tool with no name looks
// for `*.control` files there (`discover`).
//
// Windows endpoints are two named pipes (a tool lists the pipes of that
// pattern):
//
//	\\.\pipe\noirvpn-<name>-events
//	\\.\pipe\noirvpn-<name>-control

import "core:fmt"
import "core:strings"
import "noir:proto/config"

DEFAULT_NAME :: "noirvpn"

when ODIN_OS == .Windows {
	EVENTS_SUFFIX :: "-events"
	CONTROL_SUFFIX :: "-control"
	// The namespace of local pipes, and the start of the name of every bus pipe.
	PIPE_DIR :: `\\.\pipe\`
	PIPE_PREFIX :: "noirvpn-"
	// The longest pipe name that Windows accepts.
	MAX_SOCKET_PATH :: 256
} else {
	EVENTS_SUFFIX :: ".events"
	CONTROL_SUFFIX :: ".control"
	// sun_path is 108 bytes on Linux and 104 on macOS, with the final NUL.
	MAX_SOCKET_PATH :: 103
}

// The default mode of a socket file when the config gives none. A client needs
// write permission on a socket file to connect, so this is 0660. The group and
// the directory mode decide who gets in.
DEFAULT_SOCKET_MODE :: 0o660

// The mode of a directory the bus creates.
DIR_MODE :: 0o750

// The directory for the sockets of a daemon running as `euid`. `xdg` is the
// value of $XDG_RUNTIME_DIR ("" if not set). Allocated with `allocator`.
default_dir :: proc(euid: u32, xdg: string, allocator := context.allocator) -> string {
	when ODIN_OS == .Windows {
		return strings.clone(PIPE_DIR, allocator)
	}
	if euid == 0 {
		when ODIN_OS == .Linux {
			return strings.clone("/run/noirvpn", allocator)
		} else {
			return strings.clone("/var/run/noirvpn", allocator)
		}
	}
	if xdg != "" && xdg[0] == '/' {
		return strings.join({strings.trim_right(xdg, "/"), "noirvpn"}, "/", allocator)
	}
	return fmt.aprintf("/tmp/noirvpn-%d", euid, allocator = allocator)
}

// An instance name from a config file path: the base name without its last
// extension, with characters outside [A-Za-z0-9._-] replaced by '_'. Empty
// input gives DEFAULT_NAME. Allocated with `allocator`.
instance_name :: proc(config_path: string, allocator := context.allocator) -> string {
	base := config_path
	if i := strings.last_index_byte(base, '/'); i >= 0 {
		base = base[i + 1:]
	}
	when ODIN_OS == .Windows {
		if i := strings.last_index_byte(base, '\\'); i >= 0 {
			base = base[i + 1:]
		}
	}
	if i := strings.last_index_byte(base, '.'); i > 0 {
		base = base[:i]
	}
	if base == "" || base == "." || base == ".." {
		return strings.clone(DEFAULT_NAME, allocator)
	}
	out := make([]byte, len(base), allocator)
	for i in 0 ..< len(base) {
		ch := base[i]
		switch ch {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '-', '_':
			out[i] = ch
		case:
			out[i] = '_'
		}
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return string(out)
}

// The default path of the events or the control socket (the pipe name on
// Windows).
default_socket_path :: proc(dir, name, suffix: string, allocator := context.allocator) -> string {
	when ODIN_OS == .Windows {
		return strings.concatenate({dir, PIPE_PREFIX, name, suffix}, allocator)
	}
	return strings.concatenate({dir, "/", name, suffix}, allocator)
}

// Strip "ipc://" from a URL or a bare path. Other schemes are refused (the bus
// is local only). On Windows the address is a local pipe name,
// `\\.\pipe\NAME`.
socket_file_path :: proc(path_or_url: string) -> (path: string, ok: bool) {
	when ODIN_OS == .Windows {
		return pipe_name_ok(path_or_url)
	}
	p := path_or_url
	if strings.has_prefix(p, "ipc://") {
		p = p[len("ipc://"):]
	} else if strings.contains(p, "://") {
		return "", false
	}
	if len(p) == 0 || p[0] != '/' || len(p) > MAX_SOCKET_PATH || strings.contains_rune(p, 0) {
		return "", false
	}
	return p, true
}

// A local pipe name: `\\.\pipe\` and 1 or more characters, no NUL, at most
// MAX_SOCKET_PATH bytes. A remote name (`\\host\pipe\...`) is refused.
pipe_name_ok :: proc(name: string) -> (path: string, ok: bool) {
	prefix := `\\.\pipe\`
	if len(name) <= len(prefix) || len(name) > 256 || !strings.has_prefix(name, prefix) || strings.contains_rune(name, 0) {
		return "", false
	}
	return name, true
}

// The nng URL of a socket file path. On Windows the pipe name itself.
socket_url :: proc(path: string, allocator := context.allocator) -> string {
	when ODIN_OS == .Windows {
		return strings.clone(path, allocator)
	}
	return strings.concatenate({"ipc://", path}, allocator)
}

// The events address that belongs to a control address (`NAME.control` gives
// `NAME.events`, `noirvpn-NAME-control` gives `noirvpn-NAME-events`). "" if the
// name has no control suffix. Allocated with `allocator`.
events_for_control :: proc(control: string, allocator := context.allocator) -> string {
	if strings.has_suffix(control, CONTROL_SUFFIX) {
		base := control[:len(control) - len(CONTROL_SUFFIX)]
		return strings.concatenate({base, EVENTS_SUFFIX}, allocator)
	}
	return ""
}

// One bus socket, as the daemon opens it.
Endpoint :: struct {
	// Absolute path of the socket file (the pipe name on Windows).
	path:  string,
	// File mode; 0 means DEFAULT_SOCKET_MODE. Not used on Windows.
	mode:  u32,
	// Group name or number to give the socket file; "" keeps the daemon's.
	// Not used on Windows.
	group: string,
	// User name or number to give the socket file; "" keeps the daemon's.
	// Not used on Windows.
	owner: string,
}

// Turn a `bus-events` or `bus-control` setting into an endpoint.
//   - `Off` gives `enabled = false`.
//   - `Default` uses `default_path`.
//   - `ok` is false for a path that is not a local absolute path of a usable
//     length.
// Strings point into the config (and `default_path`). Nothing is allocated.
resolve_endpoint :: proc(
	ep: config.Bus_Endpoint,
	default_path: string,
) -> (
	e: Endpoint,
	enabled: bool,
	ok: bool,
) {
	switch ep.state {
	case .Off:
		return {}, false, true
	case .Default:
		p, pok := socket_file_path(default_path)
		return Endpoint{path = p, mode = ep.mode, group = ep.group}, true, pok
	case .Custom:
		p, pok := socket_file_path(ep.path)
		return Endpoint{path = p, mode = ep.mode, group = ep.group}, true, pok
	}
	return {}, false, false
}
