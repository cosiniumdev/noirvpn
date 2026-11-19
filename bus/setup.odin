// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Glue between the config and the bus: what the daemon calls at startup, and
// what the tools call to find the daemon.

import "core:os"
import "core:strings"
import "noir:proto/config"

when ODIN_OS == .Windows {
	@(private = "file")
	BAD_PATH_TEXT :: "the address must be a local pipe name (\\\\.\\pipe\\NAME) of at most 256 bytes"
} else {
	@(private = "file")
	BAD_PATH_TEXT :: "the path must be an absolute path or an ipc:// URL of at most 103 bytes"
}

Setup_Error :: enum u8 {
	None,
	// `bus-events` or `bus-control` is not a usable local absolute path.
	Bad_Events_Path,
	Bad_Control_Path,
	// A name in `bus-allow` is not a known user or group (see `unresolved`).
	Unknown_Name,
}

setup_error_string :: proc(e: Setup_Error) -> string {
	switch e {
	case .None:
		return "ok"
	case .Bad_Events_Path:
		return "bus-events: " + BAD_PATH_TEXT
	case .Bad_Control_Path:
		return "bus-control: " + BAD_PATH_TEXT
	case .Unknown_Name:
		return "bus-allow: the user or group name is unknown, or the SID is malformed"
	}
	return "?"
}

// The `--allow-user` and `--allow-group` flags of the daemon: one user and
// one group that may use the sockets, with the role `operator`. "" for none.
// They are added to the config for this run only.
Access :: struct {
	user:  string,
	group: string,
}

// The `bus-allow` rules of the config and the rules of `a`, in the temp
// allocator.
access_rules :: proc(allow: []config.Bus_Allow, a: Access) -> []config.Bus_Allow {
	out := make([dynamic]config.Bus_Allow, 0, len(allow) + 2, context.temp_allocator)
	append(&out, ..allow)
	if a.user != "" {
		append(&out, config.Bus_Allow{kind = .Uid, name = a.user, roles = {.Operator}})
	}
	if a.group != "" {
		append(&out, config.Bus_Allow{kind = .Gid, name = a.group, roles = {.Operator}})
	}
	return out[:]
}

// Gives the sockets to the user and the group of `a`: owner user with mode
// 0600, group with mode 0660, or both with mode 0660.
@(private = "file")
access_endpoint :: proc(ep: ^Endpoint, a: Access) {
	if a.user != "" {
		ep.owner = a.user
		ep.mode = 0o600
	}
	if a.group != "" {
		ep.group = a.group
		ep.mode = 0o660
	}
}

// Everything `host_open` needs, built from the config.
Setup :: struct {
	opts:       Host_Options,
	// `bus-allow` names that do not exist (only set with `Unknown_Name`).
	unresolved: [dynamic]string,
	// The paths and the instance name used (for the startup log).
	name:       string,
	events:     string, // "" if off
	control:    string, // "" if off
	owned:      [dynamic]string,
	policy:     Policy,
}

// Build the host options from the `bus-events`, `bus-control` and `bus-allow`
// settings.
// - `name` is the instance name (`--name`, or `instance_name` of the config
//   path). "" gives DEFAULT_NAME.
// - Defaults are `<dir>/<name>.events` and `<dir>/<name>.control`
//.
// - The result stays valid until `setup_destroy`. `host_open` copies what it
//   needs, so it can be destroyed right after.
setup_from_config :: proc(
	c: ^config.Common_Config,
	mode: Daemon_Mode,
	name: string,
	allocator := context.allocator,
	access := Access{},
) -> (
	s: Setup,
	err: Setup_Error,
) {
	s.owned.allocator = allocator
	own :: proc(s: ^Setup, str: string) -> string {
		append(&s.owned, str)
		return str
	}
	s.name = own(&s, strings.clone(name if name != "" else DEFAULT_NAME, allocator))

	uid := setup_euid()
	xdg, _ := os.lookup_env("XDG_RUNTIME_DIR", context.temp_allocator)
	dir := default_dir(uid, xdg, context.temp_allocator)
	def_events := default_socket_path(dir, s.name, EVENTS_SUFFIX, context.temp_allocator)
	def_control := default_socket_path(dir, s.name, CONTROL_SUFFIX, context.temp_allocator)

	events, ev_on, ev_ok := resolve_endpoint(c.bus_events, def_events)
	if !ev_ok {
		return s, .Bad_Events_Path
	}
	control, ctl_on, ctl_ok := resolve_endpoint(c.bus_control, def_control)
	if !ctl_ok {
		return s, .Bad_Control_Path
	}
	access_endpoint(&events, access)
	access_endpoint(&control, access)
	if ev_on {
		events.path = own(&s, strings.clone(events.path, allocator))
		s.events = events.path
		s.opts.events = events
	}
	if ctl_on {
		control.path = own(&s, strings.clone(control.path, allocator))
		s.control = control.path
		s.opts.control = control
	}

	s.policy, s.unresolved = policy_from_config(access_rules(c.bus_allow, access), uid, default_resolver, allocator)
	s.opts.policy = s.policy
	s.opts.mode = mode
	s.opts.open_dir = access.user != "" || access.group != ""
	s.opts.allocator = allocator
	if len(s.unresolved) > 0 {
		return s, .Unknown_Name
	}
	return s, .None
}

setup_destroy :: proc(s: ^Setup) {
	for str in s.owned {
		delete(str)
	}
	delete(s.owned)
	delete(s.unresolved)
	policy_destroy(&s.policy)
	s^ = {}
}

// ---- finding a daemon (tools) ----

Found :: struct {
	// The instance name.
	name: string,
	// The control socket URL, ready for `call`.
	url:  string,
	// The events socket URL (the file may not exist if events are off).
	events_url: string,
}

found_destroy :: proc(found: []Found, allocator := context.allocator) {
	for f in found {
		delete(f.name, allocator)
		delete(f.url, allocator)
		delete(f.events_url, allocator)
	}
	delete(found, allocator)
}
