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

	s.policy, s.unresolved = policy_from_config(c.bus_allow, uid, default_resolver, allocator)
	s.opts.policy = s.policy
	s.opts.mode = mode
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
