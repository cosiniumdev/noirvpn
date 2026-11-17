// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:strings"
import "noir:bus"

// Which daemon to talk to.
Target :: struct {
	// The control socket (a path or an ipc:// URL).
	control: string,
	// The events socket, or "" when it cannot be told.
	events:  string,
}

Target_Error :: enum u8 {
	None,
	// No daemon found (no control socket in the default directories, or none
	// of that name).
	Not_Running,
	// Several daemons found and no --name.
	Ambiguous,
	// The events socket cannot be worked out from the control socket path.
	No_Events_Socket,
}

// Work out the sockets from the options and the daemons that `bus.discover`
// found. `detail` says more for the error message (the names found).
resolve_target :: proc(c: ^Command, found: []bus.Found) -> (t: Target, err: Target_Error, detail: string) {
	events := c.events_socket
	switch {
	case c.socket != "":
		t.control = c.socket
		if events == "" {
			events = events_for_control(c.socket)
		}
	case c.name != "":
		for f in found {
			if f.name == c.name {
				t.control = f.url
				if events == "" {
					events = f.events_url
				}
				break
			}
		}
		if t.control == "" {
			return {}, .Not_Running, c.name
		}
	case:
		switch len(found) {
		case 0:
			return {}, .Not_Running, ""
		case 1:
			t.control = found[0].url
			if events == "" {
				events = found[0].events_url
			}
		case:
			names := make([dynamic]string, context.temp_allocator)
			for f in found {
				append(&names, f.name)
			}
			return {}, .Ambiguous, strings.join(names[:], ", ", context.temp_allocator)
		}
	}
	t.events = events
	if events == "" {
		return t, .No_Events_Socket, ""
	}
	return t, .None, ""
}

// `NAME.control` becomes `NAME.events` in the same directory
// (`noirvpn-NAME-control` becomes `noirvpn-NAME-events` on Windows).
events_for_control :: proc(control: string) -> string {
	return bus.events_for_control(control, context.temp_allocator)
}

when ODIN_OS == .Windows {
	ACCESS_HINT :: "the pipe requires a bus-allow sid rule for your account or one of your groups"
} else {
	ACCESS_HINT :: "your user or group requires write access to the socket"
}

// The text for a target error.
target_error_text :: proc(e: Target_Error, detail: string, c: ^Command) -> string {
	switch e {
	case .None:
		return ""
	case .Not_Running:
		if c.name != "" {
			return fmt.tprintf("the daemon '%s' is not running (there is no %s%s in the default directories)", c.name, c.name, bus.CONTROL_SUFFIX)
		}
		dirs := bus.candidate_dirs(context.temp_allocator)
		return fmt.tprintf("could not find a daemon in %s; is it running? (see --name and --socket)", strings.join(dirs, ", ", context.temp_allocator))
	case .Ambiguous:
		return fmt.tprintf("several daemons are running (%s), so choose one with --name", detail)
	case .No_Events_Socket:
		return "cannot find out where the events socket is, so give its path with --events-socket PATH"
	}
	return ""
}
