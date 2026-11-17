// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package main

// The parts of the fake daemon that differ by system: named pipes. The pipe
// names come from the name of the private directory, which is unique.

import "core:fmt"
import "core:path/filepath"
import win "core:sys/windows"
import "noir:bus"
import "noir:proto/config"

fake_control_path :: proc(f: ^Fake) -> string {
	return fmt.tprintf("%snoirvpn-%s%s", bus.PIPE_DIR, filepath.base(f.dir), bus.CONTROL_SUFFIX)
}

fake_events_path :: proc(f: ^Fake) -> string {
	return fmt.tprintf("%snoirvpn-%s%s", bus.PIPE_DIR, filepath.base(f.dir), bus.EVENTS_SUFFIX)
}

// A control pipe name that nobody listens on.
test_socket :: proc(dir, name: string) -> string {
	return fmt.tprintf("%snoirvpn-%s-%s%s", bus.PIPE_DIR, filepath.base(dir), name, bus.CONTROL_SUFFIX)
}

fake_dir_private :: proc(dir: string) {}

// Wait until the host has work, at most 20 ms.
fake_wait :: proc(h: ^bus.Host) {
	win.WaitForSingleObject(bus.host_wake_handle(h), 20)
}

test_euid :: proc() -> u32 {
	return 0
}

// A rule that gives this user `roles`.
allow_me :: proc(roles: config.Bus_Roles) -> config.Bus_Allow {
	sid, _ := bus.current_user_sid()
	return {kind = .Sid, name = bus.sid_string(sid, context.temp_allocator), roles = roles}
}
