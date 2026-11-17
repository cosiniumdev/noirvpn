// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package main

// The parts of the fake daemon that differ by system: Unix sockets.

import "core:fmt"
import "core:strings"
import "core:sys/posix"
import "noir:bus"
import "noir:proto/config"

fake_control_path :: proc(f: ^Fake) -> string {
	return fmt.tprintf("%s/fake.control", f.dir)
}

fake_events_path :: proc(f: ^Fake) -> string {
	return fmt.tprintf("%s/fake.events", f.dir)
}

// A control socket path in `dir` that nobody listens on.
test_socket :: proc(dir, name: string) -> string {
	return fmt.tprintf("%s/%s.control", dir, name)
}

// A file mode: `mode_t` is 32 bits on Linux and 16 on macOS.
@(private = "file")
mode_of :: proc(m: u32) -> posix.mode_t {
	when ODIN_OS == .Darwin {
		return transmute(posix.mode_t)u16(m)
	} else {
		return transmute(posix.mode_t)m
	}
}

// The umask may have been changed by another test.
fake_dir_private :: proc(dir: string) {
	posix.chmod(strings.clone_to_cstring(dir, context.temp_allocator), mode_of(0o700))
}

make_unreadable :: proc(path: string) {
	posix.chmod(strings.clone_to_cstring(path, context.temp_allocator), mode_of(0))
}

// Wait until the host has work, at most 20 ms.
fake_wait :: proc(h: ^bus.Host) {
	pfd := [1]posix.pollfd{{fd = posix.FD(bus.host_wake_fd(h)), events = {.IN}}}
	posix.poll(raw_data(pfd[:]), 1, 20)
}

test_euid :: proc() -> u32 {
	return bus.euid()
}

// A rule that gives this user `roles`.
allow_me :: proc(roles: config.Bus_Roles) -> config.Bus_Allow {
	return {kind = .Uid, id = bus.euid(), roles = roles}
}
