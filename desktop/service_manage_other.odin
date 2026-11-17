// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !darwin
package main

// Systems with no app-managed service: see service_manage.odin.

import "core:strings"

manage_status :: proc() -> Manage_State {
	return .Unavailable
}

manage_register :: proc() -> string {
	return strings.clone("this system has no job to register")
}

manage_unregister :: proc() -> string {
	return strings.clone("this system has no job to register")
}

manage_has_job_file :: proc() -> bool {
	return false
}

manage_daemon_path :: proc(allocator := context.allocator) -> string {
	return ""
}

manage_open_settings :: proc() {}
