// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
package dco

// Systems other than Linux have no backend: `connect` and `kernel_connect`
// fail, and the daemon runs the data path itself.

ENO_OVPN :: -65
ENOTSUP :: -95

Log_Proc :: #type proc(user: rawptr, level: Log_Level, text: string)

Conn :: struct {}

Kernel :: struct {}

connect :: proc(c: ^Conn, path: string, log: Log_Proc = nil, log_user: rawptr = nil) -> int {
	return ENOTSUP
}

disconnect :: proc(c: ^Conn) {}

daemon_name :: proc(c: ^Conn) -> string {
	return ""
}

socket_backend :: proc(c: ^Conn) -> Backend {
	return {}
}

kernel_connect :: proc(k: ^Kernel, log: Log_Proc = nil, log_user: rawptr = nil) -> int {
	return ENO_OVPN
}

kernel_disconnect :: proc(k: ^Kernel) {}

kernel_backend :: proc(k: ^Kernel) -> Backend {
	return {}
}
