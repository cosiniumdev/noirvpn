// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:strings"
import "core:sys/linux"
import "noir:platform/event"

// System parts of the client engine on Linux: what the event loop watches for
// the tun device, file checks of crl-verify. Other system parts of the daemon:
// cmd/noirvpn/sys_linux.odin.

// What a tun device needs, for the error when it cannot be opened.
TUN_HINT :: "needs CAP_NET_ADMIN and /dev/net/tun"

// ------------------------------------------------------------- event sources

// Watches the tun device for packets.
tun_watch :: proc(d: ^Daemon) -> event.Error {
	return event.add_fd(&d.loop, d.tun.fd, {.Read}, on_tun, d)
}

tun_unwatch :: proc(d: ^Daemon) {
	event.remove_fd(&d.loop, d.tun.fd)
}

on_tun :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	_ = tun_burst((^Daemon)(user))
}

// --------------------------------------------------------------- crl-verify

crl_stat :: proc(path: string) -> Crl_Stat {
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	st: linux.Stat
	if err := linux.stat(cpath, &st); err != .NONE {
		return {}
	}
	return Crl_Stat{ok = true, mtime_ns = i64(st.mtime.time_sec) * 1_000_000_000 + i64(st.mtime.time_nsec), size = i64(st.size), ino = u64(st.ino)}
}

// Why `path` cannot be read, for the log.
crl_stat_why :: proc(path: string) -> string {
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	st: linux.Stat
	#partial switch e := linux.stat(cpath, &st); e {
	case .ENOENT:
		return "no such file"
	case .EACCES:
		return "permission denied"
	case:
		return fmt.tprintf("%v", e)
	}
}

// True when no file has the name `path`. Runs inside the TLS library.
crl_file_absent :: proc "contextless" (path: cstring) -> bool {
	return linux.access(path, linux.F_OK) == .ENOENT
}
