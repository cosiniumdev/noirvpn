// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:strings"
import "core:sys/posix"
import "noir:platform/event"
import "noir:platform/tun"

// System parts of the client engine on macOS: utun name, what the event loop
// watches for the tun device, file checks of crl-verify. Other system parts of
// the daemon: cmd/noirvpn/sys_darwin.odin. A utun interface is named `utunN` and
// cannot be renamed.

// What a tun device needs, for the error when it cannot be opened.
TUN_HINT :: "a utun interface needs root: run noirvpn with sudo, and use `dev tun` or `dev utunN`"

// Tun device name from the `dev` option. A utun interface cannot be renamed, so
// `utunN` is used as is and every other name (`tun`, `tun0`, `noir0`) leaves the
// choice to the system.
utun_name_of :: proc(dev: string) -> string {
	if tun.is_utun_name(dev) {
		return dev
	}
	return ""
}

// What to tell the user about a `dev` that a utun interface cannot have, or "".
utun_dev_warning :: proc(dev: string) -> string {
	if dev == "" || dev == "tun" || tun.is_utun_name(dev) {
		return ""
	}
	return fmt.tprintf("dev %s: a macOS tunnel is named utunN and cannot be renamed; the system chooses the name (use dev utunN to ask for one)", dev)
}

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

// After `tun_watch` of a device that has packets: nothing to do, the loop
// reports a readable descriptor on the next wait.
tun_kick :: proc(d: ^Daemon) {
}

// --------------------------------------------------------------- crl-verify

crl_stat :: proc(path: string) -> Crl_Stat {
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	st: posix.stat_t
	if posix.stat(cpath, &st) != .OK {
		return {}
	}
	return Crl_Stat{ok = true, mtime_ns = i64(st.st_mtim.tv_sec) * 1_000_000_000 + i64(st.st_mtim.tv_nsec), size = i64(st.st_size), ino = u64(st.st_ino)}
}

// Why `path` cannot be read, for the log.
crl_stat_why :: proc(path: string) -> string {
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	st: posix.stat_t
	if posix.stat(cpath, &st) == .OK {
		return "it changed while it was read"
	}
	#partial switch e := posix.errno(); e {
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
	if posix.access(path, posix.F_OK) == .OK {
		return false
	}
	return posix.errno() == .ENOENT
}
