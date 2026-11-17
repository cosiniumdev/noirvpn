// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:strings"
import win "core:sys/windows"
import "noir:bus"
import "noir:platform/event"

// System parts of the client engine on Windows: what the event loop watches for
// the wintun session, adapter name, file checks of crl-verify. Other system
// parts of the daemon: cmd/noirvpn/sys_windows.odin.

// What a tun device needs, for the error when it cannot be opened.
TUN_HINT :: "needs an administrator and wintun.dll next to noirvpn.exe"

// ------------------------------------------------------------- event sources

// Watches the read event of the wintun session.
tun_watch :: proc(d: ^Daemon) -> event.Error {
	return event.add_handle(&d.loop, d.tun.read_event, on_tun_event, d)
}

tun_unwatch :: proc(d: ^Daemon) {
	event.remove_handle(&d.loop, d.tun.read_event)
}

// The event resets when the wait takes it: a burst that stopped at its limit
// asks for the next wait to report it again.
@(private = "file")
on_tun_event :: proc(loop: ^event.Loop, h: win.HANDLE, user: rawptr) {
	d := (^Daemon)(user)
	if tun_burst(d) {
		event.handle_again(loop, h)
	}
}

// ------------------------------------------------------------ the tun adapter

// The adapter name for `dev tun`, set at start from the instance name.
@(private = "file")
adapter_name := ""

// One adapter for each instance: `noirvpn` for the default instance, else
// `noirvpn-<name>`.
set_adapter_name :: proc(instance: string) {
	if instance == bus.DEFAULT_NAME {
		adapter_name = strings.clone(instance)
	} else {
		adapter_name = strings.concatenate({"noirvpn-", instance})
	}
}

generic_tun_name :: proc() -> string {
	return adapter_name
}

// IPv6 packets from the adapter that the block-ipv6 rule dropped. The first
// one gives a log line.
blocked6_drops: u64

tun_drop_blocked6 :: proc(d: ^Daemon) {
	if blocked6_drops == 0 {
		logf(.Info, "block-ipv6: IPv6 packets from %s are dropped", tun_name(d))
	}
	blocked6_drops += 1
}

// --------------------------------------------------------------- crl-verify

@(private = "file")
ERROR_FILE_NOT_FOUND :: 2
@(private = "file")
ERROR_PATH_NOT_FOUND :: 3
@(private = "file")
ERROR_ACCESS_DENIED :: 5

crl_stat :: proc(path: string) -> Crl_Stat {
	data: win.WIN32_FILE_ATTRIBUTE_DATA
	if !win.GetFileAttributesExW(win.utf8_to_wstring(path, context.temp_allocator), win.GetFileExInfoStandard, &data) {
		return {}
	}
	// A FILETIME counts 100 ns steps.
	t := i64(data.ftLastWriteTime.dwHighDateTime) << 32 | i64(data.ftLastWriteTime.dwLowDateTime)
	size := i64(data.nFileSizeHigh) << 32 | i64(data.nFileSizeLow)
	return Crl_Stat{ok = true, mtime_ns = t * 100, size = size}
}

// Why `path` cannot be read, for the log.
crl_stat_why :: proc(path: string) -> string {
	data: win.WIN32_FILE_ATTRIBUTE_DATA
	if win.GetFileAttributesExW(win.utf8_to_wstring(path, context.temp_allocator), win.GetFileExInfoStandard, &data) {
		return "it changed while it was read"
	}
	switch e := win.GetLastError(); e {
	case ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND:
		return "no such file"
	case ERROR_ACCESS_DENIED:
		return "permission denied"
	case:
		return fmt.tprintf("Windows error %d", e)
	}
}

// True if no file has the name `path`. A missing folder does not count: only
// ERROR_FILE_NOT_FOUND does. Runs inside the TLS library: the wide name is built
// on the stack.
crl_file_absent :: proc "contextless" (path: cstring) -> bool {
	wide: [4096 + 64]u16
	if win.MultiByteToWideChar(win.CP_UTF8, 0, (^u8)(path), -1, &wide[0], i32(len(wide))) == 0 {
		return false
	}
	if win.GetFileAttributesW(win.wstring(&wide[0])) != win.INVALID_FILE_ATTRIBUTES {
		return false
	}
	return win.GetLastError() == ERROR_FILE_NOT_FOUND
}
