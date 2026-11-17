// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package bus

import win "core:sys/windows"
import "noir:proto/config"

// uid and gid rules are ignored on Windows: nothing to look up.
default_resolver :: proc(kind: config.Bus_Id_Kind, name: string) -> (id: u32, ok: bool) {
	return 0, false
}

default_member :: proc(uid, gid: u32) -> bool {
	return false
}

// Windows has no user ids: 0, as the identity of every pipe client.
euid :: proc() -> u32 {
	return 0
}

// Look a Windows account name up ("BUILTIN\Users", "DOMAIN\alice"). A domain
// name can block while the domain controller is not reachable: prefer a SID in
// the config.
default_sid_resolver :: proc(name: string) -> (sid: Sid, ok: bool) {
	wname := win.utf8_to_wstring(name, context.temp_allocator)
	if wname == nil {
		return {}, false
	}
	buf: [SID_MAX]u8
	size := u32(len(buf))
	domain: [256]u16
	dsize := u32(len(domain))
	use: i32
	if lookup_account_name(nil, wname, &buf, &size, &domain[0], &dsize, &use) == win.FALSE {
		return {}, false
	}
	return sid_from_bytes(buf[:size])
}
