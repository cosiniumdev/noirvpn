// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// `user` and `group` are refused on macOS (settings_load): the daemon keeps
// root for as long as it runs, because it calls ifconfig and route again at
// every reconnect and at the stop. These are the empty counterparts of
// privdrop_linux.odin.

Priv_Target :: struct {
	on: bool,
}

PRIV: Priv_Target

privs_dropped: bool

priv_settings_error :: proc(user, group: string) -> string {
	if user != "" || group != "" {
		return "user/group: not supported on macOS; the daemon keeps root, because it changes routes and DNS when it reconnects and stops"
	}
	return ""
}

priv_prepare :: proc(user, group: string) -> bool {
	return true
}

priv_check_text :: proc(user, group: string) -> string {
	return ""
}

priv_apply :: proc(tun_later := false) -> bool {
	return true
}
