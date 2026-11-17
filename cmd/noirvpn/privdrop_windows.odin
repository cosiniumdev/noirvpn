// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// `user` and `group` are refused on Windows (settings_load); these are the
// empty counterparts of privdrop_linux.odin.

Priv_Target :: struct {
	on: bool,
}

PRIV: Priv_Target

privs_dropped: bool

priv_settings_error :: proc(user, group: string) -> string {
	if user != "" || group != "" {
		return "user/group: not supported on Windows; the service runs as LocalSystem"
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
