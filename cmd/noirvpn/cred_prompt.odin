// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import "core:os"
import "noir:proto/config"

// The terminal and file parts of the login: `auth-user-pass` read from a file,
// or typed at the terminal. The rest of the credentials are in cred.odin.

// Loads the login of the config: from the inline block, from a file, or by
// asking at the terminal (only when stdin is one).
cred_load :: proc(c: ^Creds, aup: config.Auth_User_Pass, abort_fd: i32) -> Cred_Error {
	switch {
	case aup.is_inline:
		return cred_parse(c, aup.data, aup.username_only)
	case aup.file != "":
		data, err := os.read_entire_file(aup.file, context.temp_allocator)
		if err != nil {
			return .Cannot_Read
		}
		return cred_parse(c, string(data), aup.username_only)
	}
	return cred_prompt(c, aup.username_only, abort_fd)
}

// Asks at the terminal. `abort_fd` is a descriptor (the signal descriptor)
// that cancels the question when it becomes readable; -1 for none.
cred_prompt :: proc(c: ^Creds, username_only: bool, abort_fd: i32) -> Cred_Error {
	if !tty_is(0) {
		return .No_Terminal
	}
	user: [CRED_MAX + 2]u8
	pass: [CRED_MAX + 2]u8
	defer mem.zero_explicit(&pass, size_of(pass))
	un, ok := tty_prompt("Username: ", true, user[:], abort_fd)
	if !ok {
		return .Prompt_Failed
	}
	pn := 0
	if !username_only {
		pn, ok = tty_prompt("Password: ", false, pass[:], abort_fd)
		if !ok {
			return .Prompt_Failed
		}
	}
	err := cred_set(c, string(user[:un]), string(pass[:pn]))
	if err == .None {
		c.from_prompt = true
	}
	return err
}
