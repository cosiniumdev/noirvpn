// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:mem"
import "core:strings"
import "noir:proto/session"

// User name and password of `auth-user-pass`, and the auth-token from the
// server. Wiped at exit. Never logged.
CRED_MAX :: session.CREDENTIAL_MAX

Creds :: struct {
	user:         [CRED_MAX + 1]u8,
	user_n:       int,
	pass:         [CRED_MAX + 1]u8,
	pass_n:       int,
	have:         bool,
	// Typed at the terminal: ask again after a refused login (`auth-retry interact`).
	from_prompt:  bool,
	// The auth-token of the last session and the user name it goes with.
	token:        [CRED_MAX + 1]u8,
	token_n:      int,
	token_user:   [CRED_MAX + 1]u8,
	token_user_n: int,
}

Cred_Error :: enum u8 {
	None,
	Cannot_Read,
	// A credentials file needs the user name on line 1 and the password on line 2.
	Bad_Format,
	Empty_User,
	Too_Long,
	// The config asks for a prompt and stdin is not a terminal.
	No_Terminal,
	Prompt_Failed,
}

cred_error_text :: proc "contextless" (e: Cred_Error) -> string {
	switch e {
	case .None:
		return ""
	case .Cannot_Read:
		return "cannot read the auth-user-pass file"
	case .Bad_Format:
		return "the auth-user-pass file needs the user name on line 1 and the password on line 2"
	case .Empty_User:
		return "the user name is empty"
	case .Too_Long:
		return "the user name or password is longer than 127 bytes"
	case .No_Terminal:
		return "auth-user-pass has no file and stdin is not a terminal, so there is no way to ask for the login: give a file (auth-user-pass FILE) or an inline <auth-user-pass> block"
	case .Prompt_Failed:
		return "could not read the credentials from the terminal"
	}
	return ""
}

cred_wipe :: proc(c: ^Creds) {
	mem.zero_explicit(c, size_of(Creds))
}

// Overwrites the password (and a saved token), keeps the user name.
cred_wipe_password :: proc(c: ^Creds) {
	mem.zero_explicit(&c.pass, size_of(c.pass))
	mem.zero_explicit(&c.token, size_of(c.token))
	mem.zero_explicit(&c.token_user, size_of(c.token_user))
	c.pass_n, c.token_n, c.token_user_n = 0, 0, 0
	c.have = false
}

cred_set :: proc(c: ^Creds, user, pass: string) -> Cred_Error {
	if len(user) == 0 {
		return .Empty_User
	}
	if len(user) > CRED_MAX || len(pass) > CRED_MAX {
		return .Too_Long
	}
	mem.zero_explicit(&c.user, size_of(c.user))
	mem.zero_explicit(&c.pass, size_of(c.pass))
	c.user_n = copy(c.user[:], user)
	c.pass_n = copy(c.pass[:], pass)
	c.have = true
	return .None
}

// `text`: user name on line 1, password on line 2 (file or inline block). A line
// ends at "\n"; a "\r" before it is dropped. With `username_only` the password
// line may be missing.
cred_parse :: proc(c: ^Creds, text: string, username_only: bool) -> Cred_Error {
	rest := text
	user, pass: string
	have_pass := false
	if i := strings.index_byte(rest, '\n'); i >= 0 {
		user = rest[:i]
		rest = rest[i + 1:]
		if len(rest) > 0 {
			have_pass = true
			if j := strings.index_byte(rest, '\n'); j >= 0 {
				pass = rest[:j]
			} else {
				pass = rest
			}
		}
	} else {
		user = rest
	}
	user = strings.trim_right(user, "\r")
	pass = strings.trim_right(pass, "\r")
	if !have_pass && !username_only {
		return .Bad_Format
	}
	return cred_set(c, user, pass)
}
