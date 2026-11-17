// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Secrets of `auth-user-pass FILE` and `askpass FILE`. The service runs as root
// and never opens a file a profile names; it waits over the bus, as for a
// profile with no file. The app reads the file as the user (checks of
// profiles/secret_file.odin) and responds with auth.supply. If the file is
// unusable or the server refused its content, the sign-in card asks and says why.
//
//   secret_tick (after the messages of the bus) -> auth.supply, or l.auto_note

import "core:mem"
import pf "profiles"

// secret_tick replies to a wait for a login or for the passphrase of the key from
// the file of the profile, once for each wait.
secret_tick :: proc(app: ^App) {
	l := &app.link
	if l.kind != .Bus || !l.have_auth {
		l.auto_done = false
		return
	}
	if l.auth_sent || l.web || l.auto_done {
		return
	}
	l.auto_done = true
	set_text(&l.auto_note, "")
	key := l.auth_kind == "key_pass"
	if !key && l.auth_kind != "credentials" && l.auth_kind != "" {
		return
	}
	path := secret_path(app, key)
	if path == "" {
		return
	}
	if !l.auto_force {
		// The file gave what the server or the key refused: ask, until the user
		// connects again.
		switch l.auth_reason {
		case "auth_failed":
			set_text(&l.auto_note, tprint("The server refused the login from %s. Fix the file, or sign in here instead.", path))
			return
		case "key_pass_wrong":
			set_text(&l.auto_note, tprint("The passphrase in %s does not unlock the key. Fix the file, or enter the passphrase here instead.", path))
			return
		}
	}
	data, problem, _ := pf.secret_file_read(path)
	if problem != "" {
		set_text(&l.auto_note, problem)
		return
	}
	defer {
		mem.zero_explicit(raw_data(data), len(data))
		delete(data)
	}
	if key {
		pass := pf.secret_first_line(data)
		if pass == "" {
			set_text(&l.auto_note, tprint("%s is empty.", path))
			return
		}
		bus_auth_supply_key(app, pass)
	} else {
		user, pass, bad := pf.secret_login(data, path)
		if bad != "" {
			set_text(&l.auto_note, bad)
			return
		}
		bus_auth_supply(app, user, pass)
	}
	l.auto_force = false
	l.auth_sent = true
	l.error = ""
	app.conn.phase = .Connecting
}

// secret_path is the file of the profile the service runs: the login file, or
// the passphrase file if key is true. "" if none, or if the stored text differs
// from the service's text.
secret_path :: proc(app: ^App, key: bool) -> string {
	l := &app.link
	i := app.conn.profile
	if i < 0 || i >= app.n_profiles || app.profiles[i].source != .Stored {
		return ""
	}
	id := app.profiles[i].id
	if rc := app.row_cache[id]; !l.service || !l.loaded || rc.sha != l.loaded_sha {
		return ""
	}
	_, text, ok := pf.store_load(app.store, id, context.temp_allocator)
	if !ok {
		return ""
	}
	defer mem.zero_explicit(raw_data(text), len(text))
	s, _ := pf.summarize(text, context.temp_allocator)
	return key ? s.pass_file : s.login_file
}
