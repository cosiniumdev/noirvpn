// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The profile file in the profile view: where an imported profile's text is,
// Open profile file, Show in folder, Reload profile configuration, and the
// sign-in rows for secret files (secret_supply.odin). The store keeps the text in
// `<id>/profile.ovpn`; the user may edit it, and Reload reads it again and has
// the service check it.

import "core:math"
import "core:mem"
import "core:strings"
import pf "profiles"
import "ui"

// SECRET_HELP is the help of the sign-in group of an imported profile.
when ODIN_OS == .Windows {
	SECRET_HELP :: "To read them from a file, add auth-user-pass FILE (containing the user name and the password on two lines) or askpass FILE (the passphrase on the first line) to the profile, with the full path. The app will read the file when you connect and apply it to the service. Windows: ensure that the file is in your own folder where no other user can access it."
} else {
	SECRET_HELP :: "To read them from a file, add auth-user-pass FILE (containing the user name and the password on two lines) or askpass FILE (the passphrase on the first line) to the profile, with the full path. The file must have restricted permissions (chmod 600). The app will read the file when you connect and apply it to the service."
}

// SAMPLE_PROFILE_PATH is the file of a simulated profile.
SAMPLE_PROFILE_PATH :: "/home/alice/.config/noirvpn/profiles/4f9c2e7a1b3d/profile.ovpn"

// secret_files_load takes the files of the secrets of the profile text, and
// checks them now (the file is read only at connect).
secret_files_load :: proc(e: ^Edit, login_file, pass_file: string, askpass: bool) {
	set_text(&e.login_file, login_file)
	set_text(&e.pass_file, pass_file)
	e.askpass = askpass
	set_text(&e.login_problem, login_file != "" ? pf.secret_file_problem(login_file) : "")
	set_text(&e.pass_problem, pass_file != "" ? pf.secret_file_problem(pass_file) : "")
}

// secret_row is one row of the sign-in group: "From file" and the path, or
// `value` when the profile names no file.
secret_row :: proc(app: ^App, label, file, problem, value: string) {
	u := &app.u
	if file == "" {
		value_row(app, label, value, value == "Not used" ? ui.MUTED : ui.TEXT)
		return
	}
	value_row(app, label, "From file", ui.TEXT)
	rr := inner(app, 18)
	ui.text(u, ui.ST_MONO, rr.x, rr.y + 1, ui.fit_middle(u, ui.ST_MONO, file, f32(rr.w)), ui.MUTED)
	if problem != "" {
		gap(app, 4)
		group_caption(app, problem, ui.WARN)
	}
}

// sign_in_rows draws the rows of the user name and password and of the key
// passphrase. The caller has the group open.
sign_in_rows :: proc(app: ^App) {
	e := &app.edit
	up := e.f.user_pass if e.created else e.user_pass
	login := "Not used"
	switch {
	case e.login_inline && !e.created:
		login = "In the profile"
	case up:
		login = "Asked when you connect"
	}
	secret_row(app, "User name and password", e.login_file, e.login_problem, login)
	group_sep(app)
	secret_row(app, "Key passphrase", e.pass_file, e.pass_problem, e.askpass ? "Asked when you connect" : "Not used")
	if !e.created {
		gap(app, 10)
		group_caption(app, SECRET_HELP)
	}
}

// profile_file_group draws the group of the profile file of an imported
// profile.
profile_file_group :: proc(app: ^App) {
	u := &app.u
	e := &app.edit
	section(app, "PROFILE FILE")
	gr := row(app, 0)
	y0 := app.cy
	g := ui.group_begin(u, {gr.x, y0, gr.w, 0})
	gap(app, 1 + GROUP_PAD_Y)
	{
		_ = copy_row(app, "File", e.path, "profile-path")
		gap(app, 10)
		rr := inner(app, 35)
		ow := i32(math.ceil(ui.button_width(u, "Open profile file", .Secondary)))
		sw := i32(math.ceil(ui.button_width(u, "Show in folder", .Secondary)))
		if ui.button(u, {rr.x, rr.y, ow, 35}, "Open profile file", .Secondary, e.path != "", ui.SURFACE) {
			profile_file_action(app, false)
		}
		if ui.button(u, {rr.x + ow + 8, rr.y, sw, 35}, "Show in folder", .Secondary, e.path != "", ui.SURFACE) {
			profile_file_action(app, true)
		}
		if e.file_note != "" {
			gap(app, 8)
			group_caption(app, e.file_note, ui.ERROR)
		}
		group_sep(app)
		rr = inner(app, 35)
		label := "Reload profile configuration"
		lw := i32(math.ceil(ui.button_width(u, label, .Secondary)))
		e.reload_at = {rr.x, rr.y, min(lw, rr.w), 35}
		if ui.button(u, e.reload_at, label, .Secondary, !e.dirty && app.pending.kind == .None, ui.SURFACE) {
			reload_start(app)
		}
		gap(app, 8)
		if e.dirty {
			group_caption(app, "Save or undo your changes in this view first.")
		} else {
			group_caption(app, "After you edit the file, reload it here. The service will check it first.")
		}
		if e.reload_msg != "" {
			gap(app, 8)
			group_caption(app, e.reload_msg, e.reload_error ? ui.ERROR : ui.OK)
		}
		if e.reconnect {
			gap(app, 8)
			rr = inner(app, 35)
			cw := i32(math.ceil(ui.button_width(u, "Reconnect", .Primary)))
			e.reconnect_at = {rr.x, rr.y, cw, 35}
			if ui.button(u, e.reconnect_at, "Reconnect", .Primary, app.pending.kind == .None, ui.SURFACE) {
				reload_reconnect(app)
			}
		}
	}
	gap(app, GROUP_PAD_Y + 1)
	ui.group_end(u, g, app.cy - y0)
	gap(app, 18)
}

// profile_file_action opens the profile file in the text editor of the
// desktop, or shows it in its folder.
profile_file_action :: proc(app: ^App, reveal: bool) {
	e := &app.edit
	set_text(&e.file_note, path_action(app, e.path, reveal))
}

// path_action opens a file in the text editor of the desktop, or shows it in
// its folder. It returns "" or the problem for the user. The simulation and
// the tests start no program.
path_action :: proc(app: ^App, path: string, reveal: bool) -> string {
	ok: bool
	if app.browser_test || app.link.kind == .Sim {
		app.browser_calls += 1
		set_text(&app.browser_last, tprint("%s %s", reveal ? "reveal" : "open", path))
		ok = !app.browser_fail
	} else {
		ok = file_reveal(path) if reveal else file_open(path)
	}
	switch {
	case ok:
		return ""
	case reveal:
		return "The folder could not be shown."
	}
	return "The file could not be opened from here. Open it in an editor yourself, using the path above."
}

// reload_start reads the profile file again and has the service check it,
// with the overrides of the profile view (as connect sends it).
reload_start :: proc(app: ^App) {
	e := &app.edit
	edit_reload_clear(e)
	if app.link.kind == .Sim || e.id == "" {
		set_text(&e.reload_msg, "Reloaded.")
		return
	}
	meta, text, ok := pf.store_load(app.store, e.id, context.temp_allocator)
	if !ok {
		set_text(&e.reload_msg, "The profile file could not be read.")
		e.reload_error = true
		return
	}
	defer mem.zero_explicit(raw_data(text), len(text))
	if len(text) > pf.PROFILE_MAX {
		set_text(&e.reload_msg, "The profile file is larger than 256 KiB.")
		e.reload_error = true
		return
	}
	composed := pf.compose(text, meta.overrides, context.temp_allocator)
	defer mem.zero_explicit(raw_data(composed), len(composed))
	pending_start(app, .Reload, strings.clone(composed), meta.name, "", "", {})
	set_text(&e.reload_msg, "Checking the profile…")
	form_send(app)
	e.status = ""
}

// reload_done takes the check of Reload. ok false: `text` is the refusal of
// the service; else a note or "".
reload_done :: proc(app: ^App, ok: bool, text: string) {
	e := &app.edit
	l := &app.link
	id := strings.clone(e.id, context.temp_allocator)
	note := strings.clone(text, context.temp_allocator)
	live := e.index == app.conn.profile && conn_active(app)
	store_reload(app)
	k := row_of(app, id)
	if k < 0 || !edit_load_stored(app, e, k) {
		set_text(&e.reload_msg, "The profile no longer exists.")
		e.reload_error = true
		return
	}
	switch {
	case !ok:
		set_text(&e.reload_msg, tprint("Reloaded. %s", note))
		e.reload_error = true
	case live && l.loaded && app.row_cache[id].sha == l.loaded_sha:
		set_text(&e.reload_msg, "Reloaded. The profile has not changed.")
	case live:
		set_text(&e.reload_msg, "Reloaded. Reconnect to apply the changes.")
		e.reconnect = true
	case note != "":
		set_text(&e.reload_msg, tprint("Reloaded. %s", note))
	case:
		set_text(&e.reload_msg, "Reloaded. It will be used the next time you connect.")
	}
}

// reload_reconnect ends the tunnel and connects with the text that was
// reloaded (row_connect: profile.set, then connect).
reload_reconnect :: proc(app: ^App) {
	e := &app.edit
	e.reconnect = false
	set_text(&e.reload_msg, "Reconnecting…")
	e.reload_error = false
	row_connect(app, e.index)
}
