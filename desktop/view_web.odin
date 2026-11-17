// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Web sign-in: the wait view, the browser start, and what the link holds of the
// wait.
//
//   client.auth_needed (web_auth) -> web_take, link_refresh
//   status (with the link)        -> web_take -> web_sync -> web_open or the tray
//   wait view: Open again -> web_open; Copy link; Cancel -> link_disconnect
//
// The sign-in result is the next client.state. The browser starts by itself only
// after the user pressed Connect with the window shown.

import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:time"
import "ui"

WEB_OPENED :: "The sign-in page is now open in your browser."
WEB_NOT_STARTED :: "The browser could not be started."
WEB_COPIED :: "Link copied."
WEB_PRIVATE :: "The browser setting of this profile opens a private window, but web sign-in needs a normal window."
WEB_BAD_LINK :: "The server sent a link that is not https, so it was not opened."
WEB_NO_LINK :: "You do not have permission to open the sign-in link."

// web_take reads the web_auth object of client.auth_needed or status. Only
// status has the link.
web_take :: proc(app: ^App, obj: json.Value, from_status: bool) {
	l := &app.link
	l.web = true
	set_text(&l.web_host, jstr(obj, "host"))
	l.web_deadline = 0
	if ts := jstr(obj, "deadline"); ts != "" {
		if t, consumed := time.rfc3339_to_time_utc(ts); consumed > 0 {
			l.web_deadline = app.now + time.duration_seconds(time.diff(time.now(), t))
		}
	}
	if l.web_deadline == 0 {
		if s := jint(obj, "timeout_s"); s > 0 {
			l.web_deadline = app.now + f64(s)
		}
	}
	if from_status {
		url := jstr(obj, "url")
		if url != l.web_url {
			wipe_text(&l.web_url)
			l.web_url = strings.clone(url)
		}
	}
}

// web_forget ends the wait. The link is wiped.
web_forget :: proc(l: ^Link) {
	l.web = false
	wipe_text(&l.web_url)
	set_text(&l.web_host, "")
	l.web_deadline = 0
	l.web_opened = false
	set_text(&l.web_note, "")
	l.web_note_bad = false
}

// web_sync acts once on each new link: starts the browser if the user asked for
// the connection with the window shown; else the tray says a sign-in waits.
web_sync :: proc(app: ^App) {
	l := &app.link
	if !l.web || l.web_url == "" || app.conn.phase != .Web_Sign_In {
		return
	}
	h := link_hash(l.web_url)
	if h == l.web_done {
		return
	}
	l.web_done = h
	if l.web_auto && !app.hidden {
		web_open(app)
	}
}

// web_open starts the browser with the link. It returns false when nothing started.
web_open :: proc(app: ^App) -> bool {
	l := &app.link
	note :: proc(l: ^Link, text: string, bad: bool) {
		set_text(&l.web_note, text)
		l.web_note_bad = bad
	}
	if l.web_url == "" {
		note(l, WEB_NO_LINK, true)
		return false
	}
	if web_link_host(l.web_url) == "" {
		note(l, WEB_BAD_LINK, true)
		return false
	}
	words, private := browser_words(row_browser(app, app.conn.profile))
	if private {
		note(l, WEB_PRIVATE, true)
		return false
	}
	if len(words) == 0 && BROWSER_DEFAULT != "" {
		words = {BROWSER_DEFAULT}
	}
	ok: bool
	if app.browser_test {
		app.browser_calls += 1
		set_text(&app.browser_last, strings.join(words, " ", context.temp_allocator))
		ok = !app.browser_fail
	} else {
		ok = browser_spawn(words, l.web_url)
	}
	note(l, ok ? WEB_OPENED : WEB_NOT_STARTED, !ok)
	l.web_opened ||= ok
	return ok
}

// web_copy puts the link on the clipboard.
web_copy :: proc(app: ^App) {
	l := &app.link
	if l.web_url == "" || web_link_host(l.web_url) == "" {
		set_text(&l.web_note, l.web_url == "" ? WEB_NO_LINK : WEB_BAD_LINK)
		l.web_note_bad = true
		return
	}
	ok := copy_text(app, l.web_url)
	set_text(&l.web_note, ok ? WEB_COPIED : "The clipboard is not available.")
	l.web_note_bad = !ok
}

// web_shown_host is the host that the view shows: the one of the link when
// this user has it, else the one of the event.
web_shown_host :: proc(l: ^Link) -> string {
	if l.web_url != "" {
		return web_link_host(l.web_url)
	}
	return l.web_host
}

// web_link_host is the host of an https link, or "" for a link the GUI does not
// open: other scheme, byte not printable ASCII, quote, user part, or no host.
web_link_host :: proc(url: string) -> string {
	if len(url) < 8 || !strings.equal_fold(url[:8], "https://") {
		return ""
	}
	for ch in transmute([]u8)url {
		if ch <= 0x20 || ch >= 0x7f || ch == '"' {
			return ""
		}
	}
	rest := url[8:]
	if i := strings.index_any(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if strings.index_byte(rest, '@') >= 0 {
		return ""
	}
	host := rest
	if len(rest) > 0 && rest[0] == '[' {
		end := strings.index_byte(rest, ']')
		if end < 0 {
			return ""
		}
		host = rest[:end + 1]
	} else if i := strings.last_index_byte(rest, ':'); i >= 0 {
		host = rest[:i]
	}
	if host == "" || host == "[]" {
		return ""
	}
	return host
}

// browser_words splits the browser setting of a profile into words (double
// quotes for a word with spaces). private is true if a word asks for a private window.
browser_words :: proc(cmd: string) -> (words: []string, private: bool) {
	out := make([dynamic]string, context.temp_allocator)
	b := strings.builder_make(context.temp_allocator)
	in_word, quoted := false, false
	for ch in transmute([]u8)cmd {
		switch {
		case ch == '"':
			quoted = !quoted
			in_word = true
		case !quoted && (ch == ' ' || ch == '\t'):
			if in_word {
				append(&out, strings.clone(strings.to_string(b), context.temp_allocator))
				strings.builder_reset(&b)
				in_word = false
			}
		case:
			strings.write_byte(&b, ch)
			in_word = true
		}
	}
	if in_word {
		append(&out, strings.clone(strings.to_string(b), context.temp_allocator))
	}
	for w, i in out {
		if i == 0 || len(w) < 2 || (w[0] != '-' && w[0] != '/') {
			continue
		}
		name := strings.to_lower(strings.trim_left(w, "-/"), context.temp_allocator)
		if eq := strings.index_byte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		switch name {
		case "incognito", "private", "private-window", "inprivate", "guest":
			private = true
		}
	}
	return out[:], private
}

// row_browser is the browser setting of row i, or "" for the default.
row_browser :: proc(app: ^App, i: int) -> string {
	if i < 0 || i >= len(app.profiles) || app.profiles[i].source != .Stored {
		return ""
	}
	for m in app.metas {
		if m.id == app.profiles[i].id {
			return strings.trim_space(m.browser)
		}
	}
	return ""
}

// web_left_text is the time left of the sign-in, as "4:32 left".
web_left_text :: proc(app: ^App) -> string {
	l := &app.link
	if l.web_deadline == 0 {
		return ""
	}
	left := l.web_deadline - app.now
	if left <= 0 {
		return "The sign-in time has run out"
	}
	return tprint("%s left", fmt_duration(left + 0.999))
}

// link_hash is a hash of a link, so that the link itself is not kept twice.
link_hash :: proc(s: string) -> u64 {
	h: u64 = 0xcbf29ce484222325
	for ch in transmute([]u8)s {
		h = (h ~ u64(ch)) * 0x100000001b3
	}
	return h
}

// wipe_text zeroes and frees a heap string of the view model.
wipe_text :: proc(s: ^string) {
	if len(s^) > 0 {
		mem.zero(raw_data(s^), len(s^))
		delete(s^)
	}
	s^ = ""
}

// web_panel is the wait view: where to sign in, the time left, and the actions.
web_panel :: proc(app: ^App) {
	u := &app.u
	l := &app.link
	w := u.size.x
	host := web_shown_host(l)
	hint := "Sign in with your browser to connect."
	inner_w := f32(w - 2 * ui.CARD_MARGIN - 2 - 32)
	hint_lines := ui.wrap_text(u, ui.ST_BODY, hint, inner_w)
	note_lines: []string
	if l.web_note != "" {
		note_lines = ui.wrap_text(u, ui.ST_BODY, l.web_note, inner_w)
	}
	left := web_left_text(app)
	total_h: i32 = 1 + 16 + 19 + 12 + i32(len(hint_lines)) * 17 + 10 + 17 + 6 + 17 + 12 + 35 + 8 + 35 + 16 + 1
	if len(note_lines) > 0 {
		total_h += i32(len(note_lines)) * 17 + 10
	}
	r := row(app, total_h, ui.CARD_MARGIN)
	ui.card_flat(u, r)
	x := r.x + 17
	cw := r.w - 34
	y := r.y + 17
	ui.text(u, ui.ST_HEADING, x, y, "Web sign-in", ui.TEXT)
	y += 19 + 12
	for line in hint_lines {
		ui.text(u, ui.ST_BODY, x, y, line, ui.MUTED)
		y += 17
	}
	y += 10
	ui.text(u, ui.ST_BODY, x, y, "Sign-in page", ui.MUTED)
	ui.text(u, ui.ST_BODY_BOLD, x + ui.LABEL_W, y, ui.fit_text(u, ui.ST_BODY_BOLD, host != "" ? host : "–", f32(cw - ui.LABEL_W)), ui.TEXT_STRONG)
	y += 17 + 6
	ui.text(u, ui.ST_BODY, x, y, "Time", ui.MUTED)
	ui.text(u, ui.ST_BODY, x + ui.LABEL_W, y, left != "" ? left : "–", ui.TEXT)
	y += 17 + 12
	if len(note_lines) > 0 {
		for line in note_lines {
			ui.text(u, ui.ST_BODY, x, y, line, l.web_note_bad ? ui.ERROR : ui.MUTED)
			y += 17
		}
		y += 10
	}
	have := l.web_url != "" && web_link_host(l.web_url) != ""
	bw := (cw - 8) / 2
	if ui.button(u, {x, y, bw, 35}, web_open_label(l), .Primary, have, ui.SURFACE) {
		web_open(app)
	}
	if ui.button(u, {x + bw + 8, y, cw - bw - 8, 35}, "Copy link", .Secondary, have, ui.SURFACE) {
		web_copy(app)
	}
	y += 35 + 8
	if ui.button(u, {x, y, cw, 35}, "Cancel", .Secondary, true, ui.SURFACE) {
		link_disconnect(app)
	}
}

// web_open_label is "Open again" once the browser started for this link.
web_open_label :: proc(l: ^Link) -> string {
	return l.web_opened ? "Open again" : "Open in browser"
}
