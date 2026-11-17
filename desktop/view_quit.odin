// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Close and quit prompts, one modal dialog over the current view. The GUI is the
// only user of its service, so quit with an active connection disconnects. Only
// Hide keeps the tunnel up.
//   close form (X and window close request, when a tray exists):
//     active: Cancel, "Disconnect and quit", Hide; idle: Cancel, Quit, Hide.
//   quit form (quit event, tray Quit, X without a tray):
//     Cancel and "Disconnect and quit", only while a connection is active.

import "core:math"
import mu "vendor:microui"
import "ui"

QUIT_MODAL :: "quitprompt"
QUIT_MARGIN :: 24 // window edge to card
QUIT_PAD :: 20 // card edge to content
QUIT_GAP :: 8 // between buttons
QUIT_CANCEL :: "Cancel"
QUIT_CONFIRM :: "Disconnect and quit"
QUIT_SHORT :: "Quit"
QUIT_HIDE :: "Hide"

// conn_active is true while the service has a tunnel or is creating one.
conn_active :: proc(app: ^App) -> bool {
	if app.link.kind == .Bus && app.link.state != .Up {
		return false
	}
	switch app.conn.phase {
	case .Connecting, .Handshake, .Credentials, .Web_Sign_In, .Up:
		return true
	case .Disconnected, .Stopped, .Failed, .Closing:
	}
	return false
}

// request_quit handles the quit event (end of OS session) and quit paths that
// never offer Hide. A second request while the prompt is open quits, so the end
// of the OS session is never held back.
request_quit :: proc(app: ^App) {
	if app.quit_prompt || !conn_active(app) {
		quit_now(app)
		return
	}
	open_prompt(app, false)
}

// quit_now ends the program, and the connection when one is active.
quit_now :: proc(app: ^App) {
	if conn_active(app) {
		link_disconnect(app)
	}
	app.quit_prompt = false
	app.quit = true
}

// request_close handles the close button and the window close request. With a
// tray it asks whether to hide or quit. Without one it is request_quit.
request_close :: proc(app: ^App) {
	if !app.has_tray {
		request_quit(app)
		return
	}
	if app.quit_prompt {
		quit_now(app)
		return
	}
	open_prompt(app, true)
}

// open_prompt opens the prompt. A hidden window is shown first.
open_prompt :: proc(app: ^App, hide: bool) {
	if app.hidden {
		show_window(app)
	}
	app.quit_prompt = true
	app.quit_fresh = true
	app.prompt_hide = hide
}

Prompt_Button :: enum u8 {
	Cancel,
	Disconnect,
	Quit,
	Hide,
}

Quit_Layout :: struct {
	card:           mu.Rect,
	cancel:         mu.Rect,
	disconnect:     mu.Rect, // Disconnect and quit
	confirm:        mu.Rect, // Quit
	hide:           mu.Rect,
	order:          [4]Prompt_Button, // the buttons in drawing and Tab order
	n:              int,
	title_y, body_y: i32,
	line_h:         i32,
	lines:          []string,
	stacked:        bool, // the buttons do not fit in one row
}

prompt_title :: proc(app: ^App) -> string {
	return app.prompt_hide ? "Close noirvpn?" : "Quit noirvpn?"
}

prompt_label :: proc(app: ^App, b: Prompt_Button) -> string {
	switch b {
	case .Cancel:
		return QUIT_CANCEL
	case .Disconnect:
		return QUIT_CONFIRM
	case .Quit:
		return QUIT_SHORT
	case .Hide:
		return QUIT_HIDE
	}
	return ""
}

// prompt_buttons is the row order of the buttons of the open prompt.
prompt_buttons :: proc(app: ^App) -> (b: [4]Prompt_Button, n: int) {
	active := conn_active(app)
	switch {
	case app.prompt_hide && active:
		return {.Cancel, .Disconnect, .Hide, .Hide}, 3
	case app.prompt_hide:
		return {.Cancel, .Quit, .Hide, .Hide}, 3
	}
	return {.Cancel, .Disconnect, .Disconnect, .Disconnect}, 2
}

prompt_kind :: proc(app: ^App, b: Prompt_Button) -> ui.Button_Kind {
	switch b {
	case .Cancel, .Quit:
		return .Secondary
	case .Disconnect:
		return .Danger
	case .Hide:
		return .Primary
	}
	return .Secondary
}

// quit_body is the text of the prompt for the current phase.
quit_body :: proc(app: ^App, max_w: f32) -> string {
	if app.prompt_hide && !conn_active(app) {
		return "Hide to the system tray."
	}
	name := ui.fit_text(&app.u, ui.ST_BODY, app.profiles[app.conn.profile].name, max_w - 24)
	up := app.conn.phase == .Up
	switch {
	case app.prompt_hide && up:
		return tprint("“%s” is connected.", name)
	case app.prompt_hide:
		return tprint("“%s” is connecting.", name)
	case up:
		return tprint("“%s” is connected. Quitting will terminate the tunnel.", name)
	}
	return tprint("Quitting will stop connecting “%s”.", name)
}

// quit_layout places the card and its buttons in the window.
quit_layout :: proc(app: ^App) -> (l: Quit_Layout) {
	u := &app.u
	card_w := u.size.x - 2 * QUIT_MARGIN
	inner := card_w - 2 * QUIT_PAD
	l.lines = ui.wrap_text(u, ui.ST_BODY, quit_body(app, f32(inner)), f32(inner))
	title_h := i32(math.ceil(ui.line_height(ui.ST_HEADING)))
	l.line_h = i32(math.ceil(ui.line_height(ui.ST_BODY)))
	bh := i32(ui.button_height())

	// A stack lists the buttons in the reverse of the row: the most wanted first.
	row_order, n := prompt_buttons(app)
	l.n = n
	widths: [Prompt_Button]i32
	total := QUIT_GAP * i32(l.n - 1)
	for b in row_order[:l.n] {
		widths[b] = i32(math.ceil(ui.button_width(u, prompt_label(app, b), prompt_kind(app, b))))
		total += widths[b]
	}
	l.stacked = total > inner
	rects: [Prompt_Button]^mu.Rect = {.Cancel = &l.cancel, .Disconnect = &l.disconnect, .Quit = &l.confirm, .Hide = &l.hide}
	if l.stacked {
		for b, i in row_order[:l.n] {
			l.order[l.n - 1 - i] = b
		}
	} else {
		l.order = row_order
	}

	buttons_h := l.stacked ? i32(l.n) * bh + QUIT_GAP * i32(l.n - 1) : bh
	body_h := i32(len(l.lines)) * l.line_h
	card_h := QUIT_PAD + title_h + 12 + body_h + 16 + buttons_h + QUIT_PAD
	l.card = {QUIT_MARGIN, (u.size.y - card_h) / 2, card_w, card_h}
	l.title_y = l.card.y + QUIT_PAD
	l.body_y = l.title_y + title_h + 12
	by := l.body_y + body_h + 16
	if l.stacked {
		for b, i in l.order[:l.n] {
			rects[b]^ = {l.card.x + QUIT_PAD, by + i32(i) * (bh + QUIT_GAP), inner, bh}
		}
	} else {
		x := l.card.x + card_w - QUIT_PAD
		for i := l.n - 1; i >= 0; i -= 1 {
			b := row_order[i]
			x -= widths[b]
			rects[b]^ = {x, by, widths[b], bh}
			x -= QUIT_GAP
		}
	}
	return
}

// view_quit_prompt draws the prompt when it is open and acts on its buttons. It
// runs after the other popups, so it lies above everything.
view_quit_prompt :: proc(app: ^App) {
	if !app.quit_prompt {
		return
	}
	u := &app.u
	if !ui.modal_begin(u, QUIT_MODAL, app.quit_fresh) {
		return
	}
	defer ui.modal_end(u)
	if app.quit_fresh {
		app.quit_fresh = false
		first := app.prompt_hide ? QUIT_HIDE : QUIT_CANCEL
		u.focus = mu.get_id(&u.ctx, first)
		u.focus_visible = true
	}
	l := quit_layout(app)
	mu.draw_rect(&u.ctx, {0, 0, u.size.x, u.size.y}, ui.SCRIM)
	if ui.interact(u, mu.get_id(&u.ctx, "scrim"), {0, 0, u.size.x, u.size.y}, false, true, l.card).clicked {
		app.quit_prompt = false
	}

	ui.card_flat(u, l.card)
	x := l.card.x + QUIT_PAD
	ui.text(u, ui.ST_HEADING, x, l.title_y, prompt_title(app), ui.TEXT)
	for line, i in l.lines {
		ui.text(u, ui.ST_BODY, x, l.body_y + i32(i) * l.line_h, line, ui.MUTED)
	}

	rects := [Prompt_Button]mu.Rect {
		.Cancel     = l.cancel,
		.Disconnect = l.disconnect,
		.Quit       = l.confirm,
		.Hide       = l.hide,
	}
	pressed: [Prompt_Button]bool
	for b in l.order[:l.n] {
		pressed[b] = ui.button(u, rects[b], prompt_label(app, b), prompt_kind(app, b), true, ui.CARD_FLAT)
	}
	if u.escape || pressed[.Cancel] {
		app.quit_prompt = false
	}
	if pressed[.Hide] {
		app.quit_prompt = false
		hide_window(app)
	}
	if pressed[.Disconnect] || pressed[.Quit] {
		quit_now(app)
	}
}
