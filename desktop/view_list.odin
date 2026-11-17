// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Profile list: the start view.

import "core:fmt"
import "core:math"
import mu "vendor:microui"
import "ui"

ROW_H :: 82
MENU_ROW :: "rowmenu"
MENU_PLUS :: "plusmenu"

row_menu_items := [4]ui.Menu_Item{{"Edit", false}, {"Duplicate", false}, {"Export", false}, {"Delete", true}}
plus_menu_items := [2]ui.Menu_Item{{"New profile", false}, {"Import profile", false}}
plus_menu_bus := [1]ui.Menu_Item{{"Import profile", false}}

// plus_items is the menu of the plus button. A build with no key generation
// (keygen_none.odin) only imports.
plus_items :: proc(app: ^App) -> []ui.Menu_Item {
	return app.link.kind == .Sim || KEYGEN ? plus_menu_items[:] : plus_menu_bus[:]
}

view_list :: proc(app: ^App) {
	u := &app.u
	ctx := &u.ctx
	w, h := u.size.x, u.size.y

	bar_h: i32 = 0
	msg_lines: []string
	if app.pending_delete >= 0 {
		bar_h = 56
	} else if app.message != "" {
		okw := ui.button_width(u, "OK", .Ghost)
		msg_lines = ui.wrap_text(u, ui.ST_BODY, app.message, f32(w) - 16 - 8 - okw - 12)
		bar_h = max(56, i32(len(msg_lines)) * 17 + 2 * 18 + 1)
	}
	res := topbar(app, {logo = true, simulated = app.link.kind == .Sim, plus = true})
	if res.plus {
		ui.menu_open(u, MENU_PLUS, plus_items(app), res.plus_rect.x + res.plus_rect.w - 1, res.plus_rect.y + res.plus_rect.h)
	}

	if res.settings {
		push_view(app, .Settings)
		return
	}

	scroll_begin(app, "list", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H - bar_h})
	for i in 0 ..< app.n_profiles {
		p := &app.profiles[i]
		mu.push_id(ctx, uintptr(i))
		r := row(app, ROW_H, 0)
		has_menu := p.source != .Daemon
		menu_btn := mu.Rect{w - 8 - 40, r.y + (ROW_H - 40) / 2, 40, 40}
		if !has_menu {
			menu_btn = {}
		}
		id := mu.get_id(ctx, "row")
		it := ui.interact(u, id, {r.x, r.y, r.w, r.h - 1}, true, true, menu_btn)
		if it.down {
			mu.draw_rect(ctx, {r.x, r.y, r.w, r.h - 1}, ui.SURFACE_RAISED)
		} else if it.hover {
			mu.draw_rect(ctx, {r.x, r.y, r.w, r.h - 1}, ui.SURFACE)
		}
		ui.hline(u, r.x, r.y + r.h - 1, r.w)
		maxw := f32(w) - 16 - 60
		y := r.y + 13
		if state, col, shown := row_state(app, i); shown {
			sw := ui.text_w(u, ui.ST_CAPTION, state)
			right := has_menu ? menu_btn.x - 4 : w - 16
			ui.text(u, ui.ST_CAPTION, right - i32(math.ceil(sw)), y + 3, state, col)
			maxw -= sw + 8
		}
		ui.text(u, ui.ST_HEADING, 16, y, ui.fit_text(u, ui.ST_HEADING, p.name, maxw), ui.TEXT)
		// The transport in the accent colour, then the server address.
		y += 19 + 3
		x: i32 = 16
		if p.proto != "" {
			proto := transport_label(p)
			ui.text(u, ui.ST_ROW_PROTO, x, y, proto, ui.ACCENT)
			x += i32(math.ceil(ui.text_w(u, ui.ST_ROW_PROTO, proto))) + 6
		}
		ui.text(u, ui.ST_CAPTION, x, y, ui.fit_text(u, ui.ST_CAPTION, row_address(p), f32(w - 60 - x)), ui.TEXT)
		y += 16 + 2
		used := p.source == .Daemon ? (app.link.config != "" ? app.link.config : "Service config file") : fmt_last_used(p.last_used)
		ui.text(u, ui.ST_CAPTION, 16, y, ui.fit_text(u, ui.ST_CAPTION, used, f32(w - 60 - 16)), ui.MUTED)
		if it.ring {
			ui.focus_ring(u, {f32(r.x) + 3, f32(r.y) + 3, f32(r.w) - 6, f32(r.h) - 7}, 6)
		}
		if has_menu && ui.icon_button(u, menu_btn, .More, "menu", ui.MUTED) {
			app.menu_row = i
			ui.menu_open(u, MENU_ROW, row_menu_items[:], menu_btn.x + menu_btn.w - 1, menu_btn.y + menu_btn.h)
		}
		if it.clicked {
			open_connection(app, i)
		}
		mu.pop_id(ctx)
		if current_view(app) != .List {
			break
		}
	}
	if app.n_profiles == 0 && (app.link.kind == .Sim || app.link.state == .Up) {
		gap(app, 32)
		r := row(app, 22)
		ui.text(u, ui.ST_TITLE, r.x, r.y, "No profiles", ui.TEXT)
		gap(app, 10)
		for line in ui.wrap_text(u, ui.ST_BODY, KEYGEN ? "Press + to create a profile or to import one (.ovpn file) from your VPN provider." : "Press + to import a profile (.ovpn file) from your VPN provider.", f32(w - 32)) {
			r = row(app, 17)
			ui.text(u, ui.ST_BODY, r.x, r.y, line, ui.MUTED)
		}
	}
	scroll_end(app)

	if bar_h > 0 {
		bar_rect := mu.Rect{0, h - bar_h, w, bar_h}
		ui.bar(u, bar_rect)
		by := bar_rect.y + 10 + 1
		bh := i32(ui.button_height())
		if app.pending_delete >= 0 {
			name := app.profiles[app.pending_delete].name
			prompt := fmt.tprintf("Delete “%s”?", name)
			dw := i32(math.ceil(ui.button_width(u, "Delete", .Danger)))
			cw := i32(math.ceil(ui.button_width(u, "Cancel", .Ghost)))
			th := i32(ui.line_height(ui.ST_BODY))
			ui.text(u, ui.ST_BODY, 16, bar_rect.y + 1 + (bar_h - 1 - th) / 2, prompt, ui.TEXT)
			if ui.button(u, {w - 16 - dw, by, dw, bh}, "Delete", .Danger, true, ui.SURFACE) {
				row_delete(app, app.pending_delete)
				app.pending_delete = -1
			}
			if ui.button(u, {w - 16 - dw - 8 - cw, by, cw, bh}, "Cancel", .Ghost, true, ui.SURFACE) {
				app.pending_delete = -1
			}
		} else if app.message != "" {
			okw := i32(math.ceil(ui.button_width(u, "OK", .Ghost)))
			th := i32(ui.line_height(ui.ST_BODY))
			col := app.message_error ? ui.ERROR : ui.TEXT
			ty := bar_rect.y + 1 + (bar_h - 1 - i32(len(msg_lines)) * 17) / 2
			for line, k in msg_lines {
				ui.text(u, ui.ST_BODY, 16, ty + i32(k) * 17 + (17 - th) / 2, line, col)
			}
			if ui.button(u, {w - 8 - okw, bar_rect.y + 1 + (bar_h - 1 - bh) / 2, okw, bh}, "OK", .Ghost, true, ui.SURFACE) {
				set_message(app, "")
			}
		}
	}
}

// row_state is the short state text of row i while its connection is active.
row_state :: proc(app: ^App, i: int) -> (text: string, col: ui.Color, shown: bool) {
	c := &app.conn
	if c.profile != i || !conn_active(app) {
		return
	}
	switch c.phase {
	case .Up:
		return "connected", ui.OK, true
	case .Credentials, .Web_Sign_In:
		return "sign in needed", ui.WARN, true
	case .Connecting, .Handshake:
		return "connecting", ui.WARN, true
	case .Disconnected, .Stopped, .Failed, .Closing:
	}
	return
}

delete_profile :: proc(app: ^App, i: int) {
	for k in i ..< app.n_profiles - 1 {
		app.profiles[k] = app.profiles[k + 1]
	}
	app.n_profiles -= 1
}

duplicate_profile :: proc(app: ^App, i: int) {
	if app.n_profiles >= MAX_PROFILES {
		return
	}
	src := app.profiles[i]
	app.profiles[app.n_profiles] = profile_make(fmt.tprintf("%s copy", src.name), src.host, src.port, src.proto, src.login)
	app.n_profiles += 1
}

// view_popups draws the menus and acts on what they return. It runs after the
// view, so the menus lie above it.
view_popups :: proc(app: ^App) {
	u := &app.u
	if current_view(app) != .List || app.quit_prompt {
		ui.menu_close(u, MENU_ROW)
		ui.menu_close(u, MENU_PLUS)
		return
	}
	if k := ui.menu(u, MENU_ROW, row_menu_items[:]); k >= 0 {
		i := app.menu_row
		switch k {
		case 0:
			open_profile(app, i)
		case 1:
			row_duplicate(app, i)
		case 2:
			if app.link.kind == .Sim {
				set_message(app, fmt.tprintf("Exported “%s” (simulated).", app.profiles[i].name))
			} else {
				export_start(app, i)
			}
		case 3:
			set_message(app, "")
			app.pending_delete = i
		}
	}
	items := plus_items(app)
	if k := ui.menu(u, MENU_PLUS, items); k >= 0 {
		switch items[k].label {
		case "New profile":
			create_open(app)
		case "Import profile":
			if app.link.kind == .Sim {
				set_message(app, "Importing requires the noirvpn service.")
			} else {
				import_start(app)
			}
		}
	}
}
