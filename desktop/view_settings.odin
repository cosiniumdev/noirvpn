// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Settings view: the display size and About.

import "core:math"
import mu "vendor:microui"
import sdl "vendor:sdl3"
import "ui"

// BUILD_DATE: set by build.sh (-define:BUILD_DATE=YYYY-MM-DD, local date).
// VERSION_NUMBER: daemon version of the same tree (-define:VERSION_NUMBER=X.Y.Z).
BUILD_DATE :: #config(BUILD_DATE, "")
VERSION_NUMBER :: #config(VERSION_NUMBER, "")

// about_view draws About in place of the default one. A build may set it in
// an @(init) proc; nil gives the default: the logo and the version line.
about_view: proc(app: ^App)

STEP_BUTTON :: 38 // side of the two buttons of the size stepper
STEP_VALUE_W :: 92 // width of the value between them

// scale_step returns the size setting one step from pct: larger for dir 1, smaller
// for dir -1. The steps are Automatic (0), then SCALE_MIN to SCALE_MAX in steps of
// SCALE_STEP. ok is false at the two ends.
scale_step :: proc(pct, dir: int) -> (next: int, ok: bool) {
	switch {
	case dir > 0 && pct == 0:
		return SCALE_MIN, true
	case dir > 0 && pct < SCALE_MAX:
		return pct + SCALE_STEP, true
	case dir < 0 && pct > SCALE_MIN:
		return pct - SCALE_STEP, true
	case dir < 0 && pct == SCALE_MIN:
		return 0, true
	}
	return pct, false
}

// scale_label is the text of a size setting.
scale_label :: proc(pct: int) -> string {
	return pct == 0 ? "Automatic" : tprint("%d%%", pct)
}

// set_scale applies a new size setting at once and stores it.
set_scale :: proc(app: ^App, pct: int) {
	if app.settings.scale == pct {
		return
	}
	app.settings.scale = pct
	_ = settings_save(app.settings_file, app.settings)
	app.rescale = true
}

// scale_stepped applies a step of the size stepper. A new scale moves the button
// in the window. After a click with the mouse the pointer follows the button, so
// the next click steps again.
scale_stepped :: proc(app: ^App, pct, dir: int, r: mu.Rect) {
	m := app.u.ctx.mouse_pos
	if m.x >= r.x && m.x < r.x + r.w && m.y >= r.y && m.y < r.y + r.h {
		app.scale_follow = dir
	}
	set_scale(app, pct)
}

// pointer_to moves the mouse pointer to the centre of r (logical units).
pointer_to :: proc(app: ^App, r: mu.Rect) {
	k := 1 / app.u.input_k
	app.pointer_target = {(f32(r.x) + f32(r.w) / 2) * k, (f32(r.y) + f32(r.h) / 2) * k}
	if !app.headless {
		sdl.WarpMouseInWindow(app.window, app.pointer_target.x, app.pointer_target.y)
	}
}

view_settings :: proc(app: ^App) {
	u := &app.u
	w, h := u.size.x, u.size.y
	res := topbar(app, {back = true, title = "Settings"})
	if res.back {
		pop_view(app)
		return
	}

	scroll_begin(app, "settings", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H})
	gap(app, 14)
	gr := row(app, 0)
	y0 := app.cy
	g := ui.group_begin(u, {gr.x, y0, gr.w, 0})
	gap(app, 1 + GROUP_PAD_Y)
	// Size: the label, then smaller, the value and larger at the right.
	rr := inner(app, STEP_BUTTON)
	text_y := rr.y + i32(math.round((STEP_BUTTON - ui.line_height(ui.ST_BODY)) / 2))
	ui.text(u, ui.ST_BODY, rr.x, text_y, "Display Size", ui.TEXT)
	larger := mu.Rect{rr.x + rr.w - STEP_BUTTON, rr.y, STEP_BUTTON, STEP_BUTTON}
	smaller := mu.Rect{larger.x - STEP_VALUE_W - STEP_BUTTON, rr.y, STEP_BUTTON, STEP_BUTTON}
	app.scale_btn = {smaller, larger}
	if app.scale_follow != 0 && !app.rescale {
		// The window has its new scale: the pointer goes to the button that was clicked.
		pointer_to(app, app.scale_follow < 0 ? smaller : larger)
		app.scale_follow = 0
	}
	label := scale_label(app.settings.scale)
	label_x := smaller.x + STEP_BUTTON + i32(math.round((STEP_VALUE_W - ui.text_w(u, ui.ST_BODY, label)) / 2))
	ui.text(u, ui.ST_BODY, label_x, text_y, label, ui.TEXT_STRONG)
	if down, ok := scale_step(app.settings.scale, -1); ui.box_button(u, smaller, .Minus, "smaller", 12, ok) {
		scale_stepped(app, down, -1, smaller)
	}
	if up, ok := scale_step(app.settings.scale, 1); ui.box_button(u, larger, .Plus, "larger", 12, ok) {
		scale_stepped(app, up, 1, larger)
	}
	gap(app, 10)
	rr = inner(app, 16)
	gap(app, GROUP_PAD_Y + 1)
	ui.group_end(u, g, app.cy - y0)
	gap(app, 20)
	about(app)
	gap(app, 20)
	scroll_end(app)
}

// about draws About with no box, centred: the logo, and the version and the
// build date under it.
about :: proc(app: ^App) {
	if about_view != nil {
		about_view(app)
		return
	}
	u := &app.u
	w := u.size.x
	gap(app, 16)
	lw := f32(ui.ABOUT_LOGO_W)
	lh := math.round(lw * f32(app.logo.h) / f32(app.logo.w))
	r := row(app, i32(lh), 0)
	ui.emit(u, {kind = .Mask, r = {math.round((f32(w) - lw) / 2), f32(r.y), lw, lh}, c1 = ui.TEXT_STRONG, ptr = &app.logo}, 0)
	gap(app, 12)
	r = row(app, 17, 0)
	centered(u, ui.ST_BODY, about_version_line(), r.y, w, ui.MUTED)
}

// about_version_line is "version X.Y.Z, YYYY-MM-DD".
about_version_line :: proc() -> string {
	return tprint("version %s, %s", VERSION_NUMBER if VERSION_NUMBER != "" else "unknown", BUILD_DATE if BUILD_DATE != "" else "unknown date")
}
