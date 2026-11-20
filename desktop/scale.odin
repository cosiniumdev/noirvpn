// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Display scale. Three numbers matter:
//   d  pixel density: device pixels per window coordinate (1 on Windows and X11,
//      2 on a Retina Mac, the compositor scale on Wayland)
//   S  display scale of the window: device pixels per logical unit that the
//      system settings ask for (it includes d)
//   E  effective scale: device pixels per logical unit that the UI draws with
// With the automatic setting E is S. With a percentage p it is d * p / 100.
// Mouse positions arrive in window coordinates and are multiplied by d / E.

import "core:math"
import sdl "vendor:sdl3"
import "ui"

// effective_scale is E for a setting (0 is automatic), the density d and the display scale s.
effective_scale :: proc(pct: int, d, s: f32) -> f32 {
	if pct == 0 {
		return s
	}
	return d * f32(pct) / 100
}

// window_scales reads d and S of the window.
window_scales :: proc(window: ^sdl.Window) -> (d, s: f32) {
	d = sdl.GetWindowPixelDensity(window)
	s = sdl.GetWindowDisplayScale(window)
	if d <= 0 {
		d = 1
	}
	if s <= 0 {
		s = d
	}
	return
}

// scale_sync recomputes E. If E changed, it clears the glyph atlas and resizes the
// window to its full logical size (win_width by WIN_H), so a window that the display
// limited at a larger scale grows back. A window on another display (refit) gets
// its full size too. The resulting resize keeps E, so no loop.
scale_sync :: proc(app: ^App) {
	app.rescale = false
	refit := app.refit
	app.refit = false
	if app.window == nil {
		return
	}
	if app.fixed_scale {
		return
	}
	d, s := window_scales(app.window)
	e := effective_scale(app.settings.scale, d, s)
	app.u.input_k = d / e
	if abs(e - app.eff) >= 0.001 {
		app.eff = e
		ui.gfx_set_scale(&app.u.g, e)
	} else if !refit {
		return
	}
	resize_window(app, win_width(app), WIN_H, d, e)
}

// view_width is the logical width of the window for view v. The list and the
// connection are narrow; the views that edit settings are wide.
view_width :: proc(v: View) -> i32 {
	#partial switch v {
	case .List, .Connection, .Attach:
		return WIN_W
	}
	return WIN_W_WIDE
}

// win_width is the logical width that the window has now.
win_width :: proc(app: ^App) -> i32 {
	return app.win_w if app.win_w > 0 else WIN_W
}

// view_fit gives the window the width of the current view. The wide window
// keeps the centre of the narrow one, and the narrow one goes back by the same
// shift, so it returns to its place when the wide one was not moved.
view_fit :: proc(app: ^App) {
	lw := view_width(current_view(app))
	if lw == win_width(app) {
		return
	}
	app.win_w = lw
	win := app.window
	if win == nil {
		return
	}
	if app.fixed_scale {
		// --screens: the window has the pixels of the logical size at the draw scale.
		k := app.u.g.scale
		_ = sdl.SetWindowSize(win, i32(math.round(f32(lw) * k)), i32(math.round(f32(WIN_H) * k)))
		return
	}
	if sdl.GetWindowFlags(win) & {.MAXIMIZED, .FULLSCREEN} != {} {
		return
	}
	d, _ := window_scales(win)
	x, y, old_w, new_w, h: i32
	placed := position_kept() && sdl.GetWindowPosition(win, &x, &y) && sdl.GetWindowSize(win, &old_w, &h)
	if placed {
		if lw == WIN_W {
			_ = sdl.SetWindowPosition(win, x + app.wide_shift, y)
		} else {
			k := app.eff / d
			new_w = i32(math.round(f32(lw) * k))
			_ = sdl.SetWindowPosition(win, x - (new_w - old_w) / 2, y)
		}
	}
	resize_window(app, lw, WIN_H, d, app.eff)
	if !placed {
		app.wide_shift = 0
		return
	}
	nx, ny: i32
	if lw == WIN_W {
		app.wide_shift = 0
	} else if sdl.GetWindowPosition(win, &nx, &ny) {
		app.wide_shift = x - nx
	}
}

// resize_window gives the window a logical size of lw by lh at scale e, limited
// to the usable area of its display, and keeps the window on that display.
resize_window :: proc(app: ^App, lw, lh: i32, d, e: f32) {
	win := app.window
	k := e / d
	w, h := i32(math.round(f32(lw) * k)), i32(math.round(f32(lh) * k))
	area: sdl.Rect
	limited := !app.unclamped && sdl.GetDisplayUsableBounds(sdl.GetDisplayForWindow(win), &area)
	if limited {
		top, left, bottom, right: i32
		_ = sdl.GetWindowBordersSize(win, &top, &left, &bottom, &right)
		max_w, max_h := max(area.w - left - right, 1), max(area.h - top - bottom, 1)
		w, h = min(w, max_w), min(h, max_h)
	}
	if sdl.GetWindowFlags(win) & {.MAXIMIZED, .FULLSCREEN} != {} {
		return
	}
	if cw, ch: i32; !sdl.GetWindowSize(win, &cw, &ch) || cw != w || ch != h {
		_ = sdl.SetWindowSize(win, w, h)
		_ = sdl.SyncWindow(win)
	}
	if limited {
		x, y: i32
		if sdl.GetWindowPosition(win, &x, &y) {
			top, left, bottom, right: i32
			_ = sdl.GetWindowBordersSize(win, &top, &left, &bottom, &right)
			nx := clamp(x, area.x + left, max(area.x + area.w - right - w, area.x + left))
			ny := clamp(y, area.y + top, max(area.y + area.h - bottom - h, area.y + top))
			if nx != x || ny != y {
				_ = sdl.SetWindowPosition(win, nx, ny)
			}
		}
	}
}
