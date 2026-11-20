// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The frameless window: creation, dragging by the top bar, saved position.
//
// The top bar moves the window. SDL asks a hit-test callback what lies under a
// point; it returns "draggable" except over a control. build records control
// rectangles, hit_publish copies them to hit_shared for the callback.
//
// SDL3 says only that the callback "may fire at any time". In the Windows,
// X11, Wayland and macOS backends it runs on the main thread during event
// pumping, and on Windows also in the OS move loop (no frame built there).
// hit_shared is a plain copy with a sequence counter, so any thread is safe.

import "base:intrinsics"
import "core:math"
import mu "vendor:microui"
import sdl "vendor:sdl3"
import "ui"

BAR_RECTS_MAX :: 8

WINDOW_FLAGS :: sdl.WindowFlags{.BORDERLESS, .HIGH_PIXEL_DENSITY}

POS_SAVE_DELAY :: 0.5 // seconds without a move before the position is stored
POS_START_GRACE :: 1.5 // moves before this time are the window manager placing the window

// Hit_Snapshot is what the hit-test callback needs.
Hit_Snapshot :: struct {
	k:     f32, // window coordinates to logical units: d / E
	w:     i32, // logical width of the window
	drag:  bool, // the top bar drags the window
	n:     int,
	rects: [BAR_RECTS_MAX]mu.Rect,
}

Hit_Shared :: struct {
	seq:  u32, // odd while the snapshot is written
	snap: Hit_Snapshot,
}

hit_shared: Hit_Shared

// hit_publish copies the top bar controls of the frame that was just built.
hit_publish :: proc(app: ^App) {
	snap := Hit_Snapshot {
		k    = app.u.input_k,
		w    = app.u.size.x,
		drag = !app.u.popup_open && !app.quit_prompt,
		n    = app.n_bar_rects,
	}
	copy(snap.rects[:], app.bar_rects[:app.n_bar_rects])
	intrinsics.atomic_add_explicit(&hit_shared.seq, 1, .Release)
	hit_shared.snap = snap
	intrinsics.atomic_add_explicit(&hit_shared.seq, 1, .Release)
}

// hit_read returns a consistent copy of the snapshot, or false when the writer is busy.
hit_read :: proc "contextless" (s: ^Hit_Shared) -> (snap: Hit_Snapshot, ok: bool) {
	for _ in 0 ..< 4 {
		before := intrinsics.atomic_load_explicit(&s.seq, .Acquire)
		if before & 1 != 0 {
			continue
		}
		snap = s.snap
		if intrinsics.atomic_load_explicit(&s.seq, .Acquire) == before {
			return snap, true
		}
	}
	return {}, false
}

// hit_classify says what lies at the window coordinates x, y.
hit_classify :: proc "contextless" (s: Hit_Snapshot, x, y: i32) -> sdl.HitTestResult {
	if !s.drag {
		return .NORMAL
	}
	lx, ly := i32(math.floor(f32(x) * s.k)), i32(math.floor(f32(y) * s.k))
	if lx < 0 || lx >= s.w || ly < 0 || ly >= ui.TOPBAR_H {
		return .NORMAL
	}
	for i in 0 ..< s.n {
		r := s.rects[i]
		if lx >= r.x && lx < r.x + r.w && ly >= r.y && ly < r.y + r.h {
			return .NORMAL
		}
	}
	return .DRAGGABLE
}

hit_test :: proc "c" (win: ^sdl.Window, area: ^sdl.Point, data: rawptr) -> sdl.HitTestResult {
	snap, ok := hit_read(&hit_shared)
	if !ok {
		return .NORMAL
	}
	return hit_classify(snap, area.x, area.y)
}

// create_window creates the fixed-size frameless window. pos is the saved position.
create_window :: proc(pos: Maybe([2]i32), hidden := false) -> ^sdl.Window {
	props := sdl.CreateProperties()
	defer sdl.DestroyProperties(props)
	_ = sdl.SetStringProperty(props, sdl.PROP_WINDOW_CREATE_TITLE_STRING, "noirvpn")
	_ = sdl.SetNumberProperty(props, sdl.PROP_WINDOW_CREATE_WIDTH_NUMBER, WIN_W)
	_ = sdl.SetNumberProperty(props, sdl.PROP_WINDOW_CREATE_HEIGHT_NUMBER, WIN_H)
	_ = sdl.SetBooleanProperty(props, sdl.PROP_WINDOW_CREATE_BORDERLESS_BOOLEAN, true)
	_ = sdl.SetBooleanProperty(props, sdl.PROP_WINDOW_CREATE_HIGH_PIXEL_DENSITY_BOOLEAN, true)
	_ = sdl.SetBooleanProperty(props, sdl.PROP_WINDOW_CREATE_HIDDEN_BOOLEAN, hidden)
	if hidden {
		// The offscreen driver of SDL 3.4 on macOS asks for OpenGL by default,
		// and it has none; the software renderer needs no graphics context.
		_ = sdl.SetBooleanProperty(props, sdl.PROP_WINDOW_CREATE_EXTERNAL_GRAPHICS_CONTEXT_BOOLEAN, true)
	}
	if p, ok := pos.?; ok {
		_ = sdl.SetNumberProperty(props, sdl.PROP_WINDOW_CREATE_X_NUMBER, i64(p.x))
		_ = sdl.SetNumberProperty(props, sdl.PROP_WINDOW_CREATE_Y_NUMBER, i64(p.y))
	}
	return sdl.CreateWindowWithProperties(props)
}

// ---- Saved position ----

// usable_areas lists the usable bounds of the connected displays.
usable_areas :: proc(allocator := context.temp_allocator) -> []sdl.Rect {
	count: i32
	ids := sdl.GetDisplays(&count)
	if ids == nil {
		return nil
	}
	defer sdl.free(ids)
	out := make([dynamic]sdl.Rect, 0, count, allocator)
	for id in ids[:count] {
		r: sdl.Rect
		if sdl.GetDisplayUsableBounds(id, &r) {
			append(&out, r)
		}
	}
	return out[:]
}

// on_display is true when the point lies in one of the areas.
on_display :: proc(p: [2]i32, areas: []sdl.Rect) -> bool {
	for a in areas {
		if p.x >= a.x && p.x < a.x + a.w && p.y >= a.y && p.y < a.y + a.h {
			return true
		}
	}
	return false
}

// position_kept is false where the window manager decides the position.
position_kept :: proc() -> bool {
	return sdl.GetCurrentVideoDriver() != "wayland"
}

// saved_position is the stored position when it can be used, else nothing.
saved_position :: proc(s: Settings) -> Maybe([2]i32) {
	p, ok := s.pos.?
	if ok && position_kept() && on_display(p, usable_areas()) {
		return p
	}
	return nil
}

// pos_moved notes a window move. The position is stored when the moves stop.
pos_moved :: proc(app: ^App) {
	now := now_seconds()
	if app.headless || !position_kept() || now < POS_START_GRACE {
		return
	}
	app.moved = true
	app.pos_save_at = now + POS_SAVE_DELAY
}

// pos_store writes the window position if the window was moved.
pos_store :: proc(app: ^App) {
	app.pos_save_at = 0
	if !app.moved || app.settings_file == "" || .MINIMIZED in sdl.GetWindowFlags(app.window) {
		return
	}
	x, y: i32
	if !sdl.GetWindowPosition(app.window, &x, &y) {
		return
	}
	// The stored place is the place of the narrow window.
	x += app.wide_shift
	if !on_display({x, y}, usable_areas()) {
		return
	}
	if old, ok := app.settings.pos.?; ok && old == {x, y} {
		return
	}
	app.settings.pos = [2]i32{x, y}
	_ = settings_save_pos(app.settings_file, x, y)
}
