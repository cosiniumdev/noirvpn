// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// System tray icon and the window show/hide that go with it. The tray holds the
// app while the window is hidden. Menu actions run in SDL's event pump on the
// main thread: they change app state at once and push a user event to wake
// the loop and redraw.

import "base:runtime"
import "core:math"
import "core:strings"
import sdl "vendor:sdl3"
import "ui"

TRAY_ICON_SIZE :: 64
TRAY_ICON_MARGIN :: 6

TRAY_SHOW :: "Show noirvpn"
TRAY_DISCONNECT :: "Disconnect"
TRAY_QUIT :: "Quit"
TRAY_IDLE :: "Not connected"

Tray_Kind :: enum u8 {
	Unset,
	Idle,
	Connecting,
	Sign_In,
	Up,
}

// Tray_State is what the tooltip and the menu show.
Tray_State :: struct {
	kind:    Tray_Kind,
	profile: int,
}

tray_state :: proc(app: ^App) -> Tray_State {
	if !conn_active(app) {
		return {.Idle, 0}
	}
	kind := Tray_Kind.Connecting
	#partial switch app.conn.phase {
	case .Credentials, .Web_Sign_In:
		kind = .Sign_In
	case .Up:
		kind = .Up
	}
	return {kind, app.conn.profile}
}

// tray_texts is the tooltip and the status line for a state.
tray_texts :: proc(app: ^App, s: Tray_State) -> (tip, status: string) {
	if s.kind == .Idle || s.kind == .Unset {
		return "noirvpn", TRAY_IDLE
	}
	name := app.profiles[s.profile].name
	what := "connecting"
	#partial switch s.kind {
	case .Sign_In:
		what = "sign in needed"
	case .Up:
		what = "connected"
	}
	return tprint("noirvpn: %s %s", name, what), tprint("%s: %s", name, what)
}

// tray_icon creates the tray icon from the first letter of the logo mask: light
// on transparent, TRAY_ICON_SIZE square.
tray_icon :: proc(m: ^ui.Mask) -> ^sdl.Surface {
	// The letter ends at the first empty column.
	cw: i32
	for ; cw < m.w; cw += 1 {
		col_max: u8
		for y in 0 ..< m.h {
			col_max = max(col_max, m.px[y * m.w + cw])
		}
		if cw > 0 && col_max < 16 {
			break
		}
	}
	size := i32(TRAY_ICON_SIZE)
	surf := sdl.CreateSurface(size, size, .RGBA32)
	if surf == nil {
		return nil
	}
	box := f32(size - 2 * TRAY_ICON_MARGIN)
	scale := box / f32(max(cw, m.h))
	ow, oh := i32(math.round(f32(cw) * scale)), i32(math.round(f32(m.h) * scale))
	x0, y0 := (size - ow) / 2, (size - oh) / 2
	px := ([^]u8)(surf.pixels)
	for i in 0 ..< int(size * surf.pitch) {
		px[i] = 0
	}
	for oy in 0 ..< oh {
		sy0, sy1 := f32(oy) / scale, f32(oy + 1) / scale
		for ox in 0 ..< ow {
			sx0, sx1 := f32(ox) / scale, f32(ox + 1) / scale
			sum, area: f32
			for sy := i32(sy0); sy < min(i32(math.ceil(sy1)), m.h); sy += 1 {
				wy := min(f32(sy + 1), sy1) - max(f32(sy), sy0)
				for sx := i32(sx0); sx < min(i32(math.ceil(sx1)), cw); sx += 1 {
					wx := min(f32(sx + 1), sx1) - max(f32(sx), sx0)
					sum += f32(m.px[sy * m.w + sx]) * wx * wy
					area += wx * wy
				}
			}
			p := int((y0 + oy) * surf.pitch + (x0 + ox) * 4)
			px[p], px[p + 1], px[p + 2] = 245, 248, 250
			px[p + 3] = u8(sum / max(area, 0.0001) + 0.5)
		}
	}
	return surf
}

// tray_create creates the tray icon and its menu. It returns false when the system
// has no tray; has_tray then stays false.
tray_create :: proc(app: ^App) -> bool {
	icon := tray_icon(&app.logo)
	defer if icon != nil {
		sdl.DestroySurface(icon)
	}
	tray := sdl.CreateTray(icon, "noirvpn")
	if tray == nil {
		return false
	}
	menu := sdl.CreateTrayMenu(tray)
	if menu == nil {
		sdl.DestroyTray(tray)
		return false
	}
	add :: proc(menu: ^sdl.TrayMenu, label: cstring, flags: sdl.TrayEntryFlags, cb: sdl.TrayCallback, app: ^App) -> ^sdl.TrayEntry {
		e := sdl.InsertTrayEntryAt(menu, -1, label, flags)
		if e != nil && cb != nil {
			sdl.SetTrayEntryCallback(e, cb, app)
		}
		return e
	}
	app.tray = tray
	app.tray_show = add(menu, TRAY_SHOW, sdl.TRAYENTRY_BUTTON, tray_show_cb, app)
	// The status line shows the window while a sign-in waits.
	app.tray_status = add(menu, TRAY_IDLE, sdl.TRAYENTRY_BUTTON | sdl.TRAYENTRY_DISABLED, tray_show_cb, app)
	app.tray_disconnect = add(menu, TRAY_DISCONNECT, sdl.TRAYENTRY_BUTTON | sdl.TRAYENTRY_DISABLED, tray_disconnect_cb, app)
	_ = add(menu, nil, {}, nil, app)
	app.tray_quit = add(menu, TRAY_QUIT, sdl.TRAYENTRY_BUTTON, tray_quit_cb, app)
	app.has_tray = true
	return true
}

tray_destroy :: proc(app: ^App) {
	if app.tray != nil {
		sdl.DestroyTray(app.tray)
		app.tray = nil
	}
}

// tray_sync updates the tooltip and the menu when the state changed.
tray_sync :: proc(app: ^App) {
	if app.tray == nil {
		return
	}
	s := tray_state(app)
	if s == app.tray_shown {
		return
	}
	app.tray_shown = s
	tip, status := tray_texts(app, s)
	sdl.SetTrayTooltip(app.tray, strings.clone_to_cstring(tip, context.temp_allocator))
	sdl.SetTrayEntryLabel(app.tray_status, strings.clone_to_cstring(status, context.temp_allocator))
	sdl.SetTrayEntryEnabled(app.tray_disconnect, s.kind != .Idle)
	sdl.SetTrayEntryEnabled(app.tray_status, s.kind == .Sign_In)
}

// ---- Menu actions ----

tray_wake :: proc() {
	ev: sdl.Event
	ev.type = .USER
	_ = sdl.PushEvent(&ev)
}

tray_show_cb :: proc "c" (userdata: rawptr, entry: ^sdl.TrayEntry) {
	context = runtime.default_context()
	show_window((^App)(userdata))
	tray_wake()
}

tray_disconnect_cb :: proc "c" (userdata: rawptr, entry: ^sdl.TrayEntry) {
	context = runtime.default_context()
	disconnect((^App)(userdata))
	tray_wake()
}

tray_quit_cb :: proc "c" (userdata: rawptr, entry: ^sdl.TrayEntry) {
	context = runtime.default_context()
	tray_quit((^App)(userdata))
	tray_wake()
}

// tray_quit is the Quit entry. It quits at once, or shows the window and asks
// first while a connection is active. The prompt has no Hide button.
tray_quit :: proc(app: ^App) {
	if !conn_active(app) || (app.quit_prompt && !app.prompt_hide) {
		quit_now(app)
		return
	}
	show_window(app)
	app.quit_prompt = true
	app.quit_fresh = true
	app.prompt_hide = false
}

// disconnect is the Disconnect entry. A quit prompt has no reason to stay open.
disconnect :: proc(app: ^App) {
	if app.quit_prompt && !app.prompt_hide {
		app.quit_prompt = false
	}
	link_disconnect(app)
}

// ---- Window ----

// show_window shows the window again and brings it to the front.
show_window :: proc(app: ^App) {
	app.hidden = false
	if .MINIMIZED in sdl.GetWindowFlags(app.window) {
		_ = sdl.RestoreWindow(app.window)
	}
	_ = sdl.ShowWindow(app.window)
	_ = sdl.RaiseWindow(app.window)
}

// hide_window hides the window. The app keeps running, with no timed redraws.
hide_window :: proc(app: ^App) {
	app.hidden = true
	_ = sdl.HideWindow(app.window)
}
