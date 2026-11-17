// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !darwin
package main

// The CPU renderer on Windows and X11: the window surface of SDL (a GDI bitmap, or
// an X11 image). With SDL_FRAMEBUFFER_ACCELERATION at 0 SDL keeps to that surface
// and creates no renderer. Where SDL has no window surface (Wayland), the start
// fails and the caller uses the GPU renderer.

import sdl "vendor:sdl3"
import "ui"

Presenter :: struct {
	window: ^sdl.Window,
}

// presenter_open asks SDL for the window surface once, to see that it exists and has a
// format the rasterizer writes. It returns the reason when it does not.
presenter_open :: proc(p: ^Presenter, window: ^sdl.Window) -> string {
	p.window = window
	_ = sdl.SetHint(sdl.HINT_FRAMEBUFFER_ACCELERATION, "0")
	s := sdl.GetWindowSurface(window)
	if s == nil {
		return string(sdl.GetError())
	}
	if !surface_ok(s) {
		// SDL creates no renderer for a window that has a surface, so the surface goes
		// before the caller starts the GPU renderer.
		_ = sdl.DestroyWindowSurface(window)
		return "the window surface has a pixel format that the rasterizer does not write"
	}
	return ""
}

presenter_close :: proc(p: ^Presenter) {
}

@(private = "file")
surface_ok :: proc(s: ^sdl.Surface) -> bool {
	return s.pixels != nil && (s.format == .XRGB8888 || s.format == .ARGB8888)
}

// presenter_acquire returns the pixels of the window surface. SDL creates a new
// surface after the window changed its size. It is the frame source of Gfx.
presenter_acquire :: proc(data: rawptr, w, h: i32) -> (ui.Raster_Target, bool) {
	p := (^Presenter)(data)
	s := sdl.GetWindowSurface(p.window)
	if s == nil || !surface_ok(s) {
		return {}, false
	}
	return {pixels = ([^]u32)(s.pixels), stride = int(s.pitch / 4), w = int(s.w), h = int(s.h)}, true
}

// presenter_show copies the surface to the window.
presenter_show :: proc(p: ^Presenter) {
	_ = sdl.UpdateWindowSurface(p.window)
}
