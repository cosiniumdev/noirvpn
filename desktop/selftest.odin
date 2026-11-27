// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// selftest drives the UI with synthetic SDL events in a hidden window and
// checks the result: navigation, popup menu, text field editing.

import "core:fmt"
import "core:math"
import "core:os"
import "core:strings"
import mu "vendor:microui"
import sdl "vendor:sdl3"
import "ui"

push :: proc(app: ^App, ev: sdl.Event) {
	e := ev
	if handle_app_event(app, &e) {
		app.now += 0.016
		frame(app, 0.016)
	}
}

mouse :: proc(app: ^App, x, y: f32) {
	ev: sdl.Event
	ev.motion = {type = .MOUSE_MOTION, x = x, y = y}
	push(app, ev)
}

click :: proc(app: ^App, x, y: f32) {
	mouse(app, x, y)
	ev: sdl.Event
	ev.button = {type = .MOUSE_BUTTON_DOWN, button = sdl.BUTTON_LEFT, down = true, clicks = 1, x = x, y = y}
	push(app, ev)
	ev.button = {type = .MOUSE_BUTTON_UP, button = sdl.BUTTON_LEFT, down = false, clicks = 1, x = x, y = y}
	push(app, ev)
}

typ :: proc(app: ^App, s: cstring) {
	ev: sdl.Event
	ev.text = {type = .TEXT_INPUT, text = s}
	push(app, ev)
}

key :: proc(app: ^App, k: sdl.Keycode, mod: sdl.Keymod = {}) {
	ev: sdl.Event
	ev.key = {type = .KEY_DOWN, key = k, mod = mod, down = true}
	push(app, ev)
	ev.key.type = .KEY_UP
	ev.key.down = false
	push(app, ev)
}

selftest :: proc() -> int {
	_ = sdl.SetHint(sdl.HINT_VIDEO_DRIVER, "offscreen")
	_ = sdl.Init({.VIDEO})
	app := new(App)
	app.headless = true
	app.window = create_window(nil, true)
	app.renderer = sdl.CreateRenderer(app.window, sdl.SOFTWARE_RENDERER)
	app.unclamped = true
	app.frame_border = true
	d, base := window_scales(app.window)
	_ = app_setup(app, base)
	app.u.g.always = true // the tests read pixels back: draw every frame
	app.eff = base
	app.u.input_k = d / base
	frame(app, 0)
	failed := 0
	check :: proc(name: string, ok: bool, failed: ^int) {
		fmt.println(ok ? "PASS" : "FAIL", name)
		if !ok {
			failed^ += 1
		}
	}
	click(app, 100, 90)
	check("row click opens connection", current_view(app) == .Connection, &failed)
	click(app, 28, 28)
	check("back returns to list", current_view(app) == .List, &failed)
	click(app, 372, 88)
	check("row menu opens", ui.menu_is_open(&app.u, MENU_ROW), &failed)
	click(app, 320, 128)
	check("Edit opens profile", current_view(app) == .Profile, &failed)
	check("name loaded", ui.field_text(&app.edit.name) == "Home", &failed)
	click(app, 200, 110 + NAV_H)
	key(app, sdl.K_END)
	typ(app, "xyz")
	check("typing appends", ui.field_text(&app.edit.name) == "Homexyz", &failed)
	key(app, sdl.K_BACKSPACE)
	check("backspace", ui.field_text(&app.edit.name) == "Homexy", &failed)
	ev: sdl.Event
	ev.key = {type = .KEY_DOWN, key = sdl.K_LCTRL, down = true}
	push(app, ev)
	key(app, sdl.K_A)
	ev.key.type = .KEY_UP
	ev.key.down = false
	push(app, ev)
	typ(app, "Q")
	check("select all + type replaces", ui.field_text(&app.edit.name) == "Q", &failed)
	key(app, sdl.K_ESCAPE)
	check("escape leaves profile", current_view(app) == .List, &failed)
	selftest_create(app, &failed, check)
	selftest_scale(app, &failed, check)
	selftest_background(app, &failed, check)
	selftest_atlas(app, &failed, check)
	selftest_skip(app, &failed, check)
	selftest_raster(&failed, check)
	selftest_cpu_target(&failed, check)
	selftest_cpu_views(app, &failed, check)
	selftest_renderer(&failed, check)
	selftest_frame(app, &failed, check)
	selftest_connection(app, &failed, check)
	selftest_quit(app, &failed, check)
	selftest_close(app, true, &failed, check)
	selftest_close(app, false, &failed, check)
	selftest_tray(app, &failed, check)
	selftest_matrix(&failed, check)
	selftest_settings_file(&failed, check)
	selftest_position(&failed, check)
	selftest_rules(app, &failed, check)
	when BUS_LINK {
		selftest_link(app, &failed, check)
		selftest_service(app, &failed, check)
		selftest_web(app, &failed, check)
		selftest_rules_link(app, &failed, check)
		when KEYGEN {
			selftest_create_service(app, &failed, check)
		}
	}
	return failed == 0 ? 0 : 1
}

// selftest_scale checks the settings view and the display scale. Mouse events
// are in window coordinates, so at scale E a logical point is multiplied by E / d.
selftest_scale :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	d, s := window_scales(app.window)
	size_is :: proc(app: ^App, w, h: i32) -> bool {
		return app.u.size == {w, h}
	}
	click(app, 292, 28)
	check("gear opens settings", current_view(app) == .Settings, failed)
	check("scale starts automatic", app.settings.scale == 0 && app.eff == s && size_is(app, WIN_W_WIDE, WIN_H), failed)
	// step clicks a button of the size stepper at its place in the window: -1 is smaller, 1 is larger.
	step :: proc(app: ^App, d: f32, dir: int) {
		r := app.scale_btn[dir < 0 ? 0 : 1]
		k := app.eff / d
		click(app, (f32(r.x) + f32(r.w) / 2) * k, (f32(r.y) + f32(r.h) / 2) * k)
	}
	step(app, d, -1)
	check("smaller does nothing at Automatic", app.settings.scale == 0 && app.eff == s, failed)
	step(app, d, 1)
	check("larger steps from Automatic to 100%", app.settings.scale == 100 && app.eff == d, failed)
	for _ in 0 ..< 4 {
		step(app, d, 1)
	}
	check("200% sets 2 x density", app.settings.scale == 200 && app.eff == 2 * d, failed)
	larger := app.scale_btn[1]
	check("the pointer follows the button to its place at the new scale", app.scale_follow == 0 && app.pointer_target == {(f32(larger.x) + f32(larger.w) / 2) * 2, (f32(larger.y) + f32(larger.h) / 2) * 2}, failed)
	ww, wh: i32
	_ = sdl.GetWindowSize(app.window, &ww, &wh)
	check("window grows, logical size stays", size_is(app, WIN_W_WIDE, WIN_H) && f32(ww) == WIN_W_WIDE * 2 && f32(wh) == WIN_H * 2, failed)
	e := app.eff
	k := e / d
	click(app, 28 * k, 28 * k)
	check("back at scale 2", current_view(app) == .List, failed)
	click(app, 100 * k, 150 * k)
	check("row click at scale 2 hits row 2", current_view(app) == .Connection && app.shown == 1, failed)
	click(app, 28 * k, 28 * k)
	click(app, 292 * k, 28 * k)
	check("gear at scale 2", current_view(app) == .Settings, failed)
	for _ in 0 ..< 5 {
		step(app, d, -1)
	}
	check("Automatic returns to the display scale", app.settings.scale == 0 && app.eff == s && size_is(app, WIN_W_WIDE, WIN_H), failed)
	k = app.eff / d
	click(app, 28 * k, 28 * k)
	check("back to the list", current_view(app) == .List, failed)
	ev: sdl.Event
	ev.window = {type = .WINDOW_DISPLAY_SCALE_CHANGED}
	push(app, ev)
	_ = sdl.GetWindowSize(app.window, &ww, &wh)
	check("scale event without a change keeps the window", app.eff == s && size_is(app, WIN_W, WIN_H) && f32(ww) == WIN_W * s && f32(wh) == WIN_H * s, failed)
	check("effective scale of a percentage", effective_scale(150, 2, 3) == 3 && effective_scale(0, 2, 3) == 3 && effective_scale(200, 1, 1.5) == 2, failed)
	ok := true
	for t in ([?]struct {
			in_: string,
			pct: int,
			ok:  bool,
		}{{"auto", 0, true}, {"Auto", 0, true}, {"100", 100, true}, {" 175% ", 175, true}, {"300", 300, true}, {"125x", 0, false}, {"130", 0, false}, {"75", 0, false}, {"325", 0, false}, {"0", 0, false}, {"", 0, false}}) {
		pct, good := parse_scale(t.in_)
		if pct != t.pct || good != t.ok {
			ok = false
		}
	}
	check("scale text parsing", ok, failed)
	// The stepper walks every valid size and stops at the two ends.
	steps, walk := 0, 0
	for {
		next, more := scale_step(walk, 1)
		if !more {
			break
		}
		ok = ok && scale_valid(next) && next > walk
		back, _ := scale_step(next, -1)
		ok = ok && back == walk
		walk = next
		steps += 1
	}
	_, below := scale_step(0, -1)
	check("stepper: Automatic, then 100% to 300% in steps of 25", ok && !below && walk == SCALE_MAX && steps == 1 + (SCALE_MAX - SCALE_MIN) / SCALE_STEP, failed)
	check("stepper: the value text", scale_label(0) == "Automatic" && scale_label(125) == "125%", failed)
	// A display that is too small limits the window at a large scale. The full size
	// comes back at a smaller scale, and on another display.
	shrink :: proc(app: ^App, k: i32) {
		_ = sdl.SetWindowSize(app.window, WIN_W * k, 500 * k)
		_ = sdl.SyncWindow(app.window)
		frame(app, 0)
	}
	set_scale(app, 200)
	frame(app, 0)
	shrink(app, i32(2 * d))
	limited := size_is(app, WIN_W, 500)
	set_scale(app, 100)
	frame(app, 0)
	check("a window that was limited at 200% is full again at 100%", limited && size_is(app, WIN_W, WIN_H), failed)
	shrink(app, i32(d))
	limited = size_is(app, WIN_W, 500)
	ev.window = {type = .WINDOW_DISPLAY_CHANGED}
	push(app, ev)
	check("a limited window on another display gets its full size", limited && size_is(app, WIN_W, WIN_H), failed)
	set_scale(app, 0)
	frame(app, 0)
	// The wide window keeps the centre of the narrow one; the narrow one returns to its place.
	_ = sdl.SetWindowPosition(app.window, 300, 200)
	_ = sdl.SyncWindow(app.window)
	x0, y0, xw, yw, x1, y1, nw, ww2: i32
	_ = sdl.GetWindowPosition(app.window, &x0, &y0)
	_ = sdl.GetWindowSize(app.window, &nw, &wh)
	push_view(app, .Settings)
	frame(app, 0)
	_ = sdl.GetWindowPosition(app.window, &xw, &yw)
	_ = sdl.GetWindowSize(app.window, &ww2, &wh)
	wide := size_is(app, WIN_W_WIDE, WIN_H) && xw == x0 - (ww2 - nw) / 2 && yw == y0
	pop_view(app)
	frame(app, 0)
	_ = sdl.GetWindowPosition(app.window, &x1, &y1)
	check("settings widen the window around its centre", wide, failed)
	check("the narrow window returns to its place", size_is(app, WIN_W, WIN_H) && x1 == x0 && y1 == y0 && app.wide_shift == 0, failed)
}

// near is true when two colours differ by at most tol in every channel.
near :: proc(a: [3]u8, b: ui.Color, tol: int) -> bool {
	return abs(int(a.r) - int(b.r)) <= tol && abs(int(a.g) - int(b.g)) <= tol && abs(int(a.b) - int(b.b)) <= tol
}

// selftest_background checks that the window gradient runs from the top token to
// the bottom token.
selftest_background :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	frame(app, 0)
	present(app)
	surf := sdl.RenderReadPixels(app.renderer, nil)
	if surf == nil {
		check("read back the frame", false, failed)
		return
	}
	defer sdl.DestroySurface(surf)
	px :: proc(surf: ^sdl.Surface, x, y: i32) -> (c: [3]u8) {
		a: u8
		_ = sdl.ReadSurfacePixel(surf, x, y, &c.r, &c.g, &c.b, &a)
		return
	}
	top := px(surf, 380, 2)
	bottom := px(surf, 200, surf.h - 3)
	check("background top colour", near(top, ui.BG_TOP, 2), failed)
	check("background bottom colour", near(bottom, ui.BG_BOTTOM, 2), failed)
}

// frame_pixels draws one frame and returns its pixels (RGBA, rows without gaps).
frame_pixels :: proc(app: ^App) -> []u8 {
	frame(app, 0)
	present(app)
	surf := sdl.RenderReadPixels(app.renderer, nil)
	if surf == nil {
		return nil
	}
	defer sdl.DestroySurface(surf)
	out := make([]u8, int(surf.w * surf.h * 4))
	for y in 0 ..< surf.h {
		for x in 0 ..< surf.w {
			i := int(y * surf.w + x) * 4
			_ = sdl.ReadSurfacePixel(surf, x, y, &out[i], &out[i + 1], &out[i + 2], &out[i + 3])
		}
	}
	return out
}

// selftest_atlas checks that the glyphs of a frame reach the GPU: the atlas keeps a
// CPU copy and uploads the changed area at the next flush (atlas_commit). With an
// empty atlas the first frame needs every glyph; it has to match the second frame,
// which finds them all in the atlas.
selftest_atlas :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	view, depth, state := app.stack[0], app.depth, app.link.state
	defer {
		app.stack[0], app.depth, app.link.state = view, depth, state
	}
	app.stack[0] = .Attach
	app.depth = 0
	app.link.state = .Not_Found
	ui.atlas_reset(&app.u.g)
	first := frame_pixels(app)
	second := frame_pixels(app)
	defer delete(first)
	defer delete(second)
	check("atlas: a frame is read back", len(first) > 0 && len(first) == len(second), failed)
	if len(first) == 0 || len(first) != len(second) {
		return
	}
	bright := 0
	for i := 0; i < len(first); i += 4 {
		if int(first[i]) + int(first[i + 1]) + int(first[i + 2]) > 3 * 200 {
			bright += 1
		}
	}
	check("atlas: the first frame has text and logo pixels", bright > 300, failed)
	same := true
	for i in 0 ..< len(first) {
		if first[i] != second[i] {
			same = false
			break
		}
	}
	check("atlas: the first frame, with every glyph uploaded, equals the second", same, failed)
	check("atlas: nothing waits for an upload after a frame", app.u.g.atlas.dirty.w == 0, failed)
}

// selftest_skip checks that a frame equal to the last one is not drawn or presented,
// and that a frame that differs, or one after a window event, is.
selftest_skip :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	g := &app.u.g
	view, depth, state := app.stack[0], app.depth, app.link.state
	defer {
		g.always = true
		app.stack[0], app.depth, app.link.state = view, depth, state
	}
	app.stack[0] = .Attach
	app.depth = 0
	app.link.state = .Not_Found
	g.always = false
	g.force = true
	frame(app, 0)
	present(app)
	n := g.skipped
	frame(app, 0)
	present(app)
	check("skip: a frame equal to the last one is not drawn", g.skipped == n + 1, failed)
	frame(app, 0)
	present(app)
	check("skip: and the next equal frame too", g.skipped == n + 2, failed)
	app.link.state = .Denied
	frame(app, 0)
	present(app)
	check("skip: a frame that differs is drawn", g.skipped == n + 2, failed)
	frame(app, 0)
	present(app)
	check("skip: the frame after it, equal again, is not", g.skipped == n + 3, failed)
	g.force = true
	frame(app, 0)
	present(app)
	check("skip: a forced frame is drawn", g.skipped == n + 3 && !g.force, failed)
}

// ---- CPU renderer ----

RT_DIM :: 16 // side of the atlas of the rasterizer tests

// raster_atlas is a small atlas: a white block at the origin, like the real one, and a
// glyph-like block of 6 x 5 texels with different alpha values at (4, 4).
raster_atlas :: proc() -> (a: [RT_DIM * RT_DIM]u8) {
	for y in 0 ..< 4 {
		for x in 0 ..< 4 {
			a[y * RT_DIM + x] = 255
		}
	}
	for y in 0 ..< 5 {
		for x in 0 ..< 6 {
			a[(4 + y) * RT_DIM + 4 + x] = u8((x * 41 + y * 67 + 20) % 256)
		}
	}
	return
}

pix :: proc(r, g, b: u8) -> u32 {
	return 0xff000000 | u32(r) << 16 | u32(g) << 8 | u32(b)
}

// blend_u8 is the colour c over bg with alpha a, rounded.
blend_u8 :: proc(bg, c: u8, a: f64) -> u8 {
	return u8(f64(bg) + (f64(c) - f64(bg)) * a + 0.5)
}

// within is true when the pixel differs from (r, g, b) by at most tol in each channel.
within :: proc(p: u32, r, g, b: u8, tol: int) -> bool {
	return abs(int((p >> 16) & 0xff) - int(r)) <= tol && abs(int((p >> 8) & 0xff) - int(g)) <= tol && abs(int(p & 0xff) - int(b)) <= tol
}

// quad_verts is a rectangle as two triangles (0, 1, 2) and (0, 2, 3). uv gives the
// texture coordinates of the corners top left and bottom right.
quad_verts :: proc(x0, y0, x1, y1: f32, top, bottom: sdl.FColor, uv0, uv1: sdl.FPoint) -> [4]sdl.Vertex {
	return {
		{{x0, y0}, top, {uv0.x, uv0.y}},
		{{x1, y0}, top, {uv1.x, uv0.y}},
		{{x1, y1}, bottom, {uv1.x, uv1.y}},
		{{x0, y1}, bottom, {uv0.x, uv1.y}},
	}
}

QUAD_IDX := [6]i32{0, 1, 2, 0, 2, 3}

fcol :: proc(r, g, b: u8, a: f32 = 1) -> sdl.FColor {
	return {f32(r) / 255, f32(g) / 255, f32(b) / 255, a}
}

// raster_run draws one batch of triangles into a w x h buffer that starts as bg.
raster_run :: proc(px: []u32, w, h: int, bg: ui.Color, verts: []sdl.Vertex, idx: []i32, clip: Maybe(sdl.Rect) = nil) {
	atlas := raster_atlas()
	draws := [1]ui.Draw{{clip = clip, v0 = 0, vn = len(verts), i0 = 0, in_ = len(idx)}}
	ui.raster_frame({raw_data(px), w, w, h}, bg, draws[:], verts, idx, atlas[:], RT_DIM)
}

// selftest_raster checks the rasterizer on its own, with hand made triangles.
selftest_raster :: proc(failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	W, H :: 48, 40
	bg := ui.Color{10, 20, 30, 255}
	bgp := pix(10, 20, 30)
	px := make([]u32, W * H)
	defer delete(px)
	white := sdl.FPoint{0.125, 0.125} // inside the white block

	// A solid rectangle covers exactly the pixels whose centres it contains.
	q := quad_verts(4, 3, 20, 13, fcol(200, 100, 50), fcol(200, 100, 50), white, white)
	raster_run(px, W, H, bg, q[:], QUAD_IDX[:])
	exact := true
	for y in 0 ..< H {
		for x in 0 ..< W {
			inside := x >= 4 && x < 20 && y >= 3 && y < 13
			if px[y * W + x] != (inside ? pix(200, 100, 50) : bgp) {
				exact = false
			}
		}
	}
	check("raster: a solid rectangle fills exactly its pixels", exact, failed)

	// Rectangle edges at half pixels: a centre on the edge belongs to the top and left edge.
	q = quad_verts(4.5, 3.5, 20.5, 13.5, fcol(200, 100, 50), fcol(200, 100, 50), white, white)
	raster_run(px, W, H, bg, q[:], QUAD_IDX[:])
	check("raster: top left fill rule", px[3 * W + 4] == pix(200, 100, 50) && px[3 * W + 20] == bgp && px[13 * W + 4] == bgp && px[12 * W + 19] == pix(200, 100, 50), failed)

	// A triangle with a vertical left edge, a horizontal top edge and a diagonal through pixel
	// centres: the left and top centres belong to it, the diagonal centres do not.
	tv := [3]sdl.Vertex{{{4.5, 3.5}, fcol(200, 100, 50), {0.125, 0.125}}, {{20.5, 3.5}, fcol(200, 100, 50), {0.125, 0.125}}, {{4.5, 19.5}, fcol(200, 100, 50), {0.125, 0.125}}}
	tidx := [3]i32{0, 1, 2}
	raster_run(px, W, H, bg, tv[:], tidx[:])
	tri_ok := true
	for y in 0 ..< H {
		for x in 0 ..< W {
			inside := x >= 4 && y >= 3 && (x - 4) + (y - 3) < 16
			if px[y * W + x] != (inside ? pix(200, 100, 50) : bgp) {
				tri_ok = false
			}
		}
	}
	check("raster: a triangle owns its left and top edges, not its diagonal", tri_ok, failed)

	// A translucent rectangle with fractional corners, and one whose diagonal passes
	// through pixel centres, in both diagonal directions: each pixel is blended once.
	seam := true
	third := fcol(200, 100, 50, 0.5)
	want := pix(blend_u8(10, 200, 0.5), blend_u8(20, 100, 0.5), blend_u8(30, 50, 0.5))
	for cfg in 0 ..< 3 {
		x0, y0, x1, y1: f32 = 3.3, 2.7, 40.6, 33.1
		if cfg > 0 {
			x0, y0, x1, y1 = 2, 2, 34, 34
		}
		q = quad_verts(x0, y0, x1, y1, third, third, white, white)
		idx := QUAD_IDX
		if cfg == 2 {
			idx = {0, 1, 3, 1, 2, 3}
		}
		raster_run(px, W, H, bg, q[:], idx[:])
		for y in int(y0) + 2 ..< int(y1) - 2 {
			for x in int(x0) + 2 ..< int(x1) - 2 {
				if px[y * W + x] != want {
					seam = false
				}
			}
		}
	}
	check("raster: a translucent rectangle has no seam on its diagonal", seam, failed)

	// The clip rectangle limits the drawing.
	q = quad_verts(4, 3, 20, 13, fcol(200, 100, 50), fcol(200, 100, 50), white, white)
	raster_run(px, W, H, bg, q[:], QUAD_IDX[:], sdl.Rect{8, 5, 6, 4})
	clipped := true
	for y in 0 ..< H {
		for x in 0 ..< W {
			inside := x >= 8 && x < 14 && y >= 5 && y < 9
			if px[y * W + x] != (inside ? pix(200, 100, 50) : bgp) {
				clipped = false
			}
		}
	}
	check("raster: the clip rectangle limits a rectangle", clipped, failed)

	// A glyph quad (the atlas copied to whole pixels) is the atlas alpha times the colour.
	atlas := raster_atlas()
	uv0 := sdl.FPoint{4.0 / RT_DIM, 4.0 / RT_DIM}
	uv1 := sdl.FPoint{10.0 / RT_DIM, 9.0 / RT_DIM}
	glyph_ok := true
	for alpha in ([2]f32{1, 0.5}) {
		q = quad_verts(10, 6, 16, 11, fcol(230, 220, 40, alpha), fcol(230, 220, 40, alpha), uv0, uv1)
		raster_run(px, W, H, bg, q[:], QUAD_IDX[:])
		for y in 0 ..< 5 {
			for x in 0 ..< 6 {
				a := f64(atlas[(4 + y) * RT_DIM + 4 + x]) / 255 * f64(alpha)
				if !within(px[(6 + y) * W + 10 + x], blend_u8(10, 230, a), blend_u8(20, 220, a), blend_u8(30, 40, a), 1) {
					glyph_ok = false
				}
			}
		}
		if px[5 * W + 10] != bgp || px[6 * W + 16] != bgp || px[11 * W + 10] != bgp {
			glyph_ok = false
		}
	}
	check("raster: a glyph quad is atlas alpha times colour", glyph_ok, failed)

	// The same texels at twice the size are sampled nearest, each into 2 x 2 pixels.
	q = quad_verts(10, 6, 22, 16, fcol(230, 220, 40), fcol(230, 220, 40), uv0, uv1)
	raster_run(px, W, H, bg, q[:], QUAD_IDX[:])
	nearest := true
	for y in 0 ..< 10 {
		for x in 0 ..< 12 {
			a := f64(atlas[(4 + y / 2) * RT_DIM + 4 + x / 2]) / 255
			if !within(px[(6 + y) * W + 10 + x], blend_u8(10, 230, a), blend_u8(20, 220, a), blend_u8(30, 40, a), 1) {
				nearest = false
			}
		}
	}
	check("raster: a stretched texture is sampled nearest", nearest, failed)

	// A vertical gradient, top colour to bottom colour, sampled at pixel centres.
	GH :: 200
	grad := make([]u32, 8 * GH)
	defer delete(grad)
	q = quad_verts(0, 0, 8, GH, fcol(255, 0, 0), fcol(0, 0, 255), white, white)
	raster_run(grad, 8, GH, bg, q[:], QUAD_IDX[:])
	ends := true
	for y in 0 ..< GH {
		t := (f64(y) + 0.5) / GH
		r, b := u8(255 * (1 - t) + 0.5), u8(255 * t + 0.5)
		for x in 0 ..< 8 {
			if !within(grad[y * 8 + x], r, 0, b, 1) {
				ends = false
			}
		}
	}
	check("raster: gradient from the top colour to the bottom colour", ends && within(grad[0], 255, 0, 1, 1) && within(grad[(GH - 1) * 8], 1, 0, 254, 1), failed)

	// The same gradient as a general triangle pair (a skewed quad): the planes agree.
	skew := quad_verts(0, 0, 8, GH, fcol(255, 0, 0), fcol(0, 0, 255), white, white)
	skew[1].position.x = 8.01
	raster_run(grad, 8, GH, bg, skew[:], QUAD_IDX[:])
	mid := 100.5 / f64(GH)
	check("raster: the triangle path gives the gradient too", within(grad[100 * 8 + 2], u8(255 * (1 - mid) + 0.5), 0, u8(255 * mid + 0.5), 1), failed)
}

Test_Target :: struct {
	px:    []u32,
	w, h:  int,
	calls: int,
	deny:  bool, // acquire has no pixels
}

test_acquire :: proc(data: rawptr, w, h: i32) -> (ui.Raster_Target, bool) {
	t := (^Test_Target)(data)
	t.calls += 1
	if t.deny {
		return {}, false
	}
	return {pixels = raw_data(t.px), stride = t.w, w = t.w, h = t.h}, true
}

// selftest_cpu_target checks Gfx with the CPU target: shapes with anti-aliased edges,
// the window gradient, and the rules for drawing a frame or not.
selftest_cpu_target :: proc(failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	W, H :: 48, 40
	g := new(ui.Gfx)
	defer free(g)
	if !ui.gfx_init(g, nil, 1) {
		check("cpu target: Gfx starts without a renderer", false, failed)
		return
	}
	defer ui.gfx_destroy(g)
	tt := Test_Target {
		px = make([]u32, W * H),
		w  = W,
		h  = H,
	}
	defer delete(tt.px)
	g.acquire, g.acquire_data = test_acquire, &tt
	ui.gfx_set_pixels(g, W, H)
	check("cpu target: the size comes from gfx_set_pixels", func_size(g) == {W, H}, failed)

	bg := ui.Color{10, 20, 30, 255}
	c := ui.Color{200, 100, 50, 255}
	frame_rects :: proc(g: ^ui.Gfx, bg, c: ui.Color) -> bool {
		ui.gfx_begin(g, bg)
		// Edges at x = 10.5 and 22.5 (half a pixel), and at 10.25 (a quarter).
		ui.rrect(g, {10.5, 4, 12, 10}, 0, c)
		ui.rrect(g, {10.25, 20, 12, 10}, 0, c)
		return ui.gfx_end(g)
	}
	drawn := frame_rects(g, bg, c)
	check("cpu target: the first frame is drawn", drawn && tt.calls == 1, failed)
	row :: proc(tt: ^Test_Target, y, x: int) -> u32 {
		return tt.px[y * tt.w + x]
	}
	half := pix(blend_u8(10, 200, 0.5), blend_u8(20, 100, 0.5), blend_u8(30, 50, 0.5))
	check("cpu target: an edge at a half pixel gives half coverage", within(row(&tt, 8, 10), 105, 60, 40, 1) && within(row(&tt, 8, 10), u8((half >> 16) & 0xff), u8((half >> 8) & 0xff), u8(half & 0xff), 1) && within(row(&tt, 8, 22), 105, 60, 40, 1), failed)
	check("cpu target: pixels inside are full and outside are clear", row(&tt, 8, 11) == pix(200, 100, 50) && row(&tt, 8, 21) == pix(200, 100, 50) && row(&tt, 8, 9) == pix(10, 20, 30) && row(&tt, 8, 23) == pix(10, 20, 30), failed)
	check("cpu target: an edge at a quarter pixel gives three quarters", within(row(&tt, 24, 10), blend_u8(10, 200, 0.75), blend_u8(20, 100, 0.75), blend_u8(30, 50, 0.75), 1), failed)
	check("cpu target: horizontal edges on a pixel boundary are hard", row(&tt, 4, 15) == pix(200, 100, 50) && row(&tt, 3, 15) == pix(10, 20, 30) && row(&tt, 13, 15) == pix(200, 100, 50) && row(&tt, 14, 15) == pix(10, 20, 30), failed)

	// An equal frame is skipped without asking for pixels.
	drawn = frame_rects(g, bg, c)
	check("cpu target: an equal frame is not drawn", !drawn && tt.calls == 1 && g.skipped == 1 && !g.stalled, failed)
	g.force = true
	drawn = frame_rects(g, bg, c)
	check("cpu target: a forced frame is drawn", drawn && tt.calls == 2, failed)
	tt.deny = true
	drawn = frame_rects(g, bg, ui.Color{200, 100, 51, 255})
	check("cpu target: a frame with no pixels waits", !drawn && g.stalled && tt.calls == 3, failed)
	tt.deny = false
	drawn = frame_rects(g, bg, ui.Color{200, 100, 51, 255})
	check("cpu target: the frame that waited is drawn when pixels come", drawn && !g.stalled && tt.calls == 4 && row(&tt, 8, 11) == pix(200, 100, 51), failed)

	// The window gradient.
	ui.gfx_begin(g, bg)
	ui.fill_vgradient(g, {0, 0, W, H}, ui.BG_TOP, ui.BG_BOTTOM)
	_ = ui.gfx_end(g)
	top, bottom := ui.BG_TOP, ui.BG_BOTTOM
	check("cpu target: the background gradient has its end colours", within(row(&tt, 0, 5), top.r, top.g, top.b, 1) && within(row(&tt, H - 1, 5), bottom.r, bottom.g, bottom.b, 1), failed)
}

func_size :: proc(g: ^ui.Gfx) -> [2]i32 {
	w, h := ui.gfx_size(g)
	return {w, h}
}

// cpu_pixels draws the frame that is built in app once more with the CPU rasterizer
// and returns its pixels (RGBA, rows without gaps).
cpu_pixels :: proc(app: ^App) -> []u8 {
	g := &app.u.g
	tt := Test_Target {
		px = make([]u32, int(g.px_w) * int(g.px_h)),
		w  = int(g.px_w),
		h  = int(g.px_h),
	}
	defer delete(tt.px)
	r, shift, acquire, data := g.r, g.shift, g.acquire, g.acquire_data
	g.r, g.shift, g.acquire, g.acquire_data = nil, 0, test_acquire, &tt
	ui.gfx_begin(g, ui.BG)
	ui.render(&app.u)
	_ = ui.gfx_end(g)
	g.r, g.shift, g.acquire, g.acquire_data = r, shift, acquire, data
	out := make([]u8, len(tt.px) * 4)
	for p, i in tt.px {
		out[i * 4], out[i * 4 + 1], out[i * 4 + 2], out[i * 4 + 3] = u8(p >> 16), u8(p >> 8), u8(p), 255
	}
	return out
}

// Pixel differences between the CPU frame and the frame of SDL's software renderer. The
// software renderer rounds every vertex to a whole pixel, so the two differ along
// anti-aliased edges; they agree where a colour is flat. The limits are the largest
// values measured on the four views at 100% and 200% (mean 2.5, 1.0% far), with room.
Frame_Diff :: struct {
	mean: f64, // mean of the largest channel difference of each pixel
	far:  f64, // share of pixels whose largest channel difference exceeds FAR_LEVEL
}

FAR_LEVEL :: 40
MEAN_LIMIT :: 4.0
FAR_LIMIT :: 0.02

frame_diff :: proc(a, b: []u8) -> (d: Frame_Diff) {
	sum, far := 0, 0
	for i := 0; i < len(a); i += 4 {
		m := 0
		for k in 0 ..< 3 {
			m = max(m, abs(int(a[i + k]) - int(b[i + k])))
		}
		sum += m
		if m > FAR_LEVEL {
			far += 1
		}
	}
	n := f64(len(a) / 4)
	d.mean, d.far = f64(sum) / n, f64(far) / n
	return
}

// selftest_cpu_views draws real views with the software renderer and with the CPU
// rasterizer, at 100% and 200%, and compares the pixels.
selftest_cpu_views :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	view, depth, state, scale := app.stack[0], app.depth, app.link.state, app.settings.scale
	defer {
		app.stack[0], app.depth, app.link.state = view, depth, state
		set_scale(app, scale)
		frame(app, 0)
	}
	app.link.state = .Not_Found
	names := [?]string{"list", "connection", "settings", "profile"}
	for pct in ([2]int{100, 200}) {
		set_scale(app, pct)
		for name in names {
			while_view(app, .List)
			switch name {
			case "connection":
				open_connection(app, 0)
			case "settings":
				push_view(app, .Settings)
			case "profile":
				open_profile(app, 0)
			}
			mouse(app, -10, -10)
			frame(app, 0)
			frame(app, 0)
			sw := frame_pixels(app)
			cpu := cpu_pixels(app)
			ok := len(sw) > 0 && len(sw) == len(cpu)
			d: Frame_Diff
			if ok {
				d = frame_diff(sw, cpu)
			}
			bright := 0
			for i := 0; i < len(cpu); i += 4 {
				if int(cpu[i]) + int(cpu[i + 1]) + int(cpu[i + 2]) > 3 * 200 {
					bright += 1
				}
			}
			check(fmt.tprintf("cpu view: %s at %d%% matches the software renderer (mean %.2f, %.2f%% far)", name, pct, d.mean, d.far * 100), ok && bright > 300 && d.mean < MEAN_LIMIT && d.far < FAR_LIMIT, failed)
			delete(sw)
			delete(cpu)
		}
	}
}

// selftest_renderer checks the renderer option: names, the choice of auto, the settings
// file, and the time between two frames of the CPU renderer.
selftest_renderer :: proc(failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	ok := true
	for t in ([?]struct {
			in_: string,
			r:   Renderer,
			ok:  bool,
		}{{"auto", .Auto, true}, {"gpu", .Gpu, true}, {"cpu", .Cpu, true}, {" CPU ", .Cpu, true}, {"Gpu", .Gpu, true}, {"software", .Auto, false}, {"", .Auto, false}}) {
		r, good := parse_renderer(t.in_)
		if r != t.r || good != t.ok {
			ok = false
		}
	}
	check("renderer: names parse", ok, failed)
	check("renderer: auto is gpu on Windows and cpu elsewhere", renderer_pick(.Auto) == (ODIN_OS == .Windows ? Renderer.Gpu : Renderer.Cpu) && renderer_pick(.Gpu) == .Gpu && renderer_pick(.Cpu) == .Cpu, failed)

	tmp, terr := os.temp_directory(context.temp_allocator)
	if terr != nil {
		check("temp directory", false, failed)
		return
	}
	dir := fmt.tprintf("%s/noirvpn-selftest-renderer-%d", tmp, os.get_pid())
	path := fmt.tprintf("%s/settings.ini", dir)
	defer os.remove_all(dir)
	_ = os.make_directory_all(dir)
	_ = os.write_entire_file(path, "scale = 150\nrenderer = CPU\nwindow_x = 3\n")
	s := settings_load(path)
	check("renderer: the saved renderer loads next to the other keys", s.renderer == .Cpu && s.scale == 150, failed)
	_ = os.write_entire_file(path, "renderer = fast\n")
	check("renderer: a bad value gives auto", settings_load(path).renderer == .Auto, failed)
	_ = os.write_entire_file(path, "renderer = gpu\nother = 1\n")
	_ = settings_save(path, {scale = 200})
	data, _ := os.read_entire_file(path, context.temp_allocator)
	check("renderer: saving the scale keeps the renderer line", strings.contains(string(data), "renderer = gpu") && settings_load(path).renderer == .Gpu, failed)

	check("pacing: a frame that is due waits no time, a later one waits to its slot", draw_wait(5.0, 4.9) == 0 && draw_wait(5.0, 5.0) == 0 && draw_wait(5.0, 5.0052) == 6 && draw_wait(5.0, 0) == 0, failed)
	check("pacing: the CPU renderer draws at most 15 frames a second", draw_wait(5.0, 5.0 + CPU_FRAME_GAP) == 67, failed)
}

// selftest_connection checks the state pill, the redraw rate of the glow, the
// transport label and the top bar text split.
selftest_connection :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	// The pointer is away: over a scroll area it shows the scrollbar, which redraws.
	mouse(app, -10, -10)
	start_connection(app, 2)
	c := &app.conn
	frame(app, 0.016)
	label, tone := pill_for(c.phase)
	check("pill: connecting is amber", label == "connecting" && tone == .Warn, failed)
	wait := next_wake(app) - app.now
	check("the pulse redraws 15 times a second", abs(wait - 1.0 / 15) < 1e-6, failed)
	app.now += 1.7
	frame(app, 0.016)
	label, tone = pill_for(c.phase)
	check("pill: sign in needed is amber", c.phase == .Credentials && label == "sign in needed" && tone == .Warn, failed)
	check("credentials state does not pulse", next_wake(app) == 0, failed)
	c.signed_in = true
	c.phase = .Connecting
	c.phase_start = app.now
	app.now += 0.7
	frame(app, 0.016)
	label, tone = pill_for(c.phase)
	check("pill: handshake is amber", c.phase == .Handshake && label == "handshake" && tone == .Warn, failed)
	app.now += 0.7
	frame(app, 0.016)
	label, tone = pill_for(c.phase)
	check("pill: connected is green", c.phase == .Up && label == "connected" && tone == .Ok, failed)
	for _ in 0 ..< 20 {
		frame(app, 0.016) // the scrollbar of the longer view fades out
	}
	wait = next_wake(app) - app.now
	check("up redraws once a second", wait > 0.2 && wait <= 1.0 + 1e-6, failed)
	l1, t1 := pill_for(.Failed)
	l2, t2 := pill_for(.Stopped)
	l3, t3 := pill_for(.Disconnected)
	check("pill: error is red, stopped and disconnected are grey", l1 == "error" && t1 == .Error && l2 == "stopped" && t2 == .Neutral && l3 == "disconnected" && t3 == .Neutral, failed)
	check("transport is upper case", transport_label(&app.profiles[2]) == "TLS" && transport_label(&app.profiles[0]) == "UDP", failed)
	a0, a1 := state_alpha(.Connecting, 0), state_alpha(.Connecting, PULSE_PERIOD / 2)
	check("state text pulses from 0.55 to 1 while connecting", abs(a0 - 1) < 1e-4 && abs(a1 - 0.55) < 1e-4 && state_alpha(.Up, 5) == 1 && state_alpha(.Credentials, 5) == 1, failed)

	tw, sw := split_widths(80, 120, 300)
	check("bar text: both fit", tw == 80 && sw == 120, failed)
	tw, sw = split_widths(400, 100, 300)
	check("bar text: a long title is cut", tw == 200 && sw == 100, failed)
	tw, sw = split_widths(60, 500, 300)
	check("bar text: a long server is cut", tw == 60 && sw == 240, failed)
	tw, sw = split_widths(400, 500, 300)
	check("bar text: both are cut", tw == 150 && sw == 150, failed)
	long := "A very long profile name that cannot fit in the bar"
	cut := ui.fit_text(&app.u, ui.ST_BAR_TITLE, long, 120)
	check("long text gets an ellipsis", ui.text_w(&app.u, ui.ST_BAR_TITLE, cut) <= 120 && strings.has_suffix(cut, "\u2026"), failed)
	app.profiles[2].name = long
	app.profiles[2].host = "a-very-long-server-host-name.example.organisation.net"
	frame(app, 0.016)
	check("long names build", current_view(app) == .Connection, failed)

	// The bottom bar: Edit and Settings beside the connect button.
	bar_h := big_button_bar_h()
	bh := f32(bar_h - 33)
	by := f32(WIN_H - bar_h + 17) + bh / 2
	gear_x := f32(WIN_W - ui.CARD_MARGIN) - bh / 2
	edit_x := gear_x - bh - 8
	click(app, edit_x, by)
	check("Edit opens the profile of the view", current_view(app) == .Profile && app.edit.index == 2, failed)
	key(app, sdl.K_ESCAPE)
	click(app, gear_x, by)
	check("the gear opens the settings", current_view(app) == .Settings, failed)
	key(app, sdl.K_ESCAPE)
	check("back from both to the connection view", current_view(app) == .Connection, failed)

	// Keyboard scrolling of the connection view.
	frame(app, 0.016)
	key(app, sdl.K_DOWN)
	d1 := scroll_of(app, "conn")
	key(app, sdl.K_DOWN)
	d2 := scroll_of(app, "conn")
	key(app, sdl.K_PAGEDOWN)
	frame(app, 0.016)
	page := scroll_of(app, "conn")
	key(app, sdl.K_END)
	frame(app, 0.016)
	end := scroll_of(app, "conn")
	key(app, sdl.K_UP)
	up := scroll_of(app, "conn")
	key(app, sdl.K_PAGEUP)
	frame(app, 0.016)
	page_up := scroll_of(app, "conn")
	key(app, sdl.K_END)
	key(app, sdl.K_HOME)
	frame(app, 0.016)
	check("Down, Page Down, End, Up, Page Up and Home scroll the view", d1 == 40 && d2 == 80 && page > d2 && end == page && up == end - 40 && page_up == 0 && scroll_of(app, "conn") == 0, failed)
	check("the connected view shows the DNS and route cards", app.conn.settings_ok && len(app.conn.routes) == 2 && len(row_overrides(app, 2).dns_servers) == 1, failed)

	link_disconnect(app)
	frame(app, 0.016)
	click(app, 22, 28)
	check("back from the connection view", current_view(app) == .List, failed)

	// A focused text field keeps the keys.
	open_profile(app, 0)
	frame(app, 0.016)
	key(app, sdl.K_PAGEDOWN)
	check("Page Down scrolls the profile view", scroll_of(app, "profile") > 0, failed)
	key(app, sdl.K_HOME)
	frame(app, 0.016)
	click(app, 200, 110 + NAV_H)
	key(app, sdl.K_PAGEDOWN)
	key(app, sdl.K_END)
	frame(app, 0.016)
	check("keys in a text field do not scroll", scroll_of(app, "profile") == 0 && ui.text_focused(&app.u), failed)
	key(app, sdl.K_ESCAPE)
	check("Escape from the profile view", current_view(app) == .List, failed)

	// The section bar jumps to a section and marks it.
	open_profile(app, 0)
	frame(app, 0.016)
	nv := &app.nav
	ov := -1
	for i in 0 ..< nv.n {
		if nv.items[i].label == "Overrides" {
			ov = i
		}
	}
	check("section bar lists the profile sections", nv.area == "profile" && nv.n >= 6 && nv.items[0].label == "Name" && ov > 0 && nav_active(nv, scroll_of(app, "profile")) == 0, failed)
	if ov > 0 {
		b := nv.rects[ov]
		click(app, f32(b.x + b.w / 2), f32(b.y + b.h / 2))
		frame(app, 0.016)
		check("a section item scrolls to its section", scroll_of(app, "profile") == nv.items[ov].y - NAV_OFFSET && nav_active(nv, scroll_of(app, "profile")) == ov, failed)
		b = nv.rects[0]
		click(app, f32(b.x + b.w / 2), f32(b.y + b.h / 2))
		frame(app, 0.016)
		check("Name goes back to the top", scroll_of(app, "profile") == 0 && nav_active(nv, 0) == 0, failed)
	}
	key(app, sdl.K_ESCAPE)

	open_profile(app, 1)
	check("an imported profile has Block IPv6, off", !app.edit.block_ipv6 && !app.edit.dirty && click_block6(app) && app.edit.block_ipv6 && app.edit.dirty, failed)
	check("an imported profile has the kill switch, off", !app.edit.kill_switch && click_kill(app) && app.edit.kill_switch && app.edit.dirty, failed)
	check("the kill switch toggles off again and the redirect choice stays", app.edit.redirect && click_kill(app) && !app.edit.kill_switch, failed)
	key(app, sdl.K_ESCAPE)
}

// click_block6 scrolls the profile view to the Block IPv6 switch and clicks
// it. It returns false when the view does not draw the switch.
click_block6 :: proc(app: ^App) -> bool {
	return click_switch(app, &app.edit.block6_at)
}

// click_kill does the same for the "Block traffic when the VPN is down" switch.
click_kill :: proc(app: ^App) -> bool {
	return click_switch(app, &app.edit.kill_at)
}

// click_switch scrolls the profile view to the switch that the view stores in
// `at`, and clicks it. It returns false when the view does not draw it.
click_switch :: proc(app: ^App, at: ^mu.Rect) -> bool {
	at^ = {}
	frame(app, 0.016)
	if at.w == 0 {
		return false
	}
	scroll_to(app, "profile", scroll_of(app, "profile") + at.y - 300)
	frame(app, 0.016)
	r := at^
	click(app, f32(r.x + r.w / 2), f32(r.y + r.h / 2))
	return true
}

// selftest_matrix checks the geometry and the stacks of the rate matrix.
selftest_matrix :: proc(failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	m := ui.rate_matrix(320, 78)
	check("matrix: a gap of about a fifth of a cell, square cells", m.gap == 1 && abs(m.cell - (320 - 59) / 60.0) < 1e-4, failed)
	check("matrix: as many rows as fit", m.rows == 14 && f32(m.rows) * m.cell + f32(m.rows - 1) * m.gap <= 78, failed)
	check("matrix: any rate above zero shows a block", ui.matrix_blocks(m, 1, 1e6) == 1 && ui.matrix_blocks(m, 0, 1e6) == 0, failed)
	check("matrix: the top of the axis fills the column", ui.matrix_blocks(m, 1e6, 1e6) == 14 && ui.matrix_blocks(m, 2e6, 1e6) == 14 && ui.matrix_blocks(m, 0.5e6, 1e6) == 7, failed)
	check("matrix: dark at the bottom, light at the top", ui.matrix_shade(m, 0) == 0.5 && ui.matrix_shade(m, m.rows - 1) == 1, failed)
	v := [?]f32{1, 2, 3}
	check("matrix: the newest sample is the last column", ui.matrix_sample(v[:], ui.RATE_COLUMNS - 1) == 3 && ui.matrix_sample(v[:], ui.RATE_COLUMNS - 3) == 1 && ui.matrix_sample(v[:], 0) == 0, failed)
}

// selftest_settings_file checks load and save on a temporary file.
selftest_settings_file :: proc(failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	tmp, terr := os.temp_directory(context.temp_allocator)
	if terr != nil {
		check("temp directory", false, failed)
		return
	}
	dir := fmt.tprintf("%s/noirvpn-selftest-%d", tmp, os.get_pid())
	path := fmt.tprintf("%s/sub/settings.ini", dir)
	defer os.remove_all(dir)
	check("missing file gives automatic", settings_load(path) == Settings{}, failed)
	check("save creates the directory", settings_save(path, {scale = 150}), failed)
	check("saved value loads", settings_load(path).scale == 150, failed)
	_ = os.write_entire_file(path, "other = 1\nscale = 12x\n")
	check("bad value gives automatic", settings_load(path).scale == 0, failed)
	_ = os.write_entire_file(path, "other = 1\nscale = 200\n")
	check("good value loads", settings_load(path).scale == 200, failed)
	_ = settings_save(path, {scale = 0})
	data, _ := os.read_entire_file(path, context.temp_allocator)
	check("other keys are kept", string(data) == "other = 1\nscale = auto\n", failed)
	_, terr2 := os.stat(fmt.tprintf("%s.tmp", path), context.temp_allocator)
	check("no temporary file is left", terr2 != nil, failed)
}

// selftest_frame checks the frameless window: flags, hit testing of the top bar,
// the close button and the close request.
selftest_frame :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	flags := sdl.GetWindowFlags(app.window)
	check("window is borderless and not resizable", .BORDERLESS in flags && .RESIZABLE not_in flags, failed)

	d, _ := window_scales(app.window)
	// hit asks the callback about the logical point lx, ly, given in window coordinates.
	hit :: proc(app: ^App, d, lx, ly: f32) -> sdl.HitTestResult {
		k := app.eff / d
		pt := sdl.Point{i32(math.round(lx * k)), i32(math.round(ly * k))}
		return hit_test(app.window, &pt, nil)
	}
	for pct in ([2]int{100, 200}) {
		set_scale(app, pct)
		while_view(app, .List)
		frame(app, 0)
		tag := fmt.tprintf("at %d%%", pct)
		k := app.eff / d
		check(fmt.tprintf("hit test: empty top bar drags %s", tag), hit(app, d, 150, 28) == .DRAGGABLE && hit(app, d, 2, 2) == .DRAGGABLE && hit(app, d, 399, 55) == .DRAGGABLE, failed)
		check(fmt.tprintf("hit test: close, plus and gear are normal %s", tag), hit(app, d, 372, 28) == .NORMAL && hit(app, d, 332, 28) == .NORMAL && hit(app, d, 292, 28) == .NORMAL, failed)
		check(fmt.tprintf("hit test: body is normal %s", tag), hit(app, d, 150, 56) == .NORMAL && hit(app, d, 200, 300) == .NORMAL && hit(app, d, 372, 700) == .NORMAL, failed)
		check(fmt.tprintf("hit test: outside the window is normal %s", tag), hit(app, d, -3, 20) == .NORMAL, failed)

		click(app, 100 * k, 90 * k)
		frame(app, 0)
		check(fmt.tprintf("connection view opens %s", tag), current_view(app) == .Connection, failed)
		check(fmt.tprintf("hit test: back arrow is normal, bar drags %s", tag), hit(app, d, 22, 28) == .NORMAL && hit(app, d, 150, 28) == .DRAGGABLE && hit(app, d, 372, 28) == .NORMAL, failed)
		check(fmt.tprintf("a row click does not connect %s", tag), !conn_active(app), failed)
		row_connect(app, app.shown)
		frame(app, 0)
		check(fmt.tprintf("hit test: no back arrow while connecting %s", tag), conn_active(app) && hit(app, d, 22, 28) == .DRAGGABLE, failed)
		click(app, 22 * k, 28 * k)
		check(fmt.tprintf("the bar has no back while connecting %s", tag), current_view(app) == .Connection, failed)
		link_disconnect(app)
		frame(app, 0)
		click(app, 22 * k, 28 * k)
		check(fmt.tprintf("back to the list %s", tag), current_view(app) == .List, failed)

		click(app, 332 * k, 28 * k)
		check(fmt.tprintf("plus opens its menu %s", tag), ui.menu_is_open(&app.u, MENU_PLUS), failed)
		check(fmt.tprintf("hit test: no dragging while a menu is open %s", tag), hit(app, d, 150, 28) == .NORMAL, failed)
		ui.menu_close(&app.u, MENU_PLUS)
		frame(app, 0)
		check(fmt.tprintf("hit test: dragging again after the menu closes %s", tag), hit(app, d, 150, 28) == .DRAGGABLE, failed)

		check(fmt.tprintf("not quitting before the click %s", tag), !app.quit, failed)
		click(app, 372 * k, 28 * k)
		check(fmt.tprintf("close button quits %s", tag), app.quit, failed)
		app.quit = false
	}

	open_connection(app, 0)
	app.conn.phase = .Stopped // no active connection: the close button quits
	frame(app, 0)
	click(app, 372 * (app.eff / d), 28 * (app.eff / d))
	check("close button quits on the connection view", app.quit, failed)
	app.quit = false
	while_view(app, .List)
	set_scale(app, 0)
	frame(app, 0)

	ev: sdl.Event
	ev.window = {type = .WINDOW_CLOSE_REQUESTED}
	_ = handle_app_event(app, &ev)
	check("close request (Alt+F4) quits", app.quit, failed)
	app.quit = false
	ev.type = .QUIT
	_ = handle_app_event(app, &ev)
	check("quit event quits", app.quit, failed)
	app.quit = false

	snap := Hit_Snapshot {
		k    = 1,
		w    = WIN_W,
		drag = true,
	}
	check("hit test: bar drags and the body does not", hit_classify(snap, 10, 10) == .DRAGGABLE && hit_classify(snap, 10, ui.TOPBAR_H) == .NORMAL, failed)
}

// selftest_quit checks the quit confirmation.
selftest_quit :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	d, _ := window_scales(app.window)
	k := app.eff / d
	centre :: proc(r: mu.Rect) -> (x, y: f32) {
		return f32(r.x) + f32(r.w) / 2, f32(r.y) + f32(r.h) / 2
	}
	// close_x and close_y are the close button of the top bar.
	close_x, close_y := 372 * k, 28 * k
	hit_bar :: proc(app: ^App, d: f32) -> sdl.HitTestResult {
		k := app.eff / d
		pt := sdl.Point{i32(math.round(150 * k)), i32(math.round(28 * k))}
		return hit_test(app.window, &pt, nil)
	}
	// start opens the connection of profile 0 in the given phase with no prompt.
	start :: proc(app: ^App, phase: Phase) {
		while_view(app, .List)
		app.quit, app.quit_prompt = false, false
		start_connection(app, 0)
		conn_up(&app.conn, app.now)
		app.conn.phase = phase
		frame(app, 0)
	}
	// open_prompt clicks the close button and returns the layout.
	open_prompt :: proc(app: ^App, x, y: f32) -> Quit_Layout {
		click(app, x, y)
		return quit_layout(app)
	}

	for p in Phase {
		active := p == .Connecting || p == .Handshake || p == .Credentials || p == .Web_Sign_In || p == .Up
		start(app, p)
		if conn_active(app) != active {
			check(fmt.tprintf("active connection: phase %v", p), false, failed)
		}
	}
	start(app, .Up)
	pop_view(app)
	check("the connection stays active when its view is left", conn_active(app), failed)
	while_view(app, .List)

	// No connection: the close button quits at once.
	click(app, close_x, close_y)
	check("close button without a connection quits", app.quit && !app.quit_prompt, failed)
	app.quit = false

	// Up: the prompt opens.
	start(app, .Up)
	l := open_prompt(app, close_x, close_y)
	check("close button while up opens the prompt", app.quit_prompt && !app.quit && current_view(app) == .Connection, failed)
	check("prompt names the connected case", len(l.lines) > 0 && strings.join(l.lines, " ", context.temp_allocator) == "“Home” is connected. Quitting will terminate the tunnel.", failed)
	check("two buttons in one row: Cancel, Disconnect and quit", l.n == 2 && !l.stacked && l.cancel.x + l.cancel.w < l.disconnect.x && l.disconnect.y == l.cancel.y, failed)
	check("card is centred and 24 from the edges", l.card.x == QUIT_MARGIN && l.card.w == WIN_W - 2 * QUIT_MARGIN && abs(l.card.y * 2 + l.card.h - WIN_H) <= 1, failed)
	check("top bar does not drag while the prompt is open", hit_bar(app, d) == .NORMAL, failed)

	// Cancel.
	cx, cy := centre(l.cancel)
	click(app, cx * k, cy * k)
	check("Cancel closes the prompt and the connection stays up", !app.quit_prompt && !app.quit && app.conn.phase == .Up && current_view(app) == .Connection, failed)
	check("top bar drags again after Cancel", hit_bar(app, d) == .DRAGGABLE, failed)

	// A click on a widget under the backdrop (the Disconnect button) does not reach it.
	l = open_prompt(app, close_x, close_y)
	check("prompt opens again", app.quit_prompt, failed)
	bx := f32(WIN_W / 2)
	by := f32(WIN_H - 40)
	click(app, bx * k, by * k)
	check("click on Disconnect under the backdrop does nothing to it", app.conn.phase == .Up && current_view(app) == .Connection && !app.quit, failed)
	check("a backdrop click cancels", !app.quit_prompt, failed)

	// A click inside the card, not on a button, keeps the prompt open.
	l = open_prompt(app, close_x, close_y)
	click(app, f32(l.card.x + 30) * k, f32(l.card.y + 8) * k)
	check("click on the card keeps the prompt", app.quit_prompt && !app.quit, failed)
	// A click on the close button position is a backdrop click.
	click(app, close_x, close_y)
	check("close button under the backdrop only cancels", !app.quit_prompt && !app.quit, failed)

	// Escape cancels and does not pop the view.
	l = open_prompt(app, close_x, close_y)
	key(app, sdl.K_ESCAPE)
	check("Escape cancels the prompt and keeps the view", !app.quit_prompt && !app.quit && current_view(app) == .Connection && app.conn.phase == .Up, failed)
	key(app, sdl.K_ESCAPE)
	check("Escape on a connected view stays", current_view(app) == .Connection, failed)
	app.conn.phase = .Stopped
	key(app, sdl.K_ESCAPE)
	check("Escape without a prompt goes back", current_view(app) == .List, failed)

	// Enter does nothing.
	start(app, .Up)
	l = open_prompt(app, close_x, close_y)
	key(app, sdl.K_RETURN)
	key(app, sdl.K_KP_ENTER)
	check("Enter does nothing", app.quit_prompt && !app.quit && app.conn.phase == .Up, failed)
	// Focus starts on Cancel: Space cancels.
	key(app, sdl.K_SPACE)
	check("focus starts on Cancel", !app.quit_prompt && !app.quit, failed)
	// Tab moves from Cancel to Disconnect and quit (the stack is drawn top down).
	l = open_prompt(app, close_x, close_y)
	key(app, sdl.K_TAB)
	key(app, sdl.K_SPACE)
	check("Tab then Space reaches another button", app.quit && !app.quit_prompt, failed)

	// Disconnect and quit.
	start(app, .Up)
	l = open_prompt(app, close_x, close_y)
	px, py := centre(l.disconnect)
	click(app, px * k, py * k)
	check("Disconnect and quit ends the connection and quits", app.quit && app.conn.phase == .Disconnected && !app.quit_prompt, failed)


	// Close request and quit event.
	start(app, .Up)
	ev: sdl.Event
	ev.window = {type = .WINDOW_CLOSE_REQUESTED}
	redraw := handle_app_event(app, &ev)
	frame(app, 0)
	check("close request while up opens the prompt", redraw && app.quit_prompt && !app.quit, failed)
	check("top bar does not drag after a close request", hit_bar(app, d) == .NORMAL, failed)
	_ = handle_app_event(app, &ev)
	check("a second close request disconnects and quits", app.quit && app.conn.phase == .Disconnected, failed)

	start(app, .Up)
	ev.type = .QUIT
	_ = handle_app_event(app, &ev)
	frame(app, 0)
	check("quit event while up opens the prompt", app.quit_prompt && !app.quit, failed)
	_ = handle_app_event(app, &ev)
	check("a second quit event disconnects and quits", app.quit && app.conn.phase == .Disconnected, failed)

	// The connecting text.
	start(app, .Connecting)
	app.now += 0.1
	_ = open_prompt(app, close_x, close_y)
	l = quit_layout(app)
	text := strings.join(l.lines, " ", context.temp_allocator)
	check("prompt names the connecting case", app.quit_prompt && text == "Quitting will stop connecting “Home”.", failed)

	// A long name is cut and the layout stays inside the window.
	old_name := app.profiles[0].name
	app.profiles[0].name = "A very long profile name for a corporate gateway in another region"
	frame(app, 0)
	l = quit_layout(app)
	check("long name fits the card", l.card.y >= 0 && l.card.y + l.card.h <= WIN_H && l.disconnect.x + l.disconnect.w <= l.card.x + l.card.w, failed)
	app.profiles[0].name = old_name

	app.quit, app.quit_prompt = false, false
	frame(app, 0)
	while_view(app, .List)
}

// selftest_close checks the close prompt. tray says whether the system has a
// tray (a fake flag).
selftest_close :: proc(app: ^App, tray: bool, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	d, _ := window_scales(app.window)
	k := app.eff / d
	tag := tray ? "with a tray" : "without a tray"
	centre :: proc(r: mu.Rect) -> (x, y: f32) {
		return f32(r.x) + f32(r.w) / 2, f32(r.y) + f32(r.h) / 2
	}
	close_x, close_y := 372 * k, 28 * k
	hidden :: proc(app: ^App) -> bool {
		return .HIDDEN in sdl.GetWindowFlags(app.window)
	}
	// start shows the window and opens the connection of profile 0 in a phase,
	// or stays on the list when idle is true.
	start :: proc(app: ^App, tray: bool, phase: Phase, idle := false) {
		while_view(app, .List)
		app.quit, app.quit_prompt, app.prompt_hide = false, false, false
		app.has_tray = tray
		show_window(app)
		if !idle {
			start_connection(app, 0)
			conn_up(&app.conn, app.now)
			app.conn.phase = phase
		}
		frame(app, 0)
	}
	press :: proc(app: ^App, r: mu.Rect, k: f32) {
		x, y := centre(r)
		click(app, x * k, y * k)
	}
	text_of :: proc(l: Quit_Layout) -> string {
		return strings.join(l.lines, " ", context.temp_allocator)
	}

	start(app, tray, .Up, true)
	check(fmt.tprintf("window can be shown %s", tag), !hidden(app) && !app.hidden, failed)
	click(app, close_x, close_y)
	if !tray {
		check(fmt.tprintf("close button quits at once when idle %s", tag), app.quit && !app.quit_prompt, failed)
		start(app, tray, .Up)
		click(app, close_x, close_y)
		l := quit_layout(app)
		check(fmt.tprintf("close button while up opens the quit prompt %s", tag), app.quit_prompt && !app.prompt_hide && !app.quit && l.n == 2 && prompt_title(app) == "Quit noirvpn?", failed)
		check(fmt.tprintf("quit prompt text %s", tag), text_of(l) == "“Home” is connected. Quitting will terminate the tunnel.", failed)
		ev: sdl.Event
		ev.window = {type = .WINDOW_CLOSE_REQUESTED}
		_ = handle_app_event(app, &ev)
		check(fmt.tprintf("second close request disconnects and quits %s", tag), app.quit && app.conn.phase == .Disconnected, failed)
		start(app, tray, .Up)
		_ = handle_app_event(app, &ev)
		frame(app, 0)
		check(fmt.tprintf("close request while up opens the quit prompt %s", tag), app.quit_prompt && !app.prompt_hide && !app.quit, failed)
		press(app, quit_layout(app).disconnect, k)
		check(fmt.tprintf("Disconnect and quit ends the connection %s", tag), app.quit && app.conn.phase == .Disconnected, failed)
		start(app, tray, .Up, true)
		ev.window = {type = .WINDOW_CLOSE_REQUESTED}
		_ = handle_app_event(app, &ev)
		check(fmt.tprintf("close request when idle quits %s", tag), app.quit && !app.quit_prompt, failed)
		start(app, tray, .Up)
		hide_window(app)
		ev.type = .QUIT
		_ = handle_app_event(app, &ev)
		frame(app, 0)
		check(fmt.tprintf("quit event while hidden shows the window and the quit prompt %s", tag), app.quit_prompt && !app.prompt_hide && !hidden(app), failed)
		show_window(app)
		return
	}

	// With a tray: the X opens the close prompt, also when idle.
	l := quit_layout(app)
	check(fmt.tprintf("X opens the close prompt when idle %s", tag), app.quit_prompt && app.prompt_hide && !app.quit && prompt_title(app) == "Close noirvpn?", failed)
	check(fmt.tprintf("idle text %s", tag), text_of(l) == "Hide to the system tray.", failed)
	check(fmt.tprintf("three buttons in one row, right-aligned %s", tag), l.n == 3 && !l.stacked && l.cancel.x + l.cancel.w < l.confirm.x && l.confirm.x + l.confirm.w < l.hide.x && l.hide.x + l.hide.w == l.card.x + l.card.w - QUIT_PAD, failed)
	check(fmt.tprintf("Quit is plain and Hide is primary %s", tag), prompt_kind(app, .Quit) == .Secondary && prompt_kind(app, .Hide) == .Primary && prompt_kind(app, .Disconnect) == .Danger, failed)
	// Focus starts on Hide: Space hides.
	key(app, sdl.K_RETURN)
	check(fmt.tprintf("Enter does nothing %s", tag), app.quit_prompt && !app.quit && !hidden(app), failed)
	key(app, sdl.K_SPACE)
	check(fmt.tprintf("focus starts on Hide: Space hides the window %s", tag), hidden(app) && app.hidden && !app.quit && !app.quit_prompt, failed)
	check(fmt.tprintf("no redraw wake while hidden %s", tag), next_wake(app) == 0, failed)
	show_window(app)
	check(fmt.tprintf("show_window shows it again %s", tag), !hidden(app) && !app.hidden, failed)

	// Quit with no connection.
	start(app, tray, .Up, true)
	click(app, close_x, close_y)
	press(app, quit_layout(app).confirm, k)
	check(fmt.tprintf("Quit without a connection quits %s", tag), app.quit && !hidden(app), failed)

	// Up.
	start(app, tray, .Up)
	click(app, close_x, close_y)
	l = quit_layout(app)
	check(fmt.tprintf("close prompt while up %s", tag), app.quit_prompt && app.prompt_hide && text_of(l) == "“Home” is connected.", failed)
	check(fmt.tprintf("three buttons while up: no plain Quit, Hide first in a stack %s", tag), l.n == 3 && l.confirm == {} && (!l.stacked || (l.hide.y < l.disconnect.y && l.disconnect.y < l.cancel.y)), failed)
	press(app, l.hide, k)
	check(fmt.tprintf("Hide keeps the tunnel up %s", tag), hidden(app) && !app.quit && app.conn.phase == .Up && current_view(app) == .Connection, failed)
	app.now += 5
	check(fmt.tprintf("no redraw wake while hidden and up %s", tag), next_wake(app) == 0, failed)
	show_window(app)
	frame(app, 0)
	check(fmt.tprintf("the samples catch up after show %s", tag), next_wake(app) > 0 && app.conn.count >= 5, failed)

	start(app, tray, .Up)
	click(app, close_x, close_y)
	press(app, quit_layout(app).disconnect, k)
	check(fmt.tprintf("Disconnect and quit while up %s", tag), app.quit && app.conn.phase == .Disconnected, failed)

	// Connecting: text, and the script moves on after a hidden spell.
	start(app, tray, .Connecting)
	app.conn.phase_start = app.now
	click(app, close_x, close_y)
	check(fmt.tprintf("close prompt while connecting %s", tag), text_of(quit_layout(app)) == "“Home” is connecting.", failed)
	press(app, quit_layout(app).hide, k)
	check(fmt.tprintf("hidden while connecting %s", tag), hidden(app) && next_wake(app) == 0, failed)
	app.now += 3
	show_window(app)
	frame(app, 0)
	check(fmt.tprintf("the script advances after show %s", tag), app.conn.phase == .Handshake, failed)

	// Cancel, Escape, backdrop.
	start(app, tray, .Up)
	click(app, close_x, close_y)
	press(app, quit_layout(app).cancel, k)
	check(fmt.tprintf("Cancel closes the prompt %s", tag), !app.quit_prompt && !app.quit && !hidden(app) && app.conn.phase == .Up, failed)
	click(app, close_x, close_y)
	key(app, sdl.K_ESCAPE)
	check(fmt.tprintf("Escape closes the prompt %s", tag), !app.quit_prompt && !app.quit && !hidden(app) && current_view(app) == .Connection, failed)
	click(app, close_x, close_y)
	click(app, 200 * k, (WIN_H - 40) * k)
	check(fmt.tprintf("a backdrop click closes the prompt %s", tag), !app.quit_prompt && !app.quit && !hidden(app) && app.conn.phase == .Up, failed)

	// Second close request quits.
	click(app, close_x, close_y)
	ev: sdl.Event
	ev.window = {type = .WINDOW_CLOSE_REQUESTED}
	_ = handle_app_event(app, &ev)
	check(fmt.tprintf("second close request disconnects and quits %s", tag), app.quit && app.conn.phase == .Disconnected, failed)
	start(app, tray, .Up)
	redraw := handle_app_event(app, &ev)
	frame(app, 0)
	check(fmt.tprintf("close request opens the close prompt %s", tag), redraw && app.quit_prompt && app.prompt_hide && !app.quit, failed)

	// The quit event never offers Hide, and a second one quits.
	start(app, tray, .Up)
	ev.type = .QUIT
	_ = handle_app_event(app, &ev)
	frame(app, 0)
	l = quit_layout(app)
	check(fmt.tprintf("quit event opens the quit prompt without Hide %s", tag), app.quit_prompt && !app.prompt_hide && l.n == 2 && prompt_title(app) == "Quit noirvpn?" && !app.quit, failed)
	_ = handle_app_event(app, &ev)
	check(fmt.tprintf("a second quit event quits %s", tag), app.quit, failed)
	start(app, tray, .Up, true)
	_ = handle_app_event(app, &ev)
	check(fmt.tprintf("quit event when idle quits %s", tag), app.quit && !app.quit_prompt, failed)

	// A narrow window stacks the buttons with Hide first.
	start(app, tray, .Up)
	click(app, close_x, close_y)
	app.u.size.x = 240
	l = quit_layout(app)
	inner := l.card.w - 2 * QUIT_PAD
	check(fmt.tprintf("narrow window stacks the buttons, Hide first %s", tag), l.stacked && l.hide.y < l.disconnect.y && l.disconnect.y < l.cancel.y && l.hide.w == inner && l.cancel.w == inner, failed)
	app.u.size.x = WIN_W
	app.quit_prompt = false
	start(app, tray, .Up, true)
}

// selftest_tray checks the tray menu actions and texts. The actions are called
// directly, as SDL calls them, with a fake tray flag in place of a real tray.
selftest_tray :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	hidden :: proc(app: ^App) -> bool {
		return .HIDDEN in sdl.GetWindowFlags(app.window)
	}
	start :: proc(app: ^App, phase: Phase, idle := false) {
		while_view(app, .List)
		app.quit, app.quit_prompt, app.prompt_hide = false, false, false
		app.has_tray = true
		show_window(app)
		if !idle {
			start_connection(app, 2)
			conn_up(&app.conn, app.now)
			app.conn.phase = phase
		}
		frame(app, 0)
	}
	app.profiles[2].name = "Work VPN"
	start(app, .Up, true)
	tip, status := tray_texts(app, tray_state(app))
	check("tray texts when idle", tip == "noirvpn" && status == "Not connected", failed)
	start(app, .Up)
	tip, status = tray_texts(app, tray_state(app))
	check("tray texts when connected", tip == "noirvpn: Work VPN connected" && status == "Work VPN: connected", failed)
	start(app, .Connecting)
	tip, status = tray_texts(app, tray_state(app))
	check("tray texts when connecting", tip == "noirvpn: Work VPN connecting" && status == "Work VPN: connecting", failed)
	start(app, .Credentials)
	_, status = tray_texts(app, tray_state(app))
	check("tray text when sign in is needed", status == "Work VPN: sign in needed", failed)
	start(app, .Failed)
	check("tray state is idle after a failure", tray_state(app).kind == .Idle, failed)

	// Show.
	start(app, .Up)
	hide_window(app)
	tray_show_cb(app, nil)
	check("tray Show shows the window", !hidden(app) && !app.hidden && !app.quit, failed)
	check("tray Show keeps the connection", app.conn.phase == .Up, failed)

	// Disconnect.
	hide_window(app)
	tray_disconnect_cb(app, nil)
	check("tray Disconnect disconnects", app.conn.phase == .Disconnected && !conn_active(app) && current_view(app) == .Connection && !app.quit, failed)
	check("tray state is idle after Disconnect", tray_state(app).kind == .Idle, failed)

	// Quit.
	start(app, .Up, true)
	tray_quit_cb(app, nil)
	check("tray Quit quits at once when idle", app.quit && !app.quit_prompt, failed)
	start(app, .Up)
	hide_window(app)
	tray_quit_cb(app, nil)
	l := quit_layout(app)
	check("tray Quit while up shows the window with the quit prompt", !app.quit && app.quit_prompt && !app.prompt_hide && !hidden(app) && l.n == 2 && prompt_title(app) == "Quit noirvpn?" && app.conn.phase == .Up, failed)
	tray_quit_cb(app, nil)
	check("a second tray Quit disconnects and quits", app.quit && app.conn.phase == .Disconnected, failed)
	// Quit while the close prompt is open turns it into the quit prompt.
	start(app, .Up)
	_ = handle_app_event(app, &sdl.Event{window = {type = .WINDOW_CLOSE_REQUESTED}})
	tray_quit_cb(app, nil)
	check("tray Quit turns the close prompt into the quit prompt", app.quit_prompt && !app.prompt_hide && !app.quit, failed)
	tray_disconnect_cb(app, nil)
	check("tray Disconnect closes the quit prompt", !app.quit_prompt && app.conn.phase == .Disconnected, failed)

	// The icon.
	icon := tray_icon(&app.logo)
	ok := icon != nil && icon.w == TRAY_ICON_SIZE && icon.h == TRAY_ICON_SIZE
	if ok {
		px := ([^]u8)(icon.pixels)
		corner := px[3]
		solid := 0
		for y in 0 ..< int(icon.h) {
			for x in 0 ..< int(icon.w) {
				if px[y * int(icon.pitch) + x * 4 + 3] > 200 {
					solid += 1
				}
			}
		}
		ok = corner == 0 && solid > 200
		sdl.DestroySurface(icon)
	}
	check("tray icon is a light letter on transparent", ok, failed)
	start(app, .Up, true)
}

// while_view goes back to the view v when it is the first view of the stack.
while_view :: proc(app: ^App, v: View) {
	for app.depth > 0 {
		pop_view(app)
	}
	app.conn.phase = .Disconnected
	app.stack[0] = v
	frame(app, 0)
}

// selftest_position checks the window position in the settings file and the
// display test that decides whether it is used.
selftest_position :: proc(failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	tmp, terr := os.temp_directory(context.temp_allocator)
	if terr != nil {
		check("temp directory", false, failed)
		return
	}
	dir := fmt.tprintf("%s/noirvpn-selftest-pos-%d", tmp, os.get_pid())
	path := fmt.tprintf("%s/settings.ini", dir)
	defer os.remove_all(dir)
	check("no position in a missing file", settings_load(path).pos == nil, failed)
	check("position is saved", settings_save_pos(path, 120, -40), failed)
	check("position round-trips", settings_load(path).pos == [2]i32{120, -40}, failed)
	_ = os.write_entire_file(path, "other = 1\nscale = 150\nwindow_x = 7\n")
	check("one coordinate is no position", settings_load(path).pos == nil, failed)
	_ = settings_save_pos(path, 5, 6)
	s := settings_load(path)
	check("position save keeps scale", s.scale == 150 && s.pos == [2]i32{5, 6}, failed)
	_ = settings_save(path, {scale = 200})
	s = settings_load(path)
	data, _ := os.read_entire_file(path, context.temp_allocator)
	check("scale save keeps position and other keys", s.scale == 200 && s.pos == [2]i32{5, 6} && strings.contains(string(data), "other = 1\n"), failed)
	_ = os.write_entire_file(path, "window_x = abc\nwindow_y = 4\n")
	check("bad coordinate is no position", settings_load(path).pos == nil, failed)

	areas := [2]sdl.Rect{{0, 0, 1920, 1080}, {1920, 0, 1280, 1024}}
	check("position on a display is used", on_display({0, 0}, areas[:]) && on_display({1920, 500}, areas[:]) && on_display({3199, 1023}, areas[:]), failed)
	check("position off every display is ignored", !on_display({-1, 0}, areas[:]) && !on_display({3200, 0}, areas[:]) && !on_display({500, 1080}, areas[:]) && !on_display({2000, 1030}, areas[:]), failed)
	check("off-screen saved position is ignored", saved_position({pos = [2]i32{90000, 90000}}) == nil, failed)
	if real := usable_areas(); len(real) > 0 {
		p := [2]i32{real[0].x + 3, real[0].y + 4}
		check("saved position on a display is restored", saved_position({pos = p}) == p, failed)
	}
}

// selftest_create drives the new-profile form in the simulation: plus menu,
// checks, port per transport, key view, Copy buttons.
selftest_create :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	n0 := app.n_profiles
	click(app, 332, 28)
	check("create: the plus menu opens", ui.menu_is_open(&app.u, MENU_PLUS), failed)
	click(app, 305, 66)
	check("create: New profile opens the form", current_view(app) == .Create, failed)
	e := &app.edit
	f := &e.f
	check("create: the defaults", ui.field_text(&f.port) == "1194" && f.transport == .Udp && f.key_type == .Ed25519 && f.pq == .Prefer && !f.advanced && e.created, failed)
	transport_set(f, .Tls)
	check("create: the port follows the transport", ui.field_text(&f.port) == "443", failed)
	transport_set(f, .Udp)
	click(app, 72, 296 + NAV_H)
	key(app, sdl.K_END)
	key(app, sdl.K_BACKSPACE)
	typ(app, "5")
	check("create: typing in the port field", ui.field_text(&f.port) == "1195" && f.port_edited, failed)
	transport_set(f, .Tcp)
	check("create: an edited port stays", ui.field_text(&f.port) == "1195", failed)
	create_submit(app)
	errs := form_errs(e)
	check("create: an empty host stops Create", current_view(app) == .Create && e.status_error && app.n_profiles == n0 && errs[.Host] != "" && errs[.Fingerprint] != "", failed)
	ui.field_set(&f.host, "vpn.example.com")
	ui.field_set(&f.fingerprint, "28617cc6ba524769ea9b5a7e4cc39608e7d95ffa1f4069f327df70d0b9fa2af2")
	ui.field_set(&f.mtu, "100")
	create_submit(app)
	check("create: an MTU out of range stops Create", current_view(app) == .Create && form_errs(e)[.Mtu] != "", failed)
	ui.field_set(&f.mtu, "1380")
	ui.field_set(&e.name, "Laptop")
	form := form_of(e)
	check("create: the form of the fields", form.fingerprint == SAMPLE_FP && form.port == 1195 && form.transport == "tcp" && form.mtu == "1380" && form.sni == "", failed)
	create_submit(app)
	check("create: Create shows the key view", current_view(app) == .Created && app.n_profiles == n0 + 1 && app.made.pin == SAMPLE_PIN && peers_line(app) == "Laptop " + SAMPLE_PIN, failed)
	check("create: the form keeps no key", f.ca == "" && f.tls_crypt == "", failed)
	frame(app, 0.016)
	ca := app.made.copy_at
	click(app, f32(ca.x + ca.w / 2), f32(ca.y + ca.h / 2))
	check("create: Copy puts the key pin as the line of the peers file", app.copied == peers_line(app), failed)
	got, _ := ui.clipboard_paste()
	check("create: the clipboard has the line", got == "Laptop " + SAMPLE_PIN, failed)
	click(app, 248 + WIN_W_WIDE - WIN_W, 692)
	check("create: Open profile shows the created profile", current_view(app) == .Profile && e.created && e.pin == SAMPLE_PIN && e.index == n0 && ui.field_text(&f.host) == "vpn.example.com", failed)
	check("create: the created profile has Block IPv6, off", !e.block_ipv6 && click_block6(app) && e.block_ipv6 && e.dirty, failed)
	key(app, sdl.K_ESCAPE)
	check("create: Escape goes back to the list", current_view(app) == .List && app.depth == 0, failed)
	delete_profile(app, n0)
}
