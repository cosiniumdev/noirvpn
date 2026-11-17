// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Gfx batches triangles. Shapes and glyphs sample one atlas texture (shapes: a solid
// white block, colour from vertices), so a frame is one draw call per clip
// rectangle. A frame goes to one of two targets: SDL_RenderGeometry of an SDL
// renderer, or the CPU rasterizer (raster.odin) into a buffer of pixels. Public
// coordinates are logical units; Gfx multiplies them by scale to get device pixels.

import "core:hash/xxhash"
import "core:math"
import "core:slice"
import sdl "vendor:sdl3"

ATLAS_SIZE :: 2048 // side of the glyph atlas; larger at big scales
WHITE_BLOCK :: 4 // side of the solid white block at the atlas origin

Rectf :: struct {
	x, y, w, h: f32,
}

// One draw of a recorded frame: its clip, and its parts of rec_verts and rec_idx
// (the indices are relative to the start of the vertices of the draw).
Draw :: struct {
	clip:   Maybe(sdl.Rect),
	v0, vn: int,
	i0, in_: int,
}

// Frame_Buffer_Proc returns the pixels for a frame of w x h pixels, or false when it has
// none free. The CPU target calls it only for a frame that it draws.
Frame_Buffer_Proc :: #type proc(data: rawptr, w, h: i32) -> (Raster_Target, bool)

Gfx :: struct {
	r:          ^sdl.Renderer, // nil for the CPU target
	scale:      f32, // draw units per logical unit
	text_scale: f32, // device pixels per logical unit, for glyphs; equals scale unless supersampling
	verts:      [dynamic]sdl.Vertex,
	idx:        [dynamic]i32,
	white_uv:   sdl.FPoint,
	atlas:      Atlas,
	fonts:      [Font_Id]Face,
	text_lut:   [256]u8, // coverage curve for glyph alpha
	clip:       Maybe(sdl.Rect),
	atlas_dim:  i32,
	subpx:      int, // glyph offsets per device pixel
	shift:      f32, // added to shape vertices: the software renderer truncates them
	// The frame is recorded (draws, rec_verts, rec_idx) and sent to SDL at gfx_end,
	// unless it equals the frame that is on screen: then nothing is drawn or presented.
	draws:      [dynamic]Draw,
	rec_verts:  [dynamic]sdl.Vertex,
	rec_idx:    [dynamic]i32,
	clear_color: Color,
	last_hash:  u64,
	have_last:  bool,
	always:     bool, // draw every frame (tests, --screens read the pixels back)
	force:      bool, // draw the next frame even when it is unchanged (the window was exposed)
	skipped:    int, // frames that were unchanged
	// What the last frame drew, for --stats: vertices, indices and RenderGeometry calls.
	frame_verts, frame_idx, frame_calls: int,
	// Pixel size of the render target, and the logical size derived from it. The CPU
	// target takes it from gfx_set_pixels.
	px_w, px_h: i32,
	// The CPU target asks acquire for the pixels of each frame it draws. stalled is set
	// when it had none: the frame is not drawn and the caller tries again soon.
	acquire:      Frame_Buffer_Proc,
	acquire_data: rawptr,
	stalled:      bool,
}

// gfx_init creates the atlas and loads the embedded fonts. A nil renderer selects the
// CPU target: set acquire before the first frame.
gfx_init :: proc(g: ^Gfx, r: ^sdl.Renderer, scale: f32) -> bool {
	g.r = r
	g.scale = scale
	g.text_scale = scale
	if r != nil {
		if name := sdl.GetRendererName(r); name != nil && string(name) == "software" {
			g.shift = 0.5
		}
	}
	if !fonts_load(g) {
		return false
	}
	g.atlas_dim = ATLAS_SIZE
	g.subpx = SUBPIXEL_STEPS
	set_text_gamma(g, TEXT_GAMMA)
	atlas_reset(g)
	return true
}

gfx_destroy :: proc(g: ^Gfx) {
	atlas_destroy(&g.atlas)
	delete(g.verts)
	delete(g.idx)
	delete(g.draws)
	delete(g.rec_verts)
	delete(g.rec_idx)
}

// gfx_set_scale changes the density. The atlas holds glyphs of the old size, so it is cleared.
gfx_set_scale :: proc(g: ^Gfx, scale: f32) {
	if scale == g.scale {
		return
	}
	g.scale = scale
	g.text_scale = scale
	atlas_reset(g)
}

// gfx_set_supersample prepares for a draw scale that is later averaged down to
// the given density. Shapes use the draw scale; glyphs still use the density.
gfx_set_supersample :: proc(g: ^Gfx, density: f32) {
	g.text_scale = density
	atlas_reset(g)
}

// gfx_set_pixels sets the pixel size of the CPU target.
gfx_set_pixels :: proc(g: ^Gfx, w, h: i32) {
	g.px_w, g.px_h = w, h
}

// gfx_size is the logical size of the render target.
gfx_size :: proc(g: ^Gfx) -> (w, h: i32) {
	pw, ph: i32
	if g.r != nil && sdl.GetCurrentRenderOutputSize(g.r, &pw, &ph) {
		g.px_w, g.px_h = pw, ph
	}
	return i32(math.round(f32(g.px_w) / g.scale)), i32(math.round(f32(g.px_h) / g.scale))
}

// gfx_begin starts a frame: it reads the target size and clears it.
gfx_begin :: proc(g: ^Gfx, clear_color: Color) {
	if g.atlas.full {
		atlas_reset(g)
	}
	_, _ = gfx_size(g)
	g.clip = nil
	g.clear_color = clear_color
	clear(&g.verts)
	clear(&g.idx)
	clear(&g.draws)
	clear(&g.rec_verts)
	clear(&g.rec_idx)
	g.frame_verts, g.frame_idx, g.frame_calls = 0, 0, 0
}

// frame_hash is a hash of everything the recorded frame draws. XXH3 reads the 1.5 MB of a
// busy frame in a fraction of a millisecond.
@(private)
frame_hash :: proc(g: ^Gfx) -> u64 {
	h := xxhash.XXH3_64_with_seed(slice.bytes_from_ptr(&g.clear_color, size_of(Color)), 0)
	size := [2]i32{g.px_w, g.px_h}
	h = xxhash.XXH3_64_with_seed(slice.bytes_from_ptr(&size, size_of(size)), h)
	h = xxhash.XXH3_64_with_seed(slice.to_bytes(g.draws[:]), h)
	h = xxhash.XXH3_64_with_seed(slice.to_bytes(g.rec_verts[:]), h)
	return xxhash.XXH3_64_with_seed(slice.to_bytes(g.rec_idx[:]), h)
}

// gfx_end ends the frame. It draws the recorded draws (through SDL, or into the
// pixels of the CPU target) and returns true, or returns false when the frame equals
// the one on screen: nothing is drawn, so the caller does not present. A presented
// frame keeps the graphics memory of the window in use (hundreds of MB on some
// systems), so a poll that changes nothing on screen must not cause one. The CPU
// target also returns false when it has no pixels (stalled): the frame stays due.
gfx_end :: proc(g: ^Gfx) -> (drawn: bool) {
	flush(g)
	h := frame_hash(g)
	g.stalled = false
	if !g.always && !g.force && g.have_last && h == g.last_hash {
		g.skipped += 1
		return false
	}
	if g.r == nil {
		t, ok := g.acquire(g.acquire_data, g.px_w, g.px_h)
		if !ok {
			g.stalled = true
			return false
		}
		g.last_hash, g.have_last, g.force = h, true, false
		raster_frame(t, g.clear_color, g.draws[:], g.rec_verts[:], g.rec_idx[:], g.atlas.pixels, int(g.atlas.dim))
		return true
	}
	g.last_hash, g.have_last, g.force = h, true, false
	_ = sdl.SetRenderClipRect(g.r, nil)
	c := g.clear_color
	_ = sdl.SetRenderDrawColor(g.r, c.r, c.g, c.b, 255)
	_ = sdl.RenderClear(g.r)
	atlas_commit(&g.atlas)
	for d in g.draws {
		if clip, ok := d.clip.?; ok {
			_ = sdl.SetRenderClipRect(g.r, &clip)
		} else {
			_ = sdl.SetRenderClipRect(g.r, nil)
		}
		_ = sdl.RenderGeometry(g.r, g.atlas.tex, &g.rec_verts[d.v0], i32(d.vn), &g.rec_idx[d.i0], i32(d.in_))
	}
	_ = sdl.SetRenderClipRect(g.r, nil)
	return true
}

// flush records the batch (the draw of the vertices and indices so far).
flush :: proc(g: ^Gfx) {
	if len(g.idx) > 0 {
		g.frame_verts += len(g.verts)
		g.frame_idx += len(g.idx)
		g.frame_calls += 1
		append(&g.draws, Draw{g.clip, len(g.rec_verts), len(g.verts), len(g.rec_idx), len(g.idx)})
		append(&g.rec_verts, ..g.verts[:])
		append(&g.rec_idx, ..g.idx[:])
	}
	clear(&g.verts)
	clear(&g.idx)
}

// set_clip limits drawing to r (logical units), or lifts the limit when r is nil.
set_clip :: proc(g: ^Gfx, r: Maybe(Rectf)) {
	flush(g)
	if rect, ok := r.?; ok {
		x0 := i32(math.round(rect.x * g.scale))
		y0 := i32(math.round(rect.y * g.scale))
		x1 := i32(math.round((rect.x + rect.w) * g.scale))
		y1 := i32(math.round((rect.y + rect.h) * g.scale))
		g.clip = sdl.Rect{x0, y0, max(x1 - x0, 0), max(y1 - y0, 0)}
	} else {
		g.clip = nil
	}
}

@(private)
fcolor :: #force_inline proc "contextless" (c: Color, alpha: f32 = 1) -> sdl.FColor {
	return {f32(c.r) / 255, f32(c.g) / 255, f32(c.b) / 255, f32(c.a) / 255 * alpha}
}

@(private)
vtx :: #force_inline proc(g: ^Gfx, x, y: f32, c: sdl.FColor) -> i32 {
	append(&g.verts, sdl.Vertex{{x + g.shift, y + g.shift}, c, g.white_uv})
	return i32(len(g.verts) - 1)
}

@(private)
tri :: #force_inline proc(g: ^Gfx, a, b, c: i32) {
	append(&g.idx, a, b, c)
}

@(private)
quad4 :: #force_inline proc(g: ^Gfx, a, b, c, d: i32) {
	append(&g.idx, a, b, c, a, c, d)
}

// fill_rect draws a rectangle with hard edges snapped to device pixels. It is the
// path for backgrounds, bars and separator lines.
fill_rect :: proc(g: ^Gfx, r: Rectf, c: Color) {
	if c.a == 0 {
		return
	}
	x0 := math.round(r.x * g.scale)
	y0 := math.round(r.y * g.scale)
	x1 := math.round((r.x + r.w) * g.scale)
	y1 := math.round((r.y + r.h) * g.scale)
	if x1 <= x0 || y1 <= y0 {
		return
	}
	col := fcolor(c)
	a := vtx(g, x0, y0, col)
	b := vtx(g, x1, y0, col)
	d := vtx(g, x1, y1, col)
	e := vtx(g, x0, y1, col)
	quad4(g, a, b, d, e)
}

// fill_vgradient draws a rectangle with a vertical gradient, top colour to bottom
// colour. It is the path for the window background.
fill_vgradient :: proc(g: ^Gfx, r: Rectf, top, bottom: Color) {
	x0 := math.round(r.x * g.scale)
	y0 := math.round(r.y * g.scale)
	x1 := math.round((r.x + r.w) * g.scale)
	y1 := math.round((r.y + r.h) * g.scale)
	if x1 <= x0 || y1 <= y0 {
		return
	}
	ct, cb := fcolor(top), fcolor(bottom)
	a := vtx(g, x0, y0, ct)
	b := vtx(g, x1, y0, ct)
	d := vtx(g, x1, y1, cb)
	e := vtx(g, x0, y1, cb)
	quad4(g, a, b, d, e)
}
