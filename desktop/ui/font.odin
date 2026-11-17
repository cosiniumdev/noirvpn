// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Fonts and the glyph atlas. stb_truetype draws each glyph on first use, at the
// device pixel size and one of four horizontal sub-pixel offsets. Glyphs are
// white with coverage in alpha, so the vertex colour tints them. Text measures
// in logical units, independent of density.

import "core:math"
import stbi "vendor:stb/image"
import sdl "vendor:sdl3"
import stbtt "vendor:stb/truetype"

// Embedded fonts.
//   - Google Sans Flex: SIL Open Font License (fonts/GOOGLESANSFLEX-OFL.txt);
//     static faces from fonts/make-fonts.sh.
//   - DejaVu Sans Mono: Bitstream Vera licence (fonts/DEJAVU-LICENSE.txt).
SANS_REGULAR :: #load("fonts/GoogleSansFlex-Regular.ttf")
SANS_MEDIUM :: #load("fonts/GoogleSansFlex-Medium.ttf")
SANS_SEMI_BOLD :: #load("fonts/GoogleSansFlex-SemiBold.ttf")
SANS_BOLD :: #load("fonts/GoogleSansFlex-Bold.ttf")
DEJAVU_MONO :: #load("fonts/DejaVuSansMono.ttf")

SUBPIXEL_STEPS :: 4 // horizontal glyph offsets per pixel
LINE_HEIGHT_FACTOR :: 1.26 // the line box of Google Sans Flex, as a multiple of the size

// Glyph alpha is raised to 1/TEXT_GAMMA. Light text on a dark ground looks thin
// without it.
TEXT_GAMMA :: 1.4

Face :: struct {
	info:      stbtt.fontinfo,
	ascent:    f32, // in em units
	descent:   f32,
	em_scale:  f32, // stb scale for a size of 1 pixel
	loaded:    bool,
}

Glyph :: struct {
	x, y, w, h: i32, // place in the atlas
	dx, dy:     i32, // offset of the bitmap from the pen and the baseline
}

Glyph_Key :: struct {
	cp:   rune,
	font: Font_Id,
	size: u32, // device pixel size times 16
	sub:  u8,
}

Mask_Key :: struct {
	id:   uintptr,
	w, h: i32,
}

Atlas :: struct {
	tex:                    ^sdl.Texture,
	dim:                    i32, // side of the texture in pixels
	pixels:                 []u8, // alpha of each texel: the CPU copy that atlas_commit uploads, and the CPU rasterizer reads
	dirty:                  sdl.Rect, // the changed part of pixels, not uploaded yet; w = 0 for none (kept only with a texture)
	pack_x, pack_y, shelf_h: i32,
	full:                   bool,
	glyphs:                 map[Glyph_Key]Glyph,
	masks:                  map[Mask_Key]Glyph,
}

fonts_load :: proc(g: ^Gfx) -> bool {
	srcs := [Font_Id][]byte {
		.Regular   = SANS_REGULAR,
		.Medium    = SANS_MEDIUM,
		.Semi_Bold = SANS_SEMI_BOLD,
		.Bold      = SANS_BOLD,
		.Mono      = DEJAVU_MONO,
	}
	for src, id in srcs {
		f := &g.fonts[id]
		if !stbtt.InitFont(&f.info, raw_data(src), stbtt.GetFontOffsetForIndex(raw_data(src), 0)) {
			return false
		}
		asc, desc, gap: i32
		stbtt.GetFontVMetrics(&f.info, &asc, &desc, &gap)
		f.em_scale = stbtt.ScaleForMappingEmToPixels(&f.info, 1)
		f.ascent = f32(asc) * f.em_scale
		f.descent = f32(-desc) * f.em_scale
		f.loaded = true
	}
	return true
}

set_text_gamma :: proc(g: ^Gfx, gamma: f32) {
	for i in 0 ..< 256 {
		g.text_lut[i] = u8(math.pow(f32(i) / 255, 1 / gamma) * 255 + 0.5)
	}
}

atlas_destroy :: proc(a: ^Atlas) {
	if a.tex != nil {
		sdl.DestroyTexture(a.tex)
		a.tex = nil
	}
	delete(a.glyphs)
	delete(a.masks)
	delete(a.pixels)
	a^ = {}
}

// atlas_reset empties the atlas, creating its texture the first time (the CPU target
// has none). The corner holds a white block that shapes sample.
atlas_reset :: proc(g: ^Gfx) {
	a := &g.atlas
	flush(g)
	if a.tex != nil && a.dim != g.atlas_dim {
		sdl.DestroyTexture(a.tex)
		a.tex = nil
	}
	a.dim = g.atlas_dim
	if a.tex == nil && g.r != nil {
		a.tex = sdl.CreateTexture(g.r, .RGBA32, .STATIC, a.dim, a.dim)
		_ = sdl.SetTextureBlendMode(a.tex, sdl.BLENDMODE_BLEND)
		_ = sdl.SetTextureScaleMode(a.tex, .NEAREST)
	}
	g.force = true // glyph positions changed: draw the next frame
	clear(&a.glyphs)
	clear(&a.masks)
	if n := int(a.dim) * int(a.dim); len(a.pixels) != n {
		delete(a.pixels)
		a.pixels = make([]u8, n)
	} else {
		for &p in a.pixels {
			p = 0
		}
	}
	a.dirty = {}
	white: [WHITE_BLOCK * WHITE_BLOCK]byte
	for i in 0 ..< len(white) {
		white[i] = 255
	}
	atlas_store(a, 0, 0, WHITE_BLOCK, WHITE_BLOCK, white[:], nil)
	a.pack_x, a.pack_y, a.shelf_h = WHITE_BLOCK + 1, 0, WHITE_BLOCK + 1
	a.full = false
	c := f32(WHITE_BLOCK) / 2 / f32(a.dim)
	g.white_uv = {c, c}
}

// atlas_alloc finds room for a w x h bitmap, or reports that the atlas is full.
atlas_alloc :: proc(a: ^Atlas, w, h: i32) -> (x, y: i32, ok: bool) {
	if w + 1 > a.dim || h + 1 > a.dim {
		return 0, 0, false
	}
	if a.pack_x + w + 1 > a.dim {
		a.pack_x, a.pack_y, a.shelf_h = 0, a.pack_y + a.shelf_h, 0
	}
	if a.pack_y + h + 1 > a.dim {
		a.full = true
		return 0, 0, false
	}
	x, y = a.pack_x, a.pack_y
	a.pack_x += w + 1
	a.shelf_h = max(a.shelf_h, h + 1)
	return x, y, true
}

// atlas_store puts a bitmap of coverage values in the CPU copy of the atlas (mapped
// through lut, when there is one) and extends the changed area. The GPU gets it at
// the next atlas_commit; an atlas with no texture has no upload to track.
atlas_store :: proc(a: ^Atlas, x, y, w, h: i32, alpha: []byte, lut: ^[256]u8) {
	for row in 0 ..< int(h) {
		dst := a.pixels[(int(y) + row) * int(a.dim) + int(x):][:w]
		src := alpha[row * int(w):][:w]
		for v, i in src {
			dst[i] = lut != nil ? lut[v] : v
		}
	}
	if a.tex == nil {
		return
	}
	if a.dirty.w == 0 {
		a.dirty = {x, y, w, h}
		return
	}
	x0, y0 := min(a.dirty.x, x), min(a.dirty.y, y)
	x1, y1 := max(a.dirty.x + a.dirty.w, x + w), max(a.dirty.y + a.dirty.h, y + h)
	a.dirty = {x0, y0, x1 - x0, y1 - y0}
}

atlas_upload :: proc(a: ^Atlas, x, y, w, h: i32, alpha: []byte, lut: ^[256]u8) {
	atlas_store(a, x, y, w, h, alpha, lut)
}

// atlas_commit uploads the changed area of the atlas to the GPU: a few calls for a
// frame, in bands. SDL creates a staging texture and a command buffer for each
// UpdateTexture call, so one call for each glyph made the driver reserve hundreds
// of megabytes at the start.
atlas_commit :: proc(a: ^Atlas) {
	r := a.dirty
	if r.w == 0 || a.tex == nil {
		return
	}
	a.dirty = {}
	BAND :: 128 // rows for each call
	for y := r.y; y < r.y + r.h; y += BAND {
		bh := min(BAND, r.y + r.h - y)
		rgba := make([]byte, int(r.w * bh * 4), context.temp_allocator)
		for row in 0 ..< int(bh) {
			src := a.pixels[(int(y) + row) * int(a.dim) + int(r.x):][:r.w]
			for v, col in src {
				i := (row * int(r.w) + col) * 4
				rgba[i + 0], rgba[i + 1], rgba[i + 2], rgba[i + 3] = 255, 255, 255, v
			}
		}
		rect := sdl.Rect{r.x, y, r.w, bh}
		_ = sdl.UpdateTexture(a.tex, &rect, raw_data(rgba), r.w * 4)
	}
}

@(private)
glyph_get :: proc(g: ^Gfx, cp: rune, font: Font_Id, size_px: f32, sub: u8) -> Glyph {
	key := Glyph_Key{cp, font, u32(size_px * 16 + 0.5), sub}
	if gl, ok := g.atlas.glyphs[key]; ok {
		return gl
	}
	face := &g.fonts[font]
	index := stbtt.FindGlyphIndex(&face.info, cp)
	scale := face.em_scale * size_px
	shift := f32(sub) / f32(g.subpx)
	x0, y0, x1, y1: i32
	stbtt.GetGlyphBitmapBoxSubpixel(&face.info, index, scale, scale, shift, 0, &x0, &y0, &x1, &y1)
	w, h := x1 - x0, y1 - y0
	gl := Glyph{dx = x0, dy = y0}
	if w > 0 && h > 0 {
		gx, gy, ok := atlas_alloc(&g.atlas, w, h)
		if !ok {
			return {}
		}
		alpha := make([]byte, int(w * h), context.temp_allocator)
		stbtt.MakeGlyphBitmapSubpixel(&face.info, raw_data(alpha), w, h, w, scale, scale, shift, 0, index)
		atlas_upload(&g.atlas, gx, gy, w, h, alpha, &g.text_lut)
		gl.x, gl.y, gl.w, gl.h = gx, gy, w, h
	}
	g.atlas.glyphs[key] = gl
	return gl
}

// advance_units is the advance of cp in em fractions.
@(private)
advance :: proc(face: ^Face, index: i32) -> f32 {
	adv, lsb: i32
	stbtt.GetGlyphHMetrics(&face.info, index, &adv, &lsb)
	return f32(adv) * face.em_scale
}

// line_height is the height of one line of text in logical units.
line_height :: proc(st: Text_Style) -> f32 {
	return math.ceil(st.size * LINE_HEIGHT_FACTOR)
}

// baseline is the distance from the top of a line box to its baseline.
baseline :: proc(g: ^Gfx, st: Text_Style) -> f32 {
	face := &g.fonts[st.font]
	em := face.ascent + face.descent
	return math.round((line_height(st) - em * st.size) / 2 + face.ascent * st.size)
}

// text_width measures s in logical units.
text_width :: proc(g: ^Gfx, st: Text_Style, s: string) -> f32 {
	face := &g.fonts[st.font]
	w: f32
	prev: i32 = -1
	for r in s {
		index := stbtt.FindGlyphIndex(&face.info, r)
		if prev >= 0 {
			w += f32(stbtt.GetGlyphKernAdvance(&face.info, prev, index)) * face.em_scale * st.size
		}
		w += advance(face, index) * st.size
		prev = index
	}
	return w
}

// draw_text draws s with the top of its line box at y and its left edge at x.
// It returns the width.
draw_text :: proc(g: ^Gfx, st: Text_Style, x, y: f32, s: string, c: Color) -> f32 {
	face := &g.fonts[st.font]
	// Glyphs are drawn at the text scale, which is the device density. When the
	// frame is rendered larger and averaged down, each glyph pixel is a block of ss.
	ts := g.text_scale
	ss := g.scale / ts
	size_px := st.size * ts
	base := math.round((y + baseline(g, st)) * ts)
	pen := x * ts
	col := fcolor(c)
	inv := 1 / f32(g.atlas.dim)
	prev: i32 = -1
	for r in s {
		index := stbtt.FindGlyphIndex(&face.info, r)
		if prev >= 0 {
			pen += f32(stbtt.GetGlyphKernAdvance(&face.info, prev, index)) * face.em_scale * size_px
		}
		prev = index
		// Quarter-pixel positions: whole pixel in ix, quarter in sub.
		q := math.round(pen * f32(g.subpx))
		ix := math.floor(q / f32(g.subpx))
		sub := u8(q - ix * f32(g.subpx))
		gl := glyph_get(g, r, st.font, size_px, sub)
		if gl.w > 0 {
			gx := (ix + f32(gl.dx)) * ss
			gy := (base + f32(gl.dy)) * ss
			u0, v0 := f32(gl.x) * inv, f32(gl.y) * inv
			u1, v1 := f32(gl.x + gl.w) * inv, f32(gl.y + gl.h) * inv
			b := i32(len(g.verts))
			gw, gh := f32(gl.w) * ss, f32(gl.h) * ss
			append(
				&g.verts,
				sdl.Vertex{{gx, gy}, col, {u0, v0}},
				sdl.Vertex{{gx + gw, gy}, col, {u1, v0}},
				sdl.Vertex{{gx + gw, gy + gh}, col, {u1, v1}},
				sdl.Vertex{{gx, gy + gh}, col, {u0, v1}},
			)
			append(&g.idx, b, b + 1, b + 2, b, b + 2, b + 3)
		}
		pen += advance(face, index) * size_px
	}
	return (pen / ts) - x
}

// Mask is an 8-bit coverage image, for example the logo. It is scaled to the
// device size when drawn.
Mask :: struct {
	w, h: i32,
	px:   []byte,
}

mask_from_png :: proc(data: []byte) -> (m: Mask, ok: bool) {
	w, h, comp: i32
	pix := stbi.load_from_memory(raw_data(data), i32(len(data)), &w, &h, &comp, 1)
	if pix == nil {
		return {}, false
	}
	m = {w, h, pix[:int(w * h)]}
	return m, true
}

// mask_from_png_light generates a mask from the light parts of a colour image:
// coverage = luminance times alpha, so a white mark on a dark or clear ground
// keeps its shape.
mask_from_png_light :: proc(data: []byte) -> (m: Mask, ok: bool) {
	w, h, comp: i32
	pix := stbi.load_from_memory(raw_data(data), i32(len(data)), &w, &h, &comp, 4)
	if pix == nil {
		return {}, false
	}
	defer stbi.image_free(pix)
	px := make([]byte, int(w * h))
	for i in 0 ..< int(w * h) {
		p := pix[i * 4:]
		lum := (299 * u32(p[0]) + 587 * u32(p[1]) + 114 * u32(p[2])) / 1000
		// The dark ground and a faint edge line of it stay clear.
		lum = lum > 112 ? (lum - 112) * 255 / 143 : 0
		px[i] = u8(lum * u32(p[3]) / 255)
	}
	return {w, h, px}, true
}

// draw_mask draws m with its top left at x, y, w logical units wide, h high.
// The position is rounded to a device pixel so the edges stay sharp.
draw_mask :: proc(g: ^Gfx, m: ^Mask, x, y, w, h: f32, c: Color) {
	ts := g.text_scale
	ss := g.scale / ts
	pw := i32(math.round(w * ts))
	ph := i32(math.round(h * ts))
	if pw <= 0 || ph <= 0 {
		return
	}
	key := Mask_Key{uintptr(raw_data(m.px)), pw, ph}
	gl, found := g.atlas.masks[key]
	if !found {
		gx, gy, ok := atlas_alloc(&g.atlas, pw, ph)
		if !ok {
			return
		}
		out := make([]byte, int(pw * ph), context.temp_allocator)
		// Box filter: each output pixel averages the source area it covers.
		for oy in 0 ..< ph {
			sy0 := f32(oy) * f32(m.h) / f32(ph)
			sy1 := f32(oy + 1) * f32(m.h) / f32(ph)
			for ox in 0 ..< pw {
				sx0 := f32(ox) * f32(m.w) / f32(pw)
				sx1 := f32(ox + 1) * f32(m.w) / f32(pw)
				sum, area: f32
				for sy := i32(sy0); sy < min(i32(math.ceil(sy1)), m.h); sy += 1 {
					wy := min(f32(sy + 1), sy1) - max(f32(sy), sy0)
					for sx := i32(sx0); sx < min(i32(math.ceil(sx1)), m.w); sx += 1 {
						wx := min(f32(sx + 1), sx1) - max(f32(sx), sx0)
						sum += f32(m.px[sy * m.w + sx]) * wx * wy
						area += wx * wy
					}
				}
				out[oy * pw + ox] = u8(sum / max(area, 0.0001) + 0.5)
			}
		}
		lut: [256]u8
		for i in 0 ..< 256 {
			lut[i] = u8(i)
		}
		atlas_upload(&g.atlas, gx, gy, pw, ph, out, &lut)
		gl = {gx, gy, pw, ph, 0, 0}
		g.atlas.masks[key] = gl
	}
	gx := math.round(x * ts) * ss
	gy := math.round(y * ts) * ss
	inv := 1 / f32(g.atlas.dim)
	u0, v0 := f32(gl.x) * inv, f32(gl.y) * inv
	u1, v1 := f32(gl.x + gl.w) * inv, f32(gl.y + gl.h) * inv
	col := fcolor(c)
	b := i32(len(g.verts))
	append(
		&g.verts,
		sdl.Vertex{{gx, gy}, col, {u0, v0}},
		sdl.Vertex{{gx + f32(pw) * ss, gy}, col, {u1, v0}},
		sdl.Vertex{{gx + f32(pw) * ss, gy + f32(ph) * ss}, col, {u1, v1}},
		sdl.Vertex{{gx, gy + f32(ph) * ss}, col, {u0, v1}},
	)
	append(&g.idx, b, b + 1, b + 2, b, b + 2, b + 3)
}
