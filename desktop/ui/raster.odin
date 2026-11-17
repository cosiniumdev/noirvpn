// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// A CPU rasterizer for a recorded frame (Gfx.draws, rec_verts, rec_idx). It does what
// the GPU does with this data: triangles sampled at pixel centres with the top-left
// fill rule, vertex colours interpolated as straight alpha and blended source-over
// onto an opaque target, and nearest sampling of one alpha atlas. Positions snap to
// 1/256 pixel and the edge functions are integers, so triangles that share an edge
// paint each pixel exactly once. Axis-aligned quads (fills, the window gradient and
// 1:1 glyph quads) are drawn by rows.

import "core:math"
import sdl "vendor:sdl3"

// Raster_Target is a buffer of pixels in the byte order B, G, R, A (a u32 holds
// 0xAARRGGBB). The rasterizer writes alpha 255.
Raster_Target :: struct {
	pixels: [^]u32,
	stride: int, // pixels in a row
	w, h:   int,
}

@(private = "file")
SUB :: 256 // positions snap to 1/SUB pixel
@(private = "file")
HALF :: SUB / 2
@(private = "file")
LIMIT :: 100000 // largest accepted position, in pixels

// Clip is a pixel rectangle: x1 and y1 are the first pixels outside.
@(private = "file")
Clip :: struct {
	x0, y0, x1, y1: int,
}

@(private = "file")
Raster :: struct {
	t:     Raster_Target,
	clip:  Clip,
	atlas: [^]u8,
	dim:   int,
}

// Vert is a vertex as the fill loops use it: the position in 1/SUB pixels, the colour
// with red, green and blue in 0 to 255 and alpha in 0 to 1, and the texel position.
@(private = "file")
Vert :: struct {
	x, y:       i64,
	r, g, b, a: f32,
	u, v:       f32,
}

@(private = "file")
vert_of :: #force_inline proc "contextless" (v: sdl.Vertex, dim: f32) -> (out: Vert, ok: bool) {
	px, py := v.position.x, v.position.y
	if !(abs(px) < LIMIT && abs(py) < LIMIT) {
		return {}, false
	}
	out.x = round_fixed(px)
	out.y = round_fixed(py)
	out.r, out.g, out.b, out.a = v.color.r * 255, v.color.g * 255, v.color.b * 255, v.color.a
	out.u, out.v = v.tex_coord.x * dim, v.tex_coord.y * dim
	return out, true
}

// round_fixed is p in 1/SUB pixels, rounded to the nearest.
@(private = "file")
round_fixed :: #force_inline proc "contextless" (p: f32) -> i64 {
	v := p * SUB + 0.5
	i := i64(v)
	return f32(i) > v ? i - 1 : i
}

@(private = "file")
floor_div :: #force_inline proc "contextless" (a, b: i64) -> i64 {
	q := a / b
	if a % b != 0 && a < 0 {
		q -= 1
	}
	return q
}

// first_pixel is the first pixel whose centre is at or after p (1/SUB pixels).
@(private = "file")
first_pixel :: #force_inline proc "contextless" (p: i64) -> i64 {
	return -floor_div(HALF - p, SUB)
}

@(private = "file")
pack :: #force_inline proc "contextless" (r, g, b: f32) -> u32 {
	return 0xff000000 | u32(r + 0.5) << 16 | u32(g + 0.5) << 8 | u32(b + 0.5)
}

// over blends the colour (r, g, b in 0 to 255) with alpha a over the opaque pixel d.
@(private = "file")
over :: #force_inline proc "contextless" (d: u32, r, g, b, a: f32) -> u32 {
	dr, dg, db := f32((d >> 16) & 0xff), f32((d >> 8) & 0xff), f32(d & 0xff)
	return pack(dr + (r - dr) * a, dg + (g - dg) * a, db + (b - db) * a)
}

raster_clear :: proc(t: Raster_Target, c: Color) {
	px := u32(0xff000000) | u32(c.r) << 16 | u32(c.g) << 8 | u32(c.b)
	for y in 0 ..< t.h {
		row := t.pixels[y * t.stride:][:t.w]
		for &p in row {
			p = px
		}
	}
}

// raster_frame draws the recorded frame into t: the clear colour, then each draw
// with its clip. The atlas holds one alpha byte for each texel, dim x dim.
raster_frame :: proc(t: Raster_Target, clear_color: Color, draws: []Draw, verts: []sdl.Vertex, idx: []i32, atlas: []u8, dim: int) {
	raster_clear(t, clear_color)
	if dim <= 0 || len(atlas) < dim * dim {
		return
	}
	ra := Raster {
		t     = t,
		atlas = raw_data(atlas),
		dim   = dim,
	}
	for d in draws {
		ra.clip = {0, 0, t.w, t.h}
		if c, ok := d.clip.?; ok {
			ra.clip = {max(int(c.x), 0), max(int(c.y), 0), min(int(c.x) + int(c.w), t.w), min(int(c.y) + int(c.h), t.h)}
		}
		if ra.clip.x0 >= ra.clip.x1 || ra.clip.y0 >= ra.clip.y1 {
			continue
		}
		raster_draw(&ra, verts[d.v0:d.v0 + d.vn], idx[d.i0:d.i0 + d.in_])
	}
}

@(private = "file")
raster_draw :: proc(ra: ^Raster, verts: []sdl.Vertex, idx: []i32) {
	fdim := f32(ra.dim)
	n := len(verts)
	at :: #force_inline proc "contextless" (verts: []sdl.Vertex, i: i32, n: int, fdim: f32) -> (v: Vert, ok: bool) {
		if i < 0 || int(i) >= n {
			return {}, false
		}
		return vert_of(verts[i], fdim)
	}
	i := 0
	for i + 3 <= len(idx) {
		v0, ok0 := at(verts, idx[i], n, fdim)
		v1, ok1 := at(verts, idx[i + 1], n, fdim)
		v2, ok2 := at(verts, idx[i + 2], n, fdim)
		if !(ok0 && ok1 && ok2) {
			i += 3
			continue
		}
		// Two triangles (a, b, c) and (a, c, d) may be one rectangle.
		if i + 6 <= len(idx) && idx[i] == idx[i + 3] && idx[i + 2] == idx[i + 4] {
			if v3, ok3 := at(verts, idx[i + 5], n, fdim); ok3 && raster_quad(ra, v0, v1, v2, v3) {
				i += 6
				continue
			}
		}
		raster_tri(ra, v0, v1, v2)
		i += 3
	}
}

// Edge is one side of a triangle: the pixel p is inside when s * x + k(y) >= 0, where
// k(y) = ey * y + c, with x and y of the pixel centre in 1/SUB pixels.
@(private = "file")
Edge :: struct {
	s, ey, c: i64,
}

@(private = "file")
edge_of :: #force_inline proc "contextless" (p, q: Vert) -> Edge {
	dx, dy := q.x - p.x, q.y - p.y
	e := Edge {
		s  = -dy * SUB,
		ey = dx,
		c  = dy * p.x - dx * p.y - dy * HALF,
	}
	// Edges on the left and at the top own the pixels whose centre lies on them.
	if !(dy < 0 || (dy == 0 && dx > 0)) {
		e.c -= 1
	}
	return e
}

// Plane is an attribute that changes linearly over a triangle.
@(private = "file")
Plane :: struct {
	v0, dx, dy: f32,
}

@(private = "file")
plane_of :: #force_inline proc "contextless" (a0, a1, a2: f32, bx, by, cx, cy: f32, inv: f32) -> Plane {
	d1, d2 := a1 - a0, a2 - a0
	return {a0, (d1 * cy - d2 * by) * inv, (d2 * bx - d1 * cx) * inv}
}

@(private = "file")
raster_tri :: proc(ra: ^Raster, v0, v1, v2: Vert) #no_bounds_check {
	a, b, c := v0, v1, v2
	area2 := (b.x - a.x) * (c.y - a.y) - (c.x - a.x) * (b.y - a.y)
	if area2 == 0 {
		return
	}
	if area2 < 0 {
		b, c = c, b
		area2 = -area2
	}
	clip := ra.clip
	px0 := max(int(first_pixel(min(a.x, b.x, c.x))), clip.x0)
	px1 := min(int(first_pixel(max(a.x, b.x, c.x))), clip.x1 - 1)
	py0 := max(int(first_pixel(min(a.y, b.y, c.y))), clip.y0)
	py1 := min(int(first_pixel(max(a.y, b.y, c.y))), clip.y1 - 1)
	if px0 > px1 || py0 > py1 {
		return
	}
	edges := [3]Edge{edge_of(a, b), edge_of(b, c), edge_of(c, a)}

	// Attribute planes, from the first vertex, per pixel.
	bx, by := f32(b.x - a.x), f32(b.y - a.y)
	cx, cy := f32(c.x - a.x), f32(c.y - a.y)
	inv := f32(SUB) / f32(area2)
	rgb_const := a.r == b.r && a.r == c.r && a.g == b.g && a.g == c.g && a.b == b.b && a.b == c.b
	a_const := a.a == b.a && a.a == c.a
	tex_const := a.u == b.u && a.u == c.u && a.v == b.v && a.v == c.v
	pr, pg, pb, pa, pu, pv: Plane
	pr = {a.r, 0, 0}
	pg = {a.g, 0, 0}
	pb = {a.b, 0, 0}
	pa = {a.a, 0, 0}
	if !rgb_const {
		pr = plane_of(a.r, b.r, c.r, bx, by, cx, cy, inv)
		pg = plane_of(a.g, b.g, c.g, bx, by, cx, cy, inv)
		pb = plane_of(a.b, b.b, c.b, bx, by, cx, cy, inv)
	}
	if !a_const {
		pa = plane_of(a.a, b.a, c.a, bx, by, cx, cy, inv)
	}
	tex_a: f32 = 1 // alpha of the texel, when it is the same all over
	if tex_const {
		tx := clamp(int(a.u), 0, ra.dim - 1)
		ty := clamp(int(a.v), 0, ra.dim - 1)
		tex_a = f32(ra.atlas[ty * ra.dim + tx]) * (1.0 / 255)
	} else {
		pu = plane_of(a.u, b.u, c.u, bx, by, cx, cy, inv)
		pv = plane_of(a.v, b.v, c.v, bx, by, cx, cy, inv)
	}
	const_alpha := a_const && tex_const

	for py in py0 ..= py1 {
		yc := i64(py) * SUB + HALF
		lo, hi := i64(px0), i64(px1)
		for e in edges {
			k := e.ey * yc + e.c
			if e.s > 0 {
				lo = max(lo, -floor_div(k, e.s))
			} else if e.s < 0 {
				hi = min(hi, floor_div(k, -e.s))
			} else if k < 0 {
				lo = hi + 1
			}
		}
		if lo > hi {
			continue
		}
		fx := f32(lo * SUB + HALF - a.x) * (1.0 / SUB)
		fy := f32(yc - a.y) * (1.0 / SUB)
		r := pr.v0 + pr.dx * fx + pr.dy * fy
		g := pg.v0 + pg.dx * fx + pg.dy * fy
		bl := pb.v0 + pb.dx * fx + pb.dy * fy
		al := pa.v0 + pa.dx * fx + pa.dy * fy
		u := pu.v0 + pu.dx * fx + pu.dy * fy
		v := pv.v0 + pv.dx * fx + pv.dy * fy
		row := ra.t.pixels[py * ra.t.stride:]
		n := int(hi - lo) + 1
		first := int(lo)
		if const_alpha {
			// One alpha for the whole span.
			s := clamp(al * tex_a, 0, 1)
			if s <= 0 {
				continue
			}
			if s >= 1 {
				// Opaque: the colour is written without reading the pixel.
				if rgb_const {
					px := pack(r, g, bl)
					for i in 0 ..< n {
						row[first + i] = px
					}
				} else {
					for i in 0 ..< n {
						fi := f32(i)
						row[first + i] = pack(r + pr.dx * fi, g + pg.dx * fi, bl + pb.dx * fi)
					}
				}
				continue
			}
		}
		if tex_const {
			for i in 0 ..< n {
				fi := f32(i)
				s := clamp((al + pa.dx * fi) * tex_a, 0, 1)
				row[first + i] = over(row[first + i], r + pr.dx * fi, g + pg.dx * fi, bl + pb.dx * fi, s)
			}
			continue
		}
		for i in 0 ..< n {
			fi := f32(i)
			tx := clamp(int(u + pu.dx * fi), 0, ra.dim - 1)
			ty := clamp(int(v + pv.dx * fi), 0, ra.dim - 1)
			s := clamp((al + pa.dx * fi) * f32(ra.atlas[ty * ra.dim + tx]) * (1.0 / 255), 0, 1)
			row[first + i] = over(row[first + i], r + pr.dx * fi, g + pg.dx * fi, bl + pb.dx * fi, s)
		}
	}
}

// raster_quad draws the triangles (a, b, c) and (a, c, d) as one rectangle when they
// form an axis-aligned one with the colour changing only from top to bottom and
// either one texel (a solid fill), or the atlas copied 1:1 to whole pixels (a glyph).
// It returns false for any other quad.
@(private = "file")
raster_quad :: proc(ra: ^Raster, a, b, c, d: Vert) -> bool #no_bounds_check {
	vs := [4]Vert{a, b, c, d}
	xmin, xmax := min(a.x, b.x, c.x, d.x), max(a.x, b.x, c.x, d.x)
	ymin, ymax := min(a.y, b.y, c.y, d.y), max(a.y, b.y, c.y, d.y)
	if xmin == xmax || ymin == ymax {
		return false
	}
	corner: [4]int // the vertex at each corner: bit 0 is right, bit 1 is bottom
	seen: u8
	kinds: [4]int
	for v, i in vs {
		if (v.x != xmin && v.x != xmax) || (v.y != ymin && v.y != ymax) {
			return false
		}
		k := (v.x == xmax ? 1 : 0) | (v.y == ymax ? 2 : 0)
		if seen & (1 << uint(k)) != 0 {
			return false
		}
		seen |= 1 << uint(k)
		corner[k] = i
		kinds[i] = k
	}
	if kinds[0] ~ kinds[2] != 3 {
		return false
	}
	tl, tr, bl, br := vs[corner[0]], vs[corner[1]], vs[corner[2]], vs[corner[3]]
	same_col :: #force_inline proc "contextless" (p, q: Vert) -> bool {
		return p.r == q.r && p.g == q.g && p.b == q.b && p.a == q.a
	}
	same_tex :: #force_inline proc "contextless" (p, q: Vert) -> bool {
		return p.u == q.u && p.v == q.v
	}
	if !same_col(tl, tr) || !same_col(bl, br) {
		return false
	}
	clip := ra.clip
	px0 := max(int(first_pixel(xmin)), clip.x0)
	px1 := min(int(first_pixel(xmax)) - 1, clip.x1 - 1)
	py0 := max(int(first_pixel(ymin)), clip.y0)
	py1 := min(int(first_pixel(ymax)) - 1, clip.y1 - 1)
	if px0 > px1 || py0 > py1 {
		return true
	}
	height := f32(ymax - ymin)

	if same_tex(tl, tr) && same_tex(tl, bl) && same_tex(tl, br) {
		// One texel: a solid colour, or a vertical gradient.
		tx := clamp(int(tl.u), 0, ra.dim - 1)
		ty := clamp(int(tl.v), 0, ra.dim - 1)
		tex_a := f32(ra.atlas[ty * ra.dim + tx]) * (1.0 / 255)
		flat := same_col(tl, bl)
		for py in py0 ..= py1 {
			t: f32
			if !flat {
				t = f32(i64(py) * SUB + HALF - ymin) / height
			}
			r := tl.r + (bl.r - tl.r) * t
			g := tl.g + (bl.g - tl.g) * t
			bb := tl.b + (bl.b - tl.b) * t
			s := clamp((tl.a + (bl.a - tl.a) * t) * tex_a, 0, 1)
			if s <= 0 {
				continue
			}
			row := ra.t.pixels[py * ra.t.stride:]
			if s >= 1 {
				px := pack(r, g, bb)
				for x in px0 ..= px1 {
					row[x] = px
				}
			} else {
				for x in px0 ..= px1 {
					row[x] = over(row[x], r, g, bb, s)
				}
			}
		}
		return true
	}

	// The atlas copied 1:1 onto whole pixels, in one colour.
	if !same_col(tl, bl) || xmin % SUB != 0 || ymin % SUB != 0 || xmax % SUB != 0 || ymax % SUB != 0 {
		return false
	}
	if tl.u != bl.u || tr.u != br.u || tl.v != tr.v || bl.v != br.v {
		return false
	}
	w, h := f32((xmax - xmin) / SUB), f32((ymax - ymin) / SUB)
	tx0, ty0 := math.round(tl.u), math.round(tl.v)
	if abs(tl.u - tx0) > 0.01 || abs(tl.v - ty0) > 0.01 || abs(tr.u - tl.u - w) > 0.01 || abs(bl.v - tl.v - h) > 0.01 {
		return false
	}
	left, top := int(xmin / SUB), int(ymin / SUB)
	ox, oy := int(tx0) - left, int(ty0) - top
	if int(tx0) < 0 || int(ty0) < 0 || int(tx0 + w) > ra.dim || int(ty0 + h) > ra.dim {
		return false
	}
	r, g, bb := tl.r, tl.g, tl.b
	for py in py0 ..= py1 {
		src := ra.atlas[(py + oy) * ra.dim + ox:]
		row := ra.t.pixels[py * ra.t.stride:]
		if tl.a >= 1 {
			for x in px0 ..= px1 {
				s := src[x]
				if s == 255 {
					row[x] = pack(r, g, bb)
				} else if s != 0 {
					row[x] = over(row[x], r, g, bb, f32(s) * (1.0 / 255))
				}
			}
		} else {
			for x in px0 ..= px1 {
				if s := src[x]; s != 0 {
					row[x] = over(row[x], r, g, bb, f32(s) * (1.0 / 255) * tl.a)
				}
			}
		}
	}
	return true
}
