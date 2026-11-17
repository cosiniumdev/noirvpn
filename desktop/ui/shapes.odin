// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Anti-aliased shapes. SDL_RenderGeometry has no multisampling, so each shape
// is a triangle mesh with a one pixel ramp of vertex alpha along its edge. The
// ramp is centred on the true edge: a pixel centre half a pixel inside gets full
// alpha, half a pixel outside gets none (exact coverage of an axis-aligned edge).

import "core:math"

// Pt is a point of a closed outline with its outward normal, in device pixels.
// A sharp corner has the diagonal (+-1, +-1) as normal, so offset d moves both
// edges by d.
Pt :: struct {
	x, y, nx, ny: f32,
}

MAX_LOOP :: 512

Loop :: struct {
	pts: [MAX_LOOP]Pt,
	n:   int,
}

@(private)
arc_segments :: proc(radius_px: f32) -> int {
	return clamp(int(math.ceil(math.sqrt(radius_px) * 1.6)), 2, 40)
}

// rrect_loop writes a rounded rectangle outline, clockwise on screen. segs == 0:
// segment count follows the radius. mid: add a point at half height on both
// straight sides, so a three-stop vertical gradient is exact on every triangle.
rrect_loop :: proc(l: ^Loop, x, y, w, h, r: f32, segs := 0, mid := false) {
	l.n = 0
	rad := min(r, w / 2, h / 2)
	if rad < 0.75 {
		add :: proc(l: ^Loop, px, py, nx, ny: f32) {
			l.pts[l.n] = {px, py, nx, ny}
			l.n += 1
		}
		add(l, x, y, -1, -1)
		add(l, x + w, y, 1, -1)
		add(l, x + w, y + h, 1, 1)
		add(l, x, y + h, -1, 1)
		return
	}
	n := segs > 0 ? segs : arc_segments(rad)
	centers := [4][2]f32{{x + rad, y + rad}, {x + w - rad, y + rad}, {x + w - rad, y + h - rad}, {x + rad, y + h - rad}}
	for c, k in centers {
		a0 := math.PI + f32(k) * math.PI / 2
		for i in 0 ..= n {
			a := a0 + f32(i) * (math.PI / 2) / f32(n)
			cs, sn := math.cos(a), math.sin(a)
			l.pts[l.n] = {c.x + rad * cs, c.y + rad * sn, cs, sn}
			l.n += 1
		}
		if mid && (k == 1 || k == 3) {
			l.pts[l.n] = {k == 1 ? x + w : x, y + h / 2, k == 1 ? 1 : -1, 0}
			l.n += 1
		}
	}
}

// grad3 is the colour of a three-stop vertical gradient at t (0 top, 1 bottom).
grad3 :: proc(top, mid, bottom: Color, t: f32) -> Color {
	if t < 0.5 {
		return mix(top, mid, clamp(t * 2, 0, 1))
	}
	return mix(mid, bottom, clamp(t * 2 - 1, 0, 1))
}

// fill_loop fills a convex outline with an edge ramp.
fill_loop :: proc(g: ^Gfx, l: ^Loop, c: Color) {
	if c.a == 0 || l.n < 3 {
		return
	}
	col := fcolor(c)
	clear_col := fcolor(c, 0)
	cx, cy: f32
	for i in 0 ..< l.n {
		cx += l.pts[i].x
		cy += l.pts[i].y
	}
	cx /= f32(l.n)
	cy /= f32(l.n)
	ci := vtx(g, cx, cy, col)
	first_in, first_out: i32
	prev_in, prev_out: i32
	for i in 0 ..< l.n {
		p := l.pts[i]
		vi := vtx(g, p.x - p.nx * 0.5, p.y - p.ny * 0.5, col)
		vo := vtx(g, p.x + p.nx * 0.5, p.y + p.ny * 0.5, clear_col)
		if i == 0 {
			first_in, first_out = vi, vo
		} else {
			tri(g, ci, prev_in, vi)
			quad4(g, prev_in, prev_out, vo, vi)
		}
		prev_in, prev_out = vi, vo
	}
	tri(g, ci, prev_in, first_in)
	quad4(g, prev_in, prev_out, first_out, first_in)
}

// fill_loop_grad fills a convex outline created with mid set. The colour at a point
// follows its y between y0 (top stop) and y1 (bottom stop), both in device pixels.
fill_loop_grad :: proc(g: ^Gfx, l: ^Loop, y0, y1: f32, top, mid, bottom: Color) {
	if l.n < 3 {
		return
	}
	at :: proc(y, y0, y1: f32, top, mid, bottom: Color) -> Color {
		return grad3(top, mid, bottom, (y - y0) / max(y1 - y0, 1))
	}
	cx, cy: f32
	for i in 0 ..< l.n {
		cx += l.pts[i].x
		cy += l.pts[i].y
	}
	cx /= f32(l.n)
	cy /= f32(l.n)
	ci := vtx(g, cx, cy, fcolor(at(cy, y0, y1, top, mid, bottom)))
	first_in, first_out: i32
	prev_in, prev_out: i32
	for i in 0 ..< l.n {
		p := l.pts[i]
		c := at(p.y, y0, y1, top, mid, bottom)
		vi := vtx(g, p.x - p.nx * 0.5, p.y - p.ny * 0.5, fcolor(c))
		vo := vtx(g, p.x + p.nx * 0.5, p.y + p.ny * 0.5, fcolor(c, 0))
		if i == 0 {
			first_in, first_out = vi, vo
		} else {
			tri(g, ci, prev_in, vi)
			quad4(g, prev_in, prev_out, vo, vi)
		}
		prev_in, prev_out = vi, vo
	}
	tri(g, ci, prev_in, first_in)
	quad4(g, prev_in, prev_out, first_out, first_in)
}

// stroke_loop draws a closed outline as a band of half width hw (device pixels)
// around the loop's points.
stroke_loop :: proc(g: ^Gfx, l: ^Loop, hw: f32, c: Color) {
	if c.a == 0 || l.n < 3 {
		return
	}
	peak := min(hw * 2, 1)
	cc := fcolor(c, peak)
	zc := fcolor(c, 0)
	inner := max(hw - 0.5, 0)
	outer := max(hw, 0.5) + 0.5
	// A band thinner than a pixel keeps its width as alpha.
	first: [4]i32
	prev: [4]i32
	for i in 0 ..< l.n {
		p := l.pts[i]
		v: [4]i32
		v[0] = vtx(g, p.x + p.nx * outer, p.y + p.ny * outer, zc)
		v[1] = vtx(g, p.x + p.nx * inner, p.y + p.ny * inner, cc)
		v[2] = vtx(g, p.x - p.nx * inner, p.y - p.ny * inner, cc)
		v[3] = vtx(g, p.x - p.nx * outer, p.y - p.ny * outer, zc)
		if i == 0 {
			first = v
		} else {
			band(g, prev, v)
		}
		prev = v
	}
	band(g, prev, first)
}

@(private)
band :: proc(g: ^Gfx, a, b: [4]i32) {
	quad4(g, a[0], a[1], b[1], b[0])
	quad4(g, a[1], a[2], b[2], b[1])
	quad4(g, a[2], a[3], b[3], b[2])
}

// rrect fills a rounded rectangle. Rect and radius are logical units.
rrect :: proc(g: ^Gfx, r: Rectf, radius: f32, c: Color) {
	loop: Loop
	s := g.scale
	rrect_loop(&loop, r.x * s, r.y * s, r.w * s, r.h * s, radius * s)
	fill_loop(g, &loop, c)
}

// rrect_stroke draws a border of width bw inside the rectangle.
rrect_stroke :: proc(g: ^Gfx, r: Rectf, radius, bw: f32, c: Color) {
	loop: Loop
	s := g.scale
	half := bw * s / 2
	rrect_loop(&loop, r.x * s + half, r.y * s + half, r.w * s - half * 2, r.h * s - half * 2, max(radius * s - half, 0))
	stroke_loop(g, &loop, half, c)
}

// rrect_border fills a rounded rectangle and draws a border of width bw inside it.
rrect_border :: proc(g: ^Gfx, r: Rectf, radius: f32, fill, border: Color, bw: f32 = 1) {
	if border.a == 255 && fill.a == 255 {
		// Two nested fills: each edge is blended once, against what is behind it.
		rrect(g, r, radius, border)
		rrect(g, {r.x + bw, r.y + bw, r.w - bw * 2, r.h - bw * 2}, max(radius - bw, 0), fill)
		return
	}
	rrect(g, r, radius, fill)
	rrect_stroke(g, r, radius, bw, border)
}

// rrect_card fills a rounded rectangle with a three-stop vertical gradient and a
// solid border of width bw inside it.
rrect_card :: proc(g: ^Gfx, r: Rectf, radius, bw: f32, top, mid, bottom, border: Color) {
	rrect(g, r, radius, border)
	s := g.scale
	in_ := Rectf{(r.x + bw) * s, (r.y + bw) * s, (r.w - bw * 2) * s, (r.h - bw * 2) * s}
	loop: Loop
	rrect_loop(&loop, in_.x, in_.y, in_.w, in_.h, max(radius - bw, 0) * s, 0, true)
	fill_loop_grad(g, &loop, in_.y, in_.y + in_.h, top, mid, bottom)
}

circle :: proc(g: ^Gfx, cx, cy, radius: f32, c: Color) {
	rrect(g, {cx - radius, cy - radius, radius * 2, radius * 2}, radius, c)
}

// ring draws a circle outline of width w that lies inside radius.
ring :: proc(g: ^Gfx, cx, cy, radius, w: f32, c: Color) {
	rrect_stroke(g, {cx - radius, cy - radius, radius * 2, radius * 2}, radius, w, c)
}

// shadow draws a soft shadow around a rounded rectangle, as nested outlines whose
// alpha falls off over blur units.
shadow :: proc(g: ^Gfx, r: Rectf, radius, blur, dy: f32, c: Color) {
	STEPS :: 8
	s := g.scale
	segs := arc_segments((radius + blur) * s)
	loops: [STEPS + 1]Loop
	alphas: [STEPS + 1]f32
	for k in 0 ..= STEPS {
		t := f32(k) / STEPS
		grow := blur * t * s
		rrect_loop(&loops[k], r.x * s - grow, (r.y + dy) * s - grow, r.w * s + grow * 2, r.h * s + grow * 2, radius * s + grow, segs)
		f := 1 - t
		alphas[k] = f * f * f
	}
	// The core.
	{
		l := &loops[0]
		col := fcolor(c, alphas[0])
		cx, cy: f32
		for i in 0 ..< l.n {
			cx += l.pts[i].x
			cy += l.pts[i].y
		}
		ci := vtx(g, cx / f32(l.n), cy / f32(l.n), col)
		first, prev: i32
		for i in 0 ..< l.n {
			v := vtx(g, l.pts[i].x, l.pts[i].y, col)
			if i == 0 {
				first = v
			} else {
				tri(g, ci, prev, v)
			}
			prev = v
		}
		tri(g, ci, prev, first)
	}
	for k in 0 ..< STEPS {
		a, b := &loops[k], &loops[k + 1]
		ca, cb := fcolor(c, alphas[k]), fcolor(c, alphas[k + 1])
		fa, fb, pa, pb: i32
		for i in 0 ..< a.n {
			va := vtx(g, a.pts[i].x, a.pts[i].y, ca)
			vb := vtx(g, b.pts[i].x, b.pts[i].y, cb)
			if i == 0 {
				fa, fb = va, vb
			} else {
				quad4(g, pa, pb, vb, va)
			}
			pa, pb = va, vb
		}
		quad4(g, pa, pb, fb, fa)
	}
}

// polyline strokes an open path of logical points. Joins are mitred up to a
// limit; ends are butt.
polyline :: proc(g: ^Gfx, pts: [][2]f32, width: f32, c: Color) {
	n := len(pts)
	if n < 2 || c.a == 0 {
		return
	}
	s := g.scale
	hw := width * s / 2
	peak := min(hw * 2, 1)
	cc := fcolor(c, peak)
	zc := fcolor(c, 0)
	inner := max(hw - 0.5, 0)
	outer := max(hw, 0.5) + 0.5

	// Unit directions of the segments, dropping zero-length ones.
	dirs := make([dynamic][2]f32, 0, n, context.temp_allocator)
	pp := make([dynamic][2]f32, 0, n, context.temp_allocator)
	append(&pp, pts[0] * s)
	for i in 1 ..< n {
		p := pts[i] * s
		d := p - pp[len(pp) - 1]
		l := math.sqrt(d.x * d.x + d.y * d.y)
		if l < 0.001 {
			continue
		}
		append(&dirs, d / l)
		append(&pp, p)
	}
	m := len(pp)
	if m < 2 {
		return
	}

	prev: [4]i32
	for i in 0 ..< m {
		p := pp[i]
		// Normal of the cross-section, scaled to the miter length.
		nrm: [2]f32
		scale_m: f32 = 1
		switch {
		case i == 0:
			d := dirs[0]
			nrm = {-d.y, d.x}
		case i == m - 1:
			d := dirs[m - 2]
			nrm = {-d.y, d.x}
		case:
			d0, d1 := dirs[i - 1], dirs[i]
			n0 := [2]f32{-d0.y, d0.x}
			n1 := [2]f32{-d1.y, d1.x}
			mv := n0 + n1
			ml := math.sqrt(mv.x * mv.x + mv.y * mv.y)
			if ml < 0.001 {
				nrm = n0
			} else {
				nrm = mv / ml
				cosh := nrm.x * n0.x + nrm.y * n0.y
				scale_m = min(1 / max(cosh, 0.001), 2.5)
			}
		}
		v: [4]i32
		v[0] = vtx(g, p.x + nrm.x * outer * scale_m, p.y + nrm.y * outer * scale_m, zc)
		v[1] = vtx(g, p.x + nrm.x * inner * scale_m, p.y + nrm.y * inner * scale_m, cc)
		v[2] = vtx(g, p.x - nrm.x * inner * scale_m, p.y - nrm.y * inner * scale_m, cc)
		v[3] = vtx(g, p.x - nrm.x * outer * scale_m, p.y - nrm.y * outer * scale_m, zc)
		if i > 0 {
			band(g, prev, v)
		}
		prev = v
	}
}

// line strokes one segment.
line :: proc(g: ^Gfx, a, b: [2]f32, width: f32, c: Color) {
	pts := [2][2]f32{a, b}
	polyline(g, pts[:], width, c)
}
