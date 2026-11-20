// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

import "core:math"

// Vector icons, drawn as strokes and fills from path data, sharp at any
// density. The bounding box of the path fills the square the icon is drawn in.

Icon_Id :: enum u8 {
	Back,
	Plus,
	Minus,
	More,
	Chevron_Right,
	Remove,
	Gear,
	Close,
	Lock,
	Edit,
	// Section bar: see view_nav.odin.
	Tag,
	Server,
	Badge,
	Key,
	Tunnel,
	Sliders,
	Person,
	Document,
	Shield,
	Block,
	Copy,
	Code,
}

// Bounding box of each icon's path: x0, y0, x1, y1.
@(private)
icon_box :: proc(id: Icon_Id) -> [4]f32 {
	switch id {
	case .Back:
		return {5, 2.5, 11.5, 13.5}
	case .Chevron_Right:
		return {4.5, 2.5, 11, 13.5}
	case .Plus, .Minus:
		return {2, 2, 14, 14}
	case .More:
		return {6.6, 2.5, 9.4, 13.5}
	case .Remove:
		return {1.6, 1.6, 10.4, 10.4}
	case .Gear:
		return {1, 1, 15, 15}
	case .Close:
		return {0, 0, 16, 16}
	case .Lock:
		return {3, 2, 13, 14.6}
	case .Edit:
		return {2.4, 2.4, 13.6, 13.6}
	case .Tag, .Server, .Badge, .Key, .Tunnel, .Sliders, .Person, .Document, .Shield, .Block, .Copy, .Code:
		return {1, 1, 15, 15}
	}
	return {0, 0, 16, 16}
}

// draw_icon draws an icon in the square with its top left at x, y and a side of size units.
draw_icon :: proc(g: ^Gfx, id: Icon_Id, x, y, size: f32, c: Color) {
	b := icon_box(id)
	bw, bh := b[2] - b[0], b[3] - b[1]
	k := size / max(bw, bh)
	// Maps a point of the path grid to the screen.
	ox := x + (size - bw * k) / 2 - b[0] * k
	oy := y + (size - bh * k) / 2 - b[1] * k
	p :: proc(ox, oy, k, px, py: f32) -> [2]f32 {
		return {ox + px * k, oy + py * k}
	}
	switch id {
	case .Back:
		pts := [3][2]f32{p(ox, oy, k, 11, 3), p(ox, oy, k, 6, 8), p(ox, oy, k, 11, 13)}
		polyline(g, pts[:], 1.4142 * k, c)
	case .Chevron_Right:
		pts := [3][2]f32{p(ox, oy, k, 5, 3), p(ox, oy, k, 10, 8), p(ox, oy, k, 5, 13)}
		polyline(g, pts[:], 1.4142 * k, c)
	case .Plus:
		rrect(g, {ox + 2 * k, oy + 7.25 * k, 12 * k, 1.5 * k}, 0, c)
		rrect(g, {ox + 7.25 * k, oy + 2 * k, 1.5 * k, 12 * k}, 0, c)
	case .Minus:
		// The horizontal bar of the plus.
		rrect(g, {ox + 2 * k, oy + 7.25 * k, 12 * k, 1.5 * k}, 0, c)
	case .More:
		for cy in ([3]f32{3.9, 8, 12.1}) {
			circle(g, ox + 8 * k, oy + cy * k, 1.4 * k, c)
		}
	case .Gear:
		// Eight teeth on a ring.
		for i in 0 ..< 8 {
			a := f32(i) * math.PI / 4
			dx, dy := math.cos(a), math.sin(a)
			line(g, p(ox, oy, k, 8 + 5.2 * dx, 8 + 5.2 * dy), p(ox, oy, k, 8 + 6.4 * dx, 8 + 6.4 * dy), 2.4 * k, c)
		}
		ring(g, ox + 8 * k, oy + 8 * k, 5.3 * k, 2 * k, c)
	case .Close:
		line(g, p(ox, oy, k, 3, 3), p(ox, oy, k, 13, 13), 1.5 * k, c)
		line(g, p(ox, oy, k, 13, 3), p(ox, oy, k, 3, 13), 1.5 * k, c)
	case .Remove:
		line(g, p(ox, oy, k, 2.15, 2.15), p(ox, oy, k, 9.85, 9.85), 1.556 * k, c)
		line(g, p(ox, oy, k, 9.85, 2.15), p(ox, oy, k, 2.15, 9.85), 1.556 * k, c)
	case .Lock:
		// A closed shackle over the body, and a dark keyhole.
		cx, cy, r: f32 = 8, 6.2, 3.1
		pts: [15][2]f32
		pts[0] = p(ox, oy, k, cx - r, 8.4)
		for i in 0 ..= 12 {
			a := math.PI * f32(i) / 12
			pts[i + 1] = p(ox, oy, k, cx - r * math.cos(a), cy - r * math.sin(a))
		}
		pts[14] = p(ox, oy, k, cx + r, 8.4)
		polyline(g, pts[:], 1.6 * k, c)
		rrect(g, {ox + 3 * k, oy + 7.6 * k, 10 * k, 7 * k}, 1.6 * k, c)
		hole := mix(c, Color{0, 0, 0, c.a}, 0.7)
		circle(g, ox + 8 * k, oy + 10.5 * k, 1.1 * k, hole)
		line(g, p(ox, oy, k, 8, 10.6), p(ox, oy, k, 8, 12.6), 1 * k, hole)
	case .Edit:
		// A pencil at 45 degrees: the shaft, the cap and the point.
		line(g, p(ox, oy, k, 4.6, 11.4), p(ox, oy, k, 10.9, 5.1), 2.6 * k, c)
		line(g, p(ox, oy, k, 11.9, 4.1), p(ox, oy, k, 12.7, 3.3), 2.6 * k, c)
		line(g, p(ox, oy, k, 4.2, 11.8), p(ox, oy, k, 3, 13), 1.2 * k, c)
	case .Tag:
		// A label with a pointed end and a hole.
		pts := [5][2]f32{p(ox, oy, k, 6, 3.5), p(ox, oy, k, 14, 3.5), p(ox, oy, k, 14, 12.5), p(ox, oy, k, 6, 12.5), p(ox, oy, k, 2, 8)}
		closed_path(g, pts[:], SW * k, c)
		circle(g, ox + 6.3 * k, oy + 8 * k, 1.2 * k, c)
	case .Server:
		// Two stacked units, each with a light.
		for top in ([2]f32{2, 9}) {
			rrect_stroke(g, {ox + 2 * k, oy + top * k, 12 * k, 5 * k}, 1.3 * k, SW * k, c)
			circle(g, ox + 4.9 * k, oy + (top + 2.5) * k, 0.95 * k, c)
			line(g, p(ox, oy, k, 8, top + 2.5), p(ox, oy, k, 11.2, top + 2.5), 1.1 * k, c)
		}
	case .Badge:
		// A card with a portrait and two lines of text.
		rrect_stroke(g, {ox + 1.5 * k, oy + 3 * k, 13 * k, 10 * k}, 1.6 * k, SW * k, c)
		circle(g, ox + 5.5 * k, oy + 6.6 * k, 1.5 * k, c)
		arc(g, ox, oy, k, 5.5, 11.6, 2.4, math.PI, 2 * math.PI, SW, c)
		line(g, p(ox, oy, k, 9.2, 6.6), p(ox, oy, k, 12.4, 6.6), SW * k, c)
		line(g, p(ox, oy, k, 9.2, 9.6), p(ox, oy, k, 12.4, 9.6), SW * k, c)
	case .Key:
		// A bow, a shaft and two teeth.
		ring(g, ox + 5 * k, oy + 8 * k, 3.2 * k, SW * k, c)
		line(g, p(ox, oy, k, 8.2, 8), p(ox, oy, k, 14.5, 8), SW * k, c)
		line(g, p(ox, oy, k, 13.2, 8), p(ox, oy, k, 13.2, 11), SW * k, c)
		line(g, p(ox, oy, k, 10.8, 8), p(ox, oy, k, 10.8, 10.4), SW * k, c)
	case .Tunnel:
		// An outer arch, the opening inside it and the road.
		arch(g, ox, oy, k, 8, 7.5, 6, 13.5, c)
		arch(g, ox, oy, k, 8, 10, 2.6, 13.5, c)
		line(g, p(ox, oy, k, 1, 13.5), p(ox, oy, k, 15, 13.5), SW * k, c)
	case .Sliders:
		// Three tracks, each with a knob.
		for t in ([3][2]f32{{4, 10.5}, {8, 5}, {12, 9}}) {
			line(g, p(ox, oy, k, 2, t[0]), p(ox, oy, k, 14, t[0]), SW * k, c)
			circle(g, ox + t[1] * k, oy + t[0] * k, 1.9 * k, c)
		}
	case .Person:
		ring(g, ox + 8 * k, oy + 5 * k, 2.9 * k, SW * k, c)
		arc(g, ox, oy, k, 8, 14.5, 5.5, math.PI, 2 * math.PI, SW, c)
	case .Document:
		// A page with a folded corner and two lines of text.
		pts := [5][2]f32{p(ox, oy, k, 3.5, 1.7), p(ox, oy, k, 9.3, 1.7), p(ox, oy, k, 12.5, 4.9), p(ox, oy, k, 12.5, 14.3), p(ox, oy, k, 3.5, 14.3)}
		closed_path(g, pts[:], SW * k, c)
		fold := [3][2]f32{p(ox, oy, k, 9.3, 1.7), p(ox, oy, k, 9.3, 4.9), p(ox, oy, k, 12.5, 4.9)}
		polyline(g, fold[:], SW * k, c)
		line(g, p(ox, oy, k, 5.6, 8.2), p(ox, oy, k, 10.4, 8.2), SW * k, c)
		line(g, p(ox, oy, k, 5.6, 11.2), p(ox, oy, k, 10.4, 11.2), SW * k, c)
	case .Shield:
		// A shield with a check mark.
		pts: [16][2]f32
		pts[0] = p(ox, oy, k, 8, 1.6)
		pts[1] = p(ox, oy, k, 13.4, 3.4)
		pts[2] = p(ox, oy, k, 13.4, 7.4)
		// The two sides curve down to the point.
		for i in 1 ..= 6 {
			t := f32(i) / 6
			pts[2 + i] = p(ox, oy, k, 13.4 - 5.4 * t * t, 7.4 + 7 * t)
		}
		for i in 1 ..= 6 {
			t := 1 - f32(i) / 6
			pts[8 + i] = p(ox, oy, k, 2.6 + 5.4 * t * t, 7.4 + 7 * t)
		}
		pts[15] = p(ox, oy, k, 2.6, 3.4)
		closed_path(g, pts[:], SW * k, c)
		check := [3][2]f32{p(ox, oy, k, 5.6, 8), p(ox, oy, k, 7.4, 9.8), p(ox, oy, k, 10.6, 6.4)}
		polyline(g, check[:], SW * k, c)
	case .Block:
		ring(g, ox + 8 * k, oy + 8 * k, 6.4 * k, SW * k, c)
		line(g, p(ox, oy, k, 3.6, 12.4), p(ox, oy, k, 12.4, 3.6), SW * k, c)
	case .Copy:
		// A sheet in front and the edge of a second sheet behind it.
		rrect_stroke(g, {ox + 1.8 * k, oy + 5 * k, 9.2 * k, 9.4 * k}, 1.4 * k, SW * k, c)
		back := [4][2]f32{p(ox, oy, k, 5, 4.2), p(ox, oy, k, 5, 1.8), p(ox, oy, k, 14.2, 1.8), p(ox, oy, k, 14.2, 11.2)}
		polyline(g, back[:], SW * k, c)
		line(g, p(ox, oy, k, 14.2, 11.2), p(ox, oy, k, 11.8, 11.2), SW * k, c)
	case .Code:
		left := [3][2]f32{p(ox, oy, k, 5.2, 4), p(ox, oy, k, 1.6, 8), p(ox, oy, k, 5.2, 12)}
		right := [3][2]f32{p(ox, oy, k, 10.8, 4), p(ox, oy, k, 14.4, 8), p(ox, oy, k, 10.8, 12)}
		polyline(g, left[:], SW * k, c)
		polyline(g, right[:], SW * k, c)
		line(g, p(ox, oy, k, 9.2, 2.8), p(ox, oy, k, 6.8, 13.2), SW * k, c)
	}
}

// SW is the stroke width of the section icons, in path units.
@(private)
SW :: 1.4

// closed_path strokes a closed outline. It starts and ends in the middle of the
// first side, so every corner gets a join.
@(private)
closed_path :: proc(g: ^Gfx, pts: [][2]f32, width: f32, c: Color) {
	n := len(pts)
	path := make([][2]f32, n + 2, context.temp_allocator)
	mid := (pts[0] + pts[1]) / 2
	path[0] = mid
	for i in 1 ..< n {
		path[i] = pts[i]
	}
	path[n] = pts[0]
	path[n + 1] = mid
	polyline(g, path, width, c)
}

// arc strokes the part of the circle at cx, cy (path units) from angle a0 to a1.
@(private)
arc :: proc(g: ^Gfx, ox, oy, k, cx, cy, r, a0, a1, w: f32, c: Color) {
	pts: [17][2]f32
	for i in 0 ..< len(pts) {
		a := a0 + (a1 - a0) * f32(i) / f32(len(pts) - 1)
		pts[i] = {ox + (cx + r * math.cos(a)) * k, oy + (cy + r * math.sin(a)) * k}
	}
	polyline(g, pts[:], w * k, c)
}

// arch strokes two upright sides from y = base up to cy and a half circle of
// radius r over them.
@(private)
arch :: proc(g: ^Gfx, ox, oy, k, cx, cy, r, base: f32, c: Color) {
	pts: [19][2]f32
	pts[0] = {ox + (cx - r) * k, oy + base * k}
	for i in 0 ..< 17 {
		a := math.PI + math.PI * f32(i) / 16
		pts[i + 1] = {ox + (cx + r * math.cos(a)) * k, oy + (cy + r * math.sin(a)) * k}
	}
	pts[18] = {ox + (cx + r) * k, oy + base * k}
	polyline(g, pts[:], SW * k, c)
}
