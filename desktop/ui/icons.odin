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
	}
}
