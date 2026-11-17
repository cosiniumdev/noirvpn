// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Styled widgets. Each widget gets its rectangle from the caller (usually from
// microui's layout), asks microui for hover and focus through interact(), and
// records styled shapes and text.

import "core:math"
import mu "vendor:microui"

rectf :: #force_inline proc(r: mu.Rect) -> Rectf {
	return {f32(r.x), f32(r.y), f32(r.w), f32(r.h)}
}

Interact :: struct {
	hover:   bool,
	down:    bool, // the mouse went down on the widget and is still down
	clicked: bool,
	focused: bool, // has keyboard focus
	ring:    bool, // focus ring is visible
}

// interact handles mouse and keyboard for a clickable widget. A click is press
// and release on the same widget; Space and Enter click the focused widget.
// Where exclude overlaps the mouse, the widget stays idle.
interact :: proc(ui: ^UI, id: mu.Id, r: mu.Rect, focusable := true, enabled := true, exclude: Maybe(mu.Rect) = nil) -> (res: Interact) {
	ctx := &ui.ctx
	if ex, ok := exclude.?; ok && mu.rect_overlaps_vec2(ex, ctx.mouse_pos) {
		// Another widget lies on top of this point.
		mu.update_control(ctx, id, r, {.NO_INTERACT})
		if ctx.hover_id == id {
			ctx.hover_id = 0
		}
	} else {
		mu.update_control(ctx, id, r)
	}
	if !enabled {
		return
	}
	blocked := ui.block && !ui.in_popup
	if focusable && !blocked {
		append(&ui.order, id)
	}
	if !blocked {
		res.hover = ctx.hover_id == id
		if res.hover && .LEFT in ctx.mouse_pressed_bits {
			ui.press_id = id
			ui.press_claimed = true
			if focusable {
				ui.focus = id
				ui.focus_visible = false
			}
		}
		res.down = ui.press_id == id && .LEFT in ctx.mouse_down_bits
		if ui.press_id == id && .LEFT in ctx.mouse_released_bits {
			res.clicked = res.hover
			ui.press_id = 0
		}
	}
	if focusable && ui.focus == id {
		res.focused = true
		res.ring = ui.focus_visible && !blocked
		if ui.activate && !blocked {
			res.clicked = true
		}
	}
	return
}

// focus_ring draws the keyboard focus ring around a rectangle.
focus_ring :: proc(ui: ^UI, r: Rectf, radius: f32) {
	g := Rectf{r.x - 2, r.y - 2, r.w + 4, r.h + 4}
	emit(ui, {kind = .Stroke, r = g, radius = radius + 2, width = 1.5, c1 = with_alpha(TEXT, 0.85)}, 2)
}

// ---- Buttons ----

Button_Kind :: enum u8 {
	Secondary,
	Primary,
	Danger,
	Ghost,
}

// button_width is the width of a button with the given text and horizontal padding.
button_width :: proc(ui: ^UI, label: string, kind: Button_Kind, pad_x: f32 = BUTTON_PAD_X) -> f32 {
	st := kind == .Primary ? ST_BUTTON_PRIMARY : ST_BUTTON
	return math.ceil(text_w(ui, st, label)) + pad_x * 2 + 2
}

// button_height is the height of a button with the vertical padding pad_y.
button_height :: proc(pad_y: f32 = BUTTON_PAD_Y) -> f32 {
	return line_height(ST_BUTTON) + pad_y * 2 + 2
}

// button draws a button and reports whether it was clicked. behind is the colour
// under the button, used for the pressed and hover blend of the primary kinds.
button :: proc(ui: ^UI, r: mu.Rect, label: string, kind: Button_Kind = .Secondary, enabled := true, behind := SURFACE) -> bool {
	id := mu.get_id(&ui.ctx, label)
	it := interact(ui, id, r, true, enabled)
	rf := rectf(r)
	bg, border, fg: Color
	st := kind == .Primary ? ST_BUTTON_PRIMARY : ST_BUTTON
	switch kind {
	case .Secondary:
		bg, border, fg = SURFACE_RAISED, BORDER, TEXT
		if it.down {
			bg = mix(behind, BORDER, 0.85)
		} else if it.hover {
			bg = BORDER
		}
	case .Primary:
		bg, border, fg = ACCENT, ACCENT, BG
		if it.down {
			bg = mix(behind, ACCENT, 0.75)
		} else if it.hover {
			bg = mix(behind, ACCENT, 0.88)
		}
		border = bg
	case .Danger:
		bg, border, fg = ERROR, ERROR, BG
		if it.down {
			bg = mix(behind, ERROR, 0.75)
		} else if it.hover {
			bg = mix(behind, ERROR, 0.88)
		}
		border = bg
	case .Ghost:
		bg, border, fg = {}, {}, MUTED
		if it.hover || it.down {
			bg = SURFACE_RAISED
			fg = TEXT
		}
	}
	if !enabled {
		bg, border, fg = DISABLED_BG, DISABLED_BG, DISABLED_TEXT
		if kind == .Secondary {
			bg, border = SURFACE, BORDER
		}
	}
	if bg.a > 0 {
		emit(ui, {kind = .Rrect, r = rf, radius = RADIUS_BUTTON, c1 = bg, c2 = border, width = 1})
	}
	tw := text_w(ui, st, label)
	th := line_height(st)
	text(ui, st, i32(math.round(rf.x + (rf.w - tw) / 2)), i32(math.round(rf.y + (rf.h - th) / 2)), label, fg)
	if it.ring {
		focus_ring(ui, rf, RADIUS_BUTTON)
	}
	return it.clicked
}

// icon_button draws a round 40 by 40 button with a 16 by 16 icon.
icon_button :: proc(ui: ^UI, r: mu.Rect, icon: Icon_Id, name: string, color := TEXT) -> bool {
	id := mu.get_id(&ui.ctx, name)
	it := interact(ui, id, r)
	rf := rectf(r)
	if it.hover || it.down {
		emit(ui, {kind = .Rrect, r = rf, radius = rf.w / 2, c1 = SURFACE_RAISED})
	}
	size: f32 = 16
	emit(ui, {kind = .Icon, r = {rf.x + (rf.w - size) / 2, rf.y + (rf.h - size) / 2, size, size}, icon = icon, c1 = color}, 0)
	if it.ring {
		focus_ring(ui, rf, rf.w / 2)
	}
	return it.clicked
}

// ---- Chip, state dot ----

// chip_size is the size of a chip with the given text.
chip_size :: proc(ui: ^UI, label: string) -> (w, h: f32) {
	return math.ceil(text_w(ui, ST_CHIP, label)) + 16 + 2, line_height(ST_CHIP) + 2 + 2
}

// chip draws a small outlined label with its top left at x, y.
chip :: proc(ui: ^UI, x, y: i32, label: string, tone := Tone.Neutral) {
	w, h := chip_size(ui, label)
	col := tone == .Neutral ? BORDER : tone_color(tone)
	emit(ui, {kind = .Stroke, r = {f32(x), f32(y), w, h}, radius = RADIUS_CHIP, width = 1, c1 = col})
	text(ui, ST_CHIP, x + 9, y + 2, label, tone_color(tone))
}

// state_text draws the connection state as bold text in the colour of its
// tone, centred in r, with no background. alpha (0 to 1) causes it to pulse.
state_text :: proc(ui: ^UI, r: Rectf, label: string, tone: Tone, alpha: f32) {
	c := with_alpha(pill_colors(tone).border, alpha)
	tw := text_w(ui, ST_PILL, label)
	th := line_height(ST_PILL)
	text(ui, ST_PILL, i32(math.round(r.x + (r.w - tw) / 2)), i32(math.round(r.y + (r.h - th) / 2)), label, c)
}

// ---- Panels ----

// panel draws a card: raised-less surface with a 1 unit border and rounded corners.
panel :: proc(ui: ^UI, r: mu.Rect) {
	emit(ui, {kind = .Rrect, r = rectf(r), radius = RADIUS_PANEL, c1 = SURFACE, c2 = BORDER, width = 1})
}

// card draws a card: a vertical gradient from the card tokens with a border.
// `glow` (the connected state) gives it a green border and a soft green glow.
card :: proc(ui: ^UI, r: mu.Rect, glow := false) {
	if glow {
		emit(ui, {kind = .Shadow, r = rectf(r), radius = RADIUS_CARD, width = 10, value = 0, c1 = CARD_UP_GLOW}, 12)
	}
	emit(ui, {kind = .Card, r = rectf(r), radius = RADIUS_CARD, c2 = glow ? CARD_UP_BORDER : CARD_BORDER, width = 1})
}

// card_flat draws a secondary card: one fill colour and the card border.
card_flat :: proc(ui: ^UI, r: mu.Rect) {
	emit(ui, {kind = .Rrect, r = rectf(r), radius = RADIUS_CARD, c1 = CARD_FLAT, c2 = CARD_BORDER, width = 1})
}

// well draws a recessed box: the window colour with a border.
well :: proc(ui: ^UI, r: mu.Rect) {
	emit(ui, {kind = .Rrect, r = rectf(r), radius = RADIUS_FIELD, c1 = BG, c2 = BORDER, width = 1})
}

// hline draws a 1 unit separator.
hline :: proc(ui: ^UI, x, y, w: i32, c := BORDER) {
	mu.draw_rect(&ui.ctx, {x, y, w, 1}, c)
}

// bar draws the bottom bar background: a translucent fill over the window
// gradient with a line on top.
bar :: proc(ui: ^UI, r: mu.Rect) {
	mu.draw_rect(&ui.ctx, r, BAR_FILL)
	mu.draw_rect(&ui.ctx, {r.x, r.y, r.w, 1}, BORDER)
}

// ---- Switch ----

// toggle is a switch. It returns true when it changed.
toggle :: proc(ui: ^UI, r: mu.Rect, name: string, on: ^bool, enabled := true) -> bool {
	id := mu.get_id(&ui.ctx, name)
	it := interact(ui, id, r, true, enabled)
	changed := false
	if it.clicked {
		on^ = !on^
		changed = true
	}
	t := anim(ui, id, on^ ? 1 : 0, 0.12)
	k := ease(t)
	rf := rectf(r)
	tw, th: f32 = 40, 20
	x := rf.x + rf.w - tw
	y := rf.y + (rf.h - th) / 2
	hot := it.hover || it.down
	track := mix(BG, ACCENT, k)
	stroke := mix(hot ? TEXT : MUTED, ACCENT, k)
	knob := mix(hot ? TEXT : MUTED, BG, k)
	if !enabled {
		track, stroke, knob = SURFACE, BORDER, BORDER
	}
	emit(ui, {kind = .Rrect, r = {x, y, tw, th}, radius = th / 2, c1 = track, c2 = stroke, width = 1})
	d := 12 + 2 * k
	cx := x + 10 + 20 * k
	emit(ui, {kind = .Circle, r = {cx - d / 2, y + th / 2 - d / 2, d, d}, c1 = knob})
	if it.ring {
		focus_ring(ui, {x, y, tw, th}, th / 2)
	}
	return changed
}

// ---- Choice (radio card) ----

// choice is a full-width option with a dot. It returns true when clicked.
choice :: proc(ui: ^UI, r: mu.Rect, label: string, selected: bool) -> bool {
	id := mu.get_id(&ui.ctx, label)
	it := interact(ui, id, r)
	rf := rectf(r)
	border := BORDER
	if selected {
		border = ACCENT
	} else if it.hover || it.down {
		border = MUTED
	}
	emit(ui, {kind = .Rrect, r = rf, radius = RADIUS_BUTTON, c1 = BG, c2 = border, width = 1})
	dcol := selected ? ACCENT : MUTED
	cx, cy := rf.x + 12 + 7, rf.y + rf.h / 2
	if selected {
		emit(ui, {kind = .Circle, r = {cx - 7, cy - 7, 14, 14}, c1 = dcol})
	} else {
		emit(ui, {kind = .Ring, r = {cx - 7, cy - 7, 14, 14}, width = 1.5, c1 = dcol})
	}
	th := line_height(ST_BODY)
	text(ui, ST_BODY, i32(rf.x + 12 + 14 + 10), i32(math.round(cy - th / 2)), label, TEXT)
	if it.ring {
		focus_ring(ui, rf, RADIUS_BUTTON)
	}
	return it.clicked
}

// ---- Rate matrix ----

// The live chart: RATE_COLUMNS columns of square blocks, one per second, newest
// at the right. A rate is a stack of blocks from the bottom, darker below. In a
// column the smaller of down and up is in front (up if equal), the larger above.
RATE_COLUMNS :: 60

Graph_Data :: struct {
	down, up: []f32, // bit/s, oldest first, one sample per second
	max:      f32, // top of the value axis
}

// Rate_Matrix is the geometry of the chart in logical units: square cells with
// a gap of about a fifth of a cell, as many rows as fit in the height.
Rate_Matrix :: struct {
	cell, gap: f32,
	rows:      int,
}

rate_matrix :: proc(w, h: f32) -> (m: Rate_Matrix) {
	n := f32(RATE_COLUMNS)
	m.gap = max(1, math.round(w / n * 0.2))
	m.cell = max(0, (w - m.gap * (n - 1)) / n)
	if m.cell > 0 {
		m.rows = int((h + m.gap) / (m.cell + m.gap))
	}
	return
}

// matrix_blocks is the number of blocks of a rate: at least one for a rate
// above zero, at most the rows.
matrix_blocks :: proc(m: Rate_Matrix, x, top: f32) -> int {
	if x <= 0 || top <= 0 {
		return 0
	}
	return min(m.rows, max(1, int(math.round(x / top * f32(m.rows)))))
}

// matrix_shade is the opacity of row r: 0.5 at the bottom, 1 at the top.
matrix_shade :: proc(m: Rate_Matrix, r: int) -> f32 {
	if m.rows <= 1 {
		return 1
	}
	return 0.5 + 0.5 * f32(r) / f32(m.rows - 1)
}

// matrix_sample is the sample of column c (the newest is the last column), or
// 0 before the first sample.
matrix_sample :: proc(v: []f32, c: int) -> f32 {
	i := len(v) - RATE_COLUMNS + c
	return v[i] if i >= 0 && i < len(v) else 0
}

// nice_max returns the top of the value axis: 1, 2 or 5 times a power of ten,
// at least 1000.
nice_max :: proc(value: f32) -> f32 {
	if value <= 1000 {
		return 1000
	}
	p := math.pow(f32(10), math.floor(math.log10(value)))
	m := value / p
	step: f32 = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10
	return step * p
}

// rate_graph draws the rate matrix of data in the rectangle r. The caller
// draws the axis labels.
rate_graph :: proc(ui: ^UI, r: mu.Rect, data: ^Graph_Data) {
	mu.push_clip_rect(&ui.ctx, r)
	emit(ui, {kind = .Graph, r = rectf(r), ptr = data}, 1)
	mu.pop_clip_rect(&ui.ctx)
}

@(private)
draw_graph :: proc(g: ^Gfx, s: ^Shape) {
	d := (^Graph_Data)(s.ptr)
	r := s.r
	m := rate_matrix(r.w, r.h)
	if m.rows <= 0 {
		return
	}
	sc := g.scale
	// Cells snap to device pixels, so that small blocks stay sharp; the
	// corners are rounded only where the radius is a pixel or more.
	snap :: proc(v, sc: f32) -> f32 {
		return math.round(v * sc) / sc
	}
	radius := m.cell * 0.2
	rounded := radius * sc >= 1
	for c in 0 ..< RATE_COLUMNS {
		dn := matrix_blocks(m, matrix_sample(d.down, c), d.max)
		up := matrix_blocks(m, matrix_sample(d.up, c), d.max)
		front, back, front_c, back_c := up, dn, GRAPH_UP, GRAPH_DOWN
		if dn < up {
			front, back, front_c, back_c = dn, up, GRAPH_DOWN, GRAPH_UP
		}
		x := r.x + f32(c) * (m.cell + m.gap)
		x0, x1 := snap(x, sc), snap(x + m.cell, sc)
		for k in 0 ..< m.rows {
			y := r.y + r.h - f32(k + 1) * m.cell - f32(k) * m.gap
			y0, y1 := snap(y, sc), snap(y + m.cell, sc)
			col := GRAPH_EMPTY
			switch {
			case k < front:
				col = with_alpha(front_c, matrix_shade(m, k))
			case k < back:
				col = with_alpha(back_c, matrix_shade(m, k))
			}
			cell := Rectf{x0, y0, x1 - x0, y1 - y0}
			if rounded {
				rrect(g, cell, radius, col)
			} else {
				fill_rect(g, cell, col)
			}
		}
	}
}

// box_button is a square secondary button that holds an icon of the given size.
box_button :: proc(ui: ^UI, r: mu.Rect, icon: Icon_Id, name: string, icon_size: f32, enabled := true) -> bool {
	id := mu.get_id(&ui.ctx, name)
	it := interact(ui, id, r, true, enabled)
	rf := rectf(r)
	bg, border, fg := SURFACE_RAISED, BORDER, TEXT
	if !enabled {
		bg, border, fg = SURFACE, BORDER, MUTED
	} else if it.down {
		bg = mix(SURFACE, BORDER, 0.85)
	} else if it.hover {
		bg = BORDER
	}
	emit(ui, {kind = .Rrect, r = rf, radius = RADIUS_BUTTON, c1 = bg, c2 = border, width = 1})
	emit(ui, {kind = .Icon, r = {rf.x + (rf.w - icon_size) / 2, rf.y + (rf.h - icon_size) / 2, icon_size, icon_size}, icon = icon, c1 = fg}, 0)
	if it.ring {
		focus_ring(ui, rf, RADIUS_BUTTON)
	}
	return it.clicked
}

// Group is a panel whose height is known only after its content is laid out. Its
// background shape is recorded first and the height is filled in at the end.
Group :: struct {
	shape: int,
}

group_begin :: proc(ui: ^UI, r: mu.Rect, radius: f32 = RADIUS_PANEL, fill := SURFACE) -> Group {
	idx := len(ui.shapes)
	emit(ui, {kind = .Rrect, r = {f32(r.x), f32(r.y), f32(r.w), 4000}, radius = radius, c1 = fill, c2 = BORDER, width = 1})
	return {idx}
}

group_end :: proc(ui: ^UI, g: Group, h: i32) {
	ui.shapes[g.shape].r.h = f32(h)
}
