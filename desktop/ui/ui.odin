// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// UI ties microui (layout, ids, input, containers, popups, scrolling) to the
// styled drawing in Gfx.
//
// microui records draw commands in one list that already follows container
// z-order and clip rectangles. It has no rounded shapes, so a styled widget
// records a Command_Icon with an id above CUSTOM_BASE: an index into UI.shapes,
// a per-frame table with the shape (kind, float geometry, colours). Text uses
// Command_Text with a Text_Style pointer in the font field. render() walks the
// list and draws each command with Gfx.

import "core:math"
import "core:strings"
import mu "vendor:microui"
import sdl "vendor:sdl3"

CUSTOM_BASE :: 1000

Shape_Kind :: enum u8 {
	Card, // gradient fill from the card tokens, border c2 of width width
	Rrect, // fill c1, border c2 of width width, corner radius
	Stroke, // outline only
	Circle,
	Ring,
	Shadow,
	Icon,
	Mask,
	Graph,
	Line,
	Selection,
}

Shape :: struct {
	kind:   Shape_Kind,
	r:      Rectf,
	radius: f32,
	width:  f32,
	c1, c2: Color,
	icon:   Icon_Id,
	ptr:    rawptr,
	value:  f32,
}

Anim :: struct {
	v, target: f32,
}

// A key that scrolls the view, when no text field has the focus.
Scroll_Key :: enum u8 {
	None,
	Up,
	Down,
	Page_Up,
	Page_Down,
	Home,
	End,
}

Cursor_Kind :: enum u8 {
	Default,
	Text,
	Pointer,
}

UI :: struct {
	ctx:           mu.Context,
	g:             Gfx,
	shapes:        [dynamic]Shape,
	size:          [2]i32, // logical size of the window
	window_border: bool, // draw the WINDOW_BORDER outline over the frame
	input_k:       f32, // window coordinates to logical units: d / E
	time:          f64, // seconds, set by ui_begin
	dt:            f32,

	// Keyboard focus. focus_visible is set when it moved by keyboard.
	focus:         mu.Id,
	focus_visible: bool,
	press_id:      mu.Id, // widget the mouse went down on
	press_claimed: bool,
	order:         [dynamic]mu.Id, // focusable widgets of this frame, in order
	tab_dir:       int,
	activate:      bool, // Space or Enter pressed
	escape:        bool,
	scroll_key:    Scroll_Key, // set by a key down, cleared at the end of the frame
	field_focus:   mu.Id, // the last text field that had the focus
	click_count:   int,

	// Popups. block is true while a popup was open at the start of the frame:
	// widgets outside it ignore the mouse.
	popup_open:    bool,
	block:         bool,
	in_popup:      bool,

	anims:         map[mu.Id]Anim,
	animating:     bool, // an animation needs another frame
	wake_at:       f64, // time of the next timed redraw (caret blink), 0 for none
	cursor:        Cursor_Kind,
	scroll_until:  f64, // the scrollbar shows until this time

	// Text input method state.
	preedit:       string,
	ime_rect:      Maybe(Rectf),
	ime_active:    bool,

	clipboard_buf: string,
}

@(private)
g_ui: ^UI

// ui_init sets up microui and Gfx. The UI must stay at one address.
ui_init :: proc(ui: ^UI, r: ^sdl.Renderer, scale: f32) -> bool {
	g_ui = ui
	ui.input_k = 1
	if !gfx_init(&ui.g, r, scale) {
		return false
	}
	ctx := &ui.ctx
	mu.init(ctx, clipboard_set, clipboard_get)
	ctx.text_width = proc(font: mu.Font, s: string) -> i32 {
		return i32(math.ceil(text_width(&g_ui.g, (^Text_Style)(font)^, s)))
	}
	ctx.text_height = proc(font: mu.Font) -> i32 {
		return i32(line_height((^Text_Style)(font)^))
	}
	ctx.draw_frame = draw_frame
	st := ctx.style
	st.font = font_for(ST_BODY)
	st.padding = 0
	st.spacing = 0
	st.indent = 0
	st.size = {0, 0}
	st.scrollbar_size = 8
	st.thumb_size = 24
	st.title_height = 0
	st.footer_height = 0
	return true
}

ui_destroy :: proc(ui: ^UI) {
	gfx_destroy(&ui.g)
	delete(ui.shapes)
	delete(ui.order)
	delete(ui.anims)
	delete(ui.preedit)
	delete(ui.clipboard_buf)
}

@(private)
clipboard_set :: proc(_: rawptr, text: string) -> bool {
	c := strings.clone_to_cstring(text, context.temp_allocator)
	return sdl.SetClipboardText(c)
}

@(private)
clipboard_get :: proc(_: rawptr) -> (string, bool) {
	p := sdl.GetClipboardText()
	if p == nil {
		return "", false
	}
	defer sdl.free(p)
	s := strings.clone(string(cstring(p)), context.temp_allocator)
	return s, true
}

// clipboard_copy puts text on the system clipboard.
clipboard_copy :: proc(text: string) -> bool {
	return clipboard_set(nil, text)
}

// clipboard_paste is the text of the system clipboard, in the temp allocator.
// The caller wipes it when it holds a key.
clipboard_paste :: proc() -> (string, bool) {
	return clipboard_get(nil)
}

// ui_begin starts a frame. now is the time in seconds; dt the time since the last frame.
ui_begin :: proc(ui: ^UI, now: f64, dt: f32) {
	ui.time = now
	ui.dt = dt
	ui.size.x, ui.size.y = gfx_size(&ui.g)
	clear(&ui.shapes)
	clear(&ui.order)
	ui.animating = false
	ui.wake_at = 0
	ui.cursor = .Default
	ui.press_claimed = false
	ui.block = ui.popup_open
	ui.popup_open = false
	ui.ime_rect = nil
	mu.begin(&ui.ctx)
}

// ui_end finishes the frame: focus movement and bookkeeping.
ui_end :: proc(ui: ^UI) {
	ctx := &ui.ctx
	if .LEFT in ctx.mouse_pressed_bits && !ui.press_claimed {
		ui.focus = 0
		ui.focus_visible = false
	}
	if ui.tab_dir != 0 && len(ui.order) > 0 {
		cur := -1
		for id, i in ui.order {
			if id == ui.focus {
				cur = i
			}
		}
		n := len(ui.order)
		next := ui.tab_dir > 0 ? (cur + 1) % n : (cur - 1 + n) % n
		if cur < 0 {
			next = ui.tab_dir > 0 ? 0 : n - 1
		}
		ui.focus = ui.order[next]
		ui.focus_visible = true
	}
	if ctx.scroll_target != nil || ctx.mouse_down_bits != {} && ui.time < ui.scroll_until {
		ui.scroll_until = ui.time + 1.2
	}
	if ui.scroll_until > ui.time && (ui.wake_at == 0 || ui.scroll_until < ui.wake_at) {
		ui.wake_at = ui.scroll_until
	}
	ui.tab_dir = 0
	ui.activate = false
	ui.escape = false
	ui.scroll_key = .None
	ui.click_count = 0
	mu.end(ctx)
}

// text_focused is true while a text field has the keyboard focus.
text_focused :: proc(ui: ^UI) -> bool {
	return ui.focus != 0 && ui.focus == ui.field_focus
}

// scroll_keys applies the scroll key of this frame to cnt, a scroll area whose
// visible height is view_h. It returns true when it used the key.
scroll_keys :: proc(ui: ^UI, cnt: ^mu.Container, view_h: i32) -> bool {
	if ui.scroll_key == .None || ui.block || text_focused(ui) {
		return false
	}
	STEP :: 40
	page := max(view_h - STEP, STEP)
	switch ui.scroll_key {
	case .Up:
		cnt.scroll.y -= STEP
	case .Down:
		cnt.scroll.y += STEP
	case .Page_Up:
		cnt.scroll.y -= page
	case .Page_Down:
		cnt.scroll.y += page
	case .Home:
		cnt.scroll.y = 0
	case .End:
		// microui limits the value to the content when the area begins.
		cnt.scroll.y = max(i32) / 2
	case .None:
	}
	cnt.scroll.y = max(cnt.scroll.y, 0)
	ui.scroll_key = .None
	ui.scroll_until = ui.time + 1.2
	return true
}

// ---- Drawing ----

// render draws the frame's command list. Call it between gfx_begin and gfx_end.
render :: proc(ui: ^UI) {
	g := &ui.g
	fill_vgradient(g, {0, 0, f32(g.px_w) / g.scale, f32(g.px_h) / g.scale}, BG_TOP, BG_BOTTOM)
	pcmd: ^mu.Command
	for variant in mu.next_command_iterator(&ui.ctx, &pcmd) {
		switch c in variant {
		case ^mu.Command_Rect:
			fill_rect(g, {f32(c.rect.x), f32(c.rect.y), f32(c.rect.w), f32(c.rect.h)}, c.color)
		case ^mu.Command_Text:
			st := (^Text_Style)(c.font)^
			draw_text(g, st, f32(c.pos.x), f32(c.pos.y), c.str, c.color)
		case ^mu.Command_Icon:
			idx := int(c.id) - CUSTOM_BASE
			if idx >= 0 && idx < len(ui.shapes) {
				draw_shape(ui, &ui.shapes[idx])
			}
		case ^mu.Command_Clip:
			if c.rect.w >= 0x100000 {
				set_clip(g, nil)
			} else {
				set_clip(g, Rectf{f32(c.rect.x), f32(c.rect.y), f32(c.rect.w), f32(c.rect.h)})
			}
		case ^mu.Command_Jump:
		}
	}
	set_clip(g, nil)
	if ui.window_border {
		rrect_stroke(g, {0, 0, f32(g.px_w) / g.scale, f32(g.px_h) / g.scale}, 0, 1, WINDOW_BORDER)
	}
}

@(private)
draw_shape :: proc(ui: ^UI, s: ^Shape) {
	g := &ui.g
	switch s.kind {
	case .Card:
		rrect_card(g, s.r, s.radius, s.width, CARD_TOP, CARD_MID, CARD_BOTTOM, s.c2)
	case .Rrect:
		if s.width > 0 && s.c2.a > 0 {
			rrect_border(g, s.r, s.radius, s.c1, s.c2, s.width)
		} else {
			rrect(g, s.r, s.radius, s.c1)
		}
	case .Stroke:
		rrect_stroke(g, s.r, s.radius, s.width, s.c1)
	case .Circle:
		circle(g, s.r.x + s.r.w / 2, s.r.y + s.r.h / 2, s.r.w / 2, s.c1)
	case .Ring:
		ring(g, s.r.x + s.r.w / 2, s.r.y + s.r.h / 2, s.r.w / 2, s.width, s.c1)
	case .Shadow:
		shadow(g, s.r, s.radius, s.width, s.value, s.c1)
	case .Icon:
		draw_icon(g, s.icon, s.r.x, s.r.y, s.r.w, s.c1)
	case .Mask:
		m := (^Mask)(s.ptr)
		draw_mask(g, m, s.r.x, s.r.y, s.r.w, s.r.h, s.c1)
	case .Graph:
		draw_graph(g, s)
	case .Line:
		line(g, {s.r.x, s.r.y}, {s.r.x + s.r.w, s.r.y + s.r.h}, s.width, s.c1)
	case .Selection:
		rrect(g, s.r, s.radius, s.c1)
	}
}

// emit records a shape. bound is the rectangle it can touch, used by microui to
// cull and clip it.
emit :: proc(ui: ^UI, s: Shape, grow: f32 = 1) {
	idx := len(ui.shapes)
	append(&ui.shapes, s)
	bx := i32(math.floor(s.r.x - grow))
	by := i32(math.floor(s.r.y - grow))
	bx1 := i32(math.ceil(s.r.x + s.r.w + grow))
	by1 := i32(math.ceil(s.r.y + s.r.h + grow))
	mu.draw_icon(&ui.ctx, mu.Icon(CUSTOM_BASE + idx), {bx, by, bx1 - bx, by1 - by}, s.c1)
}

// draw_frame is the microui hook for control frames. Only the scrollbar thumb is
// used by the app, drawn as a thin rounded bar inside the right margin.
@(private)
draw_frame :: proc(ctx: ^mu.Context, rect: mu.Rect, colorid: mu.Color_Type) {
	#partial switch colorid {
	case .SCROLL_THUMB:
		// The bar shows while the pointer is over a scroll area and a moment after.
		ui := g_ui
		over := abs(ui.ctx.mouse_pos.x - (rect.x + rect.w / 2)) < 12
		shown := ui.time < ui.scroll_until || over
		a := anim(ui, mu.Id(0x5c0), shown ? 1 : 0, 0.25)
		if a > 0 {
			w: f32 = 2
			r := Rectf{f32(rect.x + rect.w) - w - 2, f32(rect.y), w, f32(rect.h)}
			emit(ui, {kind = .Rrect, r = r, radius = 1, c1 = with_alpha(SCROLL_THUMB, a)})
		}
	}
}

// ---- Text helpers ----

// font_for returns a stable pointer for a text style, as microui keeps fonts as
// raw pointers.
@(private)
font_for :: proc(st: Text_Style) -> mu.Font {
	@(static) slots: [64]Text_Style
	@(static) count: int
	for i in 0 ..< count {
		if slots[i] == st {
			return mu.Font(&slots[i])
		}
	}
	assert(count < len(slots), "too many text styles")
	slots[count] = st
	count += 1
	return mu.Font(&slots[count - 1])
}

// text draws s with the top of its line box at y.
text :: proc(ui: ^UI, st: Text_Style, x, y: i32, s: string, c: Color) {
	mu.draw_text(&ui.ctx, font_for(st), s, {x, y}, c)
}

// text_w is the width of s in logical units.
text_w :: proc(ui: ^UI, st: Text_Style, s: string) -> f32 {
	return text_width(&ui.g, st, s)
}

// fit_text shortens s with an ellipsis so it fits in max_w.
fit_text :: proc(ui: ^UI, st: Text_Style, s: string, max_w: f32) -> string {
	if text_w(ui, st, s) <= max_w {
		return s
	}
	ell :: "…"
	ew := text_w(ui, st, ell)
	n := len(s)
	for n > 0 {
		n -= 1
		for n > 0 && (s[n] & 0xc0) == 0x80 {
			n -= 1
		}
		if text_w(ui, st, s[:n]) + ew <= max_w {
			break
		}
	}
	return strings.concatenate({s[:n], ell}, context.temp_allocator)
}

// fit_middle shortens s with an ellipsis in the middle so it fits in max_w:
// the start and the end stay, as for a key pin.
fit_middle :: proc(ui: ^UI, st: Text_Style, s: string, max_w: f32) -> string {
	if text_w(ui, st, s) <= max_w {
		return s
	}
	ell :: "…"
	// Keep as many characters at each end as fit, the end one shorter.
	lo, hi := 0, len(s)
	for {
		a, b := lo, hi
		if a < b {
			a += 1
			for a < b && (s[a] & 0xc0) == 0x80 {
				a += 1
			}
		}
		if a < b && b - a > 0 {
			b -= 1
			for b > a && (s[b] & 0xc0) == 0x80 {
				b -= 1
			}
		}
		if a >= b || text_w(ui, st, strings.concatenate({s[:a], ell, s[b:]}, context.temp_allocator)) > max_w {
			break
		}
		lo, hi = a, b
	}
	return strings.concatenate({s[:lo], ell, s[hi:]}, context.temp_allocator)
}

// wrap_text splits s into lines no wider than max_w, breaking at spaces and
// after "/" so long paths wrap too.
wrap_text :: proc(ui: ^UI, st: Text_Style, s: string, max_w: f32) -> []string {
	lines := make([dynamic]string, 0, 4, context.temp_allocator)
	start := 0
	last_break := -1
	i := 0
	for i < len(s) {
		c := s[i]
		i += 1
		if c == ' ' || c == '/' {
			last_break = c == ' ' ? i - 1 : i
		}
		if c == '\n' {
			append(&lines, s[start:i - 1])
			start = i
			last_break = -1
			continue
		}
		if text_w(ui, st, s[start:i]) > max_w && last_break > start {
			append(&lines, s[start:last_break])
			start = last_break
			for start < len(s) && s[start] == ' ' {
				start += 1
			}
			last_break = -1
			i = start
		}
	}
	if start < len(s) {
		append(&lines, s[start:])
	}
	return lines[:]
}

// ---- Animation ----

// anim moves a value toward target in dur seconds and returns it. A value
// that has not been seen starts at target.
anim :: proc(ui: ^UI, id: mu.Id, target: f32, dur: f32 = 0.14) -> f32 {
	a, ok := ui.anims[id]
	if !ok {
		a = {target, target}
	}
	a.target = target
	if a.v != target {
		step := ui.dt / dur
		if abs(a.v - target) <= step {
			a.v = target
		} else {
			a.v += step if a.v < target else -step
			ui.animating = true
		}
	}
	ui.anims[id] = a
	return a.v
}

// ease is a smooth step for a value in 0 to 1.
ease :: proc(t: f32) -> f32 {
	x := clamp(t, 0, 1)
	return x * x * (3 - 2 * x)
}
