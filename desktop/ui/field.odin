// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Single-line text field. microui's text box has no caret movement, so the
// field keeps text and selection in core:text/edit and uses microui for id,
// hover, and key and text input.

import "core:math"
import "core:mem"
import "core:strings"
import "core:unicode/utf8"
import textedit "core:text/edit"
import mu "vendor:microui"

CARET_BLINK :: 0.53 // seconds

Field :: struct {
	buf:      strings.Builder,
	edit:     textedit.State,
	scroll:   f32, // how far the text is scrolled left, in logical units
	blink_t0: f64, // time of the last caret move, restarts the blink
	ready:    bool,
}

Field_Opts :: struct {
	mono:     bool,
	password: bool,
	error:    bool,
	enabled:  bool,
	plain:    bool, // the default control look: darker ground, lighter border, small corners
}

field_init :: proc(f: ^Field, initial := "") {
	f.buf = strings.builder_make()
	textedit.init(&f.edit, context.allocator, context.allocator)
	f.edit.set_clipboard = clipboard_set
	f.edit.get_clipboard = clipboard_get
	f.ready = true
	field_set(f, initial)
}

field_destroy :: proc(f: ^Field) {
	strings.builder_destroy(&f.buf)
	textedit.destroy(&f.edit)
	f^ = {}
}

field_set :: proc(f: ^Field, s: string) {
	strings.builder_reset(&f.buf)
	strings.write_string(&f.buf, s)
	f.edit.selection = {len(f.buf.buf), len(f.buf.buf)}
	f.scroll = 0
}

field_text :: proc(f: ^Field) -> string {
	return strings.to_string(f.buf)
}

// field_wipe empties the field and overwrites the old text in memory, also the
// copies in the undo history. For password fields.
field_wipe :: proc(f: ^Field) {
	for stack in ([2]^[dynamic]^textedit.Undo_State{&f.edit.undo, &f.edit.redo}) {
		for item in stack {
			mem.zero(&item.text, item.len)
		}
		textedit.undo_clear(&f.edit, stack)
	}
	mem.zero(raw_data(f.buf.buf), cap(f.buf.buf))
	field_set(f, "")
}

// display_text is the text as shown: the text itself, or a bullet per character.
@(private)
display_text :: proc(f: ^Field, password: bool) -> string {
	s := field_text(f)
	if !password {
		return s
	}
	n := utf8.rune_count_in_string(s)
	return strings.repeat("•", n, context.temp_allocator)
}

// disp_index maps a byte index of the text to one of the displayed string.
@(private)
disp_index :: proc(text: string, idx: int, password: bool) -> int {
	if !password {
		return idx
	}
	return utf8.rune_count_in_string(text[:idx]) * 3
}

// field draws a text field and handles its input. It returns whether the text
// changed and whether Enter was pressed.
field :: proc(ui: ^UI, r: mu.Rect, f: ^Field, placeholder := "", o := Field_Opts{enabled = true}) -> (changed, submitted: bool) {
	ctx := &ui.ctx
	id := mu.get_id(ctx, uintptr(f))
	it := interact(ui, id, r, true, o.enabled)
	rf := rectf(r)
	st := o.mono ? ST_MONO : ST_BODY
	lh := line_height(st)
	pad: f32 = 10
	inner_w := rf.w - pad * 2
	focused := o.enabled && ui.focus == id
	if focused {
		ui.field_focus = id
	}
	text_str := field_text(f)
	disp := display_text(f, o.password)

	f.edit.builder = &f.buf
	f.edit.id = u64(id)
	textedit.update_time(&f.edit)
	sel := &f.edit.selection
	if sel[0] > len(text_str) || sel[1] > len(text_str) {
		sel^ = {len(text_str), len(text_str)}
	}

	// Mouse: place the caret, select a word on a double click, drag to select.
	caret_at :: proc(ui: ^UI, st: Text_Style, text_str, disp: string, x: f32, password: bool) -> int {
		best := 0
		best_d := abs(x)
		for i := 0; i < len(text_str); {
			_, w := utf8.decode_rune_in_string(text_str[i:])
			i += w
			d := abs(x - text_w(ui, st, disp[:disp_index(text_str, i, password)]))
			if d < best_d {
				best, best_d = i, d
			}
		}
		return best
	}
	origin_x := rf.x + pad - f.scroll
	if o.enabled && it.hover {
		ui.cursor = .Text
	}
	if o.enabled && !(ui.block && !ui.in_popup) {
		if it.hover && .LEFT in ctx.mouse_pressed_bits {
			idx := caret_at(ui, st, text_str, disp, f32(ctx.mouse_pos.x) - origin_x, o.password)
			if ui.click_count >= 2 && !o.password {
				lo, hi := word_at(text_str, idx)
				sel^ = {hi, lo}
			} else if .SHIFT in ctx.key_down_bits {
				sel[0] = idx
			} else {
				sel^ = {idx, idx}
			}
			f.blink_t0 = ui.time
		} else if ui.press_id == id && .LEFT in ctx.mouse_down_bits && ui.click_count < 2 {
			idx := caret_at(ui, st, text_str, disp, f32(ctx.mouse_pos.x) - origin_x, o.password)
			if idx != sel[0] {
				sel[0] = idx
				f.blink_t0 = ui.time
			}
		}
	}

	// Keyboard.
	if focused {
		ctrl := .CTRL in ctx.key_down_bits && .ALT not_in ctx.key_down_bits
		moved := false
		if strings.builder_len(ctx.text_input) > 0 {
			if textedit.input_text(&f.edit, strings.to_string(ctx.text_input)) > 0 {
				changed = true
				moved = true
			}
		}
		if ctrl && .A in ctx.key_pressed_bits {
			sel^ = {len(text_str), 0}
			moved = true
		}
		if ctrl && .X in ctx.key_pressed_bits && textedit.cut(&f.edit) {
			changed = true
			moved = true
		}
		if ctrl && .C in ctx.key_pressed_bits {
			textedit.copy(&f.edit)
		}
		if ctrl && .V in ctx.key_pressed_bits && textedit.paste(&f.edit) {
			changed = true
			moved = true
		}
		move_key :: proc(f: ^Field, ctx: ^mu.Context, key: mu.Key, word, plain: textedit.Translation) -> bool {
			if key not_in ctx.key_pressed_bits {
				return false
			}
			t := .CTRL in ctx.key_down_bits ? word : plain
			if .SHIFT in ctx.key_down_bits {
				textedit.select_to(&f.edit, t)
			} else {
				textedit.move_to(&f.edit, t)
			}
			return true
		}
		moved |= move_key(f, ctx, .LEFT, .Word_Left, .Left)
		moved |= move_key(f, ctx, .RIGHT, .Word_Right, .Right)
		moved |= move_key(f, ctx, .HOME, .Start, .Start)
		moved |= move_key(f, ctx, .END, .End, .End)
		if .BACKSPACE in ctx.key_pressed_bits && len(text_str) > 0 {
			textedit.delete_to(&f.edit, .Word_Left if .CTRL in ctx.key_down_bits else .Left)
			changed = true
			moved = true
		}
		if .DELETE in ctx.key_pressed_bits && len(text_str) > 0 {
			textedit.delete_to(&f.edit, .Word_Right if .CTRL in ctx.key_down_bits else .Right)
			changed = true
			moved = true
		}
		if .RETURN in ctx.key_pressed_bits {
			submitted = true
		}
		if moved {
			f.blink_t0 = ui.time
		}
		// The key that activates buttons must not also click a focused field.
		text_str = field_text(f)
		disp = display_text(f, o.password)
		sel = &f.edit.selection
	}

	// Colours.
	border := BORDER
	switch {
	case !o.enabled:
		border = BORDER
	case o.error:
		border = ERROR
	case focused:
		border = ACCENT
	case it.hover:
		border = MUTED
	}
	bg := o.enabled ? BG : SURFACE
	radius: f32 = RADIUS_FIELD
	if o.plain {
		bg = FIELD_PLAIN_BG
		radius = 4
		if !focused && !o.error {
			border = it.hover ? FIELD_PLAIN_BORDER_HOT : FIELD_PLAIN_BORDER
		}
	}
	emit(ui, {kind = .Rrect, r = rf, radius = radius, c1 = bg, c2 = border, width = 1})
	if focused && it.ring {
		focus_ring(ui, rf, RADIUS_FIELD)
	}

	// Scroll so that the caret stays inside the field.
	head := disp_index(text_str, sel[0], o.password)
	preedit := focused && ui.preedit != "" ? ui.preedit : ""
	caret_x := text_w(ui, st, disp[:head])
	total_w := text_w(ui, st, disp) + (preedit != "" ? text_w(ui, st, preedit) : 0)
	if caret_x - f.scroll > inner_w - 1 {
		f.scroll = caret_x - inner_w + 1
	}
	if caret_x - f.scroll < 0 {
		f.scroll = caret_x
	}
	f.scroll = clamp(f.scroll, 0, max(total_w - inner_w + 2, 0))

	inner := mu.Rect{r.x + 1, r.y + 1, r.w - 2, r.h - 2}
	mu.push_clip_rect(ctx, inner)
	defer mu.pop_clip_rect(ctx)
	tx := rf.x + pad - f.scroll
	ty := math.round(rf.y + (rf.h - lh) / 2) - (o.plain ? 1 : 2)

	if text_str == "" && preedit == "" {
		text(ui, st, i32(math.round(tx)), i32(ty), placeholder, MUTED)
	}
	// Selection behind the text.
	if focused && sel[0] != sel[1] {
		lo, hi := min(sel[0], sel[1]), max(sel[0], sel[1])
		x0 := tx + text_w(ui, st, disp[:disp_index(text_str, lo, o.password)])
		x1 := tx + text_w(ui, st, disp[:disp_index(text_str, hi, o.password)])
		emit(ui, {kind = .Selection, r = {x0, ty, x1 - x0, lh}, c1 = with_alpha(ACCENT, 0.5)}, 0)
	}
	col := o.enabled ? TEXT : MUTED
	pre_w: f32
	if preedit != "" {
		// The text under composition shows at the caret with an underline.
		before := disp[:head]
		text(ui, st, i32(math.round(tx)), i32(ty), before, col)
		bw := text_w(ui, st, before)
		pre_w = text_w(ui, st, preedit)
		text(ui, st, i32(math.round(tx + bw)), i32(ty), preedit, col)
		mu.draw_rect(ctx, {i32(math.round(tx + bw)), i32(ty + lh - 1), i32(math.ceil(pre_w)), 1}, col)
		text(ui, st, i32(math.round(tx + bw + pre_w)), i32(ty), disp[head:], col)
	} else if disp != "" {
		text(ui, st, i32(math.round(tx)), i32(ty), disp, col)
	}
	if focused {
		// Caret, blinking. The next toggle is a timed redraw.
		phase := (ui.time - f.blink_t0) / CARET_BLINK
		visible := int(phase) % 2 == 0
		next := f.blink_t0 + (math.floor(phase) + 1) * CARET_BLINK
		if ui.wake_at == 0 || next < ui.wake_at {
			ui.wake_at = next
		}
		cx := tx + caret_x + pre_w
		if visible && sel[0] == sel[1] {
			px := math.round(cx * ui.g.scale) / ui.g.scale
			emit(ui, {kind = .Rrect, r = {px, ty, 1, lh}, c1 = col}, 0)
		}
		ui.ime_rect = Rectf{cx, ty, 1, lh}
	}
	return
}

// word_at returns the byte range of the word that contains idx.
@(private)
word_at :: proc(s: string, idx: int) -> (lo, hi: int) {
	is_sep :: proc(b: byte) -> bool {
		return b == ' ' || b == '\t' || b == '.' || b == '/' || b == ',' || b == ':' || b == '-'
	}
	lo, hi = idx, idx
	for lo > 0 && !is_sep(s[lo - 1]) {
		lo -= 1
	}
	for hi < len(s) && !is_sep(s[hi]) {
		hi += 1
	}
	return
}
