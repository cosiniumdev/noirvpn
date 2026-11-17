// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Popup menu. It is a microui popup window, so it sits above the other
// containers, takes the mouse while it is open and closes on a click outside.

import "core:math"
import mu "vendor:microui"

MENU_ITEM_H :: 28
MENU_PAD :: 5
MENU_MIN_W :: 110

Menu_Item :: struct {
	label:  string,
	danger: bool,
}

// menu_size is the size of a menu with the given items.
menu_size :: proc(ui: ^UI, items: []Menu_Item) -> (w, h: i32) {
	wmax: f32
	for it in items {
		wmax = max(wmax, text_w(ui, ST_BODY, it.label))
	}
	w = max(i32(math.ceil(wmax)) + 48, MENU_MIN_W)
	h = i32(len(items)) * MENU_ITEM_H + MENU_PAD * 2
	return
}

// menu_container finds the container of a popup. Popups live outside the root
// window, so the id stack must be empty when its id is computed.
@(private)
menu_container :: proc(ctx: ^mu.Context, name: string, opt := mu.Options{}) -> ^mu.Container {
	saved := ctx.id_stack.idx
	ctx.id_stack.idx = 0
	defer ctx.id_stack.idx = saved
	return mu.get_container(ctx, name, opt)
}

// menu_open opens the popup name with its top right corner at x, y.
menu_open :: proc(ui: ^UI, name: string, items: []Menu_Item, right, y: i32) {
	ctx := &ui.ctx
	w, h := menu_size(ui, items)
	cnt := menu_container(ctx, name)
	cnt.open = true
	cnt.rect = {right - w, y, w, h}
	ctx.hover_root = cnt
	ctx.next_hover_root = cnt
	mu.bring_to_front(ctx, cnt)
	ui.popup_open = true
}

menu_close :: proc(ui: ^UI, name: string) {
	if cnt := menu_container(&ui.ctx, name, {.CLOSED}); cnt != nil {
		cnt.open = false
	}
}

menu_is_open :: proc(ui: ^UI, name: string) -> bool {
	cnt := menu_container(&ui.ctx, name, {.CLOSED})
	return cnt != nil && bool(cnt.open)
}

// menu draws the popup if it is open. It returns the index of the chosen item,
// or -1. Call it every frame, after the content below it.
menu :: proc(ui: ^UI, name: string, items: []Menu_Item) -> (picked: int) {
	picked = -1
	ctx := &ui.ctx
	cnt := menu_container(ctx, name, {.CLOSED})
	if cnt == nil || !cnt.open {
		return
	}
	opt := mu.Options{.POPUP, .NO_RESIZE, .NO_SCROLL, .NO_TITLE, .NO_FRAME, .NO_CLOSE}
	if !mu.begin_window(ctx, name, cnt.rect, opt) {
		return
	}
	defer mu.end_window(ctx)
	ui.popup_open = true
	ui.in_popup = true
	defer ui.in_popup = false

	r := cnt.rect
	emit(ui, {kind = .Shadow, r = rectf(r), radius = RADIUS_MENU, width = 14, value = 4, c1 = {0, 0, 0, 90}}, 20)
	emit(ui, {kind = .Rrect, r = rectf(r), radius = RADIUS_MENU, c1 = SURFACE_RAISED, c2 = BORDER, width = 1})
	for it, i in items {
		ir := mu.Rect{r.x + 1 + MENU_PAD - 1, r.y + MENU_PAD + i32(i) * MENU_ITEM_H, r.w - 2 * MENU_PAD + 2, MENU_ITEM_H}
		id := mu.get_id(ctx, it.label)
		res := interact(ui, id, ir)
		if res.hover || res.down {
			emit(ui, {kind = .Rrect, r = {f32(ir.x), f32(ir.y + 2), f32(ir.w), f32(ir.h - 4)}, radius = 4, c1 = BORDER})
		}
		col := it.danger ? ERROR : TEXT
		th := line_height(ST_BODY)
		text(ui, ST_BODY, r.x + 12, i32(math.round(f32(ir.y) + (f32(ir.h) - th) / 2)) - 2, it.label, col)
		if res.ring {
			focus_ring(ui, {f32(ir.x), f32(ir.y + 2), f32(ir.w), f32(ir.h - 4)}, 4)
		}
		if res.clicked {
			picked = i
			cnt.open = false
		}
	}
	if ui.escape {
		cnt.open = false
	}
	return
}
