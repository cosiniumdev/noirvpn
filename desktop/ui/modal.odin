// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Modal dialog layer: a popup container over the whole window. It takes the
// mouse, so the widgets below get no hover and no clicks.

import mu "vendor:microui"

// modal_begin opens the full-window container name. fresh (first frame of the
// dialog) moves it to the top. Returns false if the container is not drawn.
// Draw the dialog, then call modal_end.
modal_begin :: proc(ui: ^UI, name: string, fresh: bool) -> bool {
	ctx := &ui.ctx
	cnt := menu_container(ctx, name)
	cnt.open = true
	cnt.rect = {0, 0, ui.size.x, ui.size.y}
	if fresh {
		ctx.hover_root = cnt
		ctx.next_hover_root = cnt
		mu.bring_to_front(ctx, cnt)
	}
	opt := mu.Options{.NO_RESIZE, .NO_SCROLL, .NO_TITLE, .NO_FRAME, .NO_CLOSE}
	if !mu.begin_window(ctx, name, cnt.rect, opt) {
		return false
	}
	ui.popup_open = true
	ui.in_popup = true
	return true
}

modal_end :: proc(ui: ^UI) {
	ui.in_popup = false
	mu.end_window(&ui.ctx)
}
