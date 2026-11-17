// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Input: SDL events into microui and the UI's own state.

import "core:math"
import "core:strings"
import mu "vendor:microui"
import sdl "vendor:sdl3"

// to_logical converts a position in window coordinates to logical units.
to_logical :: proc(ui: ^UI, x, y: f32) -> (lx, ly: i32) {
	return i32(math.floor(x * ui.input_k)), i32(math.floor(y * ui.input_k))
}

// handle_event passes one SDL event on. Returns true if the screen may change.
// A key down or mouse press also needs a frame at once: see needs_frame_now.
handle_event :: proc(ui: ^UI, ev: ^sdl.Event) -> bool {
	ctx := &ui.ctx
	#partial switch ev.type {
	case .MOUSE_MOTION:
		x, y := to_logical(ui, ev.motion.x, ev.motion.y)
		mu.input_mouse_move(ctx, x, y)
		return true
	case .MOUSE_BUTTON_DOWN, .MOUSE_BUTTON_UP:
		b: mu.Mouse
		switch ev.button.button {
		case sdl.BUTTON_LEFT:
			b = .LEFT
		case sdl.BUTTON_RIGHT:
			b = .RIGHT
		case sdl.BUTTON_MIDDLE:
			b = .MIDDLE
		case:
			return false
		}
		x, y := to_logical(ui, ev.button.x, ev.button.y)
		if ev.type == .MOUSE_BUTTON_DOWN {
			ui.click_count = int(ev.button.clicks)
			mu.input_mouse_down(ctx, x, y, b)
		} else {
			mu.input_mouse_up(ctx, x, y, b)
		}
		return true
	case .MOUSE_WHEEL:
		x, y := to_logical(ui, ev.wheel.mouse_x, ev.wheel.mouse_y)
		mu.input_mouse_move(ctx, x, y)
		mu.input_scroll(ctx, 0, i32(math.round(-ev.wheel.y * 40)))
		return true
	case .KEY_DOWN, .KEY_UP:
		down := ev.type == .KEY_DOWN
		k := ev.key.key
		if down {
			switch k {
			case sdl.K_TAB:
				ui.tab_dir = .LSHIFT in ev.key.mod || .RSHIFT in ev.key.mod ? -1 : 1
			case sdl.K_SPACE, sdl.K_RETURN, sdl.K_KP_ENTER:
				ui.activate = true
			case sdl.K_ESCAPE:
				ui.escape = true
			case sdl.K_UP:
				ui.scroll_key = .Up
			case sdl.K_DOWN:
				ui.scroll_key = .Down
			case sdl.K_PAGEUP:
				ui.scroll_key = .Page_Up
			case sdl.K_PAGEDOWN:
				ui.scroll_key = .Page_Down
			case sdl.K_HOME:
				ui.scroll_key = .Home
			case sdl.K_END:
				ui.scroll_key = .End
			}
		}
		if key, ok := map_key(k); ok {
			if down {
				mu.input_key_down(ctx, key)
			} else {
				mu.input_key_up(ctx, key)
			}
		}
		return true
	case .TEXT_INPUT:
		mu.input_text(ctx, string(cstring(ev.text.text)))
		delete(ui.preedit)
		ui.preedit = ""
		return true
	case .TEXT_EDITING:
		delete(ui.preedit)
		ui.preedit = strings.clone(string(cstring(ev.edit.text)))
		return true
	}
	return false
}

// needs_frame_now tells if a frame must be built right after this event.
// microui finds the widget under the mouse while building a frame, so a press
// needs one first. Held modifiers are lost if a key goes up before a frame.
needs_frame_now :: proc(ev: ^sdl.Event) -> bool {
	#partial switch ev.type {
	case .MOUSE_BUTTON_DOWN, .KEY_DOWN:
		return true
	}
	return false
}

@(private)
map_key :: proc(k: sdl.Keycode) -> (mu.Key, bool) {
	switch k {
	case sdl.K_LSHIFT, sdl.K_RSHIFT:
		return .SHIFT, true
	case sdl.K_LCTRL, sdl.K_RCTRL:
		return .CTRL, true
	case sdl.K_LGUI, sdl.K_RGUI:
		when ODIN_OS == .Darwin {
			return .CTRL, true
		}
	case sdl.K_LALT, sdl.K_RALT:
		return .ALT, true
	case sdl.K_BACKSPACE:
		return .BACKSPACE, true
	case sdl.K_DELETE:
		return .DELETE, true
	case sdl.K_RETURN, sdl.K_KP_ENTER:
		return .RETURN, true
	case sdl.K_LEFT:
		return .LEFT, true
	case sdl.K_RIGHT:
		return .RIGHT, true
	case sdl.K_HOME:
		return .HOME, true
	case sdl.K_END:
		return .END, true
	case sdl.K_A:
		return .A, true
	case sdl.K_X:
		return .X, true
	case sdl.K_C:
		return .C, true
	case sdl.K_V:
		return .V, true
	}
	return .SHIFT, false
}
