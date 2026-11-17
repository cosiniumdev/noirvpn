// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import win "core:sys/windows"
import sdl "vendor:sdl3"
import "ui"

// frame_setup asks for rounded corners, border colour and shadow on a
// frameless window (older Windows refuses some; ignored). Returns true if the
// system draws the border.
frame_setup :: proc(window: ^sdl.Window) -> bool {
	hwnd := win.HWND(sdl.GetPointerProperty(sdl.GetWindowProperties(window), sdl.PROP_WINDOW_WIN32_HWND_POINTER, nil))
	if hwnd == nil {
		return false
	}
	corner := win.DWM_WINDOW_CORNER_PREFERENCE.ROUND
	hr_corner := win.DwmSetWindowAttribute(hwnd, u32(win.DWMWINDOWATTRIBUTE.DWMWA_WINDOW_CORNER_PREFERENCE), &corner, size_of(corner))
	// COLORREF is 0x00bbggrr.
	c := ui.WINDOW_BORDER
	colour := win.DWORD(c.b) << 16 | win.DWORD(c.g) << 8 | win.DWORD(c.r)
	hr_border := win.DwmSetWindowAttribute(hwnd, u32(win.DWMWINDOWATTRIBUTE.DWMWA_BORDER_COLOR), &colour, size_of(colour))
	margins := win.MARGINS{1, 1, 1, 1}
	hr_shadow := win.DwmExtendFrameIntoClientArea(hwnd, &margins)
	if stats_on {
		fmt.eprintfln("dwm corner=0x%08x border=0x%08x shadow=0x%08x", u32(hr_corner), u32(hr_border), u32(hr_shadow))
	}
	return hr_border >= 0
}
