// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !windows
package main

import sdl "vendor:sdl3"

// frame_setup has nothing to ask of the system here. It returns false, so the
// window draws its own border.
frame_setup :: proc(window: ^sdl.Window) -> bool {
	return false
}
