// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:intrinsics"
import win "core:sys/windows"

// Stopping `events` with Ctrl+C, Ctrl+Break or the close of the console. The
// handler runs on a thread of the system and only sets a flag; the loop reads
// it.

@(private = "file")
ctrl_seen: bool

@(private = "file")
on_ctrl :: proc "system" (kind: win.DWORD) -> win.BOOL {
	switch kind {
	case win.CTRL_C_EVENT, win.CTRL_BREAK_EVENT, win.CTRL_CLOSE_EVENT:
		intrinsics.atomic_store(&ctrl_seen, true)
		return win.TRUE
	}
	return win.FALSE
}

Stop :: struct {
	// Set by anyone to ask the loop to end (a test uses this).
	flag:      bool,
	installed: bool,
}

stop_init :: proc() -> Stop {
	return {}
}

stop_open :: proc(s: ^Stop) -> bool {
	if win.SetConsoleCtrlHandler(on_ctrl, win.TRUE) == win.FALSE {
		return false
	}
	s.installed = true
	return true
}

stop_close :: proc(s: ^Stop) {
	if s.installed {
		win.SetConsoleCtrlHandler(on_ctrl, win.FALSE)
		s.installed = false
	}
}

stop_requested :: proc(s: ^Stop) -> bool {
	return intrinsics.atomic_load(&s.flag) || intrinsics.atomic_load(&ctrl_seen)
}
