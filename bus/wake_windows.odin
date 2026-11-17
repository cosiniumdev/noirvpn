// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package bus

// The wake-up object on Windows: a manual-reset event, signalled while the
// control server has something for the daemon's loop.

import win "core:sys/windows"

Wake :: struct {
	ev: win.HANDLE,
}

wake_open :: proc(w: ^Wake) -> bool {
	w.ev = win.CreateEventW(nil, win.TRUE, win.FALSE, nil)
	return w.ev != nil
}

wake_close :: proc(w: ^Wake) {
	if w.ev != nil {
		win.CloseHandle(w.ev)
		w.ev = nil
	}
}

wake_signal :: proc(w: ^Wake) {
	win.SetEvent(w.ev)
}

wake_clear :: proc(w: ^Wake) {
	win.ResetEvent(w.ev)
}

// The event to wait on in the daemon's loop (WaitForMultipleObjects, or a
// handle source of the event loop). It is signalled while `next_request` or
// `next_notice` has something. It is reset when both are empty. Do not reset
// or close it.
host_wake_handle :: proc(h: ^Host) -> win.HANDLE {
	return h.wake.ev
}
