// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:intrinsics"
import win "core:sys/windows"
import "noir:platform/event"

// Windows has no signals. Ctrl+C, Ctrl+Break, the close of the console and a
// stop from the service manager post a signal number from another thread. An
// event wakes the loop, and `sig_read` gives the numbers to the same handlers as
// on Linux. Ctrl+C and Ctrl+Break are SIGINT; console close, log off and shut
// down are SIGTERM.

SIGHUP :: 1
SIGINT :: 2
SIGUSR1 :: 10
SIGUSR2 :: 12
SIGPIPE :: 13
SIGTERM :: 15

// What the daemon says when `has_net_admin` is false.
PRIV_TEXT :: "administrator rights are needed to create the tunnel adapter and set routes (use an elevated prompt, or run noirvpn as a service)"

@(private = "file")
sig_mask: u32
@(private = "file")
sig_event: win.HANDLE
@(private = "file")
sig_handler: event.Fd_Handler
@(private = "file")
sig_user: rawptr

// Creates the event and, in a console, installs the console handler. There is
// no descriptor: `fd` is -1.
sig_open :: proc() -> (fd: i32, ok: bool) {
	if sig_event != nil {
		return -1, true
	}
	sig_event = win.CreateEventW(nil, win.FALSE, win.FALSE, nil)
	if sig_event == nil {
		return -1, false
	}
	if !svc_mode {
		// A parent can start the process with Ctrl+C turned off (a new
		// process group, or one that ignores it): turn it on again.
		win.SetConsoleCtrlHandler(nil, win.FALSE)
		if !win.SetConsoleCtrlHandler(console_handler, win.TRUE) {
			return -1, false
		}
	}
	return -1, true
}

// Posts a signal for the loop. Safe from any thread.
sig_post :: proc "contextless" (sig: int) {
	intrinsics.atomic_or(&sig_mask, u32(1) << u32(sig))
	if sig_event != nil {
		win.SetEvent(sig_event)
	}
}

// A signal waits that `sig_read` has not taken yet.
sig_pending :: proc "contextless" () -> bool {
	return intrinsics.atomic_load(&sig_mask) != 0
}

// The next pending signal number, or 0 if there is none.
sig_read :: proc(fd: i32) -> int {
	for {
		m := intrinsics.atomic_load(&sig_mask)
		if m == 0 {
			return 0
		}
		bit := intrinsics.count_trailing_zeros(m)
		if _, ok := intrinsics.atomic_compare_exchange_strong(&sig_mask, m, m & ~(u32(1) << bit)); ok {
			return int(bit)
		}
	}
}

// Puts the event into the loop. `handler` runs as for a readable descriptor.
sig_watch :: proc(loop: ^event.Loop, fd: i32, handler: event.Fd_Handler, user: rawptr) -> event.Error {
	sig_handler, sig_user = handler, user
	return event.add_handle(loop, sig_event, on_sig_event, nil)
}

@(private = "file")
on_sig_event :: proc(loop: ^event.Loop, h: win.HANDLE, user: rawptr) {
	sig_handler(loop, -1, {.Read}, sig_user)
}

@(private = "file")
console_handler :: proc "system" (ctrl: win.DWORD) -> win.BOOL {
	switch ctrl {
	case win.CTRL_C_EVENT, win.CTRL_BREAK_EVENT:
		sig_post(SIGINT)
		return win.TRUE
	case win.CTRL_CLOSE_EVENT, win.CTRL_LOGOFF_EVENT, win.CTRL_SHUTDOWN_EVENT:
		// Windows ends the process when this returns. The loop removes the
		// routes and the DNS settings and exits first.
		sig_post(SIGTERM)
		win.Sleep(20_000)
		return win.TRUE
	}
	return win.FALSE
}

// True if the token is a member of the Administrators group with the group
// enabled: an elevated administrator, or LocalSystem. wintun needs that.
has_net_admin :: proc() -> bool {
	sid: [68]u8
	size := u32(len(sid))
	if !CreateWellKnownSid(WIN_BUILTIN_ADMINISTRATORS_SID, nil, &sid[0], &size) {
		return true
	}
	member: win.BOOL
	if !CheckTokenMembership(nil, &sid[0], &member) {
		return true
	}
	return bool(member)
}
