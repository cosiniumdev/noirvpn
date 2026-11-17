// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "noir:bus"
import "noir:platform/event"

// What the client engine needs from its host program, and what it gives back.
// The engine has no bus, signals, terminal or exit. The host (daemon or library
// caller) fills these tables; a nil hook does nothing.
//
//	Host       one table per engine instance (`d.host`): events that
//	           leave the engine, the questions it asks
//	Reply      the response to one operation (`status`, `connect`, ...): the host
//	           gives the result object and the hooks that send the response
//	Caller     who asks, as plain data
//	Sys_Hooks  system services for the whole process, set once at start
//
// The log has its own process-wide sink (log.odin).

// ----------------------------------------------------------------- the host

Host :: struct {
	user:         rawptr,
	// True when somebody takes events. When false the engine does not build them.
	events_on:    proc(user: rawptr) -> bool,
	// One event: the topic and the JSON of its data (nil when the data could
	// not be built). The data lives until the call returns.
	event:        proc(user: rawptr, topic: string, data: []u8),
	// True when credentials can come from outside (`auth.supply`).
	control_on:   proc(user: rawptr) -> bool,
	// The event loop exists: the host may watch its own descriptors in it.
	// False stops the start.
	loop_ready:   proc(user: rawptr, loop: ^event.Loop) -> bool,
	// Before the records of an earlier run are cleaned up: the host creates the
	// folders it owns.
	prepare_state: proc(user: rawptr),
	// Asks for the login again after a refused one that was typed. The host
	// owns the terminal.
	prompt_creds: proc(user: rawptr, c: ^Creds, username_only: bool) -> Cred_Error,
}

host_events_on :: proc(d: ^Daemon) -> bool {
	return d.host.events_on != nil && d.host.events_on(d.host.user)
}

host_control_on :: proc(d: ^Daemon) -> bool {
	return d.host.control_on != nil && d.host.control_on(d.host.user)
}

// Starts the data object of an event. nil when nobody takes events (then the
// caller skips the work). Finish with `ev_emit`.
ev_begin :: proc(d: ^Daemon) -> ^bus.Writer {
	if !d.ev_w_ok || !host_events_on(d) {
		return nil
	}
	bus.writer_reset(&d.ev_w)
	bus.begin_obj(&d.ev_w)
	return &d.ev_w
}

// Closes the data object and gives it to the host under `topic`.
ev_emit :: proc(d: ^Daemon, topic: string) {
	bus.end(&d.ev_w)
	if d.host.event != nil {
		if !d.ev_w.failed {
			d.host.event(d.host.user, topic, bus.writer_bytes(&d.ev_w))
		} else {
			// Out of memory: still tell the host, so that a counter shows a gap.
			d.host.event(d.host.user, topic, nil)
		}
	}
	bus.writer_reset(&d.ev_w)
}

// ---------------------------------------------------------------- operations

// Who asks. The host fills it from what it knows of the sender; the engine
// uses it for the owner rule of a service profile.
Caller :: struct {
	// The operation, for the log.
	op:    string,
	uid:   u32,
	gid:   u32,
	// Windows: the user SID. Every pipe client has the uid 0 there.
	sid:   bus.Sid,
	roles: bus.Roles,
}

// The response to one operation. `w` is the result object: the host opens it
// before the call (it may add fields), the operation adds its own, then calls
// `reply_ok`. An error goes through `reply_err`. Call exactly one, once.
Reply :: struct {
	user:        rawptr,
	w:           ^bus.Writer,
	// The result is complete: send it.
	ok:          proc(user: rawptr),
	err:         proc(user: rawptr, code: bus.Error_Code, text: string),
	err_details: proc(user: rawptr, code: bus.Error_Code, text: string, details: []u8),
	// Overwrite the strings of the request (it held a secret).
	wipe_args:   proc(user: rawptr),
}

reply_ok :: proc(r: ^Reply) {
	if r.ok != nil {
		r.ok(r.user)
	}
}

reply_err :: proc(r: ^Reply, code: bus.Error_Code, text: string) {
	if r.err != nil {
		r.err(r.user, code, text)
	}
}

reply_err_details :: proc(r: ^Reply, code: bus.Error_Code, text: string, details: []u8) {
	if r.err_details != nil {
		r.err_details(r.user, code, text, details)
	}
}

reply_wipe_args :: proc(r: ^Reply) {
	if r.wipe_args != nil {
		r.wipe_args(r.user)
	}
}

// An error reply for an operation with a secret: the strings of the request
// are overwritten first.
reply_err_wipe :: proc(r: ^Reply, code: bus.Error_Code, text: string) {
	reply_wipe_args(r)
	reply_err(r, code, text)
}

// ------------------------------------------------------------- the process

// System services that the engine needs and that belong to the program. Set
// once at start, before the first engine call.
Sys_Hooks :: struct {
	// Why `user` and `group` of the config cannot be used here, or "".
	priv_settings_error: proc(user, group: string) -> string,
	// The uid that the process has after the privilege drop (0: root).
	launch_uid:          proc() -> u32,
}

sys_hooks: Sys_Hooks

host_priv_error :: proc(user, group: string) -> string {
	if sys_hooks.priv_settings_error == nil {
		return ""
	}
	return sys_hooks.priv_settings_error(user, group)
}
