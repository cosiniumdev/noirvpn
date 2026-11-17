// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "noir:bus"
import "noir:engine"
import "noir:platform/event"

// The daemon as the host of the client engine: the one engine instance, what
// the engine needs from the process (the log sink, the privilege hooks), and
// the hooks of the instance that connect it to the bus, the signals and the
// terminal.

// The one client of this process.
D: Daemon

// The signal descriptor of the process (signals_*.odin).
@(private = "file")
sig_fd: i32
@(private = "file")
sig_ready: bool

// Set at the start of the process, also in a test.
@(init)
daemon_host_init :: proc "contextless" () {
	log_set_sink(log_write)
	engine.sys_hooks = Sys_Hooks {
		priv_settings_error = priv_settings_error,
		launch_uid          = priv_launch_uid,
	}
}

// The uid that the process has after `priv_apply` (0: it stays root).
priv_launch_uid :: proc() -> u32 {
	when ODIN_OS == .Linux {
		if PRIV.on && PRIV.change_uid {
			return PRIV.uid
		}
	}
	return 0
}

// Opens the signal descriptor, once. False after nothing was opened.
daemon_sig_open :: proc() -> (fd: i32, ok: bool) {
	if !sig_ready {
		sfd, sok := sig_open()
		if !sok {
			return -1, false
		}
		sig_fd = sfd
		sig_ready = true
	}
	return sig_fd, true
}

// Gives the engine its hooks.
daemon_attach :: proc(d: ^Daemon) {
	d.host = Host {
		user          = d,
		events_on     = host_bus_events_on,
		event         = host_bus_event,
		control_on    = host_bus_control_on,
		loop_ready    = host_loop_ready,
		prepare_state = host_prepare_state,
		prompt_creds  = host_prompt_creds,
	}
}

@(private = "file")
host_bus_events_on :: proc(user: rawptr) -> bool {
	return B.h != nil && B.events_on
}

// An event of the engine goes to the bus as it is.
@(private = "file")
host_bus_event :: proc(user: rawptr, topic: string, data: []u8) {
	bus.publish(B.h, topic, data)
}

@(private = "file")
host_bus_control_on :: proc(user: rawptr) -> bool {
	return B.h != nil && B.control_on
}

// The signals are read in the loop of the engine.
@(private = "file")
host_loop_ready :: proc(user: rawptr, loop: ^event.Loop) -> bool {
	fd, ok := daemon_sig_open()
	if !ok {
		logf(.Error, "cannot set up signal handling")
		return false
	}
	if err := sig_watch(loop, fd, on_signal, user); err != .None {
		logf(.Error, "cannot watch the signal descriptor: %v", err)
		return false
	}
	return true
}

@(private = "file")
host_prepare_state :: proc(user: rawptr) {
	d := (^Daemon)(user)
	bus_prepare_dirs(&d.cfg.common, .Client, d.inst_name)
}

@(private = "file")
host_prompt_creds :: proc(user: rawptr, c: ^Creds, username_only: bool) -> Cred_Error {
	return cred_prompt(c, username_only, sig_fd)
}

// ---------------------------------------------------------------- signals

on_signal :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := (^Daemon)(user)
	for _ in 0 ..< 16 {
		sig := sig_read(fd)
		if sig == 0 {
			return
		}
		handle_signal(d, sig)
	}
}

handle_signal :: proc(d: ^Daemon, sig: int) {
	switch sig {
	case SIGINT, SIGTERM:
		daemon_stop_signal(d)
	case SIGHUP, SIGUSR1:
		daemon_reconnect_now(d)
	case SIGUSR2:
		daemon_print_status(d)
	}
}

// The `datapath` value of the status, the stats and `daemon.start`: "dco" or "udco"
// when the data channel is the backend's, else "userspace".
bus_datapath :: proc() -> string {
	when ODIN_OS == .Linux {
		if B.mode == .Server {
			return dco_datapath_name(SV.dco.kind) if SV.dco.on else "userspace"
		}
	}
	return daemon_datapath(&D)
}
