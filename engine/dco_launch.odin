// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:strings"
import "noir:platform/dco"
import "noir:proto/config"

// Use of the launcher hook of platform/dco (empty unless a package fills it). It
// can start a DCO service for this process before the daemon connects. Runs
// before `priv_apply`, so the launcher still has the start privileges. The
// daemon connects to the socket it returns, like the one in the config.

// True when a launcher started a service for this process (the main thread
// owns it; a test has its own).
@(thread_local)
dco_launched: bool

// The last text of a failed `revive`, so that a repeat is not logged again.
@(thread_local)
dco_launch_last: string

dco_launch_log :: proc(level: dco.Log_Level, text: string) {
	logf(dco_log_level(level), "dco service: %s", text)
}

// Calls `start` of `l` for `datapath udco`. Returns the socket to connect to and
// the wait time. No launcher, or one that does not apply: config socket and
// DCO_WAIT_SECS. A failed start is logged and gives no wait, so the daemon goes
// on in this process at once.
dco_launch_start :: proc(l: dco.Launcher, mode: config.Datapath, name, socket: string, uid: u32) -> (path: string, wait_secs: int) {
	path, wait_secs = socket, DCO_WAIT_SECS
	if l.start == nil || mode != .Udco {
		return
	}
	status, sock, text := l.start(dco.Launch_Request{name = name, socket = socket, uid = uid, verbose = log_get_verb() >= 4, log = dco_launch_log})
	switch status {
	case .Skipped:
	case .Started:
		dco_launched = true
		path = strings.clone(sock)
		logf(.Info, "datapath udco: started a DCO service of its own at %s", sock)
	case .Failed:
		wait_secs = 0
		logf(.Warn, "datapath udco: cannot start a DCO service: %s", text)
	}
	return
}

// The uid that the process has after the privilege drop (0: it stays root).
// The host says it (`Sys_Hooks`).
dco_launch_uid :: proc() -> u32 {
	if sys_hooks.launch_uid == nil {
		return 0
	}
	return sys_hooks.launch_uid()
}

// Before a connect that follows a lost connection: asks the launcher for a
// service that is gone. Says once per text why it cannot be there.
dco_launch_revive :: proc() {
	if !dco_launched || dco.launcher.revive == nil {
		return
	}
	ok, text := dco.launcher.revive()
	if ok {
		delete(dco_launch_last)
		dco_launch_last = ""
		return
	}
	if text != dco_launch_last {
		logf(.Warn, "datapath udco: %s", text)
		delete(dco_launch_last)
		dco_launch_last = strings.clone(text)
	}
}

// At the end of the run, after the daemon closed its connection.
dco_launch_stop :: proc() {
	if dco_launched && dco.launcher.stop != nil {
		dco.launcher.stop()
	}
	dco_launched = false
}
