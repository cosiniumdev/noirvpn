// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package dco

// Hook for a program that starts its own data-channel service. Empty unless
// a package fills `launcher`. The daemon calls it before it connects to the
// socket and at the end of its run:
//
//   start    before the first connect, with the start-up privileges
//   revive   before a connect that follows a lost connection
//   stop     after the daemon closed its connection, at the end of the run
//
// `log` may be called from another thread.

Launch_Log :: #type proc(level: Log_Level, text: string)

Launch_Request :: struct {
	// The instance name of the daemon (unique on the host).
	name:    string,
	// The socket path from the config.
	socket:  string,
	// The user that the process runs as after start-up (0: it stays root).
	uid:     u32,
	// The daemon logs at the debug level.
	verbose: bool,
	log:     Launch_Log,
}

Launch_Status :: enum u8 {
	// The launcher does not apply: use `socket` of the config as it is.
	Skipped,
	// A service runs now at the returned socket.
	Started,
	// It was wanted and failed: `text` says why.
	Failed,
}

Launcher :: struct {
	start:  proc(req: Launch_Request) -> (status: Launch_Status, socket: string, text: string),
	// False with a text when the service is gone and cannot be started again.
	revive: proc() -> (ok: bool, text: string),
	stop:   proc(),
}

launcher: Launcher
