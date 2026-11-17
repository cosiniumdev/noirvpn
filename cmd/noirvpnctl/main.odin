// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// noirvpnctl: the command line tool for a running noirvpn daemon.
package main

import "core:os"
import "noir:bus"

main :: proc() {
	os.exit(int(run()))
}

run :: proc() -> Exit {
	io := Io {
		out = Sink{fd = 1},
		err = Sink{fd = 2},
	}
	cmd, perr := parse_command(os.args[1:])
	defer command_destroy(&cmd)
	if perr != nil {
		msg, _ := perr.(string)
		err_line(&io, "%s", msg)
		sink_write(io.err, "try 'noirvpnctl --help'\n")
		return .Usage
	}
	stop := stop_init()
	defer stop_close(&stop)
	if cmd.kind == .Events || cmd.follow {
		// Before the nng threads start, so they block the signals too.
		if !stop_open(&stop) {
			err_line(&io, "cannot set up signal handling")
			return .Failed
		}
	}
	found: []bus.Found
	if cmd.socket == "" && cmd.kind != .Help && cmd.kind != .Version {
		found = bus.discover()
	}
	defer bus.found_destroy(found)
	return run_command(&cmd, &io, found, &stop)
}
