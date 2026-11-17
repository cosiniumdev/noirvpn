// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "noir:bus"

// Exit codes of noirvpnctl. A script can tell the causes apart. The same
// table is in README.md.
Exit :: enum u8 {
	// The operation worked.
	Ok          = 0,
	// The daemon responded with an error reply (anything but `denied`).
	Error       = 1,
	// The command line is wrong.
	Usage       = 2,
	// No daemon: no control socket, or nothing listens on it.
	Not_Running = 3,
	// The socket may not be used by this user, or the reply was `denied`. On
	// Windows also a pipe that does not belong to the service.
	Denied      = 4,
	// No reply in time. The request may still have been applied.
	Timeout     = 5,
	// Some other failure: a bus connection error, a reply that cannot be
	// read, out of memory, a file that cannot be read.
	Failed      = 6,
}

exit_for_call_error :: proc(e: bus.Call_Error) -> Exit {
	switch e {
	case .None:
		return .Ok
	case .Daemon_Not_Running:
		return .Not_Running
	case .Permission_Denied, .Not_Service:
		return .Denied
	case .Bad_Url:
		return .Usage
	case .Timeout:
		return .Timeout
	case .Io, .Bad_Reply, .No_Memory:
		return .Failed
	}
	return .Failed
}

// The exit code for an error reply with this `code`.
exit_for_reply_code :: proc(code: string) -> Exit {
	if code == "denied" {
		return .Denied
	}
	return .Error
}
