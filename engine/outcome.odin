// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "noir:client"
import "noir:proto/push"
import "noir:proto/session"

// Exit codes of the daemon (see README.md).
Exit :: enum int {
	Ok       = 0,
	// The config has errors or asks for something the daemon refuses.
	Config   = 1,
	// The command line is wrong.
	Usage    = 2,
	// Privileges, tun device, netlink, sockets, event loop.
	System   = 3,
	// The server refused the login, or there are no credentials.
	Auth     = 4,
	// The server sent HALT.
	Halted   = 5,
	// connect-retry-max or resolv-retry used up, or nothing to connect to.
	Gave_Up  = 6,
	// The tunnel came up but addresses, routes or MTU could not be set.
	Network  = 7,
	// `inactive` or `session-timeout` ended the run.
	Limit    = 8,
}

// The exit code for a policy that stopped.
stop_exit :: proc "contextless" (r: client.Stop_Reason) -> Exit {
	switch r {
	case .None, .Local_Stop:
		return .Ok
	case .Auth_Failed:
		return .Auth
	case .Halted:
		return .Halted
	case .Retries_Exhausted, .Resolve_Failed:
		return .Gave_Up
	case .Inactive, .Session_Timeout:
		return .Limit
	case .No_Remote:
		return .Config
	}
	return .Ok
}

// What the session said before it failed. The events that carry the detail
// (Auth_Failed, Restart, Halt, Remote_Exit) come before the `Failed` event.
Pending_Kind :: enum u8 {
	None,
	Auth_Failed,
	Restart,
	Halt,
	Remote_Exit,
}

Pending :: struct {
	kind:        Pending_Kind,
	auth_kind:   push.Auth_Failed_Kind,
	backoff:     int,
	advance:     push.Temp_Advance,
	next_remote: bool,
	// The login used a saved auth-token.
	used_token:  bool,
}

advance_of :: proc "contextless" (a: push.Temp_Advance) -> client.Advance {
	switch a {
	case .Unset:
		return .Default
	case .No:
		return .No
	case .Addr:
		return .Addr
	case .Remote:
		return .Remote
	}
	return .Default
}

// Maps how a session failed to the outcome of the connection attempt (table
// above `client.Outcome`). `was_up`: the tunnel had come up, so a failure is a
// lost connection (before that: a failed handshake).
failure_outcome :: proc(reason: session.Fail_Reason, was_up: bool, p: Pending) -> (client.Outcome, client.Outcome_Info) {
	switch reason {
	case .None:
		return .Handshake_Failed, {}
	case .Server_Signal:
		switch p.kind {
		case .Restart:
			return .Server_Restart, {next_remote = p.next_remote}
		case .Halt:
			return .Server_Halt, {}
		case .Remote_Exit, .None, .Auth_Failed:
			return .Remote_Exit, {}
		}
	case .Auth_Failed:
		// A refused saved token (AUTH_FAILED,SESSION, or the plain form that
		// stock servers send for an expired token): log in again at once with
		// the first credentials, or a new web sign-in. The token is dropped.
		if p.used_token && p.auth_kind != .Temp {
			return .Local_Restart, {}
		}
		if p.auth_kind == .Temp {
			return .Auth_Failed_Temp, {backoff_secs = p.backoff, advance = advance_of(p.advance)}
		}
		return .Auth_Failed, {}
	case .Hand_Window:
		return .Ping_Restart if was_up else .Handshake_Timeout, {}
	case .No_Push_Reply:
		return .Handshake_Timeout, {}
	case .Tls, .Cert_Revoked, .Crl_Failed, .Key_Method, .Protocol, .Internal:
		return .Ping_Restart if was_up else .Handshake_Failed, {}
	case .Push, .Key_Export:
		return .Push_Rejected, {}
	case .Link_Error:
		return .Ping_Restart if was_up else .Connect_Failed, {}
	case .Ping_Timeout:
		return .Ping_Restart, {}
	}
	return .Handshake_Failed, {}
}

// Why a graceful close was started. The first one wins, except that a stop
// always wins.
Close_Reason :: enum u8 {
	None,
	// SIGINT or SIGTERM.
	Stop,
	// A setup error: the daemon stops with `exit_code`.
	Fatal,
	// SIGHUP or SIGUSR1: reconnect.
	Restart,
	Inactive,
	Session_Timeout,
	// `disconnect` on the bus: close, then wait for `connect`.
	Disconnect,
	// The DCO service failed the setup of the data path: close, then connect again
	// at once with the data path in this process.
	Datapath,
}

close_outcome :: proc "contextless" (r: Close_Reason) -> client.Outcome {
	switch r {
	case .None, .Stop, .Fatal, .Disconnect:
		return .Local_Stop
	case .Restart:
		return .Local_Restart
	case .Datapath:
		return .Datapath_Failed
	case .Inactive:
		return .Inactive
	case .Session_Timeout:
		return .Session_Timeout
	}
	return .Local_Stop
}

close_reason_stops :: proc "contextless" (r: Close_Reason) -> bool {
	return r == .Stop || r == .Fatal
}

// The reason ends the process. In service mode only a stop does: a fatal error
// of the connection moves the daemon to `stopped`.
close_reason_exits :: proc "contextless" (d: ^Daemon, r: Close_Reason) -> bool {
	return r == .Stop || (r == .Fatal && !d.service)
}
