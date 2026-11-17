// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Constants and tables of the bus protocol. The written spec is separate;
// when the two differ, fix the code or the spec, not one of them.

import "noir:proto/config"

// Protocol version, the "v" field in every message.
VERSION :: 1

// Largest accepted request body, in bytes. A bigger one gets `bad_request`.
MAX_REQUEST_SIZE :: 64 * 1024

// Largest request body of an operation with `big_request` (`profile.set` and
// `profile.check`). nng drops the connection (no reply) for a message of twice
// this size.
MAX_PROFILE_REQUEST_SIZE :: 256 * 1024

// Largest reply a client accepts. The daemon keeps replies far below this by
// paging long lists (`peers.list`).
MAX_REPLY_SIZE :: 8 * 1024 * 1024

// Largest event (the JSON after the topic), in bytes. A bigger one is not
// published.
MAX_EVENT_SIZE :: 64 * 1024

// A request id is 1 to 64 printable ASCII characters (0x21 to 0x7e).
MAX_ID_LEN :: 64

// Operation and topic names: lower case letters, digits, '.', '_' and '-'.
MAX_OP_LEN :: 48
MAX_TOPIC_LEN :: 48

// Request JSON may nest this deep (objects and arrays together).
MAX_JSON_DEPTH :: 16

// The longest JSON string and the most entries in one array or object that
// the parser accepts (requests, replies and events).
MAX_JSON_STRING :: MAX_PROFILE_REQUEST_SIZE
MAX_JSON_ITEMS :: 65536

// Length of the start id ("run") in events: 16 hex characters.
RUN_ID_LEN :: 16

Role :: config.Bus_Role
Roles :: config.Bus_Roles

ALL_ROLES :: Roles{.Read, .Operator, .Auth, .Admin}

// The error codes of a failed reply.
Error_Code :: enum u8 {
	Bad_Request,
	Unknown_Op,
	Denied,
	Not_Found,
	Busy,
	Conflict,
	Timeout,
	Internal,
	Unsupported,
}

@(rodata)
error_code_names := [Error_Code]string {
	.Bad_Request = "bad_request",
	.Unknown_Op  = "unknown_op",
	.Denied      = "denied",
	.Not_Found   = "not_found",
	.Busy        = "busy",
	.Conflict    = "conflict",
	.Timeout     = "timeout",
	.Internal    = "internal",
	.Unsupported = "unsupported",
}

error_code_string :: proc "contextless" (c: Error_Code) -> string {
	return error_code_names[c]
}

error_code_from_string :: proc(s: string) -> (c: Error_Code, ok: bool) {
	for name, code in error_code_names {
		if name == s {
			return code, true
		}
	}
	return {}, false
}

// Which daemon mode an operation belongs to.
Scope :: enum u8 {
	Both,
	Server,
	Client,
}

// Which kind of daemon this is. The bus replies `unsupported` for an
// operation of the other mode.
Daemon_Mode :: enum u8 {
	Server,
	Client,
}

Op_Info :: struct {
	name:        string,
	// The lowest role that may call it.
	role:        Role,
	// Changes state: applied once per request id (see dedupe.odin).
	mutating:    bool,
	scope:       Scope,
	// The request may be up to `MAX_PROFILE_REQUEST_SIZE` bytes.
	big_request: bool,
	// The request holds a secret. The host overwrites the raw request, and the
	// parsed strings when the request is freed.
	secret:      bool,
}

// Every operation.
@(rodata)
OPS := [?]Op_Info {
	{"status", .Read, false, .Both, false, false},
	{"peers.list", .Read, false, .Server, false, false},
	{"peer.get", .Read, false, .Server, false, false},
	{"stats.get", .Read, false, .Both, false, false},
	{"peer.kick", .Operator, true, .Server, false, false},
	{"peers.reload", .Operator, true, .Server, false, false},
	{"passwords.reload", .Operator, true, .Server, false, false},
	{"log.level", .Operator, true, .Both, false, false},
	{"auth.decide", .Auth, true, .Server, false, true},
	// One-shot and never cached: the reply holds a password.
	{"auth.credentials", .Auth, false, .Server, false, false},
	{"daemon.reload", .Admin, true, .Both, false, false},
	{"daemon.shutdown", .Admin, true, .Both, false, false},
	{"connect", .Operator, true, .Client, false, false},
	{"disconnect", .Operator, true, .Client, false, false},
	{"auth.supply", .Operator, true, .Client, false, true},
	// Service mode. The request holds a profile with keys.
	{"profile.set", .Operator, true, .Client, true, true},
	{"profile.check", .Operator, false, .Client, true, true},
	{"profile.clear", .Operator, true, .Client, false, false},
}

op_lookup :: proc(name: string) -> (info: ^Op_Info, ok: bool) {
	for &o in OPS {
		if o.name == name {
			return &o, true
		}
	}
	return nil, false
}

op_in_mode :: proc "contextless" (info: ^Op_Info, mode: Daemon_Mode) -> bool {
	switch info.scope {
	case .Both:
		return true
	case .Server:
		return mode == .Server
	case .Client:
		return mode == .Client
	}
	return false
}

// What a role set really grants: admin implies every role, operator and auth
// imply read.
roles_effective :: proc "contextless" (r: Roles) -> Roles {
	e := r
	if .Admin in e {
		return ALL_ROLES
	}
	if .Operator in e || .Auth in e {
		e += {.Read}
	}
	return e
}

// May someone who holds `have` do something that needs `need`?
roles_allow :: proc "contextless" (have: Roles, need: Role) -> bool {
	return need in roles_effective(have)
}

role_name :: proc "contextless" (r: Role) -> string {
	switch r {
	case .Read:
		return "read"
	case .Operator:
		return "operator"
	case .Auth:
		return "auth"
	case .Admin:
		return "admin"
	}
	return "?"
}

// Names allowed in ops and topics: [a-z0-9._-], 1 to `max` characters, and
// they start with a letter.
valid_name :: proc "contextless" (s: string, max: int) -> bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i in 0 ..< len(s) {
		ch := s[i]
		switch ch {
		case 'a' ..= 'z':
		case '0' ..= '9', '.', '_', '-':
			if i == 0 {
				return false
			}
		case:
			return false
		}
	}
	return true
}

// A request id: 1 to MAX_ID_LEN printable ASCII characters, no space.
valid_id :: proc "contextless" (s: string) -> bool {
	if len(s) == 0 || len(s) > MAX_ID_LEN {
		return false
	}
	for i in 0 ..< len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
