// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import "noir:bus"

// The operation and arguments a command sends.
// `args` is JSON object text, or nil for none, allocated with `allocator`. Free
// it with `request_destroy`, which wipes it first (it may hold a password).
Request :: struct {
	op:   string,
	args: []byte,
}

request_destroy :: proc(r: ^Request, allocator := context.allocator) {
	if len(r.args) > 0 {
		mem.zero_explicit(raw_data(r.args), len(r.args))
	}
	delete(r.args, allocator)
	r^ = {}
}

// Build the request of a command. `password` and `response` are the secrets read
// for `auth-supply`. `events` has no request. `offset` is the start of a page for
// `peers` (the first page is 0 or the given --offset).
build_request :: proc(
	c: ^Command,
	password, response: string,
	offset: i64 = -1,
	allocator := context.allocator,
	profile: string = "",
	key_pass: string = "",
) -> (
	r: Request,
	ok: bool,
) {
	w: bus.Writer
	bus.writer_init(&w, allocator)
	defer {
		// The writer's buffer may hold a password.
		mem.zero_explicit(raw_data(w.buf[:]), len(w.buf))
		bus.writer_destroy(&w)
	}
	has_args := true
	bus.begin_obj(&w)
	switch c.kind {
	case .None, .Help, .Version, .Events:
		return {}, false
	case .Status:
		r.op = "status"
		has_args = false
	case .Stats:
		r.op = "stats.get"
		if c.session != "" {
			bus.kv_str(&w, "session", c.session)
		}
	case .Peers:
		r.op = "peers.list"
		if c.all {
			bus.kv_bool(&w, "all", true)
		}
		if c.user != "" {
			bus.kv_str(&w, "name", c.user)
		}
		single := c.has_limit || c.has_offset
		bus.kv_int(&w, "limit", c.limit if c.has_limit else c.page_size)
		off := offset
		if off < 0 {
			off = c.offset if single else 0
		}
		bus.kv_int(&w, "offset", off)
	case .Peer:
		r.op = "peer.get"
		if c.has_peer_id {
			bus.kv_int(&w, "peer_id", c.peer_id)
		} else {
			bus.kv_str(&w, "session", c.session)
		}
	case .Kick:
		r.op = "peer.kick"
		switch {
		case c.serial != "":
			bus.kv_str(&w, "serial", c.serial)
			if c.user != "" {
				bus.kv_str(&w, "name", c.user)
			}
		case c.pin != "":
			bus.kv_str(&w, "pin", c.pin)
			if c.user != "" {
				bus.kv_str(&w, "name", c.user)
			}
		case c.has_peer_id:
			bus.kv_int(&w, "peer_id", c.peer_id)
		case c.user != "":
			bus.kv_str(&w, "name", c.user)
		case:
			bus.kv_str(&w, "session", c.session)
		}
		if c.halt {
			bus.kv_bool(&w, "halt", true)
		}
		if c.has_reason {
			bus.kv_str(&w, "reason", c.reason)
		}
	case .Reload_Peers:
		r.op = "peers.reload"
		has_args = false
	case .Reload_Passwords:
		r.op = "passwords.reload"
		has_args = false
	case .Log_Level:
		r.op = "log.level"
		bus.kv_int(&w, "verb", c.verb)
	case .Auth_Allow:
		r.op = "auth.decide"
		bus.kv_str(&w, "session", c.session)
		bus.kv_str(&w, "decision", "allow")
		if len(c.push) > 0 {
			bus.kv_arr(&w, "push")
			for line in c.push {
				bus.val_str(&w, line)
			}
			bus.end(&w)
		}
		if c.auth_name != "" {
			bus.kv_str(&w, "name", c.auth_name)
		}
		if c.has_lifetime {
			bus.kv_int(&w, "token_lifetime", c.lifetime_s)
		}
	case .Auth_Deny:
		r.op = "auth.decide"
		bus.kv_str(&w, "session", c.session)
		bus.kv_str(&w, "decision", "deny")
		if c.has_reason {
			bus.kv_str(&w, "reason", c.reason)
		}
	case .Auth_Pending:
		r.op = "auth.decide"
		bus.kv_str(&w, "session", c.session)
		bus.kv_str(&w, "decision", "pending")
		if c.has_timeout_s {
			bus.kv_int(&w, "timeout", c.timeout_s)
		}
		if c.url != "" {
			bus.kv_str(&w, "url", c.url)
			if len(c.flags) > 0 {
				bus.kv_arr(&w, "flags")
				for f in c.flags {
					bus.val_str(&w, f)
				}
				bus.end(&w)
			}
		}
	case .Auth_Credentials:
		r.op = "auth.credentials"
		bus.kv_str(&w, "session", c.session)
	case .Reload:
		r.op = "daemon.reload"
		has_args = false
	case .Shutdown:
		r.op = "daemon.shutdown"
		if c.has_timeout_s {
			bus.kv_int(&w, "timeout_s", c.timeout_s)
		}
	case .Connect:
		r.op = "connect"
		has_args = false
	case .Disconnect:
		r.op = "disconnect"
		has_args = false
	case .Profile_Set, .Profile_Check:
		r.op = "profile.set" if c.kind == .Profile_Set else "profile.check"
		bus.kv_str(&w, "text", profile)
		bus.kv_str(&w, "label", c.label)
		if c.sso {
			bus.kv_arr(&w, "sso")
			bus.val_str(&w, "webauth")
			bus.end(&w)
		}
	case .Profile_Clear:
		r.op = "profile.clear"
		has_args = false
	case .Rules:
		r.op = "acl.get"
		has_args = false
	case .Reload_Rules:
		r.op = "acl.reload"
		has_args = false
	case .Auth_Supply:
		r.op = "auth.supply"
		if c.has_username {
			bus.kv_str(&w, "username", c.username)
		}
		if c.password_src != .None {
			bus.kv_str(&w, "password", password)
		}
		if c.response_src != .None {
			bus.kv_str(&w, "response", response)
		}
		if c.key_pass_src != .None {
			bus.kv_str(&w, "key_pass", key_pass)
		}
	}
	bus.end(&w)
	if w.failed {
		return {}, false
	}
	if has_args {
		r.args = make([]byte, len(w.buf), allocator)
		copy(r.args, w.buf[:])
	}
	return r, true
}

// May a request be sent again with the same id after a timeout? A state-changing
// operation is applied once per id; a read can
// repeat freely. Exception: `auth.credentials` gives the password once, so a
// repeat after a lost reply would get nothing.
retry_safe :: proc(op: string) -> bool {
	return op != "auth.credentials"
}
