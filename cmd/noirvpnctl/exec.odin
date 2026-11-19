// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:os"
import "core:strings"
import "noir:bus"

// Run a parsed command: find the daemon, send the request, print the reply.
// `found` is what `bus.discover` found (a test passes its own list).
run_command :: proc(c: ^Command, io: ^Io, found: []bus.Found, stop: ^Stop) -> Exit {
	switch c.kind {
	case .Help:
		out_text(io, USAGE)
		return .Ok
	case .Version:
		out_text(io, VERSION)
		out_text(io, "\n")
		return .Ok
	case .None:
		err_line(io, "no command was given")
		return .Usage
	case .Status, .Stats, .Peers, .Peer, .Kick, .Reload_Peers, .Reload_Passwords, .Log_Level, .Auth_Allow, .Auth_Deny, .Auth_Pending, .Auth_Credentials, .Reload, .Shutdown, .Connect, .Disconnect, .Auth_Supply, .Events, .Profile_Set, .Profile_Check, .Profile_Clear, .Rules, .Reload_Rules:
	}

	t, terr, detail := resolve_target(c, found)
	if terr == .Not_Running {
		if dir := bus.hidden_dir(context.temp_allocator); dir != "" {
			err_line(io, "permission denied: this user is not allowed to look into %s (is it in the daemon's bus group?)", dir)
			return .Denied
		}
	}
	if terr != .None && !(terr == .No_Events_Socket && c.kind != .Events && !c.follow) {
		err_line(io, "%s", target_error_text(terr, detail, c))
		return .Not_Running if terr == .Not_Running else .Usage
	}
	switch c.kind {
	case .Events:
		return run_events(c, t, io, stop)
	case .Connect:
		if c.follow {
			return run_connect_follow(c, t, io, stop)
		}
	case .Peers:
		return run_peers(c, t, io)
	case .Help, .Version, .None, .Status, .Stats, .Peer, .Kick, .Reload_Peers, .Reload_Passwords, .Log_Level, .Auth_Allow, .Auth_Deny, .Auth_Pending, .Auth_Credentials, .Reload, .Shutdown, .Disconnect, .Auth_Supply, .Profile_Set, .Profile_Check, .Profile_Clear, .Rules, .Reload_Rules:
	}

	// The profile file is sent as it is. It holds keys: the copy is overwritten at the end.
	profile: string
	defer secret_destroy(&profile)
	if c.kind == .Profile_Set || c.kind == .Profile_Check {
		data, rerr := os.read_entire_file(c.file, context.allocator)
		if rerr != nil {
			err_line(io, "cannot read the profile file '%s'", c.file)
			return .Failed
		}
		profile = string(data)
		if len(profile) > PROFILE_FILE_MAX {
			err_line(io, "the profile file '%s' is larger than %d bytes", c.file, PROFILE_FILE_MAX)
			return .Failed
		}
	}

	// The secrets of auth-supply, read before the request is built.
	password, response, key_pass: string
	defer secret_destroy(&password)
	defer secret_destroy(&response)
	defer secret_destroy(&key_pass)
	if c.kind == .Auth_Supply {
		msg: string
		bad_value: bool
		password, msg, bad_value = read_secret(c.password_src, c.password_file, "password", io)
		if msg != "" {
			err_line(io, "%s", msg)
			return .Usage if bad_value else .Failed
		}
		response, msg, bad_value = read_secret(c.response_src, c.response_file, "response", io)
		if msg != "" {
			err_line(io, "%s", msg)
			return .Usage if bad_value else .Failed
		}
		key_pass, msg, bad_value = read_secret(c.key_pass_src, c.key_pass_file, "key passphrase", io)
		if msg != "" {
			err_line(io, "%s", msg)
			return .Usage if bad_value else .Failed
		}
	}

	req, ok := build_request(c, password, response, profile = profile, key_pass = key_pass)
	if !ok {
		err_line(io, "internal error: cannot build the request")
		return .Failed
	}
	defer request_destroy(&req)

	reply, id, retried, err := call_op(c, t, req.op, req.args)
	if err != .None {
		return report_call_error(c, io, t, err, id, retried)
	}
	defer bus.reply_destroy(&reply)
	return report_reply(c, io, &reply)
}

// Send one request. After a timeout a request is sent once more with the
// same id and the same bytes: the daemon applies a state-changing request
// once per id, so a repeat cannot do it twice.
call_op :: proc(
	c: ^Command,
	t: Target,
	op: string,
	args: []byte,
) -> (
	reply: bus.Reply,
	id: string,
	retried: bool,
	err: bus.Call_Error,
) {
	id = c.id
	if id == "" {
		id = bus.random_hex(16, context.temp_allocator)
	}
	reply, err = bus.call(t.control, op, args, c.timeout, id)
	if err == .Timeout && retry_safe(op) {
		retried = true
		reply, err = bus.call(t.control, op, args, c.timeout, id)
	}
	return
}

// Tell the user why no reply came, and return the exit code.
report_call_error :: proc(c: ^Command, io: ^Io, t: Target, err: bus.Call_Error, id: string, retried: bool) -> Exit {
	switch err {
	case .None:
	case .Daemon_Not_Running:
		err_line(io, "the daemon is not running (nothing is responding on %s)", t.control)
	case .Permission_Denied:
		err_line(io, "permission denied on %s (%s)", t.control, ACCESS_HINT)
	case .Bad_Url:
		when ODIN_OS == .Windows {
			err_line(io, "the pipe address must be a local pipe name (\\\\.\\pipe\\...): %s", t.control)
		} else {
			err_line(io, "the socket address must be an absolute path or an ipc:// URL: %s", t.control)
		}
	case .Not_Service:
		err_line(io, "%s does not belong to the service because another user created it, so nothing was sent", t.control)
	case .Timeout:
		tries := "twice" if retried else "once"
		err_line(
			io,
			"no reply within %v (sent %s), but the request may still have been applied; repeat it with --id %s to find out",
			c.timeout,
			tries,
			id,
		)
	case .Io, .Bad_Reply, .No_Memory:
		err_line(io, "%s", bus.call_error_string(err))
	}
	return exit_for_call_error(err)
}

// Print a reply (the raw text with --json) and return the exit code.
report_reply :: proc(c: ^Command, io: ^Io, reply: ^bus.Reply) -> Exit {
	if c.json {
		out_text(io, string(reply.raw))
		out_text(io, "\n")
		return .Ok if reply.ok else exit_for_reply_code(reply.code)
	}
	if !reply.ok {
		print_error_reply(io, reply)
		return exit_for_reply_code(reply.code)
	}
	root, parsed := view_parse(reply.raw)
	if !parsed {
		err_line(io, "%s", bus.call_error_string(.Bad_Reply))
		return .Failed
	}
	result, _ := view_get(root, "result")
	b := strings.builder_make(context.temp_allocator)
	#partial switch c.kind {
	case .Peer:
		format_peer(&b, result)
	case .Status:
		format_status(&b, result)
	case .Profile_Set, .Profile_Check:
		format_profile(&b, result)
	case .Rules:
		format_rules(&b, result)
	case:
		format_flat(&b, result)
	}
	out_text(io, strings.to_string(b))
	return .Ok
}

print_error_reply :: proc(io: ^Io, reply: ^bus.Reply) {
	msg := safe_text(reply.message)
	if reply.code == "denied" {
		err_line(io, "permission denied: %s", msg)
	} else {
		err_line(io, "error: %s: %s", safe_text(reply.code), msg)
	}
	b := strings.builder_make(context.temp_allocator)
	format_problems(&b, reply.details)
	sink_write(io.err, strings.to_string(b))
}

// `peers`: fetch every page (or the one asked for) and print a table.
run_peers :: proc(c: ^Command, t: Target, io: ^Io) -> Exit {
	replies := make([dynamic]bus.Reply, context.temp_allocator)
	defer for &r in replies {
		bus.reply_destroy(&r)
	}
	peers := make([dynamic]View, context.temp_allocator)
	single := c.has_limit || c.has_offset
	offset := c.offset if c.has_offset else 0
	count: i64 = -1
	for _ in 0 ..< 100000 {
		req, ok := build_request(c, "", "", offset)
		if !ok {
			err_line(io, "internal error: cannot build the request")
			return .Failed
		}
		reply, id, retried, err := call_op(c, t, req.op, req.args)
		request_destroy(&req)
		if err != .None {
			return report_call_error(c, io, t, err, id, retried)
		}
		append(&replies, reply)
		last := &replies[len(replies) - 1]
		if !last.ok {
			return report_reply(c, io, last)
		}
		if c.json {
			// The raw reply, one line per page.
			out_text(io, string(last.raw))
			out_text(io, "\n")
		}
		root, parsed := view_parse(last.raw)
		result, _ := view_get(root, "result")
		list, has_list := view_get(result, "peers")
		if !parsed || !has_list || list.kind != .Array {
			err_line(io, "%s", bus.call_error_string(.Bad_Reply))
			return .Failed
		}
		count = view_int(result, "count")
		append(&peers, ..list.items)
		offset += i64(len(list.items))
		if single || len(list.items) == 0 || offset >= count {
			break
		}
	}
	if c.json {
		return .Ok
	}
	b := strings.builder_make(context.temp_allocator)
	format_peers_table(&b, peers[:])
	out_text(io, strings.to_string(b))
	if single && count > i64(len(peers)) {
		note_line(io, "showing %d of %d peers", len(peers), count)
	}
	return .Ok
}
