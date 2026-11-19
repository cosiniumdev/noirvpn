// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "noir:bus"
import "noir:platform/event"
import "noir:proto/config"

// The daemon's side of the client operations: takes a request from the control
// bus, parses the arguments, gives the caller as plain data, and sends the
// reply. The operations themselves are in client_ops.odin (no bus in them).
// `daemon.reload` and `log.level` belong to the daemon: here and in bus_host.odin.

on_cli_bus :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	bus_drain(cli_bus_request)
}

// The result of an operation goes to the bus: `user` is the request.
@(private = "file")
bus_reply_ok :: proc(user: rawptr) {
	bus_ok((^bus.Request)(user))
}

@(private = "file")
bus_reply_err :: proc(user: rawptr, code: bus.Error_Code, text: string) {
	bus_err((^bus.Request)(user), code, text)
}

@(private = "file")
bus_reply_err_details :: proc(user: rawptr, code: bus.Error_Code, text: string, details: []u8) {
	bus.reply_error_details(B.h, (^bus.Request)(user), code, text, details)
}

@(private = "file")
bus_reply_wipe :: proc(user: rawptr) {
	bus.args_wipe((^bus.Request)(user))
}

// The reply of a request, with its result object open.
@(private = "file")
bus_reply_of :: proc(req: ^bus.Request) -> Reply {
	return Reply {
		user = req,
		w = bus_res(),
		ok = bus_reply_ok,
		err = bus_reply_err,
		err_details = bus_reply_err_details,
		wipe_args = bus_reply_wipe,
	}
}

@(private = "file")
bus_caller_of :: proc(req: ^bus.Request) -> Caller {
	return Caller{op = req.op, uid = req.creds.uid, gid = req.creds.gid, sid = req.creds.sid, roles = req.roles}
}

cli_bus_request :: proc(req: ^bus.Request) {
	d := &D
	switch req.op {
	case "status":
		r := bus_reply_of(req)
		c := bus_caller_of(req)
		bus_status_head(r.w)
		op_status(d, &r, &c)
	case "stats.get":
		r := bus_reply_of(req)
		op_stats(d, &r)
	case "log.level":
		bus_op_log_level(req)
	case "daemon.reload":
		cli_op_reload(d, req)
	case "daemon.shutdown":
		cli_op_shutdown(d, req)
	case "connect":
		r := bus_reply_of(req)
		c := bus_caller_of(req)
		op_connect(d, &r, &c)
	case "disconnect":
		r := bus_reply_of(req)
		c := bus_caller_of(req)
		op_disconnect(d, &r, &c)
	case "auth.supply":
		cli_op_auth_supply(d, req)
	case "profile.set", "profile.check":
		cli_op_profile(d, req)
	case "profile.clear":
		r := bus_reply_of(req)
		c := bus_caller_of(req)
		op_profile_clear(d, &r, &c)
	case "acl.get":
		r := bus_reply_of(req)
		op_acl_get(d, &r)
	case "acl.reload":
		cli_op_acl_reload(d, req)
	case:
		bus_err(req, .Unknown_Op, "no such operation")
	}
}

cli_op_reload :: proc(d: ^Daemon, req: ^bus.Request) {
	if cli_stopping(d) {
		bus_err(req, .Busy, "the daemon is shutting down")
		return
	}
	plan: Reload_Plan
	defer reload_plan_destroy(&plan)
	if err := reload_prepare(&plan); err != "" {
		logf(.Error, "reload: %s", err)
		bus_reload_report(req, nil, nil, err)
		return
	}
	reloaded := make([dynamic]string, context.temp_allocator)
	reload_apply_common(&plan, &reloaded)
	acl_change_names(acl_reload(d, &plan.cfg.client), &reloaded)
	if d.stats_secs != plan.cfg.client.stats_interval {
		B.stats_secs = plan.cfg.client.stats_interval
		d.stats_secs = plan.cfg.client.stats_interval
		client_stats_arm(d)
		append(&reloaded, "stats-interval")
	}
	for name in plan.ignored {
		logf(.Notice, "reload: %s changed, so a restart is needed", name)
	}
	logf(.Notice, "reload: applied %v", reloaded[:])
	bus_reload_report(req, reloaded[:], plan.ignored[:], "")
}

// `acl.reload`: the rule lines of the config file, and nothing else of it.
cli_op_acl_reload :: proc(d: ^Daemon, req: ^bus.Request) {
	r := bus_reply_of(req)
	c := bus_caller_of(req)
	if cli_stopping(d) {
		reply_err(&r, .Busy, "the daemon is shutting down")
		return
	}
	if service_denied(d, &r, &c) {
		return
	}
	if B.config_path == "" {
		reply_err(&r, .Conflict, "the daemon has no config file")
		return
	}
	plan: Reload_Plan
	defer reload_plan_destroy(&plan)
	if err := reload_prepare(&plan); err != "" {
		logf(.Warn, "acl.reload: %s", err)
		diags: []config.Diagnostic
		if plan.cfg_ok {
			diags = plan.cfg.diags[:]
		}
		reply_err_details(&r, .Bad_Request, "the config file has problems", acl_config_details(diags, err))
		return
	}
	ch := acl_reload(d, &plan.cfg.client)
	acl_write_reload(r.w, d, ch)
	reply_ok(&r)
}

cli_op_shutdown :: proc(d: ^Daemon, req: ^bus.Request) {
	secs, e := bus.arg_int_range(req, "timeout_s", 0, 60)
	if e == .Missing {
		secs = 5
	} else if e != .None {
		bus_bad_arg(req, "timeout_s", e)
		return
	}
	r := bus_reply_of(req)
	op_shutdown(d, &r, secs)
}

cli_op_auth_supply :: proc(d: ^Daemon, req: ^bus.Request) {
	r := bus_reply_of(req)
	c := bus_caller_of(req)
	if service_denied(d, &r, &c) {
		return
	}
	user, e1 := bus.arg_str(req, "username")
	pass, e2 := bus.arg_str(req, "password")
	resp, e3 := bus.arg_str(req, "response")
	kp, e4 := bus.arg_str(req, "key_pass")
	// The bus overwrites the strings of this request when it frees it
	// (`Op_Info.secret`). The request must not be touched after the reply.
	for pair in ([4]struct {
			n: string,
			e: bus.Arg_Error,
		}{{"username", e1}, {"password", e2}, {"response", e3}, {"key_pass", e4}}) {
		if pair.e != .None && pair.e != .Missing {
			bus_bad_arg(req, pair.n, pair.e)
			return
		}
	}
	a: Auth_Supply
	if e1 == .None {
		a.user = user
	}
	if e2 == .None {
		a.pass = pass
	}
	if e3 == .None {
		a.resp = resp
	}
	if e4 == .None {
		a.key_pass = kp
	}
	op_auth_supply(d, &r, a)
}

// `profile.set` and `profile.check`.
cli_op_profile :: proc(d: ^Daemon, req: ^bus.Request) {
	check := req.op == "profile.check"
	r := bus_reply_of(req)
	c := bus_caller_of(req)
	if !profile_precheck(d, &r, &c, check) {
		return
	}
	text, e_text := bus.arg_str(req, "text")
	label, e_label := bus.arg_str(req, "label")
	sso, e_sso := bus.arg_strs(req, "sso", context.temp_allocator)
	switch {
	case e_text != .None:
		prof_bad_arg(req, "text", e_text)
		return
	case e_label != .None:
		prof_bad_arg(req, "label", e_label)
		return
	case e_sso != .None && e_sso != .Missing:
		prof_bad_arg(req, "sso", e_sso)
		return
	}
	profile_run(d, &r, &c, check, text, label, sso)
}

@(private = "file")
prof_bad_arg :: proc(req: ^bus.Request, name: string, e: bus.Arg_Error) {
	bus.args_wipe(req)
	bus_bad_arg(req, name, e)
}
