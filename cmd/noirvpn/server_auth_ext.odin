// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:strings"
import "core:time"
import "noir:bus"
import "noir:proto/session"
import "noir:server"

// `auth-external`: a login that passed every local check waits for a controller
// on the bus.
//
//   srv_park          after the local checks: AUTH_PENDING to the client,
//                     peer.handshake and peer.auth_pending on the bus
//   auth.decide       allow (maybe with push lines), deny, or pending
//   auth.credentials  the user name and password once; the password is wiped
//   timeout           no response by the deadline is a deny (auth.fail)
//
// A parked session keeps its place in the conn table and counts against
// `max-clients`. The password stays in the session's own copy of the login
// message (never copied here). It is wiped when read, when the decision is reached,
// and when the session ends.

// Seconds to wait when the config says `auth-external` without a number.
DEFAULT_EXTERNAL_TIMEOUT :: 30

// The local checks passed and a controller must decide. `req` is the login
// (valid now only).
srv_park :: proc(d: ^Srv, c: ^Conn, req: ^session.Auth_Request, dec: ^server.Decision) {
	now := now_srv(d)
	secs := dec.external_timeout if dec.external_timeout > 0 else DEFAULT_EXTERNAL_TIMEOUT
	if err := session.session_server_auth_pending(&c.s, now, secs); err != .None {
		logf(.Error, "client %s: cannot tell the client to wait: %v", conn_label(c), err)
		srv_refuse(d, c, server.reject_make(.Internal), "")
		return
	}
	c.parked = true
	c.park_until = now + time.Duration(secs) * time.Second
	c.park_dec = dec^
	d.parked += 1
	logf(.Notice, "client %s is waiting for a decision from a controller (up to %d s)", conn_label(c), secs)
	srv_ev_auth_pending(d, c, req.peer_info_text, secs)
}

// The wait is over (any outcome): the session stops counting as parked.
srv_unpark :: proc(d: ^Srv, c: ^Conn) {
	if !c.parked {
		return
	}
	c.parked = false
	c.park_dec = {}
	d.parked -= 1
}

// The session ended without a decision (the client left, or the daemon stops).
// A kick goes through `srv_park_deny` instead. Wipes the password and tells the bus.
srv_unpark_end :: proc(d: ^Srv, c: ^Conn, why: string) {
	if !c.parked {
		return
	}
	if c.s_ok {
		session.session_server_wipe_password(&c.s)
	}
	srv_unpark(d, c)
	logf(.Notice, "client %s did not wait for the controller: %s", conn_label(c), why)
	srv_ev_auth_fail(d, c, "client_left", why)
}

// Sends what the session has to say and handles its events. `c` may be gone
// afterwards.
srv_settle :: proc(d: ^Srv, c: ^Conn) {
	if conn_pump(d, c) && c.proto == .Tcp {
		tcp_flush_conn(d, c)
	}
}

// The deadline came: no response is a deny.
srv_park_timeout :: proc(d: ^Srv, c: ^Conn) {
	if !c.parked {
		return
	}
	if c.s_ok {
		session.session_server_wipe_password(&c.s)
	}
	rej := server.server_deny_external(&d.srv, true)
	srv_refuse(d, c, rej, "no decision in time")
	srv_settle(d, c)
}

// The controller said no (or the session is kicked). `text` is what the client
// sees after AUTH_FAILED.
srv_park_deny :: proc(d: ^Srv, c: ^Conn, text: string) {
	if !c.parked {
		return
	}
	if c.s_ok {
		session.session_server_wipe_password(&c.s)
	}
	rej := server.server_deny_external(&d.srv, false)
	srv_refuse(d, c, rej, text, text)
	srv_settle(d, c)
}

// The controller said yes. `extra` is the client-config-dir text built from its
// push lines, `push_text` the lines as sent (for peer.connect). Limits are
// checked again; the client is refused if one fails. Returns the refusal
// (`reason == .None` when the client is in).
srv_park_allow :: proc(d: ^Srv, c: ^Conn, extra, push_text: string) -> (rej: server.Reject, detail: string) {
	if !c.parked {
		return server.reject_make(.Internal), ""
	}
	dec := c.park_dec
	srv_unpark(d, c)
	if c.s_ok {
		session.session_server_wipe_password(&c.s)
	}
	// The other parked sessions are what counts against max-clients now.
	r := server.server_resume(&d.srv, dec, d.parked + d.pw.waiting)
	if r.kind == .Reject {
		srv_refuse(d, c, r.reject, "")
		rej = r.reject
	} else {
		rej, detail = srv_login(d, c, &r, extra)
		if rej.reason == .None && push_text != "" {
			c.push_text = strings.clone(push_text)
		}
		if rej.reason == .None && c.idsrc == .Controller && c.s_ok {
			// A session that a controller named is checked at each renegotiation
			// (srv_web_rekey).
			session.session_server_set_reauth(&c.s, true)
		}
	}
	srv_settle(d, c)
	return
}

// `pending`: keep waiting, `secs` more from now. `info_pre` (when not empty) is
// sent to the client right after the wait notice, as `INFO_PRE,<info_pre>`.
srv_park_extend :: proc(d: ^Srv, c: ^Conn, secs: int, info_pre := "") -> (deadline: time.Time, ok: bool) {
	now := now_srv(d)
	if err := session.session_server_auth_pending(&c.s, now, secs); err != .None {
		return {}, false
	}
	if info_pre != "" {
		if err := session.session_server_info_pre(&c.s, now, info_pre); err != .None {
			return {}, false
		}
	}
	c.park_until = now + time.Duration(secs) * time.Second
	logf(.Info, "client %s: the controller requested %d more seconds", conn_label(c), secs)
	srv_settle(d, c)
	return time.time_add(time.now(), time.Duration(secs) * time.Second), true
}

// ---------------------------------------------------------------- the ops

srv_op_auth_decide :: proc(d: ^Srv, req: ^bus.Request) {
	if srv_busy_stopping(d, req) {
		return
	}
	text, e1 := bus.arg_str(req, "session")
	if e1 != .None {
		bus_bad_arg(req, "session", e1)
		return
	}
	decision, e2 := bus.arg_str(req, "decision")
	if e2 != .None {
		bus_bad_arg(req, "decision", e2)
		return
	}
	if decision != "allow" && decision != "deny" && decision != "pending" {
		bus_err(req, .Bad_Request, "decision must be allow, deny or pending")
		return
	}
	// Each argument belongs to one decision.
	only_for :: proc(req: ^bus.Request, decision: string, names: []string, which: string) -> bool {
		if decision == which {
			return true
		}
		for n in names {
			if bus.arg_has(req, n) {
				bus_err(req, .Bad_Request, strings.concatenate({"the argument ", n, " is only for ", which}, context.temp_allocator))
				return false
			}
		}
		return true
	}
	if !only_for(req, decision, {"name", "token_lifetime"}, "allow") || !only_for(req, decision, {"url", "flags"}, "pending") {
		return
	}
	// Everything is checked before anything is applied.
	extra, push_text: string
	reason := "denied"
	timeout := 0
	name: string
	life := 0
	info_pre, host: string
	switch decision {
	case "allow":
		lines, e := bus.arg_strs(req, "push", context.temp_allocator)
		if e != .None && e != .Missing {
			bus_bad_arg(req, "push", e)
			return
		}
		if e == .None {
			ccd, bad, why := server.controller_check(lines, context.temp_allocator)
			if bad > 0 {
				bus_err(req, .Bad_Request, strings.concatenate({"push line ", fmt.tprintf("%d", bad), ": ", why}, context.temp_allocator))
				return
			}
			if why != "" {
				bus_err(req, .Bad_Request, strings.concatenate({"push: ", why}, context.temp_allocator))
				return
			}
			extra = ccd
			push_text = strings.join(lines, "\n", context.temp_allocator)
		}
		if n, en := bus.arg_str(req, "name"); en == .None {
			if !server.identity_check(n) {
				bus_bad_arg(req, "name", .Out_Of_Range)
				return
			}
			name = n
		} else if en != .Missing {
			bus_bad_arg(req, "name", en)
			return
		}
		if n, el := bus.arg_int_range(req, "token_lifetime", TOKEN_LIFE_MIN, TOKEN_LIFE_MAX); el == .None {
			life = int(n)
		} else if el != .Missing {
			bus_bad_arg(req, "token_lifetime", el)
			return
		}
	case "deny":
		if r, e := bus.arg_str(req, "reason"); e == .None {
			clean, ok := clean_reason(r)
			if !ok {
				bus_bad_arg(req, "reason", .Out_Of_Range)
				return
			}
			if clean != "" {
				reason = clean
			}
		} else if e != .Missing {
			bus_bad_arg(req, "reason", e)
			return
		}
	case "pending":
		t, e := bus.arg_int_range(req, "timeout", 1, 3600)
		if e == .None {
			timeout = int(t)
		} else if e != .Missing {
			bus_bad_arg(req, "timeout", e)
			return
		}
		url, eu := bus.arg_str(req, "url")
		if eu != .None && eu != .Missing {
			bus_bad_arg(req, "url", eu)
			return
		}
		flags, ef := bus.arg_strs(req, "flags", context.temp_allocator)
		if ef != .None && ef != .Missing {
			bus_bad_arg(req, "flags", ef)
			return
		}
		if eu == .Missing && ef == .None {
			bus_err(req, .Bad_Request, "flags need a url")
			return
		}
		if eu == .None {
			for f in flags {
				if f != "hidden" && f != "external" {
					bus_bad_arg(req, "flags", .Out_Of_Range)
					return
				}
			}
			info_pre = strings.concatenate({"WEB_AUTH:", strings.join(flags, ",", context.temp_allocator), ":", url}, context.temp_allocator)
			// The same checks as the client runs. The problem text never has the URL.
			wa, problem, _ := web_auth_read(info_pre, false)
			if problem != "" {
				bus_err(req, .Bad_Request, strings.concatenate({"url: ", problem}, context.temp_allocator))
				return
			}
			host = wa.host
		}
	}

	c := srv_find_session(d, text)
	if c == nil {
		bus_err(req, .Not_Found, "no such session")
		return
	}
	if !c.parked {
		bus_err(req, .Conflict, "the session is not waiting for a decision")
		return
	}
	web_login := c.park_dec.web_login
	switch decision {
	case "allow":
		switch {
		case name != "" && !web_login:
			bus_err(req, .Conflict, "the session has a name already: name is only for a web sign-in")
			return
		case name == "" && web_login:
			bus_err(req, .Bad_Request, "missing argument: name (a web sign-in has no name until the controller gives one)")
			return
		}
		if life > 0 && !web_login && .Token not_in c.proofs {
			bus_err(req, .Conflict, "token_lifetime is only for a web sign-in")
			return
		}
	case "pending":
		if info_pre != "" && !c.web_auth {
			bus_err(req, .Conflict, "the client did not say IV_SSO=webauth: it cannot show a sign-in URL")
			return
		}
	}
	sess := srv_session_text(c)
	deadline: time.Time
	old_end: u32
	switch decision {
	case "allow":
		if web_login {
			named := server.auth_name_web(&d.srv.auth, c.park_dec, name)
			if named.kind == .Reject {
				bus_err(req, .Internal, "the name was not accepted")
				return
			}
			if life > 0 {
				// The sign-in is created before the client changes, so a full table
				// leaves the login waiting.
				end := u32(unix_now() + i64(life))
				id, made := signin_add(&d.signins, name, end, unix_now())
				if !made {
					bus_err(req, .Busy, "the table of sign-ins is full")
					return
				}
				c.token_id, c.token_end = id, end
			}
			c.park_dec = named
			c.name, c.named, c.idsrc = named.identity, true, .Controller
		} else if life > 0 {
			// A login with a token: the end of its sign-in moves.
			e := signin_find(&d.signins, c.token_id, unix_now())
			if e == nil {
				bus_err(req, .Conflict, "the sign-in has ended")
				return
			}
			old_end = e.end
			e.end = u32(unix_now() + i64(life))
			c.token_end = e.end
		}
		logf(.Notice, "bus: the controller allowed client %s", conn_label(c))
		rej, detail := srv_park_allow(d, c, extra, push_text)
		if rej.reason != .None && life > 0 {
			// The client is not in: the sign-in does not stay (a new one) or goes
			// back to its old end (a login with a token).
			if web_login {
				signin_remove(&d.signins, c.token_id)
				c.token_end = 0
			} else if e := signin_find(&d.signins, c.token_id, unix_now()); e != nil {
				e.end = old_end
			}
		}
		if rej.reason != .None && extra != "" {
			msg := server.reject_text(rej.reason)
			if detail != "" {
				msg = strings.concatenate({msg, ": ", detail}, context.temp_allocator)
			}
			bus_err(req, .Conflict, strings.concatenate({"the client was refused: ", msg}, context.temp_allocator))
			return
		}
	case "deny":
		logf(.Notice, "bus: the controller denied client %s: %s", conn_label(c), reason)
		if .Token in c.proofs {
			// A denied login with a token: the token is dead.
			srv_signin_end(d, c)
		}
		srv_park_deny(d, c, reason)
	case "pending":
		secs := timeout if timeout > 0 else (c.park_dec.external_timeout if c.park_dec.external_timeout > 0 else DEFAULT_EXTERNAL_TIMEOUT)
		if host != "" {
			logf(.Info, "bus: the controller asks client %s to sign in at %s", conn_label(c), host)
		}
		ok: bool
		deadline, ok = srv_park_extend(d, c, secs, info_pre)
		if !ok {
			bus_err(req, .Internal, "cannot send the wait notice to the client")
			return
		}
	}
	w := bus_res()
	bus.kv_str(w, "session", sess)
	bus.kv_str(w, "decision", decision)
	if decision == "pending" {
		buf: [24]u8
		bus.kv_str(w, "deadline", bus.format_ts(deadline, &buf))
	}
	bus_ok(req)
}

// The user name and password the client sent, once. A session that passed the
// hash file check has no password (null). The password is wiped from the session
// when the reply is built; the reply buffer is overwritten after it is sent.
srv_op_auth_credentials :: proc(d: ^Srv, req: ^bus.Request) {
	text, e := bus.arg_str(req, "session")
	if e != .None {
		bus_bad_arg(req, "session", e)
		return
	}
	c := srv_find_session(d, text)
	if c == nil {
		bus_err(req, .Not_Found, "no such session")
		return
	}
	if !c.parked {
		bus_err(req, .Conflict, "the session is not waiting for a decision")
		return
	}
	areq: session.Auth_Request
	if !session.session_auth_request(&c.s, &areq) {
		bus_err(req, .Conflict, "the session is not waiting for a decision")
		return
	}
	w := bus_res()
	// No reallocation while the password is in the buffer: room for the
	// longest user name and password, escaped.
	reserve(&B.rw.buf, 4096)
	bus.kv_str(w, "session", srv_session_text(c))
	bus.kv_str_or_null(w, "username", areq.username, areq.username != "")
	// "" when the client sent none. null when the password is not here to give:
	// the hash file checked and wiped it, or an earlier call read it.
	bus.kv_str_or_null(w, "password", areq.password, !c.pw_has && !c.creds_read)
	c.creds_read = true
	bus_ok_wipe(req)
	session.session_server_wipe_password(&c.s)
	areq = {}
	logf(.Info, "bus: the controller read the credentials of client %s", conn_label(c))
}
