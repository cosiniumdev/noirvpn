// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:mem"
import "core:strings"
import "core:time"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/session"
import "noir:server"

// Web sign-in on the server (`auth-web`; docs/server.md).
//
//   client      IV_SSO=webauth, no certificate, no password
//   srv_park    peer.auth_pending (web_auth true, name null)
//   controller  auth.decide pending + url   -> AUTH_PENDING, INFO_PRE,WEB_AUTH:<flags>:<url>
//               (the user signs in with a browser)
//   controller  auth.decide allow + name + token_lifetime
//   srv_login   PUSH_REPLY with auth-token (server_token.odin)
//   rekey       the client sends the token as its password: srv_web_rekey
//   reconnect   the token gives peer.auth_pending with the proof `token`
//   lifetime    srv_web_end: AUTH_FAILED,SESSION and the session closes
//
// The token key and sign-in table are generated at start and never leave this
// process. The URL of a sign-in is never logged and never in an event (only
// its host is logged).

// The Unix second a token ends and the matching instant on the clock of the
// daemon. A token that has ended gives `now`, so the session ends at once.
web_deadline :: proc "contextless" (now: time.Duration, end: u32, unix: i64) -> time.Duration {
	left := i64(end) - unix
	if left <= 0 {
		return max(now, 1)
	}
	return now + time.Duration(left) * time.Second
}

// True when IV_SSO of the peer info lists `webauth`.
web_sso_of :: proc(pi: ^push.Peer_Info) -> bool {
	v, ok := push.peer_info_get(pi, "IV_SSO")
	if !ok {
		return false
	}
	rest := v
	for len(rest) > 0 {
		item, _ := push.next_item(&rest, ',')
		if strings.trim_space(item) == "webauth" {
			return true
		}
	}
	return false
}

srv_web_start :: proc(d: ^Srv) -> bool {
	if !d.cfg.auth_web {
		return true
	}
	if !ossl.random_bytes(d.tkey[:]) {
		logf(.Error, "cannot generate the key of the session tokens")
		return false
	}
	return true
}

srv_web_stop :: proc(d: ^Srv) {
	mem.zero_explicit(&d.tkey, size_of(d.tkey))
	signin_destroy(&d.signins)
}

// What `token_check` and the sign-in table found for the password of a login.
Token_Look :: struct {
	state:  server.Token_State,
	name:   [server.MAX_IDENTITY_LEN]u8,
	name_n: int,
	id:     Token_Id,
	// The end of the token or of its sign-in, the sooner one (Unix seconds).
	end:    u32,
}

// A token is valid when its tag is ours, its end has not come, and its id is in
// the table with an end that has not come. An id not in the table is invalid.
srv_token_look :: proc(d: ^Srv, password: string, l: ^Token_Look) {
	id, end, res := token_check(&d.tkey, password, unix_now())
	if res != .Ok {
		l.state = .Invalid
		return
	}
	e := signin_find(&d.signins, id, unix_now())
	if e == nil {
		l.state = .Invalid
		return
	}
	l.state, l.id, l.end = .Valid, id, min(end, e.end)
	l.name_n = copy(l.name[:], e.name)
}

// Puts the session token in the PUSH_REPLY, with the end of the sign-in. A client
// that sent no user name is told its name too, so it sends the same pair again.
srv_token_push :: proc(d: ^Srv, c: ^Conn, cp: ^session.Client_Params) {
	if c.token_end == 0 || !c.named {
		return
	}
	e := signin_find(&d.signins, c.token_id, unix_now())
	if e == nil {
		return
	}
	buf := make([]u8, TOKEN_MAX, context.temp_allocator)
	name := server.identity_str(&c.name)
	tok, ok := token_make(&d.tkey, c.token_id, e.end, buf)
	if !ok {
		logf(.Error, "client %s: cannot generate a session token", conn_label(c))
		return
	}
	cp.options.auth_token = tok
	if !c.user_given {
		cp.options.auth_token_user = token_user_b64(name)
	}
}

// Renegotiation of a session that a controller named. The client must send the
// token as its password. The daemon checks it alone (no controller call, no
// hash). No token, or a wrong, expired or other-name token: AUTH_FAILED,SESSION.
srv_web_rekey :: proc(d: ^Srv, c: ^Conn, req: ^session.Auth_Request) {
	ok := false
	if c.token_end != 0 && token_looks_like(req.password) {
		id, _, res := token_check(&d.tkey, req.password, unix_now())
		if res == .Ok && c.named {
			e := signin_find(&d.signins, id, unix_now())
			ok = e != nil && server.name_equal(e.name, server.identity_str(&c.name))
		}
	}
	session.session_server_wipe_password(&c.s)
	if !ok {
		logf(.Notice, "client %s: the renegotiation does not have a valid session token", conn_label(c))
		pw_refuse(d, c, server.reject_make(.Token_Invalid), true, "")
		return
	}
	if err := session.session_server_accept(&c.s, nil, now_srv(d)); err != .None {
		logf(.Error, "client %s: cannot accept the renegotiation: %v", conn_label(c), err)
	}
	srv_settle(d, c)
}

// The lifetime of the session token ended.
srv_web_end :: proc(d: ^Srv, c: ^Conn) {
	logf(.Notice, "client %s: the sign-in lifetime ended", conn_label(c))
	srv_signin_end(d, c)
	c.detail_n = copy(c.detail[:], "the sign-in lifetime ended")
	conn_close(d, c, .Session_Expired, .Sign_In_Ended)
}

// Removes the sign-in of the session: its token is dead at once, also for a
// later login.
srv_signin_end :: proc(d: ^Srv, c: ^Conn) {
	if c.token_end != 0 {
		signin_remove(&d.signins, c.token_id)
	}
}
