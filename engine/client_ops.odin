// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:mem"
import "core:strings"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:proto/push"
import "noir:proto/session"

// Client operations, without the bus.
// - Input: parsed arguments, the caller as plain data, a `Reply` (host.odin).
//   An operation responds through the reply and changes the engine.
// - The host parses the request and sends the response (daemon:
//   cmd/noirvpn/cli_bus.odin).
// - Order of checks, logs and responses is the bus order. The host sees the
//   response before the work that follows it (`connect`, `auth.supply`).
// A secret argument (`profile.set`, `auth.supply`) is a string that the host
// owns. It is not used after the response.

cli_stopping :: proc(d: ^Daemon) -> bool {
	return d.shutting || close_reason_exits(d, d.close_reason)
}

// ------------------------------------------------------------------ status

// `status`: the host opened the result and may have written its own fields. The
// `client` object follows. `c` decides if the sender may read a sign-in URL.
op_status :: proc(d: ^Daemon, r: ^Reply, c: ^Caller) {
	w := r.w
	bus.kv_obj(w, "client")
	bus.kv_str(w, "state", client_bus_state(d))
	bus.kv_str(w, "datapath", daemon_datapath(d))
	pool_write_bus(w, d.wk)
	remote, has_remote := client_remote(d)
	bus.kv_str_or_null(w, "remote", remote, has_remote)
	if d.s_ok || d.state != .Idle {
		bus.kv_str(w, "proto", proto_name(d.proto, d.tls))
		bus.kv_str_or_null(w, "outer", outer_text(d.outer), d.tls)
		if d.tls {
			bus.kv_u64(w, "outer_rekeys", outer_rekeys(d))
		} else {
			bus.kv_null(w, "outer_rekeys")
		}
		pname, has_proxy := proxy_name(d)
		bus.kv_str_or_null(w, "proxy", pname, has_proxy)
		wpath, has_ws := ws_path(d)
		bus.kv_str_or_null(w, "ws", wpath, has_ws)
	} else {
		bus.kv_null(w, "proto")
		bus.kv_null(w, "outer")
		bus.kv_null(w, "outer_rekeys")
		bus.kv_null(w, "proxy")
		bus.kv_null(w, "ws")
	}
	po: ^push.Pushed_Options
	if d.up && d.s_ok {
		po = session.session_pushed(&d.s)
	}
	if po != nil {
		if ic, ok := po.ifconfig.?; ok {
			bus.kv_str(w, "vpn4", ip4_str(ic.a))
		} else {
			bus.kv_null(w, "vpn4")
		}
		if ic6, ok := po.ifconfig6.?; ok {
			bus.kv_str(w, "vpn6", ip6_str(ic6.addr))
		} else {
			bus.kv_null(w, "vpn6")
		}
		bus.kv_str(w, "cipher", push.cipher_name(session.session_cipher(&d.s)))
		bus.kv_str(w, "data_format", session.session_data_format_name(&d.s))
		bus.kv_u64(w, "peer_id", u64(session.session_peer_id(&d.s)))
		buf: [24]u8
		bus.kv_str(w, "connected_at", bus.format_ts(d.up_wall, &buf))
		// The same lists as `client.tunnel_settings`, so a program that starts
		// to follow the bus after that event can still read them.
		plan: ^client.Plan = &d.plan if d.plan_ok else nil
		client_dns_lists(w, len(d.cfg.dns_options) > 0, plan, po)
		bus.kv_obj(w, "settings")
		client_write_tunnel_settings(w, d, po)
		bus.end(w)
	} else {
		bus.kv_null(w, "vpn4")
		bus.kv_null(w, "vpn6")
		bus.kv_null(w, "cipher")
		bus.kv_null(w, "data_format")
		bus.kv_null(w, "peer_id")
		bus.kv_null(w, "connected_at")
		bus.kv_null(w, "dns_servers")
		bus.kv_null(w, "dns_domains")
		bus.kv_null(w, "settings")
	}
	bus.kv_str_or_null(w, "tun", tun_name(d), d.tun_open || d.dco.dev)
	if web_shown(d) {
		bus.kv_obj(w, "auth_needed")
		web_write_fields(w, d, web_url_reader(d, c))
		bus.end(w)
	} else if d.creds_wait && d.creds_announced {
		bus.kv_obj(w, "auth_needed")
		client_write_auth_needed(w, d, d.creds_reason, true)
		bus.end(w)
	} else {
		bus.kv_null(w, "auth_needed")
	}
	client_write_service_status(w, d)
	bus.end(w)
	reply_ok(r)
}

// `stats.get`.
op_stats :: proc(d: ^Daemon, r: ^Reply) {
	client_write_stats(r.w, d)
	reply_ok(r)
}

// -------------------------------------------------------------- connection

// `daemon.shutdown` of the daemon: `secs` is how long the exit notice may take.
op_shutdown :: proc(d: ^Daemon, r: ^Reply, secs: i64) {
	w := r.w
	bus.kv_bool(w, "stopping", true)
	reply_ok(r)
	if cli_stopping(d) {
		return
	}
	logf(.Notice, "bus: shutdown requested (%d s to send the exit notice)", secs)
	d.stop_reason = "request"
	d.close_wait = time.Duration(secs) * time.Second
	begin_close(d, .Stop)
}

op_connect :: proc(d: ^Daemon, r: ^Reply, c: ^Caller) {
	if cli_stopping(d) {
		reply_err(r, .Busy, "the daemon is shutting down")
		return
	}
	if service_denied(d, r, c) {
		return
	}
	if d.service && !d.prof_loaded {
		reply_err(r, .Conflict, "no profile is loaded")
		return
	}
	if d.service && d.clear_pending {
		reply_err(r, .Conflict, "the profile is being cleared")
		return
	}
	was := client_bus_state(d)
	already := !(was == "waiting" || was == "stopped")
	if !already {
		logf(.Notice, "bus: connect requested")
		service_begin(d)
		d.hold = false
		if d.state == .Idle {
			client.policy_outcome(&d.policy, .Local_Restart, now_of(d))
			timer_clear(d, &d.t_policy)
			schedule(d)
		}
		client_note_state(d)
	}
	w := r.w
	bus.kv_str(w, "state", client_bus_state(d))
	bus.kv_bool(w, "already", already)
	reply_ok(r)
}

op_disconnect :: proc(d: ^Daemon, r: ^Reply, c: ^Caller) {
	if cli_stopping(d) {
		reply_err(r, .Busy, "the daemon is shutting down")
		return
	}
	if service_denied(d, r, c) {
		return
	}
	if !d.hold {
		logf(.Notice, "bus: disconnect requested")
	}
	// A wait for credentials stays: `connect` finds the daemon still without them.
	was_hold := d.hold
	d.hold = true
	if d.state == .Idle {
		timer_clear(d, &d.t_policy)
		if d.service && !was_hold {
			// A service keeps no tunnel state in `stopped`, also with persist-tun.
			teardown_network(d, true)
		}
		d.bus_reason = "user_request"
		client_note_state(d)
	} else {
		if d.service {
			// `stopped` shows at once; its reason must be there for that first report.
			d.bus_reason = "user_request"
		}
		begin_close(d, .Disconnect)
	}
	w := r.w
	bus.kv_str(w, "state", "stopped" if client_bus_state(d) == "stopped" else "closing")
	reply_ok(r)
}

// ------------------------------------------------------------- credentials

CRED_ARG_MAX :: 512

KEY_PASS_WRONG_TEXT :: "the passphrase does not open the key"

// The arguments of `auth.supply`. A part that was not sent is nil.
Auth_Supply :: struct {
	user: Maybe(string),
	pass: Maybe(string),
	resp: Maybe(string),
	// The passphrase of the encrypted key of the profile (a guest, or a
	// profile of the client service with `askpass`).
	key_pass: Maybe(string),
}

// `auth.supply`. The host has asked `service_denied` first and parsed the
// arguments.
op_auth_supply :: proc(d: ^Daemon, r: ^Reply, a: Auth_Supply) {
	user, has_user := a.user.?
	pass, has_pass := a.pass.?
	_, has_resp := a.resp.?
	kp, has_kp := a.key_pass.?
	if !has_user && !has_pass && !has_resp && !has_kp {
		reply_err(r, .Bad_Request, "give at least one of username, password and response")
		return
	}
	if has_kp {
		if len(kp) > 1024 {
			reply_err_wipe(r, .Bad_Request, "key_pass is longer than 1024 bytes")
			return
		}
		if !d.creds_wait || !d.creds_key {
			reply_err_wipe(r, .Conflict, "nothing waits for credentials")
			return
		}
		asked := d.creds_announced
		slot := Key_Slot{&d.set.key_pem, "key"}
		if m := key_unlock(slot, transmute([]u8)kp); m != "" {
			logf(.Notice, "the passphrase does not open the key")
			delete(m)
			reply_err_wipe(r, .Bad_Request, KEY_PASS_WRONG_TEXT)
			client_publish_auth_needed(d, "key_pass_wrong", true)
			return
		}
		d.set.key_wait = false
		d.creds_key, d.creds_wait, d.creds_announced, d.creds_reason = false, false, false, ""
		if aup, ok := d.cfg.auth_user_pass.?; ok && !aup.is_inline {
			d.creds_wait, d.creds_reason = true, "no_credentials"
		}
		logf(.Notice, "the key is decrypted")
		if !has_user && !has_pass && !has_resp {
			bus.kv_bool(r.w, "accepted", true)
			reply_ok(r)
			if d.service && d.hold && d.state == .Idle {
				// `stopped`: as for a login, the passphrase starts a connection
				// only when the daemon asked for it.
				if asked {
					service_begin(d)
					d.hold = false
					client_note_state(d)
					client.policy_outcome(&d.policy, .Local_Restart, now_of(d))
					timer_set(d, &d.t_policy, now_of(d), on_policy_timer)
				}
				return
			}
			client.policy_outcome(&d.policy, .Local_Restart, now_of(d))
			timer_set(d, &d.t_policy, now_of(d), on_policy_timer)
			return
		}
	}
	resp, _ := a.resp.?
	if len(user) > CRED_ARG_MAX || len(pass) > CRED_ARG_MAX || len(resp) > CRED_ARG_MAX {
		reply_err(r, .Bad_Request, "a value is longer than 512 bytes")
		return
	}
	if has_resp {
		reply_err(r, .Bad_Request, "response: this client does not support challenge/response")
		return
	}
	if !d.creds_wait {
		reply_err(r, .Conflict, "nothing waits for credentials")
		return
	}
	// A missing part keeps what the daemon has (the user name after a refused login).
	new_user := user if has_user else string(d.creds.user[:d.creds.user_n])
	new_pass := pass if has_pass else string(d.creds.pass[:d.creds.pass_n])
	username_only := false
	if aup, ok := d.cfg.auth_user_pass.?; ok {
		username_only = aup.username_only
	}
	if new_user == "" {
		reply_err(r, .Bad_Request, "a user name is needed")
		return
	}
	if new_pass == "" && !username_only && !has_pass {
		reply_err(r, .Bad_Request, "a password is needed")
		return
	}
	if len(new_user) > CRED_MAX || len(new_pass) > CRED_MAX {
		reply_err(r, .Bad_Request, "the user name or password is longer than 127 bytes")
		return
	}
	// `cred_set` copies; when a part is kept it points into the buffer it
	// overwrites, so copy both first.
	ubuf, pbuf: [CRED_MAX + 1]u8
	un := copy(ubuf[:], new_user)
	pn := copy(pbuf[:], new_pass)
	err := cred_set(&d.creds, string(ubuf[:un]), string(pbuf[:pn]))
	mem.zero_explicit(&pbuf, size_of(pbuf))
	if err != .None {
		reply_err(r, .Bad_Request, cred_error_text(err))
		return
	}
	// A saved auth-token belongs to the old login.
	mem.zero_explicit(&d.creds.token, size_of(d.creds.token))
	mem.zero_explicit(&d.creds.token_user, size_of(d.creds.token_user))
	d.creds.token_n, d.creds.token_user_n = 0, 0
	asked := d.creds_announced
	d.creds_wait = false
	d.creds_announced = false
	d.creds_reason = ""
	w := r.w
	bus.kv_bool(w, "accepted", true)
	if d.service && d.hold && d.state == .Idle {
		// `stopped`: the credentials start a connection only when the daemon asked for them.
		reply_ok(r)
		if asked {
			logf(.Notice, "bus: credentials received; connecting")
			service_begin(d)
			d.hold = false
			client_note_state(d)
			client.policy_outcome(&d.policy, .Local_Restart, now_of(d))
			timer_set(d, &d.t_policy, now_of(d), on_policy_timer)
		} else {
			logf(.Notice, "bus: credentials received")
		}
		return
	}
	logf(.Notice, "bus: credentials received; connecting")
	reply_ok(r)
	// Connect now, with no back-off after the failed attempt; the loop carries on
	// from its timer.
	client.policy_outcome(&d.policy, .Local_Restart, now_of(d))
	timer_set(d, &d.t_policy, now_of(d), on_policy_timer)
}

// ------------------------------------------------------------ the profile

// Who asks, for the log: the uid, or the user SID on Windows.
caller_who :: proc(c: ^Caller) -> string {
	when ODIN_OS == .Windows {
		return fmt.tprintf("sid %s", bus.sid_string(c.sid, context.temp_allocator))
	} else {
		return fmt.tprintf("uid %d", c.uid)
	}
}

// The owner rule (`owner_allows`) for the sender of a request.
service_owner_ok :: proc(d: ^Daemon, c: ^Caller) -> bool {
	allowed := owner_allows(d.prof_loaded, d.owner, c.uid, c.roles)
	when ODIN_OS == .Windows {
		// Every pipe client has the uid 0: the user SID decides.
		allowed = allowed && (!d.prof_loaded || .Admin in c.roles || bus.sid_equal(d.owner_sid, c.sid))
	}
	return allowed
}

// Replies `denied` when the sender may not use an operation on this profile.
// True when it replied.
service_denied :: proc(d: ^Daemon, r: ^Reply, c: ^Caller) -> bool {
	if !d.service || service_owner_ok(d, c) {
		return false
	}
	when ODIN_OS == .Windows {
		logf(.Warn, "bus: denied %s op=%s: another user controls the tunnel", caller_who(c), c.op)
	} else {
		logf(.Warn, "bus: denied uid=%d gid=%d op=%s: another user controls the tunnel", c.uid, c.gid, c.op)
	}
	reply_wipe_args(r)
	reply_err(r, .Denied, "another user controls the tunnel")
	return true
}

// The checks of `profile.set` and `profile.check` that come before the
// arguments are read. False when it replied with an error.
profile_precheck :: proc(d: ^Daemon, r: ^Reply, c: ^Caller, check: bool) -> bool {
	if !d.service {
		reply_err_wipe(r, .Unsupported, SERVICE_ONLY_TEXT)
		return false
	}
	if !check {
		if cli_stopping(d) {
			reply_err_wipe(r, .Busy, "the daemon is shutting down")
			return false
		}
		if service_denied(d, r, c) {
			return false
		}
		if !service_idle(d) {
			reply_err_wipe(r, .Conflict, "disconnect first")
			return false
		}
	}
	return true
}

// `profile.set` and `profile.check`, after `profile_precheck` and the arguments.
profile_run :: proc(d: ^Daemon, r: ^Reply, c: ^Caller, check: bool, text, label: string, sso: []string, mobile := false, key_pass := "") {
	if why := label_problem(label); why != "" {
		reply_err_wipe(r, .Bad_Request, why)
		return
	}
	if why := sso_problem(sso); why != "" {
		reply_err_wipe(r, .Bad_Request, why)
		return
	}
	want_sso := len(sso) > 0
	label_copy := strings.clone(label)
	defer delete(label_copy)

	chk := profile_check_run(text, mobile)
	defer profile_check_destroy(&chk)
	// The text is parsed: the copy in the request can go.
	reply_wipe_args(r)

	if mobile && check && key_pass != "" && chk.key_encrypted && len(chk.problems) == 0 {
		if why := key_pass_try(&chk, key_pass); why != "" {
			reply_err_details(r, .Bad_Request, KEY_PASS_WRONG_TEXT, key_pass_details(why))
			delete(why)
			return
		}
	}
	if len(chk.problems) > 0 {
		n := len(chk.problems)
		msg := "the profile has problems"
		if n > PROBLEMS_MAX {
			msg = fmt.tprintf("the profile has %d problems; the first %d are listed", n, PROBLEMS_MAX)
		}
		w: bus.Writer
		bus.writer_init(&w, context.temp_allocator)
		profile_write_details(&w, chk.problems[:])
		logf(.Info, "bus: profile %s refused: %d problem(s)", "check" if check else "set", n)
		reply_err_details(r, .Bad_Request, msg, bus.writer_bytes(&w))
		return
	}
	w := r.w
	profile_write_result(w, &chk, label_copy, mobile)
	if check {
		logf(.Info, "bus: profile check: label %q, sha256 %s, %d options", label_copy, chk.sha, len(chk.prof.entries))
		reply_ok(r)
		return
	}
	uid := c.uid
	n_options := len(chk.prof.entries)
	had := d.prof_loaded
	if !service_install(d, &chk, label_copy, want_sso, uid) {
		bus.writer_reset(r.w)
		reply_err(r, .Internal, "the profile cannot be set up")
		if had {
			client_ev_profile(d, "cleared")
		}
		return
	}
	d.owner_sid = c.sid
	logf(.Notice, "bus: profile set by %s: label %q, sha256 %s, %d options", caller_who(c), d.prof_label, d.prof_sha, n_options)
	reply_ok(r)
	client_ev_profile(d, "set")
}

// `profile.clear`.
op_profile_clear :: proc(d: ^Daemon, r: ^Reply, c: ^Caller) {
	if !d.service {
		reply_err(r, .Unsupported, SERVICE_ONLY_TEXT)
		return
	}
	if cli_stopping(d) {
		reply_err(r, .Busy, "the daemon is shutting down")
		return
	}
	if service_denied(d, r, c) {
		return
	}
	if !service_idle(d) {
		if !service_closing(d) || !d.prof_loaded {
			reply_err(r, .Conflict, "disconnect first")
			return
		}
		// The connection still closes after `disconnect`. The profile goes when
		// it has ended, also when the sender does not wait for that.
		if !d.clear_pending {
			logf(.Notice, "bus: profile clear requested (label %q, %s); it will be cleared when the connection ends", d.prof_label, caller_who(c))
		}
		d.clear_pending = true
		w := r.w
		bus.kv_bool(w, "cleared", false)
		bus.kv_bool(w, "pending", true)
		reply_ok(r)
		return
	}
	was := d.prof_loaded
	if was {
		logf(.Notice, "bus: profile cleared (label %q, %s)", d.prof_label, caller_who(c))
		service_unload(d)
	}
	d.state_reason = "no_profile"
	w := r.w
	bus.kv_bool(w, "cleared", true)
	bus.kv_bool(w, "pending", false)
	reply_ok(r)
	if was {
		client_ev_profile(d, "cleared")
	}
}

// Opens the encrypted key of a checked profile with `key_pass`. Returns "" on
// success, else the reason (caller frees). The key is not kept: the check is
// destroyed after the reply.
key_pass_try :: proc(chk: ^Profile_Check, key_pass: string) -> string {
	slot := Key_Slot{&chk.set.key_pem, "key"}
	return key_unlock(slot, transmute([]u8)key_pass)
}

// The `details` of a wrong passphrase, on the temp allocator.
key_pass_details :: proc(reason: string) -> []u8 {
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_arr(&w)
	bus.begin_obj(&w)
	bus.kv_int(&w, "line", 0)
	bus.kv_str(&w, "option", "key")
	bus.kv_str(&w, "class", "passphrase")
	bus.kv_str(&w, "reason", reason)
	bus.end(&w)
	bus.end(&w)
	return bus.writer_bytes(&w)
}
