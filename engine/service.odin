// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:strings"
import "core:unicode/utf8"
import "noir:bus"
import "noir:client"
import "noir:platform/event"
import "noir:proto/config"
import "noir:proto/ossl"

// Service mode of the client daemon (`client-service`): starts with a base config
// (service settings only) and gets its profile over the control bus
// (`profile.set`). Never exits when a tunnel stops: goes to `stopped` and waits.
// Operations, states, owner rule: as the bus spec says.
//
//	main -> daemon_init (base config, state stopped, reason no_profile)
//	bus  -> profile.check  -> profile_check_run -> reply, nothing kept
//	bus  -> profile.set    -> profile_check_run -> service_install
//	                            -> service_unload (old profile) -> profile_attach
//	bus  -> profile.clear  -> service_unload, or clear_pending while the connection closes
//	end of a tunnel        -> service_stop (teardown, hold, reason, client.state)

LABEL_MAX :: 128

// The most problems a refused profile lists. A profile of 200 kB of text lines
// would give a reply of megabytes otherwise.
PROBLEMS_MAX :: 256

SERVICE_ONLY_TEXT :: "this daemon does not run in service mode (client-service)"

// ------------------------------------------------------------------ pure parts

// The `client.state` reason for a connection that ended in a service. The words
// of a daemon that exits, and three more for the stops that only a service shows.
service_reason :: proc "contextless" (o: client.Outcome, close: Close_Reason, code: Exit, kernel := false) -> string {
	r := state_reason(o, close, code, kernel)
	if r != "exit" {
		return r
	}
	switch {
	case o == .Inactive || close == .Inactive:
		return "inactive"
	case o == .Session_Timeout || close == .Session_Timeout:
		return "session_timeout"
	case close == .Fatal:
		return "system_error"
	}
	return r
}

// The reason when the policy stops a service. `last` is the reason of the
// connection that just ended, or "".
service_stop_reason :: proc "contextless" (stop: client.Stop_Reason, last: string) -> string {
	switch stop {
	case .Auth_Failed:
		return "auth_failed"
	case .Halted:
		return "server_halt"
	case .Inactive:
		return "inactive"
	case .Session_Timeout:
		return "session_timeout"
	case .No_Remote:
		return "config_error"
	case .Retries_Exhausted, .Resolve_Failed:
		switch last {
		case "tls_failed", "push_rejected", "ping_timeout", "auth_failed":
			return last
		}
		return "network_error"
	case .None, .Local_Stop:
		return last if last != "" else "exit"
	}
	return "exit"
}

// May this sender use `profile.set`, `profile.clear`, `connect`, `disconnect`,
// `auth.supply`? With no profile loaded, any caller. With one, only the owner
// and role `admin`.
owner_allows :: proc "contextless" (loaded: bool, owner: Maybe(u32), uid: u32, roles: bus.Roles) -> bool {
	if !loaded || .Admin in roles {
		return true
	}
	o, ok := owner.?
	return ok && o == uid
}

// Why a label is not valid, or "". 1 to 128 bytes, valid UTF-8, no control character.
label_problem :: proc(label: string) -> string {
	if len(label) < 1 || len(label) > LABEL_MAX {
		return "label: the length is 1 to 128 bytes"
	}
	if !utf8.valid_string(label) {
		return "label: not valid UTF-8"
	}
	for r in label {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return "label: no control characters"
		}
	}
	return ""
}

// Why the `sso` list is not valid, or "". Only "webauth" is a value.
sso_problem :: proc(items: []string) -> string {
	for s in items {
		if s != "webauth" {
			return `sso: the only value is "webauth"`
		}
	}
	return ""
}

// 64 lower-case hex digits.
sha256_hex :: proc(text: string, allocator := context.allocator) -> string {
	sum := ossl.sha256(transmute([]u8)text)
	digits := "0123456789abcdef"
	out := make([]u8, 2 * len(sum), allocator)
	for b, i in sum {
		out[2 * i] = digits[b >> 4]
		out[2 * i + 1] = digits[b & 15]
	}
	return string(out)
}

// ------------------------------------------------------------ checking a profile

// Everything that `profile.check` and `profile.set` build from the text.
Profile_Check :: struct {
	prof:     config.User_Profile,
	built:    bool,
	set:      Settings,
	// Problems of the profile build, then the ones of the daemon's own checks.
	problems: [dynamic]config.User_Problem,
	// Texts that the problems point to and that nothing else owns.
	owned:    [dynamic]string,
	sha:      string,
	// The key of the profile is encrypted (a guest asks for the passphrase).
	key_encrypted: bool,
}

profile_check_destroy :: proc(c: ^Profile_Check) {
	if c.built {
		config.user_profile_destroy(&c.prof)
	}
	settings_destroy(&c.set)
	for s in c.owned {
		delete(s)
	}
	delete(c.owned)
	delete(c.problems)
	delete(c.sha)
	c^ = {}
}

// Builds the profile with user-profile rules, then runs the daemon checks (keys
// parse, options it cannot run). Copies `text`: the caller overwrites its own
// after the call. All problems are listed.
profile_check_run :: proc(text: string, mobile := false) -> (c: Profile_Check) {
	c.sha = sha256_hex(text)
	c.prof = config.user_profile_build_for(text, mobile)
	c.built = true
	append(&c.problems, ..c.prof.problems)
	if !c.prof.ok {
		return
	}
	_ = settings_load(&c.set, &c.prof.cfg, .Guest if mobile else .Profile)
	c.key_encrypted = c.set.key_wait
	dirs := c.prof.cfg.parsed.directives
	for e in c.set.errors {
		option, reason := split_option(e)
		append(&c.problems, config.User_Problem{line = directive_line(dirs, option), option = option, class = "invalid", reason = reason})
	}
	cl := &c.prof.cfg.client
	if aup, ok := cl.auth_user_pass.?; ok && aup.is_inline {
		tmp: Creds
		if err := cred_parse(&tmp, aup.data, aup.username_only); err != .None {
			append(&c.problems, config.User_Problem{line = directive_line(dirs, "auth-user-pass"), option = "auth-user-pass", class = "invalid", reason = cred_error_text(err)})
		}
		cred_wipe(&tmp)
	}
	for conn in cl.connections {
		if !conn.tls {
			continue
		}
		ctx, err := outer_client_ctx(c.set.groups, cl.tls_transport_hello)
		if err != .None {
			msg := fmt.aprintf("cannot set up the outer TLS: %v", err)
			append(&c.owned, msg)
			append(&c.problems, config.User_Problem{line = directive_line(dirs, "remote"), option = "remote", class = "invalid", reason = msg})
		} else {
			ossl.tls_ctx_destroy(&ctx)
		}
		break
	}
	sort_problems(c.problems[:])
	return
}

// "name: text" gives the option name and the text. An error with no option name
// in front gives "" and the whole text.
@(private = "file")
split_option :: proc(msg: string) -> (option, reason: string) {
	i := strings.index(msg, ": ")
	if i <= 0 || i > 40 {
		return "", msg
	}
	for ch in transmute([]u8)msg[:i] {
		switch ch {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '_', '.':
		case:
			return "", msg
		}
	}
	return msg[:i], msg[i + 2:]
}

// The line of the first directive of this name, 0 if there is none.
@(private = "file")
directive_line :: proc(dirs: []config.Directive, name: string) -> int {
	if name == "" {
		return 0
	}
	for &d in dirs {
		if d.name == name {
			return d.line
		}
		if n := directive_line(d.block, name); n > 0 {
			return n
		}
	}
	return 0
}

// Stable sort by line; the problems with no line come last.
@(private = "file")
sort_problems :: proc(ps: []config.User_Problem) {
	before :: proc(a, b: config.User_Problem) -> bool {
		if a.line == b.line || a.line == 0 {
			return false
		}
		return b.line == 0 || a.line < b.line
	}
	for i in 1 ..< len(ps) {
		x := ps[i]
		j := i
		for j > 0 && before(x, ps[j - 1]) {
			ps[j] = ps[j - 1]
			j -= 1
		}
		ps[j] = x
	}
}

// The result of `profile.set` and `profile.check`: into the open result object.
profile_write_result :: proc(w: ^bus.Writer, c: ^Profile_Check, label: string, mobile := false) {
	bus.kv_arr(w, "options")
	for e in c.prof.entries {
		bus.begin_obj(w)
		bus.kv_str(w, "name", e.name)
		bus.kv_int(w, "line", i64(e.line))
		bus.kv_str(w, "disposition", "ignored" if e.ignored else "supported")
		bus.kv_str_or_null(w, "note", e.note, e.note != "")
		bus.end(w)
	}
	bus.end(w)
	bus.kv_str(w, "sha256", c.sha)
	bus.kv_str(w, "label", label)
	if mobile {
		bus.kv_bool(w, "key_encrypted", c.key_encrypted)
	}
	bus.kv_arr(w, "notes")
	for n in c.set.warnings {
		bus.val_str(w, n)
	}
	bus.end(w)
}

// The `details` of a refused profile: a JSON array, one object for each problem.
profile_write_details :: proc(w: ^bus.Writer, problems: []config.User_Problem) {
	bus.begin_arr(w)
	for p in problems[:min(len(problems), PROBLEMS_MAX)] {
		bus.begin_obj(w)
		bus.kv_int(w, "line", i64(p.line))
		bus.kv_str(w, "option", p.option)
		bus.kv_str(w, "class", p.class)
		bus.kv_str(w, "reason", p.reason)
		bus.end(w)
	}
	bus.end(w)
}

// ----------------------------------------------------------- state changes

// The daemon is in `stopped` with nothing running: a profile may be changed.
service_idle :: proc(d: ^Daemon) -> bool {
	return !d.exit && client_bus_state(d) == "stopped" && d.state == .Idle && !d.s_ok
}

// A tunnel run ended and the daemon does not exit: removes every change of the
// system (also with persist-tun), and waits for `connect` in `stopped`.
service_stop :: proc(d: ^Daemon, reason: string) {
	timer_clear(d, &d.t_policy)
	teardown_network(d, true)
	if reason == "auth_failed" && d.prof_loaded {
		if aup, ok := d.cfg.auth_user_pass.?; ok && !aup.is_inline && host_control_on(d) {
			// A new password goes in with `auth.supply`; the old one is not tried again.
			cred_wipe_password(&d.creds)
			d.creds_wait, d.creds_announced, d.creds_reason = true, true, "auth_failed"
		}
	}
	d.hold = true
	d.stop_hint = ""
	d.bus_reason = reason
	client_note_state(d)
	d.state_reason = reason
	logf(.Notice, "stopped (%s), waiting for a connect request", reason)
	service_clear_due(d)
}

// The connection closes after `disconnect` and has not ended yet.
service_closing :: proc(d: ^Daemon) -> bool {
	return !d.exit && d.hold && (d.state != .Idle || d.s_ok)
}

// The connection ended. A `profile.clear` that came while it closed removes the
// profile. Runs from a timer: callers still hold the profile (config, keys,
// policy) on their way out.
service_clear_due :: proc(d: ^Daemon) {
	if d.clear_pending && !d.shutting {
		timer_set(d, &d.t_clear, now_of(d), on_clear_timer)
	}
}

on_clear_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.t_clear.on = false
	service_clear_now(d)
}

service_clear_now :: proc(d: ^Daemon) {
	if !d.clear_pending || d.shutting || !service_idle(d) {
		return
	}
	d.clear_pending = false
	if !d.prof_loaded {
		return
	}
	logf(.Notice, "profile cleared (label %q)", d.prof_label)
	service_unload(d)
	d.state_reason = "no_profile"
	client_ev_profile(d, "cleared")
}

// `connect` (or a reconnect request) in `stopped`: the policy starts again.
service_begin :: proc(d: ^Daemon) {
	if !d.service {
		return
	}
	d.stop_hint = ""
	if _, stopped := client.policy_stopped(&d.policy); stopped {
		client.policy_rearm(&d.policy)
	}
	if d.creds_wait {
		// Ask again: nothing has come over the bus since the last stop.
		d.creds_announced = false
		d.bus_reason = d.creds_reason if d.creds_reason != "" else "no_credentials"
	}
}

// Takes the profile away: the tunnel state, the policy, the keys, the credentials
// and the token. Safe with no profile loaded.
service_unload :: proc(d: ^Daemon) {
	if !d.prof_loaded {
		return
	}
	teardown_network(d, true)
	profile_detach(d)
	settings_destroy(&d.set)
	config.user_profile_destroy(&d.prof)
	cred_wipe(&d.creds)
	web_clear(d)
	d.creds_wait, d.creds_announced, d.creds_reason, d.creds_key = false, false, "", false
	delete(d.prof_label)
	delete(d.prof_sha)
	d.prof_label, d.prof_sha = "", ""
	d.prof_sso = false
	d.owner = nil
	d.owner_sid = {}
	d.prof_loaded = false
	d.clear_pending = false
	timer_clear(d, &d.t_clear)
	d.dco.name = ""
	d.dev_name = ""
	d.cfg = &d.cfgw.client
}

// Puts a checked profile in place of the old one. `c` gives up its profile and
// settings. False: the new profile cannot be set up; the daemon then holds none.
service_install :: proc(d: ^Daemon, c: ^Profile_Check, label: string, sso: bool, uid: u32) -> bool {
	service_unload(d)
	// No token or password of an earlier profile goes to the new server.
	cred_wipe(&d.creds)
	web_clear(d)
	d.prof, c.prof = c.prof, {}
	c.built = false
	d.set, c.set = c.set, {}
	d.prof_loaded = true
	d.prof_label = strings.clone(label)
	d.prof_sha = strings.clone(c.sha)
	d.prof_sso = sso
	d.owner = uid
	d.creds_key = false

	// The service settings come from the base config for the whole run.
	cl := &d.prof.cfg.client
	base := &d.cfgw.client
	cl.verb, cl.writepid, cl.workers = base.verb, base.writepid, base.workers
	// `disable-dco` of the profile stays: its connections run in this process.
	cl.datapath, cl.dco_socket = base.datapath, base.dco_socket
	cl.bus_events, cl.bus_control, cl.bus_allow = base.bus_events, base.bus_control, base.bus_allow
	cl.stats_interval = base.stats_interval
	cl.service = true
	d.cfg = cl

	if !profile_attach(d) {
		service_unload(d)
		return false
	}
	// A login that the profile does not hold comes over the bus.
	if aup, ok := cl.auth_user_pass.?; ok {
		if aup.is_inline {
			_ = cred_parse(&d.creds, aup.data, aup.username_only)
		} else {
			d.creds_wait = true
			d.creds_reason = "no_credentials"
		}
	}
	if (d.guest != nil || d.service) && d.set.key_wait {
		// The key waits for its passphrase (`auth.supply`) before anything else.
		d.creds_wait, d.creds_reason, d.creds_key = true, "key_encrypted", true
	}
	if cl.disable_dco && d.dco.want {
		logf(.Notice, "the profile has disable-dco, so the data path of its connections will run in this process")
	}
	crl_log_start(&d.set.crl)
	d.hold = true
	d.state_reason = "profile_set"
	return true
}

// ------------------------------------------------------------------ the bus

// The fields of the `profile` object of `status` and of the event `client.profile`
// (after `change`): `loaded`, `label`, `sha256`, `owner`.
client_write_profile :: proc(w: ^bus.Writer, d: ^Daemon) {
	bus.kv_bool(w, "loaded", d.prof_loaded)
	bus.kv_str_or_null(w, "label", d.prof_label, d.prof_loaded)
	bus.kv_str_or_null(w, "sha256", d.prof_sha, d.prof_loaded)
	if o, ok := d.owner.?; ok && d.prof_loaded {
		when ODIN_OS == .Windows {
			bus.kv_str(w, "owner", bus.sid_string(d.owner_sid, context.temp_allocator))
			_ = o
		} else {
			bus.kv_u64(w, "owner", u64(o))
		}
	} else {
		bus.kv_null(w, "owner")
	}
}

// `change` is "set" or "cleared".
client_ev_profile :: proc(d: ^Daemon, change: string) {
	if w := ev_begin(d); w != nil {
		bus.kv_str(w, "change", change)
		client_write_profile(w, d)
		ev_emit(d, "client.profile")
	}
}

// The additions of the `client` object of `status`.
client_write_service_status :: proc(w: ^bus.Writer, d: ^Daemon) {
	bus.kv_bool(w, "service", d.service)
	if d.service {
		bus.kv_obj(w, "profile")
		client_write_profile(w, d)
		bus.end(w)
		// The data path setting of the service (its base config), so that a
		// user interface can say why a profile runs without DCO.
		bus.kv_str(w, "datapath_mode", config.datapath_name(d.cfgw.client.datapath))
	} else {
		bus.kv_null(w, "profile")
	}
	state := client_bus_state(d)
	idle := state == "waiting" || state == "stopped"
	bus.kv_str_or_null(w, "reason", d.state_reason, idle && d.state_reason != "")
	bus.kv_str_or_null(w, "detail", d.state_detail, idle && d.state_reason != "" && d.state_detail != "")
}
