// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd, windows
package main

// Tests of the bus link.
//   selftest_link     fake client daemon in this process (bus.host_open) and the
//                     real link: search, status, events, credentials, stats,
//                     disconnect, failure, sequence rule, restart, denied.
//   selftest_service  same fake in service mode: import, profile.check,
//                     profile.set, connect, profile change, owner rule.
//   live_test         the link against a real client daemon (--live-test).

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"
import sdl "vendor:sdl3"
import "noir:bus"
import "noir:proto/config"
import pf "profiles"
import "ui"

Fake :: struct {
	h:          ^bus.Host,
	control:    string,
	events:     string,
	state:      string,
	reason:     string,
	attempt:    int,
	auth:       bool, // waits for credentials
	got_user:   string,
	got_pass:   string,
	bytes_in:   u64,
	bytes_out:  u64,
	up_at:      time.Time,
	connect_ok: bool, // a connect comes up; else the login is refused
	server:     bool, // responds as a server daemon
	service:    bool, // service mode: takes profiles over the bus
	loaded:     bool,
	label:      string,
	text:       string, // the last profile.set text
	web:        bool, // profile.set asked for web sign-in
	sets:       int,
	old:        bool, // refuses a local block-ipv6 line, as a daemon without its support
	other:      bool, // another user owns the loaded profile
	clears:     int,
	closing:    int, // profile.clear responds with conflict this many times after a disconnect
	web_wait:   bool, // a connect waits for a web sign-in
	web_active: bool, // a web sign-in waits now
	web_url:    string, // the link of the sign-in
	web_nourl:  bool, // status gives no link to this user
	need_key:   bool, // a connect waits for the passphrase of the key
	need_login: bool, // a connect waits for a login
	auth_kind:  string, // the kind of the wait: "credentials" or "key_pass"
	got_key:    string,
}

// fake_wait_auth sets the fake to wait for the passphrase or for a login, and
// publishes client.auth_needed as a client service does.
fake_wait_auth :: proc(f: ^Fake) -> bool {
	kind, reason := "", ""
	switch {
	case f.need_key:
		kind, reason = "key_pass", "key_encrypted"
	case f.need_login:
		kind, reason = "credentials", "no_credentials"
	case:
		return false
	}
	f.auth, f.auth_kind = true, kind
	fake_publish_state(f, "waiting", reason)
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	bus.kv_str(&w, "kind", kind)
	bus.kv_str(&w, "reason", reason)
	bus.kv_null(&w, "username")
	bus.kv_null(&w, "prompt")
	bus.kv_bool(&w, "echo", false)
	bus.kv_null(&w, "timeout_s")
	bus.end(&w)
	bus.publish(f.h, "client.auth_needed", bus.writer_bytes(&w))
	return true
}

// fake_web_fields writes the web_auth object of client.auth_needed and status.
fake_web_fields :: proc(f: ^Fake, w: ^bus.Writer, url: bool) {
	bus.kv_str(w, "kind", "web_auth")
	bus.kv_str(w, "reason", "web_auth")
	bus.kv_null(w, "username")
	bus.kv_null(w, "prompt")
	bus.kv_bool(w, "echo", false)
	bus.kv_int(w, "timeout_s", 120)
	bus.kv_str_or_null(w, "url", f.web_url, url && !f.web_nourl)
	bus.kv_str(w, "host", "login.example.com")
	bus.kv_arr(w, "flags")
	bus.end(w)
	buf: [24]u8
	bus.kv_str(w, "deadline", bus.format_ts(time.time_add(time.now(), 120 * time.Second), &buf))
}

// fake_web_wait starts a web sign-in: the state handshake and the event, which has no link.
fake_web_wait :: proc(f: ^Fake) {
	fake_publish_state(f, "handshake", "")
	f.web_active = true
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	fake_web_fields(f, &w, false)
	bus.end(&w)
	bus.publish(f.h, "client.auth_needed", bus.writer_bytes(&w))
}

// fake_web_approve ends the sign-in, as the server does after the browser.
fake_web_approve :: proc(f: ^Fake) {
	f.web_active = false
	fake_publish_state(f, "up", "")
}

fake_open :: proc(f: ^Fake, mode := bus.Daemon_Mode.Client, allow: []config.Bus_Allow = nil) -> bool {
	allow := allow
	when ODIN_OS == .Windows {
		// The user of this process gets admin, also without elevation, and the
		// client accepts the pipe that this user owns.
		me: [1]config.Bus_Allow
		if allow == nil {
			sid, _ := bus.current_user_sid()
			me[0] = {kind = .Sid, name = bus.sid_string(sid, context.temp_allocator), roles = {.Admin}}
			allow = me[:]
		}
		bus.pipe_trust_own_user = true
	}
	policy, _ := bus.policy_from_config(allow, my_uid())
	defer bus.policy_destroy(&policy)
	opts := bus.Host_Options {
		mode    = mode,
		control = bus.Endpoint{path = f.control},
		events  = bus.Endpoint{path = f.events},
		policy  = policy,
	}
	f.server = mode == .Server
	h, err, _ := bus.host_open(opts)
	if err != .None {
		fmt.eprintln("fake daemon:", bus.open_error_string(err))
		return false
	}
	f.h = h
	return true
}

fake_close :: proc(f: ^Fake) {
	if f.h != nil {
		bus.host_close(f.h)
		f.h = nil
	}
}

fake_publish_state :: proc(f: ^Fake, state, reason: string) {
	prev := f.state
	f.state, f.reason = state, reason
	if state == "connecting" {
		f.attempt += 1
	}
	if state == "up" {
		f.up_at = time.now()
		fake_publish_settings(f)
	}
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	bus.kv_str(&w, "state", state)
	bus.kv_str(&w, "prev", prev)
	bus.kv_str_or_null(&w, "reason", reason, reason != "")
	bus.kv_str(&w, "remote", "192.0.2.7:1194")
	bus.kv_int(&w, "attempt", i64(f.attempt))
	bus.kv_str(&w, "datapath", "udco")
	bus.end(&w)
	bus.publish(f.h, "client.state", bus.writer_bytes(&w))
}

// fake_publish_settings sends client.tunnel_settings, as a daemon does just
// before up.
fake_publish_settings :: proc(f: ^Fake) {
	data := `{"peer_id":1,"cipher":"AES-256-GCM","data_format":"epoch","ifconfig":{"addr4":"10.8.0.2","netmask4":"255.255.255.0","gateway4":"10.8.0.1","addr6":"fd00:8::2","prefix6":64},"mtu":1420,"routes":[{"net":"10.20.0.0/16","gateway":"10.8.0.1","metric":null},{"net":"fd00:20::/48","gateway":null,"metric":null}],"dns_servers":["10.8.0.1"],"dns_domains":["corp.example.com"],"redirect_gateway":true,"push":[]}`
	bus.publish(f.h, "client.tunnel_settings", transmute([]byte)string(data))
}

fake_profile_fields :: proc(f: ^Fake, w: ^bus.Writer) {
	bus.kv_bool(w, "loaded", f.loaded)
	bus.kv_str_or_null(w, "label", f.label, f.loaded)
	bus.kv_str_or_null(w, "sha256", text_sha(f.text, context.temp_allocator), f.loaded)
	if f.loaded {
		bus.kv_int(w, "owner", f.other ? 4242 : i64(my_uid()))
	} else {
		bus.kv_null(w, "owner")
	}
}

fake_status :: proc(f: ^Fake, w: ^bus.Writer) {
	run, seq := bus.host_position(f.h)
	bus.begin_obj(w)
	bus.kv_str(w, "mode", f.server ? "server" : "client")
	bus.kv_str(w, "name", "fake")
	bus.kv_str(w, "version", "0")
	bus.kv_null(w, "config")
	bus.kv_obj(w, "bus")
	bus.kv_str(w, "run", run)
	bus.kv_int(w, "seq", i64(seq))
	bus.kv_bool(w, "events", true)
	bus.end(w)
	bus.kv_obj(w, "client")
	bus.kv_str(w, "state", f.state)
	bus.kv_str(w, "datapath", "udco")
	bus.kv_str(w, "remote", "192.0.2.7:1194")
	bus.kv_str(w, "proto", "udp")
	up := f.state == "up"
	bus.kv_str_or_null(w, "vpn4", "10.8.0.2", up)
	bus.kv_str_or_null(w, "vpn6", "fd00:8::2", up)
	bus.kv_str_or_null(w, "cipher", "AES-256-GCM", up)
	bus.kv_str_or_null(w, "data_format", "epoch", up)
	buf: [24]u8
	bus.kv_str_or_null(w, "connected_at", bus.format_ts(f.up_at, &buf), up)
	bus.kv_str_or_null(w, "tun", "tun0", up)
	if f.web_active {
		bus.kv_obj(w, "auth_needed")
		fake_web_fields(f, w, true)
		bus.end(w)
	} else if f.auth {
		bus.kv_obj(w, "auth_needed")
		bus.kv_str(w, "kind", f.auth_kind if f.auth_kind != "" else "credentials")
		bus.kv_str(w, "reason", "no_credentials")
		bus.kv_str(w, "username", "alice")
		bus.end(w)
	} else {
		bus.kv_null(w, "auth_needed")
	}
	bus.kv_bool(w, "service", f.service)
	if f.service {
		bus.kv_obj(w, "profile")
		fake_profile_fields(f, w)
		bus.end(w)
	} else {
		bus.kv_null(w, "profile")
	}
	idle := f.state == "stopped" || f.state == "waiting"
	bus.kv_str_or_null(w, "reason", f.reason, idle && f.reason != "")
	bus.end(w)
	bus.end(w)
}

// fake_serve replies to the requests that wait.
fake_serve :: proc(f: ^Fake) {
	if f.h == nil {
		return
	}
	for {
		req, ok := bus.next_request(f.h)
		if !ok {
			break
		}
		w: bus.Writer
		bus.writer_init(&w, context.temp_allocator)
		owner_op := req.op == "profile.set" || req.op == "connect" || req.op == "disconnect" || req.op == "auth.supply" || req.op == "profile.clear"
		if f.service && f.loaded && f.other && owner_op {
			bus.reply_error(f.h, req, .Denied, OWNER_DENIED)
			continue
		}
		switch req.op {
		case "status":
			fake_status(f, &w)
		case "stats.get":
			if f.state == "up" {
				f.bytes_in += 125_000
				f.bytes_out += 12_500
			}
			bus.begin_obj(&w)
			bus.kv_str(&w, "datapath", "udco")
			bus.kv_obj(&w, "totals")
			bus.kv_int(&w, "bytes_in", i64(f.bytes_in))
			bus.kv_int(&w, "bytes_out", i64(f.bytes_out))
			bus.kv_int(&w, "packets_in", i64(f.bytes_in / 1000))
			bus.kv_int(&w, "packets_out", i64(f.bytes_out / 1000))
			bus.end(&w)
			bus.end(&w)
		case "auth.supply":
			if !f.auth {
				bus.reply_error(f.h, req, .Conflict, "nothing waits for credentials")
				continue
			}
			if f.auth_kind == "key_pass" {
				kp, has := req.args["key_pass"].(string)
				if !has {
					bus.reply_error(f.h, req, .Bad_Request, "give at least one of username, password and response")
					continue
				}
				f.got_key = strings.clone(kp)
				f.need_key, f.auth, f.auth_kind = false, false, ""
				bus.begin_obj(&w)
				bus.kv_bool(&w, "accepted", true)
				bus.end(&w)
				bus.reply_ok(f.h, req, bus.writer_bytes(&w))
				if !fake_wait_auth(f) {
					fake_publish_state(f, "connecting", "")
					fake_publish_state(f, "up", "")
				}
				continue
			}
			u, _ := req.args["username"].(string)
			p, _ := req.args["password"].(string)
			f.need_login = false
			f.got_user = strings.clone(u)
			f.got_pass = strings.clone(p)
			f.auth = false
			bus.begin_obj(&w)
			bus.kv_bool(&w, "accepted", true)
			bus.end(&w)
			bus.reply_ok(f.h, req, bus.writer_bytes(&w))
			fake_publish_state(f, "connecting", "")
			fake_publish_state(f, "handshake", "")
			fake_publish_state(f, "up", "")
			continue
		case "profile.check", "profile.set":
			if !f.service {
				bus.reply_error(f.h, req, .Unsupported, "the daemon does not run as a client service")
				continue
			}
			text, _ := req.args["text"].(string)
			label, _ := req.args["label"].(string)
			if strings.contains(text, "\nup ") {
				details := `[{"line":4,"option":"up","class":"not_supported","reason":"runs a program"}]`
				bus.reply_error_details(f.h, req, .Bad_Request, "the profile has problems", transmute([]byte)string(details))
				continue
			}
			if i := strings.index(text, "\nblock-ipv6\n"); f.old && i >= 0 {
				n := fmt.tprint(strings.count(text[:i + 1], "\n") + 1)
				details := strings.concatenate({`[{"line":`, n, `,"option":"block-ipv6","class":"not_supported","reason":"not supported; filter IPv6 traffic with the system firewall"}]`}, context.temp_allocator)
				bus.reply_error_details(f.h, req, .Bad_Request, "the profile has problems", transmute([]byte)details)
				continue
			}
			if req.op == "profile.set" {
				if f.state != "stopped" {
					bus.reply_error(f.h, req, .Conflict, "disconnect first")
					continue
				}
				f.text = strings.clone(text)
				f.label = strings.clone(label)
				_, f.web = req.args["sso"].(json.Array)
				f.loaded = true
				f.reason = "profile_set"
				f.sets += 1
				ev: bus.Writer
				bus.writer_init(&ev, context.temp_allocator)
				bus.begin_obj(&ev)
				bus.kv_str(&ev, "change", "set")
				fake_profile_fields(f, &ev)
				bus.end(&ev)
				bus.publish(f.h, "client.profile", bus.writer_bytes(&ev))
			}
			bus.begin_obj(&w)
			bus.kv_arr(&w, "options")
			bus.begin_obj(&w)
			bus.kv_str(&w, "name", "verb")
			bus.kv_int(&w, "line", 2)
			bus.kv_str(&w, "disposition", "ignored")
			bus.kv_str(&w, "note", "no effect in a profile")
			bus.end(&w)
			bus.end(&w)
			bus.kv_str(&w, "sha256", text_sha(text, context.temp_allocator))
			bus.kv_str(&w, "label", label)
			bus.kv_arr(&w, "notes")
			if strings.contains(text, "\nmlock") {
				bus.val_str(&w, "mlock is not applied")
			}
			bus.end(&w)
			bus.end(&w)
		case "connect":
			if f.service && !f.loaded {
				bus.reply_error(f.h, req, .Conflict, "no profile is loaded")
				continue
			}
			fake_publish_state(f, "connecting", "")
			if f.web_wait {
				fake_web_wait(f)
			} else if fake_wait_auth(f) {
			} else if f.connect_ok {
				fake_publish_state(f, "handshake", "")
				fake_publish_state(f, "up", "")
			} else {
				fake_publish_state(f, "stopped", "auth_failed")
			}
			bus.begin_obj(&w)
			bus.kv_str(&w, "state", f.state)
			bus.end(&w)
		case "profile.clear":
			if !f.service {
				bus.reply_error(f.h, req, .Unsupported, "the daemon does not run as a client service")
				continue
			}
			if f.state != "stopped" || f.closing > 0 {
				f.closing = max(f.closing - 1, 0)
				bus.reply_error(f.h, req, .Conflict, "disconnect first")
				continue
			}
			if f.loaded {
				f.loaded = false
				f.reason = "no_profile"
				f.clears += 1
				ev: bus.Writer
				bus.writer_init(&ev, context.temp_allocator)
				bus.begin_obj(&ev)
				bus.kv_str(&ev, "change", "cleared")
				fake_profile_fields(f, &ev)
				bus.end(&ev)
				bus.publish(f.h, "client.profile", bus.writer_bytes(&ev))
			}
			bus.begin_obj(&w)
			bus.end(&w)
		case "disconnect":
			f.web_active = false
			fake_publish_state(f, "stopped", "user_request")
			f.closing = 2
			bus.begin_obj(&w)
			bus.kv_str(&w, "state", "stopped")
			bus.end(&w)
		case:
			bus.reply_error(f.h, req, .Unknown_Op, "no such operation")
			continue
		}
		bus.reply_ok(f.h, req, bus.writer_bytes(&w))
	}
}

Pump_Cond :: #type proc(app: ^App, f: ^Fake) -> bool

// pump runs the link and the fake daemon in real time until cond holds or
// secs pass.
pump :: proc(app: ^App, f: ^Fake, cond: Pump_Cond, secs: f64) -> bool {
	end := now_seconds() + secs
	for {
		if f != nil {
			fake_serve(f)
		}
		app.now = now_seconds()
		_ = link_poll(app)
		link_tick(app)
		build(app, 0)
		free_all(context.temp_allocator)
		if cond(app, f) {
			return true
		}
		if app.now > end {
			return false
		}
		time.sleep(5 * time.Millisecond)
	}
}

// link_app creates an App with the bus link that shares the window of base.
link_app :: proc(base: ^App, socket: string) -> ^App {
	app := new(App)
	app.headless = true
	app.window = base.window
	app.renderer = base.renderer
	app.unclamped = true
	app.link.kind = .Bus
	_ = app_setup(app, base.eff)
	app.eff = base.eff
	app.u.input_k = base.u.input_k
	bus_start(app, socket)
	app.link.impl.wake = false
	app.browser_test = true
	return app
}

// my_uid is the uid of this process (0 on Windows, where the bus has SIDs).
my_uid :: proc() -> u32 {
	when ODIN_OS == .Windows {
		return 0
	} else {
		return bus.euid()
	}
}

// test_dir creates a private directory for the files of a test.
test_dir :: proc(tag: string) -> string {
	when ODIN_OS == .Windows {
		tmp, _ := os.temp_directory(context.temp_allocator)
		dir := fmt.aprintf("%s/%s-%d", tmp, tag, os.get_pid())
	} else {
		dir := fmt.aprintf("/tmp/%s-%d", tag, os.get_pid())
	}
	_ = os.make_directory(dir, {.Read_User, .Write_User, .Execute_User})
	return dir
}

// fake_endpoints sets the control and events addresses of a fake: socket
// files in `dir`, or named pipes on Windows.
fake_endpoints :: proc(f: ^Fake, dir, name: string) {
	when ODIN_OS == .Windows {
		f.control = fmt.aprintf("%snoirvpn-%s%d%s", bus.PIPE_DIR, name, os.get_pid(), bus.CONTROL_SUFFIX)
		f.events = fmt.aprintf("%snoirvpn-%s%d%s", bus.PIPE_DIR, name, os.get_pid(), bus.EVENTS_SUFFIX)
	} else {
		f.control = fmt.aprintf("%s/%s.control", dir, name)
		f.events = fmt.aprintf("%s/%s.events", dir, name)
	}
}

selftest_link :: proc(base: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	dir := test_dir("nvgui")
	defer os.remove_all(dir)
	f := new(Fake)
	fake_endpoints(f, dir, "fake")
	f.state = "handshake"
	f.auth = true
	f.attempt = 1
	if !fake_open(f) {
		check("link: fake daemon opens", false, failed)
		return
	}
	defer fake_close(f)
	app := link_app(base, f.control)
	defer bus_stop(app)
	c := &app.conn
	l := &app.link

	ok := pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Up}, 5)
	check("link: the search finds the daemon of --socket", ok && current_view(app) == .List, failed)
	check("link: the list shows the daemon", app.n_profiles == 1 && app.profiles[0].source == .Daemon && app.profiles[0].name == "fake" && app.profiles[0].host == "192.0.2.7" && app.profiles[0].port == 1194, failed)
	check("link: a daemon that waits for credentials shows the sign-in", c.phase == .Credentials && ui.field_text(&c.user) == "", failed)
	check("link: waiting for sign-in is active", conn_active(app), failed)

	open_connection(app, 0)
	check("link: opening an active row does not connect again", current_view(app) == .Connection && c.phase == .Credentials, failed)
	ui.field_set(&c.user, "alice")
	ui.field_set(&c.pass, "pw1")
	link_auth_supply(app)
	check("link: the password field is wiped at once", ui.field_text(&c.pass) == "" && c.phase == .Connecting, failed)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return f.got_pass != "" && app.conn.phase == .Up}, 5)
	check("link: auth.supply sends the user name and the password", ok && f.got_user == "alice" && f.got_pass == "pw1", failed)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.address != ""}, 5)
	check("link: status after up gives the details", ok && c.address == "10.8.0.2, fd00:8::2" && c.cipher == "AES-256-GCM" && c.data_format == "epoch" && conn_transport(app) == "UDP" && datapath_label(c.datapath) == "DCO service", failed)
	check("link: the tunnel settings give the server address and the routes", c.settings_ok && c.peer4 == "10.8.0.1" && len(c.routes) == 2 && c.redirect, failed)
	check("link: duration starts at connected_at", app.now - c.up_start < 5 && app.now - c.up_start >= 0, failed)

	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.count >= 2}, 5)
	check("link: one rate sample a second from the counters", ok && c.down[c.count - 1] > 500_000 && c.down[c.count - 1] < 2_000_000 && c.rx_bytes >= 250_000, failed)
	app.hidden = true
	check("link: no timed wake while hidden", link_wake(app) == 0, failed)
	app.hidden = false

	link_disconnect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped}, 5)
	check("link: disconnect stops the tunnel and the view stays", ok && !conn_active(app) && current_view(app) == .Connection, failed)
	check("link: the tray is idle after disconnect", tray_state(app).kind == .Idle, failed)

	link_connect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Failed}, 5)
	check("link: a refused login ends in the error state with the reason", ok && c.failure == "The server refused the login", failed)
	f.connect_ok = true
	link_connect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 5)
	check("link: Connect after a failure brings the tunnel up", ok && c.failure == "", failed)

	// The sequence rule, with events created here.
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.status_busy}, 5)
	seq := l.seq
	run := strings.clone(l.run)
	check("link: an event inside the status snapshot is skipped", !apply_event(app, "client.tunnel_settings", run, seq, nil), failed)
	check("link: the next event is used and no read starts", apply_event(app, "client.tunnel_settings", run, seq + 1, nil) && !l.status_busy, failed)
	check("link: a gap reads status again", apply_event(app, "client.tunnel_settings", run, seq + 5, nil) && l.status_busy, failed)
	l.status_again = false
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.status_busy}, 5)
	check("link: a new run reads status again", apply_event(app, "client.tunnel_settings", "0123456789abcdef", 1, nil) && l.status_busy, failed)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.status_busy && !app.link.status_again}, 5)

	// A status reply created before the applied events changes nothing; the
	// settings object of status gives the pushed settings without the event.
	{
		seq2 := l.seq
		run2 := strings.clone(l.run, context.temp_allocator)
		ts, _ := json.parse_string(`{"ifconfig":{"addr4":"10.8.0.2","gateway4":"10.8.0.1"}}`, allocator = context.temp_allocator)
		apply_tunnel_settings(c, ts)
		stale, _ := json.parse_string(fmt.tprintf(`{{"bus":{{"run":"%s","seq":%d}},"client":{{"state":"stopped"}}}}`, run2, seq2 - 1), allocator = context.temp_allocator)
		apply_status(app, stale, app.now)
		check("link: an old status reply keeps the state and the settings", c.phase == .Up && c.settings_ok && c.peer4 == "10.8.0.1" && l.seq == seq2 && l.status_again, failed)
		l.status_again = false
		conn_settings_clear(c)
		fresh, _ := json.parse_string(
			fmt.tprintf(
				`{{"log_file":"C:\\ProgramData\\noirvpn\\desktop.log","bus":{{"run":"%s","seq":%d}},"client":{{"state":"up","vpn4":"10.8.0.2","settings":{{"ifconfig":{{"addr4":"10.8.0.2","gateway4":"10.8.0.1"}},"mtu":1428,"mss4":1388,"mss6":1368,"peer_id":7,"routes":[],"push":["route-gateway 10.8.0.1","topology subnet"]}}}}}}`,
				run2,
				seq2,
			),
			allocator = context.temp_allocator,
		)
		apply_status(app, fresh, app.now)
		check("link: the settings of status give the server address and the MSS", c.phase == .Up && c.settings_ok && c.peer4 == "10.8.0.1" && c.mss4 == 1388 && c.mss6 == 1368 && c.mtu == 1428 && c.peer_id == 7 && len(c.pushed) == 2, failed)
		check("link: status gives the log file", l.log_file == `C:\ProgramData\noirvpn\desktop.log`, failed)
	}

	// The daemon stops, and starts again with a new run.
	fake_close(f)
	link_refresh(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Not_Found && !app.link.status_busy}, 5)
	check("link: a lost daemon shows the attach view", ok && app.stack[0] == .Attach && current_view(app) == .Attach && !conn_active(app), failed)
	title, _, _ := attach_texts(app)
	check("link: attach text for no service", title == "Service not running" && strings.contains(l.looked, f.control), failed)
	f.state, f.auth = "stopped", false
	_ = fake_open(f)
	link_retry(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Up}, 5)
	check("link: Retry finds the restarted daemon", ok && current_view(app) == .List && l.run != run && app.conn.phase == .Stopped, failed)
	fake_close(f)

	if my_uid() != 0 || ODIN_OS == .Windows {
		when ODIN_OS == .Windows {
			allow := [1]config.Bus_Allow{{kind = .Sid, name = bus.SID_LOCAL_SYSTEM, roles = {.Admin}}}
		} else {
			allow := [1]config.Bus_Allow{{kind = .Uid, id = 0, roles = {.Admin}}}
		}
		_ = fake_open(f, .Client, allow[:])
		link_refresh(app)
		ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Denied}, 5)
		check("link: a daemon that gives this user no role is denied", ok && current_view(app) == .Attach, failed)
		title, _, _ = attach_texts(app)
		check("link: attach text for denied", title == "No access to the service", failed)
		fake_close(f)
	}

	_ = fake_open(f, .Server)
	link_retry(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Not_Found && !app.link.status_busy}, 5)
	check("link: a server daemon is not followed", ok && current_view(app) == .Attach, failed)

	// The job of the service in the app bundle (service_manage.odin).
	l.state = .Not_Found
	l.manage = .Requires_Approval
	t2, _, h2 := attach_texts(app)
	check("link: attach text for a service that waits for the user", t2 == "Allow the service" && strings.contains(h2, "Open Settings"), failed)
	l.manage = .Enabled
	t2, _, h2 = attach_texts(app)
	check("link: attach text for a service that is starting", t2 == "Starting the service" && strings.contains(h2, MANAGE_LOG), failed)
	l.manage = .Not_Registered
	set_text(&l.manage_err, "Operation not permitted")
	b2: string
	t2, b2, _ = attach_texts(app)
	check("link: attach text for a registration that failed", t2 == "Service not started" && strings.contains(b2, "Operation not permitted"), failed)
	set_text(&l.manage_err, "")
	t2, _, _ = attach_texts(app)
	check("link: a job that is not registered gives the text for no service", t2 == "Service not running", failed)
	// The system has not seen the job and the registration failed: the same text.
	l.manage = .Not_Found
	set_text(&l.manage_err, "Operation not permitted")
	t2, _, _ = attach_texts(app)
	check("link: attach text for a registration that failed on a first run", t2 == "Service not started", failed)
	set_text(&l.manage_err, "")
	// The daemon next to the program: the way to start it by hand.
	set_text(&l.daemon_cmd, "/Applications/NoirVPN.app/Contents/MacOS/noirvpn")
	_, _, h2 = attach_texts(app)
	check("link: the attach view shows the command that starts the daemon", strings.contains(h2, "sudo /Applications/NoirVPN.app/Contents/MacOS/noirvpn"), failed)
	set_text(&l.daemon_cmd, "/Users/a b/NoirVPN.app/Contents/MacOS/noirvpn")
	_, _, h2 = attach_texts(app)
	check("link: a path with a space is in quotes", strings.contains(h2, `sudo "/Users/a b/NoirVPN.app/Contents/MacOS/noirvpn"`), failed)
	set_text(&l.daemon_cmd, "")
	l.manage = .Unavailable
	// manage_ensure with tried = true only reads the state: the test must not
	// register a job in the login items of this Mac.
	tried := true
	st, err := manage_ensure(&tried)
	delete(err)
	if ODIN_OS == .Darwin {
		check("manage: the system gives the state of the job", st != .Unavailable && err == "", failed)
	} else {
		check("manage: no job on this system", st == .Unavailable, failed)
	}
}

// selftest_service checks stored profiles against a fake daemon in service mode:
// import with profile.check, connect with profile.set, profile change, owner rule.
selftest_service :: proc(base: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	dir := test_dir("nvsvc")
	defer os.remove_all(dir)
	in_dir := fmt.aprintf("%s/in", dir)
	_ = os.make_directory(in_dir, {.Read_User, .Write_User, .Execute_User})
	cert := "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
	_ = os.write_entire_file(fmt.tprintf("%s/ca.crt", in_dir), cert)
	_ = os.write_entire_file(fmt.tprintf("%s/c.crt", in_dir), cert)
	_ = os.write_entire_file(fmt.tprintf("%s/c.key", in_dir), "-----BEGIN PRIVATE KEY-----\nMIGHsecret\n-----END PRIVATE KEY-----\n")
	work := fmt.aprintf("%s/work.ovpn", in_dir)
	_ = os.write_entire_file(work, "client\nverb 3\nremote vpn.example.com 443 tcp-client\nca ca.crt\ncert c.crt\nkey c.key\n")
	bad := fmt.aprintf("%s/bad.ovpn", in_dir)
	_ = os.write_entire_file(bad, "client\nverb 3\nremote vpn.example.com\nup /bin/true\n")
	escape := fmt.aprintf("%s/escape.ovpn", in_dir)
	_ = os.write_entire_file(escape, "client\nremote vpn.example.com\nca ../secret.crt\n")
	noted := fmt.aprintf("%s/zed.ovpn", in_dir)
	_ = os.write_entire_file(noted, "client\nmlock\nremote vpn.example.com 443 tcp-client\nca ca.crt\ncert c.crt\nkey c.key\n")

	f := new(Fake)
	fake_endpoints(f, dir, "svc")
	f.state = "stopped"
	f.reason = "no_profile"
	f.service = true
	f.connect_ok = true
	if !fake_open(f) {
		check("service: fake daemon opens", false, failed)
		return
	}
	defer fake_close(f)
	app := link_app(base, f.control)
	defer bus_stop(app)
	app.store = pf.store_open(fmt.tprintf("%s/store", dir))
	store_reload(app)
	l := &app.link
	c := &app.conn

	ok := pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Up}, 5)
	check("service: found in service mode, no daemon row", ok && l.service && app.n_profiles == 0 && !conn_active(app), failed)
	check("service: no profile is no failure", l.reason == "no_profile" && c.phase == .Stopped && c.failure == "", failed)

	import_path(app, escape)
	check("service: a key file outside the folder stops the import", app.message_error && app.n_profiles == 0 && !app.import_wait, failed)
	import_path(app, work)
	check("service: import waits for profile.check", app.import_wait, failed)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.import_wait}, 5)
	check("service: import stores the checked profile", ok && app.n_profiles == 1 && app.profiles[0].source == .Stored && app.profiles[0].name == "work" && app.profiles[0].host == "vpn.example.com" && app.profiles[0].port == 443 && app.profiles[0].proto == "tcp", failed)
	check("service: the message counts the ignored options", !app.message_error && app.message == "Imported \u201cwork\u201d. 1 option has no effect.", failed)
	check("service: a new row was never used", app.profiles[0].last_used == 0 && fmt_last_used(0) == "Never used" && row_address(&app.profiles[0]) == "vpn.example.com", failed)
	import_path(app, work)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.import_wait}, 5)
	check("service: a second import gets a new name", app.n_profiles == 2 && app.profiles[1].name == "work 2", failed)
	import_path(app, bad)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.import_wait}, 5)
	check("service: a profile that the service refuses is not stored", app.n_profiles == 2 && app.message_error && app.message == "The profile was not imported. The service found a problem: Line 4, up: runs a program", failed)

	open_profile(app, 0)
	e := &app.edit
	shown := strings.join(e.lines[:], "\n")
	defer delete(shown)
	check("service: the profile view hides key blocks", current_view(app) == .Profile && strings.contains(shown, "<key>\n  (3 lines hidden)\n</key>") && !strings.contains(shown, "secret") && !strings.contains(shown, "BEGIN"), failed)
	check("service: the profile view shows the summary", len(e.remotes) == 1 && e.remotes[0] == "vpn.example.com:443\tTCP" && e.ident == {true, true, true, false, false}, failed)
	list_add(e, .Domain, "corp.example.com")
	list_add(e, .Server, "10.0.0.53")
	list_add(e, .Server, "not an address")
	e.redirect = false
	e.dirty = true
	edit_save(app)
	check("service: a bad DNS server stops the save", e.status_error && e.dirty, failed)
	list_remove(e, .Server, 1)
	edit_save(app)
	check("service: the overrides are saved", !e.status_error && !e.dirty, failed)
	pop_view(app)

	open_connection(app, 0)
	check("service: a row opens its view and does not connect", current_view(app) == .Connection && app.shown == 0 && f.sets == 0 && shown_phase(app) != .Up && !conn_locked(app), failed)
	row_connect(app, 0)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 5)
	check("service: Connect sends profile.set, then connect", ok && f.sets == 1 && l.sets_sent == 1 && f.label == "work" && current_view(app) == .Connection && c.profile == 0, failed)
	check("service: the text has the keys and the override lines", strings.contains(f.text, "<key>\n-----BEGIN PRIVATE KEY-----") && strings.has_suffix(f.text, "pull-filter ignore \"redirect-gateway\"\ndhcp-option DOMAIN corp.example.com\ndns server -128 address 10.0.0.53\n"), failed)
	check("service: client.profile names the loaded profile", l.loaded && l.loaded_label == "work" && l.loaded_sha == text_sha(f.text, context.temp_allocator), failed)
	check("service: the tunnel settings give the server address, routes and DNS", c.settings_ok && c.peer4 == "10.8.0.1" && len(c.routes) == 2 && c.routes[0].net == "10.20.0.0/16" && c.routes[1].gateway == "" && c.redirect && len(c.dns_servers) == 1 && c.dns_domains[0] == "corp.example.com", failed)
	o := row_overrides(app, 0)
	check("service: the overrides of the row are known to the view", len(o.domains) == 1 && o.domains[0] == "corp.example.com" && len(o.dns_servers) == 1 && o.ignore_redirect, failed)
	{
		// The service lists the own domain with the pushed DNS; the card shows it once.
		lines := dns_lines(c, o)
		want := []Kv{{label = "Servers", value = "10.8.0.1"}, {value = "10.0.0.53", own = true}, {label = "Domains", value = "corp.example.com", own = true}}
		same := len(lines) == len(want)
		for w, i in want {
			same = same && lines[i] == w
		}
		check("service: the DNS card shows each own entry once, in bold", same, failed)
	}
	check("service: the tunnel row has no way back", conn_locked(app), failed)
	key(app, sdl.K_ESCAPE)
	check("service: Escape does not leave a connected view", current_view(app) == .Connection, failed)
	meta, _, found := pf.store_load(app.store, app.profiles[0].id, context.temp_allocator)
	check("service: up writes the last use and the server address", found && meta.last_connected > 0 && meta.server_ip == "192.0.2.7" && app.profiles[0].server_ip == "192.0.2.7" && app.profiles[0].last_used == meta.last_connected, failed)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.status_busy}, 5)
	st, _, shown_state := row_state(app, 0)
	check("service: the row of the loaded profile shows the state", l.loaded && shown_state && st == "connected", failed)
	row_delete(app, 0)
	check("service: the profile of the tunnel cannot be deleted", app.n_profiles == 2 && app.message_error, failed)

	// The list at start while a tunnel runs: another row shows its own state.
	pop_view(app)
	open_connection(app, 1)
	check("service: another row shows disconnected while the tunnel runs", app.shown == 1 && !shown_is_tunnel(app) && shown_phase(app) == .Disconnected && !conn_locked(app), failed)
	row_connect(app, 1)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up && f.sets == 2}, 5)
	check("service: Connect of another profile stops the first, then sets and connects", ok && f.label == "work 2" && c.profile == 1 && shown_is_tunnel(app), failed)
	check("service: the change of profile does not clear", f.clears == 0, failed)
	link_disconnect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy && f.clears == 1 && !app.link.loaded}, 8)
	check("service: a disconnect by the user clears the profile, after the conflict replies of a closing connection", ok && !f.loaded && f.closing == 0, failed)
	check("service: after disconnect the view has its way back", !conn_locked(app) && c.failure == "", failed)
	row_connect(app, 1)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 5)
	check("service: Connect after a clear sends profile.set again", ok && f.sets == 3 && l.sets_sent == 3 && f.label == "work 2", failed)

	// The owner rule: another user loaded the profile.
	f.other = true
	link_disconnect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.error != ""}, 5)
	check("service: a request under the owner rule says that another user controls the service", ok && l.error == OWNER_TEXT && c.phase == .Up, failed)
	f.other = false
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)

	// Block IPv6: the line goes to profile.set only when the switch is on.
	pop_view(app)
	open_profile(app, 0)
	check("service: Block IPv6 is in the profile view, off", !e.block_ipv6 && click_block6(app) && e.block_ipv6 && e.dirty, failed)
	edit_save(app)
	meta6, _, _ := pf.store_load(app.store, app.profiles[0].id, context.temp_allocator)
	check("service: Save keeps Block IPv6", !e.status_error && meta6.overrides.block_ipv6, failed)
	pop_view(app)
	open_profile(app, 0)
	check("service: the profile view loads Block IPv6", e.block_ipv6 && !e.dirty, failed)
	pop_view(app)
	f.old = true
	open_connection(app, 0)
	row_connect(app, 0)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.error != "" && app.link.pending_step == .None}, 5)
	check("service: a daemon that refuses block-ipv6 says so", ok && strings.has_prefix(l.error, "The service found a problem: Line ") && strings.has_suffix(l.error, ", block-ipv6: not supported; filter IPv6 traffic with the system firewall") && c.phase != .Up && f.sets == 3, failed)
	f.old = false
	row_connect(app, 0)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 5)
	check("service: profile.set has block-ipv6 after the text", ok && f.sets == 4 && strings.has_suffix(f.text, "dns server -128 address 10.0.0.53\nblock-ipv6\n"), failed)
	blocked := false
	for kv in route_lines(c, row_overrides(app, 0)) {
		blocked ||= kv.value == "IPv6: blocked" && kv.own
	}
	check("service: the Routes card shows IPv6: blocked in bold", blocked, failed)
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)
	pop_view(app)
	open_profile(app, 0)
	_ = click_block6(app)
	edit_save(app)
	pop_view(app)
	open_connection(app, 0)
	row_connect(app, 0)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 5)
	check("service: profile.set has no block-ipv6 when the switch is off", ok && f.sets == 5 && !e.block_ipv6 && !strings.contains(f.text, "block-ipv6"), failed)
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)

	details, _ := json.parse_string(`[{"line":3,"option":"up","class":"not_supported","reason":"runs a program"},{"line":5,"option":"cd","class":"path","reason":"names a directory"}]`, allocator = context.temp_allocator)
	check("service: the refusal names the first problem", refusal_text("bad_request", "", details) == "The service found a problem: Line 3, up: runs a program (and 1 more)", failed)
	check("service: a refusal under the owner rule names it", refusal_text("denied", OWNER_DENIED, nil) == OWNER_TEXT, failed)
	check("service: the new reasons have texts, the profile reasons are no failure", reason_text("profile_set") == "" && reason_text("no_profile") == "" && reason_text("inactive") != "" && reason_text("session_timeout") != "" && reason_text("system_error") != "" && reason_text("no_credentials") != "", failed)
	check("service: a long name is cut for the label", len(service_label(strings.repeat("\u00e9", 100, context.temp_allocator))) == 128 && service_label("a\tb") == "ab" && service_label("") == "Profile", failed)

	pop_view(app)
	import_path(app, noted)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.import_wait}, 5)
	check("service: the notes of the check are in the message", app.n_profiles == 3 && strings.contains(app.message, "Note: mlock is not applied"), failed)

	f.service = false
	link_refresh(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.status_busy && !app.link.service}, 5)
	check("service: a daemon with a config file has its own row", app.profiles[0].source == .Daemon && app.profiles[0].server_ip == "192.0.2.7", failed)
	open_connection(app, 2)
	row_connect(app, 2)
	check("service: a stored row says why it cannot connect", l.error == NO_SERVICE_TEXT && current_view(app) == .Connection, failed)
}

// selftest_web checks the web sign-in against a fake daemon with a config
// file: the wait view, the browser (a stub), the link rules and the tray.
selftest_web :: proc(base: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	dir := test_dir("nvweb")
	defer os.remove_all(dir)
	f := new(Fake)
	fake_endpoints(f, dir, "web")
	f.state = "stopped"
	f.connect_ok = true
	f.web_wait = true
	f.web_url = "https://login.example.com/sso?state=abc123"
	if !fake_open(f) {
		check("web: fake daemon opens", false, failed)
		return
	}
	defer fake_close(f)
	app := link_app(base, f.control)
	defer bus_stop(app)
	l := &app.link
	waits :: proc(app: ^App, f: ^Fake) -> bool {
		return app.conn.phase == .Web_Sign_In && app.link.web_url != "" && !app.link.status_busy
	}

	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Up}, 5)
	open_connection(app, 0)
	row_connect(app, 0)
	ok := pump(app, f, waits, 5)
	check("web: the event shows the wait view and status gives the link", ok && l.web && l.web_url == f.web_url, failed)
	check("web: Connect with the window shown starts the browser once", app.browser_calls == 1 && app.browser_last == BROWSER_DEFAULT && l.web_note == WEB_OPENED, failed)
	label, tone := pill_for(shown_phase(app))
	st, _, _ := row_state(app, 0)
	check("web: the state is sign in needed, also in the list and the tray", label == "sign in needed" && tone == .Warn && st == "sign in needed" && tray_state(app).kind == .Sign_In && conn_active(app), failed)
	check("web: the view shows the host and the time left", web_shown_host(l) == "login.example.com" && strings.has_suffix(web_left_text(app), " left") && web_open_label(l) == "Open again", failed)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.status_busy}, 4)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.status_busy}, 4)
	check("web: a new status read does not start the browser again", app.browser_calls == 1, failed)
	web_copy(app)
	got, _ := ui.clipboard_paste()
	check("web: Copy link puts the link on the clipboard", got == f.web_url && l.web_note == WEB_COPIED, failed)
	check("web: Open again starts the browser again", web_open(app) && app.browser_calls == 2, failed)
	app.browser_fail = true
	check("web: a browser that does not start says so", !web_open(app) && l.web_note == WEB_NOT_STARTED && l.web_note_bad, failed)
	app.browser_fail = false
	run := strings.clone(l.run, context.temp_allocator)
	ev, _ := json.parse_string(`{"kind":"web_auth","url":"https://evil.example/x","host":"evil.example","timeout_s":60}`, allocator = context.temp_allocator)
	_ = apply_event(app, "client.auth_needed", run, l.seq + 1, ev)
	check("web: a link in an event is not used", l.web_url == f.web_url, failed)
	_ = pump(app, f, waits, 5)

	link_disconnect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped}, 5)
	check("web: Cancel disconnects and wipes the link", ok && !f.web_active && !l.web && l.web_url == "" && !conn_active(app), failed)

	// The window is hidden: no browser start, the tray says it.
	app.hidden = true
	link_connect(app)
	ok = pump(app, f, waits, 5)
	_, status := tray_texts(app, tray_state(app))
	check("web: hidden, a new sign-in starts no browser and the tray says it", ok && app.browser_calls == 3 && status == "fake: sign in needed", failed)
	app.hidden = false
	build(app, 0)
	check("web: showing the window starts no browser", app.browser_calls == 3 && web_open_label(l) == "Open in browser", failed)
	fake_web_approve(f)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 5)
	check("web: the result comes from client.state", ok && !l.web && l.web_url == "", failed)
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)

	// Links that the GUI does not open.
	f.web_url = "http://login.example.com/sso"
	link_connect(app)
	ok = pump(app, f, waits, 5)
	check("web: an http link is not opened", ok && app.browser_calls == 3 && l.web_note == WEB_BAD_LINK && web_shown_host(l) == "", failed)
	web_copy(app)
	check("web: an http link is not copied", l.web_note == WEB_BAD_LINK, failed)
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)
	f.web_url = "https://login.example.com/sso?state=def456"
	f.web_nourl = true
	link_connect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Web_Sign_In && !app.link.status_busy}, 5)
	check("web: with no link the view shows the host of the event", ok && l.web_url == "" && web_shown_host(l) == "login.example.com" && app.browser_calls == 3, failed)
	check("web: with no link Open says why", !web_open(app) && l.web_note == WEB_NO_LINK, failed)
	f.web_nourl = false
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)

	// The browser setting of a stored profile.
	p0 := app.profiles[0]
	app.profiles[0].source = .Stored
	app.profiles[0].id = "web1"
	metas := app.metas
	m := [1]pf.Meta{{id = "web1", browser = "firefox --private-window"}}
	app.metas = m[:]
	check("web: the browser of the profile is used", row_browser(app, 0) == "firefox --private-window", failed)
	set_text(&l.web_url, "https://login.example.com/x")
	n := app.browser_calls
	check("web: a private window is refused", !web_open(app) && l.web_note == WEB_PRIVATE && app.browser_calls == n, failed)
	m[0].browser = "\"/opt/Edge Beta/msedge\" --profile-directory=Work"
	check("web: a browser with a quoted path", web_open(app) && app.browser_last == "/opt/Edge Beta/msedge --profile-directory=Work", failed)
	wipe_text(&l.web_url)
	app.metas = metas
	app.profiles[0] = p0

	words, private := browser_words("chromium --incognito")
	check("web: --incognito is private", private && len(words) == 2, failed)
	_, private = browser_words("msedge -InPrivate")
	check("web: -InPrivate is private", private, failed)
	_, private = browser_words("/usr/bin/private-browser --new-window")
	check("web: a program name is no flag", !private, failed)
	check("web: the host of a link", web_link_host("https://a.example:8443/x?y#z") == "a.example" && web_link_host("HTTPS://[2001:db8::1]/") == "[2001:db8::1]", failed)
	check("web: links with no host the GUI opens", web_link_host("https://u@a.example/") == "" && web_link_host("javascript:alert(1)") == "" && web_link_host("https://a.example/\"x") == "" && web_link_host("https:///x") == "", failed)
	when ODIN_OS == .Windows {
		b := strings.builder_make(context.temp_allocator)
		win_quote(&b, `C:\a b\`)
		strings.write_byte(&b, ' ')
		win_quote(&b, `say "hi"`)
		check("web: command line quotes", strings.to_string(b) == `"C:\a b\\" "say \"hi\""`, failed)
	}
}

// live_test drives the link against a running client daemon. A daemon with a
// config file is disconnected and connected again (tunnel stays up). A client
// service needs two profile files, kept in a temporary store: connect the first,
// disconnect, connect again, then the second replaces it. The service is left stopped.
live_test :: proc(socket: string, files: []string, lc: Live_Create) -> int {
	_ = sdl.SetHint(sdl.HINT_VIDEO_DRIVER, "offscreen")
	_ = sdl.Init({.VIDEO})
	base := new(App)
	base.window = create_window(nil, true)
	base.renderer = sdl.CreateRenderer(base.window, sdl.SOFTWARE_RENDERER)
	d, sc := window_scales(base.window)
	base.eff = sc
	base.u.input_k = d / sc
	app := link_app(base, socket)
	defer bus_stop(app)
	c := &app.conn
	l := &app.link
	failed := 0
	check :: proc(name: string, ok: bool, failed: ^int) {
		fmt.println(ok ? "PASS" : "FAIL", name)
		if !ok {
			failed^ += 1
		}
	}
	ok := pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.link.state != .Searching && !app.link.status_busy}, 5)
	check("found a client daemon", ok && l.state == .Up, &failed)
	if l.state != .Up {
		_, body, _ := attach_texts(app)
		fmt.println("  ", body)
		return 1
	}
	fmt.printfln("  daemon %q, service %v, phase %v, reason %q, remote %s", l.name, l.service, c.phase, l.reason, c.remote)
	shots, has_shots := os.lookup_env("NOIRVPN_LIVE_SHOTS", context.allocator)
	if l.service {
		if len(files) > 0 || lc.peers == "" {
			live_service(app, files, shots if has_shots else "", &failed, check)
		}
		if lc.peers != "" {
			live_create(app, lc, &failed, check)
		}
		return failed == 0 ? 0 : 1
	}
	if c.phase != .Up {
		start_connection(app, 0)
		ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 30)
		check("connect brings the tunnel up", ok, &failed)
	}
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.address != "" && app.conn.count >= 2}, 10)
	check("details and rate samples", ok, &failed)
	fmt.printfln("  address %s, cipher %s, format %s, transport %s, data path %s, rx %.0f bytes", c.address, c.cipher, c.data_format, conn_transport(app), c.datapath, c.rx_bytes)
	if has_shots {
		live_shots(app, shots, "live")
	}
	link_disconnect(app)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped}, 15)
	check("disconnect stops the tunnel", ok && !conn_active(app), &failed)
	link_connect(app)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 30)
	check("connect again brings it up", ok, &failed)
	return failed == 0 ? 0 : 1
}

// live_shots writes pictures of the connection view and the list, for a look
// by eye.
live_shots :: proc(app: ^App, dir, prefix: string) {
	_ = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.count >= 8}, 15)
	if current_view(app) != .Connection {
		open_connection(app, app.conn.profile)
	}
	settle(app)
	_ = capture(app, fmt.tprintf("%s/%s-up.png", dir, prefix), 1)
	pop_view(app)
	settle(app)
	_ = capture(app, fmt.tprintf("%s/%s-list.png", dir, prefix), 1)
}

// live_service is the live test of a client service (see live_test).
live_service :: proc(app: ^App, files: []string, shots: string, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	c := &app.conn
	l := &app.link
	if len(files) < 2 {
		check("a client service needs two --profile files", false, failed)
		return
	}
	tmp, terr := os.make_directory_temp("", "noirvpn-live-*", context.allocator)
	if terr != nil {
		check("a temporary store", false, failed)
		return
	}
	defer os.remove_all(tmp)
	app.store = pf.store_open(fmt.tprintf("%s/profiles", tmp))
	store_reload(app)
	if l.svc != .Stopped {
		link_disconnect(app)
		_ = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.link.svc == .Stopped && !app.link.status_busy}, 15)
	}

	for file, i in files[:2] {
		import_path(app, file)
		checked := app.import_wait
		ok := pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return !app.import_wait}, 10)
		check(fmt.tprintf("import %s: profile.check accepts it and the store has it", file), checked && ok && !app.message_error && app.n_profiles == i + 1, failed)
		fmt.printfln("  %s", app.message)
	}
	if app.n_profiles < 2 {
		return
	}
	first := strings.clone(app.profiles[0].id)
	second := strings.clone(app.profiles[1].id)

	open_connection(app, 0)
	check("a row opens its view and does not connect", current_view(app) == .Connection && l.sets_sent == 0 && !conn_active(app), failed)
	row_connect(app, 0)
	ok := pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 30)
	check("Connect: profile.set, then connect, brings the tunnel up", ok && l.sets_sent == 1 && l.loaded && l.loaded_sha == app.row_cache[first].sha, failed)
	check("the loaded profile has the label of the row", l.loaded_label == app.profiles[app.conn.profile].name && app.profiles[app.conn.profile].id == first, failed)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.address != "" && app.conn.count >= 2}, 10)
	check("details and rate samples", ok, failed)
	fmt.printfln("  address %s, server %s, cipher %s, format %s, transport %s, data path %s, rx %.0f bytes", c.address, c.peer4, c.cipher, c.data_format, conn_transport(app), c.datapath, c.rx_bytes)
	fmt.printfln("  settings %v: %d routes, dns %v, domains %v, all traffic %v", c.settings_ok, len(c.routes), c.dns_servers[:], c.dns_domains[:], c.redirect)
	check("the tunnel settings of this connection", c.settings_ok, failed)
	meta, _, found := pf.store_load(app.store, first, context.temp_allocator)
	check("up writes the last use and the server address to meta.json", found && meta.last_connected > 0 && meta.server_ip != "", failed)
	fmt.printfln("  meta: %s, server address %s", fmt_last_used(meta.last_connected), meta.server_ip)
	if shots != "" {
		live_shots(app, shots, "live-service")
		open_connection(app, app.conn.profile)
	}

	link_disconnect(app)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 15)
	check("disconnect stops the tunnel", ok && !conn_active(app) && (l.reason == "user_request" || l.reason == "no_profile"), failed)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return !app.link.loaded && !app.link.status_busy}, 15)
	check("a disconnect by the user clears the profile in the service", ok && l.loaded_sha == "", failed)
	row_connect(app, row_of(app, first))
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 30)
	check("Connect again: profile.set, then connect", ok && l.sets_sent == 2 && l.loaded_sha == app.row_cache[first].sha, failed)

	// The list at start while a tunnel runs: the user opens the second row.
	pop_view(app)
	k := row_of(app, second)
	open_connection(app, k)
	check("the second row shows disconnected while the first runs", shown_phase(app) == .Disconnected, failed)
	row_connect(app, k)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up && app.link.pending_step == .None}, 45)
	check("Connect of the second profile: stop, profile.set, connect", ok && l.sets_sent == 3 && app.profiles[app.conn.profile].id == second && l.loaded_sha == app.row_cache[second].sha, failed)
	fmt.printfln("  loaded %q, phase %v", l.loaded_label, c.phase)

	link_disconnect(app)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 15)
	check("disconnect leaves the service stopped", ok, failed)
	ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return !app.link.loaded && !app.link.status_busy}, 15)
	check("and with no profile", ok, failed)
}

// selftest_create_service creates profiles with real keys against the fake
// service: refused check, stored text and form, Save with the same key, New key,
// pin of an imported profile, its MTU and MSS overrides.
selftest_create_service :: proc(base: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	dir := test_dir("nvcreate")
	defer os.remove_all(dir)
	f := new(Fake)
	fake_endpoints(f, dir, "svc")
	f.state = "stopped"
	f.reason = "no_profile"
	f.service = true
	f.connect_ok = true
	if !fake_open(f) {
		check("create service: fake daemon opens", false, failed)
		return
	}
	defer fake_close(f)
	app := link_app(base, f.control)
	defer bus_stop(app)
	app.store = pf.store_open(fmt.tprintf("%s/store", dir))
	store_reload(app)
	ok := pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Up && app.link.service}, 5)
	check("create service: found the service", ok, failed)
	not_pending := proc(app: ^App, f: ^Fake) -> bool {return app.pending.kind == .None}

	create_open(app)
	e := &app.edit
	fu := &e.f
	ui.field_set(&e.name, "Alice laptop")
	ui.field_set(&fu.host, "vpn.example.com")
	ui.field_set(&fu.fingerprint, SAMPLE_FP)
	fu.key_type = .Mldsa65
	list_add(e, .Extra, "up /bin/true")
	create_submit(app)
	check("create service: Create waits for profile.check", app.pending.kind == .Create && e.status == "Checking the profile…", failed)
	ok = pump(app, f, not_pending, 5)
	check("create service: a profile that the service refuses is not stored", ok && current_view(app) == .Create && e.status_error && strings.has_prefix(e.status, "Not created. The service found a problem: Line 4, up") && app.n_profiles == 0, failed)
	list_remove(e, .Extra, 0)
	create_submit(app)
	ok = pump(app, f, not_pending, 5)
	m := &app.made
	check("create service: the checked profile is stored and the key view shows its pin", ok && current_view(app) == .Created && app.n_profiles == 1 && strings.has_prefix(m.pin, "mldsa65-sha256:") && m.peer == "Alice-laptop" && m.key_label == "ML-DSA-65", failed)
	id := strings.clone(m.id)
	// Texts that live across pump() are not in the temp allocator.
	meta, text, found := pf.store_load(app.store, id)
	form, has := meta.form.?
	check("create service: meta.json has the form", found && has && form.key_type == pf.KEY_MLDSA65 && form.fingerprint == SAMPLE_FP && form.port == 1194 && meta.name == "Alice laptop", failed)
	raw, _ := os.read_entire_file(fmt.tprintf("%s/store/%s/meta.json", dir, id), context.temp_allocator)
	check("create service: meta.json holds no key", !strings.contains(string(raw), "BEGIN"), failed)
	check("create service: the text", strings.has_prefix(text, "client\ndev tun\nnobind\nremote vpn.example.com 1194 udp\npeer-fingerprint " + SAMPLE_FP + "\n") && strings.contains(text, "<key>\n-----BEGIN PRIVATE KEY-----"), failed)
	sec := pf.secrets_read(text)
	pin, label, _, pok := cert_pin(sec.cert, context.temp_allocator)
	check("create service: the pin is the pin of the stored certificate", pok && pin == m.pin && label == "ML-DSA-65", failed)
	peers := config.peers_parse(peers_line(app))
	check("create service: the peers file takes the line", config.peers_ok(&peers) && len(peers.entries) == 1 && peers.entries[0].user == "Alice-laptop" && peers.entries[0].pin.kind == .Mldsa65_Sha256, failed)
	config.peers_destroy(&peers)
	key_before := strings.clone(sec.key)

	made_open(app)
	check("create service: the profile view shows the form and the pin", current_view(app) == .Profile && e.created && e.pin == m.pin && fu.key_type == .Mldsa65 && ui.field_text(&fu.fingerprint) == SAMPLE_FP, failed)
	ui.field_set(&fu.mtu, "1380")
	ui.field_set(&fu.mss, "1300")
	transport_set(fu, .Tls)
	e.dirty = true
	edit_save(app)
	ok = pump(app, f, not_pending, 5)
	meta2, text2, _ := pf.store_load(app.store, id)
	sec2 := pf.secrets_read(text2, context.temp_allocator)
	form2, _ := meta2.form.?
	check("create service: Save writes the text again with the same key", ok && !e.status_error && strings.contains(text2, "remote vpn.example.com 443 tls-client\n") && strings.contains(text2, "\ntun-mtu 1380\nmssfix 1300\n") && sec2.key == key_before && sec2.cert == sec.cert && form2.mtu == "1380" && form2.transport == "tls", failed)
	list_add(e, .Extra, "up /bin/true")
	e.dirty = true
	edit_save(app)
	ok = pump(app, f, not_pending, 5)
	_, text3, _ := pf.store_load(app.store, id, context.temp_allocator)
	check("create service: a Save that the service refuses changes nothing", ok && e.status_error && strings.has_prefix(e.status, "Not saved.") && text3 == text2, failed)
	list_remove(e, .Extra, 0)

	old_pin := strings.clone(e.pin)
	key_renew(app)
	_, text4, _ := pf.store_load(app.store, id)
	sec4 := pf.secrets_read(text4)
	check("create service: New key creates another key and pin", current_view(app) == .Created && m.pin != old_pin && e.pin == m.pin && sec4.key != key_before && strings.contains(text4, "\ntun-mtu 1380\n"), failed)
	pop_view(app)
	pop_view(app)

	create_open(app)
	ui.field_set(&fu.host, "192.0.2.10")
	ui.field_set(&fu.fingerprint, SAMPLE_FP)
	transport_set(fu, .Tcp)
	create_submit(app)
	ok = pump(app, f, not_pending, 5)
	check("create service: an Ed25519 key, named after the host", ok && current_view(app) == .Created && strings.has_prefix(m.pin, "sha256:") && m.name == "192.0.2.10" && app.n_profiles == 2, failed)
	pop_view(app)

	// An imported profile with an inline certificate shows its pin, and its
	// MTU and MSS overrides go after the profile text.
	in_file := fmt.tprintf("%s/made.ovpn", dir)
	_ = os.write_entire_file(in_file, text4)
	import_path(app, in_file)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.import_wait}, 5)
	k := -1
	for i in 0 ..< app.n_profiles {
		if app.profiles[i].name == "made" {
			k = i
		}
	}
	check("create service: the import of a created text", ok && k >= 0, failed)
	if k < 0 {
		return
	}
	open_profile(app, k)
	pin5, _, _, _ := cert_pin(sec4.cert)
	check("create service: an imported profile shows the pin of its certificate", !e.created && e.pin == pin5 && e.key_label == "ML-DSA-65", failed)
	ui.field_set(&e.ov_mtu, "40")
	e.dirty = true
	edit_save(app)
	check("create service: a bad MTU override stops the save", e.status_error && e.dirty, failed)
	ui.field_set(&e.ov_mtu, "1400")
	ui.field_set(&e.ov_mss, "0")
	edit_save(app)
	meta5, _, _ := pf.store_load(app.store, e.id, context.temp_allocator)
	check("create service: the MTU and MSS overrides are saved", !e.status_error && meta5.overrides.tun_mtu == "1400" && meta5.overrides.mssfix == "0", failed)

	// The server of an imported profile can be edited.
	orig_host := strings.clone(ui.field_text(&e.srv[0].host))
	check("create service: an imported profile shows its server in an editable row", e.srv_n == 1 && orig_host != "" && !e.srv_custom, failed)
	ui.field_set(&e.srv[0].host, "bad host")
	edit_save(app)
	check("create service: a bad server stops the save", e.status_error, failed)
	ui.field_set(&e.srv[0].host, "new.example.net")
	ui.field_set(&e.srv[0].port, "4443")
	e.srv[0].proto = .Tcp
	e.dirty = true
	edit_save(app)
	meta6, _, _ := pf.store_load(app.store, e.id, context.temp_allocator)
	check("create service: the server override is saved", !e.status_error && e.srv_custom && len(meta6.overrides.servers) == 1 && meta6.overrides.servers[0].host == "new.example.net" && meta6.overrides.servers[0].port == 4443 && meta6.overrides.servers[0].proto == "tcp", failed)
	check("create service: the profile file keeps its server", func_text_has(app, e.id, orig_host), failed)
	k = row_of(app, e.id)
	check("create service: the list shows the new server", app.profiles[k].host == "new.example.net" && app.profiles[k].port == 4443, failed)
	pop_view(app)
	open_connection(app, k)
	row_connect(app, k)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}, 5)
	check("create service: profile.set has the new server", ok && strings.contains(f.text, "\nremote new.example.net 4443 tcp-client\n") && !strings.contains(f.text, "remote 192.0.2.10"), failed)
	check("create service: profile.set has the override lines after the text", ok && strings.has_suffix(f.text, "\ntun-mtu 1400\nmssfix 0\n") && strings.contains(f.text, "\ntun-mtu 1380\n"), failed)
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)
	pop_view(app)
	selftest_key_request(app, f, row_of(app, e.id), sec4.cert, dir, failed, check)
	selftest_files(app, f, text4, dir, failed, check)
}

// selftest_files: the profile file (path, Open, Reload, Reconnect) and secret
// files. The app reads auth-user-pass FILE and askpass FILE and responds to the
// service's wait; a file open to others is not read.
selftest_files :: proc(app: ^App, f: ^Fake, base_text, dir: string, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	not_pending := proc(app: ^App, f: ^Fake) -> bool {return app.pending.kind == .None}
	is_up := proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up}
	e := &app.edit
	// The strings live across pump, which frees the temp allocator.
	real_dir, _ := os.get_absolute_path(dir, context.temp_allocator)
	login := strings.clone(fmt.tprintf("%s/login.txt", real_dir))
	defer delete(login)
	pass_file := strings.clone(fmt.tprintf("%s/key.pass", real_dir))
	defer delete(pass_file)
	_ = os.write_entire_file(login, "carol\nfile pw\n")
	_ = os.chmod(login, {.Read_User, .Write_User})
	in_file := fmt.tprintf("%s/files.ovpn", dir)
	_ = os.write_entire_file(in_file, strings.concatenate({base_text, "auth-user-pass ", login, "\n"}, context.temp_allocator))
	import_path(app, in_file)
	ok := pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.import_wait}, 5)
	k := -1
	for i in 0 ..< app.n_profiles {
		if app.profiles[i].name == "files" {
			k = i
		}
	}
	check("files: the import keeps auth-user-pass FILE", ok && k >= 0 && !app.message_error && func_text_has(app, app.profiles[k].id, strings.concatenate({"\nauth-user-pass ", login, "\n"}, context.temp_allocator)), failed)
	if k < 0 {
		return
	}
	id := strings.clone(app.profiles[k].id)
	defer delete(id)
	open_profile(app, k)
	check("files: the profile view shows the file of the login", e.login_file == login && e.login_problem == "" && !e.askpass, failed)
	check("files: the profile view shows the profile file", strings.has_suffix(e.path, "/profile.ovpn") && strings.contains(e.path, id), failed)
	profile_file_action(app, false)
	check("files: Open profile file opens the file", app.browser_last == strings.concatenate({"open ", e.path}, context.temp_allocator), failed)
	profile_file_action(app, true)
	check("files: Show in folder shows the file", app.browser_last == strings.concatenate({"reveal ", e.path}, context.temp_allocator), failed)
	path := strings.clone(e.path)
	defer delete(path)
	pop_view(app)

	// The login comes from the file.
	f.need_login = true
	open_connection(app, k)
	row_connect(app, k)
	ok = pump(app, f, is_up, 5)
	check("files: the login of the file goes with auth.supply", ok && f.got_user == "carol" && f.got_pass == "file pw", failed)
	link_disconnect(app, clear = false)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)

	// A file open to others is not read: the card asks and says why.
	when ODIN_OS != .Windows {
		l := &app.link
		_ = os.chmod(login, {.Read_User, .Write_User, .Read_Other})
		f.need_login = true
		f.got_user, f.got_pass = "", ""
		link_connect(app)
		ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Credentials && app.link.auto_note != ""}, 5)
		check("files: a login file open to others is not read", ok && f.got_pass == "" && strings.contains(l.auto_note, "chmod 600 ") && strings.contains(l.auto_note, login), failed)
		ui.field_set(&app.conn.user, "carol")
		ui.field_set(&app.conn.pass, "typed pw")
		link_auth_supply(app)
		ok = pump(app, f, is_up, 5)
		check("files: the card still signs in", ok && f.got_pass == "typed pw", failed)
		link_disconnect(app, clear = false)
		_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)
		_ = os.chmod(login, {.Read_User, .Write_User})
	}

	// The user adds askpass FILE with an editor; Reload reads it.
	_ = os.write_entire_file(pass_file, "secret phrase\n")
	_ = os.chmod(pass_file, {.Read_User})
	open_profile(app, row_of(app, id))
	text, _ := os.read_entire_file(path, context.temp_allocator)
	_ = os.write_entire_file(path, strings.concatenate({string(text), "askpass ", pass_file, "\n"}, context.temp_allocator))
	check("files: the view has the old text until Reload", e.pass_file == "" && !e.askpass, failed)
	reload_start(app)
	ok = pump(app, f, not_pending, 5)
	check("files: Reload reads the file and the service checks it", ok && e.pass_file == pass_file && e.pass_problem == "" && e.askpass && !e.reload_error && e.reload_msg == "Reloaded. It will be used the next time you connect." && !e.reconnect, failed)
	pop_view(app)

	// The passphrase, then the login, come from the files.
	f.need_key, f.need_login = true, true
	f.got_user, f.got_pass = "", ""
	k = row_of(app, id)
	row_connect(app, k)
	ok = pump(app, f, is_up, 5)
	check("files: the passphrase of the file goes with auth.supply, then the login", ok && f.got_key == "secret phrase" && f.got_pass == "file pw" && strings.contains(f.text, "\naskpass "), failed)

	// Reload while the tunnel is up: the change waits for Reconnect.
	text, _ = os.read_entire_file(path, context.temp_allocator)
	_ = os.write_entire_file(path, strings.concatenate({string(text), "mute 10\n"}, context.temp_allocator))
	open_profile(app, k)
	reload_start(app)
	ok = pump(app, f, not_pending, 5)
	check("files: Reload of the live profile asks for Reconnect", ok && e.reconnect && e.reload_msg == "Reloaded. Reconnect to apply the changes." && app.conn.phase == .Up && !strings.contains(f.text, "mute 10"), failed)
	sets := f.sets
	reload_reconnect(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up && app.link.pending_step == .None && strings.contains(f.text, "mute 10")}, 5)
	check("files: Reconnect sets the new text and connects", ok && f.sets == sets + 1 && !e.reconnect, failed)

	// Use DCO off: disable-dco goes after the text at the next connect.
	e.use_dco = false
	e.dirty = true
	edit_save(app)
	meta_dco, _, _ := pf.store_load(app.store, id, context.temp_allocator)
	check("dco: Use DCO off is saved", !e.status_error && meta_dco.overrides.no_dco, failed)
	row_connect(app, row_of(app, id))
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up && app.link.pending_step == .None && strings.has_suffix(f.text, "\ndisable-dco\n")}, 5)
	check("dco: profile.set has disable-dco after the text", ok, failed)
	e.use_dco = true
	e.dirty = true
	edit_save(app)
	row_connect(app, row_of(app, id))
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up && app.link.pending_step == .None && !strings.contains(f.text, "disable-dco")}, 5)
	check("dco: Use DCO on sends no disable-dco", ok, failed)
	selftest_dco_switch(app, failed, check)

	// A change that the service refuses: the line is shown.
	text, _ = os.read_entire_file(path, context.temp_allocator)
	_ = os.write_entire_file(path, strings.concatenate({string(text), "up /bin/true\n"}, context.temp_allocator))
	reload_start(app)
	ok = pump(app, f, not_pending, 5)
	check("files: Reload shows the problem of the service with its line", ok && e.reload_error && !e.reconnect && strings.contains(e.reload_msg, "Line 4, up: runs a program"), failed)
	pop_view(app)
	link_disconnect(app)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 5)
	pop_view(app)
}

// selftest_key_request: key request for an imported profile, refuse a
// certificate of another key, set the new key with a self-signed certificate,
// discard a second request.
selftest_key_request :: proc(app: ^App, f: ^Fake, k: int, other_cert, dir: string, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	not_pending := proc(app: ^App, f: ^Fake) -> bool {return app.pending.kind == .None}
	e := &app.edit
	kr := &app.keyreq
	open_profile(app, k)
	key_request_open(app)
	check("key request: opens with no request and the common name of the certificate", current_view(app) == .Key_Request && !kr.has && ui.field_text(&kr.cn) == e.cn && e.cn != "", failed)
	ui.field_set(&kr.cn, " ")
	key_request_make(app)
	check("key request: an empty common name stops Make", !kr.has && kr.tried, failed)
	ui.field_set(&kr.cn, "Bob laptop")
	kr.key_type = 1
	key_request_make(app)
	// Frames free the temp allocator: what lives across a pump is allocated.
	key_file := fmt.aprintf("%s/store/%s/%s", dir, e.id, pf.REQUEST_KEY_FILE)
	req_file := fmt.aprintf("%s/store/%s/%s", dir, e.id, pf.REQUEST_FILE)
	defer delete(key_file)
	defer delete(req_file)
	fi, serr := os.stat(key_file, context.temp_allocator)
	check("key request: Make stores the key (mode 0600) and the request", kr.has && serr == nil && fi.mode & os.Permissions_All == {.Read_User, .Write_User} && strings.has_prefix(kr.req.csr, "-----BEGIN CERTIFICATE REQUEST-----") && strings.has_prefix(kr.req.pin, "sha256:") && kr.req.key_type == pf.KEY_P256 && e.request, failed)
	raw, _ := os.read_entire_file(req_file, context.temp_allocator)
	check("key request: request.json holds no key", !strings.contains(string(raw), "PRIVATE"), failed)
	cert_take(app, transmute([]u8)other_cert)
	check("key request: a certificate of another key shows the mismatch", kr.has_cert && !cert_matches(kr), failed)
	key_set(app)
	check("key request: Set new key refuses it", e.status == REQ_MISMATCH && app.pending.kind == .None, failed)
	cert_read_destroy(&kr.cert)
	kr.has_cert = false
	old_pin := strings.clone(e.pin)
	new_pin := strings.clone(kr.req.pin)
	defer delete(old_pin)
	defer delete(new_pin)
	key_set(app)
	check("key request: Set new key waits for profile.check", app.pending.kind == .Key_Set, failed)
	ok := pump(app, f, not_pending, 5)
	check("key request: the new key is set with a self-signed certificate", ok && kr.done && !e.request && e.pin == new_pin && e.pin != old_pin && e.cn == "Bob laptop" && e.key_label == "ECDSA P-256" && kr.done_line == fmt.tprintf("Bob_laptop %s", new_pin), failed)
	check("key request: the request and its key are deleted", !os.exists(key_file) && !os.exists(req_file), failed)
	_, text, _ := pf.store_load(app.store, e.id, context.temp_allocator)
	sec := pf.secrets_read(text)
	spki, sok := key_spki(sec.key)
	pin, _, _, pok := cert_pin(sec.cert, context.temp_allocator)
	check("key request: the profile holds the new key and its certificate", sok && pok && pin == new_pin && pf.pin_text(false, spki, context.temp_allocator) == new_pin, failed)
	pf.secrets_destroy(&sec)

	// A second request is discarded.
	key_request_open(app)
	key_request_make(app)
	check("key request: a second request", kr.has && os.exists(key_file), failed)
	key_discard(app)
	check("key request: Discard deletes the request and its key", !kr.has && !e.request && !os.exists(key_file), failed)
	pop_view(app)
	pop_view(app)
}

// func_text_has is true when the stored profile text holds `s`.
func_text_has :: proc(app: ^App, id, s: string) -> bool {
	_, text, ok := pf.store_load(app.store, id, context.temp_allocator)
	return ok && strings.contains(text, s)
}

// live_create is the live test of profile creation. Per key type: create a
// profile in a temporary store, add its line to the server's peers file, bring
// the tunnel up and down. The peers file is restored at the end.
live_create :: proc(app: ^App, lc: Live_Create, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	c := &app.conn
	l := &app.link
	if lc.fingerprint == "" {
		check("--peers needs --fingerprint", false, failed)
		return
	}
	original, rerr := os.read_entire_file(lc.peers, context.allocator)
	if rerr != nil {
		check(fmt.tprintf("read the peers file %s", lc.peers), false, failed)
		return
	}
	defer {
		_ = os.write_entire_file(lc.peers, original)
		live_reload(lc)
	}
	tmp, terr := os.make_directory_temp("", "noirvpn-create-*", context.allocator)
	if terr != nil {
		check("a temporary store", false, failed)
		return
	}
	defer os.remove_all(tmp)
	pf.store_close(&app.store)
	app.store = pf.store_open(fmt.tprintf("%s/profiles", tmp))
	store_reload(app)
	if l.svc != .Stopped {
		link_disconnect(app)
		_ = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.link.svc == .Stopped && !app.link.status_busy}, 15)
	}
	not_pending := proc(app: ^App, f: ^Fake) -> bool {return app.pending.kind == .None}
	lines := strings.builder_make()
	strings.write_string(&lines, string(original))
	if len(original) > 0 && original[len(original) - 1] != '\n' {
		strings.write_byte(&lines, '\n')
	}
	for kt in Key_Type {
		create_open(app)
		e := &app.edit
		ui.field_set(&e.name, fmt.tprintf("live %s %d", KEY_NAME[kt], os.get_pid()))
		ui.field_set(&e.f.host, lc.host)
		ui.field_set(&e.f.port, fmt.tprintf("%d", lc.port))
		ui.field_set(&e.f.fingerprint, lc.fingerprint)
		e.f.key_type = kt
		create_submit(app)
		checked := app.pending.kind == .Create
		ok := pump(app, nil, not_pending, 10)
		m := &app.made
		check(fmt.tprintf("%s: Create, profile.check and store", KEY_LABEL[kt]), checked && ok && current_view(app) == .Created && m.id != "", failed)
		if current_view(app) != .Created {
			fmt.printfln("  %s", e.status)
			pop_view(app)
			continue
		}
		fmt.printfln("  pin %s", m.pin)
		id := strings.clone(m.id)
		defer delete(id)
		pop_view(app)
		fmt.sbprintf(&lines, "%s\n", peers_line(app))
		check(fmt.tprintf("%s: the peers file takes the line", KEY_LABEL[kt]), os.write_entire_file(lc.peers, strings.to_string(lines)) == nil, failed)
		live_reload(lc)
		k := row_of(app, id)
		open_connection(app, k)
		row_connect(app, k)
		ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Up && app.conn.address != ""}, 30)
		check(fmt.tprintf("%s: the tunnel comes up with the new key", KEY_LABEL[kt]), ok, failed)
		fmt.printfln("  address %s, server %s, cipher %s, transport %s, data path %s", c.address, c.peer4, c.cipher, conn_transport(app), c.datapath)
		link_disconnect(app)
		ok = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return app.conn.phase == .Stopped && !app.link.status_busy}, 15)
		check(fmt.tprintf("%s: disconnect", KEY_LABEL[kt]), ok, failed)
		_ = pump(app, nil, proc(app: ^App, f: ^Fake) -> bool {return !app.link.loaded && !app.link.status_busy}, 15)
		pop_view(app)
	}
	strings.builder_destroy(&lines)
}

// live_reload runs the --reload command, when there is one.
live_reload :: proc(lc: Live_Create) {
	if lc.reload == "" {
		return
	}
	state, _, stderr, err := os.process_exec({command = {"sh", "-c", lc.reload}}, context.temp_allocator)
	if err != nil || !state.success {
		fmt.printfln("  reload: %v %s", err, string(stderr))
	}
	time.sleep(500 * time.Millisecond)
}

// selftest_dco_switch checks the Use DCO switch with a DCO service and one
// without. Clicks only where the switch is drawn (DCO_UI). Profile view is open.
selftest_dco_switch :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	e := &app.edit
	l := &app.link
	keep_service, keep_mode := l.service, strings.clone(l.datapath_mode, context.temp_allocator)
	defer {
		l.service = keep_service
		set_text(&l.datapath_mode, keep_mode)
		frame(app, 0.016)
	}
	l.service = true
	for want in ([2]bool{true, false}) {
		e.use_dco, e.dirty = want, false
		set_text(&l.datapath_mode, "auto")
		on, enabled := dco_switch(app)
		check(tprint("dco switch: the service has DCO, the switch shows the profile (%v) and is enabled", want), on == want && enabled, failed)
		set_text(&l.datapath_mode, "userspace")
		on, enabled = dco_switch(app)
		check(tprint("dco switch: the service runs without DCO, the switch is off and disabled (profile %v)", want), !on && !enabled && e.use_dco == want, failed)
	}
	when DCO_UI {
		// userspace: a click changes nothing, and the choice of the profile stays
		e.use_dco, e.dirty = true, false
		set_text(&l.datapath_mode, "userspace")
		check("dco switch (userspace): a click does not change the profile", click_dco(app) && e.use_dco && !e.dirty, failed)
		// DCO: a click turns it off
		set_text(&l.datapath_mode, "auto")
		check("dco switch (DCO): a click turns Use DCO off", click_dco(app) && !e.use_dco && e.dirty, failed)
		e.use_dco, e.dirty = true, false
	}
}

// click_dco scrolls the profile view to the Use DCO switch and clicks it.
// It returns false when the view does not draw the switch.
click_dco :: proc(app: ^App) -> bool {
	e := &app.edit
	e.dco_at = {}
	frame(app, 0.016)
	if e.dco_at.w == 0 {
		return false
	}
	scroll_to(app, "profile", scroll_of(app, "profile") + e.dco_at.y - 300)
	frame(app, 0.016)
	r := e.dco_at
	click(app, f32(r.x + r.w / 2), f32(r.y + r.h / 2))
	return true
}

