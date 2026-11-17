// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The link between the views and the service. Two forms:
//   Sim  scripted connection of data.odin (--simulate, --screens, --selftest)
//   Bus  control bus of a noirvpn client daemon (link_bus.odin)
//
// Views read only App.conn and App.link. The UI thread never waits: requests
// go to a worker thread; replies and events return as messages for link_poll.
//
//   link_tick (each loop)  -> searches, status and stats requests when due
//   link_poll (each loop)  -> replies and events -> apply_status, apply_event -> App.conn
//   link_connect, link_disconnect, link_auth_supply  <- the views and the tray

import "core:encoding/json"
import "core:strconv"
import "core:strings"
import "core:time"
import "ui"

Link_Kind :: enum u8 {
	Sim,
	Bus,
}

Link_State :: enum u8 {
	Searching, // the first search has not ended
	Not_Found, // no client daemon responds
	Denied, // the sockets exist, but this user may not use them
	Up, // following a daemon
}

// The daemon states of client.state and status.
Svc_State :: enum u8 {
	Unknown,
	Waiting,
	Connecting,
	Handshake,
	Up,
	Closing,
	Stopped,
}

SEARCH_EVERY :: 2.0 // seconds between searches while no daemon is found
STATUS_EVERY :: 3.0 // seconds between status reads while the window is visible
STATS_EVERY :: 1.0 // seconds between stats reads while the tunnel is up and visible

Link :: struct {
	kind:         Link_Kind,
	state:        Link_State,
	socket:       string, // --socket: the control socket to use, or ""
	name:         string, // instance name of the daemon
	config:       string, // config file of the daemon, or ""
	log_file:     string, // log file of the daemon, or "" for its stderr
	log_journal:  bool, // its stderr goes to the systemd journal
	looked:       string, // the directories searched, for the attach view
	manage:       Manage_State, // the job of the service in the app bundle (service_manage.odin)
	manage_err:   string, // why the app could not register it, or ""
	daemon_cmd:   string, // the daemon program next to this one, for the attach view, or ""
	error:        string, // the last failed request, for the user, or ""
	svc:          Svc_State,
	reason:       string, // reason of the last move to waiting or stopped
	have_auth:    bool, // the daemon waits for credentials
	auth_user:    string,
	auth_reason:  string,
	auth_sent:    bool, // credentials went out; waiting for the next state
	auth_kind:    string, // "credentials" or "key_pass" (the passphrase of the key)
	// The files of the profile (secret_supply.odin).
	auto_done:    bool, // the file was tried for this wait
	auto_force:   bool, // Connect was pressed: try the file even after a refusal
	auto_note:    string, // why the file was not used, for the sign-in card
	// Web sign-in. The event has no link: it comes from status.
	web:          bool, // the wait is a web sign-in
	web_url:      string, // "" while unknown, or when this user may not read it
	web_host:     string,
	web_deadline: f64, // app time when the server stops waiting, 0 for unknown
	web_auto:     bool, // the user pressed Connect with the window shown: the browser may start by itself
	web_done:     u64, // hash of the last link that was acted on, so it is not opened twice
	web_note:     string, // the result of the last action of the wait view, or ""
	web_note_bad: bool,
	web_opened:   bool, // the browser started for this link
	// Service mode: the daemon takes profiles over the bus.
	service:      bool,
	datapath_mode: string, // the data path setting of the service: auto, dco, udco or userspace
	loaded:       bool,
	loaded_label: string,
	loaded_sha:   string,
	pending_id:   string, // the stored profile that goes to the service next
	pending_step: Pending_Step,
	sets_sent:    int, // profile.set requests sent, for the tests
	use_noted:    bool, // the last move to up is in the meta of its row
	// Sequence rule.
	run:          string,
	seq:          u64,
	based:        bool, // run and seq come from a status reply
	status_busy:  bool,
	status_again: bool, // read status again when the current read ends
	stats_busy:   bool,
	next_search:  f64,
	next_status:  f64,
	next_stats:   f64,
	prev_in:      u64,
	prev_out:     u64,
	prev_t:       f64,
	have_prev:    bool,
	impl:         ^Bus_Impl,
}

// OWNER_TEXT is the user text for the owner rule of the service: another
// user loaded the profile.
OWNER_TEXT :: "Another user on this computer is controlling the VPN service."

// ---- Requests from the views ----

link_connect :: proc(app: ^App) {
	switch app.link.kind {
	case .Sim:
		c := &app.conn
		conn_reset(c, c.profile, profile_plan(c.profile), app.now)
	case .Bus:
		app.link.error = ""
		app.link.auth_sent = false
		app.link.web_auto = !app.hidden
		app.link.auto_force = true
		bus_request(app, .Connect)
	}
}

// link_disconnect ends the connection. A user disconnect also clears the
// profile from the service (no keys stay loaded). A profile change does not
// clear: profile.set replaces it.
link_disconnect :: proc(app: ^App, clear := true) {
	switch app.link.kind {
	case .Sim:
		if conn_active(app) {
			app.conn.phase = .Disconnected
		}
	case .Bus:
		app.link.error = ""
		app.link.web_auto = false
		bus_request(app, .Disconnect)
		if clear && app.link.service && app.link.loaded {
			bus_request(app, .Profile_Clear)
		}
	}
}

// link_auth_supply sends the user name and the password, and clears the
// password field.
link_auth_supply :: proc(app: ^App) {
	c := &app.conn
	switch app.link.kind {
	case .Sim:
		c.signed_in = true
		c.phase = .Connecting
		c.phase_start = app.now
	case .Bus:
		app.link.error = ""
		app.link.auth_sent = true
		if app.link.auth_kind == "key_pass" {
			bus_auth_supply_key(app, ui.field_text(&c.pass))
		} else {
			bus_auth_supply(app, ui.field_text(&c.user), ui.field_text(&c.pass))
		}
		c.phase = .Connecting
	}
	ui.field_wipe(&c.pass)
}

// link_retry searches for the daemon at once.
link_retry :: proc(app: ^App) {
	if app.link.kind == .Bus {
		bus_register_again(app)
		app.link.next_search = 0
		link_tick(app)
	}
}

// ---- Timers ----

// link_tick starts the requests that are due. It never waits.
link_tick :: proc(app: ^App) {
	l := &app.link
	if l.kind != .Bus {
		return
	}
	now := app.now
	switch l.state {
	case .Searching, .Not_Found, .Denied:
		if now >= l.next_search && !l.status_busy {
			l.next_search = now + SEARCH_EVERY
			l.status_busy = true
			bus_request(app, .Search)
		}
	case .Up:
		if !app.hidden && now >= l.next_status {
			link_refresh(app)
		}
		if l.svc == .Up && !app.hidden && now >= l.next_stats && !l.stats_busy {
			l.next_stats = now + STATS_EVERY
			l.stats_busy = true
			bus_request(app, .Stats)
		}
	}
}

// link_wake is the next time link_tick has work, or 0.
link_wake :: proc(app: ^App) -> f64 {
	l := &app.link
	if l.kind != .Bus {
		return 0
	}
	switch l.state {
	case .Searching, .Not_Found, .Denied:
		return l.status_busy ? 0 : l.next_search
	case .Up:
		if app.hidden {
			return 0
		}
		if l.svc == .Up {
			return min(l.next_status, l.next_stats)
		}
		return l.next_status
	}
	return 0
}

// link_refresh reads status again. A call during a read queues one more read
// after it, so the last state comes from a reply that started after the call.
link_refresh :: proc(app: ^App) {
	l := &app.link
	l.next_status = app.now + STATUS_EVERY
	if l.status_busy {
		l.status_again = true
		return
	}
	l.status_busy = true
	bus_request(app, .Status)
}

// ---- What the replies and events change ----

svc_state_of :: proc(s: string) -> Svc_State {
	switch s {
	case "waiting":
		return .Waiting
	case "connecting":
		return .Connecting
	case "handshake":
		return .Handshake
	case "up":
		return .Up
	case "closing":
		return .Closing
	case "stopped":
		return .Stopped
	}
	return .Unknown
}

// reason_text is the user text for a reason of client.state and status. A
// reason with no text is no failure.
reason_text :: proc(r: string) -> string {
	switch r {
	case "", "user_request", "exit", "no_profile", "profile_set":
		return ""
	case "no_credentials":
		return "The server needs you to sign in"
	case "inactive":
		return "There was no traffic for too long"
	case "session_timeout":
		return "The session reached its time limit"
	case "system_error":
		return "The system refused a setup step, such as creating the tunnel device"
	case "auth_failed":
		return "The server refused the login"
	case "tls_failed":
		return "The secure connection could not be set up"
	case "ping_timeout":
		return "The server stopped responding"
	case "server_restart":
		return "The server restarted"
	case "server_halt":
		return "The server ended the connection"
	case "network_error":
		return "The server cannot be reached"
	case "push_rejected":
		return "The server sent settings that this app cannot use"
	case "config_error":
		return "There is an error in the profile"
	case "udco_failed", "dco_failed":
		return "The fast data path is not available, so the connection is trying again"
	}
	return r
}

// phase_of maps the daemon state to the phase that the views show.
phase_of :: proc(l: ^Link, attempt: int) -> Phase {
	switch l.svc {
	case .Up:
		return .Up
	case .Handshake:
		if l.have_auth && l.web {
			return .Web_Sign_In
		}
		return l.have_auth && !l.auth_sent ? .Credentials : .Handshake
	case .Connecting:
		return .Connecting
	case .Closing:
		return .Closing
	case .Waiting:
		switch {
		case l.have_auth && !l.auth_sent:
			return .Credentials
		case l.auth_sent:
			return .Connecting
		case attempt > 0 && reason_text(l.reason) != "":
			return .Connecting // a retry after the backoff
		}
		return .Disconnected
	case .Stopped:
		return reason_text(l.reason) == "" ? .Stopped : .Failed
	case .Unknown:
	}
	return .Disconnected
}

// set_phase moves the view model to the phase of the daemon.
set_phase :: proc(app: ^App, attempt: int) {
	c := &app.conn
	l := &app.link
	p := phase_of(l, attempt)
	if p != c.phase {
		if p == .Up {
			conn_clear_series(c)
			l.have_prev = false
			l.next_stats = 0
		}
		c.phase = p
		c.phase_start = app.now
	}
	c.attempt = max(attempt, 1)
	if p != .Up {
		l.use_noted = false
	}
	// The sign-in form says it already.
	set_text(&c.failure, p == .Credentials && l.reason == "no_credentials" ? "" : reason_text(l.reason))
}

// apply_status takes the result of a status reply.
apply_status :: proc(app: ^App, result: json.Value, now: f64) {
	l := &app.link
	c := &app.conn
	b := jobj(result, "bus")
	if l.based && jstr(b, "run") == l.run && u64(jint(b, "seq")) < l.seq {
		// The reply was created before events that are already applied, and its
		// state is older than theirs. Read again for the fields of status only.
		l.status_again = true
		return
	}
	set_text(&l.run, jstr(b, "run"))
	l.seq = u64(jint(b, "seq"))
	l.based = true
	set_text(&l.name, jstr(result, "name"))
	set_text(&l.config, jstr(result, "config"))
	set_text(&l.log_file, jstr(result, "log_file"))
	l.log_journal = jbool(result, "log_journal")
	cl := jobj(result, "client")
	l.svc = svc_state_of(jstr(cl, "state"))
	l.service = jbool(cl, "service")
	set_text(&l.datapath_mode, jstr(cl, "datapath_mode"))
	prof := jobj(cl, "profile")
	l.loaded = prof != nil && jbool(prof, "loaded")
	set_text(&l.loaded_label, jstr(prof, "label"))
	set_text(&l.loaded_sha, jstr(prof, "sha256"))
	switch {
	case l.svc != .Waiting && l.svc != .Stopped:
		set_text(&l.reason, "")
	case jhas(cl, "reason"):
		// A daemon before the service mode has no reason here; the events give it.
		set_text(&l.reason, jstr(cl, "reason"))
	}
	if l.svc == .Stopped || l.svc == .Waiting || l.svc == .Connecting {
		conn_settings_clear(c)
	}
	if st := jobj(cl, "settings"); st != nil {
		// A daemon that has the field; older ones send only the event.
		apply_tunnel_settings(c, st)
	}
	auth := jobj(cl, "auth_needed")
	l.have_auth = auth != nil
	if auth != nil {
		set_text(&l.auth_user, jstr(auth, "username"))
		set_text(&l.auth_reason, jstr(auth, "reason"))
		set_text(&l.auth_kind, jstr(auth, "kind"))
	} else {
		l.auth_sent = false
	}
	if auth != nil && jstr(auth, "kind") == "web_auth" {
		web_take(app, auth, true)
	} else {
		web_forget(l)
	}
	set_text(&c.datapath, jstr(cl, "datapath"))
	if r := jstr(cl, "remote"); r != "" {
		set_text(&c.remote, r)
	}
	if p := jstr(cl, "proto"); p != "" {
		set_text(&c.proto, p)
	}
	set_text(&c.cipher, jstr(cl, "cipher"))
	set_text(&c.data_format, jstr(cl, "data_format"))
	set_text(&c.tun, jstr(cl, "tun"))
	set_address(c, jstr(cl, "vpn4"), jstr(cl, "vpn6"))
	if ts := jstr(cl, "connected_at"); ts != "" {
		if t, consumed := time.rfc3339_to_time_utc(ts); consumed > 0 {
			ago := time.duration_seconds(time.diff(t, time.now()))
			c.up_start = now - max(ago, 0)
		}
	}
	set_phase(app, c.attempt)
	rows_sync(app)
	use_tick(app)
	pending_tick(app)
	web_sync(app)
}

// apply_event takes one event. It returns false when the event is not used.
apply_event :: proc(app: ^App, topic, run: string, seq: u64, data: json.Value) -> bool {
	l := &app.link
	c := &app.conn
	if !l.based {
		return false // a status read is on its way and holds this event
	}
	switch {
	case run != l.run:
		// The daemon started again: everything comes from a new status.
		link_refresh(app)
	case seq <= l.seq:
		return false // the status reply holds it
	case seq > l.seq + 1:
		link_refresh(app)
	}
	l.seq = seq
	switch topic {
	case "client.state":
		l.svc = svc_state_of(jstr(data, "state"))
		set_text(&l.reason, jstr(data, "reason"))
		if r := jstr(data, "remote"); r != "" {
			set_text(&c.remote, r)
		}
		if d := jstr(data, "datapath"); d != "" {
			set_text(&c.datapath, d)
		}
		switch l.svc {
		case .Connecting, .Up, .Stopped, .Closing:
			l.have_auth = false
			l.auth_sent = false
		case .Waiting, .Handshake, .Unknown:
		}
		if l.svc != .Handshake && l.web {
			// The link of an attempt that ended is no good.
			l.have_auth = false
			web_forget(l)
		}
		if l.svc == .Stopped || l.svc == .Waiting || l.svc == .Connecting {
			// The settings of the next connection come before its up.
			conn_settings_clear(c)
		}
		set_phase(app, int(jint(data, "attempt")))
		if l.svc == .Up || l.svc == .Stopped {
			// The address, the start time and the device are in status only.
			link_refresh(app)
		}
		rows_sync(app)
		use_tick(app)
		pending_tick(app)
	case "client.tunnel_settings":
		apply_tunnel_settings(c, data)
	case "client.auth_needed":
		l.have_auth = true
		l.auth_sent = false
		if jstr(data, "kind") == "web_auth" {
			web_take(app, data, false)
			set_phase(app, c.attempt)
			// The link is in status only.
			link_refresh(app)
			break
		}
		web_forget(l)
		set_text(&l.auth_user, jstr(data, "username"))
		set_text(&l.auth_reason, jstr(data, "reason"))
		set_text(&l.auth_kind, jstr(data, "kind"))
		l.auto_done = false // a new wait
		if u := l.auth_user; u != "" && ui.field_text(&c.user) == "" {
			ui.field_set(&c.user, u)
		}
		set_phase(app, c.attempt)
	case "client.profile":
		l.service = true
		l.loaded = jbool(data, "loaded")
		set_text(&l.loaded_label, jstr(data, "label"))
		set_text(&l.loaded_sha, jstr(data, "sha256"))
		rows_sync(app)
	case "daemon.stop":
		l.svc = .Unknown
	}
	return true
}

// apply_tunnel_settings takes the data of client.tunnel_settings.
apply_tunnel_settings :: proc(c: ^Conn, data: json.Value) {
	set_text(&c.cipher, jstr(data, "cipher"))
	set_text(&c.data_format, jstr(data, "data_format"))
	ifc := jobj(data, "ifconfig")
	set_address(c, jstr(ifc, "addr4"), jstr(ifc, "addr6"))
	conn_settings_clear(c)
	set_text(&c.peer4, jstr(ifc, "gateway4"))
	if arr, ok := jarr(data, "routes"); ok {
		for r in arr {
			if net := jstr(r, "net"); net != "" {
				append(&c.routes, Route{strings.clone(net), strings.clone(jstr(r, "gateway"))})
			}
		}
	}
	strs :: proc(data: json.Value, k: string, out: ^[dynamic]string) {
		if arr, ok := jarr(data, k); ok {
			for v in arr {
				if s, is_str := v.(json.String); is_str && s != "" {
					append(out, strings.clone(s))
				}
			}
		}
	}
	strs(data, "dns_servers", &c.dns_servers)
	strs(data, "dns_domains", &c.dns_domains)
	strs(data, "push", &c.pushed)
	c.mtu = int(jint(data, "mtu"))
	c.mss4 = int(jint(data, "mss4"))
	c.mss6 = int(jint(data, "mss6"))
	c.peer_id = jhas(data, "peer_id") ? int(jint(data, "peer_id")) : -1
	c.redirect = jbool(data, "redirect_gateway")
	c.settings_ok = true
}

// apply_stats takes a stats.get result and adds one rate sample.
apply_stats :: proc(app: ^App, result: json.Value, now: f64) {
	l := &app.link
	c := &app.conn
	t := jobj(result, "totals")
	bin, bout := u64(jint(t, "bytes_in")), u64(jint(t, "bytes_out"))
	c.rx_bytes, c.tx_bytes = f64(bin), f64(bout)
	c.rx_packets, c.tx_packets = int(jint(t, "packets_in")), int(jint(t, "packets_out"))
	if d := jstr(result, "datapath"); d != "" {
		set_text(&c.datapath, d)
	}
	if l.have_prev && now > l.prev_t && bin >= l.prev_in && bout >= l.prev_out {
		dt := now - l.prev_t
		conn_sample(c, f32(f64(bin - l.prev_in) * 8 / dt), f32(f64(bout - l.prev_out) * 8 / dt))
	}
	l.prev_in, l.prev_out, l.prev_t, l.have_prev = bin, bout, now, true
}

// link_lost goes back to searching after a failed request.
link_lost :: proc(app: ^App) {
	l := &app.link
	l.state = .Not_Found
	l.based = false
	l.svc = .Unknown
	l.have_auth = false
	web_forget(l)
	l.service = false
	l.loaded = false
	l.pending_step = .None
	set_text(&l.pending_id, "")
	l.next_search = app.now + SEARCH_EVERY
	app.conn.phase = .Disconnected
	attach_enter(app)
}

// ---- Helpers ----

split_host_port :: proc(s: string) -> (host: string, port: int) {
	if s == "" {
		return "", 0
	}
	i := strings.last_index_byte(s, ':')
	if i < 0 {
		return s, 0
	}
	p, _ := strconv.parse_int(s[i + 1:])
	h := s[:i]
	if len(h) >= 2 && h[0] == '[' && h[len(h) - 1] == ']' {
		h = h[1:len(h) - 1]
	}
	return h, p
}

set_address :: proc(c: ^Conn, v4, v6: string) {
	switch {
	case v4 != "" && v6 != "":
		set_text(&c.address, tprint("%s, %s", v4, v6))
	case v4 != "":
		set_text(&c.address, v4)
	case:
		set_text(&c.address, v6)
	}
}

// set_text replaces a heap string held by the view model.
set_text :: proc(dst: ^string, s: string) {
	if dst^ == s {
		return
	}
	if len(dst^) > 0 {
		delete(dst^)
	}
	dst^ = strings.clone(s)
}

jobj :: proc(v: json.Value, k: string) -> json.Value {
	if o, ok := v.(json.Object); ok {
		if x, ok2 := o[k].(json.Object); ok2 {
			return x
		}
	}
	return nil
}

jstr :: proc(v: json.Value, k: string) -> string {
	if o, ok := v.(json.Object); ok {
		if s, ok2 := o[k].(json.String); ok2 {
			return s
		}
	}
	return ""
}

jhas :: proc(v: json.Value, k: string) -> bool {
	if o, ok := v.(json.Object); ok {
		_, has := o[k]
		return has
	}
	return false
}

jbool :: proc(v: json.Value, k: string) -> bool {
	if o, ok := v.(json.Object); ok {
		b, _ := o[k].(json.Boolean)
		return b
	}
	return false
}

jint :: proc(v: json.Value, k: string) -> i64 {
	if o, ok := v.(json.Object); ok {
		#partial switch n in o[k] {
		case json.Integer:
			return n
		case json.Float:
			return i64(n)
		}
	}
	return 0
}
