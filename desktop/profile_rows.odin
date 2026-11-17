// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The rows of the profile list and what the user does with stored profiles.
//
//   rows_sync        the rows: the daemon of a config file (if any), then the store
//   row_connect      Connect of the connection view; for a stored profile:
//                    disconnect if another runs, profile.set, connect
//   use_tick         the tunnel is up: the time and the server address go to meta.json
//   import_path      import_file -> profile.check (when the service has it) -> store
//   file dialogs     SDL calls back on any thread; dialog_poll takes the result

import "base:runtime"
import "core:crypto/sha2"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:sync"
import "core:time"
import "core:unicode/utf8"
import sdl "vendor:sdl3"
import pf "profiles"
import "ui"

Pending_Step :: enum u8 {
	None,
	Stop, // waits for the service to stop the other profile
	Set, // profile.set is on its way
}

// text_sha is the hex SHA-256 of the text, as `status` reports the profile.
text_sha :: proc(text: string, allocator := context.allocator) -> string {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, transmute([]byte)text)
	sum: [sha2.DIGEST_SIZE_256]byte
	sha2.final(&ctx, sum[:])
	return string(hex.encode(sum[:], allocator))
}

// set_message shows a line in the bar of the list.
set_message :: proc(app: ^App, text: string, error := false) {
	set_text(&app.message, text)
	app.message_error = error
	app.pending_delete = -1
}

// store_reload reads the store again and rebuilds the rows.
store_reload :: proc(app: ^App) {
	if app.link.kind == .Sim {
		return
	}
	pf.metas_destroy(app.metas)
	app.metas = pf.store_list(app.store)
	for &m in app.metas {
		meta, text, ok := pf.store_load(app.store, m.id, context.temp_allocator)
		_ = meta
		sha := ""
		host, proto := "", ""
		port := 0
		if ok {
			composed := pf.compose(text, m.overrides, context.temp_allocator)
			sha = text_sha(composed, context.temp_allocator)
			if s, _ := pf.summarize(composed, context.temp_allocator); len(s.remotes) > 0 {
				host, port, proto = s.remotes[0].host, s.remotes[0].port, s.remotes[0].proto
			}
		}
		cache := Row_Cache{sha = strings.clone(sha), host = strings.clone(host), port = port, proto = strings.clone(proto)}
		if old, has := app.row_cache[m.id]; has {
			delete(old.sha)
			delete(old.host)
			delete(old.proto)
		} else {
			app.row_cache[strings.clone(m.id)] = {}
		}
		app.row_cache[m.id] = cache
	}
	rows_sync(app)
}

Row_Cache :: struct {
	sha:   string,
	host:  string,
	port:  int,
	proto: string,
}

// rows_sync builds the rows of the list from the daemon and the store, and
// points conn.profile at the row of the tunnel.
rows_sync :: proc(app: ^App) {
	if app.link.kind != .Bus {
		return
	}
	l := &app.link
	n := 0
	active := -1
	if l.state == .Up && !l.service {
		p := &app.profiles[0]
		p.source = .Daemon
		set_text(&p.id, "")
		set_text(&p.name, l.name if l.name != "" else "noirvpn")
		host, port := split_host_port(app.conn.remote)
		set_text(&p.host, host)
		p.port = port
		set_text(&p.proto, app.conn.proto)
		set_text(&p.server_ip, host)
		p.last_used = 0
		active = 0
		n = 1
	}
	for m in app.metas {
		if n >= MAX_PROFILES {
			break
		}
		p := &app.profiles[n]
		rc := app.row_cache[m.id]
		p.source = .Stored
		set_text(&p.id, m.id)
		set_text(&p.name, m.name)
		set_text(&p.host, rc.host)
		p.port = rc.port
		set_text(&p.proto, rc.proto)
		set_text(&p.server_ip, m.server_ip)
		p.last_used = m.last_connected
		p.login = m.web_sign_in ? .Web : .None
		switch {
		case l.pending_id != "":
			if m.id == l.pending_id {
				active = n
			}
		case l.service && l.loaded && rc.sha == l.loaded_sha:
			active = n
		}
		n += 1
	}
	app.n_profiles = n
	if active < 0 {
		active = MAX_PROFILES // the empty row: the service has no profile of ours
		app.profiles[active] = {}
		set_text(&app.profiles[active].name, l.loaded_label)
	}
	app.conn.profile = active
	if app.pending_delete >= n {
		app.pending_delete = -1
	}
	if app.shown_id != "" {
		if k := row_of(app, app.shown_id); k >= 0 {
			app.shown = k
		}
	}
}

// use_tick writes the time and the server address of a tunnel that came up
// to the meta of its row, once for each move to up.
use_tick :: proc(app: ^App) {
	l := &app.link
	c := &app.conn
	if l.use_noted || c.phase != .Up || c.profile < 0 || c.profile >= app.n_profiles {
		return
	}
	p := &app.profiles[c.profile]
	if p.source != .Stored {
		return
	}
	l.use_noted = true
	ip, _ := split_host_port(c.remote)
	now := time.time_to_unix(time.now())
	_ = pf.store_note_use(app.store, p.id, now, ip)
	for &m in app.metas {
		if m.id == p.id {
			m.last_connected = now
			if ip != "" {
				delete(m.server_ip)
				m.server_ip = strings.clone(ip)
			}
		}
	}
	rows_sync(app)
}

// row_of returns the row of a stored profile, or -1.
row_of :: proc(app: ^App, id: string) -> int {
	for i in 0 ..< app.n_profiles {
		if app.profiles[i].source == .Stored && app.profiles[i].id == id {
			return i
		}
	}
	return -1
}

// row_connect connects row i: the Connect button of the connection view.
row_connect :: proc(app: ^App, i: int) {
	p := &app.profiles[i]
	l := &app.link
	if app.link.kind == .Sim {
		c := &app.conn
		conn_reset(c, i, profile_plan(i), app.now)
		ui.field_set(&c.user, "alice")
		ui.field_wipe(&c.pass)
		return
	}
	if p.source != .Stored {
		link_connect(app)
		return
	}
	switch {
	case l.state != .Up:
		set_text(&l.error, "The noirvpn service is not running.")
		return
	case !l.service:
		set_text(&l.error, NO_SERVICE_TEXT)
		return
	case l.pending_step != .None:
		return
	}
	cache := app.row_cache[p.id]
	same := l.loaded && cache.sha != "" && cache.sha == l.loaded_sha
	app.conn.profile = i
	if same {
		if !conn_active(app) && app.conn.phase != .Closing {
			link_connect(app)
		}
		return
	}
	l.error = ""
	set_text(&l.pending_id, p.id)
	rows_sync(app)
	if l.svc == .Stopped {
		profile_set_send(app)
	} else {
		l.pending_step = .Stop
		link_disconnect(app, clear = false)
	}
}

NO_SERVICE_TEXT :: "This service only runs the profile from its own config file. To use stored profiles, you need the noirvpn desktop service."

// pending_tick moves the change of profile on when the service has stopped.
pending_tick :: proc(app: ^App) {
	l := &app.link
	if l.pending_step == .Stop && l.svc == .Stopped {
		profile_set_send(app)
	}
}

profile_set_send :: proc(app: ^App) {
	l := &app.link
	meta, text, ok := pf.store_load(app.store, l.pending_id, context.temp_allocator)
	if !ok {
		pending_end(app, "The profile could not be read.")
		return
	}
	l.pending_step = .Set
	l.sets_sent += 1
	bus_profile_job(app, .Profile_Set, pf.compose(text, meta.overrides, context.temp_allocator), service_label(meta.name), meta.web_sign_in)
}

// service_label is a name as the service takes it: 1 to 128 bytes of UTF-8
// with no control characters.
service_label :: proc(name: string) -> string {
	b := strings.builder_make(context.temp_allocator)
	for r in name {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			continue
		}
		if strings.builder_len(b) + utf8.rune_size(r) > 128 {
			break
		}
		strings.write_rune(&b, r)
	}
	if strings.builder_len(b) == 0 {
		return "Profile"
	}
	return strings.to_string(b)
}

// pending_end stops the change of profile, with an error text or "".
pending_end :: proc(app: ^App, error: string) {
	l := &app.link
	l.pending_step = .None
	set_text(&l.pending_id, "")
	if error != "" {
		set_text(&l.error, error)
	}
	rows_sync(app)
}

// profile_set_done takes the reply of profile.set. The result names the
// profile that is loaded now, so the row is known before the event comes.
profile_set_done :: proc(app: ^App, ok: bool, code, message: string, result, details: json.Value) {
	l := &app.link
	if !ok {
		pending_end(app, refusal_text(code, message, details))
		return
	}
	l.loaded = true
	set_text(&l.loaded_sha, jstr(result, "sha256"))
	set_text(&l.loaded_label, jstr(result, "label"))
	pending_end(app, "")
	link_connect(app)
}

// refusal_text is one line for a refused profile: the first problem and how
// many more there are.
refusal_text :: proc(code, message: string, details: json.Value) -> string {
	if arr, ok := details.(json.Array); ok && len(arr) > 0 {
		first := arr[0]
		line := jint(first, "line")
		text := tprint("Line %d, %s: %s", line, jstr(first, "option"), jstr(first, "reason"))
		if len(arr) > 1 {
			text = tprint("%s (and %d more)", text, len(arr) - 1)
		}
		return tprint("The service found a problem: %s", text)
	}
	switch code {
	case "unknown_op", "unsupported":
		return NO_SERVICE_TEXT
	case "conflict":
		return "The service is busy with another connection. Try again in a moment."
	case "denied":
		return OWNER_TEXT
	}
	return message if message != "" else code
}

// ---- Import ----

// import_path reads an .ovpn file, puts its keys inline, and checks it with
// the service when the service can.
import_path :: proc(app: ^App, path: string) {
	r := pf.import_file(path)
	if !r.ok {
		msg := "The file could not be imported."
		for p in r.problems {
			if p.fatal {
				msg = p.line > 0 ? tprint("Line %d: %s", p.line, p.message) : p.message
				break
			}
		}
		set_message(app, msg, true)
		pf.import_destroy(&r)
		return
	}
	if app.link.kind == .Bus && app.link.state == .Up && app.link.service {
		import_drop(app)
		app.importing = r
		app.import_wait = true
		set_message(app, "Checking the profile…")
		bus_profile_job(app, .Profile_Check, r.text, service_label(r.name if r.name != "" else "Imported profile"), false)
		return
	}
	app.importing = r
	import_finish(app, "The service did not check it.", 0)
}

import_drop :: proc(app: ^App) {
	if app.import_wait || app.importing.text != "" || len(app.importing.problems) > 0 {
		pf.import_destroy(&app.importing)
	}
	app.importing = {}
	app.import_wait = false
}

// import_checked takes the reply of profile.check.
import_checked :: proc(app: ^App, ok: bool, code, message: string, result, details: json.Value) {
	if app.pending.kind != .None {
		form_checked(app, ok, code, message, result, details)
		return
	}
	if !app.import_wait {
		return
	}
	app.import_wait = false
	if ok {
		ignored := 0
		if arr, is_arr := jarr(result, "options"); is_arr {
			for o in arr {
				if jstr(o, "disposition") == "ignored" {
					ignored += 1
				}
			}
		}
		note := ""
		if arr, is_arr := jarr(result, "notes"); is_arr && len(arr) > 0 {
			if s, is_str := arr[0].(json.String); is_str {
				note = len(arr) > 1 ? tprint("Note: %s (and %d more)", s, len(arr) - 1) : tprint("Note: %s", s)
			}
		}
		import_finish(app, note, ignored)
		return
	}
	if code == "unknown_op" || code == "unsupported" {
		import_finish(app, "The service did not check it.", 0)
		return
	}
	set_message(app, tprint("The profile was not imported. %s", refusal_text(code, message, details)), true)
	import_drop(app)
}

// import_finish stores the profile and says so.
import_finish :: proc(app: ^App, note: string, ignored: int) {
	r := &app.importing
	name := strings.clone(unique_name(app, r.name if r.name != "" else "Imported profile"), context.temp_allocator)
	_, ok := pf.store_create(app.store, name, r.text, context.temp_allocator)
	import_drop(app)
	if !ok {
		set_message(app, "The profile could not be saved.", true)
		return
	}
	store_reload(app)
	text := tprint("Imported “%s”.", name)
	switch {
	case ignored == 1:
		text = tprint("%s 1 option has no effect.", text)
	case ignored > 1:
		text = tprint("%s %d options have no effect.", text, ignored)
	}
	if note != "" {
		text = tprint("%s %s", text, note)
	}
	set_message(app, text)
}

// unique_name adds a number to a name that a row has already.
unique_name :: proc(app: ^App, name: string) -> string {
	taken :: proc(app: ^App, s: string) -> bool {
		for m in app.metas {
			if strings.equal_fold(m.name, s) {
				return true
			}
		}
		return false
	}
	if !taken(app, name) {
		return name
	}
	for k in 2 ..< 1000 {
		s := tprint("%s %d", name, k)
		if !taken(app, s) {
			return s
		}
	}
	return name
}

// ---- Row actions ----

row_duplicate :: proc(app: ^App, i: int) {
	p := &app.profiles[i]
	if app.link.kind == .Sim {
		duplicate_profile(app, i)
		return
	}
	if _, ok := pf.store_duplicate(app.store, p.id, unique_name(app, tprint("%s copy", p.name)), context.temp_allocator); !ok {
		set_message(app, "The profile could not be copied.", true)
		return
	}
	store_reload(app)
}

row_delete :: proc(app: ^App, i: int) {
	if app.link.kind == .Sim {
		delete_profile(app, i)
		return
	}
	p := &app.profiles[i]
	if i == app.conn.profile && conn_active(app) {
		set_message(app, "Disconnect this profile before you delete it.", true)
		return
	}
	if !pf.store_delete(app.store, p.id) {
		set_message(app, "The profile could not be deleted.", true)
	}
	store_reload(app)
}

// ---- File dialogs ----

Dialog_Kind :: enum u8 {
	None,
	Import,
	Export,
	Save_Request, // view_key.odin
	Open_Cert,
}

// Dialog holds the result of a file dialog until the UI thread takes it.
Dialog :: struct {
	mu:     sync.Mutex,
	kind:   Dialog_Kind, // the dialog that is open
	id:     string, // Export: the profile
	done:   bool,
	path:   string, // "" when cancelled
	failed: bool,
}

dialog_cb :: proc "c" (userdata: rawptr, filelist: [^]cstring, filter: i32) {
	context = runtime.default_context()
	d := (^Dialog)(userdata)
	sync.mutex_lock(&d.mu)
	switch {
	case filelist == nil:
		d.failed = true
	case filelist[0] != nil:
		d.path = strings.clone(string(filelist[0]))
	}
	d.done = true
	sync.mutex_unlock(&d.mu)
	ev: sdl.Event
	ev.type = .USER
	_ = sdl.PushEvent(&ev)
}

ovpn_filters := [2]sdl.DialogFileFilter{{"OpenVPN profiles", "ovpn;conf"}, {"All files", "*"}}
csr_filters := [1]sdl.DialogFileFilter{{"Certificate requests", "csr"}}
cert_filters := [2]sdl.DialogFileFilter{{"Certificates", "pem;crt;cer;der"}, {"All files", "*"}}

sdl_save_dialog :: proc(app: ^App, filters: []sdl.DialogFileFilter, name: string) {
	sdl.ShowSaveFileDialog(dialog_cb, &app.dialog, app.window, raw_data(filters), i32(len(filters)), fmt.ctprintf("%s", name))
}

sdl_open_dialog :: proc(app: ^App, filters: []sdl.DialogFileFilter) {
	sdl.ShowOpenFileDialog(dialog_cb, &app.dialog, app.window, raw_data(filters), i32(len(filters)), nil, false)
}

import_start :: proc(app: ^App) {
	d := &app.dialog
	if d.kind != .None || app.headless {
		return
	}
	d.kind = .Import
	sdl.ShowOpenFileDialog(dialog_cb, d, app.window, raw_data(ovpn_filters[:]), len(ovpn_filters), nil, false)
}

export_start :: proc(app: ^App, i: int) {
	d := &app.dialog
	if d.kind != .None || app.headless {
		return
	}
	d.kind = .Export
	set_text(&d.id, app.profiles[i].id)
	name := fmt.ctprintf("%s.ovpn", app.profiles[i].name)
	sdl.ShowSaveFileDialog(dialog_cb, d, app.window, raw_data(ovpn_filters[:1]), 1, name)
}

// dialog_poll acts on a dialog that has closed. It returns true when one did.
dialog_poll :: proc(app: ^App) -> bool {
	d := &app.dialog
	sync.mutex_lock(&d.mu)
	done, path, failed, kind := d.done, d.path, d.failed, d.kind
	if done {
		d.done, d.path, d.failed, d.kind = false, "", false, .None
	}
	sync.mutex_unlock(&d.mu)
	if !done {
		return false
	}
	defer delete(path)
	switch {
	case failed:
		set_message(app, "The file dialog is not available on this system.", true)
	case path == "":
	case kind == .Import:
		import_path(app, path)
	case kind == .Save_Request:
		p := path
		if !strings.has_suffix(p, ".csr") {
			p = tprint("%s.csr", p)
		}
		key_request_save_to(app, p)
	case kind == .Open_Cert:
		key_request_file(app, path)
	case kind == .Export:
		p := path
		if !strings.has_suffix(p, ".ovpn") {
			p = tprint("%s.ovpn", p)
		}
		if pf.store_export(app.store, d.id, p) {
			set_message(app, tprint("Exported to %s. The file contains the private key, so keep it safe.", p))
		} else {
			set_message(app, "The profile could not be saved in that location.", true)
		}
	}
	return true
}

jarr :: proc(v: json.Value, k: string) -> (json.Array, bool) {
	if o, ok := v.(json.Object); ok {
		a, is_arr := o[k].(json.Array)
		return a, is_arr
	}
	return nil, false
}
