// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd, windows
package main

// The bus form of the link: two threads beside the UI thread.
//   worker thread   jobs in order: the search, then one bus.call per job
//   events thread   bus.subscribe with wait, then next_event in a loop
// Both post messages to one queue and wake the UI thread with an SDL user
// event; link_poll takes them there. Transport is package bus (Unix sockets,
// Windows named pipes).

import "core:encoding/json"
import "core:mem"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import sdl "vendor:sdl3"
import "noir:bus"

BUS_LINK :: true

CALL_TIMEOUT :: 5 * time.Second
// profile.clear waits for the end of the connection: the service responds
// conflict while the connection still closes.
CLEAR_TRIES :: 25
CLEAR_PAUSE :: 200 * time.Millisecond
SEARCH_TIMEOUT :: 2 * time.Second
EVENT_POLL :: 200 * time.Millisecond
DESKTOP_NAME :: "desktop" // the instance name of the packaged service
OWNER_DENIED :: "another user controls the tunnel" // the message of the owner rule

Job_Kind :: enum u8 {
	Search,
	Status,
	Stats,
	Connect,
	Disconnect,
	Auth_Supply,
	Profile_Set,
	Profile_Check,
	Profile_Clear,
	Acl_Get,
	Acl_Reload,
	Stop,
}

Job :: struct {
	kind: Job_Kind,
	args: []byte, // JSON object or nil; overwritten with zeros after the call
}

Msg_Kind :: enum u8 {
	Found,
	Not_Found,
	Reply,
	Event,
}

Msg :: struct {
	kind:       Msg_Kind,
	job:        Job_Kind,
	err:        bus.Call_Error,
	reply:      bus.Reply,
	event:      bus.Event,
	url:        string, // Found: the control socket
	events_url: string, // Found: the events socket
	denied:     bool, // Not_Found: a socket exists that this user may not use
	looked:     string, // Not_Found: the directories searched
	manage:     Manage_State, // Not_Found: the job of the service in the app bundle
	manage_err: string, // Not_Found: why the registration failed, or ""
	t:          f64, // when the reply arrived
}

Bus_Impl :: struct {
	mu:         sync.Mutex,
	cond:       sync.Cond,
	jobs:       [dynamic]Job,
	msgs:       [dynamic]Msg,
	stop:       bool,
	socket:     string, // --socket, or ""
	url:        string, // worker side: the control socket in use
	worker:     ^thread.Thread,
	events:     ^thread.Thread,
	events_url: string, // UI side: the events socket followed
	ev_stop:    bool, // atomic
	wake:       bool, // push an SDL event for each first message
	// The job of the service in the app bundle (service_manage.odin). The worker
	// registers it once; Retry allows one more try.
	register_tried: bool, // worker side
	register_err:   string, // worker side: why the last try failed, or ""
	register_again: bool, // atomic: Retry was pressed
}

// bus_start creates the threads. socket is the control socket from --socket, or "".
bus_start :: proc(app: ^App, socket: string) {
	b := new(Bus_Impl)
	b.socket = strings.clone(socket)
	b.wake = true
	app.link.impl = b
	set_text(&app.link.daemon_cmd, manage_daemon_path(context.temp_allocator))
	b.worker = thread.create_and_start_with_poly_data(b, worker_main)
}

// bus_stop sends the jobs that wait (a disconnect at quit) and ends the threads.
bus_stop :: proc(app: ^App) {
	b := app.link.impl
	if b == nil {
		return
	}
	job_push(b, {kind = .Stop})
	thread.join(b.worker)
	thread.destroy(b.worker)
	events_stop(b)
	for &m in b.msgs {
		msg_destroy(&m)
	}
	delete(b.msgs)
	delete(b.jobs)
	app.link.impl = nil
}

// bus_request queues a request with no arguments.
bus_request :: proc(app: ^App, kind: Job_Kind) {
	if app.link.impl != nil {
		job_push(app.link.impl, {kind = kind})
	}
}

bus_auth_supply :: proc(app: ^App, user, pass: string) {
	if app.link.impl == nil {
		return
	}
	w: bus.Writer
	bus.writer_init(&w)
	bus.begin_obj(&w)
	if user != "" {
		bus.kv_str(&w, "username", user)
	}
	bus.kv_str(&w, "password", pass)
	bus.end(&w)
	args := slice.clone(bus.writer_bytes(&w))
	mem.zero(raw_data(w.buf), cap(w.buf))
	bus.writer_destroy(&w)
	job_push(app.link.impl, {kind = .Auth_Supply, args = args})
}

// bus_auth_supply_key sends the passphrase of the key of the profile.
bus_auth_supply_key :: proc(app: ^App, pass: string) {
	if app.link.impl == nil {
		return
	}
	w: bus.Writer
	bus.writer_init(&w)
	bus.begin_obj(&w)
	bus.kv_str(&w, "key_pass", pass)
	bus.end(&w)
	args := slice.clone(bus.writer_bytes(&w))
	mem.zero_explicit(raw_data(w.buf), cap(w.buf))
	bus.writer_destroy(&w)
	job_push(app.link.impl, {kind = .Auth_Supply, args = args})
}

// bus_profile_job queues profile.set or profile.check.
bus_profile_job :: proc(app: ^App, kind: Job_Kind, text, label: string, web: bool) {
	if app.link.impl == nil {
		return
	}
	w: bus.Writer
	bus.writer_init(&w)
	bus.begin_obj(&w)
	bus.kv_str(&w, "text", text)
	bus.kv_str(&w, "label", label)
	if web {
		bus.kv_arr(&w, "sso")
		bus.val_str(&w, "webauth")
		bus.end(&w)
	}
	bus.end(&w)
	args := slice.clone(bus.writer_bytes(&w))
	mem.zero(raw_data(w.buf), cap(w.buf))
	bus.writer_destroy(&w)
	job_push(app.link.impl, {kind = kind, args = args})
}

job_push :: proc(b: ^Bus_Impl, j: Job) {
	sync.mutex_lock(&b.mu)
	defer sync.mutex_unlock(&b.mu)
	// A status or stats read that waits already gives the same response.
	if j.kind == .Status || j.kind == .Stats || j.kind == .Search {
		for q in b.jobs {
			if q.kind == j.kind {
				return
			}
		}
	}
	append(&b.jobs, j)
	sync.cond_signal(&b.cond)
}

msg_post :: proc(b: ^Bus_Impl, m: Msg) {
	sync.mutex_lock(&b.mu)
	first := len(b.msgs) == 0
	append(&b.msgs, m)
	sync.mutex_unlock(&b.mu)
	if first && b.wake {
		ev: sdl.Event
		ev.type = .USER
		_ = sdl.PushEvent(&ev)
	}
}

msg_destroy :: proc(m: ^Msg) {
	bus.reply_destroy(&m.reply)
	bus.event_destroy(&m.event)
	delete(m.url)
	delete(m.events_url)
	delete(m.looked)
	delete(m.manage_err)
	m^ = {}
}

op_name :: proc(k: Job_Kind) -> string {
	switch k {
	case .Status:
		return "status"
	case .Stats:
		return "stats.get"
	case .Connect:
		return "connect"
	case .Disconnect:
		return "disconnect"
	case .Auth_Supply:
		return "auth.supply"
	case .Profile_Set:
		return "profile.set"
	case .Profile_Check:
		return "profile.check"
	case .Profile_Clear:
		return "profile.clear"
	case .Acl_Get:
		return "acl.get"
	case .Acl_Reload:
		return "acl.reload"
	case .Search, .Stop:
	}
	return ""
}

worker_main :: proc(b: ^Bus_Impl) {
	for {
		sync.mutex_lock(&b.mu)
		for len(b.jobs) == 0 {
			sync.cond_wait(&b.cond, &b.mu)
		}
		j := b.jobs[0]
		ordered_remove(&b.jobs, 0)
		sync.mutex_unlock(&b.mu)

		switch j.kind {
		case .Stop:
			return
		case .Search:
			search(b)
		case .Status, .Stats, .Connect, .Disconnect, .Auth_Supply, .Profile_Set, .Profile_Check, .Profile_Clear, .Acl_Get, .Acl_Reload:
			m := Msg {
				kind = .Reply,
				job  = j.kind,
			}
			if b.url == "" {
				m.err = .Daemon_Not_Running
			} else {
				m.reply, m.err = bus.call(b.url, op_name(j.kind), j.args, CALL_TIMEOUT)
				for try := 1; j.kind == .Profile_Clear && try < CLEAR_TRIES && m.err == .None && !m.reply.ok && m.reply.code == "conflict"; try += 1 {
					bus.reply_destroy(&m.reply)
					time.sleep(CLEAR_PAUSE)
					m.reply, m.err = bus.call(b.url, op_name(j.kind), j.args, CALL_TIMEOUT)
				}
			}
			mem.zero_slice(j.args)
			delete(j.args)
			m.t = now_seconds()
			msg_post(b, m)
		}
		free_all(context.temp_allocator)
	}
}

// search finds the client daemon to follow: the one of --socket, else the
// desktop service, else the first other client daemon found.
search :: proc(b: ^Bus_Impl) {
	Cand :: struct {
		url, events_url: string,
	}
	cands := make([dynamic]Cand, context.temp_allocator)
	if b.socket != "" {
		path, ok := bus.socket_file_path(b.socket)
		if ok {
			ev := bus.events_for_control(path, context.temp_allocator)
			if ev == "" {
				ev = path
			}
			append(&cands, Cand{bus.socket_url(path, context.temp_allocator), bus.socket_url(ev, context.temp_allocator)})
		}
	} else {
		found := bus.discover(context.temp_allocator)
		for f in found {
			if f.name == DESKTOP_NAME {
				inject_at(&cands, 0, Cand{f.url, f.events_url})
			} else {
				append(&cands, Cand{f.url, f.events_url})
			}
		}
	}
	denied := false
	for c in cands {
		reply, err := bus.call(c.url, "status", nil, SEARCH_TIMEOUT)
		if err == .Permission_Denied || err == .Not_Service {
			denied = true
		}
		if err != .None {
			continue
		}
		if !reply.ok || jstr(reply.result, "mode") != "client" {
			denied ||= reply.code == "denied"
			bus.reply_destroy(&reply)
			continue
		}
		delete(b.url)
		b.url = strings.clone(c.url)
		msg_post(b, {kind = .Found, job = .Status, reply = reply, url = strings.clone(c.url), events_url = strings.clone(c.events_url), t = now_seconds()})
		return
	}
	delete(b.url)
	b.url = ""
	if !denied && b.socket == "" && bus.hidden_dir(context.temp_allocator) != "" {
		denied = true
	}
	looked := b.socket
	if looked == "" {
		looked = strings.join(bus.candidate_dirs(context.temp_allocator), ", ", context.temp_allocator)
	}
	// No service answers: the app can start its own, when it has a job for it.
	manage := Manage_State.Unavailable
	if !denied && b.socket == "" {
		if sync.atomic_exchange(&b.register_again, false) {
			b.register_tried = false
		}
		err: string
		manage, err = manage_ensure(&b.register_tried)
		if err != "" {
			delete(b.register_err)
			b.register_err = err
		}
		if manage != .Not_Registered {
			delete(b.register_err)
			b.register_err = ""
		}
	}
	msg_post(b, {kind = .Not_Found, denied = denied, looked = strings.clone(looked), manage = manage, manage_err = strings.clone(b.register_err)})
}

// bus_register_again lets the next search try to register the job of the service
// again (Retry).
bus_register_again :: proc(app: ^App) {
	if b := app.link.impl; b != nil {
		sync.atomic_store(&b.register_again, true)
	}
}

// ---- Events ----

events_start :: proc(b: ^Bus_Impl, url: string) {
	if b.events != nil && b.events_url == url {
		return
	}
	events_stop(b)
	b.events_url = strings.clone(url)
	sync.atomic_store(&b.ev_stop, false)
	b.events = thread.create_and_start_with_poly_data(b, events_main)
}

events_stop :: proc(b: ^Bus_Impl) {
	if b.events == nil {
		return
	}
	sync.atomic_store(&b.ev_stop, true)
	thread.join(b.events)
	thread.destroy(b.events)
	b.events = nil
	delete(b.events_url)
	b.events_url = ""
}

events_main :: proc(b: ^Bus_Impl) {
	url := strings.clone(b.events_url)
	defer delete(url)
	sub, err := bus.subscribe(url, nil, true)
	if err != .None {
		return
	}
	defer bus.unsubscribe(&sub)
	for !sync.atomic_load(&b.ev_stop) {
		ev, e := bus.next_event(&sub, EVENT_POLL)
		switch e {
		case .None:
			msg_post(b, {kind = .Event, event = ev, t = now_seconds()})
		case .Closed:
			return
		case .Timed_Out, .Bad_Event, .Io:
		}
	}
}

// ---- The UI side ----

// link_poll applies the messages of the threads. It returns true when there
// were any.
link_poll :: proc(app: ^App) -> bool {
	b := app.link.impl
	if app.link.kind != .Bus || b == nil {
		return false
	}
	sync.mutex_lock(&b.mu)
	msgs := b.msgs
	b.msgs = make([dynamic]Msg)
	sync.mutex_unlock(&b.mu)
	defer delete(msgs)
	for &m in msgs {
		apply_msg(app, &m)
		msg_destroy(&m)
	}
	if len(msgs) > 0 {
		secret_tick(app)
	}
	return len(msgs) > 0
}

apply_msg :: proc(app: ^App, m: ^Msg) {
	l := &app.link
	b := l.impl
	switch m.kind {
	case .Found:
		l.status_busy = false
		l.state = .Up
		l.error = ""
		events_start(b, m.events_url)
		apply_status(app, m.reply.result, m.t)
		l.next_status = app.now + STATUS_EVERY
		attach_leave(app)
	case .Not_Found:
		l.status_busy = false
		was_up := l.state == .Up
		if was_up {
			link_lost(app)
		}
		l.state = m.denied ? .Denied : .Not_Found
		set_text(&l.looked, m.looked)
		l.manage = m.manage
		set_text(&l.manage_err, m.manage_err)
		events_stop(b)
		attach_enter(app)
	case .Event:
		_ = apply_event(app, m.event.topic, m.event.run, m.event.seq, m.event.data)
	case .Reply:
		apply_reply(app, m)
	}
}

apply_reply :: proc(app: ^App, m: ^Msg) {
	l := &app.link
	#partial switch m.job {
	case .Status:
		l.status_busy = false
	case .Stats:
		l.stats_busy = false
	case .Acl_Get, .Acl_Reload:
		acl_reply(app, m)
		return
	}
	if m.err != .None && (m.job == .Profile_Set || m.job == .Profile_Check) {
		text := bus.call_error_string(m.err)
		if m.job == .Profile_Set {
			pending_end(app, text)
		} else {
			import_checked(app, false, "", text, nil, nil)
		}
	}
	if m.job == .Profile_Clear {
		// The client.profile event updates the rows. A failure leaves the
		// profile loaded, and the next profile.set replaces it.
		if m.err == .None && m.reply.ok {
			l.loaded = false
			set_text(&l.loaded_sha, "")
			set_text(&l.loaded_label, "")
			rows_sync(app)
		}
		return
	}
	if m.err != .None {
		#partial switch m.err {
		case .Daemon_Not_Running, .Permission_Denied, .Not_Service:
			call_lost(app, m.err)
		case:
			if m.job != .Stats && m.job != .Status {
				set_text(&l.error, bus.call_error_string(m.err))
			}
		}
		return
	}
	r := &m.reply
	if m.job == .Profile_Set || m.job == .Profile_Check {
		if m.job == .Profile_Set {
			profile_set_done(app, r.ok, r.code, r.message, r.result, r.details)
		} else {
			import_checked(app, r.ok, r.code, r.message, r.result, r.details)
		}
		return
	}
	if !r.ok {
		switch {
		case m.job == .Stats:
		case m.job == .Status && r.code == "denied":
			l.state = .Denied
			attach_enter(app)
		case m.job == .Auth_Supply && r.code == "conflict":
			l.auth_sent = false
			link_refresh(app)
		case:
			set_text(&l.error, request_error_text(m.job, r.code, r.message))
		}
		return
	}
	#partial switch m.job {
	case .Status:
		apply_status(app, r.result, m.t)
		if l.status_again {
			l.status_again = false
			link_refresh(app)
		}
	case .Stats:
		apply_stats(app, r.result, m.t)
	case .Connect, .Disconnect:
		// The events say the rest. Read status too, in case the events socket is off.
		link_refresh(app)
	}
}

// call_lost goes back to searching after a call found no service, or one
// that this user may not use.
call_lost :: proc(app: ^App, err: bus.Call_Error) {
	l := &app.link
	if l.state == .Up {
		link_lost(app)
		l.state = err == .Daemon_Not_Running ? .Not_Found : .Denied
		l.status_busy = true
		bus_request(app, .Search)
	}
}

// acl_reply takes the reply of acl.get or acl.reload. Their failures are no
// failure of the connection, so they never set the error of the link.
acl_reply :: proc(app: ^App, m: ^Msg) {
	r := &m.reply
	if m.job == .Acl_Get {
		if m.err == .None {
			acl_got(app, r.ok, r.code, r.result)
		} else {
			app.link.acl.busy = false
		}
	} else if m.err == .None {
		acl_reload_done(app, r.ok, r.code, r.message, r.result, r.details)
	} else {
		acl_reload_done(app, false, "", bus.call_error_string(m.err), nil, nil)
	}
	#partial switch m.err {
	case .Daemon_Not_Running, .Permission_Denied, .Not_Service:
		call_lost(app, m.err)
	}
}

// acl_reload_done takes the reply of acl.reload, then reads the rules again.
acl_reload_done :: proc(app: ^App, ok: bool, code, message: string, result, details: json.Value) {
	a := &app.link.acl
	a.reload_wait = max(a.reload_wait - 1, 0)
	a.reload_error = !ok
	set_text(&a.reload_note, "")
	if ok {
		msg := "Reloaded. Nothing changed."
		if jbool(result, "changed") {
			msg = tprint("Reloaded. %s, %s.", count_text(int(jint(result, "rules")), "rule", "rules", "No rules"), count_text(int(jint(result, "forwards")), "forward", "forwards", "no forwards"))
		}
		if closed := int(jint(result, "closed")); closed > 0 {
			msg = tprint("%s %s closed.", msg, count_text(closed, "forwarded connection was", "forwarded connections were", ""))
		}
		set_text(&a.reload_msg, msg)
		note := ""
		if jbool(result, "pending") {
			note = ACL_PENDING_TEXT
		}
		if arr, has := jarr(result, "ignored"); has && len(arr) > 0 {
			restart := tprint("Restart the service to apply %s.", acl_join(arr))
			note = note == "" ? restart : tprint("%s %s", note, restart)
		}
		set_text(&a.reload_note, note)
	} else {
		text: string
		switch code {
		case "bad_request":
			text = refusal_text(code, message, details)
			if arr, listed := details.(json.Array); listed && len(arr) > 0 {
				text = tprint("Nothing changed. %s", text)
			} else {
				text = sentence(text)
			}
		case "unknown_op", "unsupported":
			text = "This service cannot reload its rules."
		case "denied", "busy", "timeout":
			text = request_error_text(.Acl_Reload, code, message)
		case:
			text = sentence(message if message != "" else code)
		}
		set_text(&a.reload_msg, text)
	}
	acl_read(app)
}

request_error_text :: proc(job: Job_Kind, code, message: string) -> string {
	switch code {
	case "denied":
		if message == OWNER_DENIED {
			return OWNER_TEXT
		}
		return "You do not have permission to control this connection."
	case "busy":
		return "The service is busy right now. Try again in a moment."
	case "timeout":
		return "The service did not respond in time."
	}
	return message if message != "" else code
}
