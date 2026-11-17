// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Profiles the GUI creates: the Create view, the key view after Create, and the
// form groups of such a profile in the profile view. Key from keygen.odin; text
// and checks from profiles/create.odin.
//
//   create_open     New profile of the plus menu
//   create_submit   Create: check form, create key, write text,
//                   profile.check (service mode), store, show the pin
//   edit_save       (view_profile.odin) Save of a created profile rewrites the
//                   text from the form, same key
//   key_renew       New key of the profile view
//   form_checked    reply of profile.check for Create and Save

import "core:encoding/json"
import "core:math"
import "core:mem"
import "core:slice"
import "core:strconv"
import "core:strings"
import mu "vendor:microui"
import pf "profiles"
import "ui"

Transport :: enum u8 {
	Udp,
	Tcp,
	Tls,
}

Key_Type :: enum u8 {
	Ed25519,
	Mldsa65,
}

Pq_Choice :: enum u8 {
	Off,
	Prefer,
	Require,
}

TRANSPORT_NAME := [Transport]string {
	.Udp = "udp",
	.Tcp = "tcp",
	.Tls = "tls",
}
TRANSPORT_LABEL := [Transport]string {
	.Udp = "UDP",
	.Tcp = "TCP",
	.Tls = "TLS",
}
KEY_NAME := [Key_Type]string {
	.Ed25519 = pf.KEY_ED25519,
	.Mldsa65 = pf.KEY_MLDSA65,
}
KEY_LABEL := [Key_Type]string {
	.Ed25519 = "Ed25519",
	.Mldsa65 = "ML-DSA-65",
}
PQ_NAME := [Pq_Choice]string {
	.Off     = "off",
	.Prefer  = "",
	.Require = "require",
}
PQ_LABEL := [Pq_Choice]string {
	.Off     = "Off",
	.Prefer  = "Prefer",
	.Require = "Require",
}

// The pin and the fingerprint of the simulation and the pictures.
SAMPLE_PIN :: "sha256:EEdckfvr1RFzY9Di1QZKLSTburVA1g5a1196kqf4Ggw="
SAMPLE_FP :: "28:61:7C:C6:BA:52:47:69:EA:9B:5A:7E:4C:C3:96:08:E7:D9:5F:FA:1F:40:69:F3:27:DF:70:D0:B9:FA:2A:F2"

// The fields of the form. The pasted CA and tls-crypt key are never drawn.
Form_Ui :: struct {
	host:        ui.Field,
	port:        ui.Field,
	fingerprint: ui.Field,
	mtu:         ui.Field,
	mss:         ui.Field,
	ciphers:     ui.Field,
	sni:         ui.Field,
	transport:   Transport,
	key_type:    Key_Type,
	pq:          Pq_Choice,
	user_pass:   bool,
	port_edited: bool, // else the port follows the transport
	ca:          string,
	tls_crypt:   string,
	advanced:    bool,
	tried:       bool, // Create or Save was pressed: empty fields show their errors
}

Form_Check :: enum u8 {
	None,
	Create,
	Save,
	Key_Set, // the new key of a key request (view_key.odin)
	Reload, // the profile file was read again (view_profile.odin)
}

// A text on its way to profile.check. The text holds the key: it is wiped.
Form_Pending :: struct {
	kind:      Form_Check,
	text:      string,
	name:      string,
	pin:       string,
	key_label: string,
	form:      pf.Form,
}

// The profile of the key view.
Made :: struct {
	id:        string,
	name:      string,
	pin:       string,
	key_label: string,
	peer:      string, // the common name of the certificate
	row:       int, // the row of the simulation
	status:    string,
	copy_at:   mu.Rect, // the Copy button of the key pin, set by the view for the tests
}

form_ui_init :: proc(f: ^Form_Ui) {
	for fl in form_fields(f) {
		ui.field_init(fl)
	}
}

@(private = "file")
form_fields :: proc(f: ^Form_Ui) -> [7]^ui.Field {
	return {&f.host, &f.port, &f.fingerprint, &f.mtu, &f.mss, &f.ciphers, &f.sni}
}

// form_ui_reset gives the defaults of a new profile and wipes the pasted keys.
form_ui_reset :: proc(f: ^Form_Ui) {
	for fl in form_fields(f) {
		ui.field_set(fl, "")
	}
	ui.field_set(&f.port, "1194")
	pf.wipe_string(f.ca)
	pf.wipe_string(f.tls_crypt)
	f.ca, f.tls_crypt = "", ""
	f.transport, f.key_type, f.pq = .Udp, .Ed25519, .Prefer
	f.user_pass, f.port_edited, f.advanced, f.tried = false, false, false, false
}

form_ui_load :: proc(e: ^Edit, form: pf.Form, s: pf.Secrets) {
	f := &e.f
	form_ui_reset(f)
	ui.field_set(&f.host, form.host)
	ui.field_set(&f.port, tprint("%d", form.port))
	ui.field_set(&f.fingerprint, form.fingerprint)
	ui.field_set(&f.mtu, form.mtu)
	ui.field_set(&f.mss, form.mss)
	ui.field_set(&f.ciphers, form.ciphers)
	ui.field_set(&f.sni, form.sni)
	for t in Transport {
		if TRANSPORT_NAME[t] == form.transport {
			f.transport = t
		}
	}
	f.key_type = form.key_type == pf.KEY_MLDSA65 ? .Mldsa65 : .Ed25519
	for q in Pq_Choice {
		if PQ_NAME[q] == form.pq_mode {
			f.pq = q
		}
	}
	f.user_pass = form.user_pass
	f.port_edited = form.port != pf.transport_default_port(form.transport)
	f.ca = strings.clone(s.ca)
	f.tls_crypt = strings.clone(s.tls_crypt)
	for l in form.extra {
		list_add(e, .Extra, l)
	}
	f.advanced = s.ca != "" || s.tls_crypt != "" || form.user_pass || form.pq_mode != "" || form.ciphers != "" || form.sni != "" || len(form.extra) > 0
}

// form_of is the form of the fields, in the temp allocator.
form_of :: proc(e: ^Edit) -> pf.Form {
	f := &e.f
	t := TRANSPORT_NAME[f.transport]
	port, ok := strconv.parse_int(strings.trim_space(ui.field_text(&f.port)), 10)
	if !ok {
		port = 0
	}
	form := pf.Form {
		host        = strings.trim_space(ui.field_text(&f.host)),
		port        = port,
		transport   = t,
		fingerprint = strings.trim_space(ui.field_text(&f.fingerprint)),
		key_type    = KEY_NAME[f.key_type],
		mtu         = strings.trim_space(ui.field_text(&f.mtu)),
		mss         = strings.trim_space(ui.field_text(&f.mss)),
		user_pass   = f.user_pass,
		pq_mode     = PQ_NAME[f.pq],
		ciphers     = strings.trim_space(ui.field_text(&f.ciphers)),
		sni         = f.transport == .Tls ? strings.trim_space(ui.field_text(&f.sni)) : "",
		extra       = make([dynamic]string, context.temp_allocator),
	}
	if d, dok := pf.fingerprint_parse(form.fingerprint); dok {
		form.fingerprint = pf.fingerprint_text(d, context.temp_allocator)
	}
	for i in 0 ..< e.n[.Extra] {
		if l := strings.trim_space(ui.field_text(&e.lists[.Extra][i])); l != "" {
			append(&form.extra, l)
		}
	}
	return form
}

form_secrets :: proc(f: ^Form_Ui) -> pf.Secrets {
	return {ca = f.ca, tls_crypt = f.tls_crypt}
}

// form_errs checks the form; an empty field shows its error only after Create
// or Save (shown_err).
form_errs :: proc(e: ^Edit) -> [pf.Form_Field]string {
	return pf.form_errors(form_of(e), form_secrets(&e.f))
}

@(private = "file")
shown_err :: proc(f: ^Form_Ui, err: string, fl: ^ui.Field) -> string {
	if f.tried || strings.trim_space(ui.field_text(fl)) != "" {
		return err
	}
	return ""
}

// form_ok checks the form and the lists; else the status asks for a fix.
form_ok :: proc(app: ^App) -> bool {
	e := &app.edit
	bad := false
	if e.created {
		for err in form_errs(e) {
			bad ||= err != ""
		}
	}
	for k in List_Kind {
		for i in 0 ..< e.n[k] {
			bad ||= list_error(e, k, i) != ""
		}
	}
	if !e.created && e.id != "" && !e.srv_ro {
		for i in 0 ..< e.srv_n {
			bad ||= server_error(e, i) != ""
		}
	}
	if !e.created {
		bad ||= pf.mtu_error(ui.field_text(&e.ov_mtu)) != "" || pf.mss_error(ui.field_text(&e.ov_mss)) != ""
	}
	if bad {
		e.status = "Fix the marked fields first."
		e.status_error = true
	}
	return !bad
}

transport_set :: proc(f: ^Form_Ui, t: Transport) {
	f.transport = t
	if !f.port_edited {
		ui.field_set(&f.port, tprint("%d", pf.transport_default_port(TRANSPORT_NAME[t])))
	}
}

// ---- Actions ----

create_open :: proc(app: ^App) {
	e := &app.edit
	edit_clear(e)
	e.index = -1
	e.created = true
	ui.field_set(&e.name, "")
	form_ui_reset(&e.f)
	set_message(app, "")
	push_view(app, .Create)
}

create_submit :: proc(app: ^App) {
	e := &app.edit
	f := &e.f
	f.tried = true
	if app.pending.kind != .None || !form_ok(app) {
		return
	}
	form := form_of(e)
	name := strings.trim_space(ui.field_text(&e.name))
	if name == "" {
		name = form.host
	}
	if app.link.kind == .Sim {
		create_sim(app, name, form)
		return
	}
	if !KEYGEN {
		e.status = "This build cannot create keys."
		e.status_error = true
		return
	}
	cert, key, pin, ok := key_new(form.key_type, pf.peers_name(name, context.temp_allocator))
	if !ok {
		e.status = "The key could not be created."
		e.status_error = true
		return
	}
	s := form_secrets(f)
	s.cert, s.key = cert, key
	text := pf.form_text(form, s)
	pf.wipe_string(key)
	delete(cert)
	pending_start(app, .Create, text, name, pin, KEY_LABEL[f.key_type], form)
	form_send(app)
}

@(private = "file")
create_sim :: proc(app: ^App, name: string, form: pf.Form) {
	if app.n_profiles >= MAX_PROFILES {
		return
	}
	n := app.n_profiles
	app.profiles[n] = profile_make(name, form.host, form.port, form.transport, form.user_pass ? .User_Pass : .None)
	app.profiles[n].created = true
	app.n_profiles += 1
	made_set(app, "", name, SAMPLE_PIN, KEY_LABEL[app.edit.f.key_type], n)
	replace_view(app, .Created)
}

// form_send checks the pending text with the service, or stores it when the
// service cannot check.
form_send :: proc(app: ^App) {
	p := &app.pending
	if app.link.kind == .Bus && app.link.state == .Up && app.link.service {
		app.edit.status = "Checking the profile…"
		app.edit.status_error = false
		label := p.name if p.name != "" else ui.field_text(&app.edit.name)
		bus_profile_job(app, .Profile_Check, p.text, service_label(label), false)
		return
	}
	form_commit(app, "The service did not check it.")
}

// form_checked takes the reply of profile.check for the form.
form_checked :: proc(app: ^App, ok: bool, code, message: string, result, details: json.Value) {
	e := &app.edit
	if ok || code == "unknown_op" || code == "unsupported" {
		form_commit(app, ok ? "" : "The service did not check it.")
		return
	}
	verb := "Not saved."
	#partial switch app.pending.kind {
	case .Create:
		verb = "Not created."
	case .Key_Set:
		verb = "The new profile was refused."
	case .Reload:
		reload_done(app, false, refusal_text(code, message, details))
		pending_drop(app)
		return
	}
	set_text(&e.status_owned, tprint("%s %s", verb, refusal_text(code, message, details)))
	e.status = e.status_owned
	e.status_error = true
	pending_drop(app)
}

@(private = "file")
form_commit :: proc(app: ^App, note: string) {
	p := &app.pending
	e := &app.edit
	switch p.kind {
	case .None:
	case .Create:
		name := strings.clone(unique_name(app, p.name), context.temp_allocator)
		id, ok := pf.store_create_form(app.store, name, p.text, p.form, context.temp_allocator)
		if !ok {
			e.status = "The profile could not be saved."
			e.status_error = true
			pending_drop(app)
			return
		}
		store_reload(app)
		made_set(app, id, name, p.pin, p.key_label, -1)
		set_text(&app.made.status, note)
		pending_drop(app)
		form_ui_reset(&e.f)
		replace_view(app, .Created)
	case .Save:
		edit_commit(app, p.text, p.form)
		pending_drop(app)
	case .Key_Set:
		key_set_commit(app, p.text, note)
		pending_drop(app)
	case .Reload:
		reload_done(app, true, note)
		pending_drop(app)
	}
}

pending_start :: proc(app: ^App, kind: Form_Check, text, name, pin, key_label: string, form: pf.Form) {
	pending_drop(app)
	app.pending = {
		kind      = kind,
		text      = text,
		name      = strings.clone(name),
		pin       = pin,
		key_label = strings.clone(key_label),
		form      = pf.form_clone(form),
	}
}

pending_drop :: proc(app: ^App) {
	p := &app.pending
	pf.wipe_string(p.text)
	delete(p.name)
	delete(p.pin)
	delete(p.key_label)
	pf.form_destroy(&p.form)
	p^ = {}
}

made_set :: proc(app: ^App, id, name, pin, key_label: string, row: int) {
	m := &app.made
	set_text(&m.id, id)
	set_text(&m.name, name)
	set_text(&m.pin, pin)
	set_text(&m.key_label, key_label)
	delete(m.peer)
	m.peer = pf.peers_name(name)
	m.row = row
	m.copy_at = {}
	set_text(&m.status, "")
}

replace_view :: proc(app: ^App, v: View) {
	app.stack[app.depth] = v
	app.fresh = 2
	app.u.focus = 0
}

// copy_text puts a key pin, a request or a link on the clipboard.
copy_text :: proc(app: ^App, s: string) -> bool {
	set_text(&app.copied, s)
	return ui.clipboard_copy(s)
}

// pem_paste takes a CA or a tls-crypt key from the clipboard.
pem_paste :: proc(app: ^App, dst: ^string) {
	e := &app.edit
	s, ok := ui.clipboard_paste()
	defer if len(s) > 0 {
		mem.zero_explicit(raw_data(s), len(s))
	}
	if !ok || strings.trim_space(s) == "" {
		e.status = "The clipboard is empty."
		e.status_error = true
		return
	}
	pem_set(e, dst, s)
}

pem_set :: proc(e: ^Edit, dst: ^string, s: string) {
	pf.wipe_string(dst^)
	dst^ = strings.clone(strings.trim_space(s))
	e.status = ""
	e.dirty = true
}

// key_renew generates a new key for a created profile and shows its pin.
key_renew :: proc(app: ^App) {
	e := &app.edit
	e.renew_ask = false
	if app.link.kind == .Sim {
		made_set(app, "", ui.field_text(&e.name), SAMPLE_PIN, KEY_LABEL[e.f.key_type], e.index)
		push_view(app, .Created)
		return
	}
	meta, text, ok := pf.store_load(app.store, e.id, context.temp_allocator)
	defer if len(text) > 0 {
		mem.zero_explicit(raw_data(text), len(text))
	}
	form, has := meta.form.?
	if !ok || !has {
		e.status = "The profile could not be read."
		e.status_error = true
		return
	}
	cert, key, pin, kok := key_new(form.key_type, pf.peers_name(meta.name, context.temp_allocator))
	if !kok {
		e.status = "The key could not be created."
		e.status_error = true
		return
	}
	defer delete(pin)
	old := pf.secrets_read(text)
	s := old
	s.cert, s.key = cert, key
	new_text := pf.form_text(form, s)
	pf.secrets_destroy(&old)
	pf.wipe_string(key)
	delete(cert)
	saved := pf.store_save_text(app.store, e.id, new_text)
	pf.wipe_string(new_text)
	if !saved {
		e.status = "The profile could not be saved."
		e.status_error = true
		return
	}
	store_reload(app)
	label := KEY_LABEL[.Mldsa65 if form.key_type == pf.KEY_MLDSA65 else .Ed25519]
	set_text(&e.pin, pin)
	set_text(&e.key_label, label)
	set_text(&e.cn, pf.peers_name(meta.name, context.temp_allocator))
	made_set(app, e.id, meta.name, pin, label, -1)
	if e.index == app.conn.profile && conn_active(app) {
		set_text(&app.made.status, "The new key applies after you reconnect.")
	}
	push_view(app, .Created)
}

// ---- Drawing ----

// group_open starts a group in a scroll area; group_close ends it.
group_open :: proc(app: ^App) -> (g: ui.Group, y0: i32) {
	gr := row(app, 0)
	y0 = app.cy
	g = ui.group_begin(&app.u, {gr.x, y0, gr.w, 0})
	gap(app, 1 + GROUP_PAD_Y)
	return
}

group_close :: proc(app: ^App, g: ui.Group, y0: i32) {
	gap(app, GROUP_PAD_Y + 1)
	ui.group_end(&app.u, g, app.cy - y0)
	gap(app, 18)
}

// group_sep is the line between two parts of a group.
group_sep :: proc(app: ^App) {
	gap(app, 12)
	group_line(app)
	gap(app, 12)
}

field_label :: proc(app: ^App, label: string) {
	rr := inner(app, 16)
	ui.text(&app.u, ui.ST_LABEL, rr.x, rr.y, label, ui.MUTED)
	gap(app, 6)
}

field_error :: proc(app: ^App, err: string) {
	if err == "" {
		return
	}
	gap(app, 4)
	probe := inner(app, 0)
	for l in ui.wrap_text(&app.u, ui.ST_CAPTION, err, f32(probe.w)) {
		rr := inner(app, 16)
		ui.text(&app.u, ui.ST_CAPTION, rr.x, rr.y, l, ui.ERROR)
	}
}

form_field :: proc(app: ^App, label: string, fl: ^ui.Field, placeholder, err: string, mono := false) {
	field_label(app, label)
	rr := inner(app, ui.FIELD_H)
	if changed, _ := ui.field(&app.u, rr, fl, placeholder, {mono = mono, enabled = true, error = err != ""}); changed {
		app.edit.dirty = true
	}
	field_error(app, err)
}

// two_fields draws two fields side by side, each half of the row.
two_fields :: proc(app: ^App, labels: [2]string, fields: [2]^ui.Field, placeholder: string, errs: [2]string) {
	u := &app.u
	rr := inner(app, 16)
	half := (rr.w - 12) / 2
	for k in 0 ..< 2 {
		ui.text(u, ui.ST_LABEL, rr.x + i32(k) * (half + 12), rr.y, labels[k], ui.MUTED)
	}
	gap(app, 6)
	rr = inner(app, ui.FIELD_H)
	for k in 0 ..< 2 {
		r := mu.Rect{rr.x + i32(k) * (half + 12), rr.y, half, rr.h}
		if changed, _ := ui.field(u, r, fields[k], placeholder, {mono = true, enabled = true, error = errs[k] != ""}); changed {
			app.edit.dirty = true
		}
	}
	for err in errs {
		field_error(app, err)
	}
}

// mono_well draws a text in the mono face, broken at any character.
mono_well :: proc(app: ^App, s: string) {
	u := &app.u
	probe := inner(app, 0)
	cw := ui.text_w(u, ui.ST_MONO, "0")
	per := max(int(f32(probe.w - 20) / max(cw, 1)), 8)
	lines := make([dynamic]string, 0, 4, context.temp_allocator)
	start, n := 0, 0
	for _, i in s {
		if n == per {
			append(&lines, s[start:i])
			start, n = i, 0
		}
		n += 1
	}
	append(&lines, s[start:])
	rr := inner(app, 18 + i32(len(lines)) * 16)
	ui.well(u, rr)
	for l, i in lines {
		ui.text(u, ui.ST_MONO, rr.x + 10, rr.y + 9 + i32(i) * 16, l, ui.TEXT)
	}
}

// key_pin_row shows the key pin as a peers-file line of a noirvpn server
// (`<name> <pin>`), shortened in the middle, with Copy. Returns the Copy rectangle.
key_pin_row :: proc(app: ^App, line: string) -> mu.Rect {
	return copy_row(app, "Key pin", line, "key-pin")
}

// copy_row is a label, a value in mono (shortened in the middle) and Copy. It
// returns the rectangle of Copy.
copy_row :: proc(app: ^App, label, value, id: string) -> mu.Rect {
	u := &app.u
	rr := inner(app, 35)
	copied := value != "" && app.copied == value
	cw := i32(math.ceil(max(ui.button_width(u, "Copy", .Secondary), ui.button_width(u, "Copied", .Secondary))))
	th := i32(ui.line_height(ui.ST_BODY))
	ui.text(u, ui.ST_BODY, rr.x, rr.y + (35 - th) / 2, label, ui.TEXT)
	lx := rr.x + i32(math.ceil(ui.text_w(u, ui.ST_BODY, label))) + 12
	mh := i32(ui.line_height(ui.ST_MONO))
	ui.text(u, ui.ST_MONO, lx, rr.y + (35 - mh) / 2, ui.fit_middle(u, ui.ST_MONO, value, f32(rr.x + rr.w - cw - 10 - lx)), ui.TEXT)
	b := mu.Rect{rr.x + rr.w - cw, rr.y, cw, 35}
	mu.push_id(&u.ctx, id)
	defer mu.pop_id(&u.ctx)
	if ui.button(u, b, copied ? "Copied" : "Copy", .Secondary, value != "", ui.SURFACE) {
		copy_text(app, value)
	}
	return b
}

// PIN_CAPTION is the text under a key pin.
PIN_CAPTION :: "Give the key pin to the administrator of a noirvpn server that pins keys."

// group_caption draws a caption in a group, wrapped.
group_caption :: proc(app: ^App, text: string, col := ui.MUTED) {
	probe := inner(app, 0)
	for l in ui.wrap_text(&app.u, ui.ST_CAPTION, text, f32(probe.w)) {
		rr := inner(app, 16)
		ui.text(&app.u, ui.ST_CAPTION, rr.x, rr.y, l, col)
	}
}

// pem_row is a pasted PEM text: its state, Paste and Clear. The text is
// never drawn.
pem_row :: proc(app: ^App, title: string, dst: ^string, err: string, id: uintptr) {
	u := &app.u
	e := &app.edit
	mu.push_id(&u.ctx, id)
	defer mu.pop_id(&u.ctx)
	rr := inner(app, 35)
	present := dst^ != ""
	ui.text(u, ui.ST_BODY, rr.x, rr.y, title, ui.TEXT)
	ui.text(u, ui.ST_CAPTION, rr.x, rr.y + 19, present ? "Present" : "Not set", present ? ui.OK : ui.MUTED)
	pw := i32(math.ceil(ui.button_width(u, "Paste", .Secondary)))
	x := rr.x + rr.w - pw
	if ui.button(u, {x, rr.y, pw, 35}, "Paste", .Secondary, true, ui.SURFACE) {
		pem_paste(app, dst)
	}
	if present {
		cw := i32(math.ceil(ui.button_width(u, "Clear", .Ghost)))
		if ui.button(u, {x - 6 - cw, rr.y, cw, 35}, "Clear", .Ghost, true, ui.SURFACE) {
			pf.wipe_string(dst^)
			dst^ = ""
			e.dirty = true
		}
	}
	field_error(app, err)
}

// choices draws one row of choices; it returns the one clicked, or -1.
choices :: proc(app: ^App, labels: []string, selected: int, x0: i32 = 0) -> int {
	rr := inner(app, ui.FIELD_H)
	x := rr.x + x0
	n := i32(len(labels))
	cw := (rr.x + rr.w - x - (n - 1) * 6) / n
	hit := -1
	for l, k in labels {
		if ui.choice(&app.u, {x + i32(k) * (cw + 6), rr.y, cw, rr.h}, l, k == selected) && k != selected {
			hit = k
		}
	}
	return hit
}

// form_groups draws the groups of the form. In the profile view (`stored`)
// the key group shows the pin of the key in place of the key type choice.
form_groups :: proc(app: ^App, stored: bool) {
	u := &app.u
	e := &app.edit
	f := &e.f
	errs := form_errs(e)

	section(app, "SERVER")
	g, y0 := group_open(app)
	form_field(app, "Host", &f.host, "vpn.example.com", shown_err(f, errs[.Host], &f.host))
	gap(app, 12)
	{
		rr := inner(app, 16)
		pw: i32 = 84
		ui.text(u, ui.ST_LABEL, rr.x, rr.y, "Port", ui.MUTED)
		ui.text(u, ui.ST_LABEL, rr.x + pw + 12, rr.y, "Transport", ui.MUTED)
		gap(app, 6)
		port_err := shown_err(f, errs[.Port], &f.port)
		probe := inner(app, 0)
		if changed, _ := ui.field(u, {probe.x, probe.y, pw, ui.FIELD_H}, &f.port, "", {mono = true, enabled = true, error = port_err != ""}); changed {
			f.port_edited = true
			e.dirty = true
		}
		labels := TRANSPORT_LABEL
		if k := choices(app, slice.enumerated_array(&labels), int(f.transport), pw + 12); k >= 0 {
			transport_set(f, Transport(k))
			e.dirty = true
		}
		field_error(app, port_err)
	}
	gap(app, 12)
	form_field(app, "Server fingerprint", &f.fingerprint, "SHA-256 of the server certificate", shown_err(f, errs[.Fingerprint], &f.fingerprint), mono = true)
	group_close(app, g, y0)

	section(app, "YOUR KEY")
	g, y0 = group_open(app)
	if stored {
		value_row(app, "Key type", e.key_label, ui.TEXT)
		gap(app, 8)
		key_pin_row(app, pf.peers_line(e.cn, e.pin, context.temp_allocator))
		gap(app, 6)
		group_caption(app, PIN_CAPTION)
		gap(app, 10)
		rr := inner(app, 35)
		nw := i32(math.ceil(ui.button_width(u, "New key", .Secondary)))
		if ui.button(u, {rr.x, rr.y, nw, 35}, "New key", .Secondary, KEYGEN || app.link.kind == .Sim, ui.SURFACE) {
			e.renew_ask = true
		}
	} else {
		field_label(app, "Key type")
		labels := KEY_LABEL
		if k := choices(app, slice.enumerated_array(&labels), int(f.key_type)); k >= 0 {
			f.key_type = Key_Type(k)
		}
	}
	group_close(app, g, y0)

	section(app, "TUNNEL")
	g, y0 = group_open(app)
	two_fields(app, {"MTU", "MSS"}, {&f.mtu, &f.mss}, "Default", {errs[.Mtu], errs[.Mss]})
	group_close(app, g, y0)

	rr := row(app, 35)
	label := f.advanced ? "Hide advanced options" : "Show advanced options"
	bw := i32(math.ceil(ui.button_width(u, label, .Ghost)))
	mu.push_id(&u.ctx, uintptr(77))
	if ui.button(u, {rr.x, rr.y, bw, 35}, label, .Ghost) {
		f.advanced = !f.advanced
	}
	mu.pop_id(&u.ctx)
	gap(app, 10)
	if !f.advanced {
		return
	}
	section(app, "ADVANCED OPTIONS")
	g, y0 = group_open(app)
	pem_row(app, "CA certificate", &f.ca, errs[.Ca], 1)
	group_sep(app)
	pem_row(app, "tls-crypt key", &f.tls_crypt, errs[.Tls_Crypt], 2)
	group_sep(app)
	setting_row(app, "Ask for a user name and password", &f.user_pass)
	group_sep(app)
	field_label(app, "Post-quantum key exchange")
	labels := PQ_LABEL
	if k := choices(app, slice.enumerated_array(&labels), int(f.pq)); k >= 0 {
		f.pq = Pq_Choice(k)
		e.dirty = true
	}
	group_sep(app)
	form_field(app, "Data ciphers", &f.ciphers, "Default", errs[.Ciphers], mono = true)
	if f.transport == .Tls {
		gap(app, 12)
		form_field(app, "TLS server name (SNI)", &f.sni, "The host", errs[.Sni])
	}
	group_sep(app)
	list_editor(app, .Extra, "Extra options", "Enter one option per line, as in an .ovpn file.", "verb 4", "Add option")
	group_close(app, g, y0)
}

// bottom_status draws a status text at the left of a bottom bar.
bottom_status :: proc(app: ^App, br: mu.Rect, text: string, error: bool, right: i32) {
	u := &app.u
	if text == "" {
		return
	}
	th := i32(ui.line_height(ui.ST_BODY))
	st := ui.fit_text(u, ui.ST_BODY, text, f32(right - 16 - 12))
	ui.text(u, ui.ST_BODY, 16, br.y + 1 + (br.h - 1 - th) / 2, st, error ? ui.ERROR : ui.OK)
}

view_create :: proc(app: ^App) {
	u := &app.u
	e := &app.edit
	w, h := u.size.x, u.size.y
	res := topbar(app, {back = true, title = "New profile", simulated = app.link.kind == .Sim})
	if res.back {
		create_leave(app)
		return
	}
	bar_h := i32(ui.button_height()) + 20 + 1
	scroll_begin(app, "create", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H - bar_h})
	gap(app, 14)
	section(app, "NAME")
	r := row(app, ui.FIELD_H)
	_, _ = ui.field(u, r, &e.name, "Same as the host", {enabled = true})
	gap(app, 18)
	form_groups(app, false)
	gap(app, 10)
	scroll_end(app)

	br := mu.Rect{0, h - bar_h, w, bar_h}
	ui.bar(u, br)
	bw := i32(math.ceil(ui.button_width(u, "Create", .Primary)))
	bottom_status(app, br, e.status, e.status_error, w - 16 - bw)
	if ui.button(u, {w - 16 - bw, br.y + 1 + 10, bw, i32(ui.button_height())}, "Create", .Primary, app.pending.kind == .None, ui.SURFACE) {
		create_submit(app)
	}
}

// create_leave goes back to the list; a check on its way is forgotten.
create_leave :: proc(app: ^App) {
	if app.pending.kind == .Create {
		pending_drop(app)
	}
	form_ui_reset(&app.edit.f)
	pop_view(app)
}

view_created :: proc(app: ^App) {
	u := &app.u
	m := &app.made
	w, h := u.size.x, u.size.y
	res := topbar(app, {back = true, title = "Your key", simulated = app.link.kind == .Sim})
	if res.back {
		pop_view(app)
		return
	}
	bar_h := i32(ui.button_height()) + 20 + 1
	scroll_begin(app, "made", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H - bar_h})
	gap(app, 14)
	r := row(app, 20)
	ui.text(u, ui.ST_HEADING, r.x, r.y, ui.fit_text(u, ui.ST_HEADING, tprint("“%s” is ready.", m.name), f32(r.w)), ui.TEXT)
	gap(app, 6)
	r = row(app, 17)
	ui.text(u, ui.ST_BODY, r.x, r.y, "Give this to the administrator of the server.", ui.MUTED)
	gap(app, 18)

	section(app, "YOUR KEY")
	g, y0 := group_open(app)
	value_row(app, "Key type", m.key_label, ui.TEXT)
	gap(app, 8)
	m.copy_at = key_pin_row(app, peers_line(app))
	gap(app, 6)
	group_caption(app, PIN_CAPTION)
	group_close(app, g, y0)
	scroll_end(app)

	br := mu.Rect{0, h - bar_h, w, bar_h}
	ui.bar(u, br)
	bh := i32(ui.button_height())
	dw := i32(math.ceil(ui.button_width(u, "Done", .Primary)))
	ow := i32(math.ceil(ui.button_width(u, "Open profile", .Secondary)))
	bottom_status(app, br, m.status, false, w - 16 - dw - 8 - ow)
	if ui.button(u, {w - 16 - dw, br.y + 1 + 10, dw, bh}, "Done", .Primary, true, ui.SURFACE) {
		pop_view(app)
		return
	}
	if ui.button(u, {w - 16 - dw - 8 - ow, br.y + 1 + 10, ow, bh}, "Open profile", .Secondary, true, ui.SURFACE) {
		made_open(app)
	}
}

// made_open shows the profile view of the new profile.
made_open :: proc(app: ^App) {
	m := &app.made
	k := m.row if app.link.kind == .Sim else row_of(app, m.id)
	pop_view(app)
	if current_view(app) == .Profile {
		return
	}
	if k >= 0 && k < app.n_profiles {
		open_profile(app, k)
	}
}

// peers_line is the line of the key view for the peers file of the server.
peers_line :: proc(app: ^App) -> string {
	return pf.peers_line(app.made.peer, app.made.pin, context.temp_allocator)
}
