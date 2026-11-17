// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Profile view: name, summary groups, sign-in, overrides and the Save bar.
// A stored profile is read from the store; the overrides are lines that the
// GUI adds after the profile text at profile.set.

import "core:math"
import "core:mem"
import "core:slice"
import "core:strconv"
import "core:strings"
import mu "vendor:microui"
import "noir:proto/config"
import pf "profiles"
import "ui"

MAX_REMOTES_SHOWN :: 4
MAX_SERVERS :: 8

// One editable server of an imported profile.
Server_Row :: struct {
	host:  ui.Field,
	port:  ui.Field,
	proto: Transport,
}

List_Kind :: enum u8 {
	Domain,
	Server,
	Extra, // extra option lines of a created profile
}

Edit :: struct {
	index:          int,
	id:             string, // store id, "" for a simulated row
	name:           ui.Field,
	browser:        ui.Field,
	web:            bool, // web sign-in
	user_pass:      bool, // the profile asks for a user name and a password
	use_server_dns: bool,
	redirect:       bool,
	block_ipv6:     bool,
	use_dco:        bool, // the "Use DCO" switch (Linux)
	dco_in_text:    bool, // the profile text has disable-dco
	lists:          [List_Kind][MAX_DOMAINS]ui.Field,
	n:              [List_Kind]int,
	remotes:        [dynamic]string, // "host:port" and the transport, for the Server group
	more_remotes:   int,
	srv:            [MAX_SERVERS]Server_Row, // the servers of an imported profile
	srv_n:          int,
	srv_ro:         bool, // too many servers to edit: the list is only shown
	srv_custom:     bool, // the servers come from an override
	srv_tried:      bool, // Save was tried: show the errors of empty rows too
	ident:          [5]bool, // CA, certificate, key, TLS wrapping key, server fingerprint
	lines:          [dynamic]string, // the profile text, inline blocks hidden
	dirty:          bool,
	status:         string,
	status_owned:   string, // the text of a status built at run time
	status_error:   bool,
	overrides_y:    i32, // set by the view, for the screenshots
	block6_at:      mu.Rect, // the Block IPv6 switch, set by the view for the tests
	dco_at:         mu.Rect, // the Use DCO switch, set by the view for the tests
	ov_mtu:         ui.Field, // tun-mtu and mssfix overrides of an imported profile
	ov_mss:         ui.Field,
	// A profile that the GUI created: the form (view_create.odin).
	created:        bool,
	f:              Form_Ui,
	pin:            string, // the pin of the inline certificate, "" for none
	key_label:      string,
	cn:             string, // the common name of the inline certificate
	renew_ask:      bool, // New key waits for its confirmation
	login_inline:   bool, // the profile holds its user name and password
	request:        bool, // a key request waits for its certificate
	request_at:     mu.Rect, // Open of the key request, set by the view for the tests
	// The profile file (store) and the files of its secrets (secret_file.odin).
	path:           string, // the profile text in the store, "" for none
	login_file:     string, // auth-user-pass FILE
	pass_file:      string, // askpass FILE
	askpass:        bool, // the passphrase of the key is asked for
	login_problem:  string, // why login_file cannot be used now, or ""
	pass_problem:   string,
	reload_msg:     string, // the result of Reload
	reload_error:   bool,
	reconnect:      bool, // Reload changed the profile of the tunnel
	file_note:      string, // the result of Open profile file or Show in folder
	reload_at:      mu.Rect, // set by the view for the tests
	reconnect_at:   mu.Rect,
}

edit_init :: proc(e: ^Edit) {
	ui.field_init(&e.name)
	ui.field_init(&e.browser)
	ui.field_init(&e.ov_mtu)
	ui.field_init(&e.ov_mss)
	form_ui_init(&e.f)
	for &r in e.srv {
		ui.field_init(&r.host)
		ui.field_init(&r.port)
	}
	for k in List_Kind {
		for i in 0 ..< MAX_DOMAINS {
			ui.field_init(&e.lists[k][i])
		}
	}
}

edit_clear :: proc(e: ^Edit) {
	for s in e.remotes {
		delete(s)
	}
	for s in e.lines {
		delete(s)
	}
	clear(&e.remotes)
	clear(&e.lines)
	set_text(&e.id, "")
	e.n = {}
	e.more_remotes = 0
	for &r in e.srv {
		ui.field_set(&r.host, "")
		ui.field_set(&r.port, "")
		r.proto = .Udp
	}
	e.srv_n, e.srv_ro, e.srv_custom, e.srv_tried = 0, false, false, false
	e.dirty = false
	e.status = ""
	e.web = false
	e.use_server_dns = true
	e.redirect = true
	e.block_ipv6 = false
	e.use_dco, e.dco_in_text = true, false
	e.block6_at, e.dco_at = {}, {}
	ui.field_set(&e.browser, "")
	ui.field_set(&e.ov_mtu, "")
	ui.field_set(&e.ov_mss, "")
	for i in 0 ..< MAX_DOMAINS {
		ui.field_set(&e.lists[.Extra][i], "")
	}
	e.created = false
	e.renew_ask = false
	form_ui_reset(&e.f)
	set_text(&e.pin, "")
	set_text(&e.key_label, "")
	set_text(&e.cn, "")
	e.login_inline, e.request = false, false
	e.request_at = {}
	set_text(&e.path, "")
	set_text(&e.login_file, "")
	set_text(&e.pass_file, "")
	set_text(&e.login_problem, "")
	set_text(&e.pass_problem, "")
	set_text(&e.file_note, "")
	e.askpass = false
	e.reload_at, e.reconnect_at = {}, {}
}

// edit_reload_clear forgets the result of Reload.
edit_reload_clear :: proc(e: ^Edit) {
	set_text(&e.reload_msg, "")
	e.reload_error, e.reconnect = false, false
}

// edit_load fills the view from a simulated row.
edit_load :: proc(e: ^Edit, p: ^Profile, index: int) {
	edit_clear(e)
	e.index = index
	ui.field_set(&e.name, p.name)
	e.web = p.login == .Web
	e.user_pass = p.login == .User_Pass
	append(&e.remotes, strings.clone(tprint("%s:%d\t%s", p.host, p.port, strings.to_upper(p.proto, context.temp_allocator))))
	append(&e.remotes, strings.clone("backup.example.com:443\tTCP"))
	e.ident = {true, true, true, false, false}
	if p.created {
		e.created = true
		form := pf.Form {
			host        = p.host,
			port        = p.port,
			transport   = p.proto,
			fingerprint = SAMPLE_FP,
			key_type    = pf.KEY_ED25519,
			user_pass   = p.login == .User_Pass,
		}
		form_ui_load(e, form, {})
		set_text(&e.key_label, "Ed25519")
	} else {
		set_text(&e.key_label, "ECDSA P-256")
	}
	set_text(&e.pin, SAMPLE_PIN)
	set_text(&e.cn, pf.peers_name(p.name, context.temp_allocator))
	if !p.created {
		set_text(&e.path, SAMPLE_PROFILE_PATH)
	}
	sample := [?]string {
		"client",
		"dev tun",
		"nobind",
		tprint("remote %s %d %s-client", p.host, p.port, p.proto),
		"remote backup.example.com 443 tcp-client",
		"http-proxy proxy.example.com 3128",
		"peer-fingerprint 05:12:E0:73:74:F7:76:C0:B",
		"<cert>",
		"-----BEGIN CERTIFICATE-----",
		"MIIBKjCB0gADAgECAgh3CuNG5H6gKTAKBggqhkjOPQ",
		"-----END CERTIFICATE-----",
		"</cert>",
		"<key>",
		"-----BEGIN PRIVATE KEY-----",
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawI",
		"-----END PRIVATE KEY-----",
		"</key>",
	}
	hide_blocks(e, strings.join(sample[:], "\n", context.temp_allocator))
}

// edit_load_stored fills the view from the store. It returns false when the
// profile cannot be read.
edit_load_stored :: proc(app: ^App, e: ^Edit, index: int) -> bool {
	id := app.profiles[index].id
	meta, text, ok := pf.store_load(app.store, id, context.temp_allocator)
	if !ok {
		return false
	}
	edit_clear(e)
	e.index = index
	set_text(&e.id, id)
	ui.field_set(&e.name, meta.name)
	e.web = meta.web_sign_in
	ui.field_set(&e.browser, meta.browser)
	e.use_server_dns = !meta.overrides.ignore_server_dns
	e.redirect = !meta.overrides.ignore_redirect
	e.block_ipv6 = meta.overrides.block_ipv6
	e.use_dco = !meta.overrides.no_dco
	for d in meta.overrides.domains {
		list_add(e, .Domain, d)
	}
	for d in meta.overrides.dns_servers {
		list_add(e, .Server, d)
	}
	ui.field_set(&e.ov_mtu, meta.overrides.tun_mtu)
	ui.field_set(&e.ov_mss, meta.overrides.mssfix)
	secrets := pf.secrets_read(text)
	defer pf.secrets_destroy(&secrets)
	if form, has := meta.form.?; has {
		e.created = true
		form_ui_load(e, form, secrets)
	}
	if secrets.cert != "" {
		pin, label, cn, pok := cert_pin(secrets.cert, context.temp_allocator)
		if pok {
			set_text(&e.pin, pin)
			set_text(&e.key_label, label)
			set_text(&e.cn, cn)
		}
	}
	if body, found := config.inline_login(text, context.temp_allocator); found {
		e.login_inline = true
		mem.zero_explicit(raw_data(body), len(body))
	}
	set_text(&e.path, pf.store_profile_path(app.store, id, context.temp_allocator))
	if KEYGEN && !e.created {
		_, e.request = pf.store_request_load(app.store, id, context.temp_allocator)
	}
	s, _ := pf.summarize(text, context.temp_allocator)
	for r, i in s.remotes {
		if i >= MAX_REMOTES_SHOWN {
			e.more_remotes = len(s.remotes) - MAX_REMOTES_SHOWN
			break
		}
		host := strings.contains_rune(r.host, ':') ? tprint("[%s]", r.host) : r.host
		append(&e.remotes, strings.clone(tprint("%s:%d\t%s", host, r.port, strings.to_upper(r.proto, context.temp_allocator))))
	}
	if !e.created {
		sc, _ := pf.summarize(pf.compose(text, meta.overrides, context.temp_allocator), context.temp_allocator)
		e.srv_custom = len(meta.overrides.servers) > 0
		servers_load(e, sc.remotes[:])
	}
	e.user_pass = s.user_pass
	e.dco_in_text = s.disable_dco
	secret_files_load(e, s.login_file, s.pass_file, s.askpass)
	e.ident = {s.has_ca, s.has_cert, s.has_key, s.has_tls_crypt || s.has_tls_crypt_v2 || s.has_tls_auth, s.has_peer_fingerprint}
	hide_blocks(e, text)
	return true
}

// hide_blocks splits the text into lines and replaces the body of each inline
// block with one line that counts it. The UI never shows key material.
hide_blocks :: proc(e: ^Edit, text: string) {
	t := text
	block := ""
	hidden := 0
	for line in strings.split_lines_iterator(&t) {
		l := strings.trim_right(line, "\r")
		trim := strings.trim_space(l)
		if block != "" {
			if trim == tprint("</%s>", block) {
				append(&e.lines, strings.clone(tprint("  (%d lines hidden)", hidden)))
				append(&e.lines, strings.clone(l))
				block = ""
			} else {
				hidden += 1
			}
			continue
		}
		if len(trim) > 2 && trim[0] == '<' && trim[1] != '/' && trim[len(trim) - 1] == '>' && trim != "<connection>" {
			block = trim[1:len(trim) - 1]
			hidden = 0
		}
		append(&e.lines, strings.clone(l))
	}
	if block != "" {
		append(&e.lines, strings.clone(tprint("  (%d lines hidden)", hidden)))
	}
}

list_add :: proc(e: ^Edit, k: List_Kind, s: string) {
	if e.n[k] < MAX_DOMAINS {
		ui.field_set(&e.lists[k][e.n[k]], s)
		e.n[k] += 1
	}
}

list_remove :: proc(e: ^Edit, k: List_Kind, i: int) {
	// Move the text up; the last field becomes free.
	for j in i ..< e.n[k] - 1 {
		ui.field_set(&e.lists[k][j], ui.field_text(&e.lists[k][j + 1]))
	}
	e.n[k] -= 1
	ui.field_set(&e.lists[k][e.n[k]], "")
}

domain_add :: proc(e: ^Edit, s: string) {
	list_add(e, .Domain, s)
}

// list_error checks entry i of a list.
list_error :: proc(e: ^Edit, k: List_Kind, i: int) -> string {
	s := strings.trim_space(ui.field_text(&e.lists[k][i]))
	if s == "" {
		return ""
	}
	switch k {
	case .Domain:
		if !pf.domain_valid(s) {
			return "Use letters, digits, hyphens and dots."
		}
	case .Server:
		if !pf.address_valid(s) {
			return "Use an IPv4 or IPv6 address."
		}
	case .Extra:
		if msg := pf.extra_error(s); msg != "" {
			return msg
		}
	}
	for j in 0 ..< i {
		if strings.equal_fold(strings.trim_space(ui.field_text(&e.lists[k][j])), s) {
			return "This is already in the list."
		}
	}
	return ""
}

// servers_load fills the server rows. More than MAX_SERVERS turns the list
// read-only.
servers_load :: proc(e: ^Edit, remotes: []pf.Remote) {
	e.srv_n = 0
	e.srv_ro = len(remotes) > MAX_SERVERS
	if e.srv_ro {
		return
	}
	for r in remotes {
		row := &e.srv[e.srv_n]
		ui.field_set(&row.host, r.host)
		ui.field_set(&row.port, tprint("%d", r.port))
		row.proto = transport_of(r.proto)
		e.srv_n += 1
	}
}

transport_of :: proc(proto: string) -> Transport {
	for t in Transport {
		if TRANSPORT_NAME[t] == proto {
			return t
		}
	}
	return .Udp
}

server_add :: proc(e: ^Edit) {
	if e.srv_n < MAX_SERVERS {
		row := &e.srv[e.srv_n]
		ui.field_set(&row.host, "")
		ui.field_set(&row.port, tprint("%d", pf.DEFAULT_PORT))
		row.proto = .Udp
		e.srv_n += 1
	}
}

server_remove :: proc(e: ^Edit, i: int) {
	for j in i ..< e.srv_n - 1 {
		ui.field_set(&e.srv[j].host, ui.field_text(&e.srv[j + 1].host))
		ui.field_set(&e.srv[j].port, ui.field_text(&e.srv[j + 1].port))
		e.srv[j].proto = e.srv[j + 1].proto
	}
	e.srv_n -= 1
	ui.field_set(&e.srv[e.srv_n].host, "")
	ui.field_set(&e.srv[e.srv_n].port, "")
}

// server_error checks one server row.
server_error :: proc(e: ^Edit, i: int) -> string {
	r := &e.srv[i]
	port, ok := strconv.parse_int(strings.trim_space(ui.field_text(&r.port)), 10)
	if !ok {
		port = 0
	}
	return pf.server_error(ui.field_text(&r.host), port, TRANSPORT_NAME[r.proto])
}

// servers_changed gives the override servers: the rows when they differ from
// the servers of the profile text, else none.
servers_changed :: proc(e: ^Edit, text: string) -> [dynamic]pf.Server {
	out := make([dynamic]pf.Server, context.temp_allocator)
	orig, _ := pf.summarize(text, context.temp_allocator)
	same := len(orig.remotes) == e.srv_n
	for i in 0 ..< e.srv_n {
		r := &e.srv[i]
		sv := pf.Server{strings.trim_space(ui.field_text(&r.host)), 0, TRANSPORT_NAME[r.proto]}
		sv.port, _ = strconv.parse_int(strings.trim_space(ui.field_text(&r.port)), 10)
		append(&out, sv)
		if same {
			o := orig.remotes[i]
			same = o.host == sv.host && o.port == sv.port && transport_of(o.proto) == r.proto
		}
	}
	if same {
		clear(&out)
	}
	return out
}

GROUP_PAD_X :: 14
GROUP_PAD_Y :: 12

// section draws a section label and its gap.
section :: proc(app: ^App, label: string) {
	r := row(app, 16)
	ui.text(&app.u, ui.ST_SECTION, r.x + 2, r.y - 1, label, ui.MUTED)
	gap(app, 6)
}

// inner is a row inside a group: inset by the group border and padding.
inner :: proc(app: ^App, h: i32) -> mu.Rect {
	return row(app, h, ui.MARGIN + 1 + GROUP_PAD_X)
}

// line draws a separator row inside a group.
group_line :: proc(app: ^App) {
	r := inner(app, 1)
	ui.hline(&app.u, r.x, r.y, r.w)
}

// value_row is a label on the left and a value on the right.
value_row :: proc(app: ^App, label, value: string, value_col: ui.Color) {
	u := &app.u
	rr := inner(app, 25)
	ui.text(u, ui.ST_BODY, rr.x, rr.y + 3 + 1, label, ui.TEXT)
	lw := i32(math.ceil(ui.text_w(u, ui.ST_BODY, value)))
	ui.text(u, ui.ST_BODY, rr.x + rr.w - lw, rr.y + 3 + 1, value, value_col)
}

view_profile :: proc(app: ^App) {
	u := &app.u
	e := &app.edit
	w, h := u.size.x, u.size.y
	p := &app.profiles[e.index]

	res := topbar(app, {back = true, title = ui.field_text(&e.name) == "" ? p.name : ui.field_text(&e.name), simulated = app.link.kind == .Sim})
	if res.back {
		pop_view(app)
		return
	}

	bar_h := i32(ui.button_height()) + 20 + 1
	scroll_begin(app, "profile", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H - bar_h})
	scroll_y := mu.get_current_container(&u.ctx).scroll.y
	gap(app, 14)

	// Name.
	section(app, "NAME")
	r := row(app, ui.FIELD_H)
	if changed, _ := ui.field(u, r, &e.name, "", {enabled = true}); changed {
		e.dirty = true
	}
	gap(app, 18)

	gr: mu.Rect
	g: ui.Group
	y0: i32
	if e.created {
		form_groups(app, true)
	} else {
		// Server.
		section(app, "SERVER")
		gr = row(app, 0)
		g = ui.group_begin(u, {gr.x, app.cy, gr.w, 0})
		y0 = app.cy
		gap(app, 1 + GROUP_PAD_Y)
		editable := e.id != "" && !e.srv_ro
		if editable {
			servers_editor(app)
		} else if len(e.remotes) == 0 {
			rr := inner(app, 23)
			ui.text(u, ui.ST_BODY, rr.x, rr.y + 2, "No server", ui.MUTED)
		}
		shown := e.remotes[:] if !editable else nil
		for rem in shown {
			rr := inner(app, 23)
			tab := strings.index_byte(rem, '\t')
			addr, proto := rem[:tab], rem[tab + 1:]
			ui.text(u, ui.ST_MONO, rr.x, rr.y + 2 + 1, ui.fit_text(u, ui.ST_MONO, addr, f32(rr.w - 60)), ui.TEXT)
			pw := i32(math.ceil(ui.text_w(u, ui.ST_BODY, proto)))
			ui.text(u, ui.ST_BODY, rr.x + rr.w - pw, rr.y + 2, proto, ui.MUTED)
		}
		if e.more_remotes > 0 && !editable {
			rr := inner(app, 23)
			ui.text(u, ui.ST_CAPTION, rr.x, rr.y + 4, tprint("and %d more", e.more_remotes), ui.MUTED)
		}
		gap(app, GROUP_PAD_Y + 1)
		ui.group_end(u, g, app.cy - y0)
		gap(app, 18)

		// Identity.
		section(app, "IDENTITY")
		gr = row(app, 0)
		y0 = app.cy
		g = ui.group_begin(u, {gr.x, y0, gr.w, 0})
		gap(app, 1 + GROUP_PAD_Y)
		labels := [5]string{"CA certificate", "Client certificate", "Private key", "TLS wrapping key", "Server fingerprint"}
		for label, i in labels {
			present := e.ident[i]
			value_row(app, label, present ? "Present" : "–", present ? ui.TEXT : ui.MUTED)
		}
		if e.pin != "" {
			group_sep(app)
			value_row(app, "Key type", e.key_label, ui.TEXT)
			gap(app, 8)
			key_pin_row(app, pf.peers_line(e.cn, e.pin, context.temp_allocator))
		}
		gap(app, GROUP_PAD_Y + 1)
		ui.group_end(u, g, app.cy - y0)
		gap(app, 18)

	}

	// Sign-in.
	section(app, "SIGN-IN")
	gr = row(app, 0)
	y0 = app.cy
	g = ui.group_begin(u, {gr.x, y0, gr.w, 0})
	gap(app, 1 + GROUP_PAD_Y)
	{
		sign_in_rows(app)
		gap(app, 12)
		group_line(app)
		gap(app, 12)
		setting_row(app, "Web sign-in", &e.web)
		if e.web {
			gap(app, 8 + 6)
			rr := inner(app, 16)
			ui.text(u, ui.ST_LABEL, rr.x, rr.y, "Browser", ui.MUTED)
			gap(app, 6)
			rr = inner(app, ui.FIELD_H)
			if changed, _ := ui.field(u, rr, &e.browser, "System default", {mono = true, enabled = true}); changed {
				e.dirty = true
			}
		}
	}
	gap(app, GROUP_PAD_Y + 1)
	ui.group_end(u, g, app.cy - y0)
	gap(app, 18)

	// Overrides.
	section(app, "OVERRIDES")
	e.overrides_y = app.cy - 22 - ui.TOPBAR_H + scroll_y
	gr = row(app, 0)
	y0 = app.cy
	g = ui.group_begin(u, {gr.x, y0, gr.w, 0})
	gap(app, 1 + GROUP_PAD_Y)
	{
		setting_row(app, "Use the DNS settings of the server", &e.use_server_dns)
		gap(app, 12)
		group_line(app)
		gap(app, 12)
		list_editor(app, .Domain, "Extra search domains", "Short names are looked up in these domains.", "example.com", "Add domain")
		gap(app, 12)
		group_line(app)
		gap(app, 12)
		list_editor(app, .Server, "Own DNS servers", "Asked first, before the server's DNS servers.", "10.0.0.53", "Add server")
		gap(app, 12)
		group_line(app)
		gap(app, 12)
		setting_row(app, "Send all traffic through the VPN when the server asks", &e.redirect)
		gap(app, 12)
		group_line(app)
		gap(app, 12)
		e.block6_at = setting_row(app, "Block IPv6", &e.block_ipv6)
		when DCO_UI {
			dco_row(app)
		}
		if !e.created {
			group_sep(app)
			two_fields(app, {"MTU", "MSS"}, {&e.ov_mtu, &e.ov_mss}, "From the profile", {pf.mtu_error(ui.field_text(&e.ov_mtu)), pf.mss_error(ui.field_text(&e.ov_mss))})
		}
	}
	gap(app, GROUP_PAD_Y + 1)
	ui.group_end(u, g, app.cy - y0)
	gap(app, 18)

	if !e.created && e.path != "" {
		profile_file_group(app)
	}

	// Advanced.
	section(app, e.created ? "PROFILE TEXT" : "ADVANCED")
	gr = row(app, 0)
	y0 = app.cy
	g = ui.group_begin(u, {gr.x, y0, gr.w, 0})
	gap(app, 1 + GROUP_PAD_Y)
	{
		if !e.created && (KEYGEN || app.link.kind == .Sim) {
			rr := inner(app, 35)
			label := e.request ? "Certificate request waiting" : "New key and certificate request"
			ow := i32(math.ceil(ui.button_width(u, "Open", .Secondary)))
			th := i32(ui.line_height(ui.ST_BODY))
			ui.text(u, ui.ST_BODY, rr.x, rr.y + (35 - th) / 2, ui.fit_text(u, ui.ST_BODY, label, f32(rr.w - ow - 12)), e.request ? ui.WARN : ui.TEXT)
			e.request_at = {rr.x + rr.w - ow, rr.y, ow, 35}
			if ui.button(u, e.request_at, "Open", .Secondary, app.pending.kind == .None, ui.SURFACE) {
				key_request_open(app)
			}
			group_sep(app)
		}
		rr := inner(app, 16)
		caption := e.created ? "Save will write with the same key." : "The profile text. To change it, open the profile file and reload it."
		ui.text(u, ui.ST_CAPTION, rr.x, rr.y, ui.fit_text(u, ui.ST_CAPTION, caption, f32(rr.w)), ui.MUTED)
		gap(app, 10)
		rr = inner(app, 18 + i32(len(e.lines)) * 16)
		ui.well(u, rr)
		mu.push_clip_rect(&u.ctx, {rr.x + 1, rr.y + 1, rr.w - 2, rr.h - 2})
		for l, i in e.lines {
			ui.text(u, ui.ST_MONO, rr.x + 10, rr.y + 9 + i32(i) * 16, l, ui.TEXT)
		}
		mu.pop_clip_rect(&u.ctx)
	}
	gap(app, GROUP_PAD_Y + 1)
	ui.group_end(u, g, app.cy - y0)
	gap(app, 20)
	scroll_end(app)

	// Save bar, or the question of New key.
	br := mu.Rect{0, h - bar_h, w, bar_h}
	ui.bar(u, br)
	bh := i32(ui.button_height())
	if e.renew_ask {
		nw := i32(math.ceil(ui.button_width(u, "New key", .Danger)))
		cw := i32(math.ceil(ui.button_width(u, "Cancel", .Ghost)))
		th := i32(ui.line_height(ui.ST_BODY))
		q := ui.fit_text(u, ui.ST_BODY, "Replace the key? The server needs the new pin.", f32(w - 16 - nw - 8 - cw - 16 - 12))
		ui.text(u, ui.ST_BODY, 16, br.y + 1 + (bar_h - 1 - th) / 2, q, ui.TEXT)
		if ui.button(u, {w - 16 - nw, br.y + 1 + 10, nw, bh}, "New key", .Danger, true, ui.SURFACE) {
			key_renew(app)
		}
		if ui.button(u, {w - 16 - nw - 8 - cw, br.y + 1 + 10, cw, bh}, "Cancel", .Ghost, true, ui.SURFACE) {
			e.renew_ask = false
		}
		return
	}
	bw := i32(math.ceil(ui.button_width(u, "Save", .Primary)))
	if e.status != "" {
		th := i32(ui.line_height(ui.ST_BODY))
		st := ui.fit_text(u, ui.ST_BODY, e.status, f32(w - 16 - bw - 16 - 12))
		ui.text(u, ui.ST_BODY, 16, br.y + 1 + (bar_h - 1 - th) / 2, st, e.status_error ? ui.ERROR : ui.OK)
	}
	if ui.button(u, {w - 16 - bw, br.y + 1 + 10, bw, bh}, "Save", .Primary, e.dirty && app.pending.kind == .None, ui.SURFACE) {
		edit_save(app)
	}
}

// edit_save checks the lists and stores the changes. A created profile rewrites
// its text from the form with the stored key; the service checks it first.
edit_save :: proc(app: ^App) {
	e := &app.edit
	e.f.tried = e.created
	e.srv_tried = true
	if !form_ok(app) {
		return
	}
	if !e.created || e.id == "" {
		edit_commit(app, "", {})
		return
	}
	meta, text, ok := pf.store_load(app.store, e.id, context.temp_allocator)
	defer if len(text) > 0 {
		mem.zero_explicit(raw_data(text), len(text))
	}
	if !ok {
		e.status = "The profile could not be read."
		e.status_error = true
		return
	}
	old := pf.secrets_read(text)
	defer pf.secrets_destroy(&old)
	s := form_secrets(&e.f)
	s.cert, s.key = old.cert, old.key
	form := form_of(e)
	name := strings.trim_space(ui.field_text(&e.name))
	pending_start(app, .Save, pf.form_text(form, s), name if name != "" else meta.name, "", "", form)
	form_send(app)
}

// edit_commit stores the name, the sign-in and the overrides; `text` is the
// new profile text of a created profile, "" for none.
edit_commit :: proc(app: ^App, text: string, form: pf.Form) {
	e := &app.edit
	name := strings.trim_space(ui.field_text(&e.name))
	if e.id == "" {
		// A simulated row.
		if name != "" {
			app.profiles[e.index].name = strings.clone(name)
		}
		app.profiles[e.index].login = e.web ? .Web : .None
	} else {
		meta, ptext, ok := pf.store_load(app.store, e.id, context.temp_allocator)
		if !ok {
			e.status = "The profile could not be read."
			e.status_error = true
			return
		}
		if name != "" {
			meta.name = name
		}
		if !e.created && !e.srv_ro {
			meta.overrides.servers = servers_changed(e, ptext)
			e.srv_custom = len(meta.overrides.servers) > 0
		}
		meta.web_sign_in = e.web
		meta.browser = strings.trim_space(ui.field_text(&e.browser))
		meta.overrides.ignore_server_dns = !e.use_server_dns
		meta.overrides.ignore_redirect = !e.redirect
		meta.overrides.block_ipv6 = e.block_ipv6
		meta.overrides.no_dco = !e.use_dco
		meta.overrides.domains = make([dynamic]string, context.temp_allocator)
		meta.overrides.dns_servers = make([dynamic]string, context.temp_allocator)
		for i in 0 ..< e.n[.Domain] {
			if s := strings.trim_space(ui.field_text(&e.lists[.Domain][i])); s != "" {
				append(&meta.overrides.domains, s)
			}
		}
		for i in 0 ..< e.n[.Server] {
			if s := strings.trim_space(ui.field_text(&e.lists[.Server][i])); s != "" {
				append(&meta.overrides.dns_servers, s)
			}
		}
		meta.overrides.tun_mtu = "" if e.created else strings.trim_space(ui.field_text(&e.ov_mtu))
		meta.overrides.mssfix = "" if e.created else strings.trim_space(ui.field_text(&e.ov_mss))
		if text != "" {
			meta.form = form
			if !pf.store_save_text(app.store, e.id, text) {
				e.status = "The profile could not be saved."
				e.status_error = true
				return
			}
			for l in e.lines {
				delete(l)
			}
			clear(&e.lines)
			hide_blocks(e, text)
		}
		if !pf.store_save_meta(app.store, meta) {
			e.status = "The profile could not be saved."
			e.status_error = true
			return
		}
		store_reload(app)
		// A new name can move the row.
		if k := row_of(app, e.id); k >= 0 {
			e.index = k
		}
	}
	e.status = "Saved."
	if e.index == app.conn.profile && conn_active(app) {
		e.status = "Saved. Reconnect to apply the changes."
	}
	e.status_error = false
	e.dirty = false
}

// servers_editor draws the editable servers of an imported profile. The
// caller has the group open.
servers_editor :: proc(app: ^App) {
	u := &app.u
	e := &app.edit
	rr := inner(app, 16)
	ui.text(u, ui.ST_CAPTION, rr.x, rr.y, "These servers replace the ones in the profile.", ui.MUTED)
	gap(app, 8)
	remove := -1
	mu.push_id(&u.ctx, 300)
	for i in 0 ..< e.srv_n {
		mu.push_id(&u.ctx, uintptr(i))
		row := &e.srv[i]
		if i > 0 {
			group_sep(app)
		}
		rr = inner(app, 38)
		if changed, _ := ui.field(u, {rr.x, rr.y, rr.w - 38 - 6, 38}, &row.host, "vpn.example.com", {mono = true, enabled = true}); changed {
			e.dirty = true
		}
		if ui.box_button(u, {rr.x + rr.w - 38, rr.y, 38, 38}, .Remove, "remove", 12, e.srv_n > 1) {
			remove = i
		}
		gap(app, 10)
		rr = inner(app, 16)
		pw: i32 = 84
		ui.text(u, ui.ST_LABEL, rr.x, rr.y, "Port", ui.MUTED)
		ui.text(u, ui.ST_LABEL, rr.x + pw + 12, rr.y, "Transport", ui.MUTED)
		gap(app, 6)
		probe := inner(app, 0)
		if changed, _ := ui.field(u, {probe.x, probe.y, pw, ui.FIELD_H}, &row.port, "", {mono = true, enabled = true}); changed {
			e.dirty = true
		}
		labels := TRANSPORT_LABEL
		if k := choices(app, slice.enumerated_array(&labels), int(row.proto), pw + 12); k >= 0 {
			old := tprint("%d", pf.transport_default_port(TRANSPORT_NAME[row.proto]))
			if strings.trim_space(ui.field_text(&row.port)) == old {
				ui.field_set(&row.port, tprint("%d", pf.transport_default_port(TRANSPORT_NAME[Transport(k)])))
			}
			row.proto = Transport(k)
			e.dirty = true
		}
		if err := server_error(e, i); err != "" && (e.srv_tried || ui.field_text(&row.host) != "") {
			field_error(app, err)
		}
		mu.pop_id(&u.ctx)
	}
	if remove >= 0 {
		server_remove(e, remove)
		e.dirty = true
	}
	gap(app, 12)
	rr = inner(app, 35)
	bw := i32(math.ceil(ui.button_width(u, "Add server", .Secondary)))
	if ui.button(u, {rr.x, rr.y, bw, 35}, "Add server", .Secondary, e.srv_n < MAX_SERVERS, ui.SURFACE) {
		server_add(e)
		e.dirty = true
	}
	if e.srv_custom {
		label := "Use the servers of the profile"
		rw := i32(math.ceil(ui.button_width(u, label, .Ghost)))
		if ui.button(u, {rr.x + rr.w - rw, rr.y, rw, 35}, label, .Ghost, true, ui.SURFACE) {
			if _, text, ok := pf.store_load(app.store, e.id, context.temp_allocator); ok {
				orig, _ := pf.summarize(text, context.temp_allocator)
				servers_load(e, orig.remotes[:])
				e.dirty = true
			}
		}
	}
	mu.pop_id(&u.ctx)
}

// list_editor draws an editable list of short texts with Remove and Add buttons.
list_editor :: proc(app: ^App, k: List_Kind, title, hint, placeholder, add: string) {
	u := &app.u
	e := &app.edit
	rr := inner(app, 17)
	ui.text(u, ui.ST_BODY, rr.x, rr.y, title, ui.TEXT)
	gap(app, 6)
	rr = inner(app, 16)
	ui.text(u, ui.ST_CAPTION, rr.x, rr.y, hint, ui.MUTED)
	gap(app, 6)
	remove := -1
	mu.push_id(&u.ctx, uintptr(k) + 100)
	for i in 0 ..< e.n[k] {
		mu.push_id(&u.ctx, uintptr(i))
		err := list_error(e, k, i)
		gap(app, 3)
		rr = inner(app, 38)
		if changed, _ := ui.field(u, {rr.x, rr.y, rr.w - 38 - 6, 38}, &e.lists[k][i], placeholder, {mono = true, enabled = true, error = err != ""}); changed {
			e.dirty = true
		}
		if ui.box_button(u, {rr.x + rr.w - 38, rr.y, 38, 38}, .Remove, "remove", 12, true) {
			remove = i
		}
		gap(app, 3)
		if err != "" {
			gap(app, 2)
			rr = inner(app, 16)
			ui.text(u, ui.ST_CAPTION, rr.x, rr.y, err, ui.ERROR)
			gap(app, 2)
		}
		mu.pop_id(&u.ctx)
	}
	if remove >= 0 {
		list_remove(e, k, remove)
		e.dirty = true
	}
	gap(app, 6 + 2)
	rr = inner(app, 35)
	bw := i32(math.ceil(ui.button_width(u, add, .Secondary)))
	if ui.button(u, {rr.x, rr.y, bw, 35}, add, .Secondary, e.n[k] < MAX_DOMAINS, ui.SURFACE) {
		list_add(e, k, "")
		e.dirty = true
	}
	mu.pop_id(&u.ctx)
}

// setting_row is a line of text with a switch on the right. It returns the
// rectangle of the switch.
setting_row :: proc(app: ^App, label: string, on: ^bool, enabled := true) -> mu.Rect {
	u := &app.u
	probe := inner(app, 0)
	tw := f32(probe.w - 12 - 40)
	lines := ui.wrap_text(u, ui.ST_BODY, label, tw)
	rh := max(i32(len(lines)) * 17, 32)
	rr := inner(app, rh)
	ty := rr.y + (rh - i32(len(lines)) * 17) / 2
	for l, i in lines {
		ui.text(u, ui.ST_BODY, rr.x, ty + i32(i) * 17, l, ui.TEXT)
	}
	sw := mu.Rect{rr.x + rr.w - 40, rr.y, 40, rh}
	if ui.toggle(u, sw, label, on, enabled) {
		app.edit.dirty = true
	}
	return sw
}

// DCO_UI shows the Use DCO switch and the notes of the data path: DCO is
// Linux only. -define:DCO_UI=true shows them elsewhere, for the screenshots.
DCO_UI :: ODIN_OS == .Linux || #config(DCO_UI, false)

DCO_CAPTION :: "Data channel offload: the kernel or the DCO service handles packet transmission."

// dco_row is the Use DCO switch of the overrides. Off adds disable-dco after the
// profile text (data path in the service process). On uses DCO if the service
// has it. If the service runs without DCO, the switch is off and disabled and
// the profile's choice stays: a profile cannot turn DCO on.
dco_row :: proc(app: ^App) {
	e := &app.edit
	group_sep(app)
	on, enabled := dco_switch(app)
	if e.dco_in_text {
		value_row(app, "Use DCO", "Off in the profile file", ui.MUTED)
	} else if enabled {
		e.dco_at = setting_row(app, "Use DCO", &e.use_dco)
	} else {
		e.dco_at = setting_row(app, "Use DCO", &on, false)
	}
	gap(app, 6)
	group_caption(app, DCO_CAPTION)
	if !e.dco_in_text && dco_service_off(app) {
		gap(app, 4)
		group_caption(app, DCO_SERVICE_OFF, ui.WARN)
	}
}

// dco_service_off is true when the service runs without DCO (datapath
// userspace in its config).
dco_service_off :: proc(app: ^App) -> bool {
	return app.link.service && app.link.datapath_mode == "userspace"
}

// dco_switch is what the Use DCO switch shows: the choice of the profile, or
// off and disabled when the service runs without DCO.
dco_switch :: proc(app: ^App) -> (on: bool, enabled: bool) {
	if dco_service_off(app) {
		return false, false
	}
	return app.edit.use_dco, true
}

// DCO_SERVICE_OFF says why a profile with Use DCO on runs without DCO: the
// service setting.
DCO_SERVICE_OFF :: "DCO is disabled in the noirvpn service. A profile cannot enable it."

// dco_note is the note under the details of a live tunnel that runs without
// DCO although its profile has Use DCO on. "" when there is nothing to say.
dco_note :: proc(app: ^App) -> string {
	l := &app.link
	c := &app.conn
	if !l.service || c.datapath != "userspace" {
		return ""
	}
	i := c.profile
	if i >= 0 && i < app.n_profiles && app.profiles[i].source == .Stored {
		for m in app.metas {
			if m.id == app.profiles[i].id && m.overrides.no_dco {
				return ""
			}
		}
	}
	if l.datapath_mode == "userspace" {
		return DCO_SERVICE_OFF
	}
	return "DCO is not available for this connection. See service log for why."
}

