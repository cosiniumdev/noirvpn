// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Connection view: top bar, main card (state, graph, rates), details, DNS and
// route cards or the sign-in form, bottom bar. It shows one row (App.shown);
// only the tunnel's row shows its phase.

import "core:math"
import "core:strings"
import mu "vendor:microui"
import pf "profiles"
import "ui"

CONN_CARD_H :: 212
CARD_GAP :: 14
PULSE_PERIOD :: 2.4 // seconds of one pulse of the state text
PULSE_GAP :: 1.0 / 15 // seconds between two frames of the pulse: the fade is slow, so 15 frames a second look smooth

// pill_for is the text and tone of the state text.
pill_for :: proc(p: Phase) -> (label: string, tone: ui.Tone) {
	switch p {
	case .Connecting:
		return "connecting", .Warn
	case .Handshake:
		return "handshake", .Warn
	case .Credentials, .Web_Sign_In:
		return "sign in needed", .Warn
	case .Up:
		return "connected", .Ok
	case .Disconnected:
		return "disconnected", .Neutral
	case .Stopped:
		return "stopped", .Neutral
	case .Failed:
		return "error", .Error
	case .Closing:
		return "disconnecting", .Neutral
	}
	return "", .Neutral
}

// state_alpha is the opacity (0 to 1) of the state text at time now. While the
// tunnel is being set up it pulses slowly between 0.55 and 1.
state_alpha :: proc(p: Phase, now: f64) -> f32 {
	if phase_busy(p) {
		k := 0.5 + 0.5 * math.cos(f32(math.mod(now, PULSE_PERIOD) / PULSE_PERIOD) * 2 * math.PI)
		return 0.55 + 0.45 * k
	}
	return 1
}

// transport_label is the transport of a profile in upper case.
transport_label :: proc(p: ^Profile) -> string {
	return strings.to_upper(p.proto, context.temp_allocator)
}

// conn_transport is the transport the service reports, else the one of the profile.
conn_transport :: proc(app: ^App) -> string {
	if app.conn.proto != "" && shown_is_tunnel(app) {
		return strings.to_upper(app.conn.proto, context.temp_allocator)
	}
	return transport_label(&app.profiles[app.shown])
}

// conn_server is the "host:port" text of the top bar.
conn_server :: proc(p: ^Profile) -> string {
	if p.port == 0 {
		return p.host
	}
	return tprint("%s:%d", p.host, p.port)
}

view_connection :: proc(app: ^App) {
	u := &app.u
	c := &app.conn
	w, h := u.size.x, u.size.y
	p := &app.profiles[app.shown]

	if app.link.kind == .Sim {
		conn_tick(c, app.now)
	}
	phase := shown_phase(app)
	res := topbar(app, {back = !conn_locked(app), title = p.name, server = conn_server(p), flat = true})
	if res.back {
		pop_view(app)
		return
	}

	show_bar := phase != .Credentials && phase != .Web_Sign_In
	bar_h := big_button_bar_h()
	area_h := h - ui.TOPBAR_H - (show_bar ? bar_h : 0)

	logo_shade(app, {0, ui.TOPBAR_H, w, area_h})
	scroll_begin(app, "conn", {0, ui.TOPBAR_H, w, area_h})
	conn_card(app, row(app, CONN_CARD_H, ui.CARD_MARGIN), phase)
	conn_notes(app, phase)
	gap(app, CARD_GAP)
	switch phase {
	case .Credentials:
		credentials_panel(app)
	case .Web_Sign_In:
		web_panel(app)
	case .Up:
		telemetry(app)
		inbound_card(app, CARD_GAP)
		more_cards(app, true)
		tunnel_cards(app)
	case .Connecting, .Handshake, .Disconnected, .Stopped, .Failed, .Closing:
		inbound_card(app, 0)
		more_cards(app, false)
	}
	gap(app, 24)
	scroll_end(app)

	if show_bar {
		conn_bar(app, phase, {0, h - bar_h, w, bar_h})
	}
}

// conn_bar is the bottom bar: the connect button, then Edit and Settings.
conn_bar :: proc(app: ^App, phase: Phase, br: mu.Rect) {
	u := &app.u
	ui.bar(u, br)
	text, kind, enabled := "Connect", ui.Button_Kind.Primary, true
	switch {
	case phase == .Up:
		text, kind = "Disconnect", .Secondary
	case phase_busy(phase):
		text, kind = "Cancel", .Secondary
	case phase == .Closing:
		text, kind, enabled = "Disconnecting", .Secondary, false
	}
	bh := br.h - 1 - 32
	y := br.y + 1 + 16
	gear := mu.Rect{br.w - ui.CARD_MARGIN - bh, y, bh, bh}
	edit := mu.Rect{gear.x - 8 - bh, y, bh, bh}
	if ui.button(u, {ui.CARD_MARGIN, y, edit.x - 8 - ui.CARD_MARGIN, bh}, text, kind, enabled, ui.SURFACE) {
		if text == "Connect" {
			row_connect(app, app.shown)
		} else {
			link_disconnect(app)
		}
	}
	if ui.box_button(u, edit, .Edit, "edit", 16, app.profiles[app.shown].source != .Daemon) {
		open_profile(app, app.shown)
	}
	if ui.box_button(u, gear, .Gear, "app settings", 16) {
		push_view(app, .Settings)
	}
}

// conn_card draws the main card: state, padlock, transport, rate matrix, rates,
// duration. While connected it has a green border and glow.
conn_card :: proc(app: ^App, r: mu.Rect, phase: Phase) {
	u := &app.u
	c := &app.conn
	ui.card(u, r, phase == .Up)

	label, tone := pill_for(phase)
	state := ui.Rectf{f32(r.x) + (f32(r.w) - ui.PILL_W) / 2, f32(r.y + 11), ui.PILL_W, ui.PILL_H}
	ui.state_text(u, state, label, tone, state_alpha(phase, app.now))
	if phase == .Up {
		ui.emit(u, {kind = .Icon, r = {f32(r.x + 18), f32(r.y + 17), 20, 20}, icon = .Lock, c1 = ui.PILL_OK_BORDER}, 0)
	}

	transport := conn_transport(app)
	tw := i32(math.ceil(ui.text_w(u, ui.ST_TRANSPORT, transport)))
	ui.text(u, ui.ST_TRANSPORT, r.x + r.w - 18 - tw, r.y + 13, transport, ui.TRANSPORT)

	// The rate matrix, with the scale on a small dark backing at its top left.
	plot := mu.Rect{r.x + 18, r.y + 62, r.w - 36, 78}
	have_data := phase == .Up && c.count >= 2
	if have_data {
		mx: f32
		for i in 0 ..< c.count {
			mx = max(mx, c.down[i], c.up[i])
		}
		app.graph = {c.down[:c.count], c.up[:c.count], ui.nice_max(mx)}
		ui.rate_graph(u, plot, &app.graph)
		axis := fmt_axis(app.graph.max)
		aw := math.ceil(ui.text_w(u, ui.ST_GRAPH, axis))
		ah := math.ceil(ui.line_height(ui.ST_GRAPH))
		ui.emit(u, {kind = .Rrect, r = {f32(plot.x), f32(plot.y), aw + 8, ah + 2}, radius = 4, c1 = ui.GRAPH_SCALE_BG})
		ui.text(u, ui.ST_GRAPH, plot.x + 4, plot.y + 1, axis, ui.GRAPH_LABEL)
	} else {
		note := "Waiting for the tunnel"
		switch phase {
		case .Up:
			note = "Collecting data"
		case .Credentials, .Web_Sign_In:
			note = "Waiting for sign-in"
		case .Disconnected, .Stopped, .Failed, .Closing:
			note = "No tunnel"
		case .Connecting, .Handshake:
		}
		centered(u, ui.ST_CAPTION, note, plot.y + plot.h / 2 - 8, r.x * 2 + r.w, ui.MUTED)
	}
	ly := r.y + 144
	ui.text(u, ui.ST_GRAPH, plot.x, ly, "60s ago", ui.GRAPH_LABEL)
	nw := i32(math.round(ui.text_w(u, ui.ST_GRAPH, "now")))
	ui.text(u, ui.ST_GRAPH, plot.x + plot.w - nw, ly, "now", ui.GRAPH_LABEL)
	ui.hline(u, r.x + 13, r.y + 162, r.w - 26, ui.CARD_RULE)

	// Down and Up at the left, the duration right-aligned.
	last := max(c.count - 1, 0)
	inner_w := r.w - 36
	cols := [2]struct {
		x:     i32,
		label: string,
		col:   ui.Color,
		val:   f32,
	}{{r.x + 18, "Down", ui.STAT_DOWN, c.down[last]}, {r.x + 18 + i32(f32(inner_w) * 0.37), "Up", ui.STAT_UP, c.up[last]}}
	dur := phase == .Up ? fmt_duration(app.now - c.up_start) : "—"
	dw := i32(math.ceil(max(ui.text_w(u, ui.ST_STAT, dur), ui.text_w(u, ui.ST_STAT_LABEL, "Duration"))))
	right := r.x + r.w - 18
	for col, i in cols {
		value := "—"
		if phase == .Up && c.count > 0 {
			value = fmt_rate(col.val)
		}
		limit := (cols[1].x if i == 0 else right - dw) - 10 - col.x
		ui.text(u, ui.ST_STAT_LABEL, col.x, r.y + 169, col.label, ui.STAT_LABEL)
		ui.text(u, ui.ST_STAT, col.x, r.y + 184, ui.fit_text(u, ui.ST_STAT, value, f32(limit)), col.col)
	}
	lw := i32(math.ceil(ui.text_w(u, ui.ST_STAT_LABEL, "Duration")))
	ui.text(u, ui.ST_STAT_LABEL, right - lw, r.y + 169, "Duration", ui.STAT_LABEL)
	vw := i32(math.ceil(ui.text_w(u, ui.ST_STAT, dur)))
	ui.text(u, ui.ST_STAT, right - vw, r.y + 184, dur, ui.TEXT)
}

// centered draws s centered in the width w.
centered :: proc(u: ^ui.UI, st: ui.Text_Style, s: string, y: i32, w: i32, c: ui.Color) {
	tw := ui.text_w(u, st, s)
	ui.text(u, st, i32(math.round((f32(w) - tw) / 2)), y, s, c)
}

// conn_notes draws the attempt number and the last failure below the main card.
conn_notes :: proc(app: ^App, phase: Phase) {
	u := &app.u
	c := &app.conn
	w := u.size.x
	attempt_text := ""
	if (phase_busy(phase) || phase == .Credentials || phase == .Web_Sign_In) && c.attempt >= 1 {
		attempt_text = tprint("Attempt %d", c.attempt)
	}
	fail_lines: []string
	switch {
	case app.link.error != "":
		fail_lines = ui.wrap_text(u, ui.ST_BODY, app.link.error, f32(w - 2 * ui.CARD_MARGIN))
	case c.failure != "" && (phase_busy(phase) || phase == .Failed || phase == .Credentials || phase == .Web_Sign_In):
		fail_lines = ui.wrap_text(u, ui.ST_BODY, tprint("Last failure: %s", c.failure), f32(w - 2 * ui.CARD_MARGIN))
	}
	if attempt_text == "" && len(fail_lines) == 0 {
		return
	}
	gap(app, 10)
	if attempt_text != "" {
		r := row(app, 16, 0)
		centered(u, ui.ST_CAPTION, attempt_text, r.y, w, ui.MUTED)
	}
	for line in fail_lines {
		gap(app, 4)
		r := row(app, 17, 0)
		centered(u, ui.ST_BODY, line, r.y, w, ui.ERROR)
	}
}

credentials_panel :: proc(app: ^App) {
	u := &app.u
	c := &app.conn
	l := &app.link
	w := u.size.x
	key := l.auth_kind == "key_pass"
	title := "Sign in"
	hint := "The server is asking for your user name and password."
	switch {
	case key && l.auth_reason == "key_pass_wrong":
		title, hint = "Key passphrase", "That passphrase does not unlock the key. Try again."
	case key:
		title, hint = "Key passphrase", "The private key of this profile is encrypted, so enter its passphrase to continue."
	case l.auth_reason == "auth_failed":
		hint = "The server did not accept the login. Check your user name and password."
	}
	inner_w := f32(w - 2 * ui.CARD_MARGIN - 2 - 32)
	hint_lines := ui.wrap_text(u, ui.ST_BODY, hint, inner_w)
	note_lines := ui.wrap_text(u, ui.ST_BODY, l.auto_note, inner_w) if l.auto_note != "" else nil
	fields: i32 = key ? 1 : 2
	total_h: i32 = 1 + 16 + 19 + 12 + i32(len(hint_lines)) * 17 + 12 + fields * (32 + 12) + 35 + 16 + 1
	if len(note_lines) > 0 {
		total_h += i32(len(note_lines)) * 17 + 12
	}
	r := row(app, total_h, ui.CARD_MARGIN)
	ui.card_flat(u, r)
	x := r.x + 17
	cw := r.w - 34
	y := r.y + 17
	ui.text(u, ui.ST_HEADING, x, y, title, ui.TEXT)
	y += 19 + 12
	for line in hint_lines {
		ui.text(u, ui.ST_BODY, x, y, line, ui.MUTED)
		y += 17
	}
	if len(note_lines) > 0 {
		y += 12
		for line in note_lines {
			ui.text(u, ui.ST_BODY, x, y, line, ui.WARN)
			y += 17
		}
	}
	y += 12
	sub1, sub2: bool
	if !key {
		_, sub1 = ui.field(u, {x, y, cw, 32}, &c.user, "User name", {enabled = true, plain = true})
		y += 32 + 12
	}
	_, sub2 = ui.field(u, {x, y, cw, 32}, &c.pass, key ? "Passphrase" : "Password", {enabled = true, password = true, plain = true})
	y += 32 + 12
	bw := (cw - 8) / 2
	signin := ui.button(u, {x, y, bw, 35}, key ? "Continue" : "Sign in", .Primary, true, ui.SURFACE)
	cancel := ui.button(u, {x + bw + 8, y, cw - bw - 8, 35}, "Cancel", .Secondary, true, ui.SURFACE)
	if signin || sub1 || sub2 {
		link_auth_supply(app)
	}
	if cancel {
		link_disconnect(app)
	}
}

// telemetry draws the details card of a live tunnel. Duration and transport are
// in the main card. Data path: on Linux the kernel module, the DCO service or
// the service process.
telemetry :: proc(app: ^App) {
	u := &app.u
	c := &app.conn
	dash :: proc(s: string) -> string {
		return s if s != "" else "–"
	}
	rows := [7][2]string {
		{"Received", tprint("%s  ·  %d packets", fmt_bytes(c.rx_bytes), c.rx_packets)},
		{"Sent", tprint("%s  ·  %d packets", fmt_bytes(c.tx_bytes), c.tx_packets)},
		{"Your address", dash(c.address)},
		{"Server address", dash(c.peer4)},
		{"Cipher", dash(c.cipher)},
		{"Data format", dash(c.data_format)},
		{"Data path", dash(datapath_label(c.datapath))},
	}
	ir := row(app, 1 + 8 + i32(len(rows)) * 27 + 8 + 1, ui.CARD_MARGIN)
	ui.card_flat(u, ir)
	for kv, i in rows {
		y := ir.y + 9 + 5 + i32(i) * 27
		ui.text(u, ui.ST_BODY, ir.x + 16, y, kv[0], ui.MUTED)
		ui.text(u, ui.ST_BODY, ir.x + 16 + ui.LABEL_W, y, ui.fit_text(u, ui.ST_BODY, kv[1], f32(ir.w - 16 - ui.LABEL_W - 12)), ui.TEXT)
	}
	when DCO_UI {
		if note := dco_note(app); note != "" {
			gap(app, 6)
			probe := row(app, 0, ui.CARD_MARGIN)
			for line in ui.wrap_text(u, ui.ST_CAPTION, note, f32(probe.w - 32)) {
				r := row(app, 16, ui.CARD_MARGIN)
				ui.text(u, ui.ST_CAPTION, r.x + 16, r.y, line, ui.WARN)
			}
		}
	}
}

// more_cards draws the Show more button and, when open: while up, the tunnel
// numbers and pushed options, then the log card; else the log card only.
more_cards :: proc(app: ^App, up: bool) {
	u := &app.u
	c := &app.conn
	l := &app.link
	gap(app, 6)
	label := app.conn_more ? "Show less" : "Show more"
	r := row(app, 35, ui.CARD_MARGIN)
	bw := i32(math.ceil(ui.button_width(u, label, .Ghost)))
	if ui.button(u, {r.x + (r.w - bw) / 2, r.y, bw, 35}, label, .Ghost, true, ui.BG) {
		app.conn_more = !app.conn_more
	}
	if !app.conn_more {
		return
	}
	gap(app, 6)

	// Tunnel and pushed options.
	if up && c.settings_ok {
		mss := "Off"
		if c.mss4 > 0 {
			mss = tprint("%d  ·  IPv6 %d", c.mss4, c.mss6)
		}
		lines := [?]Kv {
			{label = "MTU", value = c.mtu > 0 ? tprint("%d", c.mtu) : "–"},
			{label = "TCP MSS", value = mss},
			{label = "Peer ID", value = c.peer_id >= 0 ? tprint("%d", c.peer_id) : "–"},
		}
		kv_card(app, "Tunnel", lines[:])
		if len(c.pushed) > 0 {
			gap(app, CARD_GAP)
			pushed := make([]Kv, len(c.pushed), context.temp_allocator)
			for p, i in c.pushed {
				pushed[i] = Kv{value = p}
			}
			kv_card(app, "Pushed options", pushed, mono = true)
		}
		gap(app, CARD_GAP)
	}

	// Log.
	hr := row(app, 18, ui.CARD_MARGIN)
	ui.text(u, ui.ST_SECTION, hr.x + 2, hr.y, "SERVICE LOG", ui.MUTED)
	gap(app, 4)
	place := "Standard error of the service"
	switch {
	case l.log_file != "":
		place = l.log_file
	case l.log_journal || app.link.kind == .Sim:
		place = "System journal (journalctl)"
	}
	ir := row(app, 1 + 12 + 35 + 12 + 1, ui.CARD_MARGIN)
	ui.card_flat(u, ir)
	cw := l.log_file != "" ? i32(math.ceil(ui.button_width(u, "Copy", .Secondary))) : 0
	tx := ir.x + 16
	tw := ir.w - 16 - 12 - (cw > 0 ? cw + 10 : 0)
	st := l.log_file != "" ? ui.ST_MONO : ui.ST_BODY
	ui.text(u, st, tx, ir.y + 1 + 12 + 9, ui.fit_text(u, st, place, f32(tw)), ui.TEXT)
	if cw > 0 && ui.button(u, {ir.x + ir.w - 12 - cw, ir.y + 1 + 12, cw, 35}, "Copy", .Secondary, true, ui.CARD_FLAT) {
		copy_text(app, l.log_file)
	}
	gap(app, CARD_GAP)
}

// Kv is one line of a card: a label (or "") and a value, bold when it comes
// from the overrides of the user.
Kv :: struct {
	label: string,
	value: string,
	own:   bool,
	muted: string, // a second value at the right, or ""
}

// row_overrides are the overrides of row i: from meta.json for a stored row,
// a sample for the simulated Work VPN row.
row_overrides :: proc(app: ^App, i: int) -> pf.Overrides {
	p := &app.profiles[i]
	switch p.source {
	case .Stored:
		for m in app.metas {
			if m.id == p.id {
				return m.overrides
			}
		}
	case .Sample:
		if i == 2 {
			return sample_overrides()
		}
	case .Daemon:
	}
	return {}
}

// sample_overrides are the overrides of the simulated Work VPN row.
sample_overrides :: proc() -> pf.Overrides {
	@(static) o: pf.Overrides
	if len(o.dns_servers) == 0 {
		append(&o.dns_servers, "9.9.9.9")
		append(&o.domains, "lab.example.org")
		o.block_ipv6 = true
	}
	return o
}

// tunnel_cards draws the DNS and route cards of a live tunnel. Entries from the
// user's overrides are bold. They are drawn when the service sent settings
// for this connection.
tunnel_cards :: proc(app: ^App) {
	c := &app.conn
	if !c.settings_ok {
		return
	}
	o := row_overrides(app, app.shown)
	gap(app, CARD_GAP)
	kv_card(app, "DNS", dns_lines(c, o))
	gap(app, CARD_GAP)
	kv_card(app, "Routes", route_lines(c, o))
}

// dns_lines are the lines of the DNS card (temp allocator). The service lists
// local DNS lines with the pushed ones, so an overridden entry is bold where it
// is in that list; an override missing there comes after it, bold.
dns_lines :: proc(c: ^Conn, o: pf.Overrides) -> []Kv {
	dns := make([dynamic]Kv, context.temp_allocator)
	has :: proc(list: []string, s: string) -> bool {
		for e in list {
			if strings.equal_fold(e, s) {
				return true
			}
		}
		return false
	}
	label := "Servers"
	for s in c.dns_servers {
		append(&dns, Kv{label = label, value = s, own = has(o.dns_servers[:], s)})
		label = ""
	}
	for s in o.dns_servers {
		if !has(c.dns_servers[:], s) {
			append(&dns, Kv{label = label, value = s, own = true})
			label = ""
		}
	}
	if label != "" {
		append(&dns, Kv{label = label, value = "–"})
	}
	label = "Domains"
	for s in c.dns_domains {
		append(&dns, Kv{label = label, value = s, own = has(o.domains[:], s)})
		label = ""
	}
	for s in o.domains {
		if !has(c.dns_domains[:], s) {
			append(&dns, Kv{label = label, value = s, own = true})
			label = ""
		}
	}
	if o.ignore_server_dns {
		append(&dns, Kv{label = "Server DNS", value = "Not used", own = true})
	}
	return dns[:]
}

// route_lines are the lines of the Routes card, in the temp allocator.
route_lines :: proc(c: ^Conn, o: pf.Overrides) -> []Kv {
	routes := make([dynamic]Kv, context.temp_allocator)
	if c.redirect {
		append(&routes, Kv{value = "All traffic", muted = c.peer4 != "" ? tprint("via %s", c.peer4) : ""})
	}
	if o.kill_switch {
		append(&routes, Kv{value = "Blocked when the VPN is down", own = true})
	} else if o.ignore_redirect {
		append(&routes, Kv{value = "All traffic: not sent", own = true})
	}
	if o.block_ipv6 {
		append(&routes, Kv{value = "IPv6: blocked", own = true})
	}
	for r in c.routes {
		append(&routes, Kv{value = r.net, muted = r.gateway != "" ? tprint("via %s", r.gateway) : ""})
	}
	if len(routes) == 0 {
		append(&routes, Kv{value = "None"})
	}
	return routes[:]
}

// kv_card draws a heading and a flat card with one line for each entry.
kv_card :: proc(app: ^App, title: string, lines: []Kv, mono := false) {
	u := &app.u
	hr := row(app, 18, ui.CARD_MARGIN)
	ui.text(u, ui.ST_SECTION, hr.x + 2, hr.y, strings.to_upper(title, context.temp_allocator), ui.MUTED)
	gap(app, 4)
	LINE_H :: 25
	ir := row(app, 1 + 8 + i32(len(lines)) * LINE_H + 8 + 1, ui.CARD_MARGIN)
	ui.card_flat(u, ir)
	has_labels := false
	for kv in lines {
		has_labels ||= kv.label != ""
	}
	vx := ir.x + 16 + (has_labels ? ui.LABEL_W : 0)
	for kv, i in lines {
		y := ir.y + 9 + 4 + i32(i) * LINE_H
		if kv.label != "" {
			ui.text(u, ui.ST_BODY, ir.x + 16, y, kv.label, ui.MUTED)
		}
		right := ir.x + ir.w - 12
		if kv.muted != "" {
			half := f32(right - vx) / 2
			m := ui.fit_text(u, ui.ST_BODY, kv.muted, half)
			mx := right - i32(math.ceil(ui.text_w(u, ui.ST_BODY, m)))
			ui.text(u, ui.ST_BODY, mx, y, m, ui.MUTED)
			right = mx - 10
		}
		st := kv.own ? ui.ST_BODY_BOLD : ui.ST_BODY
		if mono {
			st = ui.ST_MONO
		}
		ui.text(u, st, vx, y + (mono ? 1 : 0), ui.fit_text(u, st, kv.value, f32(right - vx)), kv.own ? ui.TEXT_STRONG : ui.TEXT)
	}
}
