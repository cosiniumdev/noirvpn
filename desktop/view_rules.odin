// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Inbound rules view: the allow-inbound and forward rules in force (acl.get),
// the connections that the filter blocked (acl.deny), the config file of the
// service with Check and reload (acl.reload), the lines of the profile, and a
// builder of lines to copy into a file. The link part is in link.odin.
//
//   inbound_card     the card of the connection view, with Open
//   rules_open       Open: the view, and a read of acl.get
//   rule_line        the line of the builder, checked by config.acl_line_problem
//   rules_from_block Allow of a blocked connection fills the builder

import "core:c/libc"
import "core:math"
import "core:mem"
import "core:slice"
import "core:strings"
import mu "vendor:microui"
import "noir:proto/config"
import pf "profiles"
import "ui"

Rule_Kind :: enum u8 {
	Allow,
	Forward,
}

Allow_Proto :: enum u8 {
	Any,
	Tcp,
	Udp,
	Icmp,
}

Fwd_Proto :: enum u8 {
	Tcp,
	Udp,
	Both,
}

RULE_KIND_LABEL := [Rule_Kind]string {
	.Allow   = "Allow inbound",
	.Forward = "Forward",
}
ALLOW_PROTO_LABEL := [Allow_Proto]string {
	.Any  = "Any",
	.Tcp  = "TCP",
	.Udp  = "UDP",
	.Icmp = "ICMP",
}
ALLOW_PROTO_WORD := [Allow_Proto]string {
	.Any  = "",
	.Tcp  = "tcp",
	.Udp  = "udp",
	.Icmp = "icmp",
}
FWD_PROTO_LABEL := [Fwd_Proto]string {
	.Tcp  = "TCP",
	.Udp  = "UDP",
	.Both = "Both",
}
// TCP is the default protocol of a forward and needs no word.
FWD_PROTO_WORDS := [Fwd_Proto]string {
	.Tcp  = "",
	.Udp  = " udp",
	.Both = " tcp udp",
}

// The first allow-inbound line starts the default deny; this one lets ping in.
BLOCK_ALL_BUT_PING :: "allow-inbound 0.0.0.0/0 ::/0 icmp"
RULE_LINES_MAX :: 32
SAMPLE_CONFIG_PATH :: "/etc/noirvpn/desktop.conf"

// The state of the view that is not the state of the service: the builder,
// the lines to copy, and the profile lines of the shown row.
Rules_View :: struct {
	kind:          Rule_Kind,
	proto:         Allow_Proto,
	fproto:        Fwd_Proto,
	addr:          ui.Field,
	port:          ui.Field,
	fport:         ui.Field,
	fhost:         ui.Field,
	ftport:        ui.Field,
	lines:         [dynamic]string, // the lines to copy
	checked:       string, // the last line that acl_line_problem checked
	problem:       string, // its problem, or ""
	builder_y:     i32, // the builder in the scroll area, set by the view
	blocked_y:     i32, // RECENTLY BLOCKED, for the screenshots
	config_y:      i32, // CONFIG FILE, for the screenshots
	jump:          bool, // scroll to the builder at the next frame
	row:           int, // the profile row of PROFILE
	profile:       bool, // that row has a profile text
	profile_lines: [dynamic]string,
	profile_next:  f64, // when to read the profile text again
	file_note:     string, // the result of Open file or Show in folder
	// Set by the views, for the tests.
	card_at:       mu.Rect, // Open of the card in the connection view, {} when hidden
	edit_at:       mu.Rect, // Edit profile of PROFILE
	reload_at:     mu.Rect,
	allow_at:      mu.Rect, // Allow of the newest blocked connection
	add_at:        mu.Rect,
	ping_at:       mu.Rect, // Block all but ping
	copy_all_at:   mu.Rect,
	add_on:        bool, // Add is enabled
	rows_drawn:    int, // rules and forwards drawn in IN FORCE
}

rules_init :: proc(r: ^Rules_View) {
	for f in ([5]^ui.Field{&r.addr, &r.port, &r.fport, &r.fhost, &r.ftport}) {
		ui.field_init(f)
	}
}

// rules_reset gives the builder its defaults and empties the lines to copy.
rules_reset :: proc(r: ^Rules_View) {
	r.kind, r.proto, r.fproto = .Allow, .Any, .Tcp
	for f in ([5]^ui.Field{&r.addr, &r.port, &r.fport, &r.fhost, &r.ftport}) {
		ui.field_set(f, "")
	}
	for l in r.lines {
		delete(l)
	}
	clear(&r.lines)
	r.jump = false
	set_text(&r.file_note, "")
}

// acl_sample is the simulated state of the service: a filter from the
// config file, three rules, one forward and two blocked connections.
acl_sample :: proc(app: ^App) {
	a := &app.link.acl
	acl_clear(a)
	acl_blocked_clear(a)
	a.known, a.old = true, false
	a.filter = true
	set_text(&a.source, "config")
	a.denied = 12
	rule :: proc(dest, protos, addresses: string, host := false) -> Acl_Rule {
		return {dest = strings.clone(dest), protos = strings.clone(protos), host = host, addresses = strings.clone(addresses)}
	}
	append(&a.rules, rule(":22", "TCP", ""))
	append(&a.rules, rule("192.168.50.0/24", "TCP", ""))
	append(&a.rules, rule("nas.lan:445", "TCP, UDP", "192.168.50.10", true))
	append(&a.forwards, Acl_Forward{port = 8080, protos = strings.clone("TCP"), target = strings.clone("127.0.0.1:80")})
	acl_block_push(a, "icmp", "10.8.0.1", "10.8.0.6", 0, 1795048732)
	acl_block_push(a, "tcp", "10.8.0.1", "10.8.0.6", 3389, 1795048867)
	a.reload_wait = 0
	set_text(&a.reload_msg, "")
	set_text(&a.reload_note, "")
	a.reload_error = false
	set_text(&app.link.config, SAMPLE_CONFIG_PATH)
}

// rules_open shows the Inbound rules view and reads the rules. PROFILE shows
// the lines of `row`, or of the shown row.
rules_open :: proc(app: ^App, row := -1) {
	r := &app.rules
	r.row = row if row >= 0 else app.shown
	set_text(&r.file_note, "")
	r.profile_next = 0
	push_view(app, .Rules)
	app.link.acl.next = app.now + ACL_EVERY
	acl_read(app)
}

// rules_known is true when the connection view can show the card: the link
// knows the rules.
rules_known :: proc(app: ^App) -> bool {
	return app.link.acl.known
}

// acl_state_text is the line of the card: "Allowed" or "Rules only" with the
// count of the rules, then the count of the forwards.
acl_state_text :: proc(a: ^Acl) -> string {
	s := "Allowed"
	if a.filter {
		s = tprint("Rules only · %s", count_text(len(a.rules), "rule", "rules", "no rules"))
	}
	if n := len(a.forwards); n > 0 {
		s = tprint("%s · %s", s, count_text(n, "forward", "forwards", ""))
	}
	return s
}

// inbound_card is the card of the connection view with the state of the
// filter and the button to the Inbound rules view. `above` is the gap before
// it.
inbound_card :: proc(app: ^App, above: i32) {
	u := &app.u
	app.rules.card_at = {}
	if !rules_known(app) {
		return
	}
	gap(app, above)
	hr := row(app, 18, ui.CARD_MARGIN)
	ui.text(u, ui.ST_SECTION, hr.x + 2, hr.y, "INBOUND CONNECTIONS", ui.MUTED)
	gap(app, 4)
	ir := row(app, 1 + 12 + 35 + 12 + 1, ui.CARD_MARGIN)
	ui.card_flat(u, ir)
	bw := i32(math.ceil(ui.button_width(u, "Open", .Secondary)))
	b := mu.Rect{ir.x + ir.w - 12 - bw, ir.y + 1 + 12, bw, 35}
	th := i32(ui.line_height(ui.ST_BODY))
	state := ui.fit_text(u, ui.ST_BODY, acl_state_text(&app.link.acl), f32(b.x - 10 - ir.x - 16))
	ui.text(u, ui.ST_BODY, ir.x + 16, b.y + (35 - th) / 2, state, ui.TEXT)
	app.rules.card_at = b
	mu.push_id(&u.ctx, "inbound")
	defer mu.pop_id(&u.ctx)
	if ui.button(u, b, "Open", .Secondary, true, ui.CARD_FLAT) {
		rules_open(app)
	}
}

// rules_profile_load reads the allow-inbound and forward lines of the profile
// of the shown row.
rules_profile_load :: proc(app: ^App) {
	r := &app.rules
	for l in r.profile_lines {
		delete(l)
	}
	clear(&r.profile_lines)
	r.profile = false
	r.profile_next = app.now + ACL_EVERY
	i := r.row
	if i < 0 || i >= app.n_profiles {
		return
	}
	p := &app.profiles[i]
	switch p.source {
	case .Stored:
		_, text, ok := pf.store_load(app.store, p.id, context.temp_allocator)
		if !ok {
			return
		}
		defer mem.zero_explicit(raw_data(text), len(text))
		r.profile = true
		for l in pf.acl_lines(text, context.temp_allocator) {
			append(&r.profile_lines, strings.clone(l))
		}
	case .Sample:
		r.profile = true
	case .Daemon:
	}
}

view_rules :: proc(app: ^App) {
	u := &app.u
	r := &app.rules
	a := &app.link.acl
	w, h := u.size.x, u.size.y
	res := topbar(app, {back = true, title = "Inbound rules", flat = true, simulated = app.link.kind == .Sim})
	if res.back {
		pop_view(app)
		return
	}
	if app.now >= r.profile_next {
		rules_profile_load(app)
	}
	nav_area_begin(app, "rules", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H})
	cnt := mu.get_current_container(&u.ctx)
	if r.jump {
		cnt.scroll.y = max(r.builder_y - 8, 0)
		r.jump = false
	}
	scroll_y := cnt.scroll.y
	gap(app, 14)
	rules_in_force(app)
	r.blocked_y = app.cy - app.nav.top + scroll_y
	if a.known && a.filter {
		rules_blocked(app)
	}
	r.config_y = app.cy - app.nav.top + scroll_y
	rules_config(app)
	if r.profile {
		rules_profile(app)
	}
	r.builder_y = app.cy - app.nav.top + scroll_y
	rules_builder(app)
	rules_copy_lines(app)
	gap(app, 6)
	nav_area_end(app)
}

// acl_row is one rule or forward: the destination in the mono face, the
// protocols at the right.
@(private = "file")
acl_row :: proc(app: ^App, left, right: string) {
	u := &app.u
	rr := inner(app, 23)
	pw := i32(math.ceil(ui.text_w(u, ui.ST_BODY, right)))
	ui.text(u, ui.ST_MONO, rr.x, rr.y + 3, ui.fit_text(u, ui.ST_MONO, left, f32(rr.w - pw - 12)), ui.TEXT)
	ui.text(u, ui.ST_BODY, rr.x + rr.w - pw, rr.y + 2, right, ui.MUTED)
	app.rules.rows_drawn += 1
}

@(private = "file")
rules_in_force :: proc(app: ^App) {
	u := &app.u
	l := &app.link
	a := &l.acl
	app.rules.rows_drawn = 0
	section(app, "IN FORCE")
	g, y0 := group_open(app)
	defer group_close(app, g, y0)
	switch {
	case a.old:
		group_caption(app, "This service does not report its rules.")
		return
	case !a.known:
		group_caption(app, "Reading the rules…")
		return
	}
	value_row(app, "Filter", a.filter ? "On" : "Off", ui.TEXT)
	gap(app, 2)
	group_caption(app, a.filter ? "Only the rules below permit new connections." : "All conections are permitted.")
	if a.filter && a.source != "" {
		gap(app, 8)
		value_row(app, "Source", a.source == "profile" ? "Profile" : "Service config", ui.TEXT)
	}
	if len(a.rules) > 0 {
		group_sep(app)
		field_label(app, "Rules")
		for &rule in a.rules {
			acl_row(app, rule.dest, rule.protos)
			if rule.host {
				rr := inner(app, 16)
				addrs := rule.addresses if rule.addresses != "" else "Not looked up yet"
				ui.text(u, ui.ST_CAPTION, rr.x, rr.y - 2, ui.fit_text(u, ui.ST_CAPTION, addrs, f32(rr.w)), ui.MUTED)
				gap(app, 2)
			}
		}
	}
	if len(a.forwards) > 0 {
		group_sep(app)
		field_label(app, "Forwards")
		for &f in a.forwards {
			protos, _ := strings.replace_all(f.protos, ", ", "/", context.temp_allocator)
			acl_row(app, tprint("%d %s → %s", f.port, protos, f.target), "")
		}
		if a.filter {
			gap(app, 4)
			group_caption(app, "A forward port also lets connections in.")
		}
	}
	if a.denied >= 0 {
		group_sep(app)
		value_row(app, "Blocked", count_text(int(a.denied), "packet", "packets", "None"), ui.TEXT)
	}
	if a.pending {
		gap(app, 10)
		group_caption(app, ACL_PENDING_TEXT, ui.WARN)
	}
	if a.profile_ignored > 0 {
		gap(app, 10)
		group_caption(app, "The service config sets its own rules, so the rules of the profile are not used.", ui.WARN)
	}
	if l.service && !l.loaded {
		gap(app, 10)
		group_caption(app, "A profile can add rules when the service config has none.")
	}
}

// proto_label is the protocol of an acl.deny event for the user.
@(private = "file")
proto_label :: proc(p: string) -> string {
	switch p {
	case "tcp":
		return "TCP"
	case "udp":
		return "UDP"
	case "icmp":
		return "ICMP"
	}
	return "Other"
}

// block_dest is the destination of a blocked connection, with its port.
@(private = "file")
block_dest :: proc(b: ^Acl_Block) -> string {
	if b.dport <= 0 {
		return b.dst
	}
	if strings.contains_rune(b.dst, ':') {
		return tprint("[%s]:%d", b.dst, b.dport)
	}
	return tprint("%s:%d", b.dst, b.dport)
}

// fmt_clock is a time in Unix seconds as local time: "14:32:05" for today,
// else with the date.
fmt_clock :: proc(t: i64) -> string {
	tt := libc.time_t(t)
	tm := libc.localtime(&tt)
	if tm == nil {
		return ""
	}
	day, year := tm.tm_yday, tm.tm_year
	hh, mm, ss := tm.tm_hour, tm.tm_min, tm.tm_sec
	now := libc.time(nil)
	tn := libc.localtime(&now)
	if tn != nil && tn.tm_yday == day && tn.tm_year == year {
		return tprint("%02d:%02d:%02d", hh, mm, ss)
	}
	return fmt_local_time(t)
}

@(private = "file")
rules_blocked :: proc(app: ^App) {
	u := &app.u
	a := &app.link.acl
	section(app, "RECENTLY BLOCKED")
	g, y0 := group_open(app)
	if a.n_blocked == 0 {
		rr := inner(app, 17)
		ui.text(u, ui.ST_BODY, rr.x, rr.y, "Nothing was blocked since the app started.", ui.MUTED)
	}
	allow := -1
	app.rules.allow_at = {}
	for i in 0 ..< a.n_blocked {
		b := &a.blocked[i]
		if i > 0 {
			gap(app, 10)
		}
		mu.push_id(&u.ctx, uintptr(600 + i))
		rr := inner(app, 36)
		bw := i32(math.ceil(ui.button_width(u, "Allow", .Secondary)))
		tw := rr.w - bw - 12
		pl := proto_label(b.proto)
		ui.text(u, ui.ST_ROW_PROTO, rr.x, rr.y + 1, pl, ui.TRANSPORT)
		px := rr.x + i32(math.ceil(ui.text_w(u, ui.ST_ROW_PROTO, pl))) + 8
		ui.text(u, ui.ST_MONO, px, rr.y + 1, ui.fit_text(u, ui.ST_MONO, block_dest(b), f32(rr.x + tw - px)), ui.TEXT)
		from := tprint("from %s · %s", b.src, fmt_clock(b.at))
		ui.text(u, ui.ST_CAPTION, rr.x, rr.y + 20, ui.fit_text(u, ui.ST_CAPTION, from, f32(tw)), ui.MUTED)
		ab := mu.Rect{rr.x + rr.w - bw, rr.y + 2, bw, 32}
		if i == 0 {
			app.rules.allow_at = ab
		}
		if ui.button(u, ab, "Allow", .Secondary, true, ui.SURFACE) {
			allow = i
		}
		mu.pop_id(&u.ctx)
	}
	if a.skipped > 0 {
		gap(app, 10)
		group_caption(app, tprint("%s not listed.", count_text(a.skipped, "more blocked connection is", "more blocked connections are", "")))
	}
	group_close(app, g, y0)
	if allow >= 0 {
		rules_from_block(app, a.blocked[allow])
	}
}

// tunnel_address is true when s is a tunnel address of this computer.
@(private = "file")
tunnel_address :: proc(app: ^App, s: string) -> bool {
	for part in strings.split(app.conn.address, ",", context.temp_allocator) {
		if p := strings.trim_space(part); p != "" && strings.equal_fold(p, s) {
			return true
		}
	}
	return false
}

// rules_from_block puts a blocked connection into the builder: the protocol,
// the port, and the destination address unless it is a tunnel address of
// this computer (the `:port` form follows those).
rules_from_block :: proc(app: ^App, b: Acl_Block) {
	r := &app.rules
	r.kind = .Allow
	addr, port := b.dst, ""
	switch b.proto {
	case "tcp", "udp":
		r.proto = b.proto == "tcp" ? .Tcp : .Udp
		if b.dport > 0 {
			port = tprint("%d", b.dport)
			if tunnel_address(app, b.dst) {
				addr = ""
			}
		}
	case "icmp":
		r.proto = .Icmp
	case:
		r.proto = .Any
	}
	ui.field_set(&r.addr, addr)
	ui.field_set(&r.port, port)
	r.jump = true
}

@(private = "file")
rules_config :: proc(app: ^App) {
	u := &app.u
	r := &app.rules
	l := &app.link
	a := &l.acl
	r.reload_at = {}
	section(app, "CONFIG FILE")
	g, y0 := group_open(app)
	defer group_close(app, g, y0)
	if l.config == "" {
		group_caption(app, "No config file.")
		return
	}
	_ = copy_row(app, "File", l.config, "acl-config")
	gap(app, 10)
	rr := inner(app, 35)
	ow := i32(math.ceil(ui.button_width(u, "Open file", .Secondary)))
	sw := i32(math.ceil(ui.button_width(u, "Show in folder", .Secondary)))
	if ui.button(u, {rr.x, rr.y, ow, 35}, "Open file", .Secondary, true, ui.SURFACE) {
		set_text(&r.file_note, path_action(app, l.config, false))
	}
	if ui.button(u, {rr.x + ow + 8, rr.y, sw, 35}, "Show in folder", .Secondary, true, ui.SURFACE) {
		set_text(&r.file_note, path_action(app, l.config, true))
	}
	if r.file_note != "" {
		gap(app, 8)
		group_caption(app, r.file_note, ui.ERROR)
	}
	if a.old {
		return
	}
	group_sep(app)
	rr = inner(app, 35)
	label := "Check and reload"
	lw := i32(math.ceil(ui.button_width(u, label, .Secondary)))
	r.reload_at = {rr.x, rr.y, min(lw, rr.w), 35}
	if ui.button(u, r.reload_at, label, .Secondary, a.reload_wait == 0, ui.SURFACE) {
		acl_reload(app)
	}
	gap(app, 8)
	group_caption(app, "Only an administrator can change this file. After an edit, reload it here and the service checks it first.")
	if a.reload_msg != "" {
		gap(app, 8)
		col := ui.OK
		switch {
		case a.reload_wait > 0:
			col = ui.MUTED
		case a.reload_error:
			col = ui.ERROR
		}
		group_caption(app, a.reload_msg, col)
		if a.reload_note != "" && a.reload_wait == 0 {
			gap(app, 4)
			group_caption(app, a.reload_note, ui.WARN)
		}
	}
}

@(private = "file")
rules_profile :: proc(app: ^App) {
	u := &app.u
	r := &app.rules
	section(app, "PROFILE")
	g, y0 := group_open(app)
	if len(r.profile_lines) == 0 {
		rr := inner(app, 17)
		ui.text(u, ui.ST_BODY, rr.x, rr.y, "None", ui.MUTED)
	}
	for line in r.profile_lines {
		rr := inner(app, 20)
		ui.text(u, ui.ST_MONO, rr.x, rr.y + 2, ui.fit_text(u, ui.ST_MONO, line, f32(rr.w)), ui.TEXT)
	}
	gap(app, 10)
	group_caption(app, "Change them in the profile view: edit the file, then Reload and Reconnect.")
	gap(app, 10)
	rr := inner(app, 35)
	bw := i32(math.ceil(ui.button_width(u, "Edit profile", .Secondary)))
	r.edit_at = {rr.x, rr.y, bw, 35}
	if ui.button(u, r.edit_at, "Edit profile", .Secondary, true, ui.SURFACE) {
		// Back to the profile view when it opened this view.
		if view_below(app) == .Profile {
			pop_view(app)
		} else {
			open_profile(app, r.row)
		}
	}
	group_close(app, g, y0)
}

// chars_ok is true when s has only letters, digits and the bytes of extra.
@(private = "file")
chars_ok :: proc(s: string, letters: bool, extra: string) -> bool {
	for c in transmute([]u8)s {
		switch c {
		case '0' ..= '9':
		case 'a' ..= 'z', 'A' ..= 'Z':
			if !letters {
				return false
			}
		case:
			if strings.index_byte(extra, c) < 0 {
				return false
			}
		}
	}
	return true
}

// rule_line is the line of the builder and the problem that the parser of
// the service finds in it. The line is "" while a field that it needs is
// empty.
rule_line :: proc(r: ^Rules_View) -> (line, problem: string) {
	text :: proc(f: ^ui.Field) -> string {
		return strings.trim_space(ui.field_text(f))
	}
	// An IPv6 address goes in brackets before a port.
	bracket :: proc(addr, port: string) -> string {
		if strings.contains_rune(addr, ':') && !strings.contains_rune(addr, '[') {
			return tprint("[%s]:%s", addr, port)
		}
		return tprint("%s:%s", addr, port)
	}
	local := ""
	switch r.kind {
	case .Allow:
		addr, port := text(&r.addr), text(&r.port)
		dest: string
		switch {
		case addr == "" && port == "":
			dest = "0.0.0.0/0 ::/0"
		case addr == "":
			dest = tprint(":%s", port)
		case port == "":
			dest = addr
		case:
			dest = bracket(addr, port)
		}
		line = tprint("allow-inbound %s", dest)
		if w := ALLOW_PROTO_WORD[r.proto]; w != "" {
			line = tprint("%s %s", line, w)
		}
		switch {
		case !chars_ok(addr, true, ".:-_/[]"):
			local = "Use only letters, digits and . : - _ / [ ] in the address."
		case !chars_ok(port, false, "-"):
			local = "A port is a number, or a range such as 8000-8099."
		}
	case .Forward:
		port, host, tport := text(&r.fport), text(&r.fhost), text(&r.ftport)
		if port == "" || host == "" || tport == "" {
			return "", ""
		}
		line = tprint("forward %s%s to %s", port, FWD_PROTO_WORDS[r.fproto], bracket(host, tport))
		switch {
		case !chars_ok(port, false, "") || !chars_ok(tport, false, ""):
			local = "A port is a number from 1 to 65535."
		case !chars_ok(host, true, ".:-_[]"):
			local = "Use only letters, digits and . : - _ [ ] in the host."
		}
	}
	if local != "" {
		return line, local
	}
	if line != r.checked {
		set_text(&r.checked, line)
		set_text(&r.problem, sentence(config.acl_line_problem(line, context.temp_allocator)))
	}
	return line, r.problem
}

// rules_add puts a line on the list to copy, once.
rules_add :: proc(r: ^Rules_View, line: string) {
	if line == "" || len(r.lines) >= RULE_LINES_MAX || slice.contains(r.lines[:], line) {
		return
	}
	append(&r.lines, strings.clone(line))
}

// rules_lines_text is the lines to copy as one text.
rules_lines_text :: proc(r: ^Rules_View) -> string {
	return strings.join(r.lines[:], "\n", context.temp_allocator)
}

// two_labels draws the labels of a narrow field after a wide one, and returns
// the width of the wide one.
@(private = "file")
two_labels :: proc(app: ^App, wide, narrow: string, narrow_w: i32) -> i32 {
	rr := inner(app, 16)
	ww := rr.w - narrow_w - 12
	ui.text(&app.u, ui.ST_LABEL, rr.x, rr.y, wide, ui.MUTED)
	ui.text(&app.u, ui.ST_LABEL, rr.x + ww + 12, rr.y, narrow, ui.MUTED)
	gap(app, 6)
	return ww
}

@(private = "file")
rules_field :: proc(app: ^App, r: mu.Rect, f: ^ui.Field, placeholder: string) {
	_, _ = ui.field(&app.u, r, f, placeholder, {mono = true, enabled = true})
}

@(private = "file")
rules_builder :: proc(app: ^App) {
	u := &app.u
	r := &app.rules
	section(app, "DEFINE A RULE")
	g, y0 := group_open(app)
	mu.push_id(&u.ctx, "builder")
	kinds := RULE_KIND_LABEL
	if k := choices(app, slice.enumerated_array(&kinds), int(r.kind)); k >= 0 {
		r.kind = Rule_Kind(k)
	}
	gap(app, 12)
	PORT_W :: 96
	switch r.kind {
	case .Allow:
		field_label(app, "Protocol")
		protos := ALLOW_PROTO_LABEL
		if k := choices(app, slice.enumerated_array(&protos), int(r.proto)); k >= 0 {
			r.proto = Allow_Proto(k)
		}
		gap(app, 12)
		aw := two_labels(app, "Address", "Port", PORT_W)
		rr := inner(app, ui.FIELD_H)
		rules_field(app, {rr.x, rr.y, aw, rr.h}, &r.addr, "host, IP or network")
		rules_field(app, {rr.x + aw + 12, rr.y, PORT_W, rr.h}, &r.port, "any")
	case .Forward:
		rr := inner(app, 16)
		pw: i32 = 84
		ui.text(u, ui.ST_LABEL, rr.x, rr.y, "Port", ui.MUTED)
		ui.text(u, ui.ST_LABEL, rr.x + pw + 12, rr.y, "Protocol", ui.MUTED)
		gap(app, 6)
		probe := inner(app, 0)
		rules_field(app, {probe.x, probe.y, pw, ui.FIELD_H}, &r.fport, "8080")
		protos := FWD_PROTO_LABEL
		if k := choices(app, slice.enumerated_array(&protos), int(r.fproto), pw + 12); k >= 0 {
			r.fproto = Fwd_Proto(k)
		}
		gap(app, 12)
		hw := two_labels(app, "Target host", "Target port", PORT_W)
		rr = inner(app, ui.FIELD_H)
		rules_field(app, {rr.x, rr.y, hw, rr.h}, &r.fhost, "127.0.0.1")
		rules_field(app, {rr.x + hw + 12, rr.y, PORT_W, rr.h}, &r.ftport, "80")
	}
	line, problem := rule_line(r)
	if line != "" {
		gap(app, 12)
		mono_well(app, line)
		field_error(app, problem)
	}
	gap(app, 12)
	rr := inner(app, 35)
	r.add_on = line != "" && problem == "" && len(r.lines) < RULE_LINES_MAX && !slice.contains(r.lines[:], line)
	aw := i32(math.ceil(ui.button_width(u, "Add", .Primary)))
	r.add_at = {rr.x, rr.y, aw, 35}
	if ui.button(u, r.add_at, "Add", .Primary, r.add_on, ui.SURFACE) {
		rules_add(r, line)
	}
	copied := line != "" && app.copied == line
	cw := i32(math.ceil(max(ui.button_width(u, "Copy", .Secondary), ui.button_width(u, "Copied", .Secondary))))
	if ui.button(u, {rr.x + aw + 8, rr.y, cw, 35}, copied ? "Copied" : "Copy", .Secondary, line != "" && problem == "", ui.SURFACE) {
		copy_text(app, line)
	}
	label := "Block all but ping"
	bw := i32(math.ceil(ui.button_width(u, label, .Secondary)))
	r.ping_at = {rr.x + rr.w - bw, rr.y, bw, 35}
	if ui.button(u, r.ping_at, label, .Secondary, !slice.contains(r.lines[:], BLOCK_ALL_BUT_PING), ui.SURFACE) {
		rules_add(r, BLOCK_ALL_BUT_PING)
	}
	mu.pop_id(&u.ctx)
	group_close(app, g, y0)
}

@(private = "file")
rules_copy_lines :: proc(app: ^App) {
	u := &app.u
	r := &app.rules
	section(app, "LINES TO COPY")
	g, y0 := group_open(app)
	if len(r.lines) == 0 {
		rr := inner(app, 17)
		ui.text(u, ui.ST_BODY, rr.x, rr.y, "No lines yet.", ui.MUTED)
	}
	remove := -1
	for line, i in r.lines {
		mu.push_id(&u.ctx, uintptr(700 + i))
		if i > 0 {
			gap(app, 4)
		}
		rr := inner(app, 32)
		mh := i32(ui.line_height(ui.ST_MONO))
		ui.text(u, ui.ST_MONO, rr.x, rr.y + (32 - mh) / 2, ui.fit_text(u, ui.ST_MONO, line, f32(rr.w - 32 - 10)), ui.TEXT)
		if ui.box_button(u, {rr.x + rr.w - 32, rr.y, 32, 32}, .Remove, "remove", 12) {
			remove = i
		}
		mu.pop_id(&u.ctx)
	}
	if remove >= 0 {
		delete(r.lines[remove])
		ordered_remove(&r.lines, remove)
	}
	gap(app, 12)
	rr := inner(app, 35)
	all := rules_lines_text(r)
	copied := all != "" && app.copied == all
	cw := i32(math.ceil(max(ui.button_width(u, "Copy all", .Secondary), ui.button_width(u, "Copied", .Secondary))))
	r.copy_all_at = {rr.x, rr.y, cw, 35}
	if ui.button(u, r.copy_all_at, copied ? "Copied" : "Copy all", .Secondary, all != "", ui.SURFACE) {
		copy_text(app, all)
	}
	clw := i32(math.ceil(ui.button_width(u, "Clear", .Ghost)))
	if ui.button(u, {rr.x + cw + 8, rr.y, clw, 35}, "Clear", .Ghost, len(r.lines) > 0, ui.SURFACE) {
		for l in r.lines {
			delete(l)
		}
		clear(&r.lines)
	}
	gap(app, 10)
	group_caption(app, "Defining any allow-inbound line will block every other new connection from the tunnel. Paste the lines into the config file of the service or into the profile file.")
	group_close(app, g, y0)
}
