// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Tests of the Inbound rules view with the simulated service: the card, the
// rule builder, the lines to copy and Check and reload. The bus part is in
// selftest_rules_bus.odin.

import "core:strings"
import mu "vendor:microui"
import sdl "vendor:sdl3"
import pf "profiles"
import "ui"

// click_rules scrolls the Inbound rules view to a button that the view
// records in `at`, and clicks it. It returns false when the view does not
// draw the button.
click_rules :: proc(app: ^App, at: ^mu.Rect) -> bool {
	at^ = {}
	frame(app, 0.016)
	if at.w == 0 {
		return false
	}
	scroll_to(app, "rules", max(scroll_of(app, "rules") + at.y - 300, 0))
	frame(app, 0.016)
	r := at^
	click(app, f32(r.x + r.w / 2), f32(r.y + r.h / 2))
	return true
}

// click_view scrolls the container `name` to a button that a view records in
// `at`, and clicks it. It returns false when the view does not draw the button.
click_view :: proc(app: ^App, name: string, at: ^mu.Rect) -> bool {
	at^ = {}
	frame(app, 0.016)
	if at.w == 0 {
		return false
	}
	scroll_to(app, name, max(scroll_of(app, name) + at.y - 300, 0))
	frame(app, 0.016)
	b := at^
	click(app, f32(b.x + b.w / 2), f32(b.y + b.h / 2))
	frame(app, 0.016)
	return true
}

// builder_line sets the builder of an allow-inbound line and gives the line
// and its problem.
builder_line :: proc(r: ^Rules_View, proto: Allow_Proto, addr, port: string) -> (string, string) {
	r.kind, r.proto = .Allow, proto
	ui.field_set(&r.addr, addr)
	ui.field_set(&r.port, port)
	return rule_line(r)
}

// builder_forward sets the builder of a forward line and gives the line and
// its problem.
builder_forward :: proc(r: ^Rules_View, port: string, proto: Fwd_Proto, host, tport: string) -> (string, string) {
	r.kind, r.fproto = .Forward, proto
	ui.field_set(&r.fport, port)
	ui.field_set(&r.fhost, host)
	ui.field_set(&r.ftport, tport)
	return rule_line(r)
}

selftest_rules :: proc(app: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	r := &app.rules
	a := &app.link.acl
	while_view(app, .List)
	rules_reset(r)
	acl_sample(app)
	open_connection(app, 0)
	frame(app, 0.016)
	check("rules: the connection view shows the card of inbound connections", r.card_at.w > 0 && acl_state_text(a) == "Rules only · 3 rules · 1 forward", failed)
	a.filter = false
	check("rules: the card says Allowed when the filter is off", acl_state_text(a) == "Allowed · 1 forward", failed)
	a.filter = true
	c := r.card_at
	click(app, f32(c.x + c.w / 2), f32(c.y + c.h / 2))
	frame(app, 0.016)
	check("rules: Open of the card shows the Inbound rules view", current_view(app) == .Rules, failed)
	check("rules: the view lists the rules and the forward", r.rows_drawn == 4, failed)

	// The builder.
	line, problem := builder_line(r, .Any, "", "22")
	check("rules: builder, Any and a port", line == "allow-inbound :22" && problem == "", failed)
	line, problem = builder_line(r, .Tcp, "10.0.0.5", "443")
	check("rules: builder, TCP with an address and a port", line == "allow-inbound 10.0.0.5:443 tcp" && problem == "", failed)
	line, problem = builder_line(r, .Udp, "fd00::5", "53")
	check("rules: builder, an IPv6 address goes in brackets", line == "allow-inbound [fd00::5]:53 udp" && problem == "", failed)
	line, problem = builder_line(r, .Icmp, "", "")
	check("rules: builder, ICMP with no address", line == "allow-inbound 0.0.0.0/0 ::/0 icmp" && problem == "", failed)
	line, problem = builder_line(r, .Tcp, "nas.lan", "")
	check("rules: builder, a host name with no port", line == "allow-inbound nas.lan tcp" && problem == "", failed)
	line, problem = builder_line(r, .Icmp, "", "22")
	frame(app, 0.016)
	check("rules: builder, ICMP with a port has a problem and Add is off", line == "allow-inbound :22 icmp" && problem != "" && !r.add_on, failed)
	line, problem = builder_line(r, .Any, "a b", "")
	check("rules: builder, a space in the address is a problem", problem != "", failed)
	line, problem = builder_line(r, .Any, "", "ssh")
	check("rules: builder, a port with letters is a problem", problem != "", failed)
	line, problem = builder_forward(r, "8080", .Tcp, "127.0.0.1", "80")
	check("rules: builder, a TCP forward has no protocol word", line == "forward 8080 to 127.0.0.1:80" && problem == "", failed)
	line, problem = builder_forward(r, "5353", .Both, "fd00::1", "53")
	check("rules: builder, a forward of both protocols to IPv6", line == "forward 5353 tcp udp to [fd00::1]:53" && problem == "", failed)
	line, problem = builder_forward(r, "5353", .Udp, "fd00::1", "")
	check("rules: builder, no line while a forward field is empty", line == "" && problem == "", failed)
	line, problem = builder_forward(r, "8080", .Tcp, "127.0.0.1", "70000")
	check("rules: builder, the parser of the service checks the line", line != "" && strings.contains(problem, "65535"), failed)

	// Add, Block all but ping, Copy all.
	_, _ = builder_line(r, .Tcp, "10.0.0.5", "443")
	check("rules: Add puts the line on the list", click_rules(app, &r.add_at) && len(r.lines) == 1 && r.lines[0] == "allow-inbound 10.0.0.5:443 tcp", failed)
	frame(app, 0.016)
	check("rules: Add is off for a line on the list", !r.add_on, failed)
	check("rules: Block all but ping adds the ICMP line", click_rules(app, &r.ping_at) && len(r.lines) == 2 && r.lines[1] == BLOCK_ALL_BUT_PING, failed)
	check("rules: Copy all copies the lines", click_rules(app, &r.copy_all_at) && app.copied == "allow-inbound 10.0.0.5:443 tcp\nallow-inbound 0.0.0.0/0 ::/0 icmp", failed)

	// Allow of a blocked connection: a tunnel address of this computer gives
	// the `:port` form.
	set_text(&app.conn.address, "10.8.0.6, fd00:8::6")
	check("rules: Allow puts a blocked connection into the builder", click_rules(app, &r.allow_at), failed)
	line, problem = rule_line(r)
	check("rules: Allow of a connection to this computer gives the port", line == "allow-inbound :3389 tcp" && problem == "", failed)
	frame(app, 0.016)
	check("rules: Allow scrolls to the builder", scroll_of(app, "rules") > 0 && !r.jump, failed)
	acl_block_push(a, "udp", "10.8.0.1", "192.168.50.20", 53, 1795048900)
	rules_from_block(app, a.blocked[0])
	line, _ = rule_line(r)
	check("rules: Allow of a connection to another address keeps it", line == "allow-inbound 192.168.50.20:53 udp", failed)
	acl_block_push(a, "icmp", "fd00:8::1", "fd00:8::6", 0, 1795048901)
	rules_from_block(app, a.blocked[0])
	line, problem = rule_line(r)
	check("rules: Allow of ICMP gives the address", line == "allow-inbound fd00:8::6 icmp" && problem == "", failed)
	acl_block_push(a, "other", "10.8.0.1", "10.8.0.6", 0, 1795048902)
	rules_from_block(app, a.blocked[0])
	line, _ = rule_line(r)
	check("rules: Allow of another protocol gives Any", line == "allow-inbound 10.8.0.6", failed)
	for i in 0 ..< 12 {
		acl_block_push(a, "tcp", "10.8.0.1", "10.8.0.6", 1000 + i, 1795049000)
	}
	check("rules: the view keeps the last 10 blocked connections, newest first", a.n_blocked == ACL_BLOCKED_MAX && a.blocked[0].dport == 1011 && a.blocked[9].dport == 1002, failed)
	set_text(&app.conn.address, "")

	// Check and reload of the simulation.
	check("rules: Check and reload of the simulation", click_rules(app, &r.reload_at) && a.reload_msg == "Reloaded. Nothing changed." && !a.reload_error, failed)
	key(app, sdl.K_ESCAPE)
	check("rules: Escape goes back to the connection view", current_view(app) == .Connection, failed)

	// The profile view and the Inbound rules view lead to each other, and go
	// back when the other one opened them.
	e := &app.edit
	base := app.depth
	check("rules: card, then Open shows the Inbound rules view", click_view(app, "conn", &r.card_at) && current_view(app) == .Rules, failed)
	check("rules: Edit profile opens the profile view", click_view(app, "rules", &r.edit_at) && current_view(app) == .Profile && app.depth == base + 2, failed)
	check("rules: the profile view has INBOUND RULES", click_view(app, "profile", &e.rules_at), failed)
	check("rules: its Open goes back to the Inbound rules view", current_view(app) == .Rules && app.depth == base + 1, failed)
	key(app, sdl.K_ESCAPE)
	open_profile(app, app.shown)
	frame(app, 0.016)
	check("rules: Open in the profile view shows the Inbound rules view", click_view(app, "profile", &e.rules_at) && current_view(app) == .Rules && r.row == e.index, failed)
	check("rules: then Edit profile goes back to the profile view", click_view(app, "rules", &r.edit_at) && current_view(app) == .Profile && app.depth == base + 1, failed)
	check("rules: the line count of a profile", pf.acl_line_count([]string{"allow-inbound :22", "forward 1 to a:2", "remote a"}) == 2, failed)
	key(app, sdl.K_ESCAPE)
	if current_view(app) == .Profile {
		pop_view(app)
	}
	check("rules: back at the connection view", current_view(app) == .Connection && app.depth == base, failed)
	rules_reset(r)
	acl_sample(app)
	while_view(app, .List)
}
