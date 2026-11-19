// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd, windows
package main

// Tests of the Inbound rules view against the fake daemon: acl.get and when
// the link reads it, acl.reload and its results, acl.deny, and a daemon
// without these operations.

import "core:os"

selftest_rules_link :: proc(base: ^App, failed: ^int, check: proc(name: string, ok: bool, failed: ^int)) {
	dir := test_dir("nvacl")
	defer os.remove_all(dir)
	f := new(Fake)
	fake_endpoints(f, dir, "acl")
	f.state = "stopped"
	f.config = "/etc/noirvpn/desktop.conf"
	if !fake_open(f) {
		check("rules: fake daemon opens", false, failed)
		return
	}
	defer fake_close(f)
	app := link_app(base, f.control)
	defer bus_stop(app)
	l := &app.link
	a := &l.acl
	r := &app.rules

	ok := pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.state == .Up && app.link.acl.known}, 5)
	check("rules: the link reads acl.get after the first status", ok && f.acl_gets == 1 && l.config == "/etc/noirvpn/desktop.conf", failed)
	ok = len(a.rules) == 2 && len(a.forwards) == 1 && a.filter && a.source == "config" && a.denied == 5 && !a.pending
	ok = ok && a.rules[0].dest == ":22" && a.rules[0].protos == "TCP" && !a.rules[0].host
	ok = ok && a.rules[1].host && a.rules[1].protos == "TCP, UDP" && a.rules[1].addresses == "192.168.50.10, fd00:50::10"
	ok = ok && a.forwards[0].port == 8080 && a.forwards[0].target == "127.0.0.1:80" && a.forwards[0].protos == "TCP"
	check("rules: acl.get gives the rules, the forwards and the blocked count", ok, failed)

	gets := f.acl_gets
	open_connection(app, 0)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.rules.card_at.w > 0 && !app.link.acl.busy}, 5)
	check("rules: the connection view reads the rules and shows the card", ok && f.acl_gets > gets && acl_state_text(a) == "Rules only · 2 rules · 1 forward", failed)

	gets = f.acl_gets
	rules_open(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return f.acl_gets > 0 && !app.link.acl.busy && app.rules.rows_drawn == 3}, 5)
	check("rules: the view opens, reads the rules and lists them", ok && current_view(app) == .Rules && f.acl_gets > gets, failed)
	check("rules: the view wakes the app for the next read", link_wake(app) <= a.next + 1e-6, failed)
	gets = f.acl_gets
	a.next = app.now - 1
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.acl.busy && app.link.acl.next > app.now}, 5)
	check("rules: the view reads the rules again every 3 s", ok && f.acl_gets == gets + 1, failed)

	// No read while the window is hidden; the read follows when it shows.
	app.hidden = true
	gets = f.acl_gets
	acl_read(app)
	a.next = app.now - 1
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return false}, 0.3)
	check("rules: no read while the window is hidden", f.acl_gets == gets && a.stale && link_wake(app) == 0, failed)
	app.hidden = false
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return !app.link.acl.stale && !app.link.acl.busy}, 5)
	check("rules: the read follows when the window shows", ok && f.acl_gets > gets, failed)

	// Check and reload.
	gets = f.acl_gets
	acl_reload(app)
	check("rules: Check and reload sends acl.reload and waits", a.reload_wait == 1 && a.reload_msg != "", failed)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.acl.reload_wait == 0 && len(app.link.acl.rules) == 3 && !app.link.acl.busy}, 5)
	check("rules: a reload that changed the rules says what changed", ok && f.acl_reloads == 1 && !a.reload_error && a.reload_msg == "Reloaded. 3 rules, 1 forward.", failed)
	check("rules: the reload gives the notes of DCO and of a restart", a.reload_note == ACL_PENDING_TEXT + " Restart the service to apply acl-max-flows.", failed)
	check("rules: the rules are read again after the reload", f.acl_gets > gets && a.pending && a.rules[2].host && a.rules[2].addresses == "" && a.rules[2].protos == "Any", failed)
	acl_reload(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.acl.reload_wait == 0 && !app.link.acl.busy}, 5)
	check("rules: a reload with no change", ok && a.reload_msg == "Reloaded. Nothing changed." && a.reload_note == "", failed)
	f.acl_bad = true
	acl_reload(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.acl.reload_wait == 0}, 5)
	check("rules: a config file with a problem gives its first problem", ok && a.reload_error && a.reload_msg == "Nothing changed. The service found a problem: Line 7, allow-inbound: '10.0.0.300' is not an address, a prefix or a host name", failed)
	f.acl_bad = false
	f.config = ""
	acl_reload(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.acl.reload_wait == 0}, 5)
	check("rules: a service with no config file gives the message", ok && a.reload_error && a.reload_msg == "The daemon has no config file.", failed)
	f.config = "/etc/noirvpn/desktop.conf"

	// acl.deny events and Allow.
	fake_publish_state(f, "up", "")
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.conn.address != "" && !app.link.acl.busy}, 5)
	check("rules: the tunnel is up", ok && app.conn.address == "10.8.0.2, fd00:8::2", failed)
	fake_publish_deny(f, "tcp", "10.8.0.1", "10.8.0.2", 3389)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.acl.n_blocked == 1}, 5)
	b := a.blocked[0]
	check("rules: acl.deny shows in the blocked list", ok && b.proto == "tcp" && b.src == "10.8.0.1" && b.dst == "10.8.0.2" && b.dport == 3389 && b.at > 0, failed)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.rules.allow_at.w > 0}, 2)
	rules_from_block(app, a.blocked[0])
	line, problem := rule_line(r)
	check("rules: Allow of a blocked connection fills the builder", ok && line == "allow-inbound :3389 tcp" && problem == "", failed)
	fake_publish_deny(f, "udp", "10.8.0.1", "fd00:8::99", 53)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.acl.n_blocked == 2}, 5)
	rules_from_block(app, a.blocked[0])
	line, problem = rule_line(r)
	check("rules: the newest blocked connection is first", ok && line == "allow-inbound [fd00:8::99]:53 udp" && problem == "", failed)

	// The state of the tunnel changes the rules in force.
	gets = f.acl_gets
	fake_publish_state(f, "stopped", "user_request")
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return f.acl_gets > 0 && app.link.svc == .Stopped && !app.link.acl.busy}, 5)
	check("rules: a stop reads the rules again", ok && f.acl_gets > gets, failed)

	// A daemon without acl.get: no card, and the view says so.
	f.acl_old = true
	acl_read(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return app.link.acl.old}, 5)
	check("rules: a daemon without acl.get does not report its rules", ok && !a.known && len(a.rules) == 0 && r.rows_drawn == 0, failed)
	pop_view(app)
	ok = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return current_view(app) == .Connection}, 2)
	check("rules: the card is hidden for an older daemon", ok && r.card_at.w == 0, failed)
	gets = f.acl_gets
	open_connection(app, 0)
	_ = pump(app, f, proc(app: ^App, f: ^Fake) -> bool {return false}, 0.2)
	check("rules: the link does not ask an older daemon again", f.acl_gets == gets && l.error == "", failed)
}
