// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Attach view: shown in place of the list while no client daemon can be used.

import "core:strings"
import mu "vendor:microui"
import "ui"

// attach_texts are the title, the body and the hint for the state of the link.
attach_texts :: proc(app: ^App) -> (title, body, hint: string) {
	l := &app.link
	if !BUS_LINK {
		return "Service not available", "This version of the app cannot connect to the noirvpn service on this system.", ""
	}
	switch l.state {
	case .Denied:
		when ODIN_OS == .Darwin {
			return "No access to the service", "The noirvpn service is running, but your account does not have permission to use it.", "Only an administrator of this Mac can use it."
		} else {
			return "No access to the service", "The noirvpn service is running, but your account does not have permission to use it.", "Ask your administrator to add you to the noirvpn group, then log out and log back in."
		}
	case .Searching:
		return "Looking for the service", "", ""
	case .Not_Found, .Up:
	}
	// How to start the daemon by hand, when it is next to this program.
	by_hand := ""
	if l.daemon_cmd != "" {
		path := strings.contains(l.daemon_cmd, " ") ? tprint("\"%s\"", l.daemon_cmd) : l.daemon_cmd
		by_hand = tprint("You can also start it in Terminal: sudo %s", path)
	}
	// The app has a job for its own service (service_manage.odin).
	switch l.manage {
	case .Requires_Approval:
		return "Allow the service", "noirvpn uses a background service on this Mac, and the system needs your permission to start it.", "Press Open Settings and turn on noirvpn under Allow in the Background. This view will close once the service starts."
	case .Enabled:
		return "Starting the service", tprint("The system runs the noirvpn service. It is not ready yet. Looked in %s.", l.looked), tprint("It starts by itself. If there are problems, check the log file %s.", MANAGE_LOG)
	case .Not_Registered, .Not_Found:
		if l.manage_err != "" {
			return "Service not started", tprint("The system did not accept the noirvpn service: %s.", l.manage_err), by_hand == "" ? "Press Retry to try again." : tprint("Press Retry to try again. %s", by_hand)
		}
	case .Unavailable:
	}
	body = "The noirvpn client service is not running."
	if l.looked != "" {
		body = tprint("The noirvpn client service is not running. Looked for it in %s.", l.looked)
	}
	hint = "Start the noirvpn service, then press Retry."
	if by_hand != "" {
		hint = tprint("Start the noirvpn service, then press Retry. %s", by_hand)
	}
	return "Service not running", body, hint
}

view_attach :: proc(app: ^App) {
	u := &app.u
	w, h := u.size.x, u.size.y
	_ = topbar(app, {logo = true})

	title, body, hint := attach_texts(app)
	bar_h := big_button_bar_h()
	scroll_begin(app, "attach", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H - bar_h})
	gap(app, 32)
	r := row(app, 22)
	ui.text(u, ui.ST_TITLE, r.x, r.y, title, ui.TEXT)
	if body != "" {
		gap(app, 10)
		for l in ui.wrap_text(u, ui.ST_BODY, body, f32(w - 32)) {
			r = row(app, 17)
			ui.text(u, ui.ST_BODY, r.x, r.y, l, ui.TEXT)
		}
	}
	if hint != "" {
		gap(app, 10 + 6)
		for l in ui.wrap_text(u, ui.ST_CAPTION, hint, f32(w - 32)) {
			r = row(app, 16)
			ui.text(u, ui.ST_CAPTION, r.x, r.y, l, ui.MUTED)
		}
	}
	scroll_end(app)

	br := mu.Rect{0, h - bar_h, w, bar_h}
	ui.bar(u, br)
	settings := app.link.state == .Not_Found && app.link.manage == .Requires_Approval
	if ui.button(u, {16, br.y + 1 + 16, w - 32, bar_h - 1 - 32}, settings ? "Open Settings" : "Retry", .Primary, BUS_LINK, ui.SURFACE) {
		if settings {
			manage_open_settings()
		}
		app.attach_retries += 1
		link_retry(app)
	}
}
