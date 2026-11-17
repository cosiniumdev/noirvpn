// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// App state, navigation and the frame: top bar, the current view and the popups.

import "core:fmt"
import "core:math"
import mu "vendor:microui"
import sdl "vendor:sdl3"
import pf "profiles"
import "ui"

View :: enum u8 {
	List,
	Connection,
	Profile,
	Attach,
	Settings,
	Create,
	Created,
	Key_Request, // view_key.odin
}

LOGO_PNG :: #load("assets/logo-mask.png")

App :: struct {
	u:              ui.UI,
	window:         ^sdl.Window,
	renderer:       ^sdl.Renderer, // nil with the CPU renderer
	cpu:            bool, // the CPU renderer draws the window: see present_darwin.odin and present_other.odin
	presenter:      Presenter,
	draw_ms:        f64, // time of the last draw (recording and drawing, without presenting), for --stats
	headless:       bool,
	quit:           bool,
	quit_prompt:    bool, // the quit confirmation is open: see view_quit.odin
	quit_fresh:     bool, // the prompt opened and has not been drawn yet
	prompt_hide:    bool, // the prompt offers Hide (close request) as well as Quit

	// System tray: see tray.odin. has_tray is false when the system has none.
	has_tray:       bool,
	tray:           ^sdl.Tray,
	tray_show:      ^sdl.TrayEntry,
	tray_status:    ^sdl.TrayEntry,
	tray_disconnect: ^sdl.TrayEntry,
	tray_quit:      ^sdl.TrayEntry,
	tray_shown:     Tray_State, // what the tray shows now
	logo:           ui.Mask,
	now:            f64,
	cursors:        [ui.Cursor_Kind]^sdl.Cursor,
	cursor_shown:   ui.Cursor_Kind,
	hidden:         bool, // the window is minimized or hidden: no timed redraws

	// Display scale: see scale.odin.
	settings:       Settings,
	settings_file:  string, // "" keeps the settings in memory only
	eff:            f32, // effective scale E in use
	rescale:        bool, // d or S may have changed, or the setting did
	fixed_scale:    bool, // the scale is set by the caller (--screens)
	refit:          bool, // the window is on another display: give it its full size again
	scale_btn:      [2]mu.Rect, // the smaller and larger buttons of the size stepper, as last laid out
	scale_follow:   int, // the stepper button that the pointer follows when the scale changes: -1 smaller, 1 larger, 0 none
	pointer_target: [2]f32, // window coordinates of the last pointer move (pointer_to)
	unclamped:      bool, // do not limit the window to its display (self-test)

	profiles:       [MAX_PROFILES + 1]Profile, // the last row is for a tunnel with no row
	n_profiles:     int,

	// The profile store and the import: see profile_rows.odin.
	store:          pf.Store,
	metas:          []pf.Meta,
	row_cache:      map[string]Row_Cache,
	importing:      pf.Import_Result,
	import_wait:    bool, // profile.check is on its way
	dialog:         Dialog,

	stack:          [4]View,
	depth:          int,

	// Frameless window: see frame.odin.
	bar_rects:      [BAR_RECTS_MAX]mu.Rect, // controls in the top bar, set while building
	n_bar_rects:    int,
	frame_border:   bool, // draw the outline ourselves (the system draws none)
	pos_save_at:    f64, // time to store the window position, 0 for none
	moved:          bool, // the window moved after it was placed

	// Connection view: the row it shows. The tunnel row is conn.profile.
	shown:          int,
	shown_id:       string, // store id of a Stored row, so that a new order of the rows keeps it

	// List view.
	menu_row:       int,
	pending_delete: int, // row to confirm, or -1
	message:        string,
	message_error:  bool,

	// The service and the connection: see link.odin.
	link:           Link,
	conn:           Conn,
	graph:          ui.Graph_Data,
	conn_more:      bool, // the connection view shows the log and the pushed settings

	// Profile view, and the Create view (view_create.odin).
	edit:           Edit,
	pending:        Form_Pending, // the text of Create or Save on its way to profile.check
	made:           Made, // the key view
	keyreq:         Key_Req, // the key request of the profile view
	confirm:        Confirm, // a question over the window (view_key.odin)
	copied:         string, // the last text put on the clipboard

	// The self-test starts no browser: web_open counts the calls.
	browser_test:   bool,
	browser_fail:   bool, // the stub fails
	browser_calls:  int,
	browser_last:   string, // the words of the last call, without the link

	fresh:          int, // frames in which scroll areas start at the top
	cy:             i32, // y below the last row reserved by row() or gap()

	// Attach view (daemon not running).
	attach_retries: int,
}

current_view :: proc(app: ^App) -> View {
	return app.stack[app.depth]
}

push_view :: proc(app: ^App, v: View) {
	if app.depth + 1 < len(app.stack) {
		app.depth += 1
		app.stack[app.depth] = v
	}
	app.fresh = 2
	app.u.focus = 0
}

pop_view :: proc(app: ^App) {
	if app.depth > 0 {
		app.depth -= 1
	}
	app.fresh = 2
	app.u.focus = 0
}

app_init :: proc(app: ^App) {
	if app.link.kind == .Sim {
		app.profiles[0] = profile_make("Home", "home.example.net", 1194, "udp", .None, "203.0.113.10", 1793733420)
		app.profiles[1] = profile_make("Lab", "lab.example.org", 1194, "udp", .Web)
		app.profiles[2] = profile_make("Work VPN", "vpn.example.com", 443, "tls", .User_Pass, "198.51.100.20", 1794472920)
		app.n_profiles = 3
	}
	app.pending_delete = -1
	ui.field_init(&app.conn.user, app.link.kind == .Sim ? "alice" : "")
	ui.field_init(&app.conn.pass)
	app.conn.phase = .Disconnected
	edit_init(&app.edit)
	key_request_init(&app.keyreq)
	app.stack[0] = .List
}

// attach_enter shows the attach view in place of the list: no service is found.
attach_enter :: proc(app: ^App) {
	if app.stack[0] == .Attach {
		return
	}
	app.stack[0] = .Attach
	if current_view(app) == .Connection {
		app.depth = 0
	}
	app.fresh = 2
}

// attach_leave goes back to the list when a service is found.
attach_leave :: proc(app: ^App) {
	if app.stack[0] == .Attach {
		app.stack[0] = .List
		app.fresh = 2
	}
}

// profile_plan is how a simulated connect of profile i goes.
profile_plan :: proc(i: int) -> Plan {
	switch i {
	case 1:
		return .Retry
	case 2:
		return .Sign_In
	}
	return .Direct
}

// open_connection shows the connection view of row i. It does not connect:
// the user presses Connect (row_connect).
open_connection :: proc(app: ^App, i: int) {
	app.shown = i
	set_text(&app.shown_id, app.profiles[i].source == .Stored ? app.profiles[i].id : "")
	if !shown_is_tunnel(app) {
		app.link.error = ""
	}
	push_view(app, .Connection)
}

// start_connection shows row i and connects it, for --open, the scenes and the
// tests.
start_connection :: proc(app: ^App, i: int) {
	open_connection(app, i)
	if !(conn_active(app) && shown_is_tunnel(app)) {
		row_connect(app, i)
	}
}

// shown_is_tunnel is true when the connection view shows the row of the tunnel.
shown_is_tunnel :: proc(app: ^App) -> bool {
	return app.shown == app.conn.profile
}

// shown_phase is the phase that the connection view shows: the phase of the
// tunnel for its own row, else disconnected.
shown_phase :: proc(app: ^App) -> Phase {
	return shown_is_tunnel(app) ? app.conn.phase : .Disconnected
}

// conn_locked is true while the tunnel of the shown row is active: the view
// has no way back until the user disconnects.
conn_locked :: proc(app: ^App) -> bool {
	return shown_is_tunnel(app) && conn_active(app)
}

open_profile :: proc(app: ^App, i: int) {
	edit_reload_clear(&app.edit)
	if app.profiles[i].source == .Stored {
		if !edit_load_stored(app, &app.edit, i) {
			set_message(app, "The profile could not be read.", true)
			return
		}
	} else {
		edit_load(&app.edit, &app.profiles[i], i)
	}
	push_view(app, .Profile)
}

// build creates one frame of UI from the current state. dt is the time since the
// previous frame, used by animations.
build :: proc(app: ^App, dt: f32) {
	u := &app.u
	if app.rescale {
		scale_sync(app)
	}
	if app.cpu {
		w, h: i32
		_ = sdl.GetWindowSizeInPixels(app.window, &w, &h)
		ui.gfx_set_pixels(&u.g, w, h)
	}
	ui.ui_begin(u, app.now, dt)
	if app.quit_prompt || app.confirm.fresh {
		u.block = true
	}
	app.n_bar_rects = 0
	u.window_border = app.frame_border
	ctx := &u.ctx
	w, h := u.size.x, u.size.y
	if mu.begin_window(ctx, "root", {0, 0, w, h}, {.NO_TITLE, .NO_FRAME, .NO_RESIZE, .NO_SCROLL, .NO_CLOSE}) {
		cnt := mu.get_current_container(ctx)
		cnt.rect = {0, 0, w, h}
		switch current_view(app) {
		case .List:
			view_list(app)
		case .Connection:
			view_connection(app)
		case .Profile:
			view_profile(app)
		case .Attach:
			view_attach(app)
		case .Settings:
			view_settings(app)
		case .Create:
			view_create(app)
		case .Created:
			view_created(app)
		case .Key_Request:
			view_key_request(app)
		}
		mu.end_window(ctx)
	}
	view_popups(app)
	view_confirm(app)
	view_quit_prompt(app)
	if u.escape && !u.popup_open {
		switch current_view(app) {
		case .List, .Attach:
		case .Connection:
			if !conn_locked(app) {
				pop_view(app)
			}
		case .Profile, .Settings, .Created:
			pop_view(app)
		case .Create:
			create_leave(app)
		case .Key_Request:
			key_request_leave(app)
		}
	}
	ui.ui_end(u)
	app.fresh = max(app.fresh - 1, 0)
	hit_publish(app)
}

// ---- Top bar ----

Top :: struct {
	back:      bool,
	logo:      bool,
	title:     string,
	server:    string, // right-aligned text, as "host:port"
	flat:      bool, // no line under the bar
	simulated: bool,
	plus:      bool, // the start view's plus and settings buttons
}

Top_Result :: struct {
	back:      bool,
	plus:      bool,
	plus_rect: mu.Rect,
	settings:  bool,
}

topbar :: proc(app: ^App, t: Top) -> (res: Top_Result) {
	u := &app.u
	w := u.size.x
	inner_h := i32(ui.TOPBAR_H - 1)
	if !t.flat {
		ui.hline(u, 0, inner_h, w)
	}
	// Buttons from the right: close, plus, settings. right is the limit for text and the chip.
	close_rect := mu.Rect{w - 8 - ui.ICON_BUTTON, 8, ui.ICON_BUTTON, ui.ICON_BUTTON}
	right := close_rect.x - 12
	gear_rect: mu.Rect
	if t.plus {
		res.plus_rect = {close_rect.x - ui.ICON_BUTTON, 8, ui.ICON_BUTTON, ui.ICON_BUTTON}
		gear_rect = {res.plus_rect.x - ui.ICON_BUTTON, 8, ui.ICON_BUTTON, ui.ICON_BUTTON}
		right = gear_rect.x - 12
	}
	chip_w, chip_h: f32
	if t.simulated {
		chip_w, chip_h = ui.chip_size(u, "Simulated")
	}
	x: i32 = 16
	if t.back {
		if bar_button(app, {4, 10, 36, 36}, .Back, "back") {
			res.back = true
		}
		x = 44
	}
	lh := ui.line_height(ui.ST_TITLE)
	if t.logo {
		lw, lhh: f32 = 17 * f32(app.logo.w) / f32(app.logo.h), 17
		ui.emit(u, {kind = .Mask, r = {f32(x), math.floor((f32(inner_h) - lhh) / 2), lw, lhh}, c1 = ui.TEXT, ptr = &app.logo}, 0)
	} else if t.server != "" {
		st_server := ui.ST_BODY
		right_edge := close_rect.x - 8
		avail := f32(right_edge - x - 12)
		tw, sw := split_widths(ui.text_w(u, ui.ST_BAR_TITLE, t.title), ui.text_w(u, st_server, t.server), avail)
		title := ui.fit_text(u, ui.ST_BAR_TITLE, t.title, tw)
		server := ui.fit_text(u, st_server, t.server, sw)
		bh := ui.line_height(ui.ST_BAR_TITLE)
		ui.text(u, ui.ST_BAR_TITLE, x, i32(math.round((f32(inner_h) - bh) / 2)) + 1, title, ui.TEXT_STRONG)
		sh := ui.line_height(st_server)
		sx := right_edge - i32(math.ceil(ui.text_w(u, st_server, server)))
		ui.text(u, st_server, sx, i32(math.round((f32(inner_h) - sh) / 2)), server, ui.TEXT_STRONG)
	} else if t.title != "" {
		limit := f32(right) - (t.simulated ? math.ceil(chip_w) + 10 : 0)
		title := ui.fit_text(u, ui.ST_TITLE, t.title, limit - f32(x) - 4)
		ui.text(u, ui.ST_TITLE, x, i32(math.round((f32(inner_h) - lh) / 2)), title, ui.TEXT)
	}
	if t.plus {
		if bar_button(app, res.plus_rect, .Plus, "plus") {
			res.plus = true
		}
		if bar_button(app, gear_rect, .Gear, "settings") {
			res.settings = true
		}
	}
	if t.simulated {
		ui.chip(u, right - i32(math.ceil(chip_w)), i32(math.round((f32(inner_h) - chip_h) / 2)), "Simulated")
	}
	if bar_button(app, close_rect, .Close, "close") {
		request_close(app)
	}
	return
}

// bar_button is an icon button in the top bar. Its rectangle is not part of the
// area that drags the window.
bar_button :: proc(app: ^App, r: mu.Rect, icon: ui.Icon_Id, name: string) -> bool {
	if app.n_bar_rects < len(app.bar_rects) {
		app.bar_rects[app.n_bar_rects] = r
		app.n_bar_rects += 1
	}
	return ui.icon_button(&app.u, r, icon, name)
}

// split_widths shares avail between a title and a server text of natural widths
// tw and sw. A text that fits in half keeps its width and the other gets the rest.
split_widths :: proc(tw, sw, avail: f32) -> (title, server: f32) {
	if tw + sw <= avail {
		return tw, sw
	}
	half := avail / 2
	switch {
	case tw <= half:
		return tw, avail - tw
	case sw <= half:
		return avail - sw, sw
	}
	return half, half
}

// ---- Layout helpers ----

// scroll_begin opens a vertical scroll area with the given rectangle. The
// scroll keys of this frame move it.
scroll_begin :: proc(app: ^App, name: string, r: mu.Rect) {
	ctx := &app.u.ctx
	if app.fresh == 0 {
		_ = ui.scroll_keys(&app.u, mu.get_container(ctx, name), r.h)
	}
	mu.layout_set_next(ctx, r, false)
	mu.begin_panel(ctx, name, {.NO_FRAME})
	if app.fresh > 0 {
		mu.get_current_container(ctx).scroll = {}
	}
}

scroll_end :: proc(app: ^App) {
	mu.end_panel(&app.u.ctx)
}

// area_container is the container of the scroll area called name, from
// outside a frame.
area_container :: proc(app: ^App, name: string) -> ^mu.Container {
	ctx := &app.u.ctx
	// The area lives inside the root window, so its id is computed with the root id on the stack.
	root := mu.get_id(ctx, "root")
	ctx.id_stack.items[0] = root
	ctx.id_stack.idx = 1
	cnt := mu.get_container(ctx, name)
	ctx.id_stack.idx = 0
	return cnt
}

// scroll_to sets the scroll position of the area called name.
scroll_to :: proc(app: ^App, name: string, y: i32) {
	area_container(app, name).scroll.y = y
}

// scroll_of is the scroll position of the area called name.
scroll_of :: proc(app: ^App, name: string) -> i32 {
	return area_container(app, name).scroll.y
}

// row reserves a full-width row of height h inside a scroll area, inset by margin.
row :: proc(app: ^App, h: i32, margin: i32 = ui.MARGIN) -> mu.Rect {
	ctx := &app.u.ctx
	mu.layout_row(ctx, {-1}, h)
	r := mu.layout_next(ctx)
	app.cy = r.y + h
	return {r.x + margin, r.y, app.u.size.x - margin * 2, h}
}

gap :: proc(app: ^App, h: i32) {
	if h <= 0 {
		return
	}
	mu.layout_row(&app.u.ctx, {-1}, h)
	r := mu.layout_next(&app.u.ctx)
	app.cy = r.y + h
}

// logo_shade draws the logo in a dark tone at the bottom right of the area r.
// Call it before the content of r, so that the content lies above it.
logo_shade :: proc(app: ^App, r: mu.Rect) {
	lw: f32 = 210
	lh := lw * f32(app.logo.h) / f32(app.logo.w)
	x := f32(r.x + r.w) - 20 - lw
	y := f32(r.y + r.h) - 22 - lh
	ui.emit(&app.u, {kind = .Mask, r = {x, y, lw, lh}, c1 = ui.LOGO_SHADE, ptr = &app.logo}, 0)
}

// ---- Bottom bars ----

BAR_PAD :: 16

// bottom_bar_h is the height of a bar that holds one button of the standard
// size with padding 16 and 12 (the big action button).
big_button_bar_h :: proc() -> i32 {
	return i32(ui.line_height(ui.ST_BUTTON)) + 12 * 2 + 2 + 16 * 2 + 1
}

tprint :: fmt.tprintf
