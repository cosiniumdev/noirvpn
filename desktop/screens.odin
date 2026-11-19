// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Headless screenshots: every view and state is drawn with the software renderer
// on SDL's offscreen video driver and written as PNG, at 1x and at 2x density.

import "core:fmt"
import "core:os"
import "core:strings"
import sdl "vendor:sdl3"
import stbi "vendor:stb/image"
import "ui"

Scene :: struct {
	name:  string,
	setup: proc(app: ^App),
}

scenes := [?]Scene {
	{"profile-list", scene_list},
	{"profile-list-menu", scene_list_menu},
	{"list-plus-menu", scene_plus_menu},
	{"profile-list-delete", scene_list_delete},
	{"profile-list-empty", scene_list_empty},
	{"profile-list-message", scene_list_message},
	{"connection-idle", scene_conn_idle},
	{"connection-connecting", scene_connecting},
	{"connection-credentials", scene_credentials},
	{"connection-web-sign-in", scene_web_sign_in},
	{"connection-handshake", scene_handshake},
	{"connection-long-names", scene_long_names},
	{"connection-stopped", scene_stopped},
	{"connection-error", scene_error},
	{"connection-up", scene_up},
	{"connection-up-dns", scene_up_dns},
	{"connection-up-more", scene_up_more},
	{"connection-error-more", scene_error_more},
	{"quit-connected", scene_quit_connected},
	{"quit-connecting", scene_quit_connecting},
	{"close-idle", scene_close_idle},
	{"close-connected", scene_close_connected},
	{"profile", scene_profile},
	{"profile-overrides-domains", scene_overrides},
	{"profile-overrides-error", scene_overrides_error},
	{"profile-dco", scene_profile_dco},
	{"profile-dco-service", scene_profile_dco_service},
	{"connection-up-no-dco", scene_up_no_dco},
	{"create-empty", scene_create_empty},
	{"create-errors", scene_create_errors},
	{"create-advanced", scene_create_advanced},
	{"create-key", scene_create_key},
	{"profile-created", scene_profile_created},
	{"profile-identity", scene_profile_identity},
	{"profile-sign-in", scene_profile_sign_in},
	{"profile-file", scene_profile_file},
	{"profile-reload", scene_profile_reload},
	{"connection-key-pass", scene_connection_key_pass},
	{"profile-advanced", scene_profile_advanced},
	{"key-request-new", scene_key_request_new},
	{"key-request", scene_key_request},
	{"key-request-cert", scene_key_request_cert},
	{"key-request-mismatch", scene_key_request_mismatch},
	{"key-request-confirm", scene_key_request_confirm},
	{"key-request-done", scene_key_request_done},
	{"attach-not-running", scene_attach},
	{"attach-denied", scene_attach_denied},
	{"attach-approval", scene_attach_approval},
	{"attach-starting", scene_attach_starting},
	{"settings", scene_settings},
	{"rules", scene_rules},
	{"rules-blocked", scene_rules_blocked},
	{"rules-builder", scene_rules_builder},
	{"rules-forward", scene_rules_forward},
	{"rules-reload-error", scene_rules_reload_error},
}

SCENE_TIME :: 100.0 // the clock of every scene, in seconds

run_screens :: proc(dir: string) -> int {
	_ = sdl.SetHint(sdl.HINT_VIDEO_DRIVER, "offscreen")
	if !sdl.Init({.VIDEO}) {
		fmt.eprintln("noirvpn: SDL_Init:", sdl.GetError())
		return 1
	}
	defer sdl.Quit()
	if err := os.make_directory_all(dir); err != nil && !os.is_dir(dir) {
		fmt.eprintln("noirvpn: cannot create", dir)
		return 1
	}
	for density in 1 ..= 2 {
		if !render_all(dir, density) {
			return 1
		}
	}
	return 0
}

// The software renderer rounds vertices to whole pixels, so no anti-aliasing at
// fractional coordinates. Pictures are drawn at RENDER_SCALE times the logical
// size, then averaged down to the density asked for.
RENDER_SCALE :: 4

render_all :: proc(dir: string, density: int) -> bool {
	scale := f32(RENDER_SCALE)
	pw, ph := i32(WIN_W * RENDER_SCALE), i32(WIN_H * RENDER_SCALE)
	app := new(App)
	app.headless = true
	app.fixed_scale = true
	app.frame_border = true
	props := sdl.CreateProperties()
	_ = sdl.SetNumberProperty(props, sdl.PROP_WINDOW_CREATE_WIDTH_NUMBER, i64(pw))
	_ = sdl.SetNumberProperty(props, sdl.PROP_WINDOW_CREATE_HEIGHT_NUMBER, i64(ph))
	_ = sdl.SetBooleanProperty(props, sdl.PROP_WINDOW_CREATE_HIDDEN_BOOLEAN, true)
	// See create_window: the offscreen driver needs no graphics context here.
	_ = sdl.SetBooleanProperty(props, sdl.PROP_WINDOW_CREATE_EXTERNAL_GRAPHICS_CONTEXT_BOOLEAN, true)
	app.window = sdl.CreateWindowWithProperties(props)
	sdl.DestroyProperties(props)
	if app.window == nil {
		fmt.eprintln("noirvpn: SDL_CreateWindow:", sdl.GetError())
		return false
	}
	defer sdl.DestroyWindow(app.window)
	app.renderer = sdl.CreateRenderer(app.window, sdl.SOFTWARE_RENDERER)
	if app.renderer == nil {
		fmt.eprintln("noirvpn: SDL_CreateRenderer:", sdl.GetError())
		return false
	}
	defer sdl.DestroyRenderer(app.renderer)
	if !app_setup(app, scale) {
		return false
	}
	app.u.g.always = true // every scene is read back: draw every frame
	ui.gfx_set_supersample(&app.u.g, f32(density))
	start_profiles, start_count := app.profiles, app.n_profiles
	for s in scenes {
		// Fresh state for each scene.
		app.profiles, app.n_profiles = start_profiles, start_count
		app.depth = 0
		app.stack[0] = .List
		app.conn.phase = .Disconnected
		app.conn.profile = 0
		app.shown = 0
		app.link.state = .Searching
		app.link.manage = .Unavailable
		app.pending_delete = -1
		app.quit_prompt = false
		app.confirm = {}
		app.prompt_hide = false
		app.has_tray = false
		app.message = ""
		app.settings = {}
		app.now = SCENE_TIME
		app.u.focus = 0
		ui.menu_close(&app.u, MENU_ROW)
		ui.menu_close(&app.u, MENU_PLUS)
		app.conn_more = false
		set_text(&app.link.auth_kind, "")
		set_text(&app.link.auto_note, "")
		set_text(&app.link.datapath_mode, "")
		app.link.service = false
		rules_reset(&app.rules)
		acl_sample(app)
		settle(app)
		s.setup(app)
		settle(app)
		name := density == 1 ? s.name : fmt.tprintf("%s@2x", s.name)
		path := fmt.tprintf("%s/%s.png", dir, name)
		if !capture(app, path, RENDER_SCALE / density) {
			return false
		}
		fmt.println(path)
		free_all(context.temp_allocator)
	}
	return true
}

// settle builds a few frames so that hover, focus, scroll limits and popups settle.
settle :: proc(app: ^App) {
	for _ in 0 ..< 4 {
		build(app, 1)
	}
}

// capture reads the rendered frame, averages every factor x factor block to one
// pixel and writes it as PNG.
capture :: proc(app: ^App, path: string, factor: int) -> bool {
	present(app)
	surf := sdl.RenderReadPixels(app.renderer, nil)
	if surf == nil {
		fmt.eprintln("noirvpn: RenderReadPixels:", sdl.GetError())
		return false
	}
	defer sdl.DestroySurface(surf)
	rgba := sdl.ConvertSurface(surf, .RGBA32)
	if rgba == nil {
		fmt.eprintln("noirvpn: ConvertSurface:", sdl.GetError())
		return false
	}
	defer sdl.DestroySurface(rgba)
	src := ([^]u8)(rgba.pixels)
	ow, oh := int(rgba.w) / factor, int(rgba.h) / factor
	out := make([]u8, ow * oh * 4, context.temp_allocator)
	n := factor * factor
	for y in 0 ..< oh {
		for x in 0 ..< ow {
			sum: [4]int
			for dy in 0 ..< factor {
				row := (y * factor + dy) * int(rgba.pitch)
				for dx in 0 ..< factor {
					p := row + (x * factor + dx) * 4
					for c in 0 ..< 4 {
						sum[c] += int(src[p + c])
					}
				}
			}
			for c in 0 ..< 4 {
				out[(y * ow + x) * 4 + c] = u8((sum[c] + n / 2) / n)
			}
		}
	}
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	if stbi.write_png(cpath, i32(ow), i32(oh), 4, raw_data(out), auto_cast (ow * 4)) == 0 {
		fmt.eprintln("noirvpn: cannot write", path)
		return false
	}
	return true
}

// ---- Scenes ----

scene_list :: proc(app: ^App) {}

scene_list_menu :: proc(app: ^App) {
	// The menu of the first row, opened as a click on its button would.
	u := &app.u
	ui.menu_open(u, MENU_ROW, row_menu_items[:], 400 - 8 - 1, 56 + (ROW_H - 40) / 2 + 40)
	app.menu_row = 0
}

scene_plus_menu :: proc(app: ^App) {
	ui.menu_open(&app.u, MENU_PLUS, plus_menu_items[:], 400 - 8 - 1, 48)
}

scene_list_delete :: proc(app: ^App) {
	app.pending_delete = 1
}

scene_list_empty :: proc(app: ^App) {
	app.n_profiles = 0
}

scene_list_message :: proc(app: ^App) {
	set_message(app, "The profile was not imported. The service found a problem: Line 12, up: runs a program (and 2 more)", true)
}

// scene_conn_idle is a row just opened: no connection yet.
scene_conn_idle :: proc(app: ^App) {
	open_connection(app, 1)
}

scene_connecting :: proc(app: ^App) {
	start_connection(app, 2)
	conn_reset(&app.conn, 2, .Retry, app.now - 0.5)
	app.conn.attempt = 2
	set_text(&app.conn.failure, "The secure connection could not be set up")
}

scene_credentials :: proc(app: ^App) {
	start_connection(app, 2)
	app.conn.phase = .Credentials
	app.conn.attempt = 1
}

scene_web_sign_in :: proc(app: ^App) {
	start_connection(app, 1)
	app.conn.phase = .Web_Sign_In
	app.conn.attempt = 1
	l := &app.link
	l.web = true
	set_text(&l.web_url, "https://login.example.com/sso/start?state=8f2c")
	l.web_deadline = app.now + 272
	l.web_opened = true
	set_text(&l.web_note, WEB_OPENED)
}

scene_handshake :: proc(app: ^App) {
	start_connection(app, 0)
	app.conn.phase = .Handshake
	app.conn.phase_start = app.now
}

scene_long_names :: proc(app: ^App) {
	scene_up(app)
	p := &app.profiles[2]
	p.name = "Corporate remote access VPN"
	p.host = "gateway-01.eu-central.vpn.example.organisation.net"
}

scene_stopped :: proc(app: ^App) {
	start_connection(app, 0)
	app.conn.phase = .Stopped
}

scene_error :: proc(app: ^App) {
	start_connection(app, 1)
	app.conn.phase = .Failed
	app.conn.attempt = 3
	set_text(&app.conn.failure, "The server cannot be reached")
}

scene_up :: proc(app: ^App) {
	start_connection(app, 2)
	c := &app.conn
	conn_up(c, app.now - 60)
	c.count = 0
	c.rx_bytes, c.tx_bytes, c.rx_packets, c.tx_packets = 0, 0, 0, 0
	conn_prefill(c, 61)
	c.next_sample = app.now + 1
}

// scene_up_dns is the end of a connected view: the DNS and route cards.
scene_up_dns :: proc(app: ^App) {
	scene_up(app)
	settle(app)
	scroll_to(app, "conn", 10000)
	hover_scrollbar(app)
}

// scene_profile_dco is the Use DCO switch (Linux; -define:DCO_UI=true
// elsewhere) of a service that runs without DCO.
scene_profile_dco :: proc(app: ^App) {
	open_profile(app, 2)
	app.link.service = true
	set_text(&app.link.datapath_mode, "userspace")
	settle(app)
	scroll_to(app, "profile", app.edit.overrides_y + 330)
	hover_scrollbar(app)
}

// scene_profile_dco_service is the Use DCO switch when the service has DCO:
// the switch shows the choice of the profile (on) and can be changed.
scene_profile_dco_service :: proc(app: ^App) {
	open_profile(app, 2)
	app.link.service = true
	set_text(&app.link.datapath_mode, "auto")
	settle(app)
	scroll_to(app, "profile", app.edit.overrides_y + 330)
	hover_scrollbar(app)
}

// scene_up_no_dco is a live tunnel that runs without DCO although the service
// has it (Linux; -define:DCO_UI=true elsewhere).
scene_up_no_dco :: proc(app: ^App) {
	scene_up(app)
	app.link.service = true
	set_text(&app.link.datapath_mode, "auto")
	set_text(&app.conn.datapath, "userspace")
	settle(app)
	scroll_to(app, "conn", 420)
}

// scene_up_more shows the log and the pushed settings below the details.
scene_up_more :: proc(app: ^App) {
	scene_up(app)
	app.conn_more = true
	settle(app)
	scroll_to(app, "conn", 420)
}

scene_error_more :: proc(app: ^App) {
	scene_error(app)
	app.conn_more = true
}

scene_quit_connected :: proc(app: ^App) {
	scene_up(app)
	request_quit(app)
}

scene_quit_connecting :: proc(app: ^App) {
	scene_connecting(app)
	request_quit(app)
}

scene_close_idle :: proc(app: ^App) {
	app.has_tray = true
	request_close(app)
}

scene_close_connected :: proc(app: ^App) {
	scene_up(app)
	app.has_tray = true
	request_close(app)
}

// hover_scrollbar parks the pointer at the right edge, as when a scroll area was in use.
hover_scrollbar :: proc(app: ^App) {
	app.u.ctx.mouse_pos = {390, 300}
	app.u.ctx.last_mouse_pos = {390, 300}
}

scene_profile :: proc(app: ^App) {
	open_profile(app, 1)
	hover_scrollbar(app)
}

scene_overrides :: proc(app: ^App) {
	open_profile(app, 2)
	e := &app.edit
	domain_add(e, "corp.example.com")
	domain_add(e, "lab.example.org")
	e.dirty = true
	settle(app)
	scroll_to(app, "profile", e.overrides_y - 26)
	hover_scrollbar(app)
}

scene_overrides_error :: proc(app: ^App) {
	open_profile(app, 2)
	e := &app.edit
	domain_add(e, "corp.example.com")
	domain_add(e, "bad name")
	domain_add(e, "Corp.Example.com")
	e.dirty = true
	settle(app)
	scroll_to(app, "profile", e.overrides_y - 26)
	hover_scrollbar(app)
}

scene_attach :: proc(app: ^App) {
	app.stack[0] = .Attach
	app.link.state = .Not_Found
	set_text(&app.link.looked, "/run/noirvpn, /run/user/1000/noirvpn")
}

scene_attach_denied :: proc(app: ^App) {
	app.stack[0] = .Attach
	app.link.state = .Denied
}

scene_attach_approval :: proc(app: ^App) {
	app.stack[0] = .Attach
	app.link.state = .Not_Found
	app.link.manage = .Requires_Approval
}

scene_attach_starting :: proc(app: ^App) {
	app.stack[0] = .Attach
	app.link.state = .Not_Found
	app.link.manage = .Enabled
	set_text(&app.link.looked, "/var/run/noirvpn")
}

scene_settings :: proc(app: ^App) {
	push_view(app, .Settings)
	hover_scrollbar(app)
}

scene_create_empty :: proc(app: ^App) {
	create_open(app)
}

scene_create_errors :: proc(app: ^App) {
	create_open(app)
	f := &app.edit.f
	ui.field_set(&f.host, "vpn example")
	ui.field_set(&f.fingerprint, "28:61:7C:C6")
	ui.field_set(&f.mtu, "9000")
	create_submit(app)
	hover_scrollbar(app)
}

scene_create_advanced :: proc(app: ^App) {
	create_open(app)
	e := &app.edit
	f := &e.f
	ui.field_set(&e.name, "Office")
	ui.field_set(&f.host, "gw.example.org")
	transport_set(f, .Tls)
	f.advanced = true
	pem_set(e, &f.ca, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	f.pq = .Require
	ui.field_set(&f.sni, "cdn.example.net")
	list_add(e, .Extra, "verb 4")
	settle(app)
	scroll_to(app, "create", 10000)
	hover_scrollbar(app)
}

@(private = "file")
scene_fill :: proc(app: ^App) {
	create_open(app)
	e := &app.edit
	ui.field_set(&e.name, "Laptop")
	ui.field_set(&e.f.host, "vpn.example.com")
	ui.field_set(&e.f.fingerprint, SAMPLE_FP)
	create_submit(app)
}

scene_create_key :: proc(app: ^App) {
	scene_fill(app)
}

scene_profile_created :: proc(app: ^App) {
	scene_fill(app)
	made_open(app)
	hover_scrollbar(app)
}

// scene_profile_identity is the identity group of an imported profile: the key
// type and the key pin as the line of the peers file.
scene_profile_identity :: proc(app: ^App) {
	open_profile(app, 1)
	settle(app)
	scroll_to(app, "profile", 150)
	hover_scrollbar(app)
}

// scene_profile_sign_in is a profile that reads its login and the passphrase
// of its key from files; the passphrase file is open to others.
scene_profile_sign_in :: proc(app: ^App) {
	open_profile(app, 2)
	e := &app.edit
	e.user_pass, e.askpass = true, true
	set_text(&e.login_file, "/home/alice/vpn/work-login.txt")
	set_text(&e.pass_file, "/home/alice/vpn/work-key.pass")
	set_text(&e.pass_problem, "Other users can open /home/alice/vpn/work-key.pass. To fix this, run: chmod 600 /home/alice/vpn/work-key.pass")
	settle(app)
	scroll_to(app, "profile", 330)
	hover_scrollbar(app)
}

// scene_profile_file is the group of the profile file.
scene_profile_file :: proc(app: ^App) {
	open_profile(app, 1)
	settle(app)
	scroll_to(app, "profile", 1100)
	hover_scrollbar(app)
}

// scene_profile_reload is Reload of the profile of the tunnel, with a
// change: it asks for Reconnect.
scene_profile_reload :: proc(app: ^App) {
	open_profile(app, 1)
	e := &app.edit
	set_text(&e.reload_msg, "Reloaded. Reconnect to apply the changes.")
	e.reconnect = true
	settle(app)
	scroll_to(app, "profile", 1100)
	hover_scrollbar(app)
}

// scene_connection_key_pass is the card that asks for the passphrase of the
// key, after the passphrase file could not be used.
scene_connection_key_pass :: proc(app: ^App) {
	scene_credentials(app)
	set_text(&app.link.auth_kind, "key_pass")
	set_text(&app.link.auto_note, "Other users can open /home/alice/vpn/work-key.pass. To fix this, run: chmod 600 /home/alice/vpn/work-key.pass")
	settle(app)
}

// scene_profile_advanced is the end of an imported profile with a request
// that waits.
scene_profile_advanced :: proc(app: ^App) {
	open_profile(app, 1)
	app.edit.request = true
	settle(app)
	scroll_to(app, "profile", 10000)
	hover_scrollbar(app)
}

scene_key_request_new :: proc(app: ^App) {
	open_profile(app, 1)
	key_request_open(app)
}

scene_key_request :: proc(app: ^App) {
	open_profile(app, 1)
	app.edit.request = true
	key_request_open(app)
	hover_scrollbar(app)
}

@(private = "file")
scene_cert :: proc(app: ^App, pin: string) {
	scene_key_request(app)
	app.keyreq.cert = Cert_Read {
		subject     = strings.clone("CN=alice, O=Example"),
		issuer      = strings.clone("CN=Example Issuing CA, O=Example"),
		common_name = strings.clone("alice"),
		not_before  = strings.clone("2026-11-01T09:00:00Z"),
		not_after   = strings.clone("2027-11-01T09:00:00Z"),
		pin         = strings.clone(pin),
	}
	app.keyreq.has_cert = true
	settle(app)
	scroll_to(app, "keyreq", 10000)
}

scene_key_request_cert :: proc(app: ^App) {
	scene_cert(app, SAMPLE_PIN)
}

scene_key_request_mismatch :: proc(app: ^App) {
	scene_cert(app, "sha256:2nQHq9b0Zl8yYV0wN1rCk3mXo7tE4uJ6fPa5sGdLhKc=")
}

scene_key_request_confirm :: proc(app: ^App) {
	scene_cert(app, SAMPLE_PIN)
	confirm_open(app, .Set_Key)
}

scene_key_request_done :: proc(app: ^App) {
	scene_key_request(app)
	key_set(app)
}

// scene_rules is the top of the Inbound rules view of a live tunnel.
scene_rules :: proc(app: ^App) {
	scene_up(app)
	rules_open(app)
	hover_scrollbar(app)
}

// scene_rules_blocked is the list of blocked connections and the config file.
scene_rules_blocked :: proc(app: ^App) {
	scene_rules(app)
	settle(app)
	scroll_to(app, "rules", app.rules.blocked_y - 8)
}

// scene_rules_builder is the builder with a line, and two lines to copy.
scene_rules_builder :: proc(app: ^App) {
	scene_rules(app)
	r := &app.rules
	r.proto = .Tcp
	ui.field_set(&r.addr, "192.168.50.20")
	ui.field_set(&r.port, "8443")
	rules_add(r, BLOCK_ALL_BUT_PING)
	rules_add(r, "allow-inbound :22 tcp")
	settle(app)
	scroll_to(app, "rules", r.builder_y - 8)
}

// scene_rules_forward is the builder of a forward, with a problem.
scene_rules_forward :: proc(app: ^App) {
	scene_rules(app)
	r := &app.rules
	r.kind = .Forward
	r.fproto = .Both
	ui.field_set(&r.fport, "5353")
	ui.field_set(&r.fhost, "fd00::1")
	ui.field_set(&r.ftport, "70000")
	settle(app)
	scroll_to(app, "rules", r.builder_y - 8)
}

// scene_rules_reload_error is Check and reload of a config file with a
// problem.
scene_rules_reload_error :: proc(app: ^App) {
	scene_rules(app)
	a := &app.link.acl
	set_text(&a.reload_msg, "Nothing changed. The service found a problem: Line 7, allow-inbound: '10.0.0.300' is not an address, a prefix or a host name")
	a.reload_error = true
	settle(app)
	scroll_to(app, "rules", app.rules.config_y - 8)
}
