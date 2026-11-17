// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// noirvpn desktop client: SDL3 (window, events), microui (layout, input),
// package ui (styled drawing). The client daemon owns the tunnel; the GUI
// follows it over the control bus (link.odin).

import "core:fmt"
import "core:math"
import "core:os"
import "core:time"
import sdl "vendor:sdl3"
import pf "profiles"
import "ui"

USAGE :: `usage: noirvpn-desktop [options]

options:
  --socket PATH   connect to the client daemon at this control socket
  --simulate      show simulated data instead of using a service
  --screens DIR   render every view to PNG files in DIR (no window), at 1x and 2x
  --open VIEW     simulated, start in a view: list, connecting, credentials, up, profile, attach, settings
  --scale SIZE    size of the UI for this run: auto, or 100 to 300 in steps of 25 (percent)
  --renderer R    how the window is drawn: auto, gpu or cpu (auto: gpu on Windows, cpu
                  on other systems). If the cpu renderer cannot start, gpu is used instead
  --stats         print one line per drawn frame to stderr
  --selftest      drive the UI with synthetic events and check the result (no window)
  --live-test     test the link against a running client daemon; this disconnects and
                  reconnects the tunnel. A service needs two --profile files, which are
                  imported into a temporary store, connected and switched
  --profile FILE  a profile file for --live-test (give it twice)
  --peers FILE    with --live-test: create a profile of each key type, add its line
                  to this peers file of the server, connect and disconnect; the
                  file is restored at the end. It requires --fingerprint, and --reload
                  when the server must be told about the new file
  --fingerprint HEX  the server fingerprint for --peers
  --reload CMD    a shell command that tells the server to read its peers file again
  --remote HOST:PORT  the server for --peers (default 127.0.0.1:1194, UDP)
  --service-status      macOS app bundle: print the state of the service job
                        (enabled, requires-approval, not-registered, not-found)
  --service-register    macOS app bundle: register the service job with the system
  --service-unregister  macOS app bundle: remove the service job, which stops the service
  -h, --help      show this text
`

// The options of the live test of profile creation (--peers).
Live_Create :: struct {
	peers:       string,
	fingerprint: string,
	reload:      string,
	host:        string,
	port:        int,
}

WIN_W :: 400
WIN_H :: 720

STALL_RETRY :: 0.002 // seconds before a frame that had no pixels is tried again
CPU_FRAME_GAP :: 1.0 / 15 // CPU renderer: least seconds between two frames. 15 frames a second keep the CPU share low while a view scrolls

stats_on := false

now_seconds :: proc() -> f64 {
	@(static) start: time.Tick
	@(static) started: bool
	if !started {
		start = time.tick_now()
		started = true
	}
	return time.duration_seconds(time.tick_diff(start, time.tick_now()))
}

main :: proc() {
	screens_dir := ""
	open_view := ""
	scale_arg := -1 // -1 uses the saved setting
	renderer_arg: Maybe(Renderer) // nothing uses the saved setting
	socket := ""
	simulate := false
	live := false
	live_files := make([dynamic]string)
	lc := Live_Create{host = "127.0.0.1", port = 1194}
	args := os.args[1:]
	for i := 0; i < len(args); i += 1 {
		switch args[i] {
		case "--screens":
			if i + 1 >= len(args) {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			i += 1
			screens_dir = args[i]
		case "--open":
			if i + 1 >= len(args) {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			i += 1
			open_view = args[i]
		case "--scale":
			if i + 1 >= len(args) {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			i += 1
			pct, ok := parse_scale(args[i])
			if !ok {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			scale_arg = pct
		case "--renderer":
			if i + 1 >= len(args) {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			i += 1
			r, ok := parse_renderer(args[i])
			if !ok {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			renderer_arg = r
		case "--socket":
			if i + 1 >= len(args) {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			i += 1
			socket = args[i]
		case "--simulate":
			simulate = true
		case "--selftest":
			os.exit(selftest())
		case "--live-test":
			live = true
		case "--profile":
			if i + 1 >= len(args) {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			i += 1
			append(&live_files, args[i])
		case "--peers", "--fingerprint", "--reload", "--remote":
			if i + 1 >= len(args) {
				fmt.eprint(USAGE)
				os.exit(2)
			}
			i += 1
			switch args[i - 1] {
			case "--peers":
				lc.peers = args[i]
			case "--fingerprint":
				lc.fingerprint = args[i]
			case "--reload":
				lc.reload = args[i]
			case "--remote":
				host, port := split_host_port(args[i])
				if host == "" || port <= 0 {
					fmt.eprint(USAGE)
					os.exit(2)
				}
				lc.host, lc.port = host, port
			}
		case "--service-status", "--service-register", "--service-unregister":
			os.exit(service_cli(args[i]))
		case "--stats":
			stats_on = true
		case "-h", "--help":
			fmt.print(USAGE)
			return
		case:
			fmt.eprint(USAGE)
			os.exit(2)
		}
	}
	if live {
		when BUS_LINK {
			os.exit(live_test(socket, live_files[:], lc))
		} else {
			fmt.eprintln("noirvpn: --live-test requires the bus")
			os.exit(2)
		}
	}
	if screens_dir != "" {
		os.exit(run_screens(screens_dir))
	}
	os.exit(run_window(open_view, scale_arg, renderer_arg, socket, simulate || open_view != ""))
}

// app_setup creates the renderer-bound state: the UI, the logo and the first data.
// With the CPU renderer the UI draws into the pixels that the presenter gives it.
app_setup :: proc(app: ^App, scale: f32) -> bool {
	if !ui.ui_init(&app.u, app.renderer, scale) {
		fmt.eprintln("noirvpn: could not load the fonts")
		return false
	}
	if app.cpu {
		app.u.g.acquire, app.u.g.acquire_data = presenter_acquire, &app.presenter
	}
	m, ok := ui.mask_from_png(LOGO_PNG)
	if !ok {
		fmt.eprintln("noirvpn: could not load the logo")
		return false
	}
	app.logo = m
	app_init(app)
	return true
}

// open_by_name jumps to a view for --open.
open_by_name :: proc(app: ^App, name: string) {
	switch name {
	case "connecting":
		start_connection(app, 1)
	case "credentials":
		start_connection(app, 2)
	case "up":
		start_connection(app, 0)
	case "profile":
		open_profile(app, 1)
	case "attach":
		app.stack[0] = .Attach
	case "settings":
		push_view(app, .Settings)
	}
}

run_window :: proc(open_view: string, scale_arg: int, renderer_arg: Maybe(Renderer), socket: string, simulate: bool) -> int {
	// Closing the window must reach request_close once. SDL by default also
	// sends QUIT after the last window's close request (a second request quits).
	// With 0, hiding the window leaves the app running.
	_ = sdl.SetHint(sdl.HINT_QUIT_ON_LAST_WINDOW_CLOSE, "0")
	// The identifier is the window class (X11) and app id (Wayland): it matches noirvpn.desktop.
	_ = sdl.SetAppMetadata("noirvpn", nil, "noirvpn")
	if !sdl.Init({.VIDEO}) {
		fmt.eprintln("noirvpn: SDL_Init:", sdl.GetError())
		return 1
	}
	defer sdl.Quit()
	app := new(App)
	app.link.kind = simulate ? .Sim : .Bus
	app.settings_file = settings_path()
	app.settings = settings_load(app.settings_file)
	app.window = create_window(saved_position(app.settings))
	if app.window == nil {
		fmt.eprintln("noirvpn: SDL_CreateWindow:", sdl.GetError())
		return 1
	}
	defer sdl.DestroyWindow(app.window)
	app.frame_border = !frame_setup(app.window)
	_ = sdl.SetWindowHitTest(app.window, hit_test, nil)
	if scale_arg >= 0 {
		app.settings.scale = scale_arg
	}
	d, sc := window_scales(app.window)
	e := effective_scale(app.settings.scale, d, sc)
	resize_window(app, WIN_W, WIN_H, d, e)
	if stats_on {
		fmt.eprintfln("scale d=%.3f S=%.3f E=%.3f", d, sc, e)
	}
	choice := renderer_pick(renderer_arg.? or_else app.settings.renderer)
	if choice == .Cpu {
		if why := presenter_open(&app.presenter, app.window); why == "" {
			app.cpu = true
		} else {
			fmt.eprintfln("noirvpn: the CPU renderer could not start (%s), so the GPU renderer will be used instead", why)
		}
	}
	defer if app.cpu {
		presenter_close(&app.presenter)
	}
	if !app.cpu {
		app.renderer = sdl.CreateRenderer(app.window, nil)
		if app.renderer == nil {
			fmt.eprintln("noirvpn: SDL_CreateRenderer:", sdl.GetError())
			return 1
		}
		_ = sdl.SetRenderVSync(app.renderer, 1)
	}
	if stats_on {
		fmt.eprintfln("renderer %s", app.cpu ? "cpu" : "gpu")
	}
	if !app_setup(app, e) {
		return 1
	}
	app.eff = e
	app.u.input_k = d / e
	app.cursors[.Default] = sdl.CreateSystemCursor(.DEFAULT)
	app.cursors[.Text] = sdl.CreateSystemCursor(.TEXT)
	app.cursors[.Pointer] = sdl.CreateSystemCursor(.POINTER)
	_ = sdl.StartTextInput(app.window)
	if open_view != "" {
		app.now = now_seconds()
		open_by_name(app, open_view)
	}
	if app.link.kind == .Bus {
		app.store = pf.store_open()
		store_reload(app)
		bus_start(app, socket)
		app.now = now_seconds()
		link_tick(app)
	}
	defer bus_stop(app)
	defer tray_destroy(app)
	if !tray_create(app) && stats_on {
		fmt.eprintfln("tray: unavailable (%s)", sdl.GetError())
	} else if stats_on {
		fmt.eprintln("tray: created")
	}

	last := now_seconds()
	dirty := true
	frames := 0
	deadline: f64 // time of the next redraw that needs no input, or 0
	next_draw: f64 // CPU renderer: the earliest time of the next frame
	for !app.quit {
		// Sleep until an event arrives or a timed redraw is due. A frame that waits for
		// its slot (CPU renderer) is due at next_draw. A frame after a pause has no wait.
		now := now_seconds()
		timeout: i32 = -1
		if deadline > 0 {
			timeout = max(i32(math.ceil((deadline - now) * 1000)), 0)
		}
		if dirty {
			timeout = draw_wait(now, next_draw)
		}
		ev: sdl.Event
		got := timeout < 0 ? sdl.WaitEvent(&ev) : sdl.WaitEventTimeout(&ev, timeout)
		for got {
			if handle_app_event(app, &ev) {
				dirty = true
			}
			got = sdl.PollEvent(&ev)
		}
		if app.quit {
			break
		}
		now = now_seconds()
		app.now = now
		if link_poll(app) {
			dirty = true
		}
		if dialog_poll(app) {
			dirty = true
		}
		link_tick(app)
		if app.pos_save_at > 0 && now >= app.pos_save_at {
			pos_store(app)
		}
		if deadline > 0 && now >= deadline {
			dirty = true
		}
		if dirty && now >= next_draw {
			dt := f32(min(now - last, 0.1))
			last = now
			frame(app, dt)
			present(app)
			tray_sync(app)
			// With no pixels to draw into, the frame stays due and is tried again soon.
			dirty = app.u.g.stalled
			gap: f64 = app.cpu ? CPU_FRAME_GAP : 0
			next_draw = now + (app.u.g.stalled ? STALL_RETRY : gap)
			deadline = next_wake(app)
			frames += 1
			if stats_on {
				ww, wh: i32
				_ = sdl.GetWindowSize(app.window, &ww, &wh)
				fmt.eprintfln("frame %d t=%.3f E=%.3f window=%dx%d logical=%dx%d verts=%d indices=%d draws=%d skipped=%d renderer=%s draw=%.3fms", frames, now, app.eff, ww, wh, app.u.size.x, app.u.size.y, app.u.g.frame_verts, app.u.g.frame_idx, app.u.g.frame_calls, app.u.g.skipped, app.cpu ? "cpu" : "gpu", app.draw_ms)
			}
		}
		free_all(context.temp_allocator)
	}
	pos_store(app)
	return 0
}

// draw_wait is the milliseconds until a frame that is due at next_draw may be drawn.
draw_wait :: proc(now, next_draw: f64) -> i32 {
	return max(i32(math.ceil((next_draw - now) * 1000)), 0)
}

// next_wake is the time of the next redraw that is needed without input, or 0.
next_wake :: proc(app: ^App) -> f64 {
	wake: f64
	add :: proc(wake: ^f64, t: f64) {
		if t > 0 && (wake^ == 0 || t < wake^) {
			wake^ = t
		}
	}
	if app.u.animating {
		add(&wake, app.now + 1.0 / 60)
	}
	add(&wake, app.u.wake_at)
	add(&wake, app.pos_save_at)
	add(&wake, link_wake(app))
	if app.hidden {
		// No timed redraws for a window that nobody sees. The script goes on
		// when the window is shown again.
		return 0
	}
	if current_view(app) == .Connection {
		c := &app.conn
		switch {
		case c.phase == .Up && app.link.kind == .Sim:
			add(&wake, c.next_sample)
		case phase_busy(c.phase):
			// The state text pulses.
			add(&wake, app.now + PULSE_GAP)
		case c.phase == .Web_Sign_In:
			// The time left of the sign-in.
			add(&wake, app.now + 0.5)
		}
	}
	return wake
}

// handle_app_event passes an event to the window logic and the UI. It returns true
// when a redraw is needed.
handle_app_event :: proc(app: ^App, ev: ^sdl.Event) -> bool {
	u := &app.u
	if ev.type >= .WINDOW_FIRST && ev.type <= .WINDOW_LAST {
		// The window was shown, exposed or changed: draw the next frame even when it
		// equals the last one.
		u.g.force = true
	}
	#partial switch ev.type {
	case .QUIT:
		request_quit(app)
		return app.quit_prompt
	case .WINDOW_CLOSE_REQUESTED:
		request_close(app)
		return app.quit_prompt
	case .USER:
		// Pushed by a tray action: the state changed, so redraw.
		return true
	case .WINDOW_DISPLAY_CHANGED:
		// The other display may have room for the full window.
		app.refit = true
		app.rescale = true
		return true
	case .WINDOW_PIXEL_SIZE_CHANGED, .WINDOW_DISPLAY_SCALE_CHANGED:
		app.rescale = true
		return true
	case .WINDOW_MOVED:
		pos_moved(app)
		return false
	case .WINDOW_MINIMIZED, .WINDOW_HIDDEN:
		app.hidden = true
		return false
	case .WINDOW_RESTORED, .WINDOW_SHOWN:
		app.hidden = false
		return true
	case .WINDOW_EXPOSED, .WINDOW_RESIZED, .WINDOW_FOCUS_GAINED, .WINDOW_FOCUS_LOST:
		return true
	case .WINDOW_MOUSE_LEAVE:
		// Park the pointer outside so that no widget stays hovered.
		u.ctx.mouse_pos = {-1, -1}
		return true
	}
	if app.quit_prompt && (ev.type == .KEY_DOWN || ev.type == .KEY_UP) && (ev.key.key == sdl.K_RETURN || ev.key.key == sdl.K_KP_ENTER) {
		// A destructive prompt has no default action.
		return false
	}
	if ev.type == .MOUSE_BUTTON_DOWN {
		// microui finds the widget under the mouse while it builds a frame, so
		// build one before the press is recorded.
		app.now = now_seconds()
		build(app, 0)
	}
	changed := ui.handle_event(u, ev)
	if ev.type == .KEY_DOWN {
		// Held modifiers are lost if the key goes up before a frame is built.
		app.now = now_seconds()
		build(app, 0)
	}
	return changed
}

// frame builds the UI twice (the second pass settles hover and focus) and draws it.
frame :: proc(app: ^App, dt: f32) {
	build(app, dt)
	build(app, 0)
}

// present draws the last built frame to the window. A frame that equals the one on
// screen is not drawn.
present :: proc(app: ^App) {
	u := &app.u
	t0 := now_seconds()
	ui.gfx_begin(&u.g, ui.BG)
	ui.render(u)
	drawn := ui.gfx_end(&u.g)
	app.draw_ms = (now_seconds() - t0) * 1000
	if drawn {
		if app.cpu {
			presenter_show(&app.presenter)
		} else {
			_ = sdl.RenderPresent(app.renderer)
		}
	}
	if u.cursor != app.cursor_shown {
		app.cursor_shown = u.cursor
		_ = sdl.SetCursor(app.cursors[u.cursor])
	}
	if r, ok := u.ime_rect.?; ok {
		// The input method wants window coordinates.
		k := 1 / u.input_k
		rect := sdl.Rect{i32(r.x * k), i32(r.y * k), i32(r.w * k), i32(r.h * k)}
		_ = sdl.SetTextInputArea(app.window, &rect, 0)
	}
}
