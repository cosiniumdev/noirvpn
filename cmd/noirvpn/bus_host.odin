// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:time"
import "noir:bus"
import "noir:platform/event"
import "noir:proto/config"

// The daemon's side of the control bus: opening sockets,
// publishing events, taking requests from the loop, and what both daemon modes
// share (`status` head, `log.level`, `daemon.reload` checks). Server events and
// operations: server_bus.odin. Client: client_bus.odin. The bus never blocks the
// loop: `publish` and `reply_*` return at once, and at most BUS_BATCH requests
// are handled per wake-up.
//
// One `Bus` global serves whichever daemon runs.

// Requests handled per wake-up of the loop. The wake descriptor stays readable
// while more wait, so the loop comes back to them after its other work.
BUS_BATCH :: 16

Bus :: struct {
	// nil when both sockets are off.
	h:            ^bus.Host,
	mode:         bus.Daemon_Mode,
	name:         string,
	events_on:    bool,
	control_on:   bool,
	events_path:  string,
	control_path: string,
	// The config as it was loaded, and the arguments to parse it again.
	cfgw:         ^config.Config,
	reload_args:  []string,
	config_path:  string,
	started:      time.Time,
	// Event data and results are built here, one at a time.
	w:            bus.Writer,
	rw:           bus.Writer,
	w_ok:         bool,
	// stats.tick.
	stats_secs:   int,
	t_stats:      Timer,
	// Why the daemon stops, for `daemon.stop`.
	stop_reason:  string,
	stop_detail:  string,
}

B: Bus

// ------------------------------------------------------------------ opening

// `--allow-user` and `--allow-group`: set once at start, used at each bus setup
// and at `daemon.reload`.
BUS_ACCESS: bus.Access

// Checks `--allow-user` and `--allow-group` and keeps them in BUS_ACCESS.
// Returns the problem for the user, or "".
bus_access_check :: proc(cli: ^Cli) -> string {
	if cli.allow_error != "" {
		return cli.allow_error
	}
	if cli.allow_user == "" && cli.allow_group == "" {
		return ""
	}
	when ODIN_OS == .Windows {
		return "--allow-user and --allow-group are for Linux and macOS; on Windows, use bus-allow sid in the config"
	} else {
		if cli.allow_user != "" {
			if _, ok := bus.default_resolver(.Uid, cli.allow_user); !ok {
				return fmt.tprintf("--allow-user: '%s' is not a user on this host", cli.allow_user)
			}
		}
		if cli.allow_group != "" {
			if _, ok := bus.default_resolver(.Gid, cli.allow_group); !ok {
				return fmt.tprintf("--allow-group: '%s' is not a group on this host", cli.allow_group)
			}
		}
		BUS_ACCESS = {user = cli.allow_user, group = cli.allow_group}
		return ""
	}
}

// Checks the bus part of the config (paths, and that every `bus-allow` name
// exists) and prints what is wrong. For `--check-config` and for the start.
bus_check :: proc(c: ^config.Common_Config, mode: bus.Daemon_Mode, name: string) -> (ok: bool) {
	setup, err := bus.setup_from_config(c, mode, name, access = BUS_ACCESS)
	defer bus.setup_destroy(&setup)
	switch err {
	case .None:
		return true
	case .Bad_Events_Path, .Bad_Control_Path:
		fmt.eprintfln("noirvpn: %s", bus.setup_error_string(err))
	case .Unknown_Name:
		for n in setup.unresolved {
			fmt.eprintfln("noirvpn: bus-allow: '%s' is not a user or group on this host", n)
		}
	}
	return false
}

// The instance name: `--name`, else the config file's name, else "noirvpn".
bus_instance_name :: proc(cli_name: string, cfgw: ^config.Config) -> string {
	if cli_name != "" {
		return clean_instance_name(cli_name)
	}
	if len(cfgw.parsed.files) > 0 {
		return bus.instance_name(cfgw.parsed.files[0])
	}
	return strings.clone(bus.DEFAULT_NAME)
}

// Creates the bus socket folders before `rec_start`. The records' state folder is
// in the default socket folder, so a missing socket folder must get the bus mode
// and group first (the bus does not change an existing folder). A daemon with
// both sockets off creates nothing. `bus_start` reports errors.
bus_prepare_dirs :: proc(c: ^config.Common_Config, mode: bus.Daemon_Mode, name: string) {
	setup, err := bus.setup_from_config(c, mode, name, access = BUS_ACCESS)
	defer bus.setup_destroy(&setup)
	if err == .None {
		bus.prepare_dirs(setup.opts)
	}
}

// Opens the sockets and puts the wake descriptor in the loop. Publishes
// `daemon.start` (its `seq` is 1). With both sockets off nothing opens and every
// bus call below does nothing. False after logging the problem.
bus_start :: proc(
	loop: ^event.Loop,
	cfgw: ^config.Config,
	mode: bus.Daemon_Mode,
	name: string,
	args: []string,
	handler: event.Fd_Handler,
) -> bool {
	B = {}
	B.mode = mode
	B.name = name
	B.cfgw = (^config.Config)(rawptr(cfgw))
	B.reload_args = args
	B.started = time.now()
	if len(cfgw.parsed.files) > 0 {
		B.config_path = cfgw.parsed.files[0]
	}
	common := config.config_common(cfgw)
	B.stats_secs = common.stats_interval
	bus.writer_init(&B.w)
	bus.writer_init(&B.rw)
	B.w_ok = true

	setup, err := bus.setup_from_config(common, mode, name, access = BUS_ACCESS)
	defer bus.setup_destroy(&setup)
	if err != .None {
		logf(.Error, "bus: %s", bus.setup_error_string(err))
		for n in setup.unresolved {
			logf(.Error, "bus-allow: '%s' is not a user or group on this host", n)
		}
		return false
	}
	_, has_events := setup.opts.events.?
	_, has_control := setup.opts.control.?
	if !has_events && !has_control {
		logf(.Info, "bus: events and control are both disabled")
		return true
	}
	h, herr, nerr := bus.host_open(setup.opts)
	if herr != .None {
		logf(.Error, "bus: cannot open the sockets: %s%s", bus.open_error_string(herr), "" if nerr == .None else fmt.tprintf(" [%v]", nerr))
		return false
	}
	B.h = h
	B.events_on = has_events
	B.control_on = has_control
	B.events_path = strings.clone(setup.events)
	B.control_path = strings.clone(setup.control)
	if err := bus_watch(loop, h, handler); err != .None {
		logf(.Error, "bus: cannot watch the wake descriptor: %v", err)
		return false
	}
	if has_events {
		logf(.Notice, "bus: sending events on %s", B.events_path)
	}
	if has_control {
		logf(.Notice, "bus: accepting control requests on %s", B.control_path)
		when ODIN_OS != .Windows {
			ctl := setup.opts.control.?
			if mode := ctl.mode if ctl.mode != 0 else bus.DEFAULT_SOCKET_MODE; bus.euid() == 0 && ctl.group == "" && ctl.owner == "" && mode & 0o006 == 0 {
				logf(.Notice, "bus: only root can use the control socket; to let a user in (for example the desktop app), start with --allow-user NAME or --allow-group NAME")
			}
		}
	}
	return true
}

// `daemon.start`. Call it right after `bus_start`, before any other event.
bus_publish_start :: proc() {
	if w := bus_ev(); w != nil {
		bus.kv_str(w, "mode", "server" if B.mode == .Server else "client")
		bus.kv_str(w, "name", B.name)
		bus.kv_str(w, "version", VERSION_NUMBER)
		bus.kv_int(w, "pid", i64(os.get_pid()))
		bus.kv_str_or_null(w, "config", B.config_path, B.config_path != "")
		bus.kv_str(w, "datapath", bus_datapath())
		bus.kv_str_or_null(w, "control", B.control_path, B.control_path != "")
		bus.kv_str_or_null(w, "events", B.events_path, B.events_path != "")
		bus_emit("daemon.start")
	}
}

// `daemon.stop`, the last event, then the sockets close. `host_close` waits a
// moment for the workers and for nng to write the last messages. Safe to call if
// the bus never started.
bus_stop :: proc() {
	if B.h != nil {
		if w := bus_ev(); w != nil {
			bus.kv_str(w, "reason", B.stop_reason if B.stop_reason != "" else "signal")
			bus.kv_str_or_null(w, "detail", B.stop_detail, B.stop_detail != "")
			bus_emit("daemon.stop")
		}
		bus.host_close(B.h)
		B.h = nil
	}
	if B.w_ok {
		bus.writer_destroy(&B.w)
		bus.writer_destroy(&B.rw)
		B.w_ok = false
	}
	delete(B.events_path)
	delete(B.control_path)
	B.events_path, B.control_path = "", ""
	delete(B.name)
	B.name = ""
}

// After a failed start: the sockets close without a `daemon.stop`.
bus_stop_quiet :: proc() {
	if B.h != nil {
		bus.host_close(B.h, 0)
		B.h = nil
	}
	B.stop_reason = "error"
	bus_stop()
}

// ------------------------------------------------------------------ events

// Starts the data object of an event. nil when no events socket is open (then
// the caller skips the work). Finish with `bus_emit`.
bus_ev :: proc() -> ^bus.Writer {
	if B.h == nil || !B.events_on {
		return nil
	}
	bus.writer_reset(&B.w)
	bus.begin_obj(&B.w)
	return &B.w
}

// Closes the data object and publishes it under `topic`.
bus_emit :: proc(topic: string) {
	bus.end(&B.w)
	if !B.w.failed {
		bus.publish(B.h, topic, bus.writer_bytes(&B.w))
	} else {
		// Out of memory: still use a sequence number, so subscribers see a gap.
		bus.publish(B.h, topic, nil)
	}
	bus.writer_reset(&B.w)
}

// ----------------------------------------------------------------- replies

// Starts a result object.
bus_res :: proc() -> ^bus.Writer {
	bus.writer_reset(&B.rw)
	bus.begin_obj(&B.rw)
	return &B.rw
}

// Closes the result and sends it.
bus_ok :: proc(req: ^bus.Request) {
	bus.end(&B.rw)
	if B.rw.failed {
		bus.reply_error(B.h, req, .Internal, "out of memory")
	} else {
		bus.reply_ok(B.h, req, bus.writer_bytes(&B.rw))
	}
	bus.writer_reset(&B.rw)
}

// Closes the result, sends it and overwrites the buffer (it held a password).
bus_ok_wipe :: proc(req: ^bus.Request) {
	bus_ok(req)
	if len(B.rw.buf) > 0 || cap(B.rw.buf) > 0 {
		mem.zero_explicit(raw_data(B.rw.buf), cap(B.rw.buf))
	}
}

bus_err :: proc(req: ^bus.Request, code: bus.Error_Code, text: string) {
	bus.reply_error(B.h, req, code, text)
}

bus_bad_arg :: proc(req: ^bus.Request, name: string, e: bus.Arg_Error) {
	bus.reply_bad_arg(B.h, req, name, e)
}

// ---------------------------------------------------------------- the loop

// Takes the waiting requests and notices. `handle` handles one request.
bus_drain :: proc(handle: proc(req: ^bus.Request)) {
	if B.h == nil {
		return
	}
	for _ in 0 ..< BUS_BATCH {
		req, ok := bus.next_request(B.h)
		if !ok {
			break
		}
		handle(req)
	}
	for _ in 0 ..< 32 {
		n, ok := bus.next_notice(B.h)
		if !ok {
			break
		}
		bus_log_notice(&n)
	}
}

bus_log_notice :: proc(n: ^bus.Notice) {
	who := ""
	if n.has_creds {
		who = fmt.tprintf(" uid=%d gid=%d", n.uid, n.gid)
		if n.has_pid {
			who = fmt.tprintf("%s pid=%d", who, n.pid)
		}
	}
	op := bus.notice_op(n)
	text := bus.notice_text(n)
	switch n.kind {
	case .Denied:
		logf(.Warn, "bus: denied%s op=%s: %s", who, op, text)
	case .Busy:
		logf(.Warn, "bus: busy%s op=%s: %s", who, op, text)
	case .Reply_Timeout:
		logf(.Warn, "bus: no reply in time%s op=%s: %s", who, op, text)
	case .Bad_Request:
		logf(.Info, "bus: bad request%s op=%s: %s", who, op, text)
	}
}

// ------------------------------------------------------------ common ops

// Writes the fields every `status` result starts with. The caller adds its
// own object and closes the result with `bus_ok`.
bus_status_head :: proc(w: ^bus.Writer) {
	bus.kv_str(w, "mode", "server" if B.mode == .Server else "client")
	bus.kv_str(w, "name", B.name)
	bus.kv_str(w, "version", VERSION_NUMBER)
	bus.kv_int(w, "pid", i64(os.get_pid()))
	buf: [24]u8
	bus.kv_str(w, "started", bus.format_ts(B.started, &buf))
	bus.kv_u64(w, "uptime_s", bus_uptime_s())
	bus.kv_str_or_null(w, "config", B.config_path, B.config_path != "")
	bus.kv_int(w, "verb", i64(log_get_verb()))
	log_file := ""
	when ODIN_OS == .Windows {
		log_file = svc_log_path
	}
	bus.kv_str_or_null(w, "log_file", log_file, log_file != "")
	// systemd sets JOURNAL_STREAM when stderr goes to the journal.
	_, journal := os.lookup_env("JOURNAL_STREAM", context.temp_allocator)
	bus.kv_bool(w, "log_journal", journal)
	bus.kv_obj(w, "bus")
	run, seq := bus.host_position(B.h)
	bus.kv_str(w, "run", run)
	bus.kv_u64(w, "seq", seq)
	bus.kv_bool(w, "events", B.events_on)
	bus.kv_u64(w, "publish_errors", bus.host_stats(B.h).publish_errors)
	bus.end(w)
}

bus_uptime_s :: proc() -> u64 {
	d := time.diff(B.started, time.now())
	return u64(max(d, 0) / time.Second)
}

// `log.level`.
bus_op_log_level :: proc(req: ^bus.Request) {
	v, e := bus.arg_int_range(req, "verb", 0, 4)
	if e != .None {
		bus_bad_arg(req, "verb", e)
		return
	}
	prev := log_get_verb()
	log_set_verb(int(v))
	logf(.Notice, "bus: the log level is now %d (was %d)", v, prev)
	w := bus_res()
	bus.kv_int(w, "verb", v)
	bus.kv_int(w, "previous", i64(prev))
	bus_ok(req)
}

// What a `daemon.reload` found in the new config. Free with `reload_plan_destroy`.
Reload_Plan :: struct {
	cfg:     config.Config,
	cfg_ok:  bool,
	policy:  bus.Policy,
	policy_ok: bool,
	// Options whose value changed and that need a restart.
	ignored: [dynamic]string,
	verb:    int,
}

reload_plan_destroy :: proc(p: ^Reload_Plan) {
	if p.cfg_ok {
		config.destroy(&p.cfg)
	}
	if p.policy_ok {
		bus.policy_destroy(&p.policy)
	}
	for s in p.ignored {
		delete(s)
	}
	delete(p.ignored)
	p^ = {}
}

// Options that `daemon.reload` applies itself. A change in any other option is
// reported as `ignored`. (`peer-keys` is not here: its path is not swapped, the
// file at the old path is read again.)
RELOAD_APPLIED :: [?]string{"bus-allow", "verb", "stats-interval", "config"}
// The client also applies its rule lines (acl_reload).
RELOAD_APPLIED_CLIENT :: [?]string{"allow-inbound", "forward", "acl-resolve-interval", "forward-max-conns"}

// Reads the config again and only checks it. `err` (temp
// allocated) says what is wrong. The new config must be for the same role.
reload_prepare :: proc(plan: ^Reload_Plan) -> (err: string) {
	parsed := config.parse_args(B.reload_args)
	plan.cfg = config.build(parsed)
	plan.cfg_ok = true
	if !config.ok(&plan.cfg) {
		return first_error_lines(&plan.cfg)
	}
	want: config.Role = .Server if B.mode == .Server else .Client
	if plan.cfg.role != want {
		return "the config is not for the same kind of daemon any more"
	}
	common := config.config_common(&plan.cfg)
	unresolved: [dynamic]string
	plan.policy, unresolved = bus.policy_from_config(bus.access_rules(common.bus_allow, BUS_ACCESS), bus.euid(), bus.default_resolver)
	plan.policy_ok = true
	defer delete(unresolved)
	if len(unresolved) > 0 {
		return fmt.tprintf("bus-allow: '%s' is not a user or group on this host", unresolved[0])
	}
	plan.verb = plan.cfg.server.verb if B.mode == .Server else plan.cfg.client.verb
	plan.ignored = make([dynamic]string)
	diff_directives(B.cfgw.parsed.directives, plan.cfg.parsed.directives, &plan.ignored)
	return ""
}

// The first few errors of a config, in one line.
first_error_lines :: proc(cfg: ^config.Config) -> string {
	sb := strings.builder_make(context.temp_allocator)
	n := 0
	for d in cfg.diags {
		if d.severity != .Error {
			continue
		}
		if n > 0 {
			strings.write_string(&sb, "; ")
		}
		strings.write_string(&sb, strings.trim_space(config.format_diagnostics({d}, context.temp_allocator)))
		n += 1
		if n == 3 {
			break
		}
	}
	text := strings.to_string(sb)
	if len(text) > 400 {
		text = text[:400]
	}
	return text
}

// Names of options that differ between two directive lists and are not applied
// by a reload. Appends clones to `out`, sorted by name.
diff_directives :: proc(old, new_: []config.Directive, out: ^[dynamic]string) {
	a := directive_summary(old)
	b := directive_summary(new_)
	defer delete(a)
	defer delete(b)
	names := make([dynamic]string, context.temp_allocator)
	for k in a {
		append(&names, k)
	}
	for k in b {
		if k not_in a {
			append(&names, k)
		}
	}
	// A small insertion sort keeps the output stable.
	for i in 1 ..< len(names) {
		j := i
		for j > 0 && names[j] < names[j - 1] {
			names[j], names[j - 1] = names[j - 1], names[j]
			j -= 1
		}
	}
	for n in names {
		skip := false
		for ap in RELOAD_APPLIED {
			skip ||= ap == n
		}
		if B.mode != .Server {
			for ap in RELOAD_APPLIED_CLIENT {
				skip ||= ap == n
			}
		}
		if skip {
			continue
		}
		if a[n] != b[n] {
			append(out, strings.clone(n))
		}
	}
}

// Option name to all of its uses (arguments and inline bodies), as one text.
// Values point into the temp allocator.
@(private = "file")
directive_summary :: proc(dirs: []config.Directive) -> map[string]string {
	m := make(map[string]string)
	for d in dirs {
		text := strings.join(d.args, " ", context.temp_allocator)
		if d.has_body {
			text = strings.concatenate({text, "\x1f", d.body}, context.temp_allocator)
		}
		if old, ok := m[d.name]; ok {
			m[d.name] = strings.concatenate({old, "\n", text}, context.temp_allocator)
		} else {
			m[d.name] = text
		}
	}
	return m
}

// The part of a reload that is the same in both modes: the `bus-allow` table
// and the log level. Returns the names applied.
reload_apply_common :: proc(plan: ^Reload_Plan, reloaded: ^[dynamic]string) {
	if B.h != nil {
		bus.host_set_policy(B.h, &plan.policy)
		append(reloaded, "bus-allow")
	}
	if plan.verb != log_get_verb() {
		log_set_verb(plan.verb)
		append(reloaded, "verb")
	}
}

// The result of `daemon.reload`, and the event. `err` is "" on success.
bus_reload_report :: proc(req: ^bus.Request, reloaded, ignored: []string, err: string) {
	if w := bus_ev(); w != nil {
		bus.kv_bool(w, "ok", err == "")
		bus.kv_arr(w, "reloaded")
		for s in reloaded {
			bus.val_str(w, s)
		}
		bus.end(w)
		bus.kv_str_or_null(w, "error", err, err != "")
		bus_emit("daemon.reload")
	}
	if req == nil {
		return
	}
	if err != "" {
		bus_err(req, .Internal, err)
		return
	}
	w := bus_res()
	bus.kv_arr(w, "reloaded")
	for s in reloaded {
		bus.val_str(w, s)
	}
	bus.end(w)
	bus.kv_arr(w, "ignored")
	for s in ignored {
		bus.val_str(w, s)
	}
	bus.end(w)
	bus_ok(req)
}
