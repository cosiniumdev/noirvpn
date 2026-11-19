// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// noirvpn: an OpenVPN-compatible VPN client and server for Linux (tun; the data
// path runs in this process or on the userspace DCO service).
package main

import "core:fmt"
import "core:os"
import "core:strings"
import _ "noir:platform/cpu"
import "noir:platform/dco"
import "noir:proto/config"

main :: proc() {
	when ODIN_OS == .Windows {
		if len(os.args) > 1 && os.args[1] == "service" {
			os.exit(int(service_command(os.args[2:])))
		}
	}
	os.exit(int(run(os.args[1:])))
}

eprint :: proc(format: string, args: ..any) {
	fmt.eprintfln(format, ..args)
}

path_exists :: proc(path: string) -> bool {
	return os.exists(path)
}

// Creates the config file `path` (and its folder). It is not secret, so it is
// readable by all; a file that exists is never touched. False after a message.
write_new_config :: proc(path, text: string) -> bool {
	dir, _ := os.split_path(path)
	if dir != "" {
		if err := os.make_directory_all(dir); err != nil && err != .Exist {
			eprint("noirvpn: cannot create the folder %s: %v", dir, err)
			return false
		}
	}
	if err := os.write_entire_file(path, text); err != nil {
		eprint("noirvpn: cannot write the config file %s: %v", path, err)
		return false
	}
	eprint("noirvpn: %s did not exist, so it was created from the defaults and the options on the command line", path)
	return true
}

// `argv` is the command line without the program name.
run :: proc(argv: []string) -> Exit {
	cli := cli_split(argv)
	defer delete(cli.args)
	switch cli.mode {
	case .Version:
		fmt.println(VERSION)
		if dco.in_process_ready() {
			fmt.printfln("data channel in this process: %s", dco_in_process_name())
		}
		return .Ok
	case .Help:
		fmt.print(USAGE)
		return .Ok
	case .Run, .Check:
	}
	if cli.name_missing {
		eprint("noirvpn: the --name option requires a value (the instance name of the control bus)")
		return .Usage
	}
	if why := bus_access_check(&cli); why != "" {
		eprint("noirvpn: %s", why)
		return .Usage
	}

	// The defaults of a client service stand in for the config file, and a config
	// file that does not exist is created from them.
	plan := config_plan(cli.args, service_default_args(), path_exists, cli.mode == .Run)
	if plan.create_path != "" {
		if !write_new_config(plan.create_path, plan.create_text) {
			return .Config
		}
	}
	if plan.defaulted && cli.name == "" {
		cli.name = "desktop"
	}

	off_load_config()
	parsed := config.parse_args(plan.args)
	cfg := config.build(parsed)
	defer config.destroy(&cfg)

	if cfg.role == .Server && config.ok(&cfg) {
		return run_server_role(&cfg, cli)
	}
	if cfg.role != .Client && config.ok(&cfg) {
		eprint("noirvpn: the config is for a %v, but noirvpn can only run as a client or a server", cfg.role)
		return .Config
	}
	service := cfg.role == .Client && cfg.client.service
	settings: Settings
	defer settings_destroy(&settings)
	settings_ok := false
	if config.ok(&cfg) {
		// A service has no keys to read: its profile comes over the control bus.
		ask := Key_Ask.Never
		if tty_is(0) {
			ask = .Check if cli.mode == .Check else .Later
		}
		settings_ok = true if service else settings_load(&settings, &cfg, ask)
	}

	if cli.mode == .Check {
		code := check_config(&cfg, &settings, settings_ok)
		if config.ok(&cfg) && cfg.role == .Client {
			name := bus_instance_name(cli.name, &cfg)
			defer delete(name)
			if !bus_check(&cfg.client.common, .Client, name) {
				return .Config
			}
		}
		return code
	}

	if !config.ok(&cfg) {
		fmt.eprint(config.format_diagnostics(cfg.diags))
		eprint("noirvpn: the config has errors, so nothing was started (run with --check-config to see the details)")
		return .Config
	}
	log_set_verb(cfg.client.verb)
	for dg in cfg.diags {
		logf(.Warn, "config: %s", strings.trim_space(config.format_diagnostics({dg}, context.temp_allocator)))
	}
	if !settings_ok {
		for e in settings.errors {
			eprint("noirvpn: %s", e)
		}
		return .Config
	}
	for w in settings.warnings {
		logf(.Warn, "%s", w)
	}
	crl_log_start(&settings.crl)
	aead_start()

	// The bus settings are a config matter (exit 1) whatever the privileges are.
	name := bus_instance_name(cli.name, &cfg)
	if !bus_check(&cfg.client.common, .Client, name) {
		delete(name)
		return .Config
	}
	when ODIN_OS == .Windows {
		set_adapter_name(name)
	}
	if !priv_prepare(cfg.client.user, cfg.client.group) {
		delete(name)
		return .Config
	}
	if !has_net_admin() {
		delete(name)
		eprint("noirvpn: %s", PRIV_TEXT)
		return .System
	}

	d := &D
	daemon_attach(d)
	defer dco_launch_stop()
	// Signals first: a prompt for the password can then be cancelled by one,
	// and the terminal is put back.
	sfd, sok := daemon_sig_open()
	if !sok {
		eprint("noirvpn: cannot set up signal handling")
		return .System
	}
	if settings.key_wait {
		slots := [1]Key_Slot{{&settings.key_pem, "key"}}
		if !keys_unlock_prompt(slots[:], sfd) {
			return .Config
		}
	}
	if aup, ok := cfg.client.auth_user_pass.?; ok {
		if cfg.client.bus_control.state != .Off && !aup.is_inline && aup.file == "" && !tty_is(0) {
			// No file and nobody to ask at a terminal: the credentials come over
			// the control bus (`client.auth_needed`, `auth.supply`).
			d.creds_wait = true
			d.creds_reason = "no_credentials"
		} else if err := cred_load(&d.creds, aup, sfd); err != .None {
			eprint("noirvpn: %s", cred_error_text(err))
			cred_wipe(&d.creds)
			return .Auth
		}
	}
	d.inst_name = name
	if !daemon_init(d, &cfg) {
		code := d.exit_code if d.exit_code != .Ok else Exit.System
		daemon_destroy(d)
		return code
	}
	if !bus_start(&d.loop, &cfg, .Client, name, cli.args, on_cli_bus) {
		bus_stop_quiet()
		daemon_destroy(d)
		return .System
	}
	d.bus_state = "stopped" if service else "waiting"
	d.set = settings
	settings = {}
	write_pidfile(cfg.client.writepid)
	if !priv_apply(tun_later = true) {
		remove_pidfile(cfg.client.writepid)
		bus_stop_quiet()
		settings = d.set
		d.set = {}
		daemon_destroy(d)
		return .System
	}
	if service {
		logf(
			.Notice,
			"%s starting (pid %d) as a client service that waits for a profile, verb %d, datapath %s",
			VERSION, os.get_pid(), cfg.client.verb, dco_start_text(d.dco.kind, d.dco.want && !d.dco.lost),
		) // fmt: skip
	} else {
		logf(
			.Notice,
			"%s starting (pid %d), %d remote(s), verb %d, datapath %s",
			VERSION, os.get_pid(), len(cfg.client.connections), cfg.client.verb, dco_start_text(d.dco.kind, d.dco.want && !d.dco.lost),
		) // fmt: skip
	}
	d.privs_dropped = privs_dropped
	bus_publish_start()
	client_stats_arm(d)
	svc_note_running()
	code := daemon_run(d)
	B.stop_reason, B.stop_detail = d.stop_reason, d.stop_detail
	if B.stop_reason == "" {
		B.stop_reason = "signal" if code == .Ok else "error"
	}
	remove_pidfile(cfg.client.writepid)
	bus_stop()
	settings = d.set
	d.set = {}
	daemon_destroy(d)
	return code
}

check_config :: proc(cfg: ^config.Config, settings: ^Settings, settings_ok: bool) -> Exit {
	report := config.check_config(cfg)
	defer config.report_destroy(&report)
	text := config.format_report(&report)
	fmt.print(text)
	if cfg.role == .Client || !config.ok(cfg) {
		notes := format_settings_notes(settings)
		fmt.print(notes)
	}
	if cfg.role == .Client && cfg.client.service && config.report_ok(&report) {
		fmt.println("daemon: this is a client service, so it has no profile and will wait for profile.set on the control bus")
	}
	if cfg.role == .Client && config.report_ok(&report) {
		if e := priv_settings_error(cfg.client.user, cfg.client.group); e != "" && cfg.client.service {
			// A service skips settings_load, which reports this for a plain client.
			fmt.printfln("daemon: error: %s", e)
			return .Config
		}
		if txt := priv_check_text(cfg.client.user, cfg.client.group); txt != "" {
			fmt.println(txt)
		}
	}
	if !config.report_ok(&report) || !settings_ok {
		return .Config
	}
	if cfg.role != .Client {
		fmt.println("daemon: error: this is not a client config")
		return .Config
	}
	return .Ok
}

write_pidfile :: proc(path: string) {
	if path == "" {
		return
	}
	text := fmt.tprintf("%d\n", os.get_pid())
	if err := os.write_entire_file(path, transmute([]u8)text); err != nil {
		logf(.Warn, "cannot write the pid file %s", path)
	}
}

remove_pidfile :: proc(path: string) {
	if path != "" && !strings.has_prefix(path, "/dev/") {
		_ = os.remove(path)
	}
}
