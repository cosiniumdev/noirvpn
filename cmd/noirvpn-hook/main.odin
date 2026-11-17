// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// noirvpn-hook: run commands for the events of a noirvpn daemon.
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "noir:bus"

main :: proc() {
	os.exit(int(run()))
}

@(private = "file")
eprint :: proc(format: string, args: ..any) {
	fmt.eprintfln(format, ..args)
}

run :: proc() -> Exit {
	o, perr := parse_options(os.args[1:])
	defer options_destroy(&o)
	if perr != nil {
		msg, _ := perr.(string)
		eprint("noirvpn-hook: %s", msg)
		eprint("try 'noirvpn-hook --help'")
		return .Usage
	}
	if o.version {
		fmt.println(VERSION)
		return .Ok
	}
	if o.help {
		fmt.print(USAGE)
		return .Ok
	}

	// The settings.
	texts := make([dynamic]string, context.temp_allocator)
	for path in o.config_files {
		data, rerr := os.read_entire_file(path, context.temp_allocator)
		if rerr != nil {
			eprint("noirvpn-hook: cannot read the config file '%s'", path)
			return .Config
		}
		append(&texts, string(data))
	}
	errors := make([dynamic]Config_Error, context.temp_allocator)
	cfg := build_config(&o, texts[:], &errors)
	defer config_destroy(&cfg)
	if len(errors) > 0 {
		for e in errors {
			eprint("noirvpn-hook: %s", e.msg)
		}
		return .Config
	}
	if len(cfg.rules) == 0 {
		eprint("noirvpn-hook: there is nothing to run, so give --config FILE or --on PREFIX=/absolute/command")
		return .Usage
	}
	if o.check_config {
		return check_config(&cfg)
	}

	log := Logger {
		verb  = o.verb,
		alloc = context.allocator,
	}
	if !may_run(u32(linux.geteuid()), o.allow_root) {
		eprint("noirvpn-hook: refusing to run as root, so run it as its own unprivileged user (or add --allow-root)")
		return .System
	}
	warn_missing_commands(&log, &cfg)

	// Where to listen.
	found := bus.discover()
	defer bus.found_destroy(found)
	dirs := bus.candidate_dirs()
	defer {
		for d in dirs {
			delete(d)
		}
		delete(dirs)
	}
	url, waiting, rerr, detail := resolve_events(&o, found, dirs, file_exists)
	if rerr != .None {
		eprint("noirvpn-hook: several daemons are running (%s), so choose one with --name", detail)
		return .Bus
	}
	path, _ := bus_path(url)
	hidden := bus.socket_presence(path) == .Permission_Denied
	if !hidden && waiting {
		if dir := bus.hidden_dir(context.temp_allocator); dir != "" {
			eprint("noirvpn-hook: no permission to look into %s (is this user in the daemon's bus group?)", dir)
			return .Bus
		}
	}
	if hidden {
		// nng would retry for ever and say nothing.
		eprint("noirvpn-hook: no permission to reach %s (is this user in the daemon's bus group?)", path)
		return .Bus
	} else if waiting {
		logf(&log, .Notice, "there is no events socket yet, waiting for %s", path)
	} else if file_exists(path) && linux.access(strings.clone_to_cstring(path, context.temp_allocator), linux.W_OK) != .NONE {
		// nng would retry for ever and say nothing.
		eprint("noirvpn-hook: no permission to connect to %s (a Unix socket needs write permission on the file)", path)
		return .Bus
	}

	// Signals, before the nng threads start.
	stop := stop_init()
	if !stop_open(&stop) {
		eprint("noirvpn-hook: cannot set up signal handling")
		return .System
	}
	defer stop_close(&stop)

	base := base_env(os_lookup_env)
	defer env_destroy(base, context.allocator)

	switch hook_run(&cfg, url, &stop, &log, base) {
	case .Ok:
		return .Ok
	case .Bus_Failed:
		return .Bus
	case .Thread_Failed:
		return .System
	}
	return .Ok
}

// A hook command should not run with the rights of root by accident.
may_run :: proc(euid: u32, allow_root: bool) -> bool {
	return euid != 0 || allow_root
}

// `--check-config`: say what would run.
check_config :: proc(cfg: ^Config) -> Exit {
	fmt.printfln("timeout %ds, max-parallel %d, max-queue %d, grace %ds", int(cfg.timeout / 1e9), cfg.max_parallel, cfg.max_queue, int(cfg.grace / 1e9))
	for r in cfg.rules {
		prefix := r.prefix if r.prefix != "" else "*"
		fmt.printfln("on %s run %s", prefix, strings.join(r.argv, " ", context.temp_allocator))
		if m := command_problem(r.argv[0]); m != "" {
			fmt.printfln("  warning: %s", m)
		}
	}
	return .Ok
}

// A warning at start for a command that cannot run, or "".
command_problem :: proc(path: string) -> string {
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	if linux.access(cpath, linux.F_OK) != .NONE {
		return fmt.tprintf("%s does not exist", path)
	}
	if linux.access(cpath, linux.X_OK) != .NONE {
		return fmt.tprintf("%s is not executable by this user", path)
	}
	return ""
}

warn_missing_commands :: proc(log: ^Logger, cfg: ^Config) {
	for r in cfg.rules {
		if m := command_problem(r.argv[0]); m != "" {
			logf(log, .Warn, "%s", m)
		}
	}
}

file_exists :: proc(path: string) -> bool {
	return os.exists(path)
}

os_lookup_env :: proc(name: string) -> (string, bool) {
	v, ok := os.lookup_env(name, context.temp_allocator)
	return v, ok
}

// The file path of a socket URL (for messages and the access check).
bus_path :: proc(url: string) -> (string, bool) {
	if strings.has_prefix(url, "ipc://") {
		return url[len("ipc://"):], true
	}
	return url, true
}
