// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:strconv"
import "core:strings"
import "noir:bus"

VERSION :: "noirvpn-hook 0.2.0-dev"

// Exit codes of noirvpn-hook.
Exit :: enum u8 {
	// Stopped by SIGINT or SIGTERM (or --help, --version, --check-config ok).
	Ok     = 0,
	// The config file or a setting is wrong.
	Config = 1,
	// The command line is wrong.
	Usage  = 2,
	// Refused to run as root, or a system call failed.
	System = 3,
	// The events socket cannot be used: no permission, several daemons, a
	// bad address, or the connection was closed.
	Bus    = 4,
}

// A mistake on the command line: the text for the user, or `nil` when the line
// is good.
Parse_Error :: union {
	string,
}

Options :: struct {
	name:           string,
	socket:         string,
	// --config files, read in order.
	config_files:   [dynamic]string,
	// --on PREFIX=/command, after the rules of the files.
	on_rules:       [dynamic]string,
	// Settings given on the command line win over the files.
	timeout:        string,
	grace:          string,
	max_queue:      string,
	max_parallel:   string,
	verb:           int,
	allow_root:     bool,
	check_config:   bool,
	help:           bool,
	version:        bool,
}

options_destroy :: proc(o: ^Options) {
	delete(o.config_files)
	delete(o.on_rules)
	o^ = {}
}

DEFAULT_VERB :: 1

// Parse the command line (without the program name). The strings point into
// `argv`.
parse_options :: proc(argv: []string) -> (o: Options, err: Parse_Error) {
	o.verb = DEFAULT_VERB
	i := 0
	for i < len(argv) {
		a := argv[i]
		i += 1
		opt := a
		value := ""
		has_value := false
		if strings.has_prefix(a, "--") {
			if eq := strings.index_byte(a, '='); eq >= 0 {
				opt = a[:eq]
				value = a[eq + 1:]
				has_value = true
			}
		}
		// The value of an option: attached or the next word.
		take :: proc(argv: []string, i: ^int, opt, value: string, has_value: bool) -> (string, Parse_Error) {
			if has_value {
				return value, nil
			}
			if i^ >= len(argv) {
				return "", fmt.tprintf("%s requires a value", opt)
			}
			v := argv[i^]
			i^ += 1
			return v, nil
		}
		flag :: proc(opt: string, has_value: bool) -> Parse_Error {
			if has_value {
				return fmt.tprintf("the %s option does not accept a value", opt)
			}
			return nil
		}
		switch opt {
		case "-h", "--help":
			o.help = true
		case "-V", "--version":
			o.version = true
		case "--name":
			v := take(argv, &i, opt, value, has_value) or_return
			if !valid_instance(v) {
				return o, fmt.tprintf("--name: '%s' is not a valid instance name (use letters, digits, '.', '_' or '-', at most 40)", v)
			}
			o.name = v
		case "--socket":
			o.socket = take(argv, &i, opt, value, has_value) or_return
			if o.socket == "" {
				return o, "--socket requires a path"
			}
		case "--config", "-c":
			v := take(argv, &i, opt, value, has_value) or_return
			append(&o.config_files, v)
		case "--on":
			v := take(argv, &i, opt, value, has_value) or_return
			append(&o.on_rules, v)
		case "--timeout":
			o.timeout = take(argv, &i, opt, value, has_value) or_return
		case "--grace":
			o.grace = take(argv, &i, opt, value, has_value) or_return
		case "--max-queue":
			o.max_queue = take(argv, &i, opt, value, has_value) or_return
		case "--max-parallel":
			o.max_parallel = take(argv, &i, opt, value, has_value) or_return
		case "--verb":
			v := take(argv, &i, opt, value, has_value) or_return
			n, ok := strconv.parse_int(v, 10)
			if !ok || n < 0 || n > 4 {
				return o, fmt.tprintf("--verb needs a level from 0 to 4, but got '%s'", v)
			}
			o.verb = n
		case "--allow-root":
			flag(opt, has_value) or_return
			o.allow_root = true
		case "--check-config":
			flag(opt, has_value) or_return
			o.check_config = true
		case:
			if strings.has_prefix(a, "-") {
				return o, fmt.tprintf("unknown option '%s'", a)
			}
			return o, fmt.tprintf("unexpected argument '%s' (give the commands with --config or --on)", a)
		}
	}
	if o.name != "" && o.socket != "" {
		return o, "--name and --socket cannot be used together"
	}
	return o, nil
}

// An instance name as it appears in a socket file name.
valid_instance :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '_', '-':
		case:
			return false
		}
	}
	return true
}

// Build the settings from the options and the config file texts (`file_texts[i]`
// belongs to `o.config_files[i]`). The command line wins over the files. Errors
// are collected; the result is good only when there are none.
build_config :: proc(o: ^Options, file_texts: []string, errors: ^[dynamic]Config_Error) -> Config {
	c := config_default()
	for text, i in file_texts {
		before := len(errors)
		parse_config(&c, text, errors)
		for k in before ..< len(errors) {
			e := &errors[k]
			e.msg = fmt.tprintf("%s:%d: %s", o.config_files[i], e.line, e.msg) if e.line > 0 else fmt.tprintf("%s: %s", o.config_files[i], e.msg)
		}
	}
	if o.timeout != "" {
		if m := set_timeout(&c, o.timeout); m != "" {
			append(errors, Config_Error{0, m})
		}
	}
	if o.grace != "" {
		if m := set_grace(&c, o.grace); m != "" {
			append(errors, Config_Error{0, m})
		}
	}
	if o.max_queue != "" {
		if m := set_max_queue(&c, o.max_queue); m != "" {
			append(errors, Config_Error{0, m})
		}
	}
	if o.max_parallel != "" {
		if m := set_max_parallel(&c, o.max_parallel); m != "" {
			append(errors, Config_Error{0, m})
		}
	}
	for spec in o.on_rules {
		if m := parse_on_flag(&c, spec); m != "" {
			append(errors, Config_Error{0, m})
		}
	}
	return c
}

// ---- finding the events socket ----

Resolve_Error :: enum u8 {
	None,
	// Several daemons and no --name.
	Ambiguous,
}

// Where to listen. `found` is what `bus.discover` found, `dirs` the directories
// where a daemon may keep its sockets, `exists` tells if a file is there.
//   --socket PATH   that
//   --name NAME     NAME.events in the first directory that has it
//   neither         the only daemon found
// When no socket exists yet the runner waits for one, in the first directory
// (`/run/noirvpn`). `waiting` says that this happened.
resolve_events :: proc(
	o: ^Options,
	found: []bus.Found,
	dirs: []string,
	exists: proc(path: string) -> bool,
) -> (
	url: string,
	waiting: bool,
	err: Resolve_Error,
	detail: string,
) {
	if o.socket != "" {
		return o.socket, false, .None, ""
	}
	name := o.name
	if name == "" {
		switch len(found) {
		case 1:
			return found[0].events_url, false, .None, ""
		case 0:
			name = bus.DEFAULT_NAME
		case:
			names := make([dynamic]string, context.temp_allocator)
			for f in found {
				append(&names, f.name)
			}
			return "", false, .Ambiguous, strings.join(names[:], ", ", context.temp_allocator)
		}
	}
	for dir in dirs {
		path := bus.default_socket_path(dir, name, bus.EVENTS_SUFFIX, context.temp_allocator)
		if exists(path) {
			return path, false, .None, ""
		}
	}
	if len(dirs) == 0 {
		return "", false, .Ambiguous, ""
	}
	return bus.default_socket_path(dirs[0], name, bus.EVENTS_SUFFIX, context.temp_allocator), true, .None, ""
}

USAGE :: `noirvpn-hook - run commands for the events of a noirvpn daemon

usage:
  noirvpn-hook [--name NAME | --socket PATH] (--config FILE | --on PREFIX=/abs/command)... [options]
  noirvpn-hook --check-config --config FILE
  noirvpn-hook --version | --help

options:
  --name NAME          the daemon instance (its events socket is NAME.events)
  --socket PATH        the events socket (path or ipc:// URL), instead of --name
  -c, --config FILE    read rules and settings from FILE (more than once is fine)
  --on PREFIX=/CMD     run /CMD (an absolute path, no arguments) for the events whose
                       topic starts with PREFIX (* for every event); more than once is fine
  --timeout SECONDS    kill a command (its process group) after this long (default 30)
  --max-parallel N     how many commands can run at the same time (default 4)
  --max-queue N        how many events can wait for a free slot; after that, new
                       events are dropped (default 100)
  --grace SECONDS      at shutdown, give running commands this long to finish (default 5)
  --verb N             log level 0 to 4 (default 1; 2 shows every command that ran)
  --allow-root         run even if the user is root (not recommended)
  --check-config       read the settings, print them and exit

Without --name and --socket, the runner uses the only daemon it finds in /run/noirvpn
and $XDG_RUNTIME_DIR/noirvpn (or /tmp/noirvpn-UID). If there is none, it waits for
noirvpn.events in /run/noirvpn.

Each command receives the event as JSON on stdin, and the variables NOIR_TOPIC,
NOIR_SEQ, NOIR_RUN, NOIR_TS and NOIR_<FIELD> for the scalar fields of the event data.
Commands run directly, without a shell. The runner stops at SIGINT or SIGTERM.

Exit codes: 0 stopped (or --check-config ok), 1 invalid settings, 2 usage error,
3 refused to run as root or system error, 4 the events socket cannot be used.
`
