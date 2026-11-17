// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:strings"

// Starting without a config file, and creating one.
//
//   noirvpn                               client service with the defaults
//   noirvpn --client-service --verb 2     the same, with the given options
//   noirvpn --config FILE [--option ...]  FILE is read; if it does not exist it
//                                         is written first, from the defaults
//                                         and the given options, then read
//
// "The defaults" are the options of a client service (`service_default_args`):
// it has no VPN config of its own; a user loads a profile over the control bus.
// They apply only when no config file is read. A command line option replaces
// the default of the same name. A command line that names a role (`client`,
// `remote`, `server`, ...) is a config of its own and gets no service defaults:
// the created file has exactly the given options.

// The result of `config_plan`.
Config_Plan :: struct {
	// The command line to give to the config parser.
	args:        []string,
	// The file to create before the parse ("" for none) and its text.
	create_path: string,
	create_text: string,
	// The defaults were used (no config file is read): the instance name is `desktop`.
	defaulted:   bool,
}

// The options that turn a command line into a config of its own.
@(private = "file")
ROLE_OPTIONS := [?]string{"client", "remote", "server", "mode", "tls-client", "tls-server", "pull"}

// The names of the config files on a command line: the values of `--config`, or
// the one bare argument.
config_files_of :: proc(args: []string, allocator := context.temp_allocator) -> []string {
	out := make([dynamic]string, allocator)
	if len(args) == 1 && !strings.has_prefix(args[0], "--") {
		append(&out, args[0])
		return out[:]
	}
	for i in 0 ..< len(args) {
		if args[i] == "--config" && i + 1 < len(args) && !strings.has_prefix(args[i + 1], "--") {
			append(&out, args[i + 1])
		}
	}
	return out[:]
}

// `args` without the `--config FILE` pairs (and without a bare file name).
@(private = "file")
options_only :: proc(args: []string, allocator := context.temp_allocator) -> []string {
	out := make([dynamic]string, allocator)
	if len(args) == 1 && !strings.has_prefix(args[0], "--") {
		return out[:]
	}
	skip := false
	for i in 0 ..< len(args) {
		if skip {
			skip = false
			continue
		}
		if args[i] == "--config" {
			skip = i + 1 < len(args) && !strings.has_prefix(args[i + 1], "--")
			continue
		}
		append(&out, args[i])
	}
	return out[:]
}

// A command line that is a service: it says `client-service`, or it names no role.
@(private = "file")
wants_service :: proc(opts: []string) -> bool {
	if has_option(opts, "client-service") {
		return true
	}
	for r in ROLE_OPTIONS {
		if has_option(opts, r) {
			return false
		}
	}
	return true
}

// `opts` with the service options added: `--client-service`, and each default
// whose name `opts` does not give.
service_args :: proc(opts: []string, defaults: []string, allocator := context.temp_allocator) -> []string {
	out := make([dynamic]string, allocator)
	append(&out, ..opts)
	if !has_option(opts, "client-service") {
		append(&out, "--client-service")
	}
	// `defaults` is a command line: groups that start with `--NAME`.
	i := 0
	for i < len(defaults) {
		j := i + 1
		for j < len(defaults) && !strings.has_prefix(defaults[j], "--") {
			j += 1
		}
		if !has_option(opts, defaults[i][2:]) {
			append(&out, ..defaults[i:j])
		}
		i = j
	}
	return out[:]
}

// One argument as it must stand in a config file.
@(private = "file")
quote_arg :: proc(sb: ^strings.Builder, a: string) {
	plain := len(a) > 0
	for c in transmute([]u8)a {
		if c <= ' ' || c == '"' || c == '\'' || c == '\\' || c == '#' || c == ';' {
			plain = false
			break
		}
	}
	if plain {
		strings.write_string(sb, a)
		return
	}
	strings.write_byte(sb, '"')
	for c in transmute([]u8)a {
		if c == '"' || c == '\\' {
			strings.write_byte(sb, '\\')
		}
		strings.write_byte(sb, c)
	}
	strings.write_byte(sb, '"')
}

// The text of a config file for a command line of options.
config_text :: proc(opts: []string, allocator := context.temp_allocator) -> string {
	sb := strings.builder_make(allocator)
	fmt.sbprintln(&sb, "# Created by noirvpn from its defaults and the options on the command line.")
	i := 0
	for i < len(opts) {
		if !strings.has_prefix(opts[i], "--") {
			i += 1
			continue
		}
		strings.write_string(&sb, opts[i][2:])
		i += 1
		for i < len(opts) && !strings.has_prefix(opts[i], "--") {
			strings.write_byte(&sb, ' ')
			quote_arg(&sb, opts[i])
			i += 1
		}
		strings.write_byte(&sb, '\n')
	}
	return strings.to_string(sb)
}

// Decides what to read and what to create. `exists` says if a file is there.
// `defaults` are the service options of the system (`service_default_args`).
//   - config file named and exists: nothing changes
//   - none named: the options (and service defaults) are the config
//   - files named, none exists: the first is created from the options and defaults
//     (`create_path`, only if `create` is true; `--check-config` creates nothing
//     and reads the options as the config), and the command line becomes
//     `--config FILE`
config_plan :: proc(args, defaults: []string, exists: proc(path: string) -> bool, create: bool) -> Config_Plan {
	files := config_files_of(args)
	for f in files {
		if exists(f) {
			return {args = args}
		}
	}
	opts := options_only(args)
	if wants_service(opts) {
		opts = service_args(opts, defaults)
	}
	plan := Config_Plan {
		args      = opts,
		defaulted = len(files) == 0,
	}
	if len(files) > 0 && create {
		plan.create_path = files[0]
		plan.create_text = config_text(opts)
		cmd := make([]string, 2, context.temp_allocator)
		cmd[0], cmd[1] = "--config", files[0]
		plan.args = cmd
	}
	return plan
}
