// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import "core:os"
import "core:strings"
import "core:time"

// The real paths and the real command runner.

@(private)
DEFAULT_BIN_DIRS := [?]string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// Where openresolv (`keys` in current versions, `interfaces` in old ones) and Debian's
// resolvconf (`interface`) keep their records.
@(private)
DEFAULT_RECORD_DIRS := [?]string {
	"/run/resolvconf/keys",
	"/run/resolvconf/interfaces",
	"/run/resolvconf/interface",
	"/var/run/resolvconf/keys",
	"/var/run/resolvconf/interfaces",
	"/var/run/resolvconf/interface",
	"/etc/resolvconf/run/interface",
}

// The paths of a normal Linux system.
dns_env_default :: proc() -> DNS_Env {
	return DNS_Env {
		resolved_dir = "/run/systemd/resolve",
		bin_dirs = DEFAULT_BIN_DIRS[:],
		record_dirs = DEFAULT_RECORD_DIRS[:],
		resolv_conf = "/etc/resolv.conf",
		backup = "/etc/resolv.conf.noirvpn-backup",
	}
}

// How long a resolver command may run.
COMMAND_TIMEOUT :: 20 * time.Second

// Start `argv` (no shell) with `stdin` as a file, and wait. Standard output
// and error are discarded. The child gets a small fixed environment.
//
// Input goes through a temporary file, not a pipe: a write to a pipe whose
// reader exited raises SIGPIPE, which would end the daemon.
dns_run_command :: proc(_: rawptr, argv: []string, stdin: string) -> (exit_code: int, started: bool) {
	if len(argv) == 0 {
		return -1, false
	}
	in_file: ^os.File
	if len(stdin) > 0 {
		f, err := os.create_temp_file("", "noirvpn-dns-*")
		if err != nil {
			return -1, false
		}
		defer {
			// The file owns its name: copy it before the file is closed.
			name := strings.clone(os.name(f), context.temp_allocator)
			_ = os.close(f)
			_ = os.remove(name)
		}
		if _, werr := os.write_string(f, stdin); werr != nil {
			return -1, false
		}
		if _, serr := os.seek(f, 0, .Start); serr != nil {
			return -1, false
		}
		in_file = f
		return run_with_stdin(argv, in_file)
	}
	return run_with_stdin(argv, nil)
}

@(private)
run_with_stdin :: proc(argv: []string, stdin: ^os.File) -> (exit_code: int, started: bool) {
	env := [?]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	desc := os.Process_Desc {
		command = argv,
		env     = env[:],
		stdin   = stdin,
	}
	p, err := os.process_start(desc)
	if err != nil {
		return -1, false
	}
	state, werr := os.process_wait(p, COMMAND_TIMEOUT)
	if werr != nil || !state.exited {
		_ = os.process_kill(p)
		_, _ = os.process_wait(p)
		return -1, false
	}
	return state.exit_code, true
}
