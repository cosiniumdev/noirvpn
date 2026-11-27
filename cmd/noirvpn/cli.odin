// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:strings"

Mode :: enum u8 {
	Run,
	Check,
	Version,
	Help,
}

// What the command line asked for. `args` are the config options (the whole
// command line without the flags of the daemon), for `config.parse_args`.
Cli :: struct {
	mode: Mode,
	args: []string,
	// `--name NAME`: the instance name for the control bus ("" = from the config file name).
	name: string,
	// `--name` was given without a value.
	name_missing: bool,
	// `--allow-user NAME` and `--allow-group NAME`: who may use the control bus
	// as an operator, for this run.
	allow_user:   string,
	allow_group:  string,
	// A problem with these flags, for the user; "" when they are good.
	allow_error:  string,
}

// Splits the daemon's own flags (`--check-config`, `--version`, `--help`, `-h`,
// `--name NAME`, `--allow-user NAME`, `--allow-group NAME`)
// off the command line. Everything else belongs to the config parser. The
// result's `args` is a new slice (free it with `delete`).
cli_split :: proc(argv: []string, allocator := context.allocator) -> Cli {
	c := Cli{}
	rest := make([dynamic]string, 0, len(argv), allocator)
	skip := false
	for a, i in argv {
		if skip {
			skip = false
			continue
		}
		switch a {
		case "--name":
			if i + 1 < len(argv) && !strings.has_prefix(argv[i + 1], "--") {
				c.name = argv[i + 1]
				skip = true
			} else {
				c.name_missing = true
			}
		case "--allow-user", "--allow-group":
			user := a == "--allow-user"
			switch {
			case i + 1 >= len(argv) || strings.has_prefix(argv[i + 1], "--") || argv[i + 1] == "":
				c.allow_error = strings.concatenate({a, " requires a name"}, context.temp_allocator)
			case (user && c.allow_user != "") || (!user && c.allow_group != ""):
				c.allow_error = strings.concatenate({a, " can be given only once"}, context.temp_allocator)
			case user:
				c.allow_user = argv[i + 1]
				skip = true
			case:
				c.allow_group = argv[i + 1]
				skip = true
			}
		case "--version", "-V":
			c.mode = .Version
		case "--help", "-h":
			if c.mode != .Version {
				c.mode = .Help
			}
		case "--check-config":
			if c.mode == .Run {
				c.mode = .Check
			}
		case:
			append(&rest, a)
		}
	}
	c.args = rest[:]
	return c
}

// True if `name` (without the dashes) is among the directives that were read.
has_option :: proc(args: []string, name: string) -> bool {
	for a in args {
		if strings.has_prefix(a, "--") && a[2:] == name {
			return true
		}
	}
	return false
}

when ODIN_OS == .Windows {
	USAGE :: `noirvpn - an OpenVPN-compatible VPN client (Windows, wintun)

usage:
  noirvpn --config FILE [--option [args...]] ...
  noirvpn FILE
  noirvpn --check-config --config FILE [--option ...]
  noirvpn service install [--name NAME] [CONFIG]
  noirvpn service uninstall [--name NAME]
  noirvpn [--option [args...]] ...        (no file: a client service, with defaults)
  noirvpn --version | --help

Without a config file, noirvpn runs as a client service with the default
settings of a service (control sockets, verb, datapath), and the options on the
command line override them. If a --config FILE does not exist yet, noirvpn
creates it from the defaults and the options you gave, and then reads it.

--name NAME sets the instance name of the control bus, so its pipes are
\\.\pipe\noirvpn-NAME-control and \\.\pipe\noirvpn-NAME-events. Without it,
the name is the config file name without its extension. Use the noirvpnctl tool
to connect to these pipes (see docs/management.md).

The options are the same as in an OpenVPN config file, written with two
dashes. Options on the command line are read after the files and override them.
A server config is refused, because on Windows noirvpn is a client only.
--check-config reads the config, prints how noirvpn will handle each option,
and exits with 0 (no errors) or 1. It does not connect.

noirvpn needs an elevated prompt (an administrator) to create the tunnel
adapter and set routes and DNS. wintun.dll and the OpenSSL DLLs must be in the
same folder as the program. "noirvpn service" runs it as a Windows service (see
"noirvpn service --help").

Ctrl+C, Ctrl+Break or closing the console notifies the server, removes the
routes and DNS, and exits; a second Ctrl+C exits immediately.

Exit codes: 0 clean exit, 1 config error, 2 usage error, 3 system error
(privileges, wintun, IP Helper), 4 login refused, 5 stopped by the server,
6 gave up reconnecting, 7 network setup failed, 8 inactive or session-timeout.
`
} else when ODIN_OS == .Darwin {
	USAGE :: `noirvpn - an OpenVPN-compatible VPN client (macOS, utun)

usage:
  sudo noirvpn --config FILE [--option [args...]] ...
  sudo noirvpn FILE
  noirvpn --check-config --config FILE [--option ...]
  noirvpn [--option [args...]] ...        (no file: a client service, with defaults)
  noirvpn --version | --help

Without a config file, noirvpn runs as a client service with the default
settings of a service (control sockets, verb, datapath), and the options on the
command line override them. If a --config FILE does not exist yet, noirvpn
creates it from the defaults and the options you gave, and then reads it.

--name NAME sets the instance name of the control bus, so its sockets are
NAME.events and NAME.control in /var/run/noirvpn. Without it, the name is the
config file name without its extension. Use the noirvpnctl tool to connect to
these sockets (see docs/management.md).

Only root can use the sockets, unless the config says more. --allow-user NAME
lets one user in (the sockets belong to that user, mode 0600), and
--allow-group NAME lets the members of a group in (mode 0660). Both give the
role operator: load a profile, connect and disconnect, as the desktop app
does. They apply to this run only and are not written to a config file.

The options are the same as in an OpenVPN config file, written with two
dashes. Options on the command line are read after the files and override them.
A server config is refused, because on macOS noirvpn is a client only.
--check-config reads the config, prints how noirvpn will handle each option,
and exits with 0 (no errors) or 1. It does not connect.

noirvpn needs root (use sudo), because the daemon opens a utun interface
itself, runs ifconfig and route to set the addresses, the MTU and the routes,
and sets DNS with scutil. It is not a Network Extension. With "dev tun" the
system chooses the utunN name, and "dev utunN" requests a specific one.

Client signals:
  SIGINT, SIGTERM  notify the server, remove the routes and DNS, and exit; a second one exits at once
  SIGHUP, SIGUSR1  reconnect
  SIGUSR2          print a status line

Exit codes: 0 clean exit, 1 config error, 2 usage error, 3 system error
(privileges, utun, ifconfig), 4 login refused, 5 stopped by the server, 6 gave
up reconnecting, 7 network setup failed, 8 inactive or session-timeout.
`
} else {
USAGE :: `noirvpn - an OpenVPN-compatible VPN, client and server (Linux, tun)

usage:
  noirvpn --config FILE [--option [args...]] ...
  noirvpn FILE
  noirvpn --check-config --config FILE [--option ...]
  noirvpn [--option [args...]] ...        (no file: a client service, with defaults)
  noirvpn --version | --help

Without a config file, noirvpn runs as a client service with the default
settings of a service (control sockets, verb, datapath), and the options on the
command line override them. If a --config FILE does not exist yet, noirvpn
creates it from the defaults and the options you gave, and then reads it.

--name NAME sets the instance name of the control bus, so its sockets are
NAME.events and NAME.control in /run/noirvpn (or $XDG_RUNTIME_DIR/noirvpn for
another user). Without it, the name is the config file name without its
extension. Use the noirvpnctl tool to connect to these sockets (see
docs/management.md).

Only root can use the sockets, unless the config says more. --allow-user NAME
lets one user in (the sockets belong to that user, mode 0600), and
--allow-group NAME lets the members of a group in (mode 0660). Both give the
role operator: load a profile, connect and disconnect, as the desktop app
does. They apply to this run only and are not written to a config file.

The options are the same as in an OpenVPN config file, written with two
dashes. Options on the command line are read after the files and override them.
A config with "server" (or "mode server") runs as a server, and any other
config runs as a client. --check-config reads the config, prints how noirvpn
will handle each option, and exits with 0 (no errors) or 1. It does not connect
or listen.

noirvpn needs CAP_NET_ADMIN (run it as root) to create the tunnel and set
routes, and also DNS for a client.

Client signals:
  SIGINT, SIGTERM  notify the server, remove the routes and DNS, and exit; a second one exits at once
  SIGHUP, SIGUSR1  reconnect
  SIGUSR2          print a status line

Server signals:
  SIGINT, SIGTERM  notify every client (RESTART with explicit-exit-notify, otherwise
                   EXIT), remove the routes and exit with 0; a second one exits at once
  SIGHUP           reload the peers file and disconnect clients whose key was removed or disabled
  SIGUSR2          print the status, with totals, drop counters and one line for each client

Exit codes: 0 clean exit, 1 config error, 2 usage error, 3 system error
(privileges, tun, netlink), 4 login refused, 5 stopped by the server, 6 gave
up reconnecting, 7 network setup failed, 8 inactive or session-timeout.
`
}

VERSION_NUMBER :: "0.2.0-dev"
// The data path is not part of the banner: the start line names the one in use.
when ODIN_OS == .Windows {
	VERSION :: "noirvpn " + VERSION_NUMBER + " (client, Windows)"
} else when ODIN_OS == .Darwin {
	VERSION :: "noirvpn " + VERSION_NUMBER + " (client, macOS)"
} else {
	VERSION :: "noirvpn " + VERSION_NUMBER + " (client and server, Linux)"
}
