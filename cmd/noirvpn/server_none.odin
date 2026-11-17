// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
package main

import "noir:proto/config"

// The server does not run on Windows or on macOS: it needs the Linux kernel's
// tun, epoll and netlink.
run_server_role :: proc(cfg: ^config.Config, cli: Cli) -> Exit {
	when ODIN_OS == .Darwin {
		eprint("noirvpn: this config is for a server, but on macOS noirvpn can only run as a client")
	} else {
		eprint("noirvpn: this config is for a server, but on Windows noirvpn can only run as a client")
	}
	return .Config
}
