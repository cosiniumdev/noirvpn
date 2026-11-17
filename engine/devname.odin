// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "noir:client"
import "noir:platform/sysnet"

// Tunnel device name for a profile from a user. The device is always new. A
// daemon with a config file keeps the `dev` rules (`tun_name_of`).
//
//	start_attempt -> dev_name_choose -> d.dev_name
//	handle_up / dco_client_device -> client_dev_name -> tun.open, or the DCO device
//
// The daemon never uses an interface it did not create: an existing name is a
// connection error.

// The first number of a default name that is not tried again.
DEV_PICK_LIMIT :: 1000

Dev_Pick :: enum u8 {
	Ok,
	// The name is the name of an interface that exists.
	Taken,
	// The names noir0 to noir999 are all in use.
	None_Free,
	// The name is longer than an interface name.
	Bad_Name,
}

// Picks the name of a new device. `dev` is the `dev` option: "tun" (and "") ask
// for the first free `noir<N>`; any other name is used as is. `taken`: names of
// existing interfaces. The name is written to `buf` and lives as long as `buf`.
dev_name_pick :: proc(dev: string, taken: []string, buf: []u8) -> (name: string, r: Dev_Pick) {
	if dev != "tun" && dev != "" {
		if len(dev) > len(buf) {
			return "", .Bad_Name
		}
		for t in taken {
			if t == dev {
				return dev, .Taken
			}
		}
		n := copy(buf, dev)
		return string(buf[:n]), .Ok
	}
	for n in 0 ..< DEV_PICK_LIMIT {
		name = fmt.bprintf(buf, "noir%d", n)
		free := true
		for t in taken {
			if t == name {
				free = false
				break
			}
		}
		if free {
			return name, .Ok
		}
	}
	return "", .None_Free
}

// A service runs profiles from users only.
user_profile :: proc(d: ^Daemon) -> bool {
	return d.service && d.prof_loaded
}

// The name for the device that the next tunnel creates: "" lets the kernel pick `tun0`
// (a config file with `dev tun`).
client_dev_name :: proc(d: ^Daemon) -> string {
	if user_profile(d) {
		return d.dev_name
	}
	return tun_name_of(d.cfg.dev)
}

// Chooses the device name of a new user-profile tunnel. No-op if the daemon
// already holds a device (`persist-tun`), or for a config file. False after
// `fatal`: the name is taken, or the system cannot say.
dev_name_choose :: proc(d: ^Daemon) -> bool {
	if !user_profile(d) || d.tun_open || d.dco.dev || d.guest != nil {
		// A guest has no device name of its own: the host creates the tunnel.
		return true
	}
	when ODIN_OS == .Darwin {
		// A utun interface is named by the system (or `dev utunN`): there is no
		// noir<N> to pick, and no name of ours to clean up after.
		d.dev_name = tun_name_of(d.cfg.dev)
		return true
	}
	links := make([dynamic]sysnet.Link_Info)
	defer delete(links)
	if err := sysnet.link_list(&d.sys, &links); err != .None {
		fatal(d, .System, "cannot list the network interfaces: %v", err)
		return false
	}
	taken := make([]string, len(links), context.temp_allocator)
	for &l, i in links {
		taken[i] = sysnet.link_name(&l)
	}
	// Windows has one tunnel for each instance, and its adapter has the name of the
	// instance, so `dev tun` does not pick noir<N> there.
	dev := d.cfg.dev
	when ODIN_OS == .Windows {
		dev = tun_name_of(dev)
	}
	name, r := dev_name_pick(dev, taken, d.dev_name_buf[:])
	switch r {
	case .Taken:
		fatal(
			d,
			.System,
			"the interface %s already exists, and the daemon will not use an interface that it did not create (use another `dev` name)",
			name,
		)
		return false
	case .None_Free:
		fatal(d, .System, "there is no free device name from noir0 to noir%d", DEV_PICK_LIMIT - 1)
		return false
	case .Bad_Name:
		fatal(d, .System, "the device name %s is too long", d.cfg.dev)
		return false
	case .Ok:
	}
	d.dev_name = name
	if err := sysnet.dns_cleanup_stale_record(d.dns_env, name); err != .None {
		logf(.Warn, "cannot clean up the DNS settings left by an earlier run for %s: %v", name, err)
	}
	return true
}

// The notes of the plan that a user interface shows (`client.tunnel_settings`).
plan_note_for_user :: proc "contextless" (k: client.Note_Kind) -> bool {
	return k == .Dropped_Host_Net || k == .Tunnel_Host_Net
}
