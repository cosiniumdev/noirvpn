// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import net "noir:platform/net"

// The IPv4 MSS of the server for one client.
srv_mss :: proc(d: ^Srv, c: ^Conn) -> int {
	_, v6 := c.ep.address.(net.IP6_Address)
	return mss_for_session(&c.s, d.cfg.link.mssfix, server_tun_mtu(d.cfg), c.proto == .Tcp, v6)
}

// One Info line for each transport that the server listens on.
srv_log_mss :: proc(d: ^Srv) {
	udp, tcp := false, false
	for l in d.cfg.listens {
		if l.proto == .Tcp {
			tcp = true
		} else {
			udp = true
		}
	}
	// Sessions in this process may negotiate the epoch format, and so may the clients of
	// a backend with epoch keys.
	epoch := !d.dco.on || srv_dco_epoch(d)
	mtu := server_tun_mtu(d.cfg)
	both := udp && tcp
	// The kernel driver cannot clamp: its clients get no clamp (the tls clients of a
	// mixed server run here and keep theirs).
	kernel := d.dco.on && d.dco.kind == .Kernel
	if udp {
		text := srv_mss_text(d.cfg.link.mssfix, mtu, false, epoch)
		if kernel && text != "off" {
			text = MSS_NOT_APPLIED
		}
		logf(.Info, "TCP MSS clamp%s: %s", " (udp)" if both else "", text)
	}
	if tcp {
		text := srv_mss_text(d.cfg.link.mssfix, mtu, true, epoch)
		if kernel && text != "off" {
			text = MSS_NOT_APPLIED
		}
		logf(.Info, "TCP MSS clamp%s: %s", " (tcp)" if both else "", text)
	}
}
