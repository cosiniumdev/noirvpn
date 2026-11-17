// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import net "noir:platform/net"
import "noir:proto/session"

// The IPv4 MSS of the server for one client.
srv_mss :: proc(d: ^Srv, c: ^Conn) -> int {
	_, v6 := c.ep.address.(net.IP6_Address)
	return mss_for_session(&c.s, d.cfg.link.mssfix, server_tun_mtu(d.cfg), c.proto == .Tcp, v6)
}

// Warns when the full tunnel packets of a client do not fit a 1500-byte path
// (`mtu_fit_warning`). One line for each address family and data format of a
// server run: every client of that kind has the same problem.
srv_warn_mtu_fit :: proc(d: ^Srv, c: ^Conn) {
	_, v6 := c.ep.address.(net.IP6_Address)
	overhead := session.session_seal_overhead(&c.s)
	text := mtu_fit_warning(server_tun_mtu(d.cfg), c.proto == .Tcp, v6, overhead)
	if text == "" {
		return
	}
	if !mtu_warned_take(d.mtu_warned[:], &d.mtu_warned_n, {v6 = v6, overhead = u8(overhead)}) {
		return
	}
	logf(.Warn, "client %s: %s (said once for clients of this kind)", conn_label(c), text)
}

// A kind of client that `srv_warn_mtu_fit` has warned about.
Mtu_Warned :: struct {
	v6:       bool,
	overhead: u8,
}

// Is a warning for this kind of client due? True the first time a kind is
// seen, and it is then kept in `list` (`n` entries used). A full list keeps
// no more kinds, so a kind beyond it warns each time.
mtu_warned_take :: proc(list: []Mtu_Warned, n: ^int, key: Mtu_Warned) -> bool {
	for i in 0 ..< n^ {
		if list[i] == key {
			return false
		}
	}
	if n^ < len(list) {
		list[n^] = key
		n^ += 1
	}
	return true
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
