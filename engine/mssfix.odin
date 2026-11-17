// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "noir:proto/config"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/mss"
import "noir:proto/push"
import "noir:proto/session"
import "noir:proto/wire"

// `mssfix`: clamps the TCP MSS of connections inside the tunnel, in SYN packets
// of both directions. Computed once per peer when transport, tun MTU and data
// format are known (client: tunnel-up; server: login), kept in `Daemon.mss4` or
// `Conn.mss4`. 0: no clamp. Packet code: proto/mss.
//
// Where it runs (thread that owns tun and sockets; workers never see plain packets):
//
//	client   tun read (`read_tun_plain`, `read_tun_vnet`) before the packet
//	         goes to the ring; `write_tun` for packets from the link
//	server   tun read (`srv_read_tun_plain`, `srv_read_tun_vnet`) after the
//	         client is known; `forward_packet` for client to client packets;
//	         `srv_on_tunnel` for packets from a client
//
// With the DCO service the same value goes in SET_PEER; the service clamps itself.

// The effective tun MTU of the client: the pushed one, else the one of the
// remote, else the default. A guest uses `guest_mtu` (at most `GUEST_MAX_MTU`).
client_tun_mtu :: proc(d: ^Daemon, po: ^push.Pushed_Options) -> int {
	if d.guest != nil {
		return guest_tun_mtu(d, po).mtu
	}
	if m, ok := po.tun_mtu.?; ok {
		return m
	}
	if mtu := d.cfg.connections[d.conn_idx].tun_mtu; mtu > 0 {
		return mtu
	}
	return DEFAULT_TUN_MTU
}

// The IPv4 MSS for a session. `tcp` counts the tls transport.
mss_for_session :: proc(s: ^session.Session, m: config.Mssfix, tun_mtu: int, tcp, remote_v6: bool) -> int {
	return mss.mss_ipv4(m, tun_mtu, tcp, remote_v6, session.session_seal_overhead(s))
}

// The IPv4 MSS of the client for the session that just came up.
client_mss :: proc(d: ^Daemon, po: ^push.Pushed_Options) -> int {
	m := d.cfg.connections[d.conn_idx].mssfix
	return mss_for_session(&d.s, m, client_tun_mtu(d, po), d.proto == .Tcp, is_v6(d.endpoint.address))
}

// The text of the client's "TCP MSS clamp" line. A backend that does not clamp (the
// kernel driver) says so when `mssfix` would have a value.
client_mss_line :: proc(d: ^Daemon) -> string {
	if d.dco.active && !d.dco.link.be.mss_clamp && d.mss4 > 0 {
		return MSS_NOT_APPLIED
	}
	return mss_text(d.mss4)
}

// The warning for a UDP link whose full tunnel packets are larger than a
// 1500-byte path, or "" when they fit. Such packets are sent as two IP
// fragments, which costs most of the throughput. A TCP link is a stream and
// has no packet limit. `overhead` is `session_seal_overhead`.
//
// Example: tun MTU 1428, IPv6, epoch data format (28 bytes):
//
//	1428 + 28 + 8 (UDP) + 40 (IPv6) = 1504 > 1500
mtu_fit_warning :: proc(tun_mtu: int, tcp, remote_v6: bool, overhead: int, allocator := context.temp_allocator) -> string {
	if tcp {
		return ""
	}
	outer := mss.outer_packet(tun_mtu, remote_v6, overhead)
	if outer <= mss.PATH_MTU {
		return ""
	}
	return fmt.aprintf(
		"with tun-mtu %d a full tunnel packet is %d bytes on the wire over %s, which is more than a %d-byte path allows, so large packets are split in two and the tunnel gets slow; set tun-mtu to %d or lower",
		tun_mtu, outer, "IPv6" if remote_v6 else "IPv4", mss.PATH_MTU, mss.fit_tun_mtu(remote_v6, overhead),
		allocator = allocator,
	) // fmt: skip
}

// The warning of `mtu_fit_warning` for the client's session that just came up.
client_mtu_fit_warning :: proc(d: ^Daemon, po: ^push.Pushed_Options) -> string {
	return mtu_fit_warning(client_tun_mtu(d, po), d.proto == .Tcp, is_v6(d.endpoint.address), session.session_seal_overhead(&d.s))
}

// The text of the line when the backend cannot clamp.
MSS_NOT_APPLIED :: "not applied (the kernel data path does not clamp)"

// The MSS for a log line: `1360 (IPv6 1340)` or `off`.
mss_text :: proc(mss4: int, allocator := context.temp_allocator) -> string {
	if mss4 <= 0 {
		return "off"
	}
	return fmt.aprintf("%d (IPv6 %d)", mss4, mss.mss_ipv6(mss4), allocator = allocator)
}

// MSS for the log of a server transport, before a client has come: baseline
// data format. `epoch`: a client may use the epoch format (more bytes per
// packet); the text says so if that changes the value. With `mssfix N mtu` the
// value depends on the client address family (outer headers): then both values
// are in the text.
srv_mss_text :: proc(m: config.Mssfix, tun_mtu: int, tcp, epoch: bool, allocator := context.temp_allocator) -> string {
	frame := wire.FRAME_PREFIX_LEN if tcp else 0
	v4 := mss.mss_ipv4(m, tun_mtu, tcp, false, crypt.packet_overhead(keys.Format.Baseline) + frame)
	v6 := mss.mss_ipv4(m, tun_mtu, tcp, true, crypt.packet_overhead(keys.Format.Baseline) + frame)
	less := 0
	if epoch && v4 > 0 {
		less = v4 - mss.mss_ipv4(m, tun_mtu, tcp, false, crypt.packet_overhead(keys.Format.Epoch) + frame)
	}
	if v4 == v6 {
		if less > 0 {
			return fmt.aprintf("%s (%d less with aead-epoch)", mss_text(v4, allocator), less, allocator = allocator)
		}
		return mss_text(v4, allocator)
	}
	note := ""
	if less > 0 {
		note = fmt.aprintf("; %d less with aead-epoch", less, allocator = allocator)
	}
	return fmt.aprintf(
		"%d for IPv4 clients, %d for IPv6 clients (inner IPv6: %d less%s)",
		v4, v6, v4 - mss.mss_ipv6(v4), note,
		allocator = allocator,
	) // fmt: skip
}

