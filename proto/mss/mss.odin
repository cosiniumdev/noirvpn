// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// The TCP MSS that the tunnel clamps to (`mssfix`), and the clamp itself.
// No OS dependency: `mss_ipv4` is a pure function of config and session,
// `clamp_syn` changes one IP packet in memory.
package mss

import "noir:proto/config"

// Lower limit of the result. A smaller result means a config that cannot work
// (a tiny `mssfix` or tun MTU) and would slow every TCP stream to a crawl, so the
// floor is used instead.
MIN_MSS :: 100
// The MSS option has 16 bits.
MAX_MSS :: 65535

// The IPv6 header is 20 bytes longer than the IPv4 one: an IPv6 SYN gets the
// IPv4 value minus this.
V6_EXTRA :: 20

// Bytes of an IPv4 TCP packet that are not payload: the IPv4 and the TCP
// header without options.
@(private)
INNER_HEADERS :: 40

// TCP MSS to clamp to for IPv4 connections in the tunnel. 0 means no clamp. IPv6
// uses `mss_ipv6` of this value.
//
//	mssfix 0        0
//	mssfix N fixed  N is the largest inner IP packet.
//	mssfix N        N is the largest data channel packet (the UDP payload, or the
//	                TCP record with its 2-byte length).
//	mssfix N mtu    N is the largest outer IP packet.
//	(not set)       as `mssfix 1492 mtu` if the tun MTU is 1500, else as
//	                `mssfix <tun MTU> fixed`.
//
// `overhead` = all the data channel adds to an inner IP packet (`session_seal_overhead`):
// - 2-byte record length (TCP only)
// - 4-byte header (opcode, key id, peer id; noirvpn always sends the peer-id form)
// - packet id (4 bytes, 8 with epoch data format)
// - 16-byte AEAD tag
// `tcp`: the link is TCP (tls transport counts as TCP). `remote_v6`: address
// family of the link's remote.
mss_ipv4 :: proc "contextless" (m: config.Mssfix, tun_mtu: int, tcp, remote_v6: bool, overhead: int) -> int {
	mf := m
	if mf.kind == .Default {
		if tun_mtu == 1500 {
			mf = {.Mtu, 1492}
		} else {
			mf = {.Fixed, tun_mtu}
		}
	}
	r: int
	switch mf.kind {
	case .Default, .Off:
		return 0
	case .Fixed:
		r = mf.value - INNER_HEADERS
	case .Link:
		r = mf.value - overhead - INNER_HEADERS
	case .Mtu:
		ip := 40 if remote_v6 else 20
		l4 := 20 if tcp else 8
		r = mf.value - ip - l4 - overhead - INNER_HEADERS
	}
	return clamp(r, MIN_MSS, MAX_MSS)
}

// The value for IPv6 connections.
mss_ipv6 :: proc "contextless" (mss4: int) -> int {
	if mss4 <= 0 {
		return 0
	}
	return max(mss4 - V6_EXTRA, 1)
}
