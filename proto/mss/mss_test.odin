// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package mss

import "core:testing"
import "noir:proto/config"

// The overhead of the data channel as the session gives it.
UDP_BASE :: 24 // 4 header + 4 packet id + 16 tag
UDP_EPOCH :: 28 // 4 header + 8 epoch and counter + 16 tag
TCP_BASE :: 26 // and the 2-byte record length
TCP_EPOCH :: 30

@(test)
test_mss_worked_cases :: proc(t: ^testing.T) {
	mtu1492 := config.Mssfix{.Mtu, 1492}
	// 1492 - 20 - 8 - 24 - 40
	testing.expect_value(t, mss_ipv4(mtu1492, 1400, false, false, UDP_BASE), 1400)
	// IPv6 remote: 20 bytes more of outer header.
	testing.expect_value(t, mss_ipv4(mtu1492, 1400, false, true, UDP_BASE), 1380)
	// TCP IPv4: 1492 - 20 - 20 - 26 - 40
	testing.expect_value(t, mss_ipv4(mtu1492, 1400, true, false, TCP_BASE), 1386)
	// The epoch format has 4 more bytes.
	testing.expect_value(t, mss_ipv4(mtu1492, 1400, false, false, UDP_EPOCH), 1396)
	testing.expect_value(t, mss_ipv4(mtu1492, 1400, true, true, TCP_EPOCH), 1362)
	// mssfix N: N is the data channel packet. 1450 - 24 - 40
	testing.expect_value(t, mss_ipv4({.Link, 1450}, 1400, false, false, UDP_BASE), 1386)
	testing.expect_value(t, mss_ipv4({.Link, 1450}, 1400, false, true, UDP_BASE), 1386)
	testing.expect_value(t, mss_ipv4({.Link, 1450}, 1400, true, false, TCP_BASE), 1384)
	// mssfix N fixed: N is the inner packet.
	testing.expect_value(t, mss_ipv4({.Fixed, 1300}, 1400, false, false, UDP_BASE), 1260)
	testing.expect_value(t, mss_ipv4({.Fixed, 1300}, 1400, true, true, TCP_EPOCH), 1260)
	// mssfix 0.
	testing.expect_value(t, mss_ipv4({.Off, 0}, 1400, false, false, UDP_BASE), 0)
}

@(test)
test_mss_default :: proc(t: ^testing.T) {
	// No mssfix line, tun MTU 1400: as `mssfix 1400 fixed`.
	testing.expect_value(t, mss_ipv4({}, 1400, false, false, UDP_BASE), 1360)
	testing.expect_value(t, mss_ipv4({}, 1400, true, true, TCP_EPOCH), 1360)
	testing.expect_value(t, mss_ipv4({}, 1280, false, false, UDP_BASE), 1240)
	// Tun MTU 1500: as `mssfix 1492 mtu`.
	testing.expect_value(t, mss_ipv4({}, 1500, false, false, UDP_BASE), 1400)
	testing.expect_value(t, mss_ipv4({}, 1500, false, true, UDP_BASE), 1380)
	testing.expect_value(t, mss_ipv4({}, 1500, true, false, TCP_BASE), 1386)
}

@(test)
test_mss_limits :: proc(t: ^testing.T) {
	// Under the floor: the floor.
	testing.expect_value(t, mss_ipv4({.Fixed, 60}, 1400, false, false, UDP_BASE), MIN_MSS)
	testing.expect_value(t, mss_ipv4({.Link, 10}, 1400, false, false, UDP_BASE), MIN_MSS)
	testing.expect_value(t, mss_ipv4({.Mtu, 0}, 1400, true, true, TCP_EPOCH), MIN_MSS)
	testing.expect_value(t, mss_ipv4({}, 100, false, false, UDP_BASE), MIN_MSS)
	testing.expect_value(t, mss_ipv4({}, 0, false, false, UDP_BASE), MIN_MSS)
	// The floor itself is not changed.
	testing.expect_value(t, mss_ipv4({.Fixed, 140}, 1400, false, false, UDP_BASE), 100)
	testing.expect_value(t, mss_ipv4({.Fixed, 141}, 1400, false, false, UDP_BASE), 101)
	// Over 16 bits: the limit.
	testing.expect_value(t, mss_ipv4({.Fixed, 100000}, 1400, false, false, UDP_BASE), MAX_MSS)
	testing.expect_value(t, mss_ipv4({}, 65535, false, false, UDP_BASE), 65495)
	testing.expect_value(t, mss_ipv4({.Fixed, 65575}, 1400, false, false, UDP_BASE), MAX_MSS)
}

@(test)
test_mss_ipv6_value :: proc(t: ^testing.T) {
	testing.expect_value(t, mss_ipv6(0), 0)
	testing.expect_value(t, mss_ipv6(1360), 1340)
	testing.expect_value(t, mss_ipv6(MIN_MSS), 80)
	testing.expect_value(t, mss_ipv6(5), 1)
}

@(test)
test_outer_packet_fit :: proc(t: ^testing.T) {
	// Tun MTU 1428 fits the baseline format over IPv6 and is 4 bytes over with epoch keys.
	testing.expect_value(t, outer_packet(1428, true, 24), 1500)
	testing.expect_value(t, outer_packet(1428, true, 28), 1504)
	testing.expect_value(t, outer_packet(1428, false, 28), 1484)
	testing.expect_value(t, outer_packet(1420, true, 28), 1496)
	// The largest tun MTU that fits is the one whose packet is exactly the path MTU.
	testing.expect_value(t, fit_tun_mtu(true, 28), 1424)
	testing.expect_value(t, fit_tun_mtu(true, 24), 1428)
	testing.expect_value(t, fit_tun_mtu(false, 28), 1444)
	testing.expect_value(t, outer_packet(fit_tun_mtu(true, 28), true, 28), PATH_MTU)
	testing.expect_value(t, outer_packet(fit_tun_mtu(false, 24), false, 24), PATH_MTU)
}
