// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package sysnet

import "core:sys/linux"
import "core:testing"
import net "noir:platform/net"
import "noir:platform/netlink"
import "noir:platform/tun"

// Tests that change network state: create tun devices, set addresses and
// routes, move packets through the tunnel.
// - Run only with -define:NOIR_NETNS_TESTS=true, inside a private network
//   namespace owned by a user namespace (platform/run-netns-tests.sh uses
//   `unshare -rn`).
// - Use -define:ODIN_TEST_THREADS=1: the tests share one namespace.
// - Without the define, the helpers below still compile (the privileged code
//   is type-checked on every build), but no test is registered.
NETNS :: #config(NOIR_NETNS_TESTS, false)

// ---- helpers ----

// True when this process is in a user namespace that is not the initial one.
// The initial namespace maps the whole uid range ("0 0 4294967295").
in_private_userns :: proc() -> bool {
	fd, e := linux.open("/proc/self/uid_map", {.CLOEXEC})
	if e != .NONE {
		return false
	}
	defer linux.close(fd)
	buf: [128]u8
	n, re := linux.read(fd, buf[:])
	if re != .NONE || n <= 0 {
		return false
	}
	text := string(buf[:n])
	for i in 0 ..< len(text) - 9 {
		if text[i:i + 10] == "4294967295" {
			return false
		}
	}
	return true
}

// Links a new namespace has by itself: `lo`, and the "fallback" tunnel devices
// that tunnel modules (gre, ipip, sit, ip6tnl, vti) create in every namespace.
// Our own test devices start with "noir".
is_expected_link :: proc(n: string) -> bool {
	if n == "lo" || (len(n) >= 4 && n[:4] == "noir") {
		return true
	}
	for known in ([]string{"gre0", "gretap0", "erspan0", "sit0", "tunl0", "ip6tnl0", "ip6gre0", "ip_vti0", "ip6_vti0"}) {
		if n == known {
			return true
		}
	}
	return false
}

// Refuse to run anywhere but a fresh private namespace. Besides the user
// namespace check, every link must be one a new namespace has, or ours.
require_private_netns :: proc(t: ^testing.T, c: ^Conn) -> bool {
	if !in_private_userns() {
		testing.expect(t, false, "not in a private user namespace: run platform/run-netns-tests.sh")
		return false
	}
	links := make([dynamic]Link_Info)
	defer delete(links)
	if err := link_list(c, &links); err != .None {
		testing.expectf(t, false, "cannot list links: %v", err)
		return false
	}
	for &l in links {
		n := link_name(&l)
		if !is_expected_link(n) {
			testing.expectf(t, false, "unexpected link %q: this is not a throwaway namespace", n)
			return false
		}
	}
	return true
}

// Open a connection and check the namespace.
open_checked :: proc(t: ^testing.T) -> (c: Conn, ok: bool) {
	err: Error
	c, err = open()
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return {}, false
	}
	if !require_private_netns(t, &c) {
		close(&c)
		return {}, false
	}
	return c, true
}

// Create a tun device and find its link.
make_tun :: proc(t: ^testing.T, c: ^Conn, name: string) -> (dev: tun.Device, link: Link_Info, ok: bool) {
	err: tun.Error
	dev, err = tun.open({name = name})
	testing.expect_value(t, err, tun.Error.None)
	if err != .None {
		return {}, {}, false
	}
	lerr: Error
	link, lerr = link_get(c, name)
	testing.expect_value(t, lerr, Error.None)
	if lerr != .None {
		tun.close(&dev)
		return {}, {}, false
	}
	return dev, link, true
}

// The bytes of an address.
v4_bytes :: proc(a: IP4_Address) -> [4]u8 {
	a := a
	return cast([4]u8)a
}

v6_bytes :: proc(a: IP6_Address) -> [16]u8 {
	a := a
	return transmute([16]u8)a
}

// True for a route the kernel created by itself (for example the connected route
// that comes with an address).
is_kernel_route :: proc(r: Route) -> bool {
	return r.protocol == netlink.RTPROT_KERNEL
}

// A UDP socket bound to `ep`.
udp_bound :: proc(family: net.Family, ep: net.Endpoint) -> (s: net.Socket, err: net.Error) {
	s, err = net.udp_open(family)
	if err != .None {
		return
	}
	if err = net.bind(s, ep); err != .None {
		net.close(s)
		return net.INVALID_SOCKET, err
	}
	return
}

find_route :: proc(routes: []Route, dst: Address, dst_len: u8) -> (r: Route, found: bool) {
	for cand in routes {
		if cand.dst == dst && cand.dst_len == dst_len {
			return cand, true
		}
	}
	return {}, false
}

// Wait up to `ms` for a descriptor to be readable.
wait_readable :: proc(fd: i32, ms: i32) -> bool {
	fds := [1]linux.Poll_Fd{{fd = linux.Fd(fd), events = {.IN}}}
	n, e := linux.poll(fds[:], ms)
	return e == .NONE && n > 0
}

// Internet checksum (RFC 1071) over `data`, added to `sum`.
checksum_add :: proc(sum: u32, data: []u8) -> u32 {
	s := sum
	i := 0
	for ; i + 1 < len(data); i += 2 {
		s += u32(data[i]) << 8 | u32(data[i + 1])
	}
	if i < len(data) {
		s += u32(data[i]) << 8
	}
	return s
}

checksum_fold :: proc(sum: u32) -> u16 {
	s := sum
	for s > 0xffff {
		s = (s & 0xffff) + (s >> 16)
	}
	return ~u16(s)
}

// IPv4 + UDP packet (UDP checksum 0: allowed on IPv4).
ipv4_udp :: proc(src, dst: [4]u8, sport, dport: u16, payload: []u8, out: []u8) -> []u8 {
	src, dst := src, dst
	total := 20 + 8 + len(payload)
	pkt := out[:total]
	for &b in pkt {
		b = 0
	}
	pkt[0] = 0x45
	pkt[2], pkt[3] = u8(total >> 8), u8(total)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	c := checksum_fold(checksum_add(0, pkt[:20]))
	pkt[10], pkt[11] = u8(c >> 8), u8(c)
	udp := pkt[20:]
	udp[0], udp[1] = u8(sport >> 8), u8(sport)
	udp[2], udp[3] = u8(dport >> 8), u8(dport)
	ulen := 8 + len(payload)
	udp[4], udp[5] = u8(ulen >> 8), u8(ulen)
	copy(udp[8:], payload)
	return pkt
}

// IPv6 + UDP packet with the mandatory UDP checksum.
ipv6_udp :: proc(src, dst: [16]u8, sport, dport: u16, payload: []u8, out: []u8) -> []u8 {
	src, dst := src, dst
	ulen := 8 + len(payload)
	total := 40 + ulen
	pkt := out[:total]
	for &b in pkt {
		b = 0
	}
	pkt[0] = 0x60
	pkt[4], pkt[5] = u8(ulen >> 8), u8(ulen)
	pkt[6] = 17 // next header: UDP
	pkt[7] = 64 // hop limit
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	udp := pkt[40:]
	udp[0], udp[1] = u8(sport >> 8), u8(sport)
	udp[2], udp[3] = u8(dport >> 8), u8(dport)
	udp[4], udp[5] = u8(ulen >> 8), u8(ulen)
	copy(udp[8:], payload)
	// Pseudo header: addresses, UDP length, next header.
	pseudo: [40]u8
	copy(pseudo[0:16], src[:])
	copy(pseudo[16:32], dst[:])
	pseudo[34], pseudo[35] = u8(ulen >> 8), u8(ulen)
	pseudo[39] = 17
	sum := checksum_add(checksum_add(0, pseudo[:]), udp)
	c := checksum_fold(sum)
	if c == 0 {
		c = 0xffff
	}
	udp[6], udp[7] = u8(c >> 8), u8(c)
	return pkt
}

// Read packets from the tun until one is UDP to `dport` (IP version `ver`), or
// time is up. Other packets (IPv6 neighbor discovery, multicast reports) are
// skipped. Returns the packet bytes in `buf`.
read_udp_packet :: proc(dev: ^tun.Device, ver: u8, dport: u16, buf: []u8, ms: int) -> (pkt: []u8, ok: bool) {
	waited := 0
	for waited <= ms {
		n, err := tun.read(dev, buf)
		if err == .Would_Block {
			if !wait_readable(dev.fd, 20) {
				waited += 20
			}
			continue
		}
		if err != .None || n < 20 {
			return nil, false
		}
		p := buf[:n]
		if p[0] >> 4 != ver {
			continue
		}
		hdr: int
		if ver == 4 {
			hdr = int(p[0] & 0xf) * 4
			if p[9] != 17 {
				continue
			}
		} else {
			hdr = 40
			if p[6] != 17 {
				continue
			}
		}
		if len(p) < hdr + 8 || u16(p[hdr + 2]) << 8 | u16(p[hdr + 3]) != dport {
			continue
		}
		return p, true
	}
	return nil, false
}

V4_LOCAL :: IP4_Address{10, 199, 0, 2}
V4_PEER :: IP4_Address{10, 199, 0, 1}
V6_LOCAL :: IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 2}
V6_PEER :: IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 1}

when NETNS {

	@(test)
	netns_loopback_up_and_lookup :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)

		// `lo` is down in a new namespace from unshare, and up in a container.
		lo, err := link_get(&c, "lo")
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, link_set_down(&c, lo.index), Error.None)
		lo, err = link_get(&c, "lo")
		testing.expect_value(t, err, Error.None)
		testing.expect(t, .Up not_in lo.flags)
		testing.expect_value(t, link_set_up(&c, lo.index), Error.None)
		lo, err = link_get(&c, "lo")
		testing.expect_value(t, err, Error.None)
		testing.expect(t, .Up in lo.flags)

		// The kernel's own local route: a lookup of 127.0.0.1 ends on lo.
		r, rerr := route_lookup(&c, IP4_Address{127, 0, 0, 1})
		testing.expect_value(t, rerr, Error.None)
		testing.expect_value(t, r.ifindex, lo.index)
		testing.expect_value(t, r.kind, Route_Kind.Local)

		testing.expect_value(t, link_set_down(&c, lo.index), Error.None)
		lo, _ = link_get(&c, "lo")
		testing.expect(t, .Up not_in lo.flags)
	}

	@(test)
	netns_link_state_and_mtu :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirsys0")
		if !made {
			return
		}
		defer tun.close(&dev)

		testing.expect_value(t, link_name(&link), "noirsys0")
		testing.expect(t, link.index > 0)
		testing.expect_value(t, link.mtu, 1500)
		testing.expect(t, .Up not_in link.flags)
		testing.expect(t, .Point_To_Point in link.flags)

		testing.expect_value(t, link_set_mtu(&c, link.index, 1400), Error.None)
		l, _ := link_get_by_index(&c, link.index)
		testing.expect_value(t, l.mtu, 1400)
		testing.expect_value(t, link_set_mtu(&c, link.index, 10), Error.Invalid)

		testing.expect_value(t, link_set_up(&c, link.index), Error.None)
		l, _ = link_get_by_index(&c, link.index)
		testing.expect(t, .Up in l.flags)
		testing.expect(t, .Lower_Up in l.flags, "an open tun has carrier")
		testing.expect_value(t, l.mtu, 1400)

		testing.expect_value(t, link_set_down(&c, link.index), Error.None)
		l, _ = link_get_by_index(&c, link.index)
		testing.expect(t, .Up not_in l.flags)

		// The tun package sees the same MTU.
		mtu, _ := tun.get_mtu(&dev)
		testing.expect_value(t, mtu, 1400)

		// Unknown links.
		testing.expect_value(t, link_set_up(&c, 0x7fff_fff0), Error.Not_Found)
		testing.expect_value(t, link_set_mtu(&c, 0x7fff_fff0, 1400), Error.Not_Found)
	}

	@(test)
	netns_addresses_v4_and_v6 :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noiradr0")
		if !made {
			return
		}
		defer tun.close(&dev)

		testing.expect_value(t, addr_add(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V4_LOCAL, 24), Error.Exists)
		v6err := addr_add(&c, link.index, V6_LOCAL, 64)
		if v6err == .Unsupported {
			testing.expect(t, false, "IPv6 is disabled in this namespace: the tests need it")
			return
		}
		testing.expect_value(t, v6err, Error.None)

		addrs := make([dynamic]Addr_Info)
		defer delete(addrs)
		testing.expect_value(t, addr_list(&c, link.index, nil, &addrs), Error.None)
		saw4, saw6 := false, false
		for a in addrs {
			testing.expect_value(t, a.index, link.index)
			if a.address == Address(V4_LOCAL) {
				saw4 = true
				testing.expect_value(t, a.prefix_len, 24)
				testing.expect(t, a.peer == nil)
			}
			if a.address == Address(V6_LOCAL) {
				saw6 = true
				testing.expect_value(t, a.prefix_len, 64)
			}
		}
		testing.expect(t, saw4, "IPv4 address listed")
		testing.expect(t, saw6, "IPv6 address listed")

		// Family filter.
		testing.expect_value(t, addr_list(&c, link.index, Family.V4, &addrs), Error.None)
		for a in addrs {
			_, is4 := a.address.(IP4_Address)
			testing.expect(t, is4)
		}
		testing.expect_value(t, addr_list(&c, link.index, Family.V6, &addrs), Error.None)
		for a in addrs {
			_, is6 := a.address.(IP6_Address)
			testing.expect(t, is6)
		}

		// Remove both. A second removal says it is gone.
		testing.expect_value(t, addr_del(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_del(&c, link.index, V6_LOCAL, 64), Error.None)
		testing.expect_value(t, addr_del(&c, link.index, V4_LOCAL, 24), Error.Not_Found)
		testing.expect_value(t, addr_del(&c, link.index, V6_LOCAL, 64), Error.Not_Found)
		testing.expect_value(t, addr_list(&c, link.index, nil, &addrs), Error.None)
		for a in addrs {
			testing.expect(t, a.address != Address(V4_LOCAL) && a.address != Address(V6_LOCAL))
		}

		// An address on a link that is not there.
		testing.expect_value(t, addr_add(&c, 0x7fff_fff0, V4_LOCAL, 24), Error.Not_Found)
	}

	@(test)
	netns_point_to_point_address :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirp2p0")
		if !made {
			return
		}
		defer tun.close(&dev)

		testing.expect_value(
			t,
			addr_add(&c, link.index, IP4_Address{10, 8, 0, 2}, 32, {peer = IP4_Address{10, 8, 0, 1}}),
			Error.None,
		)
		addrs := make([dynamic]Addr_Info)
		defer delete(addrs)
		testing.expect_value(t, addr_list(&c, link.index, Family.V4, &addrs), Error.None)
		found := false
		for a in addrs {
			if a.address == Address(IP4_Address{10, 8, 0, 2}) {
				found = true
				testing.expect_value(t, a.prefix_len, 32)
				testing.expect_value(t, a.peer, Maybe(Address)(Address(IP4_Address{10, 8, 0, 1})))
			}
		}
		testing.expect(t, found)

		// Once the link is up the kernel routes the peer through it.
		testing.expect_value(t, link_set_up(&c, link.index), Error.None)
		r, rerr := route_lookup(&c, IP4_Address{10, 8, 0, 1})
		testing.expect_value(t, rerr, Error.None)
		testing.expect_value(t, r.ifindex, link.index)
		testing.expect(t, r.gateway == nil, "the peer is on-link")

		testing.expect_value(t, addr_del(&c, link.index, IP4_Address{10, 8, 0, 2}, 32, {peer = IP4_Address{10, 8, 0, 1}}), Error.None)
	}

	@(test)
	netns_kernel_adds_the_connected_route :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirrt0")
		if !made {
			return
		}
		defer tun.close(&dev)
		testing.expect_value(t, link_set_up(&c, link.index), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V6_LOCAL, 64), Error.None)

		routes := make([dynamic]Route)
		defer delete(routes)
		testing.expect_value(t, route_list(&c, .V4, 0, link.index, &routes), Error.None)
		r4, found4 := find_route(routes[:], IP4_Address{10, 199, 0, 0}, 24)
		testing.expect(t, found4, "connected IPv4 route")
		testing.expect(t, is_kernel_route(r4))
		testing.expect_value(t, r4.scope, netlink.RT_SCOPE_LINK)
		testing.expect_value(t, r4.prefsrc, Maybe(Address)(Address(V4_LOCAL)))
		testing.expect(t, r4.gateway == nil)

		testing.expect_value(t, route_list(&c, .V6, 0, link.index, &routes), Error.None)
		r6, found6 := find_route(routes[:], IP6_Address{0xfd00, 0x0199, 0, 0, 0, 0, 0, 0}, 64)
		testing.expect(t, found6, "connected IPv6 route")
		testing.expect(t, is_kernel_route(r6))

		// With no_prefix_route the kernel adds no route for the prefix.
		testing.expect_value(
			t,
			addr_add(&c, link.index, IP4_Address{172, 20, 0, 2}, 24, {no_prefix_route = true}),
			Error.None,
		)
		testing.expect_value(t, route_list(&c, .V4, 0, link.index, &routes), Error.None)
		_, found := find_route(routes[:], IP4_Address{172, 20, 0, 0}, 24)
		testing.expect(t, !found, "no connected route with NOPREFIXROUTE")
		addrs := make([dynamic]Addr_Info)
		defer delete(addrs)
		testing.expect_value(t, addr_list(&c, link.index, Family.V4, &addrs), Error.None)
		flag_seen := false
		for a in addrs {
			if a.address == Address(IP4_Address{172, 20, 0, 2}) {
				flag_seen = a.flags & netlink.IFA_F_NOPREFIXROUTE != 0
			}
		}
		testing.expect(t, flag_seen, "IFA_F_NOPREFIXROUTE is read back")

		// Removing the address removes its connected route.
		testing.expect_value(t, addr_del(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, route_list(&c, .V4, 0, link.index, &routes), Error.None)
		_, found = find_route(routes[:], IP4_Address{10, 199, 0, 0}, 24)
		testing.expect(t, !found, "connected route goes with the address")
	}

	@(test)
	netns_add_read_and_delete_routes :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirrt1")
		if !made {
			return
		}
		defer tun.close(&dev)
		testing.expect_value(t, link_set_up(&c, link.index), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V6_LOCAL, 64), Error.None)

		routes := make([dynamic]Route)
		defer delete(routes)

		// A route through a gateway, with a metric.
		net4 := IP4_Address{192, 168, 77, 0}
		r := Route {
			dst     = net4,
			dst_len = 24,
			gateway = V4_PEER,
			ifindex = link.index,
			metric  = u32(50),
		}
		testing.expect_value(t, route_add(&c, r), Error.None)
		testing.expect_value(t, route_add(&c, r), Error.Exists)
		testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
		got, found := find_route(routes[:], net4, 24)
		testing.expect(t, found, "route listed")
		testing.expect_value(t, got.gateway, Maybe(Address)(Address(V4_PEER)))
		testing.expect_value(t, got.ifindex, link.index)
		testing.expect_value(t, got.metric, Maybe(u32)(50))
		testing.expect_value(t, got.protocol, netlink.RTPROT_STATIC)
		testing.expect_value(t, got.table, netlink.RT_TABLE_MAIN)
		testing.expect_value(t, got.scope, netlink.RT_SCOPE_UNIVERSE)

		// Replace changes the gateway of the same key instead of failing.
		r2 := r
		r2.gateway = IP4_Address{10, 199, 0, 77}
		testing.expect_value(t, route_add(&c, r2, replace = true), Error.None)
		testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
		got, found = find_route(routes[:], net4, 24)
		testing.expect(t, found)
		testing.expect_value(t, got.gateway, Maybe(Address)(Address(IP4_Address{10, 199, 0, 77})))

		// Delete matches on the gateway too: the old one no longer exists.
		testing.expect_value(t, route_del(&c, r), Error.Not_Found)
		testing.expect_value(t, route_del(&c, r2), Error.None)
		testing.expect_value(t, route_del(&c, r2), Error.Not_Found)
		testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
		_, found = find_route(routes[:], net4, 24)
		testing.expect(t, !found, "route is gone")

		// A route on the device only (no gateway), in a private table, with
		// our own protocol number.
		r3 := Route {
			dst      = IP4_Address{10, 77, 0, 0},
			dst_len  = 16,
			ifindex  = link.index,
			table    = 100,
			protocol = 201,
		}
		testing.expect_value(t, route_add(&c, r3), Error.None)
		testing.expect_value(t, route_list(&c, .V4, 100, 0, &routes), Error.None)
		got, found = find_route(routes[:], IP4_Address{10, 77, 0, 0}, 16)
		testing.expect(t, found, "route in table 100")
		testing.expect_value(t, got.table, 100)
		testing.expect_value(t, got.protocol, 201)
		testing.expect_value(t, got.scope, netlink.RT_SCOPE_LINK)
		testing.expect(t, got.gateway == nil)
		// ...and not in the main table.
		testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
		_, found = find_route(routes[:], IP4_Address{10, 77, 0, 0}, 16)
		testing.expect(t, !found)
		// A table number above 255 goes through RTA_TABLE.
		r3.table = 1000
		testing.expect_value(t, route_add(&c, r3), Error.None)
		testing.expect_value(t, route_list(&c, .V4, 1000, 0, &routes), Error.None)
		_, found = find_route(routes[:], IP4_Address{10, 77, 0, 0}, 16)
		testing.expect(t, found, "route in table 1000")
		testing.expect_value(t, route_del(&c, r3), Error.None)
		r3.table = 100
		testing.expect_value(t, route_del(&c, r3), Error.None)

		// IPv6, through a gateway on the connected prefix.
		net6 := IP6_Address{0x2001, 0x0db8, 0x0077, 0, 0, 0, 0, 0}
		r6 := Route {
			dst     = net6,
			dst_len = 48,
			gateway = V6_PEER,
			ifindex = link.index,
			metric  = u32(1024),
		}
		testing.expect_value(t, route_add(&c, r6), Error.None)
		testing.expect_value(t, route_add(&c, r6), Error.Exists)
		testing.expect_value(t, route_list(&c, .V6, 0, 0, &routes), Error.None)
		got, found = find_route(routes[:], net6, 48)
		testing.expect(t, found, "IPv6 route listed")
		testing.expect_value(t, got.gateway, Maybe(Address)(Address(V6_PEER)))
		testing.expect_value(t, got.metric, Maybe(u32)(1024))
		testing.expect_value(t, route_del(&c, r6), Error.None)
		testing.expect_value(t, route_del(&c, r6), Error.Not_Found)

		// A gateway nobody can reach.
		bad := Route {
			dst     = IP4_Address{192, 168, 88, 0},
			dst_len = 24,
			gateway = IP4_Address{172, 31, 255, 1},
		}
		testing.expect_value(t, route_add(&c, bad), Error.Network_Unreachable)
		// ... unless it is declared on-link.
		bad.onlink = true
		bad.ifindex = link.index
		testing.expect_value(t, route_add(&c, bad), Error.None)
		testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
		got, found = find_route(routes[:], IP4_Address{192, 168, 88, 0}, 24)
		testing.expect(t, found)
		testing.expect(t, got.onlink, "RTNH_F_ONLINK is read back")
		testing.expect_value(t, route_del(&c, bad), Error.None)

		// Kinds without a next hop.
		hole := Route {
			dst     = IP4_Address{198, 51, 100, 0},
			dst_len = 24,
			kind    = .Blackhole,
		}
		testing.expect_value(t, route_add(&c, hole), Error.None)
		testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
		got, found = find_route(routes[:], IP4_Address{198, 51, 100, 0}, 24)
		testing.expect(t, found)
		testing.expect_value(t, got.kind, Route_Kind.Blackhole)
		testing.expect_value(t, route_del(&c, hole), Error.None)

		testing.expect_value(t, addr_del(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_del(&c, link.index, V6_LOCAL, 64), Error.None)
	}

	// The `redirect-gateway` sequence: find the current default route, pin the
	// server through it, then cover everything else with two half routes.
	@(test)
	netns_default_route_and_redirect_gateway :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		// "Uplink" tun: pretends to be the physical interface.
		up_dev, uplink, made := make_tun(t, &c, "noirup0")
		if !made {
			return
		}
		defer tun.close(&up_dev)
		// "VPN" tun.
		vpn_dev, vpn, made2 := make_tun(t, &c, "noirvpn0")
		if !made2 {
			return
		}
		defer tun.close(&vpn_dev)
		for l in ([]Link_Info{uplink, vpn}) {
			testing.expect_value(t, link_set_up(&c, l.index), Error.None)
		}
		testing.expect_value(t, addr_add(&c, uplink.index, IP4_Address{192, 0, 2, 10}, 24), Error.None)
		testing.expect_value(t, addr_add(&c, vpn.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_add(&c, uplink.index, IP6_Address{0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 10}, 64), Error.None)
		testing.expect_value(t, addr_add(&c, vpn.index, V6_LOCAL, 64), Error.None)

		// No default route yet.
		_, derr := route_get_default(&c, .V4)
		testing.expect_value(t, derr, Error.Not_Found)
		_, derr = route_get_default(&c, .V6)
		testing.expect_value(t, derr, Error.Not_Found)
		// And a lookup says so.
		_, lerr := route_lookup(&c, IP4_Address{8, 8, 8, 8})
		testing.expect_value(t, lerr, Error.Network_Unreachable)

		// The old default route, with two metrics: the lower one wins.
		gw := IP4_Address{192, 0, 2, 1}
		def := Route {
			dst     = default_dst(.V4),
			gateway = gw,
			ifindex = uplink.index,
			metric  = u32(100),
		}
		testing.expect_value(t, route_add(&c, def), Error.None)
		worse := def
		worse.gateway = IP4_Address{192, 0, 2, 2}
		worse.metric = u32(700)
		testing.expect_value(t, route_add(&c, worse), Error.None)
		d, derr2 := route_get_default(&c, .V4)
		testing.expect_value(t, derr2, Error.None)
		testing.expect_value(t, d.gateway, Maybe(Address)(Address(gw)))
		testing.expect_value(t, d.ifindex, uplink.index)
		testing.expect_value(t, d.metric, Maybe(u32)(100))
		testing.expect_value(t, d.dst_len, 0)

		// IPv6 default route.
		gw6 := IP6_Address{0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 1}
		def6 := Route {
			dst     = default_dst(.V6),
			gateway = gw6,
			ifindex = uplink.index,
			metric  = u32(1024),
		}
		testing.expect_value(t, route_add(&c, def6), Error.None)
		d6, derr6 := route_get_default(&c, .V6)
		testing.expect_value(t, derr6, Error.None)
		testing.expect_value(t, d6.gateway, Maybe(Address)(Address(gw6)))
		testing.expect_value(t, d6.ifindex, uplink.index)

		// Where would a packet to the VPN server go? (Do this first.)
		server := Address(IP4_Address{203, 0, 113, 7})
		via, verr := route_lookup(&c, server)
		testing.expect_value(t, verr, Error.None)
		testing.expect_value(t, via.gateway, Maybe(Address)(Address(gw)))
		testing.expect_value(t, via.ifindex, uplink.index)
		testing.expect_value(t, via.prefsrc, Maybe(Address)(Address(IP4_Address{192, 0, 2, 10})))
		// A host on the uplink's own subnet is on-link: no gateway.
		near, nerr := route_lookup(&c, IP4_Address{192, 0, 2, 99})
		testing.expect_value(t, nerr, Error.None)
		testing.expect(t, near.gateway == nil)
		testing.expect_value(t, near.ifindex, uplink.index)
		via6, verr6 := route_lookup(&c, IP6_Address{0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111})
		testing.expect_value(t, verr6, Error.None)
		testing.expect_value(t, via6.gateway, Maybe(Address)(Address(gw6)))

		// Pin the server through the old gateway, then add the half routes
		// through the VPN peer (gateway on the VPN subnet).
		pin := Route {
			dst     = server,
			dst_len = 32,
			gateway = gw,
			ifindex = uplink.index,
		}
		testing.expect_value(t, route_add(&c, pin), Error.None)
		low := Route {
			dst     = IP4_Address{0, 0, 0, 0},
			dst_len = 1,
			gateway = V4_PEER,
			ifindex = vpn.index,
		}
		high := Route {
			dst     = IP4_Address{128, 0, 0, 0},
			dst_len = 1,
			gateway = V4_PEER,
			ifindex = vpn.index,
		}
		testing.expect_value(t, route_add(&c, low), Error.None)
		testing.expect_value(t, route_add(&c, high), Error.None)

		// The server still goes out the old way; everything else uses the VPN.
		r1, e1 := route_lookup(&c, server)
		testing.expect_value(t, e1, Error.None)
		testing.expect_value(t, r1.ifindex, uplink.index)
		testing.expect_value(t, r1.gateway, Maybe(Address)(Address(gw)))
		r2, e2 := route_lookup(&c, IP4_Address{8, 8, 8, 8})
		testing.expect_value(t, e2, Error.None)
		testing.expect_value(t, r2.ifindex, vpn.index)
		testing.expect_value(t, r2.gateway, Maybe(Address)(Address(V4_PEER)))
		testing.expect_value(t, r2.prefsrc, Maybe(Address)(Address(V4_LOCAL)))
		r3, e3 := route_lookup(&c, IP4_Address{200, 1, 2, 3})
		testing.expect_value(t, e3, Error.None)
		testing.expect_value(t, r3.ifindex, vpn.index)

		// Take it all down again, in reverse order.
		testing.expect_value(t, route_del(&c, high), Error.None)
		testing.expect_value(t, route_del(&c, low), Error.None)
		testing.expect_value(t, route_del(&c, pin), Error.None)
		testing.expect_value(t, route_del(&c, def6), Error.None)
		testing.expect_value(t, route_del(&c, worse), Error.None)
		testing.expect_value(t, route_del(&c, def), Error.None)
		_, derr = route_get_default(&c, .V4)
		testing.expect_value(t, derr, Error.Not_Found)
		_, derr = route_get_default(&c, .V6)
		testing.expect_value(t, derr, Error.Not_Found)
	}

	// `route_list_protocol` finds routes by protocol number, in every table,
	// and only those.
	@(test)
	netns_route_list_by_protocol :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirsys9")
		if !made {
			return
		}
		defer tun.close(&dev)
		testing.expect_value(t, link_set_up(&c, link.index), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V6_LOCAL, 64), Error.None)

		mk4 := proc(net: u8, table: u32, proto: u8, index: u32) -> Route {
			return Route{dst = IP4_Address{10, 198, net, 0}, dst_len = 24, ifindex = index, table = table, protocol = proto}
		}
		ours := []Route {
			mk4(1, 0, 201, link.index),
			mk4(2, 100, 201, link.index),
			{dst = IP6_Address{0xfd00, 0xc8, 0, 0, 0, 0, 0, 0}, dst_len = 48, ifindex = link.index, protocol = 201},
		}
		others := []Route{mk4(3, 0, 4, link.index), mk4(4, 0, 202, link.index), mk4(5, 100, 4, link.index)}
		for r in ours {
			testing.expect_value(t, route_add(&c, r), Error.None)
		}
		for r in others {
			testing.expect_value(t, route_add(&c, r), Error.None)
		}

		found := make([dynamic]Route)
		defer delete(found)
		testing.expect_value(t, route_list_protocol(&c, .V4, 201, &found), Error.None)
		testing.expect_value(t, len(found), 2)
		tables: [2]u32
		for r, i in found {
			testing.expect_value(t, r.protocol, u8(201))
			if i < 2 {
				tables[i] = r.table
			}
		}
		testing.expect(t, (tables[0] == 100 && tables[1] == 254) || (tables[0] == 254 && tables[1] == 100), "both tables")
		testing.expect_value(t, route_list_protocol(&c, .V6, 201, &found), Error.None)
		testing.expect_value(t, len(found), 1)
		// A number nobody uses.
		testing.expect_value(t, route_list_protocol(&c, .V4, 203, &found), Error.None)
		testing.expect_value(t, len(found), 0)
		// What was found can be deleted as it was found.
		testing.expect_value(t, route_list_protocol(&c, .V4, 201, &found), Error.None)
		for r in found {
			testing.expect_value(t, route_del(&c, r), Error.None)
		}
		testing.expect_value(t, route_list_protocol(&c, .V4, 201, &found), Error.None)
		testing.expect_value(t, len(found), 0)
	}

	@(test)
	netns_packets_through_the_tunnel_v4 :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirpkt0")
		if !made {
			return
		}
		defer tun.close(&dev)
		testing.expect_value(t, link_set_mtu(&c, link.index, 1400), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, link_set_up(&c, link.index), Error.None)

		// Route to a far network through the peer, to show a route we added
		// really steers packets into the device.
		far := Route {
			dst     = IP4_Address{192, 168, 77, 0},
			dst_len = 24,
			gateway = V4_PEER,
			ifindex = link.index,
		}
		testing.expect_value(t, route_add(&c, far), Error.None)

		sock, serr := net.udp_open(.V4)
		testing.expect_value(t, serr, net.Error.None)
		if serr != .None {
			return
		}
		defer net.close(sock)

		buf: [2048]u8
		payload := []u8{'h', 'e', 'l', 'l', 'o', ' ', 'v', '4'}

		// Socket to tun: an application sends to a far address; the packet
		// shows up on the tun descriptor.
		testing.expect_value(
			t,
			net.send_to(sock, payload, net.Endpoint{address = IP4_Address{192, 168, 77, 5}, port = 7777}),
			net.Error.None,
		)
		pkt, got := read_udp_packet(&dev, 4, 7777, buf[:], 1000)
		testing.expect(t, got, "packet read from the tun")
		if got {
			testing.expect_value(t, pkt[9], 17)
			testing.expect_value(t, [4]u8{pkt[12], pkt[13], pkt[14], pkt[15]}, v4_bytes(V4_LOCAL))
			testing.expect_value(t, [4]u8{pkt[16], pkt[17], pkt[18], pkt[19]}, [4]u8{192, 168, 77, 5})
			testing.expect_value(t, checksum_fold(checksum_add(0, pkt[:20])), 0)
			testing.expect_value(t, string(pkt[28:]), "hello v4")
		}

		// Tun to socket: inject a packet that arrives from the peer.
		rx, rerr := udp_bound(.V4, net.Endpoint{address = V4_LOCAL, port = 5555})
		testing.expect_value(t, rerr, net.Error.None)
		if rerr != .None {
			return
		}
		defer net.close(rx)
		out: [128]u8
		inject := ipv4_udp(v4_bytes(V4_PEER), v4_bytes(V4_LOCAL), 4444, 5555, []u8{'r', 'e', 'p', 'l', 'y'}, out[:])
		testing.expect_value(t, tun.write(&dev, inject), tun.Error.None)
		testing.expect(t, wait_readable(rx.fd, 1000), "datagram delivered")
		n, from, ferr := net.recv_from(rx, buf[:])
		testing.expect_value(t, ferr, net.Error.None)
		testing.expect_value(t, string(buf[:n]), "reply")
		testing.expect_value(t, from.address, net.Address(V4_PEER))
		testing.expect_value(t, from.port, 4444)

		testing.expect_value(t, route_del(&c, far), Error.None)
		testing.expect_value(t, addr_del(&c, link.index, V4_LOCAL, 24), Error.None)
	}

	@(test)
	netns_packets_through_the_tunnel_v6 :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirpkt1")
		if !made {
			return
		}
		defer tun.close(&dev)
		testing.expect_value(t, addr_add(&c, link.index, V6_LOCAL, 64), Error.None)
		testing.expect_value(t, link_set_up(&c, link.index), Error.None)

		sock, serr := net.udp_open(.V6)
		testing.expect_value(t, serr, net.Error.None)
		if serr != .None {
			return
		}
		defer net.close(sock)

		buf: [2048]u8
		testing.expect_value(
			t,
			net.send_to(sock, []u8{'h', 'e', 'l', 'l', 'o', ' ', 'v', '6'}, net.Endpoint{address = V6_PEER, port = 7777}),
			net.Error.None,
		)
		pkt, got := read_udp_packet(&dev, 6, 7777, buf[:], 1000)
		testing.expect(t, got, "IPv6 packet read from the tun")
		if got {
			src := v6_bytes(V6_LOCAL)
			dst := v6_bytes(V6_PEER)
			testing.expect_value(t, string(pkt[8:24]), string(src[:]))
			testing.expect_value(t, string(pkt[24:40]), string(dst[:]))
			testing.expect_value(t, string(pkt[48:]), "hello v6")
		}

		rx, rerr := udp_bound(.V6, net.Endpoint{address = V6_LOCAL, port = 5556})
		testing.expect_value(t, rerr, net.Error.None)
		if rerr != .None {
			return
		}
		defer net.close(rx)
		out: [128]u8
		inject := ipv6_udp(v6_bytes(V6_PEER), v6_bytes(V6_LOCAL), 4444, 5556, []u8{'r', 'e', 'p', 'l', 'y'}, out[:])
		testing.expect_value(t, tun.write(&dev, inject), tun.Error.None)
		testing.expect(t, wait_readable(rx.fd, 1000), "IPv6 datagram delivered")
		n, from, ferr := net.recv_from(rx, buf[:])
		testing.expect_value(t, ferr, net.Error.None)
		testing.expect_value(t, string(buf[:n]), "reply")
		testing.expect_value(t, from.address, net.Address(V6_PEER))
		testing.expect_value(t, from.port, 4444)

		testing.expect_value(t, addr_del(&c, link.index, V6_LOCAL, 64), Error.None)
	}

	// The configuration a client applies after the handshake, start to end,
	// then removed again in the opposite order.
	@(test)
	netns_client_setup_sequence :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirmvp0")
		if !made {
			return
		}
		defer tun.close(&dev)

		// ifconfig 10.199.0.2 255.255.255.0 plus ifconfig-ipv6 fd00:199::2/64
		testing.expect_value(t, tun.set_mtu(&dev, 1400), tun.Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, addr_add(&c, link.index, V6_LOCAL, 64), Error.None)
		testing.expect_value(t, link_set_up(&c, link.index), Error.None)
		// route 192.168.77.0 255.255.255.0 and route-ipv6 2001:db8:77::/48
		r4 := Route {
			dst     = IP4_Address{192, 168, 77, 0},
			dst_len = 24,
			gateway = V4_PEER,
			ifindex = link.index,
		}
		r6 := Route {
			dst     = IP6_Address{0x2001, 0x0db8, 0x0077, 0, 0, 0, 0, 0},
			dst_len = 48,
			gateway = V6_PEER,
			ifindex = link.index,
		}
		testing.expect_value(t, route_add(&c, r4), Error.None)
		testing.expect_value(t, route_add(&c, r6), Error.None)

		// Read it all back.
		l, _ := link_get(&c, "noirmvp0")
		testing.expect(t, .Up in l.flags)
		testing.expect_value(t, l.mtu, 1400)
		addrs := make([dynamic]Addr_Info)
		defer delete(addrs)
		testing.expect_value(t, addr_list(&c, link.index, nil, &addrs), Error.None)
		n4, n6 := 0, 0
		for a in addrs {
			if _, is4 := a.address.(IP4_Address); is4 {
				n4 += 1
			} else if a.address == Address(V6_LOCAL) {
				n6 += 1
			}
		}
		testing.expect_value(t, n4, 1)
		testing.expect_value(t, n6, 1)
		via, verr := route_lookup(&c, IP4_Address{192, 168, 77, 9})
		testing.expect_value(t, verr, Error.None)
		testing.expect_value(t, via.ifindex, link.index)
		testing.expect_value(t, via.gateway, Maybe(Address)(Address(V4_PEER)))
		via6, verr6 := route_lookup(&c, IP6_Address{0x2001, 0x0db8, 0x0077, 0, 0, 0, 0, 9})
		testing.expect_value(t, verr6, Error.None)
		testing.expect_value(t, via6.ifindex, link.index)

		// Tear down.
		testing.expect_value(t, route_del(&c, r6), Error.None)
		testing.expect_value(t, route_del(&c, r4), Error.None)
		testing.expect_value(t, addr_del(&c, link.index, V6_LOCAL, 64), Error.None)
		testing.expect_value(t, addr_del(&c, link.index, V4_LOCAL, 24), Error.None)
		testing.expect_value(t, link_set_down(&c, link.index), Error.None)
		_, lerr := route_lookup(&c, IP4_Address{192, 168, 77, 9})
		testing.expect_value(t, lerr, Error.Network_Unreachable)
	}

	@(test)
	netns_delete_link :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		dev, link, made := make_tun(t, &c, "noirdel0")
		if !made {
			return
		}
		defer tun.close(&dev)
		testing.expect_value(t, link_delete(&c, link.index), Error.None)
		_, err := link_get(&c, "noirdel0")
		testing.expect_value(t, err, Error.Not_Found)
		testing.expect_value(t, link_delete(&c, link.index), Error.Not_Found)
	}

	@(test)
	netns_kernel_error_text_is_kept :: proc(t: ^testing.T) {
		c, ok := open_checked(t)
		if !ok {
			return
		}
		defer close(&c)
		_, err := link_get(&c, "noir-missing")
		testing.expect_value(t, err, Error.Not_Found)
		testing.expect_value(t, last_errno(&c), linux.Errno.ENODEV)
	}
}
