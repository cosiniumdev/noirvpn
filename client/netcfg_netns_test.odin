// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package client

import "core:fmt"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sys/linux"
import "core:testing"
import "noir:platform/sysnet"
import "noir:platform/tun"
import "noir:proto/config"
import "noir:proto/push"

// Tests that change network state: they create tun devices, apply real plans
// with the executor, ask the kernel where packets would go, and check that
// teardown leaves the routing table as it was. They run only with
// -define:NOIR_NETNS_TESTS=true, and only inside a private network namespace
// owned by a user namespace (see platform/run-netns-tests.sh). Run them with
// -define:ODIN_TEST_THREADS=1: the tests share one namespace.
//
// The lab: `noirup0` plays the physical interface (192.0.2.10/24 and
// 2001:db8:1::10/64, default routes through 192.0.2.1 and 2001:db8:1::1),
// `noirvpn0` is the VPN tunnel. The VPN server is 198.51.100.7 (or
// 2001:db8:100::7) and is reached through the uplink.
//
// Without the define the helpers compile (so the privileged code is
// type-checked on every build), but no test is registered.
NETNS :: #config(NOIR_NETNS_TESTS, false)

LAB_GW4 :: sysnet.IP4_Address{192, 0, 2, 1}
LAB_GW6 :: sysnet.IP6_Address{0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 1}
LAB_SERVER4 :: sysnet.IP4_Address{198, 51, 100, 7}
LAB_SERVER6 :: sysnet.IP6_Address{0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 7}
// Hosts on the "internet" and in the "company network".
NET_HOST4 :: sysnet.IP4_Address{8, 8, 8, 8}
NET_HOST6 :: sysnet.IP6_Address{0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111}

// ---- the namespace guard (the same rules as platform/sysnet) ----

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

// Links a new namespace has by itself, and ours.
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

require_private_netns :: proc(t: ^testing.T, c: ^sysnet.Conn) -> bool {
	if !in_private_userns() {
		testing.expect(t, false, "not in a private user namespace: run platform/run-netns-tests.sh")
		return false
	}
	links := make([dynamic]sysnet.Link_Info)
	defer delete(links)
	if err := sysnet.link_list(c, &links); err != .None {
		testing.expectf(t, false, "cannot list links: %v", err)
		return false
	}
	for &l in links {
		n := sysnet.link_name(&l)
		if !is_expected_link(n) {
			testing.expectf(t, false, "unexpected link %q: this is not a throwaway namespace", n)
			return false
		}
	}
	return true
}

// ---- the lab ----

Lab :: struct {
	conn:    sysnet.Conn,
	up_dev:  tun.Device,
	vpn_dev: tun.Device,
	uplink:  sysnet.Link_Info,
	vpn:     sysnet.Link_Info,
	// The old default routes, as added.
	def4:    sysnet.Route,
	def6:    sysnet.Route,
}

lab_open :: proc(t: ^testing.T, lab: ^Lab) -> bool {
	lab^ = {}
	err: sysnet.Error
	lab.conn, err = sysnet.open()
	testing.expect_value(t, err, sysnet.Error.None)
	if err != .None {
		return false
	}
	if !require_private_netns(t, &lab.conn) {
		sysnet.close(&lab.conn)
		return false
	}
	ok := false
	defer if !ok {
		lab_close(lab)
	}

	terr: tun.Error
	lab.up_dev, terr = tun.open({name = "noirup0"})
	testing.expect_value(t, terr, tun.Error.None)
	if terr != .None {
		return false
	}
	lab.vpn_dev, terr = tun.open({name = "noirvpn0"})
	testing.expect_value(t, terr, tun.Error.None)
	if terr != .None {
		return false
	}
	lerr: sysnet.Error
	lab.uplink, lerr = sysnet.link_get(&lab.conn, "noirup0")
	testing.expect_value(t, lerr, sysnet.Error.None)
	lab.vpn, lerr = sysnet.link_get(&lab.conn, "noirvpn0")
	testing.expect_value(t, lerr, sysnet.Error.None)
	if lerr != .None {
		return false
	}

	c := &lab.conn
	testing.expect_value(t, sysnet.link_set_up(c, lab.uplink.index), sysnet.Error.None)
	testing.expect_value(t, sysnet.addr_add(c, lab.uplink.index, sysnet.IP4_Address{192, 0, 2, 10}, 24), sysnet.Error.None)
	testing.expect_value(t, sysnet.addr_add(c, lab.uplink.index, sysnet.IP6_Address{0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 10}, 64), sysnet.Error.None)
	lab.def4 = sysnet.Route {
		dst     = sysnet.default_dst(.V4),
		gateway = sysnet.Address(LAB_GW4),
		ifindex = lab.uplink.index,
		metric  = u32(100),
	}
	lab.def6 = sysnet.Route {
		dst     = sysnet.default_dst(.V6),
		gateway = sysnet.Address(LAB_GW6),
		ifindex = lab.uplink.index,
		metric  = u32(1024),
	}
	testing.expect_value(t, sysnet.route_add(c, lab.def4), sysnet.Error.None)
	testing.expect_value(t, sysnet.route_add(c, lab.def6), sysnet.Error.None)
	ok = true
	return true
}

lab_close :: proc(lab: ^Lab) {
	tun.close(&lab.vpn_dev)
	tun.close(&lab.up_dev)
	sysnet.close(&lab.conn)
}

// ---- snapshots ----

// Everything the VPN could change, as text lines: the main routing table
// (both families), routes with our protocol number in any table, and the
// state of the VPN link. Sorted, so the order of the kernel's reply does
// not matter.
snapshot :: proc(lab: ^Lab) -> []string {
	lines := make([dynamic]string, context.temp_allocator)
	c := &lab.conn
	for fam in ([]sysnet.Family{.V4, .V6}) {
		routes := make([dynamic]sysnet.Route, context.temp_allocator)
		err := sysnet.route_list(c, fam, 0, 0, &routes)
		if err != .None {
			append(&lines, fmt.tprintf("route_list(%v) failed: %v", fam, err))
			continue
		}
		for r in routes {
			append(&lines, fmt.tprintf("main %v", route_text(r)))
		}
		mine := make([dynamic]sysnet.Route, context.temp_allocator)
		if merr := sysnet.route_list_protocol(c, fam, ROUTE_PROTOCOL, &mine); merr == .None {
			for r in mine {
				append(&lines, fmt.tprintf("mine %v", route_text(r)))
			}
		}
	}
	l, lerr := sysnet.link_get_by_index(c, lab.vpn.index)
	if lerr == .None {
		append(&lines, fmt.tprintf("vpn link: up=%v mtu=%d", .Up in l.flags, l.mtu))
	} else {
		append(&lines, fmt.tprintf("vpn link: %v", lerr))
	}
	addrs := make([dynamic]sysnet.Addr_Info, context.temp_allocator)
	if aerr := sysnet.addr_list(c, lab.vpn.index, nil, &addrs); aerr == .None {
		for a in addrs {
			append(&lines, fmt.tprintf("vpn addr %v/%d", a.address, a.prefix_len))
		}
	}
	slice.sort(lines[:])
	return lines[:]
}

route_text :: proc(r: sysnet.Route) -> string {
	return fmt.tprintf(
		"%v/%d via %v dev %d metric %v table %d proto %d kind %v",
		r.dst,
		r.dst_len,
		r.gateway,
		r.ifindex,
		r.metric,
		r.table,
		r.protocol,
		r.kind,
	)
}

expect_same_snapshot :: proc(t: ^testing.T, before, after: []string, loc := #caller_location) {
	if slice.equal(before, after) {
		return
	}
	testing.expectf(
		t,
		false,
		"the system is not as it was\n  before:\n    %s\n  after:\n    %s",
		strings.join(before, "\n    ", context.temp_allocator),
		strings.join(after, "\n    ", context.temp_allocator),
		loc = loc,
	)
}

// ---- running a plan ----

// Build a plan the way the daemon does: gather first, then plan.
lab_plan :: proc(t: ^testing.T, lab: ^Lab, conf, push_text: string, server: sysnet.Address, loc := #caller_location) -> (plan: Plan, ok: bool) {
	st, gerr := netcfg_gather(&lab.conn, server, lab.vpn.index)
	testing.expect_value(t, gerr, Gather_Error.None, loc = loc)
	if gerr != .None {
		return {}, false
	}
	return lab_plan_with(t, lab, st, conf, push_text, server, loc)
}

// The same with a saved view of the system (what the daemon keeps for
// `persist-tun`).
lab_plan_with :: proc(
	t: ^testing.T,
	lab: ^Lab,
	st: System_State,
	conf, push_text: string,
	server: sysnet.Address,
	loc := #caller_location,
) -> (
	plan: Plan,
	ok: bool,
) {
	_ = lab
	cfg := load_client("remote vpn.example 1194 udp", conf)
	defer config.destroy(&cfg)
	if !expect_config_ok(t, &cfg, loc) {
		return {}, false
	}
	po: push.Pushed_Options
	perr := push.pushed_options_parse(&po, push_text)
	testing.expect_value(t, perr, push.Error.None, loc = loc)
	defer push.pushed_options_destroy(&po)

	perr2: Plan_Error
	plan, perr2 = plan_build(
		Plan_Input {
			cfg = &cfg.client,
			pushed = &po,
			server = server,
			server_route = st.server_route,
			default4 = st.default4,
			default6 = st.default6,
		},
	)
	testing.expect_value(t, perr2, Plan_Error.None, loc = loc)
	return plan, perr2 == .None
}

expect_lookup :: proc(
	t: ^testing.T,
	lab: ^Lab,
	dst: sysnet.Address,
	ifindex: u32,
	gateway: Maybe(sysnet.Address) = nil,
	loc := #caller_location,
) {
	r, err := sysnet.route_lookup(&lab.conn, dst)
	if !testing.expectf(t, err == .None, "lookup of %v failed: %v", dst, err, loc = loc) {
		return
	}
	testing.expectf(t, r.ifindex == ifindex, "%v goes out of interface %d, want %d", dst, r.ifindex, ifindex, loc = loc)
	if gateway != nil {
		testing.expectf(t, r.gateway == gateway, "%v goes via %v, want %v", dst, r.gateway, gateway, loc = loc)
	}
}

expect_unreachable :: proc(t: ^testing.T, lab: ^Lab, dst: sysnet.Address, loc := #caller_location) {
	r, err := sysnet.route_lookup(&lab.conn, dst)
	testing.expectf(t, err != .None, "%v should be unreachable, but goes out of interface %d", dst, r.ifindex, loc = loc)
}

expect_no_warnings :: proc(t: ^testing.T, nc: ^Netcfg, loc := #caller_location) {
	testing.expectf(t, len(nc.warnings) == 0, "warnings: %v", nc.warnings[:], loc = loc)
}

when NETNS {

	// IPv4 only, a few routes, no redirect: ordinary traffic stays on the uplink.
	@(test)
	client_netns_v4_routes :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		push_text := "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,tun-mtu 1400,route 10.1.0.0 255.255.0.0,route 192.168.50.0 255.255.255.0 vpn_gateway 5,route 172.16.0.0 255.240.0.0 net_gateway"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		gw := sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1})
		expect_lookup(t, &lab, sysnet.IP4_Address{10, 1, 2, 3}, lab.vpn.index, gw)
		expect_lookup(t, &lab, sysnet.IP4_Address{192, 168, 50, 9}, lab.vpn.index, gw)
		expect_lookup(t, &lab, sysnet.IP4_Address{10, 8, 0, 77}, lab.vpn.index) // the tunnel's own net
		expect_lookup(t, &lab, sysnet.IP4_Address{172, 20, 1, 1}, lab.uplink.index, sysnet.Address(LAB_GW4))
		expect_lookup(t, &lab, NET_HOST4, lab.uplink.index, sysnet.Address(LAB_GW4))
		expect_lookup(t, &lab, LAB_SERVER4, lab.uplink.index, sysnet.Address(LAB_GW4))

		l, _ := sysnet.link_get_by_index(&lab.conn, lab.vpn.index)
		testing.expect(t, .Up in l.flags)
		testing.expect_value(t, l.mtu, u32(1400))
		testing.expect_value(t, len(nc.undo), 1 + 1 + 1 + 3) // mtu, addr, up, routes

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		testing.expect(t, !netcfg_is_applied(&nc))
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// The full set: subnet topology, v4 and v6 addresses, routes, routes6,
	// redirect-gateway def1 ipv6. The internet goes through the tunnel, the
	// server goes through the uplink.
	@(test)
	client_netns_def1_with_ipv6 :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		push_text := "redirect-gateway def1 ipv6,topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,ifconfig-ipv6 fd00:8::6/64 fd00:8::1,route 10.1.0.0 255.255.0.0,route-ipv6 fd00:99::/64,dhcp-option DNS 10.8.0.1,tun-mtu 1380"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)
		testing.expect(t, plan.redirect4 && plan.redirect6)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		gw4 := sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1})
		gw6 := sysnet.Address(sysnet.IP6_Address{0xfd00, 8, 0, 0, 0, 0, 0, 1})
		expect_lookup(t, &lab, NET_HOST4, lab.vpn.index, gw4)
		expect_lookup(t, &lab, sysnet.IP4_Address{200, 1, 2, 3}, lab.vpn.index, gw4)
		expect_lookup(t, &lab, sysnet.IP4_Address{10, 1, 2, 3}, lab.vpn.index, gw4)
		expect_lookup(t, &lab, NET_HOST6, lab.vpn.index, gw6)
		expect_lookup(t, &lab, sysnet.IP6_Address{0x9000, 0, 0, 0, 0, 0, 0, 1}, lab.vpn.index, gw6)
		expect_lookup(t, &lab, sysnet.IP6_Address{0xfd00, 0x99, 0, 0, 0, 0, 0, 5}, lab.vpn.index, gw6)
		// The server is the exception.
		expect_lookup(t, &lab, LAB_SERVER4, lab.uplink.index, sysnet.Address(LAB_GW4))
		// So is the uplink's own subnet.
		expect_lookup(t, &lab, sysnet.IP4_Address{192, 0, 2, 99}, lab.uplink.index)

		// The routes are ours: they carry the private protocol number.
		mine := make([dynamic]sysnet.Route, context.temp_allocator)
		testing.expect_value(t, sysnet.route_list_protocol(&lab.conn, .V4, ROUTE_PROTOCOL, &mine), sysnet.Error.None)
		testing.expect_value(t, len(mine), 1 + 1 + 2) // pin, route, two halves
		testing.expect_value(t, sysnet.route_list_protocol(&lab.conn, .V6, ROUTE_PROTOCOL, &mine), sysnet.Error.None)
		testing.expect_value(t, len(mine), 1 + 2) // the v6 route and two halves

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
		// And the lookups are the old ones again.
		expect_lookup(t, &lab, NET_HOST4, lab.uplink.index, sysnet.Address(LAB_GW4))
		expect_lookup(t, &lab, NET_HOST6, lab.uplink.index, sysnet.Address(LAB_GW6))
	}

	@(test)
	client_netns_block_ipv6 :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		// An IPv4-only VPN with `block-ipv6`. The option is a rule for the packets of
		// the tunnel: the plan adds no route for it, and the IPv6 of the host is as before.
		push_text := "redirect-gateway def1,block-ipv6,topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		expect_lookup(t, &lab, NET_HOST4, lab.vpn.index, sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1}))
		expect_lookup(t, &lab, LAB_SERVER4, lab.uplink.index, sysnet.Address(LAB_GW4))
		// The IPv6 default route of the host is still in use.
		expect_lookup(t, &lab, NET_HOST6, lab.uplink.index, sysnet.Address(LAB_GW6))
		// The uplink's own IPv6 subnet still works.
		expect_lookup(t, &lab, sysnet.IP6_Address{0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 99}, lab.uplink.index)

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
		expect_lookup(t, &lab, NET_HOST6, lab.uplink.index, sysnet.Address(LAB_GW6))
	}

	// redirect-gateway without def1: a default route with a lower metric. The
	// old default route is never touched.
	@(test)
	client_netns_replace_default_route :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		push_text := "redirect-gateway,topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		expect_lookup(t, &lab, NET_HOST4, lab.vpn.index, sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1}))
		expect_lookup(t, &lab, LAB_SERVER4, lab.uplink.index, sysnet.Address(LAB_GW4))
		// The old default route is still in the table.
		routes := make([dynamic]sysnet.Route, context.temp_allocator)
		testing.expect_value(t, sysnet.route_list(&lab.conn, .V4, 0, lab.uplink.index, &routes), sysnet.Error.None)
		found := false
		for r in routes {
			if r.dst_len == 0 && r.gateway == Maybe(sysnet.Address)(sysnet.Address(LAB_GW4)) {
				found = true
			}
		}
		testing.expect(t, found, "the old default route must stay")

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// The server is only IPv6, and the whole VPN is IPv6 only.
	@(test)
	client_netns_ipv6_only :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		push_text := "redirect-gateway def1 ipv6 !ipv4,topology subnet,ifconfig-ipv6 fd00:8::6/64 fd00:8::1,route-ipv6 fd00:77::/48"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER6)
		if !ok {
			return
		}
		defer plan_destroy(&plan)
		testing.expect(t, !plan.redirect4 && plan.redirect6)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		gw6 := sysnet.Address(sysnet.IP6_Address{0xfd00, 8, 0, 0, 0, 0, 0, 1})
		expect_lookup(t, &lab, NET_HOST6, lab.vpn.index, gw6)
		expect_lookup(t, &lab, sysnet.IP6_Address{0xfd00, 0x77, 0, 1, 0, 0, 0, 1}, lab.vpn.index, gw6)
		expect_lookup(t, &lab, LAB_SERVER6, lab.uplink.index, sysnet.Address(LAB_GW6))
		// IPv4 is not redirected.
		expect_lookup(t, &lab, NET_HOST4, lab.uplink.index, sysnet.Address(LAB_GW4))

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// The server is reached by a route that is not the default route, and a
	// pushed route covers the server's network.
	@(test)
	client_netns_server_via_a_specific_route :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		// 198.51.100.0/24 is behind another router on the uplink, metric 50.
		gw2 := sysnet.Address(sysnet.IP4_Address{192, 0, 2, 254})
		special := sysnet.Route {
			dst     = sysnet.IP4_Address{198, 51, 100, 0},
			dst_len = 24,
			gateway = gw2,
			ifindex = lab.uplink.index,
			metric  = u32(50),
		}
		testing.expect_value(t, sysnet.route_add(&lab.conn, special), sysnet.Error.None)
		before := snapshot(&lab)

		push_text := "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,route 198.51.100.0 255.255.255.0,route 198.51.100.7 255.255.255.255"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)
		testing.expect(t, plan.pinned != nil)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		// The server still goes the old way, through the other router.
		expect_lookup(t, &lab, LAB_SERVER4, lab.uplink.index, gw2)
		// The rest of its network goes through the tunnel.
		expect_lookup(t, &lab, sysnet.IP4_Address{198, 51, 100, 8}, lab.vpn.index, sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1}))

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
		testing.expect_value(t, sysnet.route_del(&lab.conn, special), sysnet.Error.None)
	}

	// A server on the uplink's own subnet (on-link): the pin is a device route.
	@(test)
	client_netns_server_on_link :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)
		server := sysnet.Address(sysnet.IP4_Address{192, 0, 2, 77})

		push_text := "redirect-gateway def1,topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1"
		plan, ok := lab_plan(t, &lab, "", push_text, server)
		if !ok {
			return
		}
		defer plan_destroy(&plan)
		testing.expect(t, plan.pinned != nil)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)
		expect_lookup(t, &lab, server, lab.uplink.index)
		expect_lookup(t, &lab, NET_HOST4, lab.vpn.index)
		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// `route-table`: all routes go to one table; the main table is untouched,
	// and teardown and the clean-up at start both find them there.
	@(test)
	client_netns_route_table :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		push_text := "redirect-gateway def1,topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,route 10.1.0.0 255.255.0.0"
		plan, ok := lab_plan(t, &lab, "route-table 100", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		// The main table is as before (apart from the connected route).
		routes := make([dynamic]sysnet.Route, context.temp_allocator)
		testing.expect_value(t, sysnet.route_list(&lab.conn, .V4, 100, 0, &routes), sysnet.Error.None)
		testing.expect_value(t, len(routes), 4) // pin, route, two halves
		// Ordinary lookups do not use table 100 (no rule points there).
		expect_lookup(t, &lab, NET_HOST4, lab.uplink.index, sysnet.Address(LAB_GW4))

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// The tunnel goes away before teardown (the tun descriptor is closed): the
	// kernel removes the tunnel's own routes, and teardown has to cope with
	// that and still remove the pin and the IPv6 block.
	@(test)
	client_netns_teardown_after_the_tunnel_is_gone :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		// The tunnel of this test is a second one, so the lab stays whole.
		dev2, terr := tun.open({name = "noirvpn1"})
		testing.expect_value(t, terr, tun.Error.None)
		if terr != .None {
			return
		}
		defer tun.close(&dev2)
		vpn2, lerr := sysnet.link_get(&lab.conn, "noirvpn1")
		testing.expect_value(t, lerr, sysnet.Error.None)
		if lerr != .None {
			return
		}
		lab.vpn = vpn2
		before := snapshot_routes(&lab)

		push_text := "redirect-gateway def1 ipv6,block-ipv6,topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,ifconfig-ipv6 fd00:8::6/64 fd00:8::1,route 10.1.0.0 255.255.0.0"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, vpn2.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)
		testing.expect(t, snapshot_count_mine(&lab) > 0)

		// The device goes away under us.
		tun.close(&dev2)
		testing.expect_value(t, link_exists(&lab, vpn2.index), false)

		// Teardown: nothing fails; what is left of ours (the pin, the IPv6
		// block) goes too.
		testing.expect_value(t, netcfg_teardown(&nc), 0)
		testing.expect_value(t, snapshot_count_mine(&lab), 0)
		expect_same_snapshot(t, before, snapshot_routes(&lab))
	}

	// Two daemons: the second starts while the first has a live tunnel, and the
	// routes of the first stay. Then the first dies without a teardown (its
	// tunnel goes with its descriptor, the pin through the old gateway stays)
	// and the start of a third removes the pin, and nothing else.
	@(test)
	client_netns_records_two_daemons_and_a_crash :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		base, dir, env, dok := netns_state_dir(t, "two")
		if !dok {
			return
		}
		defer os.remove_all(base)

		// Somebody else's routes must survive: a static route (protocol 4)
		// and one with another private number.
		others := []sysnet.Route {
			{dst = sysnet.IP4_Address{203, 0, 113, 0}, dst_len = 24, gateway = sysnet.Address(LAB_GW4), ifindex = lab.uplink.index, protocol = 4},
			{dst = sysnet.IP4_Address{203, 0, 114, 0}, dst_len = 24, gateway = sysnet.Address(LAB_GW4), ifindex = lab.uplink.index, protocol = 202},
			{dst = sysnet.IP6_Address{0x2001, 0xdb8, 0x77, 0, 0, 0, 0, 0}, dst_len = 48, gateway = sysnet.Address(LAB_GW6), ifindex = lab.uplink.index, protocol = 4},
		}
		for r in others {
			testing.expect_value(t, sysnet.route_add(&lab.conn, r), sysnet.Error.None)
		}
		defer for r in others {
			_ = sysnet.route_del(&lab.conn, r)
		}

		// The first daemon: the plan goes into its record, then it runs.
		a: Record_File
		testing.expect_value(t, record_open(&a, dir, "first", .Client), Record_Open_Error.None)
		push_text := "redirect-gateway def1,topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			record_close(&a)
			return
		}
		defer plan_destroy(&plan)
		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		record_add_dev(&a.rec, lab.vpn.index, "noirvpn0")
		record_add_plan(&a.rec, &plan, &lab.conn, lab.vpn.index)
		testing.expect_value(t, record_write(&a), Record_Error.None)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)
		record_clear(&a.rec)
		record_add_dev(&a.rec, lab.vpn.index, "noirvpn0")
		record_add_netcfg(&a.rec, &nc)
		testing.expect_value(t, record_write(&a), Record_Error.None)
		testing.expect_value(t, len(a.rec.routes), 3) // pin, two halves
		testing.expect_value(t, snapshot_count_mine(&lab), 3)
		live := snapshot_routes(&lab)

		// The second daemon starts: nothing of the first is touched.
		b: Record_File
		testing.expect_value(t, record_open(&b, dir, "second", .Server), Record_Open_Error.None)
		rep := record_cleanup(&b, &lab.conn, env, "")
		testing.expect_value(t, rep.err, sysnet.Error.None)
		testing.expect_value(t, rep.records, 0)
		testing.expect_value(t, rep.routes + rep.unlisted, 0)
		expect_same_snapshot(t, live, snapshot_routes(&lab))
		expect_lookup(t, &lab, NET_HOST4, lab.vpn.index)
		expect_lookup(t, &lab, LAB_SERVER4, lab.uplink.index, sysnet.Address(LAB_GW4))
		record_close(&b)

		// The first daemon dies: no teardown, the lock goes, the tunnel goes.
		netcfg_destroy(&nc)
		record_release(&a)
		tun.close(&lab.vpn_dev)
		testing.expect_value(t, snapshot_count_mine(&lab), 1) // the pin
		expect_lookup(t, &lab, NET_HOST6, lab.uplink.index, sysnet.Address(LAB_GW6))

		// The next start removes the pin and the record of the dead daemon.
		c: Record_File
		testing.expect_value(t, record_open(&c, dir, "third", .Client), Record_Open_Error.None)
		defer record_close(&c)
		rep = record_cleanup(&c, &lab.conn, env, "")
		testing.expect_value(t, rep.err, sysnet.Error.None)
		testing.expect_value(t, rep.records, 1)
		testing.expect_value(t, rep.routes, 1)
		testing.expect_value(t, rep.unlisted, 0)
		testing.expect_value(t, snapshot_count_mine(&lab), 0)
		for r in others {
			list := make([dynamic]sysnet.Route, context.temp_allocator)
			fam := sysnet.Family.V6 if is_v6_addr(r.dst) else sysnet.Family.V4
			_ = sysnet.route_list(&lab.conn, fam, 0, lab.uplink.index, &list)
			found := false
			for e in list {
				if e.dst == r.dst && e.dst_len == r.dst_len {
					found = true
				}
			}
			testing.expectf(t, found, "others route %v was removed", r.dst)
		}
		s := record_scan(&c)
		testing.expect_value(t, len(s.live) + len(s.dead), 0)
		record_scan_destroy(&s)
		// A second run finds nothing.
		rep = record_cleanup(&c, &lab.conn, env, "")
		testing.expect_value(t, rep.records + rep.routes + rep.unlisted, 0)
	}

	// The fallback for routes that no record lists (an older version): a route
	// on a device that is no tunnel goes, a route on a tunnel device that no
	// record holds stays, and nothing goes while a live record is unreadable.
	@(test)
	client_netns_records_fallback :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		base, dir, env, dok := netns_state_dir(t, "fallback")
		if !dok {
			return
		}
		defer os.remove_all(base)
		// `lo` is a device that is no tunnel. It is down in a new namespace.
		testing.expect_value(t, sysnet.link_set_up(&lab.conn, 1), sysnet.Error.None)
		defer sysnet.link_set_down(&lab.conn, 1)
		stale := sysnet.Route{dst = sysnet.IP4_Address{203, 0, 113, 9}, dst_len = 32, ifindex = 1, protocol = ROUTE_PROTOCOL}
		on_tun := sysnet.Route{dst = sysnet.IP4_Address{10, 99, 0, 0}, dst_len = 16, ifindex = lab.vpn.index, protocol = ROUTE_PROTOCOL}
		testing.expect_value(t, sysnet.link_set_up(&lab.conn, lab.vpn.index), sysnet.Error.None)
		testing.expect_value(t, sysnet.route_add(&lab.conn, stale), sysnet.Error.None)
		testing.expect_value(t, sysnet.route_add(&lab.conn, on_tun), sysnet.Error.None)
		defer sysnet.route_del(&lab.conn, on_tun)
		defer sysnet.link_set_down(&lab.conn, lab.vpn.index)

		// A live record that this version cannot read: nothing goes.
		a: Record_File
		testing.expect_value(t, record_open(&a, dir, "newer", .Client), Record_Open_Error.None)
		defer record_close(&a)
		path := fmt.tprintf("%s/%s.rec", dir, record_id(&a))
		testing.expect(t, os.write_entire_file(path, "noirvpn-state 2\nend\n") == nil)
		linux.chmod(strings.clone_to_cstring(path, context.temp_allocator), transmute(linux.Mode)u32(0o600))
		b: Record_File
		testing.expect_value(t, record_open(&b, dir, "me", .Client), Record_Open_Error.None)
		defer record_close(&b)
		rep := record_cleanup(&b, &lab.conn, env, "")
		testing.expect(t, rep.live_unknown)
		testing.expect_value(t, rep.unlisted, 0)
		testing.expect_value(t, snapshot_count_mine(&lab), 2)

		// The record can be read again: the stale route goes, the tunnel route stays.
		testing.expect_value(t, record_write_now(&a), Record_Error.None)
		rep = record_cleanup(&b, &lab.conn, env, "")
		testing.expect(t, !rep.live_unknown)
		testing.expect_value(t, rep.unlisted, 1)
		testing.expect_value(t, snapshot_count_mine(&lab), 1)
		mine := make([dynamic]sysnet.Route, context.temp_allocator)
		_ = sysnet.route_list_protocol(&lab.conn, .V4, ROUTE_PROTOCOL, &mine)
		testing.expect_value(t, len(mine), 1)
		if len(mine) == 1 {
			testing.expect_value(t, mine[0].ifindex, lab.vpn.index)
		}
	}

	// DNS: the resolv.conf of a live daemon stays, the one of a dead daemon is
	// put back.
	@(test)
	client_netns_records_dns :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		base, dir, env, dok := netns_state_dir(t, "dns")
		if !dok {
			return
		}
		defer os.remove_all(base)
		testing.expect(t, os.write_entire_file(env.resolv_conf, "nameserver 192.0.2.53\n") == nil)
		dns: sysnet.DNS
		servers := []sysnet.DNS_Server{{address = sysnet.IP4_Address{10, 8, 0, 1}}}
		testing.expect_value(t, sysnet.dns_apply(&dns, env, "noirvpn0", {servers = servers}), sysnet.DNS_Error.None)
		defer sysnet.dns_destroy(&dns)
		ours, _ := os.read_entire_file(env.resolv_conf, context.temp_allocator)

		a: Record_File
		testing.expect_value(t, record_open(&a, dir, "first", .Client), Record_Open_Error.None)
		record_add_dev(&a.rec, lab.vpn.index, "noirvpn0")
		record_add_dns(&a.rec, sysnet.dns_backend_name(dns.backend), "noirvpn0", sysnet.dns_record_detail(env, dns.backend, "noirvpn0"))
		testing.expect_value(t, record_write(&a), Record_Error.None)

		b: Record_File
		testing.expect_value(t, record_open(&b, dir, "second", .Client), Record_Open_Error.None)
		rep := record_cleanup(&b, &lab.conn, env, "tun0")
		testing.expect_value(t, rep.dns, 0)
		now, _ := os.read_entire_file(env.resolv_conf, context.temp_allocator)
		testing.expect_value(t, string(now), string(ours))
		record_close(&b)

		record_release(&a)
		c: Record_File
		testing.expect_value(t, record_open(&c, dir, "third", .Client), Record_Open_Error.None)
		defer record_close(&c)
		rep = record_cleanup(&c, &lab.conn, env, "")
		testing.expect_value(t, rep.records, 1)
		testing.expect_value(t, rep.dns, 1)
		now, _ = os.read_entire_file(env.resolv_conf, context.temp_allocator)
		testing.expect_value(t, string(now), "nameserver 192.0.2.53\n")
	}

	// The DNS of a plan with local DNS lines is applied, recorded and reverted
	// as the pushed DNS: by dns_revert in the daemon, and by the clean-up of a
	// dead daemon's record.
	@(test)
	client_netns_local_dns_recorded_and_reverted :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		base, dir, env, dok := netns_state_dir(t, "localdns")
		if !dok {
			return
		}
		defer os.remove_all(base)
		host_text :: "nameserver 192.0.2.53\n"
		testing.expect(t, os.write_entire_file(env.resolv_conf, host_text) == nil)

		cfg := load_client("remote vpn.example 1194 udp", "dns server -1 address 10.8.0.53\ndhcp-option DOMAIN home.example")
		defer config.destroy(&cfg)
		if !expect_config_ok(t, &cfg) {
			return
		}
		po: push.Pushed_Options
		testing.expect_value(t, push.pushed_options_parse(&po, BASE + ",dns server 0 address 10.8.0.1,dhcp-option DOMAIN corp.example"), push.Error.None)
		defer push.pushed_options_destroy(&po)
		plan, perr := plan_build(default_input(&cfg.client, &po))
		defer plan_destroy(&plan)
		testing.expect_value(t, perr, Plan_Error.None)
		if !testing.expect(t, plan.has_dns) {
			return
		}
		want :: "nameserver 10.8.0.53\nnameserver 10.8.0.1\nsearch home.example corp.example\n"

		// Apply and revert in the same daemon.
		{
			dns: sysnet.DNS
			testing.expect_value(t, sysnet.dns_apply(&dns, env, "noirvpn0", plan.dns), sysnet.DNS_Error.None)
			now, _ := os.read_entire_file(env.resolv_conf, context.temp_allocator)
			testing.expectf(t, strings.contains(string(now), want), "resolv.conf while up:\n%s", string(now))
			testing.expect_value(t, sysnet.dns_revert(&dns), sysnet.DNS_Error.None)
			sysnet.dns_destroy(&dns)
			now, _ = os.read_entire_file(env.resolv_conf, context.temp_allocator)
			testing.expect_value(t, string(now), host_text)
		}

		// Apply and record; the daemon dies; the next daemon puts it back.
		dns: sysnet.DNS
		testing.expect_value(t, sysnet.dns_apply(&dns, env, "noirvpn0", plan.dns), sysnet.DNS_Error.None)
		defer sysnet.dns_destroy(&dns)
		a: Record_File
		testing.expect_value(t, record_open(&a, dir, "first", .Client), Record_Open_Error.None)
		record_add_dev(&a.rec, lab.vpn.index, "noirvpn0")
		record_add_dns(&a.rec, sysnet.dns_backend_name(dns.backend), "noirvpn0", sysnet.dns_record_detail(env, dns.backend, "noirvpn0"))
		testing.expect_value(t, record_write(&a), Record_Error.None)
		testing.expect_value(t, len(a.rec.dns), 1)
		record_release(&a)

		b: Record_File
		testing.expect_value(t, record_open(&b, dir, "second", .Client), Record_Open_Error.None)
		defer record_close(&b)
		rep := record_cleanup(&b, &lab.conn, env, "")
		testing.expect_value(t, rep.records, 1)
		testing.expect_value(t, rep.dns, 1)
		now, _ := os.read_entire_file(env.resolv_conf, context.temp_allocator)
		testing.expect_value(t, string(now), host_text)
	}

	// A step that must not fail does: everything that was done is undone.
	@(test)
	client_netns_failed_critical_step_rolls_back :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		plan := Plan {
			steps = make([dynamic]Step, 5),
		}
		defer delete(plan.steps)
		plan.steps[0] = Step{kind = .Set_Mtu, mtu = 1300}
		plan.steps[1] = Step{kind = .Add_Addr, addr = sysnet.IP4_Address{10, 8, 0, 6}, prefix_len = 24}
		plan.steps[2] = Step{kind = .Link_Up}
		// Fine: a route through the tunnel.
		plan.steps[3] = Step {
			kind = .Add_Route,
			on_tun = true,
			route = {dst = sysnet.IP4_Address{10, 1, 0, 0}, dst_len = 16, protocol = ROUTE_PROTOCOL},
		}
		// A gateway nobody can reach, and the step is critical.
		plan.steps[4] = Step {
			kind = .Add_Route,
			critical = true,
			route = {
				dst = sysnet.IP4_Address{10, 2, 0, 0},
				dst_len = 16,
				gateway = sysnet.Address(sysnet.IP4_Address{172, 31, 9, 9}),
				protocol = ROUTE_PROTOCOL,
			},
		}
		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		err := netcfg_apply(&nc, &plan)
		testing.expect(t, err != .None, "the critical step must fail")
		testing.expect_value(t, nc.failed_step, 4)
		testing.expect(t, !netcfg_is_applied(&nc))
		expect_same_snapshot(t, before, snapshot(&lab))

		// The same step, not critical: a warning, and the rest stays.
		plan.steps[4].critical = false
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		testing.expect_value(t, len(nc.warnings), 1)
		if len(nc.warnings) == 1 {
			testing.expect_value(t, nc.warnings[0].step, 4)
		}
		testing.expect_value(t, len(nc.undo), 4)
		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// Things that were there before are not ours to remove.
	@(test)
	client_netns_existing_things_are_left_alone :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		// The address and the link state are set already (a helper did it), and
		// so is one of the routes.
		testing.expect_value(t, sysnet.addr_add(&lab.conn, lab.vpn.index, sysnet.IP4_Address{10, 8, 0, 6}, 24), sysnet.Error.None)
		testing.expect_value(t, sysnet.link_set_up(&lab.conn, lab.vpn.index), sysnet.Error.None)
		preset := sysnet.Route {
			dst      = sysnet.IP4_Address{10, 1, 0, 0},
			dst_len  = 16,
			gateway  = sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1}),
			ifindex  = lab.vpn.index,
			onlink   = true,
			protocol = ROUTE_PROTOCOL,
		}
		testing.expect_value(t, sysnet.route_add(&lab.conn, preset), sysnet.Error.None)
		before := snapshot(&lab)

		push_text := "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,route 10.1.0.0 255.255.0.0,route 10.2.0.0 255.255.0.0"
		plan, ok := lab_plan(t, &lab, "", push_text, LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)
		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		// The old route is reported (a warning), the new one is added.
		testing.expect_value(t, len(nc.warnings), 1)
		if len(nc.warnings) == 1 {
			testing.expect_value(t, nc.warnings[0].err, sysnet.Error.Exists)
		}
		testing.expect_value(t, len(nc.undo), 1) // 10.2.0.0/16 only
		expect_lookup(t, &lab, sysnet.IP4_Address{10, 2, 3, 4}, lab.vpn.index)
		testing.expect_value(t, netcfg_teardown(&nc), 0)

		// Exactly the state from before: address, link, and the old route.
		expect_same_snapshot(t, before, snapshot(&lab))
		expect_lookup(t, &lab, sysnet.IP4_Address{10, 1, 3, 4}, lab.vpn.index)
	}

	// persist-tun: after a reconnect the plan is built again from the saved view
	// of the system. The same plan changes nothing; a different one replaces
	// the first.
	@(test)
	client_netns_update_for_persist_tun :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		base := "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,redirect-gateway def1"
		more := strings.concatenate({base, ",route 10.9.0.0 255.255.0.0"}, context.temp_allocator)
		// The view of the system before the first connection.
		st, gerr := netcfg_gather(&lab.conn, sysnet.Address(LAB_SERVER4), lab.vpn.index)
		testing.expect_value(t, gerr, Gather_Error.None)
		plan1, ok1 := lab_plan_with(t, &lab, st, "", base, LAB_SERVER4)
		if !ok1 {
			return
		}
		defer plan_destroy(&plan1)
		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan1), sysnet.Error.None)
		testing.expect_value(t, netcfg_apply(&nc, &plan1), sysnet.Error.Busy)
		during := snapshot(&lab)

		// A gather now would see the tunnel's routes: the server is covered by
		// the redirect, but the pin sends it through the uplink, so it is
		// still not "via the tunnel". An address the pin does not cover is.
		_, gerr2 := netcfg_gather(&lab.conn, sysnet.Address(sysnet.IP4_Address{9, 9, 9, 9}), lab.vpn.index)
		testing.expect_value(t, gerr2, Gather_Error.Server_Via_Tunnel)

		// Reconnect with the same push.
		again, ok2 := lab_plan_with(t, &lab, st, "", base, LAB_SERVER4)
		if !ok2 {
			return
		}
		defer plan_destroy(&again)
		testing.expect(t, plan_equal(&plan1, &again))
		changed, uerr := netcfg_update(&nc, &again)
		testing.expect_value(t, uerr, sysnet.Error.None)
		testing.expect(t, !changed)
		expect_same_snapshot(t, during, snapshot(&lab))

		// New push with another route: the old routes go, the new ones come.
		plan3, ok3 := lab_plan_with(t, &lab, st, "", more, LAB_SERVER4)
		if !ok3 {
			return
		}
		defer plan_destroy(&plan3)
		changed, uerr = netcfg_update(&nc, &plan3)
		testing.expect_value(t, uerr, sysnet.Error.None)
		testing.expect(t, changed)
		expect_lookup(t, &lab, sysnet.IP4_Address{10, 9, 1, 1}, lab.vpn.index)
		expect_lookup(t, &lab, NET_HOST4, lab.vpn.index)
		expect_lookup(t, &lab, LAB_SERVER4, lab.uplink.index, sysnet.Address(LAB_GW4))

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// The lookup for the server must not see the tunnel's own routes. If a
	// plan is still applied, the result is `Server_Via_Tunnel` for a server
	// that the redirect covers.
	@(test)
	client_netns_gather_sees_leftover_routes :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		st, gerr := netcfg_gather(&lab.conn, sysnet.Address(LAB_SERVER4), lab.vpn.index)
		testing.expect_value(t, gerr, Gather_Error.None)
		testing.expect(t, st.server_route != nil && st.default4 != nil && st.default6 != nil)
		r4, _ := st.default4.?
		testing.expect_value(t, r4.ifindex, lab.uplink.index)
		testing.expect_value(t, r4.metric, Maybe(u32)(100))

		// Apply a redirect without a pin: the plan built by hand.
		plan := Plan {
			steps = make([dynamic]Step, 3),
		}
		defer delete(plan.steps)
		plan.steps[0] = Step{kind = .Add_Addr, addr = sysnet.IP4_Address{10, 8, 0, 6}, prefix_len = 24}
		plan.steps[1] = Step{kind = .Link_Up}
		plan.steps[2] = Step {
			kind = .Add_Route,
			on_tun = true,
			route = {dst = sysnet.IP4_Address{0, 0, 0, 0}, dst_len = 1, gateway = sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1}), onlink = true, protocol = ROUTE_PROTOCOL},
		}
		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		_, gerr = netcfg_gather(&lab.conn, sysnet.Address(sysnet.IP4_Address{9, 9, 9, 9}), lab.vpn.index)
		testing.expect_value(t, gerr, Gather_Error.Server_Via_Tunnel)
		testing.expect_value(t, netcfg_teardown(&nc), 0)
		_, gerr = netcfg_gather(&lab.conn, sysnet.Address(sysnet.IP4_Address{9, 9, 9, 9}), lab.vpn.index)
		testing.expect_value(t, gerr, Gather_Error.None)
	}

	// A server nobody can reach: no route at all. The gather does not fail, and
	// a plan with a redirect says why it cannot go on.
	@(test)
	client_netns_no_route_to_the_server :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		testing.expect_value(t, sysnet.route_del(&lab.conn, lab.def4), sysnet.Error.None)
		st, gerr := netcfg_gather(&lab.conn, sysnet.Address(LAB_SERVER4), lab.vpn.index)
		testing.expect_value(t, gerr, Gather_Error.None)
		testing.expect(t, st.server_route == nil)
		testing.expect(t, st.default4 == nil)
		testing.expect(t, st.default6 != nil)
	}

	// The networks of the host: the uplink and a second interface that is up. Not
	// counted: the tunnel of the client, an interface that is down, the loopback
	// device and the IPv6 link-local addresses.
	@(test)
	client_netns_host_nets :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)

		other, terr := tun.open({name = "noirhost1"})
		testing.expect_value(t, terr, tun.Error.None)
		if terr != .None {
			return
		}
		defer tun.close(&other)
		down, derr := tun.open({name = "noirhost2"})
		testing.expect_value(t, derr, tun.Error.None)
		if derr != .None {
			return
		}
		defer tun.close(&down)
		c := &lab.conn
		oi, _ := sysnet.link_get(c, "noirhost1")
		di, _ := sysnet.link_get(c, "noirhost2")
		testing.expect_value(t, sysnet.link_set_up(c, oi.index), sysnet.Error.None)
		testing.expect_value(t, sysnet.addr_add(c, oi.index, sysnet.IP4_Address{10, 77, 0, 1}, 24), sysnet.Error.None)
		testing.expect_value(t, sysnet.addr_add(c, di.index, sysnet.IP4_Address{10, 78, 0, 1}, 24), sysnet.Error.None)

		before := snapshot(&lab)

		// The tunnel has its own address and is up.
		plan, ok := lab_plan(t, &lab, "", "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1", LAB_SERVER4)
		if !ok {
			return
		}
		defer plan_destroy(&plan)
		nc: Netcfg
		netcfg_init(&nc, c, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)

		nets, err := netcfg_host_nets(c, lab.vpn.index)
		defer host_nets_destroy(nets)
		testing.expect_value(t, err, sysnet.Error.None)
		has :: proc(nets: []Host_Net, n: Host_Net) -> bool {
			for x in nets {
				if x == n {
					return true
				}
			}
			return false
		}
		testing.expect(t, has(nets, net4(192, 0, 2, 0, 24)), "the uplink network")
		testing.expect(t, has(nets, net6({0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0}, 64)), "the IPv6 uplink network")
		testing.expect(t, has(nets, net4(10, 77, 0, 0, 24)), "the second interface")
		testing.expect(t, !has(nets, net4(10, 8, 0, 0, 24)), "the tunnel of this client does not count")
		testing.expect(t, !has(nets, net4(10, 78, 0, 0, 24)), "an interface that is down does not count")
		testing.expect(t, !has(nets, net4(127, 0, 0, 0, 8)), "the loopback device does not count")
		for n in nets {
			testing.expect(t, !(n.v6 && n.addr[0] == 0xfe && n.addr[1] & 0xc0 == 0x80), "no link-local network")
		}
		testing.expect_value(t, len(nets), 3)

		// Without the index of the tunnel it counts as a host network.
		all, aerr := netcfg_host_nets(c, 0)
		defer host_nets_destroy(all)
		testing.expect_value(t, aerr, sysnet.Error.None)
		testing.expect(t, has(all, net4(10, 8, 0, 0, 24)))

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// A plan with the networks of the host: a pushed route inside the network of
	// the uplink is not installed, a wider one is, and the uplink network still
	// goes out of the uplink.
	@(test)
	client_netns_pushed_routes_inside_a_host_network :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		nets, nerr := netcfg_host_nets(&lab.conn, lab.vpn.index)
		defer host_nets_destroy(nets)
		testing.expect_value(t, nerr, sysnet.Error.None)
		st, gerr := netcfg_gather(&lab.conn, LAB_SERVER4, lab.vpn.index)
		testing.expect_value(t, gerr, Gather_Error.None)

		cfg := load_client("remote vpn.example 1194 udp")
		defer config.destroy(&cfg)
		po: push.Pushed_Options
		push_text := "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,route 192.0.2.0 255.255.255.0,route 192.0.2.64 255.255.255.192,route 192.0.0.0 255.255.0.0,route 10.1.0.0 255.255.0.0"
		testing.expect_value(t, push.pushed_options_parse(&po, push_text), push.Error.None)
		defer push.pushed_options_destroy(&po)
		plan, perr := plan_build(
			Plan_Input{cfg = &cfg.client, pushed = &po, server = LAB_SERVER4, server_route = st.server_route, default4 = st.default4, default6 = st.default6, host_nets = nets},
		)
		testing.expect_value(t, perr, Plan_Error.None)
		defer plan_destroy(&plan)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		gw := sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1})
		expect_lookup(t, &lab, sysnet.IP4_Address{192, 0, 2, 99}, lab.uplink.index)
		expect_lookup(t, &lab, sysnet.IP4_Address{192, 0, 2, 70}, lab.uplink.index)
		expect_lookup(t, &lab, sysnet.IP4_Address{192, 0, 77, 1}, lab.vpn.index, gw)
		expect_lookup(t, &lab, sysnet.IP4_Address{10, 1, 2, 3}, lab.vpn.index, gw)
		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}

	// The tunnel network is the network of the uplink. The address has the flag
	// NOPREFIXROUTE, the tunnel has no route for it, and the uplink keeps it.
	@(test)
	client_netns_tunnel_network_is_a_host_network :: proc(t: ^testing.T) {
		lab: Lab
		if !lab_open(t, &lab) {
			return
		}
		defer lab_close(&lab)
		before := snapshot(&lab)

		nets, nerr := netcfg_host_nets(&lab.conn, lab.vpn.index)
		defer host_nets_destroy(nets)
		testing.expect_value(t, nerr, sysnet.Error.None)
		st, gerr := netcfg_gather(&lab.conn, LAB_SERVER4, lab.vpn.index)
		testing.expect_value(t, gerr, Gather_Error.None)

		cfg := load_client("remote vpn.example 1194 udp")
		defer config.destroy(&cfg)
		po: push.Pushed_Options
		push_text := "topology subnet,ifconfig 192.0.2.77 255.255.255.0,route-gateway 192.0.2.1"
		testing.expect_value(t, push.pushed_options_parse(&po, push_text), push.Error.None)
		defer push.pushed_options_destroy(&po)
		plan, perr := plan_build(
			Plan_Input{cfg = &cfg.client, pushed = &po, server = LAB_SERVER4, server_route = st.server_route, default4 = st.default4, default6 = st.default6, host_nets = nets},
		)
		testing.expect_value(t, perr, Plan_Error.None)
		defer plan_destroy(&plan)
		expect_note(t, &plan, .Tunnel_Host_Net)

		nc: Netcfg
		netcfg_init(&nc, &lab.conn, lab.vpn.index)
		defer netcfg_destroy(&nc)
		testing.expect_value(t, netcfg_apply(&nc, &plan), sysnet.Error.None)
		expect_no_warnings(t, &nc)

		addrs := make([dynamic]sysnet.Addr_Info, context.temp_allocator)
		testing.expect_value(t, sysnet.addr_list(&lab.conn, lab.vpn.index, .V4, &addrs), sysnet.Error.None)
		testing.expect_value(t, len(addrs), 1)
		if len(addrs) == 1 {
			testing.expect(t, addrs[0].flags & 0x200 != 0, "IFA_F_NOPREFIXROUTE is set")
		}
		// The address of the tunnel and the others of the network are reached through the uplink.
		expect_lookup(t, &lab, sysnet.IP4_Address{192, 0, 2, 5}, lab.uplink.index)
		routes := make([dynamic]sysnet.Route, context.temp_allocator)
		testing.expect_value(t, sysnet.route_list(&lab.conn, .V4, 0, lab.vpn.index, &routes), sysnet.Error.None)
		testing.expect_value(t, len(routes), 0)

		testing.expect_value(t, netcfg_teardown(&nc), 0)
		expect_same_snapshot(t, before, snapshot(&lab))
	}
}

// How many routes with our protocol number there are, in both families.
snapshot_count_mine :: proc(lab: ^Lab) -> int {
	n := 0
	for fam in ([]sysnet.Family{.V4, .V6}) {
		routes := make([dynamic]sysnet.Route, context.temp_allocator)
		if sysnet.route_list_protocol(&lab.conn, fam, ROUTE_PROTOCOL, &routes) == .None {
			n += len(routes)
		}
	}
	return n
}

// The route lines of `snapshot` only.
snapshot_routes :: proc(lab: ^Lab) -> []string {
	all := snapshot(lab)
	keep := make([dynamic]string, context.temp_allocator)
	for l in all {
		if strings.has_prefix(l, "main ") || strings.has_prefix(l, "mine ") {
			append(&keep, l)
		}
	}
	return keep[:]
}

link_exists :: proc(lab: ^Lab, index: u32) -> bool {
	_, err := sysnet.link_get_by_index(&lab.conn, index)
	return err == .None
}

// A state folder for the records in a new temporary folder, and DNS paths in
// it that touch no file of the host (no resolver program is found).
netns_state_dir :: proc(t: ^testing.T, tag: string) -> (base, dir: string, env: sysnet.DNS_Env, ok: bool) {
	tmp, _ := os.temp_directory(context.temp_allocator)
	b, err := os.make_directory_temp(tmp, fmt.tprintf("noir-netns-%s-*", tag), context.temp_allocator)
	if err != nil {
		testing.expectf(t, false, "cannot create a temporary folder: %v", err)
		return
	}
	linux.chmod(strings.clone_to_cstring(b, context.temp_allocator), transmute(linux.Mode)u32(0o700))
	env = sysnet.DNS_Env {
		resolved_dir = strings.concatenate({b, "/no-resolved"}, context.temp_allocator),
		resolv_conf  = strings.concatenate({b, "/resolv.conf"}, context.temp_allocator),
		backup       = strings.concatenate({b, "/resolv.conf.noirvpn-backup"}, context.temp_allocator),
		force        = .Resolv_Conf,
	}
	return b, strings.concatenate({b, "/state"}, context.temp_allocator), env, true
}

// Writes the record of `f` even when its text is the same as the last write.
record_write_now :: proc(f: ^Record_File) -> Record_Error {
	delete(f.last, f.allocator)
	f.last = ""
	return record_write(f)
}
