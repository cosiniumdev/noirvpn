// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:strings"
import "core:testing"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/push"

net4 :: proc(a, b, c, d: u8, bits: u8) -> Host_Net {
	n := Host_Net {
		addr = {a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		bits = bits,
	}
	n.addr = mask6(n.addr, int(bits))
	return n
}

net6 :: proc(a: [8]u16be, bits: u8) -> Host_Net {
	return Host_Net{v6 = true, addr = mask6(transmute([16]u8)a, int(bits)), bits = bits}
}

// A plan for a user profile: `nets` are the networks of the host.
build_user_plan :: proc(
	t: ^testing.T,
	conf, push_text: string,
	nets: []Host_Net,
	loc := #caller_location,
) -> (
	plan: Plan,
	err: Plan_Error,
) {
	cfg := load_client("remote vpn.example 1194 udp", conf)
	defer config.destroy(&cfg)
	if !expect_config_ok(t, &cfg, loc) {
		return {}, .No_Address
	}
	po: push.Pushed_Options
	perr := push.pushed_options_parse(&po, push_text)
	testing.expect_value(t, perr, push.Error.None, loc = loc)
	defer push.pushed_options_destroy(&po)
	input := default_input(&cfg.client, &po)
	input.host_nets = nets
	return plan_build(input)
}

LAN4 :: "192.168.77.0"

@(test)
plan_host_net_pushed_route_equal_inside_wider_unrelated :: proc(t: ^testing.T) {
	nets := []Host_Net{net4(192, 168, 77, 0, 24)}
	push_text := BASE + ",route 192.168.77.0 255.255.255.0,route 192.168.77.16 255.255.255.240,route 192.168.0.0 255.255.0.0,route 172.16.0.0 255.255.0.0"
	plan, err := build_user_plan(t, "", push_text, nets)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up", "route 192.168.0.0/16 via 10.8.0.1 dev tun", "route 172.16.0.0/16 via 10.8.0.1 dev tun"})
	dropped := 0
	for n in plan.notes {
		if n.kind == .Dropped_Host_Net {
			dropped += 1
			testing.expect(t, strings.contains(n.text, "192.168.77.0/24"), n.text)
		}
	}
	testing.expect_value(t, dropped, 2)
	testing.expect(t, notes_contain(&plan, "pushed route 192.168.77.0/24 was dropped because it is the same as the host network 192.168.77.0/24"))
	testing.expect(t, notes_contain(&plan, "pushed route 192.168.77.16/28 was dropped because it is inside the host network 192.168.77.0/24"))
}

notes_contain :: proc(plan: ^Plan, text: string) -> bool {
	for n in plan.notes {
		if strings.contains(n.text, text) {
			return true
		}
	}
	return false
}

@(test)
plan_host_net_pushed_route_ipv6 :: proc(t: ^testing.T) {
	nets := []Host_Net{net6({0xfd00, 0x77, 0, 0, 0, 0, 0, 0}, 64)}
	push_text := BASE_DUAL + ",route-ipv6 fd00:77::/64,route-ipv6 fd00:77:0:0:8000::/66,route-ipv6 fd00::/16,route-ipv6 fd00:99::/64"
	plan, err := build_user_plan(t, "", push_text, nets)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"addr fd00:8::6/64",
			"link up",
			"route fd00::/16 via fd00:8::1 dev tun",
			"route fd00:99::/64 via fd00:8::1 dev tun",
		},
	)
	testing.expect(t, notes_contain(&plan, "pushed route fd00:77::/64 was dropped because it is the same as the host network fd00:77::/64"))
	testing.expect(t, notes_contain(&plan, "pushed route fd00:77:0:0:8000::/66 was dropped because it is inside the host network fd00:77::/64"))
}

@(test)
plan_host_net_family_is_not_mixed :: proc(t: ^testing.T) {
	// An IPv6 host network never matches an IPv4 route, and the other way round.
	nets := []Host_Net{net6({0x0a00, 0, 0, 0, 0, 0, 0, 0}, 16), net4(10, 1, 0, 0, 16)}
	plan, err := build_user_plan(t, "", BASE_DUAL + ",route 10.0.0.0 255.0.0.0,route-ipv6 a01::/32", nets)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	testing.expect_value(t, len(plan.steps), 5)
	testing.expect(t, !has_note(&plan, .Dropped_Host_Net))
}

@(test)
plan_host_net_local_route_line_is_kept :: proc(t: ^testing.T) {
	nets := []Host_Net{net4(192, 168, 77, 0, 24)}
	conf := "route 192.168.77.0 255.255.255.0\nroute 192.168.77.32 255.255.255.224\nroute-ipv6 fd00:77::/64"
	plan, err := build_user_plan(t, conf, BASE_DUAL + ",route 192.168.77.0 255.255.255.0", nets)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	// The two local lines and the local IPv6 line are in the plan. The pushed
	// route of the same network is dropped.
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"addr fd00:8::6/64",
			"link up",
			"route 192.168.77.0/24 via 10.8.0.1 dev tun",
			"route 192.168.77.32/27 via 10.8.0.1 dev tun",
			"route fd00:77::/64 via fd00:8::1 dev tun",
		},
	)
	testing.expect(t, has_note(&plan, .Dropped_Host_Net))
}

@(test)
plan_host_net_none_is_the_plan_of_a_config_file :: proc(t: ^testing.T) {
	pushes := []string {
		BASE,
		BASE + ",route 192.168.77.0 255.255.255.0,route 10.8.0.0 255.255.255.0,route 10.9.0.0 255.255.0.0",
		BASE_DUAL + ",route-ipv6 fd00:77::/64,redirect-gateway def1 ipv6,dhcp-option DNS 10.8.0.1",
	}
	for text in pushes {
		a, aerr := build_plan(t, "route 192.168.77.0 255.255.255.0", text)
		b, berr := build_user_plan(t, "route 192.168.77.0 255.255.255.0", text, nil)
		c, cerr := build_user_plan(t, "route 192.168.77.0 255.255.255.0", text, []Host_Net{})
		testing.expect_value(t, aerr, berr)
		testing.expect_value(t, aerr, cerr)
		testing.expect(t, plan_equal(&a, &b))
		testing.expect(t, plan_equal(&a, &c))
		testing.expect_value(t, len(a.notes), len(b.notes))
		for n, i in a.notes {
			testing.expect_value(t, b.notes[i].text, n.text)
		}
		for s in a.steps {
			testing.expect(t, !s.no_prefix_route)
		}
		plan_destroy(&a)
		plan_destroy(&b)
		plan_destroy(&c)
	}
}

@(test)
plan_host_net_tunnel_network_equal_or_inside :: proc(t: ^testing.T) {
	// The tunnel network is 10.8.0.0/24.
	Case :: struct {
		host: Host_Net,
		word: string,
	}
	cases := [?]Case {
		{net4(10, 8, 0, 0, 24), "is the same as"},
		{net4(10, 0, 0, 0, 8), "is inside"},
	}
	for c in cases {
		plan, err := build_user_plan(t, "", BASE, []Host_Net{c.host})
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24 noprefixroute", "link up"})
		testing.expect(t, plan.steps[0].no_prefix_route)
		expect_note(t, &plan, .Tunnel_Host_Net)
		testing.expect(t, notes_contain(&plan, c.word), plan.notes[0].text)
		testing.expect(t, notes_contain(&plan, "the tunnel network 10.8.0.0/24"))
		plan_destroy(&plan)
	}
	// A host network next to it does not count. A host network inside the
	// tunnel network does not count either: the tunnel network is wider, keeps its
	// prefix route, and the longest prefix keeps the host network local.
	others := [?]Host_Net{net4(10, 9, 0, 0, 24), net4(10, 8, 0, 16, 28)}
	for h in others {
		plan, err := build_user_plan(t, "", BASE, []Host_Net{h})
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
		testing.expect(t, !plan.steps[0].no_prefix_route)
		testing.expect(t, !has_note(&plan, .Tunnel_Host_Net))
		testing.expect_value(t, len(plan.notes), 0)
		plan_destroy(&plan)
	}
}

@(test)
plan_host_net_tunnel_network_ipv6 :: proc(t: ^testing.T) {
	plan, err := build_user_plan(t, "", BASE6, []Host_Net{net6({0xfd00, 8, 0, 0, 0, 0, 0, 0}, 64)})
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr fd00:8::6/64 noprefixroute", "link up"})
	expect_note(t, &plan, .Tunnel_Host_Net)
}

@(test)
plan_host_net_pushed_route_of_the_tunnel_network :: proc(t: ^testing.T) {
	push_text := BASE + ",route 10.8.0.0 255.255.255.0"

	// Tunnel network equal to a host network, or inside one: the kernel created no
	// route for it, and the pushed route of that network is dropped as a host
	// network route.
	hosts := [?]Host_Net{net4(10, 8, 0, 0, 24), net4(10, 0, 0, 0, 8)}
	for h in hosts {
		plan, err := build_user_plan(t, "", push_text, []Host_Net{h})
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24 noprefixroute", "link up"})
		testing.expect(t, has_note(&plan, .Dropped_Host_Net))
		testing.expect(t, !has_note(&plan, .Skipped_Connected))
		plan_destroy(&plan)
	}

	// Tunnel network wider than a host network: the address has its prefix
	// route, and the pushed route is wider than the host network, so it is not
	// dropped. The route exists already (connected).
	plan2, err2 := build_user_plan(t, "", push_text, []Host_Net{net4(10, 8, 0, 16, 28)})
	defer plan_destroy(&plan2)
	testing.expect_value(t, err2, Plan_Error.None)
	expect_steps(t, &plan2, {"addr 10.8.0.6/24", "link up"})
	testing.expect(t, !has_note(&plan2, .Dropped_Host_Net))
	testing.expect(t, !has_note(&plan2, .Tunnel_Host_Net))
	expect_note(t, &plan2, .Skipped_Connected)

	// With no overlap the route of the tunnel network is skipped, as for a config file.
	plan3, err3 := build_user_plan(t, "", push_text, []Host_Net{net4(192, 168, 1, 0, 24)})
	defer plan_destroy(&plan3)
	testing.expect_value(t, err3, Plan_Error.None)
	expect_steps(t, &plan3, {"addr 10.8.0.6/24", "link up"})
	expect_note(t, &plan3, .Skipped_Connected)
}

@(test)
plan_host_net_pushed_route_of_the_tunnel_network_is_kept_as_before :: proc(t: ^testing.T) {
	// The tunnel device is not a host network: a pushed route of the tunnel
	// network is handled as for a config file.
	plan, err := build_user_plan(t, "", BASE + ",route 10.8.0.0 255.255.255.0", []Host_Net{net4(192, 168, 1, 0, 24)})
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_note(t, &plan, .Skipped_Connected)
	testing.expect(t, !has_note(&plan, .Dropped_Host_Net))
}

@(test)
plan_host_net_step_with_no_prefix_route_is_not_equal :: proc(t: ^testing.T) {
	a := Step {
		kind       = .Add_Addr,
		addr       = sysnet.IP4_Address{10, 8, 0, 6},
		prefix_len = 24,
	}
	b := a
	b.no_prefix_route = true
	testing.expect(t, a != b)
}

// ---- reading the host networks ----

link_of :: proc(index: u32, flags: sysnet.Link_Flags) -> sysnet.Link_Info {
	return sysnet.Link_Info{index = index, flags = flags}
}

addr4_of :: proc(index: u32, a, b, c, d, bits: u8) -> sysnet.Addr_Info {
	return sysnet.Addr_Info{index = index, address = sysnet.IP4_Address{a, b, c, d}, prefix_len = bits}
}

@(test)
host_nets_of_selects_the_connected_networks :: proc(t: ^testing.T) {
	links := []sysnet.Link_Info {
		link_of(1, {.Up, .Loopback}),
		link_of(2, {.Up}),
		link_of(3, {}), // down
		link_of(4, {.Up}), // the tunnel of this client
		link_of(5, {.Up}),
	}
	ll := sysnet.Addr_Info {
		index      = 2,
		address    = sysnet.IP6_Address{0xfe80, 0, 0, 0, 0xaaaa, 0, 0, 1},
		prefix_len = 64,
	}
	global := sysnet.Addr_Info {
		index      = 2,
		address    = sysnet.IP6_Address{0xfd00, 0x77, 0, 0, 0, 0, 0, 5},
		prefix_len = 64,
	}
	nopref := addr4_of(5, 172, 16, 0, 9, 16)
	nopref.flags = 0x200
	hostscope := addr4_of(5, 127, 0, 0, 2, 8)
	hostscope.scope = 254
	addrs := []sysnet.Addr_Info {
		addr4_of(1, 127, 0, 0, 1, 8),
		addr4_of(2, 192, 168, 77, 5, 24),
		addr4_of(2, 192, 168, 77, 6, 24), // same network again
		ll,
		global,
		addr4_of(3, 10, 3, 0, 1, 24),
		addr4_of(4, 10, 8, 0, 6, 24),
		addr4_of(5, 10, 5, 0, 1, 16),
		nopref,
		hostscope,
		addr4_of(5, 10, 6, 0, 1, 0), // no prefix
	}
	nets := host_nets_of(links, addrs, 4)
	defer host_nets_destroy(nets)
	want := []Host_Net{net4(192, 168, 77, 0, 24), net6({0xfd00, 0x77, 0, 0, 0, 0, 0, 0}, 64), net4(10, 5, 0, 0, 16)}
	testing.expect_value(t, len(nets), len(want))
	for w, i in want {
		if i < len(nets) {
			testing.expect_value(t, nets[i], w)
		}
	}
}

@(test)
host_nets_of_a_point_to_point_address_uses_the_peer :: proc(t: ^testing.T) {
	links := []sysnet.Link_Info{link_of(2, {.Up, .Point_To_Point})}
	a := addr4_of(2, 10, 64, 0, 2, 32)
	a.peer = sysnet.Address(sysnet.IP4_Address{10, 64, 0, 1})
	nets := host_nets_of(links, []sysnet.Addr_Info{a}, 0)
	defer host_nets_destroy(nets)
	testing.expect_value(t, len(nets), 1)
	testing.expect_value(t, nets[0], net4(10, 64, 0, 1, 32))
}

@(test)
host_nets_of_nothing :: proc(t: ^testing.T) {
	nets := host_nets_of(nil, nil, 0)
	defer host_nets_destroy(nets)
	testing.expect_value(t, len(nets), 0)
}
