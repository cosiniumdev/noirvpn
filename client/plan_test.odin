// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:fmt"
import "core:strings"
import "core:testing"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/push"

// ---- the lab: a laptop on a LAN, and a VPN server on the internet ----

UPLINK :: u32(2)
GW4 :: sysnet.IP4_Address{192, 168, 1, 1}
SERVER4 :: sysnet.IP4_Address{203, 0, 113, 7}
GW6 :: sysnet.IP6_Address{0xfe80, 0, 0, 0, 0, 0, 0, 1}
SERVER6 :: sysnet.IP6_Address{0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 7}

// A reply from a typical server: subnet topology and the gateway.
BASE :: "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1"
// The same with an IPv6 address on the tunnel.
BASE6 :: "topology subnet,ifconfig-ipv6 fd00:8::6/64 fd00:8::1"
BASE_DUAL :: "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,ifconfig-ipv6 fd00:8::6/64 fd00:8::1"

Tweak :: proc(input: ^Plan_Input)

// What the system looks like before the VPN: an IPv4 default route with
// metric 100 and an IPv6 one with 1024, both on interface 2, and a server
// reached through the IPv4 gateway.
default_input :: proc(cfg: ^config.Client_Config, po: ^push.Pushed_Options) -> Plan_Input {
	return Plan_Input {
		cfg = cfg,
		pushed = po,
		server = sysnet.Address(SERVER4),
		server_route = sysnet.Route {
			dst = SERVER4,
			dst_len = 32,
			gateway = sysnet.Address(GW4),
			ifindex = UPLINK,
			family = .V4,
			kind = .Unicast,
		},
		default4 = sysnet.Route {
			dst = sysnet.IP4_Address{},
			dst_len = 0,
			gateway = sysnet.Address(GW4),
			ifindex = UPLINK,
			metric = u32(100),
			family = .V4,
		},
		default6 = sysnet.Route {
			dst = sysnet.IP6_Address{},
			dst_len = 0,
			gateway = sysnet.Address(GW6),
			ifindex = UPLINK,
			metric = u32(1024),
			family = .V6,
		},
	}
}

// The route to `server` through gateway `gw` on `ifindex`; `gw` nil = on-link.
route_to :: proc(server: sysnet.Address, gw: Maybe(sysnet.Address), ifindex: u32) -> sysnet.Route {
	_, is6 := server.(sysnet.IP6_Address)
	return sysnet.Route {
		dst = server,
		dst_len = 128 if is6 else 32,
		gateway = gw,
		ifindex = ifindex,
		family = .V6 if is6 else .V4,
		kind = .Unicast,
	}
}

// A route to the server of a kind that cannot carry traffic.
kinded_route :: proc(kind: sysnet.Route_Kind) -> sysnet.Route {
	r := route_to(sysnet.Address(SERVER4), nil, UPLINK)
	r.kind = kind
	return r
}

// Build a plan from config lines and a PUSH_REPLY option list.
build_plan :: proc(t: ^testing.T, conf, push_text: string, tweak: Tweak = nil, loc := #caller_location) -> (plan: Plan, err: Plan_Error) {
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
	if tweak != nil {
		tweak(&input)
	}
	return plan_build(input)
}

// The steps as text, in order.
step_lines :: proc(plan: ^Plan) -> []string {
	out := make([]string, len(plan.steps), context.temp_allocator)
	for s, i in plan.steps {
		out[i] = step_string(s, context.temp_allocator)
	}
	return out
}

expect_steps :: proc(t: ^testing.T, plan: ^Plan, want: []string, loc := #caller_location) {
	got := step_lines(plan)
	same := len(got) == len(want)
	if same {
		for w, i in want {
			if got[i] != w {
				same = false
			}
		}
	}
	if !same {
		testing.expectf(
			t,
			false,
			"steps differ\n  got:\n    %s\n  want:\n    %s",
			strings.join(got, "\n    ", context.temp_allocator),
			strings.join(want, "\n    ", context.temp_allocator),
			loc = loc,
		)
	}
}

has_note :: proc(plan: ^Plan, kind: Note_Kind) -> bool {
	for n in plan.notes {
		if n.kind == kind {
			return true
		}
	}
	return false
}

expect_note :: proc(t: ^testing.T, plan: ^Plan, kind: Note_Kind, loc := #caller_location) {
	if !has_note(plan, kind) {
		texts := make([dynamic]string, context.temp_allocator)
		for n in plan.notes {
			append(&texts, fmt.tprintf("%v: %s", n.kind, n.text))
		}
		testing.expectf(t, false, "no note of kind %v; notes:\n  %s", kind, strings.join(texts[:], "\n  ", context.temp_allocator), loc = loc)
	}
}

// ---- addresses and the link ----

@(test)
plan_v4_only_no_routes :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
	testing.expect_value(t, plan.addr4, Maybe(sysnet.IP4_Address)(sysnet.IP4_Address{10, 8, 0, 6}))
	testing.expect_value(t, plan.prefix4, u8(24))
	testing.expect(t, plan.addr6 == nil)
	testing.expect(t, !plan.redirect4 && !plan.redirect6)
	testing.expect(t, plan.pinned == nil)
	testing.expect(t, !plan.has_dns)
}

@(test)
plan_mtu_from_the_push_or_the_config :: proc(t: ^testing.T) {
	{
		plan, err := build_plan(t, "", BASE + ",tun-mtu 1400")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"mtu 1400", "addr 10.8.0.6/24", "link up"})
		testing.expect_value(t, plan.mtu, u32(1400))
	}
	{
		// The local value is used when nothing is pushed.
		plan, err := build_plan(t, "", BASE, proc(input: ^Plan_Input) {input.local_mtu = 1380})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"mtu 1380", "addr 10.8.0.6/24", "link up"})
	}
	{
		// The pushed value wins.
		plan, err := build_plan(t, "", BASE + ",tun-mtu 1400", proc(input: ^Plan_Input) {input.local_mtu = 1380})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"mtu 1400", "addr 10.8.0.6/24", "link up"})
	}
	{
		// Out of range: clamped or dropped, with a note.
		plan, err := build_plan(t, "", BASE + ",tun-mtu 65536")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"mtu 65535", "addr 10.8.0.6/24", "link up"})
		expect_note(t, &plan, .Adjusted)
	}
	{
		plan, err := build_plan(t, "", BASE, proc(input: ^Plan_Input) {input.local_mtu = 40})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
		expect_note(t, &plan, .Adjusted)
	}
}

@(test)
plan_ipv6_only_and_dual_stack_addresses :: proc(t: ^testing.T) {
	{
		plan, err := build_plan(t, "", BASE6, proc(input: ^Plan_Input) {input.server = nil})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr fd00:8::6/64", "link up"})
		testing.expect(t, plan.addr4 == nil)
		testing.expect_value(t, plan.prefix6, u8(64))
	}
	{
		plan, err := build_plan(t, "", BASE_DUAL)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "addr fd00:8::6/64", "link up"})
	}
}

@(test)
plan_refuses_what_it_cannot_do :: proc(t: ^testing.T) {
	cases := []struct {
		name: string,
		push: string,
		want: Plan_Error,
	} {
		{"net30", "topology net30,ifconfig 10.8.0.6 10.8.0.5", .Unsupported_Topology},
		{"p2p", "topology p2p,ifconfig 10.8.0.6 10.8.0.5", .Unsupported_Topology},
		{"no topology", "ifconfig 10.8.0.6 255.255.255.0", .Missing_Topology},
		{"no address", "topology subnet,route 10.1.0.0 255.255.0.0", .No_Address},
		{"nothing", "", .No_Address},
	}
	for c in cases {
		plan, err := build_plan(t, "", c.push)
		testing.expectf(t, err == c.want, "%s: got %v, want %v", c.name, err, c.want)
		testing.expectf(t, len(plan.steps) == 0, "%s: no plan on error", c.name)
		plan_destroy(&plan)
	}
}

@(test)
plan_local_ifconfig_is_not_used :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "ifconfig 10.9.9.2 255.255.255.0", "topology subnet")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.No_Address)
	plan2, err2 := build_plan(t, "ifconfig 10.9.9.2 255.255.255.0", BASE)
	defer plan_destroy(&plan2)
	testing.expect_value(t, err2, Plan_Error.None)
	expect_steps(t, &plan2, {"addr 10.8.0.6/24", "link up"})
	expect_note(t, &plan2, .Info)
}

// ---- ordinary routes ----

@(test)
plan_pushed_routes :: proc(t: ^testing.T) {
	push_text := BASE + ",route 10.1.0.0 255.255.0.0,route 192.168.50.0 255.255.255.0 vpn_gateway 5,route 172.16.0.0 255.240.0.0 net_gateway"
	plan, err := build_plan(t, "", push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"link up",
			"route 10.1.0.0/16 via 10.8.0.1 dev tun",
			"route 192.168.50.0/24 via 10.8.0.1 dev tun metric 5",
			"route 172.16.0.0/12 via 192.168.1.1 dev #2",
		},
	)
	// Nothing covers the server, so there is no pin.
	testing.expect(t, plan.pinned == nil)
	// The gateway routes go through the tunnel on-link: the tun has no neighbours.
	r := plan.steps[2].route
	testing.expect(t, r.onlink)
	testing.expect_value(t, r.protocol, u8(ROUTE_PROTOCOL))
	testing.expect_value(t, plan.steps[2].why, Why.Pushed_Route)
	testing.expect(t, !plan.steps[2].critical)
	// A route through the old gateway is not on-link and has an interface.
	testing.expect(t, !plan.steps[4].route.onlink)
	testing.expect(t, !plan.steps[4].on_tun)
	testing.expect_value(t, plan.steps[4].route.ifindex, UPLINK)
}

@(test)
plan_without_a_pushed_gateway_uses_device_routes :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route 10.1.0.0 255.255.0.0")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up", "route 10.1.0.0/16 dev tun"})
	testing.expect(t, !plan.steps[2].route.onlink)
}

@(test)
plan_ipv6_routes :: proc(t: ^testing.T) {
	push_text := BASE_DUAL + ",route-ipv6 2001:db8:a::/48,route-ipv6 2001:db8:b::/48 vpn_gateway 20,route-ipv6 2001:db8:c::/48 net_gateway,route-ipv6 fd00:99::/64 fd00:8::77"
	plan, err := build_plan(t, "", push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"addr fd00:8::6/64",
			"link up",
			"route 2001:db8:a::/48 via fd00:8::1 dev tun",
			"route 2001:db8:b::/48 via fd00:8::1 dev tun metric 20",
			"route 2001:db8:c::/48 via fe80::1 dev #2",
			"route fd00:99::/64 via fd00:8::77 dev tun",
		},
	)
}

@(test)
plan_route_covering_the_server_pins_it :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE + ",route 203.0.113.0 255.255.255.0")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{"addr 10.8.0.6/24", "link up", "route 203.0.113.7/32 via 192.168.1.1 dev #2", "route 203.0.113.0/24 via 10.8.0.1 dev tun"},
	)
	testing.expect_value(t, plan.pinned, Maybe(sysnet.Address)(sysnet.Address(SERVER4)))
	testing.expect_value(t, plan.steps[2].why, Why.Server_Pin)
	testing.expect(t, plan.steps[2].critical)
	testing.expect_value(t, plan.steps[2].route.protocol, u8(ROUTE_PROTOCOL))
}

@(test)
plan_route_to_the_server_host_is_dropped :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE + ",route 203.0.113.7")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
	expect_note(t, &plan, .Skipped_Server_Host)
	testing.expect(t, plan.pinned == nil, "no tunnel route covers the server, so no pin")
}

@(test)
plan_server_inside_a_pushed_net_with_a_default_route :: proc(t: ^testing.T) {
	// `route 0.0.0.0 0.0.0.0` is a redirect in disguise: the server is covered.
	plan, err := build_plan(t, "", BASE + ",route 0.0.0.0 0.0.0.0")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up", "route 203.0.113.7/32 via 192.168.1.1 dev #2", "route default via 10.8.0.1 dev tun"})
	testing.expect(t, plan.steps[3].critical)
}

@(test)
plan_server_route_variants :: proc(t: ^testing.T) {
	push_text := BASE + ",redirect-gateway def1"
	// Reached through another gateway on another interface (a more specific
	// route than the default).
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {
			input.server_route = route_to(SERVER4, sysnet.Address(sysnet.IP4_Address{10, 99, 0, 254}), 7)
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, step_lines(&plan)[2], "route 203.0.113.7/32 via 10.99.0.254 dev #7")
	}
	// On-link: the pin is a device route.
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {
			input.server_route = route_to(SERVER4, nil, UPLINK)
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, step_lines(&plan)[2], "route 203.0.113.7/32 dev #2")
		testing.expect(t, plan.steps[2].route.gateway == nil)
	}
	// The server is this machine: nothing to pin.
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {
			r := route_to(SERVER4, nil, 1)
			r.kind = .Local
			input.server_route = r
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, plan.pinned == nil)
		testing.expect_value(t, len(plan.steps), 4) // addr, up, two halves
	}
}

@(test)
plan_pin_needs_a_route_to_the_server :: proc(t: ^testing.T) {
	push_text := BASE + ",redirect-gateway def1"
	// No result from the kernel.
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {input.server_route = nil})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.No_Server_Route)
	}
	// An unreachable or blocked route.
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {input.server_route = kinded_route(.Blackhole)})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.No_Server_Route)
	}
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {input.server_route = kinded_route(.Unreachable)})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.No_Server_Route)
	}
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {input.server_route = kinded_route(.Prohibit)})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.No_Server_Route)
	}
	// The route is for the wrong family.
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {
			input.server_route = route_to(sysnet.Address(SERVER6), sysnet.Address(GW6), UPLINK)
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.No_Server_Route)
	}
	// Without a redirect or a covering route the lookup is not needed.
	{
		plan, err := build_plan(t, "", BASE + ",route 10.1.0.0 255.255.0.0", proc(input: ^Plan_Input) {input.server_route = nil})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
	}
	// Server unknown: nothing is pinned, and nothing fails.
	{
		plan, err := build_plan(t, "", push_text, proc(input: ^Plan_Input) {
			input.server = nil
			input.server_route = nil
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, plan.pinned == nil)
	}
}

// ---- redirect-gateway ----

@(test)
plan_redirect_def1 :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE + ",redirect-gateway def1")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"link up",
			"route 203.0.113.7/32 via 192.168.1.1 dev #2",
			"route 0.0.0.0/1 via 10.8.0.1 dev tun",
			"route 128.0.0.0/1 via 10.8.0.1 dev tun",
		},
	)
	testing.expect(t, plan.redirect4 && !plan.redirect6)
	testing.expect_value(t, plan.steps[3].why, Why.Redirect_Low)
	testing.expect_value(t, plan.steps[4].why, Why.Redirect_High)
	testing.expect(t, plan.steps[3].critical && plan.steps[4].critical)
}

@(test)
plan_redirect_without_def1_replaces_the_default_route :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE + ",redirect-gateway")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	// One metric below the old default route (100). The old route is not touched.
	expect_steps(
		t,
		&plan,
		{"addr 10.8.0.6/24", "link up", "route 203.0.113.7/32 via 192.168.1.1 dev #2", "route default via 10.8.0.1 dev tun metric 99"},
	)
	testing.expect_value(t, plan.steps[3].why, Why.Redirect_Default)
}

@(test)
plan_redirect_without_def1_cases :: proc(t: ^testing.T) {
	// Metric 0 cannot be beaten: two half routes instead.
	{
		plan, err := build_plan(t, "", BASE + ",redirect-gateway", proc(input: ^Plan_Input) {
			r, _ := input.default4.?
			r.metric = nil
			input.default4 = r
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(
			t,
			&plan,
			{
				"addr 10.8.0.6/24",
				"link up",
				"route 203.0.113.7/32 via 192.168.1.1 dev #2",
				"route 0.0.0.0/1 via 10.8.0.1 dev tun",
				"route 128.0.0.0/1 via 10.8.0.1 dev tun",
			},
		)
		expect_note(t, &plan, .Redirect_Used_Def1)
	}
	// No default route at all: add one, with the route-metric if there is one.
	{
		plan, err := build_plan(t, "", BASE + ",redirect-gateway,route-metric 30", proc(input: ^Plan_Input) {input.default4 = nil})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, step_lines(&plan)[3], "route default via 10.8.0.1 dev tun metric 30")
	}
	// Metric 1 gives 0.
	{
		plan, err := build_plan(t, "", BASE + ",redirect-gateway", proc(input: ^Plan_Input) {
			r, _ := input.default4.?
			r.metric = u32(1)
			input.default4 = r
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, step_lines(&plan)[3], "route default via 10.8.0.1 dev tun metric 0")
	}
}

@(test)
plan_redirect_with_ipv6 :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE_DUAL + ",redirect-gateway def1 ipv6")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"addr fd00:8::6/64",
			"link up",
			"route 203.0.113.7/32 via 192.168.1.1 dev #2",
			"route 0.0.0.0/1 via 10.8.0.1 dev tun",
			"route 128.0.0.0/1 via 10.8.0.1 dev tun",
			"route ::/1 via fd00:8::1 dev tun",
			"route 8000::/1 via fd00:8::1 dev tun",
		},
	)
	testing.expect(t, plan.redirect4 && plan.redirect6)
}

@(test)
plan_redirect_ipv6_without_def1 :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE_DUAL + ",redirect-gateway ipv6")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	lines := step_lines(&plan)
	testing.expect_value(t, lines[len(lines) - 2], "route default via 10.8.0.1 dev tun metric 99")
	testing.expect_value(t, lines[len(lines) - 1], "route default6 via fd00:8::1 dev tun metric 1023")
}

@(test)
plan_redirect_ipv6_only_with_an_ipv6_server :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE6 + ",redirect-gateway def1 ipv6 !ipv4", proc(input: ^Plan_Input) {
		input.server = sysnet.Address(SERVER6)
		input.server_route = route_to(sysnet.Address(SERVER6), sysnet.Address(GW6), UPLINK)
	})
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr fd00:8::6/64",
			"link up",
			"route 2001:db8:100::7/128 via fe80::1 dev #2",
			"route ::/1 via fd00:8::1 dev tun",
			"route 8000::/1 via fd00:8::1 dev tun",
		},
	)
	testing.expect(t, !plan.redirect4 && plan.redirect6)
}

@(test)
plan_ipv4_redirect_with_an_ipv6_server_needs_no_pin :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE + ",redirect-gateway def1", proc(input: ^Plan_Input) {
		input.server = sysnet.Address(SERVER6)
		input.server_route = route_to(sysnet.Address(SERVER6), sysnet.Address(GW6), UPLINK)
	})
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up", "route 0.0.0.0/1 via 10.8.0.1 dev tun", "route 128.0.0.0/1 via 10.8.0.1 dev tun"})
	testing.expect(t, plan.pinned == nil)
}

@(test)
plan_ipv6_server_and_dual_redirect_pins_only_the_server_family :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE_DUAL + ",redirect-gateway def1 ipv6", proc(input: ^Plan_Input) {
		input.server = sysnet.Address(SERVER6)
		input.server_route = route_to(sysnet.Address(SERVER6), sysnet.Address(GW6), UPLINK)
	})
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	lines := step_lines(&plan)
	pins := 0
	for l in lines {
		if strings.contains(l, "/128 via fe80::1 dev #2") {
			pins += 1
		}
		testing.expect(t, !strings.contains(l, "203.0.113.7"))
	}
	testing.expect_value(t, pins, 1)
}

@(test)
plan_redirect_local_flags :: proc(t: ^testing.T) {
	// `local`: the server is on the LAN: no pin.
	{
		plan, err := build_plan(t, "", BASE + ",redirect-gateway local def1")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, len(plan.steps), 4)
		testing.expect(t, plan.pinned == nil)
	}
	// `autolocal`: no pin if the server is on-link, a pin if it is not.
	{
		plan, err := build_plan(t, "", BASE + ",redirect-gateway autolocal def1", proc(input: ^Plan_Input) {
			input.server_route = route_to(SERVER4, nil, UPLINK)
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, plan.pinned == nil)
	}
	{
		plan, err := build_plan(t, "", BASE + ",redirect-gateway autolocal def1")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, plan.pinned != nil)
	}
}

@(test)
plan_redirect_flags_without_an_effect :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE + ",redirect-gateway def1 block-local bypass-dhcp bypass-dns")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_note(t, &plan, .Not_Implemented)
	testing.expect_value(t, len(plan.steps), 5) // same as plain def1

	// redirect-private never changes a route.
	plan2, err2 := build_plan(t, "", BASE + ",redirect-private def1")
	defer plan_destroy(&plan2)
	testing.expect_value(t, err2, Plan_Error.None)
	expect_steps(t, &plan2, {"addr 10.8.0.6/24", "link up"})
	expect_note(t, &plan2, .Not_Implemented)
}

@(test)
plan_local_redirect_gateway_in_the_config :: proc(t: ^testing.T) {
	// The config file asks for it; the server pushes nothing.
	plan, err := build_plan(t, "redirect-gateway def1", BASE)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	testing.expect_value(t, len(plan.steps), 5)
	testing.expect(t, plan.redirect4)
	// Flags add up: the config says def1, the server adds ipv6.
	plan2, err2 := build_plan(t, "redirect-gateway def1", BASE_DUAL + ",redirect-gateway ipv6")
	defer plan_destroy(&plan2)
	testing.expect_value(t, err2, Plan_Error.None)
	testing.expect(t, plan2.redirect4 && plan2.redirect6)
	testing.expect_value(t, len(plan2.steps), 8)
}

// ---- block-ipv6 ----

// `block-ipv6` is a rule of the data path. The plan adds no route for it,
// pushed or in the config, so the IPv6 of the host that does not go into the
// tunnel is as before.
@(test)
plan_block_ipv6_adds_no_route :: proc(t: ^testing.T) {
	{
		plan, err := build_plan(t, "", BASE + ",block-ipv6")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
	}
	{
		plan, err := build_plan(t, "block-ipv6\n", BASE)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
	}
	// The routes of the same push are not touched.
	{
		plan, err := build_plan(t, "", BASE_DUAL + ",block-ipv6,route-ipv6 2001:db8::/32")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		lines := step_lines(&plan)
		testing.expect_value(t, lines[len(lines) - 1], "route 2001:db8::/32 via fd00:8::1 dev tun")
		for l in lines {
			testing.expect(t, !strings.contains(l, "unreachable"))
		}
	}
}

// ---- config file routes, route-nopull and friends ----

@(test)
plan_config_routes :: proc(t: ^testing.T) {
	conf := `route 10.200.0.0 255.255.0.0
route 10.201.0.0 255.255.0.0 192.168.1.254 3
route 10.202.0.0 255.255.0.0 10.8.0.77
route 10.203.0.0 255.255.0.0 net_gateway
route-ipv6 2001:db8:ff::/48
route intranet.example.com 255.255.255.255`
	plan, err := build_plan(t, conf, BASE_DUAL)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"addr fd00:8::6/64",
			"link up",
			"route 10.200.0.0/16 via 10.8.0.1 dev tun",
			"route 10.201.0.0/16 via 192.168.1.254 metric 3",
			"route 10.202.0.0/16 via 10.8.0.77 dev tun",
			"route 10.203.0.0/16 via 192.168.1.1 dev #2",
			"route 2001:db8:ff::/48 via fd00:8::1 dev tun",
		},
	)
	expect_note(t, &plan, .Skipped_Host_Name)
	testing.expect_value(t, plan.steps[3].why, Why.Config_Route)
}

@(test)
plan_config_routes_come_before_pushed_ones :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "route 10.1.0.0 255.255.0.0", BASE + ",route 10.2.0.0 255.255.0.0,route 10.1.0.0 255.255.0.0")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up", "route 10.1.0.0/16 via 10.8.0.1 dev tun", "route 10.2.0.0/16 via 10.8.0.1 dev tun"})
	expect_note(t, &plan, .Skipped_Duplicate)
}

@(test)
plan_route_nopull :: proc(t: ^testing.T) {
	push_text := BASE_DUAL + ",tun-mtu 1400,route 10.1.0.0 255.255.0.0,route-ipv6 2001:db8::/32,redirect-gateway def1 ipv6,block-ipv6,route-metric 9,route-gateway 10.8.0.1,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example"
	// Addresses and the MTU still come from the server. Everything routing
	// related and the DNS do not.
	{
		plan, err := build_plan(t, "route-nopull", push_text)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"mtu 1400", "addr 10.8.0.6/24", "addr fd00:8::6/64", "link up"})
		testing.expect(t, !plan.has_dns && !plan.redirect4)
		expect_note(t, &plan, .Dropped_By_Nopull)
	}
	// What the config file asks for is not pulled, so it stays. The server's
	// gateway is not used for it.
	{
		conf := "route-nopull\nroute 10.99.0.0 255.255.0.0\nredirect-gateway def1\nroute-gateway 10.8.0.1\nroute-metric 4"
		plan, err := build_plan(t, conf, push_text)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(
			t,
			&plan,
			{
				"mtu 1400",
				"addr 10.8.0.6/24",
				"addr fd00:8::6/64",
				"link up",
				"route 203.0.113.7/32 via 192.168.1.1 dev #2",
				"route 10.99.0.0/16 via 10.8.0.1 dev tun metric 4",
				"route 0.0.0.0/1 via 10.8.0.1 dev tun metric 4",
				"route 128.0.0.0/1 via 10.8.0.1 dev tun metric 4",
			},
		)
	}
	// Without the option the same reply is applied.
	{
		plan, err := build_plan(t, "", push_text)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, plan.redirect4 && plan.redirect6 && plan.has_dns)
	}
}

@(test)
plan_conflicting_pushed_routes :: proc(t: ^testing.T) {
	push_text := BASE + ",route 10.1.0.0 255.255.0.0,route 10.1.0.0 255.255.0.0,route 10.1.0.0 255.255.0.0 vpn_gateway 7,route 10.8.0.0 255.255.255.0,route 10.2.3.4 255.255.0.0"
	plan, err := build_plan(t, "", push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_steps(
		t,
		&plan,
		{
			"addr 10.8.0.6/24",
			"link up",
			"route 10.1.0.0/16 via 10.8.0.1 dev tun",
			// Same network with another metric is a different route.
			"route 10.1.0.0/16 via 10.8.0.1 dev tun metric 7",
			// The tunnel's own network is the kernel's already; the host bits of
			// the last one are cleared.
			"route 10.2.0.0/16 via 10.8.0.1 dev tun",
		},
	)
	expect_note(t, &plan, .Skipped_Duplicate)
	expect_note(t, &plan, .Skipped_Connected)
	expect_note(t, &plan, .Masked_Host_Bits)
}

@(test)
plan_connected_route_for_ipv6 :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE_DUAL + ",route-ipv6 fd00:8::/64,route-ipv6 fd00:8::/64 vpn_gateway 5")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	// The one with a metric is a different route and is kept.
	lines := step_lines(&plan)
	testing.expect_value(t, len(lines), 4)
	testing.expect_value(t, lines[3], "route fd00:8::/64 via fd00:8::1 dev tun metric 5")
	expect_note(t, &plan, .Skipped_Connected)
}

@(test)
plan_gateway_keywords_that_cannot_be_resolved :: proc(t: ^testing.T) {
	// net_gateway with no default route.
	{
		plan, err := build_plan(t, "", BASE + ",route 172.16.0.0 255.240.0.0 net_gateway", proc(input: ^Plan_Input) {input.default4 = nil})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
		expect_note(t, &plan, .Skipped_No_Gateway)
	}
	// remote_host: the next hop of the pinned server route.
	{
		plan, err := build_plan(t, "", BASE + ",route 198.51.100.0 255.255.255.0 remote_host")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up", "route 198.51.100.0/24 via 192.168.1.1 dev #2"})
	}
	// remote_host with an IPv6 server and an IPv4 route: no such hop.
	{
		plan, err := build_plan(t, "", BASE + ",route 198.51.100.0 255.255.255.0 remote_host", proc(input: ^Plan_Input) {
			input.server = sysnet.Address(SERVER6)
			input.server_route = route_to(sysnet.Address(SERVER6), sysnet.Address(GW6), UPLINK)
		})
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"addr 10.8.0.6/24", "link up"})
		expect_note(t, &plan, .Skipped_No_Gateway)
	}
}

@(test)
plan_route_metric :: proc(t: ^testing.T) {
	// The pushed route-metric is the default for routes that have none.
	{
		plan, err := build_plan(t, "", BASE + ",route-metric 50,route 10.1.0.0 255.255.0.0,route 10.2.0.0 255.255.0.0 vpn_gateway 9,redirect-gateway def1")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(
			t,
			&plan,
			{
				"addr 10.8.0.6/24",
				"link up",
				"route 203.0.113.7/32 via 192.168.1.1 dev #2",
				"route 10.1.0.0/16 via 10.8.0.1 dev tun metric 50",
				"route 10.2.0.0/16 via 10.8.0.1 dev tun metric 9",
				"route 0.0.0.0/1 via 10.8.0.1 dev tun metric 50",
				"route 128.0.0.0/1 via 10.8.0.1 dev tun metric 50",
			},
		)
	}
	// The local route-metric is used when the server pushes none, and loses to
	// the pushed one.
	{
		plan, err := build_plan(t, "route-metric 70", BASE + ",route 10.1.0.0 255.255.0.0")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, step_lines(&plan)[2], "route 10.1.0.0/16 via 10.8.0.1 dev tun metric 70")
		plan2, err2 := build_plan(t, "route-metric 70", BASE + ",route-metric 20,route 10.1.0.0 255.255.0.0")
		defer plan_destroy(&plan2)
		testing.expect_value(t, err2, Plan_Error.None)
		testing.expect_value(t, step_lines(&plan2)[2], "route 10.1.0.0/16 via 10.8.0.1 dev tun metric 20")
	}
	// A metric of 0 is a real metric.
	{
		plan, err := build_plan(t, "", BASE + ",route 10.1.0.0 255.255.0.0 vpn_gateway 0")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, step_lines(&plan)[2], "route 10.1.0.0/16 via 10.8.0.1 dev tun metric 0")
	}
}

@(test)
plan_route_table_applies_to_every_route :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "route-table 100", BASE_DUAL + ",route 10.1.0.0 255.255.0.0,redirect-gateway def1,block-ipv6")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	routes := 0
	for s in plan.steps {
		if s.kind == .Add_Route {
			routes += 1
			testing.expect_value(t, s.route.table, u32(100))
		}
	}
	// Pin, route and the two halves.
	testing.expect_value(t, routes, 4)
	testing.expect(t, strings.has_suffix(step_lines(&plan)[3], " table 100"))
}

@(test)
plan_noexec_options :: proc(t: ^testing.T) {
	push_text := BASE + ",tun-mtu 1400,route 10.1.0.0 255.255.0.0,redirect-gateway def1,block-ipv6"
	{
		plan, err := build_plan(t, "route-noexec", push_text)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_steps(t, &plan, {"mtu 1400", "addr 10.8.0.6/24", "link up"})
		testing.expect(t, !plan.redirect4 && plan.pinned == nil)
	}
	{
		plan, err := build_plan(t, "ifconfig-noexec", push_text)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		for s in plan.steps {
			testing.expect_value(t, s.kind, Step_Kind.Add_Route)
		}
		testing.expect_value(t, len(plan.steps), 1 + 1 + 2) // pin, route, halves
		// The summary still says what the tunnel has.
		testing.expect_value(t, plan.prefix4, u8(24))
	}
}

// ---- DNS ----

@(test)
plan_dns_from_dhcp_options :: proc(t: ^testing.T) {
	push_text := BASE + ",dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00:8::53,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example,dhcp-option DOMAIN-SEARCH lan.example,dhcp-option DOMAIN CORP.example,dhcp-option NBT 2"
	plan, err := build_plan(t, "", push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	testing.expect(t, plan.has_dns)
	d := plan.dns
	testing.expect_value(t, len(d.servers), 2)
	testing.expect_value(t, d.servers[0].address, sysnet.Address(sysnet.IP4_Address{10, 8, 0, 1}))
	testing.expect_value(t, d.servers[1].address, sysnet.Address(sysnet.IP6_Address{0xfd00, 8, 0, 0, 0, 0, 0, 0x53}))
	testing.expect_value(t, len(d.search_domains), 2)
	testing.expect_value(t, d.search_domains[0], "corp.example")
	testing.expect_value(t, d.search_domains[1], "lan.example")
	testing.expect_value(t, len(d.routing_domains), 0)
	testing.expect(t, !d.default_route)
	testing.expect_value(t, sysnet.dns_settings_check(d), sysnet.DNS_Error.None)
}

@(test)
plan_dns_default_route_follows_redirect_gateway :: proc(t: ^testing.T) {
	plan, err := build_plan(t, "", BASE + ",redirect-gateway def1,dhcp-option DNS 10.8.0.1")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	testing.expect(t, plan.has_dns && plan.dns.default_route)
	// An IPv6-only redirect counts too.
	plan2, err2 := build_plan(t, "", BASE6 + ",redirect-gateway def1 ipv6 !ipv4,dhcp-option DNS6 fd00:8::1", proc(input: ^Plan_Input) {input.server = nil})
	defer plan_destroy(&plan2)
	testing.expect_value(t, err2, Plan_Error.None)
	testing.expect(t, plan2.has_dns && plan2.dns.default_route)
}

@(test)
plan_dns_v2_groups :: proc(t: ^testing.T) {
	push_text := BASE + ",dns server 10 address 10.8.0.10,dns server 0 address 10.8.0.1 [fd00:8::53]:5353,dns server 0 resolve-domains corp.example,dns search-domains a.example b.example,dhcp-option DNS 9.9.9.9,dhcp-option DOMAIN old.example"
	plan, err := build_plan(t, "", push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	d := plan.dns
	// The v2 servers win over dhcp-option DNS, lowest priority first.
	testing.expect_value(t, len(d.servers), 3)
	testing.expect_value(t, d.servers[0], sysnet.DNS_Server{sysnet.IP4_Address{10, 8, 0, 1}, 0})
	testing.expect_value(t, d.servers[1], sysnet.DNS_Server{sysnet.IP6_Address{0xfd00, 8, 0, 0, 0, 0, 0, 0x53}, 5353})
	testing.expect_value(t, d.servers[2], sysnet.DNS_Server{sysnet.IP4_Address{10, 8, 0, 10}, 0})
	testing.expect_value(t, len(d.routing_domains), 1)
	testing.expect_value(t, d.routing_domains[0], "corp.example")
	// Search domains from both forms.
	testing.expect_value(t, len(d.search_domains), 3)
	testing.expect_value(t, d.search_domains[0], "a.example")
	testing.expect_value(t, d.search_domains[2], "old.example")
}

@(test)
plan_dns_skips_what_the_backends_cannot_do :: proc(t: ^testing.T) {
	// A DoT group is skipped; the plain one stays.
	{
		push_text := BASE + ",dns server 1 address 10.8.0.1,dns server 1 transport DoT,dns server 2 address 10.8.0.2"
		plan, err := build_plan(t, "", push_text)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, len(plan.dns.servers), 1)
		testing.expect_value(t, plan.dns.servers[0].address, sysnet.Address(sysnet.IP4_Address{10, 8, 0, 2}))
		expect_note(t, &plan, .Skipped_DNS_Group)
	}
	// Only a DoH group: no DNS plan.
	{
		plan, err := build_plan(t, "", BASE + ",dns server 1 address 10.8.0.1,dns server 1 transport DoH")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, !plan.has_dns)
	}
	// A bad domain is dropped, the rest stays.
	{
		plan, err := build_plan(t, "", BASE + ",dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN -evil.example,dhcp-option DOMAIN good.example")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect_value(t, len(plan.dns.search_domains), 1)
		testing.expect_value(t, plan.dns.search_domains[0], "good.example")
		expect_note(t, &plan, .Adjusted)
	}
	// Domains without a server do nothing.
	{
		plan, err := build_plan(t, "", BASE + ",dhcp-option DOMAIN corp.example")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, !plan.has_dns)
	}
}

// ---- the plan as a whole ----

@(test)
plan_summary_and_equality :: proc(t: ^testing.T) {
	push_text := BASE_DUAL + ",tun-mtu 1400,redirect-gateway def1 ipv6"
	a, aerr := build_plan(t, "", push_text)
	defer plan_destroy(&a)
	b, berr := build_plan(t, "", push_text)
	defer plan_destroy(&b)
	testing.expect_value(t, aerr, Plan_Error.None)
	testing.expect_value(t, berr, Plan_Error.None)
	testing.expect(t, plan_equal(&a, &b))
	testing.expect_value(t, a.mtu, u32(1400))
	testing.expect_value(t, a.prefix6, u8(64))
	testing.expect(t, a.redirect4 && a.redirect6)
	testing.expect_value(t, a.pinned, Maybe(sysnet.Address)(sysnet.Address(SERVER4)))

	// A different server gateway is a different plan.
	c, cerr := build_plan(t, "", push_text, proc(input: ^Plan_Input) {
		input.server_route = route_to(SERVER4, sysnet.Address(sysnet.IP4_Address{192, 168, 1, 2}), UPLINK)
	})
	defer plan_destroy(&c)
	testing.expect_value(t, cerr, Plan_Error.None)
	testing.expect(t, !plan_equal(&a, &c))
	// A shorter one is too.
	d, derr := build_plan(t, "", BASE)
	defer plan_destroy(&d)
	testing.expect_value(t, derr, Plan_Error.None)
	testing.expect(t, !plan_equal(&a, &d))
}

@(test)
plan_the_order_is_pin_before_routes_before_redirect :: proc(t: ^testing.T) {
	push_text := BASE + ",route 203.0.113.0 255.255.255.0,route 10.1.0.0 255.255.0.0,redirect-gateway def1,block-ipv6,dhcp-option DNS 10.8.0.1"
	plan, err := build_plan(t, "", push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	whys: [dynamic]Why
	defer delete(whys)
	kinds: [dynamic]Step_Kind
	defer delete(kinds)
	for s in plan.steps {
		append(&kinds, s.kind)
		if s.kind == .Add_Route {
			append(&whys, s.why)
		}
	}
	testing.expect_value(t, kinds[0], Step_Kind.Add_Addr)
	testing.expect_value(t, kinds[1], Step_Kind.Link_Up)
	want := []Why{.Server_Pin, .Pushed_Route, .Pushed_Route, .Redirect_Low, .Redirect_High}
	testing.expect_value(t, len(whys), len(want))
	for w, i in want {
		if i < len(whys) {
			testing.expect_value(t, whys[i], w)
		}
	}
}

@(test)
plan_step_string_forms :: proc(t: ^testing.T) {
	cases := []struct {
		s:    Step,
		want: string,
	} {
		{Step{kind = .Set_Mtu, mtu = 1400}, "mtu 1400"},
		{Step{kind = .Link_Up}, "link up"},
		{Step{kind = .Add_Addr, addr = sysnet.IP4_Address{10, 0, 0, 2}, prefix_len = 24}, "addr 10.0.0.2/24"},
		{Step{kind = .Add_Route, route = {dst = sysnet.IP4_Address{10, 1, 0, 0}, dst_len = 16, ifindex = 3}}, "route 10.1.0.0/16 dev #3"},
		{Step{kind = .Add_Route, on_tun = true, route = {dst = sysnet.IP4_Address{}, dst_len = 0, gateway = sysnet.Address(sysnet.IP4_Address{1, 2, 3, 4}), metric = u32(5), table = 7}}, "route default via 1.2.3.4 dev tun metric 5 table 7"},
		{Step{kind = .Add_Route, route = {dst = sysnet.IP6_Address{}, dst_len = 1, kind = .Blackhole}}, "blackhole route ::/1"},
	}
	for c in cases {
		testing.expect_value(t, step_string(c.s, context.temp_allocator), c.want)
	}
}
