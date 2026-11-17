// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:fmt"
import "core:mem"
import cnet "core:net"
import "core:strings"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/push"

// The plan: what to change in the OS for one connection.
// `plan_build` (pure) computes it from the local config, the pushed options,
// and facts about the routes that exist before the VPN changes anything.
// Only `netcfg_apply` talks to the kernel.

Step_Kind :: enum u8 {
	// Set the tunnel MTU.
	Set_Mtu,
	// Add an address to the tunnel.
	Add_Addr,
	// Bring the tunnel up.
	Link_Up,
	// Add a route.
	Add_Route,
}

// Why a route is in the plan. Tests and log lines use it.
Why :: enum u8 {
	None,
	// Host route to the VPN server through the old gateway.
	Server_Pin,
	// `route` / `route-ipv6` from the config file.
	Config_Route,
	// `route` / `route-ipv6` from the server.
	Pushed_Route,
	// `redirect-gateway def1`: the two half routes (or `::/1` and `8000::/1`).
	Redirect_Low,
	Redirect_High,
	// `redirect-gateway` without def1: one default route.
	Redirect_Default,
}

Step :: struct {
	kind:       Step_Kind,
	// Set_Mtu:
	mtu:        u32,
	// Add_Addr:
	addr:       sysnet.Address,
	prefix_len: u8,
	// The kernel adds no route for the network of the address.
	no_prefix_route: bool,
	// Add_Route. `route.ifindex` is 0 for a route that goes out of the tunnel
	// (`on_tun`): the executor fills in the tunnel's index.
	route:      sysnet.Route,
	on_tun:     bool,
	// A failure of this step must stop the connection. Without the step,
	// traffic could leak or loop (pinned server route, redirect routes, IPv6
	// block). Failures of other steps are reported and skipped.
	critical:   bool,
	why:        Why,
}

Note_Kind :: enum u8 {
	Info,
	// A route that equals the tunnel's own network: the kernel has it already.
	Skipped_Connected,
	// A tunnel route that would send the VPN server's own address into the tunnel.
	Skipped_Server_Host,
	// The same route twice (same destination, length and metric).
	Skipped_Duplicate,
	// A route in the config file names a host. Host names are not resolved here.
	Skipped_Host_Name,
	// A gateway keyword that cannot be resolved (`net_gateway` with no default route).
	Skipped_No_Gateway,
	// The destination had bits set outside the prefix; they were cleared.
	Masked_Host_Bits,
	// `redirect-gateway` without `def1` could not use a lower metric: def1 was used.
	Redirect_Used_Def1,
	// A flag or option that has no effect on this platform.
	Not_Implemented,
	// An option dropped because of `route-nopull`.
	Dropped_By_Nopull,
	// A DNS group the resolver backend cannot use (DoH, DoT).
	Skipped_DNS_Group,
	// A value was out of range and was changed or dropped.
	Adjusted,
	// A pushed route that is equal to a network of the host, or inside one.
	Dropped_Host_Net,
	// The tunnel network overlaps a network of the host: the address has no prefix route.
	Tunnel_Host_Net,
}

Note :: struct {
	kind: Note_Kind,
	text: string,
}

Plan :: struct {
	allocator:   mem.Allocator,
	// In the order to apply. Reverse order undoes them.
	steps:       [dynamic]Step,
	// Things the plan did not do, or did differently, and why.
	notes:       [dynamic]Note,
	// DNS settings for `sysnet.dns_apply`. Only valid when `has_dns`.
	dns:         sysnet.DNS_Settings,
	has_dns:     bool,
	// A summary of the tunnel settings, for the `client.tunnel_settings` event.
	mtu:         u32,
	addr4:       Maybe(sysnet.IP4_Address),
	prefix4:     u8,
	addr6:       Maybe(sysnet.IP6_Address),
	prefix6:     u8,
	// All IPv4 / IPv6 traffic is sent into the tunnel.
	redirect4:   bool,
	redirect6:   bool,
	// The server's address, when it has a host route outside the tunnel.
	pinned:      Maybe(sysnet.Address),
}

plan_destroy :: proc(p: ^Plan) {
	delete(p.steps)
	for n in p.notes {
		delete(n.text, p.allocator)
	}
	delete(p.notes)
	sysnet.dns_settings_destroy(&p.dns, p.allocator)
	p^ = {}
}

Plan_Error :: enum u8 {
	None,
	// `topology net30` or `p2p`.
	Unsupported_Topology,
	// An `ifconfig` was pushed without `topology subnet`.
	Missing_Topology,
	// The reply has neither `ifconfig` nor `ifconfig-ipv6`.
	No_Address,
	// Routes must be pinned or redirected but there is no usable route to the
	// server (the lookup failed, or it is an unreachable or blocked route).
	No_Server_Route,
}

// What the plan needs to know about the system. Fill it in with
// `netcfg_gather` (Linux) before any VPN route exists.
Plan_Input :: struct {
	cfg:          ^config.Client_Config,
	pushed:       ^push.Pushed_Options,
	// The tun-mtu from the active remote's settings; 0 if none.
	local_mtu:    int,
	// The address the transport talks to. Nil: unknown, nothing is pinned.
	server:       Maybe(sysnet.Address),
	// What `route_lookup(server)` said before any VPN route existed.
	server_route: Maybe(sysnet.Route),
	// `route_get_default` for each family, before any VPN route existed.
	default4:     Maybe(sysnet.Route),
	default6:     Maybe(sysnet.Route),
	// The networks of the host (`netcfg_host_nets`). If the list has an entry,
	// the rules for a user profile apply (`plan_hostnet.odin`). A config file
	// leaves it empty.
	host_nets:    []Host_Net,
}

@(private)
Builder :: struct {
	input:       Plan_Input,
	plan:        ^Plan,
	alloc:       mem.Allocator,
	// Pushed routing options may be used (`route-nopull` is off).
	pull_routes: bool,
	table:       u32,
	// The tunnel's own networks, for the connected-route check.
	has_net4:    bool,
	net4:        [4]u8,
	len4:        u8,
	has_net6:    bool,
	net6:        [16]u8,
	len6:        u8,
	// The kernel creates no route for the tunnel network.
	no_route4:   bool,
	no_route6:   bool,
	gw4:         Maybe(sysnet.Address),
	gw6:         Maybe(sysnet.Address),
	metric:      Maybe(u32),
	// The routes from the config file and the server, in the order they will
	// be applied.
	routes:      [dynamic]Step,
}

// Build the plan. On error nothing is returned to free.
plan_build :: proc(input: Plan_Input, allocator := context.allocator) -> (plan: Plan, err: Plan_Error) {
	plan.allocator = allocator
	plan.steps = make([dynamic]Step, allocator)
	plan.notes = make([dynamic]Note, allocator)
	b := Builder {
		input = input,
		plan  = &plan,
		alloc = allocator,
	}
	b.routes.allocator = allocator
	defer delete(b.routes)
	if e := build_all(&b); e != .None {
		plan_destroy(&plan)
		return {}, e
	}
	return plan, .None
}

@(private)
build_all :: proc(b: ^Builder) -> Plan_Error {
	cfg := b.input.cfg
	b.pull_routes = !cfg.route_nopull
	b.table = u32(max(cfg.route_table, 0))

	if e := build_link(b); e != .None {
		return e
	}
	setup_gateways(b)
	if e := build_routes(b); e != .None {
		return e
	}
	build_dns(b)
	return .None
}

// ---- MTU, addresses, link ----

@(private)
build_link :: proc(b: ^Builder) -> Plan_Error {
	cfg := b.input.cfg
	po := b.input.pushed
	p := b.plan

	switch po.topology {
	case .Net30, .P2p:
		return .Unsupported_Topology
	case .Unset:
		if po.ifconfig != nil {
			return .Missing_Topology
		}
	case .Subnet:
	}
	if po.ifconfig == nil && po.ifconfig6 == nil {
		return .No_Address
	}
	if cfg.ifconfig != nil || cfg.ifconfig_ipv6 != nil {
		// SPEC-GAP: a local `ifconfig` is overridden by the server's in
		// pull mode and has no use without it; it is ignored.
		note(b, .Info, "the local ifconfig and ifconfig-ipv6 lines were ignored because the tunnel addresses come from the server")
	}

	exec := !cfg.ifconfig_noexec

	mtu := b.input.local_mtu
	if m, ok := po.tun_mtu.?; ok {
		mtu = m
	}
	if mtu > 0 {
		if mtu < 68 {
			note(b, .Adjusted, "tun-mtu %d is below the IPv4 minimum of 68, so it was not applied", mtu)
		} else {
			if mtu > 65535 {
				note(b, .Adjusted, "tun-mtu %d is above 65535, so 65535 is used instead", mtu)
				mtu = 65535
			}
			p.mtu = u32(mtu)
			if exec {
				append(&p.steps, Step{kind = .Set_Mtu, mtu = u32(mtu)})
			}
		}
	}

	if ifc, ok := po.ifconfig.?; ok {
		prefix, pok := config.ipv4_mask_prefix(ifc.b)
		if !pok {
			// The push parser checks the mask only for routes.
			note(b, .Adjusted, "the ifconfig netmask is not a valid mask, so /32 is used instead")
			prefix = 32
		}
		p.addr4 = sysnet.IP4_Address(ifc.a)
		p.prefix4 = u8(prefix)
		b.has_net4 = true
		b.net4 = mask4(ifc.a, prefix)
		b.len4 = u8(prefix)
		b.no_route4 = tunnel_overlaps_host(b, false, b.net4[:], u8(prefix))
		if exec {
			append(&p.steps, Step{kind = .Add_Addr, addr = sysnet.IP4_Address(ifc.a), prefix_len = u8(prefix), no_prefix_route = b.no_route4})
		}
	}
	if ifc, ok := po.ifconfig6.?; ok {
		p.addr6 = to_ip6(ifc.addr)
		p.prefix6 = ifc.bits
		b.has_net6 = true
		b.net6 = mask6(ifc.addr, int(ifc.bits))
		b.len6 = ifc.bits
		b.no_route6 = tunnel_overlaps_host(b, true, b.net6[:], ifc.bits)
		if exec {
			append(&p.steps, Step{kind = .Add_Addr, addr = to_ip6(ifc.addr), prefix_len = ifc.bits, no_prefix_route = b.no_route6})
		}
	}
	if exec {
		append(&p.steps, Step{kind = .Link_Up})
	}
	return .None
}

// The gateways that `vpn_gateway` stands for, and the default metric.
@(private)
setup_gateways :: proc(b: ^Builder) {
	cfg := b.input.cfg
	po := b.input.pushed

	// IPv4: pushed route-gateway, then the local one.
	if g, ok := po.route_gateway.?; ok && b.pull_routes {
		b.gw4 = sysnet.IP4_Address(g)
	} else if lg, lok := config.ipv4_parse(cfg.route_gateway); lok && cfg.route_gateway != "" {
		b.gw4 = sysnet.IP4_Address(lg)
	}
	// IPv6: pushed route-ipv6-gateway, then the local one, then the far end of
	// ifconfig-ipv6.
	if g, ok := po.route_ipv6_gateway.?; ok && b.pull_routes {
		b.gw6 = to_ip6(g)
	} else if lg, lok := config.ipv6_parse(cfg.route_ipv6_gateway); lok && cfg.route_ipv6_gateway != "" {
		b.gw6 = to_ip6(lg)
	} else if ifc, iok := po.ifconfig6.?; iok && ifc.gateway != ([16]u8{}) {
		b.gw6 = to_ip6(ifc.gateway)
	}

	if m, ok := po.route_metric.?; ok && b.pull_routes {
		b.metric = u32(m)
	} else if cfg.route_metric >= 0 {
		b.metric = u32(cfg.route_metric)
	}
	if !b.pull_routes {
		if po.route_gateway != nil || po.route_ipv6_gateway != nil || po.route_metric != nil {
			note(b, .Dropped_By_Nopull, "route-gateway and route-metric from the server were ignored because route-nopull is set")
		}
	}
}

// ---- notes and small helpers ----

@(private)
note :: proc(b: ^Builder, kind: Note_Kind, format: string, args: ..any) {
	text := fmt.aprintf(format, ..args, allocator = b.alloc)
	append(&b.plan.notes, Note{kind = kind, text = text})
}

@(private)
to_ip6 :: proc "contextless" (b: [16]u8) -> sysnet.IP6_Address {
	return sysnet.IP6_Address(transmute([8]u16be)b)
}

@(private)
mask4 :: proc "contextless" (a: [4]u8, prefix: int) -> [4]u8 {
	m := config.ipv4_prefix_mask(prefix)
	return {a[0] & m[0], a[1] & m[1], a[2] & m[2], a[3] & m[3]}
}

@(private)
mask6 :: proc "contextless" (a: [16]u8, bits: int) -> [16]u8 {
	out := a
	for i in 0 ..< 16 {
		out[i] &= top_bits(bits - i * 8)
	}
	return out
}

// A byte with the top `n` bits set (n is clamped to 0..8).
@(private)
top_bits :: proc "contextless" (n: int) -> u8 {
	keep := u16(clamp(n, 0, 8))
	return u8((u16(0xff00) >> keep) & 0xff)
}

// True if the first `bits` bits of `a` and `net` agree.
@(private)
prefix_covers :: proc "contextless" (net: []u8, bits: int, a: []u8) -> bool {
	for i in 0 ..< len(net) {
		m := top_bits(bits - i * 8)
		if m == 0 {
			break
		}
		if net[i] & m != a[i] & m {
			return false
		}
	}
	return true
}

// The bytes of an address and whether it is IPv6.
@(private)
addr_bytes :: proc "contextless" (a: sysnet.Address) -> (b: [16]u8, v6: bool, ok: bool) {
	switch v in a {
	case sysnet.IP4_Address:
		o := cast([4]u8)v
		copy(b[:], o[:])
		return b, false, true
	case sysnet.IP6_Address:
		return transmute([16]u8)v, true, true
	}
	return {}, false, false
}

// An address as text, for notes. Valid until the temp allocator is freed.
@(private)
addr_text :: proc(b: [16]u8, v6: bool) -> string {
	return cnet.address_to_string(to_addr(b, v6), context.temp_allocator)
}

@(private)
to_addr :: proc "contextless" (b: [16]u8, v6: bool) -> sysnet.Address {
	if v6 {
		return to_ip6(b)
	}
	return sysnet.IP4_Address{b[0], b[1], b[2], b[3]}
}

@(private)
metric_of :: proc "contextless" (r: sysnet.Route) -> u32 {
	m, _ := r.metric.?
	return m
}

// ---- text form of a step (for logs and tests) ----

// One line per step, for example `route 0.0.0.0/1 via 10.8.0.1 dev tun metric 5`.
// The caller owns the string.
step_string :: proc(s: Step, allocator := context.allocator) -> string {
	sb := strings.builder_make(allocator)
	switch s.kind {
	case .Set_Mtu:
		fmt.sbprintf(&sb, "mtu %d", s.mtu)
	case .Add_Addr:
		a := cnet.address_to_string(s.addr, context.temp_allocator)
		fmt.sbprintf(&sb, "addr %s/%d", a, s.prefix_len)
		if s.no_prefix_route {
			strings.write_string(&sb, " noprefixroute")
		}
	case .Link_Up:
		strings.write_string(&sb, "link up")
	case .Add_Route:
		r := s.route
		dst: string
		if r.dst_len == 0 {
			dst = "default" if route_is_v6(r) == false else "default6"
		} else {
			dst = fmt.tprintf("%s/%d", cnet.address_to_string(r.dst, context.temp_allocator), r.dst_len)
		}
		switch r.kind {
		case .Unicast, .Local, .Other:
		case .Blackhole:
			strings.write_string(&sb, "blackhole ")
		case .Unreachable:
			strings.write_string(&sb, "unreachable ")
		case .Prohibit:
			strings.write_string(&sb, "prohibit ")
		}
		fmt.sbprintf(&sb, "route %s", dst)
		if gw, ok := r.gateway.?; ok {
			fmt.sbprintf(&sb, " via %s", cnet.address_to_string(gw, context.temp_allocator))
		}
		if s.on_tun {
			strings.write_string(&sb, " dev tun")
		} else if r.ifindex != 0 {
			fmt.sbprintf(&sb, " dev #%d", r.ifindex)
		}
		if m, ok := r.metric.?; ok {
			fmt.sbprintf(&sb, " metric %d", m)
		}
		if r.table != 0 {
			fmt.sbprintf(&sb, " table %d", r.table)
		}
	}
	return strings.to_string(sb)
}

@(private)
route_is_v6 :: proc "contextless" (r: sysnet.Route) -> bool {
	_, is6 := r.dst.(sysnet.IP6_Address)
	return is6
}

// True if two plans do the same things (same steps, same order). Notes and
// summary are not compared. For `persist-tun`: if a reconnect gives the same
// plan, the routes can stay.
plan_equal :: proc(a, b: ^Plan) -> bool {
	if len(a.steps) != len(b.steps) {
		return false
	}
	for i in 0 ..< len(a.steps) {
		if a.steps[i] != b.steps[i] {
			return false
		}
	}
	return true
}
