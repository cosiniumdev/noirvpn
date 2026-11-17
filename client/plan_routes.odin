// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/push"

// Route part of the plan. Steps added after the address and `link up` steps:
//   1. Host route to the VPN server through the old gateway ("pin"), if a later
//      route would send the server address into the tunnel.
//   2. Routes from the config file, then pushed routes.
//   3. `redirect-gateway`: two half routes (def1) or one default route.
// `block-ipv6` adds no route (the data path drops IPv6 at the tunnel).
// The pin comes first, so the transport never loops into the tunnel. Undo runs
// backwards, so the pin goes last.

// A route as the config file or the server wrote it, with the gateway still a
// keyword. v4 uses the first 4 bytes of the arrays.
@(private)
Cand :: struct {
	v6:      bool,
	dst:     [16]u8,
	bits:    u8,
	gw_kind: push.Route_Gw_Kind,
	gw:      [16]u8,
	metric:  Maybe(u32),
	why:     Why,
}

// Where a route goes.
@(private)
Hop :: struct {
	on_tun:  bool,
	gateway: Maybe(sysnet.Address),
	ifindex: u32,
	onlink:  bool,
}

@(private)
build_routes :: proc(b: ^Builder) -> Plan_Error {
	cands := make([dynamic]Cand, b.alloc)
	defer delete(cands)
	collect_config_routes(b, &cands)
	collect_pushed_routes(b, &cands)
	for c in cands {
		add_candidate(b, c)
	}
	return finish_routes(b)
}

// ---- collecting ----

@(private)
collect_config_routes :: proc(b: ^Builder, out: ^[dynamic]Cand) {
	cfg := b.input.cfg
	for r in cfg.routes {
		net, ok := config.ipv4_parse(r.network)
		if !ok {
			note(b, .Skipped_Host_Name, "route %s was skipped because host names are not resolved", r.network)
			continue
		}
		bits := 32
		if r.netmask != "" {
			mask, mok := config.ipv4_parse(r.netmask)
			p, pok := config.ipv4_mask_prefix(mask)
			if !mok || !pok {
				note(b, .Adjusted, "route %s was skipped because the netmask %s is not valid", r.network, r.netmask)
				continue
			}
			bits = p
		}
		c := Cand {
			bits = u8(bits),
			why  = .Config_Route,
		}
		copy(c.dst[:], net[:])
		if !parse_gw_word(r.gateway, false, &c) {
			note(b, .Skipped_Host_Name, "route %s was skipped because its gateway %s is a host name", r.network, r.gateway)
			continue
		}
		if r.metric >= 0 {
			c.metric = u32(r.metric)
		}
		append(out, c)
	}
	for r in cfg.routes6 {
		addr, bits, ok := config.ipv6_parse_cidr(r.prefix)
		if !ok {
			note(b, .Adjusted, "route-ipv6 %s was skipped because it is not a prefix", r.prefix)
			continue
		}
		c := Cand {
			v6   = true,
			dst  = addr,
			bits = u8(bits),
			why  = .Config_Route,
		}
		if !parse_gw_word(r.gateway, true, &c) {
			note(b, .Skipped_Host_Name, "route-ipv6 %s was skipped because its gateway %s is a host name", r.prefix, r.gateway)
			continue
		}
		if r.metric >= 0 {
			c.metric = u32(r.metric)
		}
		append(out, c)
	}
}

// A gateway word of the config file: empty, a keyword, or an address.
@(private)
parse_gw_word :: proc(s: string, v6: bool, c: ^Cand) -> bool {
	switch s {
	case "":
		c.gw_kind = .Default
		return true
	case "vpn_gateway":
		c.gw_kind = .Vpn_Gateway
		return true
	case "net_gateway":
		c.gw_kind = .Net_Gateway
		return true
	case "remote_host":
		c.gw_kind = .Remote_Host
		return true
	}
	if v6 {
		a, ok := config.ipv6_parse(s)
		c.gw_kind, c.gw = .Addr, a
		return ok
	}
	a, ok := config.ipv4_parse(s)
	c.gw_kind = .Addr
	copy(c.gw[:], a[:])
	return ok
}

@(private)
collect_pushed_routes :: proc(b: ^Builder, out: ^[dynamic]Cand) {
	po := b.input.pushed
	if !b.pull_routes {
		if n := len(po.routes) + len(po.routes6); n > 0 {
			note(b, .Dropped_By_Nopull, "%d pushed routes were ignored because route-nopull is set", n)
		}
		return
	}
	for &r in po.routes {
		bits, _ := config.ipv4_mask_prefix(r.mask)
		c := Cand {
			bits    = u8(bits),
			gw_kind = r.gateway.kind,
			why     = .Pushed_Route,
		}
		copy(c.dst[:], r.net[:])
		copy(c.gw[:], r.gateway.addr[:])
		if m, ok := r.metric.?; ok {
			c.metric = u32(m)
		}
		if pushed_route_in_host_net(b, c) {
			continue
		}
		append(out, c)
	}
	for r in po.routes6 {
		c := Cand {
			v6      = true,
			dst     = r.net,
			bits    = r.bits,
			gw_kind = r.gateway.kind,
			gw      = r.gateway.addr,
			why     = .Pushed_Route,
		}
		if m, ok := r.metric.?; ok {
			c.metric = u32(m)
		}
		if pushed_route_in_host_net(b, c) {
			continue
		}
		append(out, c)
	}
}

// ---- one route ----

@(private)
full_bits :: proc "contextless" (v6: bool) -> u8 {
	return 128 if v6 else 32
}

@(private)
vpn_gateway :: proc(b: ^Builder, v6: bool) -> Maybe(sysnet.Address) {
	return b.gw6 if v6 else b.gw4
}

// Resolve the gateway word of a route. False: the route cannot be built, and
// a note says why.
@(private)
next_hop :: proc(b: ^Builder, c: Cand) -> (h: Hop, ok: bool) {
	family := "IPv6" if c.v6 else "IPv4"
	switch c.gw_kind {
	case .Default, .Vpn_Gateway:
		gw := vpn_gateway(b, c.v6)
		return Hop{on_tun = true, gateway = gw, onlink = gw != nil}, true
	case .Net_Gateway:
		def := b.input.default6 if c.v6 else b.input.default4
		d, has := def.?
		if !has {
			note(b, .Skipped_No_Gateway, "a route with net_gateway was skipped because there is no %s default route", family)
			return {}, false
		}
		return Hop{gateway = d.gateway, ifindex = d.ifindex}, true
	case .Remote_Host:
		sr, has := b.input.server_route.?
		if !has || (sr.family == .V6) != c.v6 {
			note(b, .Skipped_No_Gateway, "a route with remote_host was skipped because there is no %s route to the server", family)
			return {}, false
		}
		return Hop{gateway = sr.gateway, ifindex = sr.ifindex}, true
	case .Addr:
		gw := to_addr(c.gw, c.v6)
		gwb := c.gw
		net4 := b.net4
		net6 := b.net6
		// A gateway inside the tunnel's own network is reached through the tunnel.
		if c.v6 && b.has_net6 && prefix_covers(net6[:], int(b.len6), gwb[:]) {
			return Hop{on_tun = true, gateway = gw, onlink = true}, true
		}
		if !c.v6 && b.has_net4 && prefix_covers(net4[:], int(b.len4), gwb[:4]) {
			return Hop{on_tun = true, gateway = gw, onlink = true}, true
		}
		// Anything else: the kernel finds the interface from its own routes.
		return Hop{gateway = gw}, true
	}
	return {}, false
}

@(private)
add_candidate :: proc(b: ^Builder, c: Cand) {
	c := c
	masked := c.dst
	if c.v6 {
		masked = mask6(c.dst, int(c.bits))
	} else {
		m := mask4({c.dst[0], c.dst[1], c.dst[2], c.dst[3]}, int(c.bits))
		copy(masked[:], m[:])
	}
	if masked != c.dst {
		note(
			b,
			.Masked_Host_Bits,
			"route %s/%d has host bits set, so %s/%d is used instead",
			addr_text(c.dst, c.v6),
			c.bits,
			addr_text(masked, c.v6),
			c.bits,
		)
		c.dst = masked
	}

	hop, ok := next_hop(b, c)
	if !ok {
		return
	}
	metric := c.metric
	if metric == nil {
		metric = b.metric
	}

	if hop.on_tun {
		// The kernel created the connected route for the tunnel's own network.
		if !c.v6 && b.has_net4 && !b.no_route4 && c.bits == b.len4 && dst4(c) == b.net4 && metric_is_zero(metric) {
			note(b, .Skipped_Connected, "route %s/%d was skipped because it is the tunnel's own network", addr_text(c.dst, false), c.bits)
			return
		}
		if c.v6 && b.has_net6 && !b.no_route6 && c.bits == b.len6 && c.dst == b.net6 && metric_is_zero(metric) {
			note(b, .Skipped_Connected, "route %s/%d was skipped because it is the tunnel's own network", addr_text(c.dst, true), c.bits)
			return
		}
		// A tunnel route to the server's own host address would loop.
		if srv, v6, known := server_bytes(b); known && v6 == c.v6 && c.bits == full_bits(v6) && c.dst == srv {
			note(b, .Skipped_Server_Host, "route %s/%d points to the VPN server itself, so it is not sent into the tunnel", addr_text(c.dst, v6), c.bits)
			return
		}
	}
	for s in b.routes {
		r := s.route
		if route_is_v6(r) == c.v6 && s.on_tun == hop.on_tun && r.dst_len == c.bits && r.metric == metric {
			d, _, _ := addr_bytes(r.dst)
			if d == c.dst {
				note(b, .Skipped_Duplicate, "route %s/%d is listed twice, so only the first one is used", addr_text(c.dst, c.v6), c.bits)
				return
			}
		}
	}

	append(
		&b.routes,
		Step {
			kind = .Add_Route,
			route = sysnet.Route {
				dst = to_addr(c.dst, c.v6),
				dst_len = c.bits,
				gateway = hop.gateway,
				ifindex = hop.ifindex,
				metric = metric,
				table = b.table,
				protocol = ROUTE_PROTOCOL,
				onlink = hop.onlink,
			},
			on_tun = hop.on_tun,
			// A default route, or half of one, pushed as a plain route is a redirect.
			critical = c.bits <= 1 && hop.on_tun,
			why = c.why,
		},
	)
}

@(private)
dst4 :: proc "contextless" (c: Cand) -> [4]u8 {
	return {c.dst[0], c.dst[1], c.dst[2], c.dst[3]}
}

// No metric, or 0: the same as the kernel's own routes have.
@(private)
metric_is_zero :: proc "contextless" (m: Maybe(u32)) -> bool {
	v, _ := m.?
	return v == 0
}

@(private)
server_bytes :: proc "contextless" (b: ^Builder) -> (a: [16]u8, v6: bool, ok: bool) {
	s, has := b.input.server.?
	if !has {
		return {}, false, false
	}
	return addr_bytes(s)
}

// ---- pin, redirect, block ----

@(private)
Redirect :: struct {
	set:   bool,
	flags: config.Redirect_Flags,
}

// The effective `redirect-gateway` or `redirect-private`: the local option
// plus the pushed one (unless `route-nopull`).
@(private)
effective_redirect :: proc(b: ^Builder, private: bool) -> (r: Redirect) {
	cfg := b.input.cfg
	po := b.input.pushed
	local_set := cfg.redirect_private_set if private else cfg.redirect_gateway_set
	local_flags := cfg.redirect_private if private else cfg.redirect_gateway
	pushed := po.redirect_private if private else po.redirect_gateway
	r.set = local_set
	r.flags = local_flags
	if pushed.set {
		if b.pull_routes {
			r.set = true
			for f in pushed.flags {
				r.flags += {config.Redirect_Flag(f)}
			}
		} else {
			note(b, .Dropped_By_Nopull, "the pushed %s was ignored because route-nopull is set", "redirect-private" if private else "redirect-gateway")
		}
	}
	return
}

@(private)
finish_routes :: proc(b: ^Builder) -> Plan_Error {
	p := b.plan
	if b.input.cfg.route_noexec {
		note(b, .Info, "route-noexec is set, so no routes will be added")
		return .None
	}

	rg := effective_redirect(b, false)
	rp := effective_redirect(b, true)
	redirect4 := rg.set && .Not_Ipv4 not_in rg.flags
	redirect6 := rg.set && .Ipv6 in rg.flags
	if rp.set {
		note(b, .Not_Implemented, "redirect-private does not change any route because it never replaces the default gateway")
	}
	all_flags := rg.flags + rp.flags
	if .Block_Local in all_flags {
		note(b, .Not_Implemented, "redirect-gateway block-local has no effect on Linux")
	}
	if .Bypass_Dhcp in all_flags || .Bypass_Dns in all_flags {
		note(b, .Not_Implemented, "redirect-gateway bypass-dhcp and bypass-dns have no effect on Linux")
	}

	// Redirect routes first, so the pin knows whether it is needed.
	redirect_steps := make([dynamic]Step, b.alloc)
	defer delete(redirect_steps)
	if rg.set {
		if redirect4 {
			build_redirect(b, false, rg.flags, &redirect_steps)
		}
		if redirect6 {
			build_redirect(b, true, rg.flags, &redirect_steps)
		}
	}
	p.redirect4 = redirect4
	p.redirect6 = redirect6

	// The pin.
	if srv, has := b.input.server.?; has {
		sb, srv6, _ := addr_bytes(srv)
		redirect_needs := redirect6 if srv6 else redirect4
		skip_local := .Local in rg.flags
		if sr, ok := b.input.server_route.?; ok && .Autolocal in rg.flags && sr.gateway == nil {
			skip_local = true
		}
		route_needs := false
		for s in b.routes {
			if !s.on_tun || route_is_v6(s.route) != srv6 {
				continue
			}
			d, _, _ := addr_bytes(s.route.dst)
			if prefix_covers(d[:], int(s.route.dst_len), sb[:]) {
				route_needs = true
			}
		}
		if (redirect_needs && !skip_local) || route_needs {
			sr, have := b.input.server_route.?
			if !have || (sr.family == .V6) != srv6 {
				return .No_Server_Route
			}
			switch sr.kind {
			case .Local:
				note(b, .Info, "the server address is on this machine, so no host route is needed")
			case .Unicast:
				append(
					&p.steps,
					Step {
						kind = .Add_Route,
						route = sysnet.Route {
							dst = srv,
							dst_len = full_bits(srv6),
							gateway = sr.gateway,
							ifindex = sr.ifindex,
							table = b.table,
							protocol = ROUTE_PROTOCOL,
						},
						critical = true,
						why = .Server_Pin,
					},
				)
				p.pinned = srv
			case .Blackhole, .Unreachable, .Prohibit, .Other:
				return .No_Server_Route
			}
		}
	}

	for s in b.routes {
		append(&p.steps, s)
	}
	for s in redirect_steps {
		append(&p.steps, s)
	}

	return .None
}

// The redirect routes of one family.
@(private)
build_redirect :: proc(b: ^Builder, v6: bool, flags: config.Redirect_Flags, out: ^[dynamic]Step) {
	gw := vpn_gateway(b, v6)
	default_route := b.input.default6 if v6 else b.input.default4

	half :: proc(b: ^Builder, v6: bool, gw: Maybe(sysnet.Address), low: bool) -> Step {
		dst: sysnet.Address
		if v6 {
			dst = sysnet.IP6_Address{} if low else sysnet.IP6_Address{0x8000, 0, 0, 0, 0, 0, 0, 0}
		} else {
			dst = sysnet.IP4_Address{0, 0, 0, 0} if low else sysnet.IP4_Address{128, 0, 0, 0}
		}
		return Step {
			kind = .Add_Route,
			route = sysnet.Route {
				dst = dst,
				dst_len = 1,
				gateway = gw,
				metric = b.metric,
				table = b.table,
				protocol = ROUTE_PROTOCOL,
				onlink = gw != nil,
			},
			on_tun = true,
			critical = true,
			why = .Redirect_Low if low else .Redirect_High,
		}
	}

	use_def1 := .Def1 in flags
	if !use_def1 {
		d, has := default_route.?
		if has && metric_of(d) == 0 {
			// There is no metric below 0 to put a default route under.
			note(
				b,
				.Redirect_Used_Def1,
				"the current default route has metric 0, so redirect-gateway uses two half routes (def1) instead of one default route",
			)
			use_def1 = true
		} else {
			// One default route, with a metric one below the current default
			// route. Nothing is deleted, so a crash leaves a working network.
			m := b.metric
			if has {
				m = metric_of(d) - 1
			}
			append(
				out,
				Step {
					kind = .Add_Route,
					route = sysnet.Route {
						dst = sysnet.default_dst(.V6 if v6 else .V4),
						dst_len = 0,
						gateway = gw,
						metric = m,
						table = b.table,
						protocol = ROUTE_PROTOCOL,
						onlink = gw != nil,
					},
					on_tun = true,
					critical = true,
					why = .Redirect_Default,
				},
			)
			return
		}
	}
	append(out, half(b, v6, gw, true))
	append(out, half(b, v6, gw, false))
}
