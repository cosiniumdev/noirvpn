// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:slice"
import "core:strconv"
import "core:strings"
import "noir:platform/sysnet"
import "noir:proto/push"

// DNS part of the plan. Merges local `dns` and `dhcp-option` lines with pushed
// ones, by OpenVPN 2.6 rules (`src/openvpn/dns.c`, `options.c`).
// Servers:
//   - Use `dns server <prio> address ...` groups (newer than 2.6) if any exist,
//     local or pushed; else `dhcp-option DNS` / `DNS6`. So a local `dns server`
//     group also turns off pushed `dhcp-option DNS`.
//   - Merge local and pushed groups by priority, lowest first. A pushed group
//     replaces the local group of the same priority.
//   - Groups go in priority order into one list (resolvers take one server list
//     per link).
//   - Skip DoH and DoT groups (backends do plain DNS only).
//   - `dhcp-option DNS`: local servers, then pushed.
// Search domains: `dns search-domains` (local, then pushed), then
// `dhcp-option DOMAIN` in all forms (local, then pushed). Upstream keeps one
// `DOMAIN` value; here each value is a search domain.
// Routing domains: `resolve-domains` of the groups used.
// `default_route` is set when the plan sends all traffic through the tunnel
// (`redirect-gateway`): every query goes to the VPN servers too.
// SPEC-GAP: groups with different `resolve-domains` cannot each get their own
// domains from a per-link resolver. All servers serve all those domains.
// `route-nopull` drops pushed DNS options (man page: "dhcp options like DNS
// servers"). `pull-filter` drops pushed options before parsing. Neither changes
// the local lines.

@(private)
build_dns :: proc(b: ^Builder) {
	po := b.input.pushed
	p := b.plan
	pushed_any := len(po.dns_servers) > 0 || len(po.dhcp_dns) > 0 || len(po.dns_search_domains) > 0 || len(po.dhcp_domains) > 0
	if !b.pull_routes && pushed_any {
		note(b, .Dropped_By_Nopull, "the pushed DNS options were ignored because route-nopull is set")
	}

	local := local_dns_parse(b)
	defer local_dns_destroy(&local)

	// The pushed lists; empty with route-nopull.
	p_groups: []push.Dns_Server
	p_dhcp_dns: []push.Ip_Addr
	p_search: []string
	p_dhcp_domains: []string
	if b.pull_routes {
		p_groups = po.dns_servers[:]
		p_dhcp_dns = po.dhcp_dns[:]
		p_search = po.dns_search_domains[:]
		p_dhcp_domains = po.dhcp_domains[:]
	}

	groups := merge_dns_groups(b, local.groups[:], p_groups)
	defer delete(groups)

	servers := make([dynamic]sysnet.DNS_Server, b.alloc)
	search := make([dynamic]string, b.alloc)
	routing := make([dynamic]string, b.alloc)
	defer delete(servers)
	defer delete(search)
	defer delete(routing)

	add_server :: proc(list: ^[dynamic]sysnet.DNS_Server, ip: push.Ip_Addr, port: u16) {
		sv := sysnet.DNS_Server {
			address = to_addr(ip.bytes, ip.v6),
			port    = port,
		}
		for e in list {
			if e == sv {
				return
			}
		}
		append(list, sv)
	}

	if len(groups) > 0 {
		for g in groups {
			if g.transport == .Doh || g.transport == .Dot {
				note(b, .Skipped_DNS_Group, "dns server group %d was skipped because only plain DNS is supported", g.prio)
				continue
			}
			for a in g.addresses {
				add_server(&servers, a.ip, a.port)
			}
			for d in g.resolve_domains {
				add_domain(b, &routing, d)
			}
		}
	} else {
		for ip in local.dhcp_dns {
			add_server(&servers, ip, 0)
		}
		for ip in p_dhcp_dns {
			add_server(&servers, ip, 0)
		}
	}
	for d in local.search {
		add_domain(b, &search, d)
	}
	for d in p_search {
		add_domain(b, &search, d)
	}
	for d in local.dhcp_domains {
		add_domain(b, &search, d)
	}
	for d in p_dhcp_domains {
		add_domain(b, &search, d)
	}

	if len(servers) == 0 {
		// Domains without a server do nothing.
		for d in search {
			delete(d, b.alloc)
		}
		for d in routing {
			delete(d, b.alloc)
		}
		return
	}
	// Exact-size slices that the plan owns (`plan_destroy` frees them). The
	// strings were cloned by `add_domain`; the dynamic arrays go away.
	s := sysnet.DNS_Settings {
		servers         = make([]sysnet.DNS_Server, len(servers), b.alloc),
		search_domains  = make([]string, len(search), b.alloc),
		routing_domains = make([]string, len(routing), b.alloc),
		default_route   = p.redirect4 || p.redirect6,
	}
	copy(s.servers, servers[:])
	copy(s.search_domains, search[:])
	copy(s.routing_domains, routing[:])
	p.dns = s
	p.has_dns = true
}

// The local `dns` and `dhcp-option` lines of the config. The strings belong
// to the config.
@(private)
Local_DNS :: struct {
	// By priority, lowest first. Each group has at least one address.
	groups:       [dynamic]push.Dns_Server,
	dhcp_dns:     [dynamic]push.Ip_Addr,
	dhcp_domains: [dynamic]string,
	search:       [dynamic]string,
}

@(private)
local_dns_destroy :: proc(l: ^Local_DNS) {
	for g in l.groups {
		delete(g.addresses)
		delete(g.resolve_domains)
	}
	delete(l.groups)
	delete(l.dhcp_dns)
	delete(l.dhcp_domains)
	delete(l.search)
}

// Reads the local lines.
// - The config build already checked the form of `dns` (sub-option and
//   priority range). The values are checked here.
// - An invalid line is dropped with a note. The other lines stay.
@(private)
local_dns_parse :: proc(b: ^Builder) -> (l: Local_DNS) {
	l.groups = make([dynamic]push.Dns_Server, b.alloc)
	l.dhcp_dns = make([dynamic]push.Ip_Addr, b.alloc)
	l.dhcp_domains = make([dynamic]string, b.alloc)
	l.search = make([dynamic]string, b.alloc)
	for o in b.input.cfg.dns_options {
		ok := true
		switch o.name {
		case "dns":
			ok = local_dns_line(b, &l, o.args)
		case "dhcp-option":
			ok = local_dhcp_line(&l, o.args)
		}
		if !ok {
			note(b, .Adjusted, "a local line was dropped because it is not valid: %s %s", o.name, strings.join(o.args, " ", context.temp_allocator))
		}
	}
	i := 0
	for i < len(l.groups) {
		g := l.groups[i]
		if len(g.addresses) > 0 {
			i += 1
			continue
		}
		note(b, .Adjusted, "local dns server group %d was dropped because it has no address", g.prio)
		delete(g.addresses)
		delete(g.resolve_domains)
		ordered_remove(&l.groups, i)
	}
	slice.stable_sort_by(l.groups[:], proc(a, c: push.Dns_Server) -> bool {
		return a.prio < c.prio
	})
	return l
}

// One `dns ...` line: `search-domains D...` or `server N KEYWORD ARGS...`.
@(private)
local_dns_line :: proc(b: ^Builder, l: ^Local_DNS, args: []string) -> bool {
	if len(args) < 2 {
		return false
	}
	switch args[0] {
	case "search-domains":
		append(&l.search, ..args[1:])
		return true
	case "server":
	case:
		return false
	}
	if len(args) < 4 {
		return false
	}
	prio, pok := strconv.parse_int(args[1], 10)
	if !pok || prio < -128 || prio > 127 {
		return false
	}
	keyword, vals := args[2], args[3:]
	one := len(vals) == 1
	// Check the values before the group is created, so that a bad line changes
	// nothing.
	addrs: [push.MAX_DNS_ADDRESSES]push.Dns_Address
	dnssec: push.Dns_Dnssec
	transport: push.Dns_Transport
	switch keyword {
	case "address":
		if len(vals) > len(addrs) {
			return false
		}
		for v, k in vals {
			a, ok := push.parse_dns_address(v)
			if !ok {
				return false
			}
			addrs[k] = a
		}
	case "resolve-domains":
	case "dnssec":
		switch {
		case one && vals[0] == "yes":
			dnssec = .Yes
		case one && vals[0] == "no":
			dnssec = .No
		case one && vals[0] == "optional":
			dnssec = .Optional
		case:
			return false
		}
	case "transport":
		switch {
		case one && vals[0] == "plain":
			transport = .Plain
		case one && vals[0] == "DoH":
			transport = .Doh
		case one && vals[0] == "DoT":
			transport = .Dot
		case:
			return false
		}
	case "sni":
		if !one {
			return false
		}
	case:
		return false
	}

	g := local_dns_group(b, l, prio)
	switch keyword {
	case "address":
		if len(g.addresses) + len(vals) > push.MAX_DNS_ADDRESSES {
			return false
		}
		append(&g.addresses, ..addrs[:len(vals)])
	case "resolve-domains":
		append(&g.resolve_domains, ..vals)
	case "dnssec":
		g.dnssec = dnssec
	case "transport":
		g.transport = transport
	case "sni":
		g.sni = vals[0]
	}
	return true
}

@(private)
local_dns_group :: proc(b: ^Builder, l: ^Local_DNS, prio: int) -> ^push.Dns_Server {
	for &g in l.groups {
		if g.prio == prio {
			return &g
		}
	}
	append(
		&l.groups,
		push.Dns_Server {
			prio = prio,
			addresses = make([dynamic]push.Dns_Address, b.alloc),
			resolve_domains = make([dynamic]string, b.alloc),
		},
	)
	return &l.groups[len(l.groups) - 1]
}

// One `dhcp-option TYPE VALUE` line.
// - As in OpenVPN, `DNS` and `DNS6` both take an address of either family.
// - The types for WINS, NetBIOS and proxies have no effect and are no error.
@(private)
local_dhcp_line :: proc(l: ^Local_DNS, args: []string) -> bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "DOMAIN", "ADAPTER_DOMAIN_SUFFIX", "DOMAIN-SEARCH":
		if len(args) != 2 || args[1] == "" {
			return false
		}
		append(&l.dhcp_domains, args[1])
	case "DNS", "DNS6":
		if len(args) != 2 {
			return false
		}
		ip: push.Ip_Addr
		if a4, ok := push.parse_ipv4(args[1]); ok {
			copy(ip.bytes[:4], a4[:])
		} else if a6, ok6 := push.parse_ipv6(args[1]); ok6 {
			ip = push.Ip_Addr {
				v6    = true,
				bytes = a6,
			}
		} else {
			return false
		}
		append(&l.dhcp_dns, ip)
	}
	return true
}

// The local and pushed groups in one list, by priority, lowest first.
// - A pushed group replaces the local group with the same priority.
// - Both input lists are sorted.
// - The result shares the arrays of the groups.
@(private)
merge_dns_groups :: proc(b: ^Builder, local, pushed: []push.Dns_Server) -> [dynamic]push.Dns_Server {
	out := make([dynamic]push.Dns_Server, 0, len(local) + len(pushed), b.alloc)
	i, j := 0, 0
	for i < len(local) || j < len(pushed) {
		switch {
		case j == len(pushed) || (i < len(local) && local[i].prio < pushed[j].prio):
			append(&out, local[i])
			i += 1
		case i < len(local) && local[i].prio == pushed[j].prio:
			note(b, .Info, "local dns server group %d was replaced by the pushed group with the same number", local[i].prio)
			append(&out, pushed[j])
			i += 1
			j += 1
		case:
			append(&out, pushed[j])
			j += 1
		}
	}
	return out
}

// Add a domain once (compared without regard to case). Names the resolver
// backends cannot take safely are dropped with a note.
@(private)
add_domain :: proc(b: ^Builder, list: ^[dynamic]string, d: string) {
	if !sysnet.dns_valid_domain(d) {
		note(b, .Adjusted, "DNS domain %q was dropped because it is not a valid name", d)
		return
	}
	for e in list {
		if strings.equal_fold(e, d) {
			return
		}
	}
	append(list, strings.clone(d, b.alloc))
}
