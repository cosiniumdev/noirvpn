// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:strings"
import "core:testing"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/push"

// The DNS step for the pushed options alone, as the plan built it before the
// local lines joined. The tests compare the plan with it for configs that
// have no local DNS line.
@(private = "file")
pushed_only_dns :: proc(b: ^Builder) {
	po := b.input.pushed
	p := b.plan
	pushed_any := len(po.dns_servers) > 0 || len(po.dhcp_dns) > 0 || len(po.dns_search_domains) > 0 || len(po.dhcp_domains) > 0
	if !b.pull_routes {
		if pushed_any {
			note(b, .Dropped_By_Nopull, "the pushed DNS options were ignored because route-nopull is set")
		}
		return
	}
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
	if len(po.dns_servers) > 0 {
		for g in po.dns_servers {
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
		for ip in po.dhcp_dns {
			add_server(&servers, ip, 0)
		}
	}
	for d in po.dns_search_domains {
		add_domain(b, &search, d)
	}
	for d in po.dhcp_domains {
		add_domain(b, &search, d)
	}
	if len(servers) == 0 {
		for d in search {
			delete(d, b.alloc)
		}
		for d in routing {
			delete(d, b.alloc)
		}
		return
	}
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

@(private = "file")
dns_equal :: proc(a, b: sysnet.DNS_Settings) -> bool {
	if a.default_route != b.default_route || len(a.servers) != len(b.servers) || len(a.search_domains) != len(b.search_domains) || len(a.routing_domains) != len(b.routing_domains) {
		return false
	}
	for s, i in a.servers {
		if s != b.servers[i] {
			return false
		}
	}
	for s, i in a.search_domains {
		if s != b.search_domains[i] {
			return false
		}
	}
	for s, i in a.routing_domains {
		if s != b.routing_domains[i] {
			return false
		}
	}
	return true
}

// Applies the `pull-filter` lines of the config to the push text, as the
// daemon does before the push parser.
@(private = "file")
dns_plan :: proc(t: ^testing.T, conf, push_text: string, loc := #caller_location) -> (plan: Plan, err: Plan_Error) {
	cfg := load_client("remote vpn.example 1194 udp", conf)
	defer config.destroy(&cfg)
	if !expect_config_ok(t, &cfg, loc) {
		return {}, .No_Address
	}
	res, ok := pull_filter_options(cfg.client.pull_filters, push_text)
	defer delete(res.options)
	testing.expect(t, ok, loc = loc)
	po: push.Pushed_Options
	testing.expect_value(t, push.pushed_options_parse(&po, res.options), push.Error.None, loc = loc)
	defer push.pushed_options_destroy(&po)
	return plan_build(default_input(&cfg.client, &po))
}

@(private = "file")
expect_servers :: proc(t: ^testing.T, plan: ^Plan, want: []sysnet.DNS_Server, loc := #caller_location) {
	testing.expect(t, plan.has_dns, loc = loc)
	got := plan.dns.servers
	same := len(got) == len(want)
	for w, i in want {
		if same && got[i] != w {
			same = false
		}
	}
	testing.expectf(t, same, "servers: got %v, want %v", got, want, loc = loc)
}

@(private = "file")
expect_domains :: proc(t: ^testing.T, got, want: []string, loc := #caller_location) {
	testing.expectf(
		t,
		strings.join(got, " ", context.temp_allocator) == strings.join(want, " ", context.temp_allocator),
		"domains: got %v, want %v",
		got,
		want,
		loc = loc,
	)
}

@(private = "file")
v4 :: proc(a, b, c, d: u8, port: u16 = 0) -> sysnet.DNS_Server {
	return sysnet.DNS_Server{sysnet.IP4_Address{a, b, c, d}, port}
}

// A config with no local DNS line gives the plan of the pushed options
// alone, for each form of the push, also with route-nopull and pull-filter.
@(test)
plan_dns_without_local_lines_is_unchanged :: proc(t: ^testing.T) {
	pushes := []string {
		BASE,
		BASE + ",dhcp-option DNS 10.8.0.1",
		BASE + ",dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00:8::53,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example,dhcp-option DOMAIN-SEARCH lan.example,dhcp-option DOMAIN CORP.example,dhcp-option NBT 2",
		BASE + ",redirect-gateway def1,dhcp-option DNS 10.8.0.1",
		BASE + ",dns server 10 address 10.8.0.10,dns server 0 address 10.8.0.1 [fd00:8::53]:5353,dns server 0 resolve-domains corp.example,dns search-domains a.example b.example,dhcp-option DNS 9.9.9.9,dhcp-option DOMAIN old.example",
		BASE + ",dns server 1 address 10.8.0.1,dns server 1 transport DoT,dns server 2 address 10.8.0.2",
		BASE + ",dns server 1 address 10.8.0.1,dns server 1 transport DoH",
		BASE + ",dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN -evil.example,dhcp-option DOMAIN good.example",
		BASE + ",dhcp-option DOMAIN corp.example",
		BASE + ",dns search-domains a.example",
	}
	confs := []string {
		"",
		"route-nopull",
		"pull-filter ignore \"dhcp-option DNS\"\npull-filter ignore \"dhcp-option DOMAIN\"\npull-filter ignore \"dns\"",
		"pull-filter ignore \"dns server 0\"",
		"redirect-gateway def1\nroute 192.0.2.0 255.255.255.0",
	}
	for conf in confs {
		for push_text in pushes {
			cfg := load_client("remote vpn.example 1194 udp", conf)
			defer config.destroy(&cfg)
			if !expect_config_ok(t, &cfg) {
				continue
			}
			testing.expect_value(t, len(cfg.client.dns_options), 0)
			res, _ := pull_filter_options(cfg.client.pull_filters, push_text)
			defer delete(res.options)
			po: push.Pushed_Options
			testing.expect_value(t, push.pushed_options_parse(&po, res.options), push.Error.None)
			defer push.pushed_options_destroy(&po)
			input := default_input(&cfg.client, &po)

			plan, err := plan_build(input)
			defer plan_destroy(&plan)
			testing.expect_value(t, err, Plan_Error.None)

			ref := Plan {
				allocator = context.allocator,
				notes     = make([dynamic]Note),
				redirect4 = plan.redirect4,
				redirect6 = plan.redirect6,
			}
			defer plan_destroy(&ref)
			rb := Builder {
				input       = input,
				plan        = &ref,
				alloc       = context.allocator,
				pull_routes = !cfg.client.route_nopull,
			}
			pushed_only_dns(&rb)

			testing.expectf(t, plan.has_dns == ref.has_dns, "has_dns differs: conf %q push %q", conf, push_text)
			testing.expectf(t, dns_equal(plan.dns, ref.dns), "DNS differs: conf %q push %q\n  got  %v\n  want %v", conf, push_text, plan.dns, ref.dns)
			// The DNS step runs last, so its notes end the list.
			n := len(ref.notes)
			if !testing.expectf(t, len(plan.notes) >= n, "notes: conf %q push %q", conf, push_text) {
				continue
			}
			tail := plan.notes[len(plan.notes) - n:]
			for rn, i in ref.notes {
				testing.expectf(t, tail[i].kind == rn.kind && tail[i].text == rn.text, "note differs: %v %q, want %v %q", tail[i].kind, tail[i].text, rn.kind, rn.text)
			}
		}
	}
}

@(test)
plan_dns_local_only :: proc(t: ^testing.T) {
	// v2 lines.
	{
		conf := "dns server 0 address 192.0.2.53 [2001:db8::53]:5353\ndns server 0 resolve-domains home.example\ndns search-domains home.example lab.example"
		plan, err := dns_plan(t, conf, BASE)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_servers(t, &plan, {v4(192, 0, 2, 53), {sysnet.IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53}, 5353}})
		expect_domains(t, plan.dns.search_domains, {"home.example", "lab.example"})
		expect_domains(t, plan.dns.routing_domains, {"home.example"})
	}
	// dhcp-option lines. DNS6 takes an IPv4 address, as in OpenVPN.
	{
		conf := "dhcp-option DNS 192.0.2.53\ndhcp-option DNS fd00::53\ndhcp-option DNS6 192.0.2.54\ndhcp-option DOMAIN home.example\ndhcp-option WINS 192.0.2.1"
		plan, err := dns_plan(t, conf, BASE)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_servers(t, &plan, {v4(192, 0, 2, 53), {sysnet.IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 0x53}, 0}, v4(192, 0, 2, 54)})
		expect_domains(t, plan.dns.search_domains, {"home.example"})
	}
	// The lines that the desktop client writes for its overrides.
	{
		conf := "dhcp-option DOMAIN lab.example.org\ndns server 0 address 9.9.9.9\ndns server 1 address 2620:fe::fe"
		plan, err := dns_plan(t, conf, BASE + ",redirect-gateway def1")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_servers(t, &plan, {v4(9, 9, 9, 9), {sysnet.IP6_Address{0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe}, 0}})
		expect_domains(t, plan.dns.search_domains, {"lab.example.org"})
		testing.expect(t, plan.dns.default_route)
		testing.expect_value(t, sysnet.dns_settings_check(plan.dns), sysnet.DNS_Error.None)
	}
	// Local domains without a server do nothing, as pushed ones.
	{
		plan, err := dns_plan(t, "dhcp-option DOMAIN home.example", BASE)
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		testing.expect(t, !plan.has_dns)
	}
}

@(test)
plan_dns_pushed_only :: proc(t: ^testing.T) {
	plan, err := dns_plan(t, "route 192.0.2.0 255.255.255.0", BASE + ",dns server 1 address 10.8.0.1,dhcp-option DOMAIN corp.example")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_servers(t, &plan, {v4(10, 8, 0, 1)})
	expect_domains(t, plan.dns.search_domains, {"corp.example"})
}

@(test)
plan_dns_same_number_pushed_replaces_local :: proc(t: ^testing.T) {
	conf := "dns server 1 address 192.0.2.53\ndns server 1 resolve-domains home.example"
	plan, err := dns_plan(t, conf, BASE + ",dns server 1 address 10.8.0.1")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_servers(t, &plan, {v4(10, 8, 0, 1)})
	// The whole local group goes, also its routing domains.
	testing.expect_value(t, len(plan.dns.routing_domains), 0)
	expect_note(t, &plan, .Info)
}

@(test)
plan_dns_different_numbers_by_order :: proc(t: ^testing.T) {
	// A local group with a lower number comes first, one with a higher number
	// after the pushed ones.
	conf := "dns server -1 address 192.0.2.1\ndns server 20 address 192.0.2.20\ndns server 5 address 192.0.2.5"
	push_text := BASE + ",dns server 10 address 10.8.0.10,dns server 0 address 10.8.0.1"
	plan, err := dns_plan(t, conf, push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_servers(t, &plan, {v4(192, 0, 2, 1), v4(10, 8, 0, 1), v4(192, 0, 2, 5), v4(10, 8, 0, 10), v4(192, 0, 2, 20)})
}

@(test)
plan_dns_local_group_before_pushed_dhcp :: proc(t: ^testing.T) {
	// A `dns server` group, local or pushed, turns off every `dhcp-option
	// DNS` server (the rule of OpenVPN). The domains stay.
	{
		conf := "dns server 0 address 192.0.2.53\ndhcp-option DNS 192.0.2.54"
		plan, err := dns_plan(t, conf, BASE + ",dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_servers(t, &plan, {v4(192, 0, 2, 53)})
		expect_domains(t, plan.dns.search_domains, {"corp.example"})
	}
	{
		plan, err := dns_plan(t, "dhcp-option DNS 192.0.2.54", BASE + ",dns server 0 address 10.8.0.1")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_servers(t, &plan, {v4(10, 8, 0, 1)})
	}
	// Without groups, the local dhcp-option servers come first.
	{
		plan, err := dns_plan(t, "dhcp-option DNS 192.0.2.54", BASE + ",dhcp-option DNS 10.8.0.1,dhcp-option DNS 192.0.2.54")
		defer plan_destroy(&plan)
		testing.expect_value(t, err, Plan_Error.None)
		expect_servers(t, &plan, {v4(192, 0, 2, 54), v4(10, 8, 0, 1)})
	}
}

@(test)
plan_dns_local_lines_stay_with_route_nopull :: proc(t: ^testing.T) {
	conf := "route-nopull\ndns server 0 address 192.0.2.53\ndhcp-option DOMAIN home.example"
	plan, err := dns_plan(t, conf, BASE + ",dns server 0 address 10.8.0.1,dhcp-option DNS 10.8.0.2,dhcp-option DOMAIN corp.example")
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_servers(t, &plan, {v4(192, 0, 2, 53)})
	expect_domains(t, plan.dns.search_domains, {"home.example"})
	expect_note(t, &plan, .Dropped_By_Nopull)
}

@(test)
plan_dns_local_lines_stay_with_pull_filter :: proc(t: ^testing.T) {
	// "Do not use the DNS settings of the server" and two overrides.
	conf := "pull-filter ignore \"dhcp-option DNS\"\npull-filter ignore \"dhcp-option DOMAIN\"\npull-filter ignore \"dns\"\ndhcp-option DOMAIN home.example\ndns server 0 address 192.0.2.53"
	push_text := BASE + ",dns server 0 address 10.8.0.1,dns search-domains corp.example,dhcp-option DNS 10.8.0.2,dhcp-option DOMAIN old.example"
	plan, err := dns_plan(t, conf, push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_servers(t, &plan, {v4(192, 0, 2, 53)})
	expect_domains(t, plan.dns.search_domains, {"home.example"})
	testing.expect(t, !has_note(&plan, .Info))
}

@(test)
plan_dns_domains_join :: proc(t: ^testing.T) {
	// Each kind: local first, then pushed. `dns search-domains` before
	// `dhcp-option DOMAIN`. A name is kept once.
	conf := "dhcp-option DOMAIN home.example\ndhcp-option DOMAIN-SEARCH CORP.example\ndns search-domains lab.example"
	push_text := BASE + ",dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example,dns search-domains a.example"
	plan, err := dns_plan(t, conf, push_text)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	expect_servers(t, &plan, {v4(10, 8, 0, 1)})
	expect_domains(t, plan.dns.search_domains, {"lab.example", "a.example", "home.example", "CORP.example"})
}

@(test)
plan_dns_bad_local_lines_are_dropped :: proc(t: ^testing.T) {
	conf := "dns server 0 address 192.0.2.300\ndns server 1 transport DoT\ndns server 1 address 192.0.2.1\ndns server 2 frobnicate x\ndns server 3 dnssec maybe\ndns server 4 resolve-domains home.example\ndhcp-option DNS not-an-ip\ndhcp-option DOMAIN -bad.example\ndns server 5 address 192.0.2.5"
	plan, err := dns_plan(t, conf, BASE)
	defer plan_destroy(&plan)
	testing.expect_value(t, err, Plan_Error.None)
	// Group 1 is DoT and is skipped; groups 0, 2, 3 and 4 have no address.
	expect_servers(t, &plan, {v4(192, 0, 2, 5)})
	expect_note(t, &plan, .Skipped_DNS_Group)
	adjusted := 0
	for n in plan.notes {
		if n.kind == .Adjusted {
			adjusted += 1
		}
	}
	// Four bad lines, one group with no address (4), one bad domain.
	testing.expect_value(t, adjusted, 4 + 1 + 1)
	testing.expect_value(t, len(plan.dns.search_domains), 0)
}
