// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:strings"
import "core:testing"
import "noir:platform/sysnet"

@(private = "file")
GW4 :: sysnet.IP4_Address{192, 0, 2, 1}
@(private = "file")
SRV4 :: sysnet.IP4_Address{198, 51, 100, 7}

@(private = "file")
sample_record :: proc(r: ^Record) {
	record_init(r)
	r.pid = 4242
	r.name = strings.clone("office vpn")
	r.role = .Client
	record_add_dev(r, 7, "tun0")
	record_add_route(r, sysnet.Route{dst = SRV4, dst_len = 32, gateway = sysnet.Address(GW4), ifindex = 2, protocol = ROUTE_PROTOCOL}, "eth0")
	record_add_route(r, sysnet.Route{dst = sysnet.IP4_Address{}, dst_len = 1, ifindex = 7, metric = 100, protocol = ROUTE_PROTOCOL}, "tun0")
	record_add_route(
		r,
		sysnet.Route{dst = sysnet.IP6_Address{0x8000, 0, 0, 0, 0, 0, 0, 0}, dst_len = 1, gateway = sysnet.Address(sysnet.IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 1}), ifindex = 7, table = 100, protocol = ROUTE_PROTOCOL},
		"tun0",
	)
	record_add_dns(r, "resolvconf", "tun0", "record tun0.noirvpn")
}

@(test)
record_round_trip :: proc(t: ^testing.T) {
	r: Record
	sample_record(&r)
	defer record_destroy(&r)
	text := record_encode(&r)
	defer delete(text)
	testing.expect(t, strings.has_prefix(text, "noirvpn-state 1\npid 4242\nname office vpn\nrole client\ndev 7 tun0\n"))
	testing.expect(t, strings.contains(text, "route 4 198.51.100.7/32 192.0.2.1 254 - 2 eth0\n"))
	testing.expect(t, strings.contains(text, "route 4 0.0.0.0/1 - 254 100 7 tun0\n"))
	testing.expect(t, strings.has_suffix(text, "dns resolvconf tun0 record tun0.noirvpn\nend\n"))

	back, err := record_decode(text)
	defer record_destroy(&back)
	testing.expect_value(t, err, Record_Error.None)
	testing.expect_value(t, back.pid, 4242)
	testing.expect_value(t, back.name, "office vpn")
	testing.expect_value(t, back.role, Record_Role.Client)
	testing.expect_value(t, len(back.devs), 1)
	testing.expect_value(t, len(back.routes), 3)
	testing.expect_value(t, len(back.dns), 1)
	for e, i in r.routes {
		testing.expectf(t, record_route_match(e.route, back.routes[i].route), "route %d differs: %v", i, back.routes[i].route)
		testing.expect_value(t, back.routes[i].dev, e.dev)
	}
	testing.expect_value(t, back.routes[2].route.table, 100)
	testing.expect_value(t, back.dns[0], Record_DNS{backend = "resolvconf", ifname = "tun0", detail = "record tun0.noirvpn"})
	again := record_encode(&back)
	defer delete(again)
	testing.expect_value(t, again, text)
}

@(test)
record_a_cut_text_is_refused :: proc(t: ^testing.T) {
	r: Record
	sample_record(&r)
	defer record_destroy(&r)
	text := record_encode(&r)
	defer delete(text)
	for n in 0 ..< len(text) {
		back, err := record_decode(text[:n])
		testing.expectf(t, err == .Truncated, "a text cut at %d gives %v", n, err)
		testing.expect_value(t, len(back.routes), 0)
	}
}

// The partial read keeps the complete lines before the cut.
@(test)
record_a_cut_text_keeps_its_first_lines :: proc(t: ^testing.T) {
	r: Record
	sample_record(&r)
	defer record_destroy(&r)
	text := record_encode(&r)
	defer delete(text)
	for n in 0 ..< len(text) {
		back, err := record_decode_partial(text[:n])
		testing.expectf(t, err == .Truncated, "a text cut at %d gives %v", n, err)
		lines := strings.count(text[:n], "\n")
		want_routes := 0
		for line, i in strings.split_lines(text, context.temp_allocator) {
			if i < lines && strings.has_prefix(line, "route ") {
				want_routes += 1
			}
		}
		testing.expectf(t, len(back.routes) == want_routes, "a text cut at %d gives %d routes, want %d", n, len(back.routes), want_routes)
		record_destroy(&back)
	}
	full, err := record_decode_partial(text)
	testing.expect_value(t, err, Record_Error.None)
	testing.expect_value(t, len(full.routes), len(r.routes))
	record_destroy(&full)
}

@(test)
record_a_bad_version_or_line_is_refused :: proc(t: ^testing.T) {
	cases := []struct {
		text: string,
		err:  Record_Error,
	} {
		{"noirvpn-state 2\npid 1\nend\n", .Bad_Version},
		{"noirvpn-state x\npid 1\nend\n", .Bad_Version},
		{"noirvpn-state\nend\n", .Bad_Line},
		{"other-state 1\nend\n", .Bad_Line},
		{"noirvpn-state 1\nfoo bar\nend\n", .Bad_Line},
		{"noirvpn-state 1\nend\npid 1\n", .Bad_Line},
		{"noirvpn-state 1\nend x\n", .Bad_Line},
		{"noirvpn-state 1\npid -3\nend\n", .Bad_Line},
		{"noirvpn-state 1\nrole boss\nend\n", .Bad_Line},
		{"noirvpn-state 1\ndev 0 tun0\nend\n", .Bad_Line},
		{"noirvpn-state 1\nroute 4 10.0.0.0/33 - 254 - 7 tun0\nend\n", .Bad_Line},
		{"noirvpn-state 1\nroute 4 10.0.0.0/8 fe80::1 254 - 7 tun0\nend\n", .Bad_Line},
		{"noirvpn-state 1\nroute 5 10.0.0.0/8 - 254 - 7 tun0\nend\n", .Bad_Line},
		{"noirvpn-state 1\nroute 4 10.0.0.0/8 - 254 - 7\nend\n", .Bad_Line},
		{"noirvpn-state 1\ndns resolvconf tun0\nend\n", .Bad_Line},
		{"noirvpn-state 1\npid 9\nend\n", .None},
	}
	for c in cases {
		r, err := record_decode(c.text)
		testing.expectf(t, err == c.err, "%q: %v, want %v", c.text, err, c.err)
		record_destroy(&r)
	}
}

// A name or device name with a control byte cannot break the line format.
@(test)
record_control_bytes_stay_on_their_line :: proc(t: ^testing.T) {
	r: Record
	record_init(&r)
	defer record_destroy(&r)
	r.pid = 1
	r.name = clean_text("a\nroute 4 0.0.0.0/0 - 254 - 1 x", r.allocator)
	record_add_dev(&r, 3, "bad\ndev")
	record_add_dns(&r, "resolvconf", "t u", "x\ny")
	text := record_encode(&r)
	defer delete(text)
	back, err := record_decode(text)
	defer record_destroy(&back)
	testing.expect_value(t, err, Record_Error.None)
	testing.expect_value(t, len(back.routes), 0)
	testing.expect_value(t, back.devs[0].name, "bad?dev")
	testing.expect_value(t, back.dns[0].ifname, "t?u")
}

// ---- the rule of what to revert ----

@(private = "file")
Plan_Case :: struct {
	routes:  []sysnet.Route,
	links:   []Record_Link,
	live:    []^Record,
	dead:    []^Record,
	unknown: bool,
}

@(private = "file")
plan_of :: proc(c: Plan_Case) -> []Cleanup_Step {
	return record_cleanup_plan(c.routes, c.links, c.live, c.dead, c.unknown, context.temp_allocator)
}

@(private = "file")
LINKS :: []Record_Link{{index = 1, name = "lo"}, {index = 2, name = "eth0"}, {index = 7, name = "tun0", tunnel = true}, {index = 8, name = "noir0", tunnel = true}}

@(private = "file")
pin_route :: proc(ifindex: u32 = 2) -> sysnet.Route {
	return sysnet.Route{dst = SRV4, dst_len = 32, gateway = sysnet.Address(GW4), ifindex = ifindex, table = 254, protocol = ROUTE_PROTOCOL}
}

@(private = "file")
half_route :: proc(ifindex: u32) -> sysnet.Route {
	return sysnet.Route{dst = sysnet.IP4_Address{}, dst_len = 1, ifindex = ifindex, table = 254, protocol = ROUTE_PROTOCOL}
}

@(test)
cleanup_plan_keeps_what_a_live_record_holds :: proc(t: ^testing.T) {
	live: Record
	record_init(&live)
	defer record_destroy(&live)
	record_add_dev(&live, 7, "tun0")
	record_add_route(&live, pin_route(), "eth0")
	// A dead record lists the same pin (two clients for one server).
	dead: Record
	record_init(&dead)
	defer record_destroy(&dead)
	record_add_route(&dead, pin_route(), "eth0")
	record_add_dev(&dead, 9, "tun1")

	routes := []sysnet.Route{pin_route(), half_route(7), {dst = sysnet.IP4_Address{10, 1, 0, 0}, dst_len = 16, ifindex = 7, table = 254, protocol = ROUTE_PROTOCOL}}
	steps := plan_of({routes = routes, links = LINKS, live = {&live}, dead = {&dead}})
	testing.expect_value(t, len(steps), 0)
}

@(test)
cleanup_plan_reverts_a_dead_record :: proc(t: ^testing.T) {
	dead: Record
	record_init(&dead)
	defer record_destroy(&dead)
	record_add_route(&dead, pin_route(), "eth0")
	record_add_dev(&dead, 8, "noir0")
	other: Record
	record_init(&other)
	defer record_destroy(&other)
	record_add_dev(&other, 7, "tun0")

	// The pin of the dead record, and a route on its device (the device of a
	// DCO service outlives the daemon).
	routes := []sysnet.Route{pin_route(), half_route(8), half_route(7)}
	steps := plan_of({routes = routes, links = LINKS, live = {&other}, dead = {&dead}, unknown = true})
	testing.expect_value(t, len(steps), 2)
	if len(steps) == 2 {
		testing.expect(t, record_route_match(steps[0].route, pin_route()))
		testing.expect_value(t, steps[0].why, Cleanup_Why.Dead_Record)
		testing.expect_value(t, steps[1].route.ifindex, 8)
		testing.expect_value(t, steps[1].why, Cleanup_Why.Dead_Record)
	}
}

// The fallback for routes that no record lists.
@(test)
cleanup_plan_fallback_rule :: proc(t: ^testing.T) {
	live: Record
	record_init(&live)
	defer record_destroy(&live)
	record_add_dev(&live, 7, "tun0")

	// An unlisted pin on the uplink goes; an unlisted route on a tunnel device
	// that no record holds stays (the process of that device runs); a route
	// on the device of the live record stays.
	stale_pin := sysnet.Route{dst = sysnet.IP4_Address{203, 0, 113, 9}, dst_len = 32, gateway = sysnet.Address(GW4), ifindex = 2, table = 254, protocol = ROUTE_PROTOCOL}
	routes := []sysnet.Route{stale_pin, half_route(8), half_route(7)}
	steps := plan_of({routes = routes, links = LINKS, live = {&live}})
	testing.expect_value(t, len(steps), 1)
	if len(steps) == 1 {
		testing.expect(t, record_route_match(steps[0].route, stale_pin))
		testing.expect_value(t, steps[0].why, Cleanup_Why.Unlisted)
	}

	// A device that is not in the list (gone) is no tunnel device.
	gone := half_route(42)
	steps = plan_of({routes = {gone}, links = LINKS, live = {&live}})
	testing.expect_value(t, len(steps), 1)

	// A live record that cannot be read: no fallback at all.
	steps = plan_of({routes = routes, links = LINKS, live = {&live}, unknown = true})
	testing.expect_value(t, len(steps), 0)
}

@(test)
cleanup_route_match_rules :: proc(t: ^testing.T) {
	a := pin_route()
	b := a
	b.table = 0
	testing.expect(t, record_route_match(a, b)) // 0 is the main table
	b.metric = 1024
	testing.expect(t, record_route_match(a, b)) // a metric on one side only
	c := a
	c.metric = 5
	testing.expect(t, !record_route_match(c, b))
	d := a
	d.gateway = nil
	testing.expect(t, !record_route_match(a, d))
	e := a
	e.ifindex = 3
	testing.expect(t, !record_route_match(a, e))
	f := sysnet.Route{family = .V4, dst_len = 0, ifindex = 7}
	g := sysnet.Route{dst = sysnet.IP4_Address{}, dst_len = 0, ifindex = 7}
	testing.expect(t, record_route_match(f, g)) // a nil destination is the default route
	h := sysnet.Route{family = .V6, dst_len = 0, ifindex = 7}
	testing.expect(t, !record_route_match(f, h))
}

@(test)
cleanup_dns_protection :: proc(t: ^testing.T) {
	live: Record
	record_init(&live)
	defer record_destroy(&live)
	record_add_dev(&live, 7, "tun0")
	record_add_dns(&live, "resolvconf", "noir1", "")
	dead: Record
	record_init(&dead)
	defer record_destroy(&dead)
	record_add_dev(&dead, 9, "noir2")

	links := []Record_Link{{index = 7, name = "tun0", tunnel = true}, {index = 9, name = "noir2", tunnel = true}, {index = 11, name = "noir3", tunnel = true}}
	live_list := []^Record{&live}
	// The interface of a live device or a live DNS change.
	testing.expect(t, record_dns_protected({backend = "resolvconf", ifname = "tun0"}, &dead, live_list, links))
	testing.expect(t, record_dns_protected({backend = "resolvconf", ifname = "noir1"}, &dead, live_list, links))
	// The device of the dead record is still there: its DNS goes.
	testing.expect(t, !record_dns_protected({backend = "resolvconf", ifname = "noir2"}, &dead, live_list, links))
	// A device of that name that is not the dead record's: someone else's now.
	testing.expect(t, record_dns_protected({backend = "resolvconf", ifname = "noir3"}, &dead, live_list, links))
	// No device and no live record: it goes.
	testing.expect(t, !record_dns_protected({backend = "resolvconf", ifname = "noir4"}, &dead, live_list, links))
	// Without an owner (the fallback), any device of the name protects it.
	testing.expect(t, record_dns_protected({backend = "resolvconf", ifname = "noir2"}, nil, live_list, links))

	when ODIN_OS == .Linux {
		// resolv.conf is one file: a live record that uses it protects it.
		other: Record
		record_init(&other)
		defer record_destroy(&other)
		record_add_dns(&other, "resolv.conf", "tun5", "")
		testing.expect(t, record_dns_protected({backend = "resolv.conf", ifname = "noir4"}, &dead, {&other}, links))
		testing.expect(t, !record_dns_protected({backend = "resolv.conf", ifname = "noir4"}, &dead, live_list, links))
	}
}
