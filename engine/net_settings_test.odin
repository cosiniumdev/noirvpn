// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:encoding/json"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:platform/sysnet"

@(private = "file")
n4 :: proc(a, b, c, d: u8, bits: u8) -> Net {
	return Net{addr = {a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = bits}
}

@(private = "file")
texts4 :: proc(list: []Net) -> string {
	sb := strings.builder_make(context.temp_allocator)
	for n, i in list {
		if i > 0 {
			strings.write_byte(&sb, ' ')
		}
		strings.write_string(&sb, net_text(n, false))
	}
	return strings.to_string(sb)
}

@(test)
net_subtract_ipv4 :: proc(t: ^testing.T) {
	out := make([dynamic]Net, context.temp_allocator)
	all := []Net{n4(0, 0, 0, 0, 0)}
	ok := net_subtract(all, {n4(10, 0, 0, 0, 8)}, 32, &out)
	testing.expect(t, ok)
	testing.expect_value(t, texts4(out[:]), "0.0.0.0/5 8.0.0.0/7 11.0.0.0/8 12.0.0.0/6 16.0.0.0/4 32.0.0.0/3 64.0.0.0/2 128.0.0.0/1")
	// Inside the excluded range: nothing is left. Outside: unchanged.
	net_subtract({n4(10, 1, 0, 0, 16), n4(192, 168, 0, 0, 16)}, {n4(10, 0, 0, 0, 8)}, 32, &out)
	testing.expect_value(t, texts4(out[:]), "192.168.0.0/16")
	// Host bits are cleared, and a covered range goes.
	net_subtract({n4(10, 1, 2, 3, 8), n4(10, 9, 0, 0, 16)}, nil, 32, &out)
	testing.expect_value(t, texts4(out[:]), "10.0.0.0/8")
	// A hole in a hole: 10/8 without 10.1/16 and without 10.2/16.
	net_subtract({n4(10, 0, 0, 0, 8)}, {n4(10, 1, 0, 0, 16), n4(10, 2, 0, 0, 16)}, 32, &out)
	covered_ok := true
	for n in out {
		if net_covers(n, n4(10, 1, 0, 0, 16)) || net_covers(n4(10, 1, 0, 0, 16), n) || net_covers(n, n4(10, 2, 3, 4, 32)) {
			covered_ok = false
		}
	}
	testing.expect(t, covered_ok)
	testing.expect(t, net_covers(n4(10, 0, 0, 0, 8), n4(10, 0, 0, 0, 9)) || len(out) > 0)
	// The pieces cover 10.3.0.1 and 10.0.0.1.
	has := proc(list: []Net, a: Net) -> bool {
		for n in list {
			if net_covers(n, a) {
				return true
			}
		}
		return false
	}
	testing.expect(t, has(out[:], n4(10, 3, 0, 1, 32)))
	testing.expect(t, has(out[:], n4(10, 0, 0, 1, 32)))
	testing.expect(t, !has(out[:], n4(10, 2, 0, 1, 32)))
	testing.expect(t, !has(out[:], n4(10, 1, 255, 1, 32)))
}

@(test)
net_subtract_ipv6 :: proc(t: ^testing.T) {
	out := make([dynamic]Net, context.temp_allocator)
	ula := Net{addr = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = 8}
	ok := net_subtract({Net{}}, {ula}, 128, &out)
	testing.expect(t, ok)
	testing.expect_value(t, len(out), 8)
	for n in out {
		testing.expect(t, !net_covers(n, ula) && !net_covers(ula, n))
	}
	// ::/1 and 8000::/1 are two halves; fd00::/8 is in the high one.
	testing.expect_value(t, net_text(out[0], true), "::/1")
	// Inside an excluded range: nothing is left.
	one := Net{addr = {0xfd, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, bits = 128}
	net_subtract({one}, {ula}, 128, &out)
	testing.expect_value(t, len(out), 0)
}

@(private = "file")
test_plan :: proc() -> client.Plan {
	p: client.Plan
	p.steps = make([dynamic]client.Step, context.temp_allocator)
	p.notes = make([dynamic]client.Note, context.temp_allocator)
	p.addr4 = sysnet.IP4_Address{10, 8, 0, 2}
	p.prefix4 = 24
	p.mtu = 1400
	return p
}

@(private = "file")
route_step :: proc(a: sysnet.Address, bits: u8, on_tun: bool, why: client.Why) -> client.Step {
	return client.Step{kind = .Add_Route, route = sysnet.Route{dst = a, dst_len = bits}, on_tun = on_tun, why = why}
}

@(private = "file")
settings_obj :: proc(t: ^testing.T, in_: Settings_In) -> (obj: json.Object, text: string) {
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	settings_write(&w, in_)
	text = strings.clone(bus.writer_string(&w), context.temp_allocator)
	v, ok := bus.parse_json(transmute([]u8)text, context.temp_allocator)
	testing.expect(t, ok)
	obj, _ = v.(json.Object)
	return
}

@(test)
settings_types_and_fields :: proc(t: ^testing.T) {
	p := test_plan()
	append(&p.steps, route_step(sysnet.IP4_Address{192, 168, 5, 0}, 24, true, .Pushed_Route))
	append(&p.steps, route_step(sysnet.IP4_Address{172, 16, 0, 0}, 12, false, .Config_Route))
	p.has_dns = true
	servers := make([]sysnet.DNS_Server, 2, context.temp_allocator)
	servers[0] = {address = sysnet.IP4_Address{10, 8, 0, 1}}
	servers[1] = {address = sysnet.IP4_Address{8, 8, 8, 8}}
	p.dns.servers = servers
	p.dns.search_domains = {"corp.example"}
	p.dns.routing_domains = {"corp.example"}
	obj, text := settings_obj(t, {plan = &p, caps = {platform = "ios", exclude_routes = true, split_dns = true}, remote = sysnet.IP4_Address{203, 0, 113, 9}, block6 = true})
	_, a4 := obj["addr4"].(json.String)
	testing.expect(t, a4)
	p4, ip4 := obj["prefix4"].(json.Integer)
	testing.expect(t, ip4 && p4 == 24)
	m, im := obj["mtu"].(json.Integer)
	testing.expect(t, im && m == 1400)
	_, has6 := obj["addr6"]
	testing.expect(t, !has6)
	for k in ([]string{"routes4", "routes6", "exclude4", "exclude6", "dns_servers", "search_domains", "match_domains", "notes"}) {
		_, is_arr := obj[k].(json.Array)
		testing.expectf(t, is_arr, "%s is an array: %s", k, text)
	}
	for k in ([]string{"redirect4", "redirect6", "dns_all", "block6"}) {
		_, is_bool := obj[k].(json.Boolean)
		testing.expectf(t, is_bool, "%s is a boolean", k)
	}
	r, _ := obj["remote"].(json.String)
	testing.expect_value(t, r, "203.0.113.9")
	testing.expect(t, strings.contains(text, `"routes4":["8.8.8.8/32","192.168.5.0/24"]`))
	testing.expect(t, strings.contains(text, `"exclude4":["172.16.0.0/12"]`))
	testing.expect(t, strings.contains(text, `"match_domains":["corp.example"]`))
	testing.expect(t, strings.contains(text, `"dns_all":false`))
	testing.expect(t, strings.contains(text, `"block6":true`))
	// No split DNS: every name goes to the servers.
	_, text2 := settings_obj(t, {plan = &p, caps = {platform = "android", exclude_routes = true}})
	testing.expect(t, strings.contains(text2, `"match_domains":[]`))
	testing.expect(t, strings.contains(text2, `"dns_all":true`))
	// The key form leaves out `remote` and `notes`.
	_, key := settings_obj(t, {plan = &p, caps = {platform = "ios", exclude_routes = true, split_dns = true}, remote = sysnet.IP4_Address{1, 2, 3, 4}, core_only = true})
	testing.expect(t, !strings.contains(key, "remote") && !strings.contains(key, "notes"))
}

// The host does not route the subnet of the tunnel address by itself, so the
// settings carry it, with the host bits cleared. It is left out if the subnet
// is a network of the host (no prefix route), and for a lone address.
@(test)
settings_route_the_tunnel_subnet :: proc(t: ^testing.T) {
	p := test_plan()
	append(&p.steps, client.Step{kind = .Add_Addr, addr = sysnet.IP4_Address{10, 9, 0, 2}, prefix_len = 24})
	a6: sysnet.IP6_Address
	a6[0], a6[1], a6[7] = 0xfd00, 0x9, 2
	append(&p.steps, client.Step{kind = .Add_Addr, addr = a6, prefix_len = 64})
	caps := Caps{platform = "ios", exclude_routes = true, split_dns = true}
	_, text := settings_obj(t, {plan = &p, caps = caps})
	testing.expectf(t, strings.contains(text, `"routes4":["10.9.0.0/24"]`), "%s", text)
	testing.expectf(t, strings.contains(text, `"routes6":["fd00:9::/64"]`), "%s", text)

	q := test_plan()
	append(&q.steps, client.Step{kind = .Add_Addr, addr = sysnet.IP4_Address{10, 9, 0, 2}, prefix_len = 24, no_prefix_route = true})
	append(&q.steps, client.Step{kind = .Add_Addr, addr = sysnet.IP4_Address{10, 9, 1, 2}, prefix_len = 32})
	_, text2 := settings_obj(t, {plan = &q, caps = caps})
	testing.expectf(t, strings.contains(text2, `"routes4":[]`), "%s", text2)
}

@(test)
settings_no_exclude_routes :: proc(t: ^testing.T) {
	p := test_plan()
	p.redirect4 = true
	append(&p.steps, route_step(sysnet.IP4_Address{0, 0, 0, 0}, 1, true, .Redirect_Low))
	append(&p.steps, route_step(sysnet.IP4_Address{128, 0, 0, 0}, 1, true, .Redirect_High))
	append(&p.steps, route_step(sysnet.IP4_Address{203, 0, 113, 9}, 32, true, .Server_Pin))
	hn := []client.Host_Net{{addr = {192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = 24}}
	obj, text := settings_obj(t, {plan = &p, caps = {platform = "android"}, host_nets = hn})
	routes, _ := obj["routes4"].(json.Array)
	testing.expect_value(t, len(routes), 24)
	testing.expect(t, strings.contains(text, `"redirect4":false`))
	testing.expect(t, strings.contains(text, `"exclude4":[]`))
	testing.expect(t, !strings.contains(text, "203.0.113.9"))
	testing.expect(t, !strings.contains(text, "192.168.1.0/24"))
	testing.expect(t, strings.contains(text, "192.168.0.0/24"))
	testing.expect(t, strings.contains(text, "192.168.2.0/23"))
	// A host that can exclude routes keeps the redirect and the exclusion.
	_, text2 := settings_obj(t, {plan = &p, caps = {platform = "ios", exclude_routes = true}, host_nets = hn})
	testing.expect(t, strings.contains(text2, `"redirect4":true`))
	testing.expect(t, strings.contains(text2, `"exclude4":["192.168.1.0/24"]`))
	testing.expect(t, strings.contains(text2, `"routes4":[]`))
}

@(test)
settings_equal_plan_same_key :: proc(t: ^testing.T) {
	a := test_plan()
	b := test_plan()
	append(&a.steps, route_step(sysnet.IP4_Address{192, 168, 5, 0}, 24, true, .Pushed_Route))
	append(&b.steps, route_step(sysnet.IP4_Address{192, 168, 5, 0}, 24, true, .Pushed_Route))
	_, ka := settings_obj(t, {plan = &a, caps = {platform = "ios"}, core_only = true})
	_, kb := settings_obj(t, {plan = &b, caps = {platform = "ios"}, core_only = true})
	testing.expect_value(t, ka, kb)
	testing.expect(t, client.plan_equal(&a, &b))
	append(&b.steps, route_step(sysnet.IP4_Address{10, 9, 0, 0}, 16, true, .Pushed_Route))
	_, kc := settings_obj(t, {plan = &b, caps = {platform = "ios"}, core_only = true})
	testing.expect(t, ka != kc)
	testing.expect(t, !client.plan_equal(&a, &b))
}

@(test)
probe_wait_follows_the_ping_interval :: proc(t: ^testing.T) {
	// No interval known: 10 s.
	testing.expect_value(t, probe_wait(0), 10 * time.Second)
	testing.expect_value(t, probe_wait(-1), 10 * time.Second)
	// Interval and 3 s, but at least 10 s.
	testing.expect_value(t, probe_wait(1), 10 * time.Second)
	testing.expect_value(t, probe_wait(5), 10 * time.Second)
	testing.expect_value(t, probe_wait(7), 10 * time.Second)
	testing.expect_value(t, probe_wait(8), 11 * time.Second)
	testing.expect_value(t, probe_wait(10), 13 * time.Second)
	testing.expect_value(t, probe_wait(15), 18 * time.Second)
	// At most 30 s.
	testing.expect_value(t, probe_wait(27), 30 * time.Second)
	testing.expect_value(t, probe_wait(28), 30 * time.Second)
	testing.expect_value(t, probe_wait(60), 30 * time.Second)
	testing.expect_value(t, probe_wait(1 << 40), 30 * time.Second)
}

@(test)
network_report_that_changes_nothing_does_nothing :: proc(t: ^testing.T) {
	a := client.Host_Net{addr = {192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = 24}
	b := client.Host_Net{addr = {10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = 8}
	// Same list, other order: no change.
	testing.expect(t, nets_equal({a, b}, {b, a}))
	testing.expect(t, nets_equal(nil, {}))
	testing.expect(t, !nets_equal({a}, {a, b}))
	testing.expect(t, !nets_equal({a, a}, {a, b}))
	testing.expect(t, !nets_equal({a}, {b}))
	// No probe, no new socket, no replan for the same state.
	testing.expect(t, !net_needs_probe(false, false, false))
	testing.expect(t, net_needs_probe(true, false, false))
	testing.expect(t, net_needs_probe(false, true, false))
	testing.expect(t, net_needs_probe(false, false, true))
	// The message of a report that changes nothing parses with no wake.
	m, ok := net_msg_parse(transmute([]u8)string(`{"state":"up","host_nets":["192.168.1.7/24","10.0.0.0/8"]}`))
	testing.expect(t, ok)
	defer net_msg_destroy(&m)
	testing.expect(t, m.up && m.have_nets && !m.wake)
	testing.expect(t, nets_equal(m.nets, {b, a}))
}

@(test)
first_network_report_is_only_a_base :: proc(t: ^testing.T) {
	// The first report: no earlier list to differ from, so no probe.
	a := client.Host_Net{addr = {192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = 24}
	first := true
	nets_changed := !first && !nets_equal(nil, {a})
	testing.expect(t, !nets_changed)
	testing.expect(t, !net_needs_probe(false, nets_changed, false))
	// The second one with another list is a change.
	first = false
	testing.expect(t, net_needs_probe(false, !first && !nets_equal({a}, nil), false))
}

// Android gives the handle of the host network for name lookups.
@(test)
network_report_carries_the_handle :: proc(t: ^testing.T) {
	// (netId 100 << 32) | 0xfacade, as Network.getNetworkHandle generates it.
	m, ok := net_msg_parse(transmute([]u8)string(`{"state":"up","host_nets":[],"handle":429513165534`))
	testing.expect(t, !ok, "not JSON: refused")
	m, ok = net_msg_parse(transmute([]u8)string(`{"state":"up","host_nets":[],"handle":429513165534}`))
	testing.expect(t, ok)
	testing.expect_value(t, m.handle, u64(100 << 32 | 0xfacade))
	net_msg_destroy(&m)
	m, ok = net_msg_parse(transmute([]u8)string(`{"state":"up"}`))
	testing.expect(t, ok)
	testing.expect_value(t, m.handle, u64(0))
	m, ok = net_msg_parse(transmute([]u8)string(`{"state":"up","handle":-5}`))
	testing.expect(t, ok)
	testing.expect_value(t, m.handle, u64(0))
}
