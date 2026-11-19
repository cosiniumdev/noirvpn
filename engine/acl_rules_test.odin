// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:encoding/json"
import "core:strings"
import "core:testing"
import "noir:bus"
import "noir:platform/event"
import "noir:proto/acl"
import "noir:proto/config"

@(private = "file")
RT_BASE :: "client-service\nverb 3\nworkers 0\ndatapath userspace\nwritepid /dev/null\n"

@(private = "file")
Rt :: struct {
	d:    ^Daemon,
	base: ^config.Config,
}

// A daemon on `RT_BASE` + `extra`. `service` false: a daemon with a config
// file, whose filter and relay start at once.
@(private = "file")
rt_make :: proc(t: ^testing.T, extra: string, service: bool) -> (rt: Rt, ok: bool) {
	rt.base = new(config.Config)
	rt.base^ = config.build(config.parse_text(strings.concatenate({RT_BASE, extra}, context.temp_allocator), "base"))
	if !config.ok(rt.base) {
		testing.expectf(t, false, "base config: %s", config.format_diagnostics(rt.base.diags, context.temp_allocator))
		config.destroy(rt.base)
		free(rt.base)
		return {}, false
	}
	rt.d = new(Daemon)
	d := rt.d
	if event.init(&d.loop) != .None {
		testing.expect(t, false, "event loop")
	}
	d.cfgw = rt.base
	d.cfg = &rt.base.client
	d.service = service
	d.hold = true
	if !service {
		acl_attach(d)
		forward_attach(d)
	}
	return rt, true
}

@(private = "file")
rt_destroy :: proc(rt: ^Rt) {
	daemon_destroy(rt.d)
	free(rt.d)
	config.destroy(rt.base)
	free(rt.base)
}

// Reads the config file again: the base config with `extra`.
@(private = "file")
rt_reload :: proc(t: ^testing.T, rt: ^Rt, extra: string) -> Acl_Change {
	c := config.build(config.parse_text(strings.concatenate({RT_BASE, extra}, context.temp_allocator), "base"))
	defer config.destroy(&c)
	if !testing.expectf(t, config.ok(&c), "%s", config.format_diagnostics(c.diags, context.temp_allocator)) {
		return {}
	}
	return acl_reload(rt.d, &c.client)
}

// The destinations in force, as the config writes them.
@(private = "file")
rt_dests :: proc(d: ^Daemon) -> string {
	parts := make([dynamic]string, context.temp_allocator)
	for r in d.cfg.allow_inbound {
		append(&parts, config.acl_dest_text(r, d.cfg.acl_hosts, context.temp_allocator))
	}
	return strings.join(parts[:], " ", context.temp_allocator)
}

@(private = "file")
Rt_Reply :: struct {
	ok:   bool,
	code: bus.Error_Code,
}

// The result of `acl.get`.
@(private = "file")
rt_get :: proc(t: ^testing.T, d: ^Daemon) -> json.Object {
	tr: Rt_Reply
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	r := Reply {
		user = &tr,
		w = &w,
		ok = proc(u: rawptr) {(^Rt_Reply)(u).ok = true},
		err = proc(u: rawptr, code: bus.Error_Code, text: string) {(^Rt_Reply)(u).code = code},
		err_details = proc(u: rawptr, code: bus.Error_Code, text: string, details: []u8) {(^Rt_Reply)(u).code = code},
		wipe_args = proc(u: rawptr) {},
	}
	op_acl_get(d, &r)
	bus.end(&w)
	testing.expect(t, tr.ok)
	v, err := json.parse(transmute([]u8)bus.writer_string(&w), .JSON, false, context.temp_allocator)
	testing.expectf(t, err == .None, "acl.get: %v: %s", err, bus.writer_string(&w))
	obj, _ := v.(json.Object)
	return obj
}

@(test)
test_acl_reload_rules_in_place :: proc(t: ^testing.T) {
	rt, ok := rt_make(t, "allow-inbound :22 tcp\nallow-inbound NAS.lan:445 tcp\n", false)
	if !ok {
		return
	}
	defer rt_destroy(&rt)
	d := rt.d
	st := d.acl
	if !testing.expect(t, st != nil) {
		return
	}
	acl.set_host(&st.a, 0, []acl.Addr{acl.map4([]u8{192, 168, 50, 10})})

	// Other protocols, and the same name in other letters: the name keeps its addresses.
	ch := rt_reload(t, &rt, "allow-inbound :22 tcp udp\nallow-inbound nas.lan:445 tcp\n")
	testing.expect(t, ch.rules && !ch.forwards)
	testing.expect(t, d.acl == st)
	testing.expect_value(t, len(st.a.rules), 2)
	testing.expect_value(t, st.a.rules[0].protos, acl.Protos{.Tcp, .Udp})
	testing.expect_value(t, st.a.hosts[0].n, 1)
	testing.expect_value(t, rt_dests(d), ":22 nas.lan:445")

	// A new name: the old one keeps its addresses, the new one waits for a lookup.
	ch = rt_reload(t, &rt, "allow-inbound :22 tcp udp\nallow-inbound nas.lan:445 tcp\nallow-inbound printer.lan\n")
	testing.expect(t, ch.rules)
	testing.expect(t, d.acl == st)
	testing.expect_value(t, len(st.lk.names), 2)
	testing.expect_value(t, len(st.a.hosts), 2)
	testing.expect_value(t, st.a.hosts[0].n, 1)
	testing.expect_value(t, st.a.hosts[1].n, 0)
	testing.expect_value(t, rt_dests(d), ":22 nas.lan:445 printer.lan")

	// The same lines: nothing changes.
	ch = rt_reload(t, &rt, "allow-inbound :22 tcp udp\nallow-inbound nas.lan:445 tcp\nallow-inbound printer.lan\n")
	testing.expect(t, !acl_change_any(ch))

	// No line: no filter.
	ch = rt_reload(t, &rt, "")
	testing.expect(t, ch.rules)
	testing.expect(t, d.acl == nil)
	get := rt_get(t, d)
	testing.expect_value(t, get["filter"].(json.Boolean), false)
	_, null_src := get["source"].(json.Null)
	testing.expect(t, null_src)

	// The default block rule: a new filter.
	ch = rt_reload(t, &rt, "allow-inbound 0.0.0.0/0 ::/0 icmp\n")
	testing.expect(t, ch.rules)
	testing.expect(t, d.acl != nil)
	testing.expect_value(t, rt_dests(d), "0.0.0.0/0 ::/0")
	get = rt_get(t, d)
	testing.expect_value(t, get["filter"].(json.Boolean), true)
	testing.expect_value(t, get["source"].(json.String), "config")
	testing.expect_value(t, get["denied"].(json.Float), 0)
	rules := get["rules"].(json.Array)
	testing.expect_value(t, len(rules), 2)
	r1 := rules[1].(json.Object)
	testing.expect_value(t, r1["dest"].(json.String), "::/0")
	protos := r1["protos"].(json.Array)
	testing.expect_value(t, len(protos), 1)
	testing.expect_value(t, protos[0].(json.String), "icmp")
}

@(test)
test_acl_reload_forwards :: proc(t: ^testing.T) {
	rt, ok := rt_make(t, "forward 8080 to 127.0.0.1:80\n", false)
	if !ok {
		return
	}
	defer rt_destroy(&rt)
	d := rt.d
	testing.expect(t, d.acl == nil)
	if !testing.expect(t, d.fwd != nil) {
		return
	}

	ch := rt_reload(t, &rt, "forward 8080 to 127.0.0.1:81\nforward-max-conns 9\nacl-max-flows 512\n")
	testing.expect(t, ch.forwards && !ch.rules && ch.max_conns && ch.max_flows)
	testing.expect_value(t, len(d.fwd.lines), 1)
	testing.expect_value(t, d.fwd.lines[0].text, "127.0.0.1:81")
	testing.expect_value(t, d.fwd.max, 9)
	// The table keeps its size until a restart.
	testing.expect(t, d.cfgw.client.acl_max_flows != 512)

	// A filter: the forward port is one of its rules.
	ch = rt_reload(t, &rt, "forward 8080 to 127.0.0.1:81\nforward-max-conns 9\nallow-inbound :22 tcp\n")
	testing.expect(t, ch.rules && !ch.forwards)
	if testing.expect(t, d.acl != nil) {
		testing.expect_value(t, len(d.acl.a.rules), 2)
		testing.expect_value(t, d.acl.a.rules[1].port_lo, 8080)
	}
	get := rt_get(t, d)
	fwds := get["forwards"].(json.Array)
	testing.expect_value(t, len(fwds), 1)
	f0 := fwds[0].(json.Object)
	testing.expect_value(t, f0["port"].(json.Float), 8080)
	testing.expect_value(t, f0["target"].(json.String), "127.0.0.1:81")

	// No forward: the relay goes, and the filter keeps only its own rule.
	ch = rt_reload(t, &rt, "allow-inbound :22 tcp\n")
	testing.expect(t, ch.forwards)
	testing.expect(t, d.fwd == nil)
	if testing.expect(t, d.acl != nil) {
		testing.expect_value(t, len(d.acl.a.rules), 1)
	}
	names := make([dynamic]string, context.temp_allocator)
	acl_change_names(ch, &names)
	testing.expect_value(t, len(names), 2)
	testing.expect_value(t, names[0], "forward")
	testing.expect_value(t, names[1], "forward-max-conns")
}

@(test)
test_acl_reload_service_merge :: proc(t: ^testing.T) {
	rt, ok := rt_make(t, "", true)
	if !ok {
		return
	}
	defer rt_destroy(&rt)
	d := rt.d

	// No profile: the base config has no rules.
	get := rt_get(t, d)
	testing.expect_value(t, get["filter"].(json.Boolean), false)
	testing.expect_value(t, get["profile_ignored"].(json.Float), 0)

	c := profile_check_run(strings.concatenate({GOOD_PROFILE, "allow-inbound :22 tcp\n"}, context.temp_allocator))
	testing.expectf(t, len(c.problems) == 0, "%v", c.problems)
	testing.expect(t, service_install(d, &c, "p", false, 1000))
	profile_check_destroy(&c)
	testing.expect(t, d.acl != nil)
	testing.expect_value(t, rt_dests(d), ":22")
	get = rt_get(t, d)
	testing.expect_value(t, get["source"].(json.String), "profile")
	rules := get["rules"].(json.Array)
	if testing.expect_value(t, len(rules), 1) {
		testing.expect_value(t, rules[0].(json.Object)["source"].(json.String), "profile")
	}

	// The base config gets its own rules: they win.
	ch := rt_reload(t, &rt, "allow-inbound 10.0.0.0/8 icmp\n")
	testing.expect(t, ch.rules)
	testing.expect_value(t, rt_dests(d), "10.0.0.0/8")
	get = rt_get(t, d)
	testing.expect_value(t, get["source"].(json.String), "config")
	testing.expect_value(t, get["profile_ignored"].(json.Float), 1)

	// Without them, the rules of the profile apply again.
	ch = rt_reload(t, &rt, "")
	testing.expect(t, ch.rules)
	testing.expect_value(t, rt_dests(d), ":22")
	testing.expect(t, d.acl != nil)

	service_unload(d)
	testing.expect(t, d.prof_allow == nil)
	testing.expect(t, d.acl == nil)
	// No profile: a reload only changes the base config.
	ch = rt_reload(t, &rt, "allow-inbound :80 tcp\n")
	testing.expect(t, ch.rules)
	testing.expect(t, d.acl == nil)
	testing.expect_value(t, rt_dests(d), ":80")
}

@(test)
test_dco_attempt_with_allow_inbound :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	cfg.allow_inbound = []acl.Rule{{target = .Tunnel, port_lo = 22, port_hi = 22, protos = {.Tcp}}}
	d: Daemon
	d.cfg = &cfg
	d.dco.want = true
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
}

@(test)
test_acl_config_details :: proc(t: ^testing.T) {
	diags := []config.Diagnostic {
		{severity = .Warning, file = "a.conf", line = 2, message = "verb: high"},
		{severity = .Error, file = "a.conf", line = 3, message = "allow-inbound: 'x' is not an address"},
		{severity = .Error, file = "a.conf", line = 0, message = "no remote given"},
	}
	v, _ := json.parse(acl_config_details(diags, "x"), .JSON, false, context.temp_allocator)
	arr := v.(json.Array)
	if testing.expect_value(t, len(arr), 2) {
		e0 := arr[0].(json.Object)
		testing.expect_value(t, e0["line"].(json.Float), 3)
		testing.expect_value(t, e0["option"].(json.String), "allow-inbound")
		testing.expect_value(t, e0["reason"].(json.String), "'x' is not an address")
		e1 := arr[1].(json.Object)
		testing.expect_value(t, e1["option"].(json.String), "")
		testing.expect_value(t, e1["reason"].(json.String), "no remote given")
	}
	v, _ = json.parse(acl_config_details(nil, "bus-allow: 'x' is not a user"), .JSON, false, context.temp_allocator)
	arr = v.(json.Array)
	if testing.expect_value(t, len(arr), 1) {
		testing.expect_value(t, arr[0].(json.Object)["reason"].(json.String), "bus-allow: 'x' is not a user")
	}
}
