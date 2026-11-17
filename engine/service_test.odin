// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:encoding/json"
import "core:strings"
import "core:testing"
import "noir:bus"
import "noir:client"
import "noir:platform/event"
import "noir:proto/config"
import "noir:proto/ossl"

// ---- the words ----

@(test)
test_service_reason_words :: proc(t: ^testing.T) {
	// What a daemon that exits says, and what a connection that ended in a service says.
	testing.expect_value(t, service_reason(.Auth_Failed, .None, .Ok), "auth_failed")
	testing.expect_value(t, service_reason(.Handshake_Failed, .None, .Ok), "tls_failed")
	testing.expect_value(t, service_reason(.Local_Stop, .Disconnect, .Ok), "user_request")
	testing.expect_value(t, service_reason(.Local_Stop, .Fatal, .Config), "config_error")
	testing.expect_value(t, service_reason(.Local_Stop, .Fatal, .Network), "network_error")
	// Only a service shows these three.
	testing.expect_value(t, service_reason(.Inactive, .Inactive, .Ok), "inactive")
	testing.expect_value(t, service_reason(.Session_Timeout, .Session_Timeout, .Ok), "session_timeout")
	testing.expect_value(t, service_reason(.Local_Stop, .Fatal, .System), "system_error")
	testing.expect_value(t, service_reason(.Local_Stop, .Fatal, .Ok), "system_error")
	// A daemon that exits keeps its words.
	testing.expect_value(t, state_reason(.Inactive, .Inactive, .Ok), "exit")
}

@(test)
test_service_stop_reason_words :: proc(t: ^testing.T) {
	testing.expect_value(t, service_stop_reason(.Auth_Failed, ""), "auth_failed")
	testing.expect_value(t, service_stop_reason(.Halted, ""), "server_halt")
	testing.expect_value(t, service_stop_reason(.Inactive, ""), "inactive")
	testing.expect_value(t, service_stop_reason(.Session_Timeout, ""), "session_timeout")
	testing.expect_value(t, service_stop_reason(.No_Remote, ""), "config_error")
	testing.expect_value(t, service_stop_reason(.Retries_Exhausted, ""), "network_error")
	testing.expect_value(t, service_stop_reason(.Resolve_Failed, "network_error"), "network_error")
	// The reason of the last connection says more than "network error".
	testing.expect_value(t, service_stop_reason(.Retries_Exhausted, "tls_failed"), "tls_failed")
	testing.expect_value(t, service_stop_reason(.Retries_Exhausted, "push_rejected"), "push_rejected")
	testing.expect_value(t, service_stop_reason(.Retries_Exhausted, "exit"), "network_error")
	testing.expect_value(t, service_stop_reason(.Local_Stop, ""), "exit")
	testing.expect_value(t, service_stop_reason(.Local_Stop, "auth_failed"), "auth_failed")
	// Every stop of the policy has a word.
	for r in client.Stop_Reason {
		testing.expect(t, service_stop_reason(r, "") != "")
	}
}

// ---- the owner rule ----

@(test)
test_owner_allows :: proc(t: ^testing.T) {
	op := bus.Roles{.Read, .Operator}
	admin := bus.Roles{.Read, .Operator, .Auth, .Admin}
	// No profile: each caller may.
	testing.expect(t, owner_allows(false, nil, 1001, op))
	testing.expect(t, owner_allows(false, u32(1000), 1001, op))
	// A profile: the owner and an admin.
	testing.expect(t, owner_allows(true, u32(1000), 1000, op))
	testing.expect(t, !owner_allows(true, u32(1000), 1001, op))
	testing.expect(t, owner_allows(true, u32(1000), 0, admin))
	testing.expect(t, owner_allows(true, u32(1000), 1001, admin))
	// The uid 0 is the owner like any other uid, and it has no role of its own here.
	testing.expect(t, owner_allows(true, u32(0), 0, op))
	testing.expect(t, !owner_allows(true, u32(0), 1000, op))
	// A loaded profile with no owner: only an admin.
	testing.expect(t, !owner_allows(true, nil, 1000, op))
	testing.expect(t, owner_allows(true, nil, 1000, admin))
}

// ---- the arguments ----

@(test)
test_label_problem :: proc(t: ^testing.T) {
	testing.expect_value(t, label_problem("Work VPN"), "")
	testing.expect_value(t, label_problem("a"), "")
	testing.expect_value(t, label_problem("B\u00fcro, Z\u00fcrich"), "")
	testing.expect_value(t, label_problem(strings.repeat("x", 128, context.temp_allocator)), "")
	testing.expect(t, label_problem("") != "")
	testing.expect(t, label_problem(strings.repeat("x", 129, context.temp_allocator)) != "")
	// 128 characters of 2 bytes are 256 bytes.
	testing.expect(t, label_problem(strings.repeat("\u00fc", 65, context.temp_allocator)) != "")
	testing.expect(t, label_problem("a\nb") != "")
	testing.expect(t, label_problem("a\tb") != "")
	testing.expect(t, label_problem("a\x00b") != "")
	testing.expect(t, label_problem("a\x7fb") != "")
	testing.expect(t, label_problem("a\u0085b") != "")
	testing.expect(t, label_problem("a\x1b[31mb") != "")
	testing.expect(t, label_problem("a\xffb") != "")
}

@(test)
test_sso_problem :: proc(t: ^testing.T) {
	testing.expect_value(t, sso_problem(nil), "")
	testing.expect_value(t, sso_problem({"webauth"}), "")
	testing.expect_value(t, sso_problem({"webauth", "webauth"}), "")
	testing.expect(t, sso_problem({"saml"}) != "")
	testing.expect(t, sso_problem({"webauth", "other"}) != "")
	testing.expect(t, sso_problem({""}) != "")
}

@(test)
test_sha256_hex :: proc(t: ^testing.T) {
	h := sha256_hex("abc")
	defer delete(h)
	testing.expect_value(t, h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	e := sha256_hex("")
	defer delete(e)
	testing.expect_value(t, e, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	testing.expect_value(t, len(h), 64)
}

// ---- checking a profile ----

TEST_STATIC_KEY :: "-----BEGIN OpenVPN Static key V1-----\n" +
	"00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n" +
	"00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n" +
	"00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n" +
	"00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n00112233445566778899aabbccddeeff\n" +
	"-----END OpenVPN Static key V1-----\n"

CA_BLOCK :: "<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</ca>\n"
ID_BLOCKS :: "<cert>\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n</cert>\n" +
	"<key>\n-----BEGIN PRIVATE KEY-----\nCCCC\n-----END PRIVATE KEY-----\n</key>\n"

GOOD_PROFILE :: "client\nremote 192.0.2.1 1194 udp\nnobind\n" +
	"<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</ca>\n" +
	"<cert>\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n</cert>\n" +
	"<key>\n-----BEGIN PRIVATE KEY-----\nCCCC\n-----END PRIVATE KEY-----\n</key>\n" +
	"<tls-crypt>\n" + TEST_STATIC_KEY + "</tls-crypt>\n" +
	"verb 9\ndisable-dco\ndaemon\n"

@(private = "file")
problem_classes :: proc(c: ^Profile_Check) -> string {
	sb := strings.builder_make(context.temp_allocator)
	for p in c.problems {
		strings.write_string(&sb, p.class)
		strings.write_byte(&sb, ' ')
	}
	return strings.to_string(sb)
}

@(test)
test_profile_check_good :: proc(t: ^testing.T) {
	c := profile_check_run(GOOD_PROFILE)
	defer profile_check_destroy(&c)
	testing.expect_value(t, len(c.problems), 0)
	testing.expect_value(t, len(c.sha), 64)
	testing.expect_value(t, c.sha, "" if false else c.sha)

	// The result: every option once, the ignored ones marked, the hash and the label.
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	profile_write_result(&w, &c, "Work VPN")
	bus.end(&w)
	v, err := json.parse(transmute([]u8)bus.writer_string(&w), .JSON, true, context.temp_allocator)
	testing.expect_value(t, err, json.Error.None)
	obj, _ := v.(json.Object)
	testing.expect_value(t, string(obj["sha256"].(json.String)), c.sha)
	testing.expect_value(t, string(obj["label"].(json.String)), "Work VPN")
	options, _ := obj["options"].(json.Array)
	testing.expect_value(t, len(options), 10)
	ignored := 0
	for o in options {
		oo, _ := o.(json.Object)
		testing.expect(t, "name" in oo && "line" in oo && "note" in oo)
		disp := string(oo["disposition"].(json.String))
		testing.expect(t, disp == "supported" || disp == "ignored")
		if disp == "ignored" {
			ignored += 1
		}
	}
	// verb and daemon; disable-dco is kept (the profile runs without DCO).
	testing.expect_value(t, ignored, 2)
	for o in options {
		oo, _ := o.(json.Object)
		if string(oo["name"].(json.String)) == "disable-dco" {
			testing.expect_value(t, string(oo["disposition"].(json.String)), "supported")
			testing.expect_value(t, string(oo["note"].(json.String)), config.DISABLE_DCO_NOTE)
		}
	}
	first, _ := options[0].(json.Object)
	testing.expect_value(t, string(first["name"].(json.String)), "client")
	testing.expect_value(t, int(first["line"].(json.Integer)), 1)
	_, note_null := first["note"].(json.Null)
	testing.expect(t, note_null)
	notes, notes_ok := obj["notes"].(json.Array)
	testing.expect(t, notes_ok)
	testing.expect_value(t, len(notes), 0)
}

@(test)
test_profile_check_hash_is_of_the_text :: proc(t: ^testing.T) {
	a := profile_check_run(GOOD_PROFILE)
	defer profile_check_destroy(&a)
	b := profile_check_run(GOOD_PROFILE + "\n")
	defer profile_check_destroy(&b)
	testing.expect(t, a.sha != b.sha)
	want := sha256_hex(GOOD_PROFILE)
	defer delete(want)
	testing.expect_value(t, a.sha, want)
}

@(test)
test_profile_check_every_class_in_one_pass :: proc(t: ^testing.T) {
	text := "client\nremote 192.0.2.1\nca /etc/passwd\nbus-allow uid 0 admin\nup /bin/sh\nserver 10.8.0.0 255.255.255.0\nfrobnicate 1\n"
	c := profile_check_run(text)
	defer profile_check_destroy(&c)
	testing.expect_value(t, problem_classes(&c), "path service not_supported server_only unknown ")
	// In the order of the lines.
	line := 0
	for p in c.problems {
		testing.expect(t, p.line > line)
		line = p.line
	}
	testing.expect_value(t, c.problems[0].option, "ca")
	testing.expect_value(t, c.problems[0].line, 3)
	testing.expect_value(t, c.problems[4].option, "frobnicate")
}

@(test)
test_profile_check_settings_problems :: proc(t: ^testing.T) {
	// The build accepts these. The keys of the daemon do not parse.
	text := "client\nremote 192.0.2.1\n" + CA_BLOCK + ID_BLOCKS + "<tls-crypt>\nnot a key\n</tls-crypt>\n"
	c := profile_check_run(text)
	defer profile_check_destroy(&c)
	testing.expect_value(t, problem_classes(&c), "invalid ")
	testing.expect_value(t, c.problems[0].option, "tls-crypt")
	testing.expect_value(t, c.problems[0].line, 18)
	testing.expect(t, c.problems[0].reason != "")
}

@(test)
test_profile_check_login_block :: proc(t: ^testing.T) {
	good := "client\nremote 192.0.2.1\n" + CA_BLOCK + "<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n"
	c := profile_check_run(good)
	testing.expect_value(t, len(c.problems), 0)
	profile_check_destroy(&c)

	// One line only: no password.
	bad := "client\nremote 192.0.2.1\n" + CA_BLOCK + "<auth-user-pass>\nalice\n</auth-user-pass>\n"
	d := profile_check_run(bad)
	defer profile_check_destroy(&d)
	testing.expect_value(t, problem_classes(&d), "invalid ")
	testing.expect_value(t, d.problems[0].option, "auth-user-pass")
	testing.expect_value(t, d.problems[0].line, 8)
	// The text of the problem has no password.
	testing.expect(t, !strings.contains(d.problems[0].reason, "alice"))
}

@(test)
test_profile_check_warnings_are_notes :: proc(t: ^testing.T) {
	// `float` is accepted and not applied: the daemon says so.
	c := profile_check_run("client\nremote 192.0.2.1\nfloat\n" + CA_BLOCK + ID_BLOCKS)
	defer profile_check_destroy(&c)
	testing.expect_value(t, len(c.problems), 0)
	testing.expect_value(t, len(c.set.warnings), 1)
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	profile_write_result(&w, &c, "x")
	bus.end(&w)
	testing.expect(t, strings.contains(bus.writer_string(&w), `"notes":["float:`))
}

@(test)
test_profile_details_writer :: proc(t: ^testing.T) {
	ps := []config.User_Problem {
		{line = 3, option = "ca", class = "path", reason = "a file"},
		{line = 0, option = "", class = "invalid", reason = `quote " and \ and` + "\n"},
	}
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	profile_write_details(&w, ps)
	v, err := json.parse(transmute([]u8)bus.writer_string(&w), .JSON, true, context.temp_allocator)
	testing.expect_value(t, err, json.Error.None)
	arr, ok := v.(json.Array)
	testing.expect(t, ok)
	testing.expect_value(t, len(arr), 2)
	o0, _ := arr[0].(json.Object)
	testing.expect_value(t, int(o0["line"].(json.Integer)), 3)
	testing.expect_value(t, string(o0["option"].(json.String)), "ca")
	testing.expect_value(t, string(o0["class"].(json.String)), "path")
	testing.expect_value(t, string(o0["reason"].(json.String)), "a file")
	o1, _ := arr[1].(json.Object)
	testing.expect_value(t, int(o1["line"].(json.Integer)), 0)
	testing.expect_value(t, string(o1["reason"].(json.String)), `quote " and \ and` + "\n")
}

@(test)
test_profile_details_writer_cap :: proc(t: ^testing.T) {
	ps := make([]config.User_Problem, PROBLEMS_MAX + 50, context.temp_allocator)
	for &p in ps {
		p = {line = 1, option = "x", class = "unknown", reason = "r"}
	}
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	profile_write_details(&w, ps)
	v, _ := json.parse(transmute([]u8)bus.writer_string(&w), .JSON, true, context.temp_allocator)
	arr, _ := v.(json.Array)
	testing.expect_value(t, len(arr), PROBLEMS_MAX)
}

// ---- the profile in the daemon ----

@(private = "file")
Test_Daemon :: struct {
	d:    ^Daemon,
	base: ^config.Config,
}

@(private = "file")
test_daemon_make :: proc(t: ^testing.T, base_text: string) -> (td: Test_Daemon, ok: bool) {
	td.base = new(config.Config)
	td.base^ = config.build(config.parse_text(base_text, "base"))
	if !config.ok(td.base) {
		testing.expectf(t, false, "base config: %s", config.format_diagnostics(td.base.diags, context.temp_allocator))
		config.destroy(td.base)
		free(td.base)
		return {}, false
	}
	td.d = new(Daemon)
	d := td.d
	// `daemon_destroy` closes the descriptors of the loop: a zero loop would close descriptor 0.
	if event.init(&d.loop) != .None {
		testing.expect(t, false, "event loop")
	}
	d.cfgw = td.base
	d.cfg = &td.base.client
	d.service = true
	d.hold = true
	d.state_reason = "no_profile"
	d.bus_state = "stopped"
	return td, true
}

@(private = "file")
test_daemon_destroy :: proc(td: ^Test_Daemon) {
	daemon_destroy(td.d)
	free(td.d)
	config.destroy(td.base)
	free(td.base)
}

@(private = "file")
install :: proc(t: ^testing.T, d: ^Daemon, text, label: string, uid: u32) -> bool {
	c := profile_check_run(text)
	defer profile_check_destroy(&c)
	if len(c.problems) > 0 {
		testing.expectf(t, false, "problems: %v", c.problems[0])
		return false
	}
	return service_install(d, &c, label, false, uid)
}

BASE_TEXT :: "client-service\nverb 3\nworkers 0\ndatapath userspace\nstats-interval 7\nwritepid /dev/null\n"

@(test)
test_profile_install_and_clear_leave_no_memory :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d

	testing.expect(t, install(t, d, GOOD_PROFILE, "one", 1000))
	testing.expect(t, d.prof_loaded)
	testing.expect_value(t, d.prof_label, "one")
	testing.expect_value(t, len(d.prof_sha), 64)
	testing.expect_value(t, d.owner, Maybe(u32)(1000))
	testing.expect(t, d.cfg == &d.prof.cfg.client)
	testing.expect_value(t, len(d.cfg.connections), 1)
	testing.expect_value(t, len(d.proxy_basic), 1)
	testing.expect(t, d.hold)
	testing.expect_value(t, d.state_reason, "profile_set")

	// A second profile replaces the first (and the memory of the first goes).
	two := strings.concatenate({GOOD_PROFILE, "remote 192.0.2.2 443 tcp\npersist-tun\n"}, context.temp_allocator)
	testing.expect(t, install(t, d, two, "two", 1001))
	testing.expect_value(t, d.prof_label, "two")
	testing.expect_value(t, d.owner, Maybe(u32)(1001))
	testing.expect_value(t, len(d.cfg.connections), 2)
	testing.expect(t, d.persist_cfg)

	service_unload(d)
	testing.expect(t, !d.prof_loaded)
	testing.expect_value(t, d.prof_label, "")
	testing.expect_value(t, d.prof_sha, "")
	testing.expect_value(t, d.owner, Maybe(u32)(nil))
	testing.expect(t, d.cfg == &td.base.client)
	testing.expect(t, d.proxy_basic == nil)
	testing.expect(t, !d.persist_cfg)
	// A second unload does nothing.
	service_unload(d)

	// And again, ending with the profile still loaded: the daemon frees it.
	testing.expect(t, install(t, d, GOOD_PROFILE, "three", 1000))
}

@(test)
test_profile_install_takes_the_service_settings_from_the_base :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	// The profile asks for other values. `verb` and `disable-dco` are removed by the
	// profile rules, and the base values stay in force whatever the profile text is.
	testing.expect(t, install(t, d, GOOD_PROFILE, "x", 1000))
	cl := d.cfg
	testing.expect_value(t, cl.verb, 3)
	testing.expect_value(t, cl.datapath, config.Datapath.Userspace)
	testing.expect_value(t, cl.workers, 0)
	testing.expect_value(t, cl.stats_interval, 7)
	testing.expect_value(t, cl.writepid, "/dev/null")
	testing.expect_value(t, cl.dco_socket, td.base.client.dco_socket)
	testing.expect(t, cl.service)
}

@(test)
test_profile_install_with_a_tls_remote :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	text := strings.concatenate({GOOD_PROFILE, "remote 192.0.2.9 443 tls\n"}, context.temp_allocator)
	testing.expect(t, install(t, d, text, "tls", 1000))
	testing.expect(t, d.tls_ctx_ok)
	testing.expect(t, len(d.olink_out) > 0)
	service_unload(d)
	testing.expect(t, !d.tls_ctx_ok)
	testing.expect(t, d.olink_out == nil)
	testing.expect(t, install(t, d, text, "tls again", 1000))
}

@(test)
test_profile_install_login_wait :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	// No login in the profile: the daemon waits for one over the bus.
	text := strings.concatenate({GOOD_PROFILE, "auth-user-pass\n"}, context.temp_allocator)
	testing.expect(t, install(t, d, text, "pw", 1000))
	testing.expect(t, d.creds_wait)
	testing.expect_value(t, d.creds_reason, "no_credentials")
	testing.expect(t, !d.creds_announced)
	service_unload(d)
	testing.expect(t, !d.creds_wait)

	// A login block: the daemon has it, and it is wiped with the profile.
	inline := strings.concatenate({GOOD_PROFILE, "<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n"}, context.temp_allocator)
	testing.expect(t, install(t, d, inline, "inline", 1000))
	testing.expect(t, !d.creds_wait)
	testing.expect_value(t, string(d.creds.user[:d.creds.user_n]), "alice")
	testing.expect_value(t, string(d.creds.pass[:d.creds.pass_n]), "secret")
	d.creds.token_n = 3
	copy(d.creds.token[:], "abc")
	service_unload(d)
	testing.expect_value(t, d.creds.user_n, 0)
	testing.expect_value(t, d.creds.pass_n, 0)
	testing.expect_value(t, d.creds.token_n, 0)
	testing.expect_value(t, d.creds.pass, [CRED_MAX + 1]u8{})
	testing.expect_value(t, d.creds.token, [CRED_MAX + 1]u8{})
}

@(test)
test_service_stop_and_begin :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	testing.expect(t, install(t, d, GOOD_PROFILE, "x", 1000))
	// The state of a connection that ended: not held, between attempts.
	d.hold = false
	d.bus_state = "waiting"
	testing.expect_value(t, client_bus_state(d), "waiting")

	client.policy_resolved(&d.policy, nil, false, 0)
	client.policy_outcome(&d.policy, .Server_Halt, 0)
	_, stopped := client.policy_stopped(&d.policy)
	testing.expect(t, stopped)

	service_stop(d, "server_halt")
	testing.expect(t, d.hold)
	testing.expect_value(t, client_bus_state(d), "stopped")
	testing.expect_value(t, d.state_reason, "server_halt")
	testing.expect_value(t, d.bus_state, "stopped")
	testing.expect(t, !d.exit)
	testing.expect_value(t, d.exit_code, Exit.Ok)

	// `connect`: the policy is ready again.
	service_begin(d)
	_, stopped = client.policy_stopped(&d.policy)
	testing.expect(t, !stopped)
	a := client.policy_next(&d.policy, 0)
	testing.expect_value(t, a.kind, client.Action_Kind.Resolve)
}

@(test)
test_service_idle :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	testing.expect(t, service_idle(d))
	d.hold = false
	d.bus_state = "waiting"
	testing.expect(t, !service_idle(d)) // waiting
	d.hold = true
	d.state = .Active
	testing.expect(t, !service_idle(d)) // `disconnect` sent, the connection is closing
	d.state = .Idle
	d.s_ok = true
	testing.expect(t, !service_idle(d))
	d.s_ok = false
	d.exit = true
	testing.expect(t, !service_idle(d))
}

@(test)
test_clear_while_the_connection_closes :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	testing.expect(t, install(t, d, GOOD_PROFILE, "one", 1000))

	// Stopped with nothing running: no connection closes.
	testing.expect(t, !service_closing(d))
	// `disconnect` was sent and the session has not ended.
	d.state = .Active
	d.s_ok = true
	testing.expect(t, service_closing(d))
	testing.expect(t, !service_idle(d))
	// Up, with no `disconnect`: not closing.
	d.hold = false
	testing.expect(t, !service_closing(d))
	d.hold = true

	// A clear that came now waits: nothing goes while the connection is there.
	d.clear_pending = true
	service_clear_now(d)
	testing.expect(t, d.prof_loaded)
	testing.expect(t, d.clear_pending)

	// The connection has ended: the profile goes.
	d.state = .Idle
	d.s_ok = false
	service_clear_now(d)
	testing.expect(t, !d.prof_loaded)
	testing.expect(t, !d.clear_pending)
	testing.expect_value(t, d.state_reason, "no_profile")
	testing.expect_value(t, d.owner, Maybe(u32)(nil))
	testing.expect(t, d.cfg == &td.base.client)

	// With no clear asked for, the end of a connection keeps the profile.
	testing.expect(t, install(t, d, GOOD_PROFILE, "two", 1000))
	service_clear_now(d)
	testing.expect(t, d.prof_loaded)

	// A new profile drops a clear that still waited.
	d.clear_pending = true
	testing.expect(t, install(t, d, GOOD_PROFILE, "three", 1000))
	testing.expect(t, !d.clear_pending)
}

// A saved auth-token and a web sign-in belong to one profile: profile.set and
// profile.clear wipe them.
@(test)
test_service_wipes_the_token :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	put_token :: proc(d: ^Daemon) {
		d.creds.token_n = copy(d.creds.token[:], "SESS_ID_AT_secret")
		d.creds.token_user_n = copy(d.creds.token_user[:], "alice")
		d.web.active = true
		d.web.url_n = copy(d.web.url[:], "https://login.example.com/x")
	}
	testing.expect(t, install(t, d, GOOD_PROFILE, "one", 1000))
	put_token(d)
	testing.expect(t, install(t, d, GOOD_PROFILE, "two", 1000))
	testing.expect_value(t, d.creds.token_n, 0)
	testing.expect_value(t, d.creds.token_user_n, 0)
	testing.expect(t, d.creds.token[0] == 0 && !d.web.active && d.web.url_n == 0)
	put_token(d)
	d.clear_pending = true
	service_clear_now(d)
	testing.expect(t, !d.prof_loaded)
	testing.expect_value(t, d.creds.token_n, 0)
	testing.expect(t, d.creds.token[0] == 0)
}

@(test)
test_close_reason_exits :: proc(t: ^testing.T) {
	d: Daemon
	testing.expect(t, close_reason_exits(&d, .Stop))
	testing.expect(t, close_reason_exits(&d, .Fatal))
	testing.expect(t, !close_reason_exits(&d, .Disconnect))
	testing.expect(t, !close_reason_exits(&d, .Restart))
	d.service = true
	testing.expect(t, close_reason_exits(&d, .Stop))
	testing.expect(t, !close_reason_exits(&d, .Fatal))
	testing.expect(t, !close_reason_exits(&d, .Inactive))
}

// ---- status ----

@(private = "file")
status_of :: proc(t: ^testing.T, d: ^Daemon) -> json.Object {
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	client_write_service_status(&w, d)
	bus.end(&w)
	v, err := json.parse(transmute([]u8)bus.writer_string(&w), .JSON, true, context.temp_allocator)
	testing.expect_value(t, err, json.Error.None)
	obj, _ := v.(json.Object)
	return obj
}

@(test)
test_status_fields_without_service :: proc(t: ^testing.T) {
	d := new(Daemon)
	defer free(d)
	d.state_reason = ""
	o := status_of(t, d)
	testing.expect_value(t, bool(o["service"].(json.Boolean)), false)
	_, profile_null := o["profile"].(json.Null)
	testing.expect(t, profile_null)
	_, reason_null := o["reason"].(json.Null)
	testing.expect(t, reason_null)
	// The reason is also given by a daemon that is not a service.
	d.state_reason = "auth_failed"
	d.hold = true
	o = status_of(t, d)
	testing.expect_value(t, string(o["reason"].(json.String)), "auth_failed")
	// Not in the other states.
	d.hold = false
	d.state = .Active
	o = status_of(t, d)
	_, reason_null = o["reason"].(json.Null)
	testing.expect(t, reason_null)
}

@(test)
test_status_fields_of_a_service :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	o := status_of(t, d)
	testing.expect_value(t, bool(o["service"].(json.Boolean)), true)
	p, _ := o["profile"].(json.Object)
	testing.expect_value(t, bool(p["loaded"].(json.Boolean)), false)
	for k in ([]string{"label", "sha256", "owner"}) {
		_, is_null := p[k].(json.Null)
		testing.expectf(t, is_null, "%s is not null", k)
	}
	testing.expect_value(t, string(o["reason"].(json.String)), "no_profile")

	testing.expect(t, install(t, d, GOOD_PROFILE, "Work", 1234))
	o = status_of(t, d)
	p, _ = o["profile"].(json.Object)
	testing.expect_value(t, bool(p["loaded"].(json.Boolean)), true)
	testing.expect_value(t, string(p["label"].(json.String)), "Work")
	testing.expect_value(t, string(p["sha256"].(json.String)), d.prof_sha)
	when ODIN_OS == .Windows {
		// On Windows the owner is the SID of the caller.
		_, is_text := p["owner"].(json.String)
		testing.expect(t, is_text, "owner is not a SID string")
	} else {
		testing.expect_value(t, int(p["owner"].(json.Integer)), 1234)
	}
	testing.expect_value(t, string(o["reason"].(json.String)), "profile_set")
	// The profile text and the keys are nowhere in it.
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	client_write_service_status(&w, d)
	bus.end(&w)
	text := bus.writer_string(&w)
	testing.expect(t, !strings.contains(text, "PRIVATE KEY"))
	testing.expect(t, !strings.contains(text, "CCCC"))
}

@(test)
test_profile_check_network_class :: proc(t: ^testing.T) {
	text := "client\nremote 192.0.2.1\n" + CA_BLOCK + ID_BLOCKS + "dev bad/name\nroute-table 253\nlocal 192.0.2.9\nlport 80\nlog /tmp/x\n"
	c := profile_check_run(text)
	defer profile_check_destroy(&c)
	testing.expect_value(t, problem_classes(&c), "network network network path ")
	testing.expect_value(t, c.problems[0].option, "dev")
	testing.expect_value(t, c.problems[0].line, 18)
	testing.expect_value(t, c.problems[2].option, "lport")

	// Written as the `details` of the reply.
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	profile_write_details(&w, c.problems[:])
	testing.expect(t, strings.contains(bus.writer_string(&w), `"class":"network"`))

	ok := profile_check_run("client\nremote 192.0.2.1 443\n" + CA_BLOCK + ID_BLOCKS + "dev work0\nroute-table 100\n")
	defer profile_check_destroy(&ok)
	testing.expect_value(t, len(ok.problems), 0)
}

// ---- the passphrase of a service profile ----

// A profile of the client service with an encrypted key and `askpass FILE`:
// the service never opens the file. The key waits for its passphrase, which
// the desktop app reads from the file and gives with `auth.supply` (`key_pass`).

@(private = "file")
SK_LOCKED := #load("../proto/ossl/testdata/keypass_pkcs8_p256.key.pem")
@(private = "file")
SK_PASS :: "noir-test-pass"

@(private = "file")
T_Reply :: struct {
	ok:    bool,
	code:  bus.Error_Code,
	wiped: bool,
}

@(private = "file")
t_reply :: proc(tr: ^T_Reply, w: ^bus.Writer) -> Reply {
	return Reply {
		user = tr,
		w = w,
		ok = proc(u: rawptr) {(^T_Reply)(u).ok = true},
		err = proc(u: rawptr, code: bus.Error_Code, text: string) {(^T_Reply)(u).code = code},
		err_details = proc(u: rawptr, code: bus.Error_Code, text: string, details: []u8) {(^T_Reply)(u).code = code},
		wipe_args = proc(u: rawptr) {(^T_Reply)(u).wiped = true},
	}
}

@(private = "file")
supply :: proc(d: ^Daemon, a: Auth_Supply) -> T_Reply {
	tr: T_Reply
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	r := t_reply(&tr, &w)
	op_auth_supply(d, &r, a)
	return tr
}

@(test)
test_service_key_pass_from_the_bus :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	text := strings.concatenate(
		{
			"client\nremote 192.0.2.1 1194 udp\nnobind\n",
			"peer-fingerprint 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\n",
			"<cert>\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n</cert>\n",
			"<key>\n",
			string(SK_LOCKED),
			"</key>\n",
			"askpass /nonexistent/key.pass\n",
		},
		context.temp_allocator,
	)
	chk := profile_check_run(text)
	testing.expectf(t, len(chk.problems) == 0, "%v", chk.problems)
	testing.expect(t, chk.key_encrypted)
	profile_check_destroy(&chk)

	testing.expect(t, install(t, d, text, "locked", 1000))
	testing.expect(t, d.creds_wait && d.creds_key && d.set.key_wait)
	testing.expect_value(t, d.creds_reason, "key_encrypted")

	// A wrong passphrase: the key stays encrypted, and the request is wiped.
	r := supply(d, Auth_Supply{key_pass = "nope"})
	testing.expect(t, !r.ok && r.code == .Bad_Request && r.wiped)
	testing.expect(t, d.creds_key && ossl.key_pem_encrypted(d.set.key_pem))

	r = supply(d, Auth_Supply{key_pass = SK_PASS})
	testing.expect(t, r.ok)
	testing.expect(t, !d.creds_key && !d.creds_wait && !d.set.key_wait)
	testing.expect(t, !ossl.key_pem_encrypted(d.set.key_pem))

	// Nothing waits now.
	r = supply(d, Auth_Supply{key_pass = SK_PASS})
	testing.expect(t, !r.ok && r.code == .Conflict)
	service_unload(d)

	// `auth-user-pass FILE`: the service waits for the login over the bus.
	login := strings.concatenate({GOOD_PROFILE, "auth-user-pass /etc/shadow\n"}, context.temp_allocator)
	testing.expect(t, install(t, d, login, "login", 1000))
	testing.expect(t, d.creds_wait && !d.creds_key)
	testing.expect_value(t, d.creds_reason, "no_credentials")
	aup, has := d.cfg.auth_user_pass.?
	testing.expect(t, has && aup.file == "" && !aup.is_inline)
}

// ---- disable-dco in a service profile ----

@(test)
test_service_profile_disable_dco :: proc(t: ^testing.T) {
	td, ok := test_daemon_make(t, BASE_TEXT)
	if !ok {
		return
	}
	defer test_daemon_destroy(&td)
	d := td.d
	// A service whose base config has a DCO backend (as `datapath auto` found).
	d.dco.want = true
	d.dco.kind = .Kernel
	plain, _ := strings.replace(GOOD_PROFILE, "disable-dco\n", "", 1, context.temp_allocator)
	testing.expect(t, install(t, d, plain, "dco", 1000))
	testing.expect(t, !d.cfg.disable_dco)
	testing.expect_value(t, daemon_datapath(d), "dco")

	testing.expect(t, install(t, d, GOOD_PROFILE, "no dco", 1000))
	testing.expect(t, d.cfg.disable_dco)
	// The data path of the service stays as the base config sets it.
	testing.expect_value(t, d.cfg.datapath, config.Datapath.Userspace)
	testing.expect(t, !dco_for_attempt(d, .Udp, false))
	testing.expect_value(t, daemon_datapath(d), "userspace")
	// Status names the data path setting of the service.
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	client_write_service_status(&w, d)
	bus.end(&w)
	testing.expectf(t, strings.contains(bus.writer_string(&w), `"datapath_mode":"userspace"`), "%s", bus.writer_string(&w))
	d.dco.want = false
	service_unload(d)
}
