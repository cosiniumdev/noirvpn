// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:encoding/base64"
import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:proto/config"
import "noir:server"

// Parses the text of a writer into a JSON object (temp allocator).
@(private = "file")
parse_obj :: proc(t: ^testing.T, w: ^bus.Writer) -> json.Object {
	text := bus.writer_string(w)
	v, err := json.parse(transmute([]u8)text, .JSON, true, context.temp_allocator)
	testing.expectf(t, err == .None, "not JSON (%v): %s", err, text)
	obj, ok := v.(json.Object)
	testing.expectf(t, ok, "not an object: %s", text)
	return obj
}

@(private = "file")
has_null :: proc(o: json.Object, k: string) -> bool {
	v, ok := o[k]
	if !ok {
		return false
	}
	_, is_null := v.(json.Null)
	return is_null
}

@(private = "file")
str_of :: proc(o: json.Object, k: string) -> string {
	if s, ok := o[k].(json.String); ok {
		return string(s)
	}
	return "<missing>"
}

@(private = "file")
int_of :: proc(o: json.Object, k: string) -> i64 {
	if n, ok := o[k].(json.Integer); ok {
		return i64(n)
	}
	return -1
}

// ---------------------------------------------------------------- the peer

@(test)
test_peer_object_has_every_key :: proc(t: ^testing.T) {
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)

	spki: [32]u8
	for i in 0 ..< 32 {
		spki[i] = u8(i)
	}
	ts := time.Time{_nsec = 1_700_000_000 * 1_000_000_000}
	v := Peer_View {
		session      = "s-7",
		peer_id      = u32(3),
		name         = "alice",
		has_name     = true,
		name_from    = "controller",
		pin          = spki,
		has_pin      = true,
		state        = "up",
		real_addr    = "192.0.2.7:51234",
		proto        = "udp",
		backend      = "service",
		vpn4         = [4]u8{10, 8, 0, 2},
		vpn6         = nil,
		cipher       = "AES-256-GCM",
		data_format  = "epoch",
		connected_at = ts,
		bytes_in     = 11,
		bytes_out    = 22,
		packets_in   = 3,
		packets_out  = 4,
		proofs       = {.Chain, .Password},
	}
	write_peer(&w, &v)
	o := parse_obj(t, &w)
	testing.expect(t, strings.contains(string(bus.writer_bytes(&w)), `"proofs":["chain","password"]`))
	testing.expect_value(t, len(o), 19)
	testing.expect_value(t, str_of(o, "backend"), "service")
	testing.expect_value(t, str_of(o, "session"), "s-7")
	testing.expect_value(t, str_of(o, "data_format"), "epoch")
	testing.expect_value(t, str_of(o, "name"), "alice")
	testing.expect_value(t, str_of(o, "identity_source"), "controller")
	testing.expect_value(t, str_of(o, "pin"), "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	testing.expect_value(t, str_of(o, "vpn4"), "10.8.0.2")
	testing.expect(t, has_null(o, "vpn6"))
	testing.expect_value(t, str_of(o, "state"), "up")
	testing.expect_value(t, str_of(o, "connected_at"), "2023-11-14T22:13:20.000Z")
	testing.expect_value(t, int_of(o, "peer_id"), i64(3))
	testing.expect_value(t, int_of(o, "bytes_in"), i64(11))
	testing.expect_value(t, int_of(o, "packets_out"), i64(4))

	// A session that is not up yet: the unknown parts are null, not missing.
	bus.writer_reset(&w)
	v2 := Peer_View {
		session   = "s-8",
		state     = "handshake",
		real_addr = "[2001:db8::1]:1194",
		proto     = "tcp",
	}
	write_peer(&w, &v2)
	o2 := parse_obj(t, &w)
	testing.expect_value(t, len(o2), 19)
	testing.expect_value(t, str_of(o2, "backend"), "daemon") // the default
	for k in ([]string{"peer_id", "name", "identity_source", "pin", "vpn4", "vpn6", "cipher", "data_format", "connected_at"}) {
		testing.expectf(t, has_null(o2, k), "%s should be null", k)
	}
}

@(test)
test_auth_fail_object :: proc(t: ^testing.T) {
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)

	bus.begin_obj(&w)
	v := Auth_Fail_View {
		session   = "s-2",
		has_sess  = true,
		name      = "bob",
		has_name  = true,
		real_addr = "192.0.2.9:1000",
		proto     = "tcp",
		reason    = "external_denied",
		detail    = "not today",
		has_detail = true,
	}
	write_auth_fail(&w, &v)
	bus.end(&w)
	o := parse_obj(t, &w)
	testing.expect_value(t, str_of(o, "reason"), "external_denied")
	testing.expect_value(t, str_of(o, "detail"), "not today")
	testing.expect_value(t, str_of(o, "name"), "bob")
	testing.expect(t, has_null(o, "pin"))

	bus.writer_reset(&w)
	bus.begin_obj(&w)
	v3 := Auth_Fail_View {
		real_addr = "192.0.2.9:1000",
		proto     = "udp",
		reason    = "unknown_key",
	}
	write_auth_fail(&w, &v3)
	bus.end(&w)
	o3 := parse_obj(t, &w)
	testing.expect(t, has_null(o3, "session"))
	testing.expect(t, has_null(o3, "detail"))
	testing.expect(t, has_null(o3, "name"))
}

// ----------------------------------------------------------------- reasons

@(test)
test_disconnect_reasons :: proc(t: ^testing.T) {
	testing.expect_value(t, disconnect_reason(.Client_Exit), "client_exit")
	testing.expect_value(t, disconnect_reason(.Kicked), "replaced")
	testing.expect_value(t, disconnect_reason(.Kicked_Key), "replaced")
	testing.expect(t, end_text(.Kicked) != end_text(.Kicked_Key))
	testing.expect_value(t, disconnect_reason(.Admin_Kick), "kicked")
	testing.expect_value(t, disconnect_reason(.Revoked), "key_revoked")
	testing.expect_value(t, disconnect_reason(.Shutdown), "server_stop")
	testing.expect_value(t, disconnect_reason(.Limit), "session_timeout")
	testing.expect_value(t, disconnect_reason(.Timeout), "timeout")
	testing.expect_value(t, disconnect_reason(.Tcp_Lost), "transport_closed")
	testing.expect_value(t, disconnect_reason(.Failed), "protocol_error")
	testing.expect_value(t, disconnect_reason(.Cert_Revoked), "cert_revoked")
	testing.expect_value(t, disconnect_reason(.Crl_Failed), "crl_failed")
	testing.expect_value(t, disconnect_reason(.Password_Gone), "user_removed")
	testing.expect_value(t, disconnect_reason(.Password_Changed), "password_changed")
	testing.expect_value(t, disconnect_reason(.Reauth_Refused), "reauth_failed")
	testing.expect_value(t, disconnect_reason(.Closed), "error")
	// Every end reason has a word from the document's list (none may be empty).
	for r in End_Reason {
		testing.expect(t, disconnect_reason(r) != "")
	}
}

@(test)
test_auth_fail_reasons :: proc(t: ^testing.T) {
	testing.expect_value(t, auth_fail_reason(.Key_Not_Pinned), "unknown_key")
	testing.expect_value(t, auth_fail_reason(.Key_Disabled), "key_disabled")
	testing.expect_value(t, auth_fail_reason(.Client_Disabled), "key_disabled")
	testing.expect_value(t, auth_fail_reason(.Username_Mismatch), "name_mismatch")
	testing.expect_value(t, auth_fail_reason(.Chain_Not_Verified), "bad_certificate")
	testing.expect_value(t, auth_fail_reason(.Max_Clients), "max_clients")
	testing.expect_value(t, auth_fail_reason(.Rate_Limited), "rate_limit")
	testing.expect_value(t, auth_fail_reason(.External_Denied), "external_denied")
	testing.expect_value(t, auth_fail_reason(.External_Timeout), "external_timeout")
	testing.expect_value(t, auth_fail_reason(.Password_Missing), "password_missing")
	testing.expect_value(t, auth_fail_reason(.Password_Failed), "password_failed")
	testing.expect_value(t, auth_fail_reason(.Password_Busy), "password_busy")
	// Everything else is an assignment problem, and the detail says which.
	testing.expect_value(t, auth_fail_reason(.Internal), "assignment_failed")
	testing.expect(t, auth_fail_detail(.Internal, "") != "")
	testing.expect_value(t, auth_fail_detail(.Internal, "pool full"), "pool full")
	testing.expect_value(t, auth_fail_detail(.External_Denied, ""), "")
	for r in server.Reject_Reason {
		testing.expect(t, auth_fail_reason(r) != "")
	}
}

@(test)
test_client_state_reasons :: proc(t: ^testing.T) {
	// The outcome of the connection decides when the daemon did not ask for the close.
	testing.expect_value(t, state_reason(.Auth_Failed, .None, .Ok), "auth_failed")
	testing.expect_value(t, state_reason(.Handshake_Failed, .None, .Ok), "tls_failed")
	testing.expect_value(t, state_reason(.Connect_Failed, .None, .Ok), "network_error")
	testing.expect_value(t, state_reason(.Handshake_Timeout, .None, .Ok), "network_error")
	testing.expect_value(t, state_reason(.Ping_Restart, .None, .Ok), "ping_timeout")
	testing.expect_value(t, state_reason(.Server_Restart, .None, .Ok), "server_restart")
	testing.expect_value(t, state_reason(.Remote_Exit, .None, .Ok), "server_restart")
	testing.expect_value(t, state_reason(.Server_Halt, .None, .Ok), "server_halt")
	testing.expect_value(t, state_reason(.Push_Rejected, .None, .Ok), "push_rejected")
	testing.expect_value(t, state_reason(.Datapath_Failed, .None, .Ok), "udco_failed")
	testing.expect_value(t, state_reason(.Local_Stop, .Datapath, .Ok), "udco_failed")
	// A close the daemon started wins over the outcome.
	testing.expect_value(t, state_reason(.Local_Stop, .Disconnect, .Ok), "user_request")
	testing.expect_value(t, state_reason(.Local_Restart, .Restart, .Ok), "user_request")
	testing.expect_value(t, state_reason(.Local_Stop, .Stop, .Ok), "exit")
	testing.expect_value(t, state_reason(.Local_Stop, .Fatal, .Config), "config_error")
	// Reasons for a stop the policy decided.
	testing.expect_value(t, stop_state_reason(.Auth_Failed), "auth_failed")
	testing.expect_value(t, stop_state_reason(.Halted), "server_halt")
	testing.expect_value(t, stop_state_reason(.Retries_Exhausted), "network_error")
	testing.expect_value(t, stop_state_reason(.Local_Stop), "exit")
}

@(test)
test_close_disconnect_does_not_stop_the_daemon :: proc(t: ^testing.T) {
	// `disconnect` closes the connection but the daemon stays alive and waits.
	testing.expect(t, !close_reason_stops(.Disconnect))
	testing.expect_value(t, close_outcome(.Disconnect), client.Outcome.Local_Stop)
	testing.expect(t, close_reason_stops(.Stop))
}

// ---------------------------------------------------------------- the texts

@(test)
test_parse_session :: proc(t: ^testing.T) {
	n, ok := parse_session("s-17")
	testing.expect(t, ok)
	testing.expect_value(t, n, 17)
	n, ok = parse_session("s-0")
	testing.expect(t, ok)
	testing.expect_value(t, n, 0)
	for bad in ([]string{"", "s-", "s", "17", "s-1x", "x-1", "s--1", "s-+1", "S-1", "s-18446744073709551616", "s-999999999999999999999999"}) {
		_, ok2 := parse_session(bad)
		testing.expectf(t, !ok2, "%q should not parse", bad)
	}
	n, ok = parse_session("s-18446744073709551615")
	testing.expect(t, ok)
	testing.expect_value(t, n, 18446744073709551615)
}

@(test)
test_clean_instance_name :: proc(t: ^testing.T) {
	cases := [?][2]string{{"", bus.DEFAULT_NAME}, {"vpn1", "vpn1"}, {"a/b c", "a_b_c"}, {"..", ".."}, {"x\x00y", "x_y"}, {"é", "__"}}
	for c in cases {
		got := clean_instance_name(c[0], context.temp_allocator)
		testing.expect_value(t, got, c[1])
	}
	long := strings.repeat("a", 100, context.temp_allocator)
	testing.expect_value(t, len(clean_instance_name(long, context.temp_allocator)), 40)
}

@(test)
test_clean_reason :: proc(t: ^testing.T) {
	s, ok := clean_reason("not allowed")
	testing.expect(t, ok)
	testing.expect_value(t, s, "not allowed")
	// Control characters are removed: the text goes to a log line and to the client.
	s, ok = clean_reason("a\r\nb\x00c\x1b[31md\x7f")
	testing.expect(t, ok)
	testing.expect_value(t, s, "abc[31md")
	// Exactly 128 characters is fine (here with multi-byte ones), 129 is not.
	s, ok = clean_reason(strings.repeat("é", 128, context.temp_allocator))
	testing.expect(t, ok)
	testing.expect_value(t, len(s), 256)
	_, ok = clean_reason(strings.repeat("é", 129, context.temp_allocator))
	testing.expect(t, !ok)
	_, ok = clean_reason(strings.repeat("a", 129, context.temp_allocator))
	testing.expect(t, !ok)
	s, ok = clean_reason("")
	testing.expect(t, ok)
	testing.expect_value(t, s, "")
}

// ------------------------------------------------------------- peer-info

@(test)
test_peer_info_filter :: proc(t: ^testing.T) {
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)

	text := "IV_VER=2.7.7\nIV_PLAT=linux\nUV_NAME=laptop\nUV_PASSWORD=hunter2\nIV_TOKEN_X=1\nUV_api_Key=zz\nUV_credit=1\nOTHER=1\nIV_NOEQUALS\n=x\nIV_BAD KEY=1\nUV_OK=a=b\r\n"
	write_peer_info(&w, text)
	o := parse_obj(t, &w)
	testing.expect_value(t, str_of(o, "IV_VER"), "2.7.7")
	testing.expect_value(t, str_of(o, "IV_PLAT"), "linux")
	testing.expect_value(t, str_of(o, "UV_NAME"), "laptop")
	testing.expect_value(t, str_of(o, "UV_OK"), "a=b")
	// Secrets by name, other prefixes, and malformed lines are left out.
	for k in ([]string{"UV_PASSWORD", "IV_TOKEN_X", "UV_api_Key", "UV_credit", "OTHER", "IV_NOEQUALS", "IV_BAD KEY"}) {
		_, present := o[k]
		testing.expectf(t, !present, "%s should be dropped", k)
	}
	testing.expect_value(t, len(o), 4)
	testing.expect(t, !strings.contains(bus.writer_string(&w), "hunter2"))

	// A long value is cut; more than 64 keys are cut.
	bus.writer_reset(&w)
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "IV_LONG=")
	strings.write_string(&sb, strings.repeat("x", 1000, context.temp_allocator))
	strings.write_string(&sb, "\n")
	for i in 0 ..< 100 {
		strings.write_string(&sb, "UV_K")
		strings.write_int(&sb, i)
		strings.write_string(&sb, "=v\n")
	}
	write_peer_info(&w, strings.to_string(sb))
	o = parse_obj(t, &w)
	testing.expect_value(t, len(o), PEER_INFO_MAX_KEYS)
	testing.expect_value(t, len(str_of(o, "IV_LONG")), PEER_INFO_MAX_VALUE)

	bus.writer_reset(&w)
	write_peer_info(&w, "")
	o = parse_obj(t, &w)
	testing.expect_value(t, len(o), 0)
}

// ------------------------------------------------------------ the counters

@(test)
test_write_u64_fields :: proc(t: ^testing.T) {
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)

	S :: struct {
		a:    u64,
		name: string,
		b:    u64,
		c:    u32,
	}
	s := S {
		a    = 5,
		name = "x",
		b    = 1 << 40,
		c    = 9,
	}
	bus.begin_obj(&w)
	write_u64_fields(&w, &s)
	write_u64_fields(&w, &s, "p_")
	bus.end(&w)
	o := parse_obj(t, &w)
	testing.expect_value(t, int_of(o, "a"), i64(5))
	testing.expect_value(t, int_of(o, "b"), i64(1 << 40))
	testing.expect_value(t, int_of(o, "p_a"), i64(5))
	// Only 64-bit counters, and no strings.
	_, has_name := o["name"]
	_, has_c := o["c"]
	testing.expect(t, !has_name && !has_c)
	testing.expect_value(t, len(o), 4)

	// The daemon's own counters all go out.
	st := Stats {
		attempts = 2,
	}
	bus.writer_reset(&w)
	bus.begin_obj(&w)
	write_u64_fields(&w, &st)
	bus.end(&w)
	o = parse_obj(t, &w)
	testing.expect_value(t, int_of(o, "attempts"), i64(2))
	testing.expect(t, len(o) >= 10)
}

@(test)
test_block6_counters_are_in_the_bus :: proc(t: ^testing.T) {
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)
	st := Stats {
		drop_block6_tx = 3,
		drop_block6_rx = 4,
	}
	bus.begin_obj(&w)
	write_u64_fields(&w, &st)
	bus.end(&w)
	o := parse_obj(t, &w)
	testing.expect_value(t, int_of(o, "drop_block6_tx"), i64(3))
	testing.expect_value(t, int_of(o, "drop_block6_rx"), i64(4))

	sst := Srv_Stats {
		drop_block6_tx = 5,
		drop_block6_rx = 6,
	}
	bus.writer_reset(&w)
	bus.begin_obj(&w)
	write_u64_fields(&w, &sst)
	bus.end(&w)
	o = parse_obj(t, &w)
	testing.expect_value(t, int_of(o, "drop_block6_tx"), i64(5))
	testing.expect_value(t, int_of(o, "drop_block6_rx"), i64(6))
}

// -------------------------------------------------------- reload and config

@(test)
test_diff_directives :: proc(t: ^testing.T) {
	a := config.parse_text("client\nverb 3\nbus-allow alice\nstats-interval 5\nremote a.example 1194\n", "a.conf")
	b := config.parse_text("client\nverb 4\nbus-allow bob\nstats-interval 9\nremote b.example 1194\nmssfix 1200\n", "b.conf")
	defer config.parsed_destroy(&a)
	defer config.parsed_destroy(&b)
	out: [dynamic]string
	defer {
		for s in out {
			delete(s)
		}
		delete(out)
	}
	diff_directives(a.directives, b.directives, &out)
	// verb, bus-allow and stats-interval are applied by a reload, the rest needs a restart.
	testing.expect_value(t, len(out), 2)
	if len(out) == 2 {
		testing.expect_value(t, out[0], "mssfix")
		testing.expect_value(t, out[1], "remote")
	}

	for s in out {
		delete(s)
	}
	clear(&out)
	diff_directives(a.directives, a.directives, &out)
	testing.expect_value(t, len(out), 0)
}

@(test)
test_mask_bits :: proc(t: ^testing.T) {
	testing.expect_value(t, mask_bits({255, 255, 255, 0}), 24)
	testing.expect_value(t, mask_bits({255, 255, 255, 255}), 32)
	testing.expect_value(t, mask_bits({0, 0, 0, 0}), 0)
	testing.expect_value(t, mask_bits({255, 128, 0, 0}), 9)
}

// ----------------------------------------------------------- push lines

// The check that `auth.decide` runs on the controller's lines: one bad line
// is named by its number, and the good ones come out as a per-user file.
@(test)
test_push_lines_check :: proc(t: ^testing.T) {
	good := []string{"ifconfig-push 10.8.0.50 255.255.255.0", "route 192.168.7.0 255.255.255.0", "dhcp-option DNS 10.8.0.1"}
	text, bad, why := server.controller_check(good, context.temp_allocator)
	testing.expect_value(t, bad, 0)
	testing.expect_value(t, why, "")
	testing.expect(t, strings.contains(text, "ifconfig-push 10.8.0.50 255.255.255.0"))
	testing.expect(t, strings.contains(text, `push "route 192.168.7.0 255.255.255.0"`))

	_, bad, why = server.controller_check([]string{"route 10.0.0.0 255.0.0.0", "route 10.1.0.0 255.0.0.0;reboot"}, context.temp_allocator)
	testing.expect_value(t, bad, 2)
	testing.expect(t, why != "")

	_, bad, _ = server.controller_check([]string{"up /bin/sh"}, context.temp_allocator)
	testing.expect_value(t, bad, 1)
}

// ------------------------------------------------------- the parked wait

@(test)
test_park_deadline_logic :: proc(t: ^testing.T) {
	sec :: time.Second
	// Not parked: the session's own wakeup stands.
	at, ok := park_wake(10 * sec, true, false, 5 * sec)
	testing.expect(t, ok)
	testing.expect_value(t, at, 10 * sec)
	_, ok = park_wake(0, false, false, 5 * sec)
	testing.expect(t, !ok)
	// Parked: the earlier of the two wins, and a session with no wakeup still gets the deadline.
	at, ok = park_wake(10 * sec, true, true, 5 * sec)
	testing.expect(t, ok)
	testing.expect_value(t, at, 5 * sec)
	at, ok = park_wake(3 * sec, true, true, 5 * sec)
	testing.expect_value(t, at, 3 * sec)
	at, ok = park_wake(0, false, true, 5 * sec)
	testing.expect(t, ok)
	testing.expect_value(t, at, 5 * sec)

	// Due: only when parked, and at the deadline itself (the session's hand window
	// ends at the same instant and must not win).
	testing.expect(t, !park_due(false, 5 * sec, 9 * sec))
	testing.expect(t, !park_due(true, 5 * sec, 5 * sec - 1))
	testing.expect(t, park_due(true, 5 * sec, 5 * sec))
	testing.expect(t, park_due(true, 5 * sec, 6 * sec))
}

// ------------------------------------------------------- the credentials

@(test)
test_cred_wipe_password :: proc(t: ^testing.T) {
	c: Creds
	testing.expect_value(t, cred_set(&c, "alice", "s3cret-pass"), Cred_Error.None)
	copy(c.token[:], "tok123")
	c.token_n = 6
	copy(c.token_user[:], "alice")
	c.token_user_n = 5

	cred_wipe_password(&c)
	testing.expect_value(t, c.pass_n, 0)
	testing.expect_value(t, c.token_n, 0)
	// The name stays; the password and the token are zero bytes, not just forgotten.
	testing.expect_value(t, string(c.user[:c.user_n]), "alice")
	zero: [CRED_MAX + 1]u8
	testing.expect(t, mem.compare(c.pass[:], zero[:]) == 0)
	testing.expect(t, mem.compare(c.token[:], zero[:]) == 0)
	testing.expect(t, mem.compare(c.token_user[:], zero[:]) == 0)
	testing.expect(t, !c.have)

	// A new login can be set after the wipe.
	testing.expect_value(t, cred_set(&c, "alice", "new"), Cred_Error.None)
	testing.expect_value(t, string(c.pass[:c.pass_n]), "new")
	testing.expect_value(t, cred_set(&c, "", "x"), Cred_Error.Empty_User)
	long := strings.repeat("p", CRED_MAX + 1, context.temp_allocator)
	testing.expect_value(t, cred_set(&c, "alice", long), Cred_Error.Too_Long)

	cred_wipe(&c)
	testing.expect(t, mem.compare(c.user[:], zero[:]) == 0)
	testing.expect_value(t, c.user_n, 0)
}

// -------------------------------------------------------- peer.kick selectors

@(test)
test_kick_selectors :: proc(t: ^testing.T) {
	// session, peer_id, name, serial
	testing.expect(t, kick_selectors_ok(true, false, false, false))
	testing.expect(t, kick_selectors_ok(false, true, false, false))
	testing.expect(t, kick_selectors_ok(false, false, true, false))
	testing.expect(t, kick_selectors_ok(false, false, false, true))
	testing.expect(t, kick_selectors_ok(false, false, true, true), "name goes with serial")
	testing.expect(t, !kick_selectors_ok(false, false, false, false))
	testing.expect(t, !kick_selectors_ok(true, true, false, false))
	testing.expect(t, !kick_selectors_ok(true, false, true, false))
	testing.expect(t, !kick_selectors_ok(false, true, true, false))
	testing.expect(t, !kick_selectors_ok(true, false, false, true))
	testing.expect(t, !kick_selectors_ok(false, true, false, true))
	testing.expect(t, !kick_selectors_ok(true, false, true, true))
	// pin: alone or with name.
	testing.expect(t, kick_selectors_ok(false, false, false, false, true))
	testing.expect(t, kick_selectors_ok(false, false, true, false, true), "name goes with pin")
	testing.expect(t, !kick_selectors_ok(true, false, false, false, true))
	testing.expect(t, !kick_selectors_ok(false, true, false, false, true))
	testing.expect(t, !kick_selectors_ok(false, false, false, true, true))
}

@(test)
test_pin_parse :: proc(t: ^testing.T) {
	spki: [32]u8
	for i in 0 ..< 32 {
		spki[i] = u8(i * 8 + 3)
	}
	buf: [71]u8
	text := pin_text_hex(spki, &buf)
	got, ok := pin_parse(text)
	testing.expect(t, ok)
	testing.expect_value(t, got, spki)
	// Hex in upper case.
	upper := strings.to_upper(text[7:], context.temp_allocator)
	got, ok = pin_parse(strings.concatenate({"sha256:", upper}, context.temp_allocator))
	testing.expect(t, ok)
	testing.expect_value(t, got, spki)
	// The other prefix, with the same digits (the peer object shows `sha256:` for
	// a key that the peers file pins as `mldsa65-sha256:`).
	got, ok = pin_parse(strings.concatenate({"mldsa65-sha256:", text[7:]}, context.temp_allocator))
	testing.expect(t, ok)
	testing.expect_value(t, got, spki)
	// The form of the peers file: base64 of the hash, with or without padding.
	b64, _ := base64.encode(spki[:], allocator = context.temp_allocator)
	testing.expect_value(t, len(b64), 44)
	for prefix in ([]string{"sha256:", "mldsa65-sha256:"}) {
		got, ok = pin_parse(strings.concatenate({prefix, b64}, context.temp_allocator))
		testing.expectf(t, ok, "%s%s", prefix, b64)
		testing.expect_value(t, got, spki)
		got, ok = pin_parse(strings.concatenate({prefix, strings.trim_right(b64, "=")}, context.temp_allocator))
		testing.expect(t, ok)
		testing.expect_value(t, got, spki)
	}
	// Bad forms.
	bad := [?]string{
		"", "sha256:", text[:70], strings.concatenate({text, "0"}, context.temp_allocator), strings.concatenate({text[:70], "g"}, context.temp_allocator),
		strings.concatenate({"md5:", text[7:]}, context.temp_allocator), text[7:], strings.concatenate({"sha256:", b64[:40]}, context.temp_allocator),
		strings.concatenate({"sha256:", b64, "AAAA"}, context.temp_allocator), "sha256:!!!!", "SHA256:" + "00",
	}
	for b in bad {
		_, ok = pin_parse(b)
		testing.expectf(t, !ok, "%q must be refused", b)
	}
}
