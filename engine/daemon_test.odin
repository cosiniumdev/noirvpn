// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:testing"
import "noir:client"
import "noir:proto/config"
import "noir:proto/push"
import "noir:proto/session"

// ---- exit codes and outcomes ----

@(test)
test_stop_exit_codes :: proc(t: ^testing.T) {
	testing.expect_value(t, stop_exit(.Local_Stop), Exit.Ok)
	testing.expect_value(t, stop_exit(.Auth_Failed), Exit.Auth)
	testing.expect_value(t, stop_exit(.Halted), Exit.Halted)
	testing.expect_value(t, stop_exit(.Retries_Exhausted), Exit.Gave_Up)
	testing.expect_value(t, stop_exit(.Resolve_Failed), Exit.Gave_Up)
	testing.expect_value(t, stop_exit(.Inactive), Exit.Limit)
	testing.expect_value(t, stop_exit(.Session_Timeout), Exit.Limit)
	testing.expect_value(t, stop_exit(.No_Remote), Exit.Config)
}

@(test)
test_failure_outcomes :: proc(t: ^testing.T) {
	o, _ := failure_outcome(.Hand_Window, false, {})
	testing.expect_value(t, o, client.Outcome.Handshake_Timeout)
	o, _ = failure_outcome(.Hand_Window, true, {})
	testing.expect_value(t, o, client.Outcome.Ping_Restart)
	o, _ = failure_outcome(.Tls, false, {})
	testing.expect_value(t, o, client.Outcome.Handshake_Failed)
	o, _ = failure_outcome(.Push, false, {})
	testing.expect_value(t, o, client.Outcome.Push_Rejected)
	o, _ = failure_outcome(.Ping_Timeout, true, {})
	testing.expect_value(t, o, client.Outcome.Ping_Restart)
	o, _ = failure_outcome(.Link_Error, false, {})
	testing.expect_value(t, o, client.Outcome.Connect_Failed)
	o, _ = failure_outcome(.No_Push_Reply, false, {})
	testing.expect_value(t, o, client.Outcome.Handshake_Timeout)
}

@(test)
test_failure_outcomes_server_signal :: proc(t: ^testing.T) {
	o, info := failure_outcome(.Server_Signal, true, Pending{kind = .Restart, next_remote = true})
	testing.expect_value(t, o, client.Outcome.Server_Restart)
	testing.expect(t, info.next_remote)
	o, _ = failure_outcome(.Server_Signal, true, Pending{kind = .Halt})
	testing.expect_value(t, o, client.Outcome.Server_Halt)
	o, _ = failure_outcome(.Server_Signal, true, Pending{kind = .Remote_Exit})
	testing.expect_value(t, o, client.Outcome.Remote_Exit)
	// No event before the failure: still a server exit.
	o, _ = failure_outcome(.Server_Signal, true, {})
	testing.expect_value(t, o, client.Outcome.Remote_Exit)
}

@(test)
test_failure_outcomes_auth :: proc(t: ^testing.T) {
	o, _ := failure_outcome(.Auth_Failed, false, Pending{kind = .Auth_Failed, auth_kind = .Plain})
	testing.expect_value(t, o, client.Outcome.Auth_Failed)
	info: client.Outcome_Info
	o, info = failure_outcome(
		.Auth_Failed,
		false,
		Pending{kind = .Auth_Failed, auth_kind = .Temp, backoff = 7, advance = .Remote},
	)
	testing.expect_value(t, o, client.Outcome.Auth_Failed_Temp)
	testing.expect_value(t, info.backoff_secs, 7)
	testing.expect_value(t, info.advance, client.Advance.Remote)
	// A refused token: log in again at once.
	o, _ = failure_outcome(.Auth_Failed, false, Pending{kind = .Auth_Failed, auth_kind = .Session, used_token = true})
	testing.expect_value(t, o, client.Outcome.Local_Restart)
	// A refused password stays a refusal even for SESSION.
	o, _ = failure_outcome(.Auth_Failed, false, Pending{kind = .Auth_Failed, auth_kind = .Session})
	testing.expect_value(t, o, client.Outcome.Auth_Failed)
}

@(test)
test_close_reasons :: proc(t: ^testing.T) {
	testing.expect_value(t, close_outcome(.Stop), client.Outcome.Local_Stop)
	testing.expect_value(t, close_outcome(.Restart), client.Outcome.Local_Restart)
	testing.expect_value(t, close_outcome(.Inactive), client.Outcome.Inactive)
	testing.expect_value(t, close_outcome(.Session_Timeout), client.Outcome.Session_Timeout)
	testing.expect(t, close_reason_stops(.Stop))
	testing.expect(t, close_reason_stops(.Fatal))
	testing.expect(t, !close_reason_stops(.Restart))
	testing.expect(t, !close_reason_stops(.Inactive))
}

@(test)
test_advance_mapping :: proc(t: ^testing.T) {
	testing.expect_value(t, advance_of(.Unset), client.Advance.Default)
	testing.expect_value(t, advance_of(.No), client.Advance.No)
	testing.expect_value(t, advance_of(.Addr), client.Advance.Addr)
	testing.expect_value(t, advance_of(.Remote), client.Advance.Remote)
}

// ---- credentials ----

@(test)
test_cred_parse :: proc(t: ^testing.T) {
	c: Creds
	defer cred_wipe(&c)
	testing.expect_value(t, cred_parse(&c, "alice\nsecret\n", false), Cred_Error.None)
	testing.expect_value(t, string(c.user[:c.user_n]), "alice")
	testing.expect_value(t, string(c.pass[:c.pass_n]), "secret")
	testing.expect(t, c.have)

	// CRLF line ends, no final newline, spaces inside kept.
	testing.expect_value(t, cred_parse(&c, "bob\r\nsec ret\r\n", false), Cred_Error.None)
	testing.expect_value(t, string(c.user[:c.user_n]), "bob")
	testing.expect_value(t, string(c.pass[:c.pass_n]), "sec ret")
	testing.expect_value(t, cred_parse(&c, "carol\npw", false), Cred_Error.None)
	testing.expect_value(t, string(c.pass[:c.pass_n]), "pw")
	// Extra lines are ignored.
	testing.expect_value(t, cred_parse(&c, "dave\npw\njunk\n", false), Cred_Error.None)
	testing.expect_value(t, string(c.pass[:c.pass_n]), "pw")
}

@(test)
test_cred_parse_errors :: proc(t: ^testing.T) {
	c: Creds
	defer cred_wipe(&c)
	testing.expect_value(t, cred_parse(&c, "alice\n", false), Cred_Error.Bad_Format)
	testing.expect_value(t, cred_parse(&c, "alice", false), Cred_Error.Bad_Format)
	testing.expect_value(t, cred_parse(&c, "\npw\n", false), Cred_Error.Empty_User)
	testing.expect_value(t, cred_parse(&c, "", false), Cred_Error.Bad_Format)
	testing.expect_value(t, cred_parse(&c, "", true), Cred_Error.Empty_User)
	long := make([]u8, 200, context.temp_allocator)
	for &b in long {
		b = 'x'
	}
	testing.expect_value(t, cred_parse(&c, string(long), true), Cred_Error.Too_Long)
}

@(test)
test_cred_username_only :: proc(t: ^testing.T) {
	c: Creds
	defer cred_wipe(&c)
	testing.expect_value(t, cred_parse(&c, "alice\n", true), Cred_Error.None)
	testing.expect_value(t, c.pass_n, 0)
	testing.expect_value(t, cred_parse(&c, "alice", true), Cred_Error.None)
}

@(test)
test_cred_wipe :: proc(t: ^testing.T) {
	c: Creds
	_ = cred_parse(&c, "alice\nsecret\n", false)
	cred_wipe(&c)
	for b in c.pass {
		testing.expect_value(t, b, 0)
	}
	testing.expect(t, !c.have)
}

@(test)
test_cred_error_text_is_clear :: proc(t: ^testing.T) {
	// Every error has a text, and the text never holds a secret.
	for e in Cred_Error {
		if e == .None {
			continue
		}
		testing.expect(t, len(cred_error_text(e)) > 10)
	}
}

// ---- the packet ring ----

@(test)
test_ring_order_and_drop_oldest :: proc(t: ^testing.T) {
	r: Ring
	testing.expect(t, ring_init(&r, 4))
	defer ring_destroy(&r)
	for i in 0 ..< 6 {
		s := ring_next(&r)
		s.n = i + 1
		ring_commit(&r)
	}
	// Capacity 4, six pushed: the two oldest are gone.
	testing.expect_value(t, r.count, 4)
	testing.expect_value(t, r.dropped, u64(2))
	for k in 0 ..< 4 {
		testing.expect_value(t, ring_at(&r, k).n, k + 3)
	}
	ring_pop(&r, 2)
	testing.expect_value(t, r.count, 2)
	testing.expect_value(t, ring_at(&r, 0).n, 5)
	s := ring_next(&r)
	s.n = 7
	ring_commit(&r)
	testing.expect_value(t, ring_at(&r, 2).n, 7)
	ring_clear(&r)
	testing.expect(t, ring_is_empty(&r))
}

@(test)
test_ring_empty_read_keeps_packets :: proc(t: ^testing.T) {
	// A read that finds nothing takes `ring_next` but never commits. A full
	// ring must not lose the oldest packet to that.
	r: Ring
	testing.expect(t, ring_init(&r, 3))
	defer ring_destroy(&r)
	for i in 0 ..< 3 {
		s := ring_next(&r)
		s.n = 10 + i
		s.sealed = true
		ring_commit(&r)
	}
	for _ in 0 ..< 5 {
		s := ring_next(&r)
		s.n = 99 // scribbles on the spare slot only
	}
	testing.expect_value(t, r.count, 3)
	testing.expect_value(t, ring_at(&r, 0).n, 10)
	testing.expect(t, ring_at(&r, 0).sealed)
	testing.expect_value(t, r.dropped, u64(0))
}

@(test)
test_slot_room :: proc(t: ^testing.T) {
	// The largest tun packet plus the headroom and the tag fits the slot.
	testing.expect(t, session.TUNNEL_HEADROOM + MAX_TUN_PACKET + 16 <= SLOT_SIZE)
	testing.expect(t, MAX_TUN_PACKET >= 1500)
}

// ---- the settings check ----

BASE :: `client
dev tun
remote 192.0.2.1 1194 udp
<ca>
CA
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`

@(private = "file")
settings_for :: proc(extra: string, s: ^Settings) -> (cfg: config.Config, ok: bool) {
	text := concat(BASE, extra)
	cfg = config.build(config.parse_text(text, "test.conf"))
	if !config.ok(&cfg) {
		return cfg, false
	}
	return cfg, settings_load(s, &cfg)
}

@(private = "file")
concat :: proc(a, b: string) -> string {
	buf := make([]u8, len(a) + len(b), context.temp_allocator)
	copy(buf, a)
	copy(buf[len(a):], b)
	return string(buf)
}

@(test)
test_settings_plain :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	cfg, ok := settings_for("", &s)
	defer config.destroy(&cfg)
	testing.expect(t, ok)
	testing.expect_value(t, len(s.conns), 1)
	testing.expect_value(t, s.conns[0].mode, session.Wrap_Mode.None)
	testing.expect_value(t, len(s.ciphers), 3)
	testing.expect_value(t, s.ciphers[0], push.Cipher.Aes_256_Gcm)
	testing.expect_value(t, string(s.ca_pem), "CA\n")
}

@(test)
test_settings_warns_about_unused_options :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	cfg, ok := settings_for("float\n", &s)
	defer config.destroy(&cfg)
	testing.expect(t, ok)
	testing.expect(t, len(s.warnings) >= 1)
}

@(test)
test_settings_bad_tls_crypt_key :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	cfg, ok := settings_for("<tls-crypt>\nnot a key\n</tls-crypt>\n", &s)
	defer config.destroy(&cfg)
	testing.expect(t, !ok)
}

@(test)
test_settings_missing_file :: proc(t: ^testing.T) {
	s: Settings
	defer settings_destroy(&s)
	text := "client\nremote 192.0.2.1 1194 udp\nca /nonexistent/ca.crt\n"
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	if !config.ok(&cfg) {
		return
	}
	testing.expect(t, !settings_load(&s, &cfg))
}

@(test)
test_tun_name :: proc(t: ^testing.T) {
	testing.expect_value(t, tun_name_of("tun"), "")
	when ODIN_OS == .Darwin {
		// A utun interface is `utunN` or the system's choice, whatever else is asked.
		testing.expect_value(t, tun_name_of("utun7"), "utun7")
		testing.expect_value(t, tun_name_of("tun7"), "")
		testing.expect_value(t, tun_name_of("noir0"), "")
		testing.expect_value(t, utun_dev_warning("tun"), "")
		testing.expect_value(t, utun_dev_warning("utun3"), "")
		testing.expect(t, utun_dev_warning("tun0") != "")
	} else {
		testing.expect_value(t, tun_name_of("tun7"), "tun7")
	}
}

@(test)
test_log_levels :: proc(t: ^testing.T) {
	log_set_verb(1)
	defer log_set_verb(1)
	testing.expect(t, log_enabled(.Error))
	testing.expect(t, log_enabled(.Notice))
	testing.expect(t, !log_enabled(.Info))
	testing.expect(t, log_enabled(.Status))
	log_set_verb(0)
	testing.expect(t, !log_enabled(.Warn))
	testing.expect(t, log_enabled(.Status))
	log_set_verb(4)
	testing.expect(t, log_enabled(.Debug))
}

// ---- pull-filter hook ----

@(test)
test_pull_filter_hook :: proc(t: ^testing.T) {
	text := concat(BASE, "pull-filter ignore \"route \"\npull-filter reject \"redirect-gateway\"\n")
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	d: Daemon
	d.cfg = &cfg.client
	defer {
		client_clear_push(&d)
		delete(d.push_lines)
	}

	out: [256]u8
	opts := "route 10.1.0.0 255.255.0.0,ping 5,route-gateway 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0"
	n, why, ok := pull_filter_hook(&d, opts, out[:])
	testing.expect(t, ok)
	testing.expect_value(t, why, "")
	got := string(out[:n])
	testing.expect_value(t, got, "ping 5,route-gateway 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0")
	testing.expect_value(t, d.filter_ignored, 1)
	// The bus gets the lines that were kept.
	testing.expect_value(t, len(d.push_lines), 3)
	testing.expect_value(t, d.push_lines[0], "ping 5")

	_, why2, ok2 := pull_filter_hook(&d, "ping 5,redirect-gateway def1", out[:])
	testing.expect(t, !ok2)
	testing.expect(t, len(why2) > 0)
}
