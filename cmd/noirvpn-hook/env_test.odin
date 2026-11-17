// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:unicode/utf8"
import "noir:bus"

// An event as the subscriber would give it. The text is the envelope.
event_of :: proc(t: ^testing.T, topic, envelope: string, loc := #caller_location) -> bus.Event {
	msg := fmt.aprintf("%s %s", topic, envelope)
	ev, err := bus.parse_event(transmute([]byte)msg)
	testing.expectf(t, err == .None, "bad test event: %s", envelope, loc = loc)
	return ev
}

env_value :: proc(env: []string, name: string) -> (string, bool) {
	prefix := strings.concatenate({name, "="}, context.temp_allocator)
	for e in env {
		if strings.has_prefix(e, prefix) {
			return e[len(prefix):], true
		}
	}
	return "", false
}

@(test)
names_are_made_safe :: proc(t: ^testing.T) {
	cases := [][2]string {
		{"session", "NOIR_SESSION"},
		{"real_addr", "NOIR_REAL_ADDR"},
		{"vpn4", "NOIR_VPN4"},
		{"a-b.c d", "NOIR_A_B_C_D"},
		{"Name", "NOIR_NAME"},
		{"x=y", "NOIR_X_Y"},
		{"naïve", "NOIR_NA_VE"},
		{"9lives", "NOIR_9LIVES"},
		{"a\nb", "NOIR_A_B"},
	}
	for c in cases {
		got, ok := env_name(c[0], context.temp_allocator)
		testing.expect(t, ok)
		testing.expectf(t, got == c[1], "%q became %q, want %q", c[0], got, c[1])
		// Whatever the input, only A-Z 0-9 and _ are left.
		for ch in got {
			testing.expect(t, (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_')
		}
	}
	_, ok := env_name("", context.temp_allocator)
	testing.expect(t, !ok)
}

@(test)
event_variables :: proc(t: ^testing.T) {
	ev := event_of(
		t,
		"peer.connect",
		`{"v":1,"run":"9f3a0c51d27be8a4","seq":42,"ts":"2026-11-09T12:34:56.789Z","topic":"peer.connect","data":{"session":"s-17","peer_id":3,"name":"alice","pin":null,"vpn4":"10.8.0.2","connected":true,"ratio":1.5,"peer_info":{"IV_VER":"2.6.8"},"push":["a","b"],"bytes_in":12345678901}}`,
	)
	defer bus.event_destroy(&ev)
	env := build_env(&ev, {"PATH=/bin", "HOME=/nonexistent"})
	defer env_destroy(env)

	want := [?][2]string {
		{"PATH", "/bin"},
		{"HOME", "/nonexistent"},
		{"NOIR_TOPIC", "peer.connect"},
		{"NOIR_SEQ", "42"},
		{"NOIR_RUN", "9f3a0c51d27be8a4"},
		{"NOIR_TS", "2026-11-09T12:34:56.789Z"},
		{"NOIR_SESSION", "s-17"},
		{"NOIR_PEER_ID", "3"},
		{"NOIR_NAME", "alice"},
		{"NOIR_PIN", ""},
		{"NOIR_VPN4", "10.8.0.2"},
		{"NOIR_CONNECTED", "true"},
		{"NOIR_RATIO", "1.5"},
		{"NOIR_BYTES_IN", "12345678901"},
	}
	for w in want {
		got, found := env_value(env, w[0])
		testing.expectf(t, found, "%s is missing", w[0])
		testing.expectf(t, got == w[1], "%s=%q, want %q", w[0], got, w[1])
	}
	// Objects and arrays are not passed, and nothing else is added.
	_, has_info := env_value(env, "NOIR_PEER_INFO")
	_, has_push := env_value(env, "NOIR_PUSH")
	testing.expect(t, !has_info && !has_push)
	testing.expect_value(t, len(env), len(want))
	// No gap and no restart: those variables are not there.
	_, has_gap := env_value(env, "NOIR_GAP")
	_, has_rest := env_value(env, "NOIR_RESTARTED")
	testing.expect(t, !has_gap && !has_rest)
}

@(test)
gap_and_restart_variables :: proc(t: ^testing.T) {
	ev := event_of(t, "daemon.start", `{"v":1,"run":"9f3a0c51d27be8a4","seq":1,"ts":"2026-11-09T12:34:56.789Z","topic":"daemon.start","data":{}}`)
	defer bus.event_destroy(&ev)
	ev.gap = 7
	ev.restarted = true
	env := build_env(&ev, nil)
	defer env_destroy(env)
	gap, _ := env_value(env, "NOIR_GAP")
	rest, _ := env_value(env, "NOIR_RESTARTED")
	testing.expect_value(t, gap, "7")
	testing.expect_value(t, rest, "1")
	testing.expect_value(t, len(env), 6)
}

@(test)
data_cannot_replace_the_event_variables :: proc(t: ^testing.T) {
	// A data field named like a reserved variable, or like another one after
	// the name is sanitized, does not win.
	ev := event_of(
		t,
		"x.test",
		`{"v":1,"run":"9f3a0c51d27be8a4","seq":5,"ts":"2026-11-09T12:34:56.789Z","topic":"x.test","data":{"topic":"evil","seq":99,"run":"evil","ts":"evil","gap":1000,"restarted":"yes","a-b":"first","a_b":"second","A.B":"third"}}`,
	)
	defer bus.event_destroy(&ev)
	env := build_env(&ev, nil)
	defer env_destroy(env)
	topic, _ := env_value(env, "NOIR_TOPIC")
	seq, _ := env_value(env, "NOIR_SEQ")
	run, _ := env_value(env, "NOIR_RUN")
	ts, _ := env_value(env, "NOIR_TS")
	testing.expect_value(t, topic, "x.test")
	testing.expect_value(t, seq, "5")
	testing.expect_value(t, run, "9f3a0c51d27be8a4")
	testing.expect_value(t, ts, "2026-11-09T12:34:56.789Z")
	_, has_gap := env_value(env, "NOIR_GAP")
	_, has_rest := env_value(env, "NOIR_RESTARTED")
	testing.expect(t, !has_gap && !has_rest)
	// Of "A.B", "a-b" and "a_b" (sorted by field name) the first wins.
	count := 0
	for e in env {
		if strings.has_prefix(e, "NOIR_A_B=") {
			count += 1
		}
	}
	testing.expect_value(t, count, 1)
	v, _ := env_value(env, "NOIR_A_B")
	testing.expect_value(t, v, "third")
}

@(test)
bad_values_are_left_out_or_cut :: proc(t: ^testing.T) {
	long := strings.repeat("é", ENV_VALUE_MAX, context.temp_allocator) // 2 bytes each
	envelope := fmt.tprintf(
		`{{"v":1,"run":"9f3a0c51d27be8a4","seq":5,"ts":"2026-11-09T12:34:56.789Z","topic":"x.test","data":{{"nul":"a\u0000b","long":"%s","newline":"l1\nl2","quote":"say \"hi\" $(id) `+"`id`"+`"}}}}`,
		long,
	)
	ev := event_of(t, "x.test", envelope)
	defer bus.event_destroy(&ev)
	env := build_env(&ev, nil)
	defer env_destroy(env)
	// A value with a NUL byte is dropped.
	_, has_nul := env_value(env, "NOIR_NUL")
	testing.expect(t, !has_nul)
	// A long value is cut at a character boundary.
	l, has_long := env_value(env, "NOIR_LONG")
	testing.expect(t, has_long)
	testing.expect_value(t, len(l), ENV_VALUE_MAX)
	testing.expect(t, utf8.valid_string(l))
	// Other characters are kept as they are: they are data.
	nl, _ := env_value(env, "NOIR_NEWLINE")
	testing.expect_value(t, nl, "l1\nl2")
	q, _ := env_value(env, "NOIR_QUOTE")
	testing.expect_value(t, q, "say \"hi\" $(id) `id`")
	// No entry has a NUL byte.
	for e in env {
		testing.expect(t, !strings.contains_rune(e, 0))
	}
}

@(test)
cutting_stays_on_a_character :: proc(t: ^testing.T) {
	testing.expect_value(t, cut_utf8("abc", 10), "abc")
	testing.expect_value(t, cut_utf8("abc", 2), "ab")
	testing.expect_value(t, cut_utf8("aé", 2), "a") // é is two bytes
	testing.expect_value(t, cut_utf8("aé", 3), "aé")
	testing.expect_value(t, cut_utf8("€", 2), "")
}

lookup_test_env :: proc(name: string) -> (string, bool) {
	switch name {
	case "PATH":
		return "/opt/bin:/bin", true
	case "HOME":
		return "/var/lib/hook", true
	case "SECRET":
		return "nope", true
	case "TZ":
		return "UTC", true
	}
	return "", false
}

lookup_no_path :: proc(name: string) -> (string, bool) {
	if name == "LANG" {
		return "C.UTF-8", true
	}
	if name == "PATH" {
		return "", true
	}
	return "", false
}

@(test)
base_environment_is_short :: proc(t: ^testing.T) {
	env := base_env(lookup_test_env)
	defer env_destroy(env)
	testing.expect_value(t, len(env), 3)
	path, _ := env_value(env, "PATH")
	home, _ := env_value(env, "HOME")
	tz, _ := env_value(env, "TZ")
	testing.expect_value(t, path, "/opt/bin:/bin")
	testing.expect_value(t, home, "/var/lib/hook")
	testing.expect_value(t, tz, "UTC")
	_, leaked := env_value(env, "SECRET")
	testing.expect(t, !leaked)

	// Without a PATH (or with an empty one) there is a default.
	env2 := base_env(lookup_no_path)
	defer env_destroy(env2)
	path2, _ := env_value(env2, "PATH")
	testing.expect_value(t, path2, DEFAULT_PATH)
	lang, _ := env_value(env2, "LANG")
	testing.expect_value(t, lang, "C.UTF-8")
}
