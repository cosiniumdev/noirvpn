// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:strings"
import "core:testing"
import "core:time"
import "noir:bus"

// ---- helpers ----

parse_ok :: proc(t: ^testing.T, argv: ..string, loc := #caller_location) -> Command {
	cmd, err := parse_command(argv)
	msg, _ := err.(string)
	testing.expectf(t, err == nil, "%v: %s", argv, msg, loc = loc)
	return cmd
}

// The parse must fail with a message that contains `want`.
expect_usage :: proc(t: ^testing.T, want: string, argv: ..string, loc := #caller_location) {
	cmd, err := parse_command(argv)
	defer command_destroy(&cmd)
	msg, is_msg := err.(string)
	testing.expectf(t, is_msg, "%v: expected a usage error", argv, loc = loc)
	testing.expectf(t, strings.contains(msg, want), "%v: message '%s' lacks '%s'", argv, msg, want, loc = loc)
}

// The request of a command line: op and args text.
request_of :: proc(t: ^testing.T, argv: ..string, loc := #caller_location) -> (op, args: string) {
	cmd := parse_ok(t, ..argv, loc = loc)
	defer command_destroy(&cmd)
	req, ok := build_request(&cmd, "", "", allocator = context.temp_allocator)
	testing.expectf(t, ok, "%v: no request", argv, loc = loc)
	return req.op, string(req.args)
}

// ---- global options ----

@(test)
global_defaults :: proc(t: ^testing.T) {
	cmd := parse_ok(t, "status")
	defer command_destroy(&cmd)
	testing.expect_value(t, cmd.kind, Kind.Status)
	testing.expect_value(t, cmd.timeout, 5 * time.Second)
	testing.expect(t, !cmd.json)
	testing.expect_value(t, cmd.name, "")
	testing.expect_value(t, cmd.socket, "")
}

@(test)
global_options :: proc(t: ^testing.T) {
	cmd := parse_ok(t, "--name", "srv", "--json", "--timeout", "2.5", "--id", "my-id-1", "status")
	defer command_destroy(&cmd)
	testing.expect_value(t, cmd.name, "srv")
	testing.expect(t, cmd.json)
	testing.expect_value(t, cmd.timeout, 2500 * time.Millisecond)
	testing.expect_value(t, cmd.id, "my-id-1")

	c2 := parse_ok(t, "--socket=/run/x/a.control", "--events-socket", "/run/x/a.events", "--timeout=1", "status")
	defer command_destroy(&c2)
	testing.expect_value(t, c2.socket, "/run/x/a.control")
	testing.expect_value(t, c2.events_socket, "/run/x/a.events")
	testing.expect_value(t, c2.timeout, time.Second)

	// --json also works after the command.
	c3 := parse_ok(t, "status", "--json")
	defer command_destroy(&c3)
	testing.expect(t, c3.json)
}

@(test)
global_option_errors :: proc(t: ^testing.T) {
	expect_usage(t, "unknown option", "--bogus", "status")
	expect_usage(t, "cannot be used together", "--name", "a", "--socket", "/x/a.control", "status")
	expect_usage(t, "--timeout", "--timeout", "0", "status")
	expect_usage(t, "--timeout", "--timeout", "abc", "status")
	expect_usage(t, "--timeout", "--timeout", "-1", "status")
	expect_usage(t, "--timeout", "--timeout", "99999", "status")
	expect_usage(t, "requires a value", "--timeout")
	expect_usage(t, "instance name", "--name", "bad/name", "status")
	expect_usage(t, "--id", "--id", "has space", "status")
	expect_usage(t, "--id", "--id", "", "status")
	expect_usage(t, "does not accept a value", "--json=1", "status")
	expect_usage(t, "no command", "--json")
	expect_usage(t, "no command")
	expect_usage(t, "unknown command", "frobnicate")
}

@(test)
help_and_version :: proc(t: ^testing.T) {
	for argv in ([][]string{{"-h"}, {"--help"}, {"help"}, {"status", "--help"}, {"peers", "--limit", "3", "-h"}, {"--json", "kick", "-h"}}) {
		cmd := parse_ok(t, ..argv)
		testing.expect_value(t, cmd.kind, Kind.Help)
		command_destroy(&cmd)
	}
	for argv in ([][]string{{"--version"}, {"-V"}}) {
		cmd := parse_ok(t, ..argv)
		testing.expect_value(t, cmd.kind, Kind.Version)
		command_destroy(&cmd)
	}
}

// ---- subcommands ----

@(test)
simple_commands :: proc(t: ^testing.T) {
	cases := []struct {
		argv: []string,
		kind: Kind,
	}{{{"status"}, .Status}, {{"reload-peers"}, .Reload_Peers}, {{"reload"}, .Reload}, {{"connect"}, .Connect}, {{"disconnect"}, .Disconnect}}
	for c in cases {
		cmd := parse_ok(t, ..c.argv)
		testing.expect_value(t, cmd.kind, c.kind)
		command_destroy(&cmd)
		expect_usage(t, "does not accept any arguments", c.argv[0], "extra")
		expect_usage(t, "unknown option", c.argv[0], "--nope")
	}
}

@(test)
stats_command :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "stats")
	testing.expect_value(t, c1.kind, Kind.Stats)
	testing.expect_value(t, c1.session, "")
	command_destroy(&c1)
	c2 := parse_ok(t, "stats", "s-17")
	testing.expect_value(t, c2.session, "s-17")
	command_destroy(&c2)
	expect_usage(t, "at most one", "stats", "a", "b")
}

@(test)
peers_command :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "peers")
	testing.expect_value(t, c1.kind, Kind.Peers)
	testing.expect(t, !c1.all && !c1.has_limit && !c1.has_offset)
	testing.expect_value(t, c1.page_size, PEERS_PAGE)
	command_destroy(&c1)

	c2 := parse_ok(t, "peers", "--all", "--user", "alice", "--limit", "10", "--offset=20")
	testing.expect(t, c2.all)
	testing.expect_value(t, c2.user, "alice")
	testing.expect_value(t, c2.limit, 10)
	testing.expect_value(t, c2.offset, 20)
	testing.expect(t, c2.has_limit && c2.has_offset)
	command_destroy(&c2)

	expect_usage(t, "--limit", "peers", "--limit", "0")
	expect_usage(t, "--limit", "peers", "--limit", "2001")
	expect_usage(t, "--limit", "peers", "--limit", "x")
	expect_usage(t, "--offset", "peers", "--offset", "-1")
	expect_usage(t, "--offset", "peers", "--offset")
	expect_usage(t, "accept any arguments", "peers", "alice")
	expect_usage(t, "unknown option", "peers", "--name", "a")
}

@(test)
peer_command :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "peer", "s-1")
	testing.expect_value(t, c1.session, "s-1")
	command_destroy(&c1)
	c2 := parse_ok(t, "peer", "--peer-id", "7")
	testing.expect(t, c2.has_peer_id)
	testing.expect_value(t, c2.peer_id, 7)
	command_destroy(&c2)
	// After `--`, an argument that starts with a dash is a session.
	c3 := parse_ok(t, "peer", "--", "-odd")
	testing.expect_value(t, c3.session, "-odd")
	command_destroy(&c3)
	expect_usage(t, "exactly one", "peer")
	expect_usage(t, "exactly one", "peer", "s-1", "--peer-id", "7")
	expect_usage(t, "one session", "peer", "a", "b")
	expect_usage(t, "--peer-id", "peer", "--peer-id", "16777215")
}

@(test)
kick_command :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "kick", "s-1", "--halt", "--reason", "maintenance window")
	testing.expect_value(t, c1.kind, Kind.Kick)
	testing.expect_value(t, c1.session, "s-1")
	testing.expect(t, c1.halt && c1.has_reason)
	testing.expect_value(t, c1.reason, "maintenance window")
	command_destroy(&c1)
	c2 := parse_ok(t, "kick", "--user", "alice")
	testing.expect_value(t, c2.user, "alice")
	command_destroy(&c2)
	c3 := parse_ok(t, "kick", "--peer-id=3")
	testing.expect_value(t, c3.peer_id, 3)
	command_destroy(&c3)
	c4 := parse_ok(t, "kick", "--serial", "0A:bc", "--user", "alice", "--halt")
	testing.expect_value(t, c4.serial, "0A:bc")
	testing.expect_value(t, c4.user, "alice")
	command_destroy(&c4)
	pin := strings.concatenate({"sha256:", strings.repeat("ab", 32, context.temp_allocator)}, context.temp_allocator)
	c5 := parse_ok(t, "kick", "--pin", pin, "--user", "alice")
	testing.expect_value(t, c5.pin, pin)
	testing.expect_value(t, c5.user, "alice")
	command_destroy(&c5)
	c6 := parse_ok(t, "kick", "--pin", pin)
	testing.expect_value(t, c6.pin, pin)
	command_destroy(&c6)
	expect_usage(t, "--pin", "kick", "s-1", "--pin", pin)
	expect_usage(t, "--pin", "kick", "--peer-id", "1", "--pin", pin)
	expect_usage(t, "--pin", "kick", "--serial", "01", "--pin", pin)
	expect_usage(t, "--pin", "kick", "--pin")

	expect_usage(t, "--serial", "kick", "s-1", "--serial", "01")
	expect_usage(t, "--serial", "kick", "--peer-id", "1", "--serial", "01")
	expect_usage(t, "--serial", "kick", "--serial")
	expect_usage(t, "exactly one", "kick")
	expect_usage(t, "exactly one", "kick", "s-1", "--user", "alice")
	expect_usage(t, "exactly one", "kick", "--user", "a", "--peer-id", "1")
	expect_usage(t, "--reason", "kick", "s-1", "--reason", strings.repeat("x", 129, context.temp_allocator))
	expect_usage(t, "requires a value", "kick", "s-1", "--reason")
	expect_usage(t, "does not accept a value", "kick", "s-1", "--halt=yes")
}

@(test)
log_level_command :: proc(t: ^testing.T) {
	levels := [?]string{"0", "1", "2", "3", "4"}
	for s, v in levels {
		cmd := parse_ok(t, "log-level", s)
		testing.expect_value(t, cmd.verb, i64(v))
		command_destroy(&cmd)
	}
	expect_usage(t, "0 to 4", "log-level", "5")
	expect_usage(t, "0 to 4", "log-level", "debug")
	expect_usage(t, "0 to 4", "log-level", "-1")
	expect_usage(t, "one argument", "log-level")
	expect_usage(t, "one argument", "log-level", "1", "2")
}

@(test)
auth_commands :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "auth", "allow", "s-4", "--push", "ifconfig-push 10.8.0.50 255.255.255.0", "--push", "route 192.168.5.0 255.255.255.0")
	testing.expect_value(t, c1.kind, Kind.Auth_Allow)
	testing.expect_value(t, c1.session, "s-4")
	testing.expect_value(t, len(c1.push), 2)
	command_destroy(&c1)
	c2 := parse_ok(t, "auth", "deny", "s-4", "--reason", "no mfa")
	testing.expect_value(t, c2.kind, Kind.Auth_Deny)
	testing.expect_value(t, c2.reason, "no mfa")
	command_destroy(&c2)
	c3 := parse_ok(t, "auth", "pending", "s-4", "--timeout", "90")
	testing.expect_value(t, c3.kind, Kind.Auth_Pending)
	testing.expect_value(t, c3.timeout_s, 90)
	testing.expect(t, c3.has_timeout_s)
	command_destroy(&c3)
	c4 := parse_ok(t, "auth", "credentials", "s-4")
	testing.expect_value(t, c4.kind, Kind.Auth_Credentials)
	command_destroy(&c4)
	c5 := parse_ok(t, "auth", "allow", "s-4", "--name", "erin@example.test", "--token-lifetime", "3600")
	testing.expect_value(t, c5.auth_name, "erin@example.test")
	testing.expect_value(t, c5.lifetime_s, 3600)
	testing.expect(t, c5.has_lifetime)
	command_destroy(&c5)
	c6 := parse_ok(t, "auth", "pending", "s-4", "--timeout", "90", "--url", "https://login.example.test/x", "--flag", "hidden", "--flag", "external")
	testing.expect_value(t, c6.url, "https://login.example.test/x")
	testing.expect_value(t, len(c6.flags), 2)
	command_destroy(&c6)

	expect_usage(t, "subcommand", "auth")
	expect_usage(t, "unknown auth subcommand", "auth", "maybe", "s-1")
	expect_usage(t, "requires a session", "auth", "allow")
	expect_usage(t, "one session", "auth", "allow", "a", "b")
	expect_usage(t, "only be used with auth allow", "auth", "deny", "s-1", "--push", "route 1.2.3.0 255.255.255.0")
	expect_usage(t, "only be used with auth deny", "auth", "allow", "s-1", "--reason", "x")
	expect_usage(t, "only be used with auth pending", "auth", "deny", "s-1", "--timeout", "5")
	expect_usage(t, "only be used with auth allow", "auth", "pending", "s-1", "--name", "x")
	expect_usage(t, "only be used with auth allow", "auth", "pending", "s-1", "--token-lifetime", "60")
	expect_usage(t, "only be used with auth pending", "auth", "allow", "s-1", "--url", "https://a.example/")
	expect_usage(t, "60 to 2592000", "auth", "allow", "s-1", "--token-lifetime", "59")
	expect_usage(t, "60 to 2592000", "auth", "allow", "s-1", "--token-lifetime", "2592001")
	expect_usage(t, "hidden or external", "auth", "pending", "s-1", "--url", "https://a.example/", "--flag", "proxy=x")
	expect_usage(t, "--flag requires --url", "auth", "pending", "s-1", "--flag", "hidden")
	expect_usage(t, "--timeout", "auth", "pending", "s-1", "--timeout", "0")
	expect_usage(t, "--timeout", "auth", "pending", "s-1", "--timeout", "3601")
	expect_usage(t, "--reason", "auth", "deny", "s-1", "--reason", strings.repeat("x", 129, context.temp_allocator))
	expect_usage(t, "--push requires", "auth", "allow", "s-1", "--push", "")
}

@(test)
shutdown_command :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "shutdown")
	testing.expect(t, !c1.has_timeout_s)
	command_destroy(&c1)
	c2 := parse_ok(t, "shutdown", "--timeout", "0")
	testing.expect(t, c2.has_timeout_s)
	testing.expect_value(t, c2.timeout_s, 0)
	command_destroy(&c2)
	c3 := parse_ok(t, "shutdown", "--timeout=60")
	testing.expect_value(t, c3.timeout_s, 60)
	command_destroy(&c3)
	expect_usage(t, "--timeout", "shutdown", "--timeout", "61")
	expect_usage(t, "accept any arguments", "shutdown", "now")
}

@(test)
auth_supply_command :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "auth-supply", "--username", "alice", "--password-stdin")
	testing.expect_value(t, c1.kind, Kind.Auth_Supply)
	testing.expect_value(t, c1.username, "alice")
	testing.expect_value(t, c1.password_src, Secret_Source.Stdin)
	command_destroy(&c1)
	c2 := parse_ok(t, "auth-supply", "--password-file", "/tmp/p", "--response-stdin")
	testing.expect_value(t, c2.password_src, Secret_Source.File)
	testing.expect_value(t, c2.password_file, "/tmp/p")
	testing.expect_value(t, c2.response_src, Secret_Source.Stdin)
	command_destroy(&c2)
	c3 := parse_ok(t, "auth-supply", "--response-file", "/tmp/r")
	testing.expect_value(t, c3.response_src, Secret_Source.File)
	command_destroy(&c3)
	c4 := parse_ok(t, "auth-supply", "--username", "bob")
	testing.expect(t, c4.has_username)
	command_destroy(&c4)

	expect_usage(t, "at least one", "auth-supply")
	// A secret is never taken from the command line.
	expect_usage(t, "not accepted", "auth-supply", "--password", "hunter2")
	expect_usage(t, "not accepted", "auth-supply", "--response=123456")
	expect_usage(t, "accept any arguments", "auth-supply", "hunter2")
	expect_usage(t, "both read standard input", "auth-supply", "--password-stdin", "--response-stdin")
	expect_usage(t, "once", "auth-supply", "--password-stdin", "--password-file", "/x")
	expect_usage(t, "once", "auth-supply", "--response-stdin", "--response-file", "/x")
	expect_usage(t, "--username", "auth-supply", "--username", strings.repeat("u", 513, context.temp_allocator))
}

@(test)
events_command :: proc(t: ^testing.T) {
	c1 := parse_ok(t, "events")
	testing.expect_value(t, c1.kind, Kind.Events)
	testing.expect_value(t, len(c1.prefixes), 0)
	testing.expect_value(t, c1.count, 0)
	testing.expect(t, !c1.wait)
	command_destroy(&c1)
	c2 := parse_ok(t, "events", "-n", "5", "--wait", "peer.", "auth.fail", "--json")
	testing.expect_value(t, len(c2.prefixes), 2)
	testing.expect_value(t, c2.prefixes[1], "auth.fail")
	testing.expect_value(t, c2.count, 5)
	testing.expect(t, c2.wait && c2.json)
	command_destroy(&c2)
	c3 := parse_ok(t, "events", "--count=2", "-w")
	testing.expect_value(t, c3.count, 2)
	testing.expect(t, c3.wait)
	command_destroy(&c3)
	expect_usage(t, "not a valid topic prefix", "events", "Peer.")
	expect_usage(t, "not a valid topic prefix", "events", "peer connect")
	expect_usage(t, "-n", "events", "-n", "0")
	expect_usage(t, "-n", "events", "-n")
}

// ---- the requests ----

@(test)
requests_carry_the_documented_op_and_args :: proc(t: ^testing.T) {
	Case :: struct {
		argv: []string,
		op:   string,
		args: string,
	}
	cases := []Case {
		{{"status"}, "status", "{}"},
		{{"stats"}, "stats.get", "{}"},
		{{"stats", "s-1"}, "stats.get", `{"session":"s-1"}`},
		{{"peers"}, "peers.list", `{"limit":500,"offset":0}`},
		{{"peers", "--all", "--user", "al\"ice"}, "peers.list", `{"all":true,"name":"al\"ice","limit":500,"offset":0}`},
		{{"peers", "--limit", "10"}, "peers.list", `{"limit":10,"offset":0}`},
		{{"peers", "--offset", "30"}, "peers.list", `{"limit":500,"offset":30}`},
		{{"peer", "s-1"}, "peer.get", `{"session":"s-1"}`},
		{{"peer", "--peer-id", "9"}, "peer.get", `{"peer_id":9}`},
		{{"kick", "s-17"}, "peer.kick", `{"session":"s-17"}`},
		{{"kick", "s-17", "--halt", "--reason", "bye"}, "peer.kick", `{"session":"s-17","halt":true,"reason":"bye"}`},
		{{"kick", "--peer-id", "4"}, "peer.kick", `{"peer_id":4}`},
		{{"kick", "--user", "alice"}, "peer.kick", `{"name":"alice"}`},
		{{"kick", "--serial", "0a:BC"}, "peer.kick", `{"serial":"0a:BC"}`},
		{{"kick", "--pin", "sha256:ab"}, "peer.kick", `{"pin":"sha256:ab"}`},
		{{"kick", "--pin", "sha256:ab", "--user", "alice"}, "peer.kick", `{"pin":"sha256:ab","name":"alice"}`},
		{{"kick", "--serial", "0abc", "--user", "alice", "--halt"}, "peer.kick", `{"serial":"0abc","name":"alice","halt":true}`},
		{{"reload-peers"}, "peers.reload", "{}"},
		{{"reload-passwords"}, "passwords.reload", "{}"},
		{{"log-level", "3"}, "log.level", `{"verb":3}`},
		{{"auth", "allow", "s-2"}, "auth.decide", `{"session":"s-2","decision":"allow"}`},
		{{"auth", "allow", "s-2", "--push", "route 10.1.0.0 255.255.0.0", "--push", "ifconfig-push 10.8.0.9 255.255.255.0"}, "auth.decide", `{"session":"s-2","decision":"allow","push":["route 10.1.0.0 255.255.0.0","ifconfig-push 10.8.0.9 255.255.255.0"]}`},
		{{"auth", "deny", "s-2"}, "auth.decide", `{"session":"s-2","decision":"deny"}`},
		{{"auth", "deny", "s-2", "--reason", "no"}, "auth.decide", `{"session":"s-2","decision":"deny","reason":"no"}`},
		{{"auth", "pending", "s-2"}, "auth.decide", `{"session":"s-2","decision":"pending"}`},
		{{"auth", "pending", "s-2", "--timeout", "120"}, "auth.decide", `{"session":"s-2","decision":"pending","timeout":120}`},
		{{"auth", "credentials", "s-2"}, "auth.credentials", `{"session":"s-2"}`},
		{{"reload"}, "daemon.reload", "{}"},
		{{"shutdown"}, "daemon.shutdown", "{}"},
		{{"shutdown", "--timeout", "10"}, "daemon.shutdown", `{"timeout_s":10}`},
		{{"connect"}, "connect", "{}"},
		{{"disconnect"}, "disconnect", "{}"},
	}
	for c in cases {
		op, args := request_of(t, ..c.argv)
		testing.expectf(t, op == c.op, "%v: op %q, want %q", c.argv, op, c.op)
		testing.expectf(t, args == c.args || (args == "" && c.args == "{}"), "%v: args %q, want %q", c.argv, args, c.args)
	}
}

@(test)
every_request_op_is_a_documented_operation :: proc(t: ^testing.T) {
	argvs := [][]string {
		{"status"},
		{"stats"},
		{"peers"},
		{"peer", "s"},
		{"kick", "s"},
		{"reload-peers"},
		{"reload-passwords"},
		{"log-level", "1"},
		{"auth", "allow", "s"},
		{"auth", "deny", "s"},
		{"auth", "pending", "s"},
		{"auth", "credentials", "s"},
		{"reload"},
		{"shutdown"},
		{"connect"},
		{"disconnect"},
	}
	for argv in argvs {
		op, _ := request_of(t, ..argv)
		_, known := bus.op_lookup(op)
		testing.expectf(t, known, "%v sends unknown op %q", argv, op)
	}
}

@(test)
auth_supply_request_has_the_secrets :: proc(t: ^testing.T) {
	cmd := parse_ok(t, "auth-supply", "--username", "alice", "--password-stdin", "--response-file", "/x")
	defer command_destroy(&cmd)
	req, ok := build_request(&cmd, "p\"w", "123456", allocator = context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, req.op, "auth.supply")
	testing.expect_value(t, string(req.args), `{"username":"alice","password":"p\"w","response":"123456"}`)

	c2 := parse_ok(t, "auth-supply", "--username", "alice")
	defer command_destroy(&c2)
	r2, ok2 := build_request(&c2, "", "", allocator = context.temp_allocator)
	testing.expect(t, ok2)
	testing.expect_value(t, string(r2.args), `{"username":"alice"}`)

	// The passphrase of the key of a service profile.
	c3 := parse_ok(t, "auth-supply", "--key-pass-file", "/k")
	defer command_destroy(&c3)
	r3, ok3 := build_request(&c3, "", "", allocator = context.temp_allocator, key_pass = "pass phrase")
	testing.expect(t, ok3)
	testing.expect_value(t, string(r3.args), `{"key_pass":"pass phrase"}`)
	expect_usage(t, "not accepted", "auth-supply", "--key-pass", "x")
	expect_usage(t, "once", "auth-supply", "--key-pass-stdin", "--key-pass-file", "/x")
	expect_usage(t, "both read standard input", "auth-supply", "--key-pass-stdin", "--password-stdin")
}

@(test)
events_has_no_request :: proc(t: ^testing.T) {
	cmd := parse_ok(t, "events")
	defer command_destroy(&cmd)
	_, ok := build_request(&cmd, "", "")
	testing.expect(t, !ok)
}

@(test)
only_credentials_is_not_retried :: proc(t: ^testing.T) {
	testing.expect(t, !retry_safe("auth.credentials"))
	for op in ([]string{"status", "peer.kick", "auth.decide", "daemon.shutdown", "peers.list", "connect"}) {
		testing.expect(t, retry_safe(op), op)
	}
}

// ---- exit codes ----

@(test)
exit_codes :: proc(t: ^testing.T) {
	testing.expect_value(t, int(Exit.Ok), 0)
	testing.expect_value(t, int(Exit.Error), 1)
	testing.expect_value(t, int(Exit.Usage), 2)
	testing.expect_value(t, int(Exit.Not_Running), 3)
	testing.expect_value(t, int(Exit.Denied), 4)
	testing.expect_value(t, int(Exit.Timeout), 5)
	testing.expect_value(t, int(Exit.Failed), 6)

	testing.expect_value(t, exit_for_call_error(.None), Exit.Ok)
	testing.expect_value(t, exit_for_call_error(.Daemon_Not_Running), Exit.Not_Running)
	testing.expect_value(t, exit_for_call_error(.Permission_Denied), Exit.Denied)
	testing.expect_value(t, exit_for_call_error(.Bad_Url), Exit.Usage)
	testing.expect_value(t, exit_for_call_error(.Timeout), Exit.Timeout)
	testing.expect_value(t, exit_for_call_error(.Io), Exit.Failed)
	testing.expect_value(t, exit_for_call_error(.Bad_Reply), Exit.Failed)
	testing.expect_value(t, exit_for_call_error(.No_Memory), Exit.Failed)

	testing.expect_value(t, exit_for_reply_code("denied"), Exit.Denied)
	for code in ([]string{"bad_request", "unknown_op", "not_found", "busy", "conflict", "timeout", "internal", "unsupported", "something_new"}) {
		testing.expect_value(t, exit_for_reply_code(code), Exit.Error)
	}
	// Every distinct cause has its own code.
	seen: [7]bool
	for e in ([]Exit{.Ok, .Error, .Usage, .Not_Running, .Denied, .Timeout, .Failed}) {
		testing.expect(t, !seen[int(e)])
		seen[int(e)] = true
	}
}

// ---- finding the daemon ----

@(test)
target_selection :: proc(t: ^testing.T) {
	one := []bus.Found{{name = "srv", url = "ipc:///run/noirvpn/srv.control", events_url = "ipc:///run/noirvpn/srv.events"}}
	two := []bus.Found {
		{name = "srv", url = "ipc:///run/noirvpn/srv.control", events_url = "ipc:///run/noirvpn/srv.events"},
		{name = "cli", url = "ipc:///run/noirvpn/cli.control", events_url = "ipc:///run/noirvpn/cli.events"},
	}

	c0 := parse_ok(t, "status")
	defer command_destroy(&c0)
	// Exactly one daemon: use it.
	tg, err, _ := resolve_target(&c0, one)
	testing.expect_value(t, err, Target_Error.None)
	testing.expect_value(t, tg.control, "ipc:///run/noirvpn/srv.control")
	testing.expect_value(t, tg.events, "ipc:///run/noirvpn/srv.events")
	// None: not running.
	_, err, _ = resolve_target(&c0, nil)
	testing.expect_value(t, err, Target_Error.Not_Running)
	// Several: ask for --name, and say which.
	detail: string
	_, err, detail = resolve_target(&c0, two)
	testing.expect_value(t, err, Target_Error.Ambiguous)
	testing.expect_value(t, detail, "srv, cli")

	c1 := parse_ok(t, "--name", "cli", "status")
	defer command_destroy(&c1)
	tg, err, _ = resolve_target(&c1, two)
	testing.expect_value(t, err, Target_Error.None)
	testing.expect_value(t, tg.control, "ipc:///run/noirvpn/cli.control")
	testing.expect_value(t, tg.events, "ipc:///run/noirvpn/cli.events")
	_, err, _ = resolve_target(&c1, one)
	testing.expect_value(t, err, Target_Error.Not_Running)

	// --socket needs no discovery; the events socket follows the name.
	when ODIN_OS == .Windows {
		c2 := parse_ok(t, "--socket", `\\.\pipe\noirvpn-a-control`, "status")
		defer command_destroy(&c2)
		tg, err, _ = resolve_target(&c2, nil)
		testing.expect_value(t, err, Target_Error.None)
		testing.expect_value(t, tg.control, `\\.\pipe\noirvpn-a-control`)
		testing.expect_value(t, tg.events, `\\.\pipe\noirvpn-a-events`)
	} else {
		c2 := parse_ok(t, "--socket", "/tmp/x/a.control", "status")
		defer command_destroy(&c2)
		tg, err, _ = resolve_target(&c2, nil)
		testing.expect_value(t, err, Target_Error.None)
		testing.expect_value(t, tg.control, "/tmp/x/a.control")
		testing.expect_value(t, tg.events, "/tmp/x/a.events")
	}
	// A control socket with another name: the events socket is unknown ...
	c3 := parse_ok(t, "--socket", "ipc:///tmp/ctl.sock", "events")
	defer command_destroy(&c3)
	_, err, _ = resolve_target(&c3, nil)
	testing.expect_value(t, err, Target_Error.No_Events_Socket)
	// ... unless it is given.
	c4 := parse_ok(t, "--socket", "/tmp/ctl.sock", "--events-socket", "/tmp/ev.sock", "events")
	defer command_destroy(&c4)
	tg, err, _ = resolve_target(&c4, nil)
	testing.expect_value(t, err, Target_Error.None)
	testing.expect_value(t, tg.events, "/tmp/ev.sock")
}

// ---- profile ----

@(test)
profile_commands_parse :: proc(t: ^testing.T) {
	set := parse_ok(t, "profile", "set", "/etc/vpn/Work.ovpn")
	defer command_destroy(&set)
	testing.expect_value(t, set.kind, Kind.Profile_Set)
	testing.expect_value(t, set.file, "/etc/vpn/Work.ovpn")
	// The label is the base name without the extension.
	testing.expect_value(t, set.label, "Work")

	named := parse_ok(t, "profile", "check", "a.b.ovpn", "--label", "My VPN")
	defer command_destroy(&named)
	testing.expect_value(t, named.kind, Kind.Profile_Check)
	testing.expect_value(t, named.label, "My VPN")

	noext := parse_ok(t, "profile", "set", "dir/home")
	defer command_destroy(&noext)
	testing.expect_value(t, noext.label, "home")

	web := parse_ok(t, "profile", "set", "w.ovpn", "--sso", "webauth")
	defer command_destroy(&web)
	testing.expect(t, web.sso)

	clear := parse_ok(t, "profile", "clear", "--json")
	defer command_destroy(&clear)
	testing.expect_value(t, clear.kind, Kind.Profile_Clear)
	testing.expect(t, clear.json)
}

@(test)
rules_commands :: proc(t: ^testing.T) {
	get := parse_ok(t, "rules")
	defer command_destroy(&get)
	testing.expect_value(t, get.kind, Kind.Rules)
	re := parse_ok(t, "reload-rules", "--json")
	defer command_destroy(&re)
	testing.expect_value(t, re.kind, Kind.Reload_Rules)
	testing.expect(t, re.json)
	expect_usage(t, "does not accept any arguments", "rules", "x")
	expect_usage(t, "does not accept any arguments", "reload-rules", "x")
}

@(test)
profile_command_errors :: proc(t: ^testing.T) {
	expect_usage(t, "subcommand", "profile")
	expect_usage(t, "unknown profile subcommand", "profile", "load", "x")
	expect_usage(t, "requires a file", "profile", "set")
	expect_usage(t, "one file", "profile", "set", "a", "b")
	expect_usage(t, "does not accept any arguments", "profile", "clear", "a")
	expect_usage(t, "--label", "profile", "clear", "--label", "x")
	expect_usage(t, "longer than", "profile", "set", "a", "--label", strings.repeat("x", 129, context.temp_allocator))
	expect_usage(t, "--label", "profile", "set", "a", "--label")
	expect_usage(t, "label", "profile", "set", "a", "--label", "")
	expect_usage(t, "unknown option", "profile", "set", "a", "--bogus")
	expect_usage(t, "only supported method", "profile", "set", "a", "--sso", "crtext")
	expect_usage(t, "--sso", "profile", "clear", "--sso", "webauth")
}

@(test)
connect_follow_parse :: proc(t: ^testing.T) {
	c := parse_ok(t, "connect", "--follow")
	defer command_destroy(&c)
	testing.expect(t, c.kind == .Connect && c.follow)
	plain := parse_ok(t, "connect")
	defer command_destroy(&plain)
	testing.expect(t, !plain.follow)
	expect_usage(t, "--json", "connect", "--follow", "--json")
	expect_usage(t, "accept any arguments", "connect", "x")
}

@(test)
profile_requests :: proc(t: ^testing.T) {
	cmd := parse_ok(t, "profile", "set", "x/Work.ovpn")
	defer command_destroy(&cmd)
	req, ok := build_request(&cmd, "", "", allocator = context.temp_allocator, profile = "client\nremote a \"q\"\n")
	testing.expect(t, ok)
	testing.expect_value(t, req.op, "profile.set")
	testing.expect_value(t, string(req.args), `{"text":"client\nremote a \"q\"\n","label":"Work"}`)
	cmd.sso = true
	req, ok = build_request(&cmd, "", "", allocator = context.temp_allocator, profile = "x")
	testing.expect_value(t, string(req.args), `{"text":"x","label":"Work","sso":["webauth"]}`)
	cmd.sso = false
	cmd.kind = .Profile_Check
	req, ok = build_request(&cmd, "", "", allocator = context.temp_allocator, profile = "x")
	testing.expect_value(t, req.op, "profile.check")
	op, args := request_of(t, "profile", "clear")
	testing.expect_value(t, op, "profile.clear")
	testing.expect_value(t, args, "")
}
