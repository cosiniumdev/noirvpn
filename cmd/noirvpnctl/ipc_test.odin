// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd, windows
package main

// noirvpnctl against a fake daemon (fake_test.odin): real sockets, real
// requests and replies.

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "noir:bus"
import "noir:proto/config"

Outcome :: struct {
	exit: Exit,
	out:  string,
	err:  string,
}

// Run `noirvpnctl` with the given global options and command in this process.
// The strings of the outcome are in temp memory.
run_argv :: proc(argv: []string, stdin: Maybe(string) = nil, page_size: i64 = 0, stop: ^Stop = nil, found: []bus.Found = nil) -> Outcome {
	// The streams live on the heap: a command may give back temporary memory
	// while it runs (the `events` loop does).
	out_b := strings.builder_make()
	err_b := strings.builder_make()
	defer strings.builder_destroy(&out_b)
	defer strings.builder_destroy(&err_b)
	io := Io {
		out = Sink{buf = &out_b},
		err = Sink{buf = &err_b},
	}
	if s, ok := stdin.?; ok {
		io.stdin_text = s
		io.stdin_set = true
	}
	cmd, perr := parse_command(argv)
	defer command_destroy(&cmd)
	if perr != nil {
		msg, _ := perr.(string)
		err_line(&io, "%s", msg)
		return Outcome{.Usage, strings.clone(strings.to_string(out_b), context.temp_allocator), strings.clone(strings.to_string(err_b), context.temp_allocator)}
	}
	if page_size > 0 {
		cmd.page_size = page_size
	}
	own_stop := stop_init()
	code := run_command(&cmd, &io, found, stop if stop != nil else &own_stop)
	return Outcome{code, strings.clone(strings.to_string(out_b), context.temp_allocator), strings.clone(strings.to_string(err_b), context.temp_allocator)}
}

// `argv` after `--socket <fake> --timeout 5`.
run_fake :: proc(f: ^Fake, argv: ..string) -> Outcome {
	return run_fake_with(f, {}, ..argv)
}

Run_Options :: struct {
	stdin:     Maybe(string),
	page_size: i64,
	stop:      ^Stop,
	timeout:   string,
}

run_fake_with :: proc(f: ^Fake, o: Run_Options, argv: ..string) -> Outcome {
	full := make([dynamic]string, context.temp_allocator)
	append(&full, "--socket", fake_url(f), "--timeout", o.timeout if o.timeout != "" else "5")
	append(&full, ..argv)
	return run_argv(full[:], o.stdin, o.page_size, o.stop)
}

// The one request the daemon saw (op and args), for tests of a single call.
only_seen :: proc(t: ^testing.T, f: ^Fake, loc := #caller_location) -> Seen {
	seen := fake_seen(f)
	testing.expect_value(t, len(seen), 1, loc)
	if len(seen) == 0 {
		return {}
	}
	return seen[0]
}

@(test)
status_prints_the_reply :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "status")
	defer fake_close(f)
	fake_result(f, "status", `{"mode":"server","name":"srv","uptime_s":61,"bus":{"run":"9f3a0c51d27be8a4","seq":42},"server":{"state":"running","peers":2,"listen":["udp 0.0.0.0:1194"]}}`)
	o := run_fake(f, "status")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.err, "")
	want := `mode           server
name           srv
uptime_s       61
bus.run        9f3a0c51d27be8a4
bus.seq        42
server.state   running
server.peers   2
server.listen  udp 0.0.0.0:1194
`
	testing.expect_value(t, o.out, want)
	seen := fake_seen(f)
	testing.expect_value(t, len(seen), 1)
	if len(seen) == 1 {
		testing.expect_value(t, seen[0].op, "status")
		testing.expect_value(t, seen[0].args, "{}")
		testing.expect_value(t, len(seen[0].id), 32)
	}
}

@(test)
requests_reach_the_daemon_with_op_and_args :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "args")
	defer fake_close(f)
	fake_result(f, "peer.kick", `{"kicked":["s-17"]}`)
	o := run_fake(f, "kick", "s-17", "--halt", "--reason", "maintenance")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.out, "kicked  s-17\n")
	s := only_seen(t, f)
	testing.expect_value(t, s.op, "peer.kick")
	testing.expect_value(t, s.args, `{"halt":true,"reason":"maintenance","session":"s-17"}`)
}

@(test)
every_command_sends_what_the_table_says :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "each")
	defer fake_close(f)
	Case :: struct {
		argv: []string,
		op:   string,
		args: string,
	}
	cases := []Case {
		{{"status"}, "status", "{}"},
		{{"stats", "s-1"}, "stats.get", `{"session":"s-1"}`},
		{{"peer", "--peer-id", "4"}, "peer.get", `{"peer_id":4}`},
		{{"reload-peers"}, "peers.reload", "{}"},
		{{"log-level", "3"}, "log.level", `{"verb":3}`},
		{{"auth", "allow", "s-2", "--push", "route 10.1.0.0 255.255.0.0"}, "auth.decide", `{"decision":"allow","push":["route 10.1.0.0 255.255.0.0"],"session":"s-2"}`},
		{{"auth", "deny", "s-2", "--reason", "no"}, "auth.decide", `{"decision":"deny","reason":"no","session":"s-2"}`},
		{{"auth", "pending", "s-2", "--timeout", "90"}, "auth.decide", `{"decision":"pending","session":"s-2","timeout":90}`},
		{{"auth", "credentials", "s-2"}, "auth.credentials", `{"session":"s-2"}`},
		{{"reload"}, "daemon.reload", "{}"},
		{{"shutdown", "--timeout", "10"}, "daemon.shutdown", `{"timeout_s":10}`},
	}
	for c in cases {
		o := run_fake(f, ..c.argv)
		testing.expectf(t, o.exit == .Ok, "%v: exit %v, stderr %q", c.argv, o.exit, o.err)
	}
	seen := fake_seen(f)
	testing.expect_value(t, len(seen), len(cases))
	for c, i in cases {
		if i >= len(seen) {
			break
		}
		testing.expectf(t, seen[i].op == c.op, "%v: op %q", c.argv, seen[i].op)
		testing.expectf(t, seen[i].args == c.args, "%v: args %q, want %q", c.argv, seen[i].args, c.args)
		// Every request has a fresh 32-digit id.
		testing.expect_value(t, len(seen[i].id), 32)
	}
	for i in 1 ..< len(seen) {
		testing.expect(t, seen[i].id != seen[i - 1].id)
	}
}

@(test)
client_commands_send_what_the_table_says :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "client", {mode = .Client})
	defer fake_close(f)
	fake_result(f, "connect", `{"state":"connecting","already":false}`)
	fake_result(f, "disconnect", `{"state":"stopped"}`)
	o := run_fake(f, "connect")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.out, "state    connecting\nalready  false\n")
	o2 := run_fake(f, "disconnect")
	testing.expect_value(t, o2.exit, Exit.Ok)
	testing.expect_value(t, o2.out, "state  stopped\n")
	seen := fake_seen(f)
	testing.expect_value(t, len(seen), 2)
	if len(seen) == 2 {
		testing.expect_value(t, seen[0].op, "connect")
		testing.expect_value(t, seen[0].args, "{}")
		testing.expect_value(t, seen[1].op, "disconnect")
	}
	// A server operation on a client daemon is refused by the bus.
	o3 := run_fake(f, "kick", "s-1")
	testing.expect_value(t, o3.exit, Exit.Error)
	testing.expect(t, strings.contains(o3.err, "unsupported"), o3.err)
}

@(test)
json_flag_prints_the_raw_reply :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "json")
	defer fake_close(f)
	fake_result(f, "reload-peers", "{}")
	fake_result(f, "peers.reload", `{"pins":3,"added":1,"removed":0,"disabled":0,"kicked":0}`)
	o := run_fake(f, "--json", "reload-peers")
	testing.expect_value(t, o.exit, Exit.Ok)
	id := only_seen(t, f).id
	want := strings.concatenate({fmt.tprintf(`{{"v":1,"id":"%s","ok":true,"result":{{"pins":3,"added":1,"removed":0,"disabled":0,"kicked":0}}}}`, id), "\n"}, context.temp_allocator)
	testing.expect_value(t, o.out, want)
	// The text form of the same reply.
	o2 := run_fake(f, "reload-peers")
	testing.expect_value(t, o2.out, "pins      3\nadded     1\nremoved   0\ndisabled  0\nkicked    0\n")
}

// ---- peers ----

peers_handler :: proc(f: ^Fake, req: ^bus.Request) -> bool {
	if req.op != "peers.list" {
		return false
	}
	TOTAL :: 5
	offset, _ := bus.arg_int(req, "offset")
	limit, _ := bus.arg_int(req, "limit")
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)
	bus.begin_obj(&w)
	bus.kv_int(&w, "count", TOTAL)
	bus.kv_arr(&w, "peers")
	for i := offset; i < min(offset + limit, TOTAL); i += 1 {
		bus.begin_obj(&w)
		bus.kv_str(&w, "session", fmt.tprintf("s-%d", i + 1))
		bus.kv_str(&w, "name", fmt.tprintf("user%d", i + 1))
		bus.kv_str(&w, "state", "active")
		bus.kv_str(&w, "proto", "udp")
		bus.kv_int(&w, "bytes_in", 1024 * (i + 1))
		bus.kv_int(&w, "bytes_out", 0)
		bus.end(&w)
	}
	bus.end(&w)
	bus.end(&w)
	bus.reply_ok(f.host, req, bus.writer_bytes(&w))
	return true
}

@(test)
peers_fetches_every_page :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "pages")
	defer fake_close(f)
	f.custom = peers_handler
	o := run_fake_with(f, {page_size = 2}, "peers")
	testing.expect_value(t, o.exit, Exit.Ok)
	lines := strings.split_lines(o.out, context.temp_allocator)
	testing.expect_value(t, len(lines), 7) // header, 5 peers, empty
	for i in 1 ..= 5 {
		testing.expect(t, strings.has_prefix(lines[i], fmt.tprintf("s-%d ", i)), lines[i])
	}
	seen := fake_seen(f)
	testing.expect_value(t, len(seen), 3)
	wants := []string{`{"limit":2,"offset":0}`, `{"limit":2,"offset":2}`, `{"limit":2,"offset":4}`}
	for w, i in wants {
		if i < len(seen) {
			testing.expect_value(t, seen[i].args, w)
		}
	}
}

@(test)
peers_with_limit_is_one_page_and_a_note :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "page1")
	defer fake_close(f)
	f.custom = peers_handler
	o := run_fake(f, "peers", "--limit", "2", "--offset", "1", "--all", "--user", "x")
	testing.expect_value(t, o.exit, Exit.Ok)
	lines := strings.split_lines(o.out, context.temp_allocator)
	testing.expect_value(t, len(lines), 4)
	testing.expect(t, strings.has_prefix(lines[1], "s-2 "))
	testing.expect(t, strings.contains(o.err, "showing 2 of 5 peers"), o.err)
	s := only_seen(t, f)
	testing.expect_value(t, s.args, `{"all":true,"limit":2,"name":"x","offset":1}`)
}

@(test)
peers_json_prints_each_page :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "pagesjson")
	defer fake_close(f)
	f.custom = peers_handler
	o := run_fake_with(f, {page_size = 2}, "--json", "peers")
	testing.expect_value(t, o.exit, Exit.Ok)
	lines := strings.split_lines(strings.trim_right(o.out, "\n"), context.temp_allocator)
	testing.expect_value(t, len(lines), 3)
	total := 0
	for l in lines {
		v, err := json.parse(transmute([]byte)l, .JSON, true, context.temp_allocator)
		testing.expect_value(t, err, json.Error.None)
		obj, _ := v.(json.Object)
		result, _ := obj["result"].(json.Object)
		peers, _ := result["peers"].(json.Array)
		total += len(peers)
	}
	testing.expect_value(t, total, 5)
}

@(test)
one_peer_is_printed :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "peer")
	defer fake_close(f)
	fake_result(f, "peer.get", `{"peer":{"session":"s-1","name":"alice","vpn4":"10.8.0.2","vpn6":null}}`)
	o := run_fake(f, "peer", "s-1")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.out, "session  s-1\nname     alice\nvpn4     10.8.0.2\nvpn6     -\n")
}

// ---- errors and exit codes ----

@(test)
error_reply_gives_exit_1 :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "errreply")
	defer fake_close(f)
	fake_error(f, "peer.kick", "not_found")
	o := run_fake(f, "kick", "s-404")
	testing.expect_value(t, o.exit, Exit.Error)
	testing.expect_value(t, o.out, "")
	testing.expect(t, strings.contains(o.err, "error: not_found: fake not_found error"), o.err)
	// With --json the reply is on stdout, the code is the same.
	o2 := run_fake(f, "--json", "kick", "s-404")
	testing.expect_value(t, o2.exit, Exit.Error)
	testing.expect(t, strings.contains(o2.out, `"ok":false`) && strings.contains(o2.out, `"code":"not_found"`), o2.out)
	testing.expect_value(t, o2.err, "")
	// Other error codes are exit 1 too.
	for code in ([]string{"busy", "conflict", "internal", "unsupported", "bad_request"}) {
		fake_error(f, "connect", code)
		o3 := run_fake(f, "connect")
		testing.expect_value(t, o3.exit, Exit.Error)
	}
}

@(test)
denied_reply_gives_the_permission_exit :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	// We may only read.
	allow := []config.Bus_Allow{allow_me({.Read})}
	f := fake_open(t, "denied", {allow = allow})
	defer fake_close(f)
	o := run_fake(f, "kick", "s-1")
	testing.expect_value(t, o.exit, Exit.Denied)
	testing.expect(t, strings.contains(o.err, "permission denied"), o.err)
	// Reading still works.
	o2 := run_fake(f, "status")
	testing.expect_value(t, o2.exit, Exit.Ok)
	// And with --json: the raw reply, the same exit code.
	o3 := run_fake(f, "--json", "reload")
	testing.expect_value(t, o3.exit, Exit.Denied)
	testing.expect(t, strings.contains(o3.out, `"code":"denied"`), o3.out)
}

@(test)
missing_socket_means_not_running :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "missing")
	defer remove_dir(dir)
	path := test_socket(dir, "none")
	o := run_argv({"--socket", path, "status"})
	testing.expect_value(t, o.exit, Exit.Not_Running)
	testing.expect(t, strings.contains(o.err, "not running"), o.err)
	when ODIN_OS != .Windows {
		// A stale socket file, with nobody listening.
		stale := fmt.tprintf("%s/stale.control", dir)
		werr := os.write_entire_file(stale, "x")
		testing.expect(t, werr == nil)
		o2 := run_argv({"--socket", stale, "status"})
		testing.expect_value(t, o2.exit, Exit.Not_Running)
	}
	// Events: the same.
	o3 := run_argv({"--socket", path, "events"})
	testing.expect_value(t, o3.exit, Exit.Not_Running)
	testing.expect(t, strings.contains(o3.err, "no events socket"), o3.err)
	// By name, with nothing found.
	o4 := run_argv({"--name", "ghost", "status"})
	testing.expect_value(t, o4.exit, Exit.Not_Running)
	testing.expect(t, strings.contains(o4.err, "'ghost'"), o4.err)
}

@(test)
unreadable_socket_means_permission_denied :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	// On Windows the pipes have an access list: see the tests of the package
	// bus.
	when ODIN_OS != .Windows {
		if bus.euid() == 0 {
			return // root can open any socket file
		}
		f := fake_open(t, "perm")
		defer fake_close(f)
		make_unreadable(fake_control_path(f))
		o := run_fake(f, "status")
		testing.expect_value(t, o.exit, Exit.Denied)
		testing.expect(t, strings.contains(o.err, "permission denied"), o.err)
	}
}

@(test)
daemon_found_by_discovery_is_used :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "found")
	defer fake_close(f)
	found := []bus.Found{{name = "fake", url = fake_url(f), events_url = fake_events_url(f)}}
	o := run_argv({"status"}, found = found)
	testing.expect_value(t, o.exit, Exit.Ok)
	o2 := run_argv({"--name", "fake", "status"}, found = found)
	testing.expect_value(t, o2.exit, Exit.Ok)
	o3 := run_argv({"--name", "other", "status"}, found = found)
	testing.expect_value(t, o3.exit, Exit.Not_Running)
	two := []bus.Found{found[0], found[0]}
	two[1].name = "second"
	o4 := run_argv({"status"}, found = two)
	testing.expect_value(t, o4.exit, Exit.Usage)
	testing.expect(t, strings.contains(o4.err, "fake, second"), o4.err)
}

// ---- timeouts and repeats ----

@(test)
timeout_is_repeated_once_with_the_same_id :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "retry")
	defer fake_close(f)
	fake_result(f, "peers.reload", `{"pins":1,"added":0,"removed":0,"disabled":0,"kicked":0}`)
	// The first reply comes after 1.5 s; the caller gives up after 1 s and
	// asks again with the same id. The daemon runs the request once and
	// gives the second ask the same reply.
	fake_delay(f, "peers.reload", 1500 * time.Millisecond)
	o := run_fake_with(f, {timeout = "1"}, "--id", "retry-me-1", "reload-peers")
	testing.expectf(t, o.exit == .Ok, "exit %v: %s", o.exit, o.err)
	testing.expect(t, strings.contains(o.out, "pins"), o.out)
	seen := fake_seen(f)
	testing.expect_value(t, len(seen), 1)
	if len(seen) == 1 {
		testing.expect_value(t, seen[0].id, "retry-me-1")
	}
}

@(test)
two_timeouts_give_exit_5_and_the_id :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "timeout")
	defer fake_close(f)
	fake_delay(f, "daemon.reload", 1500 * time.Millisecond)
	o := run_fake_with(f, {timeout = "0.4"}, "--id", "fixed-id-9", "reload")
	testing.expect_value(t, o.exit, Exit.Timeout)
	testing.expect(t, strings.contains(o.err, "twice"), o.err)
	testing.expect(t, strings.contains(o.err, "--id fixed-id-9"), o.err)
	testing.expect(t, strings.contains(o.err, "may still have been applied"), o.err)
	testing.expect_value(t, o.out, "")
}

@(test)
credentials_are_never_asked_twice :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "credtimeout")
	defer fake_close(f)
	fake_delay(f, "auth.credentials", 1200 * time.Millisecond)
	o := run_fake_with(f, {timeout = "0.4"}, "auth", "credentials", "s-1")
	testing.expect_value(t, o.exit, Exit.Timeout)
	testing.expect(t, strings.contains(o.err, "sent once"), o.err)
}

// ---- auth ----

@(test)
auth_credentials_prints_what_the_client_sent :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "creds")
	defer fake_close(f)
	fake_result(f, "auth.credentials", `{"session":"s-9","username":"alice","password":"s3cret"}`)
	o := run_fake(f, "auth", "credentials", "s-9")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.out, "session   s-9\nusername  alice\npassword  s3cret\n")
}

@(test)
auth_supply_sends_the_secret_from_stdin :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "supply", {mode = .Client})
	defer fake_close(f)
	fake_result(f, "auth.supply", `{"accepted":true}`)
	o := run_fake_with(f, {stdin = "hunter2\nignored second line\n"}, "auth-supply", "--username", "alice", "--password-stdin")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.out, "accepted  true\n")
	s := only_seen(t, f)
	testing.expect_value(t, s.op, "auth.supply")
	testing.expect_value(t, s.args, `{"password":"hunter2","username":"alice"}`)
	// The secret is not echoed anywhere.
	testing.expect(t, !strings.contains(o.out, "hunter2") && !strings.contains(o.err, "hunter2"))
}

@(test)
auth_supply_reads_files_and_checks_them :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "supplyfile", {mode = .Client})
	defer fake_close(f)
	fake_result(f, "auth.supply", `{"accepted":true}`)
	pw := fmt.tprintf("%s/pw", f.dir)
	resp := fmt.tprintf("%s/resp", f.dir)
	testing.expect(t, os.write_entire_file(pw, "pa ss\r\n") == nil)
	testing.expect(t, os.write_entire_file(resp, "123456") == nil)
	o := run_fake(f, "auth-supply", "--password-file", pw, "--response-file", resp)
	testing.expect_value(t, o.exit, Exit.Ok)
	s := only_seen(t, f)
	testing.expect_value(t, s.args, `{"password":"pa ss","response":"123456"}`)

	// Problems with the secret are found before anything is sent.
	missing := run_fake(f, "auth-supply", "--password-file", fmt.tprintf("%s/nope", f.dir))
	testing.expect_value(t, missing.exit, Exit.Failed)
	testing.expect(t, strings.contains(missing.err, "cannot read"), missing.err)
	empty := run_fake_with(f, {stdin = "\n"}, "auth-supply", "--password-stdin")
	testing.expect_value(t, empty.exit, Exit.Usage)
	testing.expect(t, strings.contains(empty.err, "empty"), empty.err)
	long := run_fake_with(f, {stdin = strings.repeat("x", 600, context.temp_allocator)}, "auth-supply", "--response-stdin")
	testing.expect_value(t, long.exit, Exit.Usage)
	testing.expect(t, strings.contains(long.err, "longer than 512"), long.err)
	testing.expect_value(t, fake_seen_count(f), 1)
}

// ---- events ----

Publisher :: struct {
	f:             ^Fake,
	done:          bool,
	// Publish an event that is too big after each pair: a gap for the reader.
	with_gap:      bool,
	// Restart the daemon after this many rounds (0: never), then publish
	// `rounds_after` more and set `stop`.
	restart_after: int,
	rounds_after:  int,
	stop:          ^Stop,
	big:           string,
}

publisher_main :: proc(th: ^thread.Thread) {
	p := (^Publisher)(th.data)
	context.allocator = p.f.alloc
	round := 0
	after := 0
	restarted := false
	for !sync.atomic_load(&p.done) {
		round += 1
		data := fmt.tprintf(`{{"session":"s-%d","name":"alice smith"}}`, round)
		bus.publish(p.f.host, "stats.tick", transmute([]byte)string(`{"interval_s":1}`))
		bus.publish(p.f.host, "peer.connect", transmute([]byte)data)
		if p.with_gap {
			bus.publish(p.f.host, "big.event", transmute([]byte)p.big)
		}
		if p.restart_after > 0 && round == p.restart_after && !restarted {
			restarted = true
			bus.host_close(p.f.host)
			p.f.host = nil
			// The policy of the first run: on Windows a subscriber needs the
			// read role.
			policy, unresolved := bus.policy_from_config(p.f.allow, test_euid())
			delete(unresolved)
			opts := bus.Host_Options {
				events    = bus.Endpoint{path = fake_events_path(p.f)},
				policy    = policy,
				allocator = context.allocator,
			}
			h, err, _ := bus.host_open(opts)
			bus.policy_destroy(&policy)
			if err != .None {
				return
			}
			p.f.host = h
		}
		if restarted {
			after += 1
			if after >= p.rounds_after && p.stop != nil {
				sync.atomic_store(&p.stop.flag, true)
			}
		}
		time.sleep(10 * time.Millisecond)
	}
}

publisher_start :: proc(p: ^Publisher) -> ^thread.Thread {
	th := thread.create(publisher_main)
	th.data = p
	thread.start(th)
	return th
}

publisher_stop :: proc(p: ^Publisher, th: ^thread.Thread) {
	sync.atomic_store(&p.done, true)
	thread.join(th)
	thread.destroy(th)
}

@(test)
events_prints_the_wanted_topics :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "events", {no_loop = true})
	defer fake_close(f)
	p := Publisher {
		f = f,
	}
	th := publisher_start(&p)
	defer publisher_stop(&p, th)
	o := run_fake(f, "events", "-n", "3", "peer.")
	testing.expect_value(t, o.exit, Exit.Ok)
	lines := strings.split_lines(strings.trim_right(o.out, "\n"), context.temp_allocator)
	testing.expect_value(t, len(lines), 3)
	for l in lines {
		testing.expect(t, strings.contains(l, " peer.connect session=s-"), l)
		testing.expect(t, strings.contains(l, `name="alice smith"`), l)
		testing.expect(t, !strings.contains(l, "stats.tick"), l)
		// The timestamp comes first: 24 characters.
		testing.expect(t, len(l) > 25 && l[24] == ' ' && l[23] == 'Z', l)
	}
}

@(test)
events_json_prints_the_raw_envelope :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "eventsjson", {no_loop = true})
	defer fake_close(f)
	p := Publisher {
		f = f,
	}
	th := publisher_start(&p)
	defer publisher_stop(&p, th)
	o := run_fake(f, "--json", "events", "-n", "2")
	testing.expect_value(t, o.exit, Exit.Ok)
	lines := strings.split_lines(strings.trim_right(o.out, "\n"), context.temp_allocator)
	testing.expect_value(t, len(lines), 2)
	for l in lines {
		testing.expect(t, strings.has_prefix(l, `{"v":1,"run":"`), l)
		v, err := json.parse(transmute([]byte)l, .JSON, true, context.temp_allocator)
		testing.expect_value(t, err, json.Error.None)
		obj, _ := v.(json.Object)
		topic, _ := obj["topic"].(json.String)
		testing.expect(t, topic == "stats.tick" || topic == "peer.connect")
	}
}

@(test)
events_reports_a_gap_on_stderr :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "eventsgap", {no_loop = true})
	defer fake_close(f)
	p := Publisher {
		f        = f,
		with_gap = true,
		big      = strings.concatenate({`{"pad":"`, strings.repeat("x", bus.MAX_EVENT_SIZE, context.temp_allocator), `"}`}, context.temp_allocator),
	}
	th := publisher_start(&p)
	defer publisher_stop(&p, th)
	o := run_fake(f, "events", "-n", "5", "peer.")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect(t, strings.contains(o.err, "note:"), o.err)
	testing.expect(t, strings.contains(o.err, "before this one (seq"), o.err)
	// The notes are on stderr only.
	testing.expect(t, !strings.contains(o.out, "missed"))
}

@(test)
events_survives_a_daemon_restart :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "eventsrestart", {no_loop = true})
	defer fake_close(f)
	stop := stop_init()
	p := Publisher {
		f             = f,
		restart_after = 30,
		rounds_after  = 120,
		stop          = &stop,
	}
	th := publisher_start(&p)
	defer publisher_stop(&p, th)
	o := run_fake_with(f, {stop = &stop}, "events", "peer.")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect(t, strings.contains(o.err, "the daemon restarted"), o.err)
	lines := strings.split_lines(strings.trim_right(o.out, "\n"), context.temp_allocator)
	testing.expect(t, len(lines) > 10, o.out)
}

@(test)
events_wait_survives_a_missing_daemon :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "evwait")
	defer remove_dir(dir)
	stop := stop_init()
	Stopper :: struct {
		stop: ^Stop,
	}
	s := Stopper {
		stop = &stop,
	}
	th := thread.create(proc(th: ^thread.Thread) {
			s := (^Stopper)(th.data)
			time.sleep(300 * time.Millisecond)
			sync.atomic_store(&s.stop.flag, true)
		})
	th.data = &s
	thread.start(th)
	defer {
		thread.join(th)
		thread.destroy(th)
	}
	start := time.now()
	o := run_argv({"--socket", test_socket(dir, "late"), "events", "--wait"}, stop = &stop)
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.out, "")
	testing.expect(t, time.since(start) < 5 * time.Second)
}

// ---- helpers ----

make_dir :: proc(t: ^testing.T, tag: string) -> string {
	base, _ := os.temp_directory(context.temp_allocator)
	if len(base) > 40 {
		base = "/tmp"
	}
	dir, err := os.make_directory_temp(base, fmt.tprintf("noir-ctl-%s-*", tag), context.allocator)
	testing.expectf(t, err == nil, "cannot create a temp dir: %v", err)
	return dir
}

remove_dir :: proc(dir: string) {
	os.remove_all(dir)
	delete(dir)
}

// ---- profile operations ----

PROFILE_RESULT :: `{"options":[{"name":"client","line":1,"disposition":"supported","note":null},{"name":"daemon","line":2,"disposition":"ignored","note":"runs in the foreground"}],"sha256":"0123abcd","label":"Work","notes":[]}`

@(test)
profile_set_sends_the_file :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "pset", {mode = .Client})
	defer fake_close(f)
	fake_result(f, "profile.set", PROFILE_RESULT)
	fake_result(f, "profile.check", PROFILE_RESULT)
	path := fmt.tprintf("%s/Work.ovpn", f.dir)
	testing.expect(t, os.write_entire_file(path, "client\nremote 192.0.2.1\n") == nil)
	o := run_fake(f, "profile", "set", path)
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.err, "")
	testing.expect(t, strings.contains(o.out, "client  1     supported"), o.out)
	testing.expect(t, strings.contains(o.out, "daemon  2     ignored      runs in the foreground"), o.out)
	testing.expect(t, strings.contains(o.out, "sha256  0123abcd"), o.out)
	s := only_seen(t, f)
	testing.expect_value(t, s.op, "profile.set")
	testing.expect_value(t, s.args, `{"label":"Work","text":"client\nremote 192.0.2.1\n"}`)

	// --json: the reply as it is.
	o2 := run_fake(f, "--json", "profile", "check", path, "--label", "L")
	testing.expect_value(t, o2.exit, Exit.Ok)
	testing.expect(t, strings.has_prefix(o2.out, `{"v":1,`), o2.out)
	testing.expect(t, strings.contains(o2.out, `"sha256":"0123abcd"`), o2.out)

	// A file that is not there.
	o3 := run_fake(f, "profile", "set", fmt.tprintf("%s/none.ovpn", f.dir))
	testing.expect_value(t, o3.exit, Exit.Failed)
	testing.expect(t, strings.contains(o3.err, "cannot read the profile file"), o3.err)
}

refuse_profile :: proc(f: ^Fake, req: ^bus.Request) -> bool {
	if req.op != "profile.set" && req.op != "profile.check" {
		return false
	}
	details := `[{"line":3,"option":"ca","class":"path","reason":"a profile cannot use a file"},{"line":9,"option":"up","class":"not_supported","reason":"scripts are removed"}]`
	bus.reply_error_details(f.host, req, .Bad_Request, "the profile has problems", transmute([]byte)details)
	return true
}

@(test)
profile_refused_lists_the_problems :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "pbad", {mode = .Client})
	defer fake_close(f)
	f.custom = refuse_profile
	path := fmt.tprintf("%s/bad.ovpn", f.dir)
	testing.expect(t, os.write_entire_file(path, "client\n") == nil)
	o := run_fake(f, "profile", "check", path)
	testing.expect_value(t, o.exit, Exit.Error)
	testing.expect_value(t, o.out, "")
	want := `noirvpnctl: error: bad_request: the profile has problems
LINE  OPTION  CLASS          REASON
3     ca      path           a profile cannot use a file
9     up      not_supported  scripts are removed
`
	testing.expect_value(t, o.err, want)
	// --json: the raw reply with the details, on standard output.
	o2 := run_fake(f, "--json", "profile", "set", path)
	testing.expect_value(t, o2.exit, Exit.Error)
	testing.expect(t, strings.contains(o2.out, `"details":[`), o2.out)
	testing.expect_value(t, o2.err, "")
}

@(test)
profile_clear_and_conflict :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "pclear", {mode = .Client})
	defer fake_close(f)
	fake_result(f, "profile.clear", `{"cleared":true}`)
	o := run_fake(f, "profile", "clear")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect_value(t, o.out, "cleared  true\n")
	s := only_seen(t, f)
	testing.expect_value(t, s.op, "profile.clear")
	fake_error(f, "profile.clear", "conflict")
	o2 := run_fake(f, "profile", "clear")
	testing.expect_value(t, o2.exit, Exit.Error)
	testing.expect(t, strings.contains(o2.err, "conflict"), o2.err)
}

// ---- connect --follow ----

@(private = "file")
follow_handler :: proc(f: ^Fake, req: ^bus.Request) -> bool {
	switch req.op {
	case "connect":
		bus.reply_ok(f.host, req, transmute([]byte)string(`{"state":"connecting","already":false}`))
		return true
	case "status":
		deadline: [24]u8
		ts := bus.format_ts(time.time_add(time.now(), 120 * time.Second), &deadline)
		result := fmt.tprintf(`{{"mode":"client","client":{{"state":"handshake","auth_needed":{{"kind":"web_auth","reason":"web_auth","username":null,"prompt":null,"echo":false,"timeout_s":120,"url":"https://login.example.com/x?state=1","host":"login.example.com","flags":[],"deadline":"%s"}},"reason":null}}}}`, ts)
		bus.reply_ok(f.host, req, transmute([]byte)result)
		return true
	}
	return false
}

Up_Publisher :: struct {
	f:    ^Fake,
	done: bool,
}

@(test)
connect_follow_prints_the_link_and_ends_when_up :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "follow", {mode = .Client})
	defer fake_close(f)
	f.custom = follow_handler
	p := Up_Publisher {
		f = f,
	}
	th := thread.create(proc(th: ^thread.Thread) {
		p := (^Up_Publisher)(th.data)
		for !sync.atomic_load(&p.done) {
			sync.mutex_lock(&p.f.mu)
			asked := p.f.handled["status"]
			sync.mutex_unlock(&p.f.mu)
			if asked > 0 {
				bus.publish(p.f.host, "client.state", transmute([]byte)string(`{"state":"up","prev":"handshake","reason":null,"detail":null,"remote":"192.0.2.1:1194","attempt":1,"datapath":"userspace"}`))
			}
			time.sleep(20 * time.Millisecond)
		}
	})
	th.data = &p
	thread.start(th)
	defer {
		sync.atomic_store(&p.done, true)
		thread.join(th)
		thread.destroy(th)
	}
	o := run_fake(f, "connect", "--follow")
	testing.expect_value(t, o.exit, Exit.Ok)
	testing.expect(t, strings.contains(o.out, "state: connecting\n"), o.out)
	testing.expect(t, strings.contains(o.out, "\n  https://login.example.com/x?state=1\n"), o.out)
	testing.expect(t, strings.contains(o.out, " seconds left to sign in\n"), o.out)
	testing.expect(t, strings.has_suffix(o.out, "state: up\n"), o.out)
	testing.expect_value(t, strings.count(o.out, "https://"), 1)
}
