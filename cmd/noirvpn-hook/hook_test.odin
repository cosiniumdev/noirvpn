// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The reader and the runner against a fake daemon (a real bus host with an
// events socket) and real /bin/sh scripts.

import "base:intrinsics"
import "base:runtime"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "noir:bus"

BASE :: []string{"PATH=/usr/bin:/bin"}

// A hook running on its own thread, with the log kept in memory.
Hook_Thread :: struct {
	cfg:    Config,
	stop:   Stop,
	log:    Logger,
	lines:  [dynamic]string,
	url:    string,
	thread: ^thread.Thread,
	joined: bool,
	exit:   Hook_Exit,
	stats:  Runner_Stats,
	alloc:  runtime.Allocator,
}

hook_thread_main :: proc(th: ^thread.Thread) {
	h := (^Hook_Thread)(th.data)
	context.allocator = h.alloc
	h.exit = hook_run(&h.cfg, h.url, &h.stop, &h.log, BASE, &h.stats)
}

// Start a hook for the config text. `fix` may change the settings (a test
// wants less than a second).
hook_start :: proc(t: ^testing.T, f: ^Fake, text: string, fix: proc(c: ^Config) = nil) -> ^Hook_Thread {
	h := new(Hook_Thread)
	h.alloc = context.allocator
	h.cfg = config_default()
	errors := make([dynamic]Config_Error, context.temp_allocator)
	parse_config(&h.cfg, text, &errors)
	testing.expect_value(t, len(errors), 0)
	if fix != nil {
		fix(&h.cfg)
	}
	h.stop = stop_init()
	h.lines.allocator = h.alloc
	h.log = Logger {
		verb    = 4,
		capture = &h.lines,
		alloc   = h.alloc,
	}
	h.url = fake_events_path(f)
	h.url = strings.clone(h.url)
	h.thread = thread.create(hook_thread_main)
	h.thread.data = h
	thread.start(h.thread)
	return h
}

// Ask it to stop and wait for it.
hook_stop :: proc(h: ^Hook_Thread) {
	if h.joined {
		return
	}
	intrinsics.atomic_store(&h.stop.flag, true)
	thread.join(h.thread)
	thread.destroy(h.thread)
	h.joined = true
}

// Stop it (if the test did not) and free everything.
hook_finish :: proc(h: ^Hook_Thread) {
	hook_stop(h)
	config_destroy(&h.cfg)
	for l in h.lines {
		delete(l, h.alloc)
	}
	delete(h.lines)
	delete(h.url)
	free(h)
}

// How many log lines contain `text`.
log_count :: proc(h: ^Hook_Thread, text: string) -> int {
	sync.mutex_lock(&h.log.mu)
	defer sync.mutex_unlock(&h.log.mu)
	n := 0
	for l in h.lines {
		if strings.contains(l, text) {
			n += 1
		}
	}
	return n
}

log_text :: proc(h: ^Hook_Thread) -> string {
	sync.mutex_lock(&h.log.mu)
	defer sync.mutex_unlock(&h.log.mu)
	return strings.join(h.lines[:], "\n", context.temp_allocator)
}

// ---- helpers for the scripts' output ----

dir_names :: proc(dir: string, suffix: string) -> []string {
	infos, err := os.read_all_directory_by_path(dir, context.temp_allocator)
	if err != nil {
		return nil
	}
	out := make([dynamic]string, context.temp_allocator)
	for info in infos {
		if strings.has_suffix(info.name, suffix) {
			append(&out, strings.clone(info.name, context.temp_allocator))
		}
	}
	return out[:]
}

File_Count :: struct {
	dir:    string,
	suffix: string,
	want:   int,
}

has_files :: proc(ctx: rawptr) -> bool {
	c := (^File_Count)(ctx)
	return len(dir_names(c.dir, c.suffix)) >= c.want
}

// Publish `topic` every 20 ms until `done` is true. A subscriber that has just
// been started misses the first events, so a test cannot publish just once.
Publish_Until :: struct {
	f:     ^Fake,
	topic: string,
	data:  string,
	done:  proc(ctx: rawptr) -> bool,
	ctx:   rawptr,
}

publish_until_done :: proc(p: Publish_Until, limit := 10 * time.Second) -> bool {
	start := time.now()
	for time.since(start) < limit {
		if p.done(p.ctx) {
			return true
		}
		publish(p.f, p.topic, p.data)
		time.sleep(20 * time.Millisecond)
	}
	return p.done(p.ctx)
}

publish :: proc(f: ^Fake, topic, data: string) {
	bus.publish(f.host, topic, transmute([]byte)data)
}

// ---- tests ----

@(test)
script_runs_for_each_matching_event :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "run")
	defer fake_close(f)
	script := write_script(t, f.dir, "on-peer", `cat > "$1/$NOIR_SEQ.in"
env > "$1/$NOIR_SEQ.env"
: > "$1/$NOIR_SEQ.done"
exit 0`)
	h := hook_start(t, f, fmt.tprintf("on peer. run %s %s\n", script, f.dir))
	defer hook_finish(h)

	count := File_Count{f.dir, ".done", 1}
	// Events that no rule wants come first; they must not run anything.
	ok := publish_until_done(Publish_Until{f, "peer.connect", `{"session":"s-1","name":"alice","peer_id":3,"pin":null,"ok":true,"peer_info":{"IV_VER":"2.6"}}`, has_files, &count})
	testing.expect(t, ok, log_text(h))
	for _ in 0 ..< 3 {
		publish(f, "auth.pending", `{"session":"s-9"}`)
	}
	time.sleep(100 * time.Millisecond)

	done := dir_names(f.dir, ".done")
	testing.expect(t, len(done) >= 1)
	seq_text := done[0][:len(done[0]) - len(".done")]

	// stdin is the envelope as sent, then a newline.
	raw := read_text(fmt.tprintf("%s/%s.in", f.dir, seq_text))
	testing.expect(t, strings.has_suffix(raw, "}\n"), raw)
	root, perr := json.parse(transmute([]byte)raw, parse_integers = true, allocator = context.temp_allocator)
	testing.expect_value(t, perr, json.Error.None)
	obj, _ := root.(json.Object)
	topic, _ := obj["topic"].(json.String)
	testing.expect_value(t, topic, "peer.connect")
	version, _ := obj["v"].(json.Integer)
	testing.expect_value(t, version, 1)
	data, _ := obj["data"].(json.Object)
	peer_name, _ := data["name"].(json.String)
	testing.expect_value(t, peer_name, "alice")

	// The environment: the base, the event, the scalar fields.
	env := read_text(fmt.tprintf("%s/%s.env", f.dir, seq_text))
	lines := strings.split_lines(env, context.temp_allocator)
	vars := make(map[string]string, allocator = context.temp_allocator)
	for line in lines {
		if eq := strings.index_byte(line, '='); eq > 0 {
			vars[line[:eq]] = line[eq + 1:]
		}
	}
	testing.expect_value(t, vars["NOIR_TOPIC"], "peer.connect")
	testing.expect_value(t, vars["NOIR_SEQ"], seq_text)
	testing.expect_value(t, len(vars["NOIR_RUN"]), 16)
	testing.expect_value(t, len(vars["NOIR_TS"]), 24)
	testing.expect_value(t, vars["NOIR_SESSION"], "s-1")
	testing.expect_value(t, vars["NOIR_NAME"], "alice")
	testing.expect_value(t, vars["NOIR_PEER_ID"], "3")
	testing.expect_value(t, vars["NOIR_OK"], "true")
	testing.expect_value(t, vars["PATH"], "/usr/bin:/bin")
	for name in vars {
		switch {
		case strings.has_prefix(name, "NOIR_"):
		case name == "PATH", name == "PWD", name == "SHLVL", name == "_", name == "OLDPWD":
		case:
			testing.expectf(t, false, "unexpected variable %s", name)
		}
	}
	_, has_info := vars["NOIR_PEER_INFO"]
	testing.expect(t, !has_info)

	// No script ran for the other topic.
	for name in dir_names(f.dir, ".in") {
		text := read_text(fmt.tprintf("%s/%s", f.dir, name))
		testing.expect(t, strings.contains(text, `"topic":"peer.connect"`), text)
	}
	// The run was logged with its exit status.
	testing.expect(t, wait_for(2 * time.Second, h, proc(ctx: rawptr) -> bool {
			return log_count((^Hook_Thread)(ctx), ": exit 0 (") >= 1
		}), log_text(h))
}

@(test)
failing_and_missing_commands_are_warnings :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "fail")
	defer fake_close(f)
	bad := write_script(t, f.dir, "bad", "exit 3")
	text := fmt.tprintf("on peer.fail run %s\non peer.nocmd run /nonexistent/hook-command\n", bad)
	h := hook_start(t, f, text)
	defer hook_finish(h)

	// Both kinds of event, until both outcomes are in the log.
	both :: proc(ctx: rawptr) -> bool {
		h := (^Hook_Thread)(ctx)
		return log_count(h, "WARN  seq=") >= 2 && log_count(h, ": exit 3 (") >= 1 && log_count(h, "cannot start: ENOENT") >= 1
	}
	start := time.now()
	for time.since(start) < 10 * time.Second && !both(h) {
		publish(f, "peer.fail", `{}`)
		publish(f, "peer.nocmd", `{}`)
		time.sleep(20 * time.Millisecond)
	}
	testing.expect(t, both(h), log_text(h))
	hook_stop(h)
	// A failing command is not fatal: the hook ended normally.
	testing.expect_value(t, h.exit, Hook_Exit.Ok)
	testing.expect(t, h.stats.failed >= 2)
}

@(test)
slow_commands_do_not_block_the_reader_and_a_full_queue_drops :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "queue")
	defer fake_close(f)
	script := write_script(t, f.dir, "slow", `echo $NOIR_SEQ >> "$1/started"
sleep 30`)
	h := hook_start(t, f, fmt.tprintf("on peer. run %s %s\n", script, f.dir), proc(c: ^Config) {
		c.max_parallel = 1
		c.max_queue = 2
		c.timeout = 60 * time.Second
		c.grace = 300 * time.Millisecond
	})
	defer hook_finish(h)

	started := fmt.tprintf("%s/started", f.dir)
	got_started :: proc(ctx: rawptr) -> bool {
		return os.exists((^string)(ctx)^)
	}
	ok := publish_until_done(Publish_Until{f, "peer.x", `{}`, got_started, &started})
	testing.expect(t, ok, log_text(h))

	// The one slot is busy. A burst must be read at once, without waiting for
	// the command, and the events that do not fit must be dropped.
	for _ in 0 ..< 40 {
		publish(f, "peer.x", `{}`)
	}
	dropped := wait_for(5 * time.Second, h, proc(ctx: rawptr) -> bool {
		return log_count((^Hook_Thread)(ctx), "the queue is full") >= 10
	})
	testing.expect(t, dropped, log_text(h))
	testing.expect(t, log_count(h, "the queue is full (2)") >= 1)
	// Only one command ever started: the slot was never free.
	testing.expect_value(t, len(strings.split_lines(strings.trim_space(read_text(started)), context.temp_allocator)), 1)

	// Stopping drops what waits and kills what runs, after the grace time.
	start := time.now()
	hook_stop(h)
	testing.expect(t, time.since(start) < 5 * time.Second)
	testing.expect_value(t, h.exit, Hook_Exit.Ok)
	testing.expect(t, h.stats.dropped >= 10)
	testing.expect_value(t, h.stats.discarded, 2)
	testing.expect_value(t, log_count(h, "killed at shutdown"), 1)
	testing.expect_value(t, log_count(h, "was still queued, so it is dropped"), 2)
}

@(test)
command_over_its_time_is_killed :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "timeout")
	defer fake_close(f)
	script := write_script(t, f.dir, "hang", `echo $NOIR_SEQ >> "$1/started"
sleep 30`)
	h := hook_start(t, f, fmt.tprintf("on peer. run %s %s\n", script, f.dir), proc(c: ^Config) {
		c.timeout = 400 * time.Millisecond
	})
	defer hook_finish(h)
	started := fmt.tprintf("%s/started", f.dir)
	got_started :: proc(ctx: rawptr) -> bool {
		return os.exists((^string)(ctx)^)
	}
	testing.expect(t, publish_until_done(Publish_Until{f, "peer.x", `{}`, got_started, &started}), log_text(h))
	killed := wait_for(5 * time.Second, h, proc(ctx: rawptr) -> bool {
		return log_count((^Hook_Thread)(ctx), "timed out after") >= 1
	})
	testing.expect(t, killed, log_text(h))
	// A timed out command is a warning.
	testing.expect_value(t, log_count(h, "ERROR"), 0)
}

@(test)
parallel_limit_is_kept :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "par")
	defer remove_dir(dir)
	script := write_script(t, dir, "count", `touch "$1/active.$$"
ls "$1" | grep -c '^active\.' >> "$1/counts"
sleep 1
rm "$1/active.$$"
: > "$1/end.$$"`)
	cfg := config_default()
	defer config_destroy(&cfg)
	cfg.max_parallel = 2
	cfg.max_queue = 10
	cfg.timeout = 20 * time.Second
	argv := []string{script, dir}

	lines: [dynamic]string
	defer {
		for l in lines {
			delete(l)
		}
		delete(lines)
	}
	log := Logger {
		verb    = 4,
		capture = &lines,
		alloc   = context.allocator,
	}
	r: Runner
	testing.expect(t, runner_start(&r, &cfg, &log))
	for i in 0 ..< 5 {
		testing.expect(t, runner_submit(&r, test_job(&r, u64(i + 1), argv)))
	}
	done := wait_for(15 * time.Second, &dir, proc(ctx: rawptr) -> bool {
		return len(end_files((^string)(ctx)^)) >= 5
	})
	testing.expect(t, done)
	runner_stop(&r, 2 * time.Second, nil)

	most := 0
	for line in strings.split_lines(read_text(fmt.tprintf("%s/counts", dir)), context.temp_allocator) {
		if line == "" {
			continue
		}
		n := 0
		for ch in line {
			n = n * 10 + int(ch - '0')
		}
		most = max(most, n)
	}
	testing.expect_value(t, most, 2)
	st := runner_stats(&r)
	testing.expect_value(t, st.submitted, 5)
	testing.expect_value(t, st.finished, 5)
	testing.expect_value(t, st.failed, 0)
}

end_files :: proc(dir: string) -> []string {
	all := dir_names(dir, "")
	out := make([dynamic]string, context.temp_allocator)
	for n in all {
		if strings.has_prefix(n, "end.") {
			append(&out, n)
		}
	}
	return out[:]
}

// A job for the runner tests. The runner frees it.
test_job :: proc(r: ^Runner, seq: u64, argv: []string) -> ^Job {
	j := new(Job, r.alloc)
	j.seq = seq
	j.topic = strings.clone("test.job", r.alloc)
	j.argv = argv
	j.env = make([]string, 1, r.alloc)
	j.env[0] = strings.clone("PATH=/usr/bin:/bin", r.alloc)
	j.input = make([]byte, 0, r.alloc)
	return j
}

@(test)
runner_refuses_when_full_and_when_stopped :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "full")
	defer remove_dir(dir)
	script := write_script(t, dir, "sleep", `sleep 30`)
	cfg := config_default()
	defer config_destroy(&cfg)
	cfg.max_parallel = 1
	cfg.max_queue = 2
	argv := []string{script}
	lines: [dynamic]string
	defer {
		for l in lines {
			delete(l)
		}
		delete(lines)
	}
	log := Logger {
		verb    = 4,
		capture = &lines,
		alloc   = context.allocator,
	}
	r: Runner
	testing.expect(t, runner_start(&r, &cfg, &log))
	// One job runs (the worker takes it out of the queue); two wait; the next is refused.
	testing.expect(t, runner_submit(&r, test_job(&r, 1, argv)))
	testing.expect(t, wait_for(5 * time.Second, &r, proc(ctx: rawptr) -> bool {
			return runner_load((^Runner)(ctx)) == 0
		}))
	testing.expect(t, runner_submit(&r, test_job(&r, 2, argv)))
	testing.expect(t, runner_submit(&r, test_job(&r, 3, argv)))
	refused := test_job(&r, 4, argv)
	testing.expect(t, !runner_submit(&r, refused))
	job_destroy(refused, r.alloc)
	testing.expect_value(t, runner_load(&r), 2)

	runner_stop(&r, 100 * time.Millisecond, nil)
	st := runner_stats(&r)
	testing.expect_value(t, st.submitted, 3)
	testing.expect_value(t, st.dropped, 1)
	testing.expect_value(t, st.discarded, 2)
	testing.expect_value(t, st.finished, 1)
	testing.expect_value(t, st.failed, 1)
}

@(test)
hook_survives_a_daemon_restart_and_reports_it :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "restart")
	defer fake_close(f)
	script := write_script(t, f.dir, "log", `echo "$NOIR_RUN ${NOIR_RESTARTED:-0} ${NOIR_GAP:-0}" >> "$1/runs"`)
	h := hook_start(t, f, fmt.tprintf("on peer. run %s %s\n", script, f.dir))
	defer hook_finish(h)
	runs := fmt.tprintf("%s/runs", f.dir)
	has_runs :: proc(ctx: rawptr) -> bool {
		return os.exists((^string)(ctx)^)
	}
	testing.expect(t, publish_until_done(Publish_Until{f, "peer.x", `{}`, has_runs, &runs}), log_text(h))
	first_run := strings.split(read_text(runs), " ", context.temp_allocator)[0]
	first_run = strings.clone(first_run, context.temp_allocator)

	// The daemon goes away and comes back as a new run.
	fake_restart(f, t)
	Restart_Check :: struct {
		runs:      string,
		first_run: string,
	}
	check := Restart_Check{runs, first_run}
	other_run :: proc(ctx: rawptr) -> bool {
		c := (^Restart_Check)(ctx)
		for line in strings.split_lines(read_text(c.runs), context.temp_allocator) {
			if line != "" && !strings.has_prefix(line, c.first_run) {
				return true
			}
		}
		return false
	}
	testing.expect(t, publish_until_done(Publish_Until{f, "peer.x", `{}`, other_run, &check}, 15 * time.Second), log_text(h))
	testing.expect(t, log_count(h, "the daemon restarted") >= 1, log_text(h))
	// The first event of the new run said so in its environment.
	text := read_text(runs)
	testing.expect(t, strings.contains(text, " 1 "), text)
	// The hook is still running.
	testing.expect_value(t, log_count(h, "ERROR"), 0)
}

@(test)
missed_events_are_reported :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	f := fake_open(t, "gap")
	defer fake_close(f)
	script := write_script(t, f.dir, "log", `echo "${NOIR_GAP:-0}" >> "$1/gaps"`)
	h := hook_start(t, f, fmt.tprintf("on peer. run %s %s\n", script, f.dir))
	defer hook_finish(h)
	gaps := fmt.tprintf("%s/gaps", f.dir)
	has_gaps :: proc(ctx: rawptr) -> bool {
		return os.exists((^string)(ctx)^)
	}
	testing.expect(t, publish_until_done(Publish_Until{f, "peer.x", `{}`, has_gaps, &gaps}), log_text(h))
	// An event that is too big is not sent but uses a sequence number.
	big := strings.repeat("a", 70000, context.temp_allocator)
	publish(f, "peer.x", fmt.tprintf(`{{"x":"%s"}}`, big))
	has_gap_line :: proc(ctx: rawptr) -> bool {
		return strings.contains(read_text((^string)(ctx)^), "\n1\n")
	}
	testing.expect(t, publish_until_done(Publish_Until{f, "peer.x", `{}`, has_gap_line, &gaps}), log_text(h))
	testing.expect(t, log_count(h, "1 event(s) were missed") >= 1, log_text(h))
}

@(test)
bad_socket_address_ends_the_hook :: proc(t: ^testing.T) {
	cfg := config_default()
	defer config_destroy(&cfg)
	errors := make([dynamic]Config_Error, context.temp_allocator)
	parse_config(&cfg, "on peer. run /bin/true\n", &errors)
	lines: [dynamic]string
	defer {
		for l in lines {
			delete(l)
		}
		delete(lines)
	}
	log := Logger {
		verb    = 4,
		capture = &lines,
		alloc   = context.allocator,
	}
	stop := stop_init()
	res := hook_run(&cfg, "http://example.invalid/x", &stop, &log, BASE)
	testing.expect_value(t, res, Hook_Exit.Bus_Failed)
	testing.expect_value(t, len(lines), 1)
	testing.expect(t, strings.contains(lines[0], "cannot follow the events"), lines[0])
}
