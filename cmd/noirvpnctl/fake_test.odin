// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd, windows
package main

// A fake daemon for the tests: a real bus host (real sockets in a private
// temp directory, or named pipes on Windows) and a thread that replies to requests from a table, like the
// daemon's event loop would.

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
import "noir:proto/config"

Seen :: struct {
	id:   string,
	op:   string,
	// The arguments as JSON, keys sorted.
	args: string,
}

Fake :: struct {
	dir:     string,
	host:    ^bus.Host,
	loop:    ^thread.Thread,
	stop:    bool,
	mu:      sync.Mutex,
	// What the daemon got, in order.
	seen:    [dynamic]Seen,
	// op -> result JSON for an ok reply.
	results: map[string]string,
	// op -> error code name, for an error reply.
	errors:  map[string]string,
	// Hold the reply to a request for this long (a timeout test).
	delay:   map[string]time.Duration,
	// How many times an op was handled (the delay applies to the first).
	handled: map[string]int,
	// A handler of its own, run instead of the table.
	custom:  proc(f: ^Fake, req: ^bus.Request) -> bool,
	allow:   []config.Bus_Allow,
	mode:    bus.Daemon_Mode,
	// The test's allocator, for the loop thread.
	alloc:   runtime.Allocator,
}

Fake_Options :: struct {
	allow:   []config.Bus_Allow,
	no_loop: bool,
	// Server (the default) or client: the bus refuses operations of the other.
	mode:    bus.Daemon_Mode,
}

fake_open :: proc(t: ^testing.T, tag: string, o: Fake_Options = {}) -> ^Fake {
	f := new(Fake)
	f.alloc = context.allocator
	f.allow = o.allow
	f.mode = o.mode
	base, _ := os.temp_directory(context.temp_allocator)
	if len(base) > 40 {
		base = "/tmp"
	}
	dir, derr := os.make_directory_temp(base, fmt.tprintf("noir-ctl-%s-*", tag), context.allocator)
	testing.expectf(t, derr == nil, "cannot create a temp dir in %q: %v", base, derr)
	f.dir = dir
	fake_dir_private(dir)
	f.results.allocator = context.allocator
	f.errors.allocator = context.allocator
	f.delay.allocator = context.allocator
	f.handled.allocator = context.allocator
	f.seen.allocator = context.allocator
	if !fake_start_host(f, t) {
		testing.fail_now(t, "cannot open the bus")
	}
	if !o.no_loop {
		f.loop = thread.create(fake_loop)
		f.loop.data = f
		thread.start(f.loop)
	}
	return f
}

fake_start_host :: proc(f: ^Fake, t: ^testing.T) -> bool {
	policy, unresolved := bus.policy_from_config(f.allow, test_euid())
	delete(unresolved)
	defer bus.policy_destroy(&policy)
	opts := bus.Host_Options {
		mode      = f.mode,
		control   = bus.Endpoint{path = fake_control_path(f)},
		events    = bus.Endpoint{path = fake_events_path(f)},
		policy    = policy,
		allocator = context.allocator,
	}
	h, err, nerr := bus.host_open(opts)
	testing.expectf(t, err == .None, "host_open: %s (%v)", bus.open_error_string(err), nerr)
	f.host = h
	return err == .None
}

// The --socket value for the fake.
fake_url :: proc(f: ^Fake) -> string {
	when ODIN_OS == .Windows {
		return fake_control_path(f)
	} else {
		return fmt.tprintf("ipc://%s", fake_control_path(f))
	}
}

fake_events_url :: proc(f: ^Fake) -> string {
	when ODIN_OS == .Windows {
		return fake_events_path(f)
	} else {
		return fmt.tprintf("ipc://%s", fake_events_path(f))
	}
}

fake_close :: proc(f: ^Fake) {
	sync.atomic_store(&f.stop, true)
	if f.loop != nil {
		thread.join(f.loop)
		thread.destroy(f.loop)
	}
	if f.host != nil {
		bus.host_close(f.host)
	}
	for s in f.seen {
		delete(s.id)
		delete(s.op)
		delete(s.args)
	}
	delete(f.seen)
	for k, v in f.results {
		delete(k)
		delete(v)
	}
	delete(f.results)
	for k, v in f.errors {
		delete(k)
		delete(v)
	}
	delete(f.errors)
	for k in f.delay {
		delete(k)
	}
	delete(f.delay)
	for k in f.handled {
		delete(k)
	}
	delete(f.handled)
	os.remove_all(f.dir)
	delete(f.dir)
	free(f)
}

// Canned replies. The strings are copied.
fake_result :: proc(f: ^Fake, op, result_json: string) {
	sync.mutex_lock(&f.mu)
	defer sync.mutex_unlock(&f.mu)
	put_string(&f.results, op, result_json)
}

fake_error :: proc(f: ^Fake, op, code: string) {
	sync.mutex_lock(&f.mu)
	defer sync.mutex_unlock(&f.mu)
	put_string(&f.errors, op, code)
}

fake_delay :: proc(f: ^Fake, op: string, d: time.Duration) {
	sync.mutex_lock(&f.mu)
	defer sync.mutex_unlock(&f.mu)
	if op in f.delay {
		f.delay[op] = d
	} else {
		f.delay[strings.clone(op)] = d
	}
}

@(private = "file")
put_string :: proc(m: ^map[string]string, key, value: string) {
	if old, found := m[key]; found {
		delete(old)
		m[key] = strings.clone(value)
	} else {
		m[strings.clone(key)] = strings.clone(value)
	}
}

// What the daemon has seen so far (the strings are shared, the slice is in
// temp memory).
fake_seen :: proc(f: ^Fake) -> []Seen {
	sync.mutex_lock(&f.mu)
	defer sync.mutex_unlock(&f.mu)
	out := make([]Seen, len(f.seen), context.temp_allocator)
	copy(out, f.seen[:])
	return out
}

fake_seen_count :: proc(f: ^Fake) -> int {
	sync.mutex_lock(&f.mu)
	defer sync.mutex_unlock(&f.mu)
	return len(f.seen)
}

fake_loop :: proc(th: ^thread.Thread) {
	f := (^Fake)(th.data)
	context.allocator = f.alloc
	for !sync.atomic_load(&f.stop) {
		h := f.host
		fake_wait(h)
		for {
			req, ok := bus.next_request(h)
			if !ok {
				break
			}
			fake_handle(f, req)
		}
		for {
			_, ok := bus.next_notice(h)
			if !ok {
				break
			}
		}
	}
}

fake_handle :: proc(f: ^Fake, req: ^bus.Request) {
	args_text := ""
	if marshaled, merr := json.marshal(req.args, {sort_maps_by_key = true}, context.temp_allocator); merr == nil {
		args_text = string(marshaled)
	}
	sync.mutex_lock(&f.mu)
	append(&f.seen, Seen{id = strings.clone(req.id), op = strings.clone(req.op), args = strings.clone(args_text)})
	n := f.handled[req.op]
	if req.op in f.handled {
		f.handled[req.op] = n + 1
	} else {
		f.handled[strings.clone(req.op)] = 1
	}
	d := f.delay[req.op] if n == 0 else 0
	code, has_err := f.errors[req.op]
	result, has_result := f.results[req.op]
	custom := f.custom
	sync.mutex_unlock(&f.mu)
	if custom != nil && custom(f, req) {
		return
	}
	if d > 0 {
		time.sleep(d)
	}
	if has_err {
		c, _ := bus.error_code_from_string(code)
		bus.reply_error(f.host, req, c, fmt.tprintf("fake %s error", code))
		return
	}
	if has_result {
		bus.reply_ok(f.host, req, transmute([]byte)result)
		return
	}
	bus.reply_ok(f.host, req, nil)
}

// Wait until `cond` is true, at most `limit`.
wait_for :: proc(limit: time.Duration, ctx: rawptr, cond: proc(ctx: rawptr) -> bool) -> bool {
	start := time.now()
	for time.since(start) < limit {
		if cond(ctx) {
			return true
		}
		time.sleep(2 * time.Millisecond)
	}
	return cond(ctx)
}
