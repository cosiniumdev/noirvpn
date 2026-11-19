// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package bus

// Tests of the whole bus over real ipc:// sockets in a private temp directory.
// A fake "daemon loop" thread waits on the wake fd, like the real loop will.
// Every test creates its own directory, so the tests can run in parallel.

import "base:intrinsics"
import "base:runtime"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"
import "noir:bus/nng"
import "noir:proto/config"

// ---- fixture ----

Handler :: proc(fx: ^Fixture, req: ^Request)

Fixture :: struct {
	dir:         string,
	host:        ^Host,
	loop:        ^thread.Thread,
	handler:     Handler,
	// Written by the test thread, read by the loop thread.
	stop:        bool,
	hold:        bool, // do not drain the queue
	// Written by the loop thread: it saw `hold` and drains nothing until `hold` is cleared.
	held:        bool,
	release:     bool, // reply to the deferred requests
	// Written by the loop thread, read by the test thread.
	handled:     int,
	kicks:       int,
	mu:          sync.Mutex,
	notices:     [dynamic]Notice,
	// Loop thread only.
	deferred:    [dynamic]^Request,
	closed_here: bool,
}

Fixture_Options :: struct {
	mode:          Daemon_Mode,
	allow:         []config.Bus_Allow,
	// Use the default policy (root and ourselves) when `allow` is empty.
	workers:       int,
	max_pending:   int,
	reply_timeout: time.Duration,
	no_loop:       bool,
	no_events:     bool,
	handler:       Handler,
	events_mode:   u32,
	control_mode:  u32,
	member:        Member_Check,
}

make_test_dir :: proc(t: ^testing.T, tag: string) -> string {
	base, _ := os.temp_directory(context.temp_allocator)
	if len(base) > 40 {
		base = "/tmp"
	}
	dir, err := os.make_directory_temp(base, fmt.tprintf("noir-bus-%s-*", tag), context.allocator)
	testing.expectf(t, err == nil, "cannot create temp dir in %q: %v", base, err)
	// Not at the mercy of the umask, which other tests change.
	posix.chmod(strings.clone_to_cstring(dir, context.temp_allocator), u32_to_mode(0o700))
	return dir
}

remove_test_dir :: proc(dir: string) {
	os.remove_all(dir)
	delete(dir)
}

fixture_open :: proc(t: ^testing.T, tag: string, o: Fixture_Options = {}) -> ^Fixture {
	fx := new(Fixture)
	fx.dir = make_test_dir(t, tag)
	fx.handler = o.handler if o.handler != nil else default_handler
	fx.notices.allocator = context.allocator
	fx.deferred.allocator = context.allocator

	policy, unresolved := policy_from_config(o.allow, euid())
	delete(unresolved)
	defer policy_destroy(&policy)

	opts := Host_Options {
		mode          = o.mode,
		control       = Endpoint{path = fmt.tprintf("%s/ctl.sock", fx.dir), mode = o.control_mode},
		policy        = policy,
		workers       = o.workers,
		max_pending   = o.max_pending,
		reply_timeout = o.reply_timeout,
		allocator     = context.allocator,
		member        = o.member,
	}
	if !o.no_events {
		opts.events = Endpoint{path = fmt.tprintf("%s/ev.sock", fx.dir), mode = o.events_mode}
	}
	h, err, nerr := host_open(opts)
	testing.expectf(t, err == .None, "host_open: %s (%v)", open_error_string(err), nerr)
	if err != .None {
		testing.fail_now(t, "cannot open the bus")
	}
	fx.host = h
	if !o.no_loop {
		fx.loop = thread.create(loop_main)
		fx.loop.data = fx
		thread.start(fx.loop)
	}
	return fx
}

fixture_close :: proc(fx: ^Fixture) {
	sync.atomic_store(&fx.stop, true)
	if fx.loop != nil {
		thread.join(fx.loop)
		thread.destroy(fx.loop)
	}
	if fx.host != nil {
		host_close(fx.host)
	}
	delete(fx.notices)
	delete(fx.deferred)
	remove_test_dir(fx.dir)
	free(fx)
}

// Stops the draining of the fake loop. The loop checks `hold` before it polls
// and drains, so a request that comes right after the store could still be
// taken: wait until the loop has seen the flag.
fixture_hold :: proc(t: ^testing.T, fx: ^Fixture) {
	sync.atomic_store(&fx.hold, true)
	seen := wait_until(10 * time.Second, fx, proc(p: rawptr) -> bool {
		return sync.atomic_load(&(^Fixture)(p).held)
	})
	testing.expect(t, seen, "the loop never stopped its draining")
}

ctl_url :: proc(fx: ^Fixture) -> string {
	return fmt.tprintf("ipc://%s/ctl.sock", fx.dir)
}

ev_url :: proc(fx: ^Fixture) -> string {
	return fmt.tprintf("ipc://%s/ev.sock", fx.dir)
}

// The fake loop: wait on the wake fd, drain requests and notices.
loop_main :: proc(t: ^thread.Thread) {
	fx := (^Fixture)(t.data)
	for !sync.atomic_load(&fx.stop) {
		h := fx.host
		if h == nil {
			return
		}
		pfd := posix.pollfd {
			fd     = posix.FD(host_wake_fd(h)),
			events = {.IN},
		}
		if sync.atomic_load(&fx.hold) {
			sync.atomic_store(&fx.held, true)
			time.sleep(5 * time.Millisecond)
			continue
		}
		sync.atomic_store(&fx.held, false)
		posix.poll(&pfd, 1, 20)
		for {
			req, ok := next_request(h)
			if !ok {
				break
			}
			fx.handler(fx, req)
			if fx.host == nil {
				return // the handler closed the bus
			}
		}
		for {
			n, ok := next_notice(h)
			if !ok {
				break
			}
			sync.mutex_lock(&fx.mu)
			append(&fx.notices, n)
			sync.mutex_unlock(&fx.mu)
		}
		if sync.atomic_load(&fx.release) && len(fx.deferred) > 0 {
			for r in fx.deferred {
				reply_ok(h, r, transmute([]byte)string(`{"decided":true}`))
			}
			clear(&fx.deferred)
		}
	}
}

default_handler :: proc(fx: ^Fixture, req: ^Request) {
	h := fx.host
	intrinsics.atomic_add(&fx.handled, 1)
	switch req.op {
	case "status":
		reply_ok(h, req, transmute([]byte)string(`{"state":"up"}`))
	case "peers.list":
		// Tell the caller who we think they are.
		w: Writer
		writer_init(&w)
		defer writer_destroy(&w)
		begin_obj(&w)
		kv_u64(&w, "uid", u64(req.creds.uid))
		kv_u64(&w, "gid", u64(req.creds.gid))
		kv_bool(&w, "admin", .Admin in req.roles)
		end(&w)
		reply_ok(h, req, writer_bytes(&w))
	case "peer.kick":
		intrinsics.atomic_add(&fx.kicks, 1)
		session, e := arg_str(req, "session")
		if e != .None {
			reply_bad_arg(h, req, "session", e)
		} else if session == "missing" {
			reply_error(h, req, .Not_Found, "no such session")
		} else {
			reply_ok(h, req, transmute([]byte)string(`{"kicked":true}`))
		}
	case "auth.decide":
		append(&fx.deferred, req)
	case "daemon.shutdown":
		reply_ok(h, req)
		host_close(h)
		fx.host = nil
		sync.atomic_store(&fx.closed_here, true)
	case "connect":
		reply_ok(h, req)
	case "profile.set", "profile.check":
		profile_handler(h, req)
	case:
		reply_error(h, req, .Internal, "test handler has nothing for this op")
	}
}

// `profile.set` and `profile.check` with a "text" and a "label". The label
// picks the reply.
profile_handler :: proc(h: ^Host, req: ^Request) {
	text, _ := arg_str(req, "text")
	label, _ := arg_str(req, "label")
	switch label {
	case "bad":
		details := `[{"line":3,"option":"ca","class":"path","reason":"a file"},{"line":9,"option":"up","class":"not_supported","reason":"scripts"}]`
		reply_error_details(h, req, .Bad_Request, "the profile has problems", transmute([]byte)details)
	case "plain":
		reply_error(h, req, .Conflict, "no details")
	case "notarray":
		reply_error_details(h, req, .Bad_Request, "x", transmute([]byte)string(`{"a":1}`))
	case "wipe":
		n := len(text)
		args_wipe(req)
		zero := n > 0
		for b in transmute([]byte)text {
			zero &&= b == 0
		}
		w: Writer
		writer_init(&w)
		defer writer_destroy(&w)
		begin_obj(&w)
		kv_bool(&w, "wiped", zero)
		end(&w)
		reply_ok(h, req, writer_bytes(&w))
	case:
		w: Writer
		writer_init(&w)
		defer writer_destroy(&w)
		begin_obj(&w)
		kv_int(&w, "len", i64(len(text)))
		end(&w)
		reply_ok(h, req, writer_bytes(&w))
	}
}

// A request from a helper thread.
Caller :: struct {
	url:       string,
	op:        string,
	args:      string,
	id:        string,
	timeout:   time.Duration,
	allocator: runtime.Allocator,
	reply:     Reply,
	err:       Call_Error,
	done:      bool,
	thread:    ^thread.Thread,
}

caller_main :: proc(t: ^thread.Thread) {
	c := (^Caller)(t.data)
	context.allocator = c.allocator
	c.reply, c.err = call(c.url, c.op, transmute([]byte)c.args, c.timeout if c.timeout > 0 else 10 * time.Second, c.id, c.allocator)
	sync.atomic_store(&c.done, true)
}

caller_start :: proc(url, op: string, args := "", id := "", timeout: time.Duration = 0) -> ^Caller {
	c := new(Caller)
	c.url = url
	c.op = op
	c.args = args
	c.id = id
	c.timeout = timeout
	c.allocator = context.allocator
	c.thread = thread.create(caller_main)
	c.thread.data = c
	thread.start(c.thread)
	return c
}

// Wait for the thread and take the result. Free the reply yourself.
caller_finish :: proc(c: ^Caller) -> (Reply, Call_Error) {
	thread.join(c.thread)
	thread.destroy(c.thread)
	r, e := c.reply, c.err
	free(c)
	return r, e
}

// Poll until `cond` holds or the time is up.
wait_until :: proc(limit: time.Duration, ctx: rawptr, cond: proc(ctx: rawptr) -> bool) -> bool {
	start := time.now()
	for time.since(start) < limit {
		if cond(ctx) {
			return true
		}
		time.sleep(2 * time.Millisecond)
	}
	return cond(ctx)
}

// The result value of an ok reply as an object.
result_obj :: proc(r: ^Reply) -> json.Object {
	obj, _ := r.result.(json.Object)
	return obj
}

expect_error :: proc(t: ^testing.T, r: ^Reply, err: Call_Error, code: string, loc := #caller_location) {
	testing.expect_value(t, err, Call_Error.None, loc)
	testing.expectf(t, !r.ok, "expected an error reply, got ok", loc = loc)
	testing.expect_value(t, r.code, code, loc)
}

// ---- requests ----

@(test)
request_round_trip :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "rt")
	defer fixture_close(fx)

	r, err := call(ctl_url(fx), "status")
	defer reply_destroy(&r)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	testing.expect_value(t, len(r.id), 32)
	obj := result_obj(&r)
	state, _ := obj["state"].(json.String)
	testing.expect_value(t, state, "up")

	// Arguments reach the handler; errors come back with a code.
	r2, err2 := call(ctl_url(fx), "peer.kick", transmute([]byte)string(`{"session":"s-1"}`))
	defer reply_destroy(&r2)
	testing.expect_value(t, err2, Call_Error.None)
	testing.expect(t, r2.ok)

	r3, err3 := call(ctl_url(fx), "peer.kick", transmute([]byte)string(`{"session":"missing"}`))
	defer reply_destroy(&r3)
	expect_error(t, &r3, err3, "not_found")
	testing.expect_value(t, r3.message, "no such session")

	r4, err4 := call(ctl_url(fx), "peer.kick", transmute([]byte)string(`{"session":5}`))
	defer reply_destroy(&r4)
	expect_error(t, &r4, err4, "bad_request")
	testing.expect(t, strings.contains(r4.message, "session"))

	r5, err5 := call(ctl_url(fx), "peer.kick")
	defer reply_destroy(&r5)
	expect_error(t, &r5, err5, "bad_request")

	// The loop saw the sender's real identity.
	r6, err6 := call(ctl_url(fx), "peers.list")
	defer reply_destroy(&r6)
	testing.expect_value(t, err6, Call_Error.None)
	obj6 := result_obj(&r6)
	uid, _ := obj6["uid"].(json.Integer)
	testing.expect_value(t, u32(uid), euid())
	admin, _ := obj6["admin"].(json.Boolean)
	testing.expect(t, admin)

	st := host_stats(fx.host)
	testing.expect_value(t, st.requests, 6)
	testing.expect_value(t, st.replied_ok, 3)
	testing.expect_value(t, st.replied_error, 3)
}

@(test)
connection_can_be_reused :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "reuse")
	defer fixture_close(fx)

	c, err := connect(ctl_url(fx))
	testing.expect_value(t, err, Call_Error.None)
	defer disconnect(&c)
	// The timer resend is switched off (-1 is accepted by nng).
	testing.expect_value(t, nng.set_req_resend_time(c.sock, -1), nng.Error.None)
	for _ in 0 ..< 5 {
		r, e := conn_call(&c, "status")
		testing.expect_value(t, e, Call_Error.None)
		testing.expect(t, r.ok)
		reply_destroy(&r)
	}
}

@(test)
reply_can_come_later :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "defer")
	defer fixture_close(fx)

	slow := caller_start(ctl_url(fx), "auth.decide", `{"session":"s-1","decision":"allow"}`)
	// A deferred request does not stop other requests.
	r, err := call(ctl_url(fx), "status")
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	reply_destroy(&r)

	time.sleep(150 * time.Millisecond)
	testing.expect(t, !sync.atomic_load(&slow.done), "reply came before the loop responded")

	sync.atomic_store(&fx.release, true)
	sr, serr := caller_finish(slow)
	defer reply_destroy(&sr)
	testing.expect_value(t, serr, Call_Error.None)
	testing.expect(t, sr.ok)
	decided, _ := result_obj(&sr)["decided"].(json.Boolean)
	testing.expect(t, decided)
}

@(test)
busy_when_queue_is_full :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "busy", {workers = 4, max_pending = 2})
	defer fixture_close(fx)
	fixture_hold(t, fx)

	a := caller_start(ctl_url(fx), "status")
	b := caller_start(ctl_url(fx), "status")
	full := wait_until(10 * time.Second, fx, proc(p: rawptr) -> bool {
		fx := (^Fixture)(p)
		sync.mutex_lock(&fx.host.mu)
		defer sync.mutex_unlock(&fx.host.mu)
		return fx.host.pending == 2
	})
	testing.expect(t, full, "two requests never queued")

	// The third one is turned away at once, without the loop's help.
	start := time.now()
	r, err := call(ctl_url(fx), "status")
	defer reply_destroy(&r)
	expect_error(t, &r, err, "busy")
	testing.expect(t, time.since(start) < 2 * time.Second)
	testing.expect_value(t, host_stats(fx.host).busy, 1)

	// The queued two are still served when the loop wakes up.
	sync.atomic_store(&fx.hold, false)
	ra, ea := caller_finish(a)
	rb, eb := caller_finish(b)
	defer reply_destroy(&ra)
	defer reply_destroy(&rb)
	testing.expect_value(t, ea, Call_Error.None)
	testing.expect_value(t, eb, Call_Error.None)
	testing.expect(t, ra.ok && rb.ok)

	// And the daemon takes new requests again.
	r2, err2 := call(ctl_url(fx), "status")
	defer reply_destroy(&r2)
	testing.expect_value(t, err2, Call_Error.None)
	testing.expect(t, r2.ok)

	// The busy refusal was reported for logging.
	sync.mutex_lock(&fx.mu)
	defer sync.mutex_unlock(&fx.mu)
	found := false
	for &n in fx.notices {
		if n.kind == .Busy {
			found = true
		}
	}
	testing.expect(t, found, "no busy notice")
}

@(test)
wake_fd_is_readable_only_while_work_waits :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "wake", {no_loop = true})
	defer fixture_close(fx)
	h := fx.host

	readable :: proc(h: ^Host, ms: i32) -> bool {
		pfd := posix.pollfd {
			fd     = posix.FD(host_wake_fd(h)),
			events = {.IN},
		}
		return posix.poll(&pfd, 1, ms) == 1
	}
	testing.expect(t, !readable(h, 0))

	c := caller_start(ctl_url(fx), "status")
	testing.expect(t, readable(h, 5000), "wake fd never became readable")
	req, ok := next_request(h)
	testing.expect(t, ok)
	testing.expect_value(t, req.op, "status")
	testing.expect_value(t, req.info.name, "status")
	// Drained: quiet again, and the next call finds nothing.
	_, again := next_request(h)
	testing.expect(t, !again)
	testing.expect(t, !readable(h, 0))
	testing.expect(t, reply_ok(h, req))
	r, err := caller_finish(c)
	defer reply_destroy(&r)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
}

@(test)
notice_wakes_the_loop :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Uid, id = 424242, roles = {.Admin}}}
	fx := fixture_open(t, "wake-notice", {allow = allow, no_loop = true})
	defer fixture_close(fx)
	h := fx.host

	r, err := call(ctl_url(fx), "status")
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, !r.ok)
	reply_destroy(&r)

	pfd := posix.pollfd {
		fd     = posix.FD(host_wake_fd(h)),
		events = {.IN},
	}
	testing.expect_value(t, posix.poll(&pfd, 1, 1000), 1)
	_, has_req := next_request(h)
	testing.expect(t, !has_req)
	// A request lookup alone does not quiet it while a notice waits.
	testing.expect_value(t, posix.poll(&pfd, 1, 0), 1)
	n, ok := next_notice(h)
	testing.expect(t, ok)
	testing.expect_value(t, n.kind, Notice_Kind.Denied)
	_, more := next_notice(h)
	testing.expect(t, !more)
	testing.expect_value(t, posix.poll(&pfd, 1, 0), 0)
}

// ---- authorisation ----

@(test)
denied_when_policy_excludes_us :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Uid, id = 424242, roles = {.Admin}}}
	fx := fixture_open(t, "deny", {allow = allow})
	defer fixture_close(fx)

	r, err := call(ctl_url(fx), "status", id = "my-id")
	defer reply_destroy(&r)
	expect_error(t, &r, err, "denied")
	// A client with no role at all is not even parsed: no id is echoed.
	testing.expect_value(t, r.id, "")

	r2, err2 := call(ctl_url(fx), "daemon.shutdown")
	defer reply_destroy(&r2)
	expect_error(t, &r2, err2, "denied")

	// The handler never ran, and the denial was reported.
	time.sleep(50 * time.Millisecond)
	testing.expect_value(t, sync.atomic_load(&fx.handled), 0)
	testing.expect_value(t, host_stats(fx.host).denied, 2)
	ok := wait_until(5 * time.Second, fx, proc(p: rawptr) -> bool {
		fx := (^Fixture)(p)
		sync.mutex_lock(&fx.mu)
		defer sync.mutex_unlock(&fx.mu)
		return len(fx.notices) == 2
	})
	testing.expect(t, ok, "notices missing")
	sync.mutex_lock(&fx.mu)
	defer sync.mutex_unlock(&fx.mu)
	if len(fx.notices) > 0 {
		n := &fx.notices[0]
		testing.expect_value(t, n.kind, Notice_Kind.Denied)
		testing.expect(t, n.has_creds)
		testing.expect_value(t, n.uid, euid())
		testing.expect(t, len(notice_text(n)) > 0)
	}
}

@(test)
roles_limit_operations :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	// Read only.
	read_only := []config.Bus_Allow{{kind = .Uid, id = euid(), roles = {.Read}}}
	fx := fixture_open(t, "role-read", {allow = read_only})
	defer fixture_close(fx)

	r, err := call(ctl_url(fx), "status")
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	reply_destroy(&r)

	r2, err2 := call(ctl_url(fx), "peer.kick", transmute([]byte)string(`{"session":"s"}`), id = "k-1")
	defer reply_destroy(&r2)
	expect_error(t, &r2, err2, "denied")
	// A client with a role gets its id back.
	testing.expect_value(t, r2.id, "k-1")
	testing.expect(t, strings.contains(r2.message, "operator"))
	testing.expect_value(t, sync.atomic_load(&fx.kicks), 0)
}

@(test)
operator_is_not_auth :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Uid, id = euid(), roles = {.Operator}}}
	fx := fixture_open(t, "role-op", {allow = allow})
	defer fixture_close(fx)

	// Operator implies read.
	r, err := call(ctl_url(fx), "status")
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	reply_destroy(&r)
	r1, err1 := call(ctl_url(fx), "peer.kick", transmute([]byte)string(`{"session":"s"}`))
	testing.expect_value(t, err1, Call_Error.None)
	testing.expect(t, r1.ok)
	reply_destroy(&r1)

	r2, err2 := call(ctl_url(fx), "auth.decide", transmute([]byte)string(`{"session":"s","decision":"allow"}`))
	defer reply_destroy(&r2)
	expect_error(t, &r2, err2, "denied")
	r3, err3 := call(ctl_url(fx), "daemon.shutdown")
	defer reply_destroy(&r3)
	expect_error(t, &r3, err3, "denied")
}

@(test)
gid_rule_grants_roles :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Gid, id = u32(posix.getegid()), roles = {.Read}}}
	fx := fixture_open(t, "role-gid", {allow = allow})
	defer fixture_close(fx)
	r, err := call(ctl_url(fx), "status")
	defer reply_destroy(&r)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
}

// A gid that is not the gid of this process.
OTHER_GID :: 0x7fff_1234

@(test)
gid_rule_grants_roles_to_a_group_member :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Gid, id = OTHER_GID, roles = {.Operator}}}
	is_member :: proc(uid, gid: u32) -> bool {
		return uid == u32(posix.geteuid()) && gid == OTHER_GID
	}
	fx := fixture_open(t, "role-member", {allow = allow, member = is_member})
	defer fixture_close(fx)
	r, err := call(ctl_url(fx), "status")
	defer reply_destroy(&r)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	// The role of the rule, and no more.
	r2, err2 := call(ctl_url(fx), "daemon.shutdown")
	defer reply_destroy(&r2)
	expect_error(t, &r2, err2, "denied")
}

@(test)
gid_rule_gives_nothing_to_a_non_member :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Gid, id = OTHER_GID, roles = {.Operator}}}
	no_member :: proc(uid, gid: u32) -> bool {
		return false
	}
	fx := fixture_open(t, "role-nomember", {allow = allow, member = no_member})
	defer fixture_close(fx)
	r, err := call(ctl_url(fx), "status")
	defer reply_destroy(&r)
	expect_error(t, &r, err, "denied")
}

@(test)
default_member_reads_the_system_database :: proc(t: ^testing.T) {
	uid := u32(posix.geteuid())
	pw := posix.getpwuid(posix.uid_t(uid))
	if pw == nil {
		// No passwd entry for this user (a bare container): nothing to compare.
		testing.expect(t, !default_member(uid, 0))
		return
	}
	testing.expect(t, default_member(uid, u32(pw.pw_gid)))
	testing.expect(t, !default_member(uid, OTHER_GID))
	testing.expect(t, !default_member(0x7fff_4321, u32(pw.pw_gid)))
}

@(test)
ops_of_the_other_mode_are_unsupported :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	{
		fx := fixture_open(t, "mode-s", {mode = .Server})
		defer fixture_close(fx)
		r, err := call(ctl_url(fx), "connect")
		defer reply_destroy(&r)
		expect_error(t, &r, err, "unsupported")
		testing.expect_value(t, sync.atomic_load(&fx.handled), 0)
		r2, err2 := call(ctl_url(fx), "status")
		defer reply_destroy(&r2)
		testing.expect(t, err2 == .None && r2.ok)
	}
	{
		fx := fixture_open(t, "mode-c", {mode = .Client})
		defer fixture_close(fx)
		r, err := call(ctl_url(fx), "peer.kick", transmute([]byte)string(`{"session":"s"}`))
		defer reply_destroy(&r)
		expect_error(t, &r, err, "unsupported")
		r2, err2 := call(ctl_url(fx), "connect")
		defer reply_destroy(&r2)
		testing.expect(t, err2 == .None && r2.ok)
		testing.expect_value(t, sync.atomic_load(&fx.handled), 1)
	}
}

// ---- bad input ----

// Send raw bytes and read the raw reply.
raw_call :: proc(t: ^testing.T, url: string, body: []byte) -> (reply: json.Value, ok: bool) {
	sock, err := nng.open(.Req)
	if err != .None {
		return nil, false
	}
	defer nng.close(sock)
	nng.set_send_timeout(sock, 5 * time.Second)
	nng.set_recv_timeout(sock, 5 * time.Second)
	nng.set_req_resend_time(sock, -1)
	if nng.dial(sock, strings.clone_to_cstring(url, context.temp_allocator)) != .None {
		return nil, false
	}
	data, cerr := nng.call(sock, body)
	if cerr != .None {
		return nil, false
	}
	defer delete(data)
	v, perr := json.parse(data, .JSON, true)
	return v, perr == nil
}

@(test)
malformed_requests_get_errors :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "bad")
	defer fixture_close(fx)

	Case :: struct {
		name, body, code, id: string,
	}
	cases := []Case {
		{"garbage", `not json at all`, "bad_request", ""},
		{"array", `[]`, "bad_request", ""},
		{"no op", `{"v":1,"id":"x1"}`, "bad_request", "x1"},
		{"wrong version", `{"v":2,"id":"x2","op":"status"}`, "bad_request", "x2"},
		{"args not object", `{"v":1,"id":"x3","op":"status","args":[1]}`, "bad_request", "x3"},
		{"bad id", `{"v":1,"id":"has space","op":"status"}`, "bad_request", ""},
		{"unknown op", `{"v":1,"id":"x4","op":"no.such.op"}`, "unknown_op", "x4"},
	}
	for c in cases {
		v, ok := raw_call(t, ctl_url(fx), transmute([]byte)c.body)
		defer json.destroy_value(v)
		testing.expectf(t, ok, "%s: no reply", c.name)
		obj, _ := v.(json.Object)
		okv, _ := obj["ok"].(json.Boolean)
		testing.expectf(t, !okv, "%s: ok reply", c.name)
		e, _ := obj["error"].(json.Object)
		code, _ := e["code"].(json.String)
		testing.expectf(t, code == c.code, "%s: code %q, want %q", c.name, code, c.code)
		msg, _ := e["message"].(json.String)
		testing.expectf(t, len(msg) > 0, "%s: empty message", c.name)
		if c.id == "" {
			_, is_null := obj["id"].(json.Null)
			testing.expectf(t, is_null, "%s: id should be null", c.name)
		} else {
			id, _ := obj["id"].(json.String)
			testing.expectf(t, id == c.id, "%s: id %q", c.name, id)
		}
	}
	testing.expect_value(t, sync.atomic_load(&fx.handled), 0)
	testing.expect_value(t, host_stats(fx.host).bad_requests, u64(len(cases)))
}

@(test)
size_limit :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "size")
	defer fixture_close(fx)

	// Just under the limit works.
	pad := strings.repeat("a", MAX_REQUEST_SIZE - 200, context.temp_allocator)
	args := fmt.tprintf(`{{"pad":"%s"}}`, pad)
	r, err := call(ctl_url(fx), "status", transmute([]byte)args)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	reply_destroy(&r)

	// Over the limit: a proper error.
	big := strings.repeat("a", MAX_REQUEST_SIZE + 100, context.temp_allocator)
	args = fmt.tprintf(`{{"pad":"%s"}}`, big)
	r2, err2 := call(ctl_url(fx), "status", transmute([]byte)args)
	defer reply_destroy(&r2)
	expect_error(t, &r2, err2, "bad_request")
	testing.expect(t, strings.contains(r2.message, "too large"))

	// Far over every limit: nng drops the connection, no reply, no harm done.
	huge := strings.repeat("a", 3 * MAX_PROFILE_REQUEST_SIZE, context.temp_allocator)
	args = fmt.tprintf(`{{"pad":"%s"}}`, huge)
	r3, err3 := call(ctl_url(fx), "status", transmute([]byte)args, 700 * time.Millisecond)
	testing.expect(t, err3 != .None, "no reply expected")
	if err3 == .None {
		reply_destroy(&r3)
	}

	// The daemon still works.
	r4, err4 := call(ctl_url(fx), "status")
	defer reply_destroy(&r4)
	testing.expect_value(t, err4, Call_Error.None)
	testing.expect(t, r4.ok)
	testing.expect_value(t, sync.atomic_load(&fx.handled), 2)
}

// A request of the given size for `op` with a "text" argument of `n` bytes.
profile_args :: proc(n: int, label := "") -> []byte {
	text := strings.repeat("a", n, context.temp_allocator)
	return transmute([]byte)fmt.tprintf(`{{"text":"%s","label":"%s"}}`, text, label)
}

@(test)
profile_request_size :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "psize", {mode = .Client})
	defer fixture_close(fx)

	// A profile of 250 kB passes end to end, for both operations.
	for op in ([?]string{"profile.set", "profile.check"}) {
		r, err := call(ctl_url(fx), op, profile_args(250_000), 20 * time.Second)
		testing.expect_value(t, err, Call_Error.None)
		testing.expectf(t, r.ok, "%s: %s %s", op, r.code, r.message)
		if obj, is_obj := r.result.(json.Object); is_obj {
			n, _ := obj["len"].(json.Integer)
			testing.expect_value(t, n, 250_000)
		}
		reply_destroy(&r)
	}

	// Above 256 KiB the reply is an error that names the request.
	r2, err2 := call(ctl_url(fx), "profile.set", profile_args(MAX_PROFILE_REQUEST_SIZE), 20 * time.Second)
	defer reply_destroy(&r2)
	expect_error(t, &r2, err2, "bad_request")
	testing.expect(t, strings.contains(r2.message, "too large"))

	// Another operation keeps the limit of 64 KiB. The reply has the id.
	for n in ([?]int{70_000, 200_000}) {
		args := fmt.tprintf(`{{"pad":"%s"}}`, strings.repeat("a", n, context.temp_allocator))
		r3, err3 := call(ctl_url(fx), "status", transmute([]byte)args, 20 * time.Second, "size-id")
		testing.expect_value(t, err3, Call_Error.None)
		testing.expect(t, !r3.ok)
		testing.expect_value(t, r3.code, "bad_request")
		testing.expect(t, strings.contains(r3.message, "too large"))
		testing.expect_value(t, r3.id, "size-id")
		reply_destroy(&r3)
	}

	// Far over the limit of the profile operations: no reply.
	huge := profile_args(3 * MAX_PROFILE_REQUEST_SIZE)
	r4, err4 := call(ctl_url(fx), "profile.set", huge, 700 * time.Millisecond)
	testing.expect(t, err4 != .None, "no reply expected")
	if err4 == .None {
		reply_destroy(&r4)
	}

	// The daemon still works, and handled the two good requests only.
	r5, err5 := call(ctl_url(fx), "status")
	defer reply_destroy(&r5)
	testing.expect_value(t, err5, Call_Error.None)
	testing.expect(t, r5.ok)
	testing.expect_value(t, sync.atomic_load(&fx.handled), 3)
}

@(test)
profile_ops_need_the_operator_role :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Uid, id = u32(euid()), roles = {.Read}}}
	fx := fixture_open(t, "prole", {mode = .Client, allow = allow})
	defer fixture_close(fx)
	for op in ([?]string{"profile.set", "profile.check", "profile.clear"}) {
		r, err := call(ctl_url(fx), op, profile_args(10))
		expect_error(t, &r, err, "denied")
		reply_destroy(&r)
	}
	testing.expect_value(t, sync.atomic_load(&fx.handled), 0)
}

@(test)
profile_ops_are_for_a_client :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "psrv", {mode = .Server})
	defer fixture_close(fx)
	r, err := call(ctl_url(fx), "profile.check", profile_args(10))
	defer reply_destroy(&r)
	expect_error(t, &r, err, "unsupported")
	testing.expect_value(t, sync.atomic_load(&fx.handled), 0)
}

@(test)
error_details_round_trip :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "details", {mode = .Client})
	defer fixture_close(fx)

	r, err := call(ctl_url(fx), "profile.check", profile_args(5, "bad"))
	defer reply_destroy(&r)
	expect_error(t, &r, err, "bad_request")
	testing.expect_value(t, r.message, "the profile has problems")
	list, is_arr := r.details.(json.Array)
	testing.expect(t, is_arr)
	if is_arr && len(list) == 2 {
		first, _ := list[0].(json.Object)
		line, _ := first["line"].(json.Integer)
		testing.expect_value(t, line, 3)
		opt, _ := first["option"].(json.String)
		testing.expect_value(t, opt, "ca")
		class, _ := first["class"].(json.String)
		testing.expect_value(t, class, "path")
		reason, _ := first["reason"].(json.String)
		testing.expect(t, reason != "")
	} else {
		testing.expectf(t, false, "details: %v", r.details)
	}

	// An error without details has none, and nothing else changes.
	r2, err2 := call(ctl_url(fx), "profile.check", profile_args(5, "plain"))
	defer reply_destroy(&r2)
	expect_error(t, &r2, err2, "conflict")
	_, has := r2.details.(json.Array)
	testing.expect(t, !has)
	testing.expect_value(t, r2.message, "no details")

	// A value that is not an array is left out.
	r3, err3 := call(ctl_url(fx), "profile.check", profile_args(5, "notarray"))
	defer reply_destroy(&r3)
	expect_error(t, &r3, err3, "bad_request")
	testing.expect(t, r3.details == nil)
}

@(test)
secret_args_can_be_wiped :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "wipe", {mode = .Client})
	defer fixture_close(fx)
	r, err := call(ctl_url(fx), "profile.check", profile_args(100, "wipe"))
	defer reply_destroy(&r)
	testing.expect_value(t, err, Call_Error.None)
	testing.expectf(t, r.ok, "%s %s", r.code, r.message)
	obj, _ := r.result.(json.Object)
	wiped, _ := obj["wiped"].(json.Boolean)
	testing.expect(t, wiped)
}

@(test)
notice_queue_is_bounded :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	allow := []config.Bus_Allow{{kind = .Uid, id = 424242, roles = {.Admin}}}
	fx := fixture_open(t, "notices", {allow = allow, no_loop = true})
	defer fixture_close(fx)

	c, err := connect(ctl_url(fx))
	testing.expect_value(t, err, Call_Error.None)
	defer disconnect(&c)
	N :: NOTICE_QUEUE + 10
	for _ in 0 ..< N {
		r, e := conn_call(&c, "status")
		testing.expect_value(t, e, Call_Error.None)
		reply_destroy(&r)
	}
	st := host_stats(fx.host)
	testing.expect_value(t, st.denied, N)
	testing.expect_value(t, st.notices_dropped, 10)
	got := 0
	for {
		_, ok := next_notice(fx.host)
		if !ok {
			break
		}
		got += 1
	}
	testing.expect_value(t, got, NOTICE_QUEUE)
}

// ---- repeated request ids ----

@(test)
repeated_id_gets_cached_reply :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "dedupe")
	defer fixture_close(fx)

	args := transmute([]byte)string(`{"session":"s-1"}`)
	r1, e1 := call(ctl_url(fx), "peer.kick", args, id = "same-id")
	defer reply_destroy(&r1)
	testing.expect_value(t, e1, Call_Error.None)
	testing.expect(t, r1.ok)
	r2, e2 := call(ctl_url(fx), "peer.kick", args, id = "same-id")
	defer reply_destroy(&r2)
	testing.expect_value(t, e2, Call_Error.None)
	testing.expect(t, r2.ok)
	testing.expect_value(t, string(r2.raw), string(r1.raw))
	// The handler ran once.
	testing.expect_value(t, sync.atomic_load(&fx.kicks), 1)
	testing.expect_value(t, host_stats(fx.host).deduped, 1)

	// Errors are cached too: the second call does not run the handler either.
	miss := transmute([]byte)string(`{"session":"missing"}`)
	r3, e3 := call(ctl_url(fx), "peer.kick", miss, id = "err-id")
	defer reply_destroy(&r3)
	r4, e4 := call(ctl_url(fx), "peer.kick", miss, id = "err-id")
	defer reply_destroy(&r4)
	expect_error(t, &r3, e3, "not_found")
	expect_error(t, &r4, e4, "not_found")
	testing.expect_value(t, sync.atomic_load(&fx.kicks), 2)

	// The same id with another request is a conflict, and does not run.
	r5, e5 := call(ctl_url(fx), "peer.kick", transmute([]byte)string(`{"session":"s-2"}`), id = "same-id")
	defer reply_destroy(&r5)
	expect_error(t, &r5, e5, "conflict")
	testing.expect_value(t, sync.atomic_load(&fx.kicks), 2)

	// A new id runs again.
	r6, e6 := call(ctl_url(fx), "peer.kick", args, id = "other-id")
	defer reply_destroy(&r6)
	testing.expect(t, e6 == .None && r6.ok)
	testing.expect_value(t, sync.atomic_load(&fx.kicks), 3)

	// Read-only operations are not cached: they always run.
	for _ in 0 ..< 3 {
		r, e := call(ctl_url(fx), "status", id = "status-id")
		testing.expect(t, e == .None && r.ok)
		reply_destroy(&r)
	}
	testing.expect_value(t, sync.atomic_load(&fx.handled), 3 + 3)
}

@(test)
repeat_while_first_is_running_waits_for_it :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "dedupe-wait", {workers = 4})
	defer fixture_close(fx)

	args := `{"session":"s-1","decision":"allow"}`
	a := caller_start(ctl_url(fx), "auth.decide", args, "dup-1")
	// Let the first reach the loop, then send the same request again.
	ok := wait_until(10 * time.Second, fx, proc(p: rawptr) -> bool {
		fx := (^Fixture)(p)
		sync.mutex_lock(&fx.host.mu)
		defer sync.mutex_unlock(&fx.host.mu)
		return fx.host.pending == 1
	})
	testing.expect(t, ok)
	b := caller_start(ctl_url(fx), "auth.decide", args, "dup-1")
	time.sleep(100 * time.Millisecond)
	// The repeat did not create a second request for the loop.
	sync.mutex_lock(&fx.host.mu)
	testing.expect_value(t, fx.host.pending, 1)
	sync.mutex_unlock(&fx.host.mu)

	sync.atomic_store(&fx.release, true)
	ra, ea := caller_finish(a)
	rb, eb := caller_finish(b)
	defer reply_destroy(&ra)
	defer reply_destroy(&rb)
	testing.expect_value(t, ea, Call_Error.None)
	testing.expect_value(t, eb, Call_Error.None)
	testing.expect(t, ra.ok && rb.ok)
	testing.expect_value(t, string(ra.raw), string(rb.raw))
	testing.expect_value(t, sync.atomic_load(&fx.handled), 1)
}

@(test)
reply_timeout_then_retry_runs_again :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	// The default handler never replies to auth.decide until released.
	fx := fixture_open(t, "timeout", {reply_timeout = 300 * time.Millisecond})
	defer fixture_close(fx)

	r, err := call(ctl_url(fx), "auth.decide", transmute([]byte)string(`{"session":"s"}`), id = "t-1")
	defer reply_destroy(&r)
	expect_error(t, &r, err, "timeout")
	testing.expect_value(t, host_stats(fx.host).reply_timeouts, 1)

	// The loop replies late: nobody listens, and nothing breaks.
	sync.atomic_store(&fx.release, true)
	time.sleep(100 * time.Millisecond)

	// A timeout leaves no cached reply: the same id goes to the loop again.
	sync.atomic_store(&fx.release, false)
	c := caller_start(ctl_url(fx), "auth.decide", `{"session":"s"}`, "t-1")
	ok := wait_until(10 * time.Second, fx, proc(p: rawptr) -> bool {
		fx := (^Fixture)(p)
		return sync.atomic_load(&fx.handled) == 2
	})
	testing.expect(t, ok, "retry did not reach the loop")
	sync.atomic_store(&fx.release, true)
	r2, e2 := caller_finish(c)
	defer reply_destroy(&r2)
	testing.expect(t, e2 == .None && r2.ok)
}

// ---- events ----

free_events :: proc(evs: ^[dynamic]Event) {
	for &e in evs {
		event_destroy(&e)
	}
	delete(evs^)
}

@(test)
events_carry_sequence_and_envelope :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "ev", {no_loop = true})
	defer fixture_close(fx)

	sub, err := subscribe(ev_url(fx), {"peer."})
	testing.expect_value(t, err, Call_Error.None)
	defer unsubscribe(&sub)

	// A probe from another topic does not match the prefix, so probe with a
	// matching topic.
	start := time.now()
	synced := false
	for time.since(start) < 10 * time.Second {
		publish(fx.host, "peer.probe")
		e, serr := next_event(&sub, 20 * time.Millisecond)
		if serr == .None {
			synced = true
			testing.expect(t, e.first)
			testing.expect_value(t, e.gap, 0)
			event_destroy(&e)
			break
		}
	}
	testing.expect(t, synced, "subscriber never got a probe")
	if !synced {
		return
	}
	// Drain probes still in flight.
	for {
		e, serr := next_event(&sub, 100 * time.Millisecond)
		if serr != .None {
			break
		}
		event_destroy(&e)
	}

	run, seq0 := host_position(fx.host)
	testing.expect_value(t, len(run), RUN_ID_LEN)

	// Filtered topics do not arrive.
	publish(fx.host, "stats.tick", transmute([]byte)string(`{"n":1}`))
	N :: 20
	for i in 0 ..< N {
		d := fmt.tprintf(`{{"session":"s-%d","name":"alice \"x\""}}`, i)
		publish(fx.host, "peer.connect", transmute([]byte)d)
	}
	evs: [dynamic]Event
	defer free_events(&evs)
	for len(evs) < N {
		e, serr := next_event(&sub, 5 * time.Second)
		if serr != .None {
			break
		}
		append(&evs, e)
	}
	testing.expect_value(t, len(evs), N)
	prev := seq0 + 1 // stats.tick used seq0 + 1
	for &e, i in evs {
		testing.expect_value(t, e.topic, "peer.connect")
		testing.expect_value(t, e.run, run)
		testing.expect_value(t, e.seq, prev + 1)
		testing.expect_value(t, e.gap, 0)
		testing.expect(t, !e.restarted && !e.first)
		prev = e.seq
		obj, _ := e.data.(json.Object)
		session, _ := obj["session"].(json.String)
		testing.expect_value(t, session, fmt.tprintf("s-%d", i))
		name, _ := obj["name"].(json.String)
		testing.expect_value(t, name, `alice "x"`)
		// The timestamp is RFC 3339 UTC with milliseconds.
		testing.expect_value(t, len(e.ts), 24)
		testing.expect(t, strings.has_suffix(e.ts, "Z") && e.ts[10] == 'T' && e.ts[19] == '.')
	}
	// The raw envelope is kept for tools that pass it on.
	if len(evs) > 0 {
		testing.expect(t, strings.has_prefix(string(evs[0].raw), `{"v":1,"run":"`))
	}
	st := host_stats(fx.host)
	testing.expect(t, st.published >= N + 1)
	testing.expect_value(t, st.publish_errors, 0)
}

@(test)
slow_subscriber_sees_gaps :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "gap", {no_loop = true})
	defer fixture_close(fx)

	sub, err := subscribe(ev_url(fx), {"stats."})
	testing.expect_value(t, err, Call_Error.None)
	defer unsubscribe(&sub)
	e0, synced := await_subscriber_topic(fx.host, &sub, "stats.probe")
	testing.expect(t, synced)
	if !synced {
		return
	}
	event_destroy(&e0)
	for { // drain probes
		e, serr := next_event(&sub, 100 * time.Millisecond)
		if serr != .None {
			break
		}
		event_destroy(&e)
	}

	// A burst while the subscriber reads nothing.
	N :: 3000
	pad := strings.repeat("x", 1000, context.temp_allocator)
	_, seq_before := host_position(fx.host)
	for i in 0 ..< N {
		d := fmt.tprintf(`{{"i":%d,"pad":"%s"}}`, i, pad)
		publish(fx.host, "stats.tick", transmute([]byte)d)
	}
	_, seq_after := host_position(fx.host)
	testing.expect_value(t, seq_after - seq_before, N)
	// publish never blocked and never failed locally.
	testing.expect_value(t, host_stats(fx.host).publish_errors, 0)

	// Read what is left. Every missing sequence number must show up as a gap
	// (after the first event we read).
	count: u64
	gaps: u64
	first_seq, last_seq: u64
	have_first := false
	for {
		e, serr := next_event(&sub, 300 * time.Millisecond)
		if serr != .None {
			break
		}
		if !have_first {
			first_seq = e.seq
			have_first = true
		} else {
			gaps += e.gap
		}
		last_seq = e.seq
		count += 1
		event_destroy(&e)
	}
	testing.expect(t, count > 0)
	testing.expect(t, count < N, "nothing was dropped?")
	// received + gaps covers the whole range from the first to the last event.
	testing.expect_value(t, count + gaps, last_seq - first_seq + 1)
	testing.expect(t, gaps > 0 || first_seq > seq_before + 1, "no drop was visible")
}

await_subscriber_topic :: proc(h: ^Host, s: ^Subscriber, topic: string) -> (ev: Event, ok: bool) {
	start := time.now()
	for time.since(start) < 10 * time.Second {
		publish(h, topic)
		e, err := next_event(s, 20 * time.Millisecond)
		if err == .None {
			return e, true
		}
	}
	return {}, false
}

@(test)
daemon_restart_shows_as_new_run :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "restart", {no_loop = true})
	defer fixture_close(fx)

	// wait = true: the subscriber reconnects by itself.
	sub, err := subscribe(ev_url(fx), {"daemon."}, wait = true)
	testing.expect_value(t, err, Call_Error.None)
	defer unsubscribe(&sub)
	e0, synced := await_subscriber_topic(fx.host, &sub, "daemon.probe")
	testing.expect(t, synced)
	if !synced {
		return
	}
	run1 := strings.clone(e0.run)
	defer delete(run1)
	event_destroy(&e0)

	// Stop the daemon and start a new one on the same path.
	opts := Host_Options {
		events    = Endpoint{path = fmt.tprintf("%s/ev.sock", fx.dir)},
		allocator = context.allocator,
	}
	host_close(fx.host)
	fx.host = nil
	h2, oerr, _ := host_open(opts)
	testing.expect_value(t, oerr, Open_Error.None)
	if oerr != .None {
		return
	}
	fx.host = h2

	// The first event of the new run is flagged.
	start := time.now()
	found := false
	for time.since(start) < 15 * time.Second && !found {
		publish(h2, "daemon.start")
		for {
			e, serr := next_event(&sub, 50 * time.Millisecond)
			if serr != .None {
				break
			}
			if e.run != run1 {
				testing.expect(t, e.restarted)
				testing.expect_value(t, e.gap, 0)
				found = true
			}
			event_destroy(&e)
		}
	}
	testing.expect(t, found, "no event from the new run")
}

@(test)
two_daemons_cannot_share_a_name :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "inuse", {no_loop = true})
	defer fixture_close(fx)
	opts := Host_Options {
		events    = Endpoint{path = fmt.tprintf("%s/ev.sock", fx.dir)},
		allocator = context.allocator,
	}
	h, err, _ := host_open(opts)
	testing.expect_value(t, err, Open_Error.Events_In_Use)
	testing.expect(t, h == nil)
	opts = Host_Options {
		control   = Endpoint{path = fmt.tprintf("%s/ctl.sock", fx.dir)},
		allocator = context.allocator,
	}
	h, err, _ = host_open(opts)
	testing.expect_value(t, err, Open_Error.Control_In_Use)
	testing.expect(t, h == nil)
	// The first daemon is unharmed.
	r, cerr := call(ctl_url(fx), "status")
	_ = cerr
	reply_destroy(&r)
}

@(test)
disabled_sockets :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	h, err, _ := host_open(Host_Options{allocator = context.allocator})
	testing.expect_value(t, err, Open_Error.None)
	defer host_close(h)
	testing.expect(t, !publish(h, "daemon.start"))
	_, again := next_request(h)
	testing.expect(t, !again)
	testing.expect(t, host_wake_fd(h) >= 0)
}

@(test)
publish_rejects_bad_topics :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "topic", {no_loop = true})
	defer fixture_close(fx)
	testing.expect(t, !publish(fx.host, "has space"))
	testing.expect(t, !publish(fx.host, ""))
	testing.expect(t, !publish(fx.host, "Upper"))
	testing.expect_value(t, host_stats(fx.host).publish_errors, 3)
	// A rejected event does not use a sequence number.
	_, seq := host_position(fx.host)
	testing.expect_value(t, seq, 0)
	// An event that is too big is refused too. It does use a sequence number,
	// so subscribers see a gap.
	big := strings.repeat("a", MAX_EVENT_SIZE, context.temp_allocator)
	body := fmt.tprintf(`{{"pad":"%s"}}`, big)
	testing.expect(t, !publish(fx.host, "big.event", transmute([]byte)body))
	testing.expect_value(t, host_stats(fx.host).publish_errors, 4)
	_, seq = host_position(fx.host)
	testing.expect_value(t, seq, 1)
	testing.expect(t, publish(fx.host, "ok.topic"))
	_, seq = host_position(fx.host)
	testing.expect_value(t, seq, 2)
}

// ---- files and directories ----

touch :: proc(path: string) {
	err := os.write_entire_file(path, []byte{'x'})
	_ = err
}

file_mode :: proc(path: string) -> (mode: u32, ok: bool) {
	st: posix.stat_t
	if posix.stat(strings.clone_to_cstring(path, context.temp_allocator), &st) != .OK {
		return 0, false
	}
	return mode_to_u32(st.st_mode) & 0o7777, true
}

@(test)
socket_files_get_the_requested_mode :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "mode", {no_loop = true, events_mode = 0o640, control_mode = 0o600})
	defer fixture_close(fx)
	m, ok := file_mode(fmt.tprintf("%s/ev.sock", fx.dir))
	testing.expect(t, ok)
	testing.expect_value(t, m, 0o640)
	m, ok = file_mode(fmt.tprintf("%s/ctl.sock", fx.dir))
	testing.expect(t, ok)
	testing.expect_value(t, m, 0o600)
}

@(test)
default_socket_mode_is_explicit :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	// Whatever the umask is.
	// The umask is for the whole process; keep the window short.
	old := posix.umask({.IWGRP, .IWOTH}) // a common 022
	defer posix.umask(old)
	fx := fixture_open(t, "defmode", {no_loop = true})
	defer fixture_close(fx)
	m, ok := file_mode(fmt.tprintf("%s/ctl.sock", fx.dir))
	testing.expect(t, ok)
	testing.expect_value(t, m, DEFAULT_SOCKET_MODE)
}

// `--allow-user`: the socket belongs to the user with mode 0600, and the
// folder gets mode 0755, also when it exists.
@(test)
socket_owner_opens_the_folder :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "owner")
	defer remove_test_dir(dir)
	me := fmt.tprintf("%d", posix.geteuid())
	sub := fmt.tprintf("%s/new", dir)
	opts := Host_Options {
		control   = Endpoint{path = fmt.tprintf("%s/c.sock", sub), owner = me, mode = 0o600},
		allocator = context.allocator,
	}
	h, err, _ := host_open(opts)
	testing.expect_value(t, err, Open_Error.None)
	if h != nil {
		st: posix.stat_t
		posix.stat(strings.clone_to_cstring(fmt.tprintf("%s/c.sock", sub), context.temp_allocator), &st)
		testing.expect_value(t, u32(st.st_uid), u32(posix.geteuid()))
		testing.expect_value(t, mode_to_u32(st.st_mode) & 0o777, 0o600)
		posix.stat(strings.clone_to_cstring(sub, context.temp_allocator), &st)
		testing.expect_value(t, mode_to_u32(st.st_mode) & 0o777, 0o755)
		host_close(h)
	}
	// The test folder exists with mode 0700.
	opts.control = Endpoint{path = fmt.tprintf("%s/d.sock", dir), owner = me, mode = 0o600}
	testing.expect_value(t, prepare_dirs(opts), Open_Error.None)
	st: posix.stat_t
	posix.stat(strings.clone_to_cstring(dir, context.temp_allocator), &st)
	testing.expect_value(t, mode_to_u32(st.st_mode) & 0o777, 0o755)

	opts.control = Endpoint{path = fmt.tprintf("%s/e.sock", dir), owner = "no-such-user-xyz"}
	h, err, _ = host_open(opts)
	testing.expect_value(t, err, Open_Error.Bad_Owner)
	testing.expect(t, h == nil)
}

@(test)
socket_group_is_applied :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "group")
	defer remove_test_dir(dir)
	gid := fmt.tprintf("%d", posix.getegid())
	h, err, _ := host_open(
		Host_Options {
			control = Endpoint{path = fmt.tprintf("%s/c.sock", dir), group = gid},
			allocator = context.allocator,
		},
	)
	testing.expect_value(t, err, Open_Error.None)
	if h != nil {
		st: posix.stat_t
		posix.stat(strings.clone_to_cstring(fmt.tprintf("%s/c.sock", dir), context.temp_allocator), &st)
		testing.expect_value(t, u32(st.st_gid), u32(posix.getegid()))
		host_close(h)
	}

	h, err, _ = host_open(
		Host_Options {
			control = Endpoint{path = fmt.tprintf("%s/d.sock", dir), group = "no-such-group-xyz"},
			allocator = context.allocator,
		},
	)
	testing.expect_value(t, err, Open_Error.Bad_Group)
	testing.expect(t, h == nil)
	// The failed open left no socket file behind.
	testing.expect(t, !os.exists(fmt.tprintf("%s/d.sock", dir)))
}

@(test)
missing_directory_is_created_with_mode_0750 :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "mkdir")
	defer remove_test_dir(dir)
	sub := fmt.tprintf("%s/noirvpn", dir)
	old := posix.umask({.IWGRP, .IWOTH, .IROTH, .IXOTH})
	defer posix.umask(old)
	h, err, _ := host_open(Host_Options{control = Endpoint{path = fmt.tprintf("%s/x.control", sub)}, allocator = context.allocator})
	testing.expect_value(t, err, Open_Error.None)
	defer host_close(h)
	m, ok := file_mode(sub)
	testing.expect(t, ok)
	testing.expect_value(t, m, DIR_MODE)
}

@(test)
unsafe_directory_is_refused :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "unsafe")
	defer remove_test_dir(dir)
	cdir := strings.clone_to_cstring(dir, context.temp_allocator)
	posix.chmod(cdir, u32_to_mode(0o777))
	h, err, _ := host_open(Host_Options{control = Endpoint{path = fmt.tprintf("%s/x.control", dir)}, allocator = context.allocator})
	testing.expect_value(t, err, Open_Error.Dir_Not_Safe)
	testing.expect(t, h == nil)
	// With the sticky bit (like /tmp) it is fine.
	posix.chmod(cdir, u32_to_mode(0o1777))
	h, err, _ = host_open(Host_Options{control = Endpoint{path = fmt.tprintf("%s/x.control", dir)}, allocator = context.allocator})
	testing.expect_value(t, err, Open_Error.None)
	host_close(h)
	// A path that is a file.
	file := fmt.tprintf("%s/afile", dir)
	touch(file)
	h, err, _ = host_open(Host_Options{control = Endpoint{path = fmt.tprintf("%s/y.control", file)}, allocator = context.allocator})
	testing.expect_value(t, err, Open_Error.Dir_Not_Safe)
}

// ---- client errors ----

@(test)
no_daemon_is_reported :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "nodaemon")
	defer remove_test_dir(dir)
	url := fmt.tprintf("ipc://%s/none.control", dir)
	_, err := call(url, "status")
	testing.expect_value(t, err, Call_Error.Daemon_Not_Running)
	_, serr := subscribe(url)
	testing.expect_value(t, serr, Call_Error.Daemon_Not_Running)

	// A file where nothing listens (a daemon that was killed).
	path := fmt.tprintf("%s/none.control", dir)
	touch(path)
	_, err = call(url, "status")
	testing.expect_value(t, err, Call_Error.Daemon_Not_Running)

	_, err = call("tcp://127.0.0.1:9", "status")
	testing.expect_value(t, err, Call_Error.Bad_Url)
	_, err = call("relative", "status")
	testing.expect_value(t, err, Call_Error.Bad_Url)
}

// A socket in a directory this user may not enter (mode 0750 of another
// group) is "permission denied", not "not running".
@(test)
hidden_socket_is_permission_denied :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	if posix.geteuid() == 0 {
		// root passes every permission check; nothing to see.
		return
	}
	dir := make_test_dir(t, "hidden")
	defer remove_test_dir(dir)
	sub := fmt.tprintf("%s/locked", dir)
	testing.expect(t, posix.mkdir(strings.clone_to_cstring(sub, context.temp_allocator), {}) == .OK)
	defer posix.rmdir(strings.clone_to_cstring(sub, context.temp_allocator))
	url := fmt.tprintf("ipc://%s/x.control", sub)
	_, err := call(url, "status")
	testing.expect_value(t, err, Call_Error.Permission_Denied)
	_, serr := subscribe(url)
	testing.expect_value(t, serr, Call_Error.Permission_Denied)
}

// ---- shutdown ----

@(test)
reply_then_shutdown_still_reaches_the_caller :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "shutdown")
	defer fixture_close(fx)

	// The handler replies and closes the bus at once, like `daemon.shutdown`.
	r, err := call(ctl_url(fx), "daemon.shutdown")
	defer reply_destroy(&r)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	ok := wait_until(10 * time.Second, fx, proc(p: rawptr) -> bool {
		return sync.atomic_load(&(^Fixture)(p).closed_here)
	})
	testing.expect(t, ok)
	// The socket files are gone.
	testing.expect(t, !os.exists(fmt.tprintf("%s/ctl.sock", fx.dir)))
	testing.expect(t, !os.exists(fmt.tprintf("%s/ev.sock", fx.dir)))
	_, err2 := call(ctl_url(fx), "status")
	testing.expect_value(t, err2, Call_Error.Daemon_Not_Running)
}

@(test)
shutdown_with_requests_in_flight :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	// The fake loop takes the requests and never replies to them.
	fx := fixture_open(t, "inflight", {workers = 8, max_pending = 6})
	defer fixture_close(fx)

	N :: 3
	callers: [N]^Caller
	for i in 0 ..< N {
		callers[i] = caller_start(ctl_url(fx), "auth.decide", fmt.tprintf(`{{"session":"s-%d"}}`, i))
	}
	// Some queued, some in the loop's hands.
	ok := wait_until(10 * time.Second, fx, proc(p: rawptr) -> bool {
		fx := (^Fixture)(p)
		sync.mutex_lock(&fx.host.mu)
		defer sync.mutex_unlock(&fx.host.mu)
		return fx.host.pending == N
	})
	testing.expect(t, ok)
	// One more is queued and not yet taken: stop the loop's draining first.
	fixture_hold(t, fx)
	extra := caller_start(ctl_url(fx), "auth.decide", `{"session":"queued"}`)
	time.sleep(100 * time.Millisecond)

	// Stop the loop thread, then close the bus under it.
	sync.atomic_store(&fx.stop, true)
	thread.join(fx.loop)
	thread.destroy(fx.loop)
	fx.loop = nil
	host_close(fx.host)
	fx.host = nil

	// Every caller got a reply or a clean failure, nothing hung.
	for i in 0 ..< N {
		r, err := caller_finish(callers[i])
		testing.expect_value(t, err, Call_Error.None)
		testing.expect_value(t, r.code, "busy")
		testing.expect(t, strings.contains(r.message, "shutting down"))
		reply_destroy(&r)
	}
	r, err := caller_finish(extra)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect_value(t, r.code, "busy")
	reply_destroy(&r)
	// (The test runner's allocator check reports any leak or bad free.)
}

@(test)
close_with_idle_workers_is_quick :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "quick", {no_loop = true, workers = 8})
	dir := fx.dir
	defer remove_test_dir(dir)
	start := time.now()
	host_close(fx.host)
	fx.host = nil
	testing.expect(t, time.since(start) < 2 * time.Second)
	delete(fx.notices)
	delete(fx.deferred)
	free(fx)
}

// Many clients at once: every caller gets its own correct reply.
@(test)
many_clients_at_once :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 120 * time.Second)
	fx := fixture_open(t, "many", {workers = 8, max_pending = 7})
	defer fixture_close(fx)

	N :: 12
	ROUNDS :: 15
	Worker_Arg :: struct {
		url:       string,
		index:     int,
		allocator: runtime.Allocator,
		ok:        int,
		busy:      int,
		bad:       int,
	}
	args: [N]Worker_Arg
	threads: [N]^thread.Thread
	for i in 0 ..< N {
		args[i] = {
			url       = ctl_url(fx),
			index     = i,
			allocator = context.allocator,
		}
		th := thread.create(proc(th: ^thread.Thread) {
				a := (^Worker_Arg)(th.data)
				context.allocator = a.allocator
				c, cerr := connect(a.url, 20 * time.Second)
				if cerr != .None {
					a.bad += 1
					return
				}
				defer disconnect(&c)
				for round in 0 ..< ROUNDS {
					session := fmt.tprintf("s-%d-%d", a.index, round)
					// Mutating op with a unique id and a session name we can check.
					body := fmt.tprintf(`{{"session":"%s"}}`, session)
					r, e := conn_call(&c, "peer.kick", transmute([]byte)body, allocator = a.allocator)
					if e != .None {
						a.bad += 1
						continue
					}
					if r.ok {
						a.ok += 1
					} else if r.code == "busy" {
						a.busy += 1
					} else {
						a.bad += 1
					}
					reply_destroy(&r, a.allocator)
				}
			})
		th.data = &args[i]
		threads[i] = th
		thread.start(th)
	}
	total_ok, total_busy, total_bad := 0, 0, 0
	for i in 0 ..< N {
		thread.join(threads[i])
		thread.destroy(threads[i])
		total_ok += args[i].ok
		total_busy += args[i].busy
		total_bad += args[i].bad
	}
	testing.expect_value(t, total_bad, 0)
	testing.expect_value(t, total_ok + total_busy, N * ROUNDS)
	// Every request that was not refused reached the handler once.
	testing.expect_value(t, sync.atomic_load(&fx.kicks), total_ok)
}

@(test)
policy_can_be_replaced_while_running :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "setpolicy")
	defer fixture_close(fx)

	r, err := call(ctl_url(fx), "status")
	testing.expect(t, err == .None && r.ok)
	reply_destroy(&r)

	// Reload with a policy that excludes us.
	only_other := []config.Bus_Allow{{kind = .Uid, id = 424242, roles = {.Admin}}}
	p, unresolved := policy_from_config(only_other, euid())
	delete(unresolved)
	host_set_policy(fx.host, &p)
	policy_destroy(&p)
	r2, err2 := call(ctl_url(fx), "status")
	expect_error(t, &r2, err2, "denied")
	reply_destroy(&r2)

	// And back to the default.
	p, unresolved = policy_from_config(nil, euid())
	delete(unresolved)
	host_set_policy(fx.host, &p)
	policy_destroy(&p)
	r3, err3 := call(ctl_url(fx), "status")
	testing.expect(t, err3 == .None && r3.ok)
	reply_destroy(&r3)
}

// A request nobody replies to must not use up the queue for ever.
@(test)
abandoned_requests_do_not_block_the_queue :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fixture_open(t, "abandon", {workers = 4, max_pending = 2, reply_timeout = 200 * time.Millisecond})
	defer fixture_close(fx)
	// Three requests the loop takes and never replies to (auth.decide is parked).
	for i in 0 ..< 3 {
		r, err := call(ctl_url(fx), "auth.decide", transmute([]byte)fmt.tprintf(`{{"session":"s-%d"}}`, i))
		expect_error(t, &r, err, "timeout")
		reply_destroy(&r)
	}
	// Still room for a normal request.
	r, err := call(ctl_url(fx), "status")
	defer reply_destroy(&r)
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	// Late replies from the loop are refused, and free the requests.
	sync.atomic_store(&fx.release, true)
	time.sleep(100 * time.Millisecond)
}

@(test)
reply_error_details_round_trip :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)
	details := `[{"line":2,"option":"ca","class":"path","reason":"x"}]`
	write_reply_error_details(&w, "r9", .Bad_Request, "refused", transmute([]byte)details)
	raw := make([]byte, len(w.buf))
	copy(raw, writer_bytes(&w))
	r, err := parse_reply(raw, "r9")
	testing.expect_value(t, err, Call_Error.None)
	defer reply_destroy(&r)
	testing.expect(t, !r.ok)
	testing.expect_value(t, r.code, "bad_request")
	testing.expect_value(t, r.message, "refused")
	list, is_arr := r.details.(json.Array)
	testing.expect(t, is_arr)
	testing.expect_value(t, len(list), 1)

	// Without details the reply is the one of today.
	writer_reset(&w)
	write_reply_error(&w, "r9", .Denied, "no")
	testing.expect(t, !strings.contains(writer_string(&w), "details"))
	raw2 := make([]byte, len(w.buf))
	copy(raw2, writer_bytes(&w))
	r2, err2 := parse_reply(raw2, "r9")
	testing.expect_value(t, err2, Call_Error.None)
	defer reply_destroy(&r2)
	testing.expect(t, r2.details == nil)
}
