// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package bus

// The named pipe transport, host and client in this process. The tests run
// in an elevated session; a client with less power is a thread that
// impersonates a restricted copy of the process token, where the
// Administrators group is for deny only (an administrator who is not
// elevated).

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import win "core:sys/windows"
import "core:testing"
import "core:thread"
import "core:time"
import "noir:proto/config"

@(private = "file")
Fx :: struct {
	h:        ^Host,
	control:  string,
	events:   string,
	loop:     ^thread.Thread,
	stop:     bool,
	mu:       sync.Mutex,
	last:     Peer_Creds,
	served:   int,
}

@(private = "file")
pipe_names :: proc(tag: string) -> (control, events: string) {
	base := fmt.tprintf("%snoirvpn-t%d-%s", PIPE_DIR, os.get_pid(), tag)
	return strings.concatenate({base, CONTROL_SUFFIX}), strings.concatenate({base, EVENTS_SUFFIX})
}

@(private = "file")
fx_open :: proc(t: ^testing.T, tag: string, allow: []config.Bus_Allow = nil, loop := true) -> ^Fx {
	fx := new(Fx)
	fx.control, fx.events = pipe_names(tag)
	policy, unresolved := policy_from_config(allow, 0)
	defer delete(unresolved)
	defer policy_destroy(&policy)
	testing.expect_value(t, len(unresolved), 0)
	h, err, terr := host_open({mode = .Client, control = Endpoint{path = fx.control}, events = Endpoint{path = fx.events}, policy = policy})
	testing.expectf(t, err == .None, "host_open: %s (%v)", open_error_string(err), terr)
	fx.h = h
	if loop && h != nil {
		fx.loop = thread.create(fx_loop)
		fx.loop.data = fx
		fx.loop.init_context = context
		thread.start(fx.loop)
	}
	return fx
}

@(private = "file")
fx_close :: proc(fx: ^Fx) {
	sync.atomic_store(&fx.stop, true)
	if fx.loop != nil {
		thread.join(fx.loop)
		thread.destroy(fx.loop)
	}
	if fx.h != nil {
		host_close(fx.h)
	}
	delete(fx.control)
	delete(fx.events)
	free(fx)
}

// The daemon's loop: wait on the wake handle, reply to every request.
@(private = "file")
fx_loop :: proc(th: ^thread.Thread) {
	fx := (^Fx)(th.data)
	for !sync.atomic_load(&fx.stop) {
		win.WaitForSingleObject(host_wake_handle(fx.h), 20)
		for {
			req, ok := next_request(fx.h)
			if !ok {
				break
			}
			sync.mutex_lock(&fx.mu)
			fx.last = req.creds
			fx.served += 1
			sync.mutex_unlock(&fx.mu)
			switch req.op {
			case "status":
				reply_ok(fx.h, req, transmute([]byte)string(`{"mode":"client"}`))
			case:
				reply_ok(fx.h, req)
			}
		}
		for {
			if _, ok := next_notice(fx.h); !ok {
				break
			}
		}
	}
}

@(test)
pipe_round_trip :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fx_open(t, "rt")
	defer fx_close(fx)
	if fx.h == nil {
		return
	}
	r, err := call(fx.control, "status")
	testing.expect_value(t, err, Call_Error.None)
	testing.expect(t, r.ok)
	obj, _ := r.result.(json.Object)
	mode, _ := obj["mode"].(json.String)
	testing.expect_value(t, mode, "client")
	reply_destroy(&r)

	// The service knows who called: the user of this process, and its pid.
	me, _ := current_user_sid()
	sync.mutex_lock(&fx.mu)
	last := fx.last
	sync.mutex_unlock(&fx.mu)
	testing.expect(t, sid_equal(last.sid, me))
	testing.expect(t, last.has_pid && int(last.pid) == os.get_pid())

	// One connection for many requests.
	c, cerr := connect(fx.control)
	testing.expect_value(t, cerr, Call_Error.None)
	for _ in 0 ..< 5 {
		rr, e := conn_call(&c, "stats.get")
		testing.expect_value(t, e, Call_Error.None)
		testing.expect(t, rr.ok)
		reply_destroy(&rr)
	}
	disconnect(&c)

	// Several clients at once. Not more than the default `max_pending` (6) of
	// the host: one more can get a `busy` reply when the loop is slow.
	Job :: struct {
		url:  string,
		ok:   int,
		// The first failed call, so a failure in CI says what went wrong.
		err:  Call_Error,
		code: string,
		msg:  string,
	}
	jobs: [6]Job
	threads: [6]^thread.Thread
	for i in 0 ..< len(jobs) {
		jobs[i].url = fx.control
		threads[i] = thread.create_and_start_with_poly_data(&jobs[i], proc(j: ^Job) {
			for _ in 0 ..< 10 {
				r, e := call(j.url, "status")
				if e == .None && r.ok {
					j.ok += 1
				} else if j.err == .None && j.code == "" {
					j.err = e
					j.code = strings.clone(r.code if e == .None else "")
					j.msg = strings.clone(r.message if e == .None else "")
				}
				reply_destroy(&r)
			}
		}, context)
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	for j in jobs {
		testing.expectf(t, j.ok == 10, "%d of 10 calls worked; first failure: error %v, reply code %q, message %q", j.ok, j.err, j.code, j.msg)
		delete(j.code)
		delete(j.msg)
	}

	// The tools find the instance.
	found := discover()
	defer found_destroy(found)
	seen := false
	for f in found {
		if f.url == fx.control {
			seen = f.events_url == fx.events
		}
	}
	testing.expect(t, seen)

	// A second host of the same name is refused.
	policy, _ := policy_from_config(nil, 0)
	defer policy_destroy(&policy)
	h2, e2, _ := host_open({mode = .Client, control = Endpoint{path = fx.control}, policy = policy})
	testing.expect_value(t, e2, Open_Error.Control_In_Use)
	testing.expect(t, h2 == nil)
}

@(test)
pipe_not_running :: proc(t: ^testing.T) {
	control, events := pipe_names("none")
	defer delete(control)
	defer delete(events)
	_, err := call(control, "status")
	testing.expect_value(t, err, Call_Error.Daemon_Not_Running)
	_, serr := subscribe(events)
	testing.expect_value(t, serr, Call_Error.Daemon_Not_Running)
	_, berr := call(`\\host\pipe\x`, "status")
	testing.expect_value(t, berr, Call_Error.Bad_Url)
}

@(test)
pipe_events_and_slow_subscriber :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fx_open(t, "ev")
	defer fx_close(fx)
	if fx.h == nil {
		return
	}
	sub, err := subscribe(fx.events, {"client."})
	testing.expect_value(t, err, Call_Error.None)
	defer unsubscribe(&sub)

	// A subscriber that never reads.
	slow, serr := pipe_open(fx.events, PIPE_EVENTS_RIGHTS, 5 * time.Second)
	testing.expect_value(t, serr, Call_Error.None)
	defer pipe_close(&slow)
	time.sleep(100 * time.Millisecond)

	Reader :: struct {
		sub:  ^Subscriber,
		got:  int,
		gaps: u64,
		want: int,
	}
	TOTAL :: 1200
	rd := Reader{sub = &sub, want = TOTAL}
	th := thread.create_and_start_with_poly_data(&rd, proc(r: ^Reader) {
		deadline := time.tick_now()
		for r.got < r.want && time.tick_since(deadline) < 30 * time.Second {
			ev, e := next_event(r.sub, 500 * time.Millisecond)
			if e != .None {
				continue
			}
			if ev.topic == "client.state" {
				r.got += 1
				r.gaps += ev.gap
			}
			event_destroy(&ev)
		}
	}, context)
	data := strings.concatenate({`{"pad":"`, strings.repeat("x", 1000, context.temp_allocator), `"}`}, context.temp_allocator)
	slowest: time.Duration
	for i in 0 ..< TOTAL {
		start := time.tick_now()
		testing.expect(t, publish(fx.h, "client.state", transmute([]byte)data))
		slowest = max(slowest, time.tick_since(start))
		if i % 100 == 99 {
			time.sleep(30 * time.Millisecond)
		}
		// Other topics are filtered out after the sequence check.
		if i % 300 == 0 {
			publish(fx.h, "daemon.tick")
		}
	}
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, rd.got, TOTAL)
	testing.expect_value(t, rd.gaps, 0)
	// The slow subscriber was disconnected and publish never waited for it.
	testing.expect_value(t, transport_dropped(fx.h), 1)
	testing.expectf(t, slowest < 50 * time.Millisecond, "publish took %v", slowest)
}

// A raw client of the control pipe for the framing tests.
@(private = "file")
raw_open :: proc(name: string, rights: u32) -> (win.HANDLE, u32) {
	wname := win.utf8_to_wstring(name, context.temp_allocator)
	h := win.CreateFileW(wname, rights, 0, nil, win.OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nil)
	if h == win.INVALID_HANDLE_VALUE {
		return nil, win.GetLastError()
	}
	return h, 0
}

// Write a header and `n` bytes of body (`text` repeated), then read what
// comes back until the pipe ends or one reply is in. `closed` says the
// service ended the connection without a reply.
@(private = "file")
raw_exchange :: proc(h: win.HANDLE, length: u32, body: []u8) -> (reply: string, closed: bool) {
	hdr := frame_header(int(length))
	done: u32
	win.WriteFile(h, &hdr, 4, &done, nil)
	if len(body) > 0 {
		for off := 0; off < len(body); {
			if win.WriteFile(h, raw_data(body[off:]), u32(len(body) - off), &done, nil) == win.FALSE {
				break
			}
			off += int(done)
		}
	}
	fr: Frame_Reader
	frame_reader_init(&fr, FRAME_MAX_REPLY, context.temp_allocator)
	for {
		buf := frame_want(&fr)
		got: u32
		if win.ReadFile(h, raw_data(buf), u32(len(buf)), &got, nil) == win.FALSE {
			return "", true
		}
		if frame_got(&fr, int(got)) == .Done {
			return string(frame_take(&fr)), false
		}
	}
}

@(test)
pipe_length_limits :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	fx := fx_open(t, "len")
	defer fx_close(fx)
	if fx.h == nil {
		return
	}
	// A length of 0: closed with no reply.
	h, e := raw_open(fx.control, PIPE_CONTROL_RIGHTS)
	testing.expect_value(t, e, 0)
	_, closed := raw_exchange(h, 0, nil)
	testing.expect(t, closed)
	win.CloseHandle(h)

	// Above the hard limit: closed before the body is read.
	h, e = raw_open(fx.control, PIPE_CONTROL_RIGHTS)
	_, closed = raw_exchange(h, FRAME_MAX_REQUEST + 1, nil)
	testing.expect(t, closed)
	win.CloseHandle(h)

	h, e = raw_open(fx.control, PIPE_CONTROL_RIGHTS)
	_, closed = raw_exchange(h, 0xffff_ffff, nil)
	testing.expect(t, closed)
	win.CloseHandle(h)

	// Between the limit of the operation and the hard limit: a proper reply.
	big := make([]u8, MAX_PROFILE_REQUEST_SIZE + 10, context.temp_allocator)
	for &b in big {
		b = ' '
	}
	h, e = raw_open(fx.control, PIPE_CONTROL_RIGHTS)
	reply, rclosed := raw_exchange(h, u32(len(big)), big)
	testing.expect(t, !rclosed)
	testing.expect(t, strings.contains(reply, `"code":"bad_request"`) && strings.contains(reply, "too large"))
	win.CloseHandle(h)

	// Bad JSON gets a reply, and the connection goes on.
	h, e = raw_open(fx.control, PIPE_CONTROL_RIGHTS)
	junk := []u8{'{', '"', 'v'}
	reply, rclosed = raw_exchange(h, 3, junk)
	testing.expect(t, !rclosed && strings.contains(reply, `"bad_request"`))
	good := `{"v":1,"id":"a1","op":"status"}`
	reply, rclosed = raw_exchange(h, u32(len(good)), transmute([]u8)good)
	testing.expect(t, !rclosed && strings.contains(reply, `"ok":true`))
	win.CloseHandle(h)

	// The host still serves.
	r, cerr := call(fx.control, "status")
	testing.expect_value(t, cerr, Call_Error.None)
	reply_destroy(&r)
}

// A copy of the process token with the Administrators group for deny only,
// for impersonation.
@(private = "file")
restricted_token :: proc() -> win.HANDLE {
	tok: win.HANDLE
	if win.OpenProcessToken(win.GetCurrentProcess(), win.TOKEN_DUPLICATE | win.TOKEN_QUERY | win.TOKEN_ASSIGN_PRIMARY | win.TOKEN_IMPERSONATE, &tok) == win.FALSE {
		return nil
	}
	defer win.CloseHandle(tok)
	admins := must_sid(SID_ADMINISTRATORS)
	disable := [1]win.SID_AND_ATTRIBUTES{{Sid = &admins.data, Attributes = 0}}
	rtok: win.HANDLE
	if CreateRestrictedToken(tok, 0, 1, &disable[0], 0, nil, 0, nil, &rtok) == win.FALSE {
		return nil
	}
	defer win.CloseHandle(rtok)
	itok: win.HANDLE
	// SecurityImpersonation, TokenImpersonation.
	if DuplicateTokenEx(rtok, win.TOKEN_IMPERSONATE | win.TOKEN_QUERY | win.TOKEN_DUPLICATE, nil, 2, 2, &itok) == win.FALSE {
		return nil
	}
	return itok
}

@(private = "file")
As_User :: struct {
	tok:     win.HANDLE,
	control: string,
	events:  string,
	// Results.
	rw_err:       u32,
	exact_err:    u32,
	instance_err: u32,
	status:       Call_Error,
	status_ok:    bool,
	reload:       string,
	sub:          Call_Error,
}

// Run as the restricted user on its own thread.
@(private = "file")
as_user :: proc(a: ^As_User) {
	if SetThreadToken(nil, a.tok) == win.FALSE {
		return
	}
	defer RevertToSelf()
	_, a.rw_err = raw_open(a.control, win.GENERIC_READ | win.GENERIC_WRITE)
	h, e := raw_open(a.control, PIPE_CONTROL_RIGHTS)
	a.exact_err = e
	if h != nil {
		win.CloseHandle(h)
	}
	// Try to add an instance of the pipe of the service.
	wname := win.utf8_to_wstring(a.control, context.temp_allocator)
	ph := win.CreateNamedPipeW(wname, win.PIPE_ACCESS_DUPLEX, win.PIPE_TYPE_BYTE, PIPE_MAX_CONNECTIONS + 1, 512, 512, 0, nil)
	if ph == win.INVALID_HANDLE_VALUE {
		a.instance_err = win.GetLastError()
	} else {
		win.CloseHandle(ph)
	}
	r, err := call(a.control, "status")
	a.status = err
	a.status_ok = r.ok
	reply_destroy(&r)
	r2, _ := call(a.control, "daemon.reload")
	a.reload = strings.clone(r2.code)
	reply_destroy(&r2)
	s, serr := subscribe(a.events)
	a.sub = serr
	unsubscribe(&s)
}

@(private = "file")
run_as_user :: proc(t: ^testing.T, fx: ^Fx) -> (a: As_User) {
	a.tok = restricted_token()
	testing.expect(t, a.tok != nil)
	a.control, a.events = fx.control, fx.events
	th := thread.create_and_start_with_poly_data(&a, as_user, context)
	thread.join(th)
	thread.destroy(th)
	win.CloseHandle(a.tok)
	return
}

@(test)
pipe_access_list_and_roles :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	me, _ := current_user_sid()
	me_text := sid_string(me, context.temp_allocator)

	// A rule for this user: read only. The Administrators group would give
	// admin, but the restricted user has it for deny only.
	allow := []config.Bus_Allow {
		{kind = .Sid, name = me_text, roles = {.Read}},
		{kind = .Sid, name = SID_ADMINISTRATORS, roles = {.Admin}},
	}
	fx := fx_open(t, "acl", allow)
	if fx.h != nil {
		a := run_as_user(t, fx)
		testing.expect_value(t, a.rw_err, win.ERROR_ACCESS_DENIED)
		testing.expect_value(t, a.exact_err, 0)
		testing.expect_value(t, a.instance_err, win.ERROR_ACCESS_DENIED)
		testing.expect_value(t, a.status, Call_Error.None)
		testing.expect(t, a.status_ok)
		testing.expect_value(t, a.reload, "denied")
		testing.expect_value(t, a.sub, Call_Error.None)
		delete(a.reload)
		// The elevated user has the Administrators group enabled: admin.
		r, err := call(fx.control, "daemon.reload")
		testing.expect_value(t, err, Call_Error.None)
		testing.expect(t, r.ok)
		reply_destroy(&r)
	}
	fx_close(fx)

	// The default policy: the restricted user cannot even open the pipes.
	fx = fx_open(t, "acl0")
	if fx.h != nil {
		a := run_as_user(t, fx)
		testing.expect_value(t, a.exact_err, win.ERROR_ACCESS_DENIED)
		testing.expect_value(t, a.status, Call_Error.Permission_Denied)
		testing.expect_value(t, a.sub, Call_Error.Permission_Denied)
		delete(a.reload)
		r, err := call(fx.control, "daemon.reload")
		testing.expect_value(t, err, Call_Error.None)
		testing.expect(t, r.ok)
		reply_destroy(&r)
	}
	fx_close(fx)
}

// A pipe of the name of the service that a normal user created: the client
// sends nothing.
@(test)
pipe_owner_check :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	control, events := pipe_names("own")
	defer delete(control)
	defer delete(events)
	me, _ := current_user_sid()
	ps: Pipe_Security
	defer pipe_security_destroy(&ps)
	testing.expect(t, pipe_security_make(&ps, {me}, PIPE_CONTROL_RIGHTS, &me))
	wname := win.utf8_to_wstring(control, context.temp_allocator)
	ph := win.CreateNamedPipeW(wname, win.PIPE_ACCESS_DUPLEX, win.PIPE_TYPE_BYTE, 4, 4096, 4096, 0, &ps.sa)
	testing.expect(t, ph != win.INVALID_HANDLE_VALUE)
	defer win.CloseHandle(ph)

	owner, _ := handle_owner(ph)
	testing.expect(t, sid_equal(owner, me))
	_, err := call(control, "auth.supply", transmute([]byte)string(`{"password":"secret"}`), 2 * time.Second)
	testing.expect_value(t, err, Call_Error.Not_Service)
	avail: u32
	if win.PeekNamedPipe(ph, nil, 0, nil, &avail, nil) != win.FALSE {
		testing.expect_value(t, avail, 0)
	}
}

@(test)
pipe_paths :: proc(t: ^testing.T) {
	dir := default_dir(0, "")
	defer delete(dir)
	p := default_socket_path(dir, "server", CONTROL_SUFFIX)
	defer delete(p)
	testing.expect_value(t, p, `\\.\pipe\noirvpn-server-control`)
	ev := events_for_control(p)
	defer delete(ev)
	testing.expect_value(t, ev, `\\.\pipe\noirvpn-server-events`)

	f, ok := socket_file_path(`\\.\pipe\noirvpn-a-control`)
	testing.expect(t, ok && f == `\\.\pipe\noirvpn-a-control`)
	bad := []string{"", `\\.\pipe\`, `\\host\pipe\x`, "/run/x/control", "ipc:///run/x", `C:\x\control`}
	for b in bad {
		_, ok = socket_file_path(b)
		testing.expectf(t, !ok, "%q should be refused", b)
	}
	e, enabled, eok := resolve_endpoint({}, `\\.\pipe\noirvpn-a-events`)
	testing.expect(t, eok && enabled && e.path == `\\.\pipe\noirvpn-a-events`)

	n := instance_name(`C:\ProgramData\noirvpn\work.ovpn`)
	defer delete(n)
	testing.expect_value(t, n, "work")
}
