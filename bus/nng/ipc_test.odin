// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package nng

// Tests of the mechanisms the control bus relies on, over real ipc://
// sockets in a private temp directory. Every test creates its own directory, so
// the tests can run in parallel.

import "core:encoding/json"
import "core:fmt"
import "core:log"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"

// Helpers.

// Create a private directory for one test. Unix socket paths are short
// (104 bytes on macOS), so fall back to /tmp when TMPDIR is long.
make_test_dir :: proc(t: ^testing.T, tag: string) -> string {
	base, _ := os.temp_directory(context.temp_allocator)
	if len(base) > 40 {
		base = "/tmp"
	}
	dir, err := os.make_directory_temp(base, fmt.tprintf("noir-%s-*", tag), context.allocator)
	testing.expectf(t, err == nil, "cannot create temp dir in %q: %v", base, err)
	return dir
}

remove_test_dir :: proc(dir: string) {
	os.remove_all(dir)
	delete(dir)
}

ipc_url :: proc(dir, name: string) -> cstring {
	return fmt.ctprintf("ipc://%s/%s.sock", dir, name)
}

ipc_file :: proc(dir, name: string) -> cstring {
	return fmt.ctprintf("%s/%s.sock", dir, name)
}

// Open a socket and fail the test on error.
must_open :: proc(t: ^testing.T, protocol: Protocol) -> Socket {
	s, err := open(protocol)
	testing.expect_value(t, err, Error.None)
	return s
}

// A sample event body, to show JSON in and out of the bus.
Peer_Event :: struct {
	v:       int,
	seq:     u64,
	session: u64,
	user:    string,
	addr:    string,
}

publish_event :: proc(s: Socket, topic: string, ev: Peer_Event) -> Error {
	body, merr := json.marshal(ev)
	if merr != nil {
		return .Internal
	}
	defer delete(body)
	return publish(s, topic, body)
}

// Publish probe events until the subscriber receives one. A new subscriber
// misses events sent before its connection is fully set up (the "slow
// joiner" problem), so a test cannot publish at once and expect delivery.
// The subscriber must have a short receive timeout. Returns false if no
// probe arrives before the limit.
await_subscriber :: proc(pub, sub: Socket, topic: string, limit: time.Duration) -> bool {
	start := time.now()
	for time.since(start) < limit {
		if publish(pub, topic, nil) != .None {
			return false
		}
		data, err := recv(sub)
		if err == .None {
			delete(data)
			return true
		}
		if err != .Timed_Out {
			return false
		}
	}
	return false
}

// PUB/SUB.

@(test)
pubsub_prefix_filter :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "ps")
	defer remove_test_dir(dir)
	url := ipc_url(dir, "events")

	pub := must_open(t, .Pub)
	defer close(pub)
	_, err := listen(pub, url)
	testing.expect_value(t, err, Error.None)

	sub := must_open(t, .Sub)
	defer close(sub)
	testing.expect_value(t, subscribe(sub, "peer."), Error.None)
	testing.expect_value(t, set_recv_timeout(sub, 20 * time.Millisecond), Error.None)
	testing.expect_value(t, dial(sub, url), Error.None)

	synced := await_subscriber(pub, sub, "peer.probe", 10 * time.Second)
	testing.expect(t, synced, "subscriber never received a probe")
	if !synced {
		return
	}

	// daemon.start does not match "peer.", so the subscriber never sees it.
	testing.expect_value(t, publish(pub, "daemon.start", transmute([]byte)string(`{"v":1,"seq":1}`)), Error.None)
	testing.expect_value(t, publish_event(pub, "peer.connect", {v = 1, seq = 2, session = 7, user = "alice", addr = "192.0.2.10:51000"}), Error.None)
	testing.expect_value(t, publish_event(pub, "peer.disconnect", {v = 1, seq = 3, session = 7, user = "alice"}), Error.None)

	topics: [dynamic]string
	defer {
		for topic in topics {
			delete(topic)
		}
		delete(topics)
	}
	seqs: [dynamic]u64
	defer delete(seqs)

	// Read until the disconnect event. Skip probes that were queued earlier.
	start := time.now()
	got_last := false
	for !got_last && time.since(start) < 10 * time.Second {
		data, rerr := recv(sub)
		if rerr == .Timed_Out {
			continue
		}
		testing.expect_value(t, rerr, Error.None)
		if rerr != .None {
			break
		}
		topic, payload := split_topic(data)
		if topic != "peer.probe" {
			append(&topics, strings.clone(topic))
			ev: Peer_Event
			uerr := json.unmarshal(payload, &ev)
			testing.expect_value(t, uerr, nil)
			append(&seqs, ev.seq)
			if topic == "peer.connect" {
				testing.expect_value(t, ev.user, "alice")
				testing.expect_value(t, ev.addr, "192.0.2.10:51000")
				testing.expect_value(t, ev.session, 7)
			}
			got_last = topic == "peer.disconnect"
			delete(ev.user)
			delete(ev.addr)
		}
		delete(data)
	}
	testing.expect_value(t, len(topics), 2)
	if len(topics) == 2 {
		testing.expect_value(t, topics[0], "peer.connect")
		testing.expect_value(t, topics[1], "peer.disconnect")
		testing.expect_value(t, seqs[0], 2)
		testing.expect_value(t, seqs[1], 3)
	}

	// Nothing else is queued. daemon.start was filtered out: the first event
	// seen has seq 2, and seq 1 went to daemon.start.
	_, rerr := recv(sub)
	testing.expect_value(t, rerr, Error.Timed_Out)
}

// PUB never blocks and never queues without limit: when a subscriber is too
// slow, messages are dropped. This is why events carry a sequence number.
@(test)
pubsub_drops_for_slow_subscriber :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "drop")
	defer remove_test_dir(dir)
	url := ipc_url(dir, "events")

	pub := must_open(t, .Pub)
	defer close(pub)
	_, err := listen(pub, url)
	testing.expect_value(t, err, Error.None)

	sub := must_open(t, .Sub)
	defer close(sub)
	testing.expect_value(t, subscribe(sub, "stats."), Error.None)
	testing.expect_value(t, set_recv_timeout(sub, 20 * time.Millisecond), Error.None)
	testing.expect_value(t, dial(sub, url), Error.None)
	if !await_subscriber(pub, sub, "stats.probe", 10 * time.Second) {
		testing.fail_now(t, "subscriber never received a probe")
	}

	// Send a burst while the subscriber reads nothing.
	N :: 3000
	padding := strings.repeat("x", 1000, context.temp_allocator)
	for i in 1 ..= N {
		body := fmt.tprintf(`{{"seq":%d,"pad":"%s"}}`, i, padding)
		serr := publish(pub, "stats.tick", transmute([]byte)body)
		if serr != .None {
			testing.expect_value(t, serr, Error.None)
			return
		}
	}

	// Drain. Sequence numbers must rise, and many must be missing. Which ones
	// depends on timing: either a gap in the middle or a lost start.
	count, first_seq, last_seq, gaps: int
	for {
		data, rerr := recv(sub)
		if rerr == .Timed_Out {
			break
		}
		testing.expect_value(t, rerr, Error.None)
		if rerr != .None {
			break
		}
		topic, payload := split_topic(data)
		if topic == "stats.tick" {
			Tick :: struct {
				seq: int,
			}
			tick: Tick
			testing.expect_value(t, json.unmarshal(payload, &tick), nil)
			testing.expectf(t, tick.seq > last_seq, "sequence went backwards: %d after %d", tick.seq, last_seq)
			if last_seq != 0 && tick.seq != last_seq + 1 {
				gaps += 1
			}
			if count == 0 {
				first_seq = tick.seq
			}
			last_seq = tick.seq
			count += 1
		}
		delete(data)
	}
	log.infof("sent %d, subscriber received %d (first seq %d, last seq %d), gaps seen %d", N, count, first_seq, last_seq, gaps)
	testing.expect(t, count > 0, "nothing received")
	testing.expect(t, count < N, "no message was dropped")
}

// REQ/REP.

Request :: struct {
	req: string,
}

Reply :: struct {
	v:      int,
	ok:     bool,
	result: string `json:"result,omitempty"`,
	error:  string `json:"error,omitempty"`,
}

// A toy control handler: one known request, everything else is an error.
handle_request :: proc(body: []byte) -> []byte {
	reply := Reply {
		v = 1,
	}
	req: Request
	if json.unmarshal(body, &req) != nil {
		reply.error = "bad request"
	} else {
		switch req.req {
		case "status":
			reply.ok = true
			reply.result = "running"
		case:
			reply.error = fmt.tprintf("unknown request: %s", req.req)
		}
		delete(req.req)
	}
	out, _ := json.marshal(reply)
	return out
}

Server :: struct {
	sock:    Socket,
	handled: int,
}

// One request at a time on the socket. Ends when the socket is closed.
serve :: proc(data: rawptr) {
	srv := (^Server)(data)
	for {
		m, err := recv_msg(srv.sock)
		if err != .None {
			return
		}
		reply := handle_request(msg_body(m))
		msg_free(m)
		// Count before the send: the caller reads the count when its reply arrives.
		sync.atomic_add(&srv.handled, 1)
		send(srv.sock, reply)
		delete(reply)
	}
}

@(test)
reqrep_round_trip_and_error_reply :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "rr")
	defer remove_test_dir(dir)
	url := ipc_url(dir, "control")

	rep := must_open(t, .Rep)
	_, err := listen(rep, url)
	testing.expect_value(t, err, Error.None)
	srv := Server {
		sock = rep,
	}
	th := thread.create_and_start_with_data(&srv, serve, context)

	req := must_open(t, .Req)
	testing.expect_value(t, set_recv_timeout(req, 5 * time.Second), Error.None)
	testing.expect_value(t, set_send_timeout(req, 5 * time.Second), Error.None)
	testing.expect_value(t, dial(req, url), Error.None)

	// Known request.
	data, cerr := call(req, transmute([]byte)string(`{"req":"status"}`))
	testing.expect_value(t, cerr, Error.None)
	reply: Reply
	testing.expect_value(t, json.unmarshal(data, &reply), nil)
	testing.expect_value(t, reply.ok, true)
	testing.expect_value(t, reply.result, "running")
	testing.expect_value(t, reply.error, "")
	delete(data)
	delete(reply.result)
	delete(reply.error)

	// Unknown request: the call works, and the reply holds the error.
	data, cerr = call(req, transmute([]byte)string(`{"req":"frobnicate"}`))
	testing.expect_value(t, cerr, Error.None)
	reply = {}
	testing.expect_value(t, json.unmarshal(data, &reply), nil)
	testing.expect_value(t, reply.ok, false)
	testing.expect_value(t, reply.error, "unknown request: frobnicate")
	delete(data)
	delete(reply.result)
	delete(reply.error)

	// Not JSON at all.
	data, cerr = call(req, transmute([]byte)string("garbage"))
	testing.expect_value(t, cerr, Error.None)
	reply = {}
	testing.expect_value(t, json.unmarshal(data, &reply), nil)
	testing.expect_value(t, reply.ok, false)
	testing.expect_value(t, reply.error, "bad request")
	delete(data)
	delete(reply.result)
	delete(reply.error)

	testing.expect_value(t, sync.atomic_load(&srv.handled), 3)

	// Closing the REP socket ends the server loop.
	close(req)
	testing.expect_value(t, close(rep), Error.None)
	thread.join(th)
	thread.destroy(th)
}

// A REQ client that cannot reach a server learns it at dial time.
@(test)
dial_without_server_fails_at_once :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	dir := make_test_dir(t, "nosrv")
	defer remove_test_dir(dir)

	req := must_open(t, .Req)
	defer close(req)
	err := dial(req, ipc_url(dir, "control"))
	log.infof("dial to a missing socket: %v (%s)", err, error_string(err))
	testing.expect(t, err != .None)
}

// A socket file left behind by a crashed daemon must not block a restart.
@(test)
listen_replaces_stale_socket_file :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	dir := make_test_dir(t, "stale")
	defer remove_test_dir(dir)

	// Create a socket file with nobody listening, like a killed process leaves.
	path := ipc_file(dir, "events")
	fd := posix.socket(.UNIX, .STREAM)
	testing.expect(t, fd != -1, "cannot create unix socket")
	addr := posix.sockaddr_un {
		sun_family = .UNIX,
	}
	copy(addr.sun_path[:], transmute([]byte)string(path))
	rc := posix.bind(fd, (^posix.sockaddr)(&addr), size_of(addr))
	testing.expect_value(t, rc, posix.result.OK)
	posix.close(fd)
	st: posix.stat_t
	testing.expect_value(t, posix.stat(path, &st), posix.result.OK)

	pub := must_open(t, .Pub)
	defer close(pub)
	_, err := listen(pub, ipc_url(dir, "events"))
	testing.expect_value(t, err, Error.None)

	// A second live listener on the same path is refused.
	pub2 := must_open(t, .Pub)
	defer close(pub2)
	_, err = listen(pub2, ipc_url(dir, "events"))
	testing.expect_value(t, err, Error.Address_In_Use)
}

// Peer credentials.

@(test)
rep_sees_peer_credentials :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "cred")
	defer remove_test_dir(dir)
	url := ipc_url(dir, "control")

	rep := must_open(t, .Rep)
	defer close(rep)
	_, err := listen(rep, url)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, set_recv_timeout(rep, 5 * time.Second), Error.None)

	req := must_open(t, .Req)
	defer close(req)
	testing.expect_value(t, set_send_timeout(req, 5 * time.Second), Error.None)
	testing.expect_value(t, set_recv_timeout(req, 5 * time.Second), Error.None)
	testing.expect_value(t, dial(req, url), Error.None)
	testing.expect_value(t, send(req, transmute([]byte)string(`{"req":"status"}`)), Error.None)

	m, rerr := recv_msg(rep)
	testing.expect_value(t, rerr, Error.None)
	if rerr != .None {
		return
	}
	pipe := msg_pipe(m)
	testing.expect(t, pipe.id != 0, "message has no pipe")
	creds, cerr := pipe_peer_creds(pipe)
	testing.expect_value(t, cerr, Error.None)
	log.infof("peer credentials: %v", creds)
	testing.expect_value(t, creds.uid, u32(posix.getuid()))
	testing.expect_value(t, creds.gid, u32(posix.getgid()))
	when ODIN_OS == .Linux {
		testing.expect(t, creds.has_pid, "Linux reports the peer pid")
		testing.expect_value(t, creds.pid, u32(posix.getpid()))
	}
	msg_free(m)

	// Finish the exchange.
	testing.expect_value(t, send(rep, transmute([]byte)string(`{"ok":true}`)), Error.None)
	reply, gerr := recv(req)
	testing.expect_value(t, gerr, Error.None)
	delete(reply)
}

// If the peer is gone by the time the daemon looks, there are no credentials.
// The daemon must then deny the request.
@(test)
peer_credentials_fail_after_disconnect :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "gone")
	defer remove_test_dir(dir)
	url := ipc_url(dir, "control")

	rep := must_open(t, .Rep)
	defer close(rep)
	_, err := listen(rep, url)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, set_recv_timeout(rep, 5 * time.Second), Error.None)

	req := must_open(t, .Req)
	testing.expect_value(t, set_send_timeout(req, 5 * time.Second), Error.None)
	testing.expect_value(t, dial(req, url), Error.None)
	testing.expect_value(t, send(req, transmute([]byte)string("hello")), Error.None)

	m, rerr := recv_msg(rep)
	testing.expect_value(t, rerr, Error.None)
	if rerr != .None {
		close(req)
		return
	}
	defer msg_free(m)
	pipe := msg_pipe(m)
	_, cerr := pipe_peer_creds(pipe)
	testing.expect_value(t, cerr, Error.None)

	// The client leaves. The pipe goes away soon after.
	close(req)
	gone := false
	start := time.now()
	for time.since(start) < 5 * time.Second {
		_, cerr = pipe_peer_creds(pipe)
		if cerr != .None {
			gone = true
			break
		}
		time.sleep(5 * time.Millisecond)
	}
	log.infof("after disconnect: %v", cerr)
	testing.expect(t, gone, "credentials were still readable 5 s after the peer left")
	testing.expect(t, cerr == .Not_Found || cerr == .Closed, "unexpected error")
}

// Socket file permissions.

file_mode :: proc(t: ^testing.T, path: cstring) -> (mode: u32, ok: bool) {
	st: posix.stat_t
	if !testing.expect_value(t, posix.stat(path, &st), posix.result.OK) {
		return 0, false
	}
	testing.expect(t, posix.S_ISSOCK(st.st_mode), "not a socket file")
	m := st.st_mode
	bits := [?]struct {
		flag: posix.Mode_Bits,
		bit:  u32,
	} {
		{.IRUSR, 0o400}, {.IWUSR, 0o200}, {.IXUSR, 0o100},
		{.IRGRP, 0o040}, {.IWGRP, 0o020}, {.IXGRP, 0o010},
		{.IROTH, 0o004}, {.IWOTH, 0o002}, {.IXOTH, 0o001},
	}
	for b in bits {
		if b.flag in m {
			mode |= b.bit
		}
	}
	return mode, true
}

@(test)
ipc_permissions_are_applied :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	dir := make_test_dir(t, "perm")
	defer remove_test_dir(dir)

	// The mode is set exactly, whatever the umask is.
	Case :: struct {
		name: string,
		mode: int,
	}
	cases := [?]Case{{"a", 0o660}, {"b", 0o600}, {"c", 0o666}}
	for c in cases {
		s := must_open(t, .Rep)
		defer close(s)
		_, err := listen(s, ipc_url(dir, c.name), ipc_permissions = c.mode)
		testing.expect_value(t, err, Error.None)
		mode, ok := file_mode(t, ipc_file(dir, c.name))
		if ok {
			testing.expectf(t, int(mode) == c.mode, "wanted %o, got %o", c.mode, mode)
		}
	}

	// Without ipc_permissions nng keeps its own default. It is only logged:
	// it is not something to rely on.
	d := must_open(t, .Rep)
	defer close(d)
	_, derr := listen(d, ipc_url(dir, "default"))
	testing.expect_value(t, derr, Error.None)
	if mode, ok := file_mode(t, ipc_file(dir, "default")); ok {
		log.infof("default socket file mode: %o", mode)
	}

	// A mode that is not valid is an error, not a silent default.
	s := must_open(t, .Rep)
	defer close(s)
	_, err := listen(s, ipc_url(dir, "bad"), ipc_permissions = -1)
	testing.expect_value(t, err, Error.Invalid)
}

// Contexts.

Gate :: struct {
	started: sync.Sema, // posted when a worker has taken the slow request
	release: sync.Sema, // the test posts this to let the slow request finish
}

Ctx_Worker :: struct {
	sock: Socket,
	gate: ^Gate,
}

ctx_worker :: proc(data: rawptr) {
	w := (^Ctx_Worker)(data)
	cx, err := ctx_open(w.sock)
	if err != .None {
		return
	}
	defer ctx_close(cx)
	for {
		m, rerr := ctx_recv_msg(cx)
		if rerr != .None {
			return
		}
		body := strings.clone(string(msg_body(m)))
		msg_free(m)
		if body == "slow" {
			sync.sema_post(&w.gate.started)
			sync.sema_wait(&w.gate.release)
		}
		reply, merr := msg_new(transmute([]byte)fmt.tprintf("done:%s", body))
		delete(body)
		if merr != .None {
			return
		}
		if ctx_send_msg(cx, reply) != .None {
			msg_free(reply)
		}
	}
}

// With one context per worker thread, a slow request does not block others.
// A plain REP socket would serve them strictly one after the other.
@(test)
rep_contexts_serve_requests_concurrently :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_test_dir(t, "ctx")
	defer remove_test_dir(dir)
	url := ipc_url(dir, "control")

	rep := must_open(t, .Rep)
	_, err := listen(rep, url)
	testing.expect_value(t, err, Error.None)

	gate: Gate
	worker := Ctx_Worker {
		sock = rep,
		gate = &gate,
	}
	threads: [2]^thread.Thread
	for &th in threads {
		th = thread.create_and_start_with_data(&worker, ctx_worker, context)
	}

	slow := must_open(t, .Req)
	defer close(slow)
	fast := must_open(t, .Req)
	defer close(fast)
	for c in ([?]Socket{slow, fast}) {
		testing.expect_value(t, set_send_timeout(c, 5 * time.Second), Error.None)
		testing.expect_value(t, set_recv_timeout(c, 5 * time.Second), Error.None)
		testing.expect_value(t, dial(c, url), Error.None)
	}

	testing.expect_value(t, send(slow, transmute([]byte)string("slow")), Error.None)
	started := sync.sema_wait_with_timeout(&gate.started, 5 * time.Second)
	testing.expect(t, started, "slow request was never taken")

	// The other worker replies while the first is still busy.
	data, cerr := call(fast, transmute([]byte)string("fast"))
	testing.expect_value(t, cerr, Error.None)
	testing.expect_value(t, string(data), "done:fast")
	delete(data)

	// The slow client has no reply yet.
	_, nerr := recv(slow, nonblock = true)
	testing.expect_value(t, nerr, Error.Try_Again)

	sync.sema_post(&gate.release)
	data, cerr = recv(slow)
	testing.expect_value(t, cerr, Error.None)
	testing.expect_value(t, string(data), "done:slow")
	delete(data)

	// Closing the socket ends the workers' contexts, so the threads return.
	testing.expect_value(t, close(rep), Error.None)
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
}
