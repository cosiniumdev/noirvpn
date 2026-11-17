// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Tool side: send one request and read the reply (`call`), or follow events
// (`Subscriber`). Used by `noirvpnctl`, `noirvpn-hook` and Odin controllers.
//
//	reply, err := bus.call(url, "peer.kick", `{"session":"s-1"}`, 5 * time.Second)
//	if err != .None { ... }
//	defer bus.reply_destroy(&reply)
//
// `call` opens one connection per request. A controller that sends many can
// keep a `Conn`.
// Transport: client_nng.odin (Unix), client_pipe.odin (Windows). It provides
// `connect`, `disconnect`, `conn_exchange`, `subscribe`, `unsubscribe`,
// `sub_recv`, `discover` and the bus address checks.

import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:time"

DEFAULT_CALL_TIMEOUT :: 5 * time.Second

Call_Error :: enum u8 {
	None,
	// The socket file (or the pipe) does not exist, or nothing listens on it.
	Daemon_Not_Running,
	// The file exists but this user may not connect to it.
	Permission_Denied,
	// The URL is not a local ipc:// path (on Windows: a local pipe name).
	Bad_Url,
	// No reply within the timeout. The request may still have been applied.
	Timeout,
	// The connection closed, or another nng error.
	Io,
	// The reply is not a valid reply envelope.
	Bad_Reply,
	No_Memory,
	// Windows: the pipe does not belong to LocalSystem or the Administrators
	// group, so it is not the service. Nothing was sent.
	Not_Service,
}

call_error_string :: proc(e: Call_Error) -> string {
	switch e {
	case .None:
		return "ok"
	case .Daemon_Not_Running:
		return "the daemon is not running (there is no bus socket)"
	case .Permission_Denied:
		return "permission denied on the bus socket"
	case .Bad_Url:
		when ODIN_OS == .Windows {
			return "the bus address must be a local pipe name (\\\\.\\pipe\\...)"
		} else {
			return "the bus address must be an absolute path or an ipc:// URL"
		}
	case .Timeout:
		return "the daemon did not reply in time"
	case .Io:
		return "the connection to the bus failed"
	case .Bad_Reply:
		return "the daemon sent a reply that cannot be read"
	case .No_Memory:
		return "out of memory"
	case .Not_Service:
		return "the bus pipe does not belong to the service because another user created it, so nothing was sent"
	}
	return "?"
}

// A reply. The strings and `result` point into `root`, which `reply_destroy`
// frees. `raw` is the reply as sent (for printing).
Reply :: struct {
	raw:     []byte,
	root:    json.Value,
	// "" if the daemon sent null (it could not read the id).
	id:      string,
	ok:      bool,
	// Valid when `ok`.
	result:  json.Value,
	// Valid when not `ok`. `code` is one of the error codes of the bus.
	code:    string,
	message: string,
	// Valid when not `ok`: the `details` array of the error, or nil when the
	// daemon sent none. A refused profile lists its problems here.
	details: json.Value,
}

reply_destroy :: proc(r: ^Reply, allocator := context.allocator) {
	json.destroy_value(r.root, allocator)
	delete(r.raw, allocator)
	r^ = {}
}

// Send a request on an open connection. `args` is a JSON object text or nil.
// `id` is the request id. Leave it empty to get a random one. To retry a
// request that timed out, call again with the same id: the daemon applies a
// state-changing request once per id.
conn_call :: proc(
	c: ^Conn,
	op: string,
	args: []byte = nil,
	id := "",
	allocator := context.allocator,
) -> (
	reply: Reply,
	err: Call_Error,
) {
	rid := id
	if rid == "" {
		rid = random_hex(16, context.temp_allocator)
	}
	w: Writer
	writer_init(&w, context.temp_allocator)
	write_request(&w, rid, op, args)

	data, err2 := conn_exchange(c, writer_bytes(&w), allocator)
	// The request may hold a secret (a profile with keys): overwrite our copy.
	if len(w.buf) > 0 {
		mem.zero_explicit(raw_data(w.buf), len(w.buf))
	}
	if err2 != .None {
		return {}, err2
	}
	return parse_reply(data, rid, allocator)
}

// Check a reply envelope. Takes ownership of `data` (frees it on error).
parse_reply :: proc(data: []byte, want_id: string, allocator := context.allocator) -> (r: Reply, err: Call_Error) {
	root, parsed := parse_json(data, allocator)
	if !parsed {
		return {}, reply_fail(data, nil, allocator)
	}
	obj, is_obj := root.(json.Object)
	if !is_obj {
		return {}, reply_fail(data, root, allocator)
	}
	v, v_ok := obj["v"].(json.Integer)
	if !v_ok || v != VERSION {
		return {}, reply_fail(data, root, allocator)
	}
	r.raw = data
	r.root = root
	#partial switch idv in obj["id"] {
	case json.String:
		r.id = idv
	case json.Null:
	case:
		return {}, reply_fail(data, root, allocator)
	}
	if r.id != "" && r.id != want_id {
		return {}, reply_fail(data, root, allocator)
	}
	okv, ok_ok := obj["ok"].(json.Boolean)
	if !ok_ok {
		return {}, reply_fail(data, root, allocator)
	}
	r.ok = okv
	if r.ok {
		r.result = obj["result"]
		if _, has := obj["result"]; !has {
			return {}, reply_fail(data, root, allocator)
		}
	} else {
		eobj, e_ok := obj["error"].(json.Object)
		if !e_ok {
			return {}, reply_fail(data, root, allocator)
		}
		r.code, _ = eobj["code"].(json.String)
		r.message, _ = eobj["message"].(json.String)
		r.details = eobj["details"]
		if r.code == "" {
			return {}, reply_fail(data, root, allocator)
		}
	}
	return r, .None
}

@(private)
reply_fail :: proc(data: []byte, root: json.Value, allocator: mem.Allocator) -> Call_Error {
	json.destroy_value(root, allocator)
	delete(data, allocator)
	return .Bad_Reply
}

// One request, one reply: connect, send, wait, close.
call :: proc(
	url, op: string,
	args: []byte = nil,
	timeout := DEFAULT_CALL_TIMEOUT,
	id := "",
	allocator := context.allocator,
) -> (
	reply: Reply,
	err: Call_Error,
) {
	c := connect(url, timeout) or_return
	defer disconnect(&c)
	return conn_call(&c, op, args, id, allocator)
}

// ---- events ----

// What a subscriber found out about the stream, besides the event itself.
Event :: struct {
	// The event envelope as sent (the JSON after the topic). Points into `buf`.
	raw:       []byte,
	// The whole message, topic included. Owned by the event.
	buf:       []byte,
	root:      json.Value,
	topic:     string,
	run:       string,
	seq:       u64,
	ts:        string,
	// The "data" object.
	data:      json.Value,
	// This many events were missed just before this one (a gap in `seq`).
	gap:       u64,
	// The daemon was restarted since the last event (new `run`). Events
	// before it are not comparable; fetch the state again.
	restarted: bool,
	// This is the first event this subscriber saw: it has no continuity
	// check yet. Fetch the state to be sure nothing was missed before it.
	first:     bool,
}

event_destroy :: proc(e: ^Event, allocator := context.allocator) {
	json.destroy_value(e.root, allocator)
	delete(e.buf, allocator)
	e^ = {}
}

Sub_Error :: enum u8 {
	None,
	// No event within the timeout (normal).
	Timed_Out,
	Closed,
	// A message that is not a valid event envelope. It is skipped; call again.
	Bad_Event,
	Io,
}

Subscriber :: struct {
	using tr:  Sub_Transport,
	have:      bool,
	last_run:  [RUN_ID_LEN]u8,
	last_seq:  u64,
	// Topic prefixes to hand out; empty means every event.
	prefixes:  [dynamic]string,
	// Findings from events that were filtered out, passed on with the next
	// event that is not.
	pend_gap:  u64,
	pend_rest: bool,
	pend_first: bool,
}

@(private)
topic_wanted :: proc(s: ^Subscriber, topic: string) -> bool {
	if len(s.prefixes) == 0 {
		return true
	}
	for p in s.prefixes {
		if strings.has_prefix(topic, p) {
			return true
		}
	}
	return false
}

// Wait for the next wanted event. A negative `timeout` waits for ever. On
// `.None` the caller owns the event (free with `event_destroy`).
next_event :: proc(
	s: ^Subscriber,
	timeout: time.Duration = -1,
	allocator := context.allocator,
) -> (
	ev: Event,
	err: Sub_Error,
) {
	start := mono_now()
	for {
		wait := timeout
		if timeout >= 0 {
			wait = max(timeout - (mono_now() - start), 0)
		}
		data, rerr := sub_recv(s, wait, allocator)
		if rerr != .None {
			return {}, rerr
		}
		ev, err = parse_event(data, allocator)
		if err != .None {
			return
		}
		track_sequence(s, &ev)
		if !topic_wanted(s, ev.topic) {
			s.pend_gap += ev.gap
			s.pend_rest ||= ev.restarted
			s.pend_first ||= ev.first
			event_destroy(&ev, allocator)
			continue
		}
		ev.gap += s.pend_gap
		ev.restarted ||= s.pend_rest
		ev.first ||= s.pend_first
		s.pend_gap, s.pend_rest, s.pend_first = 0, false, false
		return
	}
}

// Parse "<topic> <envelope>". Takes ownership of `data`.
parse_event :: proc(data: []byte, allocator := context.allocator) -> (ev: Event, err: Sub_Error) {
	topic, payload := split_topic(data)
	root, parsed := parse_json(payload, allocator)
	if !parsed {
		delete(data, allocator)
		return {}, .Bad_Event
	}
	obj, is_obj := root.(json.Object)
	if !is_obj {
		return {}, event_fail(data, root, allocator)
	}
	if v, ok := obj["v"].(json.Integer); !ok || v != VERSION {
		return {}, event_fail(data, root, allocator)
	}
	run, run_ok := obj["run"].(json.String)
	seq, seq_ok := obj["seq"].(json.Integer)
	ts, ts_ok := obj["ts"].(json.String)
	etopic, topic_ok := obj["topic"].(json.String)
	if !run_ok || !seq_ok || seq < 0 || !ts_ok || !topic_ok || etopic != topic || len(run) != RUN_ID_LEN {
		return {}, event_fail(data, root, allocator)
	}
	dv, has_data := obj["data"]
	if !has_data {
		return {}, event_fail(data, root, allocator)
	}
	ev = Event {
		raw   = payload,
		buf   = data,
		root  = root,
		topic = etopic,
		run   = run,
		seq   = u64(seq),
		ts    = ts,
		data  = dv,
	}
	return ev, .None
}

@(private)
event_fail :: proc(data: []byte, root: json.Value, allocator: mem.Allocator) -> Sub_Error {
	json.destroy_value(root, allocator)
	delete(data, allocator)
	return .Bad_Event
}

@(private)
track_sequence :: proc(s: ^Subscriber, ev: ^Event) {
	if !s.have {
		ev.first = true
	} else if string(s.last_run[:]) != ev.run {
		ev.restarted = true
	} else if ev.seq > s.last_seq + 1 {
		ev.gap = ev.seq - s.last_seq - 1
	}
	s.have = true
	copy(s.last_run[:], ev.run)
	s.last_seq = ev.seq
}

// Split an event message into its topic and its envelope. Both point into
// `msg`. With no space the whole message is the topic.
split_topic :: proc(msg: []byte) -> (topic: string, payload: []byte) {
	for b, i in msg {
		if b == ' ' {
			return transmute(string)msg[:i], msg[i + 1:]
		}
	}
	return transmute(string)msg, nil
}
