// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:runtime"
import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"
import "noir:bus"

// How often `connect --follow` prints the time left of a web sign-in.
FOLLOW_REMIND :: 30 * time.Second

// `connect --follow`: connect, then print each state and the link of a web
// sign-in until the tunnel is up (exit 0) or the daemon stops (exit 1). The link
// is in `status` only (client.auth_needed): the tool reads
// it there when the event says a sign-in waits.
//
//   subscribe -> connect -> status (a sign-in that waits already)
//   events: client.state       -> print; up: done; stopped: done
//           client.auth_needed -> web_auth: status -> print the link and time left
//           a gap, a restart   -> status
Follow :: struct {
	url:      string, // the last link printed (owned)
	host:     string, // owned
	deadline: time.Time,
	waiting:  bool, // a web sign-in waits
	remind:   time.Time,
	state:    string, // owned
}

@(private = "file")
follow_destroy :: proc(f: ^Follow) {
	delete(f.url)
	delete(f.host)
	delete(f.state)
	f^ = {}
}

run_connect_follow :: proc(c: ^Command, t: Target, io: ^Io, stop: ^Stop) -> Exit {
	sub, serr := bus.subscribe(t.events, nil, false)
	if serr != .None {
		switch serr {
		case .Daemon_Not_Running:
			err_line(io, "--follow requires the events socket, but there is none at %s (is bus-events turned off?)", t.events)
		case .Permission_Denied:
			err_line(io, "permission denied on %s (%s)", t.events, ACCESS_HINT)
		case .Not_Service:
			err_line(io, "%s does not belong to the service because another user created it, so nothing was sent", t.events)
		case .None, .Bad_Url, .Timeout, .Io, .Bad_Reply, .No_Memory:
			err_line(io, "cannot follow the events at %s: %s", t.events, bus.call_error_string(serr))
		}
		return exit_for_call_error(serr)
	}
	defer bus.unsubscribe(&sub)

	reply, id, retried, err := call_op(c, t, "connect", nil)
	if err != .None {
		return report_call_error(c, io, t, err, id, retried)
	}
	if !reply.ok {
		defer bus.reply_destroy(&reply)
		print_error_reply(io, &reply)
		return exit_for_reply_code(reply.code)
	}
	f: Follow
	defer follow_destroy(&f)
	state, _ := json_str(reply.result, "state")
	first_done, first_code, _ := follow_state(io, &f, state, "", "")
	bus.reply_destroy(&reply)
	if first_done {
		return first_code
	}
	if done, code := follow_status(c, t, io, &f); done {
		return code
	}
	for !stop_requested(stop) {
		done, code, failed := follow_step(c, t, io, &sub, &f)
		if failed {
			err_line(io, "the connection to the event stream was lost")
			return .Failed
		}
		if done {
			return code
		}
		if f.waiting && time.diff(f.remind, time.now()) >= 0 {
			follow_left(io, &f)
		}
	}
	return .Ok
}

@(private = "file")
follow_step :: proc(c: ^Command, t: Target, io: ^Io, sub: ^bus.Subscriber, f: ^Follow) -> (done: bool, code: Exit, failed: bool) {
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
	ev, serr := bus.next_event(sub, EVENT_POLL)
	switch serr {
	case .None:
	case .Timed_Out, .Bad_Event:
		return false, .Ok, false
	case .Closed, .Io:
		return false, .Ok, true
	}
	defer bus.event_destroy(&ev)
	if ev.gap > 0 || ev.restarted {
		if d, cd := follow_status(c, t, io, f); d {
			return true, cd, false
		}
	}
	switch ev.topic {
	case "client.state":
		state, _ := json_str(ev.data, "state")
		reason, _ := json_str(ev.data, "reason")
		detail, _ := json_str(ev.data, "detail")
		return follow_state(io, f, state, reason, detail)
	case "client.auth_needed":
		kind, _ := json_str(ev.data, "kind")
		if kind == "web_auth" {
			d, cd := follow_status(c, t, io, f)
			return d, cd, false
		}
		out_text(io, "the daemon is asking for a user name and password, which you can give with noirvpnctl auth-supply\n")
	case "daemon.stop":
		out_text(io, "the daemon stopped\n")
		return true, .Error, false
	}
	return false, .Ok, false
}

// Prints a new state. Up and stopped end the run.
@(private = "file")
follow_state :: proc(io: ^Io, f: ^Follow, state, reason, detail: string) -> (done: bool, code: Exit, failed: bool) {
	if state == "" || state == f.state {
		return false, .Ok, false
	}
	delete(f.state)
	f.state = strings.clone(state)
	if state != "handshake" {
		f.waiting = false
	}
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "state: ")
	strings.write_string(&b, safe_text(state))
	if reason != "" {
		fmt.sbprintf(&b, " (%s", safe_text(reason))
		if detail != "" {
			fmt.sbprintf(&b, ": %s", safe_text(detail))
		}
		strings.write_byte(&b, ')')
	}
	strings.write_byte(&b, '\n')
	out_text(io, strings.to_string(b))
	switch state {
	case "up":
		return true, .Ok, false
	case "stopped":
		return true, .Error, false
	}
	return false, .Ok, false
}

// Reads `status`: the state, and the link of a web sign-in that waits.
@(private = "file")
follow_status :: proc(c: ^Command, t: Target, io: ^Io, f: ^Follow) -> (done: bool, code: Exit) {
	reply, err := bus.call(t.control, "status", nil, c.timeout)
	if err != .None || !reply.ok {
		bus.reply_destroy(&reply)
		return false, .Ok
	}
	defer bus.reply_destroy(&reply)
	cl := json_obj(reply.result, "client")
	state, _ := json_str(cl, "state")
	reason, _ := json_str(cl, "reason")
	detail, _ := json_str(cl, "detail")
	auth := json_obj(cl, "auth_needed")
	kind, _ := json_str(auth, "kind")
	if kind == "web_auth" && state == "handshake" {
		follow_state(io, f, state, "", "")
		follow_web(io, f, auth)
		return false, .Ok
	}
	d, cd, _ := follow_state(io, f, state, reason, detail)
	return d, cd
}

// Prints the link of a web sign-in, once for each link.
@(private = "file")
follow_web :: proc(io: ^Io, f: ^Follow, auth: json.Value) {
	url, has_url := json_str(auth, "url")
	host, _ := json_str(auth, "host")
	if ts, ok := json_str(auth, "deadline"); ok {
		if d, n := time.rfc3339_to_time_utc(ts); n > 0 {
			f.deadline = d
		}
	}
	f.waiting = true
	if has_url && url == f.url || !has_url && host == f.host && f.url == "" {
		return
	}
	delete(f.url)
	delete(f.host)
	f.url = strings.clone(url if has_url else "")
	f.host = strings.clone(host)
	if has_url {
		out_text(io, fmt.tprintf("web sign-in: open this link in a browser on this or another device:\n  %s\n", safe_text(url)))
	} else {
		out_text(io, fmt.tprintf("web sign-in at %s: this user is not allowed to see the link (only the owner of the profile and the admin role can see it)\n", safe_text(host)))
	}
	follow_left(io, f)
}

@(private = "file")
follow_left :: proc(io: ^Io, f: ^Follow) {
	left := time.diff(time.now(), f.deadline)
	secs := max(i64((left + time.Second - 1) / time.Second), 0)
	out_text(io, fmt.tprintf("  %d seconds left to sign in\n", secs))
	f.remind = time.time_add(time.now(), FOLLOW_REMIND)
}

@(private = "file")
json_obj :: proc(v: json.Value, k: string) -> json.Value {
	if o, ok := v.(json.Object); ok {
		if x, ok2 := o[k].(json.Object); ok2 {
			return x
		}
	}
	return nil
}

@(private = "file")
json_str :: proc(v: json.Value, k: string) -> (string, bool) {
	if o, ok := v.(json.Object); ok {
		if s, ok2 := o[k].(json.String); ok2 {
			return s, true
		}
	}
	return "", false
}
