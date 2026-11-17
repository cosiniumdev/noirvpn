// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package nng

// Tests that need no files: they run on every platform.

import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"

@(test)
version_is_1x :: proc(t: ^testing.T) {
	init()
	v := version()
	testing.expectf(t, strings.has_prefix(v, "1."), "unexpected nng version %q", v)
}

@(test)
split_topic_cases :: proc(t: ^testing.T) {
	topic, payload := split_topic(transmute([]byte)string(`peer.connect {"seq":1}`))
	testing.expect_value(t, topic, "peer.connect")
	testing.expect_value(t, string(payload), `{"seq":1}`)

	// No payload.
	topic, payload = split_topic(transmute([]byte)string("daemon.stop"))
	testing.expect_value(t, topic, "daemon.stop")
	testing.expect_value(t, len(payload), 0)

	// Separator at the end: empty payload.
	topic, payload = split_topic(transmute([]byte)string("daemon.stop "))
	testing.expect_value(t, topic, "daemon.stop")
	testing.expect_value(t, len(payload), 0)

	// Only the first space splits. Later spaces belong to the payload.
	topic, payload = split_topic(transmute([]byte)string("a.b c d"))
	testing.expect_value(t, topic, "a.b")
	testing.expect_value(t, string(payload), "c d")

	topic, payload = split_topic(nil)
	testing.expect_value(t, topic, "")
	testing.expect_value(t, len(payload), 0)
}

@(test)
error_values :: proc(t: ^testing.T) {
	testing.expect_value(t, Error(NNG_ETIMEDOUT), Error.Timed_Out)
	testing.expect(t, strings.contains(strings.to_lower(error_string(.Timed_Out), context.temp_allocator), "timed out"))

	// An OS error keeps its number.
	e := Error(NNG_ESYSERR | 13)
	testing.expect(t, is_system_error(e))
	testing.expect(t, !is_transport_error(e))
	testing.expect_value(t, system_errno(e), 13)
	testing.expect(t, !is_system_error(.Closed))
	testing.expect_value(t, system_errno(.Closed), 0)
}

@(test)
recv_timeout_is_an_error_value :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)

	sub, err := open(.Sub)
	testing.expect_value(t, err, Error.None)
	defer close(sub)
	testing.expect_value(t, subscribe(sub, ""), Error.None)
	testing.expect_value(t, set_recv_timeout(sub, 50 * time.Millisecond), Error.None)

	start := time.now()
	data, rerr := recv(sub)
	elapsed := time.since(start)
	testing.expect_value(t, rerr, Error.Timed_Out)
	testing.expect(t, data == nil)
	testing.expectf(t, elapsed >= 40 * time.Millisecond, "returned too early: %v", elapsed)
	testing.expectf(t, elapsed < 5 * time.Second, "returned too late: %v", elapsed)

	// recv_msg reports it the same way, and returns no message.
	m, merr := recv_msg(sub)
	testing.expect_value(t, merr, Error.Timed_Out)
	testing.expect(t, m == nil)

	// A non-blocking receive does not wait at all.
	start = time.now()
	_, nerr := recv(sub, nonblock = true)
	testing.expect_value(t, nerr, Error.Try_Again)
	testing.expect(t, time.since(start) < 40 * time.Millisecond)

	// No timeout is set by default, but a negative duration clears one.
	testing.expect_value(t, set_recv_timeout(sub, -1), Error.None)
}

@(test)
request_times_out_without_server :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)

	req, err := open(.Req)
	testing.expect_value(t, err, Error.None)
	defer close(req)
	testing.expect_value(t, set_recv_timeout(req, 100 * time.Millisecond), Error.None)
	testing.expect_value(t, set_send_timeout(req, 100 * time.Millisecond), Error.None)
	testing.expect_value(t, set_req_resend_time(req, 30 * time.Second), Error.None)

	// A REQ send only completes when the request reaches a connection. With
	// no server connected it waits, so a client must set a send timeout.
	start := time.now()
	reply, cerr := call(req, transmute([]byte)string(`{"req":"status"}`))
	testing.expect_value(t, cerr, Error.Timed_Out)
	testing.expect(t, reply == nil)
	testing.expect(t, time.since(start) < 5 * time.Second)
}

@(test)
closing_wakes_a_blocked_receiver :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)

	rep, err := open(.Rep)
	testing.expect_value(t, err, Error.None)

	Shared :: struct {
		sock: Socket,
		err:  Error,
	}
	shared := Shared {
		sock = rep,
	}
	th := thread.create_and_start_with_data(&shared, proc(p: rawptr) {
		s := (^Shared)(p)
		_, s.err = recv_msg(s.sock)
	}, context)
	time.sleep(50 * time.Millisecond)
	testing.expect_value(t, close(rep), Error.None)
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, shared.err, Error.Closed)
}
