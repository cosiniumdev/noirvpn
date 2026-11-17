// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:time"
import "noir:proto/ossl"
import "noir:proto/keys"
import "noir:proto/push"
import "noir:proto/reliable"

// Runs everything that depends on the clock: retransmit and hand-window
// failures, PUSH_REQUEST, the push deadline, key expiry, keepalive failure,
// time-based rekey, the end of a close. Call it when `session_next_wakeup` says
// so, and after any call that moved the clock a lot. Then call `session_poll_tx`.
session_tick :: proc(s: ^Session, now: Time) {
	switch s.state {
	case .New, .Closed, .Failed:
		return
	case .Connecting, .Handshaking, .Up, .Closing:
	}
	check_chan(s, now)
	if s.state == .Failed {
		return
	}
	ks := &s.ks
	// Key 0: ask for the push, and give up when no reply comes.
	if ks.push_req_on && !ks.push_done && now >= ks.push_req_at && ks.tls_ok {
		buf: [16]u8
		n, ferr := push.cmd_frame(buf[:], "PUSH_REQUEST")
		if ferr == .None && ossl.tls_write_app(&ks.tls, buf[:n]) == .Ok {
			flush_tls(s, now)
		}
		ks.push_req_at = now + HANDSHAKE_REQUEST_REPEAT
	}
	if s.push_deadline_on && !ks.push_done && now >= s.push_deadline {
		fail(s, .No_Push_Reply, "the server did not send a PUSH_REPLY in time")
		return
	}
	if s.srv.auth_wait && ks.auth == .Requested && now >= s.srv.auth_at {
		fail(s, .Hand_Window, "the server did not respond to the login request")
		return
	}
	if s.state == .Up || s.state == .Closing {
		// Keys whose transition window ended.
		if dropped := keys.slots_expire(&s.slots, now); dropped != {} {
			cmd := Dp_Cmd {
				kind = .Expire,
				now  = now,
			}
			dp_send(s, &cmd)
		}
		if s.ping_restart > 0 && now - s.last_rx >= time.Duration(s.ping_restart) * time.Second {
			fail(s, .Ping_Timeout, "no packets from the peer (ping-restart)")
			return
		}
		maybe_rekey(s, now)
	}
	close_progress(s, now)
	progress(s, now)
}

// When `session_tick` should run next. Returns false if nothing is scheduled
// (the session has not started, or is over).
session_next_wakeup :: proc(s: ^Session, now: Time) -> (at: Time, ok: bool) {
	switch s.state {
	case .New, .Closed, .Failed:
		return 0, false
	case .Connecting, .Handshaking, .Up, .Closing:
	}
	consider :: proc(at: ^Time, ok: ^bool, t: Time) {
		if !ok^ || t < at^ {
			at^ = t
			ok^ = true
		}
	}
	ks := &s.ks
	if ks.chan_ok {
		if t, have := reliable.next_wakeup(&ks.chan, now); have {
			consider(&at, &ok, t)
		}
	}
	if ks.push_req_on && !ks.push_done {
		consider(&at, &ok, ks.push_req_at)
	}
	if s.push_deadline_on && !ks.push_done {
		consider(&at, &ok, s.push_deadline)
	}
	if s.srv.auth_wait && ks.auth == .Requested {
		consider(&at, &ok, s.srv.auth_at)
	}
	if s.state == .Up || s.state == .Closing {
		if t, have := keys.slots_next_expiry(&s.slots); have {
			consider(&at, &ok, t)
		}
		if s.ping > 0 {
			consider(&at, &ok, s.last_tx + time.Duration(s.ping) * time.Second)
		}
		if s.ping_restart > 0 {
			consider(&at, &ok, s.last_rx + time.Duration(s.ping_restart) * time.Second)
		}
		if _, established, have := keys.slots_primary(&s.slots); have && !s.rekeying && s.reneg_eff > 0 {
			consider(&at, &ok, established + time.Duration(s.reneg_eff) * time.Second)
		}
	}
	if s.state == .Closing {
		if s.exit_cc {
			consider(&at, &ok, s.exit_deadline)
		} else if s.exit_left > 0 {
			consider(&at, &ok, s.exit_next)
		} else {
			consider(&at, &ok, now)
		}
	}
	if ok && at < now {
		at = now
	}
	return at, ok
}
