// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "noir:proto/push"

// Events tell the caller what happened in the engine. They sit in a small ring
// inside the session. Read them with `session_next_event` after every call that
// can create one (receive, tick, poll, close, rekey).
EVENT_RING :: 32
EVENT_TEXT_MAX :: 240

Event_Kind :: enum u8 {
	None,
	// The server's first reset was accepted: the link works both ways. The
	// TLS handshake starts now.
	Link_Up,
	// The first PUSH_REPLY is complete and valid, the data keys are installed.
	// Now open the tun device and apply addresses, routes and DNS from
	// `session_pushed`.
	Up,
	// A data key was installed. `key_id` is the id; `by_peer` tells who
	// started the renegotiation. Raised for each later key; the first key is part of `Up`.
	Key_Installed,
	// A renegotiation began (soft reset sent or received).
	Rekey_Started,
	// The server pushed a new auth-token. The token is not in the event: use
	// `session_auth_token`.
	Token_Updated,
	// The server asked for more time (`AUTH_PENDING`). `timeout` is seconds.
	Auth_Pending,
	// `INFO` text from the server (in `text`).
	Info,
	// The server refused the login. `auth_kind` and `text` tell how. The session
	// is then failed (`reason` .Auth_Failed). `token_dropped`: the session held an
	// auth-token that must not be used again.
	// Server: AUTH_FAILED was sent (`auth_kind`, `text`, `backoff`). The session
	// closes after the client acked it or 5 s, with a `Closed` event.
	Auth_Failed,
	// The server said RESTART or HALT. The session is failed.
	Restart,
	Halt,
	// The peer announced that it is leaving (EXIT command or OCC exit). A
	// server keeps the session for 5 s to ack retransmits, then raises `Closed`.
	Remote_Exit,
	// A graceful close finished (`session_close`).
	Closed,
	// The session cannot go on. `reason` tells why; `text` has detail.
	Failed,
	// Server: the client's key-method message is read, the login waits for the
	// caller. Read details with `session_auth_request`, reply with
	// `session_server_accept` or `session_server_reject`. `key_id` is the key state
	// (0 for the first login; above 0 only with `reauth`).
	Auth_Request,
	// Server (UDP): an authenticated data packet came from another source address
	// than the session's. `text` holds the new address in `peer_addr_v4` form
	// (`event_addr`). Check that no other peer has it, then call
	// `session_server_set_remote`. The packet was handled normally.
	Float_Candidate,
	// Client: `INFO_PRE` from the server, such as a web sign-in URL. The text is
	// not in the event: read it with `session_info_pre`.
	Info_Pre,
}

Fail_Reason :: enum u8 {
	None,
	// Handshake or push did not finish in `hand-window`. A server also uses
	// it when the caller does not reply to `Auth_Request` in time.
	Hand_Window,
	// TLS failed: bad certificate, pin refused, alert, protocol error.
	Tls,
	// TLS failed because a certificate of the peer is revoked (`crl-verify`).
	Cert_Revoked,
	// TLS failed because of the CRL list: it is not loaded, a CRL has expired or
	// is not valid yet, or a CRL signature is bad.
	Crl_Failed,
	// A message of the key-method exchange is wrong.
	Key_Method,
	// The server refused the login.
	Auth_Failed,
	// The PUSH_REPLY text is broken or an option causes us to refuse it.
	Push,
	// No PUSH_REPLY in time.
	No_Push_Reply,
	// The server did not select TLS-EKM, or the export failed.
	Key_Export,
	// A control or framing error on TCP, which ends the connection.
	Link_Error,
	// Nothing authenticated arrived for `ping-restart` seconds.
	Ping_Timeout,
	// The server sent RESTART, HALT or EXIT.
	Server_Signal,
	// The peer's control state is wrong in a way we cannot repair.
	Protocol,
	// The crypto library or a buffer failed.
	Internal,
}

Event :: struct {
	kind:             Event_Kind,
	key_id:           u8,
	by_peer:          bool,
	reason:           Fail_Reason,
	// Auth_Failed
	auth_kind:        push.Auth_Failed_Kind,
	token_dropped:    bool,
	// Auth_Failed (TEMP), Restart, Halt
	backoff:          int, // seconds, 0 if none
	advance:          push.Temp_Advance,
	keep_credentials: bool,
	next_remote:      bool,
	// Auth_Pending
	timeout:          int,
	text_len:         u8,
	text:             [EVENT_TEXT_MAX]u8,
}

// The text of an event. A slice of the event: copy it if you keep it.
event_text :: proc "contextless" (ev: ^Event) -> string {
	return string(ev.text[:ev.text_len])
}

// The address of a `Float_Candidate` event, in the form of `peer_addr_v4`.
event_addr :: proc "contextless" (ev: ^Event) -> []u8 {
	return ev.text[:ev.text_len]
}

@(private)
event_set_text :: proc(ev: ^Event, text: string) {
	n := min(len(text), EVENT_TEXT_MAX)
	copy(ev.text[:n], text[:n])
	ev.text_len = u8(n)
}

@(private)
emit :: proc(s: ^Session, ev: Event) {
	if s.ev_count == EVENT_RING {
		// Drop the oldest. The kinds that end a session are rare, so a full
		// ring does not hide them for long.
		s.ev_head = (s.ev_head + 1) % EVENT_RING
		s.ev_count -= 1
		s.counters.events_dropped += 1
	}
	s.ev_ring[(s.ev_head + s.ev_count) % EVENT_RING] = ev
	s.ev_count += 1
}

// Takes the next event. Returns false when there is none.
session_next_event :: proc(s: ^Session) -> (ev: Event, ok: bool) {
	if s.ev_count == 0 {
		return {}, false
	}
	ev = s.ev_ring[s.ev_head]
	s.ev_head = (s.ev_head + 1) % EVENT_RING
	s.ev_count -= 1
	return ev, true
}
