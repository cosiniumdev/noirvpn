// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:time"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/sysnet"
import "noir:platform/tlslink"
import "noir:proto/config"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/reliable"
import "noir:proto/session"
import "noir:server"

// One client session of the server, first packet to end: the session object,
// how to reach the client, and the link to the peer table.
//
//   first packet -> conn_new -> (session: TLS, key exchange) -> Auth_Request
//     -> srv_auth_request: decision, kicks, addresses, accept or refuse
//     -> Up -> ... -> Remote_Exit / Closed / Failed / a kick -> conn_release
//
// `conn_pump` is the only place that reads session events and sends its packets.
// A conn that ends inside `conn_pump` is released when the pump is done. After
// calling it, do not touch the conn unless the call says it is alive.

End_Reason :: enum u8 {
	None,
	Closed,
	Client_Exit,
	// Replaced by a new login of the same name.
	Kicked,
	// Replaced by a new login with the same key (a pin session).
	Kicked_Key,
	// `peer.kick` on the control bus.
	Admin_Kick,
	Revoked,
	Shutdown,
	Limit,
	Timeout,
	Failed,
	// The user is not in the password file any more, or its hash changed.
	Password_Gone,
	Password_Changed,
	// A renegotiation of a password session failed its check.
	Reauth_Refused,
	// A renegotiation failed on the certificate of the client: it is revoked
	// (`Cert_Revoked`) or the CRL list failed (`Crl_Failed`).
	Cert_Revoked,
	Crl_Failed,
	Refused,
	Tcp_Lost,
	Slow,
	// The data path changed under the session (the DCO service was lost).
	Datapath,
	// The lifetime of the session token of a web sign-in ended.
	Sign_In_Ended,
}

end_text :: proc "contextless" (r: End_Reason) -> string {
	switch r {
	case .None:
		return "closed"
	case .Closed:
		return "closed"
	case .Client_Exit:
		return "client exit"
	case .Kicked:
		return "replaced by a new login of the same name"
	case .Kicked_Key:
		return "replaced by a new login with the same key"
	case .Admin_Kick:
		return "kicked by an administrator"
	case .Revoked:
		return "key removed or disabled"
	case .Shutdown:
		return "server stop"
	case .Limit:
		return "session-timeout"
	case .Timeout:
		return "ping timeout"
	case .Failed:
		return "session failed"
	case .Cert_Revoked, .Crl_Failed:
		return "renegotiation refused"
	case .Password_Gone:
		return "user removed from the password file"
	case .Password_Changed:
		return "password changed"
	case .Reauth_Refused:
		return "login refused at a renegotiation"
	case .Refused:
		return "login refused"
	case .Tcp_Lost:
		return "connection lost"
	case .Slow:
		return "not reading (slow TCP client)"
	case .Datapath:
		return "the data path changed"
	case .Sign_In_Ended:
		return "the sign-in lifetime ended"
	}
	return "?"
}

Conn :: struct {
	slot:       u32,
	s:          session.Session,
	s_ok:       bool,
	proto:      config.Proto,
	lidx:       u8,
	// UDP: where to send. TCP: the client's address, for the log.
	ep:         net.Endpoint,
	// UDP: the local address the client sends to; every packet to the client leaves
	// from it. Set from the first packet, moved by an authenticated data packet from
	// another address (`conn_follow_local`). Empty: the kernel does not report it.
	// TCP: the address of the accepted socket (it goes to the DCO service).
	local:      net.Local,
	addr:       session.Peer_Addr,
	key:        server.Addr_Key,
	sid:        reliable.Sid,
	sid_set:    bool,
	// Crypto workers: the one that has this session's data channel, and the
	// bytes of sealed packets that wait for it (for the TCP queue policy).
	wkr:        ^Wk_Worker,
	tx_wait:    int,
	// TCP.
	sock:       net.Socket,
	sock_open:  bool,
	// A connection on a `tls-server` listener first waits for its first bytes
	// (`classify`, tls_transport.odin): TLS client or raw OpenVPN. No session and
	// no TLS state exist until then.
	classify:   bool,
	// A `tls` connection (tls_transport.odin): the stream runs inside an outer
	// TLS stream. `tls_hs`: its handshake is not done; the login starts after it.
	tls:        bool,
	tls_hs:     bool,
	tls_routed: bool, // mixed server: the routes of this tls client are on the second device
	uroutes:    [dynamic]sysnet.Route, // kernel routes that this process created for the iroutes of the client (userspace data path)
	// `tls-transport-ws` (ws_server.odin): state of the conn's plaintext stream.
	//   .Classify - first plaintext bytes not seen yet
	//   .Request  - an HTTP request is coming in
	//   .On       - the stream runs in WebSocket frames
	ws_phase:   Ws_Phase,
	ws:         ^Ws_Conn,
	link:       ^tlslink.Link,
	link_out:   []u8,
	q:          Txq,
	want_write: bool,
	dirty:      bool,
	slow_since: time.Duration,
	// The peer table.
	dco:        Dco_Owner, // the data channel on a DCO service (server_dco.odin)
	h:          server.Peer_Handle,
	registered: bool,
	name:       server.Identity,
	named:      bool,
	// Where the name came from (`identity_source` on the bus).
	idsrc:      server.Identity_Source,
	mss4:       int, // the IPv4 TCP MSS to clamp SYNs to (mssfix.odin); 0: no clamp
	cipher:     push.Cipher,
	data_format: string, // "baseline" or "epoch" (the aead-epoch flag of this session)
	// State.
	up:         bool,
	in_pump:    bool,
	release:    bool,
	releasing:  bool, // `conn_release` is running
	closing:    bool,
	end:        End_Reason,
	fail:       [session.EVENT_TEXT_MAX]u8,
	fail_n:     int,
	created:    time.Duration,
	up_at:      time.Duration,
	limit_secs: int,
	limit_at:   time.Duration,
	t:          Timer,
	rekeys:     u64,
	// The control bus: the session id is "s-<sess>".
	sess:       u64,
	peer_id:    u32,
	vpn4:       Maybe([4]u8),
	vpn6:       Maybe([16]u8),
	pin:        [config.PIN_LEN]u8,
	has_pin:    bool,
	up_wall:    time.Time,
	// The login waits for a controller (`auth-external`).
	parked:     bool,
	park_until: time.Duration,
	park_dec:   server.Decision,
	// Hash file check (server_password.odin).
	//   pw_wait - a check runs, or the refusal of a failed one waits (`pw_delay`);
	//             the session counts as parked for `max-clients`
	//   pw_has  - the session passed a check; `pw_user` is its name in the file,
	//             `pw_line` a digest of its hash line
	pw_wait:    bool,
	pw_delay:   bool,
	pw_rekey:   bool,
	pw_job:     ^Pw_Job,
	pw_dec:     server.Decision,
	pw_has:     bool,
	pw_user:    server.Identity,
	pw_line:    [32]u8,
	// `auth.credentials` was replied to for this session, or the password was a
	// session token (it is never given out).
	creds_read: bool,
	// Web sign-in (server_web.odin).
	//   web_auth   - the client said IV_SSO=webauth
	//   user_given - it sent a user name
	//   token_end  - Unix second when the session token ends (0: no token)
	//   web_at     - the same instant on the daemon's clock, once the session is up
	web_auth:   bool,
	user_given: bool,
	token_end:  u32,
	// The sign-in (in `Srv.signins`) that the token of the session belongs to.
	token_id:   Token_Id,
	web_at:     time.Duration,
	// The proofs that let the client in (the events show them).
	proofs:     server.Proof_Set,
	// The push lines a controller added, joined by "\n".
	push_text:  string,
	// Why the controller ended it (peer.kick `reason`), for peer.disconnect.
	detail:     [128]u8,
	detail_n:   int,
	// A TLS pin check refused this client (unknown or disabled key).
	refusal:    server.Pin_Refusal,
	refusal_key: [config.PIN_LEN]u8,
	// The bus has seen peer.handshake, auth.fail, peer.connect, peer.disconnect.
	ev_handshake: bool,
	ev_fail:     bool,
	ev_connect:  bool,
	ev_disconnect: bool,
	// What crossed the tunnel for this client.
	in_pkts:    u64, // from the client
	in_bytes:   u64,
	out_pkts:   u64, // to the client
	out_bytes:  u64,
	drops:      u64,
}

// The name for logs: the identity once the login passed, then the address.
conn_label :: proc(c: ^Conn) -> string {
	where_ := endpoint_text(c.ep)
	if c.named {
		return fmt.tprintf("%s [%s]", server.identity_str(&c.name), where_)
	}
	return fmt.tprintf("[%s]", where_)
}

// ------------------------------------------------------------- the table

// A new conn for a first packet (UDP) or an accepted connection (TCP). Nil if
// the table is full or memory runs out.
conn_new :: proc(d: ^Srv, proto: config.Proto, lidx: u8, ep: net.Endpoint, local := net.Local{}) -> ^Conn {
	if len(d.free_slots) == 0 {
		return nil
	}
	c := new(Conn)
	if c == nil {
		return nil
	}
	slot := pop(&d.free_slots)
	c.slot = slot
	c.proto = proto
	c.lidx = lidx
	c.ep = ep
	c.local = local
	c.addr = endpoint_peer_addr(ep)
	c.key = endpoint_key(ep, lidx)
	c.sock = net.INVALID_SOCKET
	c.created = now_srv(d)
	d.next_sess += 1
	c.sess = d.next_sess
	d.conns[slot] = c
	d.n_conns += 1
	return c
}

// Frees the memory of a conn that is not in the table any more (or that
// `srv_destroy` finds left over).
conn_free :: proc(d: ^Srv, c: ^Conn) {
	srv_pw_cancel(d, c)
	if c.s_ok {
		session.session_destroy(&c.s)
	}
	if c.sock_open {
		net.close(c.sock)
	}
	conn_free_stream(c)
	delete(c.push_text)
	free(c)
}

// Frees what a TCP conn holds for its stream: the outer TLS, the send queue, the
// WebSocket layer.
conn_free_stream :: proc(c: ^Conn) {
	if c.link != nil {
		tlslink.link_destroy(c.link)
		free(c.link)
		delete(c.link_out)
		c.link = nil
	}
	if len(c.q.buf) > 0 {
		txq_destroy(&c.q)
	}
	srv_ws_free(c)
}

// Ends a conn: last packets go out, the peer table entry goes, the socket
// closes, memory is freed. Safe to call twice. Inside `conn_pump` it only marks
// the conn; the pump does the rest.
conn_release :: proc(d: ^Srv, c: ^Conn) {
	if c.in_pump {
		c.release = true
		return
	}
	if d.conns[c.slot] != c || c.releasing {
		return
	}
	c.releasing = true
	if c.parked {
		srv_unpark_end(d, c, "the client left")
	}
	srv_pw_cancel(d, c)
	conn_drain_tx(d, c)
	if c.proto == .Tcp && c.sock_open {
		tcp_write_now(c)
	}
	if !c.named && c.end != .None && c.end != .Closed {
		logf(.Info, "handshake with %s ended: %s", conn_label(c), end_reason_detail(c))
	}
	conn_unregister(d, c)
	if c.sid_set {
		delete_key(&d.sid_map, c.sid)
		c.sid_set = false
	}
	stimer_clear(&d.loop, &c.t)
	if c.dirty {
		for i in 0 ..< len(d.dirty) {
			if d.dirty[i] == c.slot {
				unordered_remove(&d.dirty, i)
				break
			}
		}
	}
	if c.sock_open {
		if c.link != nil {
			// A goodbye to the outer TLS (best effort), then the socket closes.
			tlslink.link_close(c.link)
		}
		event.remove_fd(&d.loop, c.sock.fd)
		net.close(c.sock)
		c.sock_open = false
	}
	srv_dco_forget(d, c)
	if c.s_ok {
		srv_dco_refresh_conn(d, c)
		counters := session.session_counters(&c.s)
		counters_add(&d.agg, counters)
		session.session_destroy(&c.s)
		c.s_ok = false
	}
	d.conns[c.slot] = nil
	append(&d.free_slots, c.slot)
	d.n_conns -= 1
	if c.up {
		d.ended.in_pkts += c.in_pkts
		d.ended.in_bytes += c.in_bytes
		d.ended.out_pkts += c.out_pkts
		d.ended.out_bytes += c.out_bytes
	}
	delete(c.push_text)
	conn_free_stream(c)
	free(c)
	if d.stopping && d.n_conns == 0 {
		srv_finish(d)
	}
}

end_reason_detail :: proc(c: ^Conn) -> string {
	if c.fail_n > 0 {
		return fmt.tprintf("%s: %s", end_text(c.end), string(c.fail[:c.fail_n]))
	}
	return end_text(c.end)
}

// Takes the client out of the peer table: addresses and routes are free again,
// the peer leaves the backend (the session lingers for the control channel
// only). Logs the disconnect. Does nothing if the client is not in it.
// `keep_peer` leaves the backend peer to the caller, who must call
// `srv_dco_peer_release` soon (a goodbye on a stream goes through it).
conn_unregister :: proc(d: ^Srv, c: ^Conn, keep_peer := false) {
	if !c.registered {
		return
	}
	srv_dco_refresh_conn(d, c)
	srv_dco_iroutes(d, c, false)
	srv_tls_routes(d, c, false)
	srv_user_iroutes(d, c, false)
	c.registered = false
	server.server_disconnect(&d.srv, c.h, now_srv(d))
	if !keep_peer {
		srv_dco_peer_release(d, c)
	}
	if c.up {
		srv_ev_disconnect(d, c)
		d.stats.disconnects += 1
		secs := int((now_srv(d) - c.up_at) / time.Second)
		logf(
			.Notice,
			"client %s disconnected (%s) after %d s: from client %d pkts/%d bytes, to client %d pkts/%d bytes",
			conn_label(c), end_reason_detail(c), secs, c.in_pkts, c.in_bytes, c.out_pkts, c.out_bytes,
		) // fmt: skip
	} else {
		logf(.Notice, "client %s disconnected before the tunnel came up (%s)", conn_label(c), end_reason_detail(c))
	}
}

// ----------------------------------------------------------------- the pump

// Sends all the session wants to say, after any call into it: link packets,
// then events (which may queue more), until nothing is left. Returns false if
// the conn ended and was released. With `arm` false the session timer stays
// unless something happened (data packets cannot move a deadline earlier).
conn_pump :: proc(d: ^Srv, c: ^Conn, arm := true) -> (alive: bool) {
	if c.in_pump {
		return true
	}
	srv_note_refusal(d, c)
	c.in_pump = true
	did := false
	for _ in 0 ..< 8 {
		if conn_drain_tx(d, c) > 0 {
			did = true
		}
		srv_dco_check(d, c)
		handled := 0
		for !c.release {
			ev, ok := session.session_next_event(&c.s)
			if !ok {
				break
			}
			handled += 1
			conn_on_event(d, c, &ev)
		}
		if handled > 0 {
			did = true
		}
		if handled == 0 || c.release {
			break
		}
	}
	if conn_drain_tx(d, c) > 0 {
		did = true
	}
	c.in_pump = false
	if c.release {
		conn_release(d, c)
		return false
	}
	if arm || did {
		conn_arm_timer(d, c)
	}
	return true
}

// Sends the packets the session has queued. Returns how many.
conn_drain_tx :: proc(d: ^Srv, c: ^Conn) -> (n: int) {
	if !c.s_ok {
		return 0
	}
	for _ in 0 ..< 10000 {
		size := session.session_poll_tx(&c.s, d.link[:], now_srv(d))
		if size == 0 {
			return
		}
		n += 1
		conn_send_ctl(d, c, d.link[:size])
	}
	return
}

// Last look at a conn's output (before the daemon ends).
conn_flush_ctl :: proc(d: ^Srv, c: ^Conn) {
	conn_drain_tx(d, c)
	if c.proto == .Tcp && c.sock_open {
		tcp_write_now(c)
	}
}

arm_conn_limit :: proc(c: ^Conn, at: ^time.Duration, ok: ^bool) {
	if c.limit_at != 0 && (!ok^ || c.limit_at < at^) {
		at^ = c.limit_at
		ok^ = true
	}
	if c.web_at != 0 && (!ok^ || c.web_at < at^) {
		at^ = c.web_at
		ok^ = true
	}
}

// The timer of a parked session wakes at the earlier of the session's own
// deadline and the end of the wait for the controller.
// `at` and `ok` are what the session wants (`ok` false: nothing).
park_wake :: proc "contextless" (at: time.Duration, ok: bool, parked: bool, until: time.Duration) -> (time.Duration, bool) {
	if parked && (!ok || until < at) {
		return until, true
	}
	return at, ok
}

// True when the wait for the controller is over. Checked before the session's
// own tick: its hand window ends at the same instant and must not win.
park_due :: proc "contextless" (parked: bool, until, now: time.Duration) -> bool {
	return parked && now >= until
}

conn_arm_timer :: proc(d: ^Srv, c: ^Conn) {
	if (c.tls_hs || c.classify || c.ws_phase == .Request) && !d.finished {
		// The first-byte wait, outer handshake and HTTP request of a WebSocket client
		// use the handshake window. The session has no deadline yet (for a tls conn,
		// none for this step).
		stimer_set(&d.loop, &c.t, c.created + time.Duration(d.cfg.tls.hand_window) * time.Second, on_conn_timer, c)
		return
	}
	if !c.s_ok || d.finished {
		stimer_clear(&d.loop, &c.t)
		return
	}
	at, ok := session.session_next_wakeup(&c.s, now_srv(d))
	arm_conn_limit(c, &at, &ok)
	at, ok = park_wake(at, ok, conn_waits(c), c.park_until)
	if !ok {
		stimer_clear(&d.loop, &c.t)
		return
	}
	stimer_set(&d.loop, &c.t, at, on_conn_timer, c)
}

on_conn_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := &SV
	c := (^Conn)(user)
	c.t.on = false
	if d.finished {
		return
	}
	if c.classify {
		if d.listeners[c.lidx].tls {
			// Nothing came in the time of the handshake window: counted as a stalled outer handshake.
			d.stats.outer_failed += 1
			logf(.Info, "outer TLS handshake with %s timed out", conn_label(c))
		} else {
			logf(.Info, "connection from %s sent nothing within the handshake window", conn_label(c))
		}
		conn_drop(d, c)
		return
	}
	if c.ws_phase == .Request {
		d.stats.outer_failed += 1
		logf(.Info, "websocket request from %s timed out", conn_label(c))
		conn_drop(d, c)
		return
	}
	if !c.s_ok {
		return
	}
	if c.tls_hs {
		d.stats.outer_failed += 1
		logf(.Info, "outer TLS handshake with %s timed out", conn_label(c))
		conn_drop(d, c)
		return
	}
	now := now_srv(d)
	if park_due(conn_waits(c), c.park_until, now) {
		// Before the session's own deadline (the same instant): no response is a deny.
		if c.pw_wait {
			srv_pw_timer(d, c)
		} else {
			srv_park_timeout(d, c)
		}
		return
	}
	if c.limit_at != 0 && now >= c.limit_at && c.up && !c.closing {
		logf(.Notice, "client %s reached its session-timeout", conn_label(c))
		conn_close(d, c, .Exit, .Limit)
		return
	}
	if c.web_at != 0 && now >= c.web_at && !c.closing {
		srv_web_end(d, c)
		return
	}
	session.session_tick(&c.s, now)
	if !conn_pump(d, c) {
		return
	}
	if c.proto == .Tcp {
		tcp_flush_conn(d, c)
	}
}

// ---------------------------------------------------------------- closing

// The server ends this client: it leaves the peer table at once (address and
// routes free for a new login); the session says goodbye (EXIT, RESTART or
// HALT) and lingers until acknowledged.
conn_close :: proc(d: ^Srv, c: ^Conn, kind: session.Close_Kind, why: End_Reason) {
	if c.closing || d.conns[c.slot] != c {
		return
	}
	if c.classify || (c.ws_phase == .Request && !c.s_ok) {
		// Nothing was said yet and there is no session to say goodbye with.
		conn_drop(d, c)
		return
	}
	c.closing = true
	if c.end == .None {
		c.end = why
	}
	if c.parked {
		srv_unpark_end(d, c, end_text(why))
	}
	srv_pw_cancel(d, c)
	conn_unregister(d, c, keep_peer = true)
	if c.s_ok {
		session.session_close(&c.s, now_srv(d), kind)
	}
	if conn_pump(d, c) {
		// The goodbye is out: the backend peer can go (its stream needs it for the goodbye).
		srv_dco_peer_release(d, c)
		if c.proto == .Tcp {
			tcp_flush_conn(d, c)
		}
	}
}

// Closes the session of a peer-table handle (a kick). A handle with no conn is
// just removed from the table.
conn_close_handle :: proc(d: ^Srv, h: server.Peer_Handle, kind: session.Close_Kind, why: End_Reason) {
	p := server.peers_get(&d.srv.reg.peers, h)
	if p == nil {
		return
	}
	slot := p.user
	d.stats.kicks += 1
	if slot < u64(len(d.conns)) && d.conns[slot] != nil && d.conns[slot].h == h {
		conn_close(d, d.conns[slot], kind, why)
		return
	}
	server.server_disconnect(&d.srv, h, now_srv(d))
}

// ----------------------------------------------------------------- events

conn_on_event :: proc(d: ^Srv, c: ^Conn, ev: ^session.Event) {
	switch ev.kind {
	case .None, .Rekey_Started, .Token_Updated, .Auth_Pending, .Info, .Info_Pre, .Restart, .Halt:
	case .Link_Up:
		logf(.Debug, "%s: link up", conn_label(c))
	case .Auth_Request:
		srv_auth_request(d, c)
	case .Up:
		conn_on_up(d, c)
	case .Key_Installed:
		c.rekeys += 1
		logf(.Info, "client %s: new data key %d installed (%s)", conn_label(c), ev.key_id, "started by the client" if ev.by_peer else "started by us")
		srv_ev_rekey(d, c, ev.key_id, ev.by_peer)
	case .Float_Candidate:
		conn_float(d, c, session.event_addr(ev))
	case .Remote_Exit:
		if c.end == .None {
			c.end = .Client_Exit
		}
		logf(.Info, "client %s sent its exit notice", conn_label(c))
		conn_unregister(d, c)
	case .Auth_Failed:
		// We refused the login (`srv_refuse` counted and logged it).
		if c.end == .None {
			c.end = .Refused
		}
	case .Closed:
		if c.end == .None {
			c.end = .Closed
		}
		conn_unregister(d, c)
		c.release = true
	case .Failed:
		text := session.event_text(ev)
		c.fail_n = copy(c.fail[:], text)
		if c.end == .None {
			switch {
			case ev.reason == .Ping_Timeout:
				c.end = .Timeout
			case c.up && ev.reason == .Cert_Revoked:
				c.end = .Cert_Revoked
			case c.up && ev.reason == .Crl_Failed:
				c.end = .Crl_Failed
			case:
				c.end = .Failed
			}
		}
		if !c.up && !c.named {
			d.stats.hs_failed += 1
			logf(.Notice, "handshake with %s failed: %s", conn_label(c), text)
			srv_ev_handshake_failed(d, c, text, ev.reason)
		}
		conn_unregister(d, c)
		c.release = true
	}
}

conn_on_up :: proc(d: ^Srv, c: ^Conn) {
	now := now_srv(d)
	c.up = true
	c.up_at = now
	c.up_wall = time.now()
	if n := session.session_crl_skipped(&c.s); n > 0 {
		logf(.Debug, "client %s: %d certificate(s) in the chain have no CRL from their issuer, so they are accepted", conn_label(c), n)
	}
	c.cipher = session.session_cipher(&c.s)
	c.data_format = session.session_data_format_name(&c.s)
	c.mss4 = srv_mss(d, c)
	if c.limit_secs > 0 {
		c.limit_at = now + time.Duration(c.limit_secs) * time.Second
	}
	if c.token_end != 0 {
		c.web_at = web_deadline(now, c.token_end, unix_now())
	}
	d.stats.connects += 1
	addrs := ""
	c.peer_id = session.session_peer_id(&c.s)
	if p := server.peers_get(&d.srv.reg.peers, c.h); p != nil {
		if p.has4 {
			c.vpn4 = p.vpn4
		}
		if p.has6 {
			c.vpn6 = p.vpn6
		}
		if p.has4 {
			addrs = fmt.tprintf("%d.%d.%d.%d", p.vpn4[0], p.vpn4[1], p.vpn4[2], p.vpn4[3])
		}
		if p.has6 {
			v := p.vpn6
			sep := "," if addrs != "" else ""
			addrs = fmt.tprintf(
				"%s%s%x:%x:%x:%x:%x:%x:%x:%x",
				addrs, sep,
				u16(v[0]) << 8 | u16(v[1]), u16(v[2]) << 8 | u16(v[3]), u16(v[4]) << 8 | u16(v[5]), u16(v[6]) << 8 | u16(v[7]),
				u16(v[8]) << 8 | u16(v[9]), u16(v[10]) << 8 | u16(v[11]), u16(v[12]) << 8 | u16(v[13]), u16(v[14]) << 8 | u16(v[15]),
			) // fmt: skip
		}
	}
	logf(
		.Notice,
		"client %s connected: %s via %s, address %s, data cipher %s, peer-id %d, data format %s, %d client(s)",
		conn_label(c), conn_proto(c), d.listeners[c.lidx].text, addrs,
		push.cipher_name(c.cipher), session.session_peer_id(&c.s), c.data_format, int(d.srv.reg.peers.count),
	) // fmt: skip
	srv_ev_connect(d, c)
}

// A data packet authenticated from another address (UDP): the client moved
// (NAT rebinding, new network). Follow it, unless another client has that address.
conn_float :: proc(d: ^Srv, c: ^Conn, addr: []u8) {
	if c.proto != .Udp || !c.registered {
		return
	}
	ep, ok := peer_addr_endpoint(addr)
	if !ok {
		return
	}
	key := endpoint_key(ep, c.lidx)
	if _, other := server.peers_by_addr(&d.srv.reg.peers, &key); other != nil {
		logf(.Notice, "client %s: not following the move to %s, because another client already uses that address", conn_label(c), endpoint_text(ep))
		return
	}
	old := conn_label(c)
	if _, err := server.server_float(&d.srv, c.h, key); err != .None {
		return
	}
	if !session.session_server_set_remote(&c.s, addr) {
		return
	}
	old_ep := c.ep
	c.ep = ep
	c.addr = endpoint_peer_addr(ep)
	c.key = key
	logf(.Notice, "client %s moved to %s", old, endpoint_text(ep))
	srv_ev_float(d, c, old_ep)
}

// The local address of a datagram as the conn keeps it: the interface is only
// kept with `multihome same-interface`.
srv_local :: proc(d: ^Srv, l: net.Local) -> net.Local {
	l := l
	if !d.cfg.multihome_same_iface {
		l.ifindex = 0
	}
	return l
}

// A data packet authenticated and came in at `local`. If the conn replies from
// another local address, the client changed the address it talks to: reply
// from the new one. Only an authenticated packet may do this.
conn_follow_local :: proc(d: ^Srv, c: ^Conn, local: net.Local) {
	if c.proto != .Udp || local.len == 0 || local == c.local {
		return
	}
	old := c.local
	c.local = local
	if old.len > 0 {
		a, _ := net.local_address(local)
		logf(.Notice, "client %s: now sends to %s, so the replies will be sent from there", conn_label(c), endpoint_text(net.Endpoint{address = a}))
	}
}

// ------------------------------------------------------------------- login

// The key-method message of a client is read: who, may it come in, what does it
// get. Replies to the session (accept or refuse), or parks it when a bus controller
// must decide (`auth-external`, server_auth_ext.odin).
srv_auth_request :: proc(d: ^Srv, c: ^Conn) {
	now := now_srv(d)
	req := &d.areq
	if !session.session_auth_request(&c.s, req) {
		return
	}
	defer d.areq = {}
	if req.key_id > 0 {
		srv_rekey_request(d, c, req)
		return
	}
	key, has_key := session.session_server_peer_key(&c.s)
	c.web_auth = web_sso_of(&req.peer_info)
	c.user_given = req.username != ""
	in_ := server.Auth_Input {
		key            = key,
		has_key        = has_key,
		cert_name      = req.common_name,
		// TLS ended in success: the proof says which check let the client in,
		// and `.None` that it sent no certificate (`verify-client-cert optional`).
		proof          = req.proof,
		username       = req.username,
		has_password   = req.password != "",
		web_auth       = c.web_auth,
		src            = c.key,
		parked         = d.parked + d.pw.waiting,
	}
	// A password with the form of a session token is never a password.
	look: Token_Look
	if d.cfg.auth_web && token_looks_like(req.password) {
		srv_token_look(d, req.password, &look)
		in_.token = look.state
		in_.token_identity = string(look.name[:look.name_n])
		session.session_server_wipe_password(&c.s)
		c.creds_read = true
	}
	dec := server.server_authorize(&d.srv, in_, now)
	c.proofs = dec.proofs
	srv_note_who(d, c, &dec, key, has_key)
	if dec.kind == .Reject {
		srv_refuse(d, c, dec.reject, "")
		return
	}
	if .Token in dec.proofs {
		c.token_end = look.end
		c.token_id = look.id
	}
	srv_ev_handshake(d, c)
	switch dec.kind {
	case .Pending_Password:
		srv_pw_login(d, c, req, &dec)
		return
	case .Pending_External:
		srv_park(d, c, req, &dec)
		return
	case .Accept, .Reject:
	}
	srv_login(d, c, &dec, "")
}

// What the login learned about the client: the name (when known) and the pin.
srv_note_who :: proc(d: ^Srv, c: ^Conn, dec: ^server.Decision, key: ossl.Peer_Key, has_key: bool) {
	if dec.identity.len > 0 {
		c.name = dec.identity
		c.named = true
		c.idsrc = dec.source
	}
	// A pin is only reported when the pins decide who may come in.
	if has_key && (server.auth_pins_decide(&d.srv.auth.policy) || dec.pinned) {
		c.pin = key.spki_sha256
		c.has_pin = true
	}
}

// Decision is Accept (or the controller said yes): replace old sessions of the
// same name, take addresses, reply to the session. `extra` is the
// client-config-dir text a controller added. On failure it refuses the client
// and returns why (`Reject` with `reason == .None` means success).
srv_login :: proc(d: ^Srv, c: ^Conn, dec: ^server.Decision, extra: string) -> (rej: server.Reject, detail: string) {
	now := now_srv(d)
	// A new login of a known name replaces the old session. Done before the
	// addresses are taken, so the new session can have the old one's.
	for i in 0 ..< dec.n_kicks {
		if dec.pinned {
			logf(.Notice, "client %s: new login from %s with the same key replaces the old session", server.identity_str(&dec.identity), conn_label(c))
			conn_close_handle(d, dec.kicks[i], .Exit, .Kicked_Key)
		} else {
			logf(.Notice, "client %s: new login from %s with the same name replaces the old session", server.identity_str(&dec.identity), conn_label(c))
			conn_close_handle(d, dec.kicks[i], .Exit, .Kicked)
		}
	}
	a, h, r, det := server.server_connect(&d.srv, dec, c.key, u64(c.slot), now, extra = extra)
	if r.reason != .None {
		srv_refuse(d, c, r, det)
		return r, det
	}
	defer server.assignment_destroy(&a)
	c.h = h
	c.registered = true
	c.limit_secs = a.session_timeout
	for n in a.notes {
		logf(.Info, "client %s: %s", conn_label(c), n)
	}

	cp: session.Client_Params
	cp.peer_id = a.peer_id
	server.assignment_push_params(&a, &cp.options)
	rest, ping, restart := split_keepalive(a.push)
	cp.options.extra = rest
	cp.options.ping = ping
	if ping == nil && d.cfg.ping > 0 {
		cp.options.ping = d.cfg.ping
	}
	cp.options.ping_restart = restart
	srv_token_push(d, c, &cp)
	cp.ping_restart_own = d.cfg.ping_restart
	if err := session.session_server_accept(&c.s, &cp, now); err != .None {
		logf(.Error, "client %s: cannot accept the login: %v (perhaps a pushed option could not be written)", conn_label(c), err)
		conn_unregister(d, c)
		ir := server.reject_make(.Internal)
		srv_refuse(d, c, ir, "")
		return ir, ""
	}
	if conn_in_service(d, c) && !srv_dco_peer(d, c) {
		// The login was accepted, so the client is not told no: the session
		// fails and the client sees the connection end.
		session.session_abort(&c.s, .Internal, fmt.tprintf("%s refused the peer", dco_who(d.dco.kind)))
		return {}, ""
	}
	if d.dco.mixed && c.tls && !srv_tls_routes(d, c, true) {
		// The same for a tls client whose host route cannot be created.
		session.session_abort(&c.s, .Internal, "the routes of the tls client could not be created")
		return {}, ""
	}
	srv_user_iroutes(d, c, true)
	logf(.Debug, "client %s: login accepted (peer-id %d)", conn_label(c), a.peer_id)
	return {}, ""
}

// The login is refused: log it, count it, tell the client (it only sees a
// generic text unless `client_text` is given), publish `auth.fail`.
srv_refuse :: proc(d: ^Srv, c: ^Conn, rej: server.Reject, detail: string, client_text := "") {
	d.stats.refused += 1
	if c.end == .None {
		c.end = .Refused
	}
	if c.parked {
		srv_unpark(d, c)
	}
	sep := ": " if detail != "" else ""
	logf(.Notice, "login of %s refused: %s%s%s", conn_label(c), server.reject_text(rej.reason), sep, detail)
	srv_ev_auth_fail(d, c, auth_fail_reason(rej.reason), auth_fail_detail(rej.reason, detail))
	kind := session.Reject_Kind.Plain
	#partial switch rej.kind {
	case .Auth_Failed_Temp:
		kind = .Temp
	case .Auth_Failed_Session:
		kind = .Session
	}
	text := client_text if client_text != "" else server.reject_client_text(rej)
	session.session_server_reject(&c.s, now_srv(d), text, kind, server.reject_backoff(rej))
}
