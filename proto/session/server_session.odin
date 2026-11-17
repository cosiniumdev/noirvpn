// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:mem"
import "core:time"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/reliable"
import "noir:proto/wire"
import "noir:proto/wrap"

// The server role, part two: one peer. See server.odin for the first packets
// and the shared state, and the package doc (session.odin) for the overview.
//
// What a peer goes through, and who acts:
//
//	first packet(s)          session
//	TLS                      session; a pinned or CA-checked certificate
//	key-method message       session reads the client's, writes its own
//	Auth_Request event       caller decides: session_server_accept / _reject
//	data keys, `Up`          session (key 0: after the accept)
//	PUSH_REPLY               session, when the client asked (or announced
//	                         REQUEST_PUSH in its peer-info)
//	rekeys                   either side; the session follows the client's soft
//	                         resets and starts its own at `reneg-sec`
//	keepalive                from the pushed `ping` and `ping-restart`
//	exit                     `session_close`, a client EXIT, or a timeout

// How long a server keeps a peer after AUTH_FAILED or after the peer's own
// exit, so that retransmits of the last message are still acked (5 s, as the
// stock server does).
SERVER_LINGER :: 5 * time.Second

// The login of a key state.
Srv_Auth :: enum u8 {
	None,
	Requested, // `Auth_Request` raised, no reply yet
	Accepted,
	Rejected,
}

// What an AUTH_FAILED says.
Reject_Kind :: enum u8 {
	// `AUTH_FAILED` or `AUTH_FAILED,<reason>`.
	Plain,
	// `AUTH_FAILED,SESSION`: the auth-token is unknown or expired.
	Session,
	// `AUTH_FAILED,TEMP[backoff N,advance X]: reason`. Sent to a client with
	// IV_PROTO bit 8; any other client gets the plain form with the reason.
	Temp,
}

// How a server ends a peer with `session_close`.
Close_Kind :: enum u8 {
	// The server removes the peer. The client gets:
	// - `cc-exit`: EXIT on the control channel
	// - UDP without it: OCC exit packets (`exit_notify` of them, once a second)
	// - TCP: nothing; the caller closes the connection
	Exit,
	// RESTART (UDP only): the client reconnects. A TCP peer is just closed.
	Restart,
	// `RESTART,[N]`: reconnect to the next remote.
	Restart_Next,
	// HALT: the client stops.
	Halt,
	// `AUTH_FAILED,SESSION`: the client drops its auth-token and signs in again.
	// Used when the lifetime of a token ends.
	Session_Expired,
}

// What the caller decided for an accepted client. `options` is what is pushed. The
// session fills in `peer_id`, `cipher`, `protocol_flags`, `legacy_key_derivation`
// (from the negotiation) and, if unset, `ping` and `ping_restart` (from
// `Server_Config`).
//
// Keepalive:
// - `options.ping`: how often the server pings this client; also told to it.
// - `options.ping_restart`: told to the client.
// - Server's own timeout for a silent client: `ping_restart_own`, or if 0, twice
//   the pushed `ping_restart` (as `keepalive A B` in a stock server: it pushes
//   `ping-restart B` and waits 2B itself, so a slightly late client keeps its
//   session until it gives up).
//
// DNS fields depend on `Auth_Request.peer_info.proto`: `dns` option
// (`dns_servers`, `dns_search_domains`) only for a client with `.Dns_Option_V2`,
// `dhcp_*` fields for the others.
Client_Params :: struct {
	// The peer id the client puts in its data packets and the server in its
	// own. Below `PEER_ID_NONE`. Unique among the peers of the server.
	peer_id: u32,
	options: push.Push_Reply_Params,
	// Seconds without a packet from this client after which the server drops
	// it. 0: twice `options.ping_restart` (none if that is not set either).
	ping_restart_own: int,
}

// What the client presented. The strings are slices of the session. They are
// valid until the caller replies (`session_server_accept` or `_reject`, which
// wipe them) or ends. Keep the password out of logs and copies.
Auth_Request :: struct {
	key_id:      u8,
	// SHA-256 of the client's public key (the pin) and of its certificate.
	peer_key:    ossl.Peer_Key,
	// The subject CN of the client certificate, empty if it has none or more
	// than one. In `.Pinned` mode nobody vouches for it: a label only.
	common_name: string,
	// `ossl.tls_peer_proof` of the first handshake: `.None` when the client sent
	// no certificate (only a server with `client_cert_optional` gets this far).
	// Otherwise it is the check that let the client in.
	proof:       ossl.Peer_Proof,
	username:    string,
	password:    string,
	peer_info:   push.Peer_Info,
	// The peer-info lines as the client sent them (`IV_VER=2.7.7\nIV_PLAT=linux\n...`).
	// For the bus event of a login that waits for a controller. Untrusted text.
	peer_info_text: string,
	// The source address of the first packet (`peer_addr_v4` form); empty on TCP.
	remote:      []u8,
	// tls-crypt-v2: the metadata of the client key (type byte first), else empty.
	metadata:    []u8,
}

NO_SERIAL :: 255

// Server-only state of a `Session`.
Srv_State :: struct {
	shared:        ^Server_Shared,
	// The address of the peer (UDP) and the last float candidate reported.
	remote:        [ADDR_MAX]u8,
	remote_n:      u8,
	cand:          [ADDR_MAX]u8,
	cand_n:        u8,
	// The session was created from a valid cookie (the stateless reset is the
	// first message in each direction).
	cookie_start:  bool,
	// tls-crypt-v2: the client key is known (the WKc was opened).
	v2_ready:      bool,
	// The first packet was unwrapped: the wrapping is decided (plain, or v2).
	first_rx:      bool,
	meta:          wrap.Metadata,
	// The TLS peer of key 0.
	peer_key:      ossl.Peer_Key,
	have_peer_key: bool,
	proof:         ossl.Peer_Proof,
	cn:            [ossl.COMMON_NAME_MAX]u8,
	cn_n:          u8,
	// The serial number of the client certificate (big-endian, no leading zero).
	serial:        [ossl.SERIAL_BYTES_MAX]u8,
	serial_n:      u8, // NO_SERIAL if the certificate has no readable serial
	// IV_PROTO and IV_MTU of the client, and what was agreed with it (key 0).
	proto:         push.Iv_Proto,
	client_mtu:    int,
	neg:           push.Negotiation,
	// The password of the pending login was wiped on request
	// (`session_server_wipe_password`); `session_auth_request` then shows none.
	pw_wiped:      bool,
	// The caller asked to be asked again at each renegotiation of this session
	// (`session_server_set_reauth`), as the server-wide `reauth` does for all.
	reauth:        bool,
	// The first key-method message had a password.
	had_password:  bool,
	// The wait for the reply to `Auth_Request`.
	auth_wait:     bool,
	auth_at:       Time,
	// The PUSH_REPLY, built at the accept and sent when asked.
	push_msgs:     [dynamic]string,
	push_ready:    bool,
	push_wanted:   bool,
	push_sent:     bool,
	// The peer said EXIT: wait the whole linger time.
	linger:        bool,
}

// -------------------------------------------------------------------- init

// Creates the session of a UDP peer, for an `Accept` of `server_first_packet`. Then
// hand the same packet to `session_receive`. `now` and `unix_now` are as in
// `server_first_packet`. Free it with `session_destroy`.
//
// Errors: `.Bad_Config` (the server listens on TCP), `.Alloc`, `.Random`.
session_init_server :: proc(s: ^Session, sh: ^Server_Shared, info: ^Accept_Info, now: Time, unix_now: i64, allocator := context.allocator) -> Error {
	if sh.cfg.transport != .Udp {
		return .Bad_Config
	}
	return srv_init(s, sh, info, now, unix_now, allocator)
}

// Creates the session of an accepted TCP connection. The server's reset is held
// until the first packet of the client arrives.
session_init_server_tcp :: proc(s: ^Session, sh: ^Server_Shared, now: Time, unix_now: i64, allocator := context.allocator) -> Error {
	if sh.cfg.transport != .Tcp {
		return .Bad_Config
	}
	info: Accept_Info
	return srv_init(s, sh, &info, now, unix_now, allocator)
}

@(private)
srv_init :: proc(s: ^Session, sh: ^Server_Shared, info: ^Accept_Info, now: Time, unix_now: i64, allocator: mem.Allocator) -> Error {
	s^ = {}
	s.allocator = allocator
	s.role = .Server
	s.transport = sh.cfg.transport
	s.cfg = sh.cfg
	s.srv.shared = sh
	s.peer_id = PEER_ID_NONE
	s.tls_ctx_ptr = sh.tls_ctx_ptr
	for i in 0 ..< sh.ciphers_n {
		s.ciphers[i] = sh.ciphers[i]
	}
	s.ciphers_n = sh.ciphers_n
	keys.slots_init(&s.slots, dp_slots_config(&s.cfg))
	dp_init(&s.dp, s.role, s.transport, dp_slots_config(&s.cfg))
	s.wall_base = unix_now - i64(now / time.Second)
	tcp := s.transport == .Tcp
	cookie := info.cookie && !tcp
	s.srv.cookie_start = cookie
	if !tcp {
		s.srv.remote_n = u8(copy(s.srv.remote[:], info.from.b[:info.from.n]))
		s.cfg.ipv4_peer = info.from.n == 7
	}

	srv_wrap_primary(s)

	// Session ids.
	if cookie {
		s.local_sid = info.server_sid
	} else {
		for {
			if !fill_random(s, s.local_sid[:]) {
				return .Random
			}
			if reliable.sid_defined(s.local_sid) {
				break
			}
		}
	}
	if reliable.sid_defined(info.client_sid) {
		s.peer_sid = info.client_sid
		s.peer_sid_set = true
	}

	// The jitter of `reneg-sec`, once per session.
	s.reneg_eff = s.cfg.reneg_sec
	if s.reneg_eff > 0 {
		rb: [4]u8
		if !fill_random(s, rb[:]) {
			return .Random
		}
		r := u32(rb[0]) << 24 | u32(rb[1]) << 16 | u32(rb[2]) << 8 | u32(rb[3])
		s.reneg_eff = int(keys.reneg_sec_jitter(i64(s.reneg_eff), r))
	}

	if tcp {
		buf, aerr := make([]u8, wire.FRAME_PREFIX_LEN + s.cfg.max_frame, allocator)
		if aerr != nil {
			return .Alloc
		}
		s.split_buf = buf
		if wire.splitter_init(&s.split, buf, s.cfg.max_frame) != .None {
			delete(buf, allocator)
			s.split_buf = nil
			return .Bad_Config
		}
	}

	ccfg := reliable.Config {
		timeout     = s.cfg.tls_timeout,
		hand_window = s.cfg.hand_window,
		max_payload = reliable.DEFAULT_MAX_PAYLOAD,
		local_sid   = s.local_sid,
		peer_sid    = s.peer_sid,
	}
	if cookie {
		// The stateless reset was message 0 of each side.
		ccfg.send_first_id = 1
		ccfg.recv_first_id = 1
	}
	if reliable.init(&s.ks.chan, ccfg, now, allocator) != .None {
		session_destroy(s)
		return .Alloc
	}
	s.ks.chan_ok = true
	s.started = true
	s.last_rx = now
	s.last_tx = now
	if cookie {
		s.ks.state = .Start
		s.state = .Handshaking
		s.link_up = true
		emit(s, Event{kind = .Link_Up})
		return .None
	}
	// No cookie: our reset is message 0, and a TCP server holds it until the
	// client has sent something.
	if _, ok := reliable.send_packet(&s.ks.chan, u8(wire.Opcode.Hard_Reset_Server_V2), nil, now); !ok {
		session_destroy(s)
		return .Internal
	}
	if tcp {
		reliable.set_hold(&s.ks.chan, true)
	}
	s.ks.state = .Pre_Start
	s.state = .Connecting
	return .None
}

// The wrap context for the packets that are not tls-crypt-v2 (the v2 context
// comes from the first packet, see `srv_unwrap_v2`).
@(private)
srv_wrap_primary :: proc(s: ^Session) {
	sh := s.srv.shared
	w := &s.wrap
	w.mode = sh.mode
	switch sh.mode {
	case .None:
		w.overhead = 0
	case .Tls_Auth:
		w.orig_key = sh.static
		w.have_key = true
		wrap.tls_auth_init(&w.auth, &w.orig_key, sh.auth_alg, sh.auth_dir)
		w.overhead = wrap.tls_auth_overhead(sh.auth_alg)
		if s.srv.cookie_start {
			w.auth.counter.id = 1
		}
	case .Tls_Crypt:
		w.orig_key = sh.static
		w.have_key = true
		wrap.tls_crypt_init(&w.crypt, &w.orig_key, .Server)
		w.overhead = reliable.WRAP_OVERHEAD_TLS_CRYPT
		if s.srv.cookie_start {
			w.crypt.counter.id = 1
		}
	case .Tls_Crypt_V2:
		w.overhead = reliable.WRAP_OVERHEAD_TLS_CRYPT
	}
}

// Opens a packet of opcode 10 or 11.
// - First one has the WKc: open it with the server key, create the wrap context
//   from Kc, run the age check.
// - Later ones (retransmits, every opcode 11): unwrap with the context we hold,
//   after cutting off the WKc.
@(private)
srv_unwrap :: proc(s: ^Session, op: wire.Opcode, pkt, out: []u8) -> (n: int, err: wrap.Error) {
	sv := &s.srv
	if op == .Hard_Reset_Client_V3 || op == .Control_Wkc_V1 {
		n, err = srv_unwrap_v2(s, pkt, out)
	} else if s.wrap.mode == .Tls_Crypt_V2 && !sv.v2_ready {
		// Only a client with a v2 key can start a session here.
		return 0, .Wrong_Opcode
	} else {
		n, err = unwrap_with(s, pkt, out)
	}
	if err == .None {
		sv.first_rx = true
	}
	return
}

@(private)
srv_unwrap_v2 :: proc(s: ^Session, pkt, out: []u8) -> (n: int, err: wrap.Error) {
	sh := s.srv.shared
	if !sh.v2 {
		return 0, .Wrong_Opcode
	}
	if s.srv.first_rx && !s.srv.v2_ready {
		// The session began with plain wrapping.
		return 0, .Wrong_Opcode
	}
	body, wkc, serr := wrap.tls_crypt_v2_split_wkc(pkt)
	if serr != .None {
		return 0, serr
	}
	w := &s.wrap
	if s.srv.v2_ready {
		return wrap.tls_crypt_unwrap(&w.crypt, body, out)
	}
	kc: wrap.Static_Key
	defer wrap.static_key_wipe(&kc)
	meta: wrap.Metadata
	if oerr := wrap.tls_crypt_v2_wkc_open(&sh.server_key, wkc, &kc, &meta); oerr != .None {
		return 0, oerr
	}
	if sh.max_age_days > 0 {
		if aerr := wrap.metadata_check_age(&meta, wall_now(s, s.last_rx), i64(sh.max_age_days)); aerr != .None {
			return 0, aerr
		}
	}
	ctx: wrap.Tls_Crypt
	defer wrap.tls_crypt_wipe(&ctx)
	wrap.tls_crypt_init(&ctx, &kc, .Server)
	m, uerr := wrap.tls_crypt_unwrap(&ctx, body, out)
	if uerr != .None {
		return 0, uerr
	}
	// The first message of a cookie session is the third packet: the stateless
	// reply already used wrap id 1.
	if s.srv.cookie_start {
		ctx.counter.id = 1
	}
	w.crypt = ctx
	w.orig_key = kc
	w.have_key = true
	w.mode = .Tls_Crypt_V2
	w.overhead = reliable.WRAP_OVERHEAD_TLS_CRYPT
	s.srv.meta = meta
	s.srv.v2_ready = true
	return m, .None
}

// Frees what only a server session holds. Called by `session_destroy`.
@(private)
srv_destroy :: proc(s: ^Session) {
	sv := &s.srv
	if sv.push_msgs != nil {
		push.push_messages_destroy(sv.push_msgs)
		sv.push_msgs = nil
	}
	mem.zero_explicit(&sv.meta, size_of(sv.meta))
}

// -------------------------------------------------------------------- input

// The checks for a server: the session id and
// the source address. Returns false if the packet is dropped (counted there).
@(private)
srv_check_source :: proc(s: ^Session, op: wire.Opcode, sid: reliable.Sid) -> bool {
	if s.peer_sid_set {
		if sid != s.peer_sid {
			rx_drop(s, &s.counters.drop_sid, "a packet had the wrong session id")
			return false
		}
	} else if op != .Hard_Reset_Client_V2 && op != .Hard_Reset_Client_V3 {
		// TCP: the first packet of a connection must be a reset.
		rx_drop(s, &s.counters.drop_opcode, "the first packet is not a reset")
		return false
	}
	sv := &s.srv
	if s.transport == .Udp && len(s.rx_from) > 0 && sv.remote_n > 0 {
		if string(s.rx_from) != string(sv.remote[:sv.remote_n]) {
			rx_drop(s, &s.counters.drop_addr, "a control packet came from another address")
			return false
		}
	}
	return true
}

// The first reset of the client: the link is verified. Returns false if the
// packet is refused.
@(private)
srv_first_reset :: proc(s: ^Session, sid: reliable.Sid, cp: ^wire.Control_Packet, now: Time) -> bool {
	if cp.packet_id != 0 {
		rx_drop(s, &s.counters.drop_reliable, "a reset packet had a message id other than 0")
		return false
	}
	if !s.peer_sid_set {
		s.peer_sid = sid
		s.peer_sid_set = true
		reliable.set_peer_sid(&s.ks.chan, sid)
	}
	s.link_up = true
	s.state = .Handshaking
	reliable.set_hold(&s.ks.chan, false)
	reliable.burst(&s.ks.chan, now)
	emit(s, Event{kind = .Link_Up})
	return true
}

// TLS bytes and reset payloads of the client, in order.
@(private)
srv_deliver :: proc(s: ^Session, now: Time) {
	ks := &s.ks
	for s.state != .Failed {
		d, ok := reliable.pop(&ks.chan)
		if !ok {
			break
		}
		#partial switch wire.Opcode(d.tag) {
		case .Hard_Reset_Client_V2, .Hard_Reset_Client_V3, .Soft_Reset_V1:
			// Message 0 is the reset itself. SPEC-GAP: any payload on it is
			// ignored; the spec defines none from a client.
		case .Control_V1, .Control_Wkc_V1:
			// The TLS session of a server starts with the first bytes of the
			// client (its ClientHello); the TLS library responds from there.
			if !ks.tls_ok {
				sess, err := tls_new_session(s)
				if err != .None {
					fail(s, .Internal, "TLS session")
					return
				}
				ks.tls = sess
				ks.tls_ok = true
			}
			if !ossl.tls_feed(&ks.tls, d.payload) {
				fail(s, .Internal, "TLS buffer")
				return
			}
		}
	}
}

// ---------------------------------------------------------------- handshake

// TLS handshake, the client's key-method message, our own, and the commands.
// Returns true if the key state moved.
@(private)
srv_drive_tls :: proc(s: ^Session, now: Time) -> (changed: bool) {
	ks := &s.ks
	if !ks.tls_ok {
		return false
	}
	hs := ossl.tls_handshake_step(&ks.tls)
	if hs == .Failed {
		fail_tls(s, now)
		return false
	}
	flush_tls(s, now)
	if hs != .Done {
		return false
	}
	if pump_app(s, now) {
		changed = true
	}
	if s.state == .Failed || s.state == .Closed {
		return false
	}
	if ks.km_sent && ks.km_got && ks.state != .Active && ks.auth != .Rejected && reliable.all_acked(&ks.chan) {
		ks.state = .Active
		ks.active_at = now
		reliable.clear_deadline(&ks.chan)
		changed = true
	}
	return changed
}

// The client's key-method message is complete (and maybe commands behind it).
@(private)
srv_handle_app_data :: proc(s: ^Session, data: []u8, now: Time) {
	ks := &s.ks
	if ks.km_got {
		srv_handle_commands(s, data, now)
		return
	}
	if ks.km_len + len(data) > len(ks.km_in) {
		fail(s, .Key_Method, "the key-method message is too long")
		return
	}
	copy(ks.km_in[ks.km_len:], data)
	ks.km_len += len(data)
	km: push.Key_Method
	used, err := push.keymethod_decode(ks.km_in[:ks.km_len], .Client, &km)
	#partial switch err {
	case .None:
	case .Need_More:
		return
	case:
		fail(s, .Key_Method, "the key-method message from the client is not valid")
		return
	}
	sv := &s.srv
	ks.km_got = true
	ks.km_used = used
	// This message has its own password: a wipe of an earlier one does not apply.
	s.srv.pw_wiped = false
	if ks.state == .Start {
		ks.state = .Got_Key
	}

	// Who is on the other end: the key of the TLS peer. A renegotiation must come
	// from the same one (a client that sent no certificate must send none again).
	// Only a server that allows it (`client_cert_optional`) takes a client with no
	// certificate.
	spki, ok1 := ossl.tls_peer_spki_sha256(&ks.tls)
	cert, ok2 := ossl.tls_peer_cert_sha256(&ks.tls)
	proof := ossl.tls_peer_proof(&ks.tls)
	has := ossl.tls_peer_has_cert(&ks.tls)
	sent := has && ok1 && ok2
	switch {
	case !has && !sv.shared.cert_optional:
		fail(s, .Tls, "the client sent no certificate")
		return
	case has && !sent:
		fail(s, .Tls, "the client certificate cannot be read")
		return
	case sent && proof == .None:
		// A certificate that no check vouched for is never an identity.
		fail(s, .Tls, "the client certificate was not verified")
		return
	}
	peer := ossl.Peer_Key {
		spki_sha256 = spki,
		cert_sha256 = cert,
	}
	same_peer := true
	if ks.id == 0 {
		sv.peer_key = peer
		sv.have_peer_key = sent
		sv.proof = proof
		if sent {
			n, _ := ossl.tls_peer_common_name(&ks.tls, sv.cn[:])
			sv.cn_n = u8(n)
			sn, sok := ossl.tls_peer_serial(&ks.tls, &sv.serial)
			sv.serial_n = u8(sn) if sok else NO_SERIAL
		}
	} else {
		same_peer = sv.have_peer_key == sent && (!sent || sv.peer_key == peer)
	}
	pi: push.Peer_Info
	_ = push.peer_info_parse(km.peer_info, &pi)
	if ks.id == 0 {
		// The first key settles the cipher and the flags. They do not change
		// on a renegotiation.
		sv.had_password = km.password != ""
		sv.proto = pi.proto
		sv.client_mtu = pi.mtu
		oi: push.Options_Info
		cipher_item := ""
		if push.options_parse(km.options, &oi) == .None {
			cipher_item = oi.cipher
		}
		offer := push.Server_Offer {
			ciphers = s.ciphers[:s.ciphers_n],
			allow   = sv.shared.flags,
		}
		sv.neg = push.negotiate_server(&pi, cipher_item, &offer)
	}

	// Our own message goes out whatever the login says.
	if !srv_send_key_method(s, now) {
		return
	}
	switch {
	case ks.id == 0 && sv.neg.failure != .None:
		// No common cipher (or a client that cannot run the baseline): the
		// caller is not asked.
		srv_reject(s, now, push.negotiation_failure_text(sv.neg.failure), .Plain, 0, .Unset)
	case !same_peer:
		srv_reject(s, now, "peer key changed on renegotiation", .Plain, 0, .Unset)
	case km.username_too_long || km.password_too_long:
		srv_reject(s, now, "", .Plain, 0, .Unset)
	case ks.id == 0 || sv.shared.reauth || sv.reauth || (km.password != "" && !sv.had_password):
		// A renegotiation with a password that the login did not have is also
		// put to the caller: the login rules apply to it again.
		ks.auth = .Requested
		sv.auth_wait = true
		sv.auth_at = now + s.cfg.hand_window
		emit(s, Event{kind = .Auth_Request, key_id = ks.id})
	case:
		ks.auth = .Accepted
		zero_bytes(ks.km_in[:used])
	}
	rest := ks.km_in[used:ks.km_len]
	if s.state != .Failed {
		srv_handle_commands(s, rest, now)
	}
	zero_bytes(rest)
	ks.km_len = used
}

@(private)
srv_send_key_method :: proc(s: ^Session, now: Time) -> bool {
	ks := &s.ks
	rnd: [push.KEY_METHOD_RANDOM_SERVER]u8
	if !fill_random(s, rnd[:]) {
		fail(s, .Internal, "random")
		return false
	}
	obuf: [push.OPTIONS_MAX_LEN]u8
	op := push.Options_Params {
		role      = .Server,
		transport = s.transport,
		tun_mtu   = s.cfg.tun_mtu,
		cipher    = s.ciphers[0],
	}
	opts, oerr := push.options_build(obuf[:], &op)
	if oerr != .None {
		fail(s, .Internal, "options string")
		return false
	}
	km := push.Key_Method {
		sender  = .Server,
		random  = rnd[:],
		options = opts,
	}
	kbuf: [push.KEY_METHOD_MAX_LEN]u8
	n, kerr := push.keymethod_encode(kbuf[:], &km)
	zero_bytes(rnd[:])
	if kerr != .None {
		fail(s, .Key_Method, "cannot build the key-method message")
		return false
	}
	st := ossl.tls_write_app(&ks.tls, kbuf[:n])
	if st != .Ok {
		fail_tls(s, now)
		return false
	}
	ks.km_sent = true
	ks.state = .Sent_Key
	flush_tls(s, now)
	return true
}

// ------------------------------------------------------------------ commands

@(private)
srv_handle_commands :: proc(s: ^Session, data: []u8, now: Time) {
	ks := &s.ks
	rest := data
	for len(rest) > 0 && s.state != .Failed {
		text, st := push.cmd_reader_next(&ks.cmd, &rest)
		switch st {
		case .Need_More:
			return
		case .Dropped:
			continue
		case .Oversize:
			fail(s, .Protocol, "a control command is too long")
			return
		case .Command:
			srv_handle_command(s, text, now)
		}
	}
}

@(private)
srv_handle_command :: proc(s: ^Session, text: string, now: Time) {
	cmd, err := push.command_parse(text, .Server)
	if err != .None {
		return // wrong direction: ignored, as a stock server does
	}
	#partial switch _ in cmd {
	case push.Push_Request:
		// A request before the login is done is remembered. A repeat after the
		// reply is ignored.
		s.srv.push_wanted = true
	case push.Exit_Cmd:
		srv_peer_exit(s, now)
	}
}

// The client says it is leaving (EXIT, or the OCC exit packet): keep the
// session for a few seconds for retransmits, then close.
@(private)
srv_peer_exit :: proc(s: ^Session, now: Time) {
	switch s.state {
	case .Closing, .Closed, .Failed:
		return
	case .New, .Connecting, .Handshaking, .Up:
	}
	emit(s, Event{kind = .Remote_Exit})
	s.closing = true
	s.state = .Closing
	s.srv.linger = true
	s.exit_cc = true
	s.exit_deadline = now + SERVER_LINGER
}

// ------------------------------------------------------------------- reply

// Causes this session to raise `Auth_Request` at each renegotiation (key id above 0)
// until turned off. The caller replies with:
// - `session_server_accept`: the new key goes live
// - `session_server_reject`: AUTH_FAILED; the old key stays in use until the
//   session closes
// A renegotiation that sends a password where the first key-method message had
// none raises it too, whatever this setting says.
session_server_set_reauth :: proc(s: ^Session, on: bool) {
	if s.role == .Server {
		s.srv.reauth = on
	}
}

// CN and serial number of the client certificate of a server session (as in
// `Auth_Request`), for a match by certificate. `ok` only if the CA chain let the
// client in (`.Chain`) and the serial is readable. A client with no certificate,
// or one only a pin let in, is not `ok`. Values point into the session.
session_server_chain_cert :: proc(s: ^Session) -> (cn: string, serial: []u8, ok: bool) {
	if s.role != .Server || s.srv.proof != .Chain || s.srv.serial_n == NO_SERIAL {
		return
	}
	sv := &s.srv
	return string(sv.cn[:sv.cn_n]), sv.serial[:sv.serial_n], true
}

// What the client presented, for the decision. False if no `Auth_Request` is
// waiting. `out` is about 3 KiB: do not keep it on a small stack.
session_auth_request :: proc(s: ^Session, out: ^Auth_Request) -> bool {
	ks := &s.ks
	if s.role != .Server || ks.auth != .Requested {
		return false
	}
	km: push.Key_Method
	if _, err := push.keymethod_decode(ks.km_in[:ks.km_used], .Client, &km); err != .None {
		return false
	}
	sv := &s.srv
	out^ = {}
	out.key_id = ks.id
	out.peer_key = sv.peer_key
	out.common_name = string(sv.cn[:sv.cn_n])
	out.proof = sv.proof
	out.username = km.username
	out.password = km.password if !sv.pw_wiped else ""
	out.peer_info_text = km.peer_info
	_ = push.peer_info_parse(km.peer_info, &out.peer_info)
	out.remote = sv.remote[:sv.remote_n]
	out.metadata = wrap.metadata_bytes(&sv.meta) if sv.v2_ready else nil
	return true
}

// Overwrites the password of the pending login with zeros, in the session's copy
// of the key-method message. The caller does this after reading the password
// (`session_auth_request`) for a controller: then it exists nowhere else.
// `session_server_accept` and `_reject` wipe the whole message anyway. Returns
// false if no `Auth_Request` waits.
session_server_wipe_password :: proc(s: ^Session) -> bool {
	ks := &s.ks
	if s.role != .Server || ks.auth != .Requested {
		return false
	}
	km: push.Key_Method
	if _, err := push.keymethod_decode(ks.km_in[:ks.km_used], .Client, &km); err != .None {
		return false
	}
	if len(km.password) > 0 {
		mem.zero_explicit(raw_data(km.password), len(km.password))
	}
	s.srv.pw_wiped = true
	return true
}

// The login passed. Key 0: builds the PUSH_REPLY from `p` and the negotiation
// (cipher, flags, peer id). The data keys follow once the control channel is
// quiet, then `Up`. A client with no common cipher never gets here: it was
// rejected with the NCP text before `Auth_Request`.
//
// Errors:
// - `.Bad_State`: no request waiting
// - `.Bad_Config`: `peer_id` out of range, or an option that cannot be written
//   (a comma in a string, ...)
// Collect the packets with `session_poll_tx` after the call.
session_server_accept :: proc(s: ^Session, p: ^Client_Params, now: Time) -> Error {
	ks := &s.ks
	if s.role != .Server || ks.auth != .Requested || s.state == .Failed || s.state == .Closed || s.state == .Closing {
		return .Bad_State
	}
	if ks.id == 0 {
		if p == nil || p.peer_id >= wire.PEER_ID_UNDEFINED {
			return .Bad_Config
		}
		if err := srv_accept_first(s, p); err != .None {
			return err
		}
	}
	ks.auth = .Accepted
	s.srv.auth_wait = false
	zero_bytes(ks.km_in[:ks.km_used])
	progress(s, now)
	return .None
}

// Key 0: the negotiation and the reply.
@(private)
srv_accept_first :: proc(s: ^Session, p: ^Client_Params) -> Error {
	sv := &s.srv
	sh := sv.shared
	neg := sv.neg
	pp := p.options
	pp.peer_id = p.peer_id
	pp.cipher = neg.cipher if neg.push_cipher else .None
	pp.protocol_flags = neg.flags
	pp.legacy_key_derivation = neg.legacy_key_derivation
	if pp.ping == nil && sh.ping > 0 {
		pp.ping = sh.ping
	}
	if pp.ping_restart == nil && sh.ping_restart > 0 {
		pp.ping_restart = sh.ping_restart
	}
	if pp.tun_mtu == nil && sh.push_tun_mtu > 0 {
		pp.tun_mtu = sh.push_tun_mtu
	}
	// Only a client that sent IV_MTU is told the MTU, and never above its own.
	if m, ok := pp.tun_mtu.?; ok {
		if sv.client_mtu > 0 {
			pp.tun_mtu = min(m, sv.client_mtu)
		} else {
			pp.tun_mtu = nil
		}
	}
	msgs, berr := push.push_reply_build(&pp, s.allocator)
	if berr != .None {
		return .Bad_Config
	}
	if sv.push_msgs != nil {
		push.push_messages_destroy(sv.push_msgs)
	}
	sv.push_msgs = msgs
	sv.push_ready = true
	sv.push_wanted = sv.push_wanted || .Request_Push in sv.proto
	s.cipher = neg.cipher
	s.flags = neg.flags
	s.peer_id = p.peer_id
	s.ping = pp.ping.? or_else 0
	s.ping_restart = p.ping_restart_own
	if s.ping_restart <= 0 {
		s.ping_restart = 2 * (pp.ping_restart.? or_else 0)
	}
	if s.cfg.ext_data {
		s.ext_ping, s.ext_ping_restart = s.ping, s.ping_restart
		s.ping, s.ping_restart = 0, 0
	}
	return .None
}

// The login failed (or no common cipher): send AUTH_FAILED, close after the ack
// or 5 s. `kind` and `backoff`/`advance` choose the form. `reason` is shown to
// the user (at most 1024 bytes; empty for none). Collect the packets with
// `session_poll_tx` after the call. Events: `Auth_Failed` now, `Closed` later.
//
// Errors: `.Bad_State` (no request waiting).
session_server_reject :: proc(
	s: ^Session,
	now: Time,
	reason: string,
	kind := Reject_Kind.Plain,
	backoff := 0,
	advance := push.Temp_Advance.Unset,
) -> Error {
	if s.role != .Server || s.ks.auth != .Requested || s.state == .Failed || s.state == .Closed || s.state == .Closing {
		return .Bad_State
	}
	srv_reject(s, now, reason, kind, backoff, advance)
	return .None
}

@(private)
srv_reject :: proc(s: ^Session, now: Time, reason: string, kind: Reject_Kind, backoff: int, advance: push.Temp_Advance) {
	ks := &s.ks
	sv := &s.srv
	buf: [push.CMD_SEND_MAX_LEN + 16]u8
	n: int
	err: push.Error
	ev := Event {
		kind      = .Auth_Failed,
		reason    = .Auth_Failed,
		auth_kind = .Reason if len(reason) > 0 else .Plain,
	}
	k := kind
	if k == .Temp && .Auth_Fail_Temp not_in sv.proto {
		k = .Plain
	}
	switch k {
	case .Plain:
		n, err = push.format_auth_failed(buf[:], reason)
	case .Session:
		n, err = push.format_auth_failed_session(buf[:])
		ev.auth_kind = .Session
	case .Temp:
		n, err = push.format_auth_failed_temp(buf[:], backoff, advance, reason)
		ev.auth_kind = .Temp
		ev.backoff = backoff
		ev.advance = advance
	}
	event_set_text(&ev, reason)
	ks.auth = .Rejected
	sv.auth_wait = false
	zero_bytes(ks.km_in[:ks.km_used])
	emit(s, ev)
	if err != .None || !ks.tls_ok || ossl.tls_write_app(&ks.tls, buf[:n]) != .Ok {
		fail(s, .Auth_Failed, "authentication failed")
		return
	}
	flush_tls(s, now)
	// Closed when the client has acked AUTH_FAILED, or after the linger.
	s.closing = true
	s.state = .Closing
	s.exit_cc = true
	s.exit_deadline = now + SERVER_LINGER
}

// Tells the client that the login takes longer (AUTH_PENDING) and gives the
// caller `timeout_s` seconds more to reply. Valid while an `Auth_Request`
// waits. The client waits at most `max(reneg-sec / 2, hand-window)`.
session_server_auth_pending :: proc(s: ^Session, now: Time, timeout_s: int) -> Error {
	ks := &s.ks
	if s.role != .Server || ks.auth != .Requested || !ks.tls_ok || timeout_s < 0 {
		return .Bad_State
	}
	buf: [64]u8
	n, err := push.format_auth_pending(buf[:], timeout_s, .Auth_Pending_Kw in s.srv.proto)
	if err != .None || ossl.tls_write_app(&ks.tls, buf[:n]) != .Ok {
		return .Internal
	}
	s.srv.auth_at = now + time.Duration(timeout_s) * time.Second
	flush_tls(s, now)
	return .None
}

// Sends `INFO_PRE,<text>` to the client (web sign-in: `WEB_AUTH:<flags>:<url>`).
// Valid while an `Auth_Request` waits for the first key. The text is not kept.
//
// Errors: `.Bad_State` (no first login waits), `.Internal` (does not fit, or the
// write failed).
session_server_info_pre :: proc(s: ^Session, now: Time, text: string) -> Error {
	ks := &s.ks
	if s.role != .Server || ks.auth != .Requested || ks.id != 0 || !ks.tls_ok {
		return .Bad_State
	}
	buf: [push.CMD_SEND_MAX_LEN + 16]u8
	defer zero_bytes(buf[:])
	n, err := push.format_info_pre(buf[:], text)
	if err != .None || ossl.tls_write_app(&ks.tls, buf[:n]) != .Ok {
		return .Internal
	}
	flush_tls(s, now)
	return .None
}

// ---------------------------------------------------------------- key state

// The server side of ACTIVE to GENERATED_KEYS: the login passed, so the data
// keys of this key id go live. For key 0 the PUSH_REPLY goes out right after
// (`srv_push_check`), when the client asked for it.
@(private)
srv_try_generate :: proc(s: ^Session, now: Time) -> bool {
	ks := &s.ks
	if ks.auth != .Accepted {
		return false
	}
	if !install_keys(s, now) {
		return false
	}
	ks.state = .Generated_Keys
	s.rekeying = false
	if ks.id == 0 {
		s.state = .Up
		s.last_rx = now
		s.last_tx = now
		emit(s, Event{kind = .Up, key_id = 0})
	} else {
		emit(s, Event{kind = .Key_Installed, key_id = ks.id, by_peer = ks.by_peer})
	}
	return true
}

// Sends the PUSH_REPLY of key 0 once: when the keys are installed, the reply
// is built, and the client asked.
@(private)
srv_push_check :: proc(s: ^Session, now: Time) -> bool {
	ks := &s.ks
	sv := &s.srv
	if ks.id != 0 || ks.state != .Generated_Keys || !sv.push_ready || sv.push_sent || !sv.push_wanted || !ks.tls_ok {
		return false
	}
	buf: [push.MAX_COMMAND_LEN]u8
	for m in sv.push_msgs {
		n, err := push.cmd_frame(buf[:], m)
		if err != .None {
			fail(s, .Push, "the PUSH_REPLY does not fit in one control command")
			return false
		}
		if ossl.tls_write_app(&ks.tls, buf[:n]) != .Ok {
			fail_tls(s, now)
			return false
		}
	}
	push.push_messages_destroy(sv.push_msgs)
	sv.push_msgs = nil
	sv.push_sent = true
	flush_tls(s, now)
	return true
}

// ------------------------------------------------------------------- close

// Server side of `session_close`.
@(private)
srv_close :: proc(s: ^Session, now: Time, kind: Close_Kind) {
	switch s.state {
	case .New, .Connecting, .Handshaking:
		s.state = .Closed
		emit(s, Event{kind = .Closed})
		return
	case .Closing, .Closed, .Failed:
		return
	case .Up:
	}
	s.closing = true
	s.state = .Closing
	ks := &s.ks
	buf: [96]u8
	n: int
	err := push.Error.Bad_Argument
	udp := s.transport == .Udp
	switch kind {
	case .Exit:
		if .Cc_Exit in s.flags {
			n, err = push.format_exit(buf[:])
		} else if udp && s.cfg.explicit_exit_notify > 0 && !s.cfg.ext_data {
			s.exit_left = s.cfg.explicit_exit_notify
			s.exit_next = now
			return
		}
	case .Restart:
		if udp {
			n, err = push.format_restart(buf[:])
		}
	case .Restart_Next:
		if udp {
			n, err = push.format_restart(buf[:], "", false, true)
		}
	case .Halt:
		n, err = push.format_halt(buf[:])
	case .Session_Expired:
		n, err = push.format_auth_failed_session(buf[:])
	}
	if err == .None && ks.state == .Generated_Keys && ks.tls_ok && ossl.tls_write_app(&ks.tls, buf[:n]) == .Ok {
		s.exit_cc = true
		s.exit_deadline = now + s.cfg.exit_timeout
		flush_tls(s, now)
		return
	}
	finish_close(s)
}

// ---------------------------------------------------------------- accessors

// The address of the peer (UDP), in the form of `peer_addr_v4`. Valid until
// the session ends or `session_server_set_remote`.
session_server_remote :: proc "contextless" (s: ^Session) -> []u8 {
	return s.srv.remote[:s.srv.remote_n]
}

// Moves the peer to a new source address after a `Float_Candidate`.
// The caller has checked that no other peer holds it. Control packets from
// the old address are dropped from now on. False for a bad address.
session_server_set_remote :: proc "contextless" (s: ^Session, addr: []u8) -> bool {
	if !addr_ok(addr) {
		return false
	}
	s.srv.remote_n = u8(copy(s.srv.remote[:], addr))
	s.srv.cand_n = 0
	s.cfg.ipv4_peer = addr[0] == 4
	return true
}

// The TLS peer of the first key (valid after `Auth_Request`).
session_server_peer_key :: proc "contextless" (s: ^Session) -> (key: ossl.Peer_Key, ok: bool) {
	return s.srv.peer_key, s.srv.have_peer_key
}

// The key of the peer's leaf certificate in the first TLS handshake: the
// server's for a client session (valid once that handshake is done), the
// client's for a server session (valid after `Auth_Request`).
session_peer_key :: proc "contextless" (s: ^Session) -> (key: ossl.Peer_Key, ok: bool) {
	if s.role == .Server {
		return s.srv.peer_key, s.srv.have_peer_key
	}
	return s.peer_key, s.peer_key_ok
}

// The metadata of the tls-crypt-v2 client key (type byte first), if any.
session_server_metadata :: proc "contextless" (s: ^Session) -> []u8 {
	if !s.srv.v2_ready {
		return nil
	}
	return wrap.metadata_bytes(&s.srv.meta)
}

// A data packet that authenticated came from another address than the one of
// the session: tell the caller once per new address. The
// caller decides, because only it knows the other peers.
@(private)
srv_float_check :: proc(s: ^Session) {
	sv := &s.srv
	from := s.rx_from
	if s.transport != .Udp || len(from) == 0 || sv.remote_n == 0 || string(from) == string(sv.remote[:sv.remote_n]) {
		return
	}
	if string(from) == string(sv.cand[:sv.cand_n]) {
		return
	}
	if !addr_ok(from) {
		return
	}
	sv.cand_n = u8(copy(sv.cand[:], from))
	ev := Event {
		kind = .Float_Candidate,
	}
	event_set_text(&ev, string(from))
	emit(s, ev)
}
