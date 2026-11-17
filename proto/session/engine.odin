// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:time"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/reliable"
import "noir:proto/wire"

// Ends the session with a failure. Raises a `Failed` event once.
@(private)
fail :: proc(s: ^Session, reason: Fail_Reason, text: string) {
	if s.state == .Failed || s.state == .Closed {
		return
	}
	s.state = .Failed
	s.fail_reason = reason
	s.ks.state = .Error
	ev := Event {
		kind   = .Failed,
		reason = reason,
	}
	event_set_text(&ev, text)
	emit(s, ev)
}

@(private)
fail_tls :: proc(s: ^Session, now: Time) {
	// One last chance to send the alert (ERROR_PRE).
	flush_tls(s, now)
	text := ossl.tls_last_error(&s.ks.tls)
	if len(text) == 0 {
		text = "TLS error"
	}
	reason := Fail_Reason.Tls
	switch {
	case ossl.tls_cert_revoked(&s.ks.tls):
		reason = .Cert_Revoked
	case ossl.tls_crl_failed(&s.ks.tls):
		reason = .Crl_Failed
	}
	fail(s, reason, text)
}

// Creates the TLS session of the current key state. The caller's `tls_prepare`
// hook runs first, so it can reload a CRL list before the handshake starts.
@(private)
tls_new_session :: proc(s: ^Session) -> (ossl.Tls_Session, ossl.Error) {
	if s.cfg.tls_prepare != nil {
		s.cfg.tls_prepare(s.cfg.tls_prepare_user, s.tls_ctx_ptr)
	}
	return ossl.tls_session_create(s.tls_ctx_ptr)
}

@(private)
ks_free_tls :: proc(ks: ^Key_State) {
	if ks.tls_ok {
		ossl.tls_session_destroy(&ks.tls)
		ks.tls_ok = false
	}
}

// -------------------------------------------------------------- soft reset

// Starts the next key state. `by_peer` is true when the
// peer's soft reset arrived first. The caller processes the packet itself right
// after this.
@(private)
begin_rekey :: proc(s: ^Session, new_id: u8, by_peer: bool, now: Time) {
	ks := &s.ks
	// SPEC-GAP (seen with stock 2.7.7): the spec drops the lame key when a
	// soft reset begins. A stock server keeps sending on its old key for a while
	// after a rekey. If a second soft reset follows within about a second, the last
	// replies on the dropped key are lost (one or two packets; the `rekey-both`
	// interop cell shows it). The slot table keeps the lame key through the
	// handshake and for a grace time after the new key is installed
	// (`keys.DEFAULT_LAME_GRACE`). Only the key before it is dropped here.
	keys.slots_rekey_started(&s.slots, now)
	cmd := Dp_Cmd {
		kind = .Rekey_Started,
		now  = now,
	}
	dp_send(s, &cmd)
	ks_free_tls(ks)
	chan := ks.chan
	ks^ = {}
	ks.chan = chan
	ks.chan_ok = true
	ks.id = new_id
	ks.by_peer = by_peer
	// SPEC-GAP: a renegotiation that fails (hand window, TLS error) ends the
	// session. A stock peer keeps the old keys until they expire and could carry
	// on; the daemon reconnects instead.
	// Ids of a new key state start at 0, also for a session that began from a
	// cookie.
	ks.chan.cfg.send_first_id, ks.chan.cfg.recv_first_id = 0, 0
	reliable.reset(&ks.chan, now)
	s.rekeying = true
	if _, ok := reliable.send_packet(&ks.chan, u8(wire.Opcode.Soft_Reset_V1), nil, now); !ok {
		fail(s, .Internal, "soft reset")
		return
	}
	ks.state = .Pre_Start
	s.counters.rekeys += 1
	emit(s, Event{kind = .Rekey_Started, key_id = new_id, by_peer = by_peer})
}

// Asks for a renegotiation now. Returns false if the session is not up or one
// is already running.
session_rekey :: proc(s: ^Session, now: Time) -> bool {
	if s.state != .Up || s.rekeying || s.closing || s.ks.state != .Generated_Keys {
		return false
	}
	begin_rekey(s, keys.key_id_next(s.ks.id), false, now)
	return s.state == .Up
}

// ----------------------------------------------------------- state machine

// Moves the key state forward as far as it can go.
@(private)
progress :: proc(s: ^Session, now: Time) {
	ks := &s.ks
	for _ in 0 ..< 8 {
		if s.state == .Failed || s.state == .Closed {
			return
		}
		changed := false
		switch ks.state {
		case .Undef, .Initial, .Error:
			return
		case .Generated_Keys:
			// Commands still arrive: a token update, INFO, EXIT, HALT.
			if ks.tls_ok {
				changed = pump_app(s, now)
			}
		case .Pre_Start:
			if reliable.all_acked(&ks.chan) {
				ks.state = .Start
				changed = true
			}
		case .Start, .Sent_Key, .Got_Key:
			changed = drive_tls(s, now)
		case .Active:
			changed = pump_app(s, now)
			if !changed && s.state != .Failed {
				changed = try_generate(s, now)
			}
		}
		if s.role == .Server && s.state != .Failed && srv_push_check(s, now) {
			changed = true
		}
		flush_tls(s, now)
		if !changed {
			return
		}
	}
}

// TLS handshake, our key-method message, and the reading of what the server
// says. Returns true if the key state moved.
@(private)
drive_tls :: proc(s: ^Session, now: Time) -> (changed: bool) {
	if s.role == .Server {
		return srv_drive_tls(s, now)
	}
	ks := &s.ks
	if !ks.tls_ok {
		sess, err := tls_new_session(s)
		if err != .None {
			fail(s, .Internal, "TLS session")
			return false
		}
		ks.tls = sess
		ks.tls_ok = true
		changed = true
	}
	hs := ossl.tls_handshake_step(&ks.tls)
	if hs == .Failed {
		fail_tls(s, now)
		return false
	}
	flush_tls(s, now)
	if hs != .Done {
		return changed
	}
	if ks.id == 0 && !s.peer_key_ok {
		s.peer_key, s.peer_key_ok = ossl.tls_peer_key(&ks.tls)
	}
	if !ks.km_sent {
		if !send_key_method(s, now) {
			return false
		}
		if ks.state == .Start {
			ks.state = .Sent_Key
		}
		changed = true
	}
	if pump_app(s, now) {
		changed = true
	}
	if s.state == .Failed {
		return false
	}
	if ks.km_sent && ks.km_got && ks.state != .Active && reliable.all_acked(&ks.chan) {
		ks.state = .Active
		ks.active_at = now
		reliable.clear_deadline(&ks.chan)
		changed = true
		if ks.id == 0 {
			// The wait for the push has its own deadline.
			// SPEC-GAP: it starts when the key state turns ACTIVE.
			s.push_deadline = now + s.cfg.hand_window
			s.push_deadline_on = true
		}
	}
	return changed
}

// Reads what the server wrote. A client that cannot tell yet whether the
// server accepted its certificate (TLS 1.3) learns it here, from the server's
// key-method message or from an alert. Returns true if data came.
@(private)
pump_app :: proc(s: ^Session, now: Time) -> (got: bool) {
	ks := &s.ks
	for s.state != .Failed {
		n, st := ossl.tls_read_app(&ks.tls, s.plain[:])
		#partial switch st {
		case .Ok:
			handle_app_data(s, s.plain[:n], now)
			zero_bytes(s.plain[:n])
			got = true
			continue
		case .Want_More, .Not_Ready:
		case .Closed:
			fail(s, .Tls, "the peer closed the TLS session")
		case .Failed:
			fail_tls(s, now)
		}
		break
	}
	return
}

// ACTIVE to GENERATED_KEYS: the keys of this key id go live. Key 0 waits for
// the PUSH_REPLY, because the cipher and the flags come from it.
@(private)
try_generate :: proc(s: ^Session, now: Time) -> bool {
	if s.role == .Server {
		return srv_try_generate(s, now)
	}
	ks := &s.ks
	if ks.id == 0 && !ks.push_done {
		return false
	}
	if !install_keys(s, now) {
		return false
	}
	ks.state = .Generated_Keys
	s.rekeying = false
	if ks.id == 0 {
		s.state = .Up
		s.push_deadline_on = false
		s.last_rx = now
		s.last_tx = now
		emit(s, Event{kind = .Up, key_id = 0})
	} else {
		emit(s, Event{kind = .Key_Installed, key_id = ks.id, by_peer = ks.by_peer})
	}
	return true
}

// ---------------------------------------------------------------- key-method

@(private)
send_key_method :: proc(s: ^Session, now: Time) -> bool {
	ks := &s.ks
	rnd: [push.KEY_METHOD_RANDOM_CLIENT]u8
	if !fill_random(s, rnd[:]) {
		fail(s, .Internal, "random")
		return false
	}
	obuf: [push.OPTIONS_MAX_LEN]u8
	op := push.Options_Params {
		role      = .Client,
		transport = s.transport,
		tun_mtu   = s.cfg.tun_mtu,
		cipher    = s.ciphers[0],
	}
	opts, oerr := push.options_build(obuf[:], &op)
	if oerr != .None {
		fail(s, .Internal, "options string")
		return false
	}
	pbuf: [1024]u8
	// SPEC-GAP: no `ID=` is sent (asymmetric peer ids are not implemented), so
	// the server pushes `peer-id`, or none, and we use 0xFFFFFF when none comes.
	pp := push.Peer_Info_Params {
		version       = string(s.ver[:s.ver_n]),
		platform      = string(s.plat[:s.plat_n]),
		tcp_nonlinear = true,
		mtu           = s.cfg.iv_mtu_sent if s.cfg.iv_mtu_sent > 0 else s.cfg.iv_mtu,
		ciphers       = s.ciphers[:s.ciphers_n],
		proto         = s.cfg.iv_proto,
	}
	sso_line: [SSO_MAX + 7]u8
	extra: [1]string
	if s.sso_n > 0 {
		n := copy(sso_line[:], "IV_SSO=")
		n += copy(sso_line[n:], s.sso[:s.sso_n])
		extra[0] = string(sso_line[:n])
		pp.extra = extra[:]
	}
	pinfo, perr := push.peer_info_build(pbuf[:], &pp)
	if perr != .None {
		fail(s, .Internal, "peer info")
		return false
	}
	// With a token the token is the password.
	user := string(s.user[:s.user_n])
	pass := string(s.pass[:s.pass_n])
	if s.token_n > 0 {
		pass = string(s.token[:s.token_n])
		if s.token_user_n > 0 {
			user = string(s.token_user[:s.token_user_n])
		}
	}
	km := push.Key_Method {
		sender    = .Client,
		random    = rnd[:],
		options   = opts,
		username  = user,
		password  = pass,
		login     = s.user_n > 0 || s.pass_n > 0 || s.token_n > 0,
		peer_info = pinfo,
	}
	kbuf: [push.KEY_METHOD_MAX_LEN]u8
	n, kerr := push.keymethod_encode(kbuf[:], &km)
	zero_bytes(rnd[:])
	if kerr != .None {
		zero_bytes(kbuf[:])
		fail(s, .Key_Method, "cannot build the key-method message")
		return false
	}
	st := ossl.tls_write_app(&ks.tls, kbuf[:n])
	zero_bytes(kbuf[:])
	if st != .Ok {
		fail_tls(s, now)
		return false
	}
	ks.km_sent = true
	flush_tls(s, now)
	return true
}

@(private)
zero_bytes :: proc "contextless" (b: []u8) {
	for i in 0 ..< len(b) {
		b[i] = 0
	}
}

// Plain data from TLS: the server's key-method message first, then commands.
@(private)
handle_app_data :: proc(s: ^Session, data: []u8, now: Time) {
	if s.role == .Server {
		srv_handle_app_data(s, data, now)
		return
	}
	ks := &s.ks
	if ks.km_got {
		handle_commands(s, data, now)
		return
	}
	if ks.km_len + len(data) > len(ks.km_in) {
		fail(s, .Key_Method, "the key-method message is too long")
		return
	}
	copy(ks.km_in[ks.km_len:], data)
	ks.km_len += len(data)
	km: push.Key_Method
	used, err := push.keymethod_decode(ks.km_in[:ks.km_len], .Server, &km)
	#partial switch err {
	case .None:
	case .Need_More:
		// SPEC-GAP: a server message that ends right after the password (no
		// peer-info field) stays "incomplete" here and waits until the hand
		// window. Stock servers always write the field (empty: two zero bytes).
		return
	case:
		fail(s, .Key_Method, "the key-method message from the server is not valid")
		return
	}
	// The options string is only for logs, but its cipher is the fallback of
	// the negotiation.
	info: push.Options_Info
	if push.options_parse(km.options, &info) == .None {
		ks.srv_cipher_n = u8(copy(ks.srv_cipher[:], info.cipher))
	}
	ks.km_got = true
	if ks.state == .Sent_Key {
		ks.state = .Got_Key
	}
	if ks.id == 0 {
		ks.push_req_on = true
		ks.push_req_at = now + HANDSHAKE_REQUEST_FIRST
	}
	rest := ks.km_in[used:ks.km_len]
	handle_commands(s, rest, now)
	zero_bytes(ks.km_in[:ks.km_len])
	ks.km_len = 0
}

// ------------------------------------------------------------------ commands

@(private)
handle_commands :: proc(s: ^Session, data: []u8, now: Time) {
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
			handle_command(s, text, now)
		}
	}
}

@(private)
handle_command :: proc(s: ^Session, text: string, now: Time) {
	// SPEC-GAP: the spec says EXIT is client to server and a command
	// for the other direction is ignored. It also says a client treats an EXIT from the
	// server as a remote exit. We follow 9.2 (stock servers never send it), so it
	// is checked before `command_parse`, which refuses it.
	if text == "EXIT" {
		emit(s, Event{kind = .Remote_Exit})
		fail(s, .Server_Signal, "the server sent EXIT")
		return
	}
	cmd, err := push.command_parse(text, .Client)
	if err != .None {
		return // wrong direction or malformed: ignored, as a stock client does
	}
	switch c in cmd {
	case push.Push_Reply_Msg:
		handle_push_reply(s, c.options, now)
	case push.Auth_Failed:
		handle_auth_failed(s, c)
	case push.Auth_Pending:
		handle_auth_pending(s, c, now)
	case push.Info_Msg:
		if c.pre {
			n := min(len(c.text), INFO_PRE_MAX)
			zero_bytes(s.info_pre[:])
			s.info_pre_n = copy(s.info_pre[:n], c.text[:n])
			s.info_pre_cut = len(c.text) > INFO_PRE_MAX
			emit(s, Event{kind = .Info_Pre})
			break
		}
		ev := Event {
			kind = .Info,
		}
		event_set_text(&ev, c.text)
		emit(s, ev)
	case push.Restart:
		ev := Event {
			kind             = .Restart,
			keep_credentials = c.keep_credentials,
			next_remote      = c.next_remote,
		}
		event_set_text(&ev, c.text)
		emit(s, ev)
		fail(s, .Server_Signal, "the server sent RESTART")
	case push.Halt:
		ev := Event {
			kind             = .Halt,
			keep_credentials = c.keep_credentials,
			next_remote      = c.next_remote,
		}
		event_set_text(&ev, c.text)
		emit(s, ev)
		fail(s, .Server_Signal, "the server sent HALT")
	case push.Exit_Cmd:
		emit(s, Event{kind = .Remote_Exit})
		fail(s, .Server_Signal, "the server sent EXIT")
	case push.Push_Update_Msg:
		// SPEC-GAP: we do not announce IV_PROTO bit 12, so a conforming server
		// never sends this. A stray one is ignored.
	case push.Push_Request, push.Cr_Response, push.Acc_Cmd, push.Unknown_Cmd:
	}
}

@(private)
handle_auth_failed :: proc(s: ^Session, a: push.Auth_Failed) {
	ev := Event {
		kind      = .Auth_Failed,
		auth_kind = a.kind,
		reason    = .Auth_Failed,
	}
	// A token the server no longer accepts must go.
	if s.token_n > 0 {
		zero_bytes(s.token[:])
		zero_bytes(s.token_user[:])
		s.token_n = 0
		s.token_user_n = 0
		ev.token_dropped = true
	}
	#partial switch a.kind {
	case .Temp:
		ev.backoff = a.temp.backoff
		ev.advance = a.temp.advance
		event_set_text(&ev, a.reason)
	case .Crv1:
		// Dynamic challenge is not supported: the text says so.
		event_set_text(&ev, "this client does not support dynamic challenges (CRV1)")
	case:
		event_set_text(&ev, a.reason)
	}
	emit(s, ev)
	fail(s, .Auth_Failed, "authentication failed")
}

@(private)
handle_auth_pending :: proc(s: ^Session, a: push.Auth_Pending, now: Time) {
	// The wait for the push reply is extended, by at
	// most max(reneg-sec / 2, hand-window).
	ext := s.cfg.hand_window
	if a.has_timeout && a.timeout > 0 {
		ext = time.Duration(a.timeout) * time.Second
		limit := max(time.Duration(max(s.cfg.reneg_sec, 0)) * time.Second / 2, s.cfg.hand_window)
		ext = min(ext, limit)
	}
	if s.push_deadline_on {
		s.push_deadline = now + ext
	}
	if s.ks.state < .Active {
		reliable.set_deadline(&s.ks.chan, now + ext)
	}
	ev := Event {
		kind    = .Auth_Pending,
		timeout = a.timeout,
	}
	emit(s, ev)
}

// ---------------------------------------------------------------------- push

@(private)
handle_push_reply :: proc(s: ^Session, options: string, now: Time) {
	ks := &s.ks
	options := options
	if s.cfg.push_filter != nil {
		// `tls_buf` holds nothing here: TLS output is taken only in `flush_tls`.
		out := s.tls_buf[:len(options)]
		n, why, ok := s.cfg.push_filter(s.cfg.push_filter_user, options, out)
		if !ok {
			fail(s, .Push, why if len(why) > 0 else "pull-filter reject")
			return
		}
		options = string(out[:n])
	}
	st, err := push.push_assembler_feed(&s.asm_, options)
	if err != .None {
		fail(s, .Push, "bad PUSH_REPLY")
		return
	}
	if st == .More {
		return
	}
	po := &s.asm_.po
	// A reply that only renews the token changes nothing else.
	if push.pushed_options_token_only(po) {
		if store_token(s, po) {
			emit(s, Event{kind = .Token_Updated, key_id = ks.id})
		}
		push.push_assembler_reset(&s.asm_)
		return
	}
	if s.have_pushed || ks.id != 0 || ks.push_done {
		// A second full reply: the first one stays.
		if store_token(s, po) {
			emit(s, Event{kind = .Token_Updated, key_id = ks.id})
		}
		push.push_assembler_reset(&s.asm_)
		return
	}
	params := push.Validate_Params {
		own_ciphers           = s.ciphers[:s.ciphers_n],
		server_options_cipher = string(ks.srv_cipher[:ks.srv_cipher_n]),
		iv_mtu                = s.cfg.iv_mtu,
	}
	res := push.pushed_options_validate(po, &params)
	if res.failure != .None {
		fail(s, .Push, push_failure_text(res.failure))
		return
	}
	if .Aead_Epoch in po.protocol_flags && .Data_Epoch not_in s.cfg.iv_proto {
		// The server decides the format, but only for a client that offered it
		//: if we did not announce bit 10, this is a server error.
		fail(s, .Push, "the server pushed aead-epoch, which this client did not offer")
		return
	}
	s.cipher = res.cipher
	s.flags = po.protocol_flags
	s.flags += {.Tls_Ekm}
	s.format = format_of_flags(s.flags)
	s.peer_id = po.peer_id.? or_else PEER_ID_NONE
	s.ping = pick_timer(s.cfg.ping, po.ping.? or_else s.cfg.ping_default)
	pushed_restart := po.ping_restart.? or_else 0
	if pushed_restart == 0 {
		pushed_restart = po.ping_exit.? or_else 0
	}
	if po.ping_restart == nil && po.ping_exit == nil {
		pushed_restart = s.cfg.ping_restart_default
	}
	s.ping_restart = pick_timer(s.cfg.ping_restart, pushed_restart)
	s.exit_notify = s.cfg.explicit_exit_notify
	// SPEC-GAP: `explicit-exit-notify` without a number counts as 1.
	if en, ok := po.explicit_exit_notify.?; ok && s.exit_notify == 0 {
		s.exit_notify = max(en, 1)
	}
	if s.cfg.ext_data {
		// The owner runs the keepalive; the exit notice goes over the control
		// channel only.
		s.ext_ping, s.ext_ping_restart = s.ping, s.ping_restart
		s.ping, s.ping_restart = 0, 0
		s.exit_notify = 0
	}
	if store_token(s, po) {
		emit(s, Event{kind = .Token_Updated, key_id = ks.id})
	}
	// Keep the parsed reply for the caller; start a fresh assembler.
	s.pushed = po^
	s.have_pushed = true
	push.push_assembler_init(&s.asm_, s.allocator)
	ks.push_done = true
	ks.push_req_on = false
}

@(private)
pick_timer :: proc "contextless" (cfg, pushed: int) -> int {
	if cfg < 0 {
		return 0
	}
	if cfg > 0 {
		return cfg
	}
	return pushed
}

@(private)
push_failure_text :: proc "contextless" (f: push.Validate_Failure) -> string {
	switch f {
	case .None:
		return ""
	case .Rejected_Option:
		return "the server pushed an option that this client refuses"
	case .Missing_Topology:
		return "the server pushed no topology, and net30 is not supported"
	case .No_Key_Derivation:
		return "the server did not select tls-ekm key derivation"
	case .Cipher_Not_Allowed:
		return "the server pushed a cipher that is not in the data-ciphers list"
	case .No_Usable_Cipher:
		return "there is no usable data cipher"
	case .Epoch_Needs_Peer_Id:
		return "the server pushed aead-epoch without a peer id"
	case .Epoch_Needs_Aead:
		return "the server pushed aead-epoch without an AEAD cipher"
	case .Mtu_Too_Large:
		return "the server pushed a tun-mtu above the IV_MTU that this client sent"
	}
	return "the pushed options were refused"
}

// Keeps the auth-token of a reply. Never logged. Returns true if one was there.
@(private)
store_token :: proc(s: ^Session, po: ^push.Pushed_Options) -> bool {
	if len(po.auth_token) == 0 {
		return false
	}
	if len(po.auth_token) > CREDENTIAL_MAX {
		return false
	}
	zero_bytes(s.token[:])
	s.token_n = copy(s.token[:], po.auth_token)
	if len(po.auth_token_user) > 0 {
		var_user: [CREDENTIAL_MAX + 1]u8
		n, ok := b64_decode(po.auth_token_user, var_user[:])
		if ok && n > 0 && n <= CREDENTIAL_MAX {
			zero_bytes(s.token_user[:])
			copy(s.token_user[:], var_user[:n])
			s.token_user_n = n
		}
	}
	return true
}
