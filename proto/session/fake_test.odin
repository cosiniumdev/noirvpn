// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:fmt"
import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/reliable"
import "noir:proto/wire"
import "noir:proto/wrap"

// A test server built from the same blocks as the client (wrap, reliable, ossl,
// push, keys, crypt) in the server role. It holds one peer, keeps state in plain
// fields and echoes tunnel packets. It may be strict where the stock server is
// lenient, so a client that passes here also passes the real thing for the points
// tested.

CA_PEM := #load("../ossl/testdata/ca.crt.pem")
SERVER_CRT := #load("../ossl/testdata/chain_server.crt.pem")
SERVER_KEY := #load("../ossl/testdata/chain_server.key.pem")
CLIENT_CRT := #load("../ossl/testdata/chain_client.crt.pem")
CLIENT_KEY := #load("../ossl/testdata/chain_client.key.pem")
OTHER_CA_PEM := #load("../ossl/testdata/other_ca.crt.pem")
P256_SERVER_CRT := #load("../ossl/testdata/p256_server.crt.pem")
P256_SERVER_KEY := #load("../ossl/testdata/p256_server.key.pem")
P256_CLIENT_CRT := #load("../ossl/testdata/p256_client.crt.pem")
P256_CLIENT_KEY := #load("../ossl/testdata/p256_client.key.pem")
P256_SERVER_SPKI := #load("../ossl/testdata/p256_server.spki.der")
P256_SERVER_DER := #load("../ossl/testdata/p256_server.crt.der")
P256_CLIENT_SPKI := #load("../ossl/testdata/p256_client.spki.der")
MLDSA_SERVER_CRT := #load("../ossl/testdata/mldsa65_server.crt.pem")
MLDSA_SERVER_KEY := #load("../ossl/testdata/mldsa65_server.key.pem")
MLDSA_CLIENT_CRT := #load("../ossl/testdata/mldsa65_client.crt.pem")
MLDSA_CLIENT_KEY := #load("../ossl/testdata/mldsa65_client.key.pem")
MLDSA_SERVER_SPKI := #load("../ossl/testdata/mldsa65_server.spki.der")

FAKE_QUEUE :: 64
FAKE_WALL_BASE :: i64(1_700_000_000)
FAKE_USER :: "alice"
FAKE_PASS :: "secret-pw"
FAKE_TOKEN :: "SESS_ID_0123456789abcdef"

Fake_Opts :: struct {
	mode:          Wrap_Mode,
	transport:     Transport,
	cipher:        push.Cipher, // default AES-256-GCM
	auth_digest:   ossl.Hmac_Alg,
	key_direction: wrap.Key_Direction, // the client's; the server takes the other
	// Pushed with protocol-flags.
	cc_exit:       bool,
	dyn:           bool,
	epoch:         bool, // push aead-epoch and use the epoch format (a client that did not offer it fails)
	// Replaces the AEAD usage limit of the fake's own data keys (0: the spec's
	// value): the fake then moves its send epoch early.
	limit:         u64,
	// Login.
	login:         bool, // check the user name and password (or the token)
	token:         bool, // push an auth-token
	// v2 over UDP: ask the client to resend the WKc on message id 1.
	early_neg:     bool,
	// Never reply to PUSH_REQUEST.
	silent_push:   bool,
	// Send AUTH_PENDING before the reply.
	pending:       int,
	// Send this text as the reply to PUSH_REQUEST (for example AUTH_FAILED).
	reject:        string,
	// Own keepalive: 0 none.
	ping:          int,
	ping_restart:  int,
	peer_id:       int, // -1 none; default 0 is a real peer id 0
	no_peer_id:    bool,
	explicit_exit: int,
	extra:         []string, // extra options for the PUSH_REPLY
	// PUSH_REPLY messages sent as they are (captured from a stock server).
	raw_reply:     []string,
	// Reply cut in parts of this many routes (push continuation test).
	routes:        int,
	// A cert chain that the client does not trust, or a plain server.
	p256:          bool,
	// ML-DSA-65 certificates, pinned (a long TLS flight).
	mldsa:         bool,
	mtu:           int,
}

Fake_Pkt :: struct {
	n: int,
	b: [LINK_BUF_SIZE]u8,
}

Fake :: struct {
	o:             Fake_Opts,
	skey:          wrap.Static_Key,
	client_key:    wrap.Client_Key,
	server_key:    wrap.Server_Key,
	kc:            wrap.Static_Key,
	auth:          wrap.Tls_Auth,
	wcrypt:        wrap.Tls_Crypt,
	crypt_ok:      bool,
	dyn:           wrap.Tls_Crypt,
	have_dyn:      bool,
	sid:           reliable.Sid,
	peer_sid:      reliable.Sid,
	peer_set:      bool,
	chan:          reliable.Channel,
	chan_ok:       bool,
	key_id:        u8,
	state_up:      bool, // a key state exists
	installed:     bool, // keys of this key state are created
	tls_ctx:       ossl.Tls_Ctx,
	tls:           ossl.Tls_Session,
	tls_ok:        bool,
	tls_failed:    bool,
	km:            [2048]u8,
	km_n:          int,
	km_got:        bool,
	km_sent:       bool,
	cmd:           push.Cmd_Reader,
	pushed:        bool,
	dk:            [8]crypt.Data_Key,
	have_dk:       [8]bool,
	tx_kid:        u8,
	q:             [FAKE_QUEUE]Fake_Pkt,
	q_head:        int,
	q_n:           int,
	last_tx:       Time,
	reply_pending: int,
	// What the tests look at.
	seen_ops:      [16]int, // control packets received, by opcode
	op11_ids:      [8]u32,
	op11_n:        int,
	client_opts:   [512]u8,
	client_opts_n: int,
	peer_info:     [1024]u8,
	peer_info_n:   int,
	user:          [128]u8,
	user_n:        int,
	pass:          [128]u8,
	pass_n:        int,
	cmds:          [8][64]u8, // commands received, first 8
	cmds_n:        int,
	got_exit:      bool,
	occ_exits:     int,
	pings:         int,
	tunnel_rx:     int,
	data_bad:      int,
	rekeys:        int,
	pushes_sent:   int,
	silent:        bool, // stop all own traffic (keepalive)
	drop_wrap:     int,
	pin:           [2][32]u8,
}

fake_text :: proc(buf: []u8, n: int) -> string {
	return string(buf[:n])
}

fake_opts_cipher :: proc(o: ^Fake_Opts) -> push.Cipher {
	if o.cipher == .None {
		return .Aes_256_Gcm
	}
	return o.cipher
}

// Deterministic bytes, so a run can be repeated.
fake_fill :: proc(seed: u64, b: []u8) {
	x := seed * 0x9E3779B97F4A7C15 + 1
	for i in 0 ..< len(b) {
		x ~= x >> 12
		x ~= x << 25
		x ~= x >> 27
		b[i] = u8((x * 0x2545F4914F6CDD1D) >> 56)
	}
}

fake_init :: proc(f: ^Fake, o: Fake_Opts) -> bool {
	f^ = {}
	f.o = o
	fake_fill(1, f.skey.bytes[:])
	// Spec rule: the first 16 bytes of each slot must not be zero.
	fake_fill(77, f.sid[:])
	switch o.mode {
	case .None:
	case .Tls_Auth:
		alg := o.auth_digest if o.auth_digest != nil else ossl.Hmac_Alg.SHA1
		dir := wrap.Key_Direction.Bidirectional
		#partial switch o.key_direction {
		case .One:
			dir = .Zero
		case .Zero:
			dir = .One
		}
		wrap.tls_auth_init(&f.auth, &f.skey, alg, dir)
	case .Tls_Crypt:
		wrap.tls_crypt_init(&f.wcrypt, &f.skey, .Server)
		f.crypt_ok = true
	case .Tls_Crypt_V2:
		sk: [wrap.SERVER_KEY_LEN]u8
		fake_fill(5, sk[:])
		if wrap.server_key_from_bytes(sk[:], &f.server_key) != .None {
			return false
		}
		fake_fill(9, f.kc.bytes[:])
		meta: [9]u8
		meta[0] = 1
		n, werr := wrap.tls_crypt_v2_wkc_build(&f.server_key, &f.kc, meta[:], f.client_key.wkc[:])
		if werr != .None {
			return false
		}
		f.client_key.wkc_len = n
		f.client_key.kc = f.kc
	}
	cfg := ossl.Tls_Config {
		role        = .Server,
		cert_pem    = SERVER_CRT,
		key_pem     = SERVER_KEY,
		verify      = .Chain,
		ca_pem      = CA_PEM,
		min_version = .TLS_1_2,
	}
	if o.p256 {
		cfg.cert_pem, cfg.key_pem = P256_SERVER_CRT, P256_SERVER_KEY
		cfg.verify = .Pinned
		cfg.pin_check = fake_pin_ok
	}
	if o.mldsa {
		cfg.cert_pem, cfg.key_pem = MLDSA_SERVER_CRT, MLDSA_SERVER_KEY
		cfg.verify = .Pinned
		cfg.pin_check = fake_pin_ok
	}
	ctx, err := ossl.tls_ctx_create(cfg)
	if err != .None {
		return false
	}
	f.tls_ctx = ctx
	ccfg := reliable.Config {
		timeout     = 2 * time.Second,
		hand_window = 60 * time.Second,
		max_payload = reliable.DEFAULT_MAX_PAYLOAD,
		local_sid   = f.sid,
	}
	if reliable.init(&f.chan, ccfg, 0) != .None {
		return false
	}
	f.chan_ok = true
	return true
}

// For the pinned server: accept every client key (the client key is not the
// subject of these tests).
fake_pin_ok :: proc "contextless" (peer: ossl.Peer_Key, user: rawptr) -> bool {
	return true
}

fake_destroy :: proc(f: ^Fake) {
	if f.tls_ok {
		ossl.tls_session_destroy(&f.tls)
	}
	if f.chan_ok {
		reliable.destroy(&f.chan)
	}
	for i in 0 ..< 8 {
		if f.have_dk[i] {
			crypt.data_key_destroy(&f.dk[i])
		}
	}
	ossl.tls_ctx_destroy(&f.tls_ctx)
}

// The client-side settings that match this server.
fake_client_config :: proc(f: ^Fake, cfg: ^Config) {
	cfg.transport = f.o.transport
	cfg.wrap.mode = f.o.mode
	cfg.wrap.auth_digest = f.o.auth_digest if f.o.auth_digest != nil else ossl.Hmac_Alg.SHA1
	cfg.wrap.key_direction = f.o.key_direction
	cfg.wrap.static_key = &f.skey
	cfg.wrap.client_key = &f.client_key
	cfg.cert_pem, cfg.key_pem = CLIENT_CRT, CLIENT_KEY
	cfg.ca_pem = CA_PEM
	cfg.verify = .Chain
	if f.o.p256 {
		cfg.cert_pem, cfg.key_pem = P256_CLIENT_CRT, P256_CLIENT_KEY
		f.pin[0] = ossl.sha256(P256_SERVER_SPKI)
		f.pin[1] = ossl.sha256(P256_SERVER_DER)
		cfg.verify = .Pinned
		cfg.pin_spki = f.pin[0:1]
	}
	if f.o.mldsa {
		cfg.cert_pem, cfg.key_pem = MLDSA_CLIENT_CRT, MLDSA_CLIENT_KEY
		f.pin[0] = ossl.sha256(MLDSA_SERVER_SPKI)
		cfg.verify = .Pinned
		cfg.pin_spki = f.pin[0:1]
	}
	cfg.ipv4_peer = true
	if f.o.login {
		cfg.username = FAKE_USER
		cfg.password = FAKE_PASS
	}
}

// ------------------------------------------------------------------- wrapping

fake_wall :: proc(now: Time) -> i64 {
	return FAKE_WALL_BASE + i64(now / time.Second)
}

fake_wrap :: proc(f: ^Fake, kid: u8, now: Time, inner, out: []u8) -> (n: int, ok: bool) {
	t := fake_wall(now)
	err: wrap.Error
	switch {
	case kid != 0 && f.have_dyn:
		n, err = wrap.tls_crypt_wrap(&f.dyn, t, inner, out)
	case f.o.mode == .None:
		copy(out, inner)
		n = len(inner)
	case f.o.mode == .Tls_Auth:
		n, err = wrap.tls_auth_wrap(&f.auth, t, inner, out)
	case:
		n, err = wrap.tls_crypt_wrap(&f.wcrypt, t, inner, out)
	}
	return n, err == .None
}

fake_unwrap :: proc(f: ^Fake, kid: u8, op: wire.Opcode, pkt, out: []u8) -> (n: int, ok: bool) {
	err: wrap.Error
	switch {
	case kid != 0 && f.have_dyn:
		n, err = wrap.tls_crypt_unwrap(&f.dyn, pkt, out)
	case f.o.mode == .None:
		copy(out, pkt)
		n = len(pkt)
	case f.o.mode == .Tls_Auth:
		n, err = wrap.tls_auth_unwrap(&f.auth, pkt, out)
	case f.o.mode == .Tls_Crypt:
		n, err = wrap.tls_crypt_unwrap(&f.wcrypt, pkt, out)
	case:
		// tls-crypt-v2: the first packet has the WKc and builds the context.
		if op == .Hard_Reset_Client_V3 && !f.crypt_ok {
			meta: wrap.Metadata
			n, err = wrap.tls_crypt_v2_server_unwrap(&f.server_key, pkt, out, &f.wcrypt, &meta)
			f.crypt_ok = err == .None
		} else if op == .Hard_Reset_Client_V3 || op == .Control_Wkc_V1 {
			body, _, serr := wrap.tls_crypt_v2_split_wkc(pkt)
			if serr != .None {
				return 0, false
			}
			n, err = wrap.tls_crypt_unwrap(&f.wcrypt, body, out)
		} else {
			n, err = wrap.tls_crypt_unwrap(&f.wcrypt, pkt, out)
		}
	}
	return n, err == .None
}

// ------------------------------------------------------------------ send side

fake_queue :: proc(f: ^Fake) -> ^Fake_Pkt {
	if f.q_n >= FAKE_QUEUE {
		return nil
	}
	p := &f.q[(f.q_head + f.q_n) % FAKE_QUEUE]
	f.q_n += 1
	p.n = 0
	return p
}

// A control packet from the reliability layer, wrapped. Returns its length.
fake_emit :: proc(f: ^Fake, tx: reliable.Tx, out: []u8, now: Time) -> int {
	cp: wire.Control_Packet
	#partial switch tx.kind {
	case .Control:
		cp.opcode = wire.Opcode(tx.tag)
		cp.packet_id = tx.id
		cp.payload = tx.payload
	case .Ack:
		cp.opcode = .Ack_V1
	}
	cp.key_id = f.key_id
	cp.session_id = f.sid
	cp.ack_count = int(tx.acks.count)
	for i in 0 ..< cp.ack_count {
		cp.acks[i] = tx.acks.ids[i]
	}
	cp.ack_remote_sid = tx.acks.sid
	inner: [INNER_MAX]u8
	n, eerr := wire.control_encode(inner[:], &cp)
	if eerr != .None {
		return 0
	}
	wn, ok := fake_wrap(f, f.key_id, now, inner[:n], out)
	if !ok {
		return 0
	}
	return wn
}

// Next packet for the client (without the TCP length prefix), or 0.
fake_poll :: proc(f: ^Fake, out: []u8, now: Time) -> int {
	if f.q_n > 0 {
		p := &f.q[f.q_head]
		n := p.n
		copy(out, p.b[:n])
		f.q_head = (f.q_head + 1) % FAKE_QUEUE
		f.q_n -= 1
		return n
	}
	if !f.chan_ok || !f.peer_set {
		return 0
	}
	if tx, ok := reliable.poll(&f.chan, now); ok {
		return fake_emit(f, tx, out, now)
	}
	return 0
}

fake_wake :: proc(f: ^Fake, now: Time) -> (at: Time, ok: bool) {
	if f.q_n > 0 {
		return now, true
	}
	if f.chan_ok && f.peer_set {
		at, ok = reliable.next_wakeup(&f.chan, now)
	}
	if f.o.ping > 0 && f.installed && !f.silent {
		t := f.last_tx + time.Duration(f.o.ping) * time.Second
		if !ok || t < at {
			at, ok = t, true
		}
	}
	return
}

fake_tick :: proc(f: ^Fake, now: Time) {
	if f.installed && f.o.ping > 0 && !f.silent && now - f.last_tx >= time.Duration(f.o.ping) * time.Second {
		buf: [crypt.PING_LEN]u8
		plain, _ := crypt.build_ping(buf[:])
		fake_data_tx(f, plain, now)
	}
	if f.chan_ok && f.peer_set {
		reliable.next_wakeup(&f.chan, now)
	}
}

// Puts what TLS wants to send into reliable packets.
fake_flush :: proc(f: ^Fake, now: Time) {
	if !f.tls_ok {
		return
	}
	budget := reliable.payload_budget(1250, reliable.WRAP_OVERHEAD_TLS_CRYPT, reliable.IP_UDP_OVERHEAD_V4)
	scratch: [6 * 1250]u8
	for ossl.tls_pending_out(&f.tls) > 0 {
		room := reliable.send_room(&f.chan)
		if room == 0 {
			return
		}
		n := ossl.tls_take(&f.tls, scratch[:min(room * budget, len(scratch), ossl.tls_pending_out(&f.tls))])
		reliable.send(&f.chan, scratch[:n], budget, u8(wire.Opcode.Control_V1), now)
	}
}

fake_text_out :: proc(f: ^Fake, text: string, now: Time) {
	buf: [push.MAX_COMMAND_LEN]u8
	n, err := push.cmd_frame(buf[:], text)
	if err != .None {
		return
	}
	ossl.tls_write_app(&f.tls, buf[:n])
	fake_flush(f, now)
}

// ---------------------------------------------------------------- data channel

// The data format the fake pushes.
fake_format :: proc(f: ^Fake) -> keys.Format {
	return .Epoch if f.o.epoch else .Baseline
}

fake_data_tx :: proc(f: ^Fake, plain: []u8, now: Time) {
	p := fake_queue(f)
	if p == nil || !f.have_dk[f.tx_kid] {
		return
	}
	head, _ := format_room(fake_format(f))
	copy(p.b[head:], plain)
	pid := u32(0xFFFFFF) if f.o.no_peer_id else u32(f.o.peer_id)
	n, err := crypt.data_key_seal(&f.dk[f.tx_kid], pid, p.b[head:][:len(plain)], p.b[:])
	if err != .None {
		f.q_n -= 1
		return
	}
	p.n = n
	f.last_tx = now
}

fake_data_rx :: proc(f: ^Fake, pkt: []u8, now: Time) {
	hdr, _, herr := wire.data_v2_decode(pkt)
	if herr != .None || !f.have_dk[hdr.key_id] {
		f.data_bad += 1
		return
	}
	head, _ := format_room(fake_format(f))
	res, err := crypt.data_key_open(&f.dk[hdr.key_id], pkt, pkt[head:])
	if err != .None {
		f.data_bad += 1
		return
	}
	plain := pkt[head:][:res.n]
	kind := crypt.classify_payload(plain)
	switch {
	case crypt.payload_is_tunnel(kind):
		f.tunnel_rx += 1
		fake_data_tx(f, plain, now)
	case kind == .Ping:
		f.pings += 1
	case kind == .Occ_Exit:
		f.occ_exits += 1
	}
}

// ------------------------------------------------------------- control receive

fake_receive :: proc(f: ^Fake, pkt: []u8, now: Time) {
	if len(pkt) < 1 {
		return
	}
	op, kid := wire.split_first_byte(pkt[0])
	if op == .Data_V2 {
		fake_data_rx(f, pkt, now)
		return
	}
	if wire.opcode_class(op) != .Control || !wire.opcode_allowed_for_receiver(op, .Server) {
		return
	}
	if len(pkt) < wire.CONTROL_PREFIX_LEN {
		return
	}
	inner: [INNER_MAX]u8
	n, ok := fake_unwrap(f, kid, op, pkt, inner[:])
	if !ok {
		f.drop_wrap += 1
		return
	}
	cp: wire.Control_Packet
	if wire.control_decode(inner[:n], &cp) != .None {
		return
	}
	f.seen_ops[int(op) & 15] += 1
	if op == .Control_Wkc_V1 && f.op11_n < len(f.op11_ids) {
		f.op11_ids[f.op11_n] = cp.packet_id
		f.op11_n += 1
	}
	#partial switch op {
	case .Hard_Reset_Client_V2, .Hard_Reset_Client_V3:
		if !f.peer_set {
			f.peer_sid = cp.session_id
			f.peer_set = true
			reliable.set_peer_sid(&f.chan, cp.session_id)
			f.state_up = true
			reliable.reset(&f.chan, now)
			payload: []u8
			tlv := [6]u8{0, 1, 0, 2, 0, 1}
			if f.o.early_neg && f.o.mode == .Tls_Crypt_V2 {
				payload = tlv[:]
			}
			reliable.send_packet(&f.chan, u8(wire.Opcode.Hard_Reset_Server_V2), payload, now)
		} else if cp.session_id != f.peer_sid {
			return
		}
	case .Soft_Reset_V1:
		if cp.session_id != f.peer_sid {
			return
		}
		if cp.key_id == keys.key_id_next(f.key_id) && f.installed {
			fake_new_state(f, cp.key_id, now)
		}
	}
	if cp.session_id != f.peer_sid || cp.key_id != f.key_id {
		return
	}
	rx := reliable.Rx {
		has_msg    = op != .Ack_V1,
		id         = cp.packet_id,
		tag        = u8(op),
		hard_reset = op == .Hard_Reset_Client_V2 || op == .Hard_Reset_Client_V3,
		payload    = cp.payload,
	}
	rx.acks.count = u8(cp.ack_count)
	for i in 0 ..< cp.ack_count {
		rx.acks.ids[i] = cp.acks[i]
	}
	rx.acks.sid = cp.ack_remote_sid
	reliable.receive(&f.chan, rx, now)
	for {
		d, have := reliable.pop(&f.chan)
		if !have {
			break
		}
		if wire.Opcode(d.tag) == .Control_V1 || wire.Opcode(d.tag) == .Control_Wkc_V1 {
			fake_tls_up(f)
			ossl.tls_feed(&f.tls, d.payload)
		}
	}
	fake_progress(f, now)
}

fake_tls_up :: proc(f: ^Fake) {
	if f.tls_ok {
		return
	}
	s, err := ossl.tls_session_create(&f.tls_ctx)
	if err == .None {
		f.tls = s
		f.tls_ok = true
	}
}

// Begins a new key state (a soft reset from either side).
fake_new_state :: proc(f: ^Fake, kid: u8, now: Time) {
	if f.tls_ok {
		ossl.tls_session_destroy(&f.tls)
		f.tls_ok = false
	}
	f.key_id = kid
	f.installed = false
	f.km_got, f.km_sent, f.km_n = false, false, 0
	f.cmd = {}
	f.pushed = false
	reliable.reset(&f.chan, now)
	reliable.send_packet(&f.chan, u8(wire.Opcode.Soft_Reset_V1), nil, now)
	f.rekeys += 1
}

// Server-started renegotiation.
fake_rekey :: proc(f: ^Fake, now: Time) {
	if f.installed {
		fake_new_state(f, keys.key_id_next(f.key_id), now)
	}
}

fake_progress :: proc(f: ^Fake, now: Time) {
	if !f.tls_ok || f.tls_failed {
		return
	}
	hs := ossl.tls_handshake_step(&f.tls)
	fake_flush(f, now)
	if hs == .Failed {
		f.tls_failed = true
		return
	}
	if hs != .Done {
		return
	}
	plain: [2048]u8
	for {
		n, st := ossl.tls_read_app(&f.tls, plain[:])
		if st != .Ok {
			break
		}
		fake_app(f, plain[:n], now)
	}
	fake_flush(f, now)
}

fake_app :: proc(f: ^Fake, data: []u8, now: Time) {
	rest := data
	if !f.km_got {
		if f.km_n + len(rest) > len(f.km) {
			return
		}
		copy(f.km[f.km_n:], rest)
		f.km_n += len(rest)
		km: push.Key_Method
		used, err := push.keymethod_decode(f.km[:f.km_n], .Client, &km)
		if err != .None {
			return
		}
		f.km_got = true
		f.client_opts_n = copy(f.client_opts[:], km.options)
		f.peer_info_n = copy(f.peer_info[:], km.peer_info)
		f.user_n = copy(f.user[:], km.username)
		f.pass_n = copy(f.pass[:], km.password)
		fake_send_km(f, now)
		rest = f.km[used:f.km_n]
		if f.o.login && !fake_login_ok(f) {
			fake_text_out(f, "AUTH_FAILED", now)
			return
		}
		if f.key_id != 0 {
			fake_install(f, now)
		}
	}
	for len(rest) > 0 {
		text, st := push.cmd_reader_next(&f.cmd, &rest)
		if st == .Need_More {
			break
		}
		if st != .Command {
			continue
		}
		if f.cmds_n < len(f.cmds) {
			copy(f.cmds[f.cmds_n][:], text)
			f.cmds_n += 1
		}
		switch {
		case text == "PUSH_REQUEST":
			fake_push(f, now)
		case text == "EXIT":
			f.got_exit = true
		}
	}
}

fake_login_ok :: proc(f: ^Fake) -> bool {
	u := string(f.user[:f.user_n])
	p := string(f.pass[:f.pass_n])
	if f.o.token && f.key_id != 0 {
		// A client that was given a token must use it from then on.
		return p == FAKE_TOKEN
	}
	if u == FAKE_USER && p == FAKE_PASS {
		return true
	}
	// After the first login the client sends the token as the password.
	return f.o.token && p == FAKE_TOKEN
}

fake_send_km :: proc(f: ^Fake, now: Time) {
	rnd: [push.KEY_METHOD_RANDOM_SERVER]u8
	fake_fill(300 + u64(f.key_id), rnd[:])
	obuf: [push.OPTIONS_MAX_LEN]u8
	op := push.Options_Params {
		role      = .Server,
		transport = f.o.transport,
		cipher    = fake_opts_cipher(&f.o),
	}
	opts, _ := push.options_build(obuf[:], &op)
	km := push.Key_Method {
		sender  = .Server,
		random  = rnd[:],
		options = opts,
	}
	buf: [push.KEY_METHOD_MAX_LEN]u8
	n, err := push.keymethod_encode(buf[:], &km)
	if err != .None {
		return
	}
	ossl.tls_write_app(&f.tls, buf[:n])
	f.km_sent = true
	fake_flush(f, now)
}

// Ends the AUTH_PENDING wait: sends the reply now.
fake_release :: proc(f: ^Fake, now: Time) {
	f.reply_pending = 2
	fake_push(f, now)
}

fake_push :: proc(f: ^Fake, now: Time) {
	if f.o.silent_push || f.pushed || f.key_id != 0 {
		return
	}
	if f.reply_pending == 1 {
		return
	}
	if f.o.pending > 0 && f.reply_pending == 0 {
		f.reply_pending = 1
		text: [48]u8
		fake_text_out(f, fmt.bprintf(text[:], "AUTH_PENDING,timeout %d", f.o.pending), now)
		return
	}
	if len(f.o.reject) > 0 {
		fake_text_out(f, f.o.reject, now)
		return
	}
	f.pushed = true
	if len(f.o.raw_reply) > 0 {
		for m in f.o.raw_reply {
			fake_text_out(f, m, now)
		}
		f.pushes_sent += 1
		fake_install(f, now)
		return
	}
	pid: Maybe(u32)
	if !f.o.no_peer_id {
		pid = u32(f.o.peer_id)
	}
	flags: push.Protocol_Flags = {.Tls_Ekm}
	if f.o.cc_exit {
		flags += {.Cc_Exit}
	}
	if f.o.dyn {
		flags += {.Dyn_Tls_Crypt}
	}
	if f.o.epoch {
		flags += {.Aead_Epoch}
	}
	routes: [dynamic]push.Route
	defer delete(routes)
	for i in 0 ..< f.o.routes {
		append(&routes, push.Route{net = {10, 100 + u8(i / 250), u8(i % 250), 0}, mask = {255, 255, 255, 0}})
	}
	pp := push.Push_Reply_Params {
		routes         = routes[:],
		route_gateway  = [4]u8{10, 8, 0, 1},
		topology       = .Subnet,
		ping           = f.o.ping if f.o.ping > 0 else 10,
		ping_restart   = f.o.ping_restart if f.o.ping_restart > 0 else 60,
		ifconfig       = push.Ifconfig{a = {10, 8, 0, 2}, b = {255, 255, 255, 0}},
		peer_id        = pid,
		cipher         = fake_opts_cipher(&f.o),
		protocol_flags = flags,
		tun_mtu        = f.o.mtu if f.o.mtu > 0 else 1500,
		extra          = f.o.extra,
	}
	if f.o.token {
		pp.auth_token = FAKE_TOKEN
	}
	msgs, err := push.push_reply_build(&pp)
	if err != .None {
		return
	}
	defer push.push_messages_destroy(msgs)
	for m in msgs {
		fake_text_out(f, m, now)
	}
	f.pushes_sent += 1
	fake_install(f, now)
}

// Derives the data keys of this key state from the TLS exporter.
fake_install :: proc(f: ^Fake, now: Time) {
	if f.installed {
		return
	}
	if f.key_id == 0 && f.o.dyn && !f.have_dyn {
		exp: [wrap.DYNAMIC_EXPORT_LEN]u8
		if !ossl.tls_export_keying_material(&f.tls, wrap.DYNAMIC_TLS_CRYPT_LABEL, exp[:]) {
			return
		}
		orig := &f.skey if f.o.mode == .Tls_Crypt else &f.kc
		if f.o.mode == .Tls_Crypt || f.o.mode == .Tls_Crypt_V2 {
			wrap.dynamic_tls_crypt_init(&f.dyn, exp[:], orig, .Server)
			f.have_dyn = true
		}
	}
	exp: [keys.EXPORT_LEN]u8
	if !ossl.tls_export_keying_material(&f.tls, keys.EXPORT_LABEL, exp[:]) {
		return
	}
	cipher := aead_of(fake_opts_cipher(&f.o))
	m, merr := keys.derive_material(exp[:], .Server, cipher)
	if merr != .None {
		return
	}
	kid := f.key_id
	if f.have_dk[kid] {
		crypt.data_key_destroy(&f.dk[kid])
	}
	if crypt.data_key_init(&f.dk[kid], fake_format(f), cipher, kid, &m, {limit_override = f.o.limit}) != .None {
		return
	}
	f.have_dk[kid] = true
	f.installed = true
	f.tx_kid = kid
	f.last_tx = now
}
