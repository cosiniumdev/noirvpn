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

// Sets up a session from `cfg`. Nothing is sent until `session_start`. Allocates
// with `allocator`; `session_destroy` frees it. Creates a client (a server peer
// uses `session_init_server`).
//
// Errors:
// - `.Bad_Config`: missing key, pin list, unknown wrap mode, a refused IV_PROTO
//   bit, no ciphers
// - `.Bad_Key`: certificate or key text
// - `.Not_Implemented`: `cfg.role` is not `.Client`
// - `.Credentials_Too_Long`, `.Alloc`
session_init :: proc(s: ^Session, cfg: ^Config, allocator := context.allocator) -> Error {
	s^ = {}
	s.allocator = allocator
	if cfg.role != .Client {
		return .Not_Implemented
	}
	s.role = cfg.role
	s.transport = cfg.transport
	s.cfg = cfg^
	c := &s.cfg
	// Borrowed pointers are not kept.
	c.tls_ctx = nil
	c.cert_pem, c.key_pem, c.ca_pem = nil, nil, nil
	c.crl_pem = nil
	c.leaf_rules = {}
	c.pin_spki, c.pin_cert = nil, nil
	c.username, c.password = "", ""
	c.wrap.static_key, c.wrap.client_key = nil, nil

	ciphers := make([dynamic]push.Cipher, 0, 4, allocator)
	defer delete(ciphers)
	if len(cfg.ciphers) == 0 {
		for x in DEFAULT_CIPHERS {
			append(&ciphers, x)
		}
	} else {
		for x in cfg.ciphers {
			if x == .None {
				return .Bad_Config
			}
			append(&ciphers, x)
		}
	}
	if len(ciphers) > MAX_CIPHERS {
		return .Bad_Config
	}
	for x, i in ciphers {
		s.ciphers[i] = x
	}
	s.ciphers_n = len(ciphers)

	if c.iv_proto == {} {
		c.iv_proto = DEFAULT_IV_PROTO
	}
	if c.ext_data && !c.ext_epoch {
		// The owner of the data channel has no epoch keys.
		c.iv_proto -= {.Data_Epoch}
	}
	if c.iv_proto & UNSUPPORTED_IV_PROTO != {} {
		return .Bad_Config
	}
	if len(cfg.version) > VERSION_MAX || len(cfg.platform) > PLATFORM_MAX || len(cfg.sso) > SSO_MAX {
		return .Bad_Config
	}
	s.sso_n = copy(s.sso[:], cfg.sso)
	s.ver_n = copy(s.ver[:], cfg.version if len(cfg.version) > 0 else "noirvpn")
	s.plat_n = copy(s.plat[:], cfg.platform if len(cfg.platform) > 0 else "linux")
	if c.iv_mtu == 0 {
		c.iv_mtu = DEFAULT_IV_MTU
	}
	if c.tun_mtu == 0 {
		c.tun_mtu = push.DEFAULT_TUN_MTU
	}
	if c.max_packet_size == 0 {
		c.max_packet_size = DEFAULT_MAX_PACKET_SIZE
	}
	if c.tls_timeout == 0 {
		c.tls_timeout = reliable.DEFAULT_TIMEOUT
	}
	if c.hand_window == 0 {
		c.hand_window = DEFAULT_HAND_WINDOW
	}
	if c.max_frame == 0 {
		c.max_frame = DEFAULT_MAX_FRAME
	}
	if c.tran_window == 0 {
		c.tran_window = keys.DEFAULT_TRAN_WINDOW
	}
	if c.reneg_sec == 0 {
		c.reneg_sec = DEFAULT_RENEG_SEC
	}
	if c.exit_timeout == 0 {
		c.exit_timeout = DEFAULT_EXIT_TIMEOUT
	}
	s.reneg_eff = c.reneg_sec
	if c.max_frame < 2048 || c.max_frame > wire.MAX_FRAME_LEN {
		return .Bad_Config
	}
	if c.random == nil {
		c.random = default_random
	}

	if len(cfg.username) > CREDENTIAL_MAX || len(cfg.password) > CREDENTIAL_MAX {
		return .Credentials_Too_Long
	}
	copy(s.user[:], cfg.username)
	s.user_n = len(cfg.username)
	copy(s.pass[:], cfg.password)
	s.pass_n = len(cfg.password)

	keys.slots_init(&s.slots, dp_slots_config(c))
	dp_init(&s.dp, s.role, s.transport, dp_slots_config(c))

	if err := wrap_setup(s, &cfg.wrap); err != .None {
		session_destroy(s)
		return err
	}
	if err := tls_setup(s, cfg); err != .None {
		session_destroy(s)
		return err
	}

	if s.transport == .Tcp {
		buf, aerr := make([]u8, wire.FRAME_PREFIX_LEN + c.max_frame, allocator)
		if aerr != nil {
			session_destroy(s)
			return .Alloc
		}
		s.split_buf = buf
		if wire.splitter_init(&s.split, buf, c.max_frame) != .None {
			session_destroy(s)
			return .Bad_Config
		}
	}

	push.push_assembler_init(&s.asm_, allocator)
	s.asm_ok = true
	ccfg := reliable.Config {
		timeout     = c.tls_timeout,
		hand_window = c.hand_window,
		max_payload = reliable.DEFAULT_MAX_PAYLOAD,
	}
	if reliable.init(&s.ks.chan, ccfg, 0, allocator) != .None {
		session_destroy(s)
		return .Alloc
	}
	s.ks.chan_ok = true
	s.state = .New
	return .None
}

// Frees everything and wipes the keys. Safe to call after a failed
// `session_init` and on a zeroed session.
session_destroy :: proc(s: ^Session) {
	srv_destroy(s)
	ks_free_tls(&s.ks)
	if s.ks.chan_ok {
		reliable.destroy(&s.ks.chan)
		s.ks.chan_ok = false
	}
	if s.rdp != nil {
		// The owner frees the keys and the data plane after the packets that are
		// queued for it.
		cmd := Dp_Cmd {
			kind = .Destroy,
		}
		s.remote.submit(s.remote.user, s.rdp, &cmd)
		s.rdp = nil
		s.remote = {}
	}
	dp_destroy(&s.dp)
	if s.have_pushed {
		push.pushed_options_destroy(&s.pushed)
		s.have_pushed = false
	}
	if s.asm_ok {
		push.push_assembler_destroy(&s.asm_)
		s.asm_ok = false
	}
	if s.tls_ctx_owned {
		ossl.tls_ctx_destroy(&s.tls_ctx)
		s.tls_ctx_owned = false
	}
	if s.pins != nil {
		delete(s.pins.spki, s.allocator)
		delete(s.pins.cert, s.allocator)
		free(s.pins, s.allocator)
		s.pins = nil
	}
	if s.split_buf != nil {
		delete(s.split_buf, s.allocator)
		s.split_buf = nil
	}
	wrap.tls_auth_wipe(&s.wrap.auth)
	wrap.tls_crypt_wipe(&s.wrap.crypt)
	wrap.tls_crypt_wipe(&s.wrap.dyn)
	wrap.static_key_wipe(&s.wrap.orig_key)
	mem.zero_explicit(&s.wrap.wkc, size_of(s.wrap.wkc))
	mem.zero_explicit(&s.user, size_of(s.user))
	mem.zero_explicit(&s.pass, size_of(s.pass))
	mem.zero_explicit(&s.token, size_of(s.token))
	mem.zero_explicit(&s.token_user, size_of(s.token_user))
	mem.zero_explicit(&s.tls_buf, size_of(s.tls_buf))
	mem.zero_explicit(&s.plain, size_of(s.plain))
	mem.zero_explicit(&s.ks.km_in, size_of(s.ks.km_in))
	s.state = .Closed
}

@(private)
default_random :: proc(user: rawptr, buf: []u8) -> bool {
	return ossl.random_bytes(buf)
}

@(private)
fill_random :: proc(s: ^Session, buf: []u8) -> bool {
	return s.cfg.random(s.cfg.random_user, buf)
}

// ---------------------------------------------------------------- wrapping

@(private)
wrap_setup :: proc(s: ^Session, wc: ^Wrap_Config) -> Error {
	w := &s.wrap
	w.mode = wc.mode
	switch wc.mode {
	case .None:
		w.overhead = 0
	case .Tls_Auth:
		if wc.static_key == nil {
			return .Bad_Config
		}
		w.orig_key = wc.static_key^
		w.have_key = true
		wrap.tls_auth_init(&w.auth, &w.orig_key, wc.auth_digest, wc.key_direction)
		w.overhead = wrap.tls_auth_overhead(wc.auth_digest)
	case .Tls_Crypt:
		if wc.static_key == nil {
			return .Bad_Config
		}
		w.orig_key = wc.static_key^
		w.have_key = true
		wrap.tls_crypt_init(&w.crypt, &w.orig_key, .Client)
		w.overhead = reliable.WRAP_OVERHEAD_TLS_CRYPT
	case .Tls_Crypt_V2:
		ck := wc.client_key
		if ck == nil || ck.wkc_len < wrap.WKC_MIN_LEN || ck.wkc_len > wrap.WKC_MAX_LEN {
			return .Bad_Config
		}
		w.orig_key = ck.kc
		w.have_key = true
		w.wkc_len = ck.wkc_len
		copy(w.wkc[:], ck.wkc[:ck.wkc_len])
		wrap.tls_crypt_v2_client_init(&w.crypt, ck)
		w.overhead = reliable.WRAP_OVERHEAD_TLS_CRYPT
	}
	return .None
}

// ---------------------------------------------------------------------- TLS

// Pin lists must outlive the TLS context; the session owns them.
@(private)
pin_check :: proc "contextless" (peer: ossl.Peer_Key, user: rawptr) -> bool {
	p := (^Pins)(user)
	for h in p.spki {
		if h == peer.spki_sha256 {
			return true
		}
	}
	for h in p.cert {
		if h == peer.cert_sha256 {
			return true
		}
	}
	return false
}

@(private)
tls_setup :: proc(s: ^Session, cfg: ^Config) -> Error {
	if cfg.tls_ctx != nil {
		s.tls_ctx_ptr = cfg.tls_ctx
		return .None
	}
	tc := ossl.Tls_Config {
		role        = .Client,
		cert_pem    = cfg.cert_pem,
		key_pem     = cfg.key_pem,
		groups      = cfg.tls_groups,
		min_version = .TLS_1_3 if cfg.tls_min == .TLS_1_3 else .TLS_1_2,
		max_version = cfg.tls_max,
		verify      = cfg.verify,
		ca_pem      = cfg.ca_pem,
		rules       = cfg.leaf_rules,
	}
	if cfg.verify == .Chain {
		tc.crl_pem = cfg.crl_pem
		tc.revoked_check = cfg.revoked_check
		tc.revoked_user = cfg.revoked_user
	}
	if cfg.verify == .Pinned {
		if len(cfg.pin_spki) == 0 && len(cfg.pin_cert) == 0 {
			return .Bad_Config
		}
		pins, perr := new(Pins, s.allocator)
		if perr != nil {
			return .Alloc
		}
		s.pins = pins
		a1, e1 := make([][32]u8, len(cfg.pin_spki), s.allocator)
		a2, e2 := make([][32]u8, len(cfg.pin_cert), s.allocator)
		if e1 != nil || e2 != nil {
			delete(a1, s.allocator)
			delete(a2, s.allocator)
			return .Alloc
		}
		copy(a1, cfg.pin_spki)
		copy(a2, cfg.pin_cert)
		pins.spki, pins.cert = a1, a2
		tc.pin_check = pin_check
		tc.pin_user = pins
	}
	ctx, err := ossl.tls_ctx_create(tc, s.allocator)
	#partial switch err {
	case .None:
	case .Bad_Cert, .Bad_Key, .Key_Encrypted, .Bad_Passphrase:
		return .Bad_Key
	case .Alloc:
		return .Alloc
	case:
		return .Bad_Config
	}
	s.tls_ctx = ctx
	s.tls_ctx_owned = true
	s.tls_ctx_ptr = &s.tls_ctx
	return .None
}

// -------------------------------------------------------------------- start

// Starts the connection: picks the session id and queues the hard reset. `now` is
// the monotonic time. `unix_now` is the wall clock in whole seconds, for the wrap
// time of tls-auth and tls-crypt packets. Collect the packet with
// `session_poll_tx`.
session_start :: proc(s: ^Session, now: Time, unix_now: i64) -> Error {
	if s.state != .New {
		return .Bad_State
	}
	s.wall_base = unix_now - i64(now / time.Second)
	for {
		if !fill_random(s, s.local_sid[:]) {
			return .Random
		}
		if reliable.sid_defined(s.local_sid) {
			break
		}
	}
	ks := &s.ks
	ks.chan.cfg.local_sid = s.local_sid
	reliable.reset(&ks.chan, now)
	ks.id = 0
	ks.state = .Initial
	op := wire.Opcode.Hard_Reset_Client_V3 if s.wrap.mode == .Tls_Crypt_V2 else wire.Opcode.Hard_Reset_Client_V2
	if _, ok := reliable.send_packet(&ks.chan, u8(op), nil, now); !ok {
		return .Internal
	}
	ks.state = .Pre_Start
	s.state = .Connecting
	s.started = true
	s.last_rx = now
	s.last_tx = now
	return .None
}

// ---------------------------------------------------------------- accessors

session_state :: proc "contextless" (s: ^Session) -> State {
	return s.state
}

// How many certificates of the peer's chain were accepted because their issuer
// has no CRL in the list (`crl-verify`). 0 if the TLS session is gone.
session_crl_skipped :: proc "contextless" (s: ^Session) -> int {
	return s.ks.tls.crl_skipped if s.ks.tls_ok else 0
}

session_fail_reason :: proc "contextless" (s: ^Session) -> Fail_Reason {
	return s.fail_reason
}

// The control key state, for logs and tests.
session_key_state :: proc "contextless" (s: ^Session) -> (key_id: u8, state: Ks_State) {
	return s.ks.id, s.ks.state
}

session_counters :: proc "contextless" (s: ^Session) -> Counters {
	c := s.counters
	if s.cfg.ext_data {
		c.epoch_adv_tx, c.epoch_adv_rx = s.ext_seen.epoch_adv_tx, s.ext_seen.epoch_adv_rx
	} else if s.rdp != nil {
		p := dp_read_public(s.rdp)
		c.epoch_adv_tx, c.epoch_adv_rx = p.adv_tx, p.adv_rx
	} else {
		c.epoch_adv_tx, c.epoch_adv_rx = dp_advances(&s.dp)
	}
	return c
}

// The data packet format of this session (`aead-epoch` was negotiated or not).
// `.Baseline` until the keys are installed.
session_data_format :: proc "contextless" (s: ^Session) -> keys.Format {
	return s.format
}

// "baseline" or "epoch", for logs and the control bus.
session_data_format_name :: proc "contextless" (s: ^Session) -> string {
	return keys.format_name(s.format)
}

// Send and receive epoch of the key that is in use now (the newest key). Both
// are 0 in the baseline format, or when no key is installed.
session_epochs :: proc "contextless" (s: ^Session) -> (tx, rx: u16) {
	if s.cfg.ext_data {
		return s.ext_seen.epoch_tx, s.ext_seen.epoch_rx
	}
	if s.rdp != nil {
		p := dp_read_public(s.rdp)
		return u16(p.epoch_tx), u16(p.epoch_rx)
	}
	return dp_epochs(&s.dp)
}

// The first PUSH_REPLY, parsed. Valid from `Up` until `session_destroy`.
session_pushed :: proc "contextless" (s: ^Session) -> ^push.Pushed_Options {
	return &s.pushed if s.have_pushed else nil
}

// What the server negotiated for the data channel.
session_cipher :: proc "contextless" (s: ^Session) -> push.Cipher {
	return s.cipher
}

session_protocol_flags :: proc "contextless" (s: ^Session) -> push.Protocol_Flags {
	return s.flags
}

// The peer id in data packets (24 bits; `PEER_ID_NONE` if the server pushed
// none). Server: the id given in `Client_Params`.
session_peer_id :: proc "contextless" (s: ^Session) -> u32 {
	return s.peer_id
}

// The text of the last `INFO_PRE` from the server (after "INFO_PRE,"), and
// whether it was longer than `INFO_PRE_MAX` and cut. A slice of the session:
// copy it if you keep it. It can hold a sign-in URL: keep it out of logs.
session_info_pre :: proc "contextless" (s: ^Session) -> (text: string, cut: bool) {
	return string(s.info_pre[:s.info_pre_n]), s.info_pre_cut
}

// How long the session still waits for the PUSH_REPLY (`AUTH_PENDING` moves
// this time). False when it does not wait.
session_push_wait_left :: proc "contextless" (s: ^Session, now: Time) -> (left: Time, ok: bool) {
	if !s.push_deadline_on {
		return 0, false
	}
	return max(s.push_deadline - now, 0), true
}

// The auth-token the server pushed, with its user name, if any. The strings are
// slices of the session. Keep them out of logs. A client that reconnects uses
// them as the login of the next session.
session_auth_token :: proc "contextless" (s: ^Session) -> (user: string, token: string, ok: bool) {
	if s.token_n == 0 {
		return "", "", false
	}
	if s.token_user_n > 0 {
		return string(s.token_user[:s.token_user_n]), string(s.token[:s.token_n]), true
	}
	return string(s.user[:s.user_n]), string(s.token[:s.token_n]), true
}
