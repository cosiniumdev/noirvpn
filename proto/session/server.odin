// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:mem"
import "core:time"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/reliable"
import "noir:proto/wire"
import "noir:proto/wrap"

// The server role, part one: what all peers of one listening server share
// (`Server_Shared`), and handling of the first packets of a UDP peer with no
// session (`server_first_packet`).
//
// Daemon use (one `Server_Shared` per listening socket):
//
//	UDP datagram arrives from `from` (see `peer_addr_v4`)
//	  data packet (opcode 9)   find the session by `server_peer_id` (or by address
//	                           when that is `PEER_ID_NONE`), then
//	                           `session_receive(s, pkt, now, from)`
//	  control packet           find the session by `server_client_sid`
//	      found                `session_receive(s, pkt, now, from)`
//	      not found            `server_first_packet(shared, pkt, from, now,
//	                           unix_now, out)`:
//	                             Drop     nothing to do
//	                             Reply    send `out[:n]` back to `from`
//	                             Accept   allocate a session, `session_init_server`,
//	                                      add it to the table under the client sid,
//	                                      and give it the same packet with
//	                                      `session_receive`
//	TCP connection accepted   `session_init_server_tcp`, one session per connection
//
// The first-packet path keeps no state per source. It allocates nothing and
// stores only two fixed-size rate limit tables in `Server_Shared`.

// Address of a peer in the one form the session uses: family (4 or 6), the IP
// bytes (4 or 16), the port in network order. 7 or 19 bytes. The cookie and
// the float check compare these bytes, so give the same form every time.
ADDR_MAX :: 19

Peer_Addr :: struct {
	b: [ADDR_MAX]u8,
	n: u8,
}

peer_addr_v4 :: proc "contextless" (ip: [4]u8, port: u16) -> (a: Peer_Addr) {
	a.b[0] = 4
	addr := ip
	copy(a.b[1:5], addr[:])
	a.b[5] = u8(port >> 8)
	a.b[6] = u8(port)
	a.n = 7
	return
}

peer_addr_v6 :: proc "contextless" (ip: [16]u8, port: u16) -> (a: Peer_Addr) {
	a.b[0] = 6
	addr := ip
	copy(a.b[1:17], addr[:])
	a.b[17] = u8(port >> 8)
	a.b[18] = u8(port)
	a.n = 19
	return
}

peer_addr_bytes :: proc "contextless" (a: ^Peer_Addr) -> []u8 {
	return a.b[:a.n]
}

// True for a well-formed address of one of the two forms.
@(private)
addr_ok :: proc "contextless" (b: []u8) -> bool {
	return (len(b) == 7 && b[0] == 4) || (len(b) == 19 && b[0] == 6)
}

// The IP part of an address (without the port).
@(private)
addr_ip :: proc "contextless" (b: []u8) -> []u8 {
	return b[1:len(b) - 2]
}

COOKIE_KEY_LEN :: 16

// How often the caller should call `server_cookie_rotate`. A cookie is valid for
// at most three buckets (90 s with the default hand window), so a period of at
// least 90 s keeps every live cookie valid across one rotation (the previous key
// stays). A shorter period causes some cookies to fail early: the client retransmits
// its reset and gets a new one.
COOKIE_ROTATE_INTERVAL :: 10 * time.Minute

// Defaults of the first-packet rate limits.
DEFAULT_INITIAL_LIMIT :: 100 // replies per window, all sources together
DEFAULT_INITIAL_WINDOW :: 10 * time.Second
DEFAULT_SOURCE_LIMIT :: 20 // replies per window for one source IP

@(private)
RATE_SLOTS :: 256

Server_Wrap_Config :: struct {
	// What a plain reset (opcode 7) uses: `.None`, `.Tls_Auth` or `.Tls_Crypt`.
	// `.Tls_Crypt_V2` means "only clients with a v2 key" (opcode 10 and 11).
	mode:          Wrap_Mode,
	// tls-auth and tls-crypt: the key file. The server copies it.
	static_key:    ^wrap.Static_Key,
	// tls-auth: the digest (default SHA1) and the server's own `key-direction`
	// (0 is the usual; the client then uses 1). Bidirectional if the file is
	// used both ways.
	auth_digest:   ossl.Hmac_Alg,
	key_direction: wrap.Key_Direction,
	// tls-crypt-v2: the server key. With `.Tls_Auth` or `.Tls_Crypt` as `mode`
	// this adds v2 clients on top of the plain ones. The server
	// copies it.
	server_key:    ^wrap.Server_Key,
	// tls-crypt-v2: refuse a first packet that does not signal early negotiation,
	// so no state is created for it. Otherwise such a client gets
	// a session at its first packet (memory cost per spoofed packet). Default off,
	// as in the stock server.
	force_cookie:  bool,
	// tls-crypt-v2-max-age: a WKc older than this many days is refused. 0: off.
	max_age_days:  int,
}

// Settings of a listening server. Zero values mean the default written next
// to each field. `server_shared_init` copies what it needs.
Server_Config :: struct {
	transport:        Transport,
	wrap:             Server_Wrap_Config,

		// ---- TLS ----
		// A prepared server context (`server_shared_destroy` does not free it),
		// or leave nil and fill the fields below.
	tls_ctx:          ^ossl.Tls_Ctx,
	cert_pem:         []u8,
	key_pem:          []u8,
	ca_pem:           []u8,
	verify:           ossl.Peer_Verify, // default .Chain
		// `.Pinned`: a callback (gets the SHA-256 of the peer's SPKI and of its
		// certificate; the server package handles it from the peers file), or the
		// two lists below. The callback runs inside the TLS library on the data
		// thread: keep it quick; `pin_user` must outlive the server.
	pin_check:        ossl.Pin_Check,
	pin_user:         rawptr,
	// `.Pin_Or_Chain`: the lookup (with `pin_user`). The chain part uses
	// `ca_pem` and the revocation fields below, as `.Chain` does.
	pin_lookup:       ossl.Pin_Lookup,
	pin_spki:         [][32]u8,
	pin_cert:         [][32]u8,
	tls_groups:       string,
	// Certificate revocation for `verify = .Chain` or `.Pin_Or_Chain`, and the hook that runs before
	// each new TLS session (see `Config`).
	crl_pem:          []u8,
	revoked_check:    ossl.Revoked_Check,
	revoked_user:     rawptr,
	// Checks on the client certificates and the TLS version range (see `Config`).
	leaf_rules:       ossl.Leaf_Rules,
		// A client may send no certificate (`ossl.Tls_Config.client_cert_optional`).
		// The caller of the session then gets `Auth_Request.proof == .None` and
		// must not give such a client a certificate identity.
	client_cert_optional: bool,
	tls_min:          ossl.Tls_Version,
	tls_max:          ossl.Tls_Version,
	tls_prepare:      Tls_Prepare,
	tls_prepare_user: rawptr,

		// ---- negotiation ----
		// `data-ciphers`, in order of preference. Default: AES-256-GCM,
		// AES-128-GCM, CHACHA20-POLY1305.
	ciphers:          []push.Cipher,
		// Protocol flags offered when the client supports them. Default `cc-exit`,
		// `dyn-tls-crypt`, `aead-epoch`. `tls-ekm` is always on. `aead-epoch` goes
		// to a client that announced IV_PROTO bit 10 (every cipher we run is AEAD,
		// every client has a peer id). Each session decides itself: an older client
		// keeps the baseline format.
	flags:            push.Protocol_Flags,
	// The tun MTU in the key-method options string (default 1500) and the
	// `tun-mtu` pushed to clients that sent IV_MTU (0: push none).
	tun_mtu:          int,
	push_tun_mtu:     int,

	// ---- control channel ----
	max_packet_size:  int, // default 1250
	max_frame:        int, // TCP, default 4096
	tls_timeout:      time.Duration, // default 2 s
	hand_window:      time.Duration, // default 60 s
	// ---- data channel and rekey ----
	tran_window:      time.Duration, // default 3600 s
		// `reneg-sec`: default 3600, -1 off. Each session takes a random value up
		// to 10 percent lower, once, so peers do not all rekey
		// together. `reneg_bytes` and `reneg_pkts`: default off.
	reneg_sec:        int,
	reneg_bytes:      u64,
	reneg_pkts:       u64,
		// Pushed to a client when `Client_Params` has none: `ping` and `ping-restart`
		// in seconds. 0 pushes none. The session pings at the pushed `ping` and drops
		// a silent client after twice the pushed `ping-restart` (or
		// `Client_Params.ping_restart_own`).
	ping:             int,
	ping_restart:     int,
	// UDP, no `cc-exit`: how many OCC exit packets `session_close` sends
	// (default 1; -1 none). Wait for an EXIT or RESTART to be acked (default 2 s).
	exit_notify:      int,
	exit_timeout:     time.Duration,
	// Ask the caller for a login again on every renegotiation (default: the
	// session checks only that the TLS peer key is the one of the first key).
	reauth:           bool,
	// A rekey that fails ends the session: no setting yet.

		// ---- first packets ----
		// Stateless replies per `initial_window`, for all sources together and for
		// one source IP. Default 100 and 20 per 10 s; -1 turns the
		// limit off.
	initial_limit:    int,
	initial_window:   time.Duration,
	source_limit:     int,
	// `connect-freq`: new sessions per window (UDP, at `Accept`). 0: off.
	session_limit:    int,
	session_window:   time.Duration,
	// The cookie key. Default: random. For tests.
	cookie_key:       Maybe([COOKIE_KEY_LEN]u8),

	// ---- other ----
	random:           Random_Proc,
	random_user:      rawptr,
	// Replaces the AEAD usage limit (tests only).
	limit_override:   u64,
	// The data channel of every peer is owned by a service (`Config.ext_data`).
	// `aead-epoch` is pushed only when the owner has epoch keys (`ext_epoch`).
	ext_data:         bool,
	ext_epoch:        bool,
}

@(private)
Window_Count :: struct {
	start: Time,
	count: int,
}

@(private)
Source_Slot :: struct {
	tag:   u64,
	start: Time,
	count: int,
}

// What every peer of one listening server shares. Read-only for the sessions. The
// first-packet path and `server_cookie_rotate` change it (cookie keys, rate
// counters): call them from the data path thread, as `server_first_packet`.
//
// Memory: about 9 KiB (per-source rate table 6 KiB), plus the TLS context.
Server_Shared :: struct {
	allocator:      mem.Allocator,
	// The session settings every session starts from.
	cfg:            Config,
	// TLS context of all sessions.
	tls_ctx:        ossl.Tls_Ctx,
	tls_ctx_owned:  bool,
	tls_ctx_ptr:    ^ossl.Tls_Ctx,
	pins:           ^Pins,
	// Wrapping.
	mode:           Wrap_Mode,
	v2:             bool,
	force_cookie:   bool,
	max_age_days:   int,
	auth_alg:       ossl.Hmac_Alg,
	auth_dir:       wrap.Key_Direction,
	static:         wrap.Static_Key,
	auth_keys:      wrap.Auth_Keys,
	crypt_keys:     wrap.Crypt_Keys,
	server_key:     wrap.Server_Key,
	// Negotiation.
	ciphers:        [MAX_CIPHERS]push.Cipher,
	ciphers_n:      int,
	flags:          push.Protocol_Flags,
	// `aead-epoch` is among the flags unless the data channel is an owner's.
	epoch_flag:     bool,
	push_tun_mtu:   int,
	ping:           int,
	ping_restart:   int,
	reauth:         bool,
	// The TLS context lets a client send no certificate.
	cert_optional:  bool,
	// Cookie keys: [0] is the current one, [1] the one before.
	cookie:         [2][COOKIE_KEY_LEN]u8,
	cookie_prev:    bool,
	cookie_at:      Time,
	cookie_bucket:  u32, // seconds
	// Rate limits (first packets).
	initial_limit:  int,
	initial_window: time.Duration,
	source_limit:   int,
	session_limit:  int,
	session_window: time.Duration,
	global:         Window_Count,
	created:        Window_Count,
	rate_seed:      u64,
	sources:        [RATE_SLOTS]Source_Slot,
	// Counters of the first-packet path.
	stats:          First_Stats,
	random:         Random_Proc,
	random_user:    rawptr,
}

// Counters of `server_first_packet` for telemetry and tests.
First_Stats :: struct {
	replies:    u64,
	accepted:   u64,
	dropped:    u64,
	rate_hit:   u64,
	odd_resets: u64,
	by_reason:  [First_Drop]u64,
}

// Sets up the shared state of a listening server.
//
// Errors:
// - `.Bad_Config`: missing key, pin list, unknown wrap mode, no ciphers, an
//   unsupported flag, a transport that does not fit
// - `.Bad_Key`: certificate or key text
// - `.Alloc`, `.Random`
server_shared_init :: proc(sh: ^Server_Shared, cfg: ^Server_Config, now: Time, allocator := context.allocator) -> Error {
	sh^ = {}
	sh.allocator = allocator
	sh.random = cfg.random if cfg.random != nil else default_random
	sh.random_user = cfg.random_user

	// Ciphers and flags.
	n := 0
	if len(cfg.ciphers) == 0 {
		for x in DEFAULT_CIPHERS {
			sh.ciphers[n] = x
			n += 1
		}
	} else {
		if len(cfg.ciphers) > MAX_CIPHERS {
			return .Bad_Config
		}
		for x in cfg.ciphers {
			if x == .None {
				return .Bad_Config
			}
			sh.ciphers[n] = x
			n += 1
		}
	}
	sh.ciphers_n = n
	sh.flags = cfg.flags if cfg.flags != {} else push.Protocol_Flags{.Cc_Exit, .Dyn_Tls_Crypt, .Aead_Epoch}
	sh.flags -= {.Tls_Ekm}
	sh.epoch_flag = .Aead_Epoch in sh.flags
	if cfg.ext_data && !cfg.ext_epoch {
		sh.flags -= {.Aead_Epoch}
	}

	// The template of every session's `Config`.
	c := &sh.cfg
	c.role = .Server
	c.transport = cfg.transport
	c.tun_mtu = cfg.tun_mtu if cfg.tun_mtu > 0 else push.DEFAULT_TUN_MTU
	c.max_packet_size = cfg.max_packet_size if cfg.max_packet_size > 0 else DEFAULT_MAX_PACKET_SIZE
	c.max_frame = cfg.max_frame if cfg.max_frame > 0 else DEFAULT_MAX_FRAME
	c.tls_timeout = cfg.tls_timeout if cfg.tls_timeout > 0 else reliable.DEFAULT_TIMEOUT
	c.hand_window = cfg.hand_window if cfg.hand_window > 0 else DEFAULT_HAND_WINDOW
	c.tran_window = cfg.tran_window if cfg.tran_window > 0 else keys_default_tran_window()
	c.reneg_sec = cfg.reneg_sec if cfg.reneg_sec != 0 else DEFAULT_RENEG_SEC
	c.reneg_bytes = cfg.reneg_bytes
	c.reneg_pkts = cfg.reneg_pkts
	c.exit_timeout = cfg.exit_timeout if cfg.exit_timeout > 0 else DEFAULT_EXIT_TIMEOUT
	c.explicit_exit_notify = cfg.exit_notify if cfg.exit_notify != 0 else 1
	c.limit_override = cfg.limit_override
	c.ext_data = cfg.ext_data
	c.ext_epoch = cfg.ext_data && cfg.ext_epoch
	c.tls_prepare = cfg.tls_prepare
	c.tls_prepare_user = cfg.tls_prepare_user
	c.random = sh.random
	c.random_user = sh.random_user
	if c.max_frame < 2048 || c.max_frame > wire.MAX_FRAME_LEN {
		return .Bad_Config
	}
	sh.push_tun_mtu = cfg.push_tun_mtu
	sh.ping = max(cfg.ping, 0)
	sh.ping_restart = max(cfg.ping_restart, 0)
	sh.reauth = cfg.reauth
	sh.cert_optional = cfg.client_cert_optional

	// Wrapping.
	wc := &cfg.wrap
	sh.mode = wc.mode
	sh.force_cookie = wc.force_cookie
	sh.max_age_days = max(wc.max_age_days, 0)
	switch wc.mode {
	case .None:
		if wc.server_key != nil {
			return .Bad_Config
		}
	case .Tls_Auth:
		if wc.static_key == nil {
			return .Bad_Config
		}
		sh.static = wc.static_key^
		sh.auth_alg = wc.auth_digest
		sh.auth_dir = wc.key_direction
		wrap.auth_keys_init(&sh.auth_keys, &sh.static, sh.auth_alg, sh.auth_dir)
	case .Tls_Crypt:
		if wc.static_key == nil {
			return .Bad_Config
		}
		sh.static = wc.static_key^
		wrap.crypt_keys_init(&sh.crypt_keys, &sh.static, .Server)
	case .Tls_Crypt_V2:
		if wc.server_key == nil {
			return .Bad_Config
		}
	}
	if wc.server_key != nil {
		sh.server_key = wc.server_key^
		sh.v2 = true
	}
	// A server with plain tls-crypt or tls-auth keeps the key only for the
	// dynamic tls-crypt XOR, which the session copies from here.

	// Cookie keys and rate limits.
	sh.cookie_bucket = u32(max((c.hand_window / time.Second + 1) / 2, 1))
	if k, ok := cfg.cookie_key.?; ok {
		sh.cookie[0] = k
	} else if !sh.random(sh.random_user, sh.cookie[0][:]) {
		server_shared_destroy(sh)
		return .Random
	}
	sh.cookie_at = now
	rs: [8]u8
	if !sh.random(sh.random_user, rs[:]) {
		server_shared_destroy(sh)
		return .Random
	}
	for b in rs {
		sh.rate_seed = sh.rate_seed << 8 | u64(b)
	}
	sh.initial_limit = cfg.initial_limit if cfg.initial_limit != 0 else DEFAULT_INITIAL_LIMIT
	sh.initial_window = cfg.initial_window if cfg.initial_window > 0 else DEFAULT_INITIAL_WINDOW
	sh.source_limit = cfg.source_limit if cfg.source_limit != 0 else DEFAULT_SOURCE_LIMIT
	sh.session_limit = cfg.session_limit
	sh.session_window = cfg.session_window if cfg.session_window > 0 else DEFAULT_INITIAL_WINDOW

	if err := server_tls_setup(sh, cfg); err != .None {
		server_shared_destroy(sh)
		return err
	}
	return .None
}

@(private)
keys_default_tran_window :: proc "contextless" () -> time.Duration {
	return 3600 * time.Second
}

@(private)
server_tls_setup :: proc(sh: ^Server_Shared, cfg: ^Server_Config) -> Error {
	if cfg.tls_ctx != nil {
		sh.tls_ctx_ptr = cfg.tls_ctx
		return .None
	}
	tc := ossl.Tls_Config {
		role        = .Server,
		cert_pem    = cfg.cert_pem,
		key_pem     = cfg.key_pem,
		groups      = cfg.tls_groups,
		min_version = .TLS_1_3 if cfg.tls_min == .TLS_1_3 else .TLS_1_2,
		max_version = cfg.tls_max,
		verify      = cfg.verify,
		ca_pem      = cfg.ca_pem,
		rules       = cfg.leaf_rules,

		client_cert_optional = cfg.client_cert_optional,
	}
	if cfg.verify == .Chain || cfg.verify == .Pin_Or_Chain {
		tc.crl_pem = cfg.crl_pem
		tc.revoked_check = cfg.revoked_check
		tc.revoked_user = cfg.revoked_user
	}
	if cfg.verify == .Pin_Or_Chain {
		if cfg.pin_lookup == nil {
			return .Bad_Config
		}
		tc.pin_lookup = cfg.pin_lookup
		tc.pin_user = cfg.pin_user
	}
	if cfg.verify == .Pinned {
		switch {
		case cfg.pin_check != nil:
			tc.pin_check = cfg.pin_check
			tc.pin_user = cfg.pin_user
		case len(cfg.pin_spki) > 0 || len(cfg.pin_cert) > 0:
			pins, perr := new(Pins, sh.allocator)
			if perr != nil {
				return .Alloc
			}
			sh.pins = pins
			a1, e1 := make([][32]u8, len(cfg.pin_spki), sh.allocator)
			a2, e2 := make([][32]u8, len(cfg.pin_cert), sh.allocator)
			if e1 != nil || e2 != nil {
				delete(a1, sh.allocator)
				delete(a2, sh.allocator)
				return .Alloc
			}
			copy(a1, cfg.pin_spki)
			copy(a2, cfg.pin_cert)
			pins.spki, pins.cert = a1, a2
			tc.pin_check = pin_check
			tc.pin_user = pins
		case:
			return .Bad_Config
		}
	}
	ctx, err := ossl.tls_ctx_create(tc, sh.allocator)
	#partial switch err {
	case .None:
	case .Bad_Cert, .Bad_Key, .Key_Encrypted, .Bad_Passphrase:
		return .Bad_Key
	case .Alloc:
		return .Alloc
	case:
		return .Bad_Config
	}
	sh.tls_ctx = ctx
	sh.tls_ctx_owned = true
	sh.tls_ctx_ptr = &sh.tls_ctx
	return .None
}

// Changes who owns the data channel of sessions that start after the call
// (`Config.ext_data`): the server stops using an owner outside the process, and
// sessions get their own data channel. Existing sessions keep their settings.
server_shared_set_ext_data :: proc(sh: ^Server_Shared, ext: bool, ext_epoch := false) {
	sh.cfg.ext_data = ext
	sh.cfg.ext_epoch = ext && ext_epoch
	if ext && !ext_epoch {
		sh.flags -= {.Aead_Epoch}
	} else if sh.epoch_flag {
		sh.flags += {.Aead_Epoch}
	}
}

// Frees the TLS context and wipes the keys. All sessions of this server must
// be destroyed first. Safe on a zeroed value.
server_shared_destroy :: proc(sh: ^Server_Shared) {
	if sh.tls_ctx_owned {
		ossl.tls_ctx_destroy(&sh.tls_ctx)
		sh.tls_ctx_owned = false
	}
	if sh.pins != nil {
		delete(sh.pins.spki, sh.allocator)
		delete(sh.pins.cert, sh.allocator)
		free(sh.pins, sh.allocator)
		sh.pins = nil
	}
	wrap.static_key_wipe(&sh.static)
	wrap.auth_keys_wipe(&sh.auth_keys)
	wrap.crypt_keys_wipe(&sh.crypt_keys)
	wrap.server_key_wipe(&sh.server_key)
	mem.zero_explicit(&sh.cookie, size_of(sh.cookie))
}

// ------------------------------------------------------------------ cookie

// Moves to a new random cookie key. The old key stays for validation (until
// the next rotation). Call it every `COOKIE_ROTATE_INTERVAL`.
server_cookie_rotate :: proc(sh: ^Server_Shared, now: Time) -> Error {
	fresh: [COOKIE_KEY_LEN]u8
	if !sh.random(sh.random_user, fresh[:]) {
		return .Random
	}
	sh.cookie[1] = sh.cookie[0]
	sh.cookie[0] = fresh
	sh.cookie_prev = true
	sh.cookie_at = now
	mem.zero_explicit(&fresh, size_of(fresh))
	return .None
}

// True when it is time to call `server_cookie_rotate`.
server_cookie_rotate_due :: proc "contextless" (sh: ^Server_Shared, now: Time) -> bool {
	return now - sh.cookie_at >= COOKIE_ROTATE_INTERVAL
}

// When the next rotation is due, for a timer.
server_cookie_next_rotation :: proc "contextless" (sh: ^Server_Shared) -> Time {
	return sh.cookie_at + COOKIE_ROTATE_INTERVAL
}

@(private)
cookie_bucket_of :: proc "contextless" (sh: ^Server_Shared, now: Time) -> u32 {
	return u32(now / time.Second) / sh.cookie_bucket
}

// The 8 byte PRF: HMAC-SHA256 over
// `u32 bucket | from | client sid`, cut to 8 bytes.
@(private)
cookie_prf :: proc "contextless" (key: ^[COOKIE_KEY_LEN]u8, bucket: u32, from: []u8, sid: reliable.Sid) -> (c: reliable.Sid, ok: bool) {
	buf: [4 + ADDR_MAX + reliable.SID_LEN]u8
	buf[0] = u8(bucket >> 24)
	buf[1] = u8(bucket >> 16)
	buf[2] = u8(bucket >> 8)
	buf[3] = u8(bucket)
	n := 4
	n += copy(buf[n:], from)
	id := sid
	n += copy(buf[n:], id[:])
	mac: [ossl.SHA256_LEN]u8
	if !ossl.hmac(.SHA256, key[:], buf[:n], mac[:]) {
		return {}, false
	}
	copy(c[:], mac[:reliable.SID_LEN])
	return c, sid_nonzero(c)
}

@(private)
sid_nonzero :: proc "contextless" (sid: reliable.Sid) -> bool {
	acc: u8
	for b in sid {
		acc |= b
	}
	return acc != 0
}

// The cookie for this source and client session id, now. `ok` is false only
// if the crypto library fails (or in one case of 2^64).
server_cookie :: proc "contextless" (sh: ^Server_Shared, from: []u8, client_sid: reliable.Sid, now: Time) -> (c: reliable.Sid, ok: bool) {
	return cookie_prf(&sh.cookie[0], cookie_bucket_of(sh, now), from, client_sid)
}

// True if `cookie` was generated for this source and client sid in the current
// bucket or one of the two before it, with the current or the previous key.
server_cookie_valid :: proc "contextless" (sh: ^Server_Shared, from: []u8, client_sid, cookie: reliable.Sid, now: Time) -> bool {
	if !sid_nonzero(cookie) {
		return false
	}
	bucket := cookie_bucket_of(sh, now)
	found := false
	// Every candidate is computed (no early exit), so the time does not tell
	// how close a guess was.
	for off in u32(0) ..< 3 {
		if off > bucket {
			break
		}
		for k in 0 ..< 2 {
			if k == 1 && !sh.cookie_prev {
				continue
			}
			want, ok := cookie_prf(&sh.cookie[k], bucket - off, from, client_sid)
			if ok && ct_equal8(want, cookie) {
				found = true
			}
		}
	}
	return found
}

@(private)
ct_equal8 :: proc "contextless" (a, b: reliable.Sid) -> bool {
	acc: u8
	for i in 0 ..< reliable.SID_LEN {
		acc |= a[i] ~ b[i]
	}
	return acc == 0
}

// -------------------------------------------------------------- rate limits

// One fixed window. Returns false if the count is at its limit.
@(private)
window_take :: proc "contextless" (w: ^Window_Count, now: Time, window: time.Duration, limit: int) -> bool {
	if limit < 0 {
		return true
	}
	if now - w.start >= window || now < w.start {
		w.start = now
		w.count = 0
	}
	if w.count >= limit {
		return false
	}
	w.count += 1
	return true
}

@(private)
source_tag :: proc "contextless" (sh: ^Server_Shared, from: []u8) -> u64 {
	h := sh.rate_seed ~ 0xcbf29ce484222325
	for b in addr_ip(from) {
		h = (h ~ u64(b)) * 0x100000001b3
	}
	return h | 1
}

@(private)
source_take :: proc "contextless" (sh: ^Server_Shared, from: []u8, now: Time) -> bool {
	if sh.source_limit < 0 {
		return true
	}
	tag := source_tag(sh, from)
	slot := &sh.sources[int(tag >> 8) % RATE_SLOTS]
	if slot.tag != tag {
		// A different source takes over the slot. A spoofer that hits a slot
		// only resets someone's count, which the global limit bounds.
		slot^ = {
			tag   = tag,
			start = now,
		}
	}
	w := Window_Count{slot.start, slot.count}
	ok := window_take(&w, now, sh.initial_window, sh.source_limit)
	slot.start, slot.count = w.start, w.count
	return ok
}

// ------------------------------------------------------------- first packet

First_Kind :: enum u8 {
	Drop,
	Reply,
	Accept,
}

First_Drop :: enum u8 {
	None,
	Not_Udp, // the server listens on TCP
	Bad_Address, // `from` is not in the form of `peer_addr_v4` or `_v6`
	Out_Too_Small, // `out` is shorter than `LINK_BUF_SIZE`
	Too_Short,
	Too_Long,
	Bad_Opcode, // not 7, 10, 4, 11 or 5
	Bad_Key_Id,
	Zero_Sid,
	Wrap_Mode, // the opcode does not fit the wrapping of this server
	Unwrap, // bad tag, bad WKc, a WKc that does not fit
	Decode,
	Metadata_Age, // tls-crypt-v2-max-age
	Force_Cookie,
	Bad_Cookie, // no ack, or the cookie in it is not ours
	Bad_Ids, // acked ids or the message id are not 0 or 1
	Rate_Source,
	Rate_Global,
	Rate_Sessions,
}

// What the caller needs to start a session for the packet.
Accept_Info :: struct {
	client_sid: reliable.Sid,
	// The session id of the server: the cookie. All zero when there is no
	// cookie (the session picks one).
	server_sid: reliable.Sid,
	cookie:     bool,
	from:       Peer_Addr,
}

First_Result :: struct {
	kind:   First_Kind,
	reason: First_Drop,
	// Reply: the length written to `out`.
	n:      int,
	// Reply: the reset acks something or has a msg id other than 0. A real
	// reset has neither; on a server with no wrapping this is usually a client
	// that wraps its packets (tls-auth or tls-crypt) and cannot read the reply.
	odd_reset: bool,
	// Accept
	accept: Accept_Info,
}

@(private)
first_drop :: proc(sh: ^Server_Shared, why: First_Drop) -> First_Result {
	sh.stats.dropped += 1
	sh.stats.by_reason[why] += 1
	return {kind = .Drop, reason = why}
}

// The route of a control packet to a session: the session id of the client
// (bytes 1 to 8). `ok` is false for a packet that is not a control packet or is
// too short (drop it).
server_client_sid :: proc "contextless" (pkt: []u8) -> (sid: reliable.Sid, ok: bool) {
	if len(pkt) < wire.CONTROL_PREFIX_LEN {
		return {}, false
	}
	op, _ := wire.split_first_byte(pkt[0])
	if wire.opcode_class(op) != .Control {
		return {}, false
	}
	copy(sid[:], pkt[1:wire.CONTROL_PREFIX_LEN])
	return sid, true
}

// The route of a data packet (opcode 9): the peer id in its header, or
// `PEER_ID_NONE` when the sender gave none (look the peer up by address).
// `ok` is false if the packet is not a data packet.
server_peer_id :: proc "contextless" (pkt: []u8) -> (id: u32, ok: bool) {
	if len(pkt) < 1 {
		return 0, false
	}
	op, _ := wire.split_first_byte(pkt[0])
	if op != .Data_V2 {
		return 0, false
	}
	return wire.data_v2_lookup_peer_id(pkt), true
}

// The packet of a client that has no session.
//
// - `pkt`: one UDP datagram (read only). `from`: its source (`peer_addr_v4`).
// - `now`: monotonic clock. `unix_now`: wall clock in seconds.
// - `out`: takes the reply (`LINK_BUF_SIZE` bytes).
//
// Stateless: no allocation, no per-source or per-client memory, no replay state.
// A reset gets one cookie reply; nothing is kept. A session is created only for a
// packet with a valid cookie in its ack array (`Accept`), or for a tls-crypt-v2
// reset of a client without early negotiation when `force_cookie` is off.
//
// Amplification: reply = 26 bytes + wrapping (66 with tls-crypt) + 6 with the
// early-negotiation TLV. Reset = 14 bytes + wrapping.
// - Reply to a stock client's first packet is longer than the request (26 vs 14
//   unwrapped, 66 vs 54 tls-crypt; at most 1.9 times).
// - A tls-crypt-v2 request (carries the 290 byte WKc) is always longer.
// - The per-source and global limits cap the number of replies.
//
// SPEC-GAP: without v2 a reply no larger than the request is impossible: the spec
// fixes the reply, the stock client its request.
server_first_packet :: proc(sh: ^Server_Shared, pkt: []u8, from: []u8, now: Time, unix_now: i64, out: []u8) -> (r: First_Result) {
	if sh.cfg.transport != .Udp {
		return first_drop(sh, .Not_Udp)
	}
	if !addr_ok(from) {
		return first_drop(sh, .Bad_Address)
	}
	if len(out) < LINK_BUF_SIZE {
		return first_drop(sh, .Out_Too_Small)
	}
	if len(pkt) < wire.CONTROL_PREFIX_LEN {
		return first_drop(sh, .Too_Short)
	}
	if len(pkt) > INNER_MAX + wrap.WKC_MAX_LEN {
		return first_drop(sh, .Too_Long)
	}
	// First checks of a packet from an unknown client.
	op, kid := wire.split_first_byte(pkt[0])
	#partial switch op {
	case .Hard_Reset_Client_V2, .Hard_Reset_Client_V3, .Control_V1, .Control_Wkc_V1, .Ack_V1:
	case:
		return first_drop(sh, .Bad_Opcode)
	}
	if kid != 0 {
		return first_drop(sh, .Bad_Key_Id)
	}
	client_sid: reliable.Sid
	copy(client_sid[:], pkt[1:wire.CONTROL_PREFIX_LEN])
	if !reliable.sid_defined(client_sid) {
		return first_drop(sh, .Zero_Sid)
	}

	// 4: unwrap in a throw-away context. Nothing of it is kept.
	is_v2_op := op == .Hard_Reset_Client_V3 || op == .Control_Wkc_V1
	if is_v2_op && !sh.v2 {
		return first_drop(sh, .Wrap_Mode)
	}
	if !is_v2_op && sh.mode == .Tls_Crypt_V2 {
		return first_drop(sh, .Wrap_Mode)
	}
	inner: [INNER_MAX]u8
	n: int
	// How to wrap the reply.
	reply_crypt: wrap.Crypt_Keys // v2: keys of this client
	early := false
	switch {
	case is_v2_op:
		body, wkc, serr := wrap.tls_crypt_v2_split_wkc(pkt)
		if serr != .None {
			return first_drop(sh, .Unwrap)
		}
		kc: wrap.Static_Key
		meta: wrap.Metadata
		defer wrap.static_key_wipe(&kc)
		if wrap.tls_crypt_v2_wkc_open(&sh.server_key, wkc, &kc, &meta) != .None {
			return first_drop(sh, .Unwrap)
		}
		wrap.crypt_keys_init(&reply_crypt, &kc, .Server)
		id: u32
		uerr: wrap.Error
		n, id, _, uerr = wrap.tls_crypt_open(&reply_crypt, body, inner[:])
		if uerr != .None {
			return first_drop(sh, .Unwrap)
		}
		early = wrap.tls_crypt_v2_signals_early_negotiation(id)
		if sh.max_age_days > 0 && wrap.metadata_check_age(&meta, unix_now, i64(sh.max_age_days)) != .None {
			return first_drop(sh, .Metadata_Age)
		}
	case len(pkt) > INNER_MAX:
		return first_drop(sh, .Too_Long)
	case sh.mode == .None:
		n = len(pkt)
		copy(inner[:], pkt)
	case sh.mode == .Tls_Auth:
		uerr: wrap.Error
		n, _, _, uerr = wrap.tls_auth_open(&sh.auth_keys, pkt, inner[:])
		if uerr != .None {
			return first_drop(sh, .Unwrap)
		}
	case:
		uerr: wrap.Error
		n, _, _, uerr = wrap.tls_crypt_open(&sh.crypt_keys, pkt, inner[:])
		if uerr != .None {
			return first_drop(sh, .Unwrap)
		}
	}
	cp: wire.Control_Packet
	if wire.control_decode(inner[:n], &cp) != .None {
		return first_drop(sh, .Decode)
	}

	// 5: by opcode.
	// 3.2 does not check the ids of a reset; they only mark it as odd for the log.
	odd := cp.ack_count != 0 || cp.packet_id != 0
	#partial switch op {
	case .Hard_Reset_Client_V2:
		if why := take_initial(sh, from, now); why != .None {
			return first_drop(sh, why)
		}
		return odd_reply(sh, stateless_reply(sh, client_sid, from, now, unix_now, false, &reply_crypt, out), odd)
	case .Hard_Reset_Client_V3:
		if why := take_initial(sh, from, now); why != .None {
			return first_drop(sh, why)
		}
		if early {
			return odd_reply(sh, stateless_reply(sh, client_sid, from, now, unix_now, true, &reply_crypt, out), odd)
		}
		if sh.force_cookie {
			return first_drop(sh, .Force_Cookie)
		}
		if sh.session_limit > 0 && !window_take(&sh.created, now, sh.session_window, sh.session_limit) {
			return first_drop(sh, .Rate_Sessions)
		}
		sh.stats.accepted += 1
		return {kind = .Accept, accept = {client_sid = client_sid, from = copy_addr(from)}}
	}

	// 4, 5, 11: the cookie (3.6).
	if cp.ack_count < 1 || !server_cookie_valid(sh, from, client_sid, cp.ack_remote_sid, now) {
		return first_drop(sh, .Bad_Cookie)
	}
	for i in 0 ..< cp.ack_count {
		if cp.acks[i] > 1 {
			return first_drop(sh, .Bad_Ids)
		}
	}
	if op != .Ack_V1 && cp.packet_id > 1 {
		return first_drop(sh, .Bad_Ids)
	}
	if sh.session_limit > 0 && !window_take(&sh.created, now, sh.session_window, sh.session_limit) {
		return first_drop(sh, .Rate_Sessions)
	}
	// A cookie handshake that worked gives its slot back (3.5).
	if sh.global.count > 0 {
		sh.global.count -= 1
	}
	sh.stats.accepted += 1
	return {kind = .Accept, accept = {client_sid = client_sid, server_sid = cp.ack_remote_sid, cookie = true, from = copy_addr(from)}}
}

@(private)
odd_reply :: proc(sh: ^Server_Shared, r: First_Result, odd: bool) -> First_Result {
	r := r
	if odd && r.kind == .Reply {
		r.odd_reset = true
		sh.stats.odd_resets += 1
	}
	return r
}

@(private)
copy_addr :: proc "contextless" (from: []u8) -> (a: Peer_Addr) {
	a.n = u8(copy(a.b[:], from))
	return
}

// The rate limits of a reply (3.5): one per source IP and one for all.
@(private)
take_initial :: proc(sh: ^Server_Shared, from: []u8, now: Time) -> First_Drop {
	if !source_take(sh, from, now) {
		sh.stats.rate_hit += 1
		return .Rate_Source
	}
	if !window_take(&sh.global, now, sh.initial_window, sh.initial_limit) {
		sh.stats.rate_hit += 1
		return .Rate_Global
	}
	return .None
}

// Builds the reply of 3.3: HARD_RESET_SERVER_V2 with the cookie as its sid,
// acking id 0 of the client, wrapped from a fresh counter (id 1, time now).
@(private)
stateless_reply :: proc(
	sh: ^Server_Shared,
	client_sid: reliable.Sid,
	from: []u8,
	now: Time,
	unix_now: i64,
	tlv: bool,
	v2keys: ^wrap.Crypt_Keys,
	out: []u8,
) -> First_Result {
	cookie, ok := server_cookie(sh, from, client_sid, now)
	if !ok {
		return first_drop(sh, .Decode)
	}
	cp := wire.Control_Packet {
		opcode         = .Hard_Reset_Server_V2,
		key_id         = 0,
		session_id     = cookie,
		ack_count      = 1,
		ack_remote_sid = client_sid,
		packet_id      = 0,
	}
	tlv_buf: [6]u8
	if tlv {
		tn, terr := wire.early_neg_encode(tlv_buf[:], wire.EARLY_NEG_FLAG_RESEND_WKC)
		if terr != .None {
			return first_drop(sh, .Decode)
		}
		cp.payload = tlv_buf[:tn]
	}
	inner: [64]u8
	n, eerr := wire.control_encode(inner[:], &cp)
	if eerr != .None {
		return first_drop(sh, .Decode)
	}
	t := wrap.wrap_time(unix_now)
	wn: int
	werr: wrap.Error
	switch {
	case tlv:
		wn, werr = wrap.tls_crypt_seal(v2keys, 1, t, inner[:n], out)
	case sh.mode == .None:
		copy(out, inner[:n])
		wn = n
	case sh.mode == .Tls_Auth:
		wn, werr = wrap.tls_auth_seal(&sh.auth_keys, 1, t, inner[:n], out)
	case:
		wn, werr = wrap.tls_crypt_seal(&sh.crypt_keys, 1, t, inner[:n], out)
	}
	if werr != .None {
		return first_drop(sh, .Decode)
	}
	sh.stats.replies += 1
	return {kind = .Reply, n = wn}
}
