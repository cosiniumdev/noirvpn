// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package session: control-channel state machine of one noirvpn connection, plus
// the data channel it installs. A `Session` is one client (`session_init`) or one
// server peer (`session_init_server`).
//
// Sans-I/O: no socket, clock, thread or log. Input comes through calls, output
// through return values and events:
//
//	in    session_receive    one datagram (UDP) or a chunk of the stream (TCP)
//	      session_encap      one tunnel packet from the tun device
//	      session_tick       the timer fired
//	      session_start, session_close, session_rekey   commands
//	out   session_poll_tx    link packets to send (control, ack, keepalive, exit)
//	      session_encap      the link packet for a tunnel packet
//	      Rx_Result.tunnel   a tunnel packet to write to the tun device
//	      session_next_event events (up, key installed, failed, ...)
//	      session_next_wakeup  when to call `session_tick` again
//
// Time: monotonic `time.Duration` from the caller (any origin). Wrapping modes
// need a wall clock: the caller gives one unix time to `session_start` (or
// `session_init_server`), the engine advances it with `now`.
//
// Server role:
// - One `Server_Shared` per listening server (TLS context, wrap keys, cookie keys,
//   limits: `server_shared_init`).
// - UDP first packets go through the stateless `server_first_packet`: Drop, Reply
//   or Accept (server.odin). Details, amplification and the daemon flow are there.
// - On Accept (and per TCP connection) the caller creates a `Session` with
//   `session_init_server` (or `_tcp`) and feeds it that peer's packets.
// - Same calls as a client, plus:
//
//	session_receive(s, pkt, now, from)   `from`: datagram source (`peer_addr_v4`);
//	                                     a control packet from another address is dropped
//	session_server_accept / _reject      reply to `Auth_Request`
//	session_auth_request                 what the client presented (certificate key
//	                                     and name, user, password, peer-info)
//	session_close(s, now, kind)          Exit, Restart, Restart_Next, Halt
//	session_server_set_remote            accept a `Float_Candidate`
//
// Login is the caller's decision. The session stops after the key-method exchange
// and raises `Auth_Request`. The caller checks the peer (peers file, user and
// password, address pool), then calls `session_server_accept` with the options to
// push, or `session_server_reject`. No login data is in an event. The password
// stays in the session only until the reply.
//
// Peer identity: `Auth_Request` has the SHA-256 of the client's public key and
// certificate, and the certificate's common name. In `.Pinned` mode the TLS
// handshake already refused every key `pin_check` did not accept.
//
// Peers share only the `Server_Shared`. The first-packet path and
// `server_cookie_rotate` change it (cookie keys, rate counters): call them, and
// every session call, from one data thread.
//
// Caller duties for a server (see server.odin, server_session.odin):
//
//	UDP demux   data: `server_peer_id` (or address if `PEER_ID_NONE`); control: the
//	            session address; no session: `server_first_packet`
//	cookies     `server_cookie_rotate` every `COOKIE_ROTATE_INTERVAL`
//	timers      `session_next_wakeup` / `session_tick` of every session
//	events      `Auth_Request`, `Float_Candidate`, `Up`, `Closed`, `Failed`
//	TCP         `session_init_server_tcp` per accepted connection
//
// Stateless first packets: with plain wrapping the reply to a stranger's reset is
// longer than the reset (26 vs 14 bytes unwrapped, 54 vs 42 tls-auth SHA1, 66 vs
// 54 tls-crypt; up to 1.9 times). The spec fixes both packets. The per-source and
// global rate limits of `Server_Config` cap it.
//
// Layers:
//
//	wrap       tls-auth, tls-crypt, tls-crypt-v2, dynamic tls-crypt   (proto/wrap)
//	reliable   ids, acks, windows, retransmission                     (proto/reliable)
//	TLS        over memory BIOs                                       (proto/ossl)
//	push       key-method-2, peer-info, commands, PUSH_REPLY          (proto/push)
//	data       key slots, AEAD, replay, keepalive                     (proto/keys, proto/crypt)
//
// The session never decides about tunnels or routes. `Up` carries the pushed
// options (`session_pushed`); the daemon applies them.
//
// Not thread-safe: one thread per `Session`. The data channel (keys, counters,
// replay windows) may live on another thread with one worker (dataplane.odin);
// the session then talks to it by commands and results from its own thread.
//
// Memory:
// - `Session` value 41,552 bytes: scratch buffers 18 KiB, one key state 5.3 KiB,
//   three data keys 8 KiB (epoch windows 2.7 KiB each: six receive keys per key
//   id), server state 1 KiB.
// - Init allocates: reliability buffers (18 * 2048 = 36 KiB), TCP frame buffer
//   (max_frame + 2), push assembler lists (client) or push messages (server,
//   until sent).
// - TLS library state is extra.
// - Server peer: about 77 KiB plus TLS state. `Server_Shared`: 7.5 KiB plus TLS
//   context.
package session

import "core:mem"
import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/reliable"
import "noir:proto/wire"
import "noir:proto/wrap"

// The clock. A monotonic `time.Duration` with an origin of the caller's choice.
Time :: time.Duration

// A session is a client or a server.
Role :: enum u8 {
	Client,
	Server,
}

Transport :: push.Transport

Error :: enum {
	None,
	// The config is wrong (reason in the field name of the proc's doc).
	Bad_Config,
	// A key or certificate could not be read.
	Bad_Key,
	// The role is not implemented (`session_init` creates clients only).
	Not_Implemented,
	// An allocation failed.
	Alloc,
	// The random source failed.
	Random,
	// The crypto library failed.
	Crypto,
	// The call is not valid in this state.
	Bad_State,
	// The packet is too big for the buffer, or the buffer lacks headroom.
	Buffer_Too_Small,
	// A username or password is too long (127 bytes at most).
	Credentials_Too_Long,
	// The session is not up, so it cannot carry tunnel packets.
	Not_Up,
	// A bug or a failed library call inside the engine.
	Internal,
	// No send key is usable (all packet ids used up). A rekey is on its way.
	No_Key,
}

State :: enum u8 {
	New, // `session_init` done, `session_start` not yet called
	Connecting, // hard reset sent, no server reset yet
	Handshaking, // TLS, key-method and push
	Up, // data keys installed
	Closing, // `session_close` sent the exit notice
	Closed, // finished by `session_close`
	Failed, // see the `Failed` event
}

// Key state of the control channel. The order matters.
Ks_State :: enum u8 {
	Undef,
	Initial,
	Pre_Start, // our reset is queued, waiting to be acked
	Start, // reset acked, TLS runs
	Sent_Key, // our key-method message is written
	Got_Key, // the peer's key-method message is read
	Active, // both sent and read, and all our packets are acked
	Generated_Keys, // data keys installed
	Error,
}

// Which wrapping the control channel uses.
Wrap_Mode :: enum u8 {
	None,
	Tls_Auth,
	Tls_Crypt,
	Tls_Crypt_V2,
}

Wrap_Config :: struct {
	mode:          Wrap_Mode,
	// tls-auth and tls-crypt: the key file. The session copies it.
	static_key:    ^wrap.Static_Key,
	// tls-auth: digest (default SHA1) and `key-direction`. A client uses
	// `.One` (the usual) or `.Bidirectional`.
	auth_digest:   ossl.Hmac_Alg,
	key_direction: wrap.Key_Direction,
	// tls-crypt-v2: the client key file. The session copies it.
	client_key:    ^wrap.Client_Key,
}

// Source of random bytes. The default is `ossl.random_bytes`.
Random_Proc :: #type proc(user: rawptr, buf: []u8) -> bool

// A filter for the option list of each PUSH_REPLY message (`pull-filter`). It
// runs before the options are parsed. `options` is the text after "PUSH_REPLY,".
// - Copy the options to keep into `out` (as long as `options`; a filter only
//   drops options) and return the byte count.
// - Keep the `push-continuation` item.
// - `ok = false` refuses the reply: the session fails with reason `.Push`, and
//   `reject` (shortened to the event text size) as the text.
// `options` and `out` are valid only during the call.
Push_Filter :: #type proc(user: rawptr, options: string, out: []u8) -> (n: int, reject: string, ok: bool)

// Called before each new TLS session starts. See `Config.tls_prepare`.
Tls_Prepare :: #type proc(user: rawptr, ctx: ^ossl.Tls_Ctx)

// Settings of a session. Zero values mean the default written next to each
// field. `session_init` copies what it needs, so strings, slices and key
// structs may go away afterwards.
Config :: struct {
	role:                 Role,
	transport:            Transport,
	wrap:                 Wrap_Config,

	// ---- TLS ----
	// A prepared TLS context (the session does not free it). Leave nil to let
	// the session build one from the fields below.
	tls_ctx:              ^ossl.Tls_Ctx,
	// PEM text. Our certificate chain and key (needed: servers ask for one),
	// and the trust anchors for `verify = .Chain`.
	cert_pem:             []u8,
	key_pem:              []u8,
	ca_pem:               []u8,
	verify:               ossl.Peer_Verify, // default .Chain
	// `.Pinned` accepts the server if the SHA-256 of its public key (SPKI) or
	// of its whole certificate is in one of these lists.
	pin_spki:             [][32]u8,
	pin_cert:             [][32]u8,
	// Key exchange groups (see ossl.Tls_Config). Empty: library default.
	tls_groups:           string,
	// Certificate revocation for `verify = .Chain` (see ossl.Tls_Config).
	crl_pem:              []u8,
	revoked_check:        ossl.Revoked_Check,
	revoked_user:         rawptr,
	// Checks on the peer certificate (`remote-cert-tls`, `remote-cert-ku`,
	// `remote-cert-eku`, `verify-x509-name`) and the TLS version range
	// (`tls-version-min`, `tls-version-max`). See ossl.Tls_Config. Version minimum
	// defaults to TLS 1.2. Rule strings are read when the context is created.
	leaf_rules:           ossl.Leaf_Rules,
	tls_min:              ossl.Tls_Version,
	tls_max:              ossl.Tls_Version,
	// Called before each new TLS session (a connection and every renegotiation)
	// with the context, from the thread that runs the handshakes. The caller can
	// reload its CRL list there (`ossl.tls_ctx_set_crl`). Kept for the life of the
	// session; `tls_prepare_user` must stay valid as long.
	tls_prepare:          Tls_Prepare,
	tls_prepare_user:     rawptr,

	// ---- login ----
	// At most 127 bytes each. Both empty: certificate-only login.
	username:             string,
	password:             string,

	// ---- negotiation ----
	// The data ciphers we run, in order of preference. Default: AES-256-GCM,
	// AES-128-GCM, CHACHA20-POLY1305.
	ciphers:              []push.Cipher,
	// Bits announced in IV_PROTO. Default `DEFAULT_IV_PROTO`: exactly what this
	// package implements (including the epoch data format, `.Data_Epoch`).
	// PUSH_UPDATE is refused. A daemon that applies the `dns` v2 option may add
	// `.Dns_Option_V2`. Without `.Data_Epoch` the server never pushes `aead-epoch`,
	// and a push of it is a server error.
	iv_proto:             push.Iv_Proto,
	// IV_VER and IV_PLAT. Default "noirvpn" and "linux".
	version:              string,
	platform:             string,
	// IV_SSO: the sign-in methods that a user interface can run, such as
	// "webauth". Empty: the line is not sent. At most `SSO_MAX` bytes.
	sso:                  string,
	// IV_MTU: largest tun MTU we take (default 1500) and the tun MTU in the
	// options string (default 1500).
	iv_mtu:               int,
	// The value of the IV_MTU line when it must differ from `iv_mtu` (a guest
	// takes a larger pushed tun-mtu than it asks for). 0: send `iv_mtu`.
	iv_mtu_sent:          int,
	tun_mtu:              int,

	// ---- control channel ----
	// `max-packet-size`, default 1250. Only sizes the TLS pieces.
	max_packet_size:      int,
	// The server is an IPv4 peer (28 bytes of IP and UDP header in the packet
	// budget instead of 48).
	ipv4_peer:            bool,
	// `tls-timeout`, default 2 s. Retransmit timer start.
	tls_timeout:          time.Duration,
	// `hand-window`, default 60 s.
	hand_window:          time.Duration,
	// Largest TCP frame (default 4096). TCP only.
	max_frame:            int,

	// ---- data channel and rekey ----
	// `tran-window`: how long the old key still receives (default 3600 s).
	tran_window:          time.Duration,
	// Wait before sending on a new key (default 0: at once).
	rekey_tx_delay:       time.Duration,
	// `reneg-sec`: default 3600, -1 off. Our own timer; a stock server also
	// has its own.
	reneg_sec:            int,
	// `reneg-bytes` and `reneg-pkts`: bytes (packets) in and out on a key.
	// Default off.
	reneg_bytes:          u64,
	reneg_pkts:           u64,
	// Overrides for the pushed `ping` and `ping-restart` (seconds, 0 keeps the
	// pushed value, -1 turns the timer off).
	ping:                 int,
	ping_restart:         int,
	// Used when the server pushes no `ping` (no `ping-restart` or `ping-exit`).
	// A pushed value, or an override above, wins over these. 0: none.
	ping_default:         int,
	ping_restart_default: int,
		// `explicit-exit-notify n` (UDP): how many OCC exit packets `session_close`
		// sends when the control-channel EXIT is not negotiated. 0 takes the pushed
		// value (or none).
	explicit_exit_notify: int,
	// How long `session_close` waits for the EXIT to be acked (default 2 s).
	exit_timeout:         time.Duration,

		// ---- push filter ----
		// `pull-filter`. nil: every option is taken. `push_filter_user` is
		// borrowed and must live as long as the session.
	push_filter:          Push_Filter,
	push_filter_user:     rawptr,

	// ---- other ----
	random:               Random_Proc,
	random_user:          rawptr,
	// Replaces the AEAD usage limit (tests only; 0 is the spec's value).
	limit_override:       u64,

		// ---- data channel owned by a service ----
		// The data channel runs outside this process (a DCO service, see dataplane.odin
		// `session_set_external`). The session then:
		// - creates no data key of its own (an `Install` command carries the key
		//   material)
		// - sends no keepalive or exit notice on the data channel (the owner does the
		//   keepalive; exit goes over the control channel only)
		// - offers the epoch data format only if `ext_epoch` is set
		// - has its own `ping` and `ping-restart` timers off (`session_keepalive` says
		//   what the owner should run)
		// Set it before `session_init`. A server sets it in `Server_Config`.
	ext_data:             bool,
	// With `ext_data`: the owner has keys of the epoch data format. The session
	// may then offer and use that format, and the `Install` command passes it.
	ext_epoch:            bool,
}

// What this package implements of IV_PROTO: DATA_V2,
// REQUEST_PUSH, TLS_KEY_EXPORT, AUTH_PENDING_KW, CC_EXIT_NOTIFY, AUTH_FAIL_TEMP,
// DYN_TLS_CRYPT, DATA_EPOCH. 1950.
//
// Not set, on purpose: PUSH_UPDATE (not implemented), DNS_OPTION_V2 (the daemon
// sets it when it applies `dns`).
DEFAULT_IV_PROTO :: push.Iv_Proto{
	.Data_V2,
	.Request_Push,
	.Tls_Key_Export,
	.Auth_Pending_Kw,
	.Cc_Exit_Notify,
	.Auth_Fail_Temp,
	.Dyn_Tls_Crypt,
	.Data_Epoch,
}

// Bits that `session_init` refuses to send, because the feature is not here.
UNSUPPORTED_IV_PROTO :: push.Iv_Proto{.Push_Update, .Ncp_P2p}

DEFAULT_CIPHERS :: [3]push.Cipher{.Aes_256_Gcm, .Aes_128_Gcm, .Chacha20_Poly1305}

DEFAULT_RENEG_SEC :: 3600
DEFAULT_MAX_PACKET_SIZE :: 1250
DEFAULT_MAX_FRAME :: 4096
DEFAULT_IV_MTU :: 1500
DEFAULT_EXIT_TIMEOUT :: 2 * time.Second
DEFAULT_HAND_WINDOW :: 60 * time.Second
PEER_ID_NONE :: wire.PEER_ID_UNDEFINED

// Room a caller must keep in front of a tunnel packet for `session_encap`: two
// bytes for the TCP length, then AEAD header, packet id and tag. The epoch format
// needs less in front (12 bytes instead of 24) and 16 bytes behind (the tag), see
// `TUNNEL_TAILROOM`. `session_encap` puts the link packet where it fits and
// returns the slice: use the returned slice, do not assume where it starts.
TUNNEL_HEADROOM :: wire.FRAME_PREFIX_LEN + crypt.BASELINE_HEADROOM
// Room a caller must keep behind a tunnel packet for `session_encap`: the tag of
// the epoch format. The baseline format needs none.
TUNNEL_TAILROOM :: crypt.EPOCH_TAILROOM

// A buffer for `session_poll_tx` that always fits a link packet.
LINK_BUF_SIZE :: 2304

// Largest credential string (the stock limit is 128 with the NUL).
CREDENTIAL_MAX :: 127

MAX_CIPHERS :: 8
VERSION_MAX :: 64
PLATFORM_MAX :: 16
SSO_MAX :: 64
// The longest `INFO_PRE` text that `session_info_pre` holds (the text after
// "INFO_PRE,"). A longer one is cut and flagged.
INFO_PRE_MAX :: 1024

@(private)
INNER_MAX :: 2048 + 128
@(private)
TLS_SCRATCH :: reliable.SEND_WINDOW * reliable.DEFAULT_MAX_PAYLOAD
@(private)
DATA_KEYS :: 3
@(private)
HANDSHAKE_REQUEST_FIRST :: time.Second
@(private)
HANDSHAKE_REQUEST_REPEAT :: 5 * time.Second

// Control state of one key id. A session has one at a time: a soft reset
// replaces it (control packets of the old id are dropped).
Key_State :: struct {
	id:            u8,
	state:         Ks_State,
	chan:          reliable.Channel,
	chan_ok:       bool,
	tls:           ossl.Tls_Session,
	tls_ok:        bool,
	// The peer started this renegotiation.
	by_peer:       bool,
	// The server asked us to put the wrapped client key on message id 1.
	resend_wkc:    bool,
	wkc_sent:      bool,
	// Key-method exchange.
	km_sent:       bool,
	km_got:        bool,
	km_len:        int,
	km_in:         [push.KEY_METHOD_MAX_LEN]u8,
	cmd:           push.Cmd_Reader,
	// Cipher item of the server's options string (a fallback for NCP).
	srv_cipher:    [32]u8,
	srv_cipher_n:  u8,
	// Server: the login of this key state, and the part of `km_in` that holds
	// the client's key-method message (the rest is commands).
	auth:          Srv_Auth,
	km_used:       int,
	// Key 0 only: the PUSH_REPLY is complete and valid.
	push_done:     bool,
	push_req_at:   Time, // next PUSH_REQUEST, if `push_req_on`
	push_req_on:   bool,
	active_at:     Time,
}

Counters :: struct {
	link_rx_pkts:       u64,
	link_rx_bytes:      u64,
	link_tx_pkts:       u64,
	link_tx_bytes:      u64,
	control_rx:         u64,
	control_tx:         u64,
	data_rx:            u64, // data packets that authenticated
	data_tx:            u64,
	tunnel_rx:          u64, // tunnel packets handed to the caller
	tunnel_tx:          u64,
	ping_rx:            u64,
	ping_tx:            u64,
	rekeys:             u64,
		// Epoch data format: how often the send epoch moved (usage limit, peer's
		// move, counter), and how often a future epoch of the peer authenticated and
		// became the receive epoch. Both stay 0 in the baseline format.
	epoch_adv_tx:       u64,
	epoch_adv_rx:       u64,
	// Why packets were dropped.
	drop_opcode:        u64, // unknown, rejected or wrong-direction opcode
	drop_short:         u64,
	drop_sid:           u64, // session id does not match (or a second server reset)
	drop_addr:          u64, // server: control packet from another address
	drop_peer_id:       u64, // server: data packet with another peer id
	drop_unwrap:        u64, // bad tag or HMAC
	drop_wrap_replay:   u64,
	drop_decode:        u64,
	drop_key_id:        u64, // key ids out of sync
	drop_reliable:      u64, // window full, too far ahead, bad ack list, ...
	drop_data_no_key:   u64,
	drop_data_epoch:    u64, // epoch format: an epoch outside the receive window
	drop_data_tag:      u64,
	drop_data_replay:   u64,
	drop_data_payload:  u64, // authentic but not a tunnel packet, ping or exit
	// `ext_data`: what the owner of the data channel dropped in each direction, all
	// reasons together (the reasons it knows are also in the `drop_data_*` above).
	drop_ext_rx:        u64,
	drop_ext_tx:        u64,
	drop_tunnel_state:  u64, // data before the session is up
	events_dropped:     u64,
}

// What `session_receive` returns.
Rx_Result :: struct {
	// Bytes of the input that were used. All of them for UDP. For TCP, the
	// part taken into the frame buffer: call again with the rest.
	consumed: int,
		// A decrypted tunnel packet to write to the tun device. It is a slice of
		// the input (UDP) or of the frame buffer (TCP). Valid until the next call
		// to `session_receive`.
	tunnel:   []u8,
	// TCP: another whole frame is already buffered, call again (with an empty
	// slice if all input is used).
	more:     bool,
}

Wrap_Ctx :: struct {
	mode:     Wrap_Mode,
	auth:     wrap.Tls_Auth,
	crypt:    wrap.Tls_Crypt, // tls-crypt, tls-crypt-v2 (keys from Kc)
	dyn:      wrap.Tls_Crypt, // dynamic tls-crypt, after key 0 is up
	have_dyn: bool,
	orig_key: wrap.Static_Key, // the static key (or Kc): the dynamic key is XORed with it
	have_key: bool,
	wkc:      [wrap.WKC_MAX_LEN]u8,
	wkc_len:  int,
	// Bytes a packet loses to the wrapping, for the TLS piece budget.
	overhead: int,
}

@(private)
Pins :: struct {
	spki: [][32]u8,
	cert: [][32]u8,
}

Session :: struct {
	role:            Role,
	transport:       Transport,
	allocator:       mem.Allocator,
	cfg:             Config, // with the defaults filled in; borrowed pointers cleared
	state:           State,
	fail_reason:     Fail_Reason,

	// Ids and clock.
	local_sid:       reliable.Sid,
	peer_sid:        reliable.Sid,
	peer_sid_set:    bool,
	wall_base:       i64, // unix seconds at monotonic time 0
	started:         bool,
	link_up:         bool,

	// Control channel.
	wrap:            Wrap_Ctx,
	ks:              Key_State,
	rekeying:        bool, // a renegotiation is in progress (the key state is not Generated_Keys)
	tls_ctx:         ossl.Tls_Ctx,
	tls_ctx_owned:   bool,
	tls_ctx_ptr:     ^ossl.Tls_Ctx,
	pins:            ^Pins,
	// Client: the key of the server's leaf certificate, when the first TLS
	// handshake is done (`session_peer_key`).
	peer_key:        ossl.Peer_Key,
	peer_key_ok:     bool,

	// Login.
	user:            [CREDENTIAL_MAX + 1]u8,
	user_n:          int,
	pass:            [CREDENTIAL_MAX + 1]u8,
	pass_n:          int,
	token:           [CREDENTIAL_MAX + 1]u8,
	token_n:         int,
	token_user:      [CREDENTIAL_MAX + 1]u8,
	token_user_n:    int,

	// Negotiation inputs, copied from the config.
	ciphers:         [MAX_CIPHERS]push.Cipher,
	ciphers_n:       int,
	ver:             [VERSION_MAX]u8,
	ver_n:           int,
	plat:            [PLATFORM_MAX]u8,
	plat_n:          int,
	sso:             [SSO_MAX]u8,
	sso_n:           int,
	// The text of the last `INFO_PRE` (`session_info_pre`).
	info_pre:        [INFO_PRE_MAX]u8,
	info_pre_n:      int,
	info_pre_cut:    bool,

	// Push.
	asm_ok:          bool,
	asm_:            push.Push_Assembler,
	pushed:          push.Pushed_Options,
	have_pushed:     bool,
	push_deadline:   Time,
	push_deadline_on: bool,
	cipher:          push.Cipher,
	flags:           push.Protocol_Flags,
	format:          keys.Format, // data packet format of every key of this session (`aead-epoch`)
	peer_id:         u32,
	ping:            int, // seconds, 0 off
	ping_restart:    int,
	exit_notify:     int,

		// Data channel.
		// The key slot table for the timers (see dataplane.odin: the data plane has
		// its own, which gets the same calls).
	slots:           keys.Key_Slots,
	// The keys, counters and replay windows. On this thread unless `rdp` is set.
	dp:              Data_Plane,
	// The data plane on another thread (`session_set_remote`), and how to reach it.
	rdp:             ^Data_Plane,
	remote:          Dp_Remote,
	last_tx:         Time, // last data packet sent (for `ping`)
	last_rx:         Time, // last authenticated packet received (for `ping-restart`)
		// `ext_data`: the keepalive values the owner runs (seconds, 0 off), and the
		// totals it reported last, with the packets and bytes at the newest key's
		// install (for `reneg-bytes` and `reneg-pkts`).
	ext_ping:        int,
	ext_ping_restart: int,
	ext_seen:        Ext_Totals,
	ext_base:        Ext_Totals,

	// Closing.
	closing:         bool,
	exit_cc:         bool, // closing by the EXIT control message
	exit_left:       int, // OCC exit packets still to send
	exit_next:       Time,
	exit_deadline:   Time,

	// TCP framing.
	split:           wire.Stream_Splitter,
	split_buf:       []u8,

	// Scratch space (never holds anything between calls).
	inner:           [INNER_MAX]u8,
	tls_buf:         [TLS_SCRATCH]u8,
	plain:           [push.MAX_COMMAND_LEN]u8,

	// Server role. `reneg_eff` is the `reneg-sec` this session runs (a server's
	// has a random cut, a client's is the setting).
	srv:             Srv_State,
	reneg_eff:       int,
	// Source address of the datagram being handled (server, UDP). Borrowed
	// from the caller for the length of one call.
	rx_from:         []u8,

	// Events.
	ev_ring:         [EVENT_RING]Event,
	ev_head:         int,
	ev_count:        int,
	counters:        Counters,
}
