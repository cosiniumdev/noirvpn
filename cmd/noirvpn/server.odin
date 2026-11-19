// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"
import "noir:client"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/sysnet"
import "noir:platform/tun"
import "noir:proto/config"
import "noir:proto/ossl"
import "noir:proto/reliable"
import "noir:proto/session"
import "noir:server"

// The server daemon: one thread, one event loop, the same binary as the
// client. Packet loops: server_datapath.odin. Connection state machine:
// server_conn.odin. Status text: server_status.odin.
//
//   start  config, peers file, pools, TLS, tun (addresses, routes), sockets
//   run    UDP: one socket per `local`/`proto` line, batched in and out
//          TCP: a listener, one connection per client
//          one session per client, found by peer-id, session id or address
//   stop   SIGTERM/SIGINT: every client gets RESTART (explicit-exit-notify)
//          or EXIT, wait a few seconds, remove the routes, exit 0
//
// Backpressure:
//   UDP  a full socket buffer keeps the unsent packets, stops tun reads and
//        waits for the socket to be writable, so the tun queues push back on
//        senders. Packets arriving for forwarding during the wait are dropped
//        and counted.
//   TCP  each client has a write queue of 128 KiB that doubles up to 1 MiB when
//        a packet does not fit. Tunnel packets are dropped (counted) at 3/4
//        full. A large tun packet cut into many is queued whole or dropped
//        whole. A client is disconnected if its queue cannot take even a
//        control packet, or if it shows no progress for 30 s while dropping.

MAX_LISTEN :: 8
// The write queue of a TCP client starts at SRV_TCP_TX_SIZE bytes and doubles
// when a packet does not fit, up to SRV_TCP_TX_MAX.
SRV_TCP_TX_SIZE :: 128 * 1024
SRV_TCP_TX_MAX :: 1024 * 1024
// TCP connections from one address that have not logged in yet.
TCP_PREAUTH_PER_IP :: 16
// A TCP client that drops packets for this long without draining is closed.
SLOW_PEER_LIMIT :: 30 * time.Second
// Per wake-up the server reads at most SRV_READ_ROUNDS batches of RX_BATCH
// datagrams from a UDP socket (or SRV_READ_ROUNDS reads of 32 KiB from a TCP
// client) and SRV_TUN_BURST packets from the tun. Traffic to clients then gets
// the same thread share as traffic from them. (With 8 rounds against 64 tun
// reads, four busy clients starved the tun side and the kernel dropped packets.)
SRV_READ_ROUNDS :: 2
SRV_TUN_BURST :: RX_BATCH * SRV_READ_ROUNDS
// Default tun transmit queue (packets the kernel holds for us; 500 is the
// kernel's default). Absorbs a downlink burst while a socket batch is processed.
SRV_TXQUEUELEN :: 2048
// How long the server waits for the clients to acknowledge its goodbye.
SHUTDOWN_WAIT :: 4 * time.Second
// The pool file is not written more often than this, whatever the config says.
PERSIST_MIN_SECONDS :: 1

Listener :: struct {
	index:      u8,
	proto:      config.Proto,
	tls:        bool, // TCP inside an outer TLS stream (`tls-server`)
	sock:       net.Socket,
	open:       bool,
	sh:         ^session.Server_Shared,
	tx_batch:   net.Batch, // UDP
	want_write: bool, // UDP: watched for writing (a send stopped)
	rx_per_msg: int, // UDP: datagrams per message the last read gave (UDP GRO), at least 1
	text:       string, // for the log
	ep:         net.Endpoint, // where it is bound
	have_host:  bool, // the `local` line names an address (else: any)
}

// One packet that waits for `sendmmsg`: sealed in place, with its destination.
Tx_Slot :: struct {
	buf:  [SLOT_SIZE]u8,
	off:  int,
	len:  int,
	lidx: u8,
	ep:   net.Endpoint,
	// The address to send from (the one the client used), see `Conn.local`.
	local: net.Local,
	// With crypto workers: the packet waits for its worker (see server_workers.odin).
	job:  ^Wk_Job,
	cidx: u32, // the conn's slot in the table
	sess: u64, // and its session number: the conn may be gone when the result is read
	n:    int, // the tunnel packet size
}

// The packets of the current batch.
Udp_Out :: struct {
	slots:   [TX_BATCH]Tx_Slot,
	count:   int,
	// A send stopped on this listener's socket and the rest waits.
	blocked: bool,
	lidx:    u8,
	// Slots before `done` hold sealed packets; the ones after wait for a worker.
	done:    int,
	sealing: bool, // `out_finish` is running
}

Srv_Stats :: struct {
	sessions:         u64, // sessions created (a first packet was accepted)
	connects:         u64, // tunnels that came up
	disconnects:      u64, // tunnels that ended
	refused:          u64, // logins refused after TLS
	hs_failed:        u64, // sessions that ended before the login (TLS failed, timed out)
	outer_failed:     u64, // connections on a `tls` listener that failed the outer TLS handshake, timed out before it, or were refused as raw OpenVPN
	kicks:            u64, // sessions removed by the server (duplicate login, reload)
	tun_read_pkts:    u64,
	tun_read_bytes:   u64,
	tun_write_pkts:   u64,
	tun_write_bytes:  u64,
	from_tun_pkts:    u64, // tun packets sealed for a client
	c2c_pkts:         u64, // client to client (no tun)
	sent_pkts:        u64, // UDP packets handed to the kernel in batches
	// Drops, by reason.
	drop_no_session:  u64, // a data packet for a peer-id or address nobody has
	drop_conn_state:  u64, // a data packet for a session that is gone or closing
	drop_bad_opcode:  u64, // neither control nor data
	drop_oversize:    u64, // a datagram larger than the receive slot
	drop_stopping:    u64, // a first packet while the server stops
	drop_conn_limit:  u64, // no room for another session or TCP connection
	drop_preauth:     u64, // too many unauthenticated TCP connections from one address
	drop_seal:        u64, // could not seal
	drop_tx_busy:     u64, // forwarded while a send waited
	drop_tcp_backlog: u64, // the TCP client's queue is full
	drop_tun_write:   u64, // the tun device refused the packet
	drop_block6_tx:   u64, // IPv6 packets read from the tun device and dropped (block-ipv6)
	drop_block6_rx:   u64, // IPv6 packets from clients dropped before routing (block-ipv6)
	tcp_slow_closed:  u64, // TCP clients closed for not reading
	tun_read_errors:  u64,
	sock_send_errors: u64,
	sock_recv_errors: u64,
	sock_blocked:     u64, // times a send stopped on a full socket
	tun_paused:       u64, // times the tun device was not read for a full socket
	pw_checks:        u64, // hash file checks started
	pw_failed:        u64, // hash file checks that did not pass
	pw_busy:          u64, // hash file checks refused for a full queue or a slow result
}

Srv :: struct {
	cfg:        ^config.Server_Config,
	set:        Server_Settings,
	exit_code:  Exit,
	exit:       bool, // leave the event loop
	stopping:   bool, // a stop signal was handled: no new clients, goodbyes are going out
	finished:   bool, // `srv_finish` has run
	loop:       event.Loop,
	sig_fd:     i32,
	sig_ready:  bool,
	started:    time.Duration,
	t_stop:     Timer,
	t_persist:  Timer,
	t_cookie:   [2]Timer,

	// What is decided: peers, pools, routes, auth.
	srv:        server.Server,
	srv_ok:      bool,
	// The outer TLS of the `tls` listeners (tls_transport.odin): one context for all connections.
	tls_ctx:    ossl.Tls_Ctx,
	tls_ctx_ok: bool,
	// The session settings by transport: 0 UDP, 1 TCP, and 2 for the `tls` clients of a
	// mixed server (`datapath udco`): TCP, with the data channel in the session.
	shared:     [3]session.Server_Shared,
	shared_ok:  [3]bool,
	listeners:  [MAX_LISTEN]Listener,
	n_listen:   int,
	persist_file: string,
	persist_secs: int,

	// The sessions.
	conns:      []^Conn,
	free_slots: [dynamic]u32,
	n_conns:    int,
	max_conns:  int,
	sid_map:    map[reliable.Sid]u32,
	dirty:      [dynamic]u32, // TCP connections with data queued

	// The tunnel and the kernel's view of it.
	sys:        sysnet.Conn,
	sys_ok:     bool,
	// The clean-up record (records.odin) and the instance name it holds.
	rec:        client.Record_File,
	inst_name:  string,
	tun:        tun.Device,
	tun_open:   bool,
	tun_paused: bool,
	ifindex:    u32,
	nc:         client.Netcfg,
	nc_ok:      bool,
	plan:       client.Plan,
	plan_ok:    bool,
	tun_mtu:    int,

	// Packet buffers: nothing is allocated per packet.
	rx_buf:     []u8,
	rx_msgs:    int, // messages per receive call (slots of `rx_buf`)
	rx_slot:    int, // bytes of each slot
	rx_batch:   net.Batch,
	tun_stage:  []u8, // one read from a tun with the virtio header
	tun_tx:     Tun_Tx, // joins the segments of a round for the tun
	off:        Offload_Stats,
	out:        Udp_Out,
	scratch:    Tx_Slot, // a TCP client's packet is sealed here, then copied to its queue
	dco:        Dco_Server, // the data channel on a DCO service (server_dco.odin)
	// Crypto workers (`workers N`, server_workers.odin); nil: the packets are sealed and opened here.
	wk:         ^Wk_Pool,
	recs:       [dynamic]Srv_Rec, // received data packets that wait for their worker, in order
	later:      [dynamic]Srv_Ref, // conns to look at when the records are done
	rx_conn:    ^Conn, // the conn whose session is in `session_receive`
	rx_from:    session.Peer_Addr, // the source of that datagram (UDP)
	rx_has_from: bool,
	rx_local:   net.Local, // the local address of that datagram (UDP)
	rx_copied:  int, // bytes of the copy area of `rx_buf` in use
	taken:      u64, // data packets the workers took
	rx_seen:    Srv_Ref, // the conn whose data packets wait for a look (`srv_rx_seen`)
	rx_running: bool, // `srv_rx_run` is running
	link:       [session.LINK_BUF_SIZE]u8,
	areq:       session.Auth_Request,

	stats:      Srv_Stats,
	agg:        session.Counters, // the counters of sessions that have ended
	first_log:  First_Log, // server_first_log.odin
	// The kinds of client that got the tunnel MTU warning (server_mss.odin).
	mtu_warned:   [8]Mtu_Warned,
	mtu_warned_n: int,

	// The hash file check (server_password.odin).
	pw:           Pw_State,
	// The key of the session tokens of a web sign-in (server_token.odin).
	tkey:         Token_Key,
	// The sign-ins that a token belongs to (server_token.odin).
	signins:      Sign_In_Table,

	// The control bus.
	parked:       int, // logins that wait for a controller (`auth-external`)
	next_sess:    u64, // the last session number handed out
	pin_seq_seen: u64, // pin refusals attributed so far (`Pin_Store.refusal_seq`)
	ended:        Ended_Totals, // tunnel traffic of the sessions that have ended
	stop_wait:    Maybe(time.Duration), // how long the goodbyes may take (unset: SHUTDOWN_WAIT)
}

// What crossed the tunnel for clients that are gone.
Ended_Totals :: struct {
	in_pkts, in_bytes, out_pkts, out_bytes: u64,
}

SV: Srv

// ----------------------------------------------------------------- timers

stimer_set :: proc(loop: ^event.Loop, t: ^Timer, at: time.Duration, handler: event.Timer_Handler, user: rawptr) {
	if t.on && event.timer_reset_at(loop, t.id, at) {
		return
	}
	id, err := event.timer_add_at(loop, at, handler, user)
	if err != .None {
		t.on = false
		logf(.Error, "cannot start a timer: %v", err)
		return
	}
	t.id = id
	t.on = true
}

stimer_clear :: proc(loop: ^event.Loop, t: ^Timer) {
	if t.on {
		event.timer_cancel(loop, t.id)
		t.on = false
	}
}

now_srv :: proc(d: ^Srv) -> time.Duration {
	return event.loop_time(&d.loop)
}

unix_now :: proc() -> i64 {
	return time.time_to_unix(time.now())
}

// ------------------------------------------------------------------- setup

// Starts everything. False after logging why (`d.exit_code` is set); the caller
// then runs `srv_destroy`.
srv_init :: proc(d: ^Srv) -> (ok: bool) {
	d.exit_code = .System
	srv_reset_fds(d)
	cfg := d.cfg

	if err := event.init(&d.loop); err != .None {
		logf(.Error, "cannot start the event loop: %v", err)
		return false
	}
	d.started = event.now()
	if !d.sig_ready {
		fd, sok := sig_open()
		if !sok {
			logf(.Error, "cannot set up signal handling")
			return false
		}
		d.sig_fd = fd
		d.sig_ready = true
	}
	if err := event.add_fd(&d.loop, d.sig_fd, {.Read}, on_srv_signal, d); err != .None {
		logf(.Error, "cannot watch the signal descriptor: %v", err)
		return false
	}
	conn, serr := sysnet.open()
	if serr != .None {
		logf(.Error, "cannot open a netlink socket: %v", serr)
		return false
	}
	d.sys = conn
	d.sys_ok = true
	if !srv_dco_init(d) {
		return false
	}
	// What stopped daemons left behind, never what a running one holds.
	bus_prepare_dirs(&d.cfg.common, .Server, d.inst_name)
	rec_start(&d.rec, &d.sys, sysnet.dns_env_default(), d.inst_name, .Server, "")

	// Peers, pools, routing table.
	pins: ^server.Pin_Table
	if cfg.peer_keys != "" {
		t, text := server.pin_table_load(cfg.peer_keys)
		if t == nil {
			logf(.Error, "peers file %s: %s", cfg.peer_keys, text)
			delete(text)
			d.exit_code = .Config
			return false
		}
		pins = t
		logf(.Notice, "peers file %s: %d keys", cfg.peer_keys, server.pin_table_len(t))
	}
	seed: [8]u8
	if !ossl.random_bytes(seed[:]) {
		logf(.Error, "cannot get random numbers from the system")
		server.pin_table_destroy(pins)
		return false
	}
	params := server.Server_Params {
		pool_hold = 5 * time.Minute,
		hash_seed = u64(seed[0]) | u64(seed[1]) << 8 | u64(seed[2]) << 16 | u64(seed[3]) << 24 | u64(seed[4]) << 32 | u64(seed[5]) << 40 | u64(seed[6]) << 48 | u64(seed[7]) << 56,
	}
	if !server.server_init(&d.srv, cfg, pins, params) {
		logf(.Error, "out of memory")
		server.pin_table_destroy(pins)
		return false
	}
	d.srv_ok = true
	d.max_conns = conn_table_size(cfg.max_clients)
	d.conns = make([]^Conn, d.max_conns)
	d.free_slots = make([dynamic]u32, 0, d.max_conns)
	for i := d.max_conns - 1; i >= 0; i -= 1 {
		append(&d.free_slots, u32(i))
	}
	d.sid_map = make(map[reliable.Sid]u32, 1024)
	d.dirty = make([dynamic]u32, 0, d.max_conns)
	for i in 0 ..< 2 {
		d.t_cookie[i] = {}
	}

	if pp, has := cfg.pool_persist.?; has {
		d.persist_file = pp.file
		d.persist_secs = max(pp.seconds, 0)
		persist_load(d)
	}

	// TLS and the session layer, one `Server_Shared` per transport in use.
	now := now_srv(d)
	use: [3]bool
	for l in cfg.listens {
		use[0 if l.proto == .Udp else 1] = true
		if l.tls && d.dco.mixed {
			use[SHARED_TLS_DAEMON] = true
		}
	}
	for i in 0 ..< len(use) {
		if !use[i] {
			continue
		}
		sc := srv_session_config(d, .Udp if i == 0 else .Tcp, i == SHARED_TLS_DAEMON)
		if err := session.server_shared_init(&d.shared[i], &sc, now); err != .None {
			text := "check the config"
			#partial switch err {
			case .Bad_Key:
				text = "cannot use the certificate or key (check that the key belongs to the certificate)"
			case .Bad_Config:
				text = "the settings cannot be used (check the wrap key and the ciphers)"
			}
			logf(.Error, "cannot set up the server: %s (%v)", text, err)
			d.exit_code = .Config
			return false
		}
		d.shared_ok[i] = true
	}

	// The outer TLS, when a listener is `tls-server`.
	for l in cfg.listens {
		if !l.tls {
			continue
		}
		err: ossl.Error
		d.tls_ctx, err = outer_server_ctx(d.set.groups, d.set.transport_cert_pem, d.set.transport_key_pem)
		if err != .None {
			logf(.Error, "cannot set up the outer TLS: %v (check tls-transport-cert and tls-transport-key, or cert and key)", err)
			d.exit_code = .Config
			return false
		}
		d.tls_ctx_ok = true
		break
	}

	// Buffers.
	d.rx_seen.cidx = NO_CONN
	d.rx_msgs, d.rx_slot = off_rx_layout()
	d.rx_buf = make([]u8, d.rx_msgs * d.rx_slot)
	if OFF.tun {
		d.tun_stage = make([]u8, TUN_BUF_SIZE)
		d.tun_tx.arena = make([]u8, TUN_TX_ARENA)
	}
	if net.batch_init(&d.rx_batch, .V6, d.rx_msgs) != .None {
		logf(.Error, "out of memory")
		return false
	}
	for i in 0 ..< d.rx_msgs {
		net.batch_set_recv(&d.rx_batch, i, d.rx_buf[i * d.rx_slot:][:d.rx_slot])
	}

	if !srv_workers_start(d) {
		d.exit_code = .System
		return false
	}
	if !srv_pw_start(d) {
		d.exit_code = .System
		return false
	}
	if !srv_web_start(d) {
		d.exit_code = .System
		return false
	}

	// The tunnel, then the sockets: a server that cannot create its tunnel never
	// listens.
	if !srv_open_tun(d) {
		return false
	}
	srv_log_mss(d)
	for l in cfg.listens {
		if d.n_listen >= MAX_LISTEN {
			logf(.Error, "only up to %d local lines are supported", MAX_LISTEN)
			d.exit_code = .Config
			return false
		}
		if !srv_listen(d, l) {
			return false
		}
	}
	for i in 0 ..< 2 {
		if d.shared_ok[i] {
			cookie_timer_arm(d, i)
		}
	}
	persist_arm(d)
	srv_dco_stats_arm(d)
	d.exit_code = .Ok
	return true
}

// The session settings of the `tls` clients of a mixed server (`Srv.shared`).
SHARED_TLS_DAEMON :: 2

// `Server_Config` of the session layer for one transport. `daemon`: for clients
// whose data channel runs in this process although a DCO service exists (the
// tls clients of a mixed server).
srv_session_config :: proc(d: ^Srv, proto: config.Proto, daemon := false) -> session.Server_Config {
	c := d.cfg
	s := &d.set
	t := &c.tls
	sc: session.Server_Config
	sc.transport = .Udp if proto == .Udp else .Tcp
	sc.wrap.mode = s.wrap_mode
	switch s.wrap_mode {
	case .None, .Tls_Crypt_V2:
	case .Tls_Auth, .Tls_Crypt:
		sc.wrap.static_key = &s.static_key
	}
	sc.wrap.auth_digest = s.digest
	sc.wrap.key_direction = s.key_dir
	if s.have_v2 {
		sc.wrap.server_key = &s.server_key
	}
	sc.wrap.force_cookie = s.force_cookie
	sc.wrap.max_age_days = s.max_age_days
	sc.cert_pem = s.cert_pem
	sc.key_pem = s.key_pem
	sc.ca_pem = s.ca_pem
	sc.verify = s.verify
	sc.client_cert_optional = s.cert_optional
	sc.leaf_rules = s.rules
	sc.tls_min, sc.tls_max = s.tls_min, s.tls_max
	crl_server_config(&sc, &s.crl)
	if s.verify == .Pinned {
		if c.peer_keys != "" {
			sc.pin_check = server.pin_check
			sc.pin_user = &d.srv.pins
		} else {
			sc.pin_cert = s.fingerprints
		}
	}
	if s.verify == .Pin_Or_Chain {
		sc.pin_lookup = server.pin_lookup
		sc.pin_user = &d.srv.pins
	}
	sc.tls_groups = s.groups
	sc.ciphers = s.ciphers
	mtu := server_tun_mtu(c)
	sc.tun_mtu = mtu
	sc.push_tun_mtu = mtu
	sc.max_packet_size = c.max_packet_size
	sc.tls_timeout = time.Duration(t.tls_timeout) * time.Second
	sc.hand_window = time.Duration(t.hand_window) * time.Second
	sc.tran_window = time.Duration(t.tran_window) * time.Second
	sc.reneg_sec = t.reneg_sec if t.reneg_sec > 0 else -1
	sc.reneg_bytes = u64(max(t.reneg_bytes, 0))
	sc.reneg_pkts = u64(max(t.reneg_pkts, 0))
	sc.exit_notify = max(c.link.explicit_exit_notify, 1)
	sc.limit_override = test_aead_limit()
	sc.ext_data = d.dco.on && !daemon
	sc.ext_epoch = sc.ext_data && srv_dco_epoch(d)
	if daemon && !srv_dco_epoch(d) {
		// One push policy for all clients of the server: the clients of a backend
		// without epoch keys never get `aead-epoch`, so these do not either.
		sc.flags = {.Cc_Exit, .Dyn_Tls_Crypt}
	}
	if c.connect_freq_initial.count > 0 {
		sc.initial_limit = c.connect_freq_initial.count
		sc.initial_window = time.Duration(max(c.connect_freq_initial.seconds, 1)) * time.Second
	}
	if n, ok := c.connect_freq_source.?; ok {
		// The session takes -1 for "no limit"; 0 would mean its default.
		sc.source_limit = n if n > 0 else -1
	}
	return sc
}

// The tun device, its addresses, and the routes of the config. With the DCO
// service or the kernel driver the device is theirs (created at `srv_dco_init`).
srv_open_tun :: proc(d: ^Srv) -> bool {
	if !d.dco.on {
		err, ok := srv_tun_open_own(d)
		if !ok {
			if err != .None {
				logf(.Error, "cannot open the tun device: %v (needs CAP_NET_ADMIN and /dev/net/tun)", err)
			}
			return false
		}
	}
	return srv_tun_setup(d)
}

// Opens this process's own tun device and watches it. `err` is why it failed
// (not logged; `.Busy` = name taken, the caller may retry). `err` is `.None`
// and `ok` false when a later step failed (logged).
srv_tun_open_own :: proc(d: ^Srv) -> (err: tun.Error, ok: bool) {
	dev, oerr := tun.open({name = tun_name_of(d.cfg.dev), offload = OFF.tun})
	if oerr != .None {
		return oerr, false
	}
	d.tun = dev
	d.tun_open = true
	off_note_tun(&d.off, &d.tun)
	d.tun_tx.on = d.tun.vnet
	if aerr := event.add_fd(&d.loop, dev.fd, {.Read}, on_srv_tun, d); aerr != .None {
		logf(.Error, "cannot watch the tun device: %v", aerr)
		return .None, false
	}
	link, lerr := sysnet.link_get(&d.sys, tun.name(&d.tun))
	if lerr != .None {
		logf(.Error, "cannot find the tun device %s: %v", tun.name(&d.tun), lerr)
		return .None, false
	}
	d.ifindex = link.index
	return .None, true
}

// The device that serves the clients is open (`d.ifindex`): queue length, MTU, the
// addresses and the routes of the config; for a mixed server the second device too.
srv_tun_setup :: proc(d: ^Srv) -> bool {
	q := d.cfg.txqueuelen if d.cfg.txqueuelen > 0 else SRV_TXQUEUELEN
	if qerr := sysnet.link_set_txqlen(&d.sys, d.ifindex, u32(q)); qerr != .None {
		logf(.Warn, "cannot set txqueuelen %d on %s: %v", q, srv_tun_name(d), qerr)
	}
	client.netcfg_init(&d.nc, &d.sys, d.ifindex)
	d.nc_ok = true
	d.tun_mtu = server_tun_mtu(d.cfg)
	plan := server_plan(d.cfg, d.tun_mtu)
	for n in plan.notes {
		logf(.Warn, "%s", n.text)
	}
	srv_rec_sync(d, &plan, d.ifindex)
	if aerr := client.netcfg_apply(&d.nc, &plan); aerr != .None {
		client.plan_destroy(&plan)
		logf(.Error, "cannot set up the tunnel: %v (step %d)", aerr, d.nc.failed_step)
		d.exit_code = .Network
		return false
	}
	srv_rec_sync(d)
	for w in d.nc.warnings {
		logf(.Warn, "network step %d (%v) failed: %v%s", w.step, w.why, w.err, " (IPv6 is off)" if w.skipped_v6 else "")
	}
	d.plan = plan
	d.plan_ok = true
	n := d.cfg.net
	logf(
		.Notice,
		"tun device %s (index %d), %d.%d.%d.%d/%d, mtu %d",
		srv_tun_name(d), d.ifindex, n.server_addr[0], n.server_addr[1], n.server_addr[2], n.server_addr[3], n.prefix, d.tun_mtu,
	) // fmt: skip
	if log_enabled(.Verbose) {
		for step in plan.steps {
			logf(.Verbose, "plan: %s", client.step_string(step, context.temp_allocator))
		}
	}
	if d.dco.mixed {
		return srv_open_tls_tun(d)
	}
	return true
}

// Second tun device of a mixed server, for the `tls` clients (read and written
// here, so it is `d.tun`): same MTU and queue length as the service's device, up,
// with the server's tunnel addresses as host addresses (`tls_tun_plan`).
srv_open_tls_tun :: proc(d: ^Srv) -> bool {
	name := d.dco.tun_name
	dev, err := tun.open({name = name, offload = OFF.tun})
	if err != .None {
		logf(.Error, "cannot open the tun device %s for the tls clients: %v (needs CAP_NET_ADMIN and /dev/net/tun)", name, err)
		return false
	}
	d.tun = dev
	d.tun_open = true
	off_note_tun(&d.off, &d.tun)
	d.tun_tx.on = d.tun.vnet
	if err := event.add_fd(&d.loop, dev.fd, {.Read}, on_srv_tun, d); err != .None {
		logf(.Error, "cannot watch the tun device: %v", err)
		return false
	}
	link, lerr := sysnet.link_get(&d.sys, tun.name(&d.tun))
	if lerr != .None {
		logf(.Error, "cannot find the tun device %s: %v", tun.name(&d.tun), lerr)
		return false
	}
	d.dco.ifindex = link.index
	// A data channel in this process drops packets between clients, also those for a
	// network behind a tls client: that network is a route on this device.
	if be := &d.dco.link.be; be.c2c_device != nil && !d.cfg.client_to_client {
		if st := be.c2c_device(be.user, d.dco.ifindex); st != 0 {
			logf(.Warn, "%s cannot watch the routes of %s for client-to-client: %s", dco_who(d.dco.kind), name, dco_why(&d.dco.link, st))
		}
	}
	q := d.cfg.txqueuelen if d.cfg.txqueuelen > 0 else SRV_TXQUEUELEN
	if qerr := sysnet.link_set_txqlen(&d.sys, d.dco.ifindex, u32(q)); qerr != .None {
		logf(.Warn, "cannot set txqueuelen %d on %s: %v", q, name, qerr)
	}
	client.netcfg_init(&d.dco.nc, &d.sys, d.dco.ifindex)
	d.dco.nc_ok = true
	plan := tls_tun_plan(d.cfg, d.tun_mtu)
	srv_rec_sync(d, &plan, d.dco.ifindex)
	if aerr := client.netcfg_apply(&d.dco.nc, &plan); aerr != .None {
		client.plan_destroy(&plan)
		logf(.Error, "cannot set up the tun device %s: %v (step %d)", name, aerr, d.dco.nc.failed_step)
		d.exit_code = .Network
		return false
	}
	srv_rec_sync(d)
	for w in d.dco.nc.warnings {
		logf(.Warn, "network step %d (%v) failed on %s: %v%s", w.step, w.why, name, w.err, " (IPv6 is off)" if w.skipped_v6 else "")
	}
	d.dco.plan = plan
	d.dco.plan_ok = true
	n := d.cfg.net
	logf(
		.Notice,
		"tun device %s (index %d) for the tls clients, %d.%d.%d.%d/32, mtu %d",
		name, d.dco.ifindex, n.server_addr[0], n.server_addr[1], n.server_addr[2], n.server_addr[3], d.tun_mtu,
	) // fmt: skip
	return true
}

// Opens one listening socket for a `local` line (or the default one).
srv_listen :: proc(d: ^Srv, l: config.Listen) -> bool {
	idx := d.n_listen
	ln := &d.listeners[idx]
	ln^ = {}
	ln.index = u8(idx)
	ln.proto = l.proto
	ln.tls = l.tls
	ln.sock = net.INVALID_SOCKET
	ln.sh = &d.shared[0 if l.proto == .Udp else 1]
	port := int(l.port)

	// The address: a host (resolved), or any address. "Any" listens on `::`
	// with IPv4 mapped; where IPv6 is off it falls back to 0.0.0.0.
	ep: net.Endpoint
	have_host := l.host != ""
	if have_host {
		pref: net.Resolve_Pref = .Any
		switch l.family {
		case .Any:
		case .V4:
			pref = .V4_Only
		case .V6:
			pref = .V6_Only
		}
		eps, rerr := net.resolve(l.host, u16(port), pref, context.temp_allocator)
		if rerr != .None || len(eps) == 0 {
			logf(.Error, "cannot resolve the local address %s", l.host)
			d.exit_code = .Config
			return false
		}
		ep = eps[0]
	}
	v6_mode := listen_v6_mode(l)
	try_v6 := !have_host && l.family != .V4
	if !have_host {
		ep.port = port
		ep.address = net.IP6_Address{} if try_v6 else net.IP4_Address{}
	}
	rcv := d.cfg.rcvbuf if d.cfg.rcvbuf > 0 else SOCKET_BUFFER
	snd := d.cfg.sndbuf if d.cfg.sndbuf > 0 else SOCKET_BUFFER

	// The kernel driver reads the data packets from this socket and passes the others up
	// as they came: no GRO (merged control packets), and no GSO either.
	kernel := d.dco.on && d.dco.kind == .Kernel
	open_one :: proc(l: config.Listen, ep: net.Endpoint, v6_mode: net.V6_Mode, rcv, snd: int, kernel: bool) -> (net.Socket, net.Error) {
		if l.proto == .Udp {
			sock, err := net.udp_open(
				net.family_of(ep),
				{recv_buffer = rcv, send_buffer = snd, reuse_addr = true, v6_mode = v6_mode, offload = (OFF.gso || OFF.gro) && !kernel, pktinfo = true},
			)
			if err != .None {
				return net.INVALID_SOCKET, err
			}
			sock = off_sock(sock)
			if berr := net.bind(sock, ep); berr != .None {
				net.close(sock)
				return net.INVALID_SOCKET, berr
			}
			return sock, .None
		}
		return net.tcp_listen(ep, 128, v6_mode)
	}
	sock, err := open_one(l, ep, v6_mode, rcv, snd, kernel)
	if err != .None && try_v6 {
		// IPv6 is off here: listen on IPv4 only.
		ep.address = net.IP4_Address{}
		sock, err = open_one(l, ep, v6_mode, rcv, snd, kernel)
	}
	if err != .None {
		logf(.Error, "cannot listen on %s port %d: %v", proto_name(l.proto, l.tls), port, err)
		d.exit_code = .System
		return false
	}
	ln.sock = sock
	ln.open = true
	ln.ep = ep
	ln.have_host = have_host
	ln.text = fmt.aprintf("%s %s", proto_name(l.proto, l.tls), endpoint_text(ep, context.temp_allocator))
	if l.proto == .Udp {
		ln.rx_per_msg = 1
		if !sock.pktinfo {
			// Replies leave from the address that the route picks. A client that used
			// another address of this host drops them.
			logf(.Warn, "%s: the kernel does not report the local address of incoming datagrams, so a client that uses a second address of this host may not receive its replies", ln.text)
		}
		d.off.udp_gso += u64(sock.gso)
		d.off.udp_gro += u64(sock.gro)
		if net.batch_init(&ln.tx_batch, sock.family, TX_BATCH) != .None {
			logf(.Error, "out of memory")
			return false
		}
		if err := event.add_fd(&d.loop, sock.fd, {.Read}, on_srv_udp, ln); err != .None {
			logf(.Error, "cannot watch the socket: %v", err)
			return false
		}
	} else if err := event.add_fd(&d.loop, sock.fd, {.Read}, on_srv_tcp_listen, ln); err != .None {
		logf(.Error, "cannot watch the socket: %v", err)
		return false
	}
	d.n_listen += 1
	logf(.Notice, "listening on %s", ln.text)
	return true
}

// Marks the descriptors as unset, before anything is opened.
srv_reset_fds :: proc(d: ^Srv) {
	d.tun.fd = -1
	for i in 0 ..< MAX_LISTEN {
		d.listeners[i].sock = net.INVALID_SOCKET
	}
}

// ------------------------------------------------------------------ teardown

srv_destroy :: proc(d: ^Srv) {
	for i in 0 ..< d.n_listen {
		ln := &d.listeners[i]
		if ln.open {
			event.remove_fd(&d.loop, ln.sock.fd)
			net.close(ln.sock)
			ln.open = false
		}
		if ln.proto == .Udp {
			net.batch_destroy(&ln.tx_batch)
		}
		delete(ln.text)
	}
	for i in 0 ..< len(d.shared) {
		if d.shared_ok[i] {
			session.server_shared_destroy(&d.shared[i])
		}
	}
	if d.srv_ok {
		server.server_destroy(&d.srv)
	}
	for c in d.conns {
		if c != nil {
			conn_free(d, c)
		}
	}
	srv_workers_stop(d)
	srv_pw_stop(d)
	srv_web_stop(d)
	srv_dco_destroy(d)
	if d.tls_ctx_ok {
		ossl.tls_ctx_destroy(&d.tls_ctx)
	}
	delete(d.conns)
	delete(d.free_slots)
	delete(d.dirty)
	delete(d.sid_map)
	delete(d.rx_buf)
	delete(d.tun_stage)
	delete(d.tun_tx.arena)
	net.batch_destroy(&d.rx_batch)
	srv_rec_end(d)
	if d.plan_ok {
		client.plan_destroy(&d.plan)
	}
	if d.nc_ok {
		client.netcfg_destroy(&d.nc)
	}
	if d.tun_open {
		tun.close(&d.tun)
	}
	if d.sys_ok {
		sysnet.close(&d.sys)
	}
	event.destroy(&d.loop)
}

// Runs until the daemon has stopped. The exit code is `d.exit_code`.
srv_run :: proc(d: ^Srv) {
	for !d.exit {
		if _, err := event.wait(&d.loop); err != .None {
			logf(.Error, "event loop failed: %v", err)
			if d.exit_code == .Ok {
				d.exit_code = .System
			}
			B.stop_reason, B.stop_detail = "error", "the event loop failed"
			srv_finish(d)
			break
		}
		srv_pw_drain(d)
		free_all(context.temp_allocator)
	}
}

// The first stop signal: tell every client, then wait for the goodbyes. A
// second one finishes at once.
srv_begin_stop :: proc(d: ^Srv) {
	if d.finished {
		return
	}
	if d.stopping {
		logf(.Notice, "second stop signal received, so exiting immediately")
		srv_finish(d)
		return
	}
	d.stopping = true
	if B.stop_reason == "" {
		B.stop_reason = "signal"
	}
	kind := shutdown_close_kind(d.cfg.link.explicit_exit_notify)
	logf(.Notice, "stop signal received, closing %d client(s) (%v)", d.n_conns, kind)
	// No new TCP clients. (UDP first packets are dropped in the demultiplexer;
	// the sockets stay open for the acknowledgements of the goodbyes.)
	for i in 0 ..< d.n_listen {
		ln := &d.listeners[i]
		if ln.open && ln.proto == .Tcp {
			event.remove_fd(&d.loop, ln.sock.fd)
		}
	}
	for slot in 0 ..< len(d.conns) {
		c := d.conns[slot]
		if c != nil && !c.closing {
			conn_close(d, c, kind, .Shutdown)
		}
	}
	srv_flush_all(d)
	if d.n_conns == 0 {
		srv_finish(d)
		return
	}
	stimer_set(&d.loop, &d.t_stop, now_srv(d) + (d.stop_wait.? or_else SHUTDOWN_WAIT), on_srv_stop_timer, d)
}

on_srv_stop_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Srv)(user)
	d.t_stop.on = false
	if d.n_conns > 0 {
		logf(.Notice, "%d client(s) did not confirm the exit notice in time", d.n_conns)
	}
	srv_finish(d)
}

// Ends the run: sessions are dropped, the pool file is written, routes and
// addresses are removed, sockets are closed. The loop then leaves.
srv_finish :: proc(d: ^Srv) {
	if d.finished {
		return
	}
	d.finished = true
	stimer_clear(&d.loop, &d.t_stop)
	stimer_clear(&d.loop, &d.t_persist)
	stimer_clear(&d.loop, &d.dco.t_stats)
	stimer_clear(&d.loop, &d.dco.t_tun)
	stimer_clear(&d.loop, &d.dco.t_gone)
	stimer_clear(&d.loop, &B.t_stats)
	stimer_clear(&d.loop, &d.pw.t_poll)
	for i in 0 ..< 2 {
		stimer_clear(&d.loop, &d.t_cookie[i])
	}
	// Whatever is still open goes now, after one last look at its output.
	for slot in 0 ..< len(d.conns) {
		if d.conns[slot] != nil {
			conn_flush_ctl(d, d.conns[slot])
		}
		if c := d.conns[slot]; c != nil {
			conn_release(d, c)
		}
	}
	persist_save(d, "exit")
	if d.nc_ok {
		if failures := client.netcfg_teardown(&d.nc); failures > 0 {
			logf(.Warn, "%d network changes could not be undone", failures)
		}
	}
	if d.dco.nc_ok {
		// The second device of a mixed server: its addresses go, and with the device (closed
		// below) the host routes of the tls clients.
		if failures := client.netcfg_teardown(&d.dco.nc); failures > 0 {
			logf(.Warn, "%d network changes on %s could not be undone", failures, d.dco.tun_name)
		}
	}
	if d.tun_open {
		event.remove_fd(&d.loop, d.tun.fd)
		tun.close(&d.tun)
		d.tun_open = false
	}
	srv_dco_refresh_all(d)
	srv_dco_detach(d)
	for i in 0 ..< d.n_listen {
		ln := &d.listeners[i]
		if ln.open {
			event.remove_fd(&d.loop, ln.sock.fd)
			net.close(ln.sock)
			ln.open = false
		}
	}
	srv_log_status(d, .Notice, "exit")
	if d.dco.link.up && d.dco.link.dev {
		dco_close_device(&d.dco.link)
	}
	d.exit = true
}

// ------------------------------------------------------------ cookie, pool file

cookie_timer_arm :: proc(d: ^Srv, i: int) {
	at := session.server_cookie_next_rotation(&d.shared[i])
	stimer_set(&d.loop, &d.t_cookie[i], at, on_srv_cookie_timer, d)
}

on_srv_cookie_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Srv)(user)
	now := now_srv(d)
	for i in 0 ..< 2 {
		if !d.shared_ok[i] || d.finished {
			continue
		}
		d.t_cookie[i].on = false
		if session.server_cookie_rotate_due(&d.shared[i], now) {
			if err := session.server_cookie_rotate(&d.shared[i], now); err != .None {
				logf(.Warn, "cannot rotate the cookie key: %v", err)
			}
		}
		cookie_timer_arm(d, i)
	}
}

persist_load :: proc(d: ^Srv) {
	data, err := os.read_entire_file(d.persist_file, context.allocator)
	if err != nil {
		logf(.Info, "pool file %s: could not be read (%v), so the pool starts empty", d.persist_file, err)
		return
	}
	defer delete(data)
	rep := server.pools_persist_load(&d.srv.pools, string(data), now_srv(d))
	defer server.persist_report_destroy(&rep)
	logf(.Notice, "pool file %s: %d address(es) remembered, %d line(s) skipped", d.persist_file, rep.loaded, rep.skipped_total)
	for s in rep.skipped {
		logf(.Info, "pool file line %d skipped: %v", s.line, s.reason)
	}
	// What was loaded is what the file holds.
	d.srv.pools.persist_dirty = false
}

// Writes the pool file if something changed (or `force`). A temporary file is
// written and renamed, so a crash never leaves half a file.
persist_save :: proc(d: ^Srv, why: string) {
	if d.persist_file == "" || d.persist_secs == 0 || !d.srv_ok {
		return
	}
	if !server.pools_persist_dirty(&d.srv.pools) {
		return
	}
	text := server.pools_persist_save(&d.srv.pools)
	defer delete(text)
	tmp := fmt.tprintf("%s.tmp", d.persist_file)
	if err := os.write_entire_file(tmp, transmute([]u8)text); err != nil {
		logf(.Warn, "cannot write the pool file %s: %v", tmp, err)
		d.srv.pools.persist_dirty = true
		return
	}
	if err := os.rename(tmp, d.persist_file); err != nil {
		logf(.Warn, "cannot replace the pool file %s: %v", d.persist_file, err)
		d.srv.pools.persist_dirty = true
		return
	}
	logf(.Debug, "pool file written (%s)", why)
}

persist_arm :: proc(d: ^Srv) {
	if d.persist_file == "" || d.persist_secs == 0 {
		return
	}
	secs := max(d.persist_secs, PERSIST_MIN_SECONDS)
	stimer_set(&d.loop, &d.t_persist, now_srv(d) + time.Duration(secs) * time.Second, on_srv_persist_timer, d)
}

on_srv_persist_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Srv)(user)
	d.t_persist.on = false
	if d.finished {
		return
	}
	persist_save(d, "timer")
	persist_arm(d)
}

// ---------------------------------------------------------------- signals

on_srv_signal :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := (^Srv)(user)
	for _ in 0 ..< 16 {
		sig := sig_read(fd)
		if sig == 0 {
			return
		}
		srv_handle_signal(d, sig)
	}
}

srv_handle_signal :: proc(d: ^Srv, sig: int) {
	if d.finished {
		return
	}
	switch sig {
	case SIGINT, SIGTERM:
		srv_begin_stop(d)
	case SIGHUP:
		if d.stopping {
			return
		}
		srv_reload(d)
	case SIGUSR2:
		srv_log_status(d, .Status, "status")
	case SIGUSR1:
		logf(.Notice, "SIGUSR1 is ignored by the server (use SIGHUP to reload the peers file, or SIGUSR2 to print the status)")
	}
}

// ----------------------------------------------------------------- the entry

// Runs the server for a parsed config. Returns the exit code. `name` is the bus
// instance name (owned by the bus from here on). `args` is the command line,
// read again for `daemon.reload`.
run_server :: proc(cfgw: ^config.Config, settings: ^Server_Settings, name: string, args: []string) -> Exit {
	d := &SV
	defer dco_launch_stop()
	// Signals first, so a stop signal during start-up is not lost.
	sfd, sok := sig_open()
	if !sok {
		fmt.eprintln("noirvpn: cannot set up signal handling")
		return .System
	}
	d.sig_fd = sfd
	d.sig_ready = true
	if settings.key_wait {
		slots: [2]Key_Slot
		ok := keys_unlock_prompt(server_key_slots(settings, &slots), sfd)
		server_transport_follow(settings)
		if !ok {
			return .Config
		}
	}
	d.set = settings^
	settings^ = {}
	// The config outlives the daemon: `run_server` returns before it is freed.
	d.cfg = (^config.Server_Config)(rawptr(&cfgw.server))
	d.inst_name = name
	ok := srv_init(d)
	if ok && !bus_start(&d.loop, cfgw, .Server, name, args, on_srv_bus) {
		d.exit_code = .System
		ok = false
	}
	if !ok {
		code := d.exit_code if d.exit_code != .Ok else Exit.System
		srv_close_all_quiet(d)
		bus_stop_quiet()
		srv_destroy(d)
		settings^ = d.set
		d.set = {}
		return code
	}
	write_pidfile(cfgw.server.writepid)
	srv_dco_attach_early(d)
	if !priv_apply() {
		srv_close_all_quiet(d)
		remove_pidfile(cfgw.server.writepid)
		bus_stop_quiet()
		srv_destroy(d)
		settings^ = d.set
		d.set = {}
		return .System
	}
	logf(
		.Notice,
		"%s starting (pid %d), %d listener(s), max-clients %d, verb %d, datapath %s",
		VERSION, os.get_pid(), d.n_listen, cfgw.server.max_clients, cfgw.server.verb, dco_start_text(d.dco.kind, d.dco.on),
	) // fmt: skip
	if d.set.password_only {
		logf(.Notice, "clients are checked by password only, because the server does not ask for a client certificate")
	}
	bus_publish_start()
	srv_stats_arm(d)
	srv_pw_arm(d)
	srv_run(d)
	code := d.exit_code
	remove_pidfile(cfgw.server.writepid)
	bus_stop()
	srv_destroy(d)
	settings^ = d.set
	d.set = {}
	return code
}

// After a failed start: nothing is open that needs a goodbye.
srv_close_all_quiet :: proc(d: ^Srv) {
	if d.nc_ok {
		client.netcfg_teardown(&d.nc)
	}
}

// The server side of `run`: the config is for a server. Reads the key files and
// the peers file, then either reports (`--check-config`) or starts.
run_server_role :: proc(cfg: ^config.Config, cli: Cli) -> Exit {
	check := cli.mode == .Check
	settings: Server_Settings
	defer server_settings_destroy(&settings)
	ask := Key_Ask.Never
	if tty_is(0) {
		ask = .Check if check else .Later
	}
	_ = server_settings_load(&settings, cfg, ask)
	server_settings_check_peers(&settings, &cfg.server)
	server_settings_check_passwords(&settings, &cfg.server)
	settings_ok := len(settings.errors) == 0
	if check {
		report := config.check_config(cfg)
		defer config.report_destroy(&report)
		fmt.print(config.format_report(&report))
		fmt.print(format_server_notes(&settings))
		if !config.report_ok(&report) || !settings_ok {
			return .Config
		}
		name := bus_instance_name(cli.name, cfg)
		defer delete(name)
		if !bus_check(&cfg.server.common, .Server, name) {
			return .Config
		}
		fmt.printfln("daemon: server, %d listener(s), %d key(s) in the peers file", len(cfg.server.listens), settings.peer_count)
		if cfg.server.peer_passwords != "" {
			fmt.printfln("daemon: %d user(s) in the password file", settings.user_count)
		}
		if settings.password_only {
			fmt.println("daemon: clients are checked by password only, because the server does not ask for a client certificate")
		}
		if txt := priv_check_text(cfg.server.user, cfg.server.group); txt != "" {
			fmt.println(txt)
		}
		return .Ok
	}
	log_set_verb(cfg.server.verb)
	for dg in cfg.diags {
		logf(.Warn, "config: %s", strings.trim_space(config.format_diagnostics({dg}, context.temp_allocator)))
	}
	if !settings_ok {
		for e in settings.errors {
			eprint("noirvpn: %s", e)
		}
		return .Config
	}
	for w in settings.warnings {
		logf(.Warn, "%s", w)
	}
	crl_log_start(&settings.crl)
	aead_start()
	// The bus settings are a config matter (exit 1) whatever the privileges are.
	name := bus_instance_name(cli.name, cfg)
	if !bus_check(&cfg.server.common, .Server, name) {
		delete(name)
		return .Config
	}
	if !priv_prepare(cfg.server.user, cfg.server.group) {
		delete(name)
		return .Config
	}
	if !has_net_admin() {
		delete(name)
		eprint("noirvpn: %s", PRIV_TEXT)
		return .System
	}
	return run_server(cfg, &settings, name, cli.args)
}

// Record of the server: its devices and the routes of its plans. With `pending`,
// also the routes of that plan before it runs on `ifindex`. Each client's routes
// are on the devices, which the record holds.
srv_rec_sync :: proc(d: ^Srv, pending: ^client.Plan = nil, ifindex: u32 = 0) {
	f := &d.rec
	if !f.ok {
		return
	}
	client.record_clear(&f.rec)
	if d.ifindex != 0 {
		client.record_add_dev(&f.rec, d.ifindex, srv_tun_name(d))
	}
	if d.nc_ok {
		client.record_add_netcfg(&f.rec, &d.nc)
	}
	if d.dco.nc_ok {
		client.record_add_dev(&f.rec, d.dco.ifindex, d.dco.tun_name)
		client.record_add_netcfg(&f.rec, &d.dco.nc)
	}
	if pending != nil {
		client.record_add_plan(&f.rec, pending, &d.sys, ifindex)
	}
	rec_save(f)
}

// After the teardown: the routes that are still applied stay in the record.
srv_rec_end :: proc(d: ^Srv) {
	f := &d.rec
	if !f.ok {
		return
	}
	client.record_clear(&f.rec)
	if d.nc_ok {
		client.record_add_netcfg(&f.rec, &d.nc)
	}
	if d.dco.nc_ok {
		client.record_add_netcfg(&f.rec, &d.dco.nc)
	}
	rec_save(f)
	rec_end(f)
}
