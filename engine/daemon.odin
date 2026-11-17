// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import cnet "core:net"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/sysnet"
import "noir:platform/tlslink"
import "noir:platform/tun"
import "noir:proto/config"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/session"

// Client daemon: one thread, one event loop; the connection state machine. Packet
// loops: datapath.odin.
//
//	policy_next -> resolve -> start_attempt -> (TCP connect) -> session
//	  Up event  -> tun, addresses, routes, DNS, policy_outcome(.Connected)
//	  Failed / Closed event -> finish_connection -> policy_outcome -> next attempt
//
// Handlers never call each other across a connection: a finished connection arms
// the policy timer for "now", so the next attempt starts from the event loop.

RX_BATCH :: 32
// Datagrams in one `sendmmsg`: the longest burst on the wire. UDP GSO does not
// change it (one GSO entry holds at most this many datagrams).
TX_BATCH :: 32
RX_SLOT :: 2304
TCP_TX_SIZE :: 256 * 1024
TCP_TX_RESERVE :: 64 * 1024
TCP_RX_SIZE :: 64 * 1024
// Packets read from the tun per wake-up (datagrams, after a large packet is
// cut). Checked between reads, so one more large packet may come on top.
TUN_BURST :: 64
// How long a graceful close may take before we give up on it.
CLOSE_WAIT :: 6 * time.Second
// Tun MTU when neither the config nor the server sets one.
DEFAULT_TUN_MTU :: 1400
SOCKET_BUFFER :: 1024 * 1024

Conn_State :: enum u8 {
	Idle, // no connection (waiting, or between attempts)
	Tcp_Connecting,
	Proxy_Connecting, // `http-proxy`: the CONNECT request and the reply (between the connect and the outer TLS or the session)
	Tls_Handshaking, // `tls` remotes: the outer TLS handshake (between the connect and the session)
	Ws_Upgrading, // `tls-transport-ws`: the HTTP upgrade request and the reply (between the outer TLS and the session)
	Active, // a session runs: handshake, up, closing
}

Timer :: struct {
	id: event.Timer_Id,
	on: bool,
}

Stats :: struct {
	attempts:         u64,
	connects:         u64, // times the tunnel came up
	tun_read_pkts:      u64, // read from the tun device
	tun_read_bytes:     u64,
	tun_write_pkts:      u64, // written to the tun device
	sent_pkts: u64, // tun packets sealed and handed to the socket
	tun_write_bytes:     u64,
	drop_ring:        u64, // tun packets dropped, the ring was full (oldest first)
	drop_seal:        u64, // tun packets we could not seal
	drop_not_up:      u64, // tun packets read while no tunnel was up
	drop_tun_write:   u64, // packets from the server that the tun device refused
	drop_oversize:    u64, // datagrams larger than the receive slot
	drop_rx_not_up:   u64, // tunnel packets that arrived with no tun device
	drop_source:      u64, // datagrams from another address than the server's (unconnected socket)
	drop_block6_tx:   u64, // IPv6 packets read from the tun device and dropped (block-ipv6)
	drop_block6_rx:   u64, // IPv6 packets from the tunnel dropped before the tun device (block-ipv6)
	tun_read_errors:  u64,
	sock_send_errors: u64,
	sock_recv_errors: u64,
	sock_blocked:     u64, // times a send stopped because the socket was full
}

// The `client.state` detail when the server refuses the saved auth-token: the
// daemon logs in again at once (a web sign-in asks the user again).
TOKEN_REFUSED :: "the server ended the saved login; signing in again"

Daemon :: struct {
	cfgw:         ^config.Config,
	cfg:          ^config.Client_Config,
	set:          Settings,
	creds:        Creds,
	exit_code:    Exit,
	exit:         bool, // leave the event loop
	shutting:     bool, // `shutdown` has run
	loop:         event.Loop,
	policy:       client.Policy,
	// What the host gives (host.odin).
	host:         Host,
	// Set when the engine is a guest of another program (guest.odin); nil for
	// the daemon.
	guest:        ^Guest,
	// The data object of the event that is built (`ev_begin`).
	ev_w:         bus.Writer,
	ev_w_ok:      bool,
	// Why the run stops, for the host (the bus says it in `daemon.stop`).
	stop_reason:  string,
	stop_detail:  string,
	// `stats.tick`: the interval in seconds (0: none) and its timer.
	stats_secs:   int,
	t_stats:      Timer,
	// The process runs as a user other than root: the DNS settings of the
	// system are not written. The host sets it after the privilege drop.
	privs_dropped: bool,
	t_policy:     Timer,
	t_session:    Timer,
	t_attempt:    Timer,
	t_close:      Timer,
	t_limit:      Timer,
	t_clear:      Timer, // a service: the profile goes after the connection has ended (service.odin)
	started:      time.Duration,

	// Service mode (`client-service`, service.odin). `cfgw` and `cfg` are the base config
	// while no profile is loaded, and the profile after `profile.set`.
	service:         bool,
	prof:            config.User_Profile,
	prof_loaded:     bool,
	prof_label:      string, // owned
	prof_sha:        string, // owned: the hash of the profile text
	prof_sso:        bool, // `profile.set` asked for web sign-in (`sso`)
	owner:           Maybe(u32), // the uid that set the profile
	owner_sid:       bus.Sid, // Windows: the user SID that set the profile
	clear_pending:   bool, // `profile.clear` came while the connection closed: the profile goes at its end
	fatal_code:      Exit, // the code of the last `fatal`, for the reason (a service does not exit with it)
	stop_hint:       string, // the reason of the next stop of the policy, if the caller knows it better

	// The control bus.
	hold:            bool, // `disconnect`: no connection until `connect`
	creds_wait:      bool, // waiting for `auth.supply`
	creds_announced: bool, // `client.auth_needed` was published for this wait
	creds_key:       bool, // a guest or a service profile: the wait is for the passphrase of the key
	creds_reason:    string,
	bus_state:       string, // the last state published (client.state)
	bus_reason:      string, // why, for the next move to waiting or stopped
	state_reason:    string, // the reason that `status` shows for `waiting` and `stopped`
	detail_next:     string, // a detail for the next move to waiting or stopped (a static text)
	state_detail:    string, // the detail that `status` shows with `state_reason`
	web:             Web_Wait, // the web sign-in that waits (webauth.odin)
	sso_warned:      bool, // the note on `setenv IV_SSO` is in the log
	close_wait:      Maybe(time.Duration), // how long the exit notice may take (unset: CLOSE_WAIT)
	up_wall:         time.Time,
	push_lines:      [dynamic]string, // the pushed options of this connection
	push_bytes:      int,

	// The connection.
	state:        Conn_State,
	conn_idx:     int,
	endpoint:     cnet.Endpoint,
	proto:        config.Proto,
	// `http-proxy` (proxy.odin): this attempt goes through the proxy; `endpoint` is the proxy's.
	via_proxy:    bool,
	px:           Proxy_State,
	proxy_basic:  []bool, // by connection: the proxy asked for Basic (`auto`), so the next try sends it
	sock:         net.Socket,
	sock_open:    bool,
	// UDP on the DCO service: the socket is not connected, and this is the address of each send.
	sock_to:      Maybe(cnet.Endpoint),
	want_write:   bool, // the socket is watched for writing
	blocked:      bool, // a send stopped: the socket or the TCP buffer is full
	tcp:          net.TCP_Conn,
	tcp_tx:       []u8,
	tcp_rx:       []u8,
	// The IPv4 TCP MSS to clamp SYNs to (mssfix.odin); 0: no clamp. Set at the tunnel-up.
	mss4:         int,
	// `block-ipv6` is in force for this connection: set in the config, or pushed. Set at the tunnel-up.
	block6:       bool,
	// The `tls` transport (tls_transport.odin): the TCP stream runs inside an outer TLS stream.
	tls:          bool, // this attempt is a tls link
	tls_ctx:      ossl.Tls_Ctx, // the settings of the outer TLS, created at start if some remote is tls
	tls_ctx_ok:   bool,
	olink:        tlslink.Link,
	olink_ok:     bool, // `olink` holds a session
	olink_out:    []u8, // TLS bytes that wait for the socket
	// `tls-transport-ws` (ws_client.odin): the stream runs in WebSocket frames inside the outer TLS stream.
	ws:           bool, // this attempt uses a WebSocket
	wsc:          Ws_Client,
	outer:        Outer_Check,
	s:            session.Session,
	s_ok:         bool,
	wk:           ^Wk_Pool, // crypto workers (`workers N`), nil: the data path runs here
	wkr:          ^Wk_Worker, // the worker that has this session's data channel
	dco:          Dco_Client, // the data channel on a DCO service (dco.odin)
	rx_jobs:      [dynamic]^Wk_Job, // received packets that wait for their worker, in order
	rx_copied:    int, // bytes of the copy area of `rx_buf` in use (see `client_take`)
	in_pump:      bool,
	up:           bool, // the tunnel is up (Up event handled)
	up_at:        time.Duration,
	close_reason: Close_Reason,
	end:          End,
	pending:      Pending,
	used_token:   bool,
	rekey_count:  u64,
	filter_ignored: int,

	// The tunnel and what we changed in the system.
	sys:          sysnet.Conn,
	sys_ok:       bool,
	tun:          tun.Device,
	tun_open:     bool,
	ifindex:      u32,
	nc:           client.Netcfg,
	nc_ok:        bool,
	have_state:   bool, // `sys_state` is valid
	sys_state:    client.System_State,
	applied:      bool, // routes and addresses of `plan` are in place
	applied_to:   cnet.Address, // the server the applied plan is for
	plan:         client.Plan,
	plan_ok:      bool,
	dns:          sysnet.DNS,
	dns_env:      sysnet.DNS_Env,
	// The clean-up record (records.odin) and the instance name it holds.
	rec:          client.Record_File,
	inst_name:    string,
	persist:      bool, // persist-tun in force
	persist_cfg:  bool, // persist-tun in the config
	// A user profile: the name of the device of this connection (devname.odin).
	dev_name_buf: [sysnet.IFNAMSIZ]u8,
	dev_name:     string,

	// Limits (session-timeout, inactive).
	inactive_pkts:  u64,
	inactive_bytes: u64,
	inactive_at:    time.Duration,

	// Packet buffers: nothing is allocated per packet.
	ring:         Ring,
	rx_buf:       []u8,
	rx_msgs:      int, // messages per receive call (slots of `rx_buf`)
	rx_slot:      int, // bytes of each slot
	rx_per_msg:   int, // datagrams per message the last read gave (UDP GRO), 0 before the first
	rx_batch:     net.Batch,
	tx_batch:     net.Batch,
	tun_stage:    []u8, // one read from a tun with the virtio header
	tun_tx:       Tun_Tx, // joins received segments for the tun
	off:          Offload_Stats,
	link:         [session.LINK_BUF_SIZE]u8,
	drain:        [4096]u8,
	stats:        Stats,
}

// ----------------------------------------------------------------- timers

timer_set :: proc(d: ^Daemon, t: ^Timer, at: time.Duration, handler: event.Timer_Handler) {
	if t.on && event.timer_reset_at(&d.loop, t.id, at) {
		return
	}
	id, err := event.timer_add_at(&d.loop, at, handler, d)
	if err != .None {
		t.on = false
		logf(.Error, "cannot set a timer: %v", err)
		return
	}
	t.id = id
	t.on = true
}

timer_clear :: proc(d: ^Daemon, t: ^Timer) {
	if t.on {
		event.timer_cancel(&d.loop, t.id)
		t.on = false
	}
}

now_of :: proc(d: ^Daemon) -> time.Duration {
	return event.loop_time(&d.loop)
}

// ------------------------------------------------------------------- setup

daemon_init :: proc(d: ^Daemon, cfgw: ^config.Config) -> (ok: bool) {
	d.cfgw = (^config.Config)(rawptr(cfgw))
	d.cfg = (^config.Client_Config)(rawptr(&cfgw.client))
	d.service = cfgw.client.service
	d.sock = net.INVALID_SOCKET
	d.tun.fd = -1
	d.stats_secs = cfgw.client.stats_interval
	bus.writer_init(&d.ev_w)
	d.ev_w_ok = true

	if err := event.init(&d.loop); err != .None {
		logf(.Error, "cannot start the event loop: %v", err)
		return false
	}
	d.started = event.now()

	if d.host.loop_ready != nil && !d.host.loop_ready(d.host.user, &d.loop) {
		return false
	}

	// A guest has no system network of its own: no netlink, no DCO, no records.
	if d.guest == nil {
		conn, serr := sysnet.open()
		if serr != .None {
			logf(.Error, "cannot open a netlink socket: %v", serr)
			return false
		}
		d.sys = conn
		d.sys_ok = true
		d.dns_env = sysnet.dns_env_default()
		if !dco_client_init(d) {
			return false
		}

		// What stopped daemons left behind: only their own records, never what a
		// running one holds.
		ifname := tun_name_of(d.cfg.dev)
		if ifname == "" {
			ifname = "tun0"
		}
		if d.service {
			// The name of a tunnel comes with the profile; `dev_name_choose` cleans up for it.
			ifname = "noir0"
		}
		if d.host.prepare_state != nil {
			d.host.prepare_state(d.host.user)
		}
		rec_start(&d.rec, &d.sys, d.dns_env, d.inst_name, .Client, ifname)
	}

	if !ring_init(&d.ring, RING_SLOTS) {
		logf(.Error, "out of memory")
		return false
	}
	d.rx_msgs, d.rx_slot = off_rx_layout()
	d.rx_buf = make([]u8, d.rx_msgs * d.rx_slot)
	d.tcp_tx = make([]u8, TCP_TX_SIZE)
	d.tcp_rx = make([]u8, TCP_RX_SIZE)
	if OFF.tun {
		d.tun_stage = make([]u8, TUN_BUF_SIZE)
		d.tun_tx.arena = make([]u8, TUN_TX_ARENA)
	}
	if net.batch_init(&d.rx_batch, .V4, d.rx_msgs) != .None || net.batch_init(&d.tx_batch, .V4, TX_BATCH) != .None {
		logf(.Error, "out of memory")
		return false
	}
	for i in 0 ..< d.rx_msgs {
		net.batch_set_recv(&d.rx_batch, i, d.rx_buf[i * d.rx_slot:][:d.rx_slot])
	}
	if d.cfg.workers > 0 {
		d.wk = pool_start(d.cfg.workers)
		if d.wk == nil {
			logf(.Error, "cannot start the crypto workers")
			return false
		}
		d.rx_jobs = make([dynamic]^Wk_Job, 0, WK_LANE_JOBS)
		logf(.Info, "crypto workers: %d", d.cfg.workers)
	}

	if d.service {
		// No profile yet: the daemon waits in `stopped` for `profile.set`.
		d.hold = true
		d.state_reason = "no_profile"
		return true
	}
	return profile_attach(d)
}

// Sets up what depends on the profile part of the config (`d.cfg`, `d.set`):
// persist-tun flag, proxy memory, outer TLS context, policy. False after it logs
// the problem. `profile_detach` is the counterpart; safe after a failed attach.
profile_attach :: proc(d: ^Daemon) -> bool {
	d.persist_cfg = d.cfg.persist_tun || d.guest != nil // a guest keeps the tunnel of the system
	d.persist = d.persist_cfg
	d.proxy_basic = make([]bool, len(d.cfg.connections))
	for c in d.cfg.connections {
		if c.tls {
			err: ossl.Error
			d.tls_ctx, err = outer_client_ctx(d.set.groups, d.cfg.tls_transport_hello)
			if err != .None {
				logf(.Error, "cannot set up the outer TLS: %v", err)
				return false
			}
			if d.cfg.tls_transport_hello == .Chrome {
				logf(.Info, "%s", ossl.tls_hello_note())
			}
			d.tls_ctx_ok = true
			d.olink_out = make([]u8, tlslink.OUT_BUF_SIZE)
			break
		}
	}
	seed := u64(time.now()._nsec)
	if err := client.policy_init(&d.policy, d.cfg, seed); err != nil {
		logf(.Error, "out of memory")
		return false
	}
	return true
}

// Releases what `profile_attach` created. The tunnel state must be gone already
// (`teardown_network`).
profile_detach :: proc(d: ^Daemon) {
	client.policy_destroy(&d.policy)
	delete(d.proxy_basic)
	d.proxy_basic = nil
	proxy_state_clear(&d.px)
	delete(d.px.rx)
	d.px.rx = nil
	if d.tls_ctx_ok {
		ossl.tls_ctx_destroy(&d.tls_ctx)
		delete(d.olink_out)
		d.olink_out = nil
		ws_client_destroy(d)
		d.tls_ctx_ok = false
	}
	d.persist_cfg, d.persist = false, false
}

daemon_destroy :: proc(d: ^Daemon) {
	profile_detach(d)
	if d.service {
		service_unload(d)
	}
	client_clear_push(d)
	delete(d.push_lines)
	client_rec_end(d)
	if d.sys_ok {
		sysnet.close(&d.sys)
	}
	cred_wipe(&d.creds)
	dco_client_destroy(d)
	if d.ev_w_ok {
		bus.writer_destroy(&d.ev_w)
		d.ev_w_ok = false
	}
	pool_stop(d.wk)
	d.wk = nil
	delete(d.rx_jobs)
	guest_destroy(d)
	ring_destroy(&d.ring)
	delete(d.rx_buf)
	delete(d.tun_stage)
	delete(d.tun_tx.arena)
	delete(d.tcp_tx)
	delete(d.tcp_rx)
	net.batch_destroy(&d.rx_batch)
	net.batch_destroy(&d.tx_batch)
	event.destroy(&d.loop)
}

// Runs until the daemon has shut down. The exit code is `d.exit_code`, and
// the proc returns it.
daemon_run :: proc(d: ^Daemon) -> Exit {
	schedule(d)
	for !d.exit {
		if _, err := event.wait(&d.loop); err != .None {
			logf(.Error, "event loop failed: %v", err)
			if d.exit_code == .Ok {
				d.exit_code = .System
			}
			shutdown(d)
			break
		}
		free_all(context.temp_allocator)
	}
	return d.exit_code
}

// -------------------------------------------------------------- the policy

on_policy_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.t_policy.on = false
	schedule(d)
}

// Asks the policy what to do next and does it.
schedule :: proc(d: ^Daemon) {
	for !d.exit && d.state == .Idle && !d.hold {
		if d.guest != nil && d.guest.paused {
			// The network is `none`: no new attempt, and the back-off waits.
			return
		}
		event.update_time(&d.loop)
		now := now_of(d)
		a := client.policy_next(&d.policy, now)
		switch a.kind {
		case .Stop:
			if d.service {
				logf(.Notice, "stopping: %s", stop_text(a.stop))
				reason := d.stop_hint if d.stop_hint != "" else service_stop_reason(a.stop, d.bus_reason)
				service_stop(d, reason)
				return
			}
			d.exit_code = stop_exit(a.stop) if d.exit_code == .Ok else d.exit_code
			logf(.Notice if d.exit_code == .Ok else .Error, "stopping: %s", stop_text(a.stop))
			if d.bus_reason == "" {
				d.bus_reason = stop_state_reason(a.stop)
			}
			if d.stop_reason == "" {
				d.stop_reason = "signal" if d.exit_code == .Ok else "error"
				d.stop_detail = stop_text(a.stop)
			}
			shutdown(d)
			return
		case .Wait:
			secs := f64(a.wake_at - now) / f64(time.Second)
			logf(.Notice, "waiting %.0f s before trying again", secs)
			timer_set(d, &d.t_policy, a.wake_at, on_policy_timer)
			return
		case .Resolve:
			if d.guest != nil {
				// The lookup runs on the helper thread; the result comes back as an event.
				guest_resolve(d, a)
				return
			}
			addrs, ok := client.resolve_action(a)
			event.update_time(&d.loop)
			kept := client.policy_resolved(&d.policy, addrs, ok, now_of(d))
			if kept {
				logf(.Warn, "cannot resolve %s, so the addresses from the last lookup will be used", a.host)
			} else if !ok {
				logf(.Warn, "cannot resolve %s", a.host)
			}
			delete(addrs)
		case .Connect:
			if d.creds_wait {
				// The login needs credentials from the bus; the policy asks again after `auth.supply`.
				if !d.creds_announced {
					client_publish_auth_needed(d, d.creds_reason if d.creds_reason != "" else "no_credentials", true)
				}
				return
			}
			start_attempt(d, a)
			return
		}
	}
}

stop_text :: proc(r: client.Stop_Reason) -> string {
	switch r {
	case .None:
		return "done"
	case .Auth_Failed:
		return "the server refused the login"
	case .Halted:
		return "the server told us to halt"
	case .Retries_Exhausted:
		return "every remote was tried connect-retry-max times without success"
	case .Resolve_Failed:
		return "the resolv-retry time ran out"
	case .Inactive:
		return "the inactive time limit was reached"
	case .Session_Timeout:
		return "the session-timeout was reached"
	case .Local_Stop:
		return "a stop was requested"
	case .No_Remote:
		return "there is no remote to connect to"
	}
	return ""
}

// ------------------------------------------------------------- an attempt

start_attempt :: proc(d: ^Daemon, a: client.Action) {
	if !dev_name_choose(d) {
		return
	}
	conn := &d.cfg.connections[a.entry]
	d.conn_idx = a.entry
	d.endpoint = a.endpoint
	d.proto = conn.proto
	d.tls = conn.tls
	d.via_proxy = a.via_proxy
	d.ws = conn.tls && d.cfg.tls.transport_ws != ""
	proxy_attempt_reset(d)
	ws_attempt_reset(d)
	d.outer = .Pending if conn.tls else .None
	d.stats.attempts += 1
	d.end = {}
	d.pending = {}
	d.close_reason = .None
	d.up = false
	d.sock_to = nil
	client_clear_push(d)
	if a.via_proxy {
		proxy_notice(d, a.endpoint, conn)
	} else {
		logf(.Notice, "connecting to [%s]:%d (%s)", cnet.address_to_string(a.endpoint.address, context.temp_allocator), a.endpoint.port, proto_name(conn.proto, conn.tls))
	}

	scfg := build_session_config(d, conn)
	// The data path of the attempt is chosen now: the session config depends on it.
	use_dco := dco_for_attempt(d, conn.proto, conn.tls)
	d.dco.path = dco_path_of(d.dco.kind) if use_dco else .Userspace
	scfg.ext_data = use_dco
	scfg.ext_epoch = use_dco && dco_epoch_ok(&d.dco.link)
	if err := session.session_init(&d.s, &scfg); err != .None {
		text := "check the config"
		#partial switch err {
		case .Bad_Key:
			text = "cannot use the certificate or key (does the key belong to the certificate?)"
		case .Bad_Config:
			text = "some settings cannot be used (wrap key, pins, ciphers)"
		case .Credentials_Too_Long:
			text = "the user name or password is too long"
		}
		fatal(d, .Config, "cannot set up the session: %s", text)
		return
	}
	d.s_ok = true
	d.dco.active = false
	if !use_dco {
		// The service may still hold the device of an earlier attempt.
		dco_client_release_device(d)
	}
	if use_dco {
		dco_attempt_begin(d)
	} else if d.wk != nil {
		w, ok := pool_attach(d.wk, &d.s, d, client_take, client_barrier)
		if !ok {
			fatal(d, .System, "cannot hand the data channel to a crypto worker")
			return
		}
		d.wkr = w
	}

	family: net.Family = .V6 if is_v6(a.endpoint.address) else .V4
	local, have_local, lerr := local_endpoint(conn, family)
	if lerr {
		fail_connection(d, .Connect_Failed, {})
		return
	}
	if conn.proto == .Udp {
		opts := net.UDP_Options {
			recv_buffer = d.cfg.rcvbuf if d.cfg.rcvbuf > 0 else SOCKET_BUFFER,
			send_buffer = d.cfg.sndbuf if d.cfg.sndbuf > 0 else SOCKET_BUFFER,
			// The kernel driver reads data packets from this socket and passes the
			// others up as they came. They must not be merged (GRO), and nothing
			// here sends batches of one flow, so no offload on this socket.
			offload     = (OFF.gso || OFF.gro) && !(use_dco && d.dco.kind == .Kernel),
		}
		sock, err := net.udp_open(family, opts)
		if err != .None {
			logf(.Warn, "cannot open a UDP socket: %v", err)
			fail_connection(d, .Connect_Failed, {})
			return
		}
		sock = off_sock(sock)
		if !guest_protect(d, sock.fd) {
			net.close(sock)
			fail_connection(d, .Connect_Failed, {})
			return
		}
		d.off.udp_gso = u64(sock.gso)
		d.off.udp_gro = u64(sock.gro)
		if have_local {
			if berr := net.bind(sock, local); berr != .None {
				logf(.Warn, "cannot bind the local address: %v", berr)
				net.close(sock)
				fail_connection(d, .Connect_Failed, {})
				return
			}
		}
		if use_dco && d.dco.kind != .Kernel {
			// The service joins its worker sockets to this port, and the kernel
			// gives every packet of a port to a connected socket. So the socket
			// stays unconnected: each send names the server, each read checks the
			// source address.
			d.sock_to = a.endpoint
			d.tx_batch.family = family
		} else if cerr := net.connect(sock, a.endpoint); cerr != .None {
			logf(.Warn, "cannot use %s: %v", "the server address", cerr)
			net.close(sock)
			fail_connection(d, .Connect_Failed, {})
			return
		}
		d.sock = sock
		d.sock_open = true
		if err := event.add_fd(&d.loop, sock.fd, {.Read}, on_socket, d); err != .None {
			logf(.Error, "cannot watch the socket: %v", err)
			fail_connection(d, .Connect_Failed, {})
			return
		}
		arm_attempt_timer(d, a)
		begin_session(d)
		return
	}
	topts := net.TCP_Options {
		recv_buffer   = d.cfg.rcvbuf,
		send_buffer   = d.cfg.sndbuf,
		// A short kernel send queue for the outer TLS stream.
		notsent_lowat = conn.tls,
	}
	if have_local {
		topts.local = local
	}
	sock, in_progress, err := engine_tcp_connect(d, a.endpoint, topts)
	if err != .None {
		logf(.Warn, "TCP connect failed: %v", err)
		fail_connection(d, .Connect_Failed, {})
		return
	}
	d.sock = sock
	d.sock_open = true
	if terr := net.tcp_conn_init(&d.tcp, sock, d.tcp_rx, d.tcp_tx, 2048); terr != .None {
		logf(.Error, "cannot set up the TCP buffers")
		fail_connection(d, .Connect_Failed, {})
		return
	}
	if conn.tls {
		sni, _ := outer_sni(d.cfg, conn.host)
		if lerr := tlslink.link_init(&d.olink, &d.tls_ctx, sock, d.olink_out, sni, outer_alpn(d.cfg.tls_transport_hello, d.ws)); lerr != .None {
			logf(.Error, "cannot set up the outer TLS: %v", lerr)
			fail_connection(d, .Connect_Failed, {})
			return
		}
		d.olink_ok = true
		if n := test_outer_rekey_bytes(); n > 0 {
			d.olink.rekey_after = n
		}
	}
	interest := event.Interest{.Read, .Write} if in_progress else event.Interest{.Read}
	if err := event.add_fd(&d.loop, sock.fd, interest, on_socket, d); err != .None {
		logf(.Error, "cannot watch the socket: %v", err)
		fail_connection(d, .Connect_Failed, {})
		return
	}
	arm_attempt_timer(d, a)
	if in_progress {
		d.state = .Tcp_Connecting
		client_note_state(d)
		return
	}
	tcp_connected(d)
}

// The TCP connection is up (to the server, or to its proxy): the next step.
tcp_connected :: proc(d: ^Daemon) {
	switch {
	case d.via_proxy:
		proxy_begin(d)
	case d.tls:
		tls_begin(d)
	case:
		begin_session(d)
	}
}

arm_attempt_timer :: proc(d: ^Daemon, a: client.Action) {
	if a.attempt_timeout > 0 {
		timer_set(d, &d.t_attempt, now_of(d) + a.attempt_timeout, on_attempt_timer)
	}
}

on_attempt_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.t_attempt.on = false
	if d.state == .Idle || d.up {
		return
	}
	logf(.Warn, "the connection attempt timed out")
	fail_connection(d, .Handshake_Timeout, {})
}

// The local address to bind to, if the config has a `local` line. Failure to
// resolve is reported in the return value.
local_endpoint :: proc(conn: ^config.Connection, family: net.Family) -> (ep: net.Endpoint, have: bool, failed: bool) {
	if conn.local_host == "" {
		return {}, false, false
	}
	pref: net.Resolve_Pref = .V4_Only if family == .V4 else .V6_Only
	port := u16(0) if conn.nobind else conn.lport
	eps, err := net.resolve(conn.local_host, port, pref, context.temp_allocator)
	if err != .None || len(eps) == 0 {
		logf(.Warn, "cannot resolve the local address %s", conn.local_host)
		return {}, false, true
	}
	return eps[0], true, false
}

// `ahead` are bytes of the stream that were read already (what came behind a
// proxy's reply): they are the first bytes the server sent.
begin_session :: proc(d: ^Daemon, ahead: []u8 = nil) {
	early := false
	if d.dco.active && d.proto == .Tcp && dco_early_ok(&d.dco.link) {
		// The TCP connection is up: it goes to the DCO service before the handshake
		// starts, and the service has it from the first record.
		if !dco_client_handover(d, ahead) {
			return
		}
		early = true
	}
	event.update_time(&d.loop)
	now := now_of(d)
	unix := time.time_to_unix(time.now())
	if err := session.session_start(&d.s, now, unix); err != .None {
		fatal(d, .System, "cannot start the session: %v", err)
		return
	}
	d.state = .Active
	d.detail_next = ""
	client_note_state(d)
	pump(d)
	if !early && len(ahead) > 0 && d.state == .Active && d.s_ok {
		// The service has the stream in the early case and takes them from `dco_client_handover`.
		if d.ws {
			ws_feed(d, ahead)
		} else {
			feed(d, ahead)
		}
		rx_flush(d)
		if d.state == .Active && d.s_ok {
			pump(d)
			flush_tx(d)
		}
	}
}

build_session_config :: proc(d: ^Daemon, conn: ^config.Connection) -> session.Config {
	keys := &d.set.conns[d.conn_idx]
	t := &d.cfg.tls
	c := session.Config {
		transport = .Udp if conn.proto == .Udp else .Tcp,
		cert_pem = d.set.cert_pem,
		key_pem = d.set.key_pem,
		ca_pem = d.set.ca_pem,
		verify = d.set.verify,
		pin_cert = d.set.pins,
		leaf_rules = d.set.rules,
		tls_min = d.set.tls_min,
		tls_max = d.set.tls_max,
		tls_groups = d.set.groups,
		ciphers = d.set.ciphers,
		max_packet_size = d.cfg.max_packet_size,
		tls_timeout = time.Duration(t.tls_timeout) * time.Second,
		hand_window = time.Duration(t.hand_window) * time.Second,
		tran_window = time.Duration(t.tran_window) * time.Second,
		reneg_sec = t.reneg_sec if t.reneg_sec > 0 else -1,
		reneg_bytes = u64(max(t.reneg_bytes, 0)),
		reneg_pkts = u64(max(t.reneg_pkts, 0)),
		ping_default = d.cfg.ping,
		ping_restart_default = d.cfg.ping_restart,
		explicit_exit_notify = conn.explicit_exit_notify,
		ipv4_peer = !is_v6(d.endpoint.address),
		limit_override = test_aead_limit(),
	}
	crl_client_config(&c, &d.set.crl)
	c.wrap.mode = keys.mode
	switch keys.mode {
	case .None:
	case .Tls_Auth:
		c.wrap.static_key = &keys.static_key
		c.wrap.auth_digest = keys.digest
		c.wrap.key_direction = keys.key_dir
	case .Tls_Crypt:
		c.wrap.static_key = &keys.static_key
	case .Tls_Crypt_V2:
		c.wrap.client_key = &keys.client_key
	}
	if conn.tun_mtu > 0 {
		c.tun_mtu = conn.tun_mtu
		c.iv_mtu = max(conn.tun_mtu, session.DEFAULT_IV_MTU)
	}
	if d.guest != nil {
		// The server is told the cap. A larger pushed value is still taken and
		// lowered (`guest_mtu`), so the check of the push has a higher limit.
		c.iv_mtu_sent = GUEST_MAX_MTU
		c.iv_mtu = MAX_TUN_PACKET
	}
	c.sso = client_sso(d)
	// The login: a saved auth-token replaces the password.
	d.used_token = false
	if d.creds.token_n > 0 {
		user := d.creds.token_user[:d.creds.token_user_n] if d.creds.token_user_n > 0 else d.creds.user[:d.creds.user_n]
		c.username = string(user)
		c.password = string(d.creds.token[:d.creds.token_n])
		d.used_token = true
	} else if d.creds.have {
		c.username = string(d.creds.user[:d.creds.user_n])
		c.password = string(d.creds.pass[:d.creds.pass_n])
	}
	// Always: the hook also keeps the pushed lines for the bus.
	c.push_filter = pull_filter_hook
	c.push_filter_user = d
	return c
}

is_v6 :: proc(a: cnet.Address) -> bool {
	_, v6 := a.(cnet.IP6_Address)
	return v6
}

// `pull-filter`: runs `client.pull_filter_options` on each PUSH_REPLY message.
pull_filter_hook :: proc(user: rawptr, options: string, out: []u8) -> (n: int, reject: string, ok: bool) {
	d := (^Daemon)(user)
	res, rok := client.pull_filter_options(d.cfg.pull_filters, options)
	if !rok {
		return 0, "out of memory", false
	}
	defer delete(res.options)
	if rejected, bad := res.rejected.?; bad {
		return 0, fmt.tprintf("pull-filter reject: %s", rejected), false
	}
	if res.ignored > 0 {
		d.filter_ignored += res.ignored
		logf(.Info, "pull-filter ignored %d pushed option(s)", res.ignored)
	}
	client_capture_push(d, res.options)
	return copy(out, res.options), "", true
}

// ------------------------------------------------------- the session pump

// Everything the session wants to say after any call into it: link packets,
// then events (which may queue more), until nothing is left. A connection that
// ended (Failed or Closed event, link error) is finished here, after the last
// packets are out.
pump :: proc(d: ^Daemon) {
	if !d.s_ok || d.in_pump {
		return
	}
	d.in_pump = true
	if d.outer == .Pending {
		outer_check(d)
	}
	for _ in 0 ..< 8 {
		drain_tx(d)
		dco_client_check(d)
		handled := 0
		for !d.end.pending {
			ev, ok := session.session_next_event(&d.s)
			if !ok {
				break
			}
			handled += 1
			on_event(d, &ev)
		}
		if handled == 0 || d.end.pending {
			break
		}
	}
	drain_tx(d)
	d.in_pump = false
	if d.end.pending {
		finish_connection(d)
		return
	}
	arm_session_timer(d)
}

drain_tx :: proc(d: ^Daemon) {
	for _ in 0 ..< 10000 {
		if !d.s_ok || d.end.pending {
			return
		}
		n := session.session_poll_tx(&d.s, d.link[:], now_of(d))
		if n == 0 {
			return
		}
		send_link(d, d.link[:n])
	}
}

arm_session_timer :: proc(d: ^Daemon) {
	if !d.s_ok || d.state != .Active {
		timer_clear(d, &d.t_session)
		return
	}
	at, ok := session.session_next_wakeup(&d.s, now_of(d))
	if !ok {
		timer_clear(d, &d.t_session)
		return
	}
	timer_set(d, &d.t_session, at, on_session_timer)
}

on_session_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.t_session.on = false
	if !d.s_ok || d.state != .Active {
		return
	}
	session.session_tick(&d.s, now_of(d))
	pump(d)
	flush_tx(d)
}

// ----------------------------------------------------------------- events

on_event :: proc(d: ^Daemon, ev: ^session.Event) {
	switch ev.kind {
	case .None:
	case .Link_Up:
		logf(.Info, "the server responded, starting the TLS handshake")
	case .Auth_Request, .Float_Candidate:
		// Server-role events: a client session never raises them.
	case .Up:
		handle_up(d)
	case .Key_Installed:
		d.rekey_count += 1
		logf(.Info, "new data key %d installed (%s)", ev.key_id, "started by the server" if ev.by_peer else "started by us")
		flush_tx(d)
	case .Rekey_Started:
		logf(.Debug, "renegotiation started: key id %d (%s)", ev.key_id, "by the server" if ev.by_peer else "by us")
	case .Token_Updated:
		if user, token, ok := session.session_auth_token(&d.s); ok {
			c := &d.creds
			c.token_n = copy(c.token[:], token)
			c.token_user_n = copy(c.token_user[:], user)
			logf(.Debug, "the server sent a new auth-token")
		}
	case .Auth_Pending:
		logf(.Notice, "the server needs more time to check the login (AUTH_PENDING, timeout %d s)", ev.timeout)
		web_on_pending(d, ev.timeout)
	case .Info:
		logf(.Notice, "server info: %s", session.event_text(ev))
	case .Info_Pre:
		web_on_info_pre(d)
	case .Auth_Failed:
		text := session.event_text(ev)
		// The login used a saved token, or the server pushed one in this session.
		held := d.used_token || ev.token_dropped
		if held && ev.auth_kind != .Temp {
			logf(.Notice, "the server refused the saved auth-token (%v%s%s); signing in again", ev.auth_kind, ": " if len(text) > 0 else "", text)
			d.detail_next = TOKEN_REFUSED
		} else {
			logf(.Error, "the server refused the login (%v%s%s)", ev.auth_kind, ": " if len(text) > 0 else "", text)
		}
		d.pending = Pending {
			kind       = .Auth_Failed,
			auth_kind  = ev.auth_kind,
			backoff    = ev.backoff,
			advance    = ev.advance,
			used_token = held,
		}
		if held {
			// The token is invalid.
			d.creds.token_n, d.creds.token_user_n = 0, 0
			for i in 0 ..< len(d.creds.token) {
				d.creds.token[i] = 0
				d.creds.token_user[i] = 0
			}
		}
	case .Restart:
		logf(.Notice, "the server asked us to restart: %s", session.event_text(ev))
		d.pending = Pending {
			kind        = .Restart,
			next_remote = ev.next_remote,
		}
	case .Halt:
		logf(.Error, "the server asked us to halt: %s", session.event_text(ev))
		d.pending = Pending {
			kind = .Halt,
		}
	case .Remote_Exit:
		logf(.Notice, "the server is closing the connection")
		if d.pending.kind == .None {
			d.pending = Pending {
				kind = .Remote_Exit,
			}
		}
	case .Closed:
		logf(.Debug, "session closed")
		outcome := close_outcome(d.close_reason)
		d.end = End {
			pending = true,
			outcome = outcome,
		}
	case .Failed:
		logf(.Warn if d.up else .Notice, "the session failed: %s", session.event_text(ev))
		if d.close_reason != .None {
			d.end = End {
				pending = true,
				outcome = close_outcome(d.close_reason),
			}
			break
		}
		outcome, info := failure_outcome(ev.reason, d.up, d.pending)
		d.end = End {
			pending = true,
			outcome = outcome,
			info    = info,
		}
	}
}

End :: struct {
	pending: bool,
	outcome: client.Outcome,
	info:    client.Outcome_Info,
}

// ----------------------------------------------------------------- tunnel up

handle_up :: proc(d: ^Daemon) {
	web_clear(d)
	if n := session.session_crl_skipped(&d.s); n > 0 {
		logf(.Debug, "crl-verify: %d certificate(s) of the server chain have no CRL of their issuer and are accepted", n)
	}
	po := session.session_pushed(&d.s)
	if po == nil {
		fatal(d, .System, "internal error: no pushed options")
		return
	}
	if m, ok := po.tun_mtu.?; ok && m > MAX_TUN_PACKET {
		fatal(d, .Network, "the server pushed tun-mtu %d, which is above the limit of %d", m, MAX_TUN_PACKET)
		return
	}
	timer_clear(d, &d.t_attempt)
	d.persist = d.persist_cfg || po.persist_tun
	d.mss4 = client_mss(d, po)
	d.block6 = d.cfg.block_ipv6 || po.block_ipv6
	d.dco.pushed_block6 = po.block_ipv6
	if d.dco.active && d.block6 && !dco_filter_ok(&d.dco.link) {
		// Only a push gets here: a block-ipv6 of the config is known when the attempt is chosen.
		dco_filter_warn(d, true)
		dco_filter_attempt_end(d)
		return
	}

	// The tun device (kept across reconnects with persist-tun). With the DCO
	// service it is the service's device.
	if d.dco.active {
		if !dco_client_prepare(d) { // created already when the connection went to the service early
			dco_setup_failed(d)
			return
		}
		if !dco_client_filter(d, d.block6) {
			dco_setup_failed(d)
			return
		}
	} else {
		dco_client_release_device(d) // a device of the service, and this attempt runs here
	}
	if !d.dco.active && !d.tun_open && d.guest == nil {
		dev, err := tun.open({name = client_dev_name(d), offload = OFF.tun})
		if err != .None {
			fatal(d, .System, "cannot open the tun device: %v (%s)", err, TUN_HINT)
			return
		}
		d.tun = dev
		d.tun_open = true
		off_note_tun(&d.off, &d.tun)
		d.tun_tx.on = d.tun.vnet
		if err := tun_watch(d); err != .None {
			fatal(d, .System, "cannot watch the tun device: %v", err)
			return
		}
		link, lerr := sysnet.link_get(&d.sys, tun_name(d))
		if lerr != .None {
			fatal(d, .System, "cannot find the tun device %s: %v", tun_name(d), lerr)
			return
		}
		d.ifindex = link.index
		if q := d.cfg.txqueuelen; q > 0 {
			if qerr := sysnet.link_set_txqlen(&d.sys, d.ifindex, u32(q)); qerr != .None {
				logf(.Warn, "cannot set txqueuelen %d on %s: %v", q, tun_name(d), qerr)
			}
		}
		client.netcfg_init(&d.nc, &d.sys, d.ifindex)
		d.nc_ok = true
		logf(.Info, "using tun device %s (index %d)", tun_name(d), d.ifindex)
	}
	// TCP connection the service has had since it was created: the peer takes its
	// pushed id first, before addresses and routes (the server sends data as soon
	// as it has our peer).
	if d.dco.active && d.dco.o.stream && !dco_client_peer_id(d) {
		dco_setup_failed(d)
		return
	}
	if d.guest != nil {
		pending, ok := guest_apply_network(d, po)
		if !ok {
			return
		}
		if pending {
			// The host applies the settings first: `guest_settings_done` goes on.
			return
		}
	} else if !apply_network(d, po) {
		return
	}
	if d.dco.active && !d.dco.o.stream && !dco_client_peer(d, po) {
		dco_setup_failed(d)
		return
	}
	handle_up_finish(d, po)
}

// The end of the tunnel-up: the state goes to `up`. A guest comes here when the
// host has applied the settings.
handle_up_finish :: proc(d: ^Daemon, po: ^push.Pushed_Options) {
	d.up = true
	d.up_at = now_of(d)
	d.up_wall = time.now()
	d.stats.connects += 1
	d.inactive_pkts = d.stats.tun_read_pkts + d.stats.tun_write_pkts
	d.inactive_bytes = d.stats.tun_read_bytes + d.stats.tun_write_bytes
	d.inactive_at = d.up_at
	client.policy_outcome(&d.policy, .Connected, d.up_at)
	ifc, _ := po.ifconfig.?
	logf(
		.Notice,
		"tunnel is up: %s, address %d.%d.%d.%d/%d, data cipher %s, peer-id %d, data format %s. Initialization Sequence Completed",
		tun_name(d),
		ifc.a[0], ifc.a[1], ifc.a[2], ifc.a[3], d.plan.prefix4,
		push.cipher_name(session.session_cipher(&d.s)),
		session.session_peer_id(&d.s),
		session.session_data_format_name(&d.s),
	) // fmt: skip
	logf(.Info, "TCP MSS clamp: %s", client_mss_line(d))
	arm_limit_timer(d)
	client_ev_tunnel_settings(d, po)
	client_note_state(d)
	flush_tx(d)
}

// Addresses, routes and DNS for the pushed settings. Returns false after
// `fatal` (the daemon then stops).
apply_network :: proc(d: ^Daemon, po: ^push.Pushed_Options) -> bool {
	conn := &d.cfg.connections[d.conn_idx]
	server := d.endpoint.address
	same_server := d.applied && d.applied_to == server

	if d.applied && !(d.persist && same_server) {
		// Another server, or no persist-tun: take the old state away first.
		teardown_network(d, false)
	}
	if !d.have_state {
		st, gerr := client.netcfg_gather(&d.sys, server, d.ifindex)
		if gerr == .Server_Via_Tunnel {
			teardown_network(d, false)
			st, gerr = client.netcfg_gather(&d.sys, server, d.ifindex)
		}
		if gerr != .None {
			fatal(d, .Network, "cannot read the routing table: %v", gerr)
			return false
		}
		d.sys_state = st
		d.have_state = true
	}
	local_mtu := conn.tun_mtu if conn.tun_mtu > 0 else DEFAULT_TUN_MTU
	input := client.Plan_Input {
		cfg          = d.cfg,
		pushed       = po,
		local_mtu    = local_mtu,
		server       = server,
		server_route = d.sys_state.server_route,
		default4     = d.sys_state.default4,
		default6     = d.sys_state.default6,
	}
	if user_profile(d) {
		// The networks of the host stay off the tunnel.
		nets, nerr := client.netcfg_host_nets(&d.sys, d.ifindex)
		if nerr != .None {
			fatal(d, .Network, "cannot read the addresses of this host: %v", nerr)
			return false
		}
		input.host_nets = nets
	}
	plan, perr := client.plan_build(input)
	client.host_nets_destroy(input.host_nets)
	if perr != .None {
		fatal(d, .Network, "cannot use the pushed settings: %v", perr)
		return false
	}
	for n in plan.notes {
		logf(.Notice if plan_note_for_user(n.kind) else .Info, "%s", n.text)
	}
	if log_enabled(.Verbose) {
		for step in plan.steps {
			logf(.Verbose, "plan: %s", client.step_string(step, context.temp_allocator))
		}
	}

	// The routes go into the record before they are added.
	client_rec_sync(d, &plan)
	if d.applied {
		// persist-tun, same server: change only what differs.
		changed, err := client.netcfg_update(&d.nc, &plan)
		if err != .None {
			client.plan_destroy(&plan)
			fatal(d, .Network, "cannot update the network settings: %v (step %d)", err, d.nc.failed_step)
			return false
		}
		if changed {
			logf(.Notice, "the network settings changed after reconnecting, so they were applied again")
		}
		if changed || !dns_equal(plan, d.plan) {
			revert_dns(d)
			apply_dns(d, &plan)
		}
	} else {
		if err := client.netcfg_apply(&d.nc, &plan); err != .None {
			client.plan_destroy(&plan)
			fatal(d, .Network, "cannot set up the tunnel: %v (step %d)", err, d.nc.failed_step)
			return false
		}
		apply_dns(d, &plan)
	}
	for w in d.nc.warnings {
		logf(.Warn, "network step %d (%v) failed: %v%s", w.step, w.why, w.err, " (IPv6 is off)" if w.skipped_v6 else "")
	}
	if d.plan_ok {
		client.plan_destroy(&d.plan)
	}
	d.plan = plan
	d.plan_ok = true
	d.applied = true
	d.applied_to = server
	client_rec_sync(d)
	return true
}

dns_equal :: proc(a, b: client.Plan) -> bool {
	if a.has_dns != b.has_dns {
		return false
	}
	if !a.has_dns {
		return true
	}
	x, y := a.dns, b.dns
	if x.default_route != y.default_route || len(x.servers) != len(y.servers) ||
	   len(x.search_domains) != len(y.search_domains) || len(x.routing_domains) != len(y.routing_domains) {
		return false
	}
	for s, i in x.servers {
		if s != y.servers[i] {
			return false
		}
	}
	for s, i in x.search_domains {
		if s != y.search_domains[i] {
			return false
		}
	}
	for s, i in x.routing_domains {
		if s != y.routing_domains[i] {
			return false
		}
	}
	return true
}

apply_dns :: proc(d: ^Daemon, plan: ^client.Plan) {
	if !plan.has_dns {
		return
	}
	if d.privs_dropped {
		logf(.Info, "DNS was not applied because the daemon runs without root (user); the DNS settings are in the client.tunnel_settings bus event")
		return
	}
	if err := sysnet.dns_apply(&d.dns, d.dns_env, tun_name(d), plan.dns); err != .None {
		logf(.Warn, "cannot set the DNS servers: %v (the tunnel works, but names may not resolve through it)", err)
		return
	}
	logf(.Info, "DNS applied using the %v backend", d.dns.backend)
	for w in d.dns.warnings {
		// What the backend cannot do (per-domain routing on a plain resolv.conf)
		// is only information.
		logf(.Notice, "DNS: %s", w)
	}
}

revert_dns :: proc(d: ^Daemon) {
	if d.dns.active {
		if err := sysnet.dns_revert(&d.dns); err != .None {
			logf(.Warn, "cannot restore the DNS settings: %v", err)
		}
	}
	sysnet.dns_destroy(&d.dns)
}

// Takes the DNS settings, routes and addresses away. With `close_tun` the tun
// device goes too.
teardown_network :: proc(d: ^Daemon, close_tun: bool) {
	if d.guest != nil {
		guest_teardown(d)
	}
	revert_dns(d)
	if d.nc_ok {
		if failures := client.netcfg_teardown(&d.nc); failures > 0 {
			logf(.Warn, "%d network changes could not be undone", failures)
		}
	}
	d.applied = false
	d.have_state = false
	if d.plan_ok {
		client.plan_destroy(&d.plan)
		d.plan_ok = false
	}
	if close_tun && d.dco.dev {
		dco_client_device_close(d)
		if d.nc_ok {
			client.netcfg_destroy(&d.nc)
			d.nc_ok = false
		}
		ring_clear(&d.ring)
	}
	if close_tun && d.tun_open {
		tun_unwatch(d)
		tun.close(&d.tun)
		d.tun_open = false
		if d.nc_ok {
			client.netcfg_destroy(&d.nc)
			d.nc_ok = false
		}
		ring_clear(&d.ring)
	}
	client_rec_sync(d)
}

// ---------------------------------------------------------- ending a connection

// The connection is over for this reason. Finishes it now, or, inside `pump`,
// when `pump` is done.
fail_connection :: proc(d: ^Daemon, outcome: client.Outcome, info: client.Outcome_Info) {
	if d.end.pending {
		return
	}
	if d.close_reason != .None {
		d.end = End {
			pending = true,
			outcome = close_outcome(d.close_reason),
		}
	} else {
		d.end = End {
			pending = true,
			outcome = outcome,
			info    = info,
		}
	}
	if !d.in_pump {
		finish_connection(d)
	}
}

close_transport :: proc(d: ^Daemon) {
	if d.olink_ok {
		// A goodbye to the outer TLS: best effort, the socket closes right after.
		tlslink.link_close(&d.olink)
		tlslink.link_destroy(&d.olink)
		d.olink_ok = false
	}
	if d.sock_open {
		event.remove_fd(&d.loop, d.sock.fd)
		net.close(d.sock)
		d.sock_open = false
		d.sock = net.INVALID_SOCKET
	}
	d.want_write = false
	d.blocked = false
}

// The session (or attempt) ended. Releases the connection, removes the network
// settings unless persist-tun keeps them, tells the policy, arms the next step.
finish_connection :: proc(d: ^Daemon) {
	end := d.end
	was_up := d.up
	if d.s_ok {
		dco_client_refresh(d)
		c := session.session_counters(&d.s)
		log_counters(.Info, &c)
	}
	close_transport(d)
	proxy_state_clear(&d.px)
	timer_clear(d, &d.t_session)
	timer_clear(d, &d.t_attempt)
	timer_clear(d, &d.t_close)
	timer_clear(d, &d.t_limit)
	if d.s_ok {
		rx_abandon(d)
		dco_client_end(d)
		session.session_destroy(&d.s)
		d.s_ok = false
		d.wkr = nil
	}
	d.up = false
	web_clear(d)
	d.state = .Idle
	d.end = {}
	d.in_pump = false
	ring_clear(&d.ring)
	reason := d.close_reason
	d.close_reason = .None
	token_refused := d.pending.kind == .Auth_Failed && d.pending.used_token && d.pending.auth_kind != .Temp
	d.pending = {}
	if d.service {
		d.bus_reason = service_reason(end.outcome, reason, d.fatal_code, d.dco.path == .Dco)
	} else {
		d.bus_reason = state_reason(end.outcome, reason, d.exit_code, d.dco.path == .Dco)
	}
	if token_refused && reason == .None {
		d.bus_reason = "auth_failed"
	}
	dco_attempt_ended(d, end.outcome)

	if close_reason_exits(d, reason) {
		shutdown(d)
		return
	}
	if d.service && reason == .Fatal {
		service_stop(d, d.bus_reason)
		return
	}
	if was_up {
		logf(.Notice, "disconnected (%v)", end.outcome)
	} else {
		logf(.Notice, "the attempt ended (%v)", end.outcome)
	}
	if d.applied || d.tun_open || d.dco.dev {
		// A service keeps no tunnel state in `stopped`, also with persist-tun.
		if d.persist && !(d.service && reason == .Disconnect) {
			logf(.Notice, "persist-tun: keeping the tunnel, routes and DNS while reconnecting")
		} else {
			teardown_network(d, true)
		}
	}
	if end.outcome == .Local_Restart {
		logf(.Notice, "reconnecting now")
	}
	outcome := end.outcome
	if outcome == .Auth_Failed {
		// `auth-retry interact`: type the credentials again if they were typed,
		// else wait for them on the bus. Without either the daemon stops.
		waiting := false
		if d.cfg.auth_retry == .Interact {
			if ask_again(d) {
			} else if host_control_on(d) && d.cfg.auth_user_pass != nil {
				waiting = true
				cred_wipe_password(&d.creds)
			} else {
				outcome = .Local_Stop
				if d.service {
					d.stop_hint = "auth_failed"
				} else {
					d.exit_code = .Auth
				}
			}
		}
		if host_control_on(d) && d.cfg.auth_user_pass != nil {
			client_publish_auth_needed(d, "auth_failed", waiting)
		}
	}
	if reason == .Disconnect {
		// Stopped by `disconnect`: stay up and wait for `connect`.
		d.hold = true
		client_note_state(d)
		service_clear_due(d)
		return
	}
	info := end.info
	if d.guest != nil && d.guest.paused {
		#partial switch outcome {
		case .Connect_Failed, .Handshake_Timeout, .Ping_Restart:
			// The network is `none`: this failure does not count for the back-off.
			outcome, info = .Local_Restart, {}
		}
	}
	client.policy_outcome(&d.policy, outcome, now_of(d), info)
	if d.service {
		if stop, stopped := client.policy_stopped(&d.policy); stopped {
			service_stop(d, d.stop_hint if d.stop_hint != "" else service_stop_reason(stop, d.bus_reason))
			return
		}
	}
	client_note_state(d)
	timer_set(d, &d.t_policy, now_of(d), on_policy_timer)
}

// `auth-retry interact`: after a refused login, ask for the credentials again
// if they were typed. False if they cannot be asked (the daemon then stops).
ask_again :: proc(d: ^Daemon) -> bool {
	if !d.creds.from_prompt {
		return false
	}
	aup, ok := d.cfg.auth_user_pass.?
	if !ok {
		return false
	}
	logf(.Notice, "the login was refused, asking for it again")
	err := Cred_Error.No_Terminal
	if d.host.prompt_creds != nil {
		err = d.host.prompt_creds(d.host.user, &d.creds, aup.username_only)
	}
	if err != .None {
		logf(.Error, "%s", cred_error_text(err))
		return false
	}
	return true
}

// Stops the daemon for good: everything is removed, the loop ends.
shutdown :: proc(d: ^Daemon) {
	if d.shutting {
		return
	}
	d.shutting = true
	timer_clear(d, &d.t_policy)
	timer_clear(d, &d.t_session)
	timer_clear(d, &d.t_attempt)
	timer_clear(d, &d.t_close)
	timer_clear(d, &d.t_limit)
	if d.s_ok {
		dco_client_refresh(d)
		c := session.session_counters(&d.s)
		log_counters(.Info, &c)
		close_transport(d)
		rx_abandon(d)
		dco_client_end(d)
		session.session_destroy(&d.s)
		d.s_ok = false
		d.wkr = nil
	}
	close_transport(d)
	teardown_network(d, true)
	d.state = .Idle
	d.exit = true
	if d.bus_reason == "" {
		d.bus_reason = "exit"
	}
	client_note_state(d)
	timer_clear(d, &d.t_stats)
	log_status(d, .Notice, "exit")
}

// A setup error: log it, remember the exit code, and stop (with a goodbye to
// the server if a session exists).
fatal :: proc(d: ^Daemon, code: Exit, format: string, args: ..any) {
	logf(.Error, format, ..args)
	if d.service {
		// The service goes to `stopped`; the exit code of the process stays.
		d.fatal_code = code
		begin_close(d, .Fatal)
		return
	}
	if d.stop_reason == "" {
		d.stop_reason = "error"
		d.stop_detail = fmt.aprintf(format, ..args)
	}
	if d.exit_code == .Ok {
		d.exit_code = code
	}
	begin_close(d, .Fatal)
}

// ------------------------------------------------------------- graceful close

// Starts a clean end of the connection: the EXIT message to the server, then
// the `Closed` event. The first reason wins, except that a stop always wins.
begin_close :: proc(d: ^Daemon, reason: Close_Reason) {
	if d.shutting {
		return
	}
	// A stop wins over everything; `disconnect` wins over a restart or a limit.
	if close_reason_stops(reason) || d.close_reason == .None || (reason == .Disconnect && !close_reason_stops(d.close_reason)) {
		d.close_reason = reason
	}
	switch d.state {
	case .Idle:
		if close_reason_exits(d, reason) {
			shutdown(d)
		} else if d.service && reason == .Fatal {
			d.close_reason = .None
			service_stop(d, service_reason(.Local_Stop, .Fatal, d.fatal_code, false))
		}
	case .Tcp_Connecting, .Proxy_Connecting, .Tls_Handshaking, .Ws_Upgrading:
		fail_connection(d, .Local_Stop, {})
	case .Active:
		if d.end.pending {
			return
		}
		session.session_close(&d.s, now_of(d))
		timer_set(d, &d.t_close, now_of(d) + (d.close_wait.? or_else CLOSE_WAIT), on_close_timer)
		pump(d)
		client_note_state(d)
	}
}

on_close_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.t_close.on = false
	if d.state == .Idle {
		return
	}
	logf(.Warn, "the server did not confirm the exit in time")
	fail_connection(d, close_outcome(d.close_reason), {})
}

// ----------------------------------------------------------------- limits

// `session-timeout` and `inactive`.
arm_limit_timer :: proc(d: ^Daemon) {
	at := time.Duration(0)
	set := false
	if st := d.cfg.session_timeout; st > 0 {
		at = d.up_at + time.Duration(st) * time.Second
		set = true
	}
	if n := d.cfg.inactive_secs; n > 0 {
		next := d.inactive_at + time.Duration(n) * time.Second
		if !set || next < at {
			at = next
		}
		set = true
	}
	if !set {
		return
	}
	timer_set(d, &d.t_limit, at, on_limit_timer)
}

on_limit_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.t_limit.on = false
	if !d.up || d.close_reason != .None {
		return
	}
	dco_client_refresh(d)
	now := now_of(d)
	if st := d.cfg.session_timeout; st > 0 && now >= d.up_at + time.Duration(st) * time.Second {
		logf(.Notice, "the session-timeout was reached")
		begin_close(d, .Session_Timeout)
		return
	}
	if n := d.cfg.inactive_secs; n > 0 && now >= d.inactive_at + time.Duration(n) * time.Second {
		pkts := d.stats.tun_read_pkts + d.stats.tun_write_pkts
		bytes := d.stats.tun_read_bytes + d.stats.tun_write_bytes
		quiet := pkts == d.inactive_pkts
		if d.cfg.inactive_bytes > 0 {
			quiet = bytes - d.inactive_bytes < u64(d.cfg.inactive_bytes)
		}
		if quiet {
			logf(.Notice, "the tunnel was inactive for %d s", n)
			begin_close(d, .Inactive)
			return
		}
		d.inactive_pkts, d.inactive_bytes, d.inactive_at = pkts, bytes, now
	}
	arm_limit_timer(d)
}

// ---------------------------------------------------------------- signals

// What the host's signals mean. The host reads the signals and calls these.

// SIGINT or SIGTERM: close the connection and leave. The second one leaves at
// once.
daemon_stop_signal :: proc(d: ^Daemon) {
	if close_reason_exits(d, d.close_reason) {
		logf(.Notice, "second stop signal received, exiting now")
		shutdown(d)
		return
	}
	logf(.Notice, "stop signal received, closing the connection")
	if d.stop_reason == "" {
		d.stop_reason = "signal"
	}
	begin_close(d, .Stop)
}

// SIGHUP or SIGUSR1: close the connection and connect again now.
daemon_reconnect_now :: proc(d: ^Daemon) {
	if d.shutting || close_reason_exits(d, d.close_reason) {
		return
	}
	if d.service && (!d.prof_loaded || d.clear_pending) {
		return
	}
	logf(.Notice, "reconnect requested")
	service_begin(d)
	d.hold = false
	if d.state == .Idle {
		client.policy_outcome(&d.policy, .Local_Restart, now_of(d))
		timer_set(d, &d.t_policy, now_of(d), on_policy_timer)
		return
	}
	begin_close(d, .Restart)
}

// SIGUSR2: print the status block to the log.
daemon_print_status :: proc(d: ^Daemon) {
	log_status(d, .Status, "status")
}
