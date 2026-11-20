// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:strings"
import "core:time"
import "noir:client"
import "noir:platform/dco"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/sysnet"
import "noir:platform/tun"
import "noir:proto/config"
import "noir:proto/session"
import "noir:server"

// Server side of the data channel on a DCO service or the kernel `ovpn` driver
// (`datapath dco`). dco.odin has what both share and how the kernel differs
// (two key slots, late TCP handover, no `mssfix`, no epoch keys, one listening
// socket). Below, "service" also means the kernel backend (via `Backend`), plus:
//   float   the kernel moves a UDP peer's endpoint silently (before Linux 7.1);
//           the stats poll (`DCO_STATS_KERNEL`, 2 s for a UDP server) finds it
//   device  if deleted, the kernel ends every peer with "teardown"
//           (`Device_Gone`); the server takes the lost-service path
//
// The service creates the tun device (MP mode: delivers inner packets by the
// peer's VPN address) and runs the data keys, replay windows and keepalive.
// It reads data packets from sockets that share its port. This process keeps
// the listener and handles control packets. A TCP connection is ours for the
// handshake, then goes to the service when the login is accepted.
//
// Service peer lifecycle:
//   start   connect, OPEN (MP), addresses and routes by interface index
//   login   first key is generated while the TLS handshake ends and waits in the
//           owner. After accept (push reply not sent yet): NEW_PEER with the
//           listener fd (first peer only), the key, then SET_PEER
//   TCP     with CAP_TCP, CAP_PEER_ID and CAP_PEER_ADDR the connection goes to
//           the service at once: NEW_PEER carries the socket under a
//           provisional id (no listener fd); the handshake runs through CTRL_TX
//           and CTRL_RX events; at login SET_PEER_ID gives the registry's id,
//           SET_PEER_ADDR the VPN addresses, then key and SET_PEER as for UDP.
//           Without these caps the handover is late, at login: NEW_PEER carries
//           the socket and the unused bytes read from it.
//           PEER_DEL (stream closed or failed) ends the conn like a read error
//   events  PEER_DEL (expired, transport), KEY_SWAP, PEER_FLOAT, CTRL_RX, log lines
//   end     DEL_PEER with the session (closes a TCP stream); DETACH; the
//           device goes when the listener closes
//
// Fallback to the data path in this process (as `datapath userspace`), logged
// and shown on the bus (`datapath`):
//   start    `datapath udco` waits up to DCO_WAIT_SECS for the service. If it is
//            missing, lacks TCP for a TCP listener, or cannot create the device,
//            the whole run is in-process (warning; `auto`: notice).
//            A config error (number of listeners) is still an error
//   running  connection lost (`srv_dco_lost`): every session ends with RESTART,
//            the second device of a mixed server goes, the server opens its own
//            tun device and workers, new logins run here. No return to the service
//   client   the service refuses a command for one client: that login ends
//
// Mixed server: a `tls-server` listener (outer TLS in this process) can exist
// too. Its `tls` clients are not the service's:
// - data channel in the session (own keys, replay window, keepalive, stats;
//   epoch keys only when the service's clients have them)
// - a second tun device, read and written here; each client has a host route
//   there, the subnet route stays on the service's device
// Raw connections of such a listener (`tls-transport-accept-tcp`) go to the service.

Dco_Server :: struct {
	link:    Dco_Link,
	on:      bool,
	kind:    dco.Backend_Kind, // which backend, when `on`
	// The one listener is TCP. Conns that the service owns, by peer id, for its
	// events. A conn can leave the peer table (exit notice) before its stream closes.
	tcp:     bool,
	// The service takes TCP connections at once, under a provisional id, and renames
	// the peer and gives its addresses at login (`dco_server_early_ok`, `srv_dco_early_fits`).
	early:   bool,
	prov_n:  u32, // how many provisional ids: the top `prov_n` ids below 0xffffff
	prov_next: u32,
	// The ids of a conn that the service owns: while it is in the handshake its
	// provisional id, after the login that one and the registry's id both.
	by_id:   map[u32]u32, // peer id -> conn slot
	t_stats: Timer,
	// A test leaves the event loop out.
	no_watch: bool,
	t_gone:  Timer, // the kernel's device is gone: end the run on the backend (from the loop)
	// How long `datapath udco` waits for the service at start (0: DCO_WAIT_SECS; a test shortens it).
	wait_secs: int,
	// After the connection was lost: the retries to open the own tun device (the name
	// can be taken for a moment).
	t_tun:   Timer,
	tun_tries: int,
	// Mixed server: a `tls-server` listener exists. Its `tls` clients run here
	// (daemon backend) on a second tun device, `d.tun`, with a host route for each.
	// Every other client is the service's.
	mixed:    bool,
	tun_name: string, // the second device
	ifindex:  u32, // its index
	nc:       client.Netcfg,
	nc_ok:    bool,
	plan:     client.Plan,
	plan_ok:  bool,
}

// Provisional ids of the early handover: top of the id range, one per conn
// table slot. Registry ids (below `max-clients`) are the bottom. No overlap.
srv_dco_early_fits :: proc "contextless" (max_clients: int) -> bool {
	return max_clients + conn_table_size(max_clients) <= dco.PEER_ID_LIMIT
}

// At start: decides, and connects. False: the server cannot start. True, and
// `d.dco.on` false: the data path runs in this process.
srv_dco_init :: proc(d: ^Srv) -> bool {
	cfg := d.cfg
	mode := cfg.datapath
	if mode == .Userspace {
		return true
	}
	path := cfg.dco_socket
	// What the backend serves: the non-`tls-server` listener, if any, and with
	// `tls-transport-accept-tcp` the raw (TCP) connections of `tls-server`
	// listeners. The tls clients are ours.
	own, any_tls, own_tcp := 0, false, false
	for l in cfg.listens {
		if l.tls {
			any_tls = true
		} else {
			own += 1
			own_tcp = l.proto == .Tcp
		}
	}
	if any_tls && mode == .Auto {
		logf(.Notice, "datapath auto: `proto tls-server` is present, so the data path will run in this process (use `datapath dco` or `udco` to hand the udp and tcp clients to the kernel or the DCO service)")
		return true
	}
	if mode == .Auto && cfg.tls.transport_ws != "" && own_tcp {
		logf(.Notice, "datapath auto: `tls-transport-ws` is set, and neither the kernel nor the DCO service supports WebSocket, so the data path will run in this process")
		return true
	}
	tcp := own_tcp || (own == 0 && cfg.tls.transport_accept_tcp)
	one := own == 1 || (own == 0 && any_tls)
	auto := mode == .Auto
	if !one {
		if auto {
			logf(.Notice, "datapath auto: the kernel and the DCO service need exactly one listening socket, so the data path will run in this process")
			return true
		}
		logf(.Error, "datapath %s needs exactly one listening socket besides the `tls-server` ones", config.datapath_name(mode))
		d.exit_code = .Config
		return false
	}
	block6 := cfg.block_ipv6
	if block6 && mode == .Dco {
		logf(.Warn, "datapath dco: the kernel ovpn driver cannot drop IPv6 traffic, which block-ipv6 requires, so the data path will run in this process")
		return true
	}
	wait_secs := DCO_WAIT_SECS
	if !dco_in_process_on(path) {
		path, wait_secs = dco_launch_start(dco.launcher, mode, d.inst_name, path, dco_launch_uid())
		cfg.dco_socket = path
	}
	if d.dco.wait_secs > 0 && wait_secs > 0 {
		wait_secs = d.dco.wait_secs
	}
	pick := dco_pick(&d.dco.link, mode, path, wait_secs, block6)
	if block6 && auto {
		if !pick.found {
			logf(.Notice, "datapath auto: the kernel ovpn driver cannot be used because block-ipv6 is set, and there is no DCO service at %s (%s), so the data path will run in this process", path, dco_status_text(pick.service_st))
		}
	} else {
		dco_pick_report(mode, path, pick)
	}
	if !pick.found {
		return true
	}
	kind := pick.kind
	who := dco_who(kind)
	if tcp && !dco_tcp_ok(&d.dco.link) {
		if kind == .In_Process {
			logf(.Notice, "datapath %s: the data channel in this process does not support TCP, so the data path will run in the daemon", config.datapath_name(mode))
		} else if auto {
			logf(.Notice, "datapath auto: the DCO service at %s does not support TCP (no TCP capability), so the data path will run in this process", path)
		} else {
			logf(.Warn, "datapath udco: the DCO service at %s does not support TCP (its HELLO reply lacks the TCP capability), so the data path will run in this process", path)
		}
		dco_link_close(&d.dco.link)
		return true
	}
	if block6 && !dco_filter_ok(&d.dco.link) {
		if auto {
			logf(.Notice, "datapath auto: the DCO service at %s cannot drop IPv6 (no BLOCK_IPV6 capability), which block-ipv6 requires, so the data path will run in this process", path)
		} else {
			logf(.Warn, "datapath udco: the DCO service at %s cannot drop IPv6 (its HELLO reply lacks the BLOCK_IPV6 capability), which block-ipv6 requires, so the data path will run in this process", path)
		}
		dco_link_close(&d.dco.link)
		return true
	}
	// The device is created here, so a backend that cannot create it leaves the server
	// in this process before sessions are set up.
	// In-process data channel drops client-to-client packets itself; the service
	// and the kernel write them to the tun device.
	extra := u32(0)
	if kind == .In_Process && !cfg.client_to_client {
		extra = dco.OPT_NO_C2C
	}
	idx, made, why := dco_try_open(&d.dco.link, tun_name_of(cfg.dev), .Mp, extra)
	if !made {
		dev := tun_name_of(cfg.dev)
		dev = dev if dev != "" else "tun0"
		logf(.Notice if auto else .Warn, "datapath %s: %s cannot create the device %s: %s, so the data path will run in this process", config.datapath_name(mode), who, dev, why)
		dco_link_close(&d.dco.link)
		return true
	}
	if block6 {
		if _, _, st := dco_filter_call(&d.dco.link, true); st != 0 {
			logf(.Notice if auto else .Warn, "datapath %s: %s refused the IPv6 filter: %s, so the data path will run in this process", config.datapath_name(mode), who, dco_why(&d.dco.link, st))
			dco_link_close(&d.dco.link)
			return true
		}
	}
	d.ifindex = idx
	d.dco.on = true
	d.dco.kind = kind
	d.dco.tcp = tcp
	if any_tls {
		d.dco.mixed = true
		d.dco.tun_name = strings.clone(config.tls_tun_name(cfg.dev, cfg.tls.transport_dev, context.temp_allocator))
	}
	if tcp && dco_server_early_ok(&d.dco.link) {
		if srv_dco_early_fits(cfg.max_clients) {
			d.dco.early = true
			d.dco.prov_n = u32(conn_table_size(cfg.max_clients))
		} else {
			logf(.Notice, "max-clients %d leaves no room for provisional peer ids, so TCP connections are handed to the DCO service at login", cfg.max_clients)
		}
	}
	if kind == .Service {
		logf(.Info, "DCO service at %s: %s", path, dco.daemon_name(&d.dco.link.c))
	} else if kind == .In_Process {
		logf(.Info, "data channel in this process: %s", dco_in_process_name())
	}
	if cfg.client_to_client {
		logf(.Notice, "client-to-client with %s: the clients reach each other through the kernel (the packets pass through the tun device, so IP forwarding must be enabled)", who)
		if d.dco.mixed {
			logf(.Notice, "client-to-client on a mixed server: packets between two tls clients stay in this process, while packets between a tls client and the clients of %s pass through the kernel between the two tun devices", who)
		}
	}
	if cfg.multihome_same_iface {
		logf(.Notice, "multihome same-interface: %s cannot select the interface, so only the control packets from this process are sent through the interface the client used", who)
	}
	if d.dco.no_watch {
		return true
	}
	if err := event.add_fd(&d.loop, d.dco.link.be.fd, {.Read}, on_srv_dco, d); err != .None {
		logf(.Error, "cannot watch the descriptor of %s: %v", who, err)
		return false
	}
	d.dco.link.watched = true
	return true
}

// The backend of the server has epoch keys: its sessions, and the `tls` clients of a
// mixed server with them, may negotiate `aead-epoch`.
srv_dco_epoch :: proc "contextless" (d: ^Srv) -> bool {
	return d.dco.on && dco_epoch_ok(&d.dco.link)
}

srv_dco_destroy :: proc(d: ^Srv) {
	delete(d.dco.by_id)
	d.dco.by_id = nil
	if d.dco.plan_ok {
		client.plan_destroy(&d.dco.plan)
		d.dco.plan_ok = false
	}
	if d.dco.nc_ok {
		client.netcfg_destroy(&d.dco.nc)
		d.dco.nc_ok = false
	}
	delete(d.dco.tun_name)
	d.dco.tun_name = ""
	if d.dco.link.up {
		if d.dco.link.watched {
			event.remove_fd(&d.loop, d.dco.link.be.fd)
		}
		dco_link_close(&d.dco.link)
	}
}

srv_tun_name :: proc(d: ^Srv) -> string {
	if d.dco.on {
		// (With a mixed server, `d.tun` is the second device: `srv_tls_tun_name`.)
		name := tun_name_of(d.cfg.dev)
		return name if name != "" else "tun0"
	}
	return tun.name(&d.tun)
}

// The name of the second tun device of a mixed server, or "".
srv_tls_tun_name :: proc(d: ^Srv) -> string {
	return d.dco.tun_name if d.dco.mixed else ""
}

// Does the DCO service run the data channel of this client? The clients of a mixed
// server that come in on a `tls` connection are the process's own.
conn_in_service :: proc(d: ^Srv, c: ^Conn) -> bool {
	return d.dco.on && !c.tls && c.ws_phase == .None
}

// The data channel of a new session belongs to the service.
srv_dco_attach :: proc(d: ^Srv, c: ^Conn) {
	dco_owner_init(&c.dco, &d.dco.link, session.session_slots_config(&c.s))
	dco_attach(&c.s, &c.dco)
}

// The address of this host that the client uses (`PEER_LOCAL`): the conn's local
// when it is known, else the address of the listener when that names one.
srv_dco_local :: proc(c: ^Conn, ln: ^Listener) -> (sa: dco.Sockaddr_Storage, ok: bool) {
	ep := ln.ep
	if c.local.len > 0 {
		a, _ := net.local_address(c.local)
		ep.address = a
	} else if !ln.have_host {
		return {}, false
	}
	la := endpoint_peer_addr(ep)
	return dco_sockaddr(session.peer_addr_bytes(&la))
}

// The login is accepted and the client has its addresses: create the peer.
srv_dco_peer :: proc(d: ^Srv, c: ^Conn) -> bool {
	ln := &d.listeners[c.lidx]
	id := session.session_peer_id(&c.s)
	remote, rok := dco_sockaddr(session.peer_addr_bytes(&c.addr))
	if !rok {
		logf(.Error, "client %s: cannot use its address for %s", conn_label(c), dco_who(d.dco.kind))
		return false
	}
	p := dco.New_Peer {
		peer_id = id,
		flags   = dco.PEER_REMOTE,
		remote  = remote,
	}
	if local, ok := srv_dco_local(c, ln); ok {
		p.flags |= dco.PEER_LOCAL
		p.local = local
	}
	if pr := server.peers_get(&d.srv.reg.peers, c.h); pr != nil {
		if pr.has4 {
			p.flags |= dco.PEER_VPN4
			p.vpn4 = pr.vpn4
		}
		if pr.has6 {
			p.flags |= dco.PEER_VPN6
			p.vpn6 = pr.vpn6
		}
	}
	interval, timeout := session.session_keepalive(&c.s)
	// The service clamps the MSS of this peer's TCP connections to this value (IPv6: 20 less).
	c.mss4 = srv_mss(d, c)
	mss4 := u32(c.mss4)
	if c.dco.stream {
		// The service has had this TCP connection since accept. The peer takes the
		// registry's id and VPN addresses (the device routes by them), then its
		// keepalive values (keys go in as the session generates them).
		if !srv_dco_rename(d, c, id) {
			return false
		}
		if p.flags & (dco.PEER_VPN4 | dco.PEER_VPN6) != 0 {
			if st := dco_peer_set_addr(&c.dco, p.flags, p.vpn4, p.vpn6); st != 0 {
				logf(.Error, "client %s: %s refused the VPN addresses: %s", conn_label(c), dco_who(d.dco.kind), dco_why(&d.dco.link, st))
				return false
			}
		}
		dco_peer_set(&c.dco, u32(max(interval, 0)), u32(max(timeout, 0)), mss4)
	} else {
		dco_peer_set(&c.dco, u32(max(interval, 0)), u32(max(timeout, 0)), mss4)
		if c.proto == .Tcp {
			if !srv_dco_stream(d, c, &p) {
				return false
			}
		} else {
			fd := i32(-1)
			if !d.dco.link.fd_sent {
				fd = ln.sock.fd
			}
			if st := dco_peer_create(&c.dco, &p, fd); st != 0 {
				logf(.Error, "client %s: %s refused the peer: %s", conn_label(c), dco_who(d.dco.kind), dco_why(&d.dco.link, st))
				srv_dco_peer_failed(d, st)
				return false
			}
		}
		c.dco.last = {}
	}
	srv_dco_iroutes(d, c, true)
	logf(.Debug, "client %s: DCO peer %d, keepalive %d/%d s", conn_label(c), id, interval, timeout)
	return true
}

// The kernel could not create a peer because the device is gone (deleted while
// no peer was there to say so). The server takes the lost-backend path, from
// the loop, not from inside the login.
srv_dco_peer_failed :: proc(d: ^Srv, st: int) {
	if d.dco.kind == .Kernel && st == DCO_ENODEV && d.dco.on && !d.dco.t_gone.on {
		stimer_set(&d.loop, &d.dco.t_gone, now_srv(d), on_srv_dco_gone_timer, d)
	}
}

on_srv_dco_gone_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Srv)(user)
	d.dco.t_gone.on = false
	if d.dco.on && !d.finished {
		srv_dco_lost(d, true)
	}
}

// Next provisional id for a TCP connection: one of `prov_n` ids at the top of
// the range, in turn, skipping ids that a conn has. A message queued by the
// service for a gone peer may still come and must not meet a new conn with the
// same id, so ids are not reused soon.
srv_dco_prov_id :: proc(d: ^Srv) -> u32 {
	n := d.dco.prov_n
	for _ in 0 ..< n {
		id := u32(DCO_PROV_TOP) - d.dco.prov_next % n
		d.dco.prov_next += 1
		if id not_in d.dco.by_id {
			return id
		}
	}
	return u32(DCO_PROV_TOP) // not reached: a conn holds one id, and the table has `prov_n` slots
}

// Hand an accepted TCP connection to the service at once, before any read or
// write (the first record is ours to send, with CTRL_TX). The peer has a
// provisional id until login (`srv_dco_rename`).
// False: the service refused; the socket is still ours, the caller ends the conn.
srv_dco_early :: proc(d: ^Srv, c: ^Conn) -> bool {
	ln := &d.listeners[c.lidx]
	remote, rok := dco_sockaddr(session.peer_addr_bytes(&c.addr))
	if !rok {
		logf(.Error, "client %s: cannot use its address for %s", conn_label(c), dco_who(d.dco.kind))
		return false
	}
	p := dco.New_Peer {
		peer_id = srv_dco_prov_id(d),
		flags   = dco.PEER_REMOTE,
		remote  = remote,
	}
	if local, ok := srv_dco_local(c, ln); ok {
		p.flags |= dco.PEER_LOCAL
		p.local = local
	}
	st := dco_peer_create_stream(&c.dco, &p, c.sock.fd, nil)
	if c.dco.stream {
		// The service has its own copy of the socket and reads and writes from now on.
		net.close(c.sock)
		c.sock = net.INVALID_SOCKET
		c.sock_open = false
		c.want_write = false
		d.dco.by_id[p.peer_id] = c.slot
	}
	if st != 0 {
		logf(.Error, "client %s: %s refused the TCP peer: %s", conn_label(c), dco_who(d.dco.kind), dco_why(&d.dco.link, st))
		return false
	}
	logf(.Debug, "client %s: TCP connection handed to the DCO service at accept (provisional peer id %d)", conn_label(c), p.peer_id)
	return true
}

// Login accepted, registry id given: the peer of an early TCP connection takes
// it. Both ids map to the conn from here (earlier queued messages carry the
// provisional one).
srv_dco_rename :: proc(d: ^Srv, c: ^Conn, id: u32) -> bool {
	if st := dco_peer_rename(&c.dco, id); st != 0 {
		logf(.Error, "client %s: %s refused the peer id %d: %s", conn_label(c), dco_who(d.dco.kind), id, dco_why(&d.dco.link, st))
		return false
	}
	d.dco.by_id[id] = c.slot
	logf(.Debug, "client %s: DCO peer %d renamed to %d", conn_label(c), c.dco.old_id, id)
	return true
}

// TCP, late handover (service without `CAP_PEER_ID`): the connection goes to
// the service at login. Our queue is written first (the service writes after
// it), and the bytes the session read and did not use go along. Nothing of the
// login is lost: the push reply is queued only after this, and goes out with CTRL_TX.
srv_dco_stream :: proc(d: ^Srv, c: ^Conn, p: ^dco.New_Peer) -> bool {
	if !c.sock_open {
		logf(.Error, "client %s: no TCP connection to hand to %s", conn_label(c), dco_who(d.dco.kind))
		return false
	}
	tcp_write_now(c)
	if txq_pending(&c.q) > 0 {
		logf(.Error, "client %s: cannot hand the TCP connection to %s, because output is still waiting to be sent", conn_label(c), dco_who(d.dco.kind))
		return false
	}
	ahead := session.session_stream_take(&c.s)
	st := dco_peer_create_stream(&c.dco, p, c.sock.fd, ahead)
	if c.dco.stream {
		// The service has its own copy of the socket, and reads and writes from now on.
		event.remove_fd(&d.loop, c.sock.fd)
		net.close(c.sock)
		c.sock = net.INVALID_SOCKET
		c.sock_open = false
		c.want_write = false
		d.dco.by_id[c.dco.peer_id] = c.slot
	}
	if st != 0 {
		logf(.Error, "client %s: %s refused the TCP peer: %s", conn_label(c), dco_who(d.dco.kind), dco_why(&d.dco.link, st))
		return false
	}
	logf(.Debug, "client %s: TCP connection handed to %s, %d bytes read ahead", conn_label(c), dco_who(d.dco.kind), len(ahead))
	return true
}

// The conn of a TCP peer of the service, or nil.
srv_dco_conn :: proc(d: ^Srv, peer_id: u32) -> ^Conn {
	slot, ok := d.dco.by_id[peer_id]
	if !ok || slot >= u32(len(d.conns)) {
		return nil
	}
	c := d.conns[slot]
	if c == nil || !c.dco.stream || !dco_owns_id(&c.dco, peer_id) {
		return nil
	}
	return c
}

// The conn goes (`conn_release`): its peer ids are released.
srv_dco_forget :: proc(d: ^Srv, c: ^Conn) {
	if !c.dco.stream {
		return
	}
	if d.dco.by_id[c.dco.peer_id] == c.slot {
		delete_key(&d.dco.by_id, c.dco.peer_id)
	}
	if c.dco.has_old && d.dco.by_id[c.dco.old_id] == c.slot {
		delete_key(&d.dco.by_id, c.dco.old_id)
	}
}

// Runs one route change for a client. `add` false ignores a route that is not there.
srv_route_apply :: proc(d: ^Srv, c: ^Conn, r: sysnet.Route, add: bool, what: string) -> bool {
	err := sysnet.route_add(&d.sys, r, true) if add else sysnet.route_del(&d.sys, r)
	if err != .None && !(err == .Not_Found && !add) {
		logf(.Warn, "client %s: %s %s: %v", conn_label(c), what, "add" if add else "delete", err)
		return false
	}
	return true
}

// The routes that a client needs, from the peer table (`peer_routes`), or nil.
srv_client_routes :: proc(d: ^Srv, c: ^Conn, ifindex: u32, host: bool) -> []sysnet.Route {
	h := c.h
	if int(h.index) >= len(d.srv.reg.extra) {
		return nil
	}
	ex := &d.srv.reg.extra[h.index]
	pr := server.peers_get(&d.srv.reg.peers, h)
	if pr == nil {
		return nil
	}
	v4: Maybe([4]u8)
	v6: Maybe([16]u8)
	if pr.has4 {
		v4 = pr.vpn4
	}
	if pr.has6 {
		v6 = pr.vpn6
	}
	return peer_routes(ifindex, v4, v6, ex.iroutes4, ex.iroutes6, host, context.temp_allocator)
}

// Iroutes of a client (networks behind it). The service sends a packet to the
// client that owns its destination address, or whose address is the gateway of
// the route taken. Each iroute becomes a route through the client's VPN
// address, replacing the gatewayless route of the same network that the
// `route` option creates. `add` false removes them when the client goes.
// Service clients only; `tls` clients use `srv_tls_routes`.
srv_dco_iroutes :: proc(d: ^Srv, c: ^Conn, add: bool) {
	if !d.dco.on || c.tls || !c.registered {
		return
	}
	for r in srv_client_routes(d, c, d.ifindex, false) {
		srv_route_apply(d, c, r, add, "iroute for the DCO service")
	}
}

// Data path in this process: the kernel sends packets for a network behind a
// client to the tunnel device, so each iroute network gets a gatewayless route
// to the device (as the `route` option creates).
// - routes are added with no replace
// - an existing route (a `route` config line) stays, also when the client goes
// - the conn keeps only the routes this call created, and removes them on exit
// A failed add is a warning.
// (Service clients: `srv_dco_iroutes`; `tls` clients of a mixed server:
// `srv_tls_routes`.)
srv_user_iroutes :: proc(d: ^Srv, c: ^Conn, add: bool) {
	op :: proc(user: rawptr, r: sysnet.Route, add: bool) -> sysnet.Error {
		d := (^Srv)(user)
		return sysnet.route_add(&d.sys, r) if add else sysnet.route_del(&d.sys, r)
	}
	failures := make([dynamic]Iroute_Failure, context.temp_allocator)
	what := "add" if add else "delete"
	if !add {
		iroutes_remove(&c.uroutes, op, d, &failures)
		delete(c.uroutes)
		c.uroutes = nil
	} else {
		if d.dco.on || !c.registered || d.ifindex == 0 || len(c.uroutes) > 0 {
			return
		}
		routes := srv_user_route_list(d, c)
		c.uroutes = make([dynamic]sysnet.Route)
		n := iroutes_add(routes, d.cfg.max_routes_per_client, op, d, &c.uroutes, &failures)
		if n.capped > 0 {
			logf(.Warn, "client %s: %d iroute(s) have no kernel route, because they exceed max-routes-per-client", conn_label(c), n.capped)
		}
		for r in c.uroutes {
			logf(.Debug, "client %s: route %s on the tunnel device", conn_label(c), route_text(r))
		}
		if n.existed > 0 {
			logf(.Debug, "client %s: %d iroute(s) already have a kernel route", conn_label(c), n.existed)
		}
	}
	for f in failures {
		logf(.Warn, "client %s: iroute %s %s: %v", conn_label(c), route_text(f.route), what, f.err)
	}
}

// The routes that `srv_user_iroutes` wants for a client, in the temp allocator.
srv_user_route_list :: proc(d: ^Srv, c: ^Conn) -> []sysnet.Route {
	h := c.h
	if int(h.index) >= len(d.srv.reg.extra) {
		return nil
	}
	ex := &d.srv.reg.extra[h.index]
	pr := server.peers_get(&d.srv.reg.peers, h)
	if pr == nil {
		return nil
	}
	return iroute_device_routes(d.ifindex, pr.has4, pr.has6, ex.iroutes4, ex.iroutes6, context.temp_allocator)
}

// Routes of a `tls` client on the second device of a mixed server:
// - a host route per tunnel address (the kernel sends its packets here)
// - a route through its address per iroute network
// Needed before the push reply; removed when the client leaves (a route
// already gone is no error).
// False (add): a host route failed. Added routes are removed, the caller
// ends the login.
srv_tls_routes :: proc(d: ^Srv, c: ^Conn, add: bool) -> bool {
	if !d.dco.mixed || !c.tls || !c.registered || add == c.tls_routed {
		return true
	}
	routes := srv_client_routes(d, c, d.dco.ifindex, true)
	if add {
		for r, i in routes {
			is_host := r.gateway == nil
			if !srv_route_apply(d, c, r, true, "route on the tls device") && is_host {
				for j := i - 1; j >= 0; j -= 1 {
					srv_route_apply(d, c, routes[j], false, "route on the tls device")
				}
				return false
			}
			logf(.Debug, "client %s: route %s on %s", conn_label(c), route_text(r), d.dco.tun_name)
		}
		c.tls_routed = true
		return true
	}
	// The iroutes go before the host routes they use as their next hop.
	for i := len(routes) - 1; i >= 0; i -= 1 {
		srv_route_apply(d, c, routes[i], false, "route on the tls device")
		logf(.Debug, "client %s: route %s removed from %s", conn_label(c), route_text(routes[i]), d.dco.tun_name)
	}
	c.tls_routed = false
	return true
}

// A route for the log: `10.8.0.2/32`, `192.168.77.0/24 via 10.8.0.2`.
route_text :: proc(r: sysnet.Route) -> string {
	dst := ""
	switch a in r.dst {
	case sysnet.IP4_Address:
		dst = ip4_text(cast([4]u8)a)
	case sysnet.IP6_Address:
		dst = ip6_text(transmute([16]u8)a)
	}
	if gw, ok := r.gateway.?; ok {
		via := ""
		switch a in gw {
		case sysnet.IP4_Address:
			via = ip4_text(cast([4]u8)a)
		case sysnet.IP6_Address:
			via = ip6_text(transmute([16]u8)a)
		}
		return fmt.tprintf("%s/%d via %s", dst, r.dst_len, via)
	}
	return fmt.tprintf("%s/%d", dst, r.dst_len)
}

// Does the daemon count packets dropped for a wrong source address?
// - userspace path: yes
// - DCO service that reports drop reasons: yes
// - kernel driver: no, it has one count for all receive drops
srv_bad_source_known :: proc(d: ^Srv) -> bool {
	return !d.dco.on || d.dco.link.be.caps & dco.CAP_STATS_REASONS != 0
}

// Removes the peer of a client from the backend. Its addresses are free in the
// peer table by now, so the backend must not keep them for a session that only
// lingers to ack its last control packets (the kernel driver refuses a new peer
// with the same address; the service would hold two). Does nothing for a client
// that runs in this process.
srv_dco_peer_release :: proc(d: ^Srv, c: ^Conn) {
	if !d.dco.on || !conn_in_service(d, c) || !c.dco.created || c.dco.gone {
		return
	}
	dco_peer_delete(&c.dco)
}

// The counters of one client from the service: the numbers that the userspace
// path counts on the tun side.
srv_dco_refresh_conn :: proc(d: ^Srv, c: ^Conn) {
	if !d.dco.on || c.tls || !c.s_ok || !c.dco.created {
		return
	}
	delta, ok := dco_stats(&c.dco, &c.s, now_srv(d))
	if !ok {
		return
	}
	c.in_pkts += delta.vpn_rx_pkts
	c.in_bytes += delta.vpn_rx_bytes
	c.out_pkts += delta.vpn_tx_pkts
	c.out_bytes += delta.vpn_tx_bytes
	c.drops += delta.rx_drops + delta.tx_drops
	if d.srv_ok {
		d.srv.reg.counters[.Drop_Bad_Source] += delta.rx_src
	}
	s := &d.stats
	s.tun_write_pkts += delta.vpn_rx_pkts
	s.tun_write_bytes += delta.vpn_rx_bytes
	s.tun_read_pkts += delta.vpn_tx_pkts
	s.tun_read_bytes += delta.vpn_tx_bytes
	s.from_tun_pkts += delta.vpn_tx_pkts
	s.sent_pkts += delta.link_tx_pkts
	if c.dco.stream {
		// TCP: the service drops a data packet while the client's stream is blocked, as
		// our own queue does. On a stream a drop only means a slow client.
		s.drop_tcp_backlog += sub0(delta.tx_drops, delta.tx_no_key)
	} else {
		s.drop_tun_write += sub0(delta.tx_drops, delta.tx_no_key)
	}
	s.drop_seal += delta.tx_no_key
}

// The IPv6 packets that the service dropped since the last call (`block-ipv6`).
srv_dco_filter_refresh :: proc(d: ^Srv) {
	rx, tx := dco_filter_poll(&d.dco.link)
	d.stats.drop_block6_rx += rx
	d.stats.drop_block6_tx += tx
}

srv_dco_refresh_all :: proc(d: ^Srv) {
	if !d.dco.on || d.finished {
		return
	}
	srv_dco_filter_refresh(d)
	for c in d.conns {
		if c != nil {
			srv_dco_refresh_conn(d, c)
		}
	}
}

// After a session call: a command that the service refused ends that client.
srv_dco_check :: proc(d: ^Srv, c: ^Conn) {
	if c.tls || c.dco.err == 0 || !c.s_ok {
		return
	}
	logf(.Error, "client %s: %s failed %s: %s", conn_label(c), dco_who(d.dco.kind), c.dco.err_op, dco_err_text(&c.dco))
	c.dco.err = 0
	session.session_abort(&c.s, .Internal, "the DCO backend failed a command")
}

srv_dco_stats_arm :: proc(d: ^Srv) {
	if !d.dco.on {
		return
	}
	secs := DCO_STATS_SLOW
	if d.dco.kind == .Kernel && !d.dco.tcp {
		// A UDP peer that floats shows only in the poll (before Linux 7.1).
		secs = DCO_STATS_KERNEL
	}
	if d.cfg.tls.reneg_bytes > 0 || d.cfg.tls.reneg_pkts > 0 {
		secs = DCO_STATS_FAST
	}
	stimer_set(&d.loop, &d.dco.t_stats, now_srv(d) + time.Duration(secs) * time.Second, on_srv_dco_stats_timer, d)
}

on_srv_dco_stats_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Srv)(user)
	d.dco.t_stats.on = false
	if d.finished {
		return
	}
	srv_dco_filter_refresh(d)
	for slot in 0 ..< len(d.conns) {
		c := d.conns[slot]
		if c == nil || !c.dco.created {
			continue
		}
		srv_dco_refresh_conn(d, c)
		// A rekey by bytes or packets starts inside the report.
		conn_pump(d, c)
	}
	out_flush(d)
	flush_dirty(d)
	srv_dco_stats_arm(d)
}

// Gives the data channel UDP socket to a backend that takes it before the first
// peer (`attach`), while root. A failure is logged; the first peer tries again.
srv_dco_attach_early :: proc(d: ^Srv) {
	l := &d.dco.link
	if !l.up || !l.dev || d.dco.tcp || l.be.attach == nil {
		return
	}
	for i in 0 ..< d.n_listen {
		ln := &d.listeners[i]
		if ln.tls || ln.proto != .Udp {
			continue
		}
		if st := l.be.attach(l.be.user, ln.sock.fd); st != 0 {
			logf(.Warn, "%s cannot accept the socket before privileges are dropped: %s", dco_who(d.dco.kind), dco_why(l, st))
		}
		return
	}
}

// The listener closes (the end of the run): the service lets go of the socket.
srv_dco_detach :: proc(d: ^Srv) {
	l := &d.dco.link
	if l.up && l.dev && !d.dco.tcp {
		if st := l.be.detach(l.be.user); st != 0 {
			logf(.Debug, "DETACH: %s", dco_status_text(st))
		}
		l.fd_sent = false
	}
}

// The descriptor of the backend is readable: events, or the end of the connection.
on_srv_dco :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := (^Srv)(user)
	l := &d.dco.link
	for _ in 0 ..< 256 {
		ev: dco.Event
		r := l.be.next_event(l.be.user, &ev)
		if r == 0 {
			break
		}
		if r < 0 {
			srv_dco_lost(d)
			return
		}
		if ev.kind == .Ctrl_Rx {
			srv_dco_ctrl(d, &ev)
		} else {
			srv_dco_event(d, &ev)
		}
		if d.finished || !l.up {
			return
		}
	}
	out_flush(d)
	flush_dirty(d)
}

// A control record from the stream of a client that the service owns: the session
// takes it as it would take a frame from the conn's own socket.
srv_dco_ctrl :: proc(d: ^Srv, ev: ^dco.Event) {
	c := srv_dco_conn(d, ev.peer_id)
	if c == nil || !c.s_ok || c.dco.gone {
		return
	}
	cidx, sess := c.slot, c.sess
	dco_ctrl_receive(&d.dco.link, &c.s, now_srv(d))
	if d.conns[cidx] != c || c.sess != sess {
		return
	}
	conn_pump(d, c)
}

srv_dco_event :: proc(d: ^Srv, ev: ^dco.Event) {
	act := dco_classify(ev, d.dco.kind)
	if act == .None {
		return
	}
	c: ^Conn
	if d.dco.tcp {
		c = srv_dco_conn(d, ev.peer_id)
	} else {
		h, p := server.peers_by_id(&d.srv.reg.peers, ev.peer_id)
		c = conn_of_handle(d, h) if p != nil else nil
	}
	if c == nil || !c.s_ok || !c.dco.created || !dco_owns_id(&c.dco, ev.peer_id) {
		logf(.Debug, "DCO event for peer %d ignored (no such client)", ev.peer_id)
		return
	}
	switch act {
	case .None:
	case .Device_Gone:
		srv_dco_lost(d, true)
	case .Expired:
		dco_peer_dropped(&c.dco)
		logf(.Info, "client %s: no packet was received within the ping-restart time (%s)", conn_label(c), dco_who_short(d.dco.kind))
		session.session_abort(&c.s, .Ping_Timeout, fmt.tprintf("ping-restart (%s)", dco_who_short(d.dco.kind)))
		conn_pump(d, c)
	case .Link_Error:
		dco_peer_dropped(&c.dco)
		if c.dco.stream {
			// The client closed the stream, or it failed: what a read error or EOF on the
			// conn's own socket is (`srv_read_tcp`).
			if c.end == .None {
				c.end = .Tcp_Lost
			}
			if ev.reason == .Transport_Error {
				d.stats.sock_recv_errors += 1
			}
			logf(.Debug, "client %s: %s ended the TCP connection (%v)", conn_label(c), dco_who(d.dco.kind), ev.reason)
			conn_drop(d, c)
			return
		}
		logf(.Warn, "client %s: %s lost the link (%v)", conn_label(c), dco_who(d.dco.kind), ev.reason)
		session.session_abort(&c.s, .Link_Error, "the DCO backend lost the link")
		conn_pump(d, c)
	case .Key_Swap:
		logf(.Debug, "client %s: data key %d is nearly used up; renegotiating", conn_label(c), ev.key_id)
		session.session_ext_key_swap(&c.s, now_srv(d))
		conn_pump(d, c)
	case .Float:
		if addr, ok := dco_peer_addr(&ev.addr); ok {
			conn_float(d, c, session.peer_addr_bytes(&addr))
		}
	}
}

// The connection to the service is lost, and the device with it. The server
// stays up:
// - every session ends with RESTART (clients come back at once)
// - the data path runs in this process for the rest of the run
// - no return to the service
// A server that is already stopping goes on with the stop.
srv_dco_lost :: proc(d: ^Srv, device_gone := false) {
	who := dco_who(d.dco.kind)
	switch {
	case device_gone && d.stopping:
		logf(.Warn, "the kernel removed the ovpn device while the server was stopping")
	case device_gone:
		logf(.Error, "the kernel removed the ovpn device, so the server will end every session and run the data path in this process")
	case d.stopping:
		logf(.Warn, "the connection to the DCO service was lost while the server was stopping")
	case:
		logf(.Error, "the connection to the DCO service was lost, so the server will end every session and run the data path in this process")
	}
	if d.dco.link.watched {
		event.remove_fd(&d.loop, d.dco.link.be.fd)
	}
	dco_link_close(&d.dco.link)
	stimer_clear(&d.loop, &d.dco.t_stats)
	// No call to the service from here: not for a session that ends, not for a key.
	for c in d.conns {
		if c != nil {
			c.dco.gone = true
		}
	}
	// Off first: the routes of the clients went with the device, and no session asks
	// the service for numbers.
	d.dco.on = false
	if d.stopping {
		return
	}
	srv_dco_end_sessions(d)
	srv_dco_release_tls_device(d)
	srv_dco_reset(d)
	// The service's device took its addresses and routes along.
	if d.plan_ok {
		client.plan_destroy(&d.plan)
		d.plan_ok = false
	}
	if d.nc_ok {
		client.netcfg_destroy(&d.nc)
		d.nc_ok = false
	}
	d.ifindex = 0
	logf(.Notice, "the data path will run in this process from now on; restart the daemon to use %s again", who)
	srv_shared_in_process(d)
	if !srv_workers_start(d) {
		srv_dco_fatal(d, "the crypto workers cannot start")
		return
	}
	d.dco.tun_tries = 0
	srv_dco_own_tun(d)
}

// Every session ends. An established one gets RESTART (a UDP client reconnects
// at once; a TCP connection closes). Sessions the service owned (their socket
// went with it) and those not up yet are dropped.
srv_dco_end_sessions :: proc(d: ^Srv) {
	for slot in 0 ..< len(d.conns) {
		c := d.conns[slot]
		if c == nil {
			continue
		}
		if c.end == .None {
			c.end = .Datapath
		}
		c.detail_n = copy(c.detail[:], "the DCO service was lost")
		if c.up && !c.closing && c.s_ok && !c.dco.stream {
			conn_close(d, c, .Restart, .Datapath)
		} else {
			conn_drop(d, c)
		}
	}
	srv_flush_all(d)
	// What the service owned is gone with it.
	delete(d.dco.by_id)
	d.dco.by_id = nil
}

// A mixed server: the second tun device goes (the sessions are over, so its host
// routes are removed already).
srv_dco_release_tls_device :: proc(d: ^Srv) {
	if !d.dco.mixed {
		return
	}
	if d.dco.nc_ok {
		if failures := client.netcfg_teardown(&d.dco.nc); failures > 0 {
			logf(.Warn, "%d network changes on %s could not be undone", failures, d.dco.tun_name)
		}
	}
	if d.tun_open {
		srv_flush_tun(d)
		event.remove_fd(&d.loop, d.tun.fd)
		tun.close(&d.tun)
		d.tun_open = false
	}
	d.tun = {}
	d.tun.fd = -1
	d.tun_tx.on = false
	d.tun_paused = false
	d.tun_wk_wait = false
	logf(.Info, "tun device %s closed", d.dco.tun_name)
}

// What of `d.dco` is left once the service is not used: nothing.
srv_dco_reset :: proc(d: ^Srv) {
	srv_dco_destroy(d)
	d.dco = {}
}

// The server's own sessions take over the settings of the transports: the data
// channel is theirs, and `aead-epoch` can be negotiated.
srv_shared_in_process :: proc(d: ^Srv) {
	for i in 0 ..< len(d.shared) {
		if d.shared_ok[i] {
			session.server_shared_set_ext_data(&d.shared[i], false)
		}
	}
}

// Own tun device after the service was lost. The service removes its device
// when the connection closes, which takes a moment: a taken name is retried
// every DCO_TUN_RETRY, DCO_TUN_TRIES times. Any other failure ends the server.
srv_dco_own_tun :: proc(d: ^Srv) {
	if d.finished {
		return
	}
	d.dco.t_tun.on = false
	err, ok := srv_tun_open_own(d)
	if !ok {
		if err == .Busy && d.dco.tun_tries < DCO_TUN_TRIES {
			d.dco.tun_tries += 1
			logf(.Debug, "the tun device name %s is already in use, trying again (%d)", tun_name_of(d.cfg.dev), d.dco.tun_tries)
			stimer_set(&d.loop, &d.dco.t_tun, now_srv(d) + DCO_TUN_RETRY, on_srv_dco_tun_timer, d)
			return
		}
		if err != .None {
			logf(.Error, "cannot open the tun device %s: %v (needs CAP_NET_ADMIN and /dev/net/tun)", tun_name_of(d.cfg.dev), err)
		}
		srv_dco_fatal(d, "the tun device cannot be opened")
		return
	}
	if !srv_tun_setup(d) {
		srv_dco_fatal(d, "the tunnel cannot be set up")
		return
	}
	srv_log_mss(d)
}

on_srv_dco_tun_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	srv_dco_own_tun((^Srv)(user))
}

// The server cannot run in this process either.
srv_dco_fatal :: proc(d: ^Srv, detail: string) {
	if d.exit_code == .Ok {
		d.exit_code = .System
	}
	B.stop_reason, B.stop_detail = "error", detail
	srv_finish(d)
}
