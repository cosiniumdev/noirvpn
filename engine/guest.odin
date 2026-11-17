// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "base:intrinsics"
import "core:c"
import "core:encoding/json"
import cnet "core:net"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/crypt"
import "noir:proto/mss"
import "noir:proto/push"
import "noir:proto/session"

// Guest mode: the engine runs inside another program (iOS Packet Tunnel
// extension, Android VpnService, Linux test host), when `d.guest` is set. If nil,
// every daemon code path stays as it is.
//
// A guest has no `sysnet`, tun device, records, subprocess or file writes. The
// host does the network:
//
//	PUSH_REPLY -> plan -> settings object -> host.apply(seq, json)
//	host: establish() or setTunnelNetworkSettings
//	nvpn_settings_done(seq, ok) -> state `up`   (no reply in 30 s, or ok false:
//	                                             `stopped`, reason `system_error`)
//
// Tunnel packets, two forms:
// - Flow (iOS): the host pushes packets into a queue (`guest_push`); the engine
//   gives tunnel packets to `tun_write`.
// - Descriptor (Android, Linux test host): the host gives a tun descriptor
//   (`guest_set_fd`); the loop reads and writes it as in the daemon.
//
// Threads: only `guest_push` runs on a host thread (copies packets to a queue,
// wakes the loop). All else runs on the loop thread; `lib.odin` queues other host
// calls to it.

APPLY_WAIT :: 30 * time.Second
// Wait of a probe (a ping after a network change) for a server packet: ping
// interval + 3 s, at least 10 s, at most 30 s. A stock server does not reply to a
// ping, it only sends its own; a wait shorter than its interval would reconnect
// for nothing.
PROBE_MIN :: 10 * time.Second
PROBE_MAX :: 30 * time.Second
PROBE_SLACK :: 3 * time.Second

probe_wait :: proc(ping_secs: int) -> time.Duration {
	if ping_secs <= 0 {
		return PROBE_MIN
	}
	w := time.Duration(min(ping_secs, 3600)) * time.Second + PROBE_SLACK
	return clamp(w, PROBE_MIN, PROBE_MAX)
}
// A name lookup that takes this long is replaced by the last good addresses,
// while the tunnel of the system is in place.
RESOLVE_SLOW :: 5 * time.Second
// The clock that counts sleep runs ahead of the clock of the loop by more
// than this: the device slept.
WAKE_JUMP :: 5 * time.Second

// Packets that the host may queue before the loop takes them.
PUSH_SLOTS :: 256
// Packets for the tunnel that go to one `tun_write` call.
OUT_PKTS :: 64
PKT_SLOT :: SLOT_SIZE

// The callbacks of the host (noirvpn.h, nvpn_host). nil: the host has none.
Guest_Host :: struct {
	user:      rawptr,
	apply:     proc "c" (user: rawptr, seq: u64, json: cstring, n: c.int),
	protect:   proc "c" (user: rawptr, fd: c.int) -> c.int,
	tun_write: proc "c" (user: rawptr, pkts: [^][^]u8, lens: [^]c.int, afs: [^]c.int, count: c.int),
}

Pkt_Pool :: struct {
	buf:  []u8,
	lens: []int,
	n:    int,
}

Res_Job :: struct {
	gen:    u64,
	host:   string, // owned
	port:   u16,
	family: config.Family,
	// Android: the network to look the name up on (`handle` of nvpn_network);
	// 0 is the default network.
	net:    u64,
}

Res_Result :: struct {
	gen:   u64,
	addrs: []cnet.Address,
	ok:    bool,
}

// Helper thread for name lookups. One job at a time: a new job replaces one
// nobody has taken yet.
Resolver :: struct {
	th:      ^thread.Thread,
	sema:    sync.Sema,
	mu:      sync.Mutex,
	loop:    ^event.Loop,
	has_job: bool,
	stop:    bool,
	job:     Res_Job,
	results: [dynamic]Res_Result,
}

Guest :: struct {
	h:             Guest_Host,
	caps:          Caps,
	// The owner of this guest (lib.odin).
	lib:           rawptr,
	// The state of the apply and the network.
	next_seq:      u64,
	pending_seq:   u64, // an `apply` waits for the host
	have_applied:  bool,
	applied_key:   string, // owned: the settings object that is in place, without `remote` and `notes`
	host_nets:     []client.Host_Net, // owned
	net_up:        bool,
	// Android: the host network for name lookups (`handle`); 0: the default one.
	// While the VPN is up the default network is the VPN itself.
	net_handle:    u64,
	net_seen:      bool, // the host has reported the network at least once
	paused:        bool, // the network is `none`: no new attempt
	t_apply:       Timer,
	t_probe:       Timer,
	t_resolve:     Timer,
	probe_rx:      u64,
	last_up:       time.Duration,
	last_sleep:    time.Duration,
	err_buf:       [160]u8,
	err_n:         int,
	saved_off:     Off_Config,
	// Name lookups.
	res_gen:       u64,
	resolving:     bool,
	rs:            Resolver,
	rs_started:    bool,
	// Flow, towards the host.
	out_buf:       []u8,
	out_len:       [OUT_PKTS]int,
	out_n:         int,
	// Flow, from the host. `mu` guards the queue; `ready` and the counters are
	// atomic.
	mu:            sync.Mutex,
	q:             [2]Pkt_Pool,
	q_cur:         int,
	ready:         bool,
	push_full:     u64,
	push_down:     u64,
	push_bad:      u64,
}

// ------------------------------------------------------------- set up, tear down

// Creates the guest of `d`. Call it before `daemon_init`. `d.loop` does not exist
// yet; the resolver finds it when its first job comes.
guest_attach :: proc(d: ^Daemon, g: ^Guest) {
	d.guest = g
	g.net_up = true
	g.saved_off = OFF
	// The phone preset: no offloads. One variable for the process.
	OFF = {}
	g.out_buf = make([]u8, OUT_PKTS * PKT_SLOT)
	for i in 0 ..< 2 {
		g.q[i] = Pkt_Pool {
			buf  = make([]u8, PUSH_SLOTS * PKT_SLOT),
			lens = make([]int, PUSH_SLOTS),
		}
	}
	g.last_up = event.now()
	g.last_sleep = sleep_clock()
}

guest_destroy :: proc(d: ^Daemon) {
	g := d.guest
	if g == nil {
		return
	}
	if g.rs_started {
		sync.mutex_lock(&g.rs.mu)
		g.rs.stop = true
		sync.mutex_unlock(&g.rs.mu)
		sync.sema_post(&g.rs.sema)
		thread.join(g.rs.th)
		thread.destroy(g.rs.th)
		delete(g.rs.job.host)
		for r in g.rs.results {
			delete(r.addrs)
		}
		delete(g.rs.results)
		g.rs_started = false
	}
	OFF = g.saved_off
	delete(g.out_buf)
	for i in 0 ..< 2 {
		delete(g.q[i].buf)
		delete(g.q[i].lens)
	}
	delete(g.applied_key)
	delete(g.host_nets)
	g.applied_key, g.host_nets = "", nil
	d.guest = nil
}

// The loop of a guest. It is `daemon_run` plus one call after each wake-up:
// `after` takes what the host queued (lib.odin).
guest_run :: proc(d: ^Daemon, after: proc(d: ^Daemon)) {
	schedule(d)
	for !d.exit {
		if _, err := event.wait(&d.loop); err != .None {
			logf(.Error, "event loop failed: %v", err)
			shutdown(d)
			break
		}
		guest_tick(d)
		after(d)
		guest_flush_out(d)
		free_all(context.temp_allocator)
	}
}

// ---------------------------------------------------------------- the settings

// Builds the plan of the push, turns it into the settings object, gives it to
// the host. `pending`: the host must reply before the tunnel is up. False for
// `ok` after `fatal`.
guest_apply_network :: proc(d: ^Daemon, po: ^push.Pushed_Options) -> (pending: bool, ok: bool) {
	g := d.guest
	conn := &d.cfg.connections[d.conn_idx]
	// The routes with `net_gateway` need a default route. The host has its own,
	// so the plan gets a stand-in; those routes go to the `exclude` lists.
	input := client.Plan_Input {
		cfg       = d.cfg,
		pushed    = po,
		default4  = client_default_route(false),
		default6  = client_default_route(true),
		host_nets = g.host_nets,
	}
	plan, perr := guest_plan_build(input, conn.tun_mtu)
	if perr != .None {
		fatal(d, .Network, "cannot use the pushed settings: %v", perr)
		return false, false
	}
	for n in plan.notes {
		logf(.Notice if plan_note_for_user(n.kind) else .Info, "%s", n.text)
	}
	in_ := Settings_In {
		plan      = &plan,
		caps      = g.caps,
		host_nets = g.host_nets,
		block6    = d.block6,
		remote    = d.endpoint.address,
		core_only = true,
	}
	key := settings_text(in_)
	same := g.have_applied && d.plan_ok && key == g.applied_key && client.plan_equal(&plan, &d.plan) && dns_equal(plan, d.plan)
	if d.plan_ok {
		client.plan_destroy(&d.plan)
	}
	d.plan = plan
	d.plan_ok = true
	d.applied = true
	d.applied_to = d.endpoint.address
	if same {
		delete(key)
		logf(.Info, "the network settings have not changed, so they were not applied again")
		return false, true
	}
	delete(g.applied_key)
	g.applied_key = key
	in_.core_only = false
	text := settings_text(in_)
	defer delete(text)
	g.next_seq += 1
	g.pending_seq = g.next_seq
	g.have_applied = true
	timer_set(d, &g.t_apply, now_of(d) + APPLY_WAIT, on_apply_timer)
	logf(.Notice, "sending the network settings to the host (seq %d)", g.pending_seq)
	if g.h.apply != nil {
		ctext := strings.clone_to_cstring(text, context.temp_allocator)
		g.h.apply(g.h.user, g.pending_seq, ctext, c.int(len(text)))
	}
	return true, true
}

// The settings object as text, on the heap.
settings_text :: proc(in_: Settings_In) -> string {
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)
	settings_write(&w, in_)
	return strings.clone(bus.writer_string(&w))
}

client_default_route :: proc(v6: bool) -> Maybe(sysnet.Route) {
	r := sysnet.Route {
		dst     = sysnet.default_dst(.V6 if v6 else .V4),
		family  = .V6 if v6 else .V4,
		ifindex = 1,
		kind    = .Unicast,
	}
	return r
}

on_apply_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.guest.t_apply.on = false
	if d.guest.pending_seq == 0 {
		return
	}
	d.guest.pending_seq = 0
	guest_apply_failed(d, "the host did not respond in time")
}

// The host refused the settings, or did not reply: the run stops with
// `system_error`.
guest_apply_failed :: proc(d: ^Daemon, why: string) {
	g := d.guest
	g.err_n = copy(g.err_buf[:], why)
	d.detail_next = string(g.err_buf[:g.err_n])
	fatal(d, .System, "the host did not apply the network settings: %s", why)
}

// `nvpn_settings_done`.
guest_settings_done :: proc(d: ^Daemon, seq: u64, ok: bool, err: string) {
	g := d.guest
	if seq == 0 || seq != g.pending_seq {
		return
	}
	g.pending_seq = 0
	timer_clear(d, &g.t_apply)
	if !ok {
		guest_apply_failed(d, err if err != "" else "no reason given")
		return
	}
	intrinsics.atomic_store(&g.ready, true)
	if d.up || !d.s_ok || d.state != .Active || d.end.pending || d.close_reason != .None {
		return
	}
	po := session.session_pushed(&d.s)
	if po != nil {
		handle_up_finish(d, po)
	}
}

// Called from `teardown_network`: the tunnel of the system goes away.
guest_teardown :: proc(d: ^Daemon) {
	g := d.guest
	g.pending_seq = 0
	g.have_applied = false
	delete(g.applied_key)
	g.applied_key = ""
	timer_clear(d, &g.t_apply)
	timer_clear(d, &g.t_probe)
	intrinsics.atomic_store(&g.ready, false)
}

// ------------------------------------------------------------------ the tun

// The descriptor of the host (Android, the Linux test host).
guest_set_fd :: proc(d: ^Daemon, fd: i32) {
	if d.tun_open {
		tun_unwatch(d)
		tun_close_dev(&d.tun)
		d.tun_open = false
	}
	dev, ok := tun_from_fd(fd)
	if !ok {
		logf(.Error, "cannot use the tun descriptor of the host")
		guest_close_fd(fd)
		return
	}
	d.tun = dev
	d.tun_open = true
	d.tun_tx.on = false
	if err := tun_watch(d); err != .None {
		logf(.Error, "cannot watch the tun descriptor: %v", err)
		tun_unwatch(d)
		tun_close_dev(&d.tun)
		d.tun_open = false
		return
	}
	intrinsics.atomic_store(&d.guest.ready, true)
	logf(.Info, "received the tun descriptor from the host")
}

// A packet of the tunnel, for the host (flow). It is copied: the memory of the
// packet is used again by the next read.
guest_flow_write :: proc(d: ^Daemon, pkt: []u8) {
	g := d.guest
	if len(pkt) == 0 || len(pkt) > PKT_SLOT {
		d.stats.drop_tun_write += 1
		return
	}
	if !intrinsics.atomic_load(&g.ready) {
		d.stats.drop_rx_not_up += 1
		return
	}
	if g.out_n >= OUT_PKTS {
		guest_flush_out(d)
	}
	slot := g.out_buf[g.out_n * PKT_SLOT:][:PKT_SLOT]
	copy(slot, pkt)
	if d.mss4 != 0 {
		mss.clamp_syn(slot[:len(pkt)], d.mss4)
	}
	g.out_len[g.out_n] = len(pkt)
	g.out_n += 1
}

// Gives the packets that wait to the host in one call.
guest_flush_out :: proc(d: ^Daemon) {
	g := d.guest
	if g == nil || g.out_n == 0 {
		return
	}
	pkts: [OUT_PKTS][^]u8
	lens: [OUT_PKTS]c.int
	afs: [OUT_PKTS]c.int
	n := g.out_n
	g.out_n = 0
	for i in 0 ..< n {
		p := g.out_buf[i * PKT_SLOT:][:g.out_len[i]]
		pkts[i] = raw_data(p)
		lens[i] = c.int(len(p))
		afs[i] = AF_INET6 if len(p) > 0 && p[0] >> 4 == 6 else AF_INET
		d.stats.tun_write_pkts += 1
		d.stats.tun_write_bytes += u64(len(p))
	}
	if g.h.tun_write != nil {
		g.h.tun_write(g.h.user, raw_data(pkts[:]), raw_data(lens[:]), raw_data(afs[:]), c.int(n))
	}
}

AF_INET :: 2
AF_INET6 :: 30

// From a host thread: copies the packets into the queue and wakes the loop.
// Returns the number of packets taken. The rest are dropped and counted.
guest_push :: proc(g: ^Guest, loop: ^event.Loop, pkts: [^][^]u8, lens: [^]c.int, count: int) -> int {
	if count <= 0 {
		return 0
	}
	if !intrinsics.atomic_load(&g.ready) {
		intrinsics.atomic_add(&g.push_down, u64(count))
		return 0
	}
	took := 0
	bad := 0
	sync.mutex_lock(&g.mu)
	p := &g.q[g.q_cur]
	for i in 0 ..< count {
		n := int(lens[i])
		if n <= 0 || n > PKT_SLOT || pkts[i] == nil {
			bad += 1
			continue
		}
		if p.n >= PUSH_SLOTS {
			break
		}
		copy(p.buf[p.n * PKT_SLOT:][:n], pkts[i][:n])
		p.lens[p.n] = n
		p.n += 1
		took += 1
	}
	sync.mutex_unlock(&g.mu)
	if bad > 0 {
		intrinsics.atomic_add(&g.push_bad, u64(bad))
	}
	if rest := count - took - bad; rest > 0 {
		intrinsics.atomic_add(&g.push_full, u64(rest))
	}
	if took > 0 {
		event.wake(loop)
	}
	return took
}

// The loop takes the queued packets and seals them like packets read from a
// tun device.
guest_pump_push :: proc(d: ^Daemon) {
	g := d.guest
	sync.mutex_lock(&g.mu)
	p := &g.q[g.q_cur]
	g.q_cur ~= 1
	sync.mutex_unlock(&g.mu)
	if p.n == 0 {
		return
	}
	for i in 0 ..< p.n {
		pkt := p.buf[i * PKT_SLOT:][:p.lens[i]]
		slot := ring_next(&d.ring)
		room := slot.buf[session.TUNNEL_HEADROOM:][:MAX_TUN_PACKET]
		if len(pkt) > len(room) {
			d.stats.drop_oversize += 1
			continue
		}
		copy(room, pkt)
		d.stats.tun_read_pkts += 1
		d.stats.tun_read_bytes += u64(len(pkt))
		if !tun_flows(d) {
			d.stats.drop_not_up += 1
			continue
		}
		if d.block6 && is_ipv6(room[:len(pkt)]) {
			d.stats.drop_block6_tx += 1
			continue
		}
		if d.mss4 != 0 {
			mss.clamp_syn(room[:len(pkt)], d.mss4)
		}
		slot.n = len(pkt)
		ring_commit(&d.ring)
		if d.ring.count + 2 > RING_SLOTS {
			flush_tx(d)
		}
	}
	p.n = 0
	d.stats.drop_ring = d.ring.dropped
	flush_tx(d)
	pump(d)
}

// The counters of the queue, for `stats.get`.
guest_write_stats :: proc(w: ^bus.Writer, g: ^Guest) {
	bus.kv_u64(w, "push_drop_full", intrinsics.atomic_load(&g.push_full))
	bus.kv_u64(w, "push_drop_down", intrinsics.atomic_load(&g.push_down))
	bus.kv_u64(w, "push_drop_bad", intrinsics.atomic_load(&g.push_bad))
}

// -------------------------------------------------------------------- sockets

// A socket of the engine goes outside the tunnel: `protect` (Android). True
// when there is nothing to do, or it is done.
guest_protect :: proc(d: ^Daemon, fd: i32) -> bool {
	if d.guest == nil || d.guest.h.protect == nil {
		return true
	}
	if d.guest.h.protect(d.guest.h.user, c.int(fd)) != 0 {
		logf(.Warn, "the host did not protect the socket")
		return false
	}
	return true
}

// A new UDP socket for the same server, after a change of the network (the
// server floats the peer by its peer id). False: the old socket stays.
guest_rebind_udp :: proc(d: ^Daemon) -> bool {
	family: net.Family = .V6 if is_v6(d.endpoint.address) else .V4
	opts := net.UDP_Options {
		recv_buffer = d.cfg.rcvbuf if d.cfg.rcvbuf > 0 else SOCKET_BUFFER,
		send_buffer = d.cfg.sndbuf if d.cfg.sndbuf > 0 else SOCKET_BUFFER,
	}
	sock, err := net.udp_open(family, opts)
	if err != .None {
		logf(.Warn, "cannot open a UDP socket: %v", err)
		return false
	}
	if !guest_protect(d, sock.fd) || net.connect(sock, d.endpoint) != .None {
		net.close(sock)
		return false
	}
	if aerr := event.add_fd(&d.loop, sock.fd, {.Read}, on_socket, d); aerr != .None {
		net.close(sock)
		return false
	}
	if d.sock_open {
		event.remove_fd(&d.loop, d.sock.fd)
		net.close(d.sock)
	}
	d.sock = sock
	d.sock_open = true
	d.want_write = false
	d.blocked = false
	return true
}

// ------------------------------------------------------------------- network

// What `nvpn_network` says.
Net_Msg :: struct {
	up:        bool,
	have_nets: bool,
	nets:      []client.Host_Net, // owned by the message
	wake:      bool,
	// Android: the network handle of the host network (Network.getNetworkHandle);
	// 0 when the report has none.
	handle:    u64,
}

net_msg_destroy :: proc(m: ^Net_Msg) {
	delete(m.nets)
	m^ = {}
}

// Reads `{"state":"none"|"up","host_nets":[...],"wake":bool,"handle":n}`.
net_msg_parse :: proc(text: []u8) -> (m: Net_Msg, ok: bool) {
	root, parsed := bus.parse_json(text, context.temp_allocator)
	if !parsed {
		return {}, false
	}
	obj, is_obj := root.(json.Object)
	if !is_obj {
		return {}, false
	}
	state, _ := obj["state"].(json.String)
	switch state {
	case "up":
		m.up = true
	case "none":
	case:
		return {}, false
	}
	if wake, has := obj["wake"].(json.Boolean); has {
		m.wake = wake
	}
	// A JSON number is a float: a handle above 2^53 would lose bits. Android
	// handles are (netId << 32) | 0xfacade, with a small netId, so they fit.
	#partial switch h in obj["handle"] {
	case json.Integer:
		if h > 0 {
			m.handle = u64(h)
		}
	case json.Float:
		if h > 0 && h < 9007199254740992 {
			m.handle = u64(h)
		}
	}
	if arr, has := obj["host_nets"].(json.Array); has {
		m.have_nets = true
		list := make([dynamic]client.Host_Net)
		for e in arr {
			s, is_str := e.(json.String)
			if !is_str {
				delete(list)
				return {}, false
			}
			n, nok := host_net_parse(s)
			if !nok {
				delete(list)
				return {}, false
			}
			append(&list, n)
		}
		m.nets = list[:]
	}
	return m, true
}

host_net_parse :: proc(s: string) -> (n: client.Host_Net, ok: bool) {
	slash := strings.index_byte(s, '/')
	if slash <= 0 {
		return {}, false
	}
	addr := cnet.parse_address(s[:slash])
	if addr == nil {
		return {}, false
	}
	bits, bok := parse_small_int(s[slash + 1:])
	if !bok {
		return {}, false
	}
	switch a in addr {
	case cnet.IP4_Address:
		if bits > 32 {
			return {}, false
		}
		o := cast([4]u8)a
		copy(n.addr[:], o[:])
	case cnet.IP6_Address:
		if bits > 128 {
			return {}, false
		}
		n.addr = transmute([16]u8)a
		n.v6 = true
	}
	n.bits = u8(bits)
	n.addr = net_masked(n.addr, bits)
	return n, true
}

parse_small_int :: proc(s: string) -> (v: int, ok: bool) {
	if len(s) == 0 || len(s) > 3 {
		return 0, false
	}
	for ch in transmute([]u8)s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		v = v * 10 + int(ch - '0')
	}
	return v, true
}

// The same networks, in any order. The host may list them in another order
// each time it reports a path update.
nets_equal :: proc(a, b: []client.Host_Net) -> bool {
	for x in a {
		found := false
		for y in b {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for y in b {
		found := false
		for x in a {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Does a network report (state `up`) need a probe? Only a new or returned
// network, a new network list, or a wake-up. The same state with the same
// networks and no `wake` does nothing: the host reports path updates often.
net_needs_probe :: proc(was_paused, nets_changed, wake: bool) -> bool {
	return was_paused || nets_changed || wake
}

// `nvpn_network`.
guest_network :: proc(d: ^Daemon, m: Net_Msg) {
	g := d.guest
	prev_up := g.net_up
	// The first report is the base: there is nothing to compare it with, and the
	// connection that is starting was started on this network.
	first := !g.net_seen
	g.net_seen = true
	nets_changed := m.have_nets && !first && !nets_equal(g.host_nets, m.nets)
	if m.have_nets {
		delete(g.host_nets)
		g.host_nets = make([]client.Host_Net, len(m.nets))
		copy(g.host_nets, m.nets)
	}
	if m.handle != 0 {
		g.net_handle = m.handle
	}
	if !m.up {
		if prev_up {
			logf(.Notice, "network: none (paused)")
		}
		g.net_up = false
		g.paused = true
		return
	}
	g.net_up = true
	was_paused := g.paused
	g.paused = false
	if (nets_changed || (first && m.have_nets)) && d.s_ok && d.up && d.close_reason == .None {
		// The networks of the host changed: build the plan again.
		po := session.session_pushed(&d.s)
		if po != nil {
			if _, ok := guest_apply_network(d, po); !ok {
				return
			}
		}
	}
	if net_needs_probe(was_paused, nets_changed, m.wake) {
		logf(.Notice, "network: up%s", " (wake)" if m.wake else "")
		guest_probe(d)
	}
}

// The device slept: the same probe as for a new network.
guest_tick :: proc(d: ^Daemon) {
	g := d.guest
	up, sl := event.now(), sleep_clock()
	if g.last_sleep != 0 && sl != 0 && (sl - g.last_sleep) - (up - g.last_up) > WAKE_JUMP && g.net_up {
		logf(.Notice, "the device was asleep, checking the connection")
		guest_probe(d)
	}
	g.last_up, g.last_sleep = up, sl
}

// Network is new or back: UDP - new socket and a ping (the server floats the
// peer by peer id); no server packet in 10 s reconnects. TCP and `tls` -
// reconnect. A connection that is not up is started again.
guest_probe :: proc(d: ^Daemon) {
	g := d.guest
	switch {
	case d.shutting || d.exit:
	case d.state == .Idle:
		if !d.hold && !d.s_ok {
			client.policy_outcome(&d.policy, .Local_Restart, now_of(d))
			timer_set(d, &d.t_policy, now_of(d), on_policy_timer)
		}
	case d.close_reason != .None || d.end.pending:
	case d.state == .Active && d.up && d.proto == .Udp:
		if !guest_rebind_udp(d) {
			fail_connection(d, .Local_Restart, {})
			return
		}
		c := session.session_counters(&d.s)
		g.probe_rx = c.link_rx_pkts
		guest_send_ping(d)
		timer_set(d, &g.t_probe, now_of(d) + probe_wait(max(d.s.ping, d.s.ext_ping)), on_probe_timer)
	case:
		fail_connection(d, .Local_Restart, {})
	}
}

guest_send_ping :: proc(d: ^Daemon) {
	slot := ring_next(&d.ring)
	plain, ok := crypt.build_ping(slot.buf[session.TUNNEL_HEADROOM:])
	if !ok {
		return
	}
	pkt, err := session.session_encap(&d.s, slot.buf[:], len(plain), now_of(d))
	if err == .None {
		send_link(d, pkt)
	}
}

on_probe_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	g := d.guest
	g.t_probe.on = false
	if !d.s_ok || !d.up || d.close_reason != .None {
		return
	}
	c := session.session_counters(&d.s)
	if c.link_rx_pkts == g.probe_rx {
		logf(.Notice, "no reply from the server after the network changed, so reconnecting")
		fail_connection(d, .Local_Restart, {})
	}
}

// ---------------------------------------------------------------- name lookups

// A `.Resolve` action. An address literal is used at once. A name goes to the
// helper thread; the result comes back as an event of the loop.
guest_resolve :: proc(d: ^Daemon, a: client.Action) {
	g := d.guest
	if g.resolving {
		return
	}
	if addr := cnet.parse_address(a.host); addr != nil {
		event.update_time(&d.loop)
		client.policy_resolved(&d.policy, {addr}, true, now_of(d))
		schedule(d)
		return
	}
	g.resolving = true
	g.res_gen += 1
	rs := &g.rs
	if !g.rs_started {
		rs.loop = &d.loop
		rs.th = thread.create_and_start_with_data(rs, resolver_main)
		g.rs_started = true
	}
	sync.mutex_lock(&rs.mu)
	delete(rs.job.host)
	rs.job = Res_Job {
		gen    = g.res_gen,
		host   = strings.clone(a.host),
		port   = a.port,
		family = a.family,
		net    = g.net_handle,
	}
	rs.has_job = true
	sync.mutex_unlock(&rs.mu)
	sync.sema_post(&rs.sema)
	// A slow lookup, with the tunnel of the system in place: the last good
	// addresses are used.
	if g.have_applied {
		timer_set(d, &g.t_resolve, now_of(d) + RESOLVE_SLOW, on_resolve_timer)
	}
}

resolver_main :: proc(data: rawptr) {
	rs := (^Resolver)(data)
	for {
		sync.sema_wait(&rs.sema)
		sync.mutex_lock(&rs.mu)
		if rs.stop {
			sync.mutex_unlock(&rs.mu)
			return
		}
		if !rs.has_job {
			sync.mutex_unlock(&rs.mu)
			continue
		}
		job := rs.job
		job.host = strings.clone(rs.job.host)
		rs.has_job = false
		sync.mutex_unlock(&rs.mu)
		addrs, ok := guest_lookup(job)
		delete(job.host)
		sync.mutex_lock(&rs.mu)
		append(&rs.results, Res_Result{gen = job.gen, addrs = addrs, ok = ok})
		sync.mutex_unlock(&rs.mu)
		event.wake(rs.loop)
	}
}

on_resolve_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	g := d.guest
	g.t_resolve.on = false
	if !g.resolving || !client.policy_has_known(&d.policy) {
		return
	}
	logf(.Warn, "the name lookup is slow, so the addresses from the last lookup will be used")
	g.resolving = false
	g.res_gen += 1
	event.update_time(&d.loop)
	client.policy_resolved(&d.policy, nil, false, now_of(d))
	schedule(d)
}

// Takes the results of the helper thread (loop thread).
guest_take_results :: proc(d: ^Daemon) {
	g := d.guest
	if !g.rs_started {
		return
	}
	sync.mutex_lock(&g.rs.mu)
	list := g.rs.results
	g.rs.results = {}
	sync.mutex_unlock(&g.rs.mu)
	for r in list {
		if !g.resolving || r.gen != g.res_gen {
			delete(r.addrs)
			continue
		}
		g.resolving = false
		timer_clear(d, &g.t_resolve)
		event.update_time(&d.loop)
		kept := client.policy_resolved(&d.policy, r.addrs, r.ok, now_of(d))
		if kept {
			logf(.Warn, "cannot resolve the server name, so the addresses from the last lookup will be used")
		} else if !r.ok {
			logf(.Warn, "cannot resolve the server name")
		}
		delete(r.addrs)
		schedule(d)
	}
	delete(list)
}
