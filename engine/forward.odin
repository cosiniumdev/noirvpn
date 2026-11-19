// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import cnet "core:net"
import "core:time"
import "noir:bus"
import "noir:platform/event"
import "noir:platform/net"
import "noir:proto/config"
import "noir:proto/push"

// `forward <port> [tcp] [udp] to <host>:<port>`: a socket relay on the loop
// thread. A tunnel peer connects to the tunnel address, the daemon accepts and
// opens its own socket to the target, and copies the bytes both ways.
//
//	handle_up_finish -> forward_up -> fwd_listen -> fwd_bind       (tunnel addresses only;
//	                                                                on Linux also the tunnel device)
//	listener readable -> fwd_on_accept -> fwd_new_conn
//	                       target known?  -> fwd_conn_start -> fwd_conn_try_connect
//	                       else           -> fwd_resolve (helper thread, forward_lookup.odin)
//	                                         fwd_on_look (loop timer) -> fwd_conn_start
//	target writable -> fwd_conn_ready -> fwd_conn_connected -> both sockets copy
//	copy: fwd_conn_read -> fwd_conn_flush; half close and errors -> fwd_conn_settle / fwd_conn_close
//	finish_connection, teardown_network -> forward_down -> every socket closes
//
// UDP is in forward_udp.odin. The `fwd_*` fields of `stats.get` and the
// `acl.forward` events are written here.

FWD_BUF :: 64 * 1024
FWD_MAX_ADDRS :: 4
FWD_CONNECT_LIMIT :: 10 * time.Second
FWD_LOOKUP_TTL :: 30 * time.Second
FWD_UDP_IDLE :: 60 * time.Second
// After one side of a TCP connection ended: the time with no bytes moved until
// the relay closes the pair.
FWD_HALF_IDLE :: 120 * time.Second
FWD_BIND_RETRY :: 15 * time.Second
FWD_TICK :: time.Second
// `acl.forward` events in one second; the others are counted in the next one.
FWD_EVENTS :: 20
// The least time between two warnings of one kind.
FWD_WARN_GAP :: 10 * time.Second
FWD_ACCEPT_BURST :: 32

FWD_PEER :: 0
FWD_TARGET :: 1

Fwd_Reason :: enum u8 {
	Eof,
	Peer_Reset,
	Target_Reset,
	Connect_Failed,
	Lookup_Failed,
	Timeout,
	Idle,
	Tunnel_Down,
	Replaced,
	// The loop cannot watch one more descriptor.
	Refused,
}

FWD_REASON_TEXT := [Fwd_Reason]string {
	.Eof            = "eof",
	.Peer_Reset     = "peer_reset",
	.Target_Reset   = "target_reset",
	.Connect_Failed = "connect_failed",
	.Lookup_Failed  = "lookup_failed",
	.Timeout        = "timeout",
	.Idle           = "idle",
	.Tunnel_Down    = "tunnel_down",
	.Replaced       = "replaced",
	.Refused        = "refused",
}

// The fields of `stats.get`, with the prefix `fwd_`. `conns` and `udp_sessions`
// are the numbers now.
Fwd_Stats :: struct {
	conns:        u64,
	udp_sessions: u64,
	opened:       u64,
	refused:      u64,
	failed:       u64,
	bytes_in:     u64, // peer to target
	bytes_out:    u64, // target to peer
}

Fwd_Warn :: enum u8 {
	Limit,
	Accept,
	Register,
}

// One `forward` line, with its target.
Fwd_Line :: struct {
	f:       config.Forward,
	text:    string, // owned: host:port, for logs
	literal: bool, // the target is an address
	addrs:   [FWD_MAX_ADDRS]cnet.Address,
	n:       int,
	// A name: the lookup result is good until this time (loop clock).
	until:   time.Duration,
	pending: bool, // a lookup runs
}

Fwd_Listener :: struct {
	fw:     ^Fwd,
	line:   int,
	id:     u16,
	udp:    bool,
	sock:   net.Socket,
	ep:     cnet.Endpoint,
	paused: bool, // accept failed: off the loop until the next tick
}

// A bind that failed because the address is not ready (IPv6 duplicate address
// detection), tried again each tick.
Fwd_Retry :: struct {
	line: int,
	udp:  bool,
	addr: cnet.Address,
}

// One direction of a connection: bytes read from `sock[d]` wait for `sock[1 - d]`.
Fwd_Pipe :: struct {
	buf:  []u8,
	head: int,
	end:  int,
	eof:  bool, // the source ended
	shut: bool, // the end was passed on to the other socket
}

Fwd_State :: enum u8 {
	Resolving,
	Connecting,
	Open,
}

Fwd_Conn :: struct {
	fw:        ^Fwd,
	lst:       ^Fwd_Listener,
	line:      int,
	idx:       int,
	state:     Fwd_State,
	sock:      [2]net.Socket,
	reg:       [2]bool, // the socket is in the loop
	ints:      [2]event.Interest,
	pipe:      [2]Fwd_Pipe,
	peer:      cnet.Endpoint,
	target:    cnet.Endpoint,
	addrs:     [FWD_MAX_ADDRS]cnet.Address,
	n:         int,
	next:      int, // the next address to try
	born:      time.Duration,
	last:      time.Duration, // after one side ended: the last time bytes moved
	opened:    bool, // the `open` event was given
	bytes_in:  u64,
	bytes_out: u64,
}

Fwd :: struct {
	d:             ^Daemon,
	lines:         []Fwd_Line,
	lst:           [dynamic]^Fwd_Listener,
	next_lst:      u16,
	conns:         [dynamic]^Fwd_Conn,
	udp:           [dynamic]^Fwd_Udp,
	udp_map:       map[Fwd_Udp_Key]^Fwd_Udp,
	// One buffer for every UDP read.
	rx:            []u8,
	max:           int,
	// The device that the listeners are limited to (forward_linux.odin), or
	// none.
	dev:           [16]u8,
	dev_n:         int,
	retries:       [dynamic]Fwd_Retry,
	retry_until:   time.Duration,
	stats:         Fwd_Stats,
	lookups:       int, // lookups started
	t_tick:        Timer,
	t_look:        Timer,
	lk:            Fwd_Lookup,
	// The times; tests set shorter ones.
	udp_idle:      time.Duration,
	half_idle:     time.Duration,
	connect_limit: time.Duration,
	lookup_ttl:    time.Duration,
	tick:          time.Duration,
	warned:        [Fwd_Warn]time.Duration,
	warned_on:     [Fwd_Warn]bool,
	ev_sec:        u32,
	ev_left:       int,
	ev_skipped:    u64,
}

// ------------------------------------------------------------------ attach

// Reads the `forward` lines. `d.fwd` stays nil when the config has none.
forward_attach :: proc(d: ^Daemon) {
	cl := d.cfg
	if len(cl.forwards) == 0 {
		return
	}
	if d.guest != nil {
		logf(.Warn, "forward: this host has no relay, so no forward port opens")
		return
	}
	fw := new(Fwd)
	fw.d = d
	fw.lines = make([]Fwd_Line, len(cl.forwards))
	for f, i in cl.forwards {
		line := &fw.lines[i]
		line.f = f
		host := f.host
		if a := cnet.parse_address(f.host); a != nil {
			line.literal = true
			line.addrs[0] = a
			line.n = 1
			if _, v6 := a.(cnet.IP6_Address); v6 {
				host = fmt.tprintf("[%s]", f.host)
			}
		}
		line.text = fmt.aprintf("%s:%d", host, f.host_port)
	}
	fw.max = max(cl.forward_max_conns, 1)
	fw.udp_idle = FWD_UDP_IDLE
	fw.half_idle = FWD_HALF_IDLE
	fw.connect_limit = FWD_CONNECT_LIMIT
	fw.lookup_ttl = FWD_LOOKUP_TTL
	fw.tick = FWD_TICK
	fw.ev_sec = max(u32)
	fwd_lookup_init(fw)
	d.fwd = fw
}

// Closes everything and frees the relay. The tunnel is down already.
forward_detach :: proc(d: ^Daemon) {
	fw := d.fwd
	if fw == nil {
		return
	}
	forward_down(d)
	fwd_lookup_destroy(fw)
	for &l in fw.lines {
		delete(l.text)
	}
	delete(fw.lines)
	delete(fw.lst)
	delete(fw.conns)
	delete(fw.udp)
	delete(fw.udp_map)
	delete(fw.retries)
	delete(fw.rx)
	free(fw)
	d.fwd = nil
}

// The tunnel is up and its addresses are on the device: opens the listeners on
// them.
forward_up :: proc(d: ^Daemon, po: ^push.Pushed_Options) {
	if d.fwd == nil {
		return
	}
	addrs: [2]cnet.Address
	n := 0
	if ifc, ok := po.ifconfig.?; ok {
		addrs[n] = cnet.IP4_Address{ifc.a[0], ifc.a[1], ifc.a[2], ifc.a[3]}
		n += 1
	}
	if ifc6, ok := po.ifconfig6.?; ok {
		addrs[n] = cnet.IP6_Address(transmute([8]u16be)ifc6.addr)
		n += 1
	}
	dev, limited := fwd_device(d)
	if limited && dev == "" {
		fwd_close_all(d.fwd, .Tunnel_Down)
		logf(.Warn, "forward: the tunnel device has no name, so no forward port opens")
		return
	}
	fwd_listen(d, addrs[:n], dev)
}

// The tunnel is down: every listener, connection and session closes.
forward_down :: proc(d: ^Daemon) {
	fw := d.fwd
	if fw == nil {
		return
	}
	fwd_close_all(fw, .Tunnel_Down)
}

forward_write_stats :: proc(w: ^bus.Writer, d: ^Daemon) {
	if d.fwd == nil {
		return
	}
	write_u64_fields(w, &d.fwd.stats, "fwd_")
}

// ---------------------------------------------------------------- listeners

// Opens the listeners of every line on each of `addrs`. With a `device` they
// take only connections that arrive on it. A test passes loopback addresses.
fwd_listen :: proc(d: ^Daemon, addrs: []cnet.Address, device := "") {
	fw := d.fwd
	if fw == nil {
		return
	}
	fwd_close_all(fw, .Tunnel_Down)
	fw.dev_n = copy(fw.dev[:], device)
	if device != "" {
		logf(.Info, "forward: the listeners take only what arrives on %s", device)
	}
	fw.retry_until = now_of(d) + FWD_BIND_RETRY
	for a in addrs {
		for line, i in fw.lines {
			if .Tcp in line.f.protos {
				fwd_listen_one(fw, i, false, a)
			}
			if .Udp in line.f.protos {
				fwd_listen_one(fw, i, true, a)
			}
		}
	}
}

@(private = "file")
fwd_listen_one :: proc(fw: ^Fwd, line: int, udp: bool, addr: cnet.Address) {
	err := fwd_bind(fw, line, udp, addr)
	#partial switch err {
	case .None:
	case .Address_Not_Available:
		append(&fw.retries, Fwd_Retry{line = line, udp = udp, addr = addr})
		fwd_arm_tick(fw)
	case:
		fwd_bind_warn(fw, line, udp, addr, err)
	}
}

@(private = "file")
fwd_bind :: proc(fw: ^Fwd, line: int, udp: bool, addr: cnet.Address) -> net.Error {
	d := fw.d
	ep := cnet.Endpoint {
		address = addr,
		port    = int(fw.lines[line].f.port),
	}
	l := new(Fwd_Listener)
	l.fw, l.line, l.udp = fw, line, udp
	err: net.Error
	dev := string(fw.dev[:fw.dev_n])
	if udp {
		l.sock, err = net.udp_open(net.family_of(ep), {v6_mode = .V6_Only})
		if err == .None && dev != "" {
			err = net.bind_device(l.sock, dev)
		}
		if err == .None {
			err = net.bind(l.sock, ep)
		}
	} else {
		l.sock, err = net.tcp_listen(ep, 128, .V6_Only, dev)
	}
	if err == .None {
		if bound, lerr := net.local_endpoint(l.sock); lerr == .None {
			ep = bound
		}
		l.ep = ep
		handler := fwd_on_udp_in if udp else fwd_on_accept
		if event.add_fd(&d.loop, l.sock.fd, {.Read}, handler, l) != .None {
			err = .Other
		}
	}
	if err != .None {
		if net.is_valid(l.sock) {
			net.close(l.sock)
		}
		free(l)
		return err
	}
	fw.next_lst += 1
	l.id = fw.next_lst
	append(&fw.lst, l)
	logf(.Notice, "forward: listening on %s %s -> %s", fwd_ep_text(ep), "udp" if udp else "tcp", fw.lines[line].text)
	return .None
}

@(private = "file")
fwd_bind_warn :: proc(fw: ^Fwd, line: int, udp: bool, addr: cnet.Address, err: net.Error) {
	port := fw.lines[line].f.port
	ep := cnet.Endpoint {
		address = addr,
		port    = int(port),
	}
	why: string
	#partial switch err {
	case .Permission:
		when ODIN_OS == .Linux {
			if port < 1024 {
				why = "permission denied (ports below 1024 need CAP_NET_BIND_SERVICE)"
			} else if fw.dev_n > 0 {
				why = "permission denied (a kernel before 5.7 needs CAP_NET_RAW to limit a socket to the tunnel device)"
			} else {
				why = "permission denied"
			}
		} else {
			why = "permission denied"
		}
	case .Address_In_Use:
		why = "the port is in use"
	case .Address_Not_Available:
		why = "the tunnel address is not ready"
	case:
		why = fmt.tprintf("%v", err)
	}
	logf(.Warn, "forward: cannot listen on %s %s: %s", fwd_ep_text(ep), "udp" if udp else "tcp", why)
}

// Closes every listener, connection and session, and forgets the lookup results.
@(private = "file")
fwd_close_all :: proc(fw: ^Fwd, reason: Fwd_Reason) {
	d := fw.d
	for len(fw.conns) > 0 {
		fwd_conn_close(fw.conns[len(fw.conns) - 1], reason)
	}
	for len(fw.udp) > 0 {
		fwd_udp_close(fw.udp[len(fw.udp) - 1], reason)
	}
	for l in fw.lst {
		if !l.paused {
			event.remove_fd(&d.loop, l.sock.fd)
		}
		net.close(l.sock)
		free(l)
	}
	clear(&fw.lst)
	clear(&fw.retries)
	for &line in fw.lines {
		if !line.literal {
			line.n = 0
			line.until = 0
		}
	}
	timer_clear(d, &fw.t_tick)
}

// ----------------------------------------------------------------- the tick

fwd_arm_tick :: proc(fw: ^Fwd) {
	if !fw.t_tick.on {
		timer_set(fw.d, &fw.t_tick, now_of(fw.d) + fw.tick, fwd_on_tick)
	}
}

// Connect limits, half-closed connections, idle sessions, bind retries and
// paused listeners. It runs while one of them exists.
@(private = "file")
fwd_on_tick :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	fw := d.fwd
	if fw == nil {
		return
	}
	fw.t_tick.on = false
	now := now_of(d)
	again := false
	for i := len(fw.conns) - 1; i >= 0; i -= 1 {
		c := fw.conns[i]
		if c.state == .Open {
			// One side ended. The loop does not watch a socket that it has
			// nothing to do with, so a peer that went away is not seen there:
			// this limit frees the pair.
			if c.pipe[FWD_PEER].eof || c.pipe[FWD_TARGET].eof {
				if now - c.last >= fw.half_idle {
					fwd_conn_close(c, .Idle)
				} else {
					again = true
				}
			}
			continue
		}
		if now - c.born >= fw.connect_limit {
			fwd_conn_close(c, .Timeout)
		} else {
			again = true
		}
	}
	for i := len(fw.udp) - 1; i >= 0; i -= 1 {
		if now - fw.udp[i].last >= fw.udp_idle {
			fwd_udp_close(fw.udp[i], .Idle)
		}
	}
	for l in fw.lst {
		if l.paused {
			if event.add_fd(&d.loop, l.sock.fd, {.Read}, fwd_on_udp_in if l.udp else fwd_on_accept, l) == .None {
				l.paused = false
			} else {
				again = true
			}
		}
	}
	for i := len(fw.retries) - 1; i >= 0; i -= 1 {
		r := fw.retries[i]
		err := fwd_bind(fw, r.line, r.udp, r.addr)
		if err == .None {
			ordered_remove(&fw.retries, i)
		} else if err == .Address_Not_Available && now < fw.retry_until {
			again = true
		} else {
			fwd_bind_warn(fw, r.line, r.udp, r.addr, err)
			ordered_remove(&fw.retries, i)
		}
	}
	if again || len(fw.udp) > 0 {
		fwd_arm_tick(fw)
	}
}

// ---------------------------------------------------------------- the target

fwd_line_ready :: proc(fw: ^Fwd, line: ^Fwd_Line) -> bool {
	return line.literal || (line.n > 0 && now_of(fw.d) < line.until)
}

// ------------------------------------------------------------------ accept

@(private = "file")
fwd_on_accept :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	l := (^Fwd_Listener)(user)
	fw := l.fw
	for _ in 0 ..< FWD_ACCEPT_BURST {
		s, from, err := net.tcp_accept(l.sock, {keepalive = true})
		#partial switch err {
		case .None:
			fwd_new_conn(fw, l, s, from)
		case .Would_Block:
			return
		case .Connection_Reset:
			continue
		case:
			fwd_warn(fw, .Accept, "forward: cannot accept a connection on %s: %v", fwd_ep_text(l.ep), err)
			event.remove_fd(loop, fd)
			l.paused = true
			fwd_arm_tick(fw)
			return
		}
	}
}

@(private = "file")
fwd_new_conn :: proc(fw: ^Fwd, l: ^Fwd_Listener, s: net.Socket, from: cnet.Endpoint) {
	if len(fw.conns) >= fw.max {
		net.close(s)
		fw.stats.refused += 1
		fwd_warn(fw, .Limit, "forward: %d connections are open, so new ones are refused (forward-max-conns)", fw.max)
		return
	}
	c := new(Fwd_Conn)
	c.pipe[FWD_PEER].buf = make([]u8, FWD_BUF)
	c.pipe[FWD_TARGET].buf = make([]u8, FWD_BUF)
	if c.pipe[FWD_PEER].buf == nil || c.pipe[FWD_TARGET].buf == nil {
		delete(c.pipe[FWD_PEER].buf)
		delete(c.pipe[FWD_TARGET].buf)
		free(c)
		net.close(s)
		fw.stats.refused += 1
		return
	}
	c.fw, c.lst, c.line = fw, l, l.line
	c.sock = {s, net.INVALID_SOCKET}
	c.peer = from
	c.born = now_of(fw.d)
	c.idx = len(fw.conns)
	append(&fw.conns, c)
	fw.stats.conns = u64(len(fw.conns))
	fwd_arm_tick(fw)
	line := &fw.lines[c.line]
	if fwd_line_ready(fw, line) {
		fwd_conn_start(c)
	} else {
		fwd_resolve(fw, c.line)
	}
}

// The target is known: connects to the first address.
fwd_conn_start :: proc(c: ^Fwd_Conn) {
	line := &c.fw.lines[c.line]
	c.addrs = line.addrs
	c.n = line.n
	c.next = 0
	c.state = .Connecting
	fwd_conn_try_connect(c)
}

// Starts a connect to the next address that works. When none is left the
// connection fails.
@(private = "file")
fwd_conn_try_connect :: proc(c: ^Fwd_Conn) {
	port := int(c.fw.lines[c.line].f.host_port)
	for c.next < c.n {
		ep := cnet.Endpoint {
			address = c.addrs[c.next],
			port    = port,
		}
		c.next += 1
		s, pending, err := net.tcp_connect(ep, {keepalive = true})
		if err != .None {
			continue
		}
		c.sock[FWD_TARGET] = s
		c.target = ep
		if pending {
			fwd_conn_update(c)
		} else {
			fwd_conn_connected(c)
		}
		return
	}
	fwd_conn_close(c, .Connect_Failed)
}

@(private = "file")
fwd_conn_connected :: proc(c: ^Fwd_Conn) {
	fw := c.fw
	c.state = .Open
	c.opened = true
	fw.stats.opened += 1
	fwd_event(fw, "open", false, c.lst.ep.port, c.peer, c.target, 0, 0, .Eof)
	logf(.Debug, "forward: tcp %s -> %s open", fwd_ep_text(c.peer), fwd_ep_text(c.target))
	fwd_conn_update(c)
}

// ------------------------------------------------------------------- copy

@(private = "file")
fwd_conn_wants_read :: proc(c: ^Fwd_Conn, s: int) -> bool {
	p := &c.pipe[s]
	return c.state == .Open && !p.eof && (p.end < len(p.buf) || p.head > 0)
}

@(private = "file")
fwd_conn_has_data :: proc(c: ^Fwd_Conn, s: int) -> bool {
	p := &c.pipe[s]
	return p.head < p.end
}

// Sets what the loop watches on both sockets. False: the connection closed.
@(private = "file")
fwd_conn_update :: proc(c: ^Fwd_Conn) -> bool {
	fw := c.fw
	d := fw.d
	for s in 0 ..< 2 {
		if !net.is_valid(c.sock[s]) {
			continue
		}
		want: event.Interest
		switch c.state {
		case .Open:
			if fwd_conn_wants_read(c, s) {
				want += {.Read}
			}
			// Bytes that wait for this socket are in the pipe of the other.
			if fwd_conn_has_data(c, 1 - s) {
				want += {.Write}
			}
		case .Connecting:
			if s == FWD_TARGET {
				want = {.Write}
			}
		case .Resolving:
		}
		fd := c.sock[s].fd
		handler := fwd_on_peer if s == FWD_PEER else fwd_on_target
		if want == {} {
			if c.reg[s] {
				event.remove_fd(&d.loop, fd)
				c.reg[s] = false
				c.ints[s] = {}
			}
		} else if !c.reg[s] {
			if event.add_fd(&d.loop, fd, want, handler, c) != .None {
				fwd_warn(fw, .Register, "forward: the event loop cannot watch more sockets, so a connection is refused")
				fwd_conn_close(c, .Refused)
				return false
			}
			c.reg[s] = true
			c.ints[s] = want
		} else if c.ints[s] != want {
			if event.modify_fd(&d.loop, fd, want) != .None {
				fwd_conn_close(c, .Peer_Reset if s == FWD_PEER else .Target_Reset)
				return false
			}
			c.ints[s] = want
		}
	}
	return true
}

@(private = "file")
fwd_on_peer :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	fwd_conn_ready((^Fwd_Conn)(user), FWD_PEER, ready)
}

@(private = "file")
fwd_on_target :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	fwd_conn_ready((^Fwd_Conn)(user), FWD_TARGET, ready)
}

@(private = "file")
fwd_conn_ready :: proc(c: ^Fwd_Conn, s: int, ready: event.Ready) {
	if c.state == .Connecting {
		if s != FWD_TARGET {
			return
		}
		#partial switch net.tcp_connect_finish(c.sock[FWD_TARGET]) {
		case .None:
			fwd_conn_connected(c)
		case .Would_Block:
		case:
			if c.reg[FWD_TARGET] {
				event.remove_fd(&c.fw.d.loop, c.sock[FWD_TARGET].fd)
				c.reg[FWD_TARGET] = false
			}
			net.close(c.sock[FWD_TARGET])
			c.sock[FWD_TARGET] = net.INVALID_SOCKET
			fwd_conn_try_connect(c)
		}
		return
	}
	if .Error in ready {
		fwd_conn_close(c, .Peer_Reset if s == FWD_PEER else .Target_Reset)
		return
	}
	if ready & {.Read, .Hangup} != {} && fwd_conn_wants_read(c, s) {
		if !fwd_conn_read(c, s) {
			return
		}
	}
	if ready & {.Write, .Hangup} != {} && fwd_conn_has_data(c, 1 - s) {
		if !fwd_conn_flush(c, 1 - s) {
			return
		}
	}
	fwd_conn_settle(c)
}

// One read from `sock[s]` into its pipe, then a write of the pipe. False: the
// connection closed.
@(private = "file")
fwd_conn_read :: proc(c: ^Fwd_Conn, s: int) -> bool {
	p := &c.pipe[s]
	if p.head == p.end {
		p.head, p.end = 0, 0
	} else if p.end == len(p.buf) {
		copy(p.buf, p.buf[p.head:p.end])
		p.end -= p.head
		p.head = 0
	}
	n, err := net.stream_recv(c.sock[s], p.buf[p.end:])
	#partial switch err {
	case .None:
		p.end += n
	case .Would_Block:
		return true
	case .Closed:
		p.eof = true
		c.last = now_of(c.fw.d)
		fwd_arm_tick(c.fw)
	case:
		fwd_conn_close(c, .Peer_Reset if s == FWD_PEER else .Target_Reset)
		return false
	}
	return fwd_conn_flush(c, s)
}

// Writes the pipe `p` to the other socket as far as it takes it. After the end
// of the source and an empty pipe, the other socket gets the end once. False:
// the connection closed.
@(private = "file")
fwd_conn_flush :: proc(c: ^Fwd_Conn, p_idx: int) -> bool {
	fw := c.fw
	p := &c.pipe[p_idx]
	dst := 1 - p_idx
	for p.head < p.end {
		n, err := net.stream_send(c.sock[dst], p.buf[p.head:p.end])
		if err == .Would_Block {
			break
		}
		if err != .None {
			fwd_conn_close(c, .Peer_Reset if dst == FWD_PEER else .Target_Reset)
			return false
		}
		p.head += n
		c.last = now_of(fw.d)
		if p_idx == FWD_PEER {
			c.bytes_in += u64(n)
			fw.stats.bytes_in += u64(n)
		} else {
			c.bytes_out += u64(n)
			fw.stats.bytes_out += u64(n)
		}
	}
	if p.head == p.end {
		p.head, p.end = 0, 0
		if p.eof && !p.shut {
			net.shutdown_write(c.sock[dst])
			p.shut = true
		}
	}
	return true
}

// Closes the pair when both directions have ended, else updates the loop.
@(private = "file")
fwd_conn_settle :: proc(c: ^Fwd_Conn) {
	if c.pipe[FWD_PEER].shut && c.pipe[FWD_TARGET].shut {
		fwd_conn_close(c, .Eof)
		return
	}
	fwd_conn_update(c)
}

// Frees the connection: sockets, buffers, and its place in the list.
fwd_conn_close :: proc(c: ^Fwd_Conn, reason: Fwd_Reason) {
	fw := c.fw
	d := fw.d
	for s in 0 ..< 2 {
		if c.reg[s] {
			event.remove_fd(&d.loop, c.sock[s].fd)
		}
		if net.is_valid(c.sock[s]) {
			net.close(c.sock[s])
		}
	}
	#partial switch reason {
	case .Connect_Failed, .Lookup_Failed, .Timeout:
		fw.stats.failed += 1
	case .Refused:
		fw.stats.refused += 1
	}
	if c.opened || reason != .Refused {
		fwd_event(fw, "close", false, c.lst.ep.port, c.peer, c.target, c.bytes_in, c.bytes_out, reason, fw.lines[c.line].text)
		logf(
			.Debug,
			"forward: tcp %s -> %s closed (%s), %d bytes in, %d bytes out",
			fwd_ep_text(c.peer),
			fw.lines[c.line].text,
			FWD_REASON_TEXT[reason],
			c.bytes_in,
			c.bytes_out,
		)
	}
	last := pop(&fw.conns)
	if c.idx < len(fw.conns) {
		fw.conns[c.idx] = last
		last.idx = c.idx
	}
	fw.stats.conns = u64(len(fw.conns))
	delete(c.pipe[FWD_PEER].buf)
	delete(c.pipe[FWD_TARGET].buf)
	free(c)
}

// --------------------------------------------------------- events and logs

// Gives an `acl.forward` event, at most `FWD_EVENTS` each second.
fwd_event :: proc(
	fw: ^Fwd,
	what: string,
	udp: bool,
	port: int,
	peer: cnet.Endpoint,
	target: cnet.Endpoint,
	bytes_in, bytes_out: u64,
	reason: Fwd_Reason,
	target_text := "",
) {
	d := fw.d
	if !host_events_on(d) {
		return
	}
	sec := u32(now_of(d) / time.Second)
	if sec != fw.ev_sec {
		fw.ev_sec = sec
		fw.ev_left = FWD_EVENTS
	}
	if fw.ev_left == 0 {
		fw.ev_skipped += 1
		return
	}
	w := ev_begin(d)
	if w == nil {
		return
	}
	fw.ev_left -= 1
	bus.kv_str(w, "what", what)
	bus.kv_str(w, "proto", "udp" if udp else "tcp")
	bus.kv_u64(w, "port", u64(port))
	bus.kv_str(w, "peer", cnet.address_to_string(peer.address, context.temp_allocator))
	bus.kv_u64(w, "peer_port", u64(peer.port))
	if target.port != 0 {
		bus.kv_str(w, "target", fwd_ep_text(target))
	} else {
		bus.kv_str(w, "target", target_text)
	}
	if what == "close" {
		bus.kv_u64(w, "bytes_in", bytes_in)
		bus.kv_u64(w, "bytes_out", bytes_out)
		bus.kv_str(w, "reason", FWD_REASON_TEXT[reason])
	}
	bus.kv_u64(w, "skipped", fw.ev_skipped)
	fw.ev_skipped = 0
	ev_emit(d, "acl.forward")
}

// "address:port", an IPv6 address in brackets. In the temp allocator.
fwd_ep_text :: proc(ep: cnet.Endpoint) -> string {
	return cnet.endpoint_to_string(ep, context.temp_allocator)
}

// A warning of one kind, at most once in `FWD_WARN_GAP`.
fwd_warn :: proc(fw: ^Fwd, kind: Fwd_Warn, format: string, args: ..any) {
	now := now_of(fw.d)
	if fw.warned_on[kind] && now - fw.warned[kind] < FWD_WARN_GAP {
		return
	}
	fw.warned_on[kind] = true
	fw.warned[kind] = now
	logf(.Warn, format, ..args)
}
