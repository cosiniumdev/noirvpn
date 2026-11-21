// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:crypto"
import cnet "core:net"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:bus"
import "noir:platform/event"
import "noir:platform/net"
import "noir:proto/config"
import "noir:proto/push"

// The relay on loopback sockets with a real loop: no root, no tun device. The
// test thread runs the loop in short steps and serves its own sockets between
// the steps.

@(private = "file")
LO4 :: cnet.IP4_Address{127, 0, 0, 1}
@(private = "file")
STEP_LIMIT :: 5000

@(private = "file")
Rig :: struct {
	cfg: config.Client_Config,
	d:   Daemon,
	evs: [dynamic]string,
}

@(private = "file")
rig_events_on :: proc(user: rawptr) -> bool {
	return true
}

@(private = "file")
rig_event :: proc(user: rawptr, topic: string, data: []u8) {
	r := (^Rig)(user)
	append(&r.evs, strings.concatenate({topic, " ", string(data)}))
}

@(private = "file")
rig_init :: proc(r: ^Rig, forwards: []config.Forward, max_conns := 256) -> bool {
	r.cfg.forwards = forwards
	r.cfg.forward_max_conns = max_conns
	r.d.cfg = &r.cfg
	r.d.host = Host {
		user      = r,
		events_on = rig_events_on,
		event     = rig_event,
	}
	bus.writer_init(&r.d.ev_w)
	r.d.ev_w_ok = true
	if event.init(&r.d.loop) != .None {
		return false
	}
	forward_attach(&r.d)
	if r.d.fwd == nil {
		return false
	}
	r.d.fwd.tick = 10 * time.Millisecond
	return true
}

@(private = "file")
rig_destroy :: proc(r: ^Rig) {
	forward_detach(&r.d)
	event.destroy(&r.d.loop)
	bus.writer_destroy(&r.d.ev_w)
	for e in r.evs {
		delete(e)
	}
	delete(r.evs)
}

@(private = "file")
rig_step :: proc(r: ^Rig, ms := 2) {
	event.wait(&r.d.loop, event.now() + time.Duration(ms) * time.Millisecond)
	free_all(context.temp_allocator)
}

@(private = "file")
rig_events_have :: proc(r: ^Rig, parts: ..string) -> bool {
	for e in r.evs {
		ok := true
		for p in parts {
			ok &&= strings.contains(e, p)
		}
		if ok {
			return true
		}
	}
	return false
}

// A TCP listener on loopback with a free port.
@(private = "file")
listener :: proc() -> (s: net.Socket, port: int) {
	s, _ = net.tcp_listen({LO4, 0})
	ep, _ := net.local_endpoint(s)
	return s, ep.port
}

// A TCP port that nobody listens on.
@(private = "file")
closed_port :: proc() -> int {
	s, port := listener()
	net.close(s)
	return port
}

@(private = "file")
tcp_forward :: proc(host: string, port: int) -> config.Forward {
	return config.Forward{port = 0, protos = {.Tcp}, host = host, host_port = u16(port)}
}

// Connects to the forward port of the first listener, and runs the loop until
// the connection is made.
@(private = "file")
dial :: proc(r: ^Rig, lst: int, loc := #caller_location) -> net.Socket {
	ep := r.d.fwd.lst[lst].ep
	s, _, err := net.tcp_connect(ep)
	if err != .None {
		return net.INVALID_SOCKET
	}
	for _ in 0 ..< STEP_LIMIT {
		if net.tcp_connect_finish(s) != .Would_Block {
			break
		}
		rig_step(r)
	}
	return s
}

// Takes one connection from the target listener, running the loop until one is
// there.
@(private = "file")
take :: proc(r: ^Rig, ls: net.Socket) -> (s: net.Socket, ok: bool) {
	for _ in 0 ..< STEP_LIMIT {
		c, _, err := net.tcp_accept(ls)
		if err == .None {
			return c, true
		}
		rig_step(r)
	}
	return net.INVALID_SOCKET, false
}

@(private = "file")
Echo :: struct {
	ls:    net.Socket,
	port:  int,
	conns: [dynamic]net.Socket,
}

@(private = "file")
echo_init :: proc(e: ^Echo) {
	e.ls, e.port = listener()
}

@(private = "file")
echo_destroy :: proc(e: ^Echo) {
	for c in e.conns {
		net.close(c)
	}
	delete(e.conns)
	net.close(e.ls)
}

// Accepts, and sends back what it reads. A closed connection is closed.
@(private = "file")
echo_step :: proc(e: ^Echo) {
	for {
		s, _, err := net.tcp_accept(e.ls)
		if err != .None {
			break
		}
		append(&e.conns, s)
	}
	buf: [4096]u8
	for i := len(e.conns) - 1; i >= 0; i -= 1 {
		n, err := net.stream_recv(e.conns[i], buf[:])
		if err == .None {
			net.stream_send(e.conns[i], buf[:n])
		} else if err != .Would_Block {
			net.close(e.conns[i])
			unordered_remove(&e.conns, i)
		}
	}
}

// Sends `msg` on `s` and waits for the same bytes to come back.
@(private = "file")
round_trip :: proc(r: ^Rig, e: ^Echo, s: net.Socket, msg: string) -> bool {
	if _, err := net.stream_send(s, transmute([]u8)msg); err != .None {
		return false
	}
	buf: [256]u8
	got := 0
	for _ in 0 ..< STEP_LIMIT {
		n, err := net.stream_recv(s, buf[got:len(msg)])
		if err == .None {
			got += n
			if got == len(msg) {
				return string(buf[:got]) == msg
			}
		} else if err != .Would_Block {
			return false
		}
		echo_step(e)
		rig_step(r)
	}
	return false
}

// True when the socket reads an end or a reset (the relay closed it).
@(private = "file")
closed_by_relay :: proc(r: ^Rig, s: net.Socket) -> bool {
	buf: [16]u8
	for _ in 0 ..< STEP_LIMIT {
		_, err := net.stream_recv(s, buf[:])
		if err == .Closed || err == .Connection_Reset {
			return true
		}
		if err != .Would_Block && err != .None {
			return false
		}
		rig_step(r)
	}
	return false
}

@(private = "file")
wait_conns :: proc(r: ^Rig, n: int, e: ^Echo = nil) -> bool {
	for _ in 0 ..< STEP_LIMIT {
		if len(r.d.fwd.conns) == n {
			return true
		}
		if e != nil {
			echo_step(e)
		}
		rig_step(r)
	}
	return false
}

// ------------------------------------------------------------------- TCP

@(private = "file")
Duplex :: struct {
	out:  []u8,
	in_:  []u8,
	sent: int,
	got:  int,
	eof:  bool,
}

@(private = "file")
duplex_step :: proc(s: net.Socket, p: ^Duplex) {
	if p.sent < len(p.out) {
		if n, err := net.stream_send(s, p.out[p.sent:]); err == .None {
			p.sent += n
		}
	}
	if p.got < len(p.in_) {
		n, err := net.stream_recv(s, p.in_[p.got:])
		if err == .None {
			p.got += n
		} else if err == .Closed {
			p.eof = true
		}
	}
}

@(test)
test_forward_tcp_copy :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	ls, tport := listener()
	defer net.close(ls)
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", tport)})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	if !testing.expect_value(t, len(fw.lst), 1) {
		return
	}
	cl := dial(&r, 0)
	defer net.close(cl)
	tc, ok := take(&r, ls)
	if !testing.expect(t, ok) {
		return
	}
	defer net.close(tc)

	N :: 1 << 20
	a := make([]u8, N)
	b := make([]u8, N)
	defer delete(a)
	defer delete(b)
	crypto.rand_bytes(a)
	crypto.rand_bytes(b)
	ra := make([]u8, N)
	rb := make([]u8, N)
	defer delete(ra)
	defer delete(rb)
	c_side := Duplex {
		out = a,
		in_ = rb,
	}
	t_side := Duplex {
		out = b,
		in_ = ra,
	}
	for _ in 0 ..< STEP_LIMIT {
		if c_side.got == N && t_side.got == N {
			break
		}
		duplex_step(cl, &c_side)
		duplex_step(tc, &t_side)
		rig_step(&r, 1)
	}
	testing.expect_value(t, t_side.got, N)
	testing.expect_value(t, c_side.got, N)
	testing.expect(t, string(ra) == string(a), "peer to target bytes differ")
	testing.expect(t, string(rb) == string(b), "target to peer bytes differ")
	testing.expect_value(t, fw.stats.bytes_in, u64(N))
	testing.expect_value(t, fw.stats.bytes_out, u64(N))
	testing.expect_value(t, fw.stats.opened, 1)
	testing.expect_value(t, fw.stats.conns, 1)
	testing.expect(t, rig_events_have(&r, "acl.forward", `"what":"open"`, `"proto":"tcp"`, `"peer":"127.0.0.1"`))
}

@(test)
test_forward_tcp_half_close :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	ls, tport := listener()
	defer net.close(ls)
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", tport)})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	cl := dial(&r, 0)
	defer net.close(cl)
	tc, ok := take(&r, ls)
	if !testing.expect(t, ok) {
		return
	}
	defer net.close(tc)

	// The client ends its write side; the target still answers.
	net.stream_send(cl, transmute([]u8)string("ping"))
	net.shutdown_write(cl)
	buf: [64]u8
	got := 0
	target_eof := false
	for _ in 0 ..< STEP_LIMIT {
		n, err := net.stream_recv(tc, buf[got:])
		if err == .None {
			got += n
		} else if err == .Closed {
			target_eof = true
			break
		}
		rig_step(&r)
	}
	testing.expect(t, target_eof, "the target did not see the end of the stream")
	testing.expect_value(t, string(buf[:got]), "ping")
	testing.expect_value(t, len(r.d.fwd.conns), 1)

	net.stream_send(tc, transmute([]u8)string("answer"))
	rbuf: [64]u8
	rgot := 0
	client_eof := false
	net.shutdown_write(tc)
	for _ in 0 ..< STEP_LIMIT {
		n, err := net.stream_recv(cl, rbuf[rgot:])
		if err == .None {
			rgot += n
		} else if err == .Closed {
			client_eof = true
			break
		}
		rig_step(&r)
	}
	testing.expect_value(t, string(rbuf[:rgot]), "answer")
	testing.expect(t, client_eof, "the client did not see the end of the stream")
	testing.expect(t, wait_conns(&r, 0))
	testing.expect(t, rig_events_have(&r, `"what":"close"`, `"reason":"eof"`, `"bytes_in":4`, `"bytes_out":6`))
}

// After one side ended, a pair that moves no bytes closes at the limit.
@(test)
test_forward_tcp_half_close_idle :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	ls, tport := listener()
	defer net.close(ls)
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", tport)})) {
		return
	}
	defer rig_destroy(&r)
	r.d.fwd.half_idle = 100 * time.Millisecond
	fwd_listen(&r.d, []cnet.Address{LO4})
	cl := dial(&r, 0)
	defer net.close(cl)
	tc, ok := take(&r, ls)
	if !testing.expect(t, ok) {
		return
	}
	defer net.close(tc)

	// An open pair with no traffic stays: the limit starts when a side ends.
	for _ in 0 ..< 100 {
		rig_step(&r)
	}
	testing.expect_value(t, len(r.d.fwd.conns), 1)

	// The client ends its write side. The target keeps its side open and is silent.
	net.shutdown_write(cl)
	testing.expect(t, closed_by_relay(&r, cl), "the pair stayed open")
	testing.expect(t, wait_conns(&r, 0))
	testing.expect(t, rig_events_have(&r, `"what":"close"`, `"reason":"idle"`))
}

// Linux: listeners limited to a device. Loopback connections arrive on "lo".
// A device that does not exist opens no listener.
@(test)
test_forward_device_limit :: proc(t: ^testing.T) {
	when ODIN_OS == .Linux {
		testing.set_fail_timeout(t, 60 * time.Second)
		r: Rig
		e: Echo
		echo_init(&e)
		defer echo_destroy(&e)
		udp_target, _ := net.udp_open(.V4)
		defer net.close(udp_target)
		net.bind(udp_target, {LO4, 0})
		uep, _ := net.local_endpoint(udp_target)
		forwards := []config.Forward {
			tcp_forward("127.0.0.1", e.port),
			{port = 0, protos = {.Udp}, host = "127.0.0.1", host_port = u16(uep.port)},
		}
		if !testing.expect(t, rig_init(&r, forwards)) {
			return
		}
		defer rig_destroy(&r)
		fw := r.d.fwd

		fwd_listen(&r.d, []cnet.Address{LO4}, "lo")
		if !testing.expect_value(t, len(fw.lst), 2) {
			return
		}
		cl := dial(&r, 0)
		testing.expect(t, round_trip(&r, &e, cl, "through the loopback device"))
		net.close(cl)
		testing.expect(t, wait_conns(&r, 0, &e))

		fwd_listen(&r.d, []cnet.Address{LO4}, "nodev-noir0")
		testing.expect_value(t, len(fw.lst), 0)
		testing.expect_value(t, len(fw.retries), 0)
	}
}

@(test)
test_forward_tcp_target_closed :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", closed_port())})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	cl := dial(&r, 0)
	defer net.close(cl)
	testing.expect(t, closed_by_relay(&r, cl), "the peer connection stayed open")
	fw := r.d.fwd
	testing.expect(t, wait_conns(&r, 0))
	testing.expect_value(t, fw.stats.failed, 1)
	testing.expect_value(t, fw.stats.opened, 0)
	testing.expect_value(t, fw.stats.conns, 0)
	testing.expect_value(t, len(fw.udp), 0)
	testing.expect(t, rig_events_have(&r, `"what":"close"`, `"reason":"connect_failed"`))
}

@(test)
test_forward_tcp_limit :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	e: Echo
	echo_init(&e)
	defer echo_destroy(&e)
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", e.port)}, 2)) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	c1 := dial(&r, 0)
	c2 := dial(&r, 0)
	defer net.close(c2)
	testing.expect(t, round_trip(&r, &e, c1, "one"))
	testing.expect(t, round_trip(&r, &e, c2, "two"))
	c3 := dial(&r, 0)
	defer net.close(c3)
	testing.expect(t, closed_by_relay(&r, c3), "the third connection stayed open")
	testing.expect_value(t, fw.stats.refused, 1)
	testing.expect_value(t, fw.stats.conns, 2)

	// One ends: a new connection works.
	net.close(c1)
	testing.expect(t, wait_conns(&r, 1, &e))
	c4 := dial(&r, 0)
	defer net.close(c4)
	testing.expect(t, round_trip(&r, &e, c4, "four"))
	testing.expect_value(t, fw.stats.refused, 1)
}

@(test)
test_forward_tcp_slow_target :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	ls, tport := listener()
	defer net.close(ls)
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", tport)})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	cl := dial(&r, 0)
	defer net.close(cl)
	tc, ok := take(&r, ls)
	if !testing.expect(t, ok) {
		return
	}
	defer net.close(tc)

	// The target does not read. The client sends until the path is full.
	data := make([]u8, 256 * 1024)
	defer delete(data)
	sent := 0
	idle := 0
	for idle < 60 && sent < 256 << 20 {
		for i in 0 ..< len(data) {
			data[i] = u8((sent + i) * 7 + (sent + i) >> 11)
		}
		n, err := net.stream_send(cl, data)
		if err == .None && n > 0 {
			sent += n
			idle = 0
		} else {
			idle += 1
		}
		rig_step(&r, 5)
	}
	if !testing.expect_value(t, len(fw.conns), 1) {
		return
	}
	c := fw.conns[0]
	p := &c.pipe[FWD_PEER]
	testing.expect_value(t, p.end - p.head, FWD_BUF)
	testing.expect(t, .Read not_in c.ints[FWD_PEER], "the relay still reads from the peer")
	testing.expect(t, sent < 256 << 20, "the peer was never stopped")

	// The target reads: every byte arrives, in order.
	chunk := make([]u8, 64 * 1024)
	defer delete(chunk)
	got := 0
	bad := 0
	for _ in 0 ..< STEP_LIMIT * 4 {
		if got == sent {
			break
		}
		n, err := net.stream_recv(tc, chunk)
		if err == .None {
			for i in 0 ..< n {
				if chunk[i] != u8((got + i) * 7 + (got + i) >> 11) {
					bad += 1
				}
			}
			got += n
			continue
		}
		rig_step(&r, 1)
	}
	testing.expect_value(t, got, sent)
	testing.expect_value(t, bad, 0)
}

// --------------------------------------------------------------------- UDP

@(private = "file")
udp_sock :: proc() -> (s: net.Socket, port: int) {
	s, _ = net.udp_open(.V4)
	net.bind(s, {LO4, 0})
	ep, _ := net.local_endpoint(s)
	return s, ep.port
}

// Answers each datagram with "re:" and the text.
@(private = "file")
udp_echo_step :: proc(s: net.Socket) {
	buf: [256]u8
	reply: [260]u8
	for {
		n, from, err := net.recv_from(s, buf[:])
		if err != .None {
			return
		}
		copy(reply[:], "re:")
		copy(reply[3:], buf[:n])
		net.send_to(s, reply[:3 + n], from)
	}
}

@(private = "file")
udp_forward :: proc(port: int) -> config.Forward {
	return config.Forward{port = 0, protos = {.Udp}, host = "127.0.0.1", host_port = u16(port)}
}

// Sends `text` from `peer` to the forward port and waits for the reply.
@(private = "file")
udp_ask :: proc(r: ^Rig, target: net.Socket, peer: net.Socket, text: string) -> string {
	net.send_to(peer, transmute([]u8)text, r.d.fwd.lst[0].ep)
	buf: [256]u8
	for _ in 0 ..< STEP_LIMIT {
		udp_echo_step(target)
		m, rerr := net.recv(peer, buf[:])
		if rerr == .None {
			return strings.clone(string(buf[:m]), context.temp_allocator)
		}
		rig_step(r)
	}
	return ""
}

@(test)
test_forward_udp_sessions :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	target, tport := udp_sock()
	defer net.close(target)
	if !testing.expect(t, rig_init(&r, {udp_forward(tport)})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	pa, _ := udp_sock()
	pb, _ := udp_sock()
	defer net.close(pa)
	defer net.close(pb)
	testing.expect_value(t, udp_ask(&r, target, pa, "alpha"), "re:alpha")
	testing.expect_value(t, udp_ask(&r, target, pb, "beta"), "re:beta")
	testing.expect_value(t, fw.stats.udp_sessions, 2)
	testing.expect_value(t, fw.stats.opened, 2)
	// Each peer has its own session, so nothing more is waiting for either.
	buf: [64]u8
	for _ in 0 ..< 10 {
		rig_step(&r)
	}
	_, e1 := net.recv(pa, buf[:])
	_, e2 := net.recv(pb, buf[:])
	testing.expect_value(t, e1, net.Error.Would_Block)
	testing.expect_value(t, e2, net.Error.Would_Block)
	testing.expect_value(t, fw.stats.bytes_in, 9)
	testing.expect_value(t, fw.stats.bytes_out, 15)
	testing.expect(t, rig_events_have(&r, "acl.forward", `"what":"open"`, `"proto":"udp"`))

	// No traffic: the sessions go.
	fw.udp_idle = 80 * time.Millisecond
	for _ in 0 ..< STEP_LIMIT {
		if len(fw.udp) == 0 {
			break
		}
		rig_step(&r)
	}
	testing.expect_value(t, len(fw.udp), 0)
	testing.expect_value(t, fw.stats.udp_sessions, 0)
	testing.expect(t, rig_events_have(&r, `"what":"close"`, `"reason":"idle"`))
}

@(test)
test_forward_udp_pool_full :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	target, tport := udp_sock()
	defer net.close(target)
	if !testing.expect(t, rig_init(&r, {udp_forward(tport)}, 2)) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	pa, port_a := udp_sock()
	pb, port_b := udp_sock()
	pc, port_c := udp_sock()
	defer net.close(pa)
	defer net.close(pb)
	defer net.close(pc)
	testing.expect_value(t, udp_ask(&r, target, pa, "a"), "re:a")
	for _ in 0 ..< 10 {
		rig_step(&r, 3)
	}
	testing.expect_value(t, udp_ask(&r, target, pb, "b"), "re:b")
	for _ in 0 ..< 10 {
		rig_step(&r, 3)
	}
	// The pool is full: the session of A has been idle the longest.
	testing.expect_value(t, udp_ask(&r, target, pc, "c"), "re:c")
	testing.expect_value(t, len(fw.udp), 2)
	ports: [3]bool
	for s in fw.udp {
		ports[0] ||= s.peer.port == port_a
		ports[1] ||= s.peer.port == port_b
		ports[2] ||= s.peer.port == port_c
	}
	testing.expect(t, !ports[0], "the oldest session stayed")
	testing.expect(t, ports[1] && ports[2], "a newer session was replaced")
	testing.expect(t, rig_events_have(&r, `"what":"close"`, `"reason":"replaced"`))
}

// ----------------------------------------------------------------- targets

@(test)
test_forward_name_target :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	e: Echo
	echo_init(&e)
	defer echo_destroy(&e)
	if !testing.expect(t, rig_init(&r, {tcp_forward("localhost", e.port)})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	// Two connections that arrive during the lookup wait for the same lookup.
	c1 := dial(&r, 0)
	c2 := dial(&r, 0)
	defer net.close(c1)
	defer net.close(c2)
	testing.expect(t, round_trip(&r, &e, c1, "one"))
	testing.expect(t, round_trip(&r, &e, c2, "two"))
	testing.expect_value(t, fw.lookups, 1)
	// The result is kept.
	c3 := dial(&r, 0)
	defer net.close(c3)
	testing.expect(t, round_trip(&r, &e, c3, "three"))
	testing.expect_value(t, fw.lookups, 1)
	// After its time, the next connection looks the name up again.
	fw.lookup_ttl = 0
	fw.lines[0].until = 0
	c4 := dial(&r, 0)
	defer net.close(c4)
	testing.expect(t, round_trip(&r, &e, c4, "four"))
	testing.expect_value(t, fw.lookups, 2)
	testing.expect_value(t, fw.stats.failed, 0)
}

@(test)
test_forward_name_target_udp :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	target, tport := udp_sock()
	defer net.close(target)
	f := udp_forward(tport)
	f.host = "localhost"
	if !testing.expect(t, rig_init(&r, {f})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	pa, _ := udp_sock()
	defer net.close(pa)
	// The datagram waits for the lookup, then goes to the target.
	testing.expect_value(t, udp_ask(&r, target, pa, "named"), "re:named")
	testing.expect_value(t, r.d.fwd.lookups, 1)
}

// ------------------------------------------------------------ down and up

@(test)
test_forward_down_up_closes_everything :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 120 * time.Second)
	r: Rig
	e: Echo
	echo_init(&e)
	defer echo_destroy(&e)
	both := config.Forward {
		port      = 0,
		protos    = {.Tcp, .Udp},
		host      = "127.0.0.1",
		host_port = u16(e.port),
	}
	if !testing.expect(t, rig_init(&r, {both})) {
		return
	}
	defer rig_destroy(&r)
	fw := r.d.fwd
	peer, _ := udp_sock()
	defer net.close(peer)
	leaked := 0
	for _ in 0 ..< 100 {
		fwd_listen(&r.d, []cnet.Address{LO4})
		if !testing.expect_value(t, len(fw.lst), 2) {
			return
		}
		tcp_i, udp_i := 0, 1
		if fw.lst[0].udp {
			tcp_i, udp_i = 1, 0
		}
		c1 := dial(&r, tcp_i)
		c2 := dial(&r, tcp_i)
		net.send_to(peer, transmute([]u8)string("x"), fw.lst[udp_i].ep)
		for _ in 0 ..< STEP_LIMIT {
			if len(fw.conns) == 2 && fw.stats.conns == 2 && len(fw.udp) == 1 && fw.conns[0].state == .Open && fw.conns[1].state == .Open {
				break
			}
			echo_step(&e)
			rig_step(&r)
		}
		testing.expect_value(t, len(fw.conns), 2)
		testing.expect_value(t, len(fw.udp), 1)
		// Every socket of the relay, by descriptor and inode.
		Sock_Id :: struct {
			fd:  i32,
			ino: u64,
		}
		ids := make([dynamic]Sock_Id, context.temp_allocator)
		for l in fw.lst {
			append(&ids, Sock_Id{l.sock.fd, fwd_test_sock_ino(l.sock.fd)})
		}
		for c in fw.conns {
			for s in c.sock {
				append(&ids, Sock_Id{s.fd, fwd_test_sock_ino(s.fd)})
			}
		}
		for s in fw.udp {
			append(&ids, Sock_Id{s.sock.fd, fwd_test_sock_ino(s.sock.fd)})
		}
		forward_down(&r.d)
		for id in ids {
			if id.ino != 0 && fwd_test_sock_ino(id.fd) == id.ino {
				leaked += 1
			}
		}
		testing.expect_value(t, len(fw.conns), 0)
		testing.expect_value(t, len(fw.udp), 0)
		testing.expect_value(t, len(fw.lst), 0)
		testing.expect_value(t, fw.stats.conns, 0)
		testing.expect_value(t, fw.stats.udp_sessions, 0)
		net.close(c1)
		net.close(c2)
		// The echo side sees the ends and closes its sockets.
		for _ in 0 ..< 200 {
			echo_step(&e)
			if len(e.conns) == 0 {
				break
			}
			rig_step(&r, 1)
		}
	}
	for _ in 0 ..< 10 {
		echo_step(&e)
		rig_step(&r)
	}
	testing.expect_value(t, leaked, 0)
	testing.expect_value(t, len(e.conns), 0)
	testing.expect_value(t, fw.stats.opened, 300)
}

// An address that is not ready is tried again each tick, and one warning comes
// at the end.
@(test)
test_forward_bind_retry :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", 9)})) {
		return
	}
	defer rig_destroy(&r)
	fw := r.d.fwd
	// 192.0.2.0/24 is for documentation: no host has it.
	fwd_listen(&r.d, []cnet.Address{cnet.IP4_Address{192, 0, 2, 77}})
	testing.expect_value(t, len(fw.lst), 0)
	testing.expect_value(t, len(fw.retries), 1)
	fw.retry_until = now_of(&r.d) + 60 * time.Millisecond
	for _ in 0 ..< STEP_LIMIT {
		if len(fw.retries) == 0 {
			break
		}
		rig_step(&r)
	}
	testing.expect_value(t, len(fw.retries), 0)
	testing.expect_value(t, len(fw.lst), 0)
	testing.expect(t, !fw.t_tick.on)
}

// The listeners bind to the tunnel addresses of the pushed options, and to no
// other address.
@(test)
test_forward_up_tunnel_addresses :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	e: Echo
	echo_init(&e)
	defer echo_destroy(&e)
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", e.port)})) {
		return
	}
	defer rig_destroy(&r)
	fw := r.d.fwd
	po: push.Pushed_Options
	po.ifconfig = push.Ifconfig {
		a = {127, 0, 0, 1},
		b = {255, 255, 255, 0},
	}
	po.ifconfig6 = push.Ifconfig6 {
		addr = {15 = 1},
		bits = 64,
	}
	// Linux: with no name for the tunnel device, nothing opens.
	when ODIN_OS == .Linux {
		forward_up(&r.d, &po)
		testing.expect_value(t, len(fw.lst), 0)
	}
	// The loopback device plays the tunnel device: it has both addresses.
	r.d.dco.dev = true
	r.d.dco.name = "lo"
	forward_up(&r.d, &po)
	when ODIN_OS == .Linux {
		testing.expect_value(t, string(fw.dev[:fw.dev_n]), "lo")
	}
	// The IPv6 loopback may be off in a container.
	testing.expect(t, len(fw.lst) >= 1)
	have6 := false
	for l in fw.lst {
		switch a in l.ep.address {
		case cnet.IP4_Address:
			testing.expect_value(t, a, cnet.IP4_Address{127, 0, 0, 1})
		case cnet.IP6_Address:
			have6 = true
			testing.expect_value(t, a, cnet.IP6_Address{0, 0, 0, 0, 0, 0, 0, 1})
		}
	}
	// A connection through the IPv4 listener reaches the target.
	if len(fw.lst) > 0 {
		c := dial(&r, 0)
		defer net.close(c)
		testing.expect(t, round_trip(&r, &e, c, "tun"))
	}
	if have6 {
		for i in 0 ..< len(fw.lst) {
			if _, v6 := fw.lst[i].ep.address.(cnet.IP6_Address); v6 {
				c6, _, err := net.tcp_connect(fw.lst[i].ep)
				testing.expect_value(t, err, net.Error.None)
				defer net.close(c6)
				for _ in 0 ..< STEP_LIMIT {
					if net.tcp_connect_finish(c6) != .Would_Block {
						break
					}
					rig_step(&r)
				}
				testing.expect(t, round_trip(&r, &e, c6, "tun6"))
			}
		}
	}
	forward_down(&r.d)
	testing.expect_value(t, len(fw.lst), 0)
}

@(test)
test_forward_none_without_config :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	d.cfg = &cfg
	forward_attach(&d)
	testing.expect(t, d.fwd == nil)
	// With no relay these do nothing.
	forward_down(&d)
	forward_detach(&d)
}

// The stats fields are written with no allow-inbound, and not at all with no
// forward.
@(test)
test_forward_stats_fields :: proc(t: ^testing.T) {
	r: Rig
	if !testing.expect(t, rig_init(&r, {tcp_forward("127.0.0.1", 9)})) {
		return
	}
	defer rig_destroy(&r)
	testing.expect(t, r.d.acl == nil)
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)
	bus.begin_obj(&w)
	forward_write_stats(&w, &r.d)
	bus.end(&w)
	text := string(bus.writer_bytes(&w))
	for name in ([]string{"fwd_conns", "fwd_udp_sessions", "fwd_opened", "fwd_refused", "fwd_failed", "fwd_bytes_in", "fwd_bytes_out"}) {
		testing.expectf(t, strings.contains(text, name), "%s is missing in %s", name, text)
	}
	other: Daemon
	bus.writer_reset(&w)
	bus.begin_obj(&w)
	forward_write_stats(&w, &other)
	bus.end(&w)
	testing.expect_value(t, string(bus.writer_bytes(&w)), "{}")
}

// A connect that fails goes on with the next address of the target.
@(test)
test_forward_next_address :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	r: Rig
	e: Echo
	echo_init(&e)
	defer echo_destroy(&e)
	if !testing.expect(t, rig_init(&r, {tcp_forward("multi.test", e.port)})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	// The echo server listens on 127.0.0.1 only, so ::1 connection will be
	// refused immediately on every system.
	fw.lines[0].addrs = {cnet.IP6_Loopback, cnet.IP4_Address{127, 0, 0, 1}, nil, nil}
	fw.lines[0].n = 2
	fw.lines[0].until = now_of(&r.d) + time.Hour
	c := dial(&r, 0)
	defer net.close(c)
	testing.expect(t, round_trip(&r, &e, c, "second"))
	testing.expect_value(t, fw.lookups, 0)
	testing.expect_value(t, fw.stats.opened, 1)
	testing.expect_value(t, fw.stats.failed, 0)
}

// A name that does not resolve fails the connection, and the failure is not
// kept: the next connection looks the name up again.
@(test)
test_forward_lookup_failed :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 120 * time.Second)
	r: Rig
	if !testing.expect(t, rig_init(&r, {tcp_forward("no-such-name.invalid", 9)})) {
		return
	}
	defer rig_destroy(&r)
	fwd_listen(&r.d, []cnet.Address{LO4})
	fw := r.d.fwd
	for i in 1 ..= 2 {
		c := dial(&r, 0)
		testing.expect(t, closed_by_relay(&r, c), "the peer connection stayed open")
		net.close(c)
		testing.expect_value(t, fw.lookups, i)
		testing.expect_value(t, int(fw.stats.failed), i)
	}
	testing.expect_value(t, fw.stats.opened, 0)
	testing.expect_value(t, len(fw.conns), 0)
	testing.expect(t, rig_events_have(&r, `"what":"close"`, `"reason":"lookup_failed"`))
}
