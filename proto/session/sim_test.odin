// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:fmt"
import "core:time"

// The test bench: one client session, one fake server, two queues between
// them and a clock that jumps from wake-up to wake-up. Nothing sleeps.

LINK_Q :: 256

Link_Q :: struct {
	pk:   [LINK_Q]Fake_Pkt,
	head: int,
	n:    int,
}

Sim :: struct {
	s:         Session,
	f:         Fake,
	cfg:       Config,
	now:       Time,
	rng:       u64,
	started:   bool,
	// The data channel of the client runs behind a loopback owner (remote_test.odin).
	remote:    bool,
	c2s:       Link_Q,
	s2c:       Link_Q,
	// Link impairments (counted in packets of that direction).
	kill_c2s:  int, // drop the next n packets
	kill_s2c:  int,
	dup_s2c:   bool, // send every packet twice
	dup_c2s:   bool,
	swap_s2c:  bool, // deliver pairs in reverse order
	swap_c2s:  bool,
	loss_c2s:  int, // random loss in percent
	loss_s2c:  int,
	// Bytes of the TCP stream towards the client and how it is cut.
	stream:    [32768]u8,
	stream_n:  int,
	chunk:     int,
	// What the client reported.
	ev:        [128]Event,
	ev_n:      int,
	tunnel:    [32]Fake_Pkt,
	tunnel_n:  int,
	tx_buf:    [LINK_BUF_SIZE]u8,
	moved:     int,
	// Packet counts on the link.
	c2s_pkts:  int,
	s2c_pkts:  int,
}

test_random :: proc(user: rawptr, buf: []u8) -> bool {
	m := (^Sim)(user)
	for i in 0 ..< len(buf) {
		m.rng ~= m.rng >> 12
		m.rng ~= m.rng << 25
		m.rng ~= m.rng >> 27
		buf[i] = u8((m.rng * 0x2545F4914F6CDD1D) >> 56)
	}
	return true
}

rnd_pct :: proc(m: ^Sim) -> int {
	m.rng ~= m.rng >> 12
	m.rng ~= m.rng << 25
	m.rng ~= m.rng >> 27
	return int(((m.rng * 0x2545F4914F6CDD1D) >> 33) % 100)
}

sim_new :: proc(o: Fake_Opts) -> ^Sim {
	m := new(Sim)
	m.rng = 0x1234_5678_9abc_def1
	m.chunk = 1 << 20
	if !fake_init(&m.f, o) {
		free(m)
		return nil
	}
	fake_client_config(&m.f, &m.cfg)
	m.cfg.random = test_random
	m.cfg.random_user = m
	m.now = time.Second
	return m
}

// Starts the client. Change `m.cfg` before this.
sim_start :: proc(m: ^Sim) -> Error {
	err := session_init(&m.s, &m.cfg)
	if err != .None {
		return err
	}
	m.started = true
	if m.remote {
		loop_attach(&m.s)
	}
	return session_start(&m.s, m.now, FAKE_WALL_BASE + i64(m.now / time.Second))
}

sim_free :: proc(m: ^Sim) {
	if m.started {
		session_destroy(&m.s)
	}
	fake_destroy(&m.f)
	free(m)
}

q_push :: proc(q: ^Link_Q, pkt: []u8) {
	if q.n >= LINK_Q {
		return
	}
	p := &q.pk[(q.head + q.n) % LINK_Q]
	p.n = len(pkt)
	copy(p.b[:], pkt)
	q.n += 1
}

q_pop :: proc(q: ^Link_Q, out: ^Fake_Pkt) -> bool {
	if q.n == 0 {
		return false
	}
	out^ = q.pk[q.head]
	q.head = (q.head + 1) % LINK_Q
	q.n -= 1
	return true
}

// Applies loss, duplication and reordering to one packet entering a queue.
impair_push :: proc(m: ^Sim, q: ^Link_Q, pkt: []u8, kill: ^int, loss: int, dup, swap: bool) {
	if kill^ > 0 {
		kill^ -= 1
		return
	}
	if loss > 0 && rnd_pct(m) < loss {
		return
	}
	q_push(q, pkt)
	if dup {
		q_push(q, pkt)
	}
	if swap && q.n >= 2 && q.n % 2 == 0 {
		a := (q.head + q.n - 1) % LINK_Q
		b := (q.head + q.n - 2) % LINK_Q
		q.pk[a], q.pk[b] = q.pk[b], q.pk[a]
	}
}

sim_drain_events :: proc(m: ^Sim) {
	for {
		ev, ok := session_next_event(&m.s)
		if !ok {
			break
		}
		if m.ev_n < len(m.ev) {
			m.ev[m.ev_n] = ev
			m.ev_n += 1
		}
	}
}

sim_has_event :: proc(m: ^Sim, kind: Event_Kind) -> bool {
	for i in 0 ..< m.ev_n {
		if m.ev[i].kind == kind {
			return true
		}
	}
	return false
}

sim_count_event :: proc(m: ^Sim, kind: Event_Kind) -> (n: int) {
	for i in 0 ..< m.ev_n {
		if m.ev[i].kind == kind {
			n += 1
		}
	}
	return
}

sim_last_event :: proc(m: ^Sim, kind: Event_Kind) -> (ev: Event, ok: bool) {
	for i := m.ev_n - 1; i >= 0; i -= 1 {
		if m.ev[i].kind == kind {
			return m.ev[i], true
		}
	}
	return
}

take_tunnel :: proc(m: ^Sim, pkt: []u8) {
	if len(pkt) == 0 {
		return
	}
	if m.tunnel_n < len(m.tunnel) {
		p := &m.tunnel[m.tunnel_n]
		p.n = len(pkt)
		copy(p.b[:], pkt)
		m.tunnel_n += 1
	}
}

// One round of I/O. Returns true if anything moved.
sim_io :: proc(m: ^Sim) -> bool {
	moved := false
	tcp := m.cfg.transport == .Tcp
	// Client to server.
	for {
		n := session_poll_tx(&m.s, m.tx_buf[:], m.now)
		if n == 0 {
			break
		}
		moved = true
		m.c2s_pkts += 1
		pkt := m.tx_buf[:n]
		if tcp {
			l := int(pkt[0]) << 8 | int(pkt[1])
			if l != n - 2 {
				panic("bad TCP frame length from the client")
			}
			pkt = pkt[2:]
		}
		impair_push(m, &m.c2s, pkt, &m.kill_c2s, m.loss_c2s, m.dup_c2s, m.swap_c2s)
	}
	p: Fake_Pkt
	for q_pop(&m.c2s, &p) {
		moved = true
		fake_receive(&m.f, p.b[:p.n], m.now)
	}
	// Server to client.
	out: [LINK_BUF_SIZE]u8
	for {
		n := fake_poll(&m.f, out[:], m.now)
		if n == 0 {
			break
		}
		moved = true
		m.s2c_pkts += 1
		if tcp {
			if m.stream_n + n + 2 <= len(m.stream) {
				m.stream[m.stream_n] = u8(n >> 8)
				m.stream[m.stream_n + 1] = u8(n)
				copy(m.stream[m.stream_n + 2:], out[:n])
				m.stream_n += n + 2
			}
		} else {
			impair_push(m, &m.s2c, out[:n], &m.kill_s2c, m.loss_s2c, m.dup_s2c, m.swap_s2c)
		}
	}
	for q_pop(&m.s2c, &p) {
		moved = true
		r := session_receive(&m.s, p.b[:p.n], m.now)
		take_tunnel(m, r.tunnel)
	}
	for m.stream_n > 0 {
		moved = true
		take := min(m.stream_n, m.chunk)
		r := session_receive(&m.s, m.stream[:take], m.now)
		take_tunnel(m, r.tunnel)
		copy(m.stream[:], m.stream[r.consumed:m.stream_n])
		m.stream_n -= r.consumed
		more := r.more
		for more {
			r2 := session_receive(&m.s, nil, m.now)
			take_tunnel(m, r2.tunnel)
			more = r2.more
		}
		if r.consumed == 0 {
			break
		}
	}
	sim_drain_events(m)
	return moved
}

// Runs I/O to a standstill.
sim_settle :: proc(m: ^Sim) {
	for _ in 0 ..< 2000 {
		if !sim_io(m) {
			return
		}
	}
	panic("the link never went quiet")
}

// Moves the clock to the next wake-up of either side and ticks both.
// Returns false if neither side wants one.
sim_advance :: proc(m: ^Sim, limit: Time) -> bool {
	at: Time
	ok := false
	if t, k := session_next_wakeup(&m.s, m.now); k {
		at, ok = t, true
	}
	if t, k := fake_wake(&m.f, m.now); k && (!ok || t < at) {
		at, ok = t, true
	}
	if !ok || at > limit {
		return false
	}
	m.now = max(at, m.now)
	session_tick(&m.s, m.now)
	fake_tick(&m.f, m.now)
	return true
}

Goal :: #type proc(m: ^Sim) -> bool

// Runs until `goal` holds, for at most `span` of simulated time. Returns
// whether the goal was reached.
sim_run :: proc(m: ^Sim, goal: Goal, span: Time) -> bool {
	limit := m.now + span
	steps := 0
	for {
		sim_settle(m)
		if goal(m) {
			return true
		}
		steps += 1
		if steps > 200000 {
			panic("the clock does not move")
		}
		before := m.now
		if !sim_advance(m, limit) {
			// Nobody has a timer: stuck, or the limit passed.
			sim_settle(m)
			return goal(m)
		}
		if m.now == before {
			// A wake-up at "now" that changes nothing must not spin: nudge.
			m.now += time.Millisecond
		}
	}
}

// Advances the clock by `span`, running every timer on the way.
sim_idle :: proc(m: ^Sim, span: Time) {
	end := m.now + span
	for {
		sim_settle(m)
		before := m.now
		if !sim_advance(m, end) {
			break
		}
		if m.now == before {
			m.now += time.Millisecond
		}
	}
	m.now = max(m.now, end)
	session_tick(&m.s, m.now)
	fake_tick(&m.f, m.now)
	sim_settle(m)
}

// ----------------------------------------------------------------- goals

g_up :: proc(m: ^Sim) -> bool {
	return m.s.state == .Up
}

g_failed :: proc(m: ^Sim) -> bool {
	return m.s.state == .Failed
}

g_closed :: proc(m: ^Sim) -> bool {
	return m.s.state == .Closed
}

g_done :: proc(m: ^Sim) -> bool {
	return m.s.state == .Failed || m.s.state == .Closed
}

// ----------------------------------------------------------- tunnel traffic

// A valid IPv4 packet with an ICMP echo request of `payload` bytes.
make_ip_packet :: proc(buf: []u8, payload: int, seq: u16) -> int {
	total := 20 + 8 + payload
	b := buf[:total]
	for i in 0 ..< total {
		b[i] = 0
	}
	b[0] = 0x45
	b[2] = u8(total >> 8)
	b[3] = u8(total)
	b[8] = 64
	b[9] = 1
	b[12], b[13], b[14], b[15] = 10, 8, 0, 2
	b[16], b[17], b[18], b[19] = 10, 8, 0, 1
	b[20] = 8
	b[26] = u8(seq >> 8)
	b[27] = u8(seq)
	for i in 0 ..< payload {
		b[28 + i] = u8(i * 7 + int(seq))
	}
	return total
}

// Sends one tunnel packet from the client and returns the link packet that
// went out (for the fake server) through the normal queues.
sim_send_ip :: proc(m: ^Sim, payload: int, seq: u16) -> Error {
	buf: [LINK_BUF_SIZE]u8
	n := make_ip_packet(buf[TUNNEL_HEADROOM:], payload, seq)
	pkt, err := session_encap(&m.s, buf[:], n, m.now)
	if err != .None {
		return err
	}
	if m.cfg.transport == .Tcp {
		pkt = pkt[2:]
	}
	m.c2s_pkts += 1
	impair_push(m, &m.c2s, pkt, &m.kill_c2s, m.loss_c2s, m.dup_c2s, m.swap_c2s)
	return .None
}

// Sends `count` packets and checks that the echoes come back unchanged.
// Returns how many matched.
sim_echo :: proc(m: ^Sim, count: int, payload: int) -> int {
	m.tunnel_n = 0
	for i in 0 ..< count {
		if sim_send_ip(m, payload, u16(i)) != .None {
			break
		}
		sim_settle(m)
	}
	sim_settle(m)
	ok := 0
	for i in 0 ..< m.tunnel_n {
		want: [LINK_BUF_SIZE]u8
		n := make_ip_packet(want[:], payload, u16(i))
		got := m.tunnel[i]
		if got.n == n && string(got.b[:n]) == string(want[:n]) {
			ok += 1
		}
	}
	return ok
}

// Prints the state of both sides (for a failing test).
sim_dump :: proc(m: ^Sim) {
	fmt.eprintfln("now=%v client state=%v ks=%v id=%d fail=%v", m.now, m.s.state, m.s.ks.state, m.s.ks.id, m.s.fail_reason)
	fmt.eprintfln("  km_sent=%v km_got=%v push_done=%v tls_ok=%v", m.s.ks.km_sent, m.s.ks.km_got, m.s.ks.push_done, m.s.ks.tls_ok)
	fmt.eprintfln("  counters=%v", m.s.counters)
	fmt.eprintfln("fake: peer_set=%v key=%d up=%v installed=%v tls_ok=%v failed=%v km_got=%v km_sent=%v pushed=%v", m.f.peer_set, m.f.key_id, m.f.state_up, m.f.installed, m.f.tls_ok, m.f.tls_failed, m.f.km_got, m.f.km_sent, m.f.pushed)
	fmt.eprintfln("  link: c2s=%d s2c=%d", m.c2s_pkts, m.s2c_pkts)
	for i in 0 ..< m.ev_n {
		e := &m.ev[i]
		fmt.eprintfln("  event %v reason=%v key=%d text=%q", e.kind, e.reason, e.key_id, event_text(e))
	}
}
