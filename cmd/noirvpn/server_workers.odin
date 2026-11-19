// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:time"
import net "noir:platform/net"
import "noir:proto/session"

// Server data path with crypto workers (`workers N`, see crypto_worker.odin).
// Each client session is pinned to one worker when created. Without workers none of
// this runs: `d.wk` is nil and the loops call the session directly.
//
//   receive  - the session hands each data packet to `srv_take` (becomes a job
//              and a record)
//            - a control packet is handled at once, after `srv_barrier` has
//              finished the data packets before it
//            - `srv_rx_flush` runs the jobs and finishes the records in order
//              (counters, route, tun write)
//   send     - `seal_and_queue` adds a job and keeps the packet in its batch slot
//            - `out_flush` runs the jobs
//            - `out_finish` applies results in slot order, moves sealed TCP
//              packets to their queues, drops slots that did not seal
//
// The receive buffer and batch slots are not reused before the jobs that point
// into them are done.

// A received data packet that waits for its worker.
Srv_Rec :: struct {
	job:      ^Wk_Job,
	cidx:     u32, // the conn's slot in the table
	sess:     u64, // and its session number: the conn may be gone when the job is done
	from:     session.Peer_Addr, // UDP: where the datagram came from
	has_from: bool,
	local:    net.Local, // UDP: the address of this host it was sent to
}

// A conn to pump once the records are done.
Srv_Ref :: struct {
	cidx: u32,
	sess: u64,
}

// The `cidx` of a reference to no conn.
NO_CONN :: max(u32)

// The conn of a table slot, if it is still the session `sess`.
conn_alive :: proc(d: ^Srv, cidx: u32, sess: u64) -> ^Conn {
	if int(cidx) >= len(d.conns) {
		return nil
	}
	c := d.conns[cidx]
	if c == nil || c.sess != sess || !c.s_ok {
		return nil
	}
	return c
}

// ---------------------------------------------------------------------- start

// Starts the workers named in the config. False: the daemon cannot start.
srv_workers_start :: proc(d: ^Srv) -> bool {
	n := d.cfg.workers
	if n <= 0 {
		return true
	}
	if d.dco.on {
		who := dco_who(d.dco.kind)
		if d.dco.mixed {
			logf(.Notice, "workers %d: ignored, because %s handles the data channel (the tls clients of a mixed server run on the main thread)", n, who)
		} else {
			logf(.Notice, "workers %d: ignored, because %s handles the data channel", n, who)
		}
		return true
	}
	d.wk = pool_start(n)
	if d.wk == nil {
		logf(.Error, "cannot start the crypto workers")
		return false
	}
	d.recs = make([dynamic]Srv_Rec, 0, WK_JOBS * 4)
	d.later = make([dynamic]Srv_Ref, 0, 64)
	logf(.Info, "crypto workers: %d", n)
	return true
}

// Gives the data channel of a new session to a worker.
srv_workers_attach :: proc(d: ^Srv, c: ^Conn) -> bool {
	if d.wk == nil {
		return true
	}
	w, ok := pool_attach(d.wk, &c.s, d, srv_take, srv_barrier)
	if !ok {
		return false
	}
	c.wkr = w
	return true
}

// Stops the workers. Call it after the last session is gone.
srv_workers_stop :: proc(d: ^Srv) {
	pool_stop(d.wk)
	d.wk = nil
	delete(d.recs)
	delete(d.later)
}

// ------------------------------------------------------------------------ rx

// Starts a call into the session of `c` that may hand packets to the hooks
// below. The conn counts as busy: nothing releases it until `srv_rx_leave`
// (a release waits for the pump that follows).
srv_rx_enter :: proc(d: ^Srv, c: ^Conn, from: []u8, local: net.Local) {
	if d.wk == nil {
		return
	}
	d.rx_conn = c
	c.in_pump = true
	d.rx_has_from = len(from) > 0
	d.rx_local = local
	if d.rx_has_from {
		d.rx_from.n = u8(copy(d.rx_from.b[:], from))
	}
}

srv_rx_leave :: proc(d: ^Srv, c: ^Conn) {
	if d.wk == nil {
		return
	}
	d.rx_conn = nil
	c.in_pump = false
}

// The session offers a data packet. It becomes a job on this session's worker;
// the tunnel packet comes out of `srv_rx_run`. True: taken.
srv_take :: proc(host: rawptr, s: ^session.Session, pkt: []u8, now: time.Duration) -> bool {
	d := (^Srv)(host)
	c := d.rx_conn
	if c == nil || &c.s != s || c.wkr == nil {
		return false
	}
	buf := pkt
	if !inside(pkt, d.rx_buf) {
		// A frame of a TCP stream, in the session's own buffer: copy it.
		room := len(d.rx_buf) - RX_COPY_AT
		if len(pkt) > room {
			return false
		}
		if d.rx_copied + len(pkt) > room {
			srv_rx_run(d, true)
		}
		buf = d.rx_buf[RX_COPY_AT + d.rx_copied:][:len(pkt)]
		copy(buf, pkt)
		d.rx_copied += len(pkt)
	}
	dp := session.session_remote_dp(s)
	j := job_add(c.wkr, .Rx, dp, buf, 0, now)
	if j == nil {
		// The lane is full: run what it has, then start again.
		srv_rx_run(d, true)
		j = job_add(c.wkr, .Rx, dp, buf, 0, now)
		if j == nil {
			return false
		}
	}
	d.taken += 1
	append(&d.recs, Srv_Rec{job = j, cidx = c.slot, sess = c.sess, from = d.rx_from, has_from = d.rx_has_from, local = d.rx_local})
	return true
}

// A control packet is next: finish the data packets before it.
srv_barrier :: proc(host: rawptr) {
	d := (^Srv)(host)
	if len(d.recs) > 0 {
		srv_rx_run(d, true)
	}
}

// Runs the jobs, then finishes the records in packet order: session counters
// and clock, then the route of the tunnel packet. `nested`: a session is in
// `session_receive`; the conns are looked at later.
srv_rx_run :: proc(d: ^Srv, nested: bool) {
	if len(d.recs) == 0 || d.rx_running {
		return
	}
	d.rx_running = true
	lane_run(d.wk, .Rx)
	prev := Srv_Ref{cidx = NO_CONN}
	for i in 0 ..< len(d.recs) {
		rec := &d.recs[i]
		c := conn_alive(d, rec.cidx, rec.sess)
		if c == nil {
			continue
		}
		from: []u8
		if rec.has_from {
			from = session.peer_addr_bytes(&rec.from)
		}
		j := rec.job
		rx_before := c.s.counters.data_rx
		plain := session.session_rx_finish(&c.s, j.buf, j.open, j.now, from)
		if c.s.counters.data_rx != rx_before {
			conn_follow_local(d, c, rec.local)
		}
		if len(plain) > 0 {
			srv_on_tunnel(d, c, plain)
		}
		ref := Srv_Ref{rec.cidx, rec.sess}
		if ref != prev {
			// The conn before this one is done for now.
			if prev.cidx != NO_CONN {
				srv_note_conn(d, prev, nested)
			}
			prev = ref
		}
	}
	if prev.cidx != NO_CONN {
		srv_note_conn(d, prev, nested)
	}
	clear(&d.recs)
	// Joined runs may point into the copy area: write them before it is reused.
	srv_flush_tun(d)
	d.rx_copied = 0
	lane_recycle(d.wk, .Rx)
	d.rx_running = false
	if !nested {
		srv_pump_later(d)
	}
}

// What the loops did after each data packet: look at the session's output.
srv_note_conn :: proc(d: ^Srv, ref: Srv_Ref, nested: bool) {
	if nested {
		append(&d.later, ref)
		return
	}
	if c := conn_alive(d, ref.cidx, ref.sess); c != nil {
		conn_pump(d, c, false)
	}
}

srv_pump_later :: proc(d: ^Srv) {
	for i := 0; i < len(d.later); i += 1 {
		ref := d.later[i]
		if c := conn_alive(d, ref.cidx, ref.sess); c != nil {
			conn_pump(d, c, false)
		}
	}
	clear(&d.later)
}

// The end of a round of reading: finish the jobs, look at the conns, write what
// is joined.
srv_rx_flush :: proc(d: ^Srv) {
	srv_rx_look(d)
	if d.wk != nil {
		srv_rx_run(d, false)
		if len(d.later) > 0 {
			srv_pump_later(d)
		}
	}
	srv_flush_tun(d)
}

// ------------------------------------------------------------------------ tx

// The packet in `slot` (`n` bytes at TUNNEL_HEADROOM) goes to the worker of `c`.
// False: it cannot be sealed (counted by the caller).
seal_submit :: proc(d: ^Srv, c: ^Conn, slot: ^Tx_Slot, n: int, now: time.Duration) -> bool {
	if err := session.session_encap_check(&c.s, slot.buf[:], n); err != .None {
		return false
	}
	j := job_add(c.wkr, .Tx, session.session_remote_dp(&c.s), slot.buf[:], n, now)
	if j == nil {
		return false
	}
	slot.job = j
	slot.cidx = c.slot
	slot.sess = c.sess
	slot.n = n
	if c.proto == .Tcp {
		c.tx_wait += n + session.session_seal_overhead(&c.s)
	}
	d.out.count += 1
	return true
}

// Applies results of the waiting slots, in order: a sealed UDP packet stays in
// the batch; a TCP one goes to its queue; others are dropped and counted. The
// batch is packed afterwards. Not re-entrant: `out_flush` stays away while it
// runs (the pump of a conn below may send control packets, which never use the batch).
out_finish :: proc(d: ^Srv) {
	o := &d.out
	if d.wk == nil || o.done == o.count {
		o.done = o.count
		return
	}
	assert(!o.sealing)
	o.sealing = true
	lane_run(d.wk, .Tx)
	keep := o.done
	for i in o.done ..< o.count {
		s := &o.slots[i]
		c := conn_alive(d, s.cidx, s.sess)
		if c != nil && c.proto == .Tcp {
			c.tx_wait = max(c.tx_wait - (s.n + session.session_seal_overhead(&c.s)), 0)
		}
		if c == nil {
			d.stats.drop_conn_state += 1
			continue
		}
		pkt, err := session.session_encap_done(&c.s, s.buf[:], s.job.seal, s.job.now)
		if err != .None {
			d.stats.drop_seal += 1
			c.drops += 1
			continue
		}
		c.out_pkts += 1
		c.out_bytes += u64(s.n)
		cidx, sess := s.cidx, s.sess
		if c.proto == .Tcp {
			// A queue that cannot take the packet may close the client: `c` can be gone.
			tcp_append(d, c, pkt, true)
		} else {
			s.off = int(uintptr(raw_data(pkt)) - uintptr(raw_data(s.buf[:])))
			s.len = len(pkt)
			s.lidx = c.lidx
			s.ep = c.ep
			s.local = c.local
			if keep != i {
				slot_move(&o.slots[keep], s)
			}
			keep += 1
		}
		// Sealing can start a rekey (bytes, packets, time); its packets wait in the
		// session. Look at the session now and then so they go out without delay.
		if c = conn_alive(d, cidx, sess); c != nil && c.out_pkts & 63 == 0 {
			conn_pump(d, c)
		}
	}
	lane_recycle(d.wk, .Tx)
	o.count = keep
	o.done = keep
	o.sealing = false
}

// Moves the sealed packet of `src` into `dst` (an earlier slot).
slot_move :: proc(dst, src: ^Tx_Slot) {
	copy(dst.buf[src.off:][:src.len], src.buf[src.off:][:src.len])
	dst.off, dst.len, dst.lidx, dst.ep, dst.local = src.off, src.len, src.lidx, src.ep, src.local
}
