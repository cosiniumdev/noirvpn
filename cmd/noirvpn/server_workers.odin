// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:time"
import net "noir:platform/net"
import "noir:proto/session"

// Server data path with crypto workers (`workers N`, see crypto_worker.odin).
// Each client session is pinned to one worker when created. Without workers none of
// this runs: `d.wk` is nil and the loops call the session directly. The main
// thread never waits for a worker.

// A received data packet that waits for its worker.
Srv_Rec :: struct {
	cidx:     u32, // the conn's slot in the table
	sess:     u64, // and its session number
	from:     session.Peer_Addr, // UDP: where the datagram came from
	has_from: bool,
	local:    net.Local, // UDP: the address of this host it was sent to
}

// A tunnel packet that waits for its worker to seal it.
Srv_Tx_Rec :: struct {
	cidx: u32,
	sess: u64,
}

// A conn to look at.
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
	d.wk = pool_start(n, &d.loop)
	if d.wk == nil {
		logf(.Error, "cannot start the crypto workers")
		return false
	}
	d.wk_rx = make([]Srv_Rec, pool_jobs(d.wk))
	d.wk_tx = make([]Srv_Tx_Rec, pool_jobs(d.wk))
	logf(.Info, "crypto workers: %d", n)
	return true
}

// Gives the data channel of a new session to a worker.
srv_workers_attach :: proc(d: ^Srv, c: ^Conn) -> bool {
	if d.wk == nil {
		return true
	}
	w, ok := pool_attach(d.wk, &c.s, d, srv_take)
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
	delete(d.wk_rx)
	delete(d.wk_tx)
	d.wk_rx, d.wk_tx = nil, nil
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
// the tunnel packet comes out of `srv_wk_drain`. True: taken (or dropped, when
// the worker has no free batch).
srv_take :: proc(host: rawptr, s: ^session.Session, pkt: []u8, now: time.Duration) -> bool {
	d := (^Srv)(host)
	c := d.rx_conn
	if c == nil || &c.s != s || c.wkr == nil || len(pkt) > WK_SLOT {
		return false
	}
	d.taken += 1
	j, id := job_add(c.wkr, .Rx, session.session_remote_dp(s), pkt, 0, now)
	if j == nil {
		return true
	}
	d.wk_rx[id] = Srv_Rec {
		cidx     = c.slot,
		sess     = c.sess,
		from     = d.rx_from,
		has_from = d.rx_has_from,
		local    = d.rx_local,
	}
	return true
}

// The records of an open batch, in packet order: session counters and clock,
// then the route of the tunnel packet. Each conn is looked at after its run of
// packets.
srv_open_done :: proc(d: ^Srv, b: ^Wk_Batch) {
	// The coalescer keeps slices of the batch memory until `srv_flush_tun`.
	d.rx_stable = b.mem
	prev := Srv_Ref{cidx = NO_CONN}
	for i in 0 ..< b.count {
		rec := &d.wk_rx[b.first + i]
		ref := Srv_Ref{rec.cidx, rec.sess}
		if ref != prev {
			if prev.cidx != NO_CONN {
				srv_look(d, prev)
			}
			prev = ref
		}
		c := conn_alive(d, rec.cidx, rec.sess)
		if c == nil {
			continue
		}
		from: []u8
		if rec.has_from {
			from = session.peer_addr_bytes(&rec.from)
		}
		j := &b.jobs[i]
		rx_before := c.s.counters.data_rx
		plain := session.session_rx_finish(&c.s, j.buf, j.open, j.now, from)
		if c.s.counters.data_rx != rx_before {
			conn_follow_local(d, c, rec.local)
		}
		if len(plain) > 0 {
			srv_on_tunnel(d, c, plain)
		}
	}
	if prev.cidx != NO_CONN {
		srv_look(d, prev)
	}
	srv_flush_tun(d)
	d.rx_stable = nil
}

srv_look :: proc(d: ^Srv, ref: Srv_Ref) {
	if c := conn_alive(d, ref.cidx, ref.sess); c != nil {
		conn_pump(d, c, false)
	}
}

// Uses every finished batch. Never waits.
srv_wk_drain :: proc(d: ^Srv) {
	if d.wk == nil || d.wk_draining {
		return
	}
	d.wk_draining = true
	defer d.wk_draining = false
	for b := pool_next(d.wk); b != nil; b = pool_next(d.wk) {
		if b.kind == .Open {
			srv_open_done(d, b)
		} else {
			srv_seal_done(d, b)
		}
		batch_free(b)
	}
	if d.tun_wk_wait && pool_room(d.wk, .Tx) >= WK_TUN_ROOM {
		d.tun_wk_wait = false
		if !d.out.blocked {
			srv_tun_pause(d, false)
		}
	}
	if rx_msgs_for_room(pool_room(d.wk, .Rx), d.rx_slot) > 0 {
		for &ln in d.listeners[:d.n_listen] {
			if ln.rx_paused {
				ln_rx_pause(d, &ln, false)
			}
		}
	}
	out_flush(d)
	flush_dirty(d)
}

// The end of a round of reading: look at the conns, start the workers, use what
// is done, write what is joined.
srv_rx_flush :: proc(d: ^Srv) {
	srv_rx_look(d)
	if d.wk != nil {
		pool_post(d.wk)
		srv_wk_drain(d)
	}
	srv_flush_tun(d)
}

// ------------------------------------------------------------------------ tx

// The packet in `slot` (`n` bytes at TUNNEL_HEADROOM) goes to the worker of `c`.
// The slot is free again at once. False: it cannot be sealed, or the worker has
// no free batch (counted by the caller).
seal_submit :: proc(d: ^Srv, c: ^Conn, slot: ^Tx_Slot, n: int, now: time.Duration) -> bool {
	if err := session.session_encap_check(&c.s, slot.buf[:], n); err != .None {
		return false
	}
	j, id := job_add(c.wkr, .Tx, session.session_remote_dp(&c.s), slot.buf[:], n, now)
	if j == nil {
		return false
	}
	d.wk_tx[id] = Srv_Tx_Rec{c.slot, c.sess}
	if c.proto == .Tcp {
		c.tx_wait += n + session.session_seal_overhead(&c.s)
	}
	return true
}

// The results of a seal batch, in order: a sealed UDP packet is copied to the
// send batch; a TCP one goes to its queue; others are dropped and counted.
srv_seal_done :: proc(d: ^Srv, b: ^Wk_Batch) {
	for i in 0 ..< b.count {
		rec := d.wk_tx[b.first + i]
		j := &b.jobs[i]
		c := conn_alive(d, rec.cidx, rec.sess)
		if c == nil {
			d.stats.drop_conn_state += 1
			continue
		}
		if c.proto == .Tcp {
			c.tx_wait = max(c.tx_wait - (j.n + session.session_seal_overhead(&c.s)), 0)
		}
		pkt, err := session.session_encap_done(&c.s, j.buf, j.seal, j.now)
		if err != .None {
			d.stats.drop_seal += 1
			c.drops += 1
			continue
		}
		c.out_pkts += 1
		c.out_bytes += u64(j.n)
		if c.proto == .Tcp {
			// A queue that cannot take the packet may close the client: `c` can be gone.
			tcp_append(d, c, pkt, true)
		} else {
			slot := out_next(d)
			if slot == nil {
				d.stats.drop_tx_busy += 1
				continue
			}
			off := int(uintptr(raw_data(pkt)) - uintptr(raw_data(j.buf)))
			copy(slot.buf[off:], pkt)
			slot.off = off
			slot.len = len(pkt)
			slot.lidx = c.lidx
			slot.ep = c.ep
			slot.local = c.local
			d.out.count += 1
		}
		// Sealing can start a rekey (bytes, packets, time); its packets wait in the
		// session. Look at the session now and then so they go out without delay.
		if c = conn_alive(d, rec.cidx, rec.sess); c != nil && c.out_pkts & 63 == 0 {
			conn_pump(d, c)
		}
	}
}
