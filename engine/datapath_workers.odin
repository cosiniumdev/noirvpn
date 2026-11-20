// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:time"
import net "noir:platform/net"
import "noir:proto/session"

// Client data path with crypto workers (`workers N`, crypto_worker.odin). Used
// only if `d.wkr` is set; with no workers the loops in datapath.odin call the
// session directly. The main thread never waits for the worker.

// ---------------------------------------------------------------------- tx

// Hands the waiting packets of the ring to the worker, in order. A slot the
// session cannot seal yet (no key) stays, with all slots after it. A packet that
// finds no free batch is dropped.
seal_ring :: proc(d: ^Daemon) {
	if d.blocked || ring_is_empty(&d.ring) || !d.s_ok {
		return
	}
	dp := session.session_remote_dp(&d.s)
	now := now_of(d)
	stream := d.proto != .Udp
	for !ring_is_empty(&d.ring) {
		slot := ring_at(&d.ring, 0)
		if slot.sealed || slot.bad {
			ring_pop(&d.ring, 1)
			continue
		}
		if cerr := session.session_encap_check(&d.s, slot.buf[:], slot.n); cerr != .None {
			#partial switch cerr {
			case .No_Key, .Not_Up:
				return
			}
			d.stats.drop_seal += 1
			ring_pop(&d.ring, 1)
			continue
		}
		if stream && net.tcp_pending(&d.tcp) + d.wk_tx_wait + wk_stream_cost(slot.n) > len(d.tcp.tx) - TCP_TX_RESERVE {
			// The socket is slower than the tun: the packets wait in the ring.
			return
		}
		if lane_room(d.wkr, .Tx) == 0 {
			// The packets wait in the ring until a batch comes back.
			return
		}
		j, id := job_add(d.wkr, .Tx, dp, slot.buf[:], slot.n, now)
		if j != nil {
			d.wk_recs[id] = d.wk_gen
			if stream {
				d.wk_tx_wait += wk_stream_cost(slot.n)
			}
		}
		ring_pop(&d.ring, 1)
	}
}

// Room a packet of `n` bytes takes in the TCP queue once sealed (an upper bound).
wk_stream_cost :: proc(n: int) -> int {
	return n + 64
}

// The sealed packets of a batch go out, in order.
wk_seal_done :: proc(d: ^Daemon, b: ^Wk_Batch) {
	stream := d.proto != .Udp
	for i in 0 ..< b.count {
		j := &b.jobs[i]
		mine := d.wk_recs[b.first + i] == d.wk_gen
		if stream && mine {
			d.wk_tx_wait = max(d.wk_tx_wait - wk_stream_cost(j.n), 0)
		}
		if !mine || !d.s_ok || !d.sock_open {
			continue
		}
		pkt, err := session.session_encap_done(&d.s, j.buf, j.seal, j.now)
		if err != .None {
			d.stats.drop_seal += 1
			continue
		}
		if stream {
			if !stream_append(d, pkt) {
				d.stats.drop_ring += 1
				continue
			}
			d.stats.sent_pkts += 1
			continue
		}
		d.wk_out[d.wk_nout] = pkt
		d.wk_nout += 1
		if d.wk_nout == TX_BATCH {
			wk_send_udp(d)
		}
	}
	if stream {
		stream_flush(d)
	} else {
		wk_send_udp(d)
	}
}

// Sends the sealed datagrams of `wk_out`. They are in batch memory, which is
// free after this: what the socket does not take now is dropped (counted in
// `drop_ring` and `sock_blocked`).
wk_send_udp :: proc(d: ^Daemon) {
	k := 0
	for k < d.wk_nout {
		net.batch_reset(&d.tx_batch)
		for x in k ..< d.wk_nout {
			net.batch_push(&d.tx_batch, d.wk_out[x], d.sock_to)
		}
		m := d.wk_nout - k
		sent, err := net.send_pushed(d.sock, &d.tx_batch)
		if errno, fresh := net.batch_take_gso_failure(&d.tx_batch); fresh {
			d.off.udp_gso_fallbacks += 1
			d.off.udp_gso = 0
			logf(.Warn, "UDP segmentation offload was refused (error %d), so datagrams will be sent one at a time", errno)
		}
		if err == .Would_Block {
			d.stats.sock_blocked += 1
			d.stats.drop_ring += u64(m)
			break
		}
		if err != .None {
			// Most likely ICMP "port unreachable" from an earlier packet: this one
			// is lost, the next one goes through.
			d.stats.sock_send_errors += 1
			k += 1
			continue
		}
		d.stats.sent_pkts += u64(sent)
		k += sent
		if sent < m {
			d.stats.sock_blocked += 1
			d.stats.drop_ring += u64(m - sent)
			break
		}
	}
	d.wk_nout = 0
}

// ---------------------------------------------------------------------- rx

// The session offers a data packet. It becomes a job on this session's worker;
// the tunnel packet comes out of `wk_drain`. True: taken (or dropped, when the
// worker has no free batch).
client_take :: proc(host: rawptr, s: ^session.Session, pkt: []u8, now: time.Duration) -> bool {
	d := (^Daemon)(host)
	if d.wkr == nil || len(pkt) > WK_SLOT {
		return false
	}
	if j, id := job_add(d.wkr, .Rx, session.session_remote_dp(s), pkt, 0, now); j != nil {
		d.wk_recs[id] = d.wk_gen
	}
	return true
}

// The tunnel packets of a batch go to the tun, in order.
wk_open_done :: proc(d: ^Daemon, b: ^Wk_Batch) {
	// The coalescer keeps slices of the batch memory until `flush_tun`.
	d.rx_stable = b.mem
	for i in 0 ..< b.count {
		if d.wk_recs[b.first + i] != d.wk_gen || !d.s_ok || !feed_ok(d) {
			continue
		}
		j := &b.jobs[i]
		plain := session.session_rx_finish(&d.s, j.buf, j.open, j.now)
		if len(plain) > 0 {
			write_tun(d, plain)
		}
	}
	flush_tun(d)
	d.rx_stable = nil
}

// Uses every finished batch. Never waits. True if a seal batch was among them.
wk_drain :: proc(d: ^Daemon) -> (sealed: bool) {
	if d.wk == nil || d.wk_draining {
		return false
	}
	d.wk_draining = true
	defer d.wk_draining = false
	for b := pool_next(d.wk); b != nil; b = pool_next(d.wk) {
		if b.kind == .Open {
			wk_open_done(d, b)
		} else {
			wk_seal_done(d, b)
			sealed = true
		}
		batch_free(b)
	}
	if d.rx_paused && (d.wkr == nil || rx_msgs_for_room(lane_room(d.wkr, .Rx), d.rx_slot) > 0) {
		rx_pause(d, false)
	}
	return
}

// After each wake-up of the loop: use what the worker finished. Sealing can start
// a renegotiation, and the free batches can take packets that wait in the ring.
wk_after_wake :: proc(d: ^Daemon) {
	if wk_drain(d) && d.s_ok && d.state == .Active {
		pump(d)
		flush_tx(d)
	}
	if d.tun_held && (d.wkr == nil || lane_room(d.wkr, .Tx) - d.ring.count >= WK_TUN_ROOM) {
		tun_hold(d, false)
	}
}

// The jobs of this session are dropped when they come back (the session is
// going away).
rx_abandon :: proc(d: ^Daemon) {
	d.wk_gen += 1
	d.wk_tx_wait = 0
}

// The end of a round of reading: start the worker, use what is done, write what
// is joined.
rx_flush :: proc(d: ^Daemon) {
	if d.wk != nil {
		pool_post(d.wk)
		wk_drain(d)
	}
	flush_tun(d)
}
