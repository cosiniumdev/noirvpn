// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:time"
import "noir:proto/session"

// Client data path with crypto workers (`workers N`, crypto_worker.odin). Used
// only if `d.wkr` is set; with no workers the loops in datapath.odin call the
// session directly.
//
//	tun -> ring -> `seal_ring` (the workers seal the whole ring, in order) ->
//	      the usual `flush_udp` / `flush_stream` send the sealed slots
//	socket -> the session hands each data packet to `client_take` (it becomes a
//	      job); control packets are handled at once, after `client_barrier` has
//	      finished the data packets before them -> `rx_flush` runs the jobs and
//	      writes the tunnel packets in the order they came
//
// The receive buffer is not reused before `rx_flush` has run the jobs: the
// loops call it where they called `flush_tun`.

// Start of the copy area of `rx_buf`. A TCP read uses the first 32 KiB as its
// chunk; frames that the session cuts from its own buffer are copied behind it.
// So all jobs of a round stay in unchanged memory until the round ends.
RX_COPY_AT :: 32 * 1024

// ---------------------------------------------------------------------- tx

// Seals the waiting packets of the ring on the worker. Results apply in ring
// order, like `seal_slot`: a slot the session cannot seal yet (no key) stays,
// with all slots after it.
seal_ring :: proc(d: ^Daemon) {
	if d.blocked || ring_is_empty(&d.ring) || !d.s_ok {
		return
	}
	dp := session.session_remote_dp(&d.s)
	now := now_of(d)
	jobs: [RING_SLOTS]^Wk_Job
	count := d.ring.count
	for k in 0 ..< count {
		slot := ring_at(&d.ring, k)
		jobs[k] = nil
		if slot.sealed || slot.bad {
			continue
		}
		if cerr := session.session_encap_check(&d.s, slot.buf[:], slot.n); cerr != .None {
			// Not up yet, or a slot that cannot be sealed: `seal_slot` says what to do.
			break
		}
		jobs[k] = job_add(d.wkr, .Tx, dp, slot.buf[:], slot.n, now)
		if jobs[k] == nil {
			break
		}
	}
	lane_run(d.wk, .Tx)
	for k in 0 ..< count {
		j := jobs[k]
		if j == nil {
			// The slot has a result already, or was left alone: from here on the
			// one-by-one path decides.
			if !(ring_at(&d.ring, k).sealed || ring_at(&d.ring, k).bad) {
				break
			}
			continue
		}
		slot := ring_at(&d.ring, k)
		pkt, err := session.session_encap_done(&d.s, slot.buf[:], j.seal, j.now)
		if !seal_slot_result(d, slot, pkt, err) {
			break
		}
	}
	lane_recycle(d.wk, .Tx)
}

// ---------------------------------------------------------------------- rx

// The session offers a data packet. It becomes a job on this session's worker;
// the tunnel packet comes out of `rx_run`. True: taken.
client_take :: proc(host: rawptr, s: ^session.Session, pkt: []u8, now: time.Duration) -> bool {
	d := (^Daemon)(host)
	if d.wkr == nil {
		return false
	}
	buf := pkt
	if !inside(pkt, d.rx_buf) {
		// A frame of a TCP stream, in the session's own buffer: copy it.
		if len(pkt) > len(d.rx_buf) - RX_COPY_AT {
			rx_run(d)
			return false
		}
		if d.rx_copied + len(pkt) > len(d.rx_buf) - RX_COPY_AT {
			rx_run(d)
		}
		buf = d.rx_buf[RX_COPY_AT + d.rx_copied:][:len(pkt)]
		copy(buf, pkt)
		d.rx_copied += len(pkt)
	}
	dp := session.session_remote_dp(s)
	j := job_add(d.wkr, .Rx, dp, buf, 0, now)
	if j == nil {
		// The lane is full: run what it has, then start again.
		rx_run(d)
		j = job_add(d.wkr, .Rx, dp, buf, 0, now)
		if j == nil {
			return false
		}
	}
	append(&d.rx_jobs, j)
	return true
}

// A control packet is next: finish the data packets before it.
client_barrier :: proc(host: rawptr) {
	d := (^Daemon)(host)
	if len(d.rx_jobs) > 0 {
		rx_run(d)
	}
}

// Runs the jobs of the round, hands the results to the session in order, and
// writes the tunnel packets. The copy area and the lane are free again after it.
rx_run :: proc(d: ^Daemon) {
	if len(d.rx_jobs) == 0 {
		return
	}
	lane_run(d.wk, .Rx)
	for j in d.rx_jobs {
		if !d.s_ok || !feed_ok(d) {
			// The session ended: the rest would not have been looked at.
			break
		}
		plain := session.session_rx_finish(&d.s, j.buf, j.open, j.now)
		if len(plain) > 0 {
			write_tun(d, plain)
		}
	}
	clear(&d.rx_jobs)
	// The joined runs hold slices of the copy area: write them before it is reused.
	flush_tun(d)
	d.rx_copied = 0
	lane_recycle(d.wk, .Rx)
}

// Drops the jobs of the round without looking at the results (the session is
// going away).
rx_abandon :: proc(d: ^Daemon) {
	if len(d.rx_jobs) == 0 {
		return
	}
	lane_run(d.wk, .Rx)
	clear(&d.rx_jobs)
	d.rx_copied = 0
	lane_recycle(d.wk, .Rx)
}

// The end of a round of reading: finish the jobs and write what is joined.
rx_flush :: proc(d: ^Daemon) {
	rx_run(d)
	flush_tun(d)
}
