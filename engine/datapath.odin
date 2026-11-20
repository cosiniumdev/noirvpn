// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/offload"
import "noir:platform/tun"
import "noir:proto/mss"
import "noir:proto/session"

// Packet loops, two directions:
//
//	tun -> ring -> seal -> socket      (`on_tun`, `flush_tx`)
//	socket -> open -> tun              (`on_socket`, `feed`)
//
// Control packets (handshake, keepalives, rekeys) go out through `send_link`
// and skip the ring.
//
// Kernel offloads (offload.odin): a large tun read is cut into ordinary packets
// at once, so ring, sealing and peer see the same packets as without offloads.
// A UDP read can hold many datagrams; the tunnel packets of a round are joined
// before the tun write.

// ----------------------------------------------------------------- tun -> link

// Reads up to TUN_BURST packets from the tun device (`on_tun` calls it when the
// device is readable). `more`: it stopped at the limit, and packets may wait.
tun_burst :: proc(d: ^Daemon) -> (more: bool) {
	if !d.tun_open {
		return false
	}
	budget := TUN_BURST
	more = true
	for budget > 0 {
		if d.wkr != nil && lane_room(d.wkr, .Tx) - d.ring.count < WK_TUN_ROOM {
			flush_tx(d)
			if lane_room(d.wkr, .Tx) - d.ring.count < WK_TUN_ROOM {
				// The worker is behind: the packets wait in the tun queue.
				tun_hold(d, true)
				more = false
				break
			}
		}
		got: int
		stop: bool
		if d.tun.vnet && len(d.tun_stage) > 0 {
			got, stop = read_tun_vnet(d)
		} else {
			got, stop = read_tun_plain(d)
		}
		if stop {
			more = false
			break
		}
		budget -= max(got, 1)
		if got > 1 && d.ring.count + 2 * got > RING_SLOTS {
			// Send first, so that the ring keeps its oldest packets.
			flush_tx(d)
		}
	}
	if d.close_reason == .Fatal {
		// The tun device failed.
		return false
	}
	d.stats.drop_ring = d.ring.dropped
	flush_tx(d)
	// Sealing can start a renegotiation: send what the session queued.
	pump(d)
	return more && d.tun_open
}

// Stops or resumes reading the tun device while the crypto worker has no send room.
tun_hold :: proc(d: ^Daemon, hold: bool) {
	if hold == d.tun_held || !d.tun_open {
		return
	}
	d.tun_held = hold
	if hold {
		tun_unwatch(d)
		return
	}
	if err := tun_watch(d); err != .None {
		logf(.Error, "cannot watch the tun device again: %v", err)
		fatal(d, .System, "the tun device cannot be watched")
		return
	}
	tun_kick(d)
}

// One read from a tun without the virtio header. `stop`: nothing more to read
// (or the device failed).
read_tun_plain :: proc(d: ^Daemon) -> (got: int, stop: bool) {
	slot := ring_next(&d.ring)
	room := slot.buf[session.TUNNEL_HEADROOM:][:MAX_TUN_PACKET]
	n, err := tun.read(&d.tun, room)
	if err != .None {
		return 0, tun_read_failed(d, err)
	}
	if n == 0 {
		return 0, false
	}
	d.stats.tun_read_pkts += 1
	d.stats.tun_read_bytes += u64(n)
	d.off.tun_reads += 1
	if !tun_flows(d) {
		d.stats.drop_not_up += 1
		return 1, false
	}
	if d.block6 && is_ipv6(room[:n]) {
		d.stats.drop_block6_tx += 1
		when ODIN_OS == .Windows {
			tun_drop_blocked6(d)
		}
		return 1, false
	}
	if d.mss4 != 0 {
		mss.clamp_syn(room[:n], d.mss4)
	}
	if d.acl != nil {
		acl_out(d, room[:n])
	}
	slot.n = n
	ring_commit(&d.ring)
	return 1, false
}

// One read from a tun with the virtio header: one packet, or a large one that
// is cut into many. The packets go to the ring.
read_tun_vnet :: proc(d: ^Daemon) -> (got: int, stop: bool) {
	n, err := tun.read(&d.tun, d.tun_stage)
	if err != .None {
		return 0, tun_read_failed(d, err)
	}
	if n <= tun.VNET_HDR_LEN {
		return 0, false
	}
	d.off.tun_reads += 1
	hdr, _ := offload.vnet_decode(d.tun_stage[:n])
	pkt := d.tun_stage[tun.VNET_HDR_LEN:n]
	if !tun_flows(d) {
		d.stats.tun_read_pkts += 1
		d.stats.tun_read_bytes += u64(len(pkt))
		d.stats.drop_not_up += 1
		return 1, false
	}
	if d.block6 && is_ipv6(pkt) {
		// Tested before the cut: a large packet is one IPv6 packet.
		d.stats.tun_read_pkts += 1
		d.stats.tun_read_bytes += u64(len(pkt))
		d.stats.drop_block6_tx += 1
		return 1, false
	}
	if d.mss4 != 0 && hdr.gso_type == offload.GSO_NONE {
		// A SYN is never a GSO packet; one that is not is left alone. With a partial
		// checksum the split completes it later, so the field is not touched.
		mss.clamp_syn(pkt, d.mss4, hdr.flags & offload.F_NEEDS_CSUM == 0)
	}
	if d.acl != nil {
		// One flow for the whole read: the cut gives the same 5-tuple to each segment.
		acl_out(d, pkt)
	}
	sp: offload.Split
	if serr := offload.split_init(&sp, hdr, pkt, MAX_TUN_PACKET); serr != .None {
		d.off.tun_split_errors += 1
		return 1, false
	}
	segs := offload.split_count(&sp)
	if segs > 1 {
		d.off.tun_gso_reads += 1
		d.off.tun_gso_segs += u64(segs)
	}
	for offload.split_count(&sp) > 0 {
		if d.ring.count >= RING_SLOTS - 1 {
			// A large packet cut into very small ones (a peer with a tiny MSS):
			// send what waits, so that the ring does not drop its oldest packets.
			flush_tx(d)
		}
		slot := ring_next(&d.ring)
		room := slot.buf[session.TUNNEL_HEADROOM:][:MAX_TUN_PACKET]
		k, ok := offload.split_next(&sp, room)
		if !ok {
			break
		}
		d.stats.tun_read_pkts += 1
		d.stats.tun_read_bytes += u64(k)
		slot.n = k
		ring_commit(&d.ring)
		got += 1
	}
	return max(got, 1), false
}

// A failed tun read. True: stop reading.
tun_read_failed :: proc(d: ^Daemon, err: tun.Error) -> bool {
	if err == .Would_Block {
		return true
	}
	d.stats.tun_read_errors += 1
	if err == .Io || err == .Closed {
		// The device went away: nothing more to read.
		logf(.Error, "the tun device failed: %v", err)
		fatal(d, .System, "the tun device has disappeared")
	}
	return true
}

// Can a tun packet be sent now?
tun_flows :: proc(d: ^Daemon) -> bool {
	return d.up && d.close_reason == .None && d.state == .Active
}

// Seals the waiting tun packets and sends them: one `sendmmsg` per call on UDP
// (up to TX_BATCH packets, repeated while the ring has more), a write into the
// TCP buffer on TCP.
flush_tx :: proc(d: ^Daemon) {
	if !d.s_ok || !d.up || d.state != .Active || d.end.pending || d.exit {
		return
	}
	if d.dco.active {
		// The service reads the tun device and sends; there is nothing to seal here.
		return
	}
	if d.wkr != nil {
		seal_ring(d)
		pool_post(d.wk)
		d.stats.drop_ring = d.ring.dropped
		return
	}
	if d.proto == .Udp {
		flush_udp(d)
	} else {
		flush_stream(d)
	}
	d.stats.drop_ring = d.ring.dropped
}

// Seals slot `k` of the ring if not sealed yet. False: stop here (no key yet,
// or session not up); the slot stays. A packet that cannot be sealed for
// another reason is marked bad and skipped.
seal_slot :: proc(d: ^Daemon, slot: ^Slot) -> bool {
	if slot.sealed || slot.bad {
		return true
	}
	pkt, err := session.session_encap(&d.s, slot.buf[:], slot.n, now_of(d))
	return seal_slot_result(d, slot, pkt, err)
}

// What `seal_slot` does with the result of the session.
seal_slot_result :: proc(d: ^Daemon, slot: ^Slot, pkt: []u8, err: session.Error) -> bool {
	if err == .None {
		// `pkt` is a slice of `slot.buf`.
		slot.off = int(uintptr(raw_data(pkt)) - uintptr(raw_data(slot.buf[:])))
		slot.len = len(pkt)
		slot.sealed = true
		return true
	}
	#partial switch err {
	case .No_Key, .Not_Up:
		return false
	}
	slot.bad = true
	d.stats.drop_seal += 1
	return true
}

flush_udp :: proc(d: ^Daemon) {
	for !ring_is_empty(&d.ring) && !d.blocked {
		net.batch_reset(&d.tx_batch)
		limit := min(d.ring.count, TX_BATCH)
		bad_first := false
		for k in 0 ..< limit {
			slot := ring_at(&d.ring, k)
			if !seal_slot(d, slot) {
				break
			}
			if slot.bad {
				// Skipped, but it keeps its place so `ring_pop` stays simple.
				// Stop the batch before it and drop it.
				if net.batch_pending(&d.tx_batch) == 0 {
					ring_pop(&d.ring, 1)
					bad_first = true
				}
				break
			}
			net.batch_push(&d.tx_batch, slot.buf[slot.off:][:slot.len], d.sock_to)
		}
		if bad_first {
			continue
		}
		count := net.batch_pending(&d.tx_batch)
		if count == 0 {
			// No key yet: wait for `Key_Installed` or the next tick.
			return
		}
		sent, err := net.send_pushed(d.sock, &d.tx_batch)
		if errno, fresh := net.batch_take_gso_failure(&d.tx_batch); fresh {
			d.off.udp_gso_fallbacks += 1
			d.off.udp_gso = 0
			logf(.Warn, "UDP segmentation offload was refused (error %d), so datagrams will be sent one at a time", errno)
		}
		if err == .Would_Block {
			set_blocked(d, true)
			return
		}
		if err != .None {
			// Most likely ICMP "port unreachable" from an earlier packet.
			// This packet is lost; the next one goes through.
			d.stats.sock_send_errors += 1
			ring_pop(&d.ring, 1)
			continue
		}
		d.stats.sent_pkts += u64(sent)
		ring_pop(&d.ring, sent)
		if sent < count {
			d.stats.sock_blocked += 1
			set_blocked(d, true)
			return
		}
	}
}

flush_stream :: proc(d: ^Daemon) {
	t := &d.tcp
	for !ring_is_empty(&d.ring) {
		slot := ring_at(&d.ring, 0)
		if net.tcp_pending(t) + slot.n + 64 > len(t.tx) - TCP_TX_RESERVE {
			// The socket is not taking data as fast as the tun gives it.
			if _, ok := stream_flush(d); !ok {
				return
			}
			if net.tcp_pending(t) + slot.n + 64 > len(t.tx) - TCP_TX_RESERVE {
				d.stats.sock_blocked += 1
				return
			}
		}
		if !seal_slot(d, slot) {
			return
		}
		if slot.bad {
			ring_pop(&d.ring, 1)
			continue
		}
		if !stream_append(d, slot.buf[slot.off:][:slot.len]) {
			d.stats.drop_ring += 1
			ring_pop(&d.ring, 1)
			continue
		}
		d.stats.sent_pkts += 1
		ring_pop(&d.ring, 1)
	}
	stream_flush(d)
}

// Adds framed bytes (the session already put the 2-byte length in front) to the
// TCP queue. False if there is no room even after moving the queue down.
stream_append :: proc(d: ^Daemon, pkt: []u8) -> bool {
	t := &d.tcp
	if t.tx_tail + len(pkt) > len(t.tx) {
		if t.tx_head > 0 {
			copy(t.tx, t.tx[t.tx_head:t.tx_tail])
			t.tx_tail -= t.tx_head
			t.tx_head = 0
		}
		if t.tx_tail + len(pkt) > len(t.tx) {
			return false
		}
	}
	copy(t.tx[t.tx_tail:], pkt)
	t.tx_tail += len(pkt)
	return true
}

// Writes the TCP queue to the socket and watches for `Write` while some is
// left. False if the connection broke (the connection is then finished).
stream_flush :: proc(d: ^Daemon) -> (pending: int, ok: bool) {
	if d.tls {
		return tls_stream_flush(d)
	}
	left, err := net.tcp_flush(&d.tcp)
	if err != .None {
		d.stats.sock_send_errors += 1
		logf(.Warn, "TCP send failed: %v", err)
		fail_connection(d, .Ping_Restart if d.up else .Connect_Failed, {})
		return 0, false
	}
	set_blocked(d, left > 0)
	return left, true
}

// Turns write interest on the socket on or off. Write interest is on only
// while output is waiting.
set_blocked :: proc(d: ^Daemon, on: bool) {
	d.blocked = on
	if on == d.want_write || !d.sock_open {
		return
	}
	d.want_write = on
	event.modify_fd(&d.loop, d.sock.fd, sock_interest(d))
}

// Read interest is off while the crypto worker has no room (`rx_paused`).
sock_interest :: proc(d: ^Daemon) -> event.Interest {
	i: event.Interest
	if !d.rx_paused {
		i += {.Read}
	}
	if d.want_write {
		i += {.Write}
	}
	return i
}

// Stops or resumes reading the UDP socket. The datagrams wait in the kernel
// buffer meanwhile.
rx_pause :: proc(d: ^Daemon, pause: bool) {
	if pause == d.rx_paused || !d.sock_open {
		return
	}
	d.rx_paused = pause
	event.modify_fd(&d.loop, d.sock.fd, sock_interest(d))
}

// A control packet (handshake, keepalive, ...) for the link.
send_link :: proc(d: ^Daemon, pkt: []u8) {
	if d.dco.active && d.dco.o.stream {
		// A TCP connection that the service owns: the record goes to CTRL_TX.
		dco_ctrl_send(&d.dco.o, pkt)
		return
	}
	if !d.sock_open {
		return
	}
	if d.proto == .Udp {
		err: net.Error
		if to, unconnected := d.sock_to.?; unconnected {
			err = net.send_to(d.sock, pkt, to)
		} else {
			err = net.send(d.sock, pkt)
		}
		#partial switch err {
		case .None:
		case .Would_Block:
			// The reliable layer sends it again.
			d.stats.sock_blocked += 1
		case:
			d.stats.sock_send_errors += 1
		}
		return
	}
	if !stream_append(d, pkt) {
		d.stats.sock_send_errors += 1
		return
	}
	stream_flush(d)
}

// ---------------------------------------------------------------- link -> tun

on_socket :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := (^Daemon)(user)
	if !d.sock_open {
		return
	}
	if d.state == .Tcp_Connecting {
		if .Write in ready || .Error in ready || .Hangup in ready {
			err := net.tcp_connect_finish(d.sock)
			if err == .Would_Block {
				return
			}
			if err != .None {
				logf(.Warn, "TCP connect failed: %v", err)
				fail_connection(d, .Connect_Failed, {})
				return
			}
			event.modify_fd(loop, fd, {.Read})
			d.want_write = false
			logf(.Debug, "TCP connected")
			tcp_connected(d)
		}
		return
	}
	if d.state == .Proxy_Connecting {
		if .Write in ready && d.px.sent < len(d.px.req) {
			proxy_send(d)
		}
		if d.state == .Proxy_Connecting && (.Read in ready || .Hangup in ready || .Error in ready) {
			proxy_read(d)
		}
		return
	}
	if d.state == .Tls_Handshaking {
		tls_step(d)
		return
	}
	if d.state == .Ws_Upgrading {
		if .Write in ready {
			ws_send(d)
		}
		if d.state == .Ws_Upgrading && (.Read in ready || .Hangup in ready || .Error in ready) {
			ws_read(d)
		}
		return
	}
	if d.state != .Active {
		return
	}
	if .Write in ready {
		if d.proto == .Udp {
			set_blocked(d, false)
		} else if _, ok := stream_flush(d); !ok {
			return
		}
		flush_tx(d)
		if d.state != .Active {
			return
		}
	}
	if .Read in ready || .Hangup in ready || .Error in ready {
		if d.proto == .Udp {
			read_udp(d)
		} else if d.tls {
			read_tls(d)
		} else {
			read_stream(d)
		}
		if d.state != .Active || !d.s_ok {
			return
		}
		pump(d)
		flush_tx(d)
	}
}

// Budget of datagrams or stream reads per wake-up, before the loop goes back to
// the other descriptors. A UDP GRO message with many datagrams uses many.
READ_ROUNDS :: 8
READ_DATAGRAMS :: READ_ROUNDS * RX_BATCH

read_udp :: proc(d: ^Daemon) {
	// The tunnel packets of a round may point into the receive buffer: write
	// them to the tun before the next read reuses it.
	defer rx_flush(d)
	left := READ_DATAGRAMS
	for left > 0 {
		want := rx_vlen(d.rx_msgs, left, d.rx_per_msg)
		if d.wkr != nil {
			// Read no more than the worker can take: the rest waits in the kernel.
			fit := rx_msgs_for_room(lane_room(d.wkr, .Rx), d.rx_slot)
			if fit == 0 {
				rx_pause(d, true)
				return
			}
			want = min(want, fit)
		}
		n, err := net.recv_batch(d.sock, &d.rx_batch, want)
		if err == .Would_Block || err == .Interrupted {
			return
		}
		if err != .None {
			// ICMP errors of a connected socket come as an error on the
			// next read. The timers decide if the server is gone.
			d.stats.sock_recv_errors += 1
			return
		}
		dgrams := 0
		for i in 0 ..< n {
			size := net.batch_len(&d.rx_batch, i)
			seg := net.batch_gro_size(&d.rx_batch, i)
			msg := d.rx_buf[i * d.rx_slot:][:size]
			if to, unconnected := d.sock_to.?; unconnected && net.batch_from(&d.rx_batch, i) != to {
				segs := max(net.batch_segments(&d.rx_batch, i), 1)
				d.stats.drop_source += u64(segs)
				dgrams += segs
				continue
			}
			if net.batch_truncated(&d.rx_batch, i) {
				d.stats.drop_oversize += 1
				dgrams += 1
				continue
			}
			if seg == 0 {
				dgrams += 1
				if size > RX_SLOT {
					d.stats.drop_oversize += 1
					continue
				}
				feed(d, msg)
				if !feed_ok(d) {
					return
				}
				continue
			}
			// A block of datagrams of `seg` bytes (the last may be shorter).
			for off := 0; off < size; off += seg {
				dgrams += 1
				if seg > RX_SLOT {
					d.stats.drop_oversize += 1
					continue
				}
				feed(d, msg[off:min(off + seg, size)])
				if !feed_ok(d) {
					return
				}
			}
		}
		left -= max(dgrams, 1)
		d.rx_per_msg = clamp(dgrams / max(n, 1), 1, 64)
		// The next read overwrites the buffer.
		rx_flush(d)
		if n < want {
			return
		}
	}
}

read_stream :: proc(d: ^Daemon) {
	defer rx_flush(d)
	scratch := d.rx_buf[:32 * 1024]
	for _ in 0 ..< READ_ROUNDS {
		n, err := net.stream_recv(d.sock, scratch)
		if err == .Would_Block || err == .Interrupted {
			return
		}
		if err != .None {
			if d.close_reason != .None {
				// We are closing: the server hung up after the exit notice.
				fail_connection(d, close_outcome(d.close_reason), {})
				return
			}
			d.stats.sock_recv_errors += 1
			logf(.Warn, "the TCP connection ended: %v", err)
			fail_connection(d, .Ping_Restart if d.up else .Connect_Failed, {})
			return
		}
		feed(d, scratch[:n])
		if !feed_ok(d) {
			return
		}
		// The next read overwrites `scratch`.
		rx_flush(d)
	}
}

// False once the session can take no more input.
feed_ok :: proc(d: ^Daemon) -> bool {
	if !d.s_ok {
		return false
	}
	st := session.session_state(&d.s)
	return st != .Failed && st != .Closed
}

// Gives the session one datagram or a chunk of a TCP stream and writes the
// tunnel packets it yields to the tun device.
feed :: proc(d: ^Daemon, data: []u8) {
	rest := data
	now := now_of(d)
	for {
		r := session.session_receive(&d.s, rest, now)
		rest = rest[r.consumed:]
		if len(r.tunnel) > 0 {
			write_tun(d, r.tunnel)
		}
		if !feed_ok(d) {
			return
		}
		if len(rest) == 0 && !r.more {
			return
		}
	}
}

write_tun :: proc(d: ^Daemon, pkt: []u8) {
	if d.block6 && is_ipv6(pkt) {
		d.stats.drop_block6_rx += 1
		return
	}
	if d.acl != nil && !acl_in(d, pkt) {
		return
	}
	if d.guest != nil && !d.tun_open && d.guest.h.tun_write != nil {
		// The host takes the packets of the tunnel (flow).
		guest_flow_write(d, pkt)
		return
	}
	if !d.tun_open {
		d.stats.drop_rx_not_up += 1
		return
	}
	if d.mss4 != 0 {
		mss.clamp_syn(pkt, d.mss4)
	}
	if d.tun.vnet && d.tun_tx.on {
		// Joins this packet to the run of its flow. Written at the end of the
		// round (`flush_tun`), or when the run is full.
		tun_tx_push(&d.tun, &d.tun_tx, &d.off, pkt, d.rx_stable if d.rx_stable != nil else d.rx_buf)
		tun_tx_account(d)
		return
	}
	err := tun.write(&d.tun, pkt)
	if err != .None {
		// The tun queue is full, or the interface is down: the packet is lost.
		d.stats.drop_tun_write += 1
		return
	}
	d.off.tun_writes += 1
	d.stats.tun_write_pkts += 1
	d.stats.tun_write_bytes += u64(len(pkt))
}

// Writes the runs that are still open. Call it before the memory the packets
// were in is used again.
flush_tun :: proc(d: ^Daemon) {
	if d.guest != nil {
		guest_flush_out(d)
	}
	if !d.tun_open || !d.tun.vnet {
		return
	}
	tun_tx_flush(&d.tun, &d.tun_tx, &d.off)
	tun_tx_account(d)
}

tun_tx_account :: proc(d: ^Daemon) {
	t := &d.tun_tx
	d.stats.tun_write_pkts += t.wrote_pkts
	d.stats.tun_write_bytes += t.wrote_bytes
	d.stats.drop_tun_write += t.dropped
	t.wrote_pkts, t.wrote_bytes, t.dropped = 0, 0, 0
}

tun_name :: proc(d: ^Daemon) -> string {
	if d.dco.dev {
		return d.dco.name
	}
	return tun.name(&d.tun)
}
