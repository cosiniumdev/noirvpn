// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:time"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/offload"
import "noir:platform/tlslink"
import "noir:platform/tun"
import "noir:proto/mss"
import "noir:proto/session"
import "noir:server"

// The packet loops of the server. One thread, three directions:
//
//   tun    -> registry (destination -> client) -> seal in a slot -> sendmmsg / TCP queue
//   socket -> demultiplex -> session -> registry (source check, destination)
//                -> tun write, or another client's slot (client-to-client)
//   timers and control packets: `conn_pump`, `conn_send_ctl`
//
// Nothing here allocates. Every drop has a counter (`Srv_Stats`, and the
// registry's own for routing verdicts).
//
// With kernel offloads (offload.odin): a tun read can be one large packet for
// one client (routed once, cut into ordinary packets, sealed one by one); a UDP
// read can be a block of datagrams of one source; a round's tunnel packets are
// joined before the tun write. The per-wake budgets (SRV_READ_ROUNDS,
// SRV_TUN_BURST) count datagrams and packets.

// ----------------------------------------------------------------- tun -> link

on_srv_tun :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := (^Srv)(user)
	if !d.tun_open || d.finished {
		return
	}
	now := now_srv(d)
	budget := SRV_TUN_BURST
	for budget > 0 {
		got: int
		stop: bool
		if d.tun.vnet && len(d.tun_stage) > 0 {
			got, stop = srv_read_tun_vnet(d, now)
		} else {
			got, stop = srv_read_tun_plain(d, now)
		}
		if stop || d.finished || !d.tun_open {
			break
		}
		budget -= max(got, 1)
		if d.out.blocked {
			break
		}
	}
	out_flush(d)
	flush_dirty(d)
}

// One read from a tun without the virtio header. `stop`: nothing more to read
// now (or the batch is blocked, or the device failed).
srv_read_tun_plain :: proc(d: ^Srv, now: time.Duration) -> (got: int, stop: bool) {
	slot := out_next(d)
	if slot == nil {
		return 0, true
	}
	room := slot.buf[session.TUNNEL_HEADROOM:][:MAX_TUN_PACKET]
	n, err := tun.read(&d.tun, room)
	if err != .None {
		return 0, srv_tun_read_failed(d, err)
	}
	if n == 0 {
		return 0, false
	}
	d.off.tun_reads += 1
	d.stats.tun_read_pkts += 1
	d.stats.tun_read_bytes += u64(n)
	if d.cfg.block_ipv6 && is_ipv6(room[:n]) {
		d.stats.drop_block6_tx += 1
		return 1, false
	}
	dest, v := server.registry_from_tun(&d.srv.reg, room[:n])
	if v != .To_Peer {
		return 1, false
	}
	c := conn_of_handle(d, dest)
	if c == nil || !c.up || c.closing || conn_in_service(d, c) {
		// (A client of the DCO service has no packets on this device: the kernel routes
		// them to the service's device.)
		d.stats.drop_conn_state += 1
		return 1, false
	}
	if c.mss4 != 0 {
		mss.clamp_syn(room[:n], c.mss4)
	}
	d.stats.from_tun_pkts += 1
	seal_and_queue(d, c, slot, n, now)
	return 1, false
}

// One read from a tun with the virtio header: one packet, or a large one that is
// cut into many, all for the same client.
srv_read_tun_vnet :: proc(d: ^Srv, now: time.Duration) -> (got: int, stop: bool) {
	if d.out.blocked {
		return 0, true
	}
	n, err := tun.read(&d.tun, d.tun_stage)
	if err != .None {
		return 0, srv_tun_read_failed(d, err)
	}
	if n <= tun.VNET_HDR_LEN {
		return 0, false
	}
	d.off.tun_reads += 1
	hdr, _ := offload.vnet_decode(d.tun_stage[:n])
	pkt := d.tun_stage[tun.VNET_HDR_LEN:n]
	if d.cfg.block_ipv6 && is_ipv6(pkt) {
		// Tested before the cut: a large packet is one IPv6 packet.
		d.stats.tun_read_pkts += 1
		d.stats.tun_read_bytes += u64(len(pkt))
		d.stats.drop_block6_tx += 1
		return 1, false
	}
	sp: offload.Split
	if serr := offload.split_init(&sp, hdr, pkt, MAX_TUN_PACKET); serr != .None {
		d.off.tun_split_errors += 1
		d.stats.tun_read_pkts += 1
		d.stats.tun_read_bytes += u64(len(pkt))
		return 1, false
	}
	segs := offload.split_count(&sp)
	d.stats.tun_read_pkts += u64(segs)
	d.stats.tun_read_bytes += u64(len(pkt))
	if segs > 1 {
		d.off.tun_gso_reads += 1
		d.off.tun_gso_segs += u64(segs)
	}
	// All packets of a large one have the same addresses: route it once, and
	// count the verdict for each packet.
	dest, v := server.registry_from_tun(&d.srv.reg, pkt)
	d.srv.reg.counters[v] += u64(segs - 1)
	if v != .To_Peer {
		return segs, false
	}
	c := conn_of_handle(d, dest)
	if c == nil || !c.up || c.closing || conn_in_service(d, c) {
		d.stats.drop_conn_state += u64(segs)
		return segs, false
	}
	if c.mss4 != 0 && hdr.gso_type == offload.GSO_NONE {
		// A SYN is never a GSO packet. With a partial checksum the split completes it
		// later, so the field is not touched.
		mss.clamp_syn(pkt, c.mss4, hdr.flags & offload.F_NEEDS_CSUM == 0)
	}
	cslot := c.slot
	if c.proto == .Tcp && segs > 1 {
		// All or nothing: a burst that loses the back half of a window is worse than
		// one that loses all of it. Wire size is the packets plus framing and tag of each.
		total := offload.split_bytes_left(&sp) + segs * session.session_seal_overhead(&c.s)
		if !tcp_reserve(d, c, total + c.tx_wait, true, segs) {
			return segs, false
		}
	}
	for offload.split_count(&sp) > 0 {
		slot := out_next(d)
		if slot == nil {
			// A send waits and the batch is full: the rest of the packets is lost.
			d.stats.drop_tx_busy += u64(offload.split_count(&sp))
			break
		}
		room := slot.buf[session.TUNNEL_HEADROOM:][:MAX_TUN_PACKET]
		k, ok := offload.split_next(&sp, room)
		if !ok {
			break
		}
		d.stats.from_tun_pkts += 1
		seal_and_queue(d, c, slot, k, now)
		if d.conns[cslot] != c {
			// A TCP client was closed for not reading: `c` is gone.
			d.stats.drop_conn_state += u64(offload.split_count(&sp))
			break
		}
	}
	return segs, false
}

// A failed tun read. True: stop reading.
srv_tun_read_failed :: proc(d: ^Srv, err: tun.Error) -> bool {
	if err == .Would_Block {
		return true
	}
	d.stats.tun_read_errors += 1
	if err == .Io || err == .Closed {
		logf(.Error, "the tun device failed: %v", err)
		d.exit_code = .System
		srv_begin_stop(d)
	}
	return true
}

// The client of a peer table handle, or nil.
conn_of_handle :: proc(d: ^Srv, h: server.Peer_Handle) -> ^Conn {
	p := server.peers_get(&d.srv.reg.peers, h)
	if p == nil || p.user >= u64(len(d.conns)) {
		return nil
	}
	c := d.conns[p.user]
	if c == nil || c.h != h {
		return nil
	}
	return c
}

// The IP packet is in `slot.buf[TUNNEL_HEADROOM:][:n]`. Seals it in place for `c`.
//   UDP - the slot joins the batch
//   TCP - sealed bytes are copied to the client's queue; the slot stays free
seal_and_queue :: proc(d: ^Srv, c: ^Conn, slot: ^Tx_Slot, n: int, now: time.Duration) {
	if c.wkr != nil {
		// The worker seals it; `out_finish` does the rest.
		if !seal_submit(d, c, slot, n, now) {
			d.stats.drop_seal += 1
			c.drops += 1
		}
		return
	}
	pkt, err := session.session_encap(&c.s, slot.buf[:], n, now)
	if err != .None {
		d.stats.drop_seal += 1
		c.drops += 1
		return
	}
	c.out_pkts += 1
	c.out_bytes += u64(n)
	slot_idx := c.slot
	if c.proto == .Tcp {
		// A queue that cannot take the packet may close the client: `c` can be gone.
		tcp_append(d, c, pkt, true)
		if d.conns[slot_idx] != c {
			return
		}
	} else {
		slot.off = int(uintptr(raw_data(pkt)) - uintptr(raw_data(slot.buf[:])))
		slot.len = len(pkt)
		slot.lidx = c.lidx
		slot.ep = c.ep
		slot.local = c.local
		d.out.count += 1
	}
	// Sealing can start a rekey (bytes, packets, time); its packets wait in the
	// session. Look at the session now and then so they go out without delay.
	if c.out_pkts & 63 == 0 {
		conn_pump(d, c)
	}
}

// A packet for another client (client-to-client): copied into a slot and sealed.
forward_packet :: proc(d: ^Srv, c: ^Conn, pkt: []u8) {
	if len(pkt) > MAX_TUN_PACKET {
		d.stats.drop_oversize += 1
		return
	}
	slot := out_next(d)
	if slot == nil {
		d.stats.drop_tx_busy += 1
		return
	}
	copy(slot.buf[session.TUNNEL_HEADROOM:], pkt)
	if c.mss4 != 0 {
		// The packet was clamped for the sender; this client has its own value.
		mss.clamp_syn(slot.buf[session.TUNNEL_HEADROOM:][:len(pkt)], c.mss4)
	}
	d.stats.c2c_pkts += 1
	seal_and_queue(d, c, slot, len(pkt), now_srv(d))
}

// The next free slot of the UDP batch, or nil while a send waits. A full batch
// is sent first.
out_next :: proc(d: ^Srv) -> ^Tx_Slot {
	o := &d.out
	if o.blocked {
		return nil
	}
	if o.count == TX_BATCH {
		out_flush(d)
		if o.blocked || o.count == TX_BATCH {
			return nil
		}
	}
	return &o.slots[o.count]
}

// Sends the batch: one `sendmmsg` per run of packets for the same socket.
// A socket that takes only some keeps the rest, stops tun reads and waits for
// `Write`. A packet the kernel refuses for another reason is dropped and counted.
out_flush :: proc(d: ^Srv) {
	o := &d.out
	if o.count == 0 || o.blocked || o.sealing {
		return
	}
	out_finish(d)
	i := 0
	for i < o.count {
		lidx := o.slots[i].lidx
		j := i
		for j < o.count && o.slots[j].lidx == lidx {
			j += 1
		}
		ln := &d.listeners[lidx]
		k := i
		stuck := false
		for k < j && !stuck {
			m := j - k
			net.batch_reset(&ln.tx_batch)
			for x in 0 ..< m {
				s := &o.slots[k + x]
				net.batch_push(&ln.tx_batch, s.buf[s.off:][:s.len], s.ep, s.local)
			}
			sent, err := net.send_pushed(ln.sock, &ln.tx_batch)
			if errno, fresh := net.batch_take_gso_failure(&ln.tx_batch); fresh {
				d.off.udp_gso_fallbacks += 1
				logf(.Warn, "UDP segmentation offload was refused on %s (error %d), so datagrams will be sent one at a time", ln.text, errno)
			}
			switch {
			case err == .Would_Block:
				stuck = true
			case err != .None:
				// Most likely a bad destination or a firewall rule: this packet is
				// lost, the others go on.
				d.stats.sock_send_errors += 1
				k += 1
			case:
				d.stats.sent_pkts += u64(sent)
				k += sent
				if sent < m {
					stuck = true
				}
			}
		}
		if stuck {
			// Keep slots k.. for the next try.
			left := o.count - k
			for x in 0 ..< left {
				o.slots[x] = o.slots[k + x]
			}
			o.count = left
			o.done = left
			o.blocked = true
			o.lidx = lidx
			d.stats.sock_blocked += 1
			if !ln.want_write {
				ln.want_write = true
				event.modify_fd(&d.loop, ln.sock.fd, {.Read, .Write})
			}
			srv_tun_pause(d, true)
			return
		}
		i = j
	}
	o.count = 0
	o.done = 0
}

// Stops or resumes reading the tun device.
srv_tun_pause :: proc(d: ^Srv, pause: bool) {
	if !d.tun_open || pause == d.tun_paused {
		return
	}
	d.tun_paused = pause
	if pause {
		d.stats.tun_paused += 1
		event.modify_fd(&d.loop, d.tun.fd, {})
	} else {
		event.modify_fd(&d.loop, d.tun.fd, {.Read})
	}
}

// A packet for the tun. With the virtio header, segments of one flow in a round
// are joined: the packet may stay in the coalescer until `srv_flush_tun`, so it
// must stay unchanged (it is a slice of the receive buffer).
tun_write :: proc(d: ^Srv, pkt: []u8) {
	if d.tun.vnet && d.tun_tx.on {
		tun_tx_push(&d.tun, &d.tun_tx, &d.off, pkt, d.rx_buf)
		srv_tun_account(d)
		return
	}
	if err := tun.write(&d.tun, pkt); err != .None {
		d.stats.drop_tun_write += 1
		return
	}
	d.off.tun_writes += 1
	d.stats.tun_write_pkts += 1
	d.stats.tun_write_bytes += u64(len(pkt))
}

// Writes the joined runs that are still open. Call it before the memory of the
// packets (the receive buffer) is used again.
srv_flush_tun :: proc(d: ^Srv) {
	if !d.tun_open || !d.tun.vnet {
		return
	}
	tun_tx_flush(&d.tun, &d.tun_tx, &d.off)
	srv_tun_account(d)
}

srv_tun_account :: proc(d: ^Srv) {
	t := &d.tun_tx
	d.stats.tun_write_pkts += t.wrote_pkts
	d.stats.tun_write_bytes += t.wrote_bytes
	d.stats.drop_tun_write += t.dropped
	t.wrote_pkts, t.wrote_bytes, t.dropped = 0, 0, 0
}

// ----------------------------------------------------------------- UDP in

on_srv_udp :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := &SV
	ln := (^Listener)(user)
	if d.finished {
		return
	}
	if .Write in ready && ln.want_write {
		ln.want_write = false
		event.modify_fd(loop, fd, {.Read})
		if d.out.blocked && d.out.lidx == ln.index {
			d.out.blocked = false
			out_flush(d)
			if !d.out.blocked {
				srv_tun_pause(d, false)
			}
		}
	}
	if .Read in ready || .Error in ready {
		srv_read_udp(d, ln)
		if d.finished {
			return
		}
		out_flush(d)
		flush_dirty(d)
	}
}

// Reads the socket: at most SRV_READ_ROUNDS * RX_BATCH datagrams (a UDP GRO
// message with many datagrams uses up that many; the size of the last read
// decides how many messages to ask for).
srv_read_udp :: proc(d: ^Srv, ln: ^Listener) {
	// The tunnel packets of a round may point into the receive buffer: write them
	// before the next read reuses it.
	defer srv_rx_flush(d)
	left := SRV_READ_ROUNDS * RX_BATCH
	for left > 0 {
		want := rx_vlen(d.rx_msgs, left, ln.rx_per_msg)
		n, err := net.recv_batch(ln.sock, &d.rx_batch, want)
		if err == .Would_Block || err == .Interrupted {
			return
		}
		if err != .None {
			d.stats.sock_recv_errors += 1
			return
		}
		now := now_srv(d)
		dgrams := 0
		for i in 0 ..< n {
			size := net.batch_len(&d.rx_batch, i)
			seg := net.batch_gro_size(&d.rx_batch, i)
			msg := d.rx_buf[i * d.rx_slot:][:size]
			if net.batch_truncated(&d.rx_batch, i) {
				d.stats.drop_oversize += 1
				dgrams += 1
				continue
			}
			from := net.batch_from(&d.rx_batch, i)
			local := srv_local(d, net.batch_local(&d.rx_batch, i))
			if seg == 0 {
				dgrams += 1
				if size > RX_SLOT {
					d.stats.drop_oversize += 1
					continue
				}
				srv_input(d, ln, msg, from, local, now)
				if d.finished {
					return
				}
				continue
			}
			// A block of datagrams of `seg` bytes from one source (the last may be shorter).
			for off := 0; off < size; off += seg {
				dgrams += 1
				if seg > RX_SLOT {
					d.stats.drop_oversize += 1
					continue
				}
				srv_input(d, ln, msg[off:min(off + seg, size)], from, local, now)
				if d.finished {
					return
				}
			}
		}
		left -= max(dgrams, 1)
		ln.rx_per_msg = clamp(dgrams / max(n, 1), 1, 64)
		// The next read overwrites the buffer.
		srv_rx_flush(d)
		if n < want {
			return
		}
	}
}

// One datagram: the demultiplexer.
//   data packet    - found by the peer-id in its header (or by source address
//                    if it has none)
//   control packet - found by the client's session id
//   first packet   - creates a session
// `local` is the host address the datagram was sent to.
srv_input :: proc(d: ^Srv, ln: ^Listener, pkt: []u8, from: net.Endpoint, local: net.Local, now: time.Duration) {
	addr := endpoint_peer_addr(from)
	fb := session.peer_addr_bytes(&addr)
	if id, is_data := session.server_peer_id(pkt); is_data {
		h: server.Peer_Handle
		p: ^server.Peer
		if id == session.PEER_ID_NONE {
			key := endpoint_key(from, ln.index)
			h, p = server.peers_by_addr(&d.srv.reg.peers, &key)
		} else {
			h, p = server.peers_by_id(&d.srv.reg.peers, id)
		}
		if p == nil {
			d.stats.drop_no_session += 1
			return
		}
		c := conn_of_handle(d, h)
		if c == nil || c.proto != .Udp || c.lidx != ln.index {
			d.stats.drop_conn_state += 1
			return
		}
		before := d.taken
		rx_before := c.s.counters.data_rx
		srv_rx_enter(d, c, fb, local)
		r := session.session_receive(&c.s, pkt, now, fb)
		srv_rx_leave(d, c)
		if c.s.counters.data_rx != rx_before {
			// The packet authenticated. (With workers this is done when the job is finished.)
			conn_follow_local(d, c, local)
		}
		if len(r.tunnel) > 0 {
			srv_on_tunnel(d, c, r.tunnel)
		}
		if d.taken == before || c.release {
			// A packet that waits for its worker is looked at when it is done.
			conn_pump(d, c, false)
		}
		return
	}
	if sid, is_ctl := session.server_client_sid(pkt); is_ctl {
		if slot, found := d.sid_map[sid]; found {
			c := d.conns[slot]
			if c != nil && c.proto == .Udp && c.lidx == ln.index {
				srv_rx_enter(d, c, fb, local)
				session.session_receive(&c.s, pkt, now, fb)
				srv_rx_leave(d, c)
				conn_pump(d, c)
			}
			return
		}
		srv_first_packet(d, ln, pkt, from, local, fb, now)
		return
	}
	d.stats.drop_bad_opcode += 1
}

// A control packet of a client that has no session: the stateless part of the
// handshake (reset replies, cookies), and a new session once a cookie came back.
srv_first_packet :: proc(d: ^Srv, ln: ^Listener, pkt: []u8, from: net.Endpoint, local: net.Local, fb: []u8, now: time.Duration) {
	if d.stopping {
		d.stats.drop_stopping += 1
		return
	}
	unix := unix_now()
	res := session.server_first_packet(ln.sh, pkt, fb, now, unix, d.link[:])
	srv_first_log(d, ln.sh, &res, from, fb)
	switch res.kind {
	case .Drop:
		return
	case .Reply:
		if err := net.send_to(ln.sock, d.link[:res.n], from, local); err != .None && err != .Would_Block {
			d.stats.sock_send_errors += 1
		}
		return
	case .Accept:
		c := conn_new(d, .Udp, ln.index, from, local)
		if c == nil {
			d.stats.drop_conn_limit += 1
			return
		}
		accept := res.accept
		if err := session.session_init_server(&c.s, ln.sh, &accept, now, unix); err != .None {
			logf(.Warn, "cannot start a session for %s: %v", conn_label(c), err)
			conn_abort(d, c)
			return
		}
		c.s_ok = true
		if d.dco.on {
			srv_dco_attach(d, c)
		} else if !srv_workers_attach(d, c) {
			logf(.Warn, "cannot hand the data channel of %s to a worker", conn_label(c))
			conn_abort(d, c)
			return
		}
		c.sid = accept.client_sid
		c.sid_set = true
		d.sid_map[c.sid] = c.slot
		d.stats.sessions += 1
		logf(.Debug, "new session from %s", conn_label(c))
		session.session_receive(&c.s, pkt, now, fb)
		conn_pump(d, c)
	}
}

// A conn that never got going: out of the table, memory freed.
conn_abort :: proc(d: ^Srv, c: ^Conn) {
	srv_dco_forget(d, c)
	d.conns[c.slot] = nil
	append(&d.free_slots, c.slot)
	d.n_conns -= 1
	conn_free(d, c)
}

// A tunnel packet from a client: where does it go?
srv_on_tunnel :: proc(d: ^Srv, c: ^Conn, pkt: []u8) {
	if d.cfg.block_ipv6 && is_ipv6(pkt) {
		d.stats.drop_block6_rx += 1
		c.drops += 1
		return
	}
	if c.mss4 != 0 {
		mss.clamp_syn(pkt, c.mss4)
	}
	dest, v := server.registry_from_peer(&d.srv.reg, c.h, pkt)
	switch v {
	case .To_Tun:
		c.in_pkts += 1
		c.in_bytes += u64(len(pkt))
		tun_write(d, pkt)
	case .To_Peer:
		c.in_pkts += 1
		c.in_bytes += u64(len(pkt))
		dc := conn_of_handle(d, dest)
		if dc == nil || !dc.up || dc.closing {
			d.stats.drop_conn_state += 1
			return
		}
		if conn_in_service(d, dc) {
			// The other client is the service's: the packet goes to the kernel through the
			// tun device, which forwards it to the service's device (as for two service clients).
			tun_write(d, pkt)
			return
		}
		forward_packet(d, dc, pkt)
	case .Drop_Bad_Packet, .Drop_Bad_Source, .Drop_No_Route, .Drop_Loop, .Drop_C2C:
		c.drops += 1
	}
}

// ---------------------------------------------------------------------- TCP

on_srv_tcp_listen :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := &SV
	ln := (^Listener)(user)
	if d.finished || d.stopping {
		return
	}
	for _ in 0 ..< 32 {
		sock, from, err := net.tcp_accept(ln.sock)
		if err == .Would_Block {
			return
		}
		if err != .None {
			logf(.Warn, "accept on %s failed: %v", ln.text, err)
			return
		}
		srv_tcp_accepted(d, ln, sock, from)
	}
}

srv_tcp_accepted :: proc(d: ^Srv, ln: ^Listener, sock: net.Socket, from: net.Endpoint) {
	if d.n_conns >= d.max_conns {
		d.stats.drop_conn_limit += 1
		net.close(sock)
		return
	}
	key := endpoint_key(from, ln.index)
	if tcp_preauth_count(d, key) >= TCP_PREAUTH_PER_IP {
		d.stats.drop_preauth += 1
		net.close(sock)
		return
	}
	c := conn_new(d, .Tcp, ln.index, from)
	if c == nil {
		d.stats.drop_conn_limit += 1
		net.close(sock)
		return
	}
	if lep, lerr := net.local_endpoint(sock); lerr == .None {
		c.local = net.local_of_address(lep.address)
	}
	c.sock = sock
	c.sock_open = true
	if !txq_init(&c.q, SRV_TCP_TX_SIZE, SRV_TCP_TX_MAX) {
		logf(.Error, "out of memory")
		conn_abort(d, c)
		return
	}
	// A listener first looks at the first bytes (`srv_classify`): on a tls-server
	// listener a TLS client and a raw OpenVPN client share the port; on any TCP
	// listener an HTTP request (`GET `) is told from OpenVPN framing. Nothing reads
	// the socket or is handed over before that. The wait is edge triggered: the
	// bytes are only peeked, so a level triggered watch would fire again and again
	// for a partial first packet.
	c.classify = true
	if err := event.add_fd(&d.loop, sock.fd, {.Read, .Edge}, on_srv_tcp_conn, c); err != .None {
		logf(.Error, "cannot watch a TCP connection: %v", err)
		conn_abort(d, c)
		return
	}
	logf(.Debug, "connection from %s, waiting for its first bytes", conn_label(c))
	conn_arm_timer(d, c)
}

// The transport of a TCP connection is known: the session starts and the
// connection goes to the DCO service or a worker. The event loop does not
// watch the socket during this.
srv_tcp_start :: proc(d: ^Srv, c: ^Conn, sh: ^session.Server_Shared) {
	sock := c.sock
	now := now_srv(d)
	sh := sh
	if d.dco.on && c.tls {
		// A tls client of a mixed server: its data channel is in the session, here.
		sh = &d.shared[SHARED_TLS_DAEMON]
	}
	if err := session.session_init_server_tcp(&c.s, sh, now, unix_now()); err != .None {
		logf(.Warn, "cannot start a session for %s: %v", conn_label(c), err)
		conn_abort(d, c)
		return
	}
	c.s_ok = true
	if conn_in_service(d, c) {
		srv_dco_attach(d, c)
		if d.dco.early && !srv_dco_early(d, c) {
			conn_abort(d, c)
			return
		}
	} else if !srv_workers_attach(d, c) {
		logf(.Warn, "cannot hand the data channel of %s to a worker", conn_label(c))
		conn_abort(d, c)
		return
	}
	if c.sock_open {
		// Not read by us when the service has it (early handover): its records come as events.
		if err := event.add_fd(&d.loop, sock.fd, {.Read}, on_srv_tcp_conn, c); err != .None {
			logf(.Error, "cannot watch a TCP connection: %v", err)
			conn_abort(d, c)
			return
		}
	}
	d.stats.sessions += 1
	logf(.Debug, "%s connection from %s", "TLS" if c.tls else "TCP", conn_label(c))
	conn_arm_timer(d, c)
}

// TCP connections from one address that have not logged in.
tcp_preauth_count :: proc(d: ^Srv, key: server.Addr_Key) -> (n: int) {
	want := server.rate_key(key)
	for c in d.conns {
		if c != nil && c.proto == .Tcp && !c.named && server.rate_key(c.key) == want {
			n += 1
		}
	}
	return
}

on_srv_tcp_conn :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := &SV
	c := (^Conn)(user)
	if d.finished || !c.sock_open {
		return
	}
	if c.classify {
		srv_classify(d, c, ready)
		return
	}
	if c.ws_phase == .Request && !c.s_ok {
		// An HTTP request on a tcp listener: the session starts when the upgrade is accepted.
		srv_http_read(d, c)
		return
	}
	if c.tls_hs {
		// The outer handshake: the login has not started.
		srv_tls_step(d, c)
		return
	}
	if .Write in ready {
		if !tcp_flush_conn(d, c) {
			return
		}
	}
	if .Read in ready || .Hangup in ready || .Error in ready {
		srv_read_tcp(d, c)
		out_flush(d)
		flush_dirty(d)
	}
}

srv_read_tcp :: proc(d: ^Srv, c: ^Conn) {
	defer srv_rx_flush(d)
	cidx, sess := c.slot, c.sess
	scratch := d.rx_buf[:32 * 1024]
	// A tls connection also goes on while the TLS library holds a record it has not given out.
	for round := 0; round < SRV_READ_ROUNDS || (c.link != nil && tlslink.link_has_input(c.link)); round += 1 {
		n, err := srv_stream_read(d, c, scratch)
		if err == .Would_Block || err == .Interrupted {
			return
		}
		if err != .None {
			if err != .Closed {
				d.stats.sock_recv_errors += 1
			}
			if c.end == .None {
				c.end = .Tcp_Lost
			}
			conn_drop(d, c)
			return
		}
		if c.ws_phase == .None {
			srv_feed_session(d, c, scratch[:n])
		} else if !srv_stream_input(d, c, scratch[:n]) {
			// The conn ended (a refused request, a broken frame, a close).
			return
		}
		// The next read overwrites `scratch`.
		srv_rx_flush(d)
		if d.conns[cidx] != c || c.sess != sess {
			// The jobs of this round ended the conn.
			return
		}
		if !conn_pump(d, c) {
			return
		}
		if !c.sock_open {
			// The login was accepted and the connection went to the DCO service.
			return
		}
	}
}

// Gives the session of `c` bytes of its stream and hands the tunnel packets on.
srv_feed_session :: proc(d: ^Srv, c: ^Conn, data: []u8) {
	rest := data
	now := now_srv(d)
	for {
		srv_rx_enter(d, c, nil, {})
		r := session.session_receive(&c.s, rest, now)
		srv_rx_leave(d, c)
		rest = rest[r.consumed:]
		if len(r.tunnel) > 0 {
			srv_on_tunnel(d, c, r.tunnel)
		}
		st := session.session_state(&c.s)
		if st == .Failed || st == .Closed {
			break
		}
		if len(rest) == 0 && !r.more {
			break
		}
	}
}

// Ends a conn at once, without a goodbye (the transport is gone or useless).
conn_drop :: proc(d: ^Srv, c: ^Conn) {
	if d.conns[c.slot] != c {
		return
	}
	conn_unregister(d, c)
	c.release = true
	conn_release(d, c)
}

// A packet for a TCP client: queued if the policy allows, else dropped or the
// client is closed (see the top of server.odin).
tcp_append :: proc(d: ^Srv, c: ^Conn, pkt: []u8, is_data: bool) -> bool {
	if !tcp_reserve(d, c, len(pkt), is_data, 1) {
		return false
	}
	if !txq_append(&c.q, pkt) {
		d.stats.drop_tcp_backlog += 1
		return false
	}
	if !c.dirty {
		c.dirty = true
		append(&d.dirty, c.slot)
	}
	return true
}

// Reserves room in the queue of `c` for `n` bytes (`pkts` packets): writes the
// queue out once if the policy refuses them, then lets it grow. Adds nothing.
// False if they do not fit: data packets are counted as dropped; for a control
// packet or a slow client `c` is closed, and may be gone.
tcp_reserve :: proc(d: ^Srv, c: ^Conn, n: int, is_data: bool, pkts: int) -> bool {
	policy := tcp_tx_policy(txq_pending(&c.q), len(c.q.buf), n, is_data)
	if policy != .Accept && txq_pending(&c.q) > 0 {
		// The queue is only written at the end of a round; a full tun burst for
		// one fast client fills it before that. Write it out once before giving up.
		if !tcp_flush_conn(d, c) {
			// The connection broke and `c` is gone.
			if is_data {
				d.stats.drop_conn_state += u64(pkts)
			}
			return false
		}
		policy = tcp_tx_policy(txq_pending(&c.q), len(c.q.buf), n, is_data)
	}
	if policy != .Accept {
		// Still full: a slow reader. Give the queue more room, up to its limit.
		// This copies the waiting bytes, but only now.
		want := tcp_tx_want_capacity(txq_pending(&c.q), len(c.q.buf), c.q.limit, n, is_data)
		if want > len(c.q.buf) && txq_grow(&c.q, want) {
			policy = tcp_tx_policy(txq_pending(&c.q), len(c.q.buf), n, is_data)
		}
	}
	switch policy {
	case .Drop:
		d.stats.drop_tcp_backlog += u64(pkts)
		c.drops += u64(pkts)
		now := now_srv(d)
		if c.slow_since == 0 {
			c.slow_since = now
		} else if now - c.slow_since > SLOW_PEER_LIMIT {
			tcp_close_slow(d, c)
		}
		return false
	case .Overflow:
		tcp_close_slow(d, c)
		return false
	case .Accept:
	}
	return true
}

tcp_close_slow :: proc(d: ^Srv, c: ^Conn) {
	if c.end == .None {
		c.end = .Slow
	}
	d.stats.tcp_slow_closed += 1
	logf(.Warn, "client %s is not reading its TCP connection, so it will be closed", conn_label(c))
	conn_drop(d, c)
}

// Writes the queue to the socket and watches for `Write` while some is left.
// False if the connection broke (the conn is then released).
tcp_flush_conn :: proc(d: ^Srv, c: ^Conn) -> bool {
	if !c.sock_open {
		return false
	}
	if c.link != nil {
		return tls_flush_conn(d, c)
	}
	if c.ws_phase == .On {
		if !srv_ws_send(d, c) {
			return false
		}
	} else {
		for txq_pending(&c.q) > 0 {
			n, err := net.stream_send(c.sock, txq_front(&c.q))
			if err == .Would_Block {
				break
			}
			if err != .None {
				d.stats.sock_send_errors += 1
				if c.end == .None {
					c.end = .Tcp_Lost
				}
				conn_drop(d, c)
				return false
			}
			txq_consume(&c.q, n)
		}
	}
	pending := txq_pending(&c.q) + srv_ws_pending(c)
	want := pending > 0
	if want != c.want_write {
		c.want_write = want
		event.modify_fd(&d.loop, c.sock.fd, {.Read, .Write} if want else {.Read})
	}
	if pending < len(c.q.buf) / 4 {
		c.slow_since = 0
	}
	return true
}

// A last try to write the queue, with nothing else done (the conn is ending).
tcp_write_now :: proc(c: ^Conn) {
	if c.link != nil {
		tls_write_now(c)
		return
	}
	if c.ws_phase == .On {
		srv_ws_write_now(c)
		return
	}
	for txq_pending(&c.q) > 0 {
		n, err := net.stream_send(c.sock, txq_front(&c.q))
		if err != .None {
			return
		}
		txq_consume(&c.q, n)
	}
}

// Writes the queues of the TCP clients that got data in this round.
flush_dirty :: proc(d: ^Srv) {
	for len(d.dirty) > 0 {
		slot := pop(&d.dirty)
		c := d.conns[slot]
		if c != nil {
			c.dirty = false
			tcp_flush_conn(d, c)
		}
	}
}

srv_flush_all :: proc(d: ^Srv) {
	out_flush(d)
	flush_dirty(d)
}

// A control packet (handshake, keepalive, rekey, goodbye) for a client.
conn_send_ctl :: proc(d: ^Srv, c: ^Conn, pkt: []u8) {
	if c.dco.stream {
		// A TCP connection that the service owns: the record goes to CTRL_TX.
		dco_ctrl_send(&c.dco, pkt)
		return
	}
	if c.proto == .Udp {
		ln := &d.listeners[c.lidx]
		err := net.send_to(ln.sock, pkt, c.ep, c.local)
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
	if !c.sock_open {
		return
	}
	if tcp_append(d, c, pkt, false) {
		tcp_flush_conn(d, c)
	}
}
