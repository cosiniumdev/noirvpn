// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:time"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/reliable"
import "noir:proto/wire"
import "noir:proto/wrap"

// ------------------------------------------------------------------ wrapping

@(private)
wall_now :: proc "contextless" (s: ^Session, now: Time) -> i64 {
	return s.wall_base + i64(now / time.Second)
}

// Wraps an inner control packet for key id `key_id` (key ids
// above 0 use the dynamic wrap once it exists).
@(private)
wrap_out :: proc(s: ^Session, key_id: u8, op: wire.Opcode, now: Time, inner, out: []u8) -> (n: int, err: wrap.Error) {
	w := &s.wrap
	t := wall_now(s, now)
	if key_id != 0 && w.have_dyn {
		return wrap.tls_crypt_wrap(&w.dyn, t, inner, out)
	}
	switch w.mode {
	case .None:
		if len(out) < len(inner) {
			return 0, .Buffer_Too_Small
		}
		copy(out, inner)
		return len(inner), .None
	case .Tls_Auth:
		return wrap.tls_auth_wrap(&w.auth, t, inner, out)
	case .Tls_Crypt:
		return wrap.tls_crypt_wrap(&w.crypt, t, inner, out)
	case .Tls_Crypt_V2:
		if op == .Hard_Reset_Client_V3 || op == .Control_Wkc_V1 {
			return wrap.tls_crypt_v2_client_wrap(&w.crypt, w.wkc[:w.wkc_len], t, inner, out)
		}
		return wrap.tls_crypt_wrap(&w.crypt, t, inner, out)
	}
	return 0, .Bad_Argument
}

@(private)
wrap_in :: proc(s: ^Session, key_id: u8, op: wire.Opcode, pkt, out: []u8) -> (n: int, err: wrap.Error) {
	w := &s.wrap
	if key_id != 0 && w.have_dyn {
		return wrap.tls_crypt_unwrap(&w.dyn, pkt, out)
	}
	if s.role == .Server {
		return srv_unwrap(s, op, pkt, out)
	}
	return unwrap_with(s, pkt, out)
}

// Unwraps with the context the session holds.
@(private)
unwrap_with :: proc(s: ^Session, pkt, out: []u8) -> (n: int, err: wrap.Error) {
	w := &s.wrap
	switch w.mode {
	case .None:
		if len(out) < len(pkt) {
			return 0, .Buffer_Too_Small
		}
		copy(out, pkt)
		return len(pkt), .None
	case .Tls_Auth:
		return wrap.tls_auth_unwrap(&w.auth, pkt, out)
	case .Tls_Crypt, .Tls_Crypt_V2:
		return wrap.tls_crypt_unwrap(&w.crypt, pkt, out)
	}
	return 0, .Bad_Argument
}

// ----------------------------------------------------------------- send side

// Puts the TLS output into reliable packets, as far as the send window
// admits. What does not fit stays inside TLS and goes out after the next ack.
@(private)
flush_tls :: proc(s: ^Session, now: Time) {
	ks := &s.ks
	if !ks.tls_ok || !ks.chan_ok || ks.chan.failure != .None {
		return
	}
	ip := reliable.IP_UDP_OVERHEAD_V4 if s.cfg.ipv4_peer else reliable.IP_UDP_OVERHEAD_V6
	// SPEC-GAP: the budget assumes four piggybacked ack ids. A stock peer counts
	// the real number, so a packet with fewer acks could carry a few bytes more.
	// Smaller is safe.
	budget := reliable.payload_budget(s.cfg.max_packet_size, s.wrap.overhead, ip)
	piece := clamp(budget, reliable.MIN_PIECE, ks.chan.cfg.max_payload)
	for {
		pending := ossl.tls_pending_out(&ks.tls)
		if pending == 0 {
			break
		}
		room := reliable.send_room(&ks.chan)
		if room == 0 {
			break
		}
		// The first packet after the reset carries the wrapped client key when
		// the server asked for it. It has less room.
		first_wkc := ks.resend_wkc && !ks.wkc_sent
		first_max := piece
		capacity := room * piece
		if first_wkc {
			first_max = min(max(budget - s.wrap.wkc_len, reliable.MIN_PIECE), piece)
			capacity = first_max + (room - 1) * piece
		}
		want := min(pending, capacity, len(s.tls_buf))
		n := ossl.tls_take(&ks.tls, s.tls_buf[:want])
		if n == 0 {
			break
		}
		data := s.tls_buf[:n]
		if first_wkc {
			m := min(n, first_max)
			if _, ok := reliable.send_packet(&ks.chan, u8(wire.Opcode.Control_Wkc_V1), data[:m], now); !ok {
				fail(s, .Internal, "control window")
				return
			}
			ks.wkc_sent = true
			data = data[m:]
		}
		if len(data) > 0 {
			used := reliable.send(&ks.chan, data, budget, u8(wire.Opcode.Control_V1), now)
			if used != len(data) {
				fail(s, .Internal, "control window")
				return
			}
		}
	}
}

// Checks the failure state of the control channel (hand window, retransmit
// limit).
@(private)
check_chan :: proc(s: ^Session, now: Time) {
	ks := &s.ks
	if !ks.chan_ok || s.state == .Failed || s.state == .Closed {
		return
	}
	// `next_wakeup` runs the failure timers.
	reliable.next_wakeup(&ks.chan, now)
	switch reliable.error(&ks.chan) {
	case .None:
	case .Hand_Window:
		fail(s, .Hand_Window, "the handshake did not finish within the hand-window time")
	case .Retransmit_Limit:
		fail(s, .Hand_Window, "retransmit limit")
	}
}

// The next link packet, written to the start of `out` (at least `LINK_BUF_SIZE`
// bytes). Returns its length, 0 if nothing to send.
// - Call it until it returns 0, after every call that can queue packets.
// - TCP: the packet has its two-byte length in front.
// - After a `Failed` or `Closed` event, call it once more (a TLS alert or the
//   EXIT message may be waiting).
session_poll_tx :: proc(s: ^Session, out: []u8, now: Time) -> int {
	if len(out) < LINK_BUF_SIZE || s.state == .New || !s.ks.chan_ok {
		return 0
	}
	if s.role == .Server && !s.srv.first_rx {
		// The wrapping of a server is chosen by its first packet.
		return 0
	}
	check_chan(s, now)
	if s.state != .Failed && s.state != .Closed {
		if tx, ok := reliable.poll(&s.ks.chan, now); ok {
			return emit_control(s, tx, out, now)
		}
		return poll_data_tx(s, out, now)
	}
	if tx, ok := reliable.poll(&s.ks.chan, now); ok {
		return emit_control(s, tx, out, now)
	}
	return 0
}

@(private)
emit_control :: proc(s: ^Session, tx: reliable.Tx, out: []u8, now: Time) -> int {
	ks := &s.ks
	cp: wire.Control_Packet
	switch tx.kind {
	case .Control:
		cp.opcode = wire.Opcode(tx.tag)
		cp.packet_id = tx.id
		cp.payload = tx.payload
	case .Ack:
		cp.opcode = .Ack_V1
	case .None:
		return 0
	}
	cp.key_id = ks.id
	cp.session_id = s.local_sid
	cp.ack_count = int(tx.acks.count)
	for i in 0 ..< cp.ack_count {
		cp.acks[i] = tx.acks.ids[i]
	}
	cp.ack_remote_sid = tx.acks.sid
	n, eerr := wire.control_encode(s.inner[:], &cp)
	if eerr != .None {
		fail(s, .Internal, "control encode")
		return 0
	}
	off := wire.FRAME_PREFIX_LEN if s.transport == .Tcp else 0
	wn, werr := wrap_out(s, cp.key_id, cp.opcode, now, s.inner[:n], out[off:])
	if werr != .None {
		fail(s, .Internal, "control wrap")
		return 0
	}
	total := wn
	if s.transport == .Tcp {
		out[0] = u8(wn >> 8)
		out[1] = u8(wn)
		total += wire.FRAME_PREFIX_LEN
	}
	s.counters.control_tx += 1
	s.counters.link_tx_pkts += 1
	s.counters.link_tx_bytes += u64(total)
	return total
}

// ------------------------------------------------------------- receive side

// Takes one datagram (UDP) or a chunk of the byte stream (TCP).
//
// UDP: `data` is one datagram, used up. The engine may overwrite it (data packets
// are decrypted in place).
//
// TCP: bytes go into the frame buffer; at most one frame per call. `consumed`:
// bytes taken. `more`: another whole frame waits.
//
//	rest := chunk
//	for {
//		r := session_receive(&s, rest, now)
//		rest = rest[r.consumed:]
//		// use r.tunnel
//		if len(rest) == 0 && !r.more { break }
//	}
//
// Control packets and failures show up as events. Call `session_poll_tx` after
// (acks and replies are queued).
//
// Server, UDP: `from` is the datagram source in `peer_addr_v4` form.
// - Control packet from another address than the session's: dropped.
// - Authenticated data packet from another address: raises `Float_Candidate`.
// - Empty `from` skips both checks. Clients and TCP ignore it.
session_receive :: proc(s: ^Session, data: []u8, now: Time, from: []u8 = nil) -> (r: Rx_Result) {
	if s.state == .New || s.state == .Closed || s.state == .Failed {
		r.consumed = len(data)
		return
	}
	s.rx_from = from
	defer s.rx_from = nil
	if s.transport == .Udp {
		r.consumed = len(data)
		s.counters.link_rx_pkts += 1
		s.counters.link_rx_bytes += u64(len(data))
		r.tunnel = process_packet(s, data, now)
		return
	}
	n := wire.splitter_feed(&s.split, data)
	r.consumed = n
	s.counters.link_rx_bytes += u64(n)
	pkt, err := wire.splitter_next(&s.split)
	#partial switch err {
	case .None:
		s.counters.link_rx_pkts += 1
		r.tunnel = process_packet(s, pkt, now)
	case .Need_More:
	case:
		fail(s, .Link_Error, "received a TCP frame that is not valid")
		r.consumed = len(data)
		return
	}
	if s.state != .Failed {
		_, _, ferr := wire.frame_decode(s.split.buf[s.split.start:s.split.end], s.split.max_packet)
		r.more = ferr == .None
	}
	return
}

// A TCP session whose data channel belongs to a service (`Config.ext_data`) as
// well as its transport. After `session_stream_take` the stream is the service's
// and control records come one by one (the CTRL_RX messages). `rec` is one record
// without its 2-byte length prefix. Counters as in `session_receive`.
session_receive_record :: proc(s: ^Session, rec: []u8, now: Time) -> (r: Rx_Result) {
	r.consumed = len(rec)
	if s.state == .New || s.state == .Closed || s.state == .Failed || s.transport != .Tcp {
		return
	}
	s.counters.link_rx_bytes += u64(len(rec) + wire.FRAME_PREFIX_LEN)
	if len(rec) == 0 || len(rec) > s.split.max_packet {
		fail(s, .Link_Error, "received a TCP frame that is not valid")
		return
	}
	s.counters.link_rx_pkts += 1
	r.tunnel = process_packet(s, rec, now)
	return
}

// Hands the caller the stream bytes the session read but did not use (part of a
// frame, or frames after the one it stopped at), and forgets them. The stream
// goes to its new owner, who reads on from there (`Config.ext_data`). Valid until
// the next call into the session. Empty for UDP.
session_stream_take :: proc(s: ^Session) -> []u8 {
	if s.transport != .Tcp {
		return nil
	}
	rest := s.split.buf[s.split.start:s.split.end]
	s.split.start, s.split.end = 0, 0
	return rest
}

// A packet that is dropped: UDP counts it, TCP ends the connection.
// Exception: a session whose data channel is a service's. A data
// packet that gets here came before the service had the peer; it is only lost.
@(private)
rx_drop :: proc(s: ^Session, counter: ^u64, why: string) {
	counter^ += 1
	if s.transport == .Tcp && !s.cfg.ext_data {
		fail(s, .Link_Error, why)
	}
}

@(private)
process_packet :: proc(s: ^Session, pkt: []u8, now: Time) -> []u8 {
	if len(pkt) < 1 {
		rx_drop(s, &s.counters.drop_short, "received an empty packet")
		return nil
	}
	op, kid := wire.split_first_byte(pkt[0])
	switch wire.opcode_class(op) {
	case .Data:
		return process_data(s, pkt, now)
	case .Control:
		process_control(s, pkt, op, kid, now)
		return nil
	case .Rejected, .Unknown:
		rx_drop(s, &s.counters.drop_opcode, "bad opcode")
		return nil
	}
	return nil
}

@(private)
process_control :: proc(s: ^Session, pkt: []u8, op: wire.Opcode, kid: u8, now: Time) {
	if s.rdp != nil && s.remote.barrier != nil {
		// Data packets taken earlier come first. One of them may have ended the
		// session (an exit notice, a failure).
		s.remote.barrier(s.remote.host)
		if s.state == .Failed || s.state == .Closed {
			return
		}
	}
	ks := &s.ks
	// Opcode and direction checks.
	server := s.role == .Server
	if !wire.opcode_allowed_for_receiver(op, .Server if server else .Client) {
		rx_drop(s, &s.counters.drop_opcode, "received a packet type that is not allowed for this role")
		return
	}
	if len(pkt) < wire.CONTROL_PREFIX_LEN {
		rx_drop(s, &s.counters.drop_short, "a control packet was too short")
		return
	}
	// 3 and 4: session id. A reset with another sid than the one we accepted
	// is ignored.
	sid: reliable.Sid
	copy(sid[:], pkt[1:wire.CONTROL_PREFIX_LEN])
	if server {
		if !srv_check_source(s, op, sid) {
			return
		}
	} else if op == .Hard_Reset_Server_V2 {
		if s.peer_sid_set && sid != s.peer_sid {
			rx_drop(s, &s.counters.drop_sid, "the server sent a second reset")
			return
		}
	} else if !s.peer_sid_set || sid != s.peer_sid {
		rx_drop(s, &s.counters.drop_sid, "a packet had the wrong session id")
		return
	}
	// 5: unwrap, with the replay check.
	n, uerr := wrap_in(s, kid, op, pkt, s.inner[:])
	if uerr != .None {
		if uerr == .Replay {
			// A stateless server builds every reply from a fresh counter, so a
			// second reply can look like a replay. Harmless.
			rx_drop(s, &s.counters.drop_wrap_replay, "wrap replay")
		} else {
			rx_drop(s, &s.counters.drop_unwrap, "a control packet failed its tag check")
		}
		return
	}
	cp: wire.Control_Packet
	if wire.control_decode(s.inner[:n], &cp) != .None {
		rx_drop(s, &s.counters.drop_decode, "a control packet could not be decoded")
		return
	}
	// 6: key id. The only exception is the soft reset that starts the next key.
	is_reset := op == .Hard_Reset_Server_V2 || op == .Hard_Reset_Client_V2 || op == .Hard_Reset_Client_V3
	if is_reset && (kid != 0 || ks.id != 0) {
		rx_drop(s, &s.counters.drop_key_id, "a reset packet had a key id")
		return
	}
	if cp.key_id != ks.id {
		if op == .Soft_Reset_V1 && cp.key_id == keys.key_id_next(ks.id) && s.state == .Up && ks.state >= .Generated_Keys {
			begin_rekey(s, cp.key_id, true, now)
		} else {
			rx_drop(s, &s.counters.drop_key_id, "the key ids are out of sync")
			return
		}
	}
	if server && is_reset && !s.link_up {
		if !srv_first_reset(s, sid, &cp, now) {
			return
		}
	}
	if op == .Hard_Reset_Server_V2 && !s.peer_sid_set {
		if cp.ack_count > 0 && cp.ack_remote_sid != s.local_sid {
			rx_drop(s, &s.counters.drop_reliable, "a reset packet acknowledged another session")
			return
		}
		if cp.packet_id != 0 {
			rx_drop(s, &s.counters.drop_reliable, "a reset packet had a message id other than 0")
			return
		}
		s.peer_sid = sid
		s.peer_sid_set = true
		reliable.set_peer_sid(&ks.chan, sid)
		s.link_up = true
		s.state = .Handshaking
		emit(s, Event{kind = .Link_Up})
	}
	// 7 and 8: acks and sequencing.
	rx := reliable.Rx {
		has_msg    = op != .Ack_V1,
		id         = cp.packet_id,
		tag        = u8(op),
		hard_reset = is_reset,
		payload    = cp.payload,
	}
	rx.acks.count = u8(cp.ack_count)
	for i in 0 ..< cp.ack_count {
		rx.acks.ids[i] = cp.acks[i]
	}
	rx.acks.sid = cp.ack_remote_sid
	switch reliable.receive(&ks.chan, rx, now) {
	case .Stored, .Duplicate, .Ack_Only:
		s.counters.control_rx += 1
		s.last_rx = now
	case .Ahead, .Window_Full, .Bad_Reset_Id, .Bad_Ack_List, .Bad_Sid, .Oversize, .Failed:
		rx_drop(s, &s.counters.drop_reliable, "a control packet was refused")
	}
	if s.state == .Failed {
		return
	}
	deliver(s, now)
	progress(s, now)
	flush_tls(s, now)
	close_progress(s, now)
}

// Hands the messages that arrived in order to their owner: TLV of a reset,
// TLS bytes.
@(private)
deliver :: proc(s: ^Session, now: Time) {
	if s.role == .Server {
		srv_deliver(s, now)
		return
	}
	ks := &s.ks
	for s.state != .Failed {
		d, ok := reliable.pop(&ks.chan)
		if !ok {
			break
		}
		#partial switch wire.Opcode(d.tag) {
		case .Hard_Reset_Server_V2:
			if d.id != 0 {
				continue
			}
			flags, terr := wire.early_neg_parse(d.payload)
			if terr != .None {
				fail(s, .Protocol, "the server reset had an early-negotiation TLV that is not valid")
				return
			}
			// Only UDP uses it, and only a client that holds
			// a tls-crypt-v2 key acts on it.
			if flags & wire.EARLY_NEG_FLAG_RESEND_WKC != 0 && s.wrap.mode == .Tls_Crypt_V2 && s.transport == .Udp {
				ks.resend_wkc = true
			}
		case .Soft_Reset_V1:
			// Message 0 is the reset itself. SPEC-GAP: anything after it with
			// this opcode is treated as TLS bytes.
			if d.id != 0 && ks.tls_ok {
				ossl.tls_feed(&ks.tls, d.payload)
			}
		case .Control_V1:
			// TLS bytes before our own ClientHello cannot be in order, so there
			// is no session to give them to: drop them.
			if ks.tls_ok {
				if !ossl.tls_feed(&ks.tls, d.payload) {
					fail(s, .Internal, "TLS buffer")
					return
				}
			}
		}
	}
}
