// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import "noir:proto/wire"

// TCP connection that carries length-framed packets
//. Receive side feeds a
// `wire.Stream_Splitter`. Send side queues frames and writes them in as few
// calls as it can, so small packets share a segment.
//
// All memory is the caller's. Typical use from an event loop handler:
//
//	// readable
//	for {
//		_, err := net.tcp_recv(&c, scratch)
//		if err == .Would_Block { break }
//		if err != .None { /* closed or broken: tear down */ }
//		for {
//			pkt, ok, perr := net.tcp_next(&c)
//			if perr != .None { /* framing broken: tear down */ }
//			if !ok { break }
//			handle(pkt)
//		}
//	}
//
//	// sending
//	net.tcp_queue(&c, pkt)
//	pending, _ := net.tcp_flush(&c)
//	// if pending > 0, watch for .Write and call tcp_flush when it fires
TCP_Conn :: struct {
	sock:    Socket,
	rx:      wire.Stream_Splitter,
	tx:      []u8,
	tx_head: int, // first queued byte
	tx_tail: int, // one past the last queued byte
}

// `rx_buf` needs at least 2 + `max_packet` bytes (the splitter checks).
// `tx_buf` holds frames waiting to be written; size it at a few packets.
// `max_packet`: largest frame accepted from the peer, 1 to 65535.
tcp_conn_init :: proc(c: ^TCP_Conn, sock: Socket, rx_buf, tx_buf: []u8, max_packet: int) -> Error {
	c^ = {
		sock = sock,
		tx   = tx_buf,
	}
	if wire.splitter_init(&c.rx, rx_buf, max_packet) != .None {
		return .Buffer_Too_Small
	}
	return .None
}

// Forget buffered data and start on a new socket (a reconnect).
tcp_conn_reset :: proc(c: ^TCP_Conn, sock: Socket) {
	c.sock = sock
	c.tx_head, c.tx_tail = 0, 0
	wire.splitter_reset(&c.rx)
}

// Read what the socket has, once, into the splitter. `scratch` is staging
// space, shareable by many connections. Returns the bytes taken.
//
//   .Would_Block  nothing to read now
//   .Closed       peer closed the stream
//   .Buffer_Full  splitter holds whole packets: call `tcp_next` first
//   .Bad_Frame    stream broke the framing rules
//   other         socket error
tcp_recv :: proc(c: ^TCP_Conn, scratch: []u8) -> (n: int, err: Error) {
	if c.rx.failed != .None {
		return 0, .Bad_Frame
	}
	free := len(c.rx.buf) - wire.splitter_pending(&c.rx)
	room := min(free, len(scratch))
	if room <= 0 {
		return 0, .Buffer_Full
	}
	got := stream_recv(c.sock, scratch[:room]) or_return
	taken := wire.splitter_feed(&c.rx, scratch[:got])
	// `room` never exceeds the free space, so everything fits.
	assert(taken == got, "splitter took less than the free space")
	return got, .None
}

// The next whole packet, if any; `ok` false: need more bytes. Valid until the
// next `tcp_recv`. `.Bad_Frame`: stream corrupt, close it.
tcp_next :: proc(c: ^TCP_Conn) -> (pkt: []u8, ok: bool, err: Error) {
	p, werr := wire.splitter_next(&c.rx)
	#partial switch werr {
	case .None:
		return p, true, .None
	case .Need_More:
		return nil, false, .None
	}
	// Zero or oversize length: the stream cannot be resynchronised.
	return nil, false, .Bad_Frame
}

// Add one packet to the send queue as a frame (2-byte length, then packet).
// Nothing is written yet.
//   .Buffer_Full  no room: flush first, or drop the packet
//   .Invalid      empty or oversize packet
tcp_queue :: proc(c: ^TCP_Conn, pkt: []u8) -> Error {
	need := wire.FRAME_PREFIX_LEN + len(pkt)
	if len(pkt) == 0 || len(pkt) > wire.MAX_FRAME_LEN {
		return .Invalid
	}
	if len(c.tx) - c.tx_tail < need {
		// Move the queued bytes to the front to free room.
		if c.tx_head > 0 {
			copy(c.tx, c.tx[c.tx_head:c.tx_tail])
			c.tx_tail -= c.tx_head
			c.tx_head = 0
		}
		if len(c.tx) - c.tx_tail < need {
			return .Buffer_Full
		}
	}
	n, werr := wire.frame_encode(c.tx[c.tx_tail:], pkt)
	if werr != .None {
		return .Invalid
	}
	c.tx_tail += n
	return .None
}

// Write queued frames to the socket. Returns the bytes still queued; if not 0,
// wait for `.Write` and call again. Errors are socket errors
// (`.Connection_Reset`, `.Closed` for a broken pipe, ...).
tcp_flush :: proc(c: ^TCP_Conn) -> (pending: int, err: Error) {
	for c.tx_head < c.tx_tail {
		n, serr := stream_send(c.sock, c.tx[c.tx_head:c.tx_tail])
		if serr == .Would_Block {
			break
		}
		if serr != .None {
			return c.tx_tail - c.tx_head, serr
		}
		c.tx_head += n
	}
	if c.tx_head == c.tx_tail {
		c.tx_head, c.tx_tail = 0, 0
	}
	return c.tx_tail - c.tx_head, .None
}

// Queue one packet and try to write it now. Same results as `tcp_flush`.
tcp_send_packet :: proc(c: ^TCP_Conn, pkt: []u8) -> (pending: int, err: Error) {
	tcp_queue(c, pkt) or_return
	return tcp_flush(c)
}

// Bytes waiting to be written.
tcp_pending :: proc(c: ^TCP_Conn) -> int {
	return c.tx_tail - c.tx_head
}
