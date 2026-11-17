// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import "core:testing"
import "core:time"
import "noir:platform/event"
import "noir:proto/wire"

// TCP over loopback: connect, framing with partial reads, partial writes,
// bad frames, and close.

// Connect a client to a fresh listener. Returns both ends. The client's
// connect is driven through the event loop, as real code does it.
@(private = "file")
Pair :: struct {
	listener: Socket,
	client:   Socket,
	server:   Socket,
	port:     int,
}

@(private = "file")
Connect_State :: struct {
	done: bool,
	err:  Error,
}

@(private = "file")
connect_pair :: proc(t: ^testing.T, client_opts: TCP_Options = {}) -> (p: Pair, ok: bool) {
	l, lerr := tcp_listen(LO4)
	testing.expect_value(t, lerr, Error.None)
	if lerr != .None {
		return {}, false
	}
	lep, _ := local_endpoint(l)
	p.listener = l
	p.port = lep.port

	c, in_progress, cerr := tcp_connect(lep, client_opts)
	testing.expect_value(t, cerr, Error.None)
	if cerr != .None {
		close(l)
		return {}, false
	}
	p.client = c

	if in_progress {
		loop: event.Loop
		testing.expect_value(t, event.init(&loop), event.Error.None)
		defer event.destroy(&loop)
		state: Connect_State
		handler :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
			st := (^Connect_State)(user)
			st.err = tcp_connect_finish(Socket{fd = fd})
			if st.err != .Would_Block {
				st.done = true
			}
		}
		testing.expect_value(t, event.add_fd(&loop, c.fd, {.Write}, handler, &state), event.Error.None)
		deadline := event.now() + 2 * time.Second
		for !state.done && event.now() < deadline {
			event.wait(&loop, deadline)
		}
		testing.expect(t, state.done, "connect did not finish")
		testing.expect_value(t, state.err, Error.None)
		if state.err != .None {
			close(l)
			close(c)
			return {}, false
		}
	}

	// Accept (the connection is complete, but be patient anyway).
	for _ in 0 ..< 200 {
		s, _, aerr := tcp_accept(l)
		if aerr == .None {
			p.server = s
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect(t, is_valid(p.server), "no connection accepted")
	if !is_valid(p.server) {
		close(l)
		close(c)
		return {}, false
	}
	return p, true
}

// Closes what is still open. Set a field to INVALID_SOCKET after closing it
// yourself: a second close could hit a descriptor another test thread now owns.
@(private = "file")
pair_close :: proc(p: ^Pair) {
	close(p.listener)
	close(p.client)
	close(p.server)
}

@(private = "file")
raw_send_all :: proc(s: Socket, data: []u8) {
	rest := data
	for len(rest) > 0 {
		n, err := stream_send(s, rest)
		if err == .Would_Block {
			time.sleep(time.Millisecond)
			continue
		}
		if err != .None {
			return
		}
		rest = rest[n:]
	}
}

// Build a framed byte stream of `count` packets. Packet i has `lens[i]` bytes
// and every byte is `i`.
@(private = "file")
framed_stream :: proc(lens: []int, allocator := context.allocator) -> []u8 {
	total := 0
	for l in lens {
		total += 2 + l
	}
	out := make([]u8, total, allocator)
	off := 0
	for l, i in lens {
		out[off] = u8(l >> 8)
		out[off + 1] = u8(l)
		for j in 0 ..< l {
			out[off + 2 + j] = u8(i)
		}
		off += 2 + l
	}
	return out
}

// ---- tests ----

@(test)
tcp_connect_accept_and_exchange :: proc(t: ^testing.T) {
	p, ok := connect_pair(t)
	if !ok {
		return
	}
	defer pair_close(&p)

	peer, perr := peer_endpoint(p.client)
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, peer.port, p.port)

	msg := "ping"
	n, err := stream_send(p.client, transmute([]u8)msg)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 4)
	buf: [16]u8
	got: int
	for _ in 0 ..< 200 {
		got, err = stream_recv(p.server, buf[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, string(buf[:got]), "ping")

	// A clean close from the server side reads as .Closed.
	close(p.server)
	p.server = INVALID_SOCKET
	for _ in 0 ..< 200 {
		_, err = stream_recv(p.client, buf[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.Closed)
}

@(test)
stream_peek_keeps_bytes :: proc(t: ^testing.T) {
	p, ok := connect_pair(t)
	if !ok {
		return
	}
	defer pair_close(&p)

	buf: [16]u8
	// Nothing sent yet.
	_, err := stream_peek(p.server, buf[:])
	testing.expect_value(t, err, Error.Would_Block)

	msg := "hello"
	_, err = stream_send(p.client, transmute([]u8)msg)
	testing.expect_value(t, err, Error.None)
	got: int
	for _ in 0 ..< 200 {
		got, err = stream_peek(p.server, buf[:3])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, string(buf[:got]), "hel")
	// A second peek sees the same bytes, and a read gets all of them.
	got, err = stream_peek(p.server, buf[:3])
	testing.expect_value(t, string(buf[:got]), "hel")
	got, err = stream_recv(p.server, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, string(buf[:got]), "hello")

	// A close with no bytes left reads as .Closed.
	close(p.client)
	p.client = INVALID_SOCKET
	for _ in 0 ..< 200 {
		_, err = stream_peek(p.server, buf[:3])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.Closed)
}

@(test)
tcp_connect_refused :: proc(t: ^testing.T) {
	// Find a port nobody listens on: bind, note the port, close.
	l, lerr := tcp_listen(LO4)
	testing.expect_value(t, lerr, Error.None)
	lep, _ := local_endpoint(l)
	close(l)

	c, in_progress, err := tcp_connect(lep)
	if err == .Connection_Refused {
		return // refused at once: fine
	}
	testing.expect_value(t, err, Error.None)
	if err != .None {
		return
	}
	defer close(c)
	testing.expect(t, in_progress)

	loop: event.Loop
	testing.expect_value(t, event.init(&loop), event.Error.None)
	defer event.destroy(&loop)
	Seen :: struct {
		done: bool,
		err:  Error,
	}
	seen: Seen
	handler :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
		s := (^Seen)(user)
		s.err = tcp_connect_finish(Socket{fd = fd})
		s.done = s.err != .Would_Block
	}
	event.add_fd(&loop, c.fd, {.Write}, handler, &seen)
	// Windows sends the SYN again twice after a reset before it reports the
	// refusal (about 2 s).
	wait_for := 5 * time.Second when ODIN_OS == .Windows else 2 * time.Second
	deadline := event.now() + wait_for
	for !seen.done && event.now() < deadline {
		event.wait(&loop, deadline)
	}
	testing.expect_value(t, seen.err, Error.Connection_Refused)
}

@(test)
tcp_framing_with_partial_reads :: proc(t: ^testing.T) {
	p, ok := connect_pair(t)
	if !ok {
		return
	}
	defer pair_close(&p)

	lens := [?]int{1, 2, 3, 100, 1500, 7, 2048, 1}
	stream := framed_stream(lens[:])
	defer delete(stream)

	rx_buf: [2 + 2048]u8
	c: TCP_Conn
	testing.expect_value(t, tcp_conn_init(&c, p.client, rx_buf[:], nil, 2048), Error.None)
	scratch: [4096]u8

	// The server writes the stream in odd-sized pieces: 1 byte, 3 bytes, ...
	// so frame boundaries fall inside reads and reads fall inside frames.
	pieces := [?]int{1, 3, 5, 1, 2, 7, 64, 1, 1, 1000, 4, 999}
	next_piece := 0
	sent := 0

	packets := 0
	partial_reads := 0 // reads that ended inside a frame
	deadline := time.tick_now()
	for packets < len(lens) && time.tick_since(deadline) < 5 * time.Second {
		// Send the next piece, then drain what the client can read.
		if sent < len(stream) {
			n := min(pieces[next_piece % len(pieces)], len(stream) - sent)
			next_piece += 1
			raw_send_all(p.server, stream[sent:][:n])
			sent += n
		}
		for {
			_, rerr := tcp_recv(&c, scratch[:])
			if rerr == .Would_Block {
				break
			}
			testing.expect_value(t, rerr, Error.None)
			if rerr != .None {
				return
			}
			for {
				pkt, have, nerr := tcp_next(&c)
				testing.expect_value(t, nerr, Error.None)
				if !have {
					break
				}
				testing.expect_value(t, len(pkt), lens[packets])
				for b in pkt {
					testing.expect_value(t, b, u8(packets))
				}
				packets += 1
			}
			if wire.splitter_pending(&c.rx) > 0 {
				partial_reads += 1
			}
		}
		if sent >= len(stream) {
			time.sleep(time.Millisecond)
		}
	}
	testing.expect_value(t, packets, len(lens))
	testing.expect(t, partial_reads > 0, "no read ended inside a frame: the test did not exercise partial reads")
}

@(test)
tcp_bad_frames_are_reported :: proc(t: ^testing.T) {
	p, ok := connect_pair(t)
	if !ok {
		return
	}
	defer pair_close(&p)

	rx_buf: [2 + 100]u8
	c: TCP_Conn
	testing.expect_value(t, tcp_conn_init(&c, p.client, rx_buf[:], nil, 100), Error.None)
	scratch: [256]u8

	// A good frame, then a frame longer than the 100 the connection allows.
	data := [?]u8{0, 2, 0xaa, 0xbb, 0, 101}
	raw_send_all(p.server, data[:])

	got := 0
	for got < len(data) {
		n, err := tcp_recv(&c, scratch[:])
		if err == .Would_Block {
			time.sleep(time.Millisecond)
			continue
		}
		testing.expect_value(t, err, Error.None)
		if err != .None {
			return
		}
		got += n
	}
	pkt, have, nerr := tcp_next(&c)
	testing.expect_value(t, nerr, Error.None)
	testing.expect(t, have)
	testing.expect_value(t, len(pkt), 2)
	_, have, nerr = tcp_next(&c)
	testing.expect(t, !have)
	testing.expect_value(t, nerr, Error.Bad_Frame)
	// The failure sticks.
	_, rerr := tcp_recv(&c, scratch[:])
	testing.expect_value(t, rerr, Error.Bad_Frame)

	// A zero length is bad as well.
	tcp_conn_reset(&c, p.client)
	zero := [?]u8{0, 0}
	raw_send_all(p.server, zero[:])
	for {
		_, err := tcp_recv(&c, scratch[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	_, have, nerr = tcp_next(&c)
	testing.expect(t, !have)
	testing.expect_value(t, nerr, Error.Bad_Frame)
}

@(test)
tcp_recv_reports_full_buffer :: proc(t: ^testing.T) {
	p, ok := connect_pair(t)
	if !ok {
		return
	}
	defer pair_close(&p)

	// Room for exactly 12 bytes: three frames of 2 bytes.
	rx_buf: [12]u8
	c: TCP_Conn
	testing.expect_value(t, tcp_conn_init(&c, p.client, rx_buf[:], nil, 10), Error.None)
	frames := [?]u8{0, 2, 1, 1, 0, 2, 2, 2, 0, 2, 3, 3, 0, 2, 4, 4}
	raw_send_all(p.server, frames[:])

	scratch: [64]u8
	total := 0
	for total < 12 {
		n, err := tcp_recv(&c, scratch[:])
		if err == .Would_Block {
			time.sleep(time.Millisecond)
			continue
		}
		testing.expect_value(t, err, Error.None)
		total += n
	}
	_, err := tcp_recv(&c, scratch[:])
	testing.expect_value(t, err, Error.Buffer_Full)

	// Take one packet: there is room again, and the 4th frame arrives.
	pkt, have, _ := tcp_next(&c)
	testing.expect(t, have)
	testing.expect_value(t, pkt[0], 1)
	n: int
	for {
		n, err = tcp_recv(&c, scratch[:])
		if err != .Would_Block {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 4)
	for want in ([?]u8{2, 3, 4}) {
		pkt, have, _ = tcp_next(&c)
		testing.expect(t, have)
		testing.expect_value(t, pkt[0], want)
	}
}

@(test)
tcp_queue_and_flush_with_partial_writes :: proc(t: ^testing.T) {
	// A small send buffer causes the kernel to accept only part of the queue at a
	// time. The receiver reads slowly, so the sender must resume its flush.
	// Windows takes the whole queue on loopback whatever the buffer size: nothing
	// to test there.
	when ODIN_OS == .Windows {
		return
	}
	p, ok := connect_pair(t, {send_buffer = 4096})
	if !ok {
		return
	}
	defer pair_close(&p)

	N :: 300
	PKT :: 1000
	tx_buf := make([]u8, N * (PKT + 2))
	defer delete(tx_buf)
	tx: TCP_Conn
	testing.expect_value(t, tcp_conn_init(&tx, p.client, make([]u8, 2 + 2048), tx_buf, 2048), Error.None)
	defer delete(tx.rx.buf)

	pkt: [PKT]u8
	for i in 0 ..< N {
		for j in 0 ..< PKT {
			pkt[j] = u8(i)
		}
		testing.expect_value(t, tcp_queue(&tx, pkt[:]), Error.None)
	}
	testing.expect_value(t, tcp_pending(&tx), N * (PKT + 2))

	// One more does not fit.
	testing.expect_value(t, tcp_queue(&tx, pkt[:]), Error.Buffer_Full)
	// Empty and oversize packets are refused.
	testing.expect_value(t, tcp_queue(&tx, nil), Error.Invalid)

	pending, ferr := tcp_flush(&tx)
	testing.expect_value(t, ferr, Error.None)
	testing.expect(t, pending > 0, "the whole queue went out at once: no partial write happened")
	testing.expect(t, pending < N * (PKT + 2), "nothing was written")

	// Receive everything on the server side, flushing as we go.
	rx_buf := make([]u8, 2 + 2048)
	defer delete(rx_buf)
	rx: TCP_Conn
	testing.expect_value(t, tcp_conn_init(&rx, p.server, rx_buf, nil, 2048), Error.None)
	scratch: [8192]u8
	got := 0
	flushes := 0
	start := time.tick_now()
	for got < N && time.tick_since(start) < 10 * time.Second {
		_, rerr := tcp_recv(&rx, scratch[:])
		if rerr == .Would_Block {
			if tcp_pending(&tx) > 0 {
				_, ferr = tcp_flush(&tx)
				testing.expect_value(t, ferr, Error.None)
				flushes += 1
			}
			time.sleep(time.Millisecond)
			continue
		}
		testing.expect_value(t, rerr, Error.None)
		if rerr != .None {
			break
		}
		for {
			pk, have, nerr := tcp_next(&rx)
			testing.expect_value(t, nerr, Error.None)
			if !have {
				break
			}
			testing.expect_value(t, len(pk), PKT)
			testing.expect_value(t, pk[0], u8(got))
			testing.expect_value(t, pk[PKT - 1], u8(got))
			got += 1
		}
	}
	testing.expect_value(t, got, N)
	testing.expect(t, flushes > 0, "no flush was needed after the first")
	testing.expect_value(t, tcp_pending(&tx), 0)
}

@(test)
tcp_send_packet_is_queue_plus_flush :: proc(t: ^testing.T) {
	p, ok := connect_pair(t)
	if !ok {
		return
	}
	defer pair_close(&p)

	tx_buf: [256]u8
	tx: TCP_Conn
	testing.expect_value(t, tcp_conn_init(&tx, p.client, make([]u8, 2 + 64), tx_buf[:], 64), Error.None)
	defer delete(tx.rx.buf)
	pkt := [?]u8{9, 8, 7}
	pending, err := tcp_send_packet(&tx, pkt[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, pending, 0)

	buf: [16]u8
	got := 0
	for got < 5 {
		n, rerr := stream_recv(p.server, buf[got:])
		if rerr == .Would_Block {
			time.sleep(time.Millisecond)
			continue
		}
		testing.expect_value(t, rerr, Error.None)
		if rerr != .None {
			return
		}
		got += n
	}
	testing.expect_value(t, buf[0], 0)
	testing.expect_value(t, buf[1], 3)
	testing.expect_value(t, buf[2], 9)
	testing.expect_value(t, buf[4], 7)
}

@(test)
tcp_conn_init_checks_buffer :: proc(t: ^testing.T) {
	c: TCP_Conn
	small: [10]u8
	testing.expect_value(t, tcp_conn_init(&c, INVALID_SOCKET, small[:], nil, 100), Error.Buffer_Too_Small)
	testing.expect_value(t, tcp_conn_init(&c, INVALID_SOCKET, small[:], nil, 0), Error.Buffer_Too_Small)
}

@(test)
write_after_peer_close_does_not_kill_us :: proc(t: ^testing.T) {
	// MSG_NOSIGNAL: a write to a closed peer is an error, not SIGPIPE.
	p, ok := connect_pair(t)
	if !ok {
		return
	}
	defer pair_close(&p)
	close(p.server)
	p.server = INVALID_SOCKET
	data: [64]u8
	err: Error
	for _ in 0 ..< 100 {
		_, err = stream_send(p.client, data[:])
		if err != .None {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect(t, err == .Closed || err == .Connection_Reset, "expected a broken connection")
}

// A failed setup must close the descriptor and return no socket, so the
// caller cannot close a number another thread now owns.
@(test)
failed_listen_returns_no_socket :: proc(t: ^testing.T) {
	l, lerr := tcp_listen(LO4)
	testing.expect_value(t, lerr, Error.None)
	if lerr != .None {
		return
	}
	defer close(l)
	lep, _ := local_endpoint(l)
	// The same port again: SO_REUSEADDR does not allow two listeners.
	s, err := tcp_listen(lep)
	testing.expect_value(t, err, Error.Address_In_Use)
	testing.expect(t, !is_valid(s), "no descriptor on failure")
	testing.expect_value(t, s.fd, INVALID_SOCKET.fd)

	// A connect that fails during setup (a local address we do not own).
	c, pending, cerr := tcp_connect(lep, {local = Endpoint{address = IP4_Address{203, 0, 113, 9}, port = 0}})
	testing.expect(t, cerr != .None)
	testing.expect(t, !pending)
	testing.expect(t, !is_valid(c), "no descriptor on failure")
}
