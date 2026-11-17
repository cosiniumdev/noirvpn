// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/tlslink"
import "noir:proto/session"

// Server side of the WebSocket layer (ws.odin). It serves a `tls-server` listener
// (after the outer handshake) and a `tcp-server` listener (a reverse proxy that
// ended the outer TLS forwards plain HTTP here).
//
// The first plaintext bytes tell the stream kind: `GET ` is an HTTP request,
// anything else is OpenVPN TCP framing (`classify_plain`). A request gets a
// `101` and the stream then runs in frames, or a refusal and the connection
// closes. A listener without `tls-transport-ws` refuses every HTTP request.
//
//	tls listener:  TCP accept -> outer handshake -> srv_stream_input (first bytes) -> ...
//	tcp listener:  TCP accept -> srv_classify (peek) -> srv_http_start -> srv_http_read -> ...

// What the plaintext stream of a conn is (`Conn.ws_phase`).
Ws_Phase :: enum u8 {
	None, // the OpenVPN framing, no WebSocket layer
	Classify, // a tls conn: the first plaintext bytes are not seen yet
	Request, // an HTTP request is coming in
	On, // the stream runs in frames
}

// The memory of a conn that has a WebSocket layer, or a request in progress.
Ws_Conn :: struct {
	// The request bytes read so far. In `.Classify` the 1 to 3 bytes that are a prefix of "GET ".
	req:   []u8,
	req_n: int,
	r:     Ws_Rx,
	o:     Ws_Out,
}

// The transport word for the logs, the status and the bus: `ws` for a conn with
// a WebSocket, else `udp`, `tcp` or `tls`.
conn_proto :: proc(c: ^Conn) -> string {
	if c.ws_phase == .On {
		return "ws"
	}
	return proto_name(c.proto, c.tls)
}

@(private = "file")
listener_kind :: proc(c: ^Conn) -> string {
	return "tls" if c.tls else "tcp"
}

srv_ws_alloc :: proc(c: ^Conn) -> bool {
	if c.ws != nil {
		return true
	}
	w := new(Ws_Conn)
	if w == nil {
		return false
	}
	w.req = make([]u8, WS_HEADER_MAX)
	if w.req == nil || !ws_out_init(&w.o, false) {
		delete(w.req)
		free(w)
		return false
	}
	w.r.want_mask = true
	c.ws = w
	return true
}

srv_ws_free :: proc(c: ^Conn) {
	if c.ws == nil {
		return
	}
	delete(c.ws.req)
	ws_out_destroy(&c.ws.o)
	free(c.ws)
	c.ws = nil
}

// Bytes of the conn's WebSocket layer that wait for the socket.
srv_ws_pending :: proc(c: ^Conn) -> int {
	if c.ws == nil {
		return 0
	}
	return ws_out_pending(&c.ws.o)
}

// Stages the next frame from the send queue of `c` (or a waiting control frame
// or reply). `staged` is false when nothing waits; `ok` is false when no mask
// key could be generated (never on the server: it does not mask).
srv_ws_stage :: proc(c: ^Conn) -> (staged: bool, ok: bool) {
	o := &c.ws.o
	used, fine := ws_out_next(o, txq_front(&c.q))
	if used > 0 {
		txq_consume(&c.q, used)
	}
	return ws_out_pending(o) > 0, fine
}

// `tcp_flush_conn` for a conn on a plain socket with a WebSocket: the frames go
// to the socket. False if the connection broke (the conn is then released).
srv_ws_send :: proc(d: ^Srv, c: ^Conn) -> bool {
	o := &c.ws.o
	for {
		staged, ok := srv_ws_stage(c)
		if !ok || !staged {
			return true
		}
		n, err := net.stream_send(c.sock, o.buf[o.head:o.tail])
		if err == .Would_Block {
			return true
		}
		if err != .None {
			d.stats.sock_send_errors += 1
			if c.end == .None {
				c.end = .Tcp_Lost
			}
			conn_drop(d, c)
			return false
		}
		o.head += n
	}
}

// A last try to write the frames, with nothing else done (the conn is ending).
srv_ws_write_now :: proc(c: ^Conn) {
	o := &c.ws.o
	for {
		staged, ok := srv_ws_stage(c)
		if !ok || !staged {
			return
		}
		n, err := net.stream_send(c.sock, o.buf[o.head:o.tail])
		if err != .None {
			return
		}
		o.head += n
	}
}

// Queues a control frame for the peer, and ensures it is written at the end of the round.
@(private = "file")
srv_ws_ctl :: proc(d: ^Srv, c: ^Conn, opcode: u8, payload: []u8) {
	ws_out_ctl(&c.ws.o, opcode, payload)
	if !c.dirty {
		c.dirty = true
		append(&d.dirty, c.slot)
	}
}

// Writes `text` to the peer once, without a queue (an HTTP reply: small, at the
// start of the connection). Best effort.
@(private = "file")
srv_ws_write_text :: proc(c: ^Conn, text: string) {
	data := transmute([]u8)text
	if c.link != nil {
		if tlslink.link_write(c.link, data) == .None {
			tlslink.link_flush(c.link)
		}
		return
	}
	net.stream_send(c.sock, data)
}

// Cuts a path from a request for the log: no control characters, at most 64 bytes.
@(private = "file")
log_text :: proc(s: string) -> string {
	n := min(len(s), 64)
	b := make([]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		c := s[i]
		b[i] = c if c >= 0x20 && c < 0x7f else '?'
	}
	if len(s) > n {
		return fmt.tprintf("%s...", string(b))
	}
	return string(b)
}

// Plaintext bytes `data` of `c` came in, and the conn has a WebSocket phase (not
// `.None`). Classifies the first bytes, reads the request, or takes frames
// apart. False when the conn is gone (the caller returns at once).
srv_stream_input :: proc(d: ^Srv, c: ^Conn, data: []u8) -> bool {
	switch c.ws_phase {
	case .None:
		srv_feed_session(d, c, data)
		return true
	case .Classify:
		known := 0 if c.ws == nil else c.ws.req_n
		// The bytes of an earlier short read, then these.
		joined: [4]u8
		if known > 0 {
			copy(joined[:], c.ws.req[:known])
		}
		take := min(len(data), 4 - known)
		copy(joined[known:], data[:take])
		switch classify_plain(joined[:known + take]) {
		case .Need_More:
			if !srv_ws_alloc(c) {
				logf(.Error, "out of memory")
				conn_abort(d, c)
				return false
			}
			copy(c.ws.req[known:], data[:take])
			c.ws.req_n = known + take
			return true
		case .Raw:
			c.ws_phase = .None
			if known > 0 {
				stash: [3]u8
				copy(stash[:], c.ws.req[:known])
				c.ws.req_n = 0
				// A TCP session copies what it reads into its splitter.
				srv_feed_session(d, c, ([^]u8)(rawptr(&stash))[:known])
				st := session.session_state(&c.s)
				if st == .Failed || st == .Closed {
					return true
				}
			}
			srv_ws_free(c)
			srv_feed_session(d, c, data)
			return true
		case .Http:
			if !srv_ws_alloc(c) {
				logf(.Error, "out of memory")
				conn_abort(d, c)
				return false
			}
			c.ws_phase = .Request
			// The stashed bytes are the start of "GET ".
			c.ws.req_n = known
			conn_arm_timer(d, c)
			return srv_ws_request(d, c, data)
		}
	case .Request:
		return srv_ws_request(d, c, data)
	case .On:
		return srv_ws_input(d, c, data)
	}
	return true
}

// A connection on a tcp listener sent `GET `: the request is read from the
// socket before any session exists.
srv_http_start :: proc(d: ^Srv, c: ^Conn) {
	c.classify = false
	if !srv_ws_alloc(c) {
		logf(.Error, "out of memory")
		conn_abort(d, c)
		return
	}
	c.ws_phase = .Request
	conn_arm_timer(d, c)
	srv_http_read(d, c)
}

// The socket of a conn in `.Request` with no session is readable: read it until it has nothing more
// (the watch is edge triggered).
srv_http_read :: proc(d: ^Srv, c: ^Conn) {
	slot := c.slot
	buf := d.rx_buf[:4096]
	for {
		n, err := net.stream_recv(c.sock, buf)
		#partial switch err {
		case .None:
		case .Would_Block, .Interrupted:
			return
		case .Closed:
			logf(.Debug, "connection from %s closed before its request was complete", conn_label(c))
			conn_drop(d, c)
			return
		case:
			d.stats.sock_recv_errors += 1
			logf(.Debug, "connection from %s failed before its request was complete: %v", conn_label(c), err)
			conn_drop(d, c)
			return
		}
		if !srv_ws_request(d, c, buf[:n]) {
			return
		}
		if d.conns[slot] != c || c.ws_phase != .Request {
			// Accepted: the session runs and the socket is level triggered now.
			return
		}
	}
}

// Adds request bytes and acts when the header is complete. False when the conn is gone.
@(private = "file")
srv_ws_request :: proc(d: ^Srv, c: ^Conn, data: []u8) -> bool {
	w := c.ws
	take := min(len(data), len(w.req) - w.req_n)
	copy(w.req[w.req_n:], data[:take])
	w.req_n += take
	end, st := http_head_end(w.req[:w.req_n])
	switch st {
	case .Need_More:
		return true
	case .Too_Long:
		d.stats.outer_failed += 1
		logf(.Info, "websocket request from %s refused: the header is longer than %d bytes", conn_label(c), WS_HEADER_MAX)
		srv_ws_write_text(c, WS_REPLY_400)
		conn_drop(d, c)
		return false
	case .Done:
	}
	path := d.cfg.tls.transport_ws
	if path == "" {
		d.stats.outer_failed += 1
		logf(.Info, "HTTP request from %s on a %s listener refused (set tls-transport-ws to accept WebSocket clients there)", conn_label(c), listener_kind(c))
		srv_ws_write_text(c, WS_REPLY_404)
		conn_drop(d, c)
		return false
	}
	req := ws_request_check(w.req[:end], path)
	if req.verdict != .Accept {
		d.stats.outer_failed += 1
		reason := "wrong path"
		switch req.verdict {
		case .Not_Upgrade:
			reason = "not a websocket upgrade"
		case .Bad_Version:
			reason = fmt.tprintf("version %s", log_text(req.version))
		case .Bad_Path, .Accept:
		}
		logf(.Info, "websocket request from %s for %s refused: %s", conn_label(c), log_text(req.target), reason)
		srv_ws_write_text(c, ws_refusal(req.verdict))
		conn_drop(d, c)
		return false
	}
	// Accepted. The 101 waits in the staging buffer; frames follow it.
	reply := ws_reply_build(req.key, context.temp_allocator)
	copy(w.o.buf, reply)
	w.o.head, w.o.tail = 0, len(reply)
	w.r = {
		want_mask = true,
	}
	c.ws_phase = .On
	slot := c.slot
	if !c.s_ok {
		// A tcp listener: the session starts now.
		event.remove_fd(&d.loop, c.sock.fd)
		srv_tcp_start(d, c, d.listeners[c.lidx].sh)
		if d.conns[slot] != c {
			return false
		}
	} else {
		conn_arm_timer(d, c)
	}
	if !tcp_flush_conn(d, c) {
		return false
	}
	// Bytes behind the blank line are frames: the part of the header buffer past the end, then what was not copied.
	if more := w.req[end:w.req_n]; len(more) > 0 {
		keep := make([]u8, len(more), context.temp_allocator)
		copy(keep, more)
		if !srv_ws_input(d, c, keep) {
			return false
		}
	}
	if take < len(data) {
		return srv_ws_input(d, c, data[take:])
	}
	return true
}

// Takes received frame bytes of `c` apart and gives the stream bytes in them to
// the session. `data` is changed (unmasked). False when the conn is gone.
@(private = "file")
srv_ws_input :: proc(d: ^Srv, c: ^Conn, data: []u8) -> bool {
	w := c.ws
	rest := data
	for len(rest) > 0 {
		ev := ws_rx_next(&w.r, rest)
		rest = rest[ev.used:]
		switch ev.kind {
		case .More, .Pong:
		case .Data:
			srv_feed_session(d, c, ev.data)
			st := session.session_state(&c.s)
			if st == .Failed || st == .Closed {
				return true
			}
		case .Ping:
			srv_ws_ctl(d, c, WS_OP_PONG, ev.data)
		case .Close:
			// Reply with a close frame (status 1000); the drop writes it.
			pl := ws_close_payload()
			ws_out_ctl(&w.o, WS_OP_CLOSE, pl[:])
			if c.end == .None {
				c.end = .Tcp_Lost
			}
			conn_drop(d, c)
			return false
		case .Error:
			logf(.Info, "websocket frame from %s breaks the protocol: %s", conn_label(c), ev.text)
			d.stats.sock_recv_errors += 1
			if c.end == .None {
				c.end = .Tcp_Lost
			}
			conn_drop(d, c)
			return false
		}
	}
	return true
}
