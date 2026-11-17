// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import cnet "core:net"
import "noir:platform/tlslink"
import "noir:proto/ossl"

// Client side of the WebSocket layer (ws.odin), for an attempt on a `tls` remote
// with `tls-transport-ws`:
//
//	connect -> [HTTP proxy] -> outer TLS -> upgrade request -> 101 -> the session
//
// Request and reply are plain HTTP inside the outer TLS stream. After the 101
// the OpenVPN stream travels in binary frames, cut and joined here: `ws_feed`
// takes stream bytes out of received frames, `tls_stream_flush`
// (tls_transport.odin) frames the queue.

// The state of the WebSocket layer of the attempt.
Ws_Client :: struct {
	// The `Sec-WebSocket-Key` of the request.
	key:  [24]u8,
	// The request, and how much of it is written.
	req:  []u8,
	sent: int,
	// The reply bytes read so far. The bytes after the blank line are frames.
	rx:   []u8,
	rx_n: int,
	// The upgrade is done: the stream runs in frames.
	on:   bool,
	r:    Ws_Rx,
	out:  Ws_Out,
	// `out` has its buffer.
	ok:   bool,
}

// A new attempt: forget the exchange of the last one.
ws_attempt_reset :: proc(d: ^Daemon) {
	w := &d.wsc
	delete(w.req)
	w.req = nil
	w.sent, w.rx_n = 0, 0
	w.on = false
	w.r = {}
	if w.ok {
		ws_out_reset(&w.out)
	}
}

// The memory of the layer goes (the daemon ends).
ws_client_destroy :: proc(d: ^Daemon) {
	w := &d.wsc
	delete(w.req)
	delete(w.rx)
	if w.ok {
		ws_out_destroy(&w.out)
	}
	w^ = {}
}

@(private = "file")
ws_remote_text :: proc(d: ^Daemon) -> string {
	return fmt.tprintf("[%s]:%d", cnet.address_to_string(d.endpoint.address, context.temp_allocator), d.endpoint.port)
}

// The outer TLS handshake is done: ask for the upgrade.
ws_begin :: proc(d: ^Daemon) {
	w := &d.wsc
	conn := &d.cfg.connections[d.conn_idx]
	if w.rx == nil {
		w.rx = make([]u8, WS_HEADER_MAX)
	}
	if !w.ok {
		if !ws_out_init(&w.out, true) {
			logf(.Error, "out of memory")
			fail_connection(d, .Connect_Failed, {})
			return
		}
		w.ok = true
	}
	key, kok := ws_new_key(ossl.random_bytes)
	if !kok {
		logf(.Error, "cannot generate a random WebSocket key")
		fail_connection(d, .Connect_Failed, {})
		return
	}
	w.key = key
	// The name the server knows: the SNI name if the config gives one, else the remote as written.
	host := d.cfg.tls_transport_sni if d.cfg.tls_transport_sni != "" else conn.host
	hv := ws_host_header(host, conn.rport, context.temp_allocator)
	req, ok := ws_request_build(d.cfg.tls.transport_ws, hv, w.key[:], hello = d.cfg.tls_transport_hello)
	if !ok {
		logf(.Error, "cannot request a WebSocket because the path or the host name contains a space or a control character")
		fail_connection(d, .Connect_Failed, {})
		return
	}
	w.req, w.sent, w.rx_n = req, 0, 0
	d.state = .Ws_Upgrading
	client_note_state(d)
	logf(.Debug, "asking %s for a WebSocket upgrade at %s", ws_remote_text(d), d.cfg.tls.transport_ws)
	ws_send(d)
	if d.state == .Ws_Upgrading && tlslink.link_has_input(&d.olink) {
		ws_read(d)
	}
}

// Writes the request into the outer TLS stream, and the TLS bytes to the socket.
ws_send :: proc(d: ^Daemon) {
	w := &d.wsc
	l := &d.olink
	if w.sent < len(w.req) {
		if tlslink.link_write(l, w.req) != .None {
			d.stats.sock_send_errors += 1
			logf(.Warn, "cannot send the WebSocket request: %s", tlslink.link_error_text(l))
			fail_connection(d, .Connect_Failed, {})
			return
		}
		w.sent = len(w.req)
	}
	left, err := tlslink.link_flush(l)
	if err != .None {
		d.stats.sock_send_errors += 1
		logf(.Warn, "cannot send the WebSocket request: %s", tlslink.link_error_text(l))
		fail_connection(d, .Connect_Failed, {})
		return
	}
	set_blocked(d, left > 0)
}

// The socket is readable (or hung up) while the upgrade waits for its reply.
ws_read :: proc(d: ^Daemon) {
	w := &d.wsc
	l := &d.olink
	for {
		n, err := tlslink.link_read(l, w.rx[w.rx_n:])
		if err == .Would_Block {
			return
		}
		if err != .None {
			if err == .Closed {
				logf(.Warn, "%s closed the connection before it finished replying to the WebSocket request", ws_remote_text(d))
			} else {
				logf(.Warn, "the connection to %s failed before it finished replying to the WebSocket request: %s", ws_remote_text(d), tlslink.link_error_text(l))
			}
			fail_connection(d, .Connect_Failed, {})
			return
		}
		w.rx_n += n
		end, st := http_head_end(w.rx[:w.rx_n])
		switch st {
		case .Need_More:
			continue
		case .Too_Long:
			logf(.Error, "the websocket upgrade reply from %s is not HTTP because the header is longer than %d bytes", ws_remote_text(d), WS_HEADER_MAX)
			fail_connection(d, .Connect_Failed, {})
		case .Done:
			ws_reply(d, end)
		}
		return
	}
}

// The header of the reply is complete: go on, or fail the attempt.
@(private = "file")
ws_reply :: proc(d: ^Daemon, end: int) {
	w := &d.wsc
	res, line := ws_reply_check(w.rx[:end], w.key[:])
	addr := ws_remote_text(d)
	switch res {
	case .Ok:
	case .Refused:
		logf(.Error, "websocket upgrade refused by %s: %s", addr, line)
		fail_connection(d, .Connect_Failed, {})
		return
	case .Not_Http:
		logf(.Error, "the websocket upgrade reply from %s is not HTTP", addr)
		fail_connection(d, .Connect_Failed, {})
		return
	case .Not_Upgrade:
		logf(.Error, "the websocket upgrade reply from %s does not accept the upgrade", addr)
		fail_connection(d, .Connect_Failed, {})
		return
	case .Bad_Accept:
		logf(.Error, "the websocket upgrade reply from %s has the wrong Sec-WebSocket-Accept", addr)
		fail_connection(d, .Connect_Failed, {})
		return
	}
	logf(.Debug, "websocket upgrade accepted by %s", addr)
	w.on = true
	w.r = {}
	// What follows the reply is the first frames: the session takes them.
	ahead := w.rx[end:w.rx_n]
	w.rx_n = 0
	begin_session(d, ahead)
	if d.state == .Active && d.s_ok && tlslink.link_has_input(&d.olink) {
		read_tls(d)
		pump(d)
	}
}

// Takes received stream bytes of the outer TLS (`data`: frames) apart and gives
// the stream bytes in them to the session. `data` is changed (unmasked).
ws_feed :: proc(d: ^Daemon, data: []u8) {
	w := &d.wsc
	rest := data
	for len(rest) > 0 {
		ev := ws_rx_next(&w.r, rest)
		rest = rest[ev.used:]
		switch ev.kind {
		case .More, .Pong:
		case .Data:
			feed(d, ev.data)
			if !feed_ok(d) || d.end.pending {
				return
			}
		case .Ping:
			if !ws_out_ctl(&w.out, WS_OP_PONG, ev.data) {
				logf(.Error, "cannot generate a random mask key")
				fail_connection(d, .Ping_Restart if d.up else .Connect_Failed, {})
				return
			}
		case .Close:
			// Reply with a close frame (status 1000) if the socket takes it, then end.
			pl := ws_close_payload()
			if ws_out_ctl(&w.out, WS_OP_CLOSE, pl[:]) {
				stream_flush(d)
			}
			if d.close_reason != .None {
				fail_connection(d, close_outcome(d.close_reason), {})
				return
			}
			d.stats.sock_recv_errors += 1
			logf(.Warn, "the server closed the WebSocket")
			fail_connection(d, .Ping_Restart if d.up else .Connect_Failed, {})
			return
		case .Error:
			logf(.Error, "a websocket frame from %s does not follow the protocol: %s", ws_remote_text(d), ev.text)
			d.stats.sock_recv_errors += 1
			fail_connection(d, .Ping_Restart if d.up else .Connect_Failed, {})
			return
		}
	}
}

// ` ws=PATH` for the status line while an attempt with a WebSocket exists, else "".
ws_status :: proc(d: ^Daemon) -> string {
	if path, ok := ws_path(d); ok {
		return fmt.tprintf(" ws=%s", path)
	}
	return ""
}

// The path of the WebSocket of the connection in use.
ws_path :: proc(d: ^Daemon) -> (path: string, ok: bool) {
	if !d.ws || (d.state == .Idle && !d.s_ok) {
		return "", false
	}
	return d.cfg.tls.transport_ws, true
}
