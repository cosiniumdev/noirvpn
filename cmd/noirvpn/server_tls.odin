// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/tlslink"
import "noir:proto/ossl"

// The server side of the `tls` transport (tls_transport.odin has the client
// side and what both use).

// A connection on a `tls-server` listener waits for its first bytes. Peek at
// them without taking them out of the socket, then go on as a TLS or a raw
// OpenVPN connection. The event loop stops watching the socket after this.
srv_classify :: proc(d: ^Srv, c: ^Conn, ready: event.Ready) {
	head: [4]u8
	n, err := net.stream_peek(c.sock, head[:])
	#partial switch err {
	case .None:
	case .Would_Block, .Interrupted:
		return
	case .Closed:
		logf(.Debug, "connection from %s closed before it sent anything", conn_label(c))
		conn_drop(d, c)
		return
	case:
		d.stats.sock_recv_errors += 1
		logf(.Debug, "connection from %s failed before it sent anything: %v", conn_label(c), err)
		conn_drop(d, c)
		return
	}
	if !d.listeners[c.lidx].tls {
		// A tcp listener: an HTTP request or the OpenVPN framing.
		switch classify_plain(head[:n]) {
		case .Need_More:
			if .Hangup in ready {
				logf(.Debug, "connection from %s closed before it sent its first bytes", conn_label(c))
				conn_drop(d, c)
			}
		case .Http:
			srv_http_start(d, c)
		case .Raw:
			srv_classified(d, c, false)
		}
		return
	}
	switch classify_first_bytes(head[:n]) {
	case .Need_More:
		if .Hangup in ready {
			logf(.Debug, "connection from %s closed before it sent its first bytes", conn_label(c))
			conn_drop(d, c)
		}
		// Else: the next bytes form a new edge, or the handshake window ends.
	case .Tls:
		srv_classified(d, c, true)
	case .Raw:
		if !d.cfg.tls.transport_accept_tcp {
			d.stats.outer_failed += 1
			logf(.Info, "raw OpenVPN connection from %s on a tls listener refused (set tls-transport-accept-tcp to accept tcp-client connections there)", conn_label(c))
			conn_drop(d, c)
			return
		}
		srv_classified(d, c, false)
	}
}

// The first bytes are seen: the connection goes on as a tls connection (outer
// handshake first) or a plain tcp connection. A raw connection keeps no TLS state.
srv_classified :: proc(d: ^Srv, c: ^Conn, tls: bool) {
	c.classify = false
	// The watch is set again by `srv_tcp_start`, level triggered. (The DCO
	// service may take the socket there, and a closed socket must not stay in the loop.)
	event.remove_fd(&d.loop, c.sock.fd)
	if tls {
		// A short kernel send queue for the outer TLS stream.
		net.tcp_set_notsent_lowat(c.sock)
		if !srv_tls_init(d, c) {
			conn_abort(d, c)
			return
		}
	}
	srv_tcp_start(d, c, d.listeners[c.lidx].sh)
}

// A tls connection was accepted: set up the outer TLS session and handshake
// state. The login starts after the handshake (`srv_tls_step`). False: out of
// memory (logged).
srv_tls_init :: proc(d: ^Srv, c: ^Conn) -> bool {
	c.link = new(tlslink.Link)
	c.link_out = make([]u8, tlslink.OUT_BUF_SIZE)
	if c.link == nil || c.link_out == nil {
		logf(.Error, "out of memory")
		return false
	}
	if err := tlslink.link_init(c.link, &d.tls_ctx, c.sock, c.link_out); err != .None {
		logf(.Error, "cannot set up the outer TLS for %s: %v", conn_label(c), err)
		return false
	}
	if n := test_outer_rekey_bytes(); n > 0 {
		c.link.rekey_after = n
	}
	c.tls = true
	c.tls_hs = true
	// The plaintext stream may be an HTTP request (`GET `) or the OpenVPN framing (`srv_stream_input`).
	c.ws_phase = .Classify
	return true
}

// Runs the outer handshake of `c` as far as the socket allows. A failure frees
// the slot with one log line (a client that does not speak TLS, such as a stock
// OpenVPN client, ends here). A success starts the login.
srv_tls_step :: proc(d: ^Srv, c: ^Conn) {
	l := c.link
	switch tlslink.link_handshake(l) {
	case .Want_Read:
		tls_watch_write(d, c, false)
	case .Want_Write:
		tls_watch_write(d, c, true)
	case .Failed:
		d.stats.outer_failed += 1
		logf(.Info, "outer TLS handshake with %s failed: %s", conn_label(c), tlslink.link_error_text(l))
		conn_drop(d, c)
	case .Done:
		c.tls_hs = false
		logf(.Debug, "outer TLS with %s: %s, %s, %s", conn_label(c), ossl.tls_version_name(&l.s), ossl.tls_cipher_name(&l.s), ossl.tls_negotiated_group_name(&l.s))
		if !l.tls13 {
			logf(.Debug, "outer TLS with %s: the session uses %s, which has no key update, so the outer keys will not be renewed", conn_label(c), ossl.tls_version_name(&l.s))
		}
		conn_arm_timer(d, c)
		// The client may have sent its first packet with its last handshake flight: read now.
		slot := c.slot
		srv_read_tcp(d, c)
		if d.conns[slot] == c && c.sock_open {
			tcp_flush_conn(d, c)
		}
		out_flush(d)
		flush_dirty(d)
	}
}

@(private = "file")
tls_watch_write :: proc(d: ^Srv, c: ^Conn, on: bool) {
	if on != c.want_write {
		c.want_write = on
		event.modify_fd(&d.loop, c.sock.fd, {.Read, .Write} if on else {.Read})
	}
}

// What `net.stream_recv` is for a raw TCP connection: a read of the stream of
// `c`, through the outer TLS if any. Errors are `net.Error`s:
//   .Closed - end of stream (close notice or closed socket)
//   .Other  - the stream broke the TLS rules, or the socket failed
srv_stream_read :: proc(d: ^Srv, c: ^Conn, buf: []u8) -> (n: int, err: net.Error) {
	if c.link == nil {
		return net.stream_recv(c.sock, buf)
	}
	got, lerr := tlslink.link_read(c.link, buf)
	switch lerr {
	case .None:
		return got, .None
	case .Would_Block:
		return 0, .Would_Block
	case .Closed:
		return 0, .Closed
	case .Tls, .Socket, .Invalid:
		logf(.Debug, "outer TLS of %s: %s", conn_label(c), tlslink.link_error_text(c.link))
		return 0, .Other
	}
	return 0, .Other
}

// `tcp_flush_conn` for a tls connection: the plaintext queue goes into the outer
// TLS stream in records of up to 16 KiB, and the records to the socket.
// Nothing is written before the outer handshake is done.
tls_flush_conn :: proc(d: ^Srv, c: ^Conn) -> bool {
	if c.tls_hs {
		return true
	}
	for {
		left, err := tlslink.link_flush(c.link)
		if err != .None {
			return tls_send_lost(d, c)
		}
		if left > 0 {
			break
		}
		if c.ws_phase == .On {
			// One frame at a time (ws_server.odin).
			framed, ok := srv_ws_stage(c)
			if !ok {
				return tls_send_lost(d, c)
			}
			if !framed {
				break
			}
			o := &c.ws.o
			if tlslink.link_write(c.link, o.buf[o.head:o.tail]) != .None {
				return tls_send_lost(d, c)
			}
			o.head = o.tail
		} else {
			queued := txq_pending(&c.q)
			if queued == 0 {
				break
			}
			n := min(queued, tlslink.RECORD_PLAINTEXT)
			if tlslink.link_write(c.link, txq_front(&c.q)[:n]) != .None {
				return tls_send_lost(d, c)
			}
			txq_consume(&c.q, n)
		}
		if bytes, rekeyed := tlslink.link_rekey_note(c.link); rekeyed {
			logf(.Info, "outer TLS with %s: keys updated after %s", conn_label(c), rekey_size_text(bytes))
		}
	}
	pending := txq_pending(&c.q) + tlslink.link_pending(c.link)
	want := pending > 0
	tls_watch_write(d, c, want)
	if pending < len(c.q.buf) / 4 {
		c.slow_since = 0
	}
	return true
}

@(private = "file")
tls_send_lost :: proc(d: ^Srv, c: ^Conn) -> bool {
	d.stats.sock_send_errors += 1
	if c.end == .None {
		c.end = .Tcp_Lost
	}
	conn_drop(d, c)
	return false
}

// A last try to write the queue of a tls connection, with nothing else done
// (the conn is ending).
tls_write_now :: proc(c: ^Conn) {
	if c.tls_hs {
		return
	}
	for {
		left, err := tlslink.link_flush(c.link)
		if err != .None || left > 0 {
			return
		}
		if c.ws_phase == .On {
			framed, ok := srv_ws_stage(c)
			if !ok || !framed {
				return
			}
			o := &c.ws.o
			if tlslink.link_write(c.link, o.buf[o.head:o.tail]) != .None {
				return
			}
			o.head = o.tail
			continue
		}
		queued := txq_pending(&c.q)
		if queued == 0 {
			return
		}
		n := min(queued, tlslink.RECORD_PLAINTEXT)
		if tlslink.link_write(c.link, txq_front(&c.q)[:n]) != .None {
			return
		}
		txq_consume(&c.q, n)
	}
}
