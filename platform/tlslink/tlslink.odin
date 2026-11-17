// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package tlslink puts a TLS stream (the outer TLS of the `tls` transport)
// between a non-blocking socket and the code that reads and writes framed
// bytes. The TLS library (proto/ossl) uses a custom BIO: it appends the
// library's records to the link's output buffer and reads the socket straight
// into the library's buffer. No memory BIO between saves one copy per side.
//
// One `Link` has one owner thread, which does all socket I/O of the
// connection. Memory is the caller's, except what the TLS library takes for
// its session. A `Tls_Ctx` (library settings) can be shared by many links.
//
// A link must not move or be copied between `link_init` and `link_destroy`:
// the BIO of its session holds a pointer to it. Keep it in a fixed place (a
// field of a struct that does not move, or a heap object).
//
// The handshake, driven from the event loop:
//
//	link_init(&l, &ctx, sock, out_buf)
//	// the socket is connected (client) or accepted (server)
//	switch link_handshake(&l) {
//	case .Want_Read:  // watch .Read, call again when it fires
//	case .Want_Write: // watch .Write, call again when it fires
//	case .Done:       // established; `l.peer` is the other side's key
//	case .Failed:     // `link_error_text(&l)` says why; close the socket
//	}
//
// After that, reading and writing look like `net.stream_recv` and
// `net.stream_send` with a queue:
//
//	n, err := link_read(&l, buf)               // .Would_Block: wait for .Read
//	link_write(&l, plaintext)                  // encrypts; nothing is sent yet
//	pending, err := link_flush(&l)             // pending > 0: watch .Write
//
// A key update (TLS 1.3) happens inside `link_write` after `rekey_after`
// bytes; see `Link.rekey_after`.
package tlslink

import "core:fmt"
import net "noir:platform/net"
import "noir:proto/ossl"

// The most plaintext one `link_write` hands to the TLS library at a time: one
// TLS record. A caller that writes a batch gets full records.
RECORD_PLAINTEXT :: 16 * 1024

// Most that one record and its key update message add to the plaintext:
// record header and tag (TLS 1.2 CBC is not offered; AEAD adds at most 40
// bytes) plus a KeyUpdate message before it.
RECORD_OVERHEAD :: 64

// Holds one full record as it leaves the library, with room for the small
// messages that reading can cause us to send (key update response, alert).
OUT_BUF_SIZE :: RECORD_PLAINTEXT + 256

// After this many plaintext bytes written, the link updates its sending keys
// (TLS 1.3). Far below the AES-GCM limit of the outer record layer (about
// 360 GiB at 16 KiB records). The link does it.
REKEY_BYTES :: u64(32) << 30

Error :: enum {
	None,
	Would_Block, // nothing now; wait for the socket (read, or write for a flush)
	Closed, // the peer sent close_notify, or closed the socket
	Tls, // the TLS library refused something: `link_error_text`
	Socket, // the socket failed: `l.sock_err`
	Invalid, // wrong state or argument (no handshake yet, empty buffer)
}

Hs_Status :: enum {
	Want_Read, // the handshake needs bytes from the peer: watch .Read
	Want_Write, // the socket took only part of our bytes: watch .Write
	Done,
	Failed,
}

Link :: struct {
	s:           ossl.Tls_Session,
	sock:        net.Socket,
	// TLS bytes the library has generated and the socket has not taken yet. The
	// library's BIO appends at `out_tail`; `link_flush` sends from `out_head`.
	out:         []u8,
	out_head:    int,
	out_tail:    int,
	// Bytes fed to the link before the socket is read (`link_feed`): they come
	// first. The link owns this memory.
	fed:         []u8,
	fed_head:    int,
	// The other side's leaf key, set when the handshake is done and the peer
	// sent a certificate (a client always gets one).
	peer:        ossl.Peer_Key,
	peer_ok:     bool,
	// The socket error behind the last `.Socket`, and whether the end of the
	// stream came without a close_notify (a truncated stream).
	sock_err:    net.Error,
	eof:         bool,
	ok:          bool, // `link_init` created a session
	done:        bool, // the handshake is complete
	tls13:       bool, // set with `done`: the session can update its keys
	// What the last call into the library ran into: the socket had nothing to
	// read, or the output buffer had no room.
	rd_blocked:  bool,
	wr_blocked:  bool,
	// The outer rekey. `link_write` counts the plaintext it takes (`written`); at
	// `rekey_after` on a TLS 1.3 session it updates the sending keys and restarts
	// the count. `link_init` sets `rekey_after` to `REKEY_BYTES`; a caller may set
	// it lower after init (a test knob). `link_rekey_note` reports a rekey so the
	// caller can log it.
	rekey_after: u64,
	written:     u64,
	rekeys:      u64, // key updates we started, ever
	rekey_bytes: u64, // the bytes written before the last one
	rekeys_seen: u64,
}

// Starts a link on a connected socket. `out` holds the TLS bytes that wait for
// the socket. `OUT_BUF_SIZE` is a good size; `link_write` needs at least the
// data plus `RECORD_OVERHEAD` per record. A client link may send `sni` (a host
// name) and offer `alpn`. `l` must stay in place until
// `link_destroy`.
link_init :: proc(l: ^Link, ctx: ^ossl.Tls_Ctx, sock: net.Socket, out: []u8, sni := "", alpn: []string = nil) -> Error {
	if len(out) == 0 {
		return .Invalid
	}
	l^ = {
		sock        = sock,
		out         = out,
		rekey_after = REKEY_BYTES,
	}
	io := ossl.Link_Io {
		user        = l,
		write       = bio_write,
		read        = bio_read,
		pending_in  = bio_pending_in,
		pending_out = bio_pending_out,
	}
	if ossl.tls_session_init_link(&l.s, ctx, io) != .None {
		return .Tls
	}
	l.ok = true
	if ctx.role == .Client {
		if len(sni) > 0 && !ossl.tls_session_set_sni(&l.s, sni) {
			link_destroy(l)
			return .Invalid
		}
		if len(alpn) > 0 && !ossl.tls_session_set_alpn(&l.s, alpn) {
			link_destroy(l)
			return .Invalid
		}
	}
	return .None
}

// Frees the TLS session. The socket stays the caller's.
link_destroy :: proc(l: ^Link) {
	if l.ok {
		ossl.tls_session_destroy(&l.s)
	}
	delete(l.fed)
	l^ = {}
}

// Starts a link again on a new socket, keeping the buffers and the settings
// of the session's context. (A session cannot be reused: this creates a new one.)
link_reset :: proc(l: ^Link, ctx: ^ossl.Tls_Ctx, sock: net.Socket, sni := "", alpn: []string = nil) -> Error {
	out := l.out
	after := l.rekey_after
	link_destroy(l)
	err := link_init(l, ctx, sock, out, sni, alpn)
	if err == .None && after != 0 {
		l.rekey_after = after
	}
	return err
}

// Gives the link bytes from the peer that came before it reads the socket
// (bytes that followed an HTTP proxy's reply). They are copied and served
// first. False if out of memory.
link_feed :: proc(l: ^Link, data: []u8) -> bool {
	if !l.ok {
		return false
	}
	if len(data) == 0 {
		return true
	}
	rest := l.fed[l.fed_head:]
	joined := make([]u8, len(rest) + len(data))
	if joined == nil {
		return false
	}
	copy(joined, rest)
	copy(joined[len(rest):], data)
	delete(l.fed)
	l.fed = joined
	l.fed_head = 0
	return true
}

// TLS bytes that still wait for the socket.
link_pending :: proc(l: ^Link) -> int {
	if !l.ok {
		return 0
	}
	return l.out_tail - l.out_head
}

// True if `link_read` may have data without a new socket read: a whole record
// is received but not given out, or the library read ahead into the next one.
// The socket does not turn readable for it, so read until `.Would_Block`.
link_has_input :: proc(l: ^Link) -> bool {
	return l.ok && ossl.tls_has_input(&l.s)
}

// The reason of the last `.Tls`, `.Socket` or `.Closed`, as text. Valid until
// the next call on the same thread that formats text.
link_error_text :: proc(l: ^Link) -> string {
	if !l.ok {
		return "no TLS session"
	}
	// The socket's own reason first: the library reports it as a read error too.
	if l.sock_err != .None {
		return fmt.tprintf("%v", l.sock_err)
	}
	if l.eof {
		return "the peer closed the connection without close_notify"
	}
	if t := ossl.tls_last_error(&l.s); t != "" {
		return t
	}
	return "closed by the peer"
}

// Says if the link updated its sending keys since the last call, and after how
// many plaintext bytes, for the caller to log. Each update is reported once.
link_rekey_note :: proc(l: ^Link) -> (bytes: u64, rekeyed: bool) {
	if l.rekeys == l.rekeys_seen {
		return 0, false
	}
	l.rekeys_seen = l.rekeys
	return l.rekey_bytes, true
}

// Writes waiting TLS bytes to the socket. Returns what still waits; if more
// than 0, wait for writable and call again. `.Socket`: broken connection
// (`l.sock_err`).
link_flush :: proc(l: ^Link) -> (pending: int, err: Error) {
	if !l.ok {
		return 0, .Invalid
	}
	for l.out_head < l.out_tail {
		n, serr := net.stream_send(l.sock, l.out[l.out_head:l.out_tail])
		if serr == .Would_Block {
			return link_pending(l), .None
		}
		if serr != .None {
			l.sock_err = serr
			return link_pending(l), .Socket
		}
		l.out_head += n
	}
	l.out_head, l.out_tail = 0, 0
	return 0, .None
}

// Runs the handshake as far as the socket allows (see the top of this file):
// writes what the library wants to send, reads what the peer sent. After
// `.Done` bytes may still wait (`link_pending`): flush them like other output.
link_handshake :: proc(l: ^Link) -> Hs_Status {
	if !l.ok {
		return .Failed
	}
	if l.done {
		return .Done
	}
	for {
		l.rd_blocked, l.wr_blocked = false, false
		st := ossl.tls_handshake_step(&l.s)
		fed_trim(l)
		// Whatever the step produced goes out first, a failure's alert too.
		pending, ferr := link_flush(l)
		switch st {
		case .Failed:
			return .Failed
		case .Done:
			l.done = true
			l.tls13 = ossl.tls_is_tls13(&l.s)
			l.peer, l.peer_ok = ossl.tls_peer_key(&l.s)
			if ferr != .None {
				// The Finished message could not be sent: the link is broken.
				return .Failed
			}
			return .Done
		case .Want_More:
		}
		if ferr != .None {
			return .Failed
		}
		if pending > 0 {
			return .Want_Write
		}
		if l.wr_blocked {
			// The library could not put a whole message in the buffer, and the
			// socket has taken it all now: let it go on.
			continue
		}
		return .Want_Read
	}
}

// Reads decrypted bytes into `buf`. Returns after one non-empty read or when
// the socket has nothing more:
//
//   .None         `n` bytes are in `buf`
//   .Would_Block  nothing now: wait for .Read
//   .Closed       close_notify, or socket closed (`l.eof` tells which)
//   .Tls          the stream broke the TLS rules
//   .Socket       socket failed
//
// Reading can cause the library to queue bytes (a key update response). They go out
// at the next `link_flush`, so flush after reading.
link_read :: proc(l: ^Link, buf: []u8) -> (n: int, err: Error) {
	if !l.done || len(buf) == 0 {
		return 0, .Invalid
	}
	for {
		l.rd_blocked, l.wr_blocked = false, false
		got, st := ossl.tls_read_app(&l.s, buf)
		fed_trim(l)
		switch st {
		case .Ok:
			return got, .None
		case .Closed:
			return 0, .Closed
		case .Failed:
			// The library says what it saw; we know whether the socket was the cause.
			if l.sock_err != .None {
				return 0, .Socket
			}
			if l.eof {
				return 0, .Closed
			}
			return 0, .Tls
		case .Not_Ready:
			return 0, .Invalid
		case .Want_More:
		}
		if l.wr_blocked {
			// A response of ours (a key update) did not fit the output buffer. Send what
			// is there and go on. If the socket is full too, the caller's next flush creates
			// room and its next read goes on.
			pending, ferr := link_flush(l)
			if ferr != .None {
				return 0, .Socket
			}
			if pending == 0 {
				continue
			}
		}
		return 0, .Would_Block
	}
}

// Encrypts `data` in records of at most `RECORD_PLAINTEXT` bytes, so a batch
// of packets fills whole records. Nothing is sent: call `link_flush`. All of
// `data` is taken, or none:
//
//   .None         taken; records wait in the output buffer
//   .Would_Block  no room for all of it: flush, call again
//   .Invalid      would not fit an empty output buffer (write less at a time)
//
// A caller that flushes until nothing is pending, then writes one record,
// never gets `.Would_Block`. After `rekey_after` bytes the sending keys are
// updated first (TLS 1.3).
link_write :: proc(l: ^Link, data: []u8) -> Error {
	if !l.done {
		return .Invalid
	}
	if len(data) == 0 {
		return .None
	}
	records := (len(data) + RECORD_PLAINTEXT - 1) / RECORD_PLAINTEXT
	need := len(data) + records * RECORD_OVERHEAD
	if need > len(l.out) {
		return .Invalid
	}
	if len(l.out) - link_pending(l) < need {
		link_flush(l)
		if len(l.out) - link_pending(l) < need {
			return .Would_Block
		}
	}
	rest := data
	for len(rest) > 0 {
		n := min(len(rest), RECORD_PLAINTEXT)
		if l.tls13 && l.written >= l.rekey_after {
			if ossl.tls_key_update(&l.s) {
				l.rekeys += 1
				l.rekey_bytes = l.written
				l.written = 0
			}
		}
		l.wr_blocked = false
		if ossl.tls_write_app(&l.s, rest[:n]) != .Ok {
			// `.Want_More` cannot happen after the check above, unless the
			// library wrote more than `RECORD_OVERHEAD` around a record.
			return .Tls
		}
		l.written += u64(n)
		rest = rest[n:]
	}
	return .None
}

// Says goodbye (close_notify) and tries once to send it. Best effort: it does
// not wait for the peer's response, and a full socket drops the alert. The
// socket stays open: the caller closes it.
link_close :: proc(l: ^Link) {
	if !l.ok || !l.done {
		return
	}
	ossl.tls_shutdown(&l.s)
	link_flush(l)
}

// Frees the fed bytes once the library has read them all.
@(private = "file")
fed_trim :: proc(l: ^Link) {
	if l.fed != nil && l.fed_head == len(l.fed) {
		delete(l.fed)
		l.fed = nil
		l.fed_head = 0
	}
}

// --- the hooks of the BIO ---
//
// These run inside the TLS library, as C procedures: no Odin context, no
// allocation. `user` is the link.

// The library generated `n` bytes of records: append what fits to `out`.
@(private = "file")
bio_write :: proc "c" (user: rawptr, data: [^]u8, n: int) -> int {
	l := (^Link)(user)
	if l.out_head == l.out_tail {
		l.out_head, l.out_tail = 0, 0
	}
	room := len(l.out) - l.out_tail
	if room < n && l.out_head > 0 {
		// Move the unsent bytes to the start to free room at the end.
		live := l.out_tail - l.out_head
		copy(l.out[:live], l.out[l.out_head:l.out_tail])
		l.out_head, l.out_tail = 0, live
		room = len(l.out) - live
	}
	m := min(n, room)
	if m < n {
		l.wr_blocked = true
	}
	if m <= 0 {
		return 0
	}
	copy(l.out[l.out_tail:][:m], data[:m])
	l.out_tail += m
	return m
}

// The library wants up to `n` bytes: the fed bytes first, then the socket.
@(private = "file")
bio_read :: proc "c" (user: rawptr, buf: [^]u8, n: int) -> int {
	l := (^Link)(user)
	if l.fed_head < len(l.fed) {
		m := min(n, len(l.fed) - l.fed_head)
		copy(buf[:m], l.fed[l.fed_head:][:m])
		l.fed_head += m
		return m
	}
	if l.eof {
		return ossl.IO_END
	}
	if l.sock_err != .None {
		return ossl.IO_ERROR
	}
	got, err := net.stream_recv(l.sock, buf[:n])
	#partial switch err {
	case .None:
		return got
	case .Would_Block, .Interrupted:
		l.rd_blocked = true
		return ossl.IO_RETRY
	case .Closed:
		l.eof = true
		return ossl.IO_END
	}
	l.sock_err = err
	return ossl.IO_ERROR
}

@(private = "file")
bio_pending_in :: proc "c" (user: rawptr) -> int {
	l := (^Link)(user)
	return len(l.fed) - l.fed_head
}

@(private = "file")
bio_pending_out :: proc "c" (user: rawptr) -> int {
	l := (^Link)(user)
	return l.out_tail - l.out_head
}
