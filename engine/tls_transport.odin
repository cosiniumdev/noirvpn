// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import cnet "core:net"
import net "noir:platform/net"
import "noir:platform/tlslink"
import "noir:proto/config"
import "noir:proto/ossl"
import "noir:proto/session"

// The `tls` transport: the TCP transport inside an outer TLS stream. Outer TLS
// settings for client and server are here; the stream is `platform/tlslink`; the
// byte-moving code is in datapath.odin (client) and server_datapath.odin
// (server).
//
// The inner OpenVPN session is the trust anchor: the client accepts any outer
// TLS certificate and compares its key with the key the inner handshake saw
// (`outer_check`).

// TLS 1.3 suites in order. AES-128 first: the inner layer gives the
// confidentiality, so the outer one only has to look like TLS.
OUTER_SUITES :: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
OUTER_ALPN := [?]string{"http/1.1"}
// The ALPN list of the `chrome` profile: what a browser offers.
OUTER_ALPN_CHROME := [?]string{"h2", "http/1.1"}

// ALPN protocols the outer ClientHello offers. `chrome` offers h2 like a
// browser, except in a WebSocket: a proxy that ended the outer TLS and chose h2
// would break the upgrade, so it gets `http/1.1` alone. Our server chooses no
// protocol, so h2 is harmless there.
outer_alpn :: proc(hello: config.Tls_Hello, ws: bool) -> []string {
	if hello == .Chrome && !ws {
		return OUTER_ALPN_CHROME[:]
	}
	return OUTER_ALPN[:]
}

// The profile of the library for a config value.
outer_hello_profile :: proc "contextless" (hello: config.Tls_Hello) -> ossl.Hello_Profile {
	return .Chrome if hello == .Chrome else .Default
}

// The key exchange groups of the `chrome` profile: Chrome's, with the hybrid
// first. They apply to the outer TLS only.
OUTER_GROUPS_CHROME :: "X25519MLKEM768:X25519:P-256:P-384"

// The transport name for logs and the status output.
proto_name :: proc "contextless" (proto: config.Proto, tls: bool) -> string {
	if proto == .Udp {
		return "udp"
	}
	return "tls" if tls else "tcp"
}

// Is the outer certificate the server's own? Set once the inner handshake has
// shown its key.
Outer_Check :: enum u8 {
	None, // not a tls link
	Pending, // the inner handshake is not done yet
	Direct, // same key: the outer TLS ends at the server
	Terminated, // another key: another party ends the outer TLS (a proxy, an SNI front)
}

outer_text :: proc "contextless" (o: Outer_Check) -> string {
	switch o {
	case .None:
		return "-"
	case .Pending:
		return "pending"
	case .Direct:
		return "direct"
	case .Terminated:
		return "terminated"
	}
	return "?"
}

// How many plaintext bytes an outer key update came after, for the log line:
// whole GiB, or MiB below one GiB (a test knob sets the threshold small).
rekey_size_text :: proc(bytes: u64) -> string {
	if bytes >= 1 << 30 {
		return fmt.tprintf("%d GiB", bytes >> 30)
	}
	return fmt.tprintf("%d MiB", bytes >> 20)
}

// Outer TLS settings of a client: TLS 1.3 preferred, 1.2 allowed, key exchange
// groups as the inner session, no certificate check (see above).
// `tls-transport-hello chrome` has its own group list, which replaces `groups`,
// and changes the rest of the ClientHello.
outer_client_ctx :: proc(groups: string, hello := config.Tls_Hello.Default) -> (ctx: ossl.Tls_Ctx, err: ossl.Error) {
	g := groups
	if hello == .Chrome {
		g = OUTER_GROUPS_CHROME
	}
	return ossl.tls_ctx_create({role = .Client, groups = g, verify = .None, tls13_ciphersuites = OUTER_SUITES, hello = outer_hello_profile(hello)})
}

// The same for a server, with the certificate and key of the outer identity.
outer_server_ctx :: proc(groups: string, cert_pem, key_pem: []u8) -> (ctx: ossl.Tls_Ctx, err: ossl.Error) {
	return ossl.tls_ctx_create({role = .Server, groups = groups, verify = .None, tls13_ciphersuites = OUTER_SUITES, cert_pem = cert_pem, key_pem = key_pem})
}

// Server name for the outer ClientHello. `explicit`: the config named it
// (`tls-transport-sni`); else the remote host name, none for an address.
outer_sni :: proc(cfg: ^config.Client_Config, host: string) -> (name: string, explicit: bool) {
	if cfg.tls_transport_sni != "" {
		return cfg.tls_transport_sni, true
	}
	if cnet.parse_address(host) != nil {
		return "", false
	}
	return host, false
}

// ------------------------------------------------------------ client side

// The TCP connection is up: the outer TLS handshake starts.
tls_begin :: proc(d: ^Daemon) {
	d.state = .Tls_Handshaking
	client_note_state(d)
	tls_step(d)
}

// Runs the outer handshake as far as the socket allows. On `.Done` the
// session starts, as it does right after the connect of a plain TCP link.
tls_step :: proc(d: ^Daemon) {
	l := &d.olink
	switch tlslink.link_handshake(l) {
	case .Want_Read:
		set_blocked(d, false)
	case .Want_Write:
		set_blocked(d, true)
	case .Failed:
		logf(.Warn, "the outer TLS handshake failed: %s", tlslink.link_error_text(l))
		fail_connection(d, .Connect_Failed, {})
	case .Done:
		logf(.Info, "outer TLS: %s, %s, %s", ossl.tls_version_name(&l.s), ossl.tls_cipher_name(&l.s), ossl.tls_negotiated_group_name(&l.s))
		if !l.tls13 {
			logf(.Debug, "outer TLS: the session is %s and has no key update, so the outer keys are not renewed", ossl.tls_version_name(&l.s))
		}
		set_blocked(d, tlslink.link_pending(l) > 0)
		if d.ws {
			ws_begin(d)
			return
		}
		begin_session(d)
		if d.state == .Active && d.s_ok && tlslink.link_has_input(l) {
			// The server's first bytes came with its last handshake flight.
			read_tls(d)
			pump(d)
		}
	}
}

// Writes the plaintext queue (`d.tcp`, framed packets) into the outer TLS
// stream, records of up to 16 KiB, and the records to the socket. Records are
// cut without regard to frames: the stream is bytes. Same results as
// `stream_flush`.
tls_stream_flush :: proc(d: ^Daemon) -> (pending: int, ok: bool) {
	t := &d.tcp
	l := &d.olink
	for {
		left, err := tlslink.link_flush(l)
		if err != .None {
			return 0, tls_send_failed(d)
		}
		if left > 0 {
			// The socket is full: the rest of the queue stays plaintext.
			set_blocked(d, true)
			return left + net.tcp_pending(t), true
		}
		queued := net.tcp_pending(t)
		n := 0
		if d.ws && d.wsc.on {
			// One frame at a time: the next frame is a waiting control frame, or
			// the front of the queue, copied (and masked) behind its header.
			o := &d.wsc.out
			used, framed := ws_out_next(o, t.tx[t.tx_head:t.tx_tail])
			if !framed {
				logf(.Error, "cannot generate a random mask key")
				return 0, tls_send_failed(d)
			}
			if ws_out_pending(o) == 0 {
				break
			}
			n = used
			if tlslink.link_write(l, o.buf[o.head:o.tail]) != .None {
				return 0, tls_send_failed(d)
			}
			o.head = o.tail
		} else {
			if queued == 0 {
				break
			}
			n = min(queued, tlslink.RECORD_PLAINTEXT)
			if tlslink.link_write(l, t.tx[t.tx_head:][:n]) != .None {
				return 0, tls_send_failed(d)
			}
		}
		if bytes, rekeyed := tlslink.link_rekey_note(l); rekeyed {
			logf(.Info, "outer TLS: keys updated after %s", rekey_size_text(bytes))
		}
		t.tx_head += n
		if t.tx_head == t.tx_tail {
			t.tx_head, t.tx_tail = 0, 0
		}
	}
	set_blocked(d, false)
	return 0, true
}

@(private = "file")
tls_send_failed :: proc(d: ^Daemon) -> bool {
	d.stats.sock_send_errors += 1
	logf(.Warn, "TLS send failed: %s", tlslink.link_error_text(&d.olink))
	fail_connection(d, .Ping_Restart if d.up else .Connect_Failed, {})
	return false
}

// `read_stream` for a tls link: the bytes come out of the outer TLS stream.
read_tls :: proc(d: ^Daemon) {
	defer rx_flush(d)
	l := &d.olink
	plain := d.rx_buf[:32 * 1024]
	// The socket stays readable for bytes it holds, but not for a record that
	// the TLS library already has: go on while it does.
	for round := 0; round < READ_ROUNDS || tlslink.link_has_input(l); round += 1 {
		n, err := tlslink.link_read(l, plain)
		if err == .Would_Block {
			break
		}
		if err != .None {
			if d.close_reason != .None {
				// We are closing: the server hung up after the exit notice.
				fail_connection(d, close_outcome(d.close_reason), {})
				return
			}
			d.stats.sock_recv_errors += 1
			logf(.Warn, "the TLS connection ended: %s", tlslink.link_error_text(l))
			fail_connection(d, .Ping_Restart if d.up else .Connect_Failed, {})
			return
		}
		if d.ws {
			ws_feed(d, plain[:n])
		} else {
			feed(d, plain[:n])
		}
		if !feed_ok(d) || d.end.pending || d.state != .Active {
			return
		}
		// The next read overwrites `plain`.
		rx_flush(d)
	}
	if tlslink.link_pending(l) > 0 || (d.ws && ws_out_has_ctl(&d.wsc.out)) {
		// Reading can queue bytes for the peer (a key update).
		stream_flush(d)
	}
}

// The key updates the outer TLS session of this link has started (the
// `outer-rekeys` of the status line). 0 when there is no link.
outer_rekeys :: proc(d: ^Daemon) -> u64 {
	return d.olink.rekeys if d.olink_ok else 0
}

// Compares the outer TLS certificate key with the inner server certificate key,
// once the inner handshake shows it. The inner session is the trust anchor, so a
// difference gives a notice.
outer_check :: proc(d: ^Daemon) {
	inner, ok := session.session_peer_key(&d.s)
	if !ok {
		return
	}
	if d.olink_ok && d.olink.peer_ok && inner.spki_sha256 == d.olink.peer.spki_sha256 {
		d.outer = .Direct
		logf(.Debug, "the outer TLS reaches the server directly")
		return
	}
	d.outer = .Terminated
	if d.cfg.tls_transport_strict {
		// `tls-transport-strict`: the attempt fails, and the usual back-off applies.
		logf(.Error, "the outer TLS does not end at the server, so the connection is refused because tls-transport-strict is set")
		fail_connection(d, .Connect_Failed, {})
		return
	}
	if !d.olink_ok || !d.olink.peer_ok {
		return
	}
	if d.cfg.tls_transport_sni == "" {
		logf(.Warn, "the outer TLS is ended by another party whose certificate has a different key from the server's (a proxy that inspects TLS?); the inner session is still authenticated")
	} else {
		logf(.Info, "the outer TLS is ended by another party (expected with tls-transport-sni %s) whose certificate has a different key from the server's; the inner session is still authenticated", d.cfg.tls_transport_sni)
	}
}

// ------------------------------------------------------------ server side

// What the first bytes of a connection on a `tls-server` listener say.
First_Bytes :: enum u8 {
	Need_More, // too few bytes to tell
	Tls, // the start of a TLS record: a TLS client
	Raw, // anything else: a raw OpenVPN client (or something that is neither)
}

// Tells a TLS client from a raw OpenVPN `tcp-client` by the first 3 bytes. TLS
// handshake record: 16 03 xx (xx 00..04: record version).
//
// Raw OpenVPN starts with the 2-byte length of its first packet (reset packet,
// about 14 to 100 bytes). That reads as 16 03 only for a packet of exactly 5635
// bytes. This server's TCP framing refuses packets far below that, so a raw
// client never looks like TLS; no extra check needed (the outer handshake would
// refuse it anyway).
//
// A prefix that already breaks the rule is decided at once. Only a prefix that
// still fits TLS (nothing, 16, or 16 03) waits for more bytes.
classify_first_bytes :: proc "contextless" (b: []u8) -> First_Bytes {
	if len(b) >= 1 && b[0] != 0x16 {
		return .Raw
	}
	if len(b) >= 2 && b[1] != 0x03 {
		return .Raw
	}
	if len(b) < 3 {
		return .Need_More
	}
	return .Tls if b[2] <= 0x04 else .Raw
}

