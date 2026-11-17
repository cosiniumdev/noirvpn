// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:encoding/base64"
import "core:fmt"
import "core:mem"
import cnet "core:net"
import "core:strings"
import net "noir:platform/net"
import "noir:platform/tlslink"
import "noir:proto/config"

// Remote through an HTTP proxy (`http-proxy`): connect to the proxy, ask for a
// tunnel with `CONNECT`, run the `tcp` or `tls` transport inside it.
//
//	connect to the proxy -> request -> reply up to the blank line -> 200: the transport starts
//
// Request and reply are plain HTTP on the TCP connection, before any outer TLS.
// The remote name goes to the proxy as written in the config (the proxy resolves it).

// The longest reply header that is accepted, in bytes.
PROXY_HEADER_MAX :: 8192

// ------------------------------------------------------------------ request

// What goes into the CONNECT request.
Proxy_Request :: struct {
	// The remote, as written in the config.
	host:    string,
	port:    u16,
	http10:  bool,
	agent:   string,
	// Send `Proxy-Authorization: Basic` for this user and password.
	basic:   bool,
	user:    string,
	pass:    string,
	headers: []config.Proxy_Header,
}

// `host:port` as the request line has it: an IPv6 literal goes in brackets.
proxy_target :: proc(host: string, port: u16, allocator := context.allocator) -> string {
	if strings.contains_rune(host, ':') && !strings.has_prefix(host, "[") {
		return fmt.aprintf("[%s]:%d", host, port, allocator = allocator)
	}
	return fmt.aprintf("%s:%d", host, port, allocator = allocator)
}

// True if `s` can be part of a header line.
@(private = "file")
proxy_text_ok :: proc(s: string) -> bool {
	for c in transmute([]u8)s {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// The request as bytes. `ok` is false if the host, agent or a header has a line
// break or other control character (the config checks the options, not a host
// name), or if the host has a space.
proxy_request_build :: proc(r: Proxy_Request, allocator := context.allocator) -> (out: []u8, ok: bool) {
	if r.host == "" || strings.contains_rune(r.host, ' ') || !proxy_text_ok(r.host) || !proxy_text_ok(r.agent) {
		return nil, false
	}
	for h in r.headers {
		if !proxy_text_ok(h.name) || !proxy_text_ok(h.content) {
			return nil, false
		}
	}
	sb := strings.builder_make(allocator)
	target := proxy_target(r.host, r.port, context.temp_allocator)
	fmt.sbprintf(&sb, "CONNECT %s HTTP/%s\r\n", target, "1.0" if r.http10 else "1.1")
	fmt.sbprintf(&sb, "Host: %s\r\n", target)
	if r.agent != "" {
		fmt.sbprintf(&sb, "User-Agent: %s\r\n", r.agent)
	}
	if r.basic {
		login := strings.concatenate({r.user, ":", r.pass}, context.temp_allocator)
		enc, err := base64.encode(transmute([]u8)login, allocator = context.temp_allocator)
		// The login does not stay in memory (the request is wiped when the exchange ends).
		mem.zero_explicit(raw_data(login), len(login))
		if err != nil {
			strings.builder_destroy(&sb)
			return nil, false
		}
		fmt.sbprintf(&sb, "Proxy-Authorization: Basic %s\r\n", enc)
		mem.zero_explicit(raw_data(enc), len(enc))
	}
	for h in r.headers {
		fmt.sbprintf(&sb, "%s: %s\r\n", h.name, h.content)
	}
	strings.write_string(&sb, "\r\n")
	return sb.buf[:], true
}

// ------------------------------------------------------------------- reply

Proxy_Parse :: enum u8 {
	// The blank line has not come yet.
	Need_More,
	// The header is complete: see `Proxy_Reply`.
	Done,
	// No blank line within `PROXY_HEADER_MAX` bytes.
	Too_Long,
	// The first line is not an HTTP status line.
	Malformed,
}

// What the first lines of a reply say. The strings point into the bytes that
// were parsed.
Proxy_Reply :: struct {
	code:        int,
	// The status line without the line end, for messages.
	status_line: string,
	// 407: the scheme of the first `Proxy-Authenticate` header ("" if none).
	scheme:      string,
	// 407: some `Proxy-Authenticate` header offers Basic.
	basic:       bool,
	// Bytes of the reply header including the blank line. What follows in the
	// buffer is the tunnel's.
	end:         int,
}

// Reads status line and header of a proxy reply from `buf` (all read so far). A
// line ends at "\n"; a "\r" before it is dropped; a blank line ends the header.
proxy_parse_reply :: proc(buf: []u8) -> (r: Proxy_Reply, st: Proxy_Parse) {
	text := string(buf)
	start := 0
	first := true
	for start < len(text) {
		nl := strings.index_byte(text[start:], '\n')
		if nl < 0 {
			break
		}
		line := strings.trim_right(text[start:start + nl], "\r")
		next := start + nl + 1
		if first {
			if !proxy_status_line(line, &r) {
				return {}, .Malformed
			}
			first = false
		} else if line == "" {
			if next > PROXY_HEADER_MAX {
				return {}, .Too_Long
			}
			r.end = next
			return r, .Done
		} else if colon := strings.index_byte(line, ':'); colon > 0 {
			if strings.equal_fold(line[:colon], "proxy-authenticate") {
				value := strings.trim_space(line[colon + 1:])
				if r.scheme == "" {
					r.scheme = proxy_first_word(value)
				}
				if proxy_offers_basic(value) {
					r.basic = true
				}
			}
		}
		start = next
	}
	if len(buf) >= PROXY_HEADER_MAX {
		return {}, .Too_Long
	}
	// A first line that cannot become a status line does not wait for more: what
	// is there must start "HTTP/". `has_prefix` arguments are in this order on
	// purpose: "HT" is fine, "xy" is not.
	if first && start == 0 && len(buf) > 0 && !strings.has_prefix("HTTP/", text[:min(len(text), 5)]) {
		return {}, .Malformed
	}
	return {}, .Need_More
}

// `HTTP/1.x 407 Reason`. Fills code and the status line.
proxy_status_line :: proc(line: string, r: ^Proxy_Reply) -> bool {
	if !strings.has_prefix(line, "HTTP/") {
		return false
	}
	sp := strings.index_byte(line, ' ')
	if sp < 0 {
		return false
	}
	rest := strings.trim_left(line[sp:], " ")
	if len(rest) < 3 || (len(rest) > 3 && rest[3] != ' ') {
		return false
	}
	code := 0
	for c in transmute([]u8)rest[:3] {
		if c < '0' || c > '9' {
			return false
		}
		code = code * 10 + int(c - '0')
	}
	r.code = code
	r.status_line = line
	return true
}

@(private = "file")
proxy_first_word :: proc(s: string) -> string {
	end := strings.index_any(s, " \t,")
	return s if end < 0 else s[:end]
}

// Does a `Proxy-Authenticate` value offer Basic? It can list several
// challenges, separated by commas: `Negotiate, Basic realm="x"`.
@(private = "file")
proxy_offers_basic :: proc(value: string) -> bool {
	rest := value
	for rest != "" {
		part := rest
		if c := strings.index_byte(rest, ','); c >= 0 {
			part, rest = rest[:c], rest[c + 1:]
		} else {
			rest = ""
		}
		if strings.equal_fold(proxy_first_word(strings.trim_space(part)), "basic") {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------- the daemon

// The state of the exchange with the proxy of the attempt.
Proxy_State :: struct {
	// The request, and how much of it is sent.
	req:    []u8,
	sent:   int,
	// The reply bytes read so far. The bytes after the blank line stay here
	// until the transport has taken them.
	rx:     []u8,
	rx_n:   int,
	// `host:port` of the remote, for the log.
	target: string,
}

proxy_state_clear :: proc(p: ^Proxy_State) {
	if p.req != nil {
		mem.zero_explicit(raw_data(p.req), len(p.req))
		delete(p.req)
	}
	delete(p.target)
	// The reply buffer is kept for the next attempt.
	rx := p.rx
	p^ = {
		rx = rx,
	}
}

// The user name and password for the proxy of connection `idx`, if loaded.
@(private = "file")
proxy_login :: proc(d: ^Daemon, idx: int) -> (user, pass: string, have: bool) {
	k := &d.set.conns[idx]
	if !k.proxy_creds.have {
		return "", "", false
	}
	return string(k.proxy_creds.user[:k.proxy_creds.user_n]), string(k.proxy_creds.pass[:k.proxy_creds.pass_n]), true
}

// The TCP connection to the proxy is up: send the request.
proxy_begin :: proc(d: ^Daemon) {
	conn := &d.cfg.connections[d.conn_idx]
	px, _ := conn.proxy.?
	p := &d.px
	if p.rx == nil {
		p.rx = make([]u8, PROXY_HEADER_MAX)
	}
	p.rx_n = 0
	user, pass, have := proxy_login(d, d.conn_idx)
	send_basic := have && (px.auth == .Basic || (px.auth == .Auto && d.proxy_basic[d.conn_idx]))
	req, ok := proxy_request_build(
		Proxy_Request {
			host = conn.host,
			port = conn.rport,
			http10 = px.http10,
			agent = px.agent,
			basic = send_basic,
			user = user,
			pass = pass,
			headers = px.headers,
		},
	)
	if !ok {
		logf(.Error, "cannot send the remote %s to the proxy because it contains a space or a control character", conn.host)
		fail_connection(d, .Connect_Failed, {})
		return
	}
	p.req, p.sent = req, 0
	p.target = proxy_target(conn.host, conn.rport)
	d.state = .Proxy_Connecting
	client_note_state(d)
	logf(.Debug, "asking the proxy for a tunnel to %s%s", p.target, " (with Basic authentication)" if send_basic else "")
	proxy_send(d)
}

// Writes what is left of the request. The socket is watched for writing while
// some is left.
proxy_send :: proc(d: ^Daemon) {
	p := &d.px
	for p.sent < len(p.req) {
		n, err := net.stream_send(d.sock, p.req[p.sent:])
		if err == .Would_Block {
			set_blocked(d, true)
			return
		}
		if err != .None {
			d.stats.sock_send_errors += 1
			logf(.Warn, "cannot send the request to the proxy: %v", err)
			fail_connection(d, .Connect_Failed, {})
			return
		}
		p.sent += n
	}
	set_blocked(d, false)
}

// The socket is readable (or hung up) in `Proxy_Connecting`: read the reply.
proxy_read :: proc(d: ^Daemon) {
	p := &d.px
	for {
		n, err := net.stream_recv(d.sock, p.rx[p.rx_n:])
		if err == .Would_Block || err == .Interrupted {
			return
		}
		if err != .None {
			if err == .Closed {
				logf(.Warn, "the proxy closed the connection before it finished its reply")
			} else {
				logf(.Warn, "the connection to the proxy failed before the proxy finished its reply: %v", err)
			}
			fail_connection(d, .Connect_Failed, {})
			return
		}
		p.rx_n += n
		if p.sent < len(p.req) {
			// A reply before the request is out: the proxy does not wait for it.
			logf(.Debug, "the proxy responded before the request was sent in full")
		}
		r, st := proxy_parse_reply(p.rx[:p.rx_n])
		switch st {
		case .Need_More:
			continue
		case .Too_Long:
			logf(.Warn, "the reply header from the proxy is longer than %d bytes", PROXY_HEADER_MAX)
			fail_connection(d, .Connect_Failed, {})
		case .Malformed:
			logf(.Warn, "the proxy did not respond with an HTTP status line")
			fail_connection(d, .Connect_Failed, {})
		case .Done:
			proxy_reply(d, r)
		}
		return
	}
}

// The header of the reply is complete: go on, or fail the attempt.
proxy_reply :: proc(d: ^Daemon, r: Proxy_Reply) {
	p := &d.px
	conn := &d.cfg.connections[d.conn_idx]
	px, _ := conn.proxy.?
	switch {
	case r.code >= 200 && r.code < 300:
		logf(.Info, "the proxy opened a tunnel to %s", p.target)
		proxy_established(d, r.end)
	case r.code == 407:
		_, _, have := proxy_login(d, d.conn_idx)
		scheme := r.scheme if r.scheme != "" else "none"
		switch {
		case px.auth == .Auto && have && r.basic:
			if d.proxy_basic[d.conn_idx] {
				logf(.Error, "the proxy refused the Basic login (is the user name or password wrong?): %s", r.status_line)
			} else {
				d.proxy_basic[d.conn_idx] = true
				logf(.Notice, "the proxy asked for Basic authentication, so the next attempt will include it")
			}
		case px.auth == .Basic && r.basic:
			logf(.Error, "the proxy refused the Basic login (is the user name or password wrong?): %s", r.status_line)
		case r.basic:
			logf(.Error, "the proxy asked for Basic authentication, but there are no credentials for it (use `http-proxy HOST PORT auto` with http-proxy-user-pass, or an AUTHFILE)")
		case:
			logf(.Error, "the proxy asked for %s authentication, but only basic proxy authentication is supported", scheme)
		}
		fail_connection(d, .Connect_Failed, {})
	case:
		logf(.Warn, "the proxy refused the tunnel to %s: %s", p.target, r.status_line)
		fail_connection(d, .Connect_Failed, {})
	}
}

// The proxy said yes: the tunnel is open. Bytes behind the reply belong to the
// tunnel (a correct proxy sends none before we speak). Starts the transport as
// on a direct connection.
proxy_established :: proc(d: ^Daemon, end: int) {
	p := &d.px
	ahead := p.rx[end:p.rx_n]
	if len(ahead) > 0 {
		logf(.Debug, "%d bytes of the tunnel came with the proxy's reply", len(ahead))
	}
	if d.tls {
		// They are the start of the server's outer TLS bytes.
		if !tlslink.link_feed(&d.olink, ahead) {
			logf(.Error, "out of memory")
			fail_connection(d, .Connect_Failed, {})
			return
		}
		tls_begin(d)
		return
	}
	begin_session(d, ahead)
}

// A new attempt: forget the exchange of the last one.
proxy_attempt_reset :: proc(d: ^Daemon) {
	proxy_state_clear(&d.px)
}

// `connecting to [10.1.2.3]:3128 (tls) through the HTTP proxy, for vpn.example:443`.
proxy_notice :: proc(d: ^Daemon, ep: cnet.Endpoint, conn: ^config.Connection) {
	logf(
		.Notice,
		"connecting to [%s]:%d (%s) through the HTTP proxy, for %s",
		cnet.address_to_string(ep.address, context.temp_allocator),
		ep.port,
		proto_name(conn.proto, conn.tls),
		proxy_target(conn.host, conn.rport, context.temp_allocator),
	)
}

// ` proxy=HOST:PORT` for the status line while a connection through a proxy
// exists, else "".
proxy_status :: proc(d: ^Daemon) -> string {
	if name, ok := proxy_name(d); ok {
		return fmt.tprintf(" proxy=%s", name)
	}
	return ""
}

// `host:port` of the proxy of the connection in use, as the config names it.
proxy_name :: proc(d: ^Daemon) -> (name: string, ok: bool) {
	if !d.via_proxy || (d.state == .Idle && !d.s_ok) {
		return "", false
	}
	px, has := d.cfg.connections[d.conn_idx].proxy.?
	if !has {
		return "", false
	}
	return fmt.tprintf("%s:%d", px.host, px.port), true
}
