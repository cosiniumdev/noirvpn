// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "base:intrinsics"
import "core:crypto/legacy/sha1"
import "core:encoding/base64"
import "core:fmt"
import "core:strings"
import "noir:platform/tlslink"
import "noir:proto/config"
import "noir:proto/ossl"

// WebSocket framing for the `tls` transport (RFC 6455). The OpenVPN TCP stream
// (2-byte length, packet) travels in binary frames inside the outer TLS stream,
// after an HTTP `Upgrade`, so a reverse proxy that ends the outer TLS at the HTTP
// layer passes it.
//
// Pure code: frame header, masking, request and reply, accept key, and two state
// machines (`Ws_Rx` takes frames apart, `Ws_Out` builds them). Sockets:
// ws_client.odin, ws_server.odin.

// The key suffix of RFC 6455 section 1.3.
WS_GUID :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// The longest request or reply header that is accepted, in bytes.
WS_HEADER_MAX :: 8192

// The longest path of `tls-transport-ws`.
WS_PATH_MAX :: 255

// One frame we send carries at most this many payload bytes: with its header it
// fits one outer TLS record.
WS_FRAME_MAX :: tlslink.RECORD_PLAINTEXT - 16

// The most payload bytes of one received frame that is accepted.
WS_RX_MAX :: tlslink.RECORD_PLAINTEXT

// A control frame has at most 125 payload bytes.
WS_CTL_MAX :: 125

// The longest frame header: 2 bytes, 8 bytes of length, 4 bytes of mask.
WS_HEADER_LEN_MAX :: 14

// The staging buffer of a sender: the longest header and a full frame.
WS_OUT_SIZE :: WS_HEADER_LEN_MAX + WS_FRAME_MAX

WS_OP_CONT :: 0x0
WS_OP_TEXT :: 0x1
WS_OP_BINARY :: 0x2
WS_OP_CLOSE :: 0x8
WS_OP_PING :: 0x9
WS_OP_PONG :: 0xA

// ------------------------------------------------------------ frame header

// Writes the header of a final frame (FIN set) with `n` payload bytes. With
// `mask`, the MASK bit is set and the key follows the length. Returns the header
// length. `out` needs `WS_HEADER_LEN_MAX` bytes.
ws_header :: proc(out: []u8, opcode: u8, n: int, mask: Maybe([4]u8)) -> int {
	out[0] = 0x80 | (opcode & 0x0f)
	m: u8 = 0x80 if mask != nil else 0
	pos := 2
	switch {
	case n < 126:
		out[1] = m | u8(n)
	case n <= 0xffff:
		out[1] = m | 126
		out[2] = u8(n >> 8)
		out[3] = u8(n)
		pos = 4
	case:
		out[1] = m | 127
		for i in 0 ..< 8 {
			out[2 + i] = u8(u64(n) >> u64(56 - 8 * i))
		}
		pos = 10
	}
	if key, ok := mask.?; ok {
		copy(out[pos:], key[:])
		pos += 4
	}
	return pos
}

// XORs `data` with the mask key, in place. `offset` is the position of the
// first byte of `data` in the payload (the key repeats every 4 bytes).
ws_mask :: proc(data: []u8, key: [4]u8, offset := 0) {
	k8: [8]u8
	for i in 0 ..< 8 {
		k8[i] = key[(i + offset) & 3]
	}
	kw := intrinsics.unaligned_load((^u64)(&k8[0]))
	i := 0
	for ; i + 8 <= len(data); i += 8 {
		p := (^u64)(&data[i])
		intrinsics.unaligned_store(p, intrinsics.unaligned_load(p) ~ kw)
	}
	for ; i < len(data); i += 1 {
		data[i] ~= k8[i & 3]
	}
}

// `dst = src ^ key`, one pass. `dst` is at least as long as `src`.
ws_mask_copy :: proc(dst, src: []u8, key: [4]u8) {
	n := len(src)
	k8 := [8]u8{key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3]}
	kw := intrinsics.unaligned_load((^u64)(&k8[0]))
	i := 0
	for ; i + 8 <= n; i += 8 {
		intrinsics.unaligned_store((^u64)(&dst[i]), intrinsics.unaligned_load((^u64)(&src[i])) ~ kw)
	}
	for ; i < n; i += 1 {
		dst[i] = src[i] ~ k8[i & 3]
	}
}

// ---------------------------------------------------------------- receiving

Ws_Kind :: enum u8 {
	More, // the bytes are used up; nothing to act on yet
	Data, // `data` is stream bytes
	Ping, // `data` is the ping's payload: reply with a pong that has it
	Pong, // ignore
	Close, // the peer closes; `data` is its payload (status code and reason)
	Error, // the peer broke the protocol: `text` says how
}

Ws_Event :: struct {
	kind: Ws_Kind,
	// Bytes of the input this call used. Always more than 0 for a non-empty input.
	used: int,
	data: []u8,
	text: string,
}

// The receiving half: takes the frames apart across any split of the input.
Ws_Rx :: struct {
	// The server needs masked frames from the client, the client needs unmasked
	// frames from the server.
	want_mask: bool,
	hdr:       [WS_HEADER_LEN_MAX]u8,
	hdr_n:     int,
	// The frame whose payload is coming.
	active:    bool,
	opcode:    u8,
	masked:    bool,
	key:       [4]u8,
	remain:    u64,
	seen:      int, // payload bytes of the frame seen so far (for the mask)
	// A data message with FIN clear is open: the next data frame continues it.
	msg_open:  bool,
	ctl:       [WS_CTL_MAX]u8,
	ctl_n:     int,
}

@(private = "file")
rx_error :: proc(used: int, text: string) -> Ws_Event {
	return {kind = .Error, used = used, text = text}
}

// How many header bytes a frame needs, from its first two bytes.
@(private = "file")
header_need :: proc(b0, b1: u8) -> int {
	n := 2
	switch b1 & 0x7f {
	case 126:
		n += 2
	case 127:
		n += 8
	}
	if b1 & 0x80 != 0 {
		n += 4
	}
	return n
}

// Takes the next step on `buf`: uses some bytes, says what they produced. Callers
// loop until `buf` is used up. Data payload is unmasked in place (`data` points
// into `buf`). A control payload is collected in `r.ctl` across calls and given
// out whole.
ws_rx_next :: proc(r: ^Ws_Rx, buf: []u8) -> Ws_Event {
	pos := 0
	if !r.active {
		for pos < len(buf) {
			r.hdr[r.hdr_n] = buf[pos]
			r.hdr_n += 1
			pos += 1
			if r.hdr_n >= 2 && r.hdr_n == header_need(r.hdr[0], r.hdr[1]) {
				break
			}
		}
		if r.hdr_n < 2 || r.hdr_n < header_need(r.hdr[0], r.hdr[1]) {
			return {kind = .More, used = pos}
		}
		if ev, bad := ws_rx_header(r, pos); bad {
			return ev
		}
		if r.remain == 0 {
			return ws_rx_end(r, pos)
		}
	}
	// Payload.
	n := int(min(r.remain, u64(len(buf) - pos)))
	chunk := buf[pos:][:n]
	if r.masked {
		ws_mask(chunk, r.key, r.seen)
	}
	r.seen += n
	r.remain -= u64(n)
	pos += n
	if r.opcode >= WS_OP_CLOSE {
		copy(r.ctl[r.ctl_n:], chunk)
		r.ctl_n += n
		if r.remain > 0 {
			return {kind = .More, used = pos}
		}
		return ws_rx_end(r, pos)
	}
	if r.remain == 0 {
		r.active = false
		r.hdr_n = 0
	}
	if n == 0 {
		return {kind = .More, used = pos}
	}
	return {kind = .Data, used = pos, data = chunk}
}

// The whole header is in `r.hdr`: checks it and sets up the frame.
@(private = "file")
ws_rx_header :: proc(r: ^Ws_Rx, used: int) -> (ev: Ws_Event, bad: bool) {
	b0, b1 := r.hdr[0], r.hdr[1]
	fin := b0 & 0x80 != 0
	op := b0 & 0x0f
	if b0 & 0x70 != 0 {
		return rx_error(used, "reserved bits are set"), true
	}
	switch op {
	case WS_OP_CONT, WS_OP_BINARY, WS_OP_CLOSE, WS_OP_PING, WS_OP_PONG:
	case WS_OP_TEXT:
		return rx_error(used, "a text frame (only binary frames are used)"), true
	case:
		return rx_error(used, fmt.tprintf("reserved opcode %d", op)), true
	}
	masked := b1 & 0x80 != 0
	if masked != r.want_mask {
		return rx_error(used, "the frame is masked" if masked else "the frame is not masked"), true
	}
	pos := 2
	n: u64 = u64(b1 & 0x7f)
	switch n {
	case 126:
		n = u64(r.hdr[2]) << 8 | u64(r.hdr[3])
		pos = 4
	case 127:
		n = 0
		for i in 0 ..< 8 {
			n = n << 8 | u64(r.hdr[2 + i])
		}
		pos = 10
		if n >> 63 != 0 {
			return rx_error(used, "a frame length with the top bit set"), true
		}
	}
	if masked {
		copy(r.key[:], r.hdr[pos:][:4])
	}
	if op >= WS_OP_CLOSE {
		if !fin {
			return rx_error(used, "a fragmented control frame"), true
		}
		if n > WS_CTL_MAX {
			return rx_error(used, "a control frame with more than 125 bytes"), true
		}
	} else {
		if n > WS_RX_MAX {
			return rx_error(used, fmt.tprintf("a frame of %d bytes (the limit is %d)", n, WS_RX_MAX)), true
		}
		if op == WS_OP_CONT && !r.msg_open {
			return rx_error(used, "a continuation frame with no message to continue"), true
		}
		if op == WS_OP_BINARY && r.msg_open {
			return rx_error(used, "a new message inside a fragmented one"), true
		}
		r.msg_open = !fin
	}
	r.active = true
	r.opcode = op
	r.masked = masked
	r.remain = n
	r.seen = 0
	r.ctl_n = 0
	return {}, false
}

// A control frame is complete (or a frame with no payload): gives it out.
@(private = "file")
ws_rx_end :: proc(r: ^Ws_Rx, used: int) -> Ws_Event {
	op := r.opcode
	r.active = false
	r.hdr_n = 0
	switch op {
	case WS_OP_PING:
		return {kind = .Ping, used = used, data = r.ctl[:r.ctl_n]}
	case WS_OP_PONG:
		return {kind = .Pong, used = used}
	case WS_OP_CLOSE:
		return {kind = .Close, used = used, data = r.ctl[:r.ctl_n]}
	}
	// A data frame with no payload.
	return {kind = .More, used = used}
}

// ------------------------------------------------------------------ sending

// The sending half. One frame is staged in `buf` at a time (header, payload):
// the stream is cut into frames of at most `WS_FRAME_MAX` bytes and copied once
// (masked in the same pass on the client).
Ws_Out :: struct {
	buf:    []u8,
	head:   int,
	tail:   int,
	// A control frame (a pong, a close) waits here for the gap between two frames.
	ctl:    [WS_HEADER_LEN_MAX + WS_CTL_MAX]u8,
	ctl_n:  int,
	// The client masks its frames, with a new key each from `rand`.
	masked: bool,
	rand:   proc "contextless" (buf: []u8) -> bool,
}

ws_out_init :: proc(o: ^Ws_Out, masked: bool) -> bool {
	o^ = {
		masked = masked,
		rand   = ossl.random_bytes,
	}
	o.buf = make([]u8, WS_OUT_SIZE)
	return o.buf != nil
}

ws_out_destroy :: proc(o: ^Ws_Out) {
	delete(o.buf)
	o^ = {}
}

// Forget what is staged (a new attempt).
ws_out_reset :: proc(o: ^Ws_Out) {
	o.head, o.tail, o.ctl_n = 0, 0, 0
}

// Staged bytes that the socket (or the TLS link) has not taken.
ws_out_pending :: proc(o: ^Ws_Out) -> int {
	return o.tail - o.head
}

// Is something waiting that is not stream bytes?
ws_out_has_ctl :: proc(o: ^Ws_Out) -> bool {
	return o.ctl_n > 0
}

@(private = "file")
out_key :: proc(o: ^Ws_Out) -> (key: Maybe([4]u8), ok: bool) {
	if !o.masked {
		return nil, true
	}
	k: [4]u8
	if !o.rand(k[:]) {
		return nil, false
	}
	return k, true
}

// Stages the next frame if none is staged: a waiting control frame first, else
// up to `WS_FRAME_MAX` bytes of `src`. Returns bytes of `src` taken (0 for a
// control frame or nothing). `ok` false: no key could be generated. Staged bytes:
// `buf[head:tail]`.
ws_out_next :: proc(o: ^Ws_Out, src: []u8) -> (used: int, ok: bool) {
	if o.tail > o.head {
		return 0, true
	}
	o.head, o.tail = 0, 0
	if o.ctl_n > 0 {
		copy(o.buf, o.ctl[:o.ctl_n])
		o.tail = o.ctl_n
		o.ctl_n = 0
		return 0, true
	}
	if len(src) == 0 {
		return 0, true
	}
	n := min(len(src), WS_FRAME_MAX)
	key, kok := out_key(o)
	if !kok {
		return 0, false
	}
	h := ws_header(o.buf, WS_OP_BINARY, n, key)
	if k, masked := key.?; masked {
		ws_mask_copy(o.buf[h:][:n], src[:n], k)
	} else {
		copy(o.buf[h:], src[:n])
	}
	o.tail = h + n
	return n, true
}

// Queues a control frame (it replaces one that is still waiting). `payload` is
// at most 125 bytes. False when no key could be generated.
ws_out_ctl :: proc(o: ^Ws_Out, opcode: u8, payload: []u8) -> bool {
	n := min(len(payload), WS_CTL_MAX)
	key, ok := out_key(o)
	if !ok {
		return false
	}
	h := ws_header(o.ctl[:], opcode, n, key)
	if k, masked := key.?; masked {
		ws_mask_copy(o.ctl[h:][:n], payload[:n], k)
	} else {
		copy(o.ctl[h:], payload[:n])
	}
	o.ctl_n = h + n
	return true
}

// The bytes of `buf` that follow a close frame of status 1000.
ws_close_payload :: proc() -> [2]u8 {
	return {0x03, 0xe8}
}

// ---------------------------------------------------------- the HTTP header

Http_Head :: enum u8 {
	Need_More, // the blank line has not come
	Done,
	Too_Long, // no blank line within `WS_HEADER_MAX` bytes
}

// Finds the end of an HTTP header in `buf`: the blank line. `end` counts the
// bytes up to and including it. A line ends at "\n", a "\r" before it is dropped.
http_head_end :: proc(buf: []u8) -> (end: int, st: Http_Head) {
	start := 0
	first := true
	for start < len(buf) {
		nl := -1
		for i in start ..< len(buf) {
			if buf[i] == '\n' {
				nl = i
				break
			}
		}
		if nl < 0 {
			break
		}
		line := nl - start
		if line > 0 && buf[nl - 1] == '\r' {
			line -= 1
		}
		start = nl + 1
		if line == 0 && !first {
			if start > WS_HEADER_MAX {
				return 0, .Too_Long
			}
			return start, .Done
		}
		first = false
	}
	if len(buf) >= WS_HEADER_MAX {
		return 0, .Too_Long
	}
	return 0, .Need_More
}

// The value of the first header `name` of `head` (the header text without the
// first line), trimmed. Names are compared without regard to case.
@(private = "file")
head_value :: proc(head, name: string) -> (value: string, found: bool) {
	rest := head
	for rest != "" {
		line := rest
		if nl := strings.index_byte(rest, '\n'); nl >= 0 {
			line, rest = rest[:nl], rest[nl + 1:]
		} else {
			rest = ""
		}
		line = strings.trim_right(line, "\r")
		colon := strings.index_byte(line, ':')
		if colon > 0 && strings.equal_fold(strings.trim_space(line[:colon]), name) {
			return strings.trim_space(line[colon + 1:]), true
		}
	}
	return "", false
}

// Does some header `name` hold the token `token` in its comma separated list?
@(private = "file")
head_has_token :: proc(head, name, token: string) -> bool {
	rest := head
	for rest != "" {
		line := rest
		if nl := strings.index_byte(rest, '\n'); nl >= 0 {
			line, rest = rest[:nl], rest[nl + 1:]
		} else {
			rest = ""
		}
		line = strings.trim_right(line, "\r")
		colon := strings.index_byte(line, ':')
		if colon <= 0 || !strings.equal_fold(strings.trim_space(line[:colon]), name) {
			continue
		}
		list := line[colon + 1:]
		for list != "" {
			part := list
			if c := strings.index_byte(list, ','); c >= 0 {
				part, list = list[:c], list[c + 1:]
			} else {
				list = ""
			}
			if strings.equal_fold(strings.trim_space(part), token) {
				return true
			}
		}
	}
	return false
}

// The text after the first line of a header (up to the blank line), and the
// first line.
@(private = "file")
head_split :: proc(text: string) -> (first, rest: string) {
	nl := strings.index_byte(text, '\n')
	if nl < 0 {
		return strings.trim_right(text, "\r"), ""
	}
	return strings.trim_right(text[:nl], "\r"), text[nl + 1:]
}

// ------------------------------------------------------------ the handshake

// A new `Sec-WebSocket-Key`: 16 random bytes in base64 (24 characters).
ws_new_key :: proc(rand: proc "contextless" (buf: []u8) -> bool) -> (key: [24]u8, ok: bool) {
	raw: [16]u8
	if !rand(raw[:]) {
		return {}, false
	}
	out, err := base64.encode_into_buf(key[:], raw[:])
	return key, err == nil && len(out) == 24
}

// base64(SHA-1(key + GUID)): the `Sec-WebSocket-Accept` that responds to `key`.
ws_accept_key :: proc(key: string) -> (accept: [28]u8) {
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]u8)key)
	sha1.update(&ctx, transmute([]u8)string(WS_GUID))
	digest: [sha1.DIGEST_SIZE]u8
	sha1.final(&ctx, digest[:])
	base64.encode_into_buf(accept[:], digest[:])
	return
}

// The `Host` header value: the name, and the port when it is not 443. An IPv6
// literal goes in brackets.
ws_host_header :: proc(host: string, port: u16, allocator := context.allocator) -> string {
	h := host
	if strings.contains_rune(h, ':') && !strings.has_prefix(h, "[") {
		h = fmt.tprintf("[%s]", h)
	}
	if port == 443 {
		return strings.clone(h, allocator)
	}
	return fmt.aprintf("%s:%d", h, port, allocator = allocator)
}

// True if `s` can be part of a header line.
@(private = "file")
ws_text_ok :: proc(s: string) -> bool {
	for c in transmute([]u8)s {
		if c <= 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// Is this a path for `tls-transport-ws`: starts with `/`, at most 255 bytes, no
// space or control character.
ws_path_ok :: proc(path: string) -> bool {
	return len(path) >= 1 && len(path) <= WS_PATH_MAX && path[0] == '/' && ws_text_ok(path)
}

// User-Agent of the `chrome` profile. Update the version now and then: keep it a
// current Chrome (same major version as the TLS ClientHello the profile copies).
WS_CHROME_USER_AGENT :: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

// The upgrade request of a client.
// `host` is the full `Host` value. `chrome` sends the headers of a Chrome
// WebSocket, in its order. The server reads only what it needs. No
// `permessage-deflate`: the reply has no `Sec-WebSocket-Extensions`, frames are
// never compressed.
ws_request_build :: proc(path, host: string, key: []u8, allocator := context.allocator, hello := config.Tls_Hello.Default) -> (out: []u8, ok: bool) {
	if !ws_path_ok(path) || host == "" || !ws_text_ok(host) || len(key) != 24 {
		return nil, false
	}
	if hello == .Chrome {
		chrome := fmt.aprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nUser-Agent: %s\r\nUpgrade: websocket\r\nOrigin: https://%s\r\nSec-WebSocket-Version: 13\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n",
			path,
			host,
			WS_CHROME_USER_AGENT,
			host,
			string(key),
			allocator = allocator,
		)
		return transmute([]u8)chrome, true
	}
	text := fmt.aprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path,
		host,
		string(key),
		allocator = allocator,
	)
	return transmute([]u8)text, true
}

Ws_Reply :: enum u8 {
	Ok, // 101, upgrade, and the right accept key
	Refused, // another status: `status_line` says which
	Not_Http, // the first line is not a status line
	Not_Upgrade, // 101, but not `Upgrade: websocket` and `Connection: upgrade`
	Bad_Accept, // the accept key is missing or wrong
}

// Checks the header of the reply to a request with `key`. `header` is the bytes
// up to the blank line. `status_line` is the first line, for the log.
ws_reply_check :: proc(header: []u8, key: []u8) -> (res: Ws_Reply, status_line: string) {
	first, rest := head_split(string(header))
	r: Proxy_Reply
	if !proxy_status_line(first, &r) {
		return .Not_Http, ""
	}
	if r.code != 101 {
		return .Refused, strings.trim_space(first)
	}
	up, has_up := head_value(rest, "upgrade")
	if !has_up || !strings.equal_fold(up, "websocket") || !head_has_token(rest, "connection", "upgrade") {
		return .Not_Upgrade, first
	}
	got, has_acc := head_value(rest, "sec-websocket-accept")
	want := ws_accept_key(string(key))
	if !has_acc || got != string(want[:]) {
		return .Bad_Accept, first
	}
	return .Ok, first
}

// What a server says to a request.
Ws_Verdict :: enum u8 {
	Accept, // 101
	Bad_Path, // 404
	Not_Upgrade, // 400: not a WebSocket upgrade (or no key)
	Bad_Version, // 426
}

Ws_Request :: struct {
	verdict: Ws_Verdict,
	// The key, to reply with the accept key (Accept only). Points into the header.
	key:     string,
	// Bad_Version: the version the client asked for.
	version: string,
	// The request target as the client wrote it (for the log). Points into the header.
	target:  string,
}

// Checks the header of a request (the bytes up to the blank line) against the
// path of `tls-transport-ws`.
ws_request_check :: proc(header: []u8, path: string) -> Ws_Request {
	first, rest := head_split(string(header))
	// `GET PATH HTTP/1.1`
	parts: [3]string
	n := 0
	line := first
	for n < 3 && line != "" {
		sp := strings.index_byte(line, ' ')
		if sp < 0 {
			parts[n] = line
			n += 1
			line = ""
			break
		}
		parts[n] = line[:sp]
		n += 1
		line = strings.trim_left(line[sp:], " ")
	}
	if n != 3 || parts[0] != "GET" || !strings.has_prefix(parts[2], "HTTP/1.") {
		return {verdict = .Not_Upgrade, target = parts[1]}
	}
	if parts[1] != path {
		return {verdict = .Bad_Path, target = parts[1]}
	}
	up, has_up := head_value(rest, "upgrade")
	key, has_key := head_value(rest, "sec-websocket-key")
	version, has_ver := head_value(rest, "sec-websocket-version")
	if !has_up || !strings.equal_fold(up, "websocket") || !head_has_token(rest, "connection", "upgrade") || !has_key || key == "" || !has_ver {
		return {verdict = .Not_Upgrade, target = parts[1]}
	}
	if version != "13" {
		return {verdict = .Bad_Version, version = version, target = parts[1]}
	}
	return {verdict = .Accept, key = key, target = parts[1]}
}

// The 101 reply for a request with `key`.
ws_reply_build :: proc(key: string, allocator := context.allocator) -> []u8 {
	accept := ws_accept_key(key)
	text := fmt.aprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", string(accept[:]), allocator = allocator)
	return transmute([]u8)text
}

// The refusals: no body, and the connection closes.
WS_REPLY_404 :: "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
WS_REPLY_400 :: "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
WS_REPLY_426 :: "HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"

ws_refusal :: proc(v: Ws_Verdict) -> string {
	switch v {
	case .Accept:
		return ""
	case .Bad_Path:
		return WS_REPLY_404
	case .Not_Upgrade:
		return WS_REPLY_400
	case .Bad_Version:
		return WS_REPLY_426
	}
	return WS_REPLY_400
}

// What the first bytes of a plaintext stream say on a listener that may serve
// WebSocket clients.
Plain_Bytes :: enum u8 {
	Need_More, // the bytes so far are a prefix of "GET " and too few to tell
	Http, // "GET ": an HTTP request
	Raw, // anything else: the OpenVPN TCP framing
}

// An HTTP request starts with `GET `. OpenVPN framing starts with a 2-byte
// length: "GE" is 0x4745 = 18245, above the framing packet cap (the server
// refuses packets far below that), so no raw stream starts that way.
classify_plain :: proc "contextless" (b: []u8) -> Plain_Bytes {
	GET := [4]u8{'G', 'E', 'T', ' '}
	for i in 0 ..< min(len(b), 4) {
		if b[i] != GET[i] {
			return .Raw
		}
	}
	return .Http if len(b) >= 4 else .Need_More
}
