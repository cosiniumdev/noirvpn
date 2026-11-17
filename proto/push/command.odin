// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

// Text commands inside TLS.
// - One command is one NUL-terminated string, written with one TLS write.
// - A reader gets whatever TLS plaintext arrived: several commands, or a command
//   whose NUL comes later. `Cmd_Reader` splits that.

// A sender never exceeds this for AUTH_FAILED, AUTH_PENDING, INFO_PRE and each
// PUSH_REPLY message. It counts the
// NUL.
CMD_SEND_MAX_LEN :: 1024

// ---------------------------------------------------------------- framing

// True if every byte is allowed in a command: 0x20 and up, except 0x7F.
// Bytes from 0x80 up are fine (UTF-8).
cmd_bytes_ok :: proc "contextless" (text: string) -> bool {
	for c in transmute([]u8)text {
		if c < 0x20 || c == 0x7F {
			return false
		}
	}
	return true
}

// Writes `text` and its closing NUL into `buf`. Returns the bytes written.
// `max_len` bounds the length with the NUL. Use `CMD_SEND_MAX_LEN` for the
// commands that have that limit.
cmd_frame :: proc(buf: []u8, text: string, max_len := MAX_COMMAND_LEN) -> (n: int, err: Error) {
	if !cmd_bytes_ok(text) {
		return 0, .Bad_Byte
	}
	if len(text) + 1 > max_len {
		return 0, .Oversize
	}
	if len(buf) < len(text) + 1 {
		return 0, .Buffer_Too_Small
	}
	copy(buf, text)
	buf[len(text)] = 0
	return len(text) + 1, .None
}

Cmd_Status :: enum u8 {
	// All bytes were taken and no command is complete yet.
	Need_More,
	// A command is ready (`text`). Call again for the rest of the bytes.
	Command,
	// A complete command was dropped because it held a control byte. The
	// stock peers log a warning and go on.
	Dropped,
	// More than 2047 bytes without a NUL. The stream is broken.
	Oversize,
}

// Splits TLS plaintext into commands. Holds up to one partial command.
Cmd_Reader :: struct {
	buf: [MAX_COMMAND_LEN]u8,
	len: int,
}

cmd_reader_reset :: proc "contextless" (r: ^Cmd_Reader) {
	r.len = 0
}

// Bytes held for a command that has no NUL yet.
cmd_reader_pending :: proc "contextless" (r: ^Cmd_Reader) -> int {
	return r.len
}

// Takes bytes from the front of `data` (and shortens it) until one command is
// complete or the data runs out.
//
//	rest := tls_plaintext
//	for len(rest) > 0 {
//		text, st := cmd_reader_next(&r, &rest)
//		switch st { ... }
//	}
//
// - `text` is a slice of the reader, valid until the next call.
// - A trailing `\r` or `\n` is removed.
// - After `.Oversize` no resync is possible: reset the reader, close the session.
cmd_reader_next :: proc(r: ^Cmd_Reader, data: ^[]u8) -> (text: string, st: Cmd_Status) {
	for i in 0 ..< len(data^) {
		c := data^[i]
		if c == 0 {
			data^ = data^[i + 1:]
			n := r.len
			r.len = 0
			for n > 0 && (r.buf[n - 1] == '\n' || r.buf[n - 1] == '\r') {
				n -= 1
			}
			text = string(r.buf[:n])
			if !cmd_bytes_ok(text) {
				return "", .Dropped
			}
			return text, .Command
		}
		if r.len >= MAX_COMMAND_LEN - 1 {
			data^ = data^[i:]
			return "", .Oversize
		}
		r.buf[r.len] = c
		r.len += 1
	}
	data^ = data^[len(data^):]
	return "", .Need_More
}

// ---------------------------------------------------------------- dispatch

Command_Kind :: enum u8 {
	Unknown,
	Auth_Failed,
	Push_Request,
	Push_Reply,
	Push_Update,
	Restart,
	Halt,
	Info_Pre,
	Info,
	Cr_Response,
	Auth_Pending,
	Acc,
	Exit,
}

// Finds the command by the start of the text, in spec order.
// `INFO_PRE` comes before `INFO`. The `PUSH_` family matches by exact
// name: a comma or the end of the text must follow. Else `.Unknown`.
command_kind :: proc "contextless" (text: string) -> Command_Kind {
	starts :: proc "contextless" (s, prefix: string) -> bool {
		return len(s) >= len(prefix) && s[:len(prefix)] == prefix
	}
	named :: proc "contextless" (s, name: string) -> bool {
		if !starts(s, name) {
			return false
		}
		return len(s) == len(name) || s[len(name)] == ','
	}
	switch {
	case starts(text, "AUTH_FAILED"):
		return .Auth_Failed
	case named(text, "PUSH_REQUEST"):
		return .Push_Request
	case named(text, "PUSH_REPLY"):
		return .Push_Reply
	case named(text, "PUSH_UPDATE"):
		return .Push_Update
	case starts(text, "RESTART"):
		return .Restart
	case starts(text, "HALT"):
		return .Halt
	case starts(text, "INFO_PRE"):
		return .Info_Pre
	case starts(text, "INFO"):
		return .Info
	case starts(text, "CR_RESPONSE"):
		return .Cr_Response
	case starts(text, "AUTH_PENDING"):
		return .Auth_Pending
	case starts(text, "ACC"):
		return .Acc
	case starts(text, "EXIT"):
		return .Exit
	}
	return .Unknown
}

// True if a receiver with this role acts on the command.
// A command in the wrong direction is ignored.
command_for_receiver :: proc "contextless" (k: Command_Kind, receiver: Role) -> bool {
	switch k {
	case .Unknown:
		return false
	case .Push_Request, .Cr_Response, .Exit:
		return receiver == .Server
	case .Acc:
		return true // both ways; noirvpn ignores it
	case .Push_Reply, .Push_Update, .Auth_Failed, .Restart, .Halt, .Info_Pre, .Info, .Auth_Pending:
		return receiver == .Client
	}
	return false
}

// ------------------------------------------------------------ typed forms

Push_Request :: struct {}

// `PUSH_REPLY,<options>`. `options` is the text after the first comma, as
// one string (see `pushed.odin`). Empty for a bare `PUSH_REPLY`.
Push_Reply_Msg :: struct {
	options: string,
}

// `PUSH_UPDATE,<options>`; same definition.
Push_Update_Msg :: struct {
	options: string,
}

Auth_Failed_Kind :: enum u8 {
	// `AUTH_FAILED` with nothing after it.
	Plain,
	// `AUTH_FAILED,<text>`.
	Reason,
	// `AUTH_FAILED,SESSION`: drop the auth-token and log in again.
	Session,
	// `AUTH_FAILED,TEMP[...]: text`.
	Temp,
	// `AUTH_FAILED,CRV1:...` (dynamic challenge; not supported).
	Crv1,
}

Temp_Advance :: enum u8 {
	Unset,
	No, // `advance no`: stay on the same remote and address
	Addr, // `advance addr`: next address of the same remote
	Remote, // `advance remote`: next remote
}

Auth_Temp :: struct {
	// Seconds to wait; 0 if not given or not a valid number.
	backoff:         int,
	advance:         Temp_Advance,
	// Flags that were unknown or had a bad value (ignored, as a stock client does).
	bad_flags:       int,
	// A `[` with no closing `]`.
	flags_malformed: bool,
}

Auth_Crv1 :: struct {
	flags:     string, // comma separated letters R and E
	state_id:  string,
	user_b64:  string,
	challenge: string,
}

Auth_Failed :: struct {
	kind:   Auth_Failed_Kind,
	// Reason text: the free text for `.Reason`, the message after the colon
	// for `.Temp`.
	reason: string,
	temp:   Auth_Temp,
	crv1:   Auth_Crv1,
}

// `AUTH_PENDING` or `AUTH_PENDING,timeout N[,keyword...]`.
Auth_Pending :: struct {
	has_timeout:      bool,
	// Seconds. Meaningful only if `has_timeout`.
	timeout:          int,
	// Keywords this version does not know (ignored).
	unknown_keywords: int,
}

// `INFO,<text>` and `INFO_PRE,<text>`.
Info_Msg :: struct {
	pre:  bool,
	text: string,
}

// `CR_RESPONSE,<base64>`.
Cr_Response :: struct {
	response: string,
}

// RESTART and HALT share a form: `RESTART[,[<flags>] <text>]`.
Server_Signal :: struct {
	// Flag `P`: keep the cached credentials.
	keep_credentials: bool,
	// Flag `N`: go to the next remote before reconnecting.
	next_remote:      bool,
	// Another letter was present (ignored).
	unknown_flags:    bool,
	text:             string,
}

Restart :: distinct Server_Signal
Halt :: distinct Server_Signal

Exit_Cmd :: struct {}

// `ACC...` (custom control channel). noirvpn ignores it.
Acc_Cmd :: struct {
	text: string,
}

Unknown_Cmd :: struct {
	text: string,
}

Command :: union {
	Unknown_Cmd,
	Push_Request,
	Push_Reply_Msg,
	Push_Update_Msg,
	Auth_Failed,
	Auth_Pending,
	Info_Msg,
	Cr_Response,
	Restart,
	Halt,
	Exit_Cmd,
	Acc_Cmd,
}

// Text after the command name: past one comma if there is one. Without a
// comma, whatever follows the name is the text (stock matches by prefix, so
// `AUTH_FAILED: oops` is still an AUTH_FAILED).
@(private)
after_name :: proc "contextless" (text: string, name: string) -> string {
	rest := text[len(name):]
	if len(rest) > 0 && rest[0] == ',' {
		return rest[1:]
	}
	return rest
}

// Parses one command (without its NUL). `receiver` is the role of the reading
// side.
// - Wrong direction: the parsed value with `.Wrong_Direction`; the caller
//   ignores it.
// - Unknown command: `Unknown_Cmd` with `.None`; log it and carry on.
// The text must already have passed the framing checks (`Cmd_Reader` does).
command_parse :: proc(text: string, receiver: Role) -> (cmd: Command, err: Error) {
	kind := command_kind(text)
	switch kind {
	case .Unknown:
		return Unknown_Cmd{text}, .None
	case .Push_Request:
		cmd = Push_Request{}
	case .Push_Reply:
		cmd = Push_Reply_Msg{after_name(text, "PUSH_REPLY")}
	case .Push_Update:
		cmd = Push_Update_Msg{after_name(text, "PUSH_UPDATE")}
	case .Auth_Failed:
		cmd = parse_auth_failed(after_name(text, "AUTH_FAILED"))
	case .Auth_Pending:
		cmd = parse_auth_pending(after_name(text, "AUTH_PENDING"))
	case .Info_Pre:
		cmd = Info_Msg{true, after_name(text, "INFO_PRE")}
	case .Info:
		cmd = Info_Msg{false, after_name(text, "INFO")}
	case .Cr_Response:
		cmd = Cr_Response{after_name(text, "CR_RESPONSE")}
	case .Restart:
		cmd = Restart(parse_server_signal(after_name(text, "RESTART")))
	case .Halt:
		cmd = Halt(parse_server_signal(after_name(text, "HALT")))
	case .Exit:
		cmd = Exit_Cmd{}
	case .Acc:
		cmd = Acc_Cmd{text}
	}
	if !command_for_receiver(kind, receiver) {
		return cmd, .Wrong_Direction
	}
	return cmd, .None
}

@(private)
parse_server_signal :: proc "contextless" (t: string) -> (s: Server_Signal) {
	// `[<flags>] <text>`: the flags are letters in brackets before the text.
	if len(t) > 0 && t[0] == '[' {
		close := -1
		for c, i in transmute([]u8)t {
			if c == ']' {
				close = i
				break
			}
		}
		if close > 0 {
			for c in transmute([]u8)t[1:close] {
				switch c {
				case 'P':
					s.keep_credentials = true
				case 'N':
					s.next_remote = true
				case:
					s.unknown_flags = true
				}
			}
			rest := t[close + 1:]
			if len(rest) > 0 && rest[0] == ' ' {
				rest = rest[1:]
			}
			s.text = rest
			return
		}
	}
	s.text = t
	return
}

@(private)
parse_auth_failed :: proc "contextless" (t: string) -> (a: Auth_Failed) {
	if len(t) == 0 {
		a.kind = .Plain
		return
	}
	if t == "SESSION" {
		a.kind = .Session
		return
	}
	if len(t) >= 4 && t[:4] == "TEMP" {
		a.kind = .Temp
		parse_temp(t[4:], &a)
		return
	}
	if len(t) >= 5 && t[:5] == "CRV1:" {
		if crv1, ok := parse_crv1(t[5:]); ok {
			a.kind = .Crv1
			a.crv1 = crv1
			a.reason = t
			return
		}
	}
	a.kind = .Reason
	a.reason = t
	return
}

// After `TEMP`: an optional `[flags]`, then an optional `:` and a message.
@(private)
parse_temp :: proc "contextless" (t: string, a: ^Auth_Failed) {
	rest := t
	if len(rest) > 0 && rest[0] == '[' {
		close := -1
		for c, i in transmute([]u8)rest {
			if c == ']' {
				close = i
				break
			}
		}
		if close < 0 {
			// SPEC-GAP: the spec does not say what an unclosed bracket means.
			// Treat it as TEMP with no flags; the rest is the message.
			a.temp.flags_malformed = true
			rest = rest[1:]
		} else {
			parse_temp_flags(rest[1:close], &a.temp)
			rest = rest[close + 1:]
		}
	}
	if len(rest) > 0 && rest[0] == ':' {
		rest = rest[1:]
	}
	if len(rest) > 0 && rest[0] == ' ' {
		rest = rest[1:]
	}
	a.reason = rest
}

@(private)
parse_temp_flags :: proc "contextless" (flags: string, t: ^Auth_Temp) {
	rest := flags
	for len(rest) > 0 {
		comma := -1
		for c, i in transmute([]u8)rest {
			if c == ',' {
				comma = i
				break
			}
		}
		item: string
		if comma < 0 {
			item, rest = rest, ""
		} else {
			item, rest = rest[:comma], rest[comma + 1:]
		}
		if len(item) == 0 {
			continue
		}
		switch {
		case len(item) > 8 && item[:8] == "backoff ":
			if v, ok := parse_uint_max(item[8:], 0x7FFFFFFF); ok {
				t.backoff = int(v)
			} else {
				t.bad_flags += 1 // stock: invalid backoff is ignored (0)
			}
		case len(item) > 8 && item[:8] == "advance ":
			switch item[8:] {
			case "no":
				t.advance = .No
			case "addr":
				t.advance = .Addr
			case "remote":
				t.advance = .Remote
			case:
				t.bad_flags += 1
			}
		case:
			t.bad_flags += 1
		}
	}
}

// `<flags>:<state_id>:<user_b64>:<challenge>`. The challenge may hold colons.
@(private)
parse_crv1 :: proc "contextless" (t: string) -> (c: Auth_Crv1, ok: bool) {
	rest := t
	fields: [3]string
	for k in 0 ..< 3 {
		colon := -1
		for ch, i in transmute([]u8)rest {
			if ch == ':' {
				colon = i
				break
			}
		}
		if colon < 0 {
			return {}, false
		}
		fields[k] = rest[:colon]
		rest = rest[colon + 1:]
	}
	return Auth_Crv1{flags = fields[0], state_id = fields[1], user_b64 = fields[2], challenge = rest}, true
}

@(private)
parse_auth_pending :: proc "contextless" (t: string) -> (a: Auth_Pending) {
	rest := t
	for len(rest) > 0 {
		comma := -1
		for c, i in transmute([]u8)rest {
			if c == ',' {
				comma = i
				break
			}
		}
		item: string
		if comma < 0 {
			item, rest = rest, ""
		} else {
			item, rest = rest[:comma], rest[comma + 1:]
		}
		if len(item) == 0 {
			continue
		}
		if len(item) > 8 && item[:8] == "timeout " {
			if v, ok := parse_uint_max(item[8:], 0x7FFFFFFF); ok && !a.has_timeout {
				a.has_timeout = true
				a.timeout = int(v)
				continue
			}
		}
		a.unknown_keywords += 1
	}
	return
}

// ----------------------------------------------------------- INFO_PRE text

Info_Pre_Kind :: enum u8 {
	Unknown,
	Web_Auth, // `WEB_AUTH:<flags>:<url>`
	Open_Url, // `OPEN_URL:<url>` (old form)
	Cr_Text, // `CR_TEXT:<flags>:<challenge>`
	Notify, // `NOTIFY:<flags>:<text>`
}

Info_Pre :: struct {
	kind:  Info_Pre_Kind,
	flags: string,
	// URL, challenge or notification text.
	text:  string,
}

// Reads the typed text of an `INFO_PRE` message. A conforming server sends
// `WEB_AUTH` and `OPEN_URL` only to a client that sent `IV_SSO`.
info_pre_parse :: proc "contextless" (text: string) -> (p: Info_Pre) {
	colon := -1
	for c, i in transmute([]u8)text {
		if c == ':' {
			colon = i
			break
		}
	}
	if colon < 0 {
		return Info_Pre{kind = .Unknown, text = text}
	}
	key, rest := text[:colon], text[colon + 1:]
	if key == "OPEN_URL" {
		return Info_Pre{kind = .Open_Url, text = rest}
	}
	kind: Info_Pre_Kind
	switch key {
	case "WEB_AUTH":
		kind = .Web_Auth
	case "CR_TEXT":
		kind = .Cr_Text
	case "NOTIFY":
		kind = .Notify
	case:
		return Info_Pre{kind = .Unknown, text = text}
	}
	// `<flags>:<text>`. The text may hold colons (a URL does).
	c2 := -1
	for c, i in transmute([]u8)rest {
		if c == ':' {
			c2 = i
			break
		}
	}
	if c2 < 0 {
		return Info_Pre{kind = kind, text = rest}
	}
	return Info_Pre{kind = kind, flags = rest[:c2], text = rest[c2 + 1:]}
}

// ------------------------------------------------------------ format

// The formatters write the command and its NUL into `buf` and return the
// length. Each one checks the 1024-byte limit where the spec sets one.

format_push_request :: proc(buf: []u8) -> (n: int, err: Error) {
	return cmd_frame(buf, "PUSH_REQUEST")
}

format_exit :: proc(buf: []u8) -> (n: int, err: Error) {
	return cmd_frame(buf, "EXIT")
}

// `PUSH_REPLY,<options>` for already joined options (the builder in
// reply_build.odin builds the parts and the continuation).
format_push_reply_text :: proc(buf: []u8, options: string) -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, "PUSH_REPLY")
	if len(options) > 0 {
		wr_byte(&w, ',')
		wr_str(&w, options)
	}
	return finish_command(&w, CMD_SEND_MAX_LEN)
}

@(private)
finish_command :: proc(w: ^Wr, max_len: int) -> (n: int, err: Error) {
	if w.over {
		return 0, .Buffer_Too_Small
	}
	if !cmd_bytes_ok(string(w.buf[:w.n])) {
		return 0, .Bad_Byte
	}
	if w.n + 1 > max_len {
		return 0, .Oversize
	}
	if w.n >= len(w.buf) {
		return 0, .Buffer_Too_Small
	}
	w.buf[w.n] = 0
	return w.n + 1, .None
}

// `AUTH_FAILED` (empty reason) or `AUTH_FAILED,<reason>`.
format_auth_failed :: proc(buf: []u8, reason := "") -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, "AUTH_FAILED")
	if len(reason) > 0 {
		wr_byte(&w, ',')
		wr_str(&w, reason)
	}
	return finish_command(&w, CMD_SEND_MAX_LEN)
}

format_auth_failed_session :: proc(buf: []u8) -> (n: int, err: Error) {
	return cmd_frame(buf, "AUTH_FAILED,SESSION")
}

// `AUTH_FAILED,TEMP[backoff N,advance X]: message`. Send it only to a client
// with IV_PROTO bit 8. The bracket group is left out when no flag is set. The
// colon part is left out when `message` is empty.
format_auth_failed_temp :: proc(buf: []u8, backoff := 0, advance := Temp_Advance.Unset, message := "") -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, "AUTH_FAILED,TEMP")
	if backoff > 0 || advance != .Unset {
		wr_byte(&w, '[')
		if backoff > 0 {
			wr_str(&w, "backoff ")
			wr_uint(&w, u64(backoff))
		}
		if advance != .Unset {
			if backoff > 0 {
				wr_byte(&w, ',')
			}
			wr_str(&w, "advance ")
			switch advance {
			case .No:
				wr_str(&w, "no")
			case .Addr:
				wr_str(&w, "addr")
			case .Remote:
				wr_str(&w, "remote")
			case .Unset:
			}
		}
		wr_byte(&w, ']')
	}
	if len(message) > 0 {
		wr_str(&w, ": ")
		wr_str(&w, message)
	}
	return finish_command(&w, CMD_SEND_MAX_LEN)
}

// `AUTH_PENDING,timeout N` for a client with IV_PROTO bit 4, or a bare
// `AUTH_PENDING` otherwise.
format_auth_pending :: proc(buf: []u8, timeout: int, keyword_form: bool) -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, "AUTH_PENDING")
	if keyword_form {
		if timeout < 0 {
			return 0, .Bad_Argument
		}
		wr_str(&w, ",timeout ")
		wr_uint(&w, u64(timeout))
	}
	return finish_command(&w, CMD_SEND_MAX_LEN)
}

format_info :: proc(buf: []u8, text: string) -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, "INFO,")
	wr_str(&w, text)
	return finish_command(&w, MAX_COMMAND_LEN)
}

format_info_pre :: proc(buf: []u8, text: string) -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, "INFO_PRE,")
	wr_str(&w, text)
	return finish_command(&w, CMD_SEND_MAX_LEN)
}

// `CR_RESPONSE,<base64>`. The caller has already encoded the response.
format_cr_response :: proc(buf: []u8, response_b64: string) -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, "CR_RESPONSE,")
	wr_str(&w, response_b64)
	return finish_command(&w, MAX_COMMAND_LEN)
}

// `RESTART`, or `RESTART,text`, or `RESTART,[PN] text` (HALT the same).
// - `P`: the client keeps its credentials. `N`: it moves to the next remote.
// - The bracket group comes before the text, in the same string.
// - Flags and no text: `RESTART,[N]`, as a stock server sends it.
format_restart :: proc(buf: []u8, text := "", keep_credentials := false, next_remote := false) -> (n: int, err: Error) {
	return format_signal(buf, "RESTART", text, keep_credentials, next_remote)
}

format_halt :: proc(buf: []u8, text := "", keep_credentials := false, next_remote := false) -> (n: int, err: Error) {
	return format_signal(buf, "HALT", text, keep_credentials, next_remote)
}

@(private)
format_signal :: proc(buf: []u8, name: string, text: string, keep: bool, next: bool) -> (n: int, err: Error) {
	w := Wr{buf = buf}
	wr_str(&w, name)
	if keep || next || len(text) > 0 {
		wr_byte(&w, ',')
		if keep || next {
			wr_byte(&w, '[')
			if keep {
				wr_byte(&w, 'P')
			}
			if next {
				wr_byte(&w, 'N')
			}
			wr_byte(&w, ']')
			if len(text) > 0 {
				wr_byte(&w, ' ')
			}
		}
		wr_str(&w, text)
	}
	return finish_command(&w, MAX_COMMAND_LEN)
}
