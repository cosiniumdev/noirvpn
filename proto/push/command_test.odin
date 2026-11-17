// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:testing"

// Reads every command from `data` with a reader.
read_all :: proc(r: ^Cmd_Reader, data: []u8, out: ^[dynamic]string) -> (dropped: int, err: Cmd_Status) {
	rest := data
	for len(rest) > 0 {
		text, st := cmd_reader_next(r, &rest)
		switch st {
		case .Need_More:
		case .Command:
			append(out, string(clone_bytes(text)))
		case .Dropped:
			dropped += 1
		case .Oversize:
			return dropped, .Oversize
		}
	}
	return dropped, .Need_More
}

clone_bytes :: proc(s: string) -> []u8 {
	b := make([]u8, len(s), context.temp_allocator)
	copy(b, s)
	return b
}

@(test)
cmd_frame_rules :: proc(t: ^testing.T) {
	buf: [64]u8
	n, err := cmd_frame(buf[:], "PUSH_REQUEST")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 13)
	testing.expect_value(t, buf[12], 0)
	testing.expect_value(t, string(buf[:12]), "PUSH_REQUEST")

	// Control bytes are refused, UTF-8 is fine.
	_, err = cmd_frame(buf[:], "a\x01b")
	testing.expect_value(t, err, Error.Bad_Byte)
	_, err = cmd_frame(buf[:], "a\x7fb")
	testing.expect_value(t, err, Error.Bad_Byte)
	_, err = cmd_frame(buf[:], "a\nb")
	testing.expect_value(t, err, Error.Bad_Byte)
	n, err = cmd_frame(buf[:], "caf\xc3\xa9 \xe2\x82\xac")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 10)
	// Sizes: the NUL counts.
	_, err = cmd_frame(buf[:4], "abcd")
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	_, err = cmd_frame(buf[:], "abcd", max_len = 4)
	testing.expect_value(t, err, Error.Oversize)
	n, err = cmd_frame(buf[:], "abc", max_len = 4)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 4)
	// The empty command is one NUL.
	n, err = cmd_frame(buf[:], "")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 1)
}

@(test)
cmd_reader_two_commands_in_one_read :: proc(t: ^testing.T) {
	r: Cmd_Reader
	out := make([dynamic]string, context.temp_allocator)
	_, st := read_all(&r, transmute([]u8)string("PUSH_REQUEST\x00EXIT\x00"), &out)
	testing.expect_value(t, st, Cmd_Status.Need_More)
	testing.expect_value(t, len(out), 2)
	testing.expect_value(t, out[0], "PUSH_REQUEST")
	testing.expect_value(t, out[1], "EXIT")
	testing.expect_value(t, cmd_reader_pending(&r), 0)
}

@(test)
cmd_reader_command_split_over_reads :: proc(t: ^testing.T) {
	r: Cmd_Reader
	out := make([dynamic]string, context.temp_allocator)
	msg := transmute([]u8)string("AUTH_FAILED,reason text\x00")
	for cut in 0 ..< len(msg) {
		clear(&out)
		cmd_reader_reset(&r)
		_, _ = read_all(&r, msg[:cut], &out)
		testing.expect_value(t, len(out), 0)
		testing.expect_value(t, cmd_reader_pending(&r), cut)
		_, _ = read_all(&r, msg[cut:], &out)
		testing.expect_value(t, len(out), 1)
		testing.expect_value(t, out[0], "AUTH_FAILED,reason text")
	}
	// One byte at a time.
	clear(&out)
	for i in 0 ..< len(msg) {
		_, _ = read_all(&r, msg[i:i + 1], &out)
	}
	testing.expect_value(t, len(out), 1)
}

@(test)
cmd_reader_strips_trailing_newline :: proc(t: ^testing.T) {
	// trailing CR and LF before the NUL are removed.
	r: Cmd_Reader
	out := make([dynamic]string, context.temp_allocator)
	_, _ = read_all(&r, transmute([]u8)string("AUTH_FAILED,SESSION\n\x00RESTART\r\n\x00EXIT\r\r\n\n\x00"), &out)
	testing.expect_value(t, len(out), 3)
	testing.expect_value(t, out[0], "AUTH_FAILED,SESSION")
	testing.expect_value(t, out[1], "RESTART")
	testing.expect_value(t, out[2], "EXIT")
	// A newline in the middle is a bad byte: the command is dropped.
	clear(&out)
	dropped, _ := read_all(&r, transmute([]u8)string("INFO,a\nb\x00EXIT\x00"), &out)
	testing.expect_value(t, dropped, 1)
	testing.expect_value(t, len(out), 1)
	testing.expect_value(t, out[0], "EXIT")
}

@(test)
cmd_reader_drops_control_bytes :: proc(t: ^testing.T) {
	r: Cmd_Reader
	out := make([dynamic]string, context.temp_allocator)
	for bad in ([]string{"A\x01B\x00", "A\x1fB\x00", "A\x7fB\x00", "\x08\x00"}) {
		dropped, _ := read_all(&r, transmute([]u8)bad, &out)
		testing.expectf(t, dropped == 1, "%q", bad)
	}
	testing.expect_value(t, len(out), 0)
	// UTF-8 is kept.
	_, _ = read_all(&r, transmute([]u8)string("INFO,caf\xc3\xa9\x00"), &out)
	testing.expect_value(t, len(out), 1)
	// A lone NUL is an empty command.
	clear(&out)
	_, _ = read_all(&r, []u8{0}, &out)
	testing.expect_value(t, len(out), 1)
	testing.expect_value(t, out[0], "")
}

@(test)
cmd_reader_oversize :: proc(t: ^testing.T) {
	r: Cmd_Reader
	out := make([dynamic]string, context.temp_allocator)
	// 2047 characters and a NUL is the largest command.
	b := make([]u8, MAX_COMMAND_LEN, context.temp_allocator)
	for i in 0 ..< MAX_COMMAND_LEN - 1 {
		b[i] = 'a'
	}
	b[MAX_COMMAND_LEN - 1] = 0
	_, st := read_all(&r, b, &out)
	testing.expect_value(t, st, Cmd_Status.Need_More)
	testing.expect_value(t, len(out), 1)
	testing.expect_value(t, len(out[0]), MAX_COMMAND_LEN - 1)
	// 2048 characters with no NUL: the stream is broken.
	cmd_reader_reset(&r)
	clear(&out)
	for i in 0 ..< MAX_COMMAND_LEN {
		b[i] = 'a'
	}
	_, st = read_all(&r, b, &out)
	testing.expect_value(t, st, Cmd_Status.Oversize)
	testing.expect_value(t, len(out), 0)
}

@(test)
command_dispatch_order :: proc(t: ^testing.T) {
	Case :: struct {
		text: string,
		kind: Command_Kind,
	}
	cases := []Case {
		{"AUTH_FAILED", .Auth_Failed},
		{"AUTH_FAILED,TEMP: x", .Auth_Failed},
		{"PUSH_REQUEST", .Push_Request},
		{"PUSH_REPLY", .Push_Reply},
		{"PUSH_REPLY,route 1.2.3.4", .Push_Reply},
		{"PUSH_UPDATE,-route", .Push_Update},
		{"PUSH_FOO", .Unknown},
		{"PUSH_REPLYX", .Unknown},
		{"PUSH_REQUESTX", .Unknown},
		{"PUSH_", .Unknown},
		{"RESTART", .Restart},
		{"RESTART,[N]", .Restart},
		{"HALT,bye", .Halt},
		{"INFO_PRE,WEB_AUTH::http://x", .Info_Pre},
		{"INFO,hello", .Info},
		{"INFO", .Info},
		{"CR_RESPONSE,YWJj", .Cr_Response},
		{"AUTH_PENDING", .Auth_Pending},
		{"AUTH_PENDING,timeout 30", .Auth_Pending},
		{"ACC,x", .Acc},
		{"EXIT", .Exit},
		{"", .Unknown},
		{"push_request", .Unknown},
		{"hello", .Unknown},
	}
	for c in cases {
		testing.expectf(t, command_kind(c.text) == c.kind, "%q: got %v, want %v", c.text, command_kind(c.text), c.kind)
	}
}

@(test)
command_directions :: proc(t: ^testing.T) {
	// A server acts on PUSH_REQUEST, CR_RESPONSE, EXIT; a client on the others.
	for k in ([]Command_Kind{.Push_Request, .Cr_Response, .Exit}) {
		testing.expect(t, command_for_receiver(k, .Server))
		testing.expect(t, !command_for_receiver(k, .Client))
	}
	for k in ([]Command_Kind{.Push_Reply, .Push_Update, .Auth_Failed, .Restart, .Halt, .Info_Pre, .Info, .Auth_Pending}) {
		testing.expect(t, command_for_receiver(k, .Client))
		testing.expect(t, !command_for_receiver(k, .Server))
	}
	testing.expect(t, !command_for_receiver(.Unknown, .Client))

	cmd, err := command_parse("AUTH_FAILED", .Server)
	testing.expect_value(t, err, Error.Wrong_Direction)
	_, is_af := cmd.(Auth_Failed)
	testing.expect(t, is_af)
	_, err = command_parse("PUSH_REQUEST", .Client)
	testing.expect_value(t, err, Error.Wrong_Direction)
	cmd, err = command_parse("FUTURE_THING,1", .Client)
	testing.expect_value(t, err, Error.None)
	u, is_unknown := cmd.(Unknown_Cmd)
	testing.expect(t, is_unknown)
	testing.expect_value(t, u.text, "FUTURE_THING,1")
}

@(test)
command_parse_push_family :: proc(t: ^testing.T) {
	cmd, err := command_parse("PUSH_REQUEST", .Server)
	testing.expect_value(t, err, Error.None)
	_, ok := cmd.(Push_Request)
	testing.expect(t, ok)

	cmd, err = command_parse("PUSH_REPLY,route 10.0.0.0 255.0.0.0,ping 5", .Client)
	testing.expect_value(t, err, Error.None)
	pr, pok := cmd.(Push_Reply_Msg)
	testing.expect(t, pok)
	testing.expect_value(t, pr.options, "route 10.0.0.0 255.0.0.0,ping 5")

	cmd, _ = command_parse("PUSH_REPLY", .Client)
	pr, pok = cmd.(Push_Reply_Msg)
	testing.expect(t, pok)
	testing.expect_value(t, pr.options, "")

	cmd, _ = command_parse("PUSH_UPDATE,-route 1.2.3.0,?dns search-domains a.b", .Client)
	pu, uok := cmd.(Push_Update_Msg)
	testing.expect(t, uok)
	testing.expect_value(t, pu.options, "-route 1.2.3.0,?dns search-domains a.b")
}

@(test)
command_parse_auth_failed :: proc(t: ^testing.T) {
	af :: proc(t: ^testing.T, text: string, loc := #caller_location) -> Auth_Failed {
		cmd, err := command_parse(text, .Client)
		testing.expect_value(t, err, Error.None, loc = loc)
		a, ok := cmd.(Auth_Failed)
		testing.expect(t, ok, "not an Auth_Failed", loc = loc)
		return a
	}
	a := af(t, "AUTH_FAILED")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Plain)
	a = af(t, "AUTH_FAILED,")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Plain)
	a = af(t, "AUTH_FAILED,Wrong password")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Reason)
	testing.expect_value(t, a.reason, "Wrong password")
	a = af(t, "AUTH_FAILED,SESSION")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Session)
	// A reason that only starts with SESSION is free text.
	a = af(t, "AUTH_FAILED,SESSION expired")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Reason)
	// Junk after the name with no comma is still an AUTH_FAILED.
	a = af(t, "AUTH_FAILED: oops")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Reason)
	testing.expect_value(t, a.reason, ": oops")

	// TEMP.
	a = af(t, "AUTH_FAILED,TEMP[backoff 30,advance addr]: server is busy")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Temp)
	testing.expect_value(t, a.temp.backoff, 30)
	testing.expect_value(t, a.temp.advance, Temp_Advance.Addr)
	testing.expect_value(t, a.reason, "server is busy")
	testing.expect_value(t, a.temp.bad_flags, 0)
	a = af(t, "AUTH_FAILED,TEMP[advance remote]")
	testing.expect_value(t, a.temp.advance, Temp_Advance.Remote)
	testing.expect_value(t, a.temp.backoff, 0)
	testing.expect_value(t, a.reason, "")
	a = af(t, "AUTH_FAILED,TEMP[advance no,backoff 5]:msg")
	testing.expect_value(t, a.temp.advance, Temp_Advance.No)
	testing.expect_value(t, a.temp.backoff, 5)
	testing.expect_value(t, a.reason, "msg")
	// No brackets: TEMP: message, and bare TEMP.
	a = af(t, "AUTH_FAILED,TEMP: try later")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Temp)
	testing.expect_value(t, a.reason, "try later")
	testing.expect_value(t, a.temp, Auth_Temp{})
	a = af(t, "AUTH_FAILED,TEMP")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Temp)
	testing.expect_value(t, a.reason, "")
	// Unknown flags and a bad backoff are ignored (counted).
	a = af(t, "AUTH_FAILED,TEMP[backoff x,advance sideways,wiggle 3,backoff 7]: hi")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Temp)
	testing.expect_value(t, a.temp.backoff, 7)
	testing.expect_value(t, a.temp.advance, Temp_Advance.Unset)
	testing.expect_value(t, a.temp.bad_flags, 3)
	// An unclosed bracket: TEMP with no flags.
	a = af(t, "AUTH_FAILED,TEMP[backoff 30: busy")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Temp)
	testing.expect(t, a.temp.flags_malformed)
	testing.expect_value(t, a.temp.backoff, 0)
	// A backoff too large for an int is ignored.
	a = af(t, "AUTH_FAILED,TEMP[backoff 99999999999]")
	testing.expect_value(t, a.temp.backoff, 0)
	testing.expect_value(t, a.temp.bad_flags, 1)

	// CRV1 challenge.
	a = af(t, "AUTH_FAILED,CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmw==:YWxpY2U=:Enter token: 1234")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Crv1)
	testing.expect_value(t, a.crv1.flags, "R,E")
	testing.expect_value(t, a.crv1.state_id, "Om01u7Fh4LrGBS7uh0SWmw==")
	testing.expect_value(t, a.crv1.user_b64, "YWxpY2U=")
	testing.expect_value(t, a.crv1.challenge, "Enter token: 1234")
	// A malformed challenge is plain text.
	a = af(t, "AUTH_FAILED,CRV1:R")
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Reason)
}

@(test)
command_parse_auth_pending_and_info :: proc(t: ^testing.T) {
	cmd, _ := command_parse("AUTH_PENDING", .Client)
	ap, ok := cmd.(Auth_Pending)
	testing.expect(t, ok)
	testing.expect(t, !ap.has_timeout)

	cmd, _ = command_parse("AUTH_PENDING,timeout 300", .Client)
	ap, _ = cmd.(Auth_Pending)
	testing.expect(t, ap.has_timeout)
	testing.expect_value(t, ap.timeout, 300)

	// More keywords may follow; unknown ones are ignored.
	cmd, _ = command_parse("AUTH_PENDING,timeout 60,future thing,other", .Client)
	ap, _ = cmd.(Auth_Pending)
	testing.expect_value(t, ap.timeout, 60)
	testing.expect_value(t, ap.unknown_keywords, 2)

	cmd, _ = command_parse("AUTH_PENDING,timeout nope", .Client)
	ap, _ = cmd.(Auth_Pending)
	testing.expect(t, !ap.has_timeout)
	testing.expect_value(t, ap.unknown_keywords, 1)

	cmd, _ = command_parse("INFO_PRE,WEB_AUTH::https://example.com/auth?id=1", .Client)
	im, iok := cmd.(Info_Msg)
	testing.expect(t, iok)
	testing.expect(t, im.pre)
	testing.expect_value(t, im.text, "WEB_AUTH::https://example.com/auth?id=1")
	p := info_pre_parse(im.text)
	testing.expect_value(t, p.kind, Info_Pre_Kind.Web_Auth)
	testing.expect_value(t, p.flags, "")
	testing.expect_value(t, p.text, "https://example.com/auth?id=1")

	p = info_pre_parse("WEB_AUTH:proxy=h;8080;dTE=;cDE=,hidden:https://x/y")
	testing.expect_value(t, p.flags, "proxy=h;8080;dTE=;cDE=,hidden")
	testing.expect_value(t, p.text, "https://x/y")
	p = info_pre_parse("OPEN_URL:https://old.example")
	testing.expect_value(t, p.kind, Info_Pre_Kind.Open_Url)
	testing.expect_value(t, p.text, "https://old.example")
	p = info_pre_parse("CR_TEXT:R,E:Enter the code")
	testing.expect_value(t, p.kind, Info_Pre_Kind.Cr_Text)
	testing.expect_value(t, p.flags, "R,E")
	p = info_pre_parse("NOTIFY:x:wait please")
	testing.expect_value(t, p.kind, Info_Pre_Kind.Notify)
	p = info_pre_parse("SOMETHING_NEW:a:b")
	testing.expect_value(t, p.kind, Info_Pre_Kind.Unknown)
	p = info_pre_parse("no colon at all")
	testing.expect_value(t, p.kind, Info_Pre_Kind.Unknown)

	// INFO with and without a comma.
	cmd, _ = command_parse("INFO", .Client)
	im, _ = cmd.(Info_Msg)
	testing.expect(t, !im.pre)
	testing.expect_value(t, im.text, "")
	cmd, _ = command_parse("INFO,hello world", .Client)
	im, _ = cmd.(Info_Msg)
	testing.expect_value(t, im.text, "hello world")

	err: Error
	cmd, err = command_parse("CR_RESPONSE,YWJj", .Server)
	testing.expect_value(t, err, Error.None)
	cr, cok := cmd.(Cr_Response)
	testing.expect(t, cok)
	testing.expect_value(t, cr.response, "YWJj")
}

@(test)
command_parse_restart_halt_exit :: proc(t: ^testing.T) {
	cmd, _ := command_parse("RESTART", .Client)
	r, ok := cmd.(Restart)
	testing.expect(t, ok)
	testing.expect_value(t, Server_Signal(r), Server_Signal{})

	cmd, _ = command_parse("RESTART,[N]", .Client)
	r, _ = cmd.(Restart)
	testing.expect(t, r.next_remote && !r.keep_credentials)
	testing.expect_value(t, r.text, "")

	cmd, _ = command_parse("RESTART,[PN] server is restarting", .Client)
	r, _ = cmd.(Restart)
	testing.expect(t, r.next_remote && r.keep_credentials)
	testing.expect_value(t, r.text, "server is restarting")

	cmd, _ = command_parse("RESTART,plain text", .Client)
	r, _ = cmd.(Restart)
	testing.expect(t, !r.next_remote && !r.keep_credentials)
	testing.expect_value(t, r.text, "plain text")

	// Unknown flag letters do not fail.
	cmd, _ = command_parse("RESTART,[QPZ] x", .Client)
	r, _ = cmd.(Restart)
	testing.expect(t, r.keep_credentials && r.unknown_flags)
	testing.expect_value(t, r.text, "x")

	// `[` with no `]` is text.
	cmd, _ = command_parse("RESTART,[N no end", .Client)
	r, _ = cmd.(Restart)
	testing.expect(t, !r.next_remote)
	testing.expect_value(t, r.text, "[N no end")

	cmd, _ = command_parse("HALT,[P] done", .Client)
	h, hok := cmd.(Halt)
	testing.expect(t, hok)
	testing.expect(t, h.keep_credentials)
	testing.expect_value(t, h.text, "done")

	err: Error
	cmd, err = command_parse("EXIT", .Server)
	testing.expect_value(t, err, Error.None)
	_, eok := cmd.(Exit_Cmd)
	testing.expect(t, eok)
	_, err = command_parse("EXIT", .Client)
	testing.expect_value(t, err, Error.Wrong_Direction)
}

@(test)
command_format_forms :: proc(t: ^testing.T) {
	buf: [2048]u8
	check :: proc(t: ^testing.T, buf: []u8, n: int, err: Error, want: string, loc := #caller_location) {
		testing.expect_value(t, err, Error.None, loc = loc)
		testing.expect_value(t, string(buf[:n - 1]), want, loc = loc)
		testing.expect_value(t, buf[n - 1], 0, loc = loc)
	}
	n, err := format_push_request(buf[:])
	check(t, buf[:], n, err, "PUSH_REQUEST")
	n, err = format_exit(buf[:])
	check(t, buf[:], n, err, "EXIT")
	n, err = format_auth_failed(buf[:])
	check(t, buf[:], n, err, "AUTH_FAILED")
	n, err = format_auth_failed(buf[:], "Wrong password")
	check(t, buf[:], n, err, "AUTH_FAILED,Wrong password")
	n, err = format_auth_failed(buf[:], NCP_FAIL_NO_SHARED_CIPHER)
	check(t, buf[:], n, err, "AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)")
	n, err = format_auth_failed_session(buf[:])
	check(t, buf[:], n, err, "AUTH_FAILED,SESSION")
	n, err = format_auth_failed_temp(buf[:], 30, .Addr, "server is busy")
	check(t, buf[:], n, err, "AUTH_FAILED,TEMP[backoff 30,advance addr]: server is busy")
	n, err = format_auth_failed_temp(buf[:], 0, .Remote)
	check(t, buf[:], n, err, "AUTH_FAILED,TEMP[advance remote]")
	n, err = format_auth_failed_temp(buf[:], 5)
	check(t, buf[:], n, err, "AUTH_FAILED,TEMP[backoff 5]")
	n, err = format_auth_failed_temp(buf[:], message = "later")
	check(t, buf[:], n, err, "AUTH_FAILED,TEMP: later")
	n, err = format_auth_failed_temp(buf[:])
	check(t, buf[:], n, err, "AUTH_FAILED,TEMP")
	n, err = format_auth_pending(buf[:], 120, true)
	check(t, buf[:], n, err, "AUTH_PENDING,timeout 120")
	n, err = format_auth_pending(buf[:], 120, false)
	check(t, buf[:], n, err, "AUTH_PENDING")
	n, err = format_info(buf[:], "hello")
	check(t, buf[:], n, err, "INFO,hello")
	n, err = format_info_pre(buf[:], "WEB_AUTH::https://x")
	check(t, buf[:], n, err, "INFO_PRE,WEB_AUTH::https://x")
	n, err = format_cr_response(buf[:], "YWJj")
	check(t, buf[:], n, err, "CR_RESPONSE,YWJj")
	n, err = format_restart(buf[:])
	check(t, buf[:], n, err, "RESTART")
	n, err = format_restart(buf[:], next_remote = true)
	check(t, buf[:], n, err, "RESTART,[N]")
	n, err = format_restart(buf[:], "going down", keep_credentials = true, next_remote = true)
	check(t, buf[:], n, err, "RESTART,[PN] going down")
	n, err = format_halt(buf[:], "bye")
	check(t, buf[:], n, err, "HALT,bye")
	n, err = format_push_reply_text(buf[:], "")
	check(t, buf[:], n, err, "PUSH_REPLY")
	n, err = format_push_reply_text(buf[:], "ping 5,ping-restart 30")
	check(t, buf[:], n, err, "PUSH_REPLY,ping 5,ping-restart 30")
}

@(test)
command_format_limits :: proc(t: ^testing.T) {
	buf: [2048]u8
	long := make([]u8, 1100, context.temp_allocator)
	for &c in long {
		c = 'x'
	}
	// AUTH_FAILED reason: 1024 bytes with the NUL at most.
	_, err := format_auth_failed(buf[:], string(long[:1024 - len("AUTH_FAILED,") - 1]))
	testing.expect_value(t, err, Error.None)
	_, err = format_auth_failed(buf[:], string(long[:1024 - len("AUTH_FAILED,")]))
	testing.expect_value(t, err, Error.Oversize)
	_, err = format_info_pre(buf[:], string(long[:1100]))
	testing.expect_value(t, err, Error.Oversize)
	// INFO may use the whole plain buffer.
	_, err = format_info(buf[:], string(long[:1100]))
	testing.expect_value(t, err, Error.None)
	// Control bytes in text.
	_, err = format_auth_failed(buf[:], "a\nb")
	testing.expect_value(t, err, Error.Bad_Byte)
	_, err = format_info(buf[:], "a\x00b")
	testing.expect_value(t, err, Error.Bad_Byte)
	small: [5]u8
	_, err = format_auth_failed(small[:], "xx")
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	_, err = format_auth_pending(buf[:], -1, true)
	testing.expect_value(t, err, Error.Bad_Argument)
}

@(test)
command_format_parse_round_trip :: proc(t: ^testing.T) {
	buf: [2048]u8
	// Every formatted command parses back to the same fields.
	n, _ := format_auth_failed_temp(buf[:], 45, .No, "maintenance: back at 10:00")
	r: Cmd_Reader
	rest := buf[:n]
	text, st := cmd_reader_next(&r, &rest)
	testing.expect_value(t, st, Cmd_Status.Command)
	cmd, _ := command_parse(text, .Client)
	a, ok := cmd.(Auth_Failed)
	testing.expect(t, ok)
	testing.expect_value(t, a.kind, Auth_Failed_Kind.Temp)
	testing.expect_value(t, a.temp.backoff, 45)
	testing.expect_value(t, a.temp.advance, Temp_Advance.No)
	testing.expect_value(t, a.reason, "maintenance: back at 10:00")

	n, _ = format_restart(buf[:], "x y", true, true)
	rest = buf[:n]
	text, _ = cmd_reader_next(&r, &rest)
	cmd, _ = command_parse(text, .Client)
	rs, rok := cmd.(Restart)
	testing.expect(t, rok)
	testing.expect(t, rs.keep_credentials && rs.next_remote)
	testing.expect_value(t, rs.text, "x y")
}
