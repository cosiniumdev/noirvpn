// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:encoding/json"
import "core:strings"
import "core:testing"
import "core:time"

// Parse a request and free it. Returns what the checks need.
@(private = "file")
parse :: proc(text: string) -> (p: Parsed_Request, code: Error_Code, msg: string, ok: bool) {
	return parse_request(transmute([]byte)text)
}

@(test)
request_good :: proc(t: ^testing.T) {
	p, _, _, ok := parse(`{"v":1,"id":"abc-123","op":"peer.kick","args":{"session":"s-1","n":5}}`)
	defer parsed_destroy(&p)
	testing.expect(t, ok)
	testing.expect_value(t, p.id, "abc-123")
	testing.expect_value(t, p.op, "peer.kick")
	testing.expect_value(t, len(p.args), 2)
	s, is_str := p.args["session"].(json.String)
	testing.expect(t, is_str)
	testing.expect_value(t, s, "s-1")
}

@(test)
request_no_args_is_empty :: proc(t: ^testing.T) {
	p, _, _, ok := parse(`{"v":1,"id":"1","op":"status"}`)
	defer parsed_destroy(&p)
	testing.expect(t, ok)
	testing.expect_value(t, len(p.args), 0)
}

@(test)
request_unknown_fields_ignored :: proc(t: ^testing.T) {
	p, _, _, ok := parse(`{"v":1,"id":"1","op":"status","future":[1,2,3]}`)
	defer parsed_destroy(&p)
	testing.expect(t, ok)
}

@(test)
request_bad_cases :: proc(t: ^testing.T) {
	long_id := strings.repeat("x", 65, context.temp_allocator)
	max_id := strings.repeat("x", 64, context.temp_allocator)
	Case :: struct {
		name: string,
		body: string,
		// The id the error reply can still use ("" = none).
		id:   string,
	}
	cases := []Case {
		{"empty", ``, ""},
		{"not json", `hello`, ""},
		{"trailing junk", `{"v":1,"id":"1","op":"status"} x`, ""},
		{"json5 comment", `{"v":1,"id":"1","op":"status"} // c`, ""},
		{"trailing comma", `{"v":1,"id":"1","op":"status",}`, ""},
		{"array", `[1]`, ""},
		{"string", `"x"`, ""},
		{"missing id", `{"v":1,"op":"status"}`, ""},
		{"missing v", `{"id":"1","op":"status"}`, "1"},
		{"missing op", `{"v":1,"id":"1"}`, "1"},
		{"wrong version", `{"v":2,"id":"1","op":"status"}`, "1"},
		{"version as string", `{"v":"1","id":"1","op":"status"}`, "1"},
		{"version as float", `{"v":1.5,"id":"1","op":"status"}`, "1"},
		{"id empty", `{"v":1,"id":"","op":"status"}`, ""},
		{"id number", `{"v":1,"id":7,"op":"status"}`, ""},
		{"id with space", `{"v":1,"id":"a b","op":"status"}`, ""},
		{"id with control", `{"v":1,"id":"a\u0001b","op":"status"}`, ""},
		{"id non-ascii", `{"v":1,"id":"café","op":"status"}`, ""},
		{"op number", `{"v":1,"id":"1","op":3}`, "1"},
		{"op upper case", `{"v":1,"id":"1","op":"Status"}`, "1"},
		{"op with space", `{"v":1,"id":"1","op":"peer kick"}`, "1"},
		{"op empty", `{"v":1,"id":"1","op":""}`, "1"},
		{"args array", `{"v":1,"id":"1","op":"status","args":[]}`, "1"},
		{"args string", `{"v":1,"id":"1","op":"status","args":"x"}`, "1"},
		{"args null", `{"v":1,"id":"1","op":"status","args":null}`, "1"},
		{"duplicate key", `{"v":1,"id":"1","id":"2","op":"status"}`, ""},
		{"too deep", strings.concatenate({`{"v":1,"id":"1","op":"status","args":`, strings.repeat("[", 40, context.temp_allocator), strings.repeat("]", 40, context.temp_allocator), `}`}, context.temp_allocator), ""},
	}
	for c in cases {
		p, code, msg, ok := parse(c.body)
		testing.expectf(t, !ok, "%s: should fail", c.name)
		testing.expectf(t, code == .Bad_Request, "%s: code %v", c.name, code)
		testing.expectf(t, len(msg) > 0, "%s: no message", c.name)
		testing.expectf(t, p.id == c.id, "%s: id %q, want %q", c.name, p.id, c.id)
		parsed_destroy(&p)
	}

	// Id length limits.
	body := strings.concatenate({`{"v":1,"id":"`, long_id, `","op":"status"}`}, context.temp_allocator)
	p, _, _, ok := parse(body)
	testing.expect(t, !ok, "65 character id")
	parsed_destroy(&p)
	body = strings.concatenate({`{"v":1,"id":"`, max_id, `","op":"status"}`}, context.temp_allocator)
	p, _, _, ok = parse(body)
	testing.expect(t, ok, "64 character id")
	parsed_destroy(&p)
}

@(test)
json_limits_check :: proc(t: ^testing.T) {
	ok: bool
	ok, _ = json_limits_ok(transmute([]byte)string(`{"a":[{"b":[]}]}`), 4)
	testing.expect(t, ok)
	ok, _ = json_limits_ok(transmute([]byte)string(`{"a":[{"b":[]}]}`), 3)
	testing.expect(t, !ok)
	// Brackets and commas inside strings, with escapes, do not count.
	ok, _ = json_limits_ok(transmute([]byte)string(`{"a":"[[[[[[[[\"[[[,]"}`), 1)
	testing.expect(t, ok)
	ok, _ = json_limits_ok(transmute([]byte)string(`[1,2, ]`), 4)
	testing.expect(t, !ok)
	ok, _ = json_limits_ok(transmute([]byte)string("{\"a\":1,\n}"), 4)
	testing.expect(t, !ok)
}

@(test)
op_names :: proc(t: ^testing.T) {
	testing.expect(t, valid_name("peer.kick", MAX_OP_LEN))
	testing.expect(t, valid_name("a", MAX_OP_LEN))
	testing.expect(t, !valid_name("", MAX_OP_LEN))
	testing.expect(t, !valid_name(".x", MAX_OP_LEN))
	testing.expect(t, !valid_name("Peer", MAX_OP_LEN))
	testing.expect(t, !valid_name("a b", MAX_OP_LEN))
	testing.expect(t, !valid_name(strings.repeat("a", 49, context.temp_allocator), MAX_OP_LEN))
}

@(test)
reply_models :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)

	write_reply_ok(&w, "r1", transmute([]byte)string(`{"n":1}`))
	testing.expect_value(t, writer_string(&w), `{"v":1,"id":"r1","ok":true,"result":{"n":1}}`)

	writer_reset(&w)
	write_reply_ok(&w, "r1", nil)
	testing.expect_value(t, writer_string(&w), `{"v":1,"id":"r1","ok":true,"result":{}}`)

	writer_reset(&w)
	write_reply_error(&w, "r2", .Not_Found, `no such "session"`)
	testing.expect_value(t, writer_string(&w), `{"v":1,"id":"r2","ok":false,"error":{"code":"not_found","message":"no such \"session\""}}`)

	writer_reset(&w)
	write_reply_error(&w, "", .Denied, "x")
	testing.expect_value(t, writer_string(&w), `{"v":1,"id":null,"ok":false,"error":{"code":"denied","message":"x"}}`)
	testing.expect(t, json.is_valid(writer_bytes(&w), .JSON))

	writer_reset(&w)
	write_request(&w, "abc", "status", nil)
	testing.expect_value(t, writer_string(&w), `{"v":1,"id":"abc","op":"status","args":{}}`)
}

@(test)
event_model :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)
	write_event(&w, "0123456789abcdef", 7, "2026-11-09T12:00:00.123Z", "peer.connect", transmute([]byte)string(`{"session":"s-1"}`))
	testing.expect_value(
		t,
		writer_string(&w),
		`{"v":1,"run":"0123456789abcdef","seq":7,"ts":"2026-11-09T12:00:00.123Z","topic":"peer.connect","data":{"session":"s-1"}}`,
	)
	ev, err := parse_event(transmute([]byte)strings.clone(strings.concatenate({"peer.connect ", writer_string(&w)}, context.temp_allocator)))
	defer event_destroy(&ev)
	testing.expect_value(t, err, Sub_Error.None)
	testing.expect_value(t, ev.topic, "peer.connect")
	testing.expect_value(t, ev.seq, 7)
	testing.expect_value(t, ev.run, "0123456789abcdef")
}

@(test)
error_codes_round_trip :: proc(t: ^testing.T) {
	for name, code in error_code_names {
		c, ok := error_code_from_string(name)
		testing.expect(t, ok)
		testing.expect_value(t, c, code)
	}
	_, ok := error_code_from_string("nope")
	testing.expect(t, !ok)
	testing.expect_value(t, error_code_string(.Unsupported), "unsupported")
}

@(test)
timestamp_format :: proc(t: ^testing.T) {
	buf: [24]u8
	testing.expect_value(t, format_ts(time.unix(0, 0), &buf), "1970-01-01T00:00:00.000Z")
	// 2026-11-09 12:34:56.789 UTC
	tm, _ := time.components_to_time(2026, 11, 9, 12, 34, 56, 789_000_000)
	testing.expect_value(t, format_ts(tm, &buf), "2026-11-09T12:34:56.789Z")
	// Milliseconds are cut, not rounded.
	tm, _ = time.components_to_time(2026, 1, 2, 3, 4, 5, 999_999_999)
	testing.expect_value(t, format_ts(tm, &buf), "2026-01-02T03:04:05.999Z")
	// Before 1970: still a valid, positive millisecond field.
	tm, _ = time.components_to_time(1969, 12, 31, 23, 59, 59, 500_000_000)
	testing.expect_value(t, format_ts(tm, &buf), "1969-12-31T23:59:59.500Z")
}

@(test)
random_ids :: proc(t: ^testing.T) {
	a := random_hex(8)
	b := random_hex(8)
	defer delete(a)
	defer delete(b)
	testing.expect_value(t, len(a), 16)
	testing.expect(t, a != b)
	for ch in transmute([]byte)a {
		testing.expect(t, (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))
	}
}
