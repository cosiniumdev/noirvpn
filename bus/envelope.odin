// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Message envelopes: parse a request, write a reply, write an event. The
// exact JSON schemas are in the bus spec.

import "core:crypto"
import "core:encoding/json"
import "core:time"

// Hex text of `n` random bytes (2n characters). For request ids and the start
// id of a daemon run.
random_hex :: proc(n: int, allocator := context.allocator) -> string {
	assert(n >= 1 && n <= 32)
	raw: [32]byte
	crypto.rand_bytes(raw[:n])
	out := make([]byte, 2 * n, allocator)
	hex_into(out, raw[:n])
	return string(out)
}

@(private)
hex_into :: proc "contextless" (dst: []byte, src: []byte) {
	HEX := "0123456789abcdef"
	for b, i in src {
		dst[2 * i] = HEX[b >> 4]
		dst[2 * i + 1] = HEX[b & 15]
	}
}

// RFC 3339 time in UTC with milliseconds: 2026-11-09T12:34:56.789Z (24 bytes).
format_ts :: proc "contextless" (t: time.Time, buf: ^[24]u8) -> string {
	dt, ok := time.time_to_datetime(t)
	if !ok {
		copy(buf[:], "1970-01-01T00:00:00.000Z")
		return string(buf[:])
	}
	ms := (time.to_unix_nanoseconds(t) %% 1_000_000_000) / 1_000_000
	digits :: proc "contextless" (dst: []u8, v: i64) {
		v := v
		for i := len(dst) - 1; i >= 0; i -= 1 {
			dst[i] = '0' + u8(v % 10)
			v /= 10
		}
	}
	digits(buf[0:4], dt.year)
	buf[4] = '-'
	digits(buf[5:7], i64(dt.month))
	buf[7] = '-'
	digits(buf[8:10], i64(dt.day))
	buf[10] = 'T'
	digits(buf[11:13], i64(dt.hour))
	buf[13] = ':'
	digits(buf[14:16], i64(dt.minute))
	buf[16] = ':'
	digits(buf[17:19], i64(dt.second))
	buf[19] = '.'
	digits(buf[20:23], ms)
	buf[23] = 'Z'
	return string(buf[:])
}

// A request, parsed and checked. `root` owns the memory that `id`, `op` and
// `args` point into. Free with `parsed_destroy`, also after an error. On an
// error `id` is still set if the request carried a valid one, so the error
// reply can name it.
Parsed_Request :: struct {
	root: json.Value,
	id:   string,
	op:   string,
	// Empty when the request has no "args".
	args: json.Object,
}

parsed_destroy :: proc(p: ^Parsed_Request, allocator := context.allocator) {
	json.destroy_value(p.root, allocator)
	p^ = {}
}

// Cheap checks on JSON text before it is parsed:
//   - nesting no deeper than `max` (the parser recurses)
//   - no comma before a closing bracket (the Odin parser accepts that)
//   - no string longer than `max_string` bytes
//   - no array or object with more than `max_items` entries
// Strings are skipped, so brackets inside strings do not count.
json_limits_ok :: proc "contextless" (
	data: []byte,
	max: int,
	max_string := MAX_JSON_STRING,
	max_items := MAX_JSON_ITEMS,
) -> (
	ok: bool,
	why: string,
) {
	depth := 0
	in_str := false
	esc := false
	str_len := 0
	comma := false // the last token outside a string was a comma
	// Entries of the open arrays and objects, by depth.
	items: [MAX_JSON_DEPTH + 2]int
	for b in data {
		if in_str {
			if esc {
				esc = false
			} else if b == '\\' {
				esc = true
			} else if b == '"' {
				in_str = false
				continue
			}
			str_len += 1
			if str_len > max_string {
				return false, "the request contains a string that is too long"
			}
			continue
		}
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '"':
			in_str = true
			str_len = 0
		case '{', '[':
			depth += 1
			if depth > max || depth >= len(items) {
				return false, "the request is nested too deeply"
			}
			items[depth] = 1
		case '}', ']':
			if depth > 0 {
				depth -= 1
			}
			if comma {
				return false, "the request is not valid JSON (it has a comma before a closing bracket)"
			}
		case ',':
			if depth > 0 {
				items[depth] += 1
				if items[depth] > max_items {
					return false, "the request contains a list that is too long"
				}
			}
		}
		comma = b == ','
	}
	return true, ""
}

// Parse JSON strictly: standard JSON only, integers kept as integers, one
// value with nothing after it. Checks the format first.
parse_json :: proc(data: []byte, allocator := context.allocator) -> (v: json.Value, ok: bool) {
	if limits_ok, _ := json_limits_ok(data, MAX_JSON_DEPTH); !limits_ok {
		return nil, false
	}
	// The parser leaks the object it was building when a closing brace is
	// missing: check the syntax first, without allocations.
	if !json.is_valid(data, .JSON, true) {
		return nil, false
	}
	context.allocator = allocator
	p := json.make_parser(data, .JSON, true, allocator)
	val, err := json.parse_value(&p)
	if err != nil {
		return nil, false
	}
	if p.curr_token.kind != .EOF {
		json.destroy_value(val, allocator)
		return nil, false
	}
	return val, true
}

// Parse and check a request body. On failure `code` and
// `msg` say why (`msg` is a fixed string). It checks only the syntax of the op
// name. Use `op_lookup` for the rest.
parse_request :: proc(
	data: []byte,
	allocator := context.allocator,
) -> (
	p: Parsed_Request,
	code: Error_Code,
	msg: string,
	ok: bool,
) {
	if len(data) == 0 {
		return p, .Bad_Request, "the request is empty", false
	}
	if limits_ok, why := json_limits_ok(data, MAX_JSON_DEPTH); !limits_ok {
		return p, .Bad_Request, why, false
	}
	root, parsed := parse_json(data, allocator)
	if !parsed {
		return p, .Bad_Request, "the request is not valid JSON", false
	}
	p.root = root
	obj, is_obj := root.(json.Object)
	if !is_obj {
		return p, .Bad_Request, "the request must be a JSON object", false
	}

	// The id first, so that every later error can carry it.
	id_val, has_id := obj["id"]
	if !has_id {
		return p, .Bad_Request, "the request is missing the id field", false
	}
	id, id_is_str := id_val.(json.String)
	if !id_is_str || !valid_id(id) {
		return p, .Bad_Request, "the id must be between 1 and 64 printable ASCII characters", false
	}
	p.id = id

	v_val, has_v := obj["v"]
	if !has_v {
		return p, .Bad_Request, "the request is missing the v field", false
	}
	v, v_is_int := v_val.(json.Integer)
	if !v_is_int || v != VERSION {
		return p, .Bad_Request, "this protocol version is not supported (this daemon only supports v 1)", false
	}

	op_val, has_op := obj["op"]
	if !has_op {
		return p, .Bad_Request, "the request is missing the op field", false
	}
	op, op_is_str := op_val.(json.String)
	if !op_is_str || !valid_name(op, MAX_OP_LEN) {
		return p, .Bad_Request, "the op must be a name such as \"peer.kick\"", false
	}
	p.op = op

	if args_val, has_args := obj["args"]; has_args {
		args, args_is_obj := args_val.(json.Object)
		if !args_is_obj {
			return p, .Bad_Request, "the args field must be a JSON object", false
		}
		p.args = args
	}
	return p, .Bad_Request, "", true
}

// Write a success reply. `result` is a JSON value; nil means {}.
write_reply_ok :: proc(w: ^Writer, id: string, result: []byte) {
	begin_obj(w)
	kv_int(w, "v", VERSION)
	kv_str(w, "id", id)
	kv_bool(w, "ok", true)
	if len(result) == 0 {
		kv_raw(w, "result", transmute([]byte)string("{}"))
	} else {
		kv_raw(w, "result", result)
	}
	end(w)
}

// Write an error reply. An empty `id` is written as null (used when the
// request had no usable id).
write_reply_error :: proc(w: ^Writer, id: string, code: Error_Code, message: string) {
	write_reply_error_details(w, id, code, message, nil)
}

// Like `write_reply_error`, with a `details` field in the error object.
// `details` is JSON text, an array; nil or empty writes no field.
write_reply_error_details :: proc(w: ^Writer, id: string, code: Error_Code, message: string, details: []byte) {
	begin_obj(w)
	kv_int(w, "v", VERSION)
	kv_str_or_null(w, "id", id, id != "")
	kv_bool(w, "ok", false)
	kv_obj(w, "error")
	kv_str(w, "code", error_code_string(code))
	kv_str(w, "message", message)
	if len(details) > 0 {
		kv_raw(w, "details", details)
	}
	end(w)
	end(w)
}

// Write a request (client side). `args` is a JSON object text, or nil for {}.
write_request :: proc(w: ^Writer, id, op: string, args: []byte) {
	begin_obj(w)
	kv_int(w, "v", VERSION)
	kv_str(w, "id", id)
	kv_str(w, "op", op)
	if len(args) == 0 {
		kv_raw(w, "args", transmute([]byte)string("{}"))
	} else {
		kv_raw(w, "args", args)
	}
	end(w)
}

// Write an event envelope. `data` is a JSON object text, or nil for {}.
write_event :: proc(w: ^Writer, run: string, seq: u64, ts, topic: string, data: []byte) {
	begin_obj(w)
	kv_int(w, "v", VERSION)
	kv_str(w, "run", run)
	kv_u64(w, "seq", seq)
	kv_str(w, "ts", ts)
	kv_str(w, "topic", topic)
	if len(data) == 0 {
		kv_raw(w, "data", transmute([]byte)string("{}"))
	} else {
		kv_raw(w, "data", data)
	}
	end(w)
}

// FNV-1a, 64 bit. Used to tell whether a repeated request id carries the
// same request. Not a security measure.
hash_bytes :: proc "contextless" (data: []byte) -> u64 {
	h := u64(0xcbf29ce484222325)
	for b in data {
		h ~= u64(b)
		h *= 0x100000001b3
	}
	return h
}
