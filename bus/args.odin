// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Read the "args" object of a request. Each helper returns the value and an
// `Arg_Error`. A handler checks `.Missing` for an optional field. Any other
// error is a bad request. `arg_message` builds the `bad_request` text.
//
//	session, e := bus.arg_str(req, "session")
//	if e != .None {
//		bus.reply_bad_arg(host, req, "session", e)
//		return
//	}
//	reason, e2 := bus.arg_str(req, "reason")
//	if e2 != .None && e2 != .Missing { ... }
//
// Strings and arrays point into the request: valid until the handler replies.

import "core:encoding/json"
import "core:fmt"
import "core:mem"

Arg_Error :: enum u8 {
	None,
	// The field is not there (or is null).
	Missing,
	// The field has another JSON type.
	Wrong_Type,
	// A number does not fit, or an array element has the wrong type.
	Out_Of_Range,
}

@(private)
arg_value :: proc(req: ^Request, name: string) -> (v: json.Value, err: Arg_Error) {
	val, found := req.args[name]
	if !found {
		return nil, .Missing
	}
	if _, is_null := val.(json.Null); is_null {
		return nil, .Missing
	}
	return val, .None
}

arg_has :: proc(req: ^Request, name: string) -> bool {
	_, err := arg_value(req, name)
	return err == .None
}

arg_str :: proc(req: ^Request, name: string) -> (s: string, err: Arg_Error) {
	val := arg_value(req, name) or_return
	str, ok := val.(json.String)
	if !ok {
		return "", .Wrong_Type
	}
	return str, .None
}

// A whole number. A JSON float is refused.
arg_int :: proc(req: ^Request, name: string) -> (n: i64, err: Arg_Error) {
	val := arg_value(req, name) or_return
	i, ok := val.(json.Integer)
	if !ok {
		return 0, .Wrong_Type
	}
	return i, .None
}

// A whole number in [lo, hi].
arg_int_range :: proc(req: ^Request, name: string, lo, hi: i64) -> (n: i64, err: Arg_Error) {
	n = arg_int(req, name) or_return
	if n < lo || n > hi {
		return 0, .Out_Of_Range
	}
	return n, .None
}

arg_bool :: proc(req: ^Request, name: string) -> (b: bool, err: Arg_Error) {
	val := arg_value(req, name) or_return
	bv, ok := val.(json.Boolean)
	if !ok {
		return false, .Wrong_Type
	}
	return bv, .None
}

// An array of strings. The strings point into the request; only the slice is
// allocated (free it with delete).
arg_strs :: proc(
	req: ^Request,
	name: string,
	allocator := context.allocator,
) -> (
	out: []string,
	err: Arg_Error,
) {
	val := arg_value(req, name) or_return
	arr, ok := val.(json.Array)
	if !ok {
		return nil, .Wrong_Type
	}
	out = make([]string, len(arr), allocator)
	for elem, i in arr {
		s, is_str := elem.(json.String)
		if !is_str {
			delete(out, allocator)
			return nil, .Out_Of_Range
		}
		out[i] = s
	}
	return out, .None
}

// Text for a `bad_request` reply about one field, written into `buf` (128
// bytes are enough for names up to 64 characters). The result points into
// `buf`.
arg_message :: proc(name: string, err: Arg_Error, buf: []byte) -> string {
	switch err {
	case .None:
		return ""
	case .Missing:
		return fmt.bprintf(buf, "the %s argument is missing", name)
	case .Wrong_Type:
		return fmt.bprintf(buf, "the %s argument has the wrong type", name)
	case .Out_Of_Range:
		return fmt.bprintf(buf, "the %s argument is out of range", name)
	}
	return ""
}

// Overwrites every string value of the args of a request with zeros.
// - A handler calls it after it copied a secret (a key, a password) out of the
//   request.
// - The host does the same when it frees a request of an operation with a
//   secret (`Op_Info.secret`).
args_wipe :: proc(req: ^Request) {
	for _, v in req.args {
		json_wipe(v)
	}
}

// Overwrites the strings in the "args" of a request value.
@(private)
wipe_args_of :: proc(root: json.Value) {
	if obj, is_obj := root.(json.Object); is_obj {
		if a, has := obj["args"]; has {
			json_wipe(a)
		}
	}
}

// Overwrites the strings in a JSON value with zeros. Keys are left alone.
@(private)
json_wipe :: proc(v: json.Value) {
	#partial switch x in v {
	case json.String:
		if len(x) > 0 {
			mem.zero_explicit(raw_data(x), len(x))
		}
	case json.Array:
		for e in x {
			json_wipe(e)
		}
	case json.Object:
		for _, e in x {
			json_wipe(e)
		}
	}
}
