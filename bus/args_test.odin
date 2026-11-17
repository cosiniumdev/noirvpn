// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:encoding/json"
import "core:strings"
import "core:testing"

// A request with these args, for the helpers. Free with parsed_destroy.
@(private = "file")
make_req :: proc(args_json: string) -> (req: Request, p: Parsed_Request) {
	body := strings.concatenate({`{"v":1,"id":"1","op":"status","args":`, args_json, "}"}, context.temp_allocator)
	pr, _, _, _ := parse_request(transmute([]byte)body)
	return Request{id = pr.id, op = pr.op, args = pr.args}, pr
}

@(test)
args_strings :: proc(t: ^testing.T) {
	req, p := make_req(`{"s":"hello","n":5,"b":true,"z":null,"f":1.5}`)
	defer parsed_destroy(&p)

	v, e := arg_str(&req, "s")
	testing.expect_value(t, e, Arg_Error.None)
	testing.expect_value(t, v, "hello")
	_, e = arg_str(&req, "absent")
	testing.expect_value(t, e, Arg_Error.Missing)
	_, e = arg_str(&req, "z") // null counts as missing
	testing.expect_value(t, e, Arg_Error.Missing)
	_, e = arg_str(&req, "n")
	testing.expect_value(t, e, Arg_Error.Wrong_Type)
	testing.expect(t, arg_has(&req, "s"))
	testing.expect(t, !arg_has(&req, "z"))
	testing.expect(t, !arg_has(&req, "absent"))
}

@(test)
args_numbers_and_bools :: proc(t: ^testing.T) {
	req, p := make_req(`{"n":5,"neg":-3,"f":1.5,"s":"7","b":true,"big":99999999999}`)
	defer parsed_destroy(&p)

	n, e := arg_int(&req, "n")
	testing.expect_value(t, e, Arg_Error.None)
	testing.expect_value(t, n, 5)
	n, e = arg_int(&req, "neg")
	testing.expect_value(t, n, -3)
	_, e = arg_int(&req, "f") // no silent truncation
	testing.expect_value(t, e, Arg_Error.Wrong_Type)
	_, e = arg_int(&req, "s") // no silent conversion
	testing.expect_value(t, e, Arg_Error.Wrong_Type)
	_, e = arg_int(&req, "nope")
	testing.expect_value(t, e, Arg_Error.Missing)

	n, e = arg_int_range(&req, "n", 1, 10)
	testing.expect_value(t, e, Arg_Error.None)
	testing.expect_value(t, n, 5)
	_, e = arg_int_range(&req, "n", 6, 10)
	testing.expect_value(t, e, Arg_Error.Out_Of_Range)
	_, e = arg_int_range(&req, "big", 0, 100)
	testing.expect_value(t, e, Arg_Error.Out_Of_Range)

	b, be := arg_bool(&req, "b")
	testing.expect_value(t, be, Arg_Error.None)
	testing.expect(t, b)
	_, be = arg_bool(&req, "n")
	testing.expect_value(t, be, Arg_Error.Wrong_Type)
}

@(test)
args_string_arrays :: proc(t: ^testing.T) {
	req, p := make_req(`{"push":["route 10.0.0.0 255.0.0.0","dhcp-option DNS 1.1.1.1"],"bad":["a",1],"num":5,"empty":[]}`)
	defer parsed_destroy(&p)

	v, e := arg_strs(&req, "push")
	defer delete(v)
	testing.expect_value(t, e, Arg_Error.None)
	testing.expect_value(t, len(v), 2)
	if len(v) == 2 {
		testing.expect_value(t, v[0], "route 10.0.0.0 255.0.0.0")
		testing.expect_value(t, v[1], "dhcp-option DNS 1.1.1.1")
	}
	_, e = arg_strs(&req, "bad")
	testing.expect_value(t, e, Arg_Error.Out_Of_Range)
	_, e = arg_strs(&req, "num")
	testing.expect_value(t, e, Arg_Error.Wrong_Type)
	_, e = arg_strs(&req, "absent")
	testing.expect_value(t, e, Arg_Error.Missing)
	empty, e2 := arg_strs(&req, "empty")
	defer delete(empty)
	testing.expect_value(t, e2, Arg_Error.None)
	testing.expect_value(t, len(empty), 0)
}

@(test)
args_messages_name_the_field :: proc(t: ^testing.T) {
	buf: [160]byte
	testing.expect_value(t, arg_message("session", .Missing, buf[:]), "the session argument is missing")
	testing.expect_value(t, arg_message("session", .Wrong_Type, buf[:]), "the session argument has the wrong type")
	testing.expect_value(t, arg_message("n", .Out_Of_Range, buf[:]), "the n argument is out of range")
	testing.expect_value(t, arg_message("n", .None, buf[:]), "")
}

@(test)
request_without_args_has_no_args :: proc(t: ^testing.T) {
	pr, _, _, ok := parse_request(transmute([]byte)string(`{"v":1,"id":"1","op":"status"}`))
	defer parsed_destroy(&pr)
	testing.expect(t, ok)
	req := Request {
		args = pr.args,
	}
	_, e := arg_str(&req, "anything")
	testing.expect_value(t, e, Arg_Error.Missing)
}

@(test)
args_wipe_zeroes_strings :: proc(t: ^testing.T) {
	req, p := make_req(`{"text":"secret","list":["a","bc"],"obj":{"k":"vv"},"n":5}`)
	defer parsed_destroy(&p)
	text, _ := arg_str(&req, "text")
	args_wipe(&req)
	testing.expect_value(t, len(text), 6)
	for b in transmute([]byte)text {
		testing.expect_value(t, b, 0)
	}
	// Numbers and keys stay.
	n, e := arg_int(&req, "n")
	testing.expect_value(t, e, Arg_Error.None)
	testing.expect_value(t, n, 5)
	obj := req.args["obj"].(json.Object)
	for _, v in obj {
		for b in transmute([]byte)v.(json.String) {
			testing.expect_value(t, b, 0)
		}
	}
	list := req.args["list"].(json.Array)
	for v in list {
		for b in transmute([]byte)v.(json.String) {
			testing.expect_value(t, b, 0)
		}
	}
}
