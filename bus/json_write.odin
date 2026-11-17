// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Small JSON writer for event data and results. One growing buffer, commas
// added automatically, strings escaped: the output is always valid JSON and
// valid UTF-8 (bad bytes become U+FFFD). Reuse a writer with `writer_reset`.
//
//	w: bus.Writer
//	bus.writer_init(&w)
//	defer bus.writer_destroy(&w)
//	bus.begin_obj(&w)
//	bus.kv_str(&w, "name", "alice")
//	bus.kv_arr(&w, "addrs")
//	bus.val_str(&w, "10.8.0.2")
//	bus.end(&w)             // closes the array
//	bus.end(&w)             // closes the object
//	data := bus.writer_bytes(&w)

import "core:strconv"
import "core:unicode/utf8"

WRITER_MAX_DEPTH :: 24

@(private)
Frame :: enum u8 {
	Obj_Empty,
	Obj_Used,
	Arr_Empty,
	Arr_Used,
}

Writer :: struct {
	buf:       [dynamic]byte,
	stack:     [WRITER_MAX_DEPTH]Frame,
	depth:     int,
	// A key was just written: the next value follows it without a comma.
	after_key: bool,
	// Set when an allocation failed or the nesting was too deep. The output
	// must not be used then.
	failed:    bool,
}

writer_init :: proc(w: ^Writer, allocator := context.allocator) {
	w^ = {}
	w.buf = make([dynamic]byte, 0, 256, allocator)
}

writer_destroy :: proc(w: ^Writer) {
	delete(w.buf)
	w^ = {}
}

// Start over, keeping the memory.
writer_reset :: proc(w: ^Writer) {
	clear(&w.buf)
	w.depth = 0
	w.after_key = false
	w.failed = false
}

// What was written so far. Valid until the next write.
writer_bytes :: proc(w: ^Writer) -> []byte {
	return w.buf[:]
}

writer_string :: proc(w: ^Writer) -> string {
	return string(w.buf[:])
}

// True when every container is closed, nothing failed and no key waits for
// its value.
writer_complete :: proc(w: ^Writer) -> bool {
	return !w.failed && w.depth == 0 && !w.after_key
}

@(private)
put :: proc(w: ^Writer, data: []byte) {
	if _, err := append(&w.buf, ..data); err != nil {
		w.failed = true
	}
}

@(private)
put_byte :: proc(w: ^Writer, b: byte) {
	if _, err := append(&w.buf, b); err != nil {
		w.failed = true
	}
}

@(private)
put_str :: proc(w: ^Writer, s: string) {
	put(w, transmute([]byte)s)
}

// Comma handling before a value, or before a key inside an object.
@(private)
before_value :: proc(w: ^Writer) {
	if w.after_key {
		w.after_key = false
		return
	}
	if w.depth == 0 {
		return
	}
	#partial switch w.stack[w.depth - 1] {
	case .Obj_Used, .Arr_Used:
		put_byte(w, ',')
	case .Obj_Empty:
		w.stack[w.depth - 1] = .Obj_Used
	case .Arr_Empty:
		w.stack[w.depth - 1] = .Arr_Used
	}
}

@(private)
push_frame :: proc(w: ^Writer, f: Frame) {
	if w.depth >= WRITER_MAX_DEPTH {
		w.failed = true
		return
	}
	w.stack[w.depth] = f
	w.depth += 1
}

begin_obj :: proc(w: ^Writer) {
	before_value(w)
	put_byte(w, '{')
	push_frame(w, .Obj_Empty)
}

begin_arr :: proc(w: ^Writer) {
	before_value(w)
	put_byte(w, '[')
	push_frame(w, .Arr_Empty)
}

// Close the innermost object or array.
end :: proc(w: ^Writer) {
	if w.depth == 0 {
		w.failed = true
		return
	}
	w.depth -= 1
	switch w.stack[w.depth] {
	case .Obj_Empty, .Obj_Used:
		put_byte(w, '}')
	case .Arr_Empty, .Arr_Used:
		put_byte(w, ']')
	}
}

// An object key. A value must follow.
key :: proc(w: ^Writer, k: string) {
	before_value(w)
	write_string(w, k)
	put_byte(w, ':')
	w.after_key = true
}

val_str :: proc(w: ^Writer, s: string) {
	before_value(w)
	write_string(w, s)
}

val_int :: proc(w: ^Writer, v: i64) {
	before_value(w)
	tmp: [24]byte
	put_str(w, strconv.write_int(tmp[:], v, 10))
}

val_u64 :: proc(w: ^Writer, v: u64) {
	before_value(w)
	tmp: [24]byte
	put_str(w, strconv.write_uint(tmp[:], v, 10))
}

// NaN and infinity have no JSON form: they are written as null.
val_f64 :: proc(w: ^Writer, v: f64) {
	before_value(w)
	if v != v || v > max(f64) || v < -max(f64) {
		put_str(w, "null")
		return
	}
	tmp: [40]byte
	text := strconv.write_float(tmp[:], v, 'g', -1, 64)
	if len(text) > 0 && text[0] == '+' {
		text = text[1:]
	}
	put_str(w, text)
}

val_bool :: proc(w: ^Writer, v: bool) {
	before_value(w)
	put_str(w, "true" if v else "false")
}

val_null :: proc(w: ^Writer) {
	before_value(w)
	put_str(w, "null")
}

// Insert text that is already valid JSON (a value).
val_raw :: proc(w: ^Writer, json_text: []byte) {
	before_value(w)
	put(w, json_text)
}

kv_str :: proc(w: ^Writer, k, v: string) {
	key(w, k)
	val_str(w, v)
}

kv_int :: proc(w: ^Writer, k: string, v: i64) {
	key(w, k)
	val_int(w, v)
}

kv_u64 :: proc(w: ^Writer, k: string, v: u64) {
	key(w, k)
	val_u64(w, v)
}

kv_f64 :: proc(w: ^Writer, k: string, v: f64) {
	key(w, k)
	val_f64(w, v)
}

kv_bool :: proc(w: ^Writer, k: string, v: bool) {
	key(w, k)
	val_bool(w, v)
}

kv_null :: proc(w: ^Writer, k: string) {
	key(w, k)
	val_null(w)
}

kv_raw :: proc(w: ^Writer, k: string, json_text: []byte) {
	key(w, k)
	val_raw(w, json_text)
}

// The string, or null when `ok` is false (for "present or null" fields).
kv_str_or_null :: proc(w: ^Writer, k, v: string, ok: bool) {
	key(w, k)
	if ok {
		val_str(w, v)
	} else {
		val_null(w)
	}
}

// A key followed by the start of an object or an array.
kv_obj :: proc(w: ^Writer, k: string) {
	key(w, k)
	begin_obj(w)
}

kv_arr :: proc(w: ^Writer, k: string) {
	key(w, k)
	begin_arr(w)
}

// Write a quoted, escaped string. Quote, backslash and control characters are
// escaped. Valid UTF-8 passes through unchanged. A byte that is not part of
// valid UTF-8 becomes U+FFFD.
write_string :: proc(w: ^Writer, s: string) {
	HEX := "0123456789abcdef"
	put_byte(w, '"')
	run_start := 0
	i := 0
	for i < len(s) {
		b := s[i]
		if b >= 0x20 && b != '"' && b != '\\' && b < 0x80 {
			i += 1
			continue
		}
		if b >= 0x80 {
			r, n := utf8.decode_rune_in_string(s[i:])
			if r != utf8.RUNE_ERROR || n != 1 {
				i += n
				continue
			}
			// Bad byte: flush the good run, then write U+FFFD.
			put_str(w, s[run_start:i])
			put_str(w, "\xef\xbf\xbd")
			i += 1
			run_start = i
			continue
		}
		put_str(w, s[run_start:i])
		switch b {
		case '"':
			put_str(w, `\"`)
		case '\\':
			put_str(w, `\\`)
		case '\n':
			put_str(w, `\n`)
		case '\r':
			put_str(w, `\r`)
		case '\t':
			put_str(w, `\t`)
		case '\b':
			put_str(w, `\b`)
		case '\f':
			put_str(w, `\f`)
		case:
			esc := [6]byte{'\\', 'u', '0', '0', HEX[b >> 4], HEX[b & 15]}
			put(w, esc[:])
		}
		i += 1
		run_start = i
	}
	put_str(w, s[run_start:])
	put_byte(w, '"')
}
