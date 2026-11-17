// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import "core:strings"
import "core:unicode/utf8"

// A read-only picture of a JSON text, for printing. Unlike `core:encoding/json`
// it keeps the key order (as the daemon wrote it) and the exact text of numbers
// (a u64 counter above 2^63 stays correct). The input has passed the bus
// library's strict parser already; this parser still checks bounds and depth,
// so a wrong input gives `ok = false`, never a crash.

View_Kind :: enum u8 {
	Null,
	Bool,
	Number,
	String,
	Array,
	Object,
}

View :: struct {
	kind:  View_Kind,
	// String: the value, unescaped. Number: its text. Bool: "true" or "false".
	text:  string,
	// Array: the elements. Object: the values.
	items: []View,
	// Object: the keys, in the order of `items`.
	keys:  []string,
}

VIEW_MAX_DEPTH :: 32

@(private = "file")
View_Parser :: struct {
	data:  []byte,
	pos:   int,
	depth: int,
	alloc: mem.Allocator,
	bad:   bool,
}

// Parse one JSON value. The result points into `data` (strings without
// escapes are not copied) and into `allocator`.
view_parse :: proc(data: []byte, allocator := context.temp_allocator) -> (v: View, ok: bool) {
	p := View_Parser {
		data  = data,
		alloc = allocator,
	}
	v = parse_value(&p)
	skip_space(&p)
	if p.bad || p.pos != len(p.data) {
		return {}, false
	}
	return v, true
}

// The value of a key of an object.
view_get :: proc(v: View, key: string) -> (View, bool) {
	if v.kind != .Object {
		return {}, false
	}
	for k, i in v.keys {
		if k == key {
			return v.items[i], true
		}
	}
	return {}, false
}

view_is_scalar :: proc(v: View) -> bool {
	return v.kind != .Array && v.kind != .Object
}

@(private = "file")
skip_space :: proc(p: ^View_Parser) {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos += 1
		case:
			return
		}
	}
}

@(private = "file")
fail :: proc(p: ^View_Parser) -> View {
	p.bad = true
	return {}
}

@(private = "file")
parse_value :: proc(p: ^View_Parser) -> View {
	skip_space(p)
	if p.bad || p.pos >= len(p.data) {
		return fail(p)
	}
	switch p.data[p.pos] {
	case '{':
		return parse_object(p)
	case '[':
		return parse_array(p)
	case '"':
		s, ok := parse_string(p)
		if !ok {
			return fail(p)
		}
		return View{kind = .String, text = s}
	case 't':
		return parse_word(p, "true", .Bool)
	case 'f':
		return parse_word(p, "false", .Bool)
	case 'n':
		return parse_word(p, "null", .Null)
	case '-', '0' ..= '9':
		start := p.pos
		for p.pos < len(p.data) {
			switch p.data[p.pos] {
			case '0' ..= '9', '-', '+', '.', 'e', 'E':
				p.pos += 1
				continue
			}
			break
		}
		return View{kind = .Number, text = string(p.data[start:p.pos])}
	}
	return fail(p)
}

@(private = "file")
parse_word :: proc(p: ^View_Parser, word: string, kind: View_Kind) -> View {
	if p.pos + len(word) > len(p.data) || string(p.data[p.pos:p.pos + len(word)]) != word {
		return fail(p)
	}
	p.pos += len(word)
	if kind == .Null {
		return View{kind = .Null}
	}
	return View{kind = .Bool, text = word}
}

@(private = "file")
parse_array :: proc(p: ^View_Parser) -> View {
	if p.depth >= VIEW_MAX_DEPTH {
		return fail(p)
	}
	p.depth += 1
	defer p.depth -= 1
	p.pos += 1 // [
	items := make([dynamic]View, p.alloc)
	skip_space(p)
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos += 1
		return View{kind = .Array}
	}
	for {
		item := parse_value(p)
		if p.bad {
			return {}
		}
		append(&items, item)
		skip_space(p)
		if p.pos >= len(p.data) {
			return fail(p)
		}
		c := p.data[p.pos]
		p.pos += 1
		if c == ']' {
			break
		}
		if c != ',' {
			return fail(p)
		}
	}
	return View{kind = .Array, items = items[:]}
}

@(private = "file")
parse_object :: proc(p: ^View_Parser) -> View {
	if p.depth >= VIEW_MAX_DEPTH {
		return fail(p)
	}
	p.depth += 1
	defer p.depth -= 1
	p.pos += 1 // {
	items := make([dynamic]View, p.alloc)
	keys := make([dynamic]string, p.alloc)
	skip_space(p)
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos += 1
		return View{kind = .Object}
	}
	for {
		skip_space(p)
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return fail(p)
		}
		k, kok := parse_string(p)
		if !kok {
			return fail(p)
		}
		skip_space(p)
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return fail(p)
		}
		p.pos += 1
		item := parse_value(p)
		if p.bad {
			return {}
		}
		append(&keys, k)
		append(&items, item)
		skip_space(p)
		if p.pos >= len(p.data) {
			return fail(p)
		}
		c := p.data[p.pos]
		p.pos += 1
		if c == '}' {
			break
		}
		if c != ',' {
			return fail(p)
		}
	}
	return View{kind = .Object, items = items[:], keys = keys[:]}
}

@(private = "file")
hex_digit :: proc(c: byte) -> (v: u32, ok: bool) {
	switch c {
	case '0' ..= '9':
		return u32(c - '0'), true
	case 'a' ..= 'f':
		return u32(c - 'a' + 10), true
	case 'A' ..= 'F':
		return u32(c - 'A' + 10), true
	}
	return 0, false
}

@(private = "file")
hex4 :: proc(p: ^View_Parser) -> (r: u32, ok: bool) {
	if p.pos + 4 > len(p.data) {
		return 0, false
	}
	for i in 0 ..< 4 {
		d, dok := hex_digit(p.data[p.pos + i])
		if !dok {
			return 0, false
		}
		r = r << 4 | d
	}
	p.pos += 4
	return r, true
}

// Read a string starting at the opening quote. A string without escapes is
// returned as a slice of the input.
@(private = "file")
parse_string :: proc(p: ^View_Parser) -> (s: string, ok: bool) {
	p.pos += 1 // "
	start := p.pos
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == '"' {
			s = string(p.data[start:p.pos])
			p.pos += 1
			return s, true
		}
		if c == '\\' {
			break
		}
		p.pos += 1
	}
	if p.pos >= len(p.data) {
		return "", false
	}
	// Escapes: build a copy.
	b := strings.builder_make(p.alloc)
	strings.write_bytes(&b, p.data[start:p.pos])
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		p.pos += 1
		switch c {
		case '"':
			return strings.to_string(b), true
		case '\\':
			if p.pos >= len(p.data) {
				return "", false
			}
			e := p.data[p.pos]
			p.pos += 1
			switch e {
			case '"', '\\', '/':
				strings.write_byte(&b, e)
			case 'b':
				strings.write_byte(&b, '\b')
			case 'f':
				strings.write_byte(&b, '\f')
			case 'n':
				strings.write_byte(&b, '\n')
			case 'r':
				strings.write_byte(&b, '\r')
			case 't':
				strings.write_byte(&b, '\t')
			case 'u':
				r, rok := hex4(p)
				if !rok {
					return "", false
				}
				// A high surrogate needs a low one right after it.
				if r >= 0xd800 && r <= 0xdbff {
					if p.pos + 6 <= len(p.data) && p.data[p.pos] == '\\' && p.data[p.pos + 1] == 'u' {
						save := p.pos
						p.pos += 2
						lo, lok := hex4(p)
						if lok && lo >= 0xdc00 && lo <= 0xdfff {
							r = 0x10000 + ((r - 0xd800) << 10) + (lo - 0xdc00)
						} else {
							p.pos = save
							r = 0xfffd
						}
					} else {
						r = 0xfffd
					}
				} else if r >= 0xdc00 && r <= 0xdfff {
					r = 0xfffd
				}
				strings.write_rune(&b, rune(r))
			case:
				return "", false
			}
		case:
			strings.write_byte(&b, c)
		}
	}
	return "", false
}

// ---- text for a terminal ----

// A character that must not reach a terminal as is: a control character (could
// run an escape sequence), a C1 control, a line or paragraph separator, or a
// bidirectional override (can cause text to look different from what it is). Strings
// from the daemon may come from the network.
unsafe_rune :: proc(r: rune) -> bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0xfeff:
		return true
	}
	return false
}

@(private = "file")
write_escape :: proc(b: ^strings.Builder, r: rune) {
	HEX := "0123456789abcdef"
	v := u32(r)
	strings.write_string(b, "\\u")
	if v > 0xffff {
		// Not reached today: every unsafe rune is in the first plane.
		v = 0xfffd
	}
	strings.write_byte(b, HEX[(v >> 12) & 15])
	strings.write_byte(b, HEX[(v >> 8) & 15])
	strings.write_byte(b, HEX[(v >> 4) & 15])
	strings.write_byte(b, HEX[v & 15])
}

// `s` with each unsafe character written as `\uXXXX`. A byte that is not UTF-8
// becomes `�`. Without such characters `s` itself is returned.
safe_text :: proc(s: string, allocator := context.temp_allocator) -> string {
	clean := true
	for i := 0; i < len(s); {
		if s[i] < 0x80 {
			if s[i] < 0x20 || s[i] == 0x7f {
				clean = false
				break
			}
			i += 1
			continue
		}
		r, n := utf8.decode_rune_in_string(s[i:])
		if (r == utf8.RUNE_ERROR && n == 1) || unsafe_rune(r) {
			clean = false
			break
		}
		i += n
	}
	if clean {
		return s
	}
	b := strings.builder_make(allocator)
	for i := 0; i < len(s); {
		r, n := utf8.decode_rune_in_string(s[i:])
		if r == utf8.RUNE_ERROR && n == 1 {
			write_escape(&b, 0xfffd)
		} else if unsafe_rune(r) {
			write_escape(&b, r)
		} else {
			strings.write_string(&b, s[i:i + n])
		}
		i += n
	}
	return strings.to_string(b)
}

// `s` in double quotes, JSON style, safe for a terminal.
quote_text :: proc(s: string, allocator := context.temp_allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_byte(&b, '"')
	for i := 0; i < len(s); {
		r, n := utf8.decode_rune_in_string(s[i:])
		switch {
		case r == utf8.RUNE_ERROR && n == 1:
			write_escape(&b, 0xfffd)
		case r == '"':
			strings.write_string(&b, `\"`)
		case r == '\\':
			strings.write_string(&b, `\\`)
		case r == '\n':
			strings.write_string(&b, `\n`)
		case r == '\r':
			strings.write_string(&b, `\r`)
		case r == '\t':
			strings.write_string(&b, `\t`)
		case unsafe_rune(r):
			write_escape(&b, r)
		case:
			strings.write_string(&b, s[i:i + n])
		}
		i += n
	}
	strings.write_byte(&b, '"')
	return strings.to_string(b)
}

// The value as compact JSON (for nested values in a one-line output).
view_compact :: proc(b: ^strings.Builder, v: View) {
	switch v.kind {
	case .Null:
		strings.write_string(b, "null")
	case .Bool, .Number:
		strings.write_string(b, v.text)
	case .String:
		strings.write_string(b, quote_text(v.text))
	case .Array:
		strings.write_byte(b, '[')
		for item, i in v.items {
			if i > 0 {
				strings.write_byte(b, ',')
			}
			view_compact(b, item)
		}
		strings.write_byte(b, ']')
	case .Object:
		strings.write_byte(b, '{')
		for item, i in v.items {
			if i > 0 {
				strings.write_byte(b, ',')
			}
			strings.write_string(b, quote_text(v.keys[i]))
			strings.write_byte(b, ':')
			view_compact(b, item)
		}
		strings.write_byte(b, '}')
	}
}
