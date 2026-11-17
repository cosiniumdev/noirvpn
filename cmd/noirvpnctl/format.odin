// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:encoding/json"
import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"

// Human-readable output. Every proc here is pure: it takes a parsed reply or
// event and writes text, so tests need no daemon. Strings from the daemon may
// come from the network, so they pass through `safe_text` or `quote_text` before
// the terminal.

Pair :: struct {
	key:   string,
	value: string,
}

// The text of a scalar for a `key value` line.
scalar_text :: proc(v: View) -> string {
	switch v.kind {
	case .Null:
		return "-"
	case .Bool, .Number:
		return v.text
	case .String:
		if v.text == "" {
			return `""`
		}
		return safe_text(v.text)
	case .Array, .Object:
	}
	return ""
}

// Turn a value into `key value` pairs. Objects add `.key` to the prefix, arrays
// of scalars become one comma-separated value, arrays of other things add `.0`,
// `.1`, ... Key order is the order the daemon wrote.
flatten_pairs :: proc(out: ^[dynamic]Pair, prefix: string, v: View) {
	switch v.kind {
	case .Null, .Bool, .Number, .String:
		append(out, Pair{prefix, scalar_text(v)})
	case .Object:
		for item, i in v.items {
			key := safe_text(v.keys[i])
			if prefix != "" {
				key = strings.concatenate({prefix, ".", key}, context.temp_allocator)
			}
			flatten_pairs(out, key, item)
		}
	case .Array:
		all_scalar := true
		for item in v.items {
			if !view_is_scalar(item) {
				all_scalar = false
				break
			}
		}
		if all_scalar {
			if len(v.items) == 0 {
				append(out, Pair{prefix, "-"})
				return
			}
			b := strings.builder_make(context.temp_allocator)
			for item, i in v.items {
				if i > 0 {
					strings.write_string(&b, ", ")
				}
				strings.write_string(&b, scalar_text(item))
			}
			append(out, Pair{prefix, strings.to_string(b)})
			return
		}
		for item, i in v.items {
			key := fmt.tprintf("%s.%d", prefix, i)
			flatten_pairs(out, key, item)
		}
	}
}

// `key  value` lines, the values lined up in one column.
write_pairs :: proc(b: ^strings.Builder, pairs: []Pair) {
	width := 0
	for p in pairs {
		width = max(width, utf8.rune_count_in_string(p.key))
	}
	for p in pairs {
		strings.write_string(b, p.key)
		pad(b, width - utf8.rune_count_in_string(p.key) + 2)
		strings.write_string(b, p.value)
		strings.write_byte(b, '\n')
	}
}

@(private = "file")
pad :: proc(b: ^strings.Builder, n: int) {
	for _ in 0 ..< n {
		strings.write_byte(b, ' ')
	}
}

// The generic output of a result: every field as `key value`, nested
// objects as `a.b value`.
format_flat :: proc(b: ^strings.Builder, result: View) {
	pairs := make([dynamic]Pair, context.temp_allocator)
	if view_is_scalar(result) {
		append(&pairs, Pair{"result", scalar_text(result)})
	} else {
		flatten_pairs(&pairs, "", result)
	}
	write_pairs(b, pairs[:])
}

// `status` and `stats.get` are plain `key value` lists in the daemon's order.
format_status :: proc(b: ^strings.Builder, result: View) {
	format_flat(b, result)
}

// ---- peers ----

@(private = "file")
Column :: struct {
	header: string,
	key:    string,
	// Show a byte count as 1.5K, 3.2M, ...
	bytes:  bool,
}

@(rodata, private = "file")
PEER_COLUMNS := [?]Column {
	{"SESSION", "session", false},
	{"NAME", "name", false},
	{"STATE", "state", false},
	{"PROTO", "proto", false},
	{"REAL_ADDR", "real_addr", false},
	{"VPN4", "vpn4", false},
	{"VPN6", "vpn6", false},
	{"CONNECTED", "connected_at", false},
	{"IN", "bytes_in", true},
	{"OUT", "bytes_out", true},
}

// A byte count with a unit: 512B, 1.5K, 12.0M. Anything that is not a plain
// non-negative integer is returned as it is.
human_bytes :: proc(text: string) -> string {
	n, ok := strconv.parse_u64(text, 10)
	if !ok {
		return text
	}
	if n < 1024 {
		return fmt.tprintf("%dB", n)
	}
	units := [?]string{"K", "M", "G", "T", "P", "E"}
	v := f64(n)
	unit := 0
	v /= 1024
	for v >= 1024 && unit < len(units) - 1 {
		v /= 1024
		unit += 1
	}
	return fmt.tprintf("%.1f%s", v, units[unit])
}

// A table of peer objects. The columns are left aligned,
// two spaces apart; the last one is not padded.
format_peers_table :: proc(b: ^strings.Builder, peers: []View) {
	cols := len(PEER_COLUMNS)
	cells := make([][]string, len(peers), context.temp_allocator)
	widths := make([]int, cols, context.temp_allocator)
	for c in 0 ..< cols {
		widths[c] = utf8.rune_count_in_string(PEER_COLUMNS[c].header)
	}
	for p, row in peers {
		cells[row] = make([]string, cols, context.temp_allocator)
		for col, c in PEER_COLUMNS {
			text := "-"
			if v, found := view_get(p, col.key); found && view_is_scalar(v) {
				text = scalar_text(v)
				if col.bytes {
					text = human_bytes(text)
				}
			}
			cells[row][c] = text
			widths[c] = max(widths[c], utf8.rune_count_in_string(text))
		}
	}
	write_row :: proc(b: ^strings.Builder, cells: []string, widths: []int) {
		for cell, c in cells {
			strings.write_string(b, cell)
			if c < len(cells) - 1 {
				pad(b, widths[c] - utf8.rune_count_in_string(cell) + 2)
			}
		}
		strings.write_byte(b, '\n')
	}
	headers := make([]string, cols, context.temp_allocator)
	for col, c in PEER_COLUMNS {
		headers[c] = col.header
	}
	write_row(b, headers, widths)
	for row in cells {
		write_row(b, row, widths)
	}
}

// One peer in detail: its fields as `key value` lines.
format_peer :: proc(b: ^strings.Builder, result: View) {
	if peer, ok := view_get(result, "peer"); ok {
		format_flat(b, peer)
		return
	}
	format_flat(b, result)
}

// ---- events ----

@(private = "file")
token_char :: proc(c: byte) -> bool {
	switch c {
	case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '_', '.', ':', '/', '@', '+', '-', ',', '[', ']':
		return true
	}
	return false
}

// A value in `key=value` form: bare when it is a plain word, quoted when it
// is empty or has a space, quote, `=` or other unusual character.
event_value :: proc(b: ^strings.Builder, v: View) {
	switch v.kind {
	case .Null:
		strings.write_string(b, "null")
	case .Bool, .Number:
		strings.write_string(b, v.text)
	case .String:
		bare := len(v.text) > 0
		for i in 0 ..< len(v.text) {
			if !token_char(v.text[i]) {
				bare = false
				break
			}
		}
		if bare {
			strings.write_string(b, v.text)
		} else {
			strings.write_string(b, quote_text(v.text))
		}
	case .Array, .Object:
		view_compact(b, v)
	}
}

// One line for an event envelope: `TS TOPIC key=value key=value ...`, data fields
// in the order the daemon wrote them. `ok` is false when the envelope has no topic.
format_event_line :: proc(b: ^strings.Builder, envelope: View) -> (ok: bool) {
	topic_v, has_topic := view_get(envelope, "topic")
	if !has_topic || topic_v.kind != .String {
		return false
	}
	ts := "-"
	if ts_v, found := view_get(envelope, "ts"); found && ts_v.kind == .String {
		ts = safe_text(ts_v.text)
	}
	strings.write_string(b, ts)
	strings.write_byte(b, ' ')
	strings.write_string(b, safe_text(topic_v.text))
	if data, found := view_get(envelope, "data"); found && data.kind == .Object {
		for item, i in data.items {
			strings.write_byte(b, ' ')
			strings.write_string(b, safe_text(data.keys[i]))
			strings.write_byte(b, '=')
			event_value(b, item)
		}
	}
	strings.write_byte(b, '\n')
	return true
}

// ---- small helpers for the callers ----

// The number of a count field, or -1.
view_int :: proc(v: View, key: string) -> i64 {
	item, found := view_get(v, key)
	if !found || item.kind != .Number {
		return -1
	}
	n, ok := strconv.parse_i64(item.text)
	if !ok {
		return -1
	}
	return n
}

// ---- profiles ----

// A table: the columns are left aligned, two spaces apart; the last one is not padded.
write_table :: proc(b: ^strings.Builder, headers: []string, rows: [][]string) {
	widths := make([]int, len(headers), context.temp_allocator)
	for h, c in headers {
		widths[c] = utf8.rune_count_in_string(h)
	}
	for row in rows {
		for cell, c in row {
			widths[c] = max(widths[c], utf8.rune_count_in_string(cell))
		}
	}
	write_row :: proc(b: ^strings.Builder, cells: []string, widths: []int) {
		last := len(cells) - 1
		for last > 0 && cells[last] == "" {
			last -= 1
		}
		for cell, c in cells[:last + 1] {
			strings.write_string(b, cell)
			if c < last {
				pad(b, widths[c] - utf8.rune_count_in_string(cell) + 2)
			}
		}
		strings.write_byte(b, '\n')
	}
	write_row(b, headers, widths)
	for row in rows {
		write_row(b, row, widths)
	}
}

// The result of `profile set` and `profile check`: a table of the options with their
// disposition and note, then the hash, the label and the notes of the daemon.
format_profile :: proc(b: ^strings.Builder, result: View) {
	options, _ := view_get(result, "options")
	rows := make([dynamic][]string, context.temp_allocator)
	for o in options.items {
		row := make([]string, 4, context.temp_allocator)
		row[0] = field_text(o, "name")
		row[1] = field_text(o, "line")
		row[2] = field_text(o, "disposition")
		note, _ := view_get(o, "note")
		row[3] = "" if note.kind == .Null else scalar_text(note)
		append(&rows, row)
	}
	write_table(b, {"OPTION", "LINE", "DISPOSITION", "NOTE"}, rows[:])
	strings.write_byte(b, '\n')
	pairs := make([dynamic]Pair, context.temp_allocator)
	append(&pairs, Pair{"sha256", field_text(result, "sha256")})
	append(&pairs, Pair{"label", field_text(result, "label")})
	if notes, ok := view_get(result, "notes"); ok {
		for n in notes.items {
			append(&pairs, Pair{"note", scalar_text(n)})
		}
	}
	write_pairs(b, pairs[:])
}

@(private = "file")
field_text :: proc(v: View, key: string) -> string {
	item, found := view_get(v, key)
	if !found {
		return "-"
	}
	return scalar_text(item)
}

// The `details` of a refused profile: a table of the problems (line, option,
// class, reason). Writes nothing for other details.
format_problems :: proc(b: ^strings.Builder, details: json.Value) {
	list, is_list := details.(json.Array)
	if !is_list || len(list) == 0 {
		return
	}
	rows := make([dynamic][]string, context.temp_allocator)
	for item in list {
		obj, is_obj := item.(json.Object)
		if !is_obj {
			continue
		}
		row := make([]string, 4, context.temp_allocator)
		line, _ := obj["line"].(json.Integer)
		row[0] = "-" if line <= 0 else fmt.tprintf("%d", line)
		option, _ := obj["option"].(json.String)
		row[1] = "-" if option == "" else safe_text(string(option))
		class, _ := obj["class"].(json.String)
		row[2] = safe_text(string(class))
		reason, _ := obj["reason"].(json.String)
		row[3] = safe_text(string(reason))
		append(&rows, row)
	}
	write_table(b, {"LINE", "OPTION", "CLASS", "REASON"}, rows[:])
}
