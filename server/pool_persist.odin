// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:strings"
import "core:time"
import "noir:proto/config"

// `ifconfig-pool-persist`: the file that remembers which client had which
// address. This package reads and writes text. The daemon does the disk I/O:
//   - write a temporary file, then rename (a crash never leaves a half file)
//   - every `seconds` of the option while `pools_persist_dirty`, at startup and at
//     exit; read-only if `seconds` is 0
//
// Format, one client per line, no header, no comments:
//   name,ipv4
//   name,ipv4,ipv6
//   name,,ipv6            (a client that only has an IPv6 address)
// The first two are what stock writes (man page: "<Common-Name>,<IP-address>").
// The IPv6 field is our reading of the stock extension; the empty IPv4 field is
// ours.
// SPEC-GAP: the stock line for a dual-stack client is not in the man page
// summary; `name,ipv4,ipv6` is assumed. Names with a comma cannot be written
// without doubt: they are left out (they get a fresh address next time).
//
// The file is a suggestion, as in stock. An entry is skipped and reported if its
// address is outside the pool, reserved for a static client, or taken. Static
// addresses (`ifconfig-push`) are never written.

Persist_Skip_Reason :: enum u8 {
	// Not `name,ip[,ip6]`.
	Bad_Format,
	Line_Too_Long,
	Bad_Name,
	Bad_Ipv4,
	Bad_Ipv6,
	// The address is not inside the pool (or there is no such pool).
	Out_Of_Range,
	// The name is already in the file.
	Duplicate_Name,
	// The address is taken, or reserved for a static client.
	Address_Taken,
}

Persist_Skip :: struct {
	// 1-based line number.
	line:   int,
	reason: Persist_Skip_Reason,
}

// At most this many skipped lines are listed; `skipped_total` counts them all.
PERSIST_MAX_REPORT :: 64
PERSIST_MAX_LINE :: 600

Persist_Report :: struct {
	loaded:        int,
	skipped_total: int,
	skipped:       [dynamic]Persist_Skip,
}

persist_report_destroy :: proc(r: ^Persist_Report) {
	delete(r.skipped)
	r^ = {}
}

// Loads remembered addresses from file text. Call it once, at startup, before
// any client connects. Never fails as a whole: bad lines are skipped.
pools_persist_load :: proc(
	ps: ^Pools,
	text: string,
	now: time.Duration,
	allocator := context.allocator,
) -> (
	rep: Persist_Report,
) {
	rep.skipped = make([dynamic]Persist_Skip, allocator)
	skip :: proc(rep: ^Persist_Report, line: int, why: Persist_Skip_Reason) {
		rep.skipped_total += 1
		if len(rep.skipped) < PERSIST_MAX_REPORT {
			append(&rep.skipped, Persist_Skip{line, why})
		}
	}
	text := text
	if strings.has_prefix(text, "\xef\xbb\xbf") {
		text = text[3:]
	}
	lineno := 0
	for len(text) > 0 {
		line: string
		if nl := strings.index_byte(text, '\n'); nl >= 0 {
			line, text = text[:nl], text[nl + 1:]
		} else {
			line, text = text, ""
		}
		lineno += 1
		line = strings.trim_right(line, "\r")
		if len(line) == 0 {
			continue
		}
		if len(line) > PERSIST_MAX_LINE {
			skip(&rep, lineno, .Line_Too_Long)
			continue
		}
		// At most three fields; more is an error.
		fields: [4]string
		n := 0
		rest := line
		for {
			c := strings.index_byte(rest, ',')
			if n < len(fields) {
				fields[n] = rest if c < 0 else rest[:c]
			}
			n += 1
			if c < 0 || n > len(fields) {
				break
			}
			rest = rest[c + 1:]
		}
		if n < 2 || n > 3 {
			skip(&rep, lineno, .Bad_Format)
			continue
		}
		name, s4, s6 := fields[0], fields[1], fields[2] if n == 3 else ""
		if !identity_check(name) || strings.index_byte(name, ',') >= 0 {
			skip(&rep, lineno, .Bad_Name)
			continue
		}
		if s4 == "" && s6 == "" {
			skip(&rep, lineno, .Bad_Format)
			continue
		}
		slot4, slot6 := NONE, NONE
		if s4 != "" {
			a, ok := config.ipv4_parse(s4)
			if !ok {
				skip(&rep, lineno, .Bad_Ipv4)
				continue
			}
			s, in_range := NONE, false
			if ps.has4 {
				s, in_range = pool_slot_of(&ps.v4, u128(config.ipv4_to_u32(a)))
			}
			if !in_range {
				skip(&rep, lineno, .Out_Of_Range)
				continue
			}
			slot4 = s
		}
		if s6 != "" {
			a, ok := config.ipv6_parse(s6)
			if !ok {
				skip(&rep, lineno, .Bad_Ipv6)
				continue
			}
			s, in_range := NONE, false
			if ps.has6 {
				s, in_range = pool_slot_of(&ps.v6, u128_from_v6(a))
			}
			if !in_range {
				skip(&rep, lineno, .Out_Of_Range)
				continue
			}
			slot6 = s
		}
		// Check both before changing either, so a line is loaded whole or not
		// at all.
		if slot4 != NONE {
			if by_name_find(&ps.v4, name) != NONE {
				skip(&rep, lineno, .Duplicate_Name)
				continue
			}
			if !bit_tree_test(&ps.v4.virgin, int(slot4)) {
				skip(&rep, lineno, .Address_Taken)
				continue
			}
		}
		if slot6 != NONE {
			if by_name_find(&ps.v6, name) != NONE {
				skip(&rep, lineno, .Duplicate_Name)
				continue
			}
			if !bit_tree_test(&ps.v6.virgin, int(slot6)) {
				skip(&rep, lineno, .Address_Taken)
				continue
			}
		}
		if slot4 != NONE && !pool_remember(&ps.v4, slot4, name, now) {
			skip(&rep, lineno, .Address_Taken)
			continue
		}
		if slot6 != NONE && !pool_remember(&ps.v6, slot6, name, now) {
			// Undo the IPv4 half.
			if slot4 != NONE {
				slot_forget(&ps.v4, slot4)
			}
			skip(&rep, lineno, .Address_Taken)
			continue
		}
		rep.loaded += 1
	}
	return
}

@(private)
Persist_Row :: struct {
	name:  string,
	slot4: u32,
	slot6: u32,
}

// The file text for the current leases and memories. Allocated with
// `allocator`. Clears the dirty flag.
pools_persist_save :: proc(ps: ^Pools, allocator := context.allocator) -> string {
	rows := make([dynamic]Persist_Row, context.temp_allocator)
	index := make(map[string]int, context.temp_allocator)
	if ps.has4 {
		for &s, i in ps.v4.slots {
			if s.state == .Free || .Static in s.flags || len(s.name) == 0 {
				continue
			}
			if by_name_find(&ps.v4, s.name) != u32(i) || strings.index_byte(s.name, ',') >= 0 {
				continue
			}
			index[s.name] = len(rows)
			append(&rows, Persist_Row{s.name, u32(i), NONE})
		}
	}
	if ps.has6 {
		for &s, i in ps.v6.slots {
			if s.state == .Free || .Static in s.flags || len(s.name) == 0 {
				continue
			}
			if by_name_find(&ps.v6, s.name) != u32(i) || strings.index_byte(s.name, ',') >= 0 {
				continue
			}
			if r, found := index[s.name]; found {
				rows[r].slot6 = u32(i)
			} else {
				append(&rows, Persist_Row{s.name, NONE, u32(i)})
			}
		}
	}
	sb := strings.builder_make(allocator)
	for r in rows {
		strings.write_string(&sb, r.name)
		strings.write_byte(&sb, ',')
		if r.slot4 != NONE {
			write_ip4(&sb, config.ipv4_from_u32(u32(pool_addr(&ps.v4, r.slot4))))
		}
		if r.slot6 != NONE {
			strings.write_byte(&sb, ',')
			write_ip6(&sb, u128_to_v6(pool_addr(&ps.v6, r.slot6)))
		}
		strings.write_byte(&sb, '\n')
	}
	ps.persist_dirty = false
	return strings.to_string(sb)
}

// True if the leases changed since the last `pools_persist_save`.
pools_persist_dirty :: proc "contextless" (ps: ^Pools) -> bool {
	return ps.persist_dirty
}

// ---------------------------------------------------------------------------
// Address text

write_ip4 :: proc(sb: ^strings.Builder, a: [4]u8) {
	for b, i in a {
		if i > 0 {
			strings.write_byte(sb, '.')
		}
		strings.write_int(sb, int(b))
	}
}

// RFC 5952 form: lower case hex, the longest run of zero groups (two or more)
// as "::", the first run on a tie.
write_ip6 :: proc(sb: ^strings.Builder, a: [16]u8) {
	g: [8]u16
	for i in 0 ..< 8 {
		g[i] = u16(a[2 * i]) << 8 | u16(a[2 * i + 1])
	}
	best_at, best_len := -1, 0
	for i := 0; i < 8; {
		if g[i] != 0 {
			i += 1
			continue
		}
		j := i
		for j < 8 && g[j] == 0 {
			j += 1
		}
		if j - i > best_len {
			best_at, best_len = i, j - i
		}
		i = j
	}
	if best_len < 2 {
		best_at, best_len = -1, 0
	}
	hex := "0123456789abcdef"
	for i := 0; i < 8; i += 1 {
		if i == best_at {
			strings.write_string(sb, "::")
			i += best_len - 1
			continue
		}
		if i > 0 && i != best_at + best_len {
			strings.write_byte(sb, ':')
		}
		v := g[i]
		started := false
		for sh := 12; sh >= 0; sh -= 4 {
			d := (v >> u16(sh)) & 0xf
			if d != 0 || started || sh == 0 {
				strings.write_byte(sb, hex[d])
				started = true
			}
		}
	}
}
