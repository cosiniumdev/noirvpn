// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:fmt"
import "core:mem"
import "core:strings"
import "noir:proto/ossl"

// The hash file (`peer-passwords FILE`): user names and password hashes.
//
//	# a comment line
//	<user name><TAB>pbkdf2-sha256:<iterations>:<salt>:<hash>
//
// `salt` and `hash` are standard base64 with padding.
// - The table holds only parsed lines. It never sees a password: the daemon does
//   the PBKDF2 check on a worker thread, from a copy of one entry.
// - Lookup folds ASCII case (`name_equal`). Lines differing only in case are one
//   user: the first counts, the other gets a warning.
// - An unreadable line is left out with a warning (never containing the hash).
// - A table is built once and never changes. A reload builds a new one.

PW_SCHEME :: "pbkdf2-sha256"
PW_MAX_ITERATIONS :: 10_000_000
PW_SALT_MAX :: 64
PW_HASH_MAX :: 64
// Shortest accepted salt and hash.
PW_SALT_MIN :: 1
PW_HASH_MIN :: 16
// The file may not be larger than this, and a line may not be longer.
PW_FILE_MAX :: 8 * 1024 * 1024
PW_LINE_MAX :: 1024
// Warnings kept per table; the rest are only counted.
PW_WARNINGS_MAX :: 20

Pw_Entry :: struct {
	user:       string, // as the file spells it
	iterations: int,
	salt_n:     u8,
	hash_n:     u8,
	salt:       [PW_SALT_MAX]u8,
	hash:       [PW_HASH_MAX]u8,
}

Pw_Table :: struct {
	entries:    [dynamic]Pw_Entry,
	index:      map[string]int, // the folded user name to the place in `entries`
	warnings:   [dynamic]string,
	skipped:    int, // lines left out because they cannot be read
	duplicates: int, // lines left out because an earlier line has the user
	// The cost of the lines, for the decoy check (`pw_decoy`): the iteration
	// count that most lines have (the larger one if two counts tie), and the
	// salt and hash lengths of the first line with that count. 0: no lines.
	decoy_iterations: int,
	decoy_salt_n:     int,
	decoy_hash_n:     int,
	allocator:  mem.Allocator,
}

// What the decoy check of an unknown user costs when the table has no lines
// (or there is no table).
PW_DECOY_ITERATIONS :: 260_000
PW_DECOY_SALT_N :: 16
PW_DECOY_HASH_N :: 32

// The iterations, salt length and hash length of the decoy check: those of the
// lines of the file, so the time of a refusal does not tell if the user exists.
pw_decoy :: proc(t: ^Pw_Table) -> (iterations, salt_n, hash_n: int) {
	if t == nil || t.decoy_iterations == 0 {
		return PW_DECOY_ITERATIONS, PW_DECOY_SALT_N, PW_DECOY_HASH_N
	}
	return t.decoy_iterations, t.decoy_salt_n, t.decoy_hash_n
}

@(private = "file")
pw_pick_decoy :: proc(t: ^Pw_Table) {
	counts := make(map[int]int, allocator = context.temp_allocator)
	for e in t.entries {
		counts[e.iterations] += 1
	}
	best, best_n := 0, 0
	for its, n in counts {
		if n > best_n || (n == best_n && its > best) {
			best, best_n = its, n
		}
	}
	for e in t.entries {
		if e.iterations == best {
			t.decoy_iterations, t.decoy_salt_n, t.decoy_hash_n = best, int(e.salt_n), int(e.hash_n)
			return
		}
	}
}

pw_destroy :: proc(t: ^Pw_Table) {
	if t == nil {
		return
	}
	a := t.allocator
	for e in t.entries {
		delete(e.user, a)
	}
	delete(t.entries)
	for k in t.index {
		delete(k, a)
	}
	delete(t.index)
	for w in t.warnings {
		delete(w, a)
	}
	delete(t.warnings)
	free(t, a)
}

pw_len :: proc "contextless" (t: ^Pw_Table) -> int {
	return len(t.entries) if t != nil else 0
}

// The entry of a user name, folding ASCII case. Nil when there is none.
pw_find :: proc(t: ^Pw_Table, user: string) -> ^Pw_Entry {
	if t == nil || len(user) == 0 || len(user) > MAX_IDENTITY_LEN {
		return nil
	}
	var: [MAX_IDENTITY_LEN]u8
	for i in 0 ..< len(user) {
		var[i] = ascii_lower(user[i])
	}
	i, ok := t.index[string(var[:len(user)])]
	if !ok {
		return nil
	}
	return &t.entries[i]
}

// The same hash line: iterations, salt and hash.
pw_same_line :: proc "contextless" (a, b: ^Pw_Entry) -> bool {
	if a.iterations != b.iterations || a.salt_n != b.salt_n || a.hash_n != b.hash_n {
		return false
	}
	return mem.compare(a.salt[:a.salt_n], b.salt[:b.salt_n]) == 0 && mem.compare(a.hash[:a.hash_n], b.hash[:b.hash_n]) == 0
}

// A digest of the hash line of an entry (iterations, salt and hash). A session
// keeps it to see that its user still has the same hash.
pw_entry_digest :: proc(e: ^Pw_Entry) -> [32]u8 {
	buf: [8 + 2 + PW_SALT_MAX + PW_HASH_MAX]u8
	it := u64(e.iterations)
	for i in 0 ..< 8 {
		buf[i] = u8(it >> uint(8 * i))
	}
	buf[8] = e.salt_n
	buf[9] = e.hash_n
	n := 10
	n += copy(buf[n:], e.salt[:e.salt_n])
	n += copy(buf[n:], e.hash[:e.hash_n])
	return ossl.sha256(buf[:n])
}

@(private = "file")
pw_warn :: proc(t: ^Pw_Table, line: int, text: string) {
	if len(t.warnings) >= PW_WARNINGS_MAX {
		return
	}
	append(&t.warnings, strings.clone(fmt.tprintf("line %d: %s", line, text), t.allocator))
}

// Parses the text of a hash file. Always gives a table; read `warnings`. A line
// that is wrong is left out.
pw_parse :: proc(text: string, allocator := context.allocator) -> ^Pw_Table {
	t := new(Pw_Table, allocator)
	t.allocator = allocator
	t.entries = make([dynamic]Pw_Entry, allocator)
	t.index = make(map[string]int, allocator = allocator)
	t.warnings = make([dynamic]string, allocator)
	rest := text
	n := 0
	for len(rest) > 0 {
		line := rest
		if i := strings.index_byte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i + 1:]
		} else {
			rest = ""
		}
		n += 1
		if len(line) > 0 && line[len(line) - 1] == '\r' {
			line = line[:len(line) - 1]
		}
		if len(line) == 0 || line[0] == '#' || strings.trim_space(line) == "" {
			continue
		}
		pw_add_line(t, n, line)
	}
	pw_pick_decoy(t)
	return t
}

@(private = "file")
pw_add_line :: proc(t: ^Pw_Table, n: int, line: string) {
	if len(line) > PW_LINE_MAX {
		t.skipped += 1
		pw_warn(t, n, "the line is too long, so it was skipped")
		return
	}
	tab := strings.index_byte(line, '\t')
	if tab < 0 {
		t.skipped += 1
		pw_warn(t, n, "there is no TAB between the user name and the hash, so the line was skipped")
		return
	}
	user := line[:tab]
	hash_text := strings.trim_space(line[tab + 1:])
	if !identity_check(user) {
		t.skipped += 1
		pw_warn(t, n, "the user name is not valid, so the line was skipped")
		return
	}
	e: Pw_Entry
	why := pw_parse_hash(hash_text, &e)
	if why != "" {
		t.skipped += 1
		pw_warn(t, n, strings.concatenate({"user ", user, ": ", why, ", so the line was skipped"}, context.temp_allocator))
		return
	}
	// Fold the name for the index.
	folded := make([]u8, len(user), t.allocator)
	for i in 0 ..< len(user) {
		folded[i] = ascii_lower(user[i])
	}
	key := string(folded)
	if _, dup := t.index[key]; dup {
		delete(key, t.allocator)
		t.duplicates += 1
		pw_warn(t, n, strings.concatenate({"user ", user, " is already in the file (names are not case-sensitive), so the line was skipped"}, context.temp_allocator))
		return
	}
	e.user = strings.clone(user, t.allocator)
	append(&t.entries, e)
	t.index[key] = len(t.entries) - 1
}

// `pbkdf2-sha256:<iterations>:<salt>:<hash>`. Returns "" when it is right, else
// the reason (never has the text of the hash).
pw_parse_hash :: proc(text: string, e: ^Pw_Entry) -> string {
	parts: [5]string
	count := 0
	rest := text
	for count < len(parts) {
		i := strings.index_byte(rest, ':')
		if i < 0 {
			parts[count] = rest
			count += 1
			break
		}
		parts[count] = rest[:i]
		count += 1
		rest = rest[i + 1:]
	}
	if count != 4 || parts[0] != PW_SCHEME {
		return "the hash is not in the form `pbkdf2-sha256:ITERATIONS:SALT:HASH`"
	}
	its := parts[1]
	if len(its) == 0 || len(its) > 8 {
		return "the iteration count must be from 1 to 10000000"
	}
	v := 0
	for c in transmute([]u8)its {
		if c < '0' || c > '9' {
			return "the iteration count must be from 1 to 10000000"
		}
		v = v * 10 + int(c - '0')
	}
	if v < 1 || v > PW_MAX_ITERATIONS {
		return "the iteration count must be from 1 to 10000000"
	}
	e.iterations = v
	n, ok := b64_decode(parts[2], e.salt[:])
	if !ok || n < PW_SALT_MIN {
		return "the salt must be base64 of 1 to 64 bytes"
	}
	e.salt_n = u8(n)
	n, ok = b64_decode(parts[3], e.hash[:])
	if !ok || n < PW_HASH_MIN {
		return "the hash must be base64 of 16 to 64 bytes"
	}
	e.hash_n = u8(n)
	return ""
}

// Standard base64 with padding, in its one canonical form. False for a wrong
// character, a wrong length, padding in the middle, bits that should be zero,
// or output that does not fit in `out`.
b64_decode :: proc "contextless" (s: string, out: []u8) -> (n: int, ok: bool) {
	if len(s) == 0 || len(s) % 4 != 0 {
		return 0, false
	}
	val :: proc "contextless" (c: u8) -> int {
		switch {
		case c >= 'A' && c <= 'Z':
			return int(c - 'A')
		case c >= 'a' && c <= 'z':
			return int(c - 'a') + 26
		case c >= '0' && c <= '9':
			return int(c - '0') + 52
		case c == '+':
			return 62
		case c == '/':
			return 63
		}
		return -1
	}
	groups := len(s) / 4
	for g in 0 ..< groups {
		q := s[g * 4:][:4]
		pad := 0
		if g == groups - 1 {
			if q[3] == '=' {
				pad = 1
				if q[2] == '=' {
					pad = 2
				}
			}
		}
		var: [4]int
		for i in 0 ..< 4 - pad {
			var[i] = val(q[i])
			if var[i] < 0 {
				return 0, false
			}
		}
		for i in 4 - pad ..< 4 {
			if q[i] != '=' {
				return 0, false
			}
		}
		bits := var[0] << 18 | var[1] << 12 | var[2] << 6 | var[3]
		take := 3 - pad
		// The unused bits of the last character must be zero.
		if pad == 2 && var[1] & 0xf != 0 {
			return 0, false
		}
		if pad == 1 && var[2] & 0x3 != 0 {
			return 0, false
		}
		if n + take > len(out) {
			return 0, false
		}
		for k in 0 ..< take {
			out[n + k] = u8(bits >> uint(16 - 8 * k))
		}
		n += take
	}
	return n, true
}

// ---------------------------------------------------------------- the diff

Pw_Change_Kind :: enum u8 {
	Added,
	Removed,
	Changed,
}

Pw_Change :: struct {
	kind: Pw_Change_Kind,
	user: string, // the spelling of the table that has the user (a copy)
}

// What a new table does to the users of an old one. Each name in the result
// is a copy allocated with `allocator`. `old` may be nil (a file that was lost).
pw_diff :: proc(old, new_table: ^Pw_Table, allocator := context.allocator) -> (changes: [dynamic]Pw_Change) {
	changes = make([dynamic]Pw_Change, allocator)
	if old != nil {
		for i in 0 ..< len(old.entries) {
			oe := &old.entries[i]
			ne := pw_find(new_table, oe.user)
			switch {
			case ne == nil:
				append(&changes, Pw_Change{.Removed, strings.clone(oe.user, allocator)})
			case !pw_same_line(oe, ne):
				append(&changes, Pw_Change{.Changed, strings.clone(ne.user, allocator)})
			}
		}
	}
	if new_table != nil {
		for i in 0 ..< len(new_table.entries) {
			ne := &new_table.entries[i]
			if pw_find(old, ne.user) == nil {
				append(&changes, Pw_Change{.Added, strings.clone(ne.user, allocator)})
			}
		}
	}
	return
}

pw_changes_destroy :: proc(c: ^[dynamic]Pw_Change, allocator := context.allocator) {
	for ch in c {
		delete(ch.user, allocator)
	}
	delete(c^)
}
