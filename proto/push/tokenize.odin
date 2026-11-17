// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

// Word splitter for one pushed option.
//
// A PUSH_REPLY is split at commas first (an option never holds a comma, even in
// quotes), then each option into words at spaces:
//   - `"..."` and `'...'` group a word (spaces allowed); quotes are removed. A
//     quote may start mid-word.
//   - Backslash before `\`, `"` or space gives that character (not inside single
//     quotes). Before anything else it stays a backslash.
//   - Unquoted word starting with `;` or `#` is a comment: it and the rest of the
//     option are dropped.
//   - Leading and repeated spaces are skipped.
//
// SPEC-GAP: the spec is silent on where a quote may start, backslash before other
// characters, and `\"` inside double quotes. The choices above are the common
// shell-like reading.

MAX_OPTION_WORDS :: 32

// Words of one option. The text of every word is stored inside the struct
// (escapes and quotes already removed), so a `Words` can be copied.
Words :: struct {
	count: int,
	used:  int,
	off:   [MAX_OPTION_WORDS][2]u16,
	buf:   [MAX_COMMAND_LEN]u8,
}

// Word `i`, as a slice of `w.buf`. Empty if out of range.
words_get :: proc(w: ^Words, i: int) -> string {
	if i < 0 || i >= w.count {
		return ""
	}
	return string(w.buf[w.off[i][0]:w.off[i][1]])
}

// Splits one option. Errors: `.Bad_Quoting` (a quote that never closes),
// `.Too_Many_Words`, `.Oversize` (option longer than 2047 bytes).
tokenize_option :: proc(opt: string, w: ^Words) -> Error {
	w.count = 0
	w.used = 0
	if len(opt) >= MAX_COMMAND_LEN {
		return .Oversize
	}
	b := transmute([]u8)opt
	i := 0
	for {
		for i < len(b) && b[i] == ' ' {
			i += 1
		}
		if i >= len(b) {
			return .None
		}
		if b[i] == ';' || b[i] == '#' {
			return .None // comment: the rest is dropped
		}
		if w.count >= MAX_OPTION_WORDS {
			return .Too_Many_Words
		}
		start := w.used
		quote: u8 = 0
		for i < len(b) {
			c := b[i]
			if c == '\\' && quote != '\'' {
				if i + 1 < len(b) && (b[i + 1] == '\\' || b[i + 1] == '"' || b[i + 1] == ' ') {
					w.buf[w.used] = b[i + 1]
					i += 2
				} else {
					w.buf[w.used] = '\\'
					i += 1
				}
				w.used += 1
				continue
			}
			if quote != 0 {
				if c == quote {
					quote = 0
				} else {
					w.buf[w.used] = c
					w.used += 1
				}
				i += 1
				continue
			}
			if c == ' ' {
				break // end of the word
			}
			if c == '"' || c == '\'' {
				quote = c
				i += 1
				continue
			}
			w.buf[w.used] = c
			w.used += 1
			i += 1
		}
		if quote != 0 {
			return .Bad_Quoting
		}
		w.off[w.count] = {u16(start), u16(w.used)}
		w.count += 1
	}
}

// Option names and arguments joined back with single spaces, for logs and for
// the builder. Does not quote.
words_join :: proc(w: ^Words, buf: []u8) -> string {
	wr := Wr{buf = buf}
	for k in 0 ..< w.count {
		if k > 0 {
			wr_byte(&wr, ' ')
		}
		wr_str(&wr, words_get(w, k))
	}
	return string(buf[:wr.n])
}
