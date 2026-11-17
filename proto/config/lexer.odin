// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:mem"
import "core:strings"

// Most arguments one directive may have.
MAX_ARGS :: 128

Lex_Error :: enum u8 {
	None,
	// A quote was opened and the line ended.
	Unterminated_Quote,
	// A backslash was the last character of the line.
	Dangling_Backslash,
	// A quoted argument was followed by more text without a space.
	Text_After_Quote,
	// A NUL byte in the line.
	Nul_Byte,
	// More than MAX_ARGS arguments.
	Too_Many_Args,
}

lex_error_text :: proc(e: Lex_Error) -> string {
	switch e {
	case .None:
		return ""
	case .Unterminated_Quote:
		return "quote is not closed"
	case .Dangling_Backslash:
		return "the line ends with a backslash"
	case .Text_After_Quote:
		return "there is text directly after a closing quote; put a space between arguments"
	case .Nul_Byte:
		return "the line contains a NUL byte"
	case .Too_Many_Args:
		return "the line has too many arguments"
	}
	return ""
}

@(private)
is_space :: #force_inline proc "contextless" (c: u8) -> bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'
}

// Removes leading and trailing white space.
@(private)
trim_space :: proc "contextless" (s: string) -> string {
	i, j := 0, len(s)
	for i < j && is_space(s[i]) {
		i += 1
	}
	for j > i && is_space(s[j - 1]) {
		j -= 1
	}
	return s[i:j]
}

// Splits one config line into arguments (the first is the option name).
// Rules (upstream man page, "--config"):
//   - White space (space, tab) separates arguments.
//   - A leading double or single quote encloses an argument that may hold white
//     space. It ends at the next quote of the same kind, which white space or
//     the line end must follow. A quote inside an argument is ordinary.
//   - Outside single quotes, a backslash escapes a following backslash, quote or
//     white space. Before any other character it stays (`c:\temp` stays as written).
//   - Single quotes keep everything as written, backslashes too.
//   - The caller removes comment lines (`#` or `;` first) before calling.
// Arguments are slices of `line` where possible; one that needed an escape or
// quote removal is copied into `allocator`. `scratch` is a work buffer the caller
// owns and may reuse between calls.
lex_line :: proc(
	line: string,
	out: ^[dynamic]string,
	scratch: ^[dynamic]u8,
	allocator: mem.Allocator,
) -> Lex_Error {
	if strings.index_byte(line, 0) >= 0 {
		return .Nul_Byte
	}
	n := len(line)
	i := 0
	for {
		for i < n && is_space(line[i]) {
			i += 1
		}
		if i >= n {
			break
		}
		if len(out) >= MAX_ARGS {
			return .Too_Many_Args
		}
		clear(scratch)
		start := i
		copied := false // an escape was processed, so the text is in `scratch`
		quote := u8(0)
		if line[i] == '"' || line[i] == '\'' {
			quote = line[i]
			i += 1
			start = i
		}
		end := 0
		if quote != 0 {
			for {
				if i >= n {
					return .Unterminated_Quote
				}
				ch := line[i]
				if ch == quote {
					end = i
					i += 1
					break
				}
				if quote == '"' && ch == '\\' {
					if i + 1 >= n {
						return .Dangling_Backslash
					}
					if escapable(line[i + 1]) {
						copied = true
						append(scratch, line[i + 1])
						i += 2
						continue
					}
				}
				append(scratch, ch)
				i += 1
			}
			if i < n && !is_space(line[i]) {
				return .Text_After_Quote
			}
		} else {
			for i < n && !is_space(line[i]) {
				ch := line[i]
				if ch == '\\' {
					if i + 1 >= n {
						return .Dangling_Backslash
					}
					if escapable(line[i + 1]) {
						copied = true
						append(scratch, line[i + 1])
						i += 2
						continue
					}
				}
				append(scratch, ch)
				i += 1
			}
			end = i
		}
		if copied {
			append(out, strings.clone(string(scratch[:]), allocator))
		} else {
			append(out, line[start:end])
		}
	}
	return .None
}

// True for the characters a backslash may escape.
@(private)
escapable :: #force_inline proc "contextless" (c: u8) -> bool {
	return c == '\\' || c == '"' || c == '\'' || c == ' ' || c == '\t'
}
