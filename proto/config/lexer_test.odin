// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

// Lexes one line with the default allocator and returns the tokens as a
// joined string for easy comparison: tokens are wrapped in [] and joined.
lex_join :: proc(line: string) -> (s: string, err: Lex_Error) {
	toks: [dynamic]string
	scratch: [dynamic]u8
	defer delete(toks)
	defer delete(scratch)
	err = lex_line(line, &toks, &scratch, context.temp_allocator)
	sb := strings.builder_make(context.temp_allocator)
	for t in toks {
		strings.write_byte(&sb, '[')
		strings.write_string(&sb, t)
		strings.write_byte(&sb, ']')
	}
	return strings.to_string(sb), err
}

@(private = "file")
expect_lex :: proc(t: ^testing.T, line, want: string, loc := #caller_location) {
	got, err := lex_join(line)
	testing.expectf(t, err == .None, "line %q: unexpected error %v", line, err, loc = loc)
	testing.expectf(t, got == want, "line %q:\n  got  %s\n  want %s", line, got, want, loc = loc)
}

@(private = "file")
expect_lex_err :: proc(t: ^testing.T, line: string, want: Lex_Error, loc := #caller_location) {
	_, err := lex_join(line)
	testing.expectf(t, err == want, "line %q: got error %v, want %v", line, err, want, loc = loc)
}

@(test)
test_lex_plain :: proc(t: ^testing.T) {
	expect_lex(t, "remote vpn.example.com 1194", "[remote][vpn.example.com][1194]")
	expect_lex(t, "  verb\t3  ", "[verb][3]")
	expect_lex(t, "client", "[client]")
	expect_lex(t, "", "")
	expect_lex(t, "   \t ", "")
	// A CR left over from a CRLF line end counts as white space.
	expect_lex(t, "verb 3\r", "[verb][3]")
}

@(test)
test_lex_double_quotes :: proc(t: ^testing.T) {
	expect_lex(t, `push "route 10.0.0.0 255.0.0.0"`, "[push][route 10.0.0.0 255.0.0.0]")
	expect_lex(t, `a "" b`, "[a][][b]")
	expect_lex(t, `a "x  y"`, "[a][x  y]")
	// A quote in the middle of an argument is an ordinary character.
	expect_lex(t, `a b"c d`, `[a][b"c][d]`)
	expect_lex(t, `a it's`, "[a][it's]")
	// A hash or semicolon inside the line is not a comment.
	expect_lex(t, "a b #c ;d", "[a][b][#c][;d]")
}

@(test)
test_lex_single_quotes :: proc(t: ^testing.T) {
	expect_lex(t, `a 'b c'`, "[a][b c]")
	// Backslashes and double quotes stay as written inside single quotes.
	expect_lex(t, `a 'b\c "d"'`, `[a][b\c "d"]`)
	expect_lex(t, `a ''`, "[a][]")
}

@(test)
test_lex_escapes :: proc(t: ^testing.T) {
	expect_lex(t, `a b\ c`, "[a][b c]")
	expect_lex(t, `a b\\c`, `[a][b\c]`)
	expect_lex(t, `a b\"c`, `[a][b"c]`)
	expect_lex(t, `a "x\"y"`, `[a][x"y]`)
	expect_lex(t, `a "x\\y"`, `[a][x\y]`)
	expect_lex(t, `a "x\ y"`, "[a][x y]")
	// A backslash before an ordinary character stays, so Windows paths work.
	expect_lex(t, `a c:\temp\file`, `[a][c:\temp\file]`)
	expect_lex(t, `a "c:\temp"`, `[a][c:\temp]`)
	expect_lex(t, `a \\server\share`, `[a][\server\share]`)
	expect_lex(t, "a b\\\tc", "[a][b\tc]")
}

@(test)
test_lex_errors :: proc(t: ^testing.T) {
	expect_lex_err(t, `a "b`, .Unterminated_Quote)
	expect_lex_err(t, `a 'b`, .Unterminated_Quote)
	expect_lex_err(t, `a "b\"`, .Unterminated_Quote)
	expect_lex_err(t, `a b\`, .Dangling_Backslash)
	expect_lex_err(t, `a "b\`, .Dangling_Backslash)
	expect_lex_err(t, `a "b"c`, .Text_After_Quote)
	expect_lex_err(t, `a 'b'c`, .Text_After_Quote)
	expect_lex_err(t, "a b\x00c", .Nul_Byte)
	// "a" followed by MAX_ARGS more arguments is one too many.
	sb := strings.builder_make(context.temp_allocator)
	for _ in 0 ..= MAX_ARGS {
		strings.write_string(&sb, "x ")
	}
	expect_lex_err(t, strings.to_string(sb), .Too_Many_Args)
}

@(test)
test_lex_max_args_ok :: proc(t: ^testing.T) {
	sb := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< MAX_ARGS {
		strings.write_string(&sb, "x ")
	}
	got, err := lex_join(strings.to_string(sb))
	testing.expect_value(t, err, Lex_Error.None)
	testing.expect_value(t, len(got), MAX_ARGS * 3)
}

@(test)
test_lex_slices_avoid_copy :: proc(t: ^testing.T) {
	// An argument without escapes points into the line.
	line := "remote host 1194"
	toks: [dynamic]string
	scratch: [dynamic]u8
	defer delete(toks)
	defer delete(scratch)
	err := lex_line(line, &toks, &scratch, context.temp_allocator)
	testing.expect_value(t, err, Lex_Error.None)
	testing.expect(t, len(toks) == 3)
	testing.expect(
		t,
		raw_data(toks[1]) == &(transmute([]u8)line)[7],
		"argument should be a slice of the line",
	)
}

@(test)
test_trim_space :: proc(t: ^testing.T) {
	testing.expect_value(t, trim_space("  a b \t\r"), "a b")
	testing.expect_value(t, trim_space(""), "")
	testing.expect_value(t, trim_space(" \t"), "")
}

@(test)
test_lex_error_text_all :: proc(t: ^testing.T) {
	for e in Lex_Error {
		if e == .None {
			continue
		}
		testing.expectf(t, len(lex_error_text(e)) > 0, "no text for %v", e)
	}
}
