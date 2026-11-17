// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:mem"
import "core:strings"

// Rewrites of a profile text; other lines stay as they are. Used by the engine
// library and the desktop client:
// - the new key and certificate of `identity.set`
// - the login of the inline `<auth-user-pass>` block
//
//	identity_blocks(cert, key, chain, allocator) -> string    the <cert>, <key> and <extra-certs> blocks
//	identity_text(text, blocks, allocator) -> string          text without its key and certificate, then blocks
//	inline_login(text, allocator) -> (body, found)            the body of the inline <auth-user-pass> that counts
//	login_text(text, user, pass, allocator) -> (string, bool) text with a new login in that block
//	inline_block_span(text, name) -> (start, end, found)      where the body of the last inline <name> is
//	text_line_end(text) -> string                             "\r\n" or "\n"
//
// The results hold a key or a password. Wipe them before they are freed.

// The options that give a key or a certificate (as a file, or with a
// passphrase), and the inline blocks among them.
@(private = "file", rodata)
IDENTITY_OPTIONS := [?]string{"key", "cert", "pkcs12", "askpass", "extra-certs"}
@(private = "file", rodata)
IDENTITY_BLOCKS := [?]string{"key", "cert", "pkcs12", "extra-certs"}

// The inline blocks of a new identity, "\n" line ends: `<cert>` (leaf, PEM),
// `<key>` (PEM as is), and `<extra-certs>` (certificates after the leaf, only if
// `chain` is not ""). Each PEM ends with a line end. Holds the key: wipe it.
identity_blocks :: proc(cert, key, chain: string, allocator := context.allocator) -> string {
	parts := make([dynamic]string, 0, 8, context.temp_allocator)
	append(&parts, "<cert>\n", cert, "</cert>\n<key>\n", key, "</key>\n")
	if chain != "" {
		append(&parts, "<extra-certs>\n", chain, "</extra-certs>\n")
	}
	return strings.concatenate(parts[:], allocator)
}

// `text` without its key and certificate lines and blocks, then `blocks`. New
// lines use the line end of the first line of `text` ("\r\n" or "\n"); `blocks`
// has "\n". Uses `allocator`, holds the key of `blocks`: wipe it.
identity_text :: proc(text: string, blocks: string, allocator := context.allocator) -> string {
	crlf := text_line_end(text) == "\r\n"
	extra := strings.count(blocks, "\n") if crlf else 0
	sb := strings.builder_make(0, len(text) + len(blocks) + extra + 2, allocator)
	rest := text
	if strings.has_prefix(rest, "\xef\xbb\xbf") {
		strings.write_string(&sb, rest[:3])
		rest = rest[3:]
	}
	skip := "" // a block that is taken out, until its closing tag
	keep := "" // another inline block, copied as it is
	for len(rest) > 0 {
		end := strings.index_byte(rest, '\n')
		end = len(rest) if end < 0 else end + 1
		raw := rest[:end]
		rest = rest[end:]
		t := strings.trim(raw, " \t\r\n\v\f")
		switch {
		case skip != "":
			if closing_tag(t, skip) {
				skip = ""
			}
			continue
		case keep != "":
			strings.write_string(&sb, raw)
			if closing_tag(t, keep) {
				keep = ""
			}
			continue
		}
		if name, ok := opening_tag(t); ok {
			if is_one_of(name, IDENTITY_BLOCKS[:]) {
				skip = name
				continue
			}
			if name != "connection" {
				keep = name
			}
		} else if is_one_of(option_name(t), IDENTITY_OPTIONS[:]) {
			continue
		}
		strings.write_string(&sb, raw)
	}
	out := strings.to_string(sb)
	if len(out) > 0 && out[len(out) - 1] != '\n' {
		strings.write_string(&sb, "\r\n" if crlf else "\n")
	}
	if !crlf {
		strings.write_string(&sb, blocks)
	} else {
		b := blocks
		for len(b) > 0 {
			nl := strings.index_byte(b, '\n')
			if nl < 0 {
				strings.write_string(&sb, b)
				break
			}
			strings.write_string(&sb, b[:nl])
			strings.write_string(&sb, "\r\n")
			b = b[nl + 1:]
		}
	}
	return strings.to_string(sb)
}

// The login in a profile: the body of its inline `auth-user-pass` block (the
// last one counts, as for the engine). Uses `allocator`: wipe it. `found` is
// false for a plain line or none. The parse is wiped (the profile may hold a key).
inline_login :: proc(text: string, allocator := context.allocator) -> (body: string, found: bool) {
	parsed := parse_text(text, "profile", Parse_Options{no_files = true, wipeable = true})
	defer {
		store_wipe(parsed.store)
		parsed_destroy(&parsed)
	}
	last: ^Directive
	for &d in parsed.directives {
		if d.name == "auth-user-pass" {
			last = &d
		}
	}
	if last == nil || !last.has_body {
		return "", false
	}
	return strings.clone(last.body, allocator), true
}

// `text` with `user` and `pass` as the body of its inline `<auth-user-pass>`
// block, one per line, with the text's line end. Other lines stay. `ok` is false
// if there is no inline login. The caller checks the values. Holds the password: wipe it.
login_text :: proc(text, user, pass: string, allocator := context.allocator) -> (out: string, ok: bool) {
	body, inline := inline_login(text)
	if len(body) > 0 {
		mem.zero_explicit(raw_data(body), len(body))
	}
	delete(body)
	start, end, found := inline_block_span(text, "auth-user-pass")
	if !inline || !found {
		return "", false
	}
	le := text_line_end(text)
	parts := [?]string{text[:start], user, le, pass, le, text[end:]}
	return strings.concatenate(parts[:], allocator), true
}

// Body of the last inline block `<name>` outside any `<connection>` block: from
// the line after the opening tag to the start of the closing tag's line. Blocks
// are found as the profile parser finds them (another inline block is skipped
// whole).
inline_block_span :: proc(text: string, name: string) -> (body_start, body_end: int, found: bool) {
	pos := 0
	if strings.has_prefix(text, "\xef\xbb\xbf") {
		pos = 3
	}
	in_conn := false
	block := "" // the inline block we are in
	start := 0
	for pos < len(text) {
		line_start := pos
		end := strings.index_byte(text[pos:], '\n')
		pos = len(text) if end < 0 else pos + end + 1
		t := strings.trim(text[line_start:pos], " \t\r\n\v\f")
		if block != "" {
			if closing_tag(t, block) {
				if block == name && !in_conn {
					body_start, body_end, found = start, line_start, true
				}
				block = ""
			}
			continue
		}
		if in_conn && t == "</connection>" {
			in_conn = false
			continue
		}
		if tag, ok := opening_tag(t); ok {
			if tag == "connection" {
				in_conn = true
			} else {
				block, start = tag, pos
			}
		}
	}
	return
}

// The line end of a text: "\r\n" when its first line ends so, else "\n".
text_line_end :: proc(text: string) -> string {
	if nl := strings.index_byte(text, '\n'); nl > 0 && text[nl - 1] == '\r' {
		return "\r\n"
	}
	return "\n"
}

// The name of an opening tag `<name>` of an inline block, as the profile
// parser reads it (parse_lines).
@(private = "file")
opening_tag :: proc(t: string) -> (name: string, ok: bool) {
	if len(t) < 3 || t[0] != '<' || t[1] == '/' || t[len(t) - 1] != '>' {
		return "", false
	}
	name = t[1:len(t) - 1]
	if len(name) > 64 {
		return "", false
	}
	for ch in transmute([]u8)name {
		switch ch {
		case 'a' ..= 'z', '0' ..= '9', '-':
		case:
			return "", false
		}
	}
	return name, true
}

@(private = "file")
closing_tag :: proc(t: string, name: string) -> bool {
	return len(t) == len(name) + 3 && t[0] == '<' && t[1] == '/' && t[2:2 + len(name)] == name && t[len(t) - 1] == '>'
}

// The option name of a directive line (trimmed), with no "--"; "" for an empty
// line, a comment and a tag.
@(private = "file")
option_name :: proc(t: string) -> string {
	if t == "" || t[0] == '#' || t[0] == ';' || t[0] == '<' {
		return ""
	}
	name := t
	if t[0] == '"' || t[0] == '\'' {
		end := strings.index_byte(t[1:], t[0])
		name = t[1:] if end < 0 else t[1:1 + end]
	} else if i := strings.index_any(t, " \t\v\f"); i >= 0 {
		name = t[:i]
	}
	return strings.trim_prefix(name, "--")
}

@(private = "file")
is_one_of :: proc(s: string, list: []string) -> bool {
	for x in list {
		if s == x {
			return true
		}
	}
	return false
}
