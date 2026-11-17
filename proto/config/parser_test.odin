// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

// Names of the directives, joined with spaces.
names_of :: proc(dirs: []Directive) -> string {
	sb := strings.builder_make(context.temp_allocator)
	for d, i in dirs {
		if i > 0 {
			strings.write_byte(&sb, ' ')
		}
		strings.write_string(&sb, d.name)
	}
	return strings.to_string(sb)
}

@(test)
test_parse_basic :: proc(t: ^testing.T) {
	text := "# a comment\n; another\n\nclient\n  remote  vpn.example.com   1194  \n--verb 4\nnobind\n"
	p := parse_text(text, "a.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "client remote verb nobind")
	testing.expect_value(t, p.directives[1].line, 5)
	testing.expect_value(t, p.directives[1].file, "a.conf")
	testing.expect_value(t, len(p.directives[1].args), 2)
	testing.expect_value(t, p.directives[1].args[1], "1194")
	// The `--` prefix is optional in a file.
	testing.expect_value(t, p.directives[2].name, "verb")
	testing.expect_value(t, p.directives[2].line, 6)
}

@(test)
test_parse_comment_only_at_line_start :: proc(t: ^testing.T) {
	// A hash after other text is an argument (man page, config).
	p := parse_text("verb 3 # not a comment\n", "a.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.directives), 1)
	testing.expect_value(t, len(p.directives[0].args), 5)
	// A comment may be indented.
	p2 := parse_text("   # indented\n\t; tab\nclient\n", "a.conf")
	defer parsed_destroy(&p2)
	testing.expect_value(t, names_of(p2.directives), "client")
}

@(test)
test_parse_crlf_and_bom :: proc(t: ^testing.T) {
	p := parse_text(
		"\xef\xbb\xbfclient\r\nremote a.example 1194\r\n<ca>\r\nLINE1\r\nLINE2\r\n</ca>\r\n",
		"w.conf",
	)
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "client remote ca")
	testing.expect_value(t, p.directives[1].args[1], "1194")
	testing.expect(t, p.directives[2].has_body)
	// CRLF in an inline block becomes LF.
	testing.expect_value(t, p.directives[2].body, "LINE1\nLINE2\n")
}

@(test)
test_parse_no_trailing_newline :: proc(t: ^testing.T) {
	p := parse_text("client\nverb 3", "a.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, names_of(p.directives), "client verb")
	p2 := parse_text("", "a.conf")
	defer parsed_destroy(&p2)
	testing.expect_value(t, len(p2.directives), 0)
	p3 := parse_text("\xef\xbb\xbf", "a.conf")
	defer parsed_destroy(&p3)
	testing.expect_value(t, len(p3.directives), 0)
}

@(test)
test_parse_quoting_in_file :: proc(t: ^testing.T) {
	p := parse_text(
		"push \"route 10.1.0.0 255.255.0.0\"\nauth-user-pass 'my file.txt'\nca my\\ ca.crt\n",
		"q.conf",
	)
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, p.directives[0].args[0], "route 10.1.0.0 255.255.0.0")
	testing.expect_value(t, p.directives[1].args[0], "my file.txt")
	testing.expect_value(t, p.directives[2].args[0], "my ca.crt")
}

@(test)
test_parse_bad_syntax_has_file_and_line :: proc(t: ^testing.T) {
	p := parse_text("client\nremote \"unterminated 1194\nverb 3\nca file\\\nnobind\n", "bad.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 2)
	// Bad lines are skipped; good lines survive.
	testing.expect_value(t, names_of(p.directives), "client verb nobind")
	if len(p.diags) == 2 {
		testing.expect_value(t, p.diags[0].file, "bad.conf")
		testing.expect_value(t, p.diags[0].line, 2)
		testing.expect_value(t, p.diags[0].severity, Severity.Error)
		testing.expect_value(t, p.diags[1].line, 4)
	}
	expect_error(t, p.diags, 2, "quote is not closed")
	expect_error(t, p.diags, 4, "backslash")
}

@(test)
test_parse_nul_byte :: proc(t: ^testing.T) {
	p := parse_text("client\nverb\x003\n", "n.conf")
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 2, "NUL")
	testing.expect_value(t, names_of(p.directives), "client")
}

@(test)
test_parse_very_long_lines :: proc(t: ^testing.T) {
	// A line just under the limit is fine; one over is an error, and the
	// lines around it still parse.
	ok_arg, _ := strings.repeat("x", 60 * 1024, context.temp_allocator)
	bad_arg, _ := strings.repeat("y", DEFAULT_MAX_LINE, context.temp_allocator)
	text := strings.concatenate(
		{"client\nremark ", ok_arg, "\nremark ", bad_arg, "\nnobind\n"},
		context.temp_allocator,
	)
	p := parse_text(text, "long.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, names_of(p.directives), "client remark nobind")
	testing.expect_value(t, len(p.directives[1].args[0]), 60 * 1024)
	expect_error(t, p.diags, 3, "too long")

	// The limit can be changed.
	p2 := parse_text("client\nverb 3 4 5\n", "x.conf", Parse_Options{max_line = 8})
	defer parsed_destroy(&p2)
	expect_error(t, p2.diags, 2, "too long")
	testing.expect_value(t, names_of(p2.directives), "client")
}

@(test)
test_parse_many_args :: proc(t: ^testing.T) {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "push")
	for _ in 0 ..= MAX_ARGS {
		strings.write_string(&sb, " a")
	}
	p := parse_text(strings.to_string(sb), "m.conf")
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 1, "too many arguments")
}

@(test)
test_parse_inline_blocks :: proc(t: ^testing.T) {
	text := `client
<ca>
-----BEGIN CERTIFICATE-----
# not a comment inside a block
; nor this
MIIB
-----END CERTIFICATE-----
</ca>
<tls-crypt>
# 2048 bit OpenVPN static key
-----BEGIN OpenVPN Static key V1-----
00112233
-----END OpenVPN Static key V1-----
</tls-crypt>
<peer-fingerprint>
AA:BB
</peer-fingerprint>
verb 3
`
	p := parse_text(text, "b.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "client ca tls-crypt peer-fingerprint verb")
	ca := p.directives[1]
	testing.expect(t, ca.has_body)
	testing.expect_value(t, ca.line, 2)
	testing.expect(t, strings.contains(ca.body, "# not a comment inside a block\n"))
	testing.expect(t, strings.contains(ca.body, "; nor this\n"))
	testing.expect(t, strings.has_prefix(ca.body, "-----BEGIN CERTIFICATE-----\n"))
	testing.expect(t, strings.has_suffix(ca.body, "-----END CERTIFICATE-----\n"))
	testing.expect_value(t, p.directives[2].name, "tls-crypt")
	testing.expect(t, strings.has_prefix(p.directives[2].body, "# 2048 bit"))
	// The directive after a block has the right line number.
	testing.expect_value(t, p.directives[4].line, 18)
}

@(test)
test_parse_inline_block_edge_cases :: proc(t: ^testing.T) {
	// Empty block, indented tags, closing tag without a newline at the end.
	p := parse_text("<cert>\n</cert>\n  <key>  \nK\n  </key>  \n<ca>\nX\n</ca>", "e.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "cert key ca")
	testing.expect_value(t, p.directives[0].body, "")
	testing.expect(t, p.directives[0].has_body)
	testing.expect_value(t, p.directives[1].body, "K\n")
	testing.expect_value(t, p.directives[2].body, "X\n")
}

@(test)
test_parse_inline_block_errors :: proc(t: ^testing.T) {
	p := parse_text("client\n<ca>\nabc\nverb 3\n", "u.conf")
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 2, "not closed")
	testing.expect_value(t, names_of(p.directives), "client")

	p2 := parse_text("client\n</ca>\n<ca\nverb 3\n", "u.conf")
	defer parsed_destroy(&p2)
	expect_error(t, p2.diags, 2, "has no matching opening tag")
	expect_error(t, p2.diags, 3, "is not a valid tag")
	testing.expect_value(t, names_of(p2.directives), "client verb")

	// A block closed with the wrong tag is not closed at all.
	p3 := parse_text("<ca>\nabc\n</cert>\n", "u.conf")
	defer parsed_destroy(&p3)
	expect_error(t, p3.diags, 1, "not closed")

	p4 := parse_text("<Bad Name>\nx\n</Bad Name>\n", "u.conf")
	defer parsed_destroy(&p4)
	testing.expect(t, diags_have_error(p4.diags))
}

@(test)
test_parse_inline_block_too_large :: proc(t: ^testing.T) {
	p := parse_text("<ca>\nabcdefghij\n</ca>\nverb 3\n", "l.conf", Parse_Options{max_inline = 5})
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 1, "too large")
	testing.expect_value(t, names_of(p.directives), "verb")
}

@(test)
test_parse_connection_blocks :: proc(t: ^testing.T) {
	text := "client\n<connection>\nremote a.example 1194 udp\n</connection>\n<connection>\nremote b.example 443 tcp\nproto tcp\n</connection>\nverb 3\n"
	p := parse_text(text, "c.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "client connection connection verb")
	testing.expect_value(t, len(p.directives[1].block), 1)
	testing.expect_value(t, len(p.directives[2].block), 2)
	testing.expect_value(t, p.directives[2].block[1].line, 7)

	p2 := parse_text("<connection>\nremote a 1\n", "c.conf")
	defer parsed_destroy(&p2)
	expect_error(t, p2.diags, 1, "not closed")

	p3 := parse_text(
		"<connection>\n<connection>\nremote a 1\n</connection>\n</connection>\n",
		"c.conf",
	)
	defer parsed_destroy(&p3)
	expect_error(t, p3.diags, 2, "cannot contain another <connection> block")
}

@(test)
test_parse_include :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["main.conf"] = "client\nconfig extra.conf\nnobind\n"
	files["extra.conf"] = "verb 5\nconfig deep.conf\n"
	files["deep.conf"] = "<ca>\nX\n</ca>\n"
	opts := Parse_Options {
		loader      = mem_loader,
		loader_data = &files,
	}
	p := parse_file("main.conf", opts)
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	// Included directives sit where the `config` line was. The `config` line
	// itself stays so it can be reported.
	testing.expect_value(t, names_of(p.directives), "client config verb config ca nobind")
	testing.expect_value(t, p.directives[2].file, "extra.conf")
	testing.expect_value(t, p.directives[2].line, 1)
	testing.expect_value(t, p.directives[4].file, "deep.conf")
	testing.expect_value(t, len(p.files), 3)
	testing.expect_value(t, p.files[0], "main.conf")
}

@(test)
test_parse_include_missing :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["main.conf"] = "client\nconfig nothere.conf\nnobind\n"
	p := parse_file("main.conf", Parse_Options{loader = mem_loader, loader_data = &files})
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 2, "cannot read config file 'nothere.conf'")
	testing.expect_value(t, p.diags[0].file, "main.conf")

	p2 := parse_file("none.conf", Parse_Options{loader = mem_loader, loader_data = &files})
	defer parsed_destroy(&p2)
	testing.expect(t, diags_have_error(p2.diags))
}

@(test)
test_parse_include_cycle :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["a.conf"] = "client\nconfig b.conf\n"
	files["b.conf"] = "verb 3\nconfig ./c/../a.conf\n"
	opts := Parse_Options {
		loader      = mem_loader,
		loader_data = &files,
	}
	// The cycle is caught even when the path is written differently. The
	// loader only sees the cleaned form of the cycle check, not the path.
	files["a.conf"] = "client\nconfig b.conf\n"
	p := parse_file("a.conf", opts)
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 2, "include each other in a loop")
	testing.expect_value(t, p.diags[0].file, "b.conf")
	testing.expect(
		t,
		strings.contains(p.diags[0].message, "a.conf -> b.conf -> a.conf"),
		p.diags[0].message,
	)

	// A file that includes itself.
	files["self.conf"] = "config self.conf\n"
	p2 := parse_file("self.conf", opts)
	defer parsed_destroy(&p2)
	expect_error(t, p2.diags, 1, "include each other in a loop")

	// The same file included twice (one after the other) is allowed.
	files["twice.conf"] = "config one.conf\nconfig one.conf\n"
	files["one.conf"] = "verb 1\n"
	p3 := parse_file("twice.conf", opts)
	defer parsed_destroy(&p3)
	testing.expect_value(t, len(p3.diags), 0)
}

@(test)
test_parse_include_depth_limit :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	// f0 includes f1, f1 includes f2, ... f12 includes nothing.
	names: [13]string
	for i in 0 ..< 13 {
		letter := [1]u8{u8('a' + i)}
		names[i] = strings.concatenate({"f", string(letter[:]), ".conf"})
	}
	defer for n in names {
		delete(n)
	}
	for i in 0 ..< 12 {
		files[names[i]] = strings.concatenate(
			{"verb 1\nconfig ", names[i + 1], "\n"},
			context.temp_allocator,
		)
	}
	files[names[12]] = "verb 2\n"
	opts := Parse_Options {
		loader      = mem_loader,
		loader_data = &files,
	}
	p := parse_file(names[0], opts)
	defer parsed_destroy(&p)
	testing.expect(t, diags_have_error(p.diags))
	expect_error(t, p.diags, 2, "nested too deeply")

	// With a higher limit the chain loads.
	opts.max_depth = 20
	p2 := parse_file(names[0], opts)
	defer parsed_destroy(&p2)
	testing.expect_value(t, len(p2.diags), 0)
	testing.expect_value(t, len(p2.files), 13)
}

@(test)
test_parse_include_in_connection_is_error :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["a.conf"] = "<connection>\nconfig b.conf\nremote x 1\n</connection>\n"
	files["b.conf"] = "verb 1\n"
	p := parse_file("a.conf", Parse_Options{loader = mem_loader, loader_data = &files})
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 2, "cannot be used inside a <connection> block")
}

@(test)
test_parse_cd_changes_include_base :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["main.conf"] = "cd /etc/vpn\nconfig sub.conf\n"
	files["/etc/vpn/sub.conf"] = "verb 7\n"
	p := parse_file("main.conf", Parse_Options{loader = mem_loader, loader_data = &files})
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "cd config verb")
	testing.expect_value(t, p.directives[2].file, "/etc/vpn/sub.conf")
}

@(test)
test_parse_file_limits :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["big.conf"] = "verb 1\nverb 2\nverb 3\n"
	p := parse_file(
		"big.conf",
		Parse_Options{loader = mem_loader, loader_data = &files, max_file = 10},
	)
	defer parsed_destroy(&p)
	expect_error(t, p.diags, 0, "too large")

	files["a.conf"] = "config b.conf\n"
	files["b.conf"] = "config c.conf\n"
	files["c.conf"] = "verb 1\n"
	p2 := parse_file(
		"a.conf",
		Parse_Options{loader = mem_loader, loader_data = &files, max_files = 2},
	)
	defer parsed_destroy(&p2)
	expect_error(t, p2.diags, 1, "too many config files")
}

@(test)
test_parse_args_basic :: proc(t: ^testing.T) {
	p := parse_args({"--client", "--remote", "vpn.example.com", "443", "--verb", "4"})
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "client remote verb")
	testing.expect_value(t, len(p.directives[1].args), 2)
	testing.expect(t, p.directives[1].cmdline)
	testing.expect_value(t, p.directives[1].file, COMMAND_LINE)
	// Position is the 1-based index of the option argument.
	testing.expect_value(t, p.directives[1].line, 2)
	testing.expect_value(t, p.directives[2].line, 5)
}

@(test)
test_parse_args_errors :: proc(t: ^testing.T) {
	p := parse_args({"--client", "stray", "--", "--verb", "3"})
	defer parsed_destroy(&p)
	// "stray" is consumed as an argument of --client; "--" is empty.
	expect_error(t, p.diags, 3, "has no option name")
	testing.expect_value(t, names_of(p.directives), "client verb")

	p2 := parse_args({"stray"})
	defer parsed_destroy(&p2)
	// A single bare argument is a config file name.
	testing.expect(t, diags_have_error(p2.diags))

	p3 := parse_args({"--config"})
	defer parsed_destroy(&p3)
	expect_error(t, p3.diags, 1, "exactly one argument")
}

@(test)
test_parse_args_merge_with_file :: proc(t: ^testing.T) {
	files := Mem_Files{}
	defer delete(files)
	files["c.conf"] = "client\nremote a 1194\nverb 3\n"
	opts := Parse_Options {
		loader      = mem_loader,
		loader_data = &files,
	}
	// Command-line options come after the file options, whatever the order.
	p := parse_args({"--verb", "6", "--config", "c.conf", "--nobind"}, opts)
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, names_of(p.directives), "config client remote verb verb nobind")
	testing.expect_value(t, p.directives[3].file, "c.conf")
	testing.expect(t, p.directives[4].cmdline)
	testing.expect_value(t, p.directives[4].args[0], "6")

	// A lone file name is the same as --config file.
	p2 := parse_args({"c.conf"}, opts)
	defer parsed_destroy(&p2)
	testing.expect_value(t, names_of(p2.directives), "client remote verb")

	// The last verb wins when the config is built.
	cfg := build(parse_args({"--verb", "6", "--config", "c.conf"}, opts))
	defer destroy(&cfg)
	testing.expect_value(t, cfg.client.verb, 6)
}

@(test)
test_parse_file_from_disk :: proc(t: ^testing.T) {
	// Include paths are relative to the working directory, so the test spells
	// out the full path of the file next to this source.
	part := #directory + "testdata/include-part.conf"
	text := strings.concatenate({"client\nconfig ", part, "\nnobind\n"}, context.temp_allocator)
	p := parse_text(text, "main.conf")
	defer parsed_destroy(&p)
	testing.expect_value(t, len(p.diags), 0)
	testing.expect_value(t, len(p.files), 1)
	testing.expect_value(t, names_of(p.directives), "client config verb nobind nobind")
	testing.expect_value(t, p.directives[2].file, part)

	p2 := parse_file(#directory + "testdata/does-not-exist.conf")
	defer parsed_destroy(&p2)
	expect_error(t, p2.diags, 0, "cannot read")

	p3 := parse_file(part)
	defer parsed_destroy(&p3)
	testing.expect_value(t, len(p3.diags), 0)
	testing.expect_value(t, names_of(p3.directives), "verb nobind")
}

@(test)
test_normalize_path :: proc(t: ^testing.T) {
	cases := [][2]string {
		{"a.conf", "a.conf"},
		{"./a.conf", "a.conf"},
		{"a/../b.conf", "b.conf"},
		{"/etc//vpn/./x.conf", "/etc/vpn/x.conf"},
		{"/../x", "/x"},
		{"../x", "../x"},
		{"a/b/../../c", "c"},
	}
	for c in cases {
		got := normalize_path(c[0], context.temp_allocator)
		testing.expectf(t, got == c[1], "normalize_path(%q) = %q, want %q", c[0], got, c[1])
	}
}

@(test)
test_diags_have_error :: proc(t: ^testing.T) {
	testing.expect(t, !diags_have_error(nil))
	testing.expect(t, !diags_have_error([]Diagnostic{{.Warning, "", 0, "w"}}))
	testing.expect(t, diags_have_error([]Diagnostic{{.Warning, "", 0, "w"}, {.Error, "", 0, "e"}}))
}
