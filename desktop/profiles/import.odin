// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Import of an `.ovpn` file. Key files the profile names go into inline blocks.
// Only files in the profile folder (or below) are read.
//
//	import_file(path, allocator) -> Import_Result
//	import_text(text, folder, allocator) -> Import_Result
//	import_destroy(r, allocator)
package profiles

import "core:mem"
import "core:os"
import "core:strings"

import "noir:proto/config"

// The largest text that `profile.set` takes.
PROFILE_MAX :: 262144

Import_Result :: struct {
	// The profile with the keys inline. Set only when ok.
	text:     string,
	// The file name without the extension (import_file only).
	name:     string,
	// Of `text` when ok, else of the input.
	summary:  Summary,
	problems: [dynamic]Problem,
	// No fatal problem.
	ok:       bool,
}

@(private, rodata)
key_options := [?]string {
	"ca",
	"cert",
	"key",
	"extra-certs",
	"tls-crypt",
	"tls-auth",
	"tls-crypt-v2",
	"secret",
	"dh",
	"pkcs12",
	"crl-verify",
}

// An option that names a file or a directory in argument `arg`.
@(private)
File_Rule :: struct {
	name: string,
	arg:  int,
}

@(private, rodata)
file_rules := [?]File_Rule {
	{"config", 0},
	{"cd", 0},
	{"chroot", 0},
	{"log", 0},
	{"log-append", 0},
	{"writepid", 0},
	{"capath", 0},
	{"status", 0},
	{"askpass", 0},
	{"replay-persist", 0},
	{"tmp-dir", 0},
	{"pkcs11-providers", 0},
	{"management", 2},
	{"http-proxy", 2},
	{"socks-proxy", 2},
}

@(private)
MSG_NAMES_FILE :: "names a file; only inline keys can be imported"

MSG_LOGIN_STRIPPED :: "the saved password was not imported, so the app will ask for it when you connect. To keep it, put the user name and the password on two lines in a file that only you can read (chmod 600), and add auth-user-pass /path/to/file to the profile (Open profile file)"

import_file :: proc(path: string, allocator := context.allocator) -> (r: Import_Result) {
	data, real, err := read_capped(path, FILE_MAX, allocator)
	delete(real, allocator)
	if err != .None {
		r.problems = make([dynamic]Problem, allocator)
		switch err {
		case .Missing:
			problem_add(&r.problems, 0, "", true, allocator, "file '%s' not found", path)
		case .Not_File:
			problem_add(&r.problems, 0, "", true, allocator, "'%s' is not a file", path)
		case .Too_Large:
			problem_add(&r.problems, 0, "", true, allocator, "the profile is larger than 1 MiB")
		case .Io, .None:
			problem_add(&r.problems, 0, "", true, allocator, "cannot read file '%s'", path)
		}
		r.summary.remotes = make([dynamic]Remote, allocator)
	} else {
		folder := os.dir(path)
		if folder == "" {
			folder = "."
		}
		r = import_text(string(data), folder, allocator)
		delete(data, allocator)
	}
	r.name = strings.clone(os.stem(path), allocator)
	return
}

// `folder` is the folder of the profile; relative file names are taken from
// it. With folder "" every file reference is a fatal problem.
import_text :: proc(text: string, folder: string, allocator := context.allocator) -> (r: Import_Result) {
	r.problems = make([dynamic]Problem, allocator)
	if len(text) > FILE_MAX {
		problem_add(&r.problems, 0, "", true, allocator, "the profile is larger than 1 MiB")
		r.summary.remotes = make([dynamic]Remote, allocator)
		return
	}
	p := parse_profile(text)
	defer config.parsed_destroy(&p)

	c := Import_Ctx {
		allocator = allocator,
		problems  = &r.problems,
		folder    = folder,
		edits     = make([dynamic]Edit, allocator),
	}
	defer {
		for e in c.edits {
			delete(e.text, allocator)
		}
		delete(c.edits)
		delete(c.lines)
		delete(c.folder_real, allocator)
	}
	body := strings.trim_prefix(text, "\xef\xbb\xbf")
	c.lines = make([dynamic]string, allocator)
	for rest := body; rest != ""; {
		nl := strings.index_byte(rest, '\n')
		n := nl < 0 ? len(rest) : nl + 1
		append(&c.lines, rest[:n])
		rest = rest[n:]
	}
	if folder != "" {
		c.folder_real = real_dir(folder, allocator)
	}

	for dg in p.diags {
		if !names_config(p.directives, dg.line) {
			problem_add(&r.problems, dg.line, "", dg.severity == .Error, allocator, "%s", dg.message)
		}
	}
	walk(&c, p.directives)

	if !has_fatal(r.problems[:]) {
		out := apply_edits(c.lines[:], c.edits[:], allocator)
		if len(out) > PROFILE_MAX {
			delete(out, allocator)
			problem_add(&r.problems, 0, "", true, allocator, "the profile is larger than 256 KiB with the keys inline")
		} else {
			r.text = out
			r.ok = true
		}
	}
	r.summary, _ = summarize(r.ok ? r.text : text, allocator)
	return
}

import_destroy :: proc(r: ^Import_Result, allocator := context.allocator) {
	delete(r.text, allocator)
	delete(r.name, allocator)
	summary_destroy(&r.summary, allocator)
	problems_destroy(&r.problems, allocator)
	r^ = {}
}

// Lines `first` to `last` (1-based, inclusive) become `text`.
@(private)
Edit :: struct {
	first, last: int,
	text:        string,
}

@(private)
Import_Ctx :: struct {
	allocator:   mem.Allocator,
	problems:    ^[dynamic]Problem,
	folder:      string,
	folder_real: string,
	// Lines of the text with their line ends, without a BOM.
	lines:       [dynamic]string,
	// In line order, as the directives come.
	edits:       [dynamic]Edit,
}

@(private)
walk :: proc(c: ^Import_Ctx, ds: []config.Directive) {
	for d in ds {
		if d.name == "connection" {
			walk(c, d.block)
			continue
		}
		if secret_file_of(d) != "" {
			keep_secret_file(c, d)
			continue
		}
		if names_file(d) {
			fatal(c, d, MSG_NAMES_FILE)
			continue
		}
		if d.name == "auth-user-pass" {
			if !d.has_body && len(d.args) == 0 {
				continue
			}
			last := d.has_body ? block_end(c, d) : d.line
			edit(c, d.line, last, strings.clone("auth-user-pass\n", c.allocator))
			if d.has_body || d.args[0] != "[inline]" {
				problem_add(
					c.problems,
					d.line,
					d.name,
					false,
					c.allocator,
					MSG_LOGIN_STRIPPED,
				)
			}
			continue
		}
		if d.has_body || len(d.args) == 0 || d.args[0] == "[inline]" || !is_key_option(d.name) {
			continue
		}
		if d.name == "crl-verify" && len(d.args) > 1 && d.args[1] == "dir" {
			fatal(c, d, "a CRL directory cannot be imported; use one CRL file")
			continue
		}
		content, ok := read_key(c, d)
		if !ok {
			continue
		}
		sb := strings.builder_make(c.allocator)
		strings.write_string(&sb, "<")
		strings.write_string(&sb, d.name)
		strings.write_string(&sb, ">\n")
		strings.write_string(&sb, content)
		if !strings.has_suffix(content, "\n") {
			strings.write_string(&sb, "\n")
		}
		strings.write_string(&sb, "</")
		strings.write_string(&sb, d.name)
		strings.write_string(&sb, ">\n")
		if (d.name == "tls-auth" || d.name == "secret") && len(d.args) > 1 {
			strings.write_string(&sb, "key-direction ")
			strings.write_string(&sb, d.args[1])
			strings.write_string(&sb, "\n")
		}
		delete(content, c.allocator)
		edit(c, d.line, d.line, strings.to_string(sb))
	}
}

// Reads the key file of `d`. It must be a text file inside the folder of
// the profile after symlinks are followed.
@(private)
read_key :: proc(c: ^Import_Ctx, d: config.Directive) -> (content: string, ok: bool) {
	name := d.args[0]
	if c.folder_real == "" {
		fatal(c, d, "file '%s' cannot be read because the folder of the profile is not known", name)
		return
	}
	path := name
	if !os.is_absolute_path(name) {
		joined, jerr := os.join_path({c.folder, name}, c.allocator)
		if jerr != nil {
			fatal(c, d, "cannot read file '%s'", name)
			return
		}
		path = joined
	}
	defer if path != name {
		delete(path, c.allocator)
	}
	data, real, err := read_capped(path, FILE_MAX, c.allocator)
	defer delete(real, c.allocator)
	switch err {
	case .None:
	case .Missing:
		fatal(c, d, "file '%s' not found", name)
		return
	case .Not_File:
		fatal(c, d, "'%s' is not a file", name)
		return
	case .Too_Large:
		fatal(c, d, "file '%s' is larger than 1 MiB", name)
		return
	case .Io:
		fatal(c, d, "cannot read file '%s'", name)
		return
	}
	defer delete(data, c.allocator)
	text := string(data)
	switch {
	case !path_inside(real, c.folder_real):
		fatal(c, d, "file '%s' is outside the folder of the profile", name)
	case strings.index_byte(text, 0) >= 0:
		fatal(c, d, "file '%s' is not a text file", name)
	case has_close_tag(text, d.name):
		fatal(c, d, "file '%s' contains the line </%s>", name, d.name)
	case:
		return strings.clone(strings.trim_prefix(text, "\xef\xbb\xbf"), c.allocator), true
	}
	return
}

// secret_file_of is the file of `auth-user-pass FILE` or `askpass FILE`, or "".
// The app reads it at connect (secret_file.odin); the import keeps the line.
@(private)
secret_file_of :: proc(d: config.Directive) -> string {
	if d.has_body || len(d.args) != 1 {
		return ""
	}
	switch d.name {
	case "auth-user-pass":
		if d.args[0] != "[inline]" && d.args[0] != "username-only" {
			return d.args[0]
		}
	case "askpass":
		if d.args[0] != "stdin" {
			return d.args[0]
		}
	}
	return ""
}

// keep_secret_file keeps the line of a secret file. A relative path is resolved to an
// absolute one from the profile folder, since it is read later from elsewhere. An
// unusable file is a non-fatal problem.
@(private)
keep_secret_file :: proc(c: ^Import_Ctx, d: config.Directive) {
	name := secret_file_of(d)
	path := name
	if !os.is_absolute_path(name) && c.folder_real != "" {
		joined, err := os.join_path({c.folder_real, name}, context.temp_allocator)
		if err == nil {
			path = joined
			sb := strings.builder_make(c.allocator)
			strings.write_string(&sb, d.name)
			strings.write_string(&sb, " ")
			write_arg(&sb, path)
			strings.write_string(&sb, "\n")
			edit(c, d.line, d.line, strings.to_string(sb))
		}
	}
	if p := secret_file_problem(path); p != "" {
		problem_add(c.problems, d.line, d.name, false, c.allocator, "%s", p)
	}
}

// write_arg writes one argument of an option line, in quotes when it needs
// them.
@(private)
write_arg :: proc(sb: ^strings.Builder, arg: string) {
	if strings.index_any(arg, " \t\"'\\#;") < 0 && arg != "" {
		strings.write_string(sb, arg)
		return
	}
	strings.write_byte(sb, '"')
	for i in 0 ..< len(arg) {
		if arg[i] == '"' || arg[i] == '\\' {
			strings.write_byte(sb, '\\')
		}
		strings.write_byte(sb, arg[i])
	}
	strings.write_byte(sb, '"')
}

@(private)
names_file :: proc(d: config.Directive) -> bool {
	if d.has_body {
		return false
	}
	if d.name == "management" && len(d.args) > 1 && d.args[1] == "unix" {
		return true
	}
	for r in file_rules {
		if r.name != d.name {
			continue
		}
		if len(d.args) <= r.arg {
			return false
		}
		if r.name == "http-proxy" || r.name == "socks-proxy" {
			switch d.args[r.arg] {
			case "auto", "auto-nct", "none", "[inline]":
				return false
			}
		}
		return true
	}
	return false
}

@(private)
is_key_option :: proc(name: string) -> bool {
	for k in key_options {
		if k == name {
			return true
		}
	}
	return false
}

// True when a `config` directive stands on `line`; its include error is then
// reported as MSG_NAMES_FILE.
@(private)
names_config :: proc(ds: []config.Directive, line: int) -> bool {
	for d in ds {
		if d.name == "config" && d.line == line {
			return true
		}
		if d.name == "connection" && names_config(d.block, line) {
			return true
		}
	}
	return false
}

// The line of the closing tag of the block that opens on d.line.
@(private)
block_end :: proc(c: ^Import_Ctx, d: config.Directive) -> int {
	for i in d.line ..< len(c.lines) {
		if is_close_tag(c.lines[i], d.name) {
			return i + 1
		}
	}
	return d.line
}

@(private)
has_close_tag :: proc(text, name: string) -> bool {
	rest := text
	for line in strings.split_lines_iterator(&rest) {
		if is_close_tag(line, name) {
			return true
		}
	}
	return false
}

@(private)
is_close_tag :: proc(line, name: string) -> bool {
	t := strings.trim_space(line)
	return len(t) == len(name) + 3 && strings.has_prefix(t, "</") && t[2:len(t) - 1] == name && t[len(t) - 1] == '>'
}

@(private)
edit :: proc(c: ^Import_Ctx, first, last: int, text: string) {
	append(&c.edits, Edit{first, last, text})
}

@(private)
fatal :: proc(c: ^Import_Ctx, d: config.Directive, format: string, args: ..any) {
	problem_add(c.problems, d.line, d.name, true, c.allocator, format, ..args)
}

@(private)
apply_edits :: proc(lines: []string, edits: []Edit, allocator: mem.Allocator) -> string {
	sb := strings.builder_make(allocator)
	next := 1
	for e in edits {
		for i in next ..< e.first {
			strings.write_string(&sb, lines[i - 1])
		}
		strings.write_string(&sb, e.text)
		next = e.last + 1
	}
	for i in next ..= len(lines) {
		strings.write_string(&sb, lines[i - 1])
	}
	return strings.to_string(sb)
}
