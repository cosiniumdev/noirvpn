// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:fmt"
import "core:mem"
import "core:strings"

// Reads a file (`config` includes and the main file). Returns the bytes (from
// `allocator`) or ok = false. The loader resolves relative paths (the default
// uses the process directory, as upstream does).
Loader :: #type proc(
	user: rawptr,
	path: string,
	allocator: mem.Allocator,
) -> (
	data: []u8,
	ok: bool,
)

DEFAULT_MAX_DEPTH :: 10
DEFAULT_MAX_LINE :: 64 * 1024
DEFAULT_MAX_FILE :: 16 * 1024 * 1024
DEFAULT_MAX_FILES :: 256
DEFAULT_MAX_INLINE :: 1024 * 1024

// Pseudo file name for diagnostics about command-line arguments.
COMMAND_LINE :: "<command line>"

Parse_Options :: struct {
	// Reads files. nil = the default loader (core:os), where there is one.
	loader:      Loader,
	loader_data: rawptr,
	// Deepest `config` nesting (default 10).
	max_depth:   int,
	// Longest config line in bytes (default 64 KiB). Inline blocks are exempt.
	max_line:    int,
	// Largest file in bytes (default 16 MiB).
	max_file:    int,
	// Most files one parse may open (default 256).
	max_files:   int,
	// Largest inline block in bytes (default 1 MiB).
	max_inline:  int,
	// No file access at all. `config` and `cd` stay ordinary directives, and
	// `parse_file` and `parse_args` report an error for a file.
	no_files:    bool,
	// The store of the result can be wiped (`store_wipe`), and the work buffer
	// of the lexer is overwritten after the parse.
	wipeable:    bool,
}

@(private)
Parse_Ctx :: struct {
	alloc:   mem.Allocator, // the arena
	opts:    Parse_Options,
	diags:   [dynamic]Diagnostic,
	files:   [dynamic]string,
	stack:   [dynamic]string, // normalised names of the files being read
	loads:   int,
	cd:      string,
	scratch: [dynamic]u8,
	toks:    [dynamic]string,
}

@(private)
ctx_init :: proc(opts: Parse_Options, allocator: mem.Allocator) -> (c: Parse_Ctx, store: ^Store) {
	store = store_new(allocator, opts.wipeable)
	c.alloc = store_allocator(store)
	c.opts = opts
	if c.opts.max_depth <= 0 {
		c.opts.max_depth = DEFAULT_MAX_DEPTH
	}
	if c.opts.max_line <= 0 {
		c.opts.max_line = DEFAULT_MAX_LINE
	}
	if c.opts.max_file <= 0 {
		c.opts.max_file = DEFAULT_MAX_FILE
	}
	if c.opts.max_files <= 0 {
		c.opts.max_files = DEFAULT_MAX_FILES
	}
	if c.opts.max_inline <= 0 {
		c.opts.max_inline = DEFAULT_MAX_INLINE
	}
	c.diags.allocator = c.alloc
	c.files.allocator = c.alloc
	c.stack.allocator = c.alloc
	c.scratch.allocator = allocator // freed by ctx_done
	c.toks.allocator = allocator
	return
}

@(private)
ctx_done :: proc(c: ^Parse_Ctx, store: ^Store, dirs: [dynamic]Directive) -> Parsed {
	if c.opts.wipeable && cap(c.scratch) > 0 {
		mem.zero_explicit(raw_data(c.scratch), cap(c.scratch))
	}
	delete(c.scratch)
	delete(c.toks)
	return Parsed{directives = dirs[:], files = c.files[:], diags = c.diags[:], store = store}
}

@(private)
diag :: proc(c: ^Parse_Ctx, sev: Severity, file: string, line: int, format: string, args: ..any) {
	append(&c.diags, Diagnostic{sev, file, line, fmt.aprintf(format, ..args, allocator = c.alloc)})
}

// Parses config text. `name` is used in diagnostics and for cycle detection.
// The text is copied; the caller may free it afterwards.
parse_text :: proc(
	text: string,
	name := "<text>",
	opts := Parse_Options{},
	allocator := context.allocator,
) -> Parsed {
	c, store := ctx_init(opts, allocator)
	dirs := make([dynamic]Directive, c.alloc)
	file := strings.clone(name, c.alloc)
	append(&c.stack, normalize_path(file, c.alloc))
	parse_source(&c, strings.clone(text, c.alloc), file, &dirs)
	return ctx_done(&c, store, dirs)
}

// Reads and parses a config file.
parse_file :: proc(
	path: string,
	opts := Parse_Options{},
	allocator := context.allocator,
) -> Parsed {
	c, store := ctx_init(opts, allocator)
	dirs := make([dynamic]Directive, c.alloc)
	include_file(&c, path, "", 0, &dirs)
	return ctx_done(&c, store, dirs)
}

// Parses command-line arguments (no program name) in the upstream form:
// `--option arg arg ...`, or one bare file name meaning `--config file`.
// Merge rule: `--config` files are read in order of appearance. Options given
// directly on the command line come after all of them: they override
// single-valued file settings and add to list settings. (Upstream applies options
// strictly in argument order; noirvpn lets the command line win everywhere.)
parse_args :: proc(
	args: []string,
	opts := Parse_Options{},
	allocator := context.allocator,
) -> Parsed {
	c, store := ctx_init(opts, allocator)
	dirs := make([dynamic]Directive, c.alloc)
	cmd := make([dynamic]Directive, c.alloc)
	if len(args) == 1 && !strings.has_prefix(args[0], "--") {
		include_file(&c, args[0], COMMAND_LINE, 1, &dirs)
		return ctx_done(&c, store, dirs)
	}
	i := 0
	for i < len(args) {
		a := args[i]
		pos := i + 1
		i += 1
		if !strings.has_prefix(a, "--") {
			diag(
				&c,
				.Error,
				COMMAND_LINE,
				pos,
				"unexpected argument '%s'; options must start with --",
				a,
			)
			continue
		}
		name := a[2:]
		first := i
		for i < len(args) && !strings.has_prefix(args[i], "--") {
			i += 1
		}
		rest := args[first:i]
		if name == "" {
			diag(&c, .Error, COMMAND_LINE, pos, "'--' has no option name after it")
			continue
		}
		d := Directive {
			name    = strings.clone(name, c.alloc),
			args    = clone_args(rest, c.alloc),
			file    = COMMAND_LINE,
			line    = pos,
			cmdline = true,
		}
		if name == "config" {
			if len(rest) != 1 {
				diag(
					&c,
					.Error,
					COMMAND_LINE,
					pos,
					"option 'config' needs exactly one argument (a file name)",
				)
				continue
			}
			append(&dirs, d)
			include_file(&c, d.args[0], COMMAND_LINE, pos, &dirs)
		} else {
			append(&cmd, d)
		}
	}
	for d in cmd {
		append(&dirs, d)
	}
	return ctx_done(&c, store, dirs)
}

// Copies the strings too (used for caller-owned argument vectors).
@(private)
clone_args :: proc(src: []string, allocator: mem.Allocator) -> []string {
	out := make([]string, len(src), allocator)
	for s, i in src {
		out[i] = strings.clone(s, allocator)
	}
	return out
}

// Copies only the slice. The strings already live in the arena.
@(private)
dup_args :: proc(src: []string, allocator: mem.Allocator) -> []string {
	out := make([]string, len(src), allocator)
	copy(out, src)
	return out
}

// Frees everything a `Parsed` owns.
parsed_destroy :: proc(p: ^Parsed) {
	store_free(p.store)
	p^ = {}
}

// True if a diagnostic list holds an error.
diags_have_error :: proc(diags: []Diagnostic) -> bool {
	for d in diags {
		if d.severity == .Error {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------

// Cleans a path for comparison: removes "." and empty parts and resolves ".."
// where it can. The result is only used to detect include cycles.
@(private)
normalize_path :: proc(p: string, allocator: mem.Allocator) -> string {
	abs := strings.has_prefix(p, "/")
	parts := make([dynamic]string, allocator)
	it := p
	for seg in strings.split_iterator(&it, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(parts) > 0 && parts[len(parts) - 1] != ".." {
				pop(&parts)
			} else if !abs {
				append(&parts, seg)
			}
		case:
			append(&parts, seg)
		}
	}
	joined, _ := strings.join(parts[:], "/", allocator)
	if abs {
		return strings.concatenate({"/", joined}, allocator)
	}
	return joined
}

// A relative path is taken relative to `cd` if one was set.
@(private)
resolve_path :: proc(c: ^Parse_Ctx, path: string) -> string {
	if c.cd == "" || strings.has_prefix(path, "/") {
		return strings.clone(path, c.alloc)
	}
	return strings.concatenate({c.cd, "/", path}, c.alloc)
}

// Reads `path` and parses it into `out`. `from_file` and `from_line` say where
// the include stands, for messages.
@(private)
include_file :: proc(
	c: ^Parse_Ctx,
	path: string,
	from_file: string,
	from_line: int,
	out: ^[dynamic]Directive,
) {
	if c.opts.no_files {
		diag(c, .Error, from_file, from_line, "other files cannot be read here")
		return
	}
	if len(c.stack) >= c.opts.max_depth {
		diag(
			c,
			.Error,
			from_file,
			from_line,
			"config files are nested too deeply (limit %d): '%s'",
			c.opts.max_depth,
			path,
		)
		return
	}
	if c.loads >= c.opts.max_files {
		diag(c, .Error, from_file, from_line, "too many config files (limit %d)", c.opts.max_files)
		return
	}
	resolved := resolve_path(c, path)
	norm := normalize_path(resolved, c.alloc)
	for s, i in c.stack {
		if s == norm {
			sb := strings.builder_make(c.alloc)
			for t in c.stack[i:] {
				strings.write_string(&sb, t)
				strings.write_string(&sb, " -> ")
			}
			strings.write_string(&sb, norm)
			diag(
				c,
				.Error,
				from_file,
				from_line,
				"config files include each other in a loop: %s",
				strings.to_string(sb),
			)
			return
		}
	}
	loader := c.opts.loader
	if loader == nil {
		loader = default_loader
	}
	if loader == nil {
		diag(
			c,
			.Error,
			from_file,
			from_line,
			"cannot read '%s' because this build has no file loader",
			path,
		)
		return
	}
	c.loads += 1
	data, ok := loader(c.opts.loader_data, resolved, c.alloc)
	if !ok {
		diag(c, .Error, from_file, from_line, "cannot read config file '%s'", path)
		return
	}
	if len(data) > c.opts.max_file {
		diag(
			c,
			.Error,
			from_file,
			from_line,
			"config file '%s' is too large (limit %d bytes)",
			path,
			c.opts.max_file,
		)
		return
	}
	append(&c.files, resolved)
	append(&c.stack, norm)
	parse_source(c, string(data), resolved, out)
	pop(&c.stack)
}

// Splits `text` into lines and turns them into directives.
@(private)
parse_source :: proc(c: ^Parse_Ctx, text: string, file: string, out: ^[dynamic]Directive) {
	text := text
	if strings.has_prefix(text, "\xef\xbb\xbf") {
		text = text[3:]
	}
	pos, lineno := 0, 0
	parse_lines(c, text, &pos, &lineno, file, false, out)
}

// Returns the next line without its line end, and moves `pos` past it.
@(private)
next_line :: proc(text: string, pos: ^int) -> string {
	start := pos^
	nl := strings.index_byte(text[start:], '\n')
	line: string
	if nl < 0 {
		line = text[start:]
		pos^ = len(text)
	} else {
		line = text[start:start + nl]
		pos^ = start + nl + 1
	}
	if len(line) > 0 && line[len(line) - 1] == '\r' {
		line = line[:len(line) - 1]
	}
	return line
}

@(private)
valid_tag_name :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for ch in transmute([]u8)s {
		switch ch {
		case 'a' ..= 'z', '0' ..= '9', '-':
		case:
			return false
		}
	}
	return true
}

// Parses lines until the end of the text, or (inside a connection block) until
// `</connection>`. Returns true if it stopped at the closing tag.
@(private)
parse_lines :: proc(
	c: ^Parse_Ctx,
	text: string,
	pos: ^int,
	lineno: ^int,
	file: string,
	in_conn: bool,
	out: ^[dynamic]Directive,
) -> (
	closed: bool,
) {
	for pos^ < len(text) {
		line := next_line(text, pos)
		lineno^ += 1
		ln := lineno^
		if len(line) > c.opts.max_line {
			diag(c, .Error, file, ln, "the line is too long (limit %d bytes)", c.opts.max_line)
			continue
		}
		t := trim_space(line)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if t[0] == '<' {
			if t[len(t) - 1] != '>' {
				diag(c, .Error, file, ln, "'%s' is not a valid tag", t)
				continue
			}
			name := t[1:len(t) - 1]
			if strings.has_prefix(name, "/") {
				if in_conn && name == "/connection" {
					return true
				}
				diag(c, .Error, file, ln, "closing tag <%s> has no matching opening tag", name)
				continue
			}
			if !valid_tag_name(name) {
				diag(c, .Error, file, ln, "'%s' is not a valid tag", t)
				continue
			}
			parse_block(c, text, pos, lineno, file, ln, name, in_conn, out)
			continue
		}
		parse_directive(c, t, file, ln, in_conn, out)
	}
	return false
}

// Reads the rest of a `<name>` block. `ln` is the line of the opening tag.
@(private)
parse_block :: proc(
	c: ^Parse_Ctx,
	text: string,
	pos: ^int,
	lineno: ^int,
	file: string,
	ln: int,
	name: string,
	in_conn: bool,
	out: ^[dynamic]Directive,
) {
	if name == "connection" {
		if in_conn {
			diag(c, .Error, file, ln, "a <connection> block cannot contain another <connection> block")
		}
		children := make([dynamic]Directive, c.alloc)
		closed := parse_lines(c, text, pos, lineno, file, true, &children)
		if !closed {
			diag(c, .Error, file, ln, "a <connection> block is not closed; add a </connection> line")
		}
		if !in_conn {
			append(out, Directive{name = name, file = file, line = ln, block = children[:]})
		}
		return
	}
	body_start := pos^
	for pos^ < len(text) {
		line_start := pos^
		line := next_line(text, pos)
		lineno^ += 1
		if is_closing_tag(trim_space(line), name) {
			body := text[body_start:line_start]
			if len(body) > c.opts.max_inline {
				diag(
					c,
					.Error,
					file,
					ln,
					"inline block <%s> is too large (limit %d bytes)",
					name,
					c.opts.max_inline,
				)
				return
			}
			if strings.index_byte(body, '\r') >= 0 {
				body, _ = strings.replace_all(body, "\r\n", "\n", c.alloc)
			}
			if strings.index_byte(body, 0) >= 0 {
				diag(c, .Error, file, ln, "inline block <%s> contains a NUL byte", name)
				return
			}
			append(
				out,
				Directive{name = name, file = file, line = ln, body = body, has_body = true},
			)
			return
		}
	}
	diag(c, .Error, file, ln, "inline block <%s> is not closed; add a </%s> line", name, name)
}

// True if `t` (trimmed) is exactly `</name>`.
@(private)
is_closing_tag :: proc(t: string, name: string) -> bool {
	return(
		len(t) == len(name) + 3 &&
		t[0] == '<' &&
		t[1] == '/' &&
		t[2:2 + len(name)] == name &&
		t[len(t) - 1] == '>' \
	)
}

// Turns one text line into a directive and handles `config` and `cd`.
@(private)
parse_directive :: proc(
	c: ^Parse_Ctx,
	line: string,
	file: string,
	ln: int,
	in_conn: bool,
	out: ^[dynamic]Directive,
) {
	clear(&c.toks)
	if err := lex_line(line, &c.toks, &c.scratch, c.alloc); err != .None {
		diag(c, .Error, file, ln, "%s", lex_error_text(err))
		return
	}
	if len(c.toks) == 0 {
		return
	}
	name := c.toks[0]
	if strings.has_prefix(name, "--") {
		name = name[2:]
	}
	if name == "" {
		diag(c, .Error, file, ln, "the option name is empty")
		return
	}
	d := Directive {
		name = name,
		args = dup_args(c.toks[1:], c.alloc),
		file = file,
		line = ln,
	}
	append(out, d)
	if c.opts.no_files {
		return
	}
	switch name {
	case "config":
		if in_conn {
			diag(c, .Error, file, ln, "option 'config' cannot be used inside a <connection> block")
		} else if len(d.args) != 1 {
			diag(c, .Error, file, ln, "option 'config' needs exactly one argument (a file name)")
		} else {
			include_file(c, d.args[0], file, ln, out)
		}
	case "cd":
		if len(d.args) == 1 && strings.has_prefix(d.args[0], "/") && !in_conn {
			c.cd = d.args[0]
		}
	}
}
