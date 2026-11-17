// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:fmt"
import "core:strings"

// The `--check-config` report: what noirvpn does with every option in a
// config, and what is wrong with it.

// What went wrong with one option, if anything.
Check_Status :: enum u8 {
	Ok,
	// A diagnostic at the option's line (and with its name) is a warning.
	Warning,
	// ... or an error.
	Error,
}

// One option as written in the config.
Check_Entry :: struct {
	name:     string,
	// false: the name is not in the option table.
	known:    bool,
	// Valid only if `known`.
	disp:     Disposition,
	file:     string,
	line:     int,
	// Inside a `<connection>` block.
	in_block: bool,
	// For Rejected and Ignored: the reason and replacement from the table.
	note:     string,
	// The worst diagnostic about this option (a Supported option with a bad
	// value is `Error`).
	status:   Check_Status,
}

Report :: struct {
	role:     Role,
	// In the order they were read, includes expanded.
	entries:  []Check_Entry,
	// Number of entries per disposition (unknown options are not counted here).
	counts:   [Disposition]int,
	unknown:  int,
	errors:   int,
	warnings: int,
	// Files that were read.
	files:    []string,
	// The diagnostics of the config (not copied).
	diags:    []Diagnostic,
}

// Builds the report for a config that was parsed and built. The report points
// into `cfg`; keep `cfg` alive while you use it.
check_config :: proc(cfg: ^Config, allocator := context.allocator) -> Report {
	r := Report {
		role  = cfg.role,
		files = cfg.parsed.files,
		diags = cfg.diags,
	}
	entries := make([dynamic]Check_Entry, allocator)
	for &d in cfg.parsed.directives {
		check_directive(&entries, &r, &d, false)
	}
	r.entries = entries[:]
	for &e in r.entries {
		for d in cfg.diags {
			if d.line != e.line ||
			   d.file != e.file ||
			   !strings.has_prefix(d.message, e.name) ||
			   len(d.message) <= len(e.name) ||
			   d.message[len(e.name)] != ':' {
				continue
			}
			s := Check_Status.Error if d.severity == .Error else Check_Status.Warning
			e.status = max(e.status, s)
		}
		// An unknown option is always an error unless it was told to be ignored.
		if !e.known && e.status == .Ok {
			e.status = .Error
		}
	}
	for d in cfg.diags {
		switch d.severity {
		case .Error:
			r.errors += 1
		case .Warning:
			r.warnings += 1
		}
	}
	return r
}

report_destroy :: proc(r: ^Report, allocator := context.allocator) {
	delete(r.entries, allocator)
	r^ = {}
}

// True if the config has no errors.
report_ok :: proc(r: ^Report) -> bool {
	return r.errors == 0
}

@(private)
check_directive :: proc(out: ^[dynamic]Check_Entry, r: ^Report, d: ^Directive, in_block: bool) {
	e := Check_Entry {
		name     = d.name,
		file     = d.file,
		line     = d.line,
		in_block = in_block,
	}
	if opt := option_find(d.name); opt != nil {
		e.known = true
		e.disp = opt.disp
		if opt.disp == .Rejected || opt.disp == .Ignored {
			e.note = opt.note
		}
		r.counts[opt.disp] += 1
	} else {
		r.unknown += 1
	}
	append(out, e)
	for &inner in d.block {
		check_directive(out, r, &inner, true)
	}
}

// One line per diagnostic: `file:line: error: message`.
format_diagnostics :: proc(diags: []Diagnostic, allocator := context.allocator) -> string {
	sb := strings.builder_make(allocator)
	for d in diags {
		write_diag(&sb, d)
	}
	return strings.to_string(sb)
}

@(private)
write_diag :: proc(sb: ^strings.Builder, d: Diagnostic) {
	if d.file != "" {
		strings.write_string(sb, d.file)
		if d.line > 0 {
			fmt.sbprintf(sb, ":%d", d.line)
		}
		strings.write_string(sb, ": ")
	} else if d.line > 0 {
		fmt.sbprintf(sb, "line %d: ", d.line)
	}
	strings.write_string(sb, "error: " if d.severity == .Error else "warning: ")
	strings.write_string(sb, d.message)
	strings.write_byte(sb, '\n')
}

@(private)
disp_label :: proc(e: Check_Entry) -> string {
	if !e.known {
		return "unknown"
	}
	switch e.disp {
	case .Supported:
		return "supported"
	case .Ignored:
		return "ignored"
	case .Rejected:
		return "rejected"
	case .New:
		return "new"
	}
	return "?"
}

// The text `--check-config` prints:
//
//   config check: server (3 files)
//     supported  server.conf:1  proto
//     rejected   server.conf:7  comp-lzo  -- compression has been removed ...
//   problems:
//     server.conf:7: error: not supported: ...
//   result: 1 error, 0 warnings
format_report :: proc(r: ^Report, allocator := context.allocator) -> string {
	sb := strings.builder_make(allocator)
	role := "unknown role"
	switch r.role {
	case .Client:
		role = "client"
	case .Server:
		role = "server"
	case .None:
	}
	fmt.sbprintf(
		&sb,
		"config check: %s, %d option%s",
		role,
		len(r.entries),
		plural(len(r.entries)),
	)
	if len(r.files) > 0 {
		fmt.sbprintf(&sb, " in %d file%s", len(r.files), plural(len(r.files)))
	}
	strings.write_byte(&sb, '\n')
	for e in r.entries {
		pad := 9 - len(disp_label(e))
		strings.write_string(&sb, "  ")
		strings.write_string(&sb, disp_label(e))
		for _ in 0 ..< pad {
			strings.write_byte(&sb, ' ')
		}
		strings.write_string(&sb, "  ")
		strings.write_string(&sb, e.file)
		if e.line > 0 {
			fmt.sbprintf(&sb, ":%d", e.line)
		}
		strings.write_string(&sb, "  ")
		if e.in_block {
			strings.write_string(&sb, "  ")
		}
		strings.write_string(&sb, e.name)
		switch e.status {
		case .Ok:
		case .Warning:
			strings.write_string(&sb, "  [warning]")
		case .Error:
			strings.write_string(&sb, "  [error]")
		}
		if e.note != "" {
			strings.write_string(&sb, "  -- ")
			strings.write_string(&sb, e.note)
		}
		strings.write_byte(&sb, '\n')
	}
	if len(r.diags) > 0 {
		strings.write_string(&sb, "problems:\n")
		for d in r.diags {
			strings.write_string(&sb, "  ")
			write_diag(&sb, d)
		}
	}
	fmt.sbprintf(
		&sb,
		"summary: %d supported, %d new, %d ignored, %d rejected, %d unknown\n",
		r.counts[.Supported],
		r.counts[.New],
		r.counts[.Ignored],
		r.counts[.Rejected],
		r.unknown,
	)
	fmt.sbprintf(
		&sb,
		"result: %s (%d error%s, %d warning%s)\n",
		"ok" if r.errors == 0 else "FAILED",
		r.errors,
		plural(r.errors),
		r.warnings,
		plural(r.warnings),
	)
	return strings.to_string(sb)
}
