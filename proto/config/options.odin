// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"

// Looks an option up by name. Returns nil if there is no such option. The
// table is sorted by name, so this is a binary search.
option_find :: proc(name: string) -> ^Option {
	lo, hi := 0, len(OPTIONS)
	for lo < hi {
		mid := lo + (hi - lo) / 2
		switch strings.compare(OPTIONS[mid].name, name) {
		case 0:
			return &OPTIONS[mid]
		case -1:
			lo = mid + 1
		case:
			hi = mid
		}
	}
	return nil
}

// The whole table, sorted by name.
option_table :: proc() -> []Option {
	return OPTIONS[:]
}

disposition_name :: proc(d: Disposition) -> string {
	switch d {
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

applies_name :: proc(a: Applies) -> string {
	switch a {
	case .Both:
		return "both"
	case .Client:
		return "client"
	case .Server:
		return "server"
	}
	return "?"
}

// Counts of table rows per disposition.
option_counts :: proc() -> (counts: [Disposition]int) {
	for &o in OPTIONS {
		counts[o.disp] += 1
	}
	return
}

// True for a row the table lists as supported but the daemon does not act on yet:
// its note starts with "not applied yet" (warning or nothing) or "not available
// yet" (start-up error of the daemon).
option_not_applied :: proc(o: ^Option) -> bool {
	if o.disp != .Supported {
		return false
	}
	return strings.has_prefix(o.note, "not applied yet") || strings.has_prefix(o.note, "not available yet")
}

// Renders the table as Markdown, grouped by disposition; supported rows not
// applied yet get their own section. Source of the option reference docs.
option_table_markdown :: proc(allocator := context.allocator) -> string {
	Group :: struct {
		title:       string,
		disp:        Disposition,
		not_applied: bool,
	}
	groups := [?]Group {
		{"Supported", .Supported, false},
		{"New in noirvpn", .New, false},
		{"Not applied yet", .Supported, true},
		{"Ignored (warning)", .Ignored, false},
		{"Rejected (error)", .Rejected, false},
	}
	sb := strings.builder_make(allocator)
	for g in groups {
		strings.write_string(&sb, "## ")
		strings.write_string(&sb, g.title)
		strings.write_string(
			&sb,
			"\n\n| Option | Applies to | Arguments | Pushable | Notes |\n|---|---|---|---|---|\n",
		)
		for &o in OPTIONS {
			if o.disp != g.disp || option_not_applied(&o) != g.not_applied {
				continue
			}
			strings.write_string(&sb, "| `")
			strings.write_string(&sb, o.name)
			strings.write_string(&sb, "` | ")
			strings.write_string(&sb, applies_name(o.applies))
			strings.write_string(&sb, " | ")
			write_arity(&sb, &o)
			strings.write_string(&sb, " | ")
			strings.write_string(&sb, "yes" if .Pushable in o.flags else "")
			strings.write_string(&sb, " | ")
			strings.write_string(&sb, o.note)
			strings.write_string(&sb, " |\n")
		}
		strings.write_string(&sb, "\n")
	}
	return strings.to_string(sb)
}

@(private)
write_arity :: proc(sb: ^strings.Builder, o: ^Option) {
	if o.max_args < 0 {
		strings.write_int(sb, o.min_args)
		strings.write_string(sb, "+")
	} else if o.min_args == o.max_args {
		strings.write_int(sb, o.min_args)
	} else {
		strings.write_int(sb, o.min_args)
		strings.write_string(sb, "-")
		strings.write_int(sb, o.max_args)
	}
}
