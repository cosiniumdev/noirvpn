// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// The `allow-inbound` and `forward` lines of a profile, for the Inbound rules
// view.
//
//	acl_lines(text, allocator) -> [dynamic]string
//	acl_line_count(lines) -> int
package profiles

import "core:strings"

import "noir:proto/config"

// acl_lines gives the `allow-inbound` and `forward` lines of the text as the
// file writes them, in order. Comment lines and the bodies of inline blocks
// are skipped.
acl_lines :: proc(text: string, allocator := context.allocator) -> [dynamic]string {
	out := make([dynamic]string, allocator)
	p := parse_profile(text)
	defer config.parsed_destroy(&p)
	lines := strings.split_lines(text, context.temp_allocator)
	for d in p.directives {
		if d.has_body || (d.name != "allow-inbound" && d.name != "forward") {
			continue
		}
		line := ""
		if d.line >= 1 && d.line <= len(lines) {
			line = strings.trim_space(lines[d.line - 1])
		}
		if line == "" {
			// The parser gave no line of this text: write the option again.
			parts := make([dynamic]string, 0, len(d.args) + 1, context.temp_allocator)
			append(&parts, d.name)
			append(&parts, ..d.args)
			line = strings.join(parts[:], " ", context.temp_allocator)
		}
		append(&out, strings.clone(line, allocator))
	}
	return out
}

// acl_line_count counts the `allow-inbound` and `forward` lines of a profile
// text that is split into lines, with the bodies of inline blocks left out.
acl_line_count :: proc(lines: []string) -> int {
	n := 0
	for l in lines {
		s := strings.trim_left_space(l)
		for name in ([2]string{"allow-inbound", "forward"}) {
			if strings.has_prefix(s, name) && (len(s) == len(name) || s[len(name)] == ' ' || s[len(name)] == '\t') {
				n += 1
			}
		}
	}
	return n
}
