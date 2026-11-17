// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Server override: the `remote` lines and `<connection>` blocks of a profile
// are replaced by the user's servers.
//
//	servers_replace(text, servers, allocator) -> string
package profiles

import "core:fmt"
import "core:strings"

import "noir:proto/config"

// Returns a copy of `text`. With no valid server the copy is the same text.
// Other options in a `<connection>` block are dropped with the block.
servers_replace :: proc(text: string, servers: []Server, allocator := context.allocator) -> string {
	valid := make([dynamic]Server, context.temp_allocator)
	for sv in servers {
		if server_error(sv.host, sv.port, sv.proto) == "" {
			append(&valid, sv)
		}
	}
	if len(valid) == 0 {
		return strings.clone(text, allocator)
	}
	sb := strings.builder_make(context.temp_allocator)
	for sv in valid {
		proto := "udp"
		switch sv.proto {
		case "tcp":
			proto = "tcp-client"
		case "tls":
			proto = "tls-client"
		}
		fmt.sbprintf(&sb, "remote %s %d %s\n", strings.trim_space(sv.host), sv.port, proto)
	}
	new_lines := strings.to_string(sb)

	p := parse_profile(text)
	defer config.parsed_destroy(&p)
	body := strings.trim_prefix(text, "\xef\xbb\xbf")
	lines := make([dynamic]string, context.temp_allocator)
	for rest := body; rest != ""; {
		nl := strings.index_byte(rest, '\n')
		n := nl < 0 ? len(rest) : nl + 1
		append(&lines, rest[:n])
		rest = rest[n:]
	}
	edits := make([dynamic]Edit, context.temp_allocator)
	for d in p.directives {
		last := 0
		switch d.name {
		case "remote":
			last = d.line
		case "connection":
			last = d.line
			for i in d.line ..< len(lines) {
				if is_close_tag(lines[i], "connection") {
					last = i + 1
					break
				}
			}
		case:
			continue
		}
		append(&edits, Edit{d.line, last, len(edits) == 0 ? new_lines : ""})
	}
	if len(edits) == 0 {
		sep := len(body) > 0 && !strings.has_suffix(body, "\n") ? "\n" : ""
		return strings.concatenate({body, sep, new_lines}, allocator)
	}
	return apply_edits(lines[:], edits[:], allocator)
}
