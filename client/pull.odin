// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:strings"
import "noir:proto/config"
import "noir:proto/push"

// `pull-filter accept|ignore|reject <text>` on a PUSH_REPLY option list.
// - Rules see each option as text, before it is parsed into
//   `push.Pushed_Options`. Run on `Push_Reply_Msg.options`, then feed the result
//   to `push.push_assembler_feed`.
// - A rule matches if the option starts with its text. First match decides; no
//   match accepts. `push-continuation` is never filtered (the assembler needs it).
// `route-nopull` is not here: it belongs to the plan (see `plan_build`), because
// a text rule cannot tell a route from a redirect.

// What a rule list does with one option.
Pull_Verdict :: enum u8 {
	Accept,
	// Drop the option and go on.
	Ignore,
	// The server's reply is not acceptable: the connection must fail.
	Reject,
}

pull_filter_match :: proc(filters: []config.Pull_Filter, option: string) -> Pull_Verdict {
	opt := strings.trim_left(option, " \t")
	for f in filters {
		if strings.has_prefix(opt, f.text) {
			switch f.action {
			case .Accept:
				return .Accept
			case .Ignore:
				return .Ignore
			case .Reject:
				return .Reject
			}
		}
	}
	return .Accept
}

Pull_Result :: struct {
	// The options that survived, comma separated like the input. Owned by the
	// caller. Empty when every option was dropped.
	options:  string,
	// How many options were dropped by an `ignore` rule.
	ignored:  int,
	// The first option a `reject` rule matched. It is a slice of the input.
	rejected: Maybe(string),
}

// Apply the rules to the option list of one message (the text after
// `PUSH_REPLY,`). After a reject the scan goes on, so `ignored` stays right,
// but the caller must fail the connection.
pull_filter_options :: proc(
	filters: []config.Pull_Filter,
	options: string,
	allocator := context.allocator,
) -> (
	res: Pull_Result,
	ok: bool,
) {
	if len(filters) == 0 {
		cloned, err := strings.clone(options, allocator)
		return Pull_Result{options = cloned}, err == nil
	}
	sb := strings.builder_make(0, len(options), allocator)
	rest := options
	first := true
	for len(rest) > 0 {
		item, _ := push.next_item(&rest, ',')
		trimmed := strings.trim_left(item, " \t")
		if len(trimmed) == 0 {
			continue
		}
		keep := true
		if !is_continuation(trimmed) {
			switch pull_filter_match(filters, trimmed) {
			case .Accept:
			case .Ignore:
				keep = false
				res.ignored += 1
			case .Reject:
				keep = false
				if res.rejected == nil {
					res.rejected = item
				}
			}
		}
		if keep {
			if !first {
				strings.write_byte(&sb, ',')
			}
			strings.write_string(&sb, item)
			first = false
		}
	}
	res.options = strings.to_string(sb)
	return res, true
}

@(private)
is_continuation :: proc "contextless" (item: string) -> bool {
	name :: "push-continuation"
	return len(item) >= len(name) && item[:len(name)] == name
}
