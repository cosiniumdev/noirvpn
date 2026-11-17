// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:mem"
import "core:strings"
import "core:testing"

// An in-memory file system for include tests. Keys are paths as the parser
// passes them to the loader.
Mem_Files :: map[string]string

mem_loader :: proc(
	user: rawptr,
	path: string,
	allocator: mem.Allocator,
) -> (
	data: []u8,
	ok: bool,
) {
	files := (^Mem_Files)(user)
	s, found := files[path]
	if !found {
		return nil, false
	}
	return transmute([]u8)strings.clone(s, allocator), true
}

// True if some diagnostic has this severity, line (0 = any) and a message
// containing `part`.
has_diag :: proc(diags: []Diagnostic, sev: Severity, line: int, part: string) -> bool {
	for d in diags {
		if d.severity == sev &&
		   (line == 0 || d.line == line) &&
		   strings.contains(d.message, part) {
			return true
		}
	}
	return false
}

expect_error :: proc(
	t: ^testing.T,
	diags: []Diagnostic,
	line: int,
	part: string,
	loc := #caller_location,
) -> bool {
	if has_diag(diags, .Error, line, part) {
		return true
	}
	testing.expectf(
		t,
		false,
		"no error with line %d containing '%s'; got:\n%s",
		line,
		part,
		format_diagnostics(diags, context.temp_allocator),
		loc = loc,
	)
	return false
}

expect_warning :: proc(
	t: ^testing.T,
	diags: []Diagnostic,
	line: int,
	part: string,
	loc := #caller_location,
) -> bool {
	if has_diag(diags, .Warning, line, part) {
		return true
	}
	testing.expectf(
		t,
		false,
		"no warning with line %d containing '%s'; got:\n%s",
		line,
		part,
		format_diagnostics(diags, context.temp_allocator),
		loc = loc,
	)
	return false
}

// Expects no errors; prints the diagnostics if there are some.
expect_clean :: proc(t: ^testing.T, diags: []Diagnostic, loc := #caller_location) -> bool {
	if diags_have_error(diags) {
		testing.expectf(
			t,
			false,
			"unexpected errors:\n%s",
			format_diagnostics(diags, context.temp_allocator),
			loc = loc,
		)
		return false
	}
	return true
}

// Parses and builds a config from text.
load :: proc(text: string) -> Config {
	return build(parse_text(text, "test.conf"))
}

// Fixed pieces for a valid client and server. Inline keys are not parsed, so
// any text does.
CLIENT_BASE :: `client
remote vpn.example.com 1194
dev tun
<ca>
CA
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`

SERVER_BASE :: `server 10.8.0.0 255.255.255.0
dev tun
<ca>
CA
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`

// Builds a client config: CLIENT_BASE plus `extra`.
load_client :: proc(extra: string) -> Config {
	return load(strings.concatenate({CLIENT_BASE, extra}, context.temp_allocator))
}

load_server :: proc(extra: string) -> Config {
	return load(strings.concatenate({SERVER_BASE, extra}, context.temp_allocator))
}

// Small deterministic PRNG (xorshift64*) so fuzz tests repeat exactly.
Rng :: struct {
	s: u64,
}

rng_next :: proc(r: ^Rng) -> u64 {
	r.s ~= r.s >> 12
	r.s ~= r.s << 25
	r.s ~= r.s >> 27
	return r.s * 0x2545F4914F6CDD1D
}

rng_below :: proc(r: ^Rng, n: int) -> int {
	return int(rng_next(r) % u64(n))
}

// For debugging a test: the diagnostics as text.
diag_text :: proc(diags: []Diagnostic) -> string {
	return format_diagnostics(diags, context.temp_allocator)
}
