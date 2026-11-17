// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:os"
import "core:strings"
import "core:testing"

// A new empty folder for one test, in the temp allocator.
test_dir :: proc(t: ^testing.T) -> string {
	d, err := os.make_directory_temp("", "noirvpn-profiles-*", context.temp_allocator)
	testing.expect(t, err == nil)
	return d
}

test_dir_remove :: proc(d: string) {
	_ = os.remove_all(d)
}

test_write :: proc(t: ^testing.T, dir, name, content: string) -> string {
	p, _ := os.join_path({dir, name}, context.temp_allocator)
	testing.expect(t, os.write_entire_file(p, content) == nil)
	return p
}

test_mkdir :: proc(t: ^testing.T, dir, name: string) -> string {
	p, _ := os.join_path({dir, name}, context.temp_allocator)
	testing.expect(t, os.make_directory(p) == nil)
	return p
}

// True if a problem has this fatal flag, line (0 = any) and a message that
// contains `part`.
has_problem :: proc(ps: []Problem, fatal: bool, line: int, part: string) -> bool {
	for p in ps {
		if p.fatal == fatal && (line == 0 || p.line == line) && strings.contains(p.message, part) {
			return true
		}
	}
	return false
}

PEM_CA :: "-----BEGIN CERTIFICATE-----\nMIIBca\n-----END CERTIFICATE-----\n"
PEM_KEY :: "-----BEGIN PRIVATE KEY-----\nMIGkey\n-----END PRIVATE KEY-----\n"
STATIC_KEY :: "-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----\n"
