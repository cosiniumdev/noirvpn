// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package bus

import "core:testing"

@(test)
default_resolver_numbers_and_root :: proc(t: ^testing.T) {
	id, ok := default_resolver(.Uid, "1234")
	testing.expect(t, ok)
	testing.expect_value(t, id, 1234)
	id, ok = default_resolver(.Uid, "root")
	testing.expect(t, ok)
	testing.expect_value(t, id, 0)
	_, ok = default_resolver(.Uid, "no-such-user-xyz")
	testing.expect(t, !ok)
	_, ok = default_resolver(.Gid, "no-such-group-xyz")
	testing.expect(t, !ok)
}
