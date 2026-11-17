// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux:android
package engine

import cnet "core:net"
import "core:testing"

// The lookup on a network finds localhost on the default network, and a
// handle of a network that does not exist returns no result: the handle is used.
@(test)
lookup_on_network_uses_the_handle :: proc(t: ^testing.T) {
	addrs, ok := lookup_on_network("localhost", .V4, 0, context.temp_allocator)
	testing.expect(t, ok)
	found := false
	for a in addrs {
		if a == cnet.Address(cnet.IP4_Address{127, 0, 0, 1}) {
			found = true
		}
	}
	testing.expectf(t, found, "localhost: %v", addrs)
	_, ok = lookup_on_network("localhost", .Any, 9999 << 32 | 0xfacade, context.temp_allocator)
	testing.expect(t, !ok, "a network that does not exist returns no result")
}
