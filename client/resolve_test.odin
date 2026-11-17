// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import cnet "core:net"
import "core:testing"
import net "noir:platform/net"
import "noir:proto/config"

@(test)
resolve_action_literals :: proc(t: ^testing.T) {
	// Literal addresses never reach the network.
	a, ok := resolve_action(Action{host = "192.0.2.1", port = 1194})
	testing.expect(t, ok)
	defer delete(a)
	testing.expect_value(t, len(a), 1)
	testing.expect_value(t, a[0], cnet.Address(cnet.IP4_Address{192, 0, 2, 1}))

	b, bok := resolve_action(Action{host = "[2001:db8::1]", port = 1194})
	testing.expect(t, bok)
	defer delete(b)
	testing.expect_value(t, b[0], cnet.Address(cnet.IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}))

	// The family filter applies to literals too.
	_, v6ok := resolve_action(Action{host = "192.0.2.1", family = .V6})
	testing.expect(t, !v6ok)
	_, v4ok := resolve_action(Action{host = "2001:db8::1", family = .V4})
	testing.expect(t, !v4ok)
	c, cok := resolve_action(Action{host = "2001:db8::1", family = .V6})
	testing.expect(t, cok)
	delete(c)

	// Not a name and not an address.
	_, badok := resolve_action(Action{host = "a:b:c"})
	testing.expect(t, !badok)
	_, emptyok := resolve_action(Action{host = ""})
	testing.expect(t, !emptyok)
}

@(test)
resolve_pref_maps_families :: proc(t: ^testing.T) {
	testing.expect_value(t, resolve_pref(config.Family.Any), net.Resolve_Pref.Any)
	testing.expect_value(t, resolve_pref(config.Family.V4), net.Resolve_Pref.V4_Only)
	testing.expect_value(t, resolve_pref(config.Family.V6), net.Resolve_Pref.V6_Only)
}
