// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import "core:testing"

// Only literals are tested for sure: the test host may have no resolver.

@(test)
resolve_ipv4_literal :: proc(t: ^testing.T) {
	eps, err := resolve("192.0.2.5", 1194)
	defer delete(eps)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(eps), 1)
	if len(eps) == 1 {
		testing.expect_value(t, eps[0].address, Address(IP4_Address{192, 0, 2, 5}))
		testing.expect_value(t, eps[0].port, 1194)
	}
}

@(test)
resolve_ipv6_literals :: proc(t: ^testing.T) {
	want := Address(IP6_Address{0x2001, 0x0db8, 0, 0, 0, 0, 0, 1})
	for text in ([?]string{"2001:db8::1", "[2001:db8::1]"}) {
		eps, err := resolve(text, 443)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, len(eps), 1)
		if len(eps) == 1 {
			testing.expect_value(t, eps[0].address, want)
			testing.expect_value(t, eps[0].port, 443)
		}
		delete(eps)
	}
}

@(test)
resolve_filters_literals_by_family :: proc(t: ^testing.T) {
	eps, err := resolve("192.0.2.5", 1, .V6_Only)
	testing.expect_value(t, err, Error.Resolve_Failed)
	testing.expect(t, eps == nil)
	eps, err = resolve("::1", 1, .V4_Only)
	testing.expect_value(t, err, Error.Resolve_Failed)
	testing.expect(t, eps == nil)
	eps, err = resolve("::1", 1, .V6_Only)
	testing.expect_value(t, err, Error.None)
	delete(eps)
}

@(test)
resolve_rejects_bad_names :: proc(t: ^testing.T) {
	for name in ([?]string{"", "[]", "host:1194", "2001:db8::zz", "bad name", "-bad.example"}) {
		eps, err := resolve(name, 1)
		testing.expectf(t, err == .Resolve_Failed, "%q: got %v", name, err)
		testing.expect(t, eps == nil)
	}
}

@(test)
resolve_localhost_if_the_host_can :: proc(t: ^testing.T) {
	// The host may have no resolver (a container with no network), so a
	// failure is fine. If it works, the results must be loopback.
	eps, err := resolve("localhost", 5)
	defer delete(eps)
	if err != .None {
		return
	}
	testing.expect(t, len(eps) > 0)
	for ep in eps {
		testing.expect_value(t, ep.port, 5)
		switch a in ep.address {
		case IP4_Address:
			testing.expect_value(t, a[0], 127)
		case IP6_Address:
			testing.expect_value(t, a, IP6_Address{0, 0, 0, 0, 0, 0, 0, 1})
		}
	}
}
