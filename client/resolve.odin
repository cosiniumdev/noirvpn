// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import cnet "core:net"
import "core:mem"
import net "noir:platform/net"
import "noir:proto/config"

// The address family filter of a `udp4` / `tcp6` style remote.
resolve_pref :: proc "contextless" (f: config.Family) -> net.Resolve_Pref {
	switch f {
	case .Any:
		return .Any
	case .V4:
		return .V4_Only
	case .V6:
		return .V6_Only
	}
	return .Any
}

// Run a `.Resolve` action: look the host up and return its addresses in the
// order to try.
// - An address literal returns at once.
// - It blocks (name look-ups are blocking calls). Run it away from the data
//   path.
// - Report the result with `policy_resolved(p, addrs, ok, now)`.
// The caller owns `addrs`.
resolve_action :: proc(a: Action, allocator := context.allocator) -> (addrs: []cnet.Address, ok: bool) {
	eps, err := net.resolve(a.host, a.port, resolve_pref(a.family), allocator)
	if err != .None {
		return nil, false
	}
	defer delete(eps, allocator)
	out, merr := make([]cnet.Address, len(eps), allocator)
	if merr != mem.Allocator_Error.None {
		return nil, false
	}
	for ep, i in eps {
		out[i] = ep.address
	}
	return out, true
}
