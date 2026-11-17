// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

// Name lookups of the guest (helper thread of guest.odin).
//
// On Android the lookup must use the host network: while the VPN is up the
// app's default network is the VPN, so a plain lookup would enter a tunnel that
// is not up yet. The host gives the host-network handle in nvpn_network
// (`handle`); android_getaddrinfofornetwork uses it. Everywhere else, and with
// no handle, the lookup is client.resolve_action.

import cnet "core:net"

import "noir:client"

// Looks the name of `job` up. Blocks: the helper thread only.
guest_lookup :: proc(job: Res_Job, allocator := context.allocator) -> (addrs: []cnet.Address, ok: bool) {
	when ODIN_PLATFORM_SUBTARGET == .Android {
		if job.net != 0 {
			return lookup_on_network(job.host, job.family, job.net, allocator)
		}
	}
	return client.resolve_action(client.Action{host = job.host, port = job.port, family = job.family}, allocator)
}

