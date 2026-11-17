// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "noir:client"
import "noir:proto/push"

// Tunnel MTU of a guest. At 1500 the outer UDP packets exceed 1500 and are cut
// on the way, so the library never goes above this cap. The daemon ignores it.
GUEST_MAX_MTU :: 1428

Guest_Mtu :: struct {
	mtu:     int, // the value to use
	wanted:  int, // the value before the cap
	lowered: bool, // `wanted` was above the cap
}

// The one place that decides a guest MTU. `pushed`: server tun-mtu. `conn_mtu`:
// profile or override (0: none). Order as in the plan: pushed, else profile,
// else default. A value above the cap becomes the cap; a smaller one stays.
guest_mtu :: proc "contextless" (pushed: Maybe(int), conn_mtu: int) -> Guest_Mtu {
	wanted := DEFAULT_TUN_MTU
	if m, ok := pushed.?; ok {
		wanted = m
	} else if conn_mtu > 0 {
		wanted = conn_mtu
	}
	if wanted > GUEST_MAX_MTU {
		return {mtu = GUEST_MAX_MTU, wanted = wanted, lowered = true}
	}
	return {mtu = wanted, wanted = wanted}
}

// The MTU of the guest `d` for the push `po`.
guest_tun_mtu :: proc(d: ^Daemon, po: ^push.Pushed_Options) -> Guest_Mtu {
	return guest_mtu(po.tun_mtu, d.cfg.connections[d.conn_idx].tun_mtu)
}

// The plan of a guest. It is `client.plan_build` with the MTU of `guest_mtu`,
// and a note when the value was lowered. `input.pushed` is not changed.
guest_plan_build :: proc(input: client.Plan_Input, conn_mtu: int) -> (plan: client.Plan, err: client.Plan_Error) {
	in_ := input
	po := in_.pushed^
	g := guest_mtu(po.tun_mtu, conn_mtu)
	po.tun_mtu = g.mtu
	in_.pushed = &po
	in_.local_mtu = g.mtu
	plan, err = client.plan_build(in_)
	if err == .None && g.lowered {
		text := fmt.aprintf("tun-mtu %d lowered to %d (the largest on mobile)", g.wanted, g.mtu, allocator = plan.allocator)
		append(&plan.notes, client.Note{kind = .Adjusted, text = text})
	}
	return
}
