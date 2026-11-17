// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:mem"
import "noir:platform/sysnet"

// Runs a plan with platform/sysnet, records what it adds, and removes exactly
// that. Rules:
//   - Steps run in plan order. A failed step is a warning and the run goes on.
//     Exceptions: `critical` steps and the address and `link up` steps stop the
//     run; `netcfg_apply` undoes all earlier steps first.
//   - `.Exists` is no error and is not recorded: teardown leaves it alone.
//   - If IPv6 is off here, IPv6 steps are skipped with a warning (nothing can
//     leak over an off protocol).
//   - Teardown goes backwards through the record and ignores `.Not_Found` (the
//     tunnel may be gone with its routes and addresses).
// The caller opens the tunnel device (`tun.open`). Its index comes from
// `sysnet.link_get`.
//
// Windows copy of netcfg_linux.odin. Two steps differ:
//   - `link up` sets the tunnel metric `TUN_METRIC`, so Windows prefers its
//     routes and DNS. The adapter is up already while its session runs.
//   - Windows has no unreachable or blackhole routes: such a route goes to the
//     tunnel. No plan step has such a kind today.

Undo_Kind :: enum u8 {
	Route,
	Addr,
	Link_Down,
	Mtu,
}

Undo :: struct {
	kind:       Undo_Kind,
	route:      sysnet.Route, // Route
	addr:       sysnet.Address, // Addr
	prefix_len: u8, // Addr
	mtu:        u32, // Mtu: the value to put back
}

// A step that failed without stopping the run.
Warning :: struct {
	step: int, // index into `Plan.steps`
	why:  Why,
	err:  sysnet.Error, // `.Exists`, `.Network_Unreachable`, ...
	// The step was skipped because IPv6 is off here.
	skipped_v6: bool,
}

// The interface metric of the tunnel. Lower than what Windows gives a wired
// or wireless link (25 and up).
TUN_METRIC :: 5

Netcfg :: struct {
	conn:        ^sysnet.Conn,
	ifindex:     u32,
	allocator:   mem.Allocator,
	// What was added, in order.
	undo:        [dynamic]Undo,
	// The steps that were applied (for `netcfg_update`).
	applied:     [dynamic]Step,
	warnings:    [dynamic]Warning,
	// After a failed `netcfg_apply`: the step that stopped it.
	failed_step: int,
	v6_off:      bool,
}

// `conn` stays with the caller and must outlive `nc`.
netcfg_init :: proc(nc: ^Netcfg, conn: ^sysnet.Conn, ifindex: u32, allocator := context.allocator) {
	nc^ = {}
	nc.conn = conn
	nc.ifindex = ifindex
	nc.allocator = allocator
	nc.undo = make([dynamic]Undo, allocator)
	nc.applied = make([dynamic]Step, allocator)
	nc.warnings = make([dynamic]Warning, allocator)
	nc.failed_step = -1
}

// Frees the records. It does not undo anything: call `netcfg_teardown` first.
netcfg_destroy :: proc(nc: ^Netcfg) {
	delete(nc.undo)
	delete(nc.applied)
	delete(nc.warnings)
	nc^ = {}
}

netcfg_is_applied :: proc(nc: ^Netcfg) -> bool {
	return len(nc.undo) > 0
}

@(private)
is_v6_addr :: proc "contextless" (a: sysnet.Address) -> bool {
	_, v6 := a.(sysnet.IP6_Address)
	return v6
}

// Run the plan.
// - Returns `.None` on success. Warnings are in `nc.warnings`.
// - On error, `nc.failed_step` is the step that stopped the run. All earlier
//   steps are already undone.
// - Applying twice without a teardown gives `.Busy`.
netcfg_apply :: proc(nc: ^Netcfg, plan: ^Plan) -> sysnet.Error {
	if netcfg_is_applied(nc) {
		return .Busy
	}
	clear(&nc.warnings)
	nc.failed_step = -1
	nc.v6_off = false
	c := nc.conn

	for step, i in plan.steps {
		err: sysnet.Error
		switch step.kind {
		case .Set_Mtu:
			prev, gerr := sysnet.link_get_by_index(c, nc.ifindex)
			err = sysnet.link_set_mtu(c, nc.ifindex, step.mtu)
			if err == .None {
				if gerr == .None && prev.mtu != step.mtu {
					append(&nc.undo, Undo{kind = .Mtu, mtu = prev.mtu})
				}
			} else {
				warn(nc, i, step, err, false)
			}

		case .Add_Addr:
			v6 := is_v6_addr(step.addr)
			if v6 && nc.v6_off {
				warn(nc, i, step, .Unsupported, true)
				continue
			}
			err = sysnet.addr_add(c, nc.ifindex, step.addr, step.prefix_len)
			switch err {
			case .None:
				append(&nc.undo, Undo{kind = .Addr, addr = step.addr, prefix_len = step.prefix_len})
			case .Exists:
			// Already there: not ours to remove.
			case .Unsupported, .Permission:
				if v6 {
					// IPv6 is off in this namespace or on this interface.
					nc.v6_off = true
					warn(nc, i, step, err, true)
				} else {
					return fail(nc, i, err)
				}
			case .Not_Found, .Invalid, .Network_Unreachable, .No_Buffer, .Busy, .Timeout, .Io, .Protocol, .Other:
				return fail(nc, i, err)
			}

		case .Link_Up:
			err = sysnet.link_set_up(c, nc.ifindex)
			if err != .None {
				return fail(nc, i, err)
			}
			// The metric goes away with the adapter: nothing to undo.
			if merr := sysnet.link_set_metric(c, nc.ifindex, TUN_METRIC); merr != .None {
				warn(nc, i, step, merr, false)
			}

		case .Add_Route:
			r := step.route
			if step.on_tun {
				r.ifindex = nc.ifindex
			}
			if r.kind != .Unicast {
				r.kind = .Unicast
				r.gateway = nil
				r.ifindex = nc.ifindex
			}
			v6 := is_v6_addr(r.dst)
			if v6 && nc.v6_off {
				warn(nc, i, step, .Unsupported, true)
				continue
			}
			err = sysnet.route_add(c, r)
			switch err {
			case .None:
				append(&nc.undo, Undo{kind = .Route, route = r})
			case .Exists:
				// Not ours: it was there before, and teardown leaves it. SPEC-GAP: we
				// do not check that the old route sends traffic the way the plan wants.
				warn(nc, i, step, err, false)
			case .Unsupported:
				if v6 {
					nc.v6_off = true
					warn(nc, i, step, err, true)
				} else if step.critical {
					return fail(nc, i, err)
				} else {
					warn(nc, i, step, err, false)
				}
			case .Not_Found,
			     .Permission,
			     .Invalid,
			     .Network_Unreachable,
			     .No_Buffer,
			     .Busy,
			     .Timeout,
			     .Io,
			     .Protocol,
			     .Other:
				if step.critical {
					return fail(nc, i, err)
				}
				warn(nc, i, step, err, false)
			}
		}
	}
	append(&nc.applied, ..plan.steps[:])
	return .None
}

@(private)
warn :: proc(nc: ^Netcfg, i: int, step: Step, err: sysnet.Error, skipped_v6: bool) {
	append(&nc.warnings, Warning{step = i, why = step.why, err = err, skipped_v6 = skipped_v6})
}

// A step failed for good: undo what was done and report.
@(private)
fail :: proc(nc: ^Netcfg, i: int, err: sysnet.Error) -> sysnet.Error {
	nc.failed_step = i
	netcfg_teardown(nc)
	return err
}

// Undo everything `netcfg_apply` did, last first.
// Returns how many undo operations failed for a reason other than "already
// gone". The record is empty afterwards, whatever the result.
netcfg_teardown :: proc(nc: ^Netcfg) -> (failures: int) {
	c := nc.conn
	#reverse for u in nc.undo {
		err: sysnet.Error
		switch u.kind {
		case .Route:
			err = sysnet.route_del(c, u.route)
		case .Addr:
			err = sysnet.addr_del(c, nc.ifindex, u.addr, u.prefix_len)
		case .Link_Down:
			err = sysnet.link_set_down(c, nc.ifindex)
		case .Mtu:
			err = sysnet.link_set_mtu(c, nc.ifindex, u.mtu)
		}
		if err != .None && err != .Not_Found {
			failures += 1
		}
	}
	clear(&nc.undo)
	clear(&nc.applied)
	return failures
}

// For `persist-tun`: set the system to match `plan`.
// - Same plan as the applied one: nothing happens (`changed` is false).
// - Other plan: tear down the old one, apply the new one. In between there is
//   a short gap in which the old routes are gone.
netcfg_update :: proc(nc: ^Netcfg, plan: ^Plan) -> (changed: bool, err: sysnet.Error) {
	if netcfg_is_applied(nc) {
		same := len(nc.applied) == len(plan.steps)
		if same {
			for i in 0 ..< len(nc.applied) {
				if nc.applied[i] != plan.steps[i] {
					same = false
					break
				}
			}
		}
		if same {
			return false, .None
		}
		netcfg_teardown(nc)
	}
	return true, netcfg_apply(nc, plan)
}

// ---- looking at the system before anything changes ----

// What `plan_build` needs from the system.
System_State :: struct {
	server_route: Maybe(sysnet.Route),
	default4:     Maybe(sysnet.Route),
	default6:     Maybe(sysnet.Route),
}

Gather_Error :: enum u8 {
	None,
	// The route to the server goes out of the tunnel: routes of an earlier
	// connection are still in place. Tear them down first.
	Server_Via_Tunnel,
	// The kernel returned no result.
	Netlink,
}

// Ask the kernel how the server is reached and what the default routes are.
// - Call it after the tunnel exists and before any VPN route exists. The
//   lookup of the server must not see the routes of the VPN.
// - A missing route is no error: the field stays nil. `plan_build` decides if
//   it matters.
netcfg_gather :: proc(
	conn: ^sysnet.Conn,
	server: Maybe(sysnet.Address),
	tun_ifindex: u32,
) -> (
	st: System_State,
	err: Gather_Error,
) {
	if srv, ok := server.?; ok {
		r, lerr := sysnet.route_lookup(conn, srv)
		#partial switch lerr {
		case .None:
			if r.ifindex == tun_ifindex && tun_ifindex != 0 {
				return {}, .Server_Via_Tunnel
			}
			st.server_route = r
		case .Network_Unreachable, .Not_Found:
		case:
			return {}, .Netlink
		}
	}
	for fam in ([]sysnet.Family{.V4, .V6}) {
		d, derr := sysnet.route_get_default(conn, fam)
		#partial switch derr {
		case .None:
			if d.ifindex == tun_ifindex && tun_ifindex != 0 {
				continue
			}
			if fam == .V4 {
				st.default4 = d
			} else {
				st.default6 = d
			}
		case .Not_Found:
		case .Unsupported:
			// IPv6 is off.
			if fam == .V4 {
				return {}, .Netlink
			}
		case:
			return {}, .Netlink
		}
	}
	return st, .None
}

// The connected networks of the host, built by `host_nets_of` from the links
// and addresses of the system.
// `tun_ifindex` is the device of this client (0 if it has none yet).
// The caller owns the result.
netcfg_host_nets :: proc(conn: ^sysnet.Conn, tun_ifindex: u32, allocator := context.allocator) -> (nets: []Host_Net, err: sysnet.Error) {
	links := make([dynamic]sysnet.Link_Info)
	defer delete(links)
	addrs := make([dynamic]sysnet.Addr_Info)
	defer delete(addrs)
	sysnet.link_list(conn, &links) or_return
	sysnet.addr_list(conn, 0, nil, &addrs) or_return
	return host_nets_of(links[:], addrs[:], tun_ifindex, allocator), .None
}
