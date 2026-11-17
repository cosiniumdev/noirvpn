// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package client: the part of the client daemon outside the protocol.
//   - choose the next server to connect to
//   - turn the config and pushed options into OS state (addresses, routes, DNS)
// It does not import proto/session. The daemon maps session events to
// `Outcome` values for `policy_*`, feeds pushed options to `plan_build`, and
// runs the plan with `netcfg_*`.
//
//   remote.odin       ordered remote list, shuffling, back-off arithmetic
//   policy.odin       reconnect state machine (pure, takes `now`)
//   resolve.odin      host name lookup for one policy step
//   pull.odin         pull-filter rules on a PUSH_REPLY option list
//   plan.odin         config + pushed options + route info -> steps (pure)
//   plan_routes.odin  route part of the plan
//   plan_dns.odin     DNS part of the plan
//   netcfg_linux.odin runs a plan with platform/sysnet and undoes it
//   record.odin       clean-up record of each daemon, and clean-up at start
//   record_linux.odin files and locks of the records (record_windows.odin)
//
// Order of calls
//
// Program start, once, before the first tunnel exists:
//
//	conn := sysnet.open()
//	record_open(&rf, record_default_dir(), name, .Client)
//	record_cleanup(&rf, &conn, dns_env, ifname)   // what stopped daemons left
//
// Around each route or DNS change: set the record (`record_clear`,
// `record_add_*`), then `record_write`. Plan routes go into the record before
// they are added. At the end, after teardown: `record_close`.
//
// One connection:
//
//	policy_next -> (Resolve: resolve_action, policy_resolved) -> (Connect: transport + session)
//	... session reaches PUSH_REPLY ...
//	pull_filter_options(cfg.pull_filters, reply)   // before the push parser
//	push.pushed_options_parse(...)
//	tun.open                                        // once (a reconnect with persist-tun keeps it)
//	netcfg_gather(conn, server_address, tun_ifindex)
//	plan_build(...)                                 // pure: log plan.notes
//	netcfg_apply(&nc, &plan)                        // addresses, link up, routes
//	sysnet.dns_apply(...) if plan.has_dns           // after the routes: the server is reachable
//	policy_outcome(.Connected)
//
// Disconnect (any outcome):
//
//	sysnet.dns_revert            // first: no query may go to a dead tunnel
//	netcfg_teardown              // routes, addresses, link down
//	tun.close                    // unless persist-tun
//	policy_outcome(...); policy_next(...)
//
// persist-tun keeps the tun descriptor, routes and DNS, so no traffic leaks
// during a reconnect. Keep the `System_State` from `netcfg_gather` before the
// first apply. After the next PUSH_REPLY:
//
//	same server address:  plan_build with the saved System_State, then
//	                      netcfg_update (does nothing if the plan is equal)
//	other server address: netcfg_teardown, netcfg_gather, plan_build,
//	                      netcfg_apply (the tun stays open)
//
// `netcfg_gather` must run while no route of this client is in place. If it
// returns `Server_Via_Tunnel`, a plan from an earlier connection is still
// applied: tear it down first.
// System calls live in *_linux.odin, *_windows.odin, *_darwin.odin (netcfg and
// record), with the same names in each.
package client

// Routing protocol number (RTPROT_*) on every route this package adds.
// It is in the "unassigned" range. The clean-up at start (`record_cleanup`)
// looks only at routes with it, so nothing else may use this number.
ROUTE_PROTOCOL :: 201
