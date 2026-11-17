// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package server: the server side of noirvpn that does not touch the network
// (who may connect, what each client gets, where packets go). Sans-I/O: no
// sockets, tun, clock (callers pass `now`, a monotonic `time.Duration`) or
// threads. It does not import `proto/session`; the daemon maps these plain types
// onto the session's.
//
// Parts (one file each):
//   pin.odin            peers file as a lookup table; fail-closed `ossl.Pin_Check`;
//                       reload diff and kick list
//   auth.odin           identity and accept / reject / pending decision,
//                       max-clients, duplicate-cn
//   ratelimit.odin      per-source token buckets (connect-freq)
//   pool.odin           IPv4 / IPv6 address pools, static address rules
//   pool_persist.odin   ifconfig-pool-persist text format
//   peers.odin          peer table: peer-ids, handles, hash lookups
//   route.odin          longest-prefix match for the tun side
//   registry.odin       peer table + routes together; packet verdicts
//   client_params.odin  server config + ccd file + peers entry + pools -> one
//                       client's `Assignment`
//   server.odin         this file: `Server`, the calls a daemon performs
//
// Calls a daemon performs (single thread):
//
//   startup     cfg := config build; pins := pin_table_load(cfg.peer_keys);
//               server_init(&srv, &cfg, pins, params); if a pool file is set,
//               `pools_persist_load(&srv.pools, text, now)`.
//               TLS: `Tls_Config{pin_check = pin_check, pin_user = &srv.pins}`.
//
//   Auth_Request  d := server_authorize(&srv, input, now)
//                   .Reject            -> AUTH_FAILED[,TEMP] (reject_client_text),
//                                         log reject_text(d.reject.reason)
//                   .Pending_Password  -> check user name and password against the
//                                         hash file (not in this package); yes:
//                                         d = server_password_passed(&srv, d),
//                                         may give .Pending_External; no:
//                                         `server_deny_password`
//                   .Pending_External  -> publish peer.auth_pending, wait; yes:
//                                         d = server_resume(&srv, d); no or
//                                         timeout: `server_deny_external`
//                   .Accept            -> next step
//                 for each d.kicks[i]: server_disconnect(&srv, h, now) and close
//                   that session (frees the old address for the new session);
//                 a, h, rej, detail := server_connect(&srv, &d, src, user, now)
//                   rej.reason != .None -> AUTH_FAILED as above
//                 else assignment_push_params(&a, &reply_params) and
//                   session_server_accept (peer_id = a.peer_id); free `a` with
//                   assignment_destroy once the PUSH_REPLY is built.
//                 If the session fails before it is active, or ends at any time:
//                 server_disconnect(&srv, h, now).
//
//   disconnect  server_disconnect: routes, indexes, the peer-id (waits
//               `id_reuse_delay`), the addresses (remembered for the next
//               connect of the same identity, then free once the pool is full
//               and the hold time is over).
//
//   float       after a packet from a new address authenticated:
//               server_float(&srv, h, new_addr_key).
//
//   data path   from a peer:  registry_from_peer(&srv.reg, h, packet)
//                               -> To_Tun | To_Peer(dest) | drop
//               from the tun: registry_from_tun(&srv.reg, packet)
//                               -> To_Peer(dest) | drop
//               peer lookup:  peers_by_id (header peer-id), peers_by_addr
//
//   reload      t, errors := pin_table_load(path); if t == nil keep the old one
//               and log `errors`. Else r := server_reload_peers(&srv, t),
//               disconnect and close every r.kicks[i].handle, log r.changes,
//               then reload_result_destroy(&r).
package server

import "core:mem"
import "core:time"
import "noir:proto/config"

Server_Params :: struct {
	// How long a released pool address is kept for its old client when the
	// pool is otherwise full. 0 = may be reused at once if nothing else is free.
	pool_hold:        time.Duration,
	// How long a freed peer-id stays unused (default 30 s).
	id_reuse_delay:   time.Duration,
	// Spare peer-id slots beyond `max-clients`, for ids waiting out the reuse
	// delay. 0 = max(256, max-clients / 2).
	id_headroom:      int,
	// Room for iroutes of all clients, per family (default 4096).
	max_iroutes:      int,
	// Sources remembered by the connect-freq limiter (default 4096).
	rate_sources:     int,
	// Pool slots at most (default POOL_MAX_SLOTS).
	max_pool_slots:   int,
	// Random bytes for the hash tables. The daemon fills them from the RNG.
	hash_seed:        u64,
	// Reads client-config-dir files. nil = the OS.
	loader:           config.Loader,
	loader_data:      rawptr,
}

Server :: struct {
	cfg:       ^config.Server_Config,
	// What the TLS pin check reads. Its table is owned by the server.
	pins:      Pin_Store,
	auth:      Auth_State,
	pools:     Pools,
	reg:       Registry,
	env:       Params_Env,
	allocator: mem.Allocator,
}

// `pins` is the peers file table; nil when the mode does not use pins. The
// server owns it from now on. `cfg` must outlive the server.
server_init :: proc(
	s: ^Server,
	cfg: ^config.Server_Config,
	pins: ^Pin_Table,
	p: Server_Params = {},
	allocator := context.allocator,
) -> bool {
	s^ = {}
	s.allocator = allocator
	s.cfg = cfg
	pin_store_init(&s.pins, pins)
	policy := auth_policy_from_config(cfg)
	if !auth_init(&s.auth, policy, &s.pins, p.rate_sources if p.rate_sources > 0 else DEFAULT_RATE_SOURCES, p.hash_seed, allocator) {
		return false
	}
	if !pools_init(&s.pools, cfg, p.pool_hold, p.max_pool_slots if p.max_pool_slots > 0 else POOL_MAX_SLOTS, allocator) {
		auth_destroy(&s.auth)
		return false
	}
	max_clients := max(cfg.max_clients, 1)
	headroom := p.id_headroom if p.id_headroom > 0 else max(256, max_clients / 2)
	delay := p.id_reuse_delay if p.id_reuse_delay > 0 else DEFAULT_ID_REUSE_DELAY
	rp := Registry_Params {
		max_peers        = min(max_clients + headroom, MAX_PEERS),
		max_iroutes      = p.max_iroutes if p.max_iroutes > 0 else DEFAULT_MAX_IROUTES,
		reuse_delay      = delay,
		hash_seed        = p.hash_seed,
		client_to_client = cfg.client_to_client,
	}
	if !registry_init(&s.reg, rp, allocator) {
		pools_destroy(&s.pools)
		auth_destroy(&s.auth)
		return false
	}
	s.env = Params_Env {
		cfg         = cfg,
		pools       = &s.pools,
		pins        = &s.pins,
		loader      = p.loader,
		loader_data = p.loader_data,
	}
	server_reserve_pin_statics(s)
	return true
}

server_destroy :: proc(s: ^Server) {
	registry_destroy(&s.reg)
	pools_destroy(&s.pools)
	auth_destroy(&s.auth)
	pin_table_destroy(pin_store_current(&s.pins))
	s^ = {}
}

// Reserves the static addresses of the peers file so dynamic clients never get
// them. Done at init and after every reload.
server_reserve_pin_statics :: proc(s: ^Server) {
	pools_unreserve_all(&s.pools, .Reserved_Pin)
	t := pin_store_current(&s.pins)
	if t == nil {
		return
	}
	for &e in t.peers.entries {
		a4: Maybe([4]u8)
		a6: Maybe([16]u8)
		if ip, ok := e.client.ifconfig_push.?; ok && ip.local_is_ip {
			a4 = ip.local_ip
		}
		if ip6, ok := e.client.ifconfig_ipv6_push.?; ok {
			a6 = ip6.addr
		}
		pools_reserve_static(&s.pools, a4, a6, .Reserved_Pin)
	}
}

// ---------------------------------------------------------------------------
// Auth

server_authorize :: proc(s: ^Server, in_: Auth_Input, now: time.Duration) -> Decision {
	return auth_decide(&s.auth, &s.reg.peers, in_, now)
}

// The hash file said yes to a `.Pending_Password` decision. `form` is the user
// name as the hash file spells it ("" if not known). The result is an Accept,
// or a `.Pending_External` if `auth-external` is also configured.
server_password_passed :: proc(s: ^Server, d: Decision, form := "", parked := 0) -> Decision {
	return auth_password_passed(&s.auth, &s.reg.peers, d, form, parked)
}

// The hash file said no (the user is not in it, or the password is wrong).
server_deny_password :: proc(s: ^Server) -> Reject {
	s.auth.stats.rejected[.Password_Failed] += 1
	return reject_make(.Password_Failed)
}

// The hash file check could not run (queue full, or too slow). The client is
// told to try again later.
server_deny_password_busy :: proc(s: ^Server) -> Reject {
	s.auth.stats.rejected[.Password_Busy] += 1
	return reject_make(.Password_Busy)
}

// The controller said yes to a `.Pending_External` decision.
server_resume :: proc(s: ^Server, d: Decision, parked := 0) -> Decision {
	return auth_resume(&s.auth, &s.reg.peers, d, parked)
}

// The controller said no, or did not respond in time.
server_deny_external :: proc(s: ^Server, timed_out: bool) -> Reject {
	reason := Reject_Reason.External_Timeout if timed_out else Reject_Reason.External_Denied
	s.auth.stats.rejected[reason] += 1
	return reject_make(reason)
}

// ---------------------------------------------------------------------------
// Connect, disconnect, float

// Adds an accepted client: takes a peer-id and addresses, reads its ccd file,
// and adds it to the peer and routing tables. Run the decision's `kicks` first.
// `user` is stored in the peer for the caller (a session index). On a reject
// nothing is held; `detail` (temp allocator) is log text.
server_connect :: proc(
	s: ^Server,
	d: ^Decision,
	src: Addr_Key,
	user: u64,
	now: time.Duration,
	allocator := context.allocator,
	extra := "",
) -> (
	a: Assignment,
	h: Peer_Handle,
	rej: Reject,
	detail: string,
) {
	if d.kind != .Accept {
		return {}, {}, reject_make(.Internal), ""
	}
	hh, ok := registry_reserve(&s.reg, now)
	if !ok {
		return {}, {}, reject_make(.Id_Exhausted), ""
	}
	name := identity_str(&d.identity)
	req := Connect_Request {
		identity = name,
		spki     = d.spki,
		pinned   = d.pinned,
		peer_id  = hh.index,
		extra    = extra,
	}
	as, r, det := client_params_build(&s.env, req, now, allocator)
	if r.reason != .None {
		registry_cancel(&s.reg, hh, now)
		return {}, {}, r, det
	}
	cr := registry_commit(&s.reg, hh, name, src, as.lease, as.iroutes4, as.iroutes6, d.spki, d.pinned, user, now)
	if cr != .None {
		pools_release(&s.pools, as.lease, now)
		registry_cancel(&s.reg, hh, now)
		assignment_destroy(&as)
		return {}, {}, reject_make(cr), ""
	}
	s.reg.extra[hh.index].by_chain = d.by_chain
	return as, hh, {}, ""
}

// Removes a client everywhere. False if the handle is stale (already gone).
server_disconnect :: proc(s: ^Server, h: Peer_Handle, now: time.Duration) -> bool {
	lease, ok := registry_remove(&s.reg, h, now)
	if !ok {
		return false
	}
	pools_release(&s.pools, lease, now)
	return true
}

server_float :: proc(s: ^Server, h: Peer_Handle, new_addr: Addr_Key) -> (old: Addr_Key, err: Peer_Error) {
	return registry_float(&s.reg, h, new_addr)
}

// ---------------------------------------------------------------------------
// Reload

Reload_Result :: struct {
	// Live sessions the new file no longer allows. Disconnect each.
	kicks:   [dynamic]Reload_Kick,
	// What changed in the file, for the log.
	changes: [dynamic]Pin_Change,
	// The table that was replaced. The strings in `changes` point into it;
	// `reload_result_destroy` frees it.
	old:     ^Pin_Table,
}

// Swaps in a new peers table (from `pin_table_load`). The server owns `t` from
// now on. Single thread: `reload_result_destroy` frees the old table. Call it
// only after the TLS layer cannot be inside the pin check (that holds if you
// are on the thread that runs handshakes).
server_reload_peers :: proc(s: ^Server, t: ^Pin_Table, allocator := context.allocator) -> (r: Reload_Result) {
	live := registry_live_keys(&s.reg, context.temp_allocator)
	r.kicks = pin_kicks(t, live[:], allocator)
	old := pin_store_current(&s.pins)
	if old != nil {
		r.changes = pin_diff(old, t, allocator)
	}
	r.old = pin_store_swap(&s.pins, t)
	server_reserve_pin_statics(s)
	return
}

reload_result_destroy :: proc(r: ^Reload_Result) {
	delete(r.kicks)
	delete(r.changes)
	pin_table_destroy(r.old)
	r^ = {}
}
