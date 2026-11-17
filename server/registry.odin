// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:mem"
import "core:time"
import "noir:proto/config"

// Registry: joins the peer table and the routing table. One call adds or removes
// a client in all indexes. It also decides where a packet goes.
// Routes per peer: IPv4 /32, IPv6 /128 and its `iroute` networks. Owner value =
// peer slot index (the wire peer-id).
// Packet rules (all counted in `counters`):
//   from the tun    Destination picks the peer. No route: drop.
//   from a peer     Source must be one of the peer's VPN addresses or inside an
//                   iroute, else drop (`.Drop_Bad_Source`): a client cannot send
//                   as someone else. Then:
//                   - `client-to-client`: destination of another peer goes to
//                     that peer; the rest goes to the tun (kernel routes it).
//                   - no `client-to-client`: destination of another peer is
//                     dropped (`.Drop_C2C`), so clients stay apart even when the
//                     host forwards packets.
//                   - destination is the sender: dropped (`.Drop_Loop`).

Verdict :: enum u8 {
	// Write it to the tun.
	To_Tun,
	// Seal it for `dest` (client-to-client, or from the tun).
	To_Peer,
	// Not an IPv4 or IPv6 packet, or truncated.
	Drop_Bad_Packet,
	// The source address is not the peer's.
	Drop_Bad_Source,
	// From the tun: nobody owns the destination.
	Drop_No_Route,
	// To the sender itself.
	Drop_Loop,
	// To another peer, without `client-to-client`.
	Drop_C2C,
}

Registry_Params :: struct {
	// `max-clients`.
	max_peers:        int,
	// Room for iroutes of all clients together, per family.
	max_iroutes:      int,
	reuse_delay:      time.Duration,
	hash_seed:        u64,
	client_to_client: bool,
}

DEFAULT_MAX_IROUTES :: 4096

// Per peer data that is not needed on the packet path.
Peer_Extra :: struct {
	lease:    Lease,
	iroutes4: []config.Iroute,
	iroutes6: []config.Iroute6,
	// Either mode: admitted by the chain (see `Decision.by_chain`).
	by_chain: bool,
}

Registry :: struct {
	peers:            Peer_Table,
	routes:           Route_Table,
	extra:            []Peer_Extra,
	client_to_client: bool,
	counters:         [Verdict]u64,
	allocator:        mem.Allocator,
}

registry_init :: proc(reg: ^Registry, p: Registry_Params, allocator := context.allocator) -> bool {
	reg^ = {}
	reg.allocator = allocator
	reg.client_to_client = p.client_to_client
	if !peers_init(&reg.peers, Peer_Table_Params{p.max_peers, p.reuse_delay, p.hash_seed}, allocator) {
		return false
	}
	max_ir := p.max_iroutes
	if !route_table_init(&reg.routes, p.max_peers + max_ir, p.max_peers + max_ir, u32(p.hash_seed), allocator) {
		peers_destroy(&reg.peers)
		return false
	}
	extra, err := make([]Peer_Extra, p.max_peers, allocator)
	if err != nil {
		route_table_destroy(&reg.routes)
		peers_destroy(&reg.peers)
		return false
	}
	reg.extra = extra
	return true
}

registry_destroy :: proc(reg: ^Registry) {
	for &e in reg.extra {
		delete(e.iroutes4, reg.allocator)
		delete(e.iroutes6, reg.allocator)
	}
	delete(reg.extra, reg.allocator)
	route_table_destroy(&reg.routes)
	peers_destroy(&reg.peers)
	reg^ = {}
}

registry_memory :: proc(reg: ^Registry) -> int {
	return peers_memory(&reg.peers) + route_memory(&reg.routes) + len(reg.extra) * size_of(Peer_Extra)
}

// Takes a peer-id. Pair it with `registry_commit` or `registry_cancel`.
registry_reserve :: proc(reg: ^Registry, now: time.Duration) -> (Peer_Handle, bool) {
	return peers_alloc(&reg.peers, now)
}

// Gives back an id that was reserved but never committed.
registry_cancel :: proc(reg: ^Registry, h: Peer_Handle, now: time.Duration) {
	if h.index < reg.peers.capacity && reg.peers.peers[h.index].state == .Reserved {
		peers_remove(&reg.peers, h, now)
	}
}

// Sets a reserved peer live: peer table, VPN addresses, iroutes. Returns
// `.None`, or the reject reason. On a reject nothing was added and the peer is
// still reserved (the caller cancels it).
registry_commit :: proc(
	reg: ^Registry,
	h: Peer_Handle,
	identity: string,
	addr: Addr_Key,
	lease: Lease,
	iroutes4: []config.Iroute,
	iroutes6: []config.Iroute6,
	spki: [config.PIN_LEN]u8,
	pinned: bool,
	user: u64,
	now: time.Duration,
) -> Reject_Reason {
	if h.index >= reg.peers.capacity ||
	   reg.peers.peers[h.index].gen != h.gen ||
	   reg.peers.peers[h.index].state != .Reserved {
		return .Internal
	}
	owner := h.index
	// Routes first: they are the cheapest to undo.
	n4, n6 := 0, 0
	rejected := Reject_Reason.None
	has4, has6 := lease.kind4 != .None, lease.kind6 != .None
	if has4 {
		switch route_add4(&reg.routes, lease.addr4, 32, owner) {
		case .None:
			n4 += 1
		case .Full:
			rejected = .Too_Many_Routes
		case .Bad_Prefix, .Host_Bits, .Conflict, .Duplicate, .Out_Of_Memory:
			rejected = .Route_Conflict
		}
	}
	if rejected == .None && has6 {
		switch route_add6(&reg.routes, lease.addr6, 128, owner) {
		case .None:
			n6 += 1
		case .Full:
			rejected = .Too_Many_Routes
		case .Bad_Prefix, .Host_Bits, .Conflict, .Duplicate, .Out_Of_Memory:
			rejected = .Route_Conflict
		}
	}
	// What was added for iroutes, to undo on failure. A route that the same
	// peer already has (a repeated line) is skipped.
	added4 := make([dynamic]config.Iroute, 0, len(iroutes4), context.temp_allocator)
	added6 := make([dynamic]config.Iroute6, 0, len(iroutes6), context.temp_allocator)
	for r in iroutes4 {
		if rejected != .None {
			break
		}
		switch route_add4(&reg.routes, r.network, r.prefix, owner) {
		case .None:
			append(&added4, r)
		case .Duplicate:
		case .Full:
			rejected = .Too_Many_Routes
		case .Bad_Prefix, .Host_Bits, .Conflict, .Out_Of_Memory:
			rejected = .Route_Conflict
		}
	}
	for r in iroutes6 {
		if rejected != .None {
			break
		}
		switch route_add6(&reg.routes, r.prefix, r.bits, owner) {
		case .None:
			append(&added6, r)
		case .Duplicate:
		case .Full:
			rejected = .Too_Many_Routes
		case .Bad_Prefix, .Host_Bits, .Conflict, .Out_Of_Memory:
			rejected = .Route_Conflict
		}
	}
	// Copies of the iroutes, kept for removal.
	e4: []config.Iroute
	e6: []config.Iroute6
	if rejected == .None {
		err4, err6: mem.Allocator_Error
		e4, err4 = make([]config.Iroute, len(added4), reg.allocator)
		e6, err6 = make([]config.Iroute6, len(added6), reg.allocator)
		if err4 != nil || err6 != nil {
			rejected = .Internal
		} else {
			copy(e4, added4[:])
			copy(e6, added6[:])
		}
	}
	if rejected == .None {
		v4: Maybe([4]u8)
		v6: Maybe([16]u8)
		if has4 {
			v4 = lease.addr4
		}
		if has6 {
			v6 = lease.addr6
		}
		switch peers_commit(&reg.peers, h, identity, addr, v4, v6, user, now, Peer_Key{spki, pinned}) {
		case .None:
		case .Addr_In_Use, .Vpn_Addr_In_Use:
			rejected = .Route_Conflict
		case .Bad_Handle, .Out_Of_Memory:
			rejected = .Internal
		}
	}
	if rejected != .None {
		delete(e4, reg.allocator)
		delete(e6, reg.allocator)
		if has4 && n4 > 0 {
			route_remove4(&reg.routes, lease.addr4, 32, owner)
		}
		if has6 && n6 > 0 {
			route_remove6(&reg.routes, lease.addr6, 128, owner)
		}
		for r in added4 {
			route_remove4(&reg.routes, r.network, r.prefix, owner)
		}
		for r in added6 {
			route_remove6(&reg.routes, r.prefix, r.bits, owner)
		}
		return rejected
	}
	reg.extra[owner] = Peer_Extra {
		lease    = lease,
		iroutes4 = e4,
		iroutes6 = e6,
	}
	return .None
}

// Removes a peer from every index. Returns the lease so the caller can give
// the addresses back to the pools. Do that after this call, so no route points
// at an address that is free. `ok` is false for a stale handle.
registry_remove :: proc(reg: ^Registry, h: Peer_Handle, now: time.Duration) -> (lease: Lease, ok: bool) {
	p := peers_get(&reg.peers, h)
	if p == nil {
		return {}, false
	}
	owner := h.index
	ex := &reg.extra[owner]
	lease = ex.lease
	if lease.kind4 != .None {
		route_remove4(&reg.routes, lease.addr4, 32, owner)
	}
	if lease.kind6 != .None {
		route_remove6(&reg.routes, lease.addr6, 128, owner)
	}
	for r in ex.iroutes4 {
		route_remove4(&reg.routes, r.network, r.prefix, owner)
	}
	for r in ex.iroutes6 {
		route_remove6(&reg.routes, r.prefix, r.bits, owner)
	}
	delete(ex.iroutes4, reg.allocator)
	delete(ex.iroutes6, reg.allocator)
	ex^ = {}
	peers_remove(&reg.peers, h, now)
	return lease, true
}

// Moves a peer to a new transport address after a packet from there
// authenticated.
registry_float :: proc(reg: ^Registry, h: Peer_Handle, new_addr: Addr_Key) -> (old: Addr_Key, err: Peer_Error) {
	return peers_float(&reg.peers, h, new_addr)
}

// The live sessions with their keys, for `pin_kicks`. The identity strings
// belong to the peer table: use the list before the next disconnect.
registry_live_keys :: proc(reg: ^Registry, allocator := context.allocator) -> [dynamic]Live_Key {
	out := make([dynamic]Live_Key, 0, int(reg.peers.count), allocator)
	from := u32(0)
	for {
		h, ok := peers_next_active(&reg.peers, from)
		if !ok {
			break
		}
		from = h.index + 1
		ex := &reg.extra[h.index]
		key := &reg.peers.keys[h.index]
		if !key.pinned && !ex.by_chain {
			continue
		}
		append(&out, Live_Key{h, reg.peers.peers[h.index].identity, key.spki, ex.by_chain})
	}
	return out
}

// ---------------------------------------------------------------------------
// Packets

// The addresses of an IP packet. Only the fixed header is read.
Ip_Header :: struct {
	v6:  bool,
	src: [16]u8,
	dst: [16]u8,
}

// Reads the version and the two addresses. IPv4 addresses are in the first four
// bytes of `src` / `dst`. False for anything that is not a whole IP header.
ip_header_parse :: proc "contextless" (pkt: []u8) -> (h: Ip_Header, ok: bool) {
	if len(pkt) < 1 {
		return {}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[0] & 0xf < 5 {
			return {}, false
		}
		for i in 0 ..< 4 {
			h.src[i] = pkt[12 + i]
			h.dst[i] = pkt[16 + i]
		}
		return h, true
	case 6:
		if len(pkt) < 40 {
			return {}, false
		}
		h.v6 = true
		for i in 0 ..< 16 {
			h.src[i] = pkt[8 + i]
			h.dst[i] = pkt[24 + i]
		}
		return h, true
	}
	return {}, false
}

@(private)
count_verdict :: #force_inline proc "contextless" (reg: ^Registry, v: Verdict) -> Verdict {
	reg.counters[v] += 1
	return v
}

// The peer that owns an address, by longest prefix. `NONE` if none.
registry_route :: #force_inline proc "contextless" (reg: ^Registry, hd: ^Ip_Header) -> u32 {
	owner: u32
	ok: bool
	if hd.v6 {
		owner, _, ok = route_lookup6(&reg.routes, &hd.dst)
	} else {
		owner, _, ok = route_lookup4(&reg.routes, {hd.dst[0], hd.dst[1], hd.dst[2], hd.dst[3]})
	}
	return owner if ok else NONE
}

// A packet read from the tun. `To_Peer` with the peer to seal it for, or a drop.
registry_from_tun :: proc "contextless" (reg: ^Registry, pkt: []u8) -> (dest: Peer_Handle, v: Verdict) {
	hd, ok := ip_header_parse(pkt)
	if !ok {
		return {}, count_verdict(reg, .Drop_Bad_Packet)
	}
	owner := registry_route(reg, &hd)
	if owner == NONE {
		return {}, count_verdict(reg, .Drop_No_Route)
	}
	h, p := peers_by_id(&reg.peers, owner)
	if p == nil {
		return {}, count_verdict(reg, .Drop_No_Route)
	}
	return h, count_verdict(reg, .To_Peer)
}

// Is `src` an address the peer may send from? Its own VPN address, or a
// network of its iroutes.
@(private)
source_ok :: #force_inline proc "contextless" (reg: ^Registry, owner: u32, p: ^Peer, hd: ^Ip_Header) -> bool {
	if hd.v6 {
		if p.has6 && p.vpn6 == hd.src {
			return true
		}
		if len(reg.extra[owner].iroutes6) == 0 {
			return false
		}
		o, _, ok := route_lookup6(&reg.routes, &hd.src)
		return ok && o == owner
	}
	src4 := [4]u8{hd.src[0], hd.src[1], hd.src[2], hd.src[3]}
	if p.has4 && p.vpn4 == src4 {
		return true
	}
	if len(reg.extra[owner].iroutes4) == 0 {
		return false
	}
	o, _, ok := route_lookup4(&reg.routes, src4)
	return ok && o == owner
}

// A packet from a peer, already decrypted. `h` is the peer it came from.
registry_from_peer :: proc "contextless" (reg: ^Registry, h: Peer_Handle, pkt: []u8) -> (dest: Peer_Handle, v: Verdict) {
	p := peers_get(&reg.peers, h)
	if p == nil {
		return {}, count_verdict(reg, .Drop_Bad_Source)
	}
	hd, ok := ip_header_parse(pkt)
	if !ok {
		return {}, count_verdict(reg, .Drop_Bad_Packet)
	}
	if !source_ok(reg, h.index, p, &hd) {
		return {}, count_verdict(reg, .Drop_Bad_Source)
	}
	owner := registry_route(reg, &hd)
	if owner == NONE {
		return {}, count_verdict(reg, .To_Tun)
	}
	if owner == h.index {
		return {}, count_verdict(reg, .Drop_Loop)
	}
	if !reg.client_to_client {
		return {}, count_verdict(reg, .Drop_C2C)
	}
	dh, dp := peers_by_id(&reg.peers, owner)
	if dp == nil {
		return {}, count_verdict(reg, .To_Tun)
	}
	return dh, count_verdict(reg, .To_Peer)
}
