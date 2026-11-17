// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:mem"
import "core:strings"
import "core:time"
import "noir:proto/config"

// Peer table: every connected client, with fast lookups.
//   by peer-id          array index (data path from a peer)
//   by transport addr   open-addressing hash (data path from a peer, UDP)
//   by VPN address      v4 and v6 hashes (kicks, bus requests, collision checks)
//   by identity         hash with a chain per name (duplicate-cn)
// Fixed capacity. After `peers_init` only one identity string per connect is
// allocated. Lookups never allocate. Single thread, no locks.
//
// Peer-id = slot index.
//   - Issued in order; none repeats before every other id was used once.
//   - A freed id waits `reuse_delay`, so a late packet for a dead peer reads as
//     "unknown peer" and never reaches the next slot owner.
//   - 0xFFFFFF is never issued (it means "no peer" on the wire): capacity is at
//     most 0xFFFFFF.
// `Peer_Handle` = index + a generation that changes each time the slot is handed
// out. A stale handle fails every call safely, so a timer or queue may keep one.

MAX_PEERS :: 0xFFFFFE

Peer_Handle :: struct {
	index: u32,
	gen:   u32,
}

// A handle that is never valid (generations start at 1).
NO_HANDLE :: Peer_Handle{}

Peer_State :: enum u8 {
	Free,
	// An id is taken; the client is not visible in any lookup yet.
	Reserved,
	Active,
}

Peer :: struct {
	// Transport address the peer was last seen at.
	addr:       Addr_Key,
	vpn6:       [16]u8,
	vpn4:       [4]u8,
	state:      Peer_State,
	has4:       bool,
	has6:       bool,
	gen:        u32,
	// Next peer with the same identity (NONE = last).
	ident_next: u32,
	// Owned copy.
	identity:   string,
	// Free for the caller: a session index or pointer.
	user:       u64,
	// Active: when it connected. Free: when it was freed (reuse delay).
	since:      time.Duration,
}

// The key that a session was admitted with. `pinned`: the proof of the session is
// a pin (the key is in the peers file), so the session is unique by this key.
Peer_Key :: struct {
	spki:   [config.PIN_LEN]u8,
	pinned: bool,
}

Peer_Table_Params :: struct {
	// Most clients at one time (the `max-clients` value).
	capacity:    int,
	// How long a freed peer-id stays unused.
	reuse_delay: time.Duration,
	// Random per table. Mixed into the address hash.
	hash_seed:   u64,
}

DEFAULT_ID_REUSE_DELAY :: 30 * time.Second

Peer_Table :: struct {
	peers:       []Peer,
	capacity:    u32,
	// Active and Reserved.
	count:       u32,
	// Ids below this have been used at least once.
	next_virgin: u32,
	// Freed ids, oldest first.
	ring:        []u32,
	ring_head:   u32,
	ring_len:    u32,
	reuse_delay: time.Duration,
	seed:        u64,
	by_addr:     Hash_Index,
	by_vpn4:     Hash_Index,
	by_vpn6:     Hash_Index,
	by_ident:    Hash_Index,
	// The key of each Active peer, by slot index.
	keys:        []Peer_Key,
	allocator:   mem.Allocator,
}

Peer_Error :: enum u8 {
	None,
	// The handle is stale or the peer is in the wrong state.
	Bad_Handle,
	// Another peer has this transport address.
	Addr_In_Use,
	// Another peer has this VPN address.
	Vpn_Addr_In_Use,
	Out_Of_Memory,
}

peers_init :: proc(pt: ^Peer_Table, p: Peer_Table_Params, allocator := context.allocator) -> bool {
	pt^ = {}
	if p.capacity < 1 || p.capacity > MAX_PEERS {
		return false
	}
	pt.allocator = allocator
	pt.capacity = u32(p.capacity)
	pt.reuse_delay = p.reuse_delay
	pt.seed = p.hash_seed
	peers, e1 := make([]Peer, p.capacity, allocator)
	ring, e2 := make([]u32, p.capacity, allocator)
	keys, e3 := make([]Peer_Key, p.capacity, allocator)
	if e1 != nil || e2 != nil || e3 != nil {
		delete(peers, allocator)
		delete(ring, allocator)
		delete(keys, allocator)
		pt^ = {}
		return false
	}
	pt.peers = peers
	pt.ring = ring
	pt.keys = keys
	ok := hash_index_init(&pt.by_addr, p.capacity, allocator)
	ok = hash_index_init(&pt.by_vpn4, p.capacity, allocator) && ok
	ok = hash_index_init(&pt.by_vpn6, p.capacity, allocator) && ok
	ok = hash_index_init(&pt.by_ident, p.capacity, allocator) && ok
	if !ok {
		peers_destroy(pt)
		return false
	}
	return true
}

// Frees everything, including the identity strings of live peers.
peers_destroy :: proc(pt: ^Peer_Table) {
	a := pt.allocator
	for &p in pt.peers {
		if p.state != .Free && len(p.identity) > 0 {
			delete(p.identity, a)
		}
	}
	delete(pt.peers, a)
	delete(pt.ring, a)
	delete(pt.keys, a)
	hash_index_destroy(&pt.by_addr, a)
	hash_index_destroy(&pt.by_vpn4, a)
	hash_index_destroy(&pt.by_vpn6, a)
	hash_index_destroy(&pt.by_ident, a)
	pt^ = {}
}

// Bytes held by the table (capacity based; nothing grows afterwards).
peers_memory :: proc(pt: ^Peer_Table) -> int {
	n := len(pt.peers) * size_of(Peer) + len(pt.ring) * size_of(u32) + len(pt.keys) * size_of(Peer_Key)
	n += (len(pt.by_addr.cells) + len(pt.by_vpn4.cells) + len(pt.by_vpn6.cells) + len(pt.by_ident.cells)) * size_of(Cell)
	return n
}

peers_count :: proc "contextless" (pt: ^Peer_Table) -> int {
	return int(pt.count)
}

// ---------------------------------------------------------------------------
// Handles

// The peer a handle names, or nil if the handle is stale or the peer is not
// active. Reserved slots are not returned.
peers_get :: #force_inline proc "contextless" (pt: ^Peer_Table, h: Peer_Handle) -> ^Peer {
	if h.index >= pt.capacity {
		return nil
	}
	p := &pt.peers[h.index]
	if p.gen != h.gen || p.state != .Active {
		return nil
	}
	return p
}

// The wire peer-id of a handle.
peer_id :: #force_inline proc "contextless" (h: Peer_Handle) -> u32 {
	return h.index
}

@(private)
handle_of :: #force_inline proc "contextless" (pt: ^Peer_Table, idx: u32) -> Peer_Handle {
	return Peer_Handle{idx, pt.peers[idx].gen}
}

// ---------------------------------------------------------------------------
// Allocation

// Takes a peer-id. `ok` is false when the table is full or every free id is
// still waiting out the reuse delay.
peers_alloc :: proc(pt: ^Peer_Table, now: time.Duration) -> (h: Peer_Handle, ok: bool) {
	idx: u32
	switch {
	case pt.next_virgin < pt.capacity:
		idx = pt.next_virgin
		pt.next_virgin += 1
	case pt.ring_len > 0:
		cand := pt.ring[pt.ring_head]
		if now - pt.peers[cand].since < pt.reuse_delay {
			return {}, false
		}
		pt.ring_head = (pt.ring_head + 1) % pt.capacity
		pt.ring_len -= 1
		idx = cand
	case:
		return {}, false
	}
	p := &pt.peers[idx]
	p.state = .Reserved
	p.gen += 1
	p.has4, p.has6 = false, false
	p.ident_next = NONE
	p.user = 0
	p.since = now
	pt.count += 1
	return Peer_Handle{idx, p.gen}, true
}

// Sets a reserved peer visible. The identity is copied. `vpn4` and `vpn6` are
// optional. On any error nothing is changed and the peer stays reserved.
peers_commit :: proc(
	pt: ^Peer_Table,
	h: Peer_Handle,
	identity: string,
	addr: Addr_Key,
	vpn4: Maybe([4]u8),
	vpn6: Maybe([16]u8),
	user: u64,
	now: time.Duration,
	key: Peer_Key = {},
) -> Peer_Error {
	if h.index >= pt.capacity {
		return .Bad_Handle
	}
	p := &pt.peers[h.index]
	if p.gen != h.gen || p.state != .Reserved {
		return .Bad_Handle
	}
	addr := addr
	if _, taken := find_addr(pt, &addr); taken {
		return .Addr_In_Use
	}
	if a, ok := vpn4.?; ok {
		if _, other := peers_by_vpn4(pt, a); other != nil {
			return .Vpn_Addr_In_Use
		}
	}
	if a, ok := vpn6.?; ok {
		a := a
		if _, other := peers_by_vpn6(pt, &a); other != nil {
			return .Vpn_Addr_In_Use
		}
	}
	name, nerr := strings.clone(identity, pt.allocator)
	if nerr != nil {
		return .Out_Of_Memory
	}
	p.identity = name
	p.addr = addr
	p.user = user
	p.since = now
	pt.keys[h.index] = key
	hash_index_insert(&pt.by_addr, addr_hash(pt, &addr), h.index)
	if a, ok := vpn4.?; ok {
		p.vpn4, p.has4 = a, true
		hash_index_insert(&pt.by_vpn4, key4(a), h.index)
	}
	if a, ok := vpn6.?; ok {
		p.vpn6, p.has6 = a, true
		hash_index_insert(&pt.by_vpn6, hash_bytes(&p.vpn6, 16, pt.seed), h.index)
	}
	ident_link(pt, h.index)
	p.state = .Active
	return .None
}

// Frees a peer, active or only reserved. Its id waits `reuse_delay`.
peers_remove :: proc(pt: ^Peer_Table, h: Peer_Handle, now: time.Duration) -> bool {
	if h.index >= pt.capacity {
		return false
	}
	p := &pt.peers[h.index]
	if p.gen != h.gen || p.state == .Free {
		return false
	}
	if p.state == .Active {
		hash_index_remove(&pt.by_addr, addr_hash(pt, &p.addr), h.index)
		if p.has4 {
			hash_index_remove(&pt.by_vpn4, key4(p.vpn4), h.index)
		}
		if p.has6 {
			hash_index_remove(&pt.by_vpn6, hash_bytes(&p.vpn6, 16, pt.seed), h.index)
		}
		ident_unlink(pt, h.index)
		delete(p.identity, pt.allocator)
	}
	p.identity = ""
	p.state = .Free
	p.has4, p.has6 = false, false
	p.since = now
	pt.count -= 1
	tail := (pt.ring_head + pt.ring_len) % pt.capacity
	pt.ring[tail] = h.index
	pt.ring_len += 1
	return true
}

// Moves a peer to a new transport address. Call it only after a packet from
// that address authenticated. Fails if another peer already has the address.
peers_float :: proc(pt: ^Peer_Table, h: Peer_Handle, new_addr: Addr_Key) -> (old: Addr_Key, err: Peer_Error) {
	p := peers_get(pt, h)
	if p == nil {
		return {}, .Bad_Handle
	}
	new_addr := new_addr
	if other, found := find_addr(pt, &new_addr); found {
		if other == h.index {
			return p.addr, .None
		}
		return p.addr, .Addr_In_Use
	}
	old = p.addr
	hash_index_remove(&pt.by_addr, addr_hash(pt, &p.addr), h.index)
	p.addr = new_addr
	hash_index_insert(&pt.by_addr, addr_hash(pt, &p.addr), h.index)
	return old, .None
}

// ---------------------------------------------------------------------------
// Lookups (no allocation)

// By the id in a P_DATA_V2 header. Unknown, free and reserved ids give nil.
peers_by_id :: #force_inline proc "contextless" (pt: ^Peer_Table, id: u32) -> (h: Peer_Handle, p: ^Peer) {
	if id >= pt.capacity {
		return {}, nil
	}
	p = &pt.peers[id]
	if p.state != .Active {
		return {}, nil
	}
	return Peer_Handle{id, p.gen}, p
}

@(private)
addr_hash :: #force_inline proc "contextless" (pt: ^Peer_Table, a: ^Addr_Key) -> u32 {
	return hash_bytes(a, ADDR_KEY_LEN, pt.seed)
}

@(private)
find_addr :: proc "contextless" (pt: ^Peer_Table, a: ^Addr_Key) -> (idx: u32, found: bool) {
	hi := &pt.by_addr
	key := addr_hash(pt, a)
	#no_bounds_check {
		i := hash_index_home(hi, key)
		for {
			c := hi.cells[i]
			if c.idx == NONE {
				return NONE, false
			}
			if c.key == key && pt.peers[c.idx].addr == a^ {
				return c.idx, true
			}
			i = (i + 1) & hi.mask
		}
	}
}

// By transport address (the packet's source).
peers_by_addr :: proc "contextless" (pt: ^Peer_Table, a: ^Addr_Key) -> (h: Peer_Handle, p: ^Peer) {
	idx, found := find_addr(pt, a)
	if !found {
		return {}, nil
	}
	return handle_of(pt, idx), &pt.peers[idx]
}

@(private)
key4 :: #force_inline proc "contextless" (a: [4]u8) -> u32 {
	return u32(a[0]) << 24 | u32(a[1]) << 16 | u32(a[2]) << 8 | u32(a[3])
}

// By tunnel IPv4 address.
peers_by_vpn4 :: proc "contextless" (pt: ^Peer_Table, a: [4]u8) -> (h: Peer_Handle, p: ^Peer) {
	hi := &pt.by_vpn4
	key := key4(a)
	#no_bounds_check {
		i := hash_index_home(hi, key)
		for {
			c := hi.cells[i]
			if c.idx == NONE {
				return {}, nil
			}
			if c.key == key {
				return handle_of(pt, c.idx), &pt.peers[c.idx]
			}
			i = (i + 1) & hi.mask
		}
	}
}

// By tunnel IPv6 address.
peers_by_vpn6 :: proc "contextless" (pt: ^Peer_Table, a: ^[16]u8) -> (h: Peer_Handle, p: ^Peer) {
	hi := &pt.by_vpn6
	key := hash_bytes(a, 16, pt.seed)
	#no_bounds_check {
		i := hash_index_home(hi, key)
		for {
			c := hi.cells[i]
			if c.idx == NONE {
				return {}, nil
			}
			if c.key == key && pt.peers[c.idx].vpn6 == a^ {
				return handle_of(pt, c.idx), &pt.peers[c.idx]
			}
			i = (i + 1) & hi.mask
		}
	}
}

// The first peer with this identity (the newest), or nil. There may be more (a
// name with several pinned keys, or `duplicate-cn`). Follow with
// `peers_next_same_identity`.
peers_by_identity :: proc(pt: ^Peer_Table, name: string) -> (h: Peer_Handle, p: ^Peer) {
	hi := &pt.by_ident
	key := hash_name(name)
	i := hash_index_home(hi, key)
	for {
		c := hi.cells[i]
		if c.idx == NONE {
			return {}, nil
		}
		if c.key == key && name_equal(pt.peers[c.idx].identity, name) {
			return handle_of(pt, c.idx), &pt.peers[c.idx]
		}
		i = (i + 1) & hi.mask
	}
}

peers_next_same_identity :: proc "contextless" (pt: ^Peer_Table, h: Peer_Handle) -> (next: Peer_Handle, p: ^Peer) {
	cur := peers_get(pt, h)
	if cur == nil || cur.ident_next == NONE {
		return {}, nil
	}
	return handle_of(pt, cur.ident_next), &pt.peers[cur.ident_next]
}

// Collects up to len(out) handles of peers with this identity. Returns the
// number found in total (more than len(out) means some did not fit).
peers_identity_handles :: proc(pt: ^Peer_Table, name: string, out: []Peer_Handle) -> int {
	h, p := peers_by_identity(pt, name)
	n := 0
	for p != nil {
		if n < len(out) {
			out[n] = h
		}
		n += 1
		h, p = peers_next_same_identity(pt, h)
	}
	return n
}

// Walks active peers in id order. Start with `from = 0`; continue with the
// returned index + 1. `ok` is false at the end.
peers_next_active :: proc "contextless" (pt: ^Peer_Table, from: u32) -> (h: Peer_Handle, ok: bool) {
	for i := from; i < pt.next_virgin; i += 1 {
		if pt.peers[i].state == .Active {
			return handle_of(pt, i), true
		}
	}
	return {}, false
}

// ---------------------------------------------------------------------------
// The identity chains

@(private)
ident_link :: proc(pt: ^Peer_Table, idx: u32) {
	p := &pt.peers[idx]
	hi := &pt.by_ident
	key := hash_name(p.identity)
	i := hash_index_home(hi, key)
	for {
		c := &hi.cells[i]
		if c.idx == NONE {
			break
		}
		if c.key == key && name_equal(pt.peers[c.idx].identity, p.identity) {
			// Put the new peer at the head of the chain.
			p.ident_next = c.idx
			c.idx = idx
			return
		}
		i = (i + 1) & hi.mask
	}
	p.ident_next = NONE
	hash_index_insert(hi, key, idx)
}

@(private)
ident_unlink :: proc(pt: ^Peer_Table, idx: u32) {
	p := &pt.peers[idx]
	hi := &pt.by_ident
	key := hash_name(p.identity)
	i := hash_index_home(hi, key)
	for {
		c := &hi.cells[i]
		if c.idx == NONE {
			return
		}
		if c.key == key && name_equal(pt.peers[c.idx].identity, p.identity) {
			if c.idx == idx {
				if p.ident_next == NONE {
					hash_index_remove(hi, key, idx)
				} else {
					c.idx = p.ident_next
				}
			} else {
				prev := c.idx
				for pt.peers[prev].ident_next != idx {
					prev = pt.peers[prev].ident_next
					if prev == NONE {
						return
					}
				}
				pt.peers[prev].ident_next = p.ident_next
			}
			p.ident_next = NONE
			return
		}
		i = (i + 1) & hi.mask
	}
}
