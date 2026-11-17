// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "base:intrinsics"
import "core:mem"
import "core:strings"
import "core:time"
import "noir:proto/config"

// Address pools. A `Pool` is a range of consecutive addresses (IPv4 or IPv6, as
// 128-bit numbers) cut into slots: Free, Used (a client has it) or Released
// (client left; the slot remembers its name).
//
// Allocation for a name `X`, first match wins:
//   1. The slot that remembered `X`, if still Released (sticky address).
//   2. The `hint` slot, if never used (keeps the IPv6 slot equal to the IPv4
//      slot, as stock servers do).
//   3. The lowest never-used slot (a bitmap tree: 3 or 4 steps).
//   4. The oldest Released slot whose hold time is over; its old name is
//      forgotten. Slots are released in time order, so this is a queue head.
//
// All O(1) or O(log64 n). After init, only one name string per used slot is
// allocated. A name is remembered by one slot (the first it got). A second
// session of the same name (`duplicate-cn`) gets another slot, forgotten on
// release.
// Static addresses (`ifconfig-push`) are reserved slots, never returned by
// dynamic allocation. Rule for both families: `pools_acquire`.

// Most slots one pool keeps. A larger range is cut to its first addresses.
// SPEC-GAP: the stock pool is limited only by the address range. We cap the
// number of slots (memory is 56 bytes per slot and family) and shrink a larger
// range to its first POOL_MAX_SLOTS addresses.
POOL_MAX_SLOTS :: 1 << 18

Slot_State :: enum u8 {
	Free,
	Used,
	Released,
}

Slot_Flag :: enum u8 {
	// Reserved for a static address from the peers file (cleared on reload).
	Reserved_Pin,
	// Reserved for a static address seen in a client-config-dir file.
	Reserved_Lazy,
	// Never handed out: network, broadcast and server address.
	Reserved_Sys,
	// The client that uses the slot got it as a static address.
	Static,
}

Slot_Flags :: bit_set[Slot_Flag;u8]

RESERVED_ANY :: Slot_Flags{.Reserved_Pin, .Reserved_Lazy, .Reserved_Sys}

Pool_Slot :: struct {
	name:        string,
	released_at: i64,
	// Queue links while Released.
	prev:        u32,
	next:        u32,
	state:       Slot_State,
	flags:       Slot_Flags,
}

Pool :: struct {
	base:      u128,
	count:     u32,
	slots:     []Pool_Slot,
	// Slots that are Free and not reserved ("virgin").
	virgin:    Bit_Tree,
	// name -> slot that remembers it.
	by_name:   Hash_Index,
	// Released slots, oldest first.
	q_head:    u32,
	q_tail:    u32,
	q_len:     u32,
	hold:      time.Duration,
	used:      u32,
	allocator: mem.Allocator,
}

pool_init :: proc(p: ^Pool, base: u128, count: u32, hold: time.Duration, allocator: mem.Allocator) -> bool {
	p^ = {}
	if count == 0 || count > POOL_MAX_SLOTS {
		return false
	}
	slots, err := make([]Pool_Slot, count, allocator)
	if err != nil {
		return false
	}
	for &s in slots {
		s.prev, s.next = NONE, NONE
	}
	p.allocator = allocator
	p.base = base
	p.count = count
	p.slots = slots
	p.hold = hold
	p.q_head, p.q_tail = NONE, NONE
	if !bit_tree_init(&p.virgin, int(count), allocator) || !hash_index_init(&p.by_name, int(count), allocator) {
		pool_destroy(p)
		return false
	}
	bit_tree_fill(&p.virgin)
	return true
}

pool_destroy :: proc(p: ^Pool) {
	for &s in p.slots {
		if len(s.name) > 0 {
			delete(s.name, p.allocator)
		}
	}
	delete(p.slots, p.allocator)
	bit_tree_destroy(&p.virgin, p.allocator)
	hash_index_destroy(&p.by_name, p.allocator)
	p^ = {}
}

pool_memory :: proc(p: ^Pool) -> int {
	n := len(p.slots) * size_of(Pool_Slot) + len(p.by_name.cells) * size_of(Cell)
	for l in p.virgin.levels {
		n += len(l) * size_of(u64)
	}
	return n
}

// Slots in use / remembered after a client left / never used and not reserved.
pool_used :: proc "contextless" (p: ^Pool) -> int {
	return int(p.used)
}

pool_remembered :: proc "contextless" (p: ^Pool) -> int {
	return int(p.q_len)
}

pool_virgin :: proc "contextless" (p: ^Pool) -> int {
	return bit_tree_count(&p.virgin)
}

// The slot of an address, if it lies in the range.
pool_slot_of :: proc "contextless" (p: ^Pool, addr: u128) -> (slot: u32, ok: bool) {
	if addr < p.base || addr - p.base >= u128(p.count) {
		return NONE, false
	}
	return u32(addr - p.base), true
}

pool_addr :: #force_inline proc "contextless" (p: ^Pool, slot: u32) -> u128 {
	return p.base + u128(slot)
}

@(private)
name_hash :: proc "contextless" (name: string) -> u32 {
	return hash_name(name)
}

// The slot that remembers `name` (Used or Released), or NONE.
@(private)
by_name_find :: proc(p: ^Pool, name: string) -> u32 {
	hi := &p.by_name
	key := name_hash(name)
	i := hash_index_home(hi, key)
	for {
		c := hi.cells[i]
		if c.idx == NONE {
			return NONE
		}
		if c.key == key && name_equal(p.slots[c.idx].name, name) {
			return c.idx
		}
		i = (i + 1) & hi.mask
	}
}

@(private)
q_push :: proc(p: ^Pool, i: u32, now: i64) {
	s := &p.slots[i]
	s.released_at = now
	s.prev = p.q_tail
	s.next = NONE
	if p.q_tail != NONE {
		p.slots[p.q_tail].next = i
	} else {
		p.q_head = i
	}
	p.q_tail = i
	p.q_len += 1
}

@(private)
q_unlink :: proc(p: ^Pool, i: u32) {
	s := &p.slots[i]
	if s.prev != NONE {
		p.slots[s.prev].next = s.next
	} else {
		p.q_head = s.next
	}
	if s.next != NONE {
		p.slots[s.next].prev = s.prev
	} else {
		p.q_tail = s.prev
	}
	s.prev, s.next = NONE, NONE
	p.q_len -= 1
}

// Forgets a slot's name and sets it Free (virgin unless reserved).
@(private)
slot_forget :: proc(p: ^Pool, i: u32) {
	s := &p.slots[i]
	if s.state == .Released {
		q_unlink(p, i)
	}
	if len(s.name) > 0 {
		hash_index_remove(&p.by_name, name_hash(s.name), i)
		delete(s.name, p.allocator)
		s.name = ""
	}
	s.state = .Free
	s.flags -= {.Static}
	if s.flags & RESERVED_ANY == {} {
		bit_tree_set(&p.virgin, int(i))
	}
}

// Marks slot `i` as Used by `name`. The slot must not be Used. `remember`
// says whether the name should point at this slot.
@(private)
slot_take :: proc(p: ^Pool, i: u32, name: string, remember: bool, static: bool) -> bool {
	s := &p.slots[i]
	if s.state == .Released {
		if name_equal(s.name, name) {
			// Sticky hit: keep the name and its map entry.
			q_unlink(p, i)
			s.state = .Used
			p.used += 1
			if static {
				s.flags += {.Static}
			}
			return true
		}
		// Another name had it: forget that name (this also leaves the queue).
		slot_forget(p, i)
	}
	copy_name, err := strings.clone(name, p.allocator)
	if err != nil {
		// Leave the slot as it is (Free after the forget above).
		return false
	}
	bit_tree_clear(&p.virgin, int(i))
	s.name = copy_name
	s.state = .Used
	if static {
		s.flags += {.Static}
	}
	if remember {
		hash_index_insert(&p.by_name, name_hash(name), i)
	}
	p.used += 1
	return true
}

// Takes a slot for `name`. See the order at the top of the file. `hint` is a
// slot to try before the lowest free one (NONE = none).
pool_alloc :: proc(p: ^Pool, name: string, now: time.Duration, hint: u32 = NONE) -> (slot: u32, ok: bool) {
	known := by_name_find(p, name)
	// Does the name already point at a slot (Used by another session of the
	// same name, or Released)?
	if known != NONE && p.slots[known].state == .Released && p.slots[known].flags & RESERVED_ANY == {} {
		if slot_take(p, known, name, true, false) {
			return known, true
		}
		return NONE, false
	}
	i := NONE
	switch {
	case hint < p.count && bit_tree_test(&p.virgin, int(hint)):
		i = hint
	case:
		first, found := bit_tree_first(&p.virgin)
		if found {
			i = u32(first)
		}
	}
	if i == NONE && p.q_head != NONE {
		h := &p.slots[p.q_head]
		if i64(now) - h.released_at >= i64(p.hold) {
			i = p.q_head
		}
	}
	if i == NONE {
		return NONE, false
	}
	// Only the first slot a name gets is remembered under that name.
	if !slot_take(p, i, name, known == NONE, false) {
		return NONE, false
	}
	return i, true
}

// A client left. The slot remembers its name for the next connect (unless it
// is a static slot, or a second session's slot that the name does not point at).
pool_release :: proc(p: ^Pool, slot: u32, now: time.Duration) {
	if slot >= p.count || p.slots[slot].state != .Used {
		return
	}
	s := &p.slots[slot]
	p.used -= 1
	if .Static not_in s.flags && by_name_find(p, s.name) == slot {
		s.state = .Released
		q_push(p, slot, i64(now))
		return
	}
	s.state = .Used // slot_forget handles a Used slot as a plain free
	slot_forget(p, slot)
}

// Reserves a slot for a static address. `why` is `.Reserved_Pin` or
// `.Reserved_Lazy`. Fails if a dynamic client holds the slot.
pool_reserve :: proc(p: ^Pool, slot: u32, why: Slot_Flag) -> bool {
	if slot >= p.count {
		return false
	}
	s := &p.slots[slot]
	if s.state == .Used && .Static not_in s.flags {
		return false
	}
	if s.state == .Released {
		slot_forget(p, slot)
	}
	s.flags += {why}
	bit_tree_clear(&p.virgin, int(slot))
	return true
}

// Drops reservations created with `why`. Free slots become allocatable again.
pool_unreserve_all :: proc(p: ^Pool, why: Slot_Flag) {
	for &s, i in p.slots {
		if why in s.flags {
			s.flags -= {why}
			if s.state == .Free && s.flags & RESERVED_ANY == {} {
				bit_tree_set(&p.virgin, i)
			}
		}
	}
}

// Takes a reserved slot for a static client. Fails if it is in use.
pool_take_static :: proc(p: ^Pool, slot: u32, name: string) -> bool {
	if slot >= p.count || p.slots[slot].state == .Used {
		return false
	}
	return slot_take(p, slot, name, false, true)
}

// Loads one remembered (name, slot) pair, as from the persist file. The slot
// must be free and not reserved, and the name unused in this pool.
pool_remember :: proc(p: ^Pool, slot: u32, name: string, now: time.Duration) -> bool {
	if slot >= p.count || !bit_tree_test(&p.virgin, int(slot)) || by_name_find(p, name) != NONE {
		return false
	}
	copy_name, err := strings.clone(name, p.allocator)
	if err != nil {
		return false
	}
	s := &p.slots[slot]
	bit_tree_clear(&p.virgin, int(slot))
	s.name = copy_name
	s.state = .Released
	hash_index_insert(&p.by_name, name_hash(name), slot)
	// Old, so a loaded address can be taken over first when the pool is full;
	// never older than the queue's tail, so the queue stays in time order.
	t := i64(now) - i64(p.hold)
	if p.q_tail != NONE {
		t = max(t, p.slots[p.q_tail].released_at)
	}
	q_push(p, slot, t)
	return true
}

// ---------------------------------------------------------------------------
// A tree of bit sets: finds the lowest set bit in at most 4 steps.

Bit_Tree :: struct {
	// levels[0] has one bit per item; levels[k+1] has one bit per word of
	// levels[k] that is not zero.
	levels: [5][]u64,
	n:      int,
	depth:  int,
}

bit_tree_init :: proc(b: ^Bit_Tree, n: int, allocator: mem.Allocator) -> bool {
	b^ = {}
	b.n = n
	size := n
	for {
		words := (size + 63) / 64
		l, err := make([]u64, words, allocator)
		if err != nil {
			bit_tree_destroy(b, allocator)
			return false
		}
		b.levels[b.depth] = l
		b.depth += 1
		if words == 1 {
			break
		}
		if b.depth == len(b.levels) {
			bit_tree_destroy(b, allocator)
			return false
		}
		size = words
	}
	return true
}

bit_tree_destroy :: proc(b: ^Bit_Tree, allocator: mem.Allocator) {
	for l in b.levels {
		delete(l, allocator)
	}
	b^ = {}
}

// Sets every item.
bit_tree_fill :: proc(b: ^Bit_Tree) {
	size := b.n
	for d in 0 ..< b.depth {
		l := b.levels[d]
		for &w in l {
			w = ~u64(0)
		}
		if size % 64 != 0 {
			l[len(l) - 1] = (u64(1) << u64(size % 64)) - 1
		}
		size = len(l)
	}
}

bit_tree_set :: proc "contextless" (b: ^Bit_Tree, i: int) {
	i := i
	for d in 0 ..< b.depth {
		w := &b.levels[d][i >> 6]
		was := w^
		w^ |= u64(1) << u64(i & 63)
		if was != 0 {
			return
		}
		i >>= 6
	}
}

bit_tree_clear :: proc "contextless" (b: ^Bit_Tree, i: int) {
	i := i
	for d in 0 ..< b.depth {
		w := &b.levels[d][i >> 6]
		w^ &= ~(u64(1) << u64(i & 63))
		if w^ != 0 {
			return
		}
		i >>= 6
	}
}

bit_tree_test :: proc "contextless" (b: ^Bit_Tree, i: int) -> bool {
	if i < 0 || i >= b.n {
		return false
	}
	return b.levels[0][i >> 6] & (u64(1) << u64(i & 63)) != 0
}

// The lowest set item.
bit_tree_first :: proc "contextless" (b: ^Bit_Tree) -> (i: int, ok: bool) {
	top := b.levels[b.depth - 1][0]
	if top == 0 {
		return 0, false
	}
	i = int(intrinsics.count_trailing_zeros(top))
	for d := b.depth - 2; d >= 0; d -= 1 {
		i = i * 64 + int(intrinsics.count_trailing_zeros(b.levels[d][i]))
	}
	return i, true
}

bit_tree_count :: proc "contextless" (b: ^Bit_Tree) -> (n: int) {
	for w in b.levels[0] {
		n += int(intrinsics.count_ones(w))
	}
	return
}

// ---------------------------------------------------------------------------
// Both families together

// What a client got. `slot4` and `slot6` are for `pools_release`.
Lease_Kind :: enum u8 {
	None,
	Dynamic,
	// A static address inside the dynamic range (a reserved slot).
	Static_In_Range,
	// A static address outside the dynamic range.
	Static_Outside,
}

Lease :: struct {
	kind4: Lease_Kind,
	kind6: Lease_Kind,
	addr4: [4]u8,
	addr6: [16]u8,
	slot4: u32,
	slot6: u32,
}

Pools :: struct {
	// The server network (from `server`), always set.
	net4:        config.Server_Net,
	net6:        Maybe(config.Server_Net6),
	// Dynamic pools; has4 / has6 say whether they exist.
	v4:          Pool,
	v6:          Pool,
	has4:        bool,
	has6:        bool,
	// Static addresses in use that lie outside the dynamic ranges.
	static4:     map[u32]struct{},
	static6:     map[[16]u8]struct{},
	allocator:   mem.Allocator,
	// Set when a lease changed what the persist file would hold.
	persist_dirty: bool,
}

u128_from_v6 :: proc "contextless" (a: [16]u8) -> (v: u128) {
	for b in a {
		v = v << 8 | u128(b)
	}
	return
}

u128_to_v6 :: proc "contextless" (v: u128) -> (a: [16]u8) {
	x := v
	for i := 15; i >= 0; i -= 1 {
		a[i] = u8(x)
		x >>= 8
	}
	return
}

// Builds the pools from a server config. `hold` is how long a released
// address is kept for its old client when the pool is otherwise full.
pools_init :: proc(
	ps: ^Pools,
	cfg: ^config.Server_Config,
	hold: time.Duration = 0,
	max_slots: int = POOL_MAX_SLOTS,
	allocator := context.allocator,
) -> bool {
	ps^ = {}
	ps.allocator = allocator
	ps.net4 = cfg.net
	ps.net6 = cfg.net6
	limit := clamp(max_slots, 1, POOL_MAX_SLOTS)
	ps.static4 = make(map[u32]struct{}, allocator)
	ps.static6 = make(map[[16]u8]struct{}, allocator)
	count4 := u32(0)
	if p4, ok := cfg.pool.?; ok {
		lo, hi := config.ipv4_to_u32(p4.start), config.ipv4_to_u32(p4.end)
		if hi >= lo {
			n := u64(hi) - u64(lo) + 1
			count4 = u32(min(n, u64(limit)))
			if !pool_init(&ps.v4, u128(lo), count4, hold, allocator) {
				pools_destroy(ps)
				return false
			}
			ps.has4 = true
			// Network, broadcast and the server's own address are never leased.
			net := config.ipv4_to_u32(cfg.net.network)
			bcast := net | ~config.ipv4_to_u32(cfg.net.netmask)
			srv := config.ipv4_to_u32(cfg.net.server_addr)
			for a in ([3]u32{net, bcast, srv}) {
				if slot, in_range := pool_slot_of(&ps.v4, u128(a)); in_range {
					pool_reserve(&ps.v4, slot, .Reserved_Sys)
				}
			}
		}
	}
	if n6, ok := cfg.net6.?; ok {
		base := n6.pool_base
		if p6, set := cfg.pool6.?; set {
			base = p6
		}
		prefix_start := u128_from_v6(n6.prefix)
		// Zero the host part, in case the config kept the server address.
		host_bits := u32(128 - n6.bits)
		prefix_start = (prefix_start >> host_bits) << host_bits
		prefix_end := prefix_start | ((u128(1) << host_bits) - 1)
		b := u128_from_v6(base)
		// The pool does not start on the server's own address, so that IPv4
		// slot i and IPv6 slot i pair up (10.8.0.2 and fd00:8::2).
		if b == u128_from_v6(n6.server_addr) {
			b += 1
		}
		if b >= prefix_start && b <= prefix_end {
			room := prefix_end - b + 1
			count6 := u32(min(room, u128(limit)))
			if ps.has4 {
				count6 = min(count6, count4)
			}
			if count6 > 0 {
				if !pool_init(&ps.v6, b, count6, hold, allocator) {
					pools_destroy(ps)
					return false
				}
				ps.has6 = true
				if slot, in_range := pool_slot_of(&ps.v6, u128_from_v6(n6.server_addr)); in_range {
					pool_reserve(&ps.v6, slot, .Reserved_Sys)
				}
			}
		}
	}
	return true
}

pools_destroy :: proc(ps: ^Pools) {
	if ps.has4 {
		pool_destroy(&ps.v4)
	}
	if ps.has6 {
		pool_destroy(&ps.v6)
	}
	delete(ps.static4)
	delete(ps.static6)
	ps^ = {}
}

pools_memory :: proc(ps: ^Pools) -> int {
	n := 0
	if ps.has4 {
		n += pool_memory(&ps.v4)
	}
	if ps.has6 {
		n += pool_memory(&ps.v6)
	}
	return n
}

// Why a static address is not usable (`.None` = fine).
Static_Problem :: enum u8 {
	None,
	// Outside the server network or prefix.
	Outside_Network,
	// The network address, the broadcast address or the server's own address.
	Reserved_Address,
	// IPv6 given but the server has no `server-ipv6`.
	No_Family,
}

// Rule for a static IPv4 address (`ifconfig-push`):
//   - Inside the server network; not the network address, broadcast address or
//     server address.
//   - May lie in the dynamic range: the slot is reserved, so dynamic clients
//     never get it.
//   - If a dynamic client holds it now, the static client is refused
//     (`Address_In_Use`).
pools_check_static4 :: proc(ps: ^Pools, a: [4]u8) -> Static_Problem {
	v := config.ipv4_to_u32(a)
	mask := config.ipv4_to_u32(ps.net4.netmask)
	net := config.ipv4_to_u32(ps.net4.network)
	if v & mask != net {
		return .Outside_Network
	}
	if v == net || v == net | ~mask || a == ps.net4.server_addr {
		return .Reserved_Address
	}
	return .None
}

// The rule for a static IPv6 address: inside the `server-ipv6` prefix, not the
// server's address, not the all-zero host (the subnet-router anycast address).
pools_check_static6 :: proc(ps: ^Pools, a: [16]u8) -> Static_Problem {
	n6, ok := ps.net6.?
	if !ok {
		return .No_Family
	}
	bits := int(n6.bits)
	for i in 0 ..< 16 {
		keep := clamp(bits - 8 * i, 0, 8)
		m := u8(0xff) << u8(8 - keep) if keep < 8 else u8(0xff)
		if a[i] & m != n6.prefix[i] & m {
			return .Outside_Network
		}
	}
	if a == n6.server_addr || config.ipv6_host_part_is_zero(a, bits) {
		return .Reserved_Address
	}
	return .None
}

// Reserves the static addresses of the peers file, so dynamic clients never
// get them. Call it after loading and after every reload of the file, with the
// old reservations dropped first (`pools_unreserve_all(ps, .Reserved_Pin)`).
// Addresses that fail the static rules are skipped.
pools_reserve_static :: proc(ps: ^Pools, a4: Maybe([4]u8), a6: Maybe([16]u8), why: Slot_Flag = .Reserved_Pin) {
	if a, ok := a4.?; ok && ps.has4 && pools_check_static4(ps, a) == .None {
		if slot, in_range := pool_slot_of(&ps.v4, u128(config.ipv4_to_u32(a))); in_range {
			pool_reserve(&ps.v4, slot, why)
		}
	}
	if a, ok := a6.?; ok && ps.has6 && pools_check_static6(ps, a) == .None {
		if slot, in_range := pool_slot_of(&ps.v6, u128_from_v6(a)); in_range {
			pool_reserve(&ps.v6, slot, why)
		}
	}
}

pools_unreserve_all :: proc(ps: ^Pools, why: Slot_Flag) {
	if ps.has4 {
		pool_unreserve_all(&ps.v4, why)
	}
	if ps.has6 {
		pool_unreserve_all(&ps.v6, why)
	}
}

// The name of the session that holds a static address, or "" (the address is free,
// held with no name, or outside the pool).
pools_static_holder :: proc(ps: ^Pools, a4: Maybe([4]u8), a6: Maybe([16]u8)) -> string {
	if a, ok := a4.?; ok && ps.has4 {
		if slot, in_range := pool_slot_of(&ps.v4, u128(config.ipv4_to_u32(a))); in_range && ps.v4.slots[slot].state == .Used {
			return ps.v4.slots[slot].name
		}
	}
	if a, ok := a6.?; ok && ps.has6 {
		if slot, in_range := pool_slot_of(&ps.v6, u128_from_v6(a)); in_range && ps.v6.slots[slot].state == .Used {
			return ps.v6.slots[slot].name
		}
	}
	return ""
}

Acquire_Error :: enum u8 {
	None,
	Bad_Static_Address,
	Address_In_Use,
	// No free dynamic address.
	Pool_Exhausted,
	// No static address and no dynamic pool for the family the server has.
	No_Address,
}

// Gives a client its addresses. `static4` / `static6` come from `ifconfig-push`
// and `ifconfig-ipv6-push`. Without them, the dynamic pools are used. A client
// always gets an IPv4 address, and an IPv6 address if the server has
// `server-ipv6`. On error nothing is held.
pools_acquire :: proc(
	ps: ^Pools,
	name: string,
	static4: Maybe([4]u8),
	static6: Maybe([16]u8),
	now: time.Duration,
) -> (
	l: Lease,
	err: Acquire_Error,
) {
	// A bad static IPv6 address is refused before anything is taken, so the
	// refusal leaves no trace in the IPv4 pool.
	if a6, ok := static6.?; ok && pools_check_static6(ps, a6) != .None {
		return {}, .Bad_Static_Address
	}
	// IPv4.
	if a, ok := static4.?; ok {
		switch pools_check_static4(ps, a) {
		case .None:
		case .Outside_Network, .Reserved_Address, .No_Family:
			return {}, .Bad_Static_Address
		}
		l.addr4 = a
		v := config.ipv4_to_u32(a)
		slot, in_range := NONE, false
		if ps.has4 {
			slot, in_range = pool_slot_of(&ps.v4, u128(v))
		}
		if in_range {
			if !pool_reserve(&ps.v4, slot, .Reserved_Lazy) || !pool_take_static(&ps.v4, slot, name) {
				return {}, .Address_In_Use
			}
			l.kind4, l.slot4 = .Static_In_Range, slot
		} else {
			if v in ps.static4 {
				return {}, .Address_In_Use
			}
			ps.static4[v] = {}
			l.kind4, l.slot4 = .Static_Outside, NONE
		}
	} else if ps.has4 {
		slot, got := pool_alloc(&ps.v4, name, now)
		if !got {
			return {}, .Pool_Exhausted
		}
		l.kind4, l.slot4 = .Dynamic, slot
		l.addr4 = config.ipv4_from_u32(u32(pool_addr(&ps.v4, slot)))
	} else {
		return {}, .No_Address
	}

	// IPv6.
	if _, has_net6 := ps.net6.?; has_net6 {
		if a, ok := static6.?; ok {
			if pools_check_static6(ps, a) != .None {
				pools_release(ps, l, now)
				return {}, .Bad_Static_Address
			}
			l.addr6 = a
			slot, in_range := NONE, false
			if ps.has6 {
				slot, in_range = pool_slot_of(&ps.v6, u128_from_v6(a))
			}
			if in_range {
				if !pool_reserve(&ps.v6, slot, .Reserved_Lazy) || !pool_take_static(&ps.v6, slot, name) {
					pools_release(ps, l, now)
					return {}, .Address_In_Use
				}
				l.kind6, l.slot6 = .Static_In_Range, slot
			} else {
				if a in ps.static6 {
					pools_release(ps, l, now)
					return {}, .Address_In_Use
				}
				ps.static6[a] = {}
				l.kind6, l.slot6 = .Static_Outside, NONE
			}
		} else if ps.has6 {
			hint := l.slot4 if l.kind4 == .Dynamic else NONE
			slot, got := pool_alloc(&ps.v6, name, now, hint)
			if !got {
				pools_release(ps, l, now)
				return {}, .Pool_Exhausted
			}
			l.kind6, l.slot6 = .Dynamic, slot
			l.addr6 = u128_to_v6(pool_addr(&ps.v6, slot))
		}
		// else: server-ipv6 without a pool (nothing fits): no IPv6 for this client.
	} else if _, ok := static6.?; ok {
		pools_release(ps, l, now)
		return {}, .Bad_Static_Address
	}
	ps.persist_dirty = true
	return l, .None
}

// Returns a lease. Dynamic slots remember their client for the next connect.
pools_release :: proc(ps: ^Pools, l: Lease, now: time.Duration) {
	switch l.kind4 {
	case .None:
	case .Dynamic, .Static_In_Range:
		pool_release(&ps.v4, l.slot4, now)
	case .Static_Outside:
		delete_key(&ps.static4, config.ipv4_to_u32(l.addr4))
	}
	switch l.kind6 {
	case .None:
	case .Dynamic, .Static_In_Range:
		pool_release(&ps.v6, l.slot6, now)
	case .Static_Outside:
		delete_key(&ps.static6, l.addr6)
	}
	ps.persist_dirty = true
}
