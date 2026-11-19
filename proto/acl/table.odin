// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

import "base:intrinsics"

// The flow table: open addressing with linear probes and backward-shift
// delete (no tombstones). Allocated once; no allocation per packet.
//
// The key is oriented to the client, so both directions give the same key:
//
//	local  = source of an outbound packet = destination of an inbound packet
//	remote = destination of an outbound packet = source of an inbound packet

// Five words, so that the key is written, compared and hashed as words.
Flow_Key :: struct {
	laddr: Addr,
	raddr: Addr,
	// lport | rport << 16 | af << 32 | proto << 40. The top 16 bits are 0.
	meta:  u64,
}
#assert(size_of(Flow_Key) == 40)

key_make :: #force_inline proc "contextless" (af, proto: u8, laddr, raddr: ^Addr, lport, rport: u16) -> (k: Flow_Key) {
	k.laddr = laddr^
	k.raddr = raddr^
	k.meta = u64(lport) | u64(rport) << 16 | u64(af) << 32 | u64(proto) << 40
	return
}

key_proto :: #force_inline proc "contextless" (k: ^Flow_Key) -> u8 {
	return u8(k.meta >> 40)
}

// The ports first: they differ between most flows.
key_equal :: #force_inline proc "contextless" (a, b: ^Flow_Key) -> bool {
	x, y := (^[5]u64)(a), (^[5]u64)(b)
	return x[4] == y[4] && x[3] == y[3] && x[1] == y[1] && x[2] == y[2] && x[0] == y[0]
}

State :: enum u8 {
	Syn,    // TCP: one side seen
	Reply,  // TCP: both sides seen
	Est,    // TCP: the side that started sent again after the reply
	Fin,    // TCP: a FIN was seen
	Closed, // TCP: a RST was seen
	One,    // other protocols: one side seen
	Both,   // other protocols: both sides seen
}

Origin :: enum u8 {
	Out, // the client started it
	In,  // a tunnel peer started it, and a rule let it in
}

Entry :: struct {
	key:    Flow_Key,
	hash:   u32,
	last:   u32, // seconds of the caller's clock
	state:  State,
	origin: Origin,
	used:   bool,
}

Table :: struct {
	slots: []Entry,
	mask:  u32,
	count: int,
	max:   int,
	k0:    u64, // the table key
	k1:    u64,
	rk:    Round_Keys, // made from the table key, for the AES form of the hash
	sweep: u32, // the next slot the sweep looks at
}

// Idle timeouts in seconds, by state. Only `Est` is long: a peer cannot reach
// it with packets of its own, the client has to answer and the peer has to
// send again.
@(rodata)
TIMEOUT := [State]u32 {
	.Syn    = 30,
	.Reply  = 60,
	.Est    = 24 * 3600,
	.Fin    = 120,
	.Closed = 10,
	.One    = 30,
	.Both   = 180,
}

// The order in which a full table gives up flows: a lower class goes first.
CLASS_ENDING :: 1
CLASS_HALF_OPEN :: 2

@(rodata)
EVICT_CLASS := [State]u8 {
	.Syn    = CLASS_HALF_OPEN,
	.Reply  = CLASS_HALF_OPEN,
	.Est    = 4,
	.Fin    = CLASS_ENDING,
	.Closed = CLASS_ENDING,
	.One    = CLASS_HALF_OPEN,
	.Both   = 3,
}

// Slots that a full table looks at to find a flow to replace.
EVICT_SCAN :: 64

// What `table_insert` freed to get room.
Removed :: enum u8 {
	None,
	Expired,
	Evicted, // a flow that was not expired
}

table_init :: proc(t: ^Table, max_flows: int, seed: [16]u8, allocator := context.allocator) {
	n := u32(16)
	for int(n) * 3 < max(max_flows, 1) * 4 {
		n <<= 1
	}
	t.slots = make([]Entry, int(n), allocator)
	t.mask = n - 1
	t.max = max(max_flows, 1)
	t.count = 0
	t.sweep = 0
	t.k0 = transmute(u64)[8]u8{seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7]}
	t.k1 = transmute(u64)[8]u8{seed[8], seed[9], seed[10], seed[11], seed[12], seed[13], seed[14], seed[15]}
	t.rk = round_keys_make(t.k0, t.k1)
}

table_destroy :: proc(t: ^Table, allocator := context.allocator) {
	delete(t.slots, allocator)
	t^ = {}
}

table_clear :: proc "contextless" (t: ^Table) {
	intrinsics.mem_zero(raw_data(t.slots), len(t.slots) * size_of(Entry))
	t.count = 0
}

expired :: #force_inline proc "contextless" (e: ^Entry, now: u32) -> bool {
	return now - e.last > TIMEOUT[e.state]
}

// The slot of `k`, or -1.
table_find :: proc "contextless" (t: ^Table, k: ^Flow_Key, h: u32) -> int {
	i := h & t.mask
	for {
		e := &t.slots[i]
		if !e.used {
			return -1
		}
		if e.hash == h && key_equal(&e.key, k) {
			return int(i)
		}
		i = (i + 1) & t.mask
	}
}

// Adds `k` (not in the table) as a flow that `origin` started. A full table
// first frees one flow near the home slot of `k`:
//
//	an expired flow, else
//	origin Out: the most idle flow of the lowest class
//	origin In:  the most idle half-open flow that a peer started
//
// Returns slot -1 when no flow can go. A peer can then only replace flows of
// peers that are not answered yet, never a flow of the client.
table_insert :: proc "contextless" (t: ^Table, k: ^Flow_Key, h: u32, now: u32, origin: Origin) -> (slot: int, removed: Removed) {
	if t.count >= t.max {
		victim, old := pick_victim(t, h, now, origin)
		if victim < 0 {
			return -1, .None
		}
		table_delete(t, victim)
		removed = .Expired if old else .Evicted
	}
	i := h & t.mask
	for t.slots[i].used {
		i = (i + 1) & t.mask
	}
	t.slots[i] = {
		key    = k^,
		hash   = h,
		last   = now,
		state  = .Syn if key_proto(k) == PROTO_TCP else .One,
		origin = origin,
		used   = true,
	}
	t.count += 1
	return int(i), removed
}

@(private)
pick_victim :: proc "contextless" (t: ^Table, h: u32, now: u32, origin: Origin) -> (slot: int, old: bool) {
	i := h & t.mask
	slot = -1
	best_class := u8(255)
	best_age := u32(0)
	for _ in 0 ..< EVICT_SCAN {
		e := &t.slots[i]
		if e.used {
			if expired(e, now) {
				return int(i), true
			}
			class := EVICT_CLASS[e.state]
			if origin == .Out || (class == CLASS_HALF_OPEN && e.origin == .In) {
				age := now - e.last
				if class < best_class || (class == best_class && age > best_age) {
					slot, best_class, best_age = int(i), class, age
				}
			}
		}
		i = (i + 1) & t.mask
	}
	return slot, false
}

// Frees slot `i` and moves the next entries of the run back, so that every
// entry stays reachable from its home slot.
table_delete :: proc "contextless" (t: ^Table, slot: int) {
	i := u32(slot)
	j := i
	for {
		j = (j + 1) & t.mask
		e := &t.slots[j]
		if !e.used {
			break
		}
		home := e.hash & t.mask
		// The entry at `j` stays if its home is cyclically in (i, j].
		stays := (home > i && home <= j) if i <= j else (home > i || home <= j)
		if stays {
			continue
		}
		t.slots[i] = e^
		i = j
	}
	t.slots[i] = {}
	t.count -= 1
}

// Frees expired flows in the next `budget` slots. Returns the number freed.
table_sweep :: proc "contextless" (t: ^Table, now: u32, budget: int) -> (freed: int) {
	i := t.sweep
	for _ in 0 ..< min(budget, len(t.slots)) {
		e := &t.slots[i]
		if e.used && expired(e, now) {
			table_delete(t, int(i))
			freed += 1
			// The delete can move a later entry into this slot: look again.
			if t.slots[i].used {
				continue
			}
		}
		i = (i + 1) & t.mask
	}
	t.sweep = i
	return
}
