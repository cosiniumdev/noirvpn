// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:mem"
import "core:time"

// Connection rate limits (`connect-freq`, `connect-freq-initial`).
// Token bucket per source, one number per source ("theoretical arrival time"):
//   - `count` attempts at once; refills at `count` per `seconds`.
//   - Bounded memory: fixed number of sources. When full, the source seen longest
//     ago is forgotten and starts with a full bucket (the price of the bound; the
//     optional global limit still caps the total).
//   - Source = `rate_key`: a whole IPv4 address, or an IPv6 /64.
// SPEC-GAP: stock `connect-freq` is one global limit. Here it is per source
// address (one noisy source cannot lock out others). The daemon can also set the
// global bucket (`Rate_Limiter.global`) for the stock behavior.
// `now` is any monotonic clock. Single thread.

Rate_Params :: struct {
	// Attempts per window. 0 = no limit.
	count:   int,
	seconds: int,
}

// Entries are kept on a doubly linked list in order of last use.
@(private)
Rate_Entry :: struct {
	key:  [16]u8,
	// The earliest time the bucket is empty again.
	tat:  i64,
	prev: u32,
	next: u32,
}

Rate_Limiter :: struct {
	per_source:  Rate_Params,
	global:      Rate_Params,
	// Nanoseconds per attempt and the size of the bucket in nanoseconds.
	src_t:       i64,
	src_tau:     i64,
	glob_t:      i64,
	glob_tau:    i64,
	glob_tat:    i64,
	entries:     []Rate_Entry,
	used:        u32,
	// Most recently used first.
	head:        u32,
	tail:        u32,
	index:       Hash_Index,
	seed:        u64,
	evictions:   u64,
	allocator:   mem.Allocator,
}

DEFAULT_RATE_SOURCES :: 4096

// `capacity` is the number of sources remembered at most.
rate_limiter_init :: proc(
	rl: ^Rate_Limiter,
	per_source: Rate_Params,
	global: Rate_Params = {},
	capacity := DEFAULT_RATE_SOURCES,
	seed: u64 = 0,
	allocator := context.allocator,
) -> bool {
	rl^ = {}
	if capacity < 1 || per_source.count < 0 || global.count < 0 || per_source.seconds < 0 || global.seconds < 0 {
		return false
	}
	if (per_source.count > 0 && per_source.seconds == 0) || (global.count > 0 && global.seconds == 0) {
		return false
	}
	rl.allocator = allocator
	rl.per_source, rl.global = per_source, global
	rl.seed = seed
	if per_source.count > 0 {
		rl.src_tau = i64(per_source.seconds) * i64(time.Second)
		rl.src_t = max(rl.src_tau / i64(per_source.count), 1)
	}
	if global.count > 0 {
		rl.glob_tau = i64(global.seconds) * i64(time.Second)
		rl.glob_t = max(rl.glob_tau / i64(global.count), 1)
	}
	e, err := make([]Rate_Entry, capacity, allocator)
	if err != nil {
		return false
	}
	rl.entries = e
	if !hash_index_init(&rl.index, capacity, allocator) {
		delete(e, allocator)
		rl^ = {}
		return false
	}
	rl.head, rl.tail = NONE, NONE
	return true
}

rate_limiter_destroy :: proc(rl: ^Rate_Limiter) {
	delete(rl.entries, rl.allocator)
	hash_index_destroy(&rl.index, rl.allocator)
	rl^ = {}
}

// Sources currently remembered. Never more than the capacity.
rate_limiter_sources :: proc "contextless" (rl: ^Rate_Limiter) -> int {
	return int(rl.used)
}

rate_limiter_memory :: proc(rl: ^Rate_Limiter) -> int {
	return len(rl.entries) * size_of(Rate_Entry) + len(rl.index.cells) * size_of(Cell)
}

@(private)
rl_hash :: proc "contextless" (rl: ^Rate_Limiter, key: ^[16]u8) -> u32 {
	return hash_bytes(key, 16, rl.seed)
}

@(private)
rl_unlink :: proc "contextless" (rl: ^Rate_Limiter, i: u32) {
	e := &rl.entries[i]
	if e.prev != NONE {
		rl.entries[e.prev].next = e.next
	} else {
		rl.head = e.next
	}
	if e.next != NONE {
		rl.entries[e.next].prev = e.prev
	} else {
		rl.tail = e.prev
	}
}

@(private)
rl_push_front :: proc "contextless" (rl: ^Rate_Limiter, i: u32) {
	e := &rl.entries[i]
	e.prev = NONE
	e.next = rl.head
	if rl.head != NONE {
		rl.entries[rl.head].prev = i
	}
	rl.head = i
	if rl.tail == NONE {
		rl.tail = i
	}
}

// Takes one attempt from the global bucket and the bucket of `key`. Returns
// false when either is empty. A refused attempt takes nothing.
rate_limiter_allow :: proc(rl: ^Rate_Limiter, key: [16]u8, now: time.Duration) -> bool {
	t := i64(now)
	// The global bucket is only charged if the source bucket allows it too, so
	// work out both and then commit.
	new_glob := rl.glob_tat
	if rl.global.count > 0 {
		new_glob = max(rl.glob_tat, t) + rl.glob_t
		if new_glob - t > rl.glob_tau {
			return false
		}
	}
	if rl.per_source.count == 0 {
		rl.glob_tat = new_glob
		return true
	}
	key := key
	h := rl_hash(rl, &key)
	i := hash_index_home(&rl.index, h)
	found := NONE
	for {
		c := rl.index.cells[i]
		if c.idx == NONE {
			break
		}
		if c.key == h && rl.entries[c.idx].key == key {
			found = c.idx
			break
		}
		i = (i + 1) & rl.index.mask
	}
	if found == NONE {
		// A new source starts with a full bucket: this attempt is allowed.
		slot: u32
		if int(rl.used) < len(rl.entries) {
			slot = rl.used
			rl.used += 1
		} else {
			slot = rl.tail
			ev := &rl.entries[slot]
			hash_index_remove(&rl.index, rl_hash(rl, &ev.key), slot)
			rl_unlink(rl, slot)
			rl.evictions += 1
		}
		rl.entries[slot] = Rate_Entry {
			key  = key,
			tat  = t + rl.src_t,
			prev = NONE,
			next = NONE,
		}
		hash_index_insert(&rl.index, h, slot)
		rl_push_front(rl, slot)
		rl.glob_tat = new_glob
		return true
	}
	e := &rl.entries[found]
	new_tat := max(e.tat, t) + rl.src_t
	// Touch the entry even when it is refused, so a flood keeps its own entry
	// alive instead of pushing others out.
	if found != rl.head {
		rl_unlink(rl, found)
		rl_push_front(rl, found)
	}
	if new_tat - t > rl.src_tau {
		return false
	}
	e.tat = new_tat
	rl.glob_tat = new_glob
	return true
}
