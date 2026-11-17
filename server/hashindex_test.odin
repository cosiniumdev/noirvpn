// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"

find_in :: proc(h: ^Hash_Index, key: u32) -> (idx: u32, ok: bool) {
	i := hash_index_home(h, key)
	for {
		c := h.cells[i]
		if c.idx == NONE {
			return NONE, false
		}
		if c.key == key {
			return c.idx, true
		}
		i = (i + 1) & h.mask
	}
}

// Random inserts and removes against a model, with keys from a small range so
// clusters and backward shifts happen all the time.
@(test)
test_hash_index_model :: proc(t: ^testing.T) {
	for seed in u64(1) ..= 8 {
		r := rng_make(seed)
		h: Hash_Index
		testing.expect(t, hash_index_init(&h, 200, context.allocator))
		defer hash_index_destroy(&h, context.allocator)
		model := make(map[u32]u32)
		defer delete(model)
		for step in 0 ..< 20000 {
			key := u32(rng_below(&r, 300))
			if key in model {
				if rng_below(&r, 2) == 0 {
					ok := hash_index_remove(&h, key, model[key])
					testing.expect(t, ok)
					delete_key(&model, key)
				}
			} else if len(model) < 200 {
				idx := u32(rng_below(&r, 1000))
				hash_index_insert(&h, key, idx)
				model[key] = idx
			}
			if step % 97 == 0 {
				testing.expect_value(t, int(h.count), len(model))
				for k in 0 ..< u32(300) {
					idx, found := find_in(&h, k)
					want, in_model := model[k]
					testing.expect_value(t, found, in_model)
					if in_model {
						testing.expect_value(t, idx, want)
					}
				}
			}
		}
		// Removing something that is not there is a no-op.
		testing.expect(t, !hash_index_remove(&h, 5000, 1))
	}
}

@(test)
test_hash_index_remove_needs_matching_owner :: proc(t: ^testing.T) {
	h: Hash_Index
	testing.expect(t, hash_index_init(&h, 4, context.allocator))
	defer hash_index_destroy(&h, context.allocator)
	hash_index_insert(&h, 7, 1)
	testing.expect(t, !hash_index_remove(&h, 7, 2))
	testing.expect(t, hash_index_remove(&h, 7, 1))
	_, found := find_in(&h, 7)
	testing.expect(t, !found)
}

@(test)
test_hash_spread :: proc(t: ^testing.T) {
	// Sequential keys (a pool of addresses) must not pile into few buckets.
	h: Hash_Index
	testing.expect(t, hash_index_init(&h, 4096, context.allocator))
	defer hash_index_destroy(&h, context.allocator)
	for i in 0 ..< u32(4096) {
		hash_index_insert(&h, 0x0a080000 + i, i)
	}
	longest := 0
	run := 0
	for c in h.cells {
		if c.idx != NONE {
			run += 1
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	testing.expectf(t, longest < 64, "longest cluster %d", longest)
}
