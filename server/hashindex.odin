// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "base:intrinsics"
import "core:mem"

// Fixed-size open-addressing hash index: linear probing, backward-shift delete
// (no tombstones, so lookups stay short after any churn).
// - A cell holds a 32-bit key and the index of the owner record. The key is an
//   exact value (an IPv4 address) or a hash (the caller then verifies the record).
// - Sized once, never grows. The caller keeps the load at one half or less.

NONE :: u32(0xFFFFFFFF)

Cell :: struct {
	key: u32,
	idx: u32,
}

Hash_Index :: struct {
	cells: []Cell,
	mask:  u32,
	count: u32,
}

// Room for `n` entries at load 0.5 or less.
hash_index_init :: proc(h: ^Hash_Index, n: int, allocator: mem.Allocator) -> bool {
	size := 16
	for size < n * 2 {
		size <<= 1
	}
	if size > 1 << 31 {
		return false
	}
	cells, err := make([]Cell, size, allocator)
	if err != nil {
		return false
	}
	for &c in cells {
		c.idx = NONE
	}
	h.cells = cells
	h.mask = u32(size - 1)
	h.count = 0
	return true
}

hash_index_destroy :: proc(h: ^Hash_Index, allocator: mem.Allocator) {
	delete(h.cells, allocator)
	h^ = {}
}

hash_index_clear :: proc(h: ^Hash_Index) {
	for &c in h.cells {
		c = Cell{0, NONE}
	}
	h.count = 0
}

// 32-bit finalizer (murmur3): sequential keys land far apart.
mix32 :: #force_inline proc "contextless" (x: u32) -> u32 {
	h := x
	h ~= h >> 16
	h *= 0x85ebca6b
	h ~= h >> 13
	h *= 0xc2b2ae35
	h ~= h >> 16
	return h
}

// Fast hash of 16 or 20 bytes (the address keys). `seed` is random per table,
// so a client that picks its source port cannot aim for one cluster.
hash_bytes :: #force_inline proc "contextless" (p: rawptr, n: int, seed: u64) -> u32 {
	K1 :: u64(0x9E3779B97F4A7C15)
	K2 :: u64(0xC2B2AE3D27D4EB4F)
	a := intrinsics.unaligned_load((^u64)(p)) ~ seed
	b := intrinsics.unaligned_load((^u64)(uintptr(p) + 8))
	h := (a * K1) ~ ((b ~ (a >> 29)) * K2)
	if n > 16 {
		c := intrinsics.unaligned_load((^u32)(uintptr(p) + 16))
		h ~= u64(c) * 0x165667B19E3779F9
	}
	h ~= h >> 32
	return u32(h)
}

// Hash of a user name (FNV-1a, folded), ASCII case ignored: names that
// `name_equal` calls equal have one hash. Used for identities at connect time
// only.
hash_name :: proc "contextless" (s: string) -> u32 {
	h := u64(0xcbf29ce484222325)
	for c in transmute([]u8)s {
		h ~= u64(ascii_lower(c))
		h *= 0x100000001b3
	}
	h ~= h >> 32
	return u32(h)
}

@(private = "file")
home :: #force_inline proc "contextless" (key: u32, mask: u32) -> u32 {
	return mix32(key) & mask
}

// Adds an entry. The caller has checked that it is not there.
hash_index_insert :: proc "contextless" (h: ^Hash_Index, key: u32, idx: u32) {
	#no_bounds_check {
		i := home(key, h.mask)
		for h.cells[i].idx != NONE {
			i = (i + 1) & h.mask
		}
		h.cells[i] = Cell{key, idx}
	}
	h.count += 1
}

// Removes the entry with this key and owner.
hash_index_remove :: proc "contextless" (h: ^Hash_Index, key: u32, idx: u32) -> bool {
	#no_bounds_check {
		i := home(key, h.mask)
		for {
			c := h.cells[i]
			if c.idx == NONE {
				return false
			}
			if c.key == key && c.idx == idx {
				break
			}
			i = (i + 1) & h.mask
		}
		// Backward shift: move later entries of the cluster into the hole when
		// their home position allows it.
		hole := i
		j := i
		for {
			j = (j + 1) & h.mask
			c := h.cells[j]
			if c.idx == NONE {
				break
			}
			k := home(c.key, h.mask)
			// c may move to `hole` unless its home lies cyclically in (hole, j].
			in_range := (hole < k && k <= j) if hole <= j else (hole < k || k <= j)
			if !in_range {
				h.cells[hole] = c
				hole = j
			}
		}
		h.cells[hole] = Cell{0, NONE}
	}
	h.count -= 1
	return true
}

// The probe start for a key, for the lookup loops written next to each index.
hash_index_home :: #force_inline proc "contextless" (h: ^Hash_Index, key: u32) -> u32 {
	return home(key, h.mask)
}
