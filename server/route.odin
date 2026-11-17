// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "base:intrinsics"
import "core:mem"

// Longest-prefix match: a destination address to the peer that owns it.
// One hash table per family maps (masked address, prefix length) -> owner. A bit
// set marks prefix lengths in use, so a lookup probes only those, longest first,
// and stops at the first hit (2 or 3 probes). No allocation after init, no locks.
// Owner = peer slot index (the wire peer-id), chosen by the caller. Peer
// addresses are /32 and /128 routes; an iroute is any prefix.
// Rules (deterministic lookups):
//   - The network part has no host bits set.
//   - One route per (network, prefix length): a second owner is a `Conflict`.
//   - The same route twice for one owner is a `Duplicate` (not stored again).

Route_Error :: enum u8 {
	None,
	Bad_Prefix,
	Host_Bits,
	Conflict,
	Duplicate,
	Full,
	Out_Of_Memory,
}

Route4 :: struct {
	addr:   u32,
	owner:  u32, // NONE = empty cell
	prefix: u8,
}

Route6 :: struct {
	hi:     u64,
	lo:     u64,
	owner:  u32, // NONE = empty cell
	prefix: u8,
}

Route_Table :: struct {
	cells4:    []Route4,
	mask4:     u32,
	count4:    u32,
	max4:      u32,
	// How many routes use each prefix length, and the same as a bit set.
	len4:      [33]u32,
	lens4:     u64,
	cells6:    []Route6,
	mask6:     u32,
	count6:    u32,
	max6:      u32,
	len6:      [129]u32,
	// Bits 0..128 over three words.
	lens6:     [3]u64,
	seed:      u32,
	allocator: mem.Allocator,
}

// `max4` and `max6` are the most routes of each family (peers plus iroutes).
route_table_init :: proc(rt: ^Route_Table, max4, max6: int, seed: u32 = 0, allocator := context.allocator) -> bool {
	rt^ = {}
	rt.allocator = allocator
	rt.seed = seed
	size4, size6 := 16, 16
	for size4 < max4 * 2 {
		size4 <<= 1
	}
	for size6 < max6 * 2 {
		size6 <<= 1
	}
	if size4 > 1 << 30 || size6 > 1 << 30 {
		return false
	}
	c4, e4 := make([]Route4, size4, allocator)
	c6, e6 := make([]Route6, size6, allocator)
	if e4 != nil || e6 != nil {
		delete(c4, allocator)
		delete(c6, allocator)
		return false
	}
	for &c in c4 {
		c.owner = NONE
	}
	for &c in c6 {
		c.owner = NONE
	}
	rt.cells4, rt.mask4, rt.max4 = c4, u32(size4 - 1), u32(max4)
	rt.cells6, rt.mask6, rt.max6 = c6, u32(size6 - 1), u32(max6)
	return true
}

route_table_destroy :: proc(rt: ^Route_Table) {
	delete(rt.cells4, rt.allocator)
	delete(rt.cells6, rt.allocator)
	rt^ = {}
}

route_memory :: proc(rt: ^Route_Table) -> int {
	return len(rt.cells4) * size_of(Route4) + len(rt.cells6) * size_of(Route6)
}

route_count4 :: proc "contextless" (rt: ^Route_Table) -> int {
	return int(rt.count4)
}

route_count6 :: proc "contextless" (rt: ^Route_Table) -> int {
	return int(rt.count6)
}

// ---------------------------------------------------------------------------
// IPv4

@(private)
mask4_of :: #force_inline proc "contextless" (prefix: u32) -> u32 {
	return 0 if prefix == 0 else ~u32(0) << (32 - prefix)
}

@(private)
h4 :: #force_inline proc "contextless" (rt: ^Route_Table, addr: u32, prefix: u32) -> u32 {
	return mix32(addr * 0x9E3779B1 + prefix + rt.seed) & rt.mask4
}

route_add4 :: proc(rt: ^Route_Table, net: [4]u8, prefix: u8, owner: u32) -> Route_Error {
	if prefix > 32 || owner == NONE {
		return .Bad_Prefix
	}
	addr := key4(net)
	if addr & ~mask4_of(u32(prefix)) != 0 {
		return .Host_Bits
	}
	i := h4(rt, addr, u32(prefix))
	for rt.cells4[i].owner != NONE {
		c := rt.cells4[i]
		if c.addr == addr && c.prefix == prefix {
			return .Duplicate if c.owner == owner else .Conflict
		}
		i = (i + 1) & rt.mask4
	}
	if rt.count4 >= rt.max4 {
		return .Full
	}
	rt.cells4[i] = Route4{addr, owner, prefix}
	rt.count4 += 1
	rt.len4[prefix] += 1
	rt.lens4 |= u64(1) << prefix
	return .None
}

// Removes a route. The owner must match, so one peer cannot remove another's.
route_remove4 :: proc(rt: ^Route_Table, net: [4]u8, prefix: u8, owner: u32) -> bool {
	if prefix > 32 {
		return false
	}
	addr := key4(net)
	i := h4(rt, addr, u32(prefix))
	for {
		c := rt.cells4[i]
		if c.owner == NONE {
			return false
		}
		if c.addr == addr && c.prefix == prefix {
			if c.owner != owner {
				return false
			}
			break
		}
		i = (i + 1) & rt.mask4
	}
	hole := i
	j := i
	for {
		j = (j + 1) & rt.mask4
		c := rt.cells4[j]
		if c.owner == NONE {
			break
		}
		k := h4(rt, c.addr, u32(c.prefix))
		in_range := (hole < k && k <= j) if hole <= j else (hole < k || k <= j)
		if !in_range {
			rt.cells4[hole] = c
			hole = j
		}
	}
	rt.cells4[hole] = Route4{0, NONE, 0}
	rt.count4 -= 1
	rt.len4[prefix] -= 1
	if rt.len4[prefix] == 0 {
		rt.lens4 &= ~(u64(1) << prefix)
	}
	return true
}

// The owner of the longest route that covers `a`.
route_lookup4 :: proc "contextless" (rt: ^Route_Table, a: [4]u8) -> (owner: u32, prefix: u8, ok: bool) {
	addr := key4(a)
	m := rt.lens4
	#no_bounds_check for m != 0 {
		p := u32(63 - intrinsics.count_leading_zeros(m))
		m &= ~(u64(1) << p)
		net := addr & mask4_of(p)
		i := h4(rt, net, p)
		for {
			c := rt.cells4[i]
			if c.owner == NONE {
				break
			}
			if c.addr == net && c.prefix == u8(p) {
				return c.owner, u8(p), true
			}
			i = (i + 1) & rt.mask4
		}
	}
	return NONE, 0, false
}

// The owner of exactly this route, if any.
route_get4 :: proc "contextless" (rt: ^Route_Table, net: [4]u8, prefix: u8) -> (owner: u32, ok: bool) {
	if prefix > 32 {
		return NONE, false
	}
	addr := key4(net)
	i := h4(rt, addr, u32(prefix))
	for {
		c := rt.cells4[i]
		if c.owner == NONE {
			return NONE, false
		}
		if c.addr == addr && c.prefix == prefix {
			return c.owner, true
		}
		i = (i + 1) & rt.mask4
	}
}

// ---------------------------------------------------------------------------
// IPv6

@(private)
split6 :: #force_inline proc "contextless" (a: ^[16]u8) -> (hi, lo: u64) {
	hi = intrinsics.byte_swap(intrinsics.unaligned_load((^u64)(&a[0])))
	lo = intrinsics.byte_swap(intrinsics.unaligned_load((^u64)(&a[8])))
	return
}

@(private)
mask6_of :: #force_inline proc "contextless" (prefix: u32) -> (hi, lo: u64) {
	switch {
	case prefix == 0:
		return 0, 0
	case prefix <= 64:
		return ~u64(0) << (64 - prefix), 0
	case prefix < 128:
		return ~u64(0), ~u64(0) << (128 - prefix)
	}
	return ~u64(0), ~u64(0)
}

@(private)
h6 :: #force_inline proc "contextless" (rt: ^Route_Table, hi, lo: u64, prefix: u32) -> u32 {
	x := (hi * 0x9E3779B97F4A7C15) ~ ((lo + u64(prefix)) * 0xC2B2AE3D27D4EB4F)
	x ~= x >> 32
	return mix32(u32(x) + rt.seed) & rt.mask6
}

route_add6 :: proc(rt: ^Route_Table, net: [16]u8, prefix: u8, owner: u32) -> Route_Error {
	if prefix > 128 || owner == NONE {
		return .Bad_Prefix
	}
	net := net
	hi, lo := split6(&net)
	mh, ml := mask6_of(u32(prefix))
	if hi & ~mh != 0 || lo & ~ml != 0 {
		return .Host_Bits
	}
	i := h6(rt, hi, lo, u32(prefix))
	for rt.cells6[i].owner != NONE {
		c := rt.cells6[i]
		if c.hi == hi && c.lo == lo && c.prefix == prefix {
			return .Duplicate if c.owner == owner else .Conflict
		}
		i = (i + 1) & rt.mask6
	}
	if rt.count6 >= rt.max6 {
		return .Full
	}
	rt.cells6[i] = Route6{hi, lo, owner, prefix}
	rt.count6 += 1
	rt.len6[prefix] += 1
	rt.lens6[prefix >> 6] |= u64(1) << (prefix & 63)
	return .None
}

route_remove6 :: proc(rt: ^Route_Table, net: [16]u8, prefix: u8, owner: u32) -> bool {
	if prefix > 128 {
		return false
	}
	net := net
	hi, lo := split6(&net)
	i := h6(rt, hi, lo, u32(prefix))
	for {
		c := rt.cells6[i]
		if c.owner == NONE {
			return false
		}
		if c.hi == hi && c.lo == lo && c.prefix == prefix {
			if c.owner != owner {
				return false
			}
			break
		}
		i = (i + 1) & rt.mask6
	}
	hole := i
	j := i
	for {
		j = (j + 1) & rt.mask6
		c := rt.cells6[j]
		if c.owner == NONE {
			break
		}
		k := h6(rt, c.hi, c.lo, u32(c.prefix))
		in_range := (hole < k && k <= j) if hole <= j else (hole < k || k <= j)
		if !in_range {
			rt.cells6[hole] = c
			hole = j
		}
	}
	rt.cells6[hole] = Route6{0, 0, NONE, 0}
	rt.count6 -= 1
	rt.len6[prefix] -= 1
	if rt.len6[prefix] == 0 {
		rt.lens6[prefix >> 6] &= ~(u64(1) << (prefix & 63))
	}
	return true
}

route_lookup6 :: proc "contextless" (rt: ^Route_Table, a: ^[16]u8) -> (owner: u32, prefix: u8, ok: bool) {
	hi, lo := split6(a)
	#no_bounds_check for w := 2; w >= 0; w -= 1 {
		m := rt.lens6[w]
		for m != 0 {
			b := u32(63 - intrinsics.count_leading_zeros(m))
			m &= ~(u64(1) << b)
			p := u32(w) * 64 + b
			mh, ml := mask6_of(p)
			nh, nl := hi & mh, lo & ml
			i := h6(rt, nh, nl, p)
			for {
				c := rt.cells6[i]
				if c.owner == NONE {
					break
				}
				if c.hi == nh && c.lo == nl && c.prefix == u8(p) {
					return c.owner, u8(p), true
				}
				i = (i + 1) & rt.mask6
			}
		}
	}
	return NONE, 0, false
}

route_get6 :: proc "contextless" (rt: ^Route_Table, net: ^[16]u8, prefix: u8) -> (owner: u32, ok: bool) {
	if prefix > 128 {
		return NONE, false
	}
	hi, lo := split6(net)
	i := h6(rt, hi, lo, u32(prefix))
	for {
		c := rt.cells6[i]
		if c.owner == NONE {
			return NONE, false
		}
		if c.hi == hi && c.lo == lo && c.prefix == prefix {
			return c.owner, true
		}
		i = (i + 1) & rt.mask6
	}
}
