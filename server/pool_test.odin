// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:proto/config"

// ---------------------------------------------------------------------------
// Bit tree

@(test)
test_bit_tree_model :: proc(t: ^testing.T) {
	sizes := [?]int{1, 2, 63, 64, 65, 4096, 4097, 5000, 70000}
	for n, si in sizes {
		r := rng_make(u64(si) + 1)
		b: Bit_Tree
		testing.expect(t, bit_tree_init(&b, n, context.allocator))
		defer bit_tree_destroy(&b, context.allocator)
		bit_tree_fill(&b)
		model := make([]bool, n, context.temp_allocator)
		for i in 0 ..< n {
			model[i] = true
		}
		testing.expect_value(t, bit_tree_count(&b), n)
		for step in 0 ..< 3000 {
			i := rng_below(&r, n)
			if rng_below(&r, 3) == 0 {
				bit_tree_set(&b, i)
				model[i] = true
			} else {
				bit_tree_clear(&b, i)
				model[i] = false
			}
			if step % 11 == 0 {
				first := -1
				cnt := 0
				for v, j in model {
					if v {
						cnt += 1
						if first < 0 {
							first = j
						}
					}
				}
				got, ok := bit_tree_first(&b)
				testing.expect_value(t, ok, first >= 0)
				if ok {
					testing.expect_value(t, got, first)
				}
				testing.expect_value(t, bit_tree_count(&b), cnt)
				testing.expect_value(t, bit_tree_test(&b, i), model[i])
			}
		}
		// Out of range tests are false.
		testing.expect(t, !bit_tree_test(&b, n))
		testing.expect(t, !bit_tree_test(&b, -1))
	}
}

// ---------------------------------------------------------------------------
// One pool

make_pool :: proc(t: ^testing.T, n: u32, hold := time.Duration(0)) -> ^Pool {
	p := new(Pool)
	testing.expect(t, pool_init(p, 1000, n, hold, context.allocator))
	return p
}

free_pool :: proc(p: ^Pool) {
	pool_destroy(p)
	free(p)
}

@(test)
test_pool_alloc_lowest_first :: proc(t: ^testing.T) {
	p := make_pool(t, 5)
	defer free_pool(p)
	for i in 0 ..< 5 {
		s, ok := pool_alloc(p, fmt.tprintf("c%d", i), 0)
		testing.expect(t, ok)
		testing.expect_value(t, s, u32(i))
	}
	_, ok := pool_alloc(p, "extra", 0)
	testing.expect(t, !ok)
	testing.expect_value(t, pool_used(p), 5)
	testing.expect_value(t, pool_virgin(p), 0)
}

@(test)
test_pool_sticky :: proc(t: ^testing.T) {
	p := make_pool(t, 5)
	defer free_pool(p)
	a, _ := pool_alloc(p, "alice", 0)
	b, _ := pool_alloc(p, "bob", 0)
	testing.expect_value(t, a, u32(0))
	testing.expect_value(t, b, u32(1))
	pool_release(p, a, 10 * SEC)
	pool_release(p, b, 11 * SEC)
	testing.expect_value(t, pool_used(p), 0)
	testing.expect_value(t, pool_remembered(p), 2)
	// Others get fresh slots, and each name gets its own back.
	c, _ := pool_alloc(p, "carol", 12 * SEC)
	testing.expect_value(t, c, u32(2))
	b2, _ := pool_alloc(p, "bob", 12 * SEC)
	testing.expect_value(t, b2, u32(1))
	a2, _ := pool_alloc(p, "alice", 12 * SEC)
	testing.expect_value(t, a2, u32(0))
	testing.expect_value(t, pool_remembered(p), 0)
}

@(test)
test_pool_eviction_order_and_hold :: proc(t: ^testing.T) {
	p := make_pool(t, 3, 30 * SEC)
	defer free_pool(p)
	for n, i in ([?]string{"a", "b", "c"}) {
		s, _ := pool_alloc(p, n, 0)
		testing.expect_value(t, s, u32(i))
	}
	pool_release(p, 1, 100 * SEC) // b first
	pool_release(p, 0, 105 * SEC) // then a
	// All slots are taken or remembered. During the hold nothing is free.
	_, ok := pool_alloc(p, "d", 110 * SEC)
	testing.expect(t, !ok)
	_, ok = pool_alloc(p, "d", 129 * SEC)
	testing.expect(t, !ok)
	// After 30 s the oldest release (b, slot 1) can be taken over.
	s, ok2 := pool_alloc(p, "d", 130 * SEC)
	testing.expect(t, ok2)
	testing.expect_value(t, s, u32(1))
	// b lost its memory; a still has it.
	_, ok = pool_alloc(p, "e", 130 * SEC) // a's release was at 105 s: not yet
	testing.expect(t, !ok)
	a, ok3 := pool_alloc(p, "a", 130 * SEC)
	testing.expect(t, ok3)
	testing.expect_value(t, a, u32(0))
	s2, ok4 := pool_alloc(p, "b", 130 * SEC)
	testing.expect(t, !ok4) // no slot left for the forgotten b
	_ = s2
}

@(test)
test_pool_hint :: proc(t: ^testing.T) {
	p := make_pool(t, 10)
	defer free_pool(p)
	s, _ := pool_alloc(p, "a", 0, 6)
	testing.expect_value(t, s, u32(6)) // the hint, free
	s, _ = pool_alloc(p, "b", 0, 6)
	testing.expect_value(t, s, u32(0)) // hint taken: lowest
	s, _ = pool_alloc(p, "c", 0, 99)
	testing.expect_value(t, s, u32(1)) // hint outside the pool: ignored
}

@(test)
test_pool_duplicate_name :: proc(t: ^testing.T) {
	// duplicate-cn: two sessions of one name hold two slots. The name is
	// remembered by the first slot only.
	p := make_pool(t, 5)
	defer free_pool(p)
	a, _ := pool_alloc(p, "x", 0)
	b, _ := pool_alloc(p, "x", 0)
	testing.expect_value(t, a, u32(0))
	testing.expect_value(t, b, u32(1))
	pool_release(p, b, 1 * SEC) // the second: forgotten at once
	testing.expect_value(t, pool_remembered(p), 0)
	testing.expect_value(t, pool_virgin(p), 4)
	pool_release(p, a, 2 * SEC) // the first: remembered
	testing.expect_value(t, pool_remembered(p), 1)
	c, _ := pool_alloc(p, "x", 3 * SEC)
	testing.expect_value(t, c, a)
}

@(test)
test_pool_reserve :: proc(t: ^testing.T) {
	p := make_pool(t, 5)
	defer free_pool(p)
	testing.expect(t, pool_reserve(p, 0, .Reserved_Pin))
	testing.expect(t, pool_reserve(p, 2, .Reserved_Lazy))
	// Dynamic allocation skips them.
	got: [3]u32
	for i in 0 ..< 3 {
		s, ok := pool_alloc(p, fmt.tprintf("c%d", i), 0)
		testing.expect(t, ok)
		got[i] = s
	}
	testing.expect_value(t, got, [3]u32{1, 3, 4})
	_, ok := pool_alloc(p, "d", 0)
	testing.expect(t, !ok)
	// A used dynamic slot cannot be reserved.
	testing.expect(t, !pool_reserve(p, 3, .Reserved_Pin))
	// A static client takes a reserved slot; a second one is refused.
	testing.expect(t, pool_take_static(p, 0, "alice"))
	testing.expect(t, !pool_take_static(p, 0, "bob"))
	// Releasing a static slot does not turn it dynamic.
	pool_release(p, 0, 5 * SEC)
	testing.expect_value(t, pool_remembered(p), 0)
	_, ok = pool_alloc(p, "d", 6 * SEC)
	testing.expect(t, !ok)
	// Dropping the reservation frees it.
	pool_unreserve_all(p, .Reserved_Pin)
	s, ok2 := pool_alloc(p, "d", 6 * SEC)
	testing.expect(t, ok2)
	testing.expect_value(t, s, u32(0))
	// The other reservation stays.
	pool_unreserve_all(p, .Reserved_Pin)
	_, ok = pool_alloc(p, "e", 6 * SEC)
	testing.expect(t, !ok)
	pool_unreserve_all(p, .Reserved_Lazy)
	s, ok2 = pool_alloc(p, "e", 6 * SEC)
	testing.expect(t, ok2)
	testing.expect_value(t, s, u32(2))
}

@(test)
test_pool_reserve_forgets_old_memory :: proc(t: ^testing.T) {
	p := make_pool(t, 3)
	defer free_pool(p)
	s, _ := pool_alloc(p, "alice", 0)
	pool_release(p, s, 1 * SEC)
	testing.expect(t, pool_reserve(p, s, .Reserved_Pin))
	testing.expect_value(t, pool_remembered(p), 0)
	// alice now gets a different slot.
	s2, ok := pool_alloc(p, "alice", 2 * SEC)
	testing.expect(t, ok)
	testing.expect(t, s2 != s)
}

// Random connects and disconnects against a model: no slot is held twice, no
// slot leaks, a client that leaves and returns before the pool needs its slot
// gets the same one, and a failure means the pool really is out of room.
@(test)
test_pool_model :: proc(t: ^testing.T) {
	N :: 40
	HOLD :: 20 * SEC
	for seed in u64(1) ..= 8 {
		r := rng_make(seed)
		p := make_pool(t, N, HOLD)
		defer free_pool(p)
		Session :: struct {
			name: string,
			slot: u32,
		}
		live := make([dynamic]Session, context.temp_allocator)
		names := make([]string, 60, context.temp_allocator)
		for i in 0 ..< len(names) {
			names[i] = fmt.tprintf("user%d", i)
		}
		// Where each name was last seen released, to check stickiness.
		last_slot := make(map[string]u32, 64, context.temp_allocator)
		allocs_since: [60]int // allocations by others since the name left
		now := time.Duration(0)
		for step in 0 ..< 8000 {
			now += time.Duration(rng_below(&r, 2000)) * time.Millisecond
			if rng_below(&r, 2) == 0 {
				ni := rng_below(&r, len(names))
				name := names[ni]
				already := false
				for s in live {
					already ||= s.name == name
				}
				if already {
					continue
				}
				slot, ok := pool_alloc(p, name, now)
				if !ok {
					// Out of room: no virgin slot, and the oldest release is within the hold.
					testing.expect_value(t, pool_virgin(p), 0)
					if p.q_head != NONE {
						testing.expect(t, now - time.Duration(p.slots[p.q_head].released_at) < HOLD)
					}
					continue
				}
				for s in live {
					testing.expectf(t, s.slot != slot, "slot %d given twice", slot)
				}
				if prev, known := last_slot[name]; known && allocs_since[ni] == 0 {
					testing.expectf(t, prev == slot, "%s moved from %d to %d", name, prev, slot)
				}
				for i in 0 ..< len(allocs_since) {
					if i != ni {
						allocs_since[i] += 1
					}
				}
				allocs_since[ni] = 0
				delete_key(&last_slot, name)
				append(&live, Session{name, slot})
			} else if len(live) > 0 {
				i := rng_below(&r, len(live))
				s := live[i]
				pool_release(p, s.slot, now)
				for ni in 0 ..< len(names) {
					if names[ni] == s.name {
						last_slot[s.name] = s.slot
						allocs_since[ni] = 0
					}
				}
				unordered_remove(&live, i)
			}
			if step % 101 == 0 {
				testing.expect_value(t, pool_used(p), len(live))
				// Every slot is in exactly one of: used, remembered, virgin.
				testing.expect_value(t, pool_used(p) + pool_remembered(p) + pool_virgin(p), N)
			}
		}
		for s in live {
			pool_release(p, s.slot, now)
		}
		testing.expect_value(t, pool_used(p), 0)
		testing.expect_value(t, pool_used(p) + pool_remembered(p) + pool_virgin(p), N)
	}
}

// ---------------------------------------------------------------------------
// Both pools from a config

make_pools :: proc(t: ^testing.T, cfg: ^config.Config, hold := time.Duration(0)) -> ^Pools {
	ps := new(Pools)
	testing.expect(t, pools_init(ps, &cfg.server, hold))
	return ps
}

free_pools :: proc(ps: ^Pools) {
	pools_destroy(ps)
	free(ps)
}

@(test)
test_pools_default_ranges :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	// 10.8.0.2 to 10.8.0.253.
	testing.expect(t, ps.has4)
	testing.expect_value(t, int(ps.v4.count), 252)
	testing.expect(t, ps.has6)
	testing.expect_value(t, int(ps.v6.count), 252)
	l, err := pools_acquire(ps, "alice", nil, nil, 0)
	testing.expect_value(t, err, Acquire_Error.None)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, l.kind4, Lease_Kind.Dynamic)
	// The IPv6 pool starts after the server's own address (fd00:8::1), so
	// 10.8.0.2 pairs with fd00:8::2.
	testing.expect_value(t, l.kind6, Lease_Kind.Dynamic)
	testing.expect_value(t, l.addr6, v6("fd00:8::2"))
}

@(test)
test_pools_explicit_pool_skips_reserved_addresses :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "ifconfig-pool 10.8.0.0 10.8.0.255\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	testing.expect_value(t, int(ps.v4.count), 256)
	seen := make(map[[4]u8]bool, context.temp_allocator)
	for i in 0 ..< 253 {
		l, err := pools_acquire(ps, fmt.tprintf("c%d", i), nil, nil, 0)
		testing.expect_value(t, err, Acquire_Error.None)
		seen[l.addr4] = true
		testing.expect(t, l.addr4 != [4]u8{10, 8, 0, 0})
		testing.expect(t, l.addr4 != [4]u8{10, 8, 0, 1})
		testing.expect(t, l.addr4 != [4]u8{10, 8, 0, 255})
	}
	testing.expect_value(t, len(seen), 253)
	_, err := pools_acquire(ps, "one-too-many", nil, nil, 0)
	testing.expect_value(t, err, Acquire_Error.Pool_Exhausted)
}

@(test)
test_pools_nopool :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, "server 10.8.0.0 255.255.255.0 nopool\n" + SERVER_BASE[len("server 10.8.0.0 255.255.255.0\n"):])
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	testing.expect(t, !ps.has4)
	// No dynamic address: a client without a static one is refused.
	_, err := pools_acquire(ps, "alice", nil, nil, 0)
	testing.expect_value(t, err, Acquire_Error.No_Address)
	// With a static address it works.
	l, err2 := pools_acquire(ps, "alice", [4]u8{10, 8, 0, 50}, nil, 0)
	testing.expect_value(t, err2, Acquire_Error.None)
	testing.expect_value(t, l.kind4, Lease_Kind.Static_Outside)
	// The same address twice is refused.
	_, err = pools_acquire(ps, "bob", [4]u8{10, 8, 0, 50}, nil, 0)
	testing.expect_value(t, err, Acquire_Error.Address_In_Use)
	pools_release(ps, l, 1 * SEC)
	_, err = pools_acquire(ps, "bob", [4]u8{10, 8, 0, 50}, nil, 2 * SEC)
	testing.expect_value(t, err, Acquire_Error.None)
}

@(test)
test_pools_static_rules_v4 :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE)
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	check :: proc(ps: ^Pools, s: string) -> Static_Problem {
		return pools_check_static4(ps, v4(s))
	}
	testing.expect_value(t, check(ps, "10.8.0.10"), Static_Problem.None)
	testing.expect_value(t, check(ps, "10.8.0.254"), Static_Problem.None) // outside the pool
	testing.expect_value(t, check(ps, "10.8.0.2"), Static_Problem.None) // the first pool address
	testing.expect_value(t, check(ps, "10.8.0.0"), Static_Problem.Reserved_Address)
	testing.expect_value(t, check(ps, "10.8.0.1"), Static_Problem.Reserved_Address)
	testing.expect_value(t, check(ps, "10.8.0.255"), Static_Problem.Reserved_Address)
	testing.expect_value(t, check(ps, "10.8.1.5"), Static_Problem.Outside_Network)
	testing.expect_value(t, check(ps, "192.168.1.1"), Static_Problem.Outside_Network)
	testing.expect_value(t, check(ps, "0.0.0.0"), Static_Problem.Outside_Network)

	for bad in ([?]string{"10.8.0.0", "10.8.0.1", "10.8.0.255", "10.8.1.5"}) {
		_, err := pools_acquire(ps, "x", v4(bad), nil, 0)
		testing.expect_value(t, err, Acquire_Error.Bad_Static_Address)
	}
	// IPv6 static on a server without server-ipv6.
	_, err := pools_acquire(ps, "x", nil, v6("fd00::5"), 0)
	testing.expect_value(t, err, Acquire_Error.Bad_Static_Address)
	testing.expect_value(t, pool_used(&ps.v4), 0) // nothing held after the refusals
}

@(test)
test_pools_static_inside_pool :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE)
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)

	// A dynamic client holds .2. A static client for .2 is refused.
	d1, _ := pools_acquire(ps, "dyn", nil, nil, 0)
	testing.expect_value(t, d1.addr4, [4]u8{10, 8, 0, 2})
	_, err := pools_acquire(ps, "stat", [4]u8{10, 8, 0, 2}, nil, 0)
	testing.expect_value(t, err, Acquire_Error.Address_In_Use)

	// A static client for .3 gets it, and dynamic ones then skip it.
	s1, err2 := pools_acquire(ps, "stat", [4]u8{10, 8, 0, 3}, nil, 0)
	testing.expect_value(t, err2, Acquire_Error.None)
	testing.expect_value(t, s1.kind4, Lease_Kind.Static_In_Range)
	d2, _ := pools_acquire(ps, "dyn2", nil, nil, 0)
	testing.expect_value(t, d2.addr4, [4]u8{10, 8, 0, 4})

	// Another static client for .3 while the first is connected: refused.
	_, err = pools_acquire(ps, "other", [4]u8{10, 8, 0, 3}, nil, 0)
	testing.expect_value(t, err, Acquire_Error.Address_In_Use)

	// The static client leaves. The address stays reserved for it (a dynamic
	// client does not get it), and it can come back.
	pools_release(ps, s1, 10 * SEC)
	got := make(map[[4]u8]bool, context.temp_allocator)
	for i in 0 ..< 20 {
		l, e := pools_acquire(ps, fmt.tprintf("n%d", i), nil, nil, 11 * SEC)
		testing.expect_value(t, e, Acquire_Error.None)
		got[l.addr4] = true
	}
	testing.expect(t, [4]u8{10, 8, 0, 3} not_in got)
	s2, err3 := pools_acquire(ps, "stat", [4]u8{10, 8, 0, 3}, nil, 12 * SEC)
	testing.expect_value(t, err3, Acquire_Error.None)
	testing.expect_value(t, s2.addr4, [4]u8{10, 8, 0, 3})
}

@(test)
test_pools_reserve_from_peers_file :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE)
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	// The peers file says alice has .2 and .3: dynamic clients never get them,
	// even before alice has connected.
	pools_reserve_static(ps, [4]u8{10, 8, 0, 2}, nil)
	pools_reserve_static(ps, [4]u8{10, 8, 0, 3}, nil)
	pools_reserve_static(ps, [4]u8{10, 9, 0, 3}, nil) // outside: ignored
	l, _ := pools_acquire(ps, "dyn", nil, nil, 0)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 4})
	// After a reload that dropped them they are free again.
	pools_unreserve_all(ps, .Reserved_Pin)
	l, _ = pools_acquire(ps, "dyn2", nil, nil, 0)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 2})
}

@(test)
test_pools_v6 :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	check :: proc(ps: ^Pools, s: string) -> Static_Problem {
		return pools_check_static6(ps, v6(s))
	}
	testing.expect_value(t, check(ps, "fd00:8::10"), Static_Problem.None)
	testing.expect_value(t, check(ps, "fd00:8:0:0:1::5"), Static_Problem.None) // far outside the pool, inside the prefix
	testing.expect_value(t, check(ps, "fd00:8::1"), Static_Problem.Reserved_Address) // the server
	testing.expect_value(t, check(ps, "fd00:8::"), Static_Problem.Reserved_Address) // all-zero host
	testing.expect_value(t, check(ps, "fd00:9::10"), Static_Problem.Outside_Network)
	testing.expect_value(t, check(ps, "2001:db8::1"), Static_Problem.Outside_Network)

	// Static v6 inside the pool range reserves its slot.
	l, err := pools_acquire(ps, "alice", nil, v6("fd00:8::10"), 0)
	testing.expect_value(t, err, Acquire_Error.None)
	testing.expect_value(t, l.kind6, Lease_Kind.Static_In_Range)
	testing.expect_value(t, l.kind4, Lease_Kind.Dynamic)
	// And one far outside it.
	l2, err2 := pools_acquire(ps, "bob", nil, v6("fd00:8:0:0:1::5"), 0)
	testing.expect_value(t, err2, Acquire_Error.None)
	testing.expect_value(t, l2.kind6, Lease_Kind.Static_Outside)
	_, err = pools_acquire(ps, "carol", nil, v6("fd00:8:0:0:1::5"), 0)
	testing.expect_value(t, err, Acquire_Error.Address_In_Use)
	// A bad static v6 releases the v4 address it had already taken.
	before := pool_used(&ps.v4)
	_, err = pools_acquire(ps, "dave", nil, v6("fd00:9::1"), 0)
	testing.expect_value(t, err, Acquire_Error.Bad_Static_Address)
	testing.expect_value(t, pool_used(&ps.v4), before)
}

@(test)
test_pools_v6_paired_with_v4 :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	// A static v4 client (slot 10 of the v4 pool) gets the first free v6 slot.
	// Dynamic dual-stack clients keep v4 slot == v6 slot while both are free.
	a, _ := pools_acquire(ps, "a", nil, nil, 0)
	b, _ := pools_acquire(ps, "b", nil, nil, 0)
	testing.expect_value(t, a.slot4, a.slot6)
	testing.expect_value(t, b.slot4, b.slot6)
	pools_release(ps, a, 1 * SEC)
	// Reconnect: both families are sticky.
	a2, _ := pools_acquire(ps, "a", nil, nil, 2 * SEC)
	testing.expect_value(t, a2.addr4, a.addr4)
	testing.expect_value(t, a2.addr6, a.addr6)
}

@(test)
test_pools_release_everything_no_leak :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	leases := make([dynamic]Lease, context.temp_allocator)
	for i in 0 ..< 100 {
		static4: Maybe([4]u8)
		if i % 10 == 0 {
			static4 = [4]u8{10, 8, 0, u8(100 + i)}
		}
		l, err := pools_acquire(ps, fmt.tprintf("c%d", i), static4, nil, 0)
		testing.expect_value(t, err, Acquire_Error.None)
		append(&leases, l)
	}
	for l in leases {
		pools_release(ps, l, 5 * SEC)
	}
	testing.expect_value(t, pool_used(&ps.v4), 0)
	testing.expect_value(t, pool_used(&ps.v6), 0)
	testing.expect_value(t, len(ps.static4), 0)
	total := pool_used(&ps.v4) + pool_remembered(&ps.v4) + pool_virgin(&ps.v4)
	reserved := 0
	for s in ps.v4.slots {
		if s.flags & RESERVED_ANY != {} {
			reserved += 1
		}
	}
	testing.expect_value(t, total + reserved, int(ps.v4.count))
}

// A 64k pool: allocation and release stay cheap and correct.
@(test)
test_pool_64k :: proc(t: ^testing.T) {
	N :: 65536
	p := new(Pool)
	defer free_pool(p)
	testing.expect(t, pool_init(p, 1 << 24, N, 0, context.allocator))
	slots := make([]u32, N, context.temp_allocator)
	names := make([]string, N, context.temp_allocator)
	for i in 0 ..< N {
		names[i] = fmt.tprintf("client-%d", i)
		s, ok := pool_alloc(p, names[i], 0)
		testing.expect(t, ok)
		slots[i] = s
		if s != u32(i) {
			testing.expectf(t, false, "slot %d for client %d", s, i)
			return
		}
	}
	_, ok := pool_alloc(p, "full", 0)
	testing.expect(t, !ok)
	for i := 0; i < N; i += 3 {
		pool_release(p, slots[i], 1 * SEC)
	}
	// They come back to their own slots.
	for i := 0; i < N; i += 3 {
		s, ok2 := pool_alloc(p, names[i], 2 * SEC)
		testing.expect(t, ok2 && s == slots[i])
	}
	testing.expect_value(t, pool_used(p), N)
}

// ---------------------------------------------------------------------------
// ifconfig-pool-persist

@(test)
test_persist_round_trip :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	names := [?]string{"alice", "bob", "carol@example.com", "dave smith"}
	leases: [len(names)]Lease
	for n, i in names {
		l, err := pools_acquire(ps, n, nil, nil, 0)
		testing.expect_value(t, err, Acquire_Error.None)
		leases[i] = l
	}
	// A static client is not written.
	st, _ := pools_acquire(ps, "static", [4]u8{10, 8, 0, 100}, nil, 0)
	pools_release(ps, leases[1], 5 * SEC) // bob left: still written
	text := pools_persist_save(ps)
	defer delete(text)
	testing.expect(t, !pools_persist_dirty(ps))
	// The static client's IPv4 address is not written (its dynamic IPv6 one is).
	testing.expect(t, !strings.contains(text, "static,10."))
	testing.expect(t, strings.contains(text, "alice,10.8.0.2,fd00:8::2\n"))
	testing.expect(t, strings.contains(text, "bob,10.8.0.3,fd00:8::3\n"))
	testing.expect(t, strings.contains(text, "dave smith,10.8.0.5,fd00:8::5\n"))
	pools_release(ps, st, 5 * SEC)

	// A fresh server loads the file and gives everyone the same addresses back,
	// whatever order they come in.
	ps2 := make_pools(t, &cfg)
	defer free_pools(ps2)
	rep := pools_persist_load(ps2, text, 0)
	defer persist_report_destroy(&rep)
	testing.expect_value(t, rep.loaded, 5)
	testing.expect_value(t, rep.skipped_total, 0)
	#reverse for n, i in names {
		l, err := pools_acquire(ps2, n, nil, nil, 1 * SEC)
		testing.expect_value(t, err, Acquire_Error.None)
		if err == .None {
			expect_addrs := leases[i]
			testing.expect_value(t, l.addr4, expect_addrs.addr4)
			testing.expect_value(t, l.addr6, expect_addrs.addr6)
		}
	}
	// And a new name gets a slot nobody remembered.
	l, _ := pools_acquire(ps2, "newcomer", nil, nil, 2 * SEC)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 6})
}

@(test)
test_persist_ipv4_only_and_ipv6_only_rows :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	text := "old,10.8.0.9\nv6only,,fd00:8::20\nboth,10.8.0.10,fd00:8::21\n"
	rep := pools_persist_load(ps, text, 0)
	defer persist_report_destroy(&rep)
	testing.expect_value(t, rep.loaded, 3)
	l, _ := pools_acquire(ps, "old", nil, nil, 0)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 9})
	l, _ = pools_acquire(ps, "v6only", nil, nil, 0)
	testing.expect_value(t, l.addr6, v6("fd00:8::20"))
	l, _ = pools_acquire(ps, "both", nil, nil, 0)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 10})
	testing.expect_value(t, l.addr6, v6("fd00:8::21"))
}

@(test)
test_persist_corrupt_lines :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\nifconfig-pool 10.8.0.10 10.8.0.50\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	pools_reserve_static(ps, [4]u8{10, 8, 0, 20}, nil)
	text := strings.concatenate(
		{
			"good1,10.8.0.11\n", // 1 ok
			"\n", // 2 blank: ignored
			"no-comma\n", // 3 format
			"x,notanip\n", // 4 bad ipv4
			"y,10.8.0.12,notv6\n", // 5 bad ipv6
			"z,10.9.0.1\n", // 6 out of range (v4)
			"good1,10.8.0.13\n", // 7 duplicate name
			"w,10.8.0.11\n", // 8 address taken
			"static,10.8.0.20\n", // 9 reserved for a static client
			"a/b,10.8.0.14\n", // 10 bad name
			",10.8.0.15\n", // 11 empty name
			"too,many,10.8.0.16,fd00:8::40,extra\n", // 12 too many fields
			"v,,\n", // 13 no address at all
			"good2,10.8.0.17\r\n", // 14 ok (CRLF)
			"half,10.8.0.18,fd00:9::1\n", // 15 bad v6 range: whole line refused, v4 not kept
			"after-half,10.8.0.18\n", // 16 ok: .18 was not taken by line 15
			"bad,name,10.8.0.19\n", // 17 name with a comma looks like 3 fields: bad ipv4
			"nul\x00name,10.8.0.19\n", // 18 bad name
		},
		context.temp_allocator,
	)
	rep := pools_persist_load(ps, text, 0)
	defer persist_report_destroy(&rep)
	testing.expect_value(t, rep.loaded, 3) // good1, good2, after-half
	testing.expect_value(t, rep.skipped_total, 14)
	want := make(map[int]Persist_Skip_Reason, context.temp_allocator)
	want[3] = .Bad_Format
	want[4] = .Bad_Ipv4
	want[5] = .Bad_Ipv6
	want[6] = .Out_Of_Range
	want[7] = .Duplicate_Name
	want[8] = .Address_Taken
	want[9] = .Address_Taken
	want[10] = .Bad_Name
	want[11] = .Bad_Name
	want[12] = .Bad_Format
	want[13] = .Bad_Format
	want[15] = .Out_Of_Range
	want[17] = .Bad_Ipv4
	want[18] = .Bad_Name
	for s in rep.skipped {
		w, found := want[s.line]
		testing.expectf(t, found, "unexpected skip of line %d (%v)", s.line, s.reason)
		testing.expectf(t, w == s.reason, "line %d: got %v want %v", s.line, s.reason, w)
	}
	l, _ := pools_acquire(ps, "after-half", nil, nil, 0)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 18})
	l, _ = pools_acquire(ps, "good2", nil, nil, 0)
	testing.expect_value(t, l.addr4, [4]u8{10, 8, 0, 17})
}

@(test)
test_persist_skips_names_with_commas_on_save :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE)
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	ps := make_pools(t, &cfg)
	defer free_pools(ps)
	l1, _ := pools_acquire(ps, "Smith, John", nil, nil, 0)
	l2, _ := pools_acquire(ps, "plain", nil, nil, 0)
	pools_release(ps, l1, 1 * SEC)
	pools_release(ps, l2, 1 * SEC)
	text := pools_persist_save(ps)
	defer delete(text)
	testing.expect_value(t, text, "plain,10.8.0.3\n")
}

@(test)
test_persist_garbage_never_crashes :: proc(t: ^testing.T) {
	cfg, ok := make_cfg(t, SERVER_BASE, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer config.destroy(&cfg)
	r := rng_make(99)
	alphabet := "ab,.:/\n\r 0123456789\x00\xff#"
	for _ in 0 ..< 300 {
		ps := make_pools(t, &cfg)
		n := rng_below(&r, 400)
		buf := make([]u8, n, context.temp_allocator)
		for &c in buf {
			c = alphabet[rng_below(&r, len(alphabet))]
		}
		rep := pools_persist_load(ps, string(buf), 0)
		lines := strings.count(string(buf), "\n") + 1
		testing.expect(t, rep.loaded + rep.skipped_total <= lines)
		testing.expect(t, len(rep.skipped) <= PERSIST_MAX_REPORT)
		// The pool still works and saving gives text that loads back whole.
		text := pools_persist_save(ps)
		ps2 := make_pools(t, &cfg)
		rep2 := pools_persist_load(ps2, text, 0)
		testing.expect_value(t, rep2.skipped_total, 0)
		testing.expect_value(t, rep2.loaded, rep.loaded)
		persist_report_destroy(&rep2)
		free_pools(ps2)
		delete(text)
		persist_report_destroy(&rep)
		free_pools(ps)
	}
}

@(test)
test_write_ip6_forms :: proc(t: ^testing.T) {
	cases := [?]struct {
		addr: string,
		want: string,
	} {
		{"fd00:8::2", "fd00:8::2"},
		{"::", "::"},
		{"::1", "::1"},
		{"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
		{"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
		{"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
		{"1:0:3:4:5:6:7:8", "1:0:3:4:5:6:7:8"},
		{"fe80::abcd:ef01", "fe80::abcd:ef01"},
		{"1::", "1::"},
	}
	for c in cases {
		sb := strings.builder_make(context.temp_allocator)
		write_ip6(&sb, v6(c.addr))
		testing.expect_value(t, strings.to_string(sb), c.want)
	}
}

@(test)
test_pool_sticky_ignores_name_case :: proc(t: ^testing.T) {
	p := make_pool(t, 5)
	defer free_pool(p)
	a, _ := pool_alloc(p, "Alice", 0)
	pool_release(p, a, 10 * SEC)
	b, _ := pool_alloc(p, "bob", 11 * SEC)
	testing.expect(t, b != a)
	// The same user in another case gets the address back.
	a2, _ := pool_alloc(p, "ALICE", 12 * SEC)
	testing.expect_value(t, a2, a)
	testing.expect_value(t, pool_remembered(p), 0)
}
