// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"
import "core:time"

make_table :: proc(t: ^testing.T, cap_: int, delay := 10 * SEC, seed: u64 = 1) -> (pt: ^Peer_Table) {
	pt = new(Peer_Table)
	ok := peers_init(pt, Peer_Table_Params{cap_, delay, seed})
	testing.expect(t, ok)
	return
}

free_table :: proc(pt: ^Peer_Table) {
	peers_destroy(pt)
	free(pt)
}

add_peer :: proc(
	t: ^testing.T,
	pt: ^Peer_Table,
	name: string,
	n: int,
	now := time.Duration(0),
	key := Peer_Key{},
	loc := #caller_location,
) -> (
	h: Peer_Handle,
) {
	ok: bool
	h, ok = peers_alloc(pt, now)
	testing.expect(t, ok, loc = loc)
	err := peers_commit(pt, h, name, tkey(n), [4]u8{10, 8, 0, u8(n)}, v6n(n), u64(n), now, key)
	testing.expect_value(t, err, Peer_Error.None, loc = loc)
	return
}

@(test)
test_peers_basic :: proc(t: ^testing.T) {
	pt := make_table(t, 8)
	defer free_table(pt)
	h := add_peer(t, pt, "alice", 5)
	testing.expect_value(t, peers_count(pt), 1)
	testing.expect_value(t, peer_id(h), u32(0))

	p := peers_get(pt, h)
	testing.expect(t, p != nil)
	testing.expect_value(t, p.identity, "alice")
	testing.expect_value(t, p.user, u64(5))
	testing.expect(t, p.has4 && p.has6)

	// Every lookup finds it.
	h2, p2 := peers_by_id(pt, 0)
	testing.expect(t, p2 == p && h2 == h)
	k := tkey(5)
	h3, p3 := peers_by_addr(pt, &k)
	testing.expect(t, p3 == p && h3 == h)
	h4, p4 := peers_by_vpn4(pt, {10, 8, 0, 5})
	testing.expect(t, p4 == p && h4 == h)
	a6 := v6n(5)
	h5, p5 := peers_by_vpn6(pt, &a6)
	testing.expect(t, p5 == p && h5 == h)
	h6, p6 := peers_by_identity(pt, "alice")
	testing.expect(t, p6 == p && h6 == h)

	// And nothing finds things that are not there.
	_, np := peers_by_id(pt, 1)
	testing.expect(t, np == nil)
	_, np = peers_by_id(pt, 0xFFFFFF)
	testing.expect(t, np == nil)
	_, np = peers_by_id(pt, 100)
	testing.expect(t, np == nil)
	k2 := tkey(6)
	_, np = peers_by_addr(pt, &k2)
	testing.expect(t, np == nil)
	_, np = peers_by_vpn4(pt, {10, 8, 0, 6})
	testing.expect(t, np == nil)
	_, np = peers_by_identity(pt, "bob")
	testing.expect(t, np == nil)

	testing.expect(t, peers_remove(pt, h, 1 * SEC))
	testing.expect_value(t, peers_count(pt), 0)
	testing.expect(t, peers_get(pt, h) == nil)
	_, np = peers_by_addr(pt, &k)
	testing.expect(t, np == nil)
	_, np = peers_by_vpn4(pt, {10, 8, 0, 5})
	testing.expect(t, np == nil)
	_, np = peers_by_identity(pt, "alice")
	testing.expect(t, np == nil)
	// A second remove of the same handle does nothing.
	testing.expect(t, !peers_remove(pt, h, 2 * SEC))
}

@(test)
test_peers_reserved_is_invisible :: proc(t: ^testing.T) {
	pt := make_table(t, 4)
	defer free_table(pt)
	h, ok := peers_alloc(pt, 0)
	testing.expect(t, ok)
	testing.expect(t, peers_get(pt, h) == nil)
	_, p := peers_by_id(pt, h.index)
	testing.expect(t, p == nil)
	testing.expect_value(t, peers_count(pt), 1)
	// A reserved id can be given back.
	testing.expect(t, peers_remove(pt, h, 0))
	testing.expect_value(t, peers_count(pt), 0)
}

@(test)
test_peers_commit_conflicts :: proc(t: ^testing.T) {
	pt := make_table(t, 8)
	defer free_table(pt)
	add_peer(t, pt, "alice", 1)
	h, _ := peers_alloc(pt, 0)

	// Same transport address.
	err := peers_commit(pt, h, "bob", tkey(1), [4]u8{10, 8, 0, 9}, nil, 0, 0)
	testing.expect_value(t, err, Peer_Error.Addr_In_Use)
	// Same VPN address.
	err = peers_commit(pt, h, "bob", tkey(2), [4]u8{10, 8, 0, 1}, nil, 0, 0)
	testing.expect_value(t, err, Peer_Error.Vpn_Addr_In_Use)
	a6 := v6n(1)
	err = peers_commit(pt, h, "bob", tkey(2), nil, a6, 0, 0)
	testing.expect_value(t, err, Peer_Error.Vpn_Addr_In_Use)
	// Nothing was changed by the failures.
	testing.expect_value(t, peers_get(pt, h) == nil, true)
	_, p := peers_by_identity(pt, "bob")
	testing.expect(t, p == nil)
	// And now it works.
	err = peers_commit(pt, h, "bob", tkey(2), [4]u8{10, 8, 0, 2}, nil, 0, 0)
	testing.expect_value(t, err, Peer_Error.None)
	// Committing twice is a bad handle.
	err = peers_commit(pt, h, "bob", tkey(3), nil, nil, 0, 0)
	testing.expect_value(t, err, Peer_Error.Bad_Handle)
	// An invented handle too.
	err = peers_commit(pt, Peer_Handle{7, 99}, "x", tkey(4), nil, nil, 0, 0)
	testing.expect_value(t, err, Peer_Error.Bad_Handle)
	err = peers_commit(pt, Peer_Handle{999, 1}, "x", tkey(4), nil, nil, 0, 0)
	testing.expect_value(t, err, Peer_Error.Bad_Handle)
}

@(test)
test_peers_v4_only_and_v6_only :: proc(t: ^testing.T) {
	pt := make_table(t, 4)
	defer free_table(pt)
	h1, _ := peers_alloc(pt, 0)
	testing.expect_value(t, peers_commit(pt, h1, "a", tkey(1), [4]u8{10, 0, 0, 1}, nil, 0, 0), Peer_Error.None)
	h2, _ := peers_alloc(pt, 0)
	a6 := v6("fd00::7")
	testing.expect_value(t, peers_commit(pt, h2, "b", tkey(2), nil, a6, 0, 0), Peer_Error.None)
	_, p := peers_by_vpn4(pt, {10, 0, 0, 1})
	testing.expect(t, p != nil && p.identity == "a" && !p.has6)
	_, p = peers_by_vpn6(pt, &a6)
	testing.expect(t, p != nil && p.identity == "b" && !p.has4)
	// Removing them clears their indexes.
	testing.expect(t, peers_remove(pt, h1, 0))
	testing.expect(t, peers_remove(pt, h2, 0))
	_, p = peers_by_vpn4(pt, {10, 0, 0, 1})
	testing.expect(t, p == nil)
	_, p = peers_by_vpn6(pt, &a6)
	testing.expect(t, p == nil)
}

@(test)
test_peers_id_reuse_delay :: proc(t: ^testing.T) {
	// Capacity 3: ids 0, 1, 2 are used once each before any comes back.
	pt := make_table(t, 3, 10 * SEC)
	defer free_table(pt)
	hs: [3]Peer_Handle
	for i in 0 ..< 3 {
		hs[i] = add_peer(t, pt, "x", i + 1, 0)
	}
	testing.expect_value(t, hs[0].index, u32(0))
	testing.expect_value(t, hs[1].index, u32(1))
	testing.expect_value(t, hs[2].index, u32(2))
	// Full.
	_, ok := peers_alloc(pt, 0)
	testing.expect(t, !ok)

	// Free id 1 at t=5s. It is not available until t=15s.
	testing.expect(t, peers_remove(pt, hs[1], 5 * SEC))
	_, ok = peers_alloc(pt, 5 * SEC)
	testing.expect(t, !ok)
	_, ok = peers_alloc(pt, 14 * SEC)
	testing.expect(t, !ok)
	h, ok2 := peers_alloc(pt, 15 * SEC)
	testing.expect(t, ok2)
	testing.expect_value(t, h.index, u32(1))
	// The generation changed, so the old handle is dead even though the id is back.
	testing.expect(t, h.gen != hs[1].gen)
	testing.expect(t, peers_get(pt, hs[1]) == nil)
	testing.expect(t, peers_remove(pt, h, 15 * SEC))

	// Order of reuse: oldest freed first.
	testing.expect(t, peers_remove(pt, hs[0], 20 * SEC))
	testing.expect(t, peers_remove(pt, hs[2], 21 * SEC))
	h, ok2 = peers_alloc(pt, 40 * SEC)
	testing.expect_value(t, h.index, u32(1)) // freed at 15 s, the oldest
	h, ok2 = peers_alloc(pt, 40 * SEC)
	testing.expect_value(t, h.index, u32(0))
	h, ok2 = peers_alloc(pt, 40 * SEC)
	testing.expect_value(t, h.index, u32(2))
}

@(test)
test_peers_ids_never_all_ones :: proc(t: ^testing.T) {
	testing.expect(t, MAX_PEERS == 0xFFFFFE)
	pt: Peer_Table
	testing.expect(t, !peers_init(&pt, Peer_Table_Params{MAX_PEERS + 1, SEC, 0}))
	testing.expect(t, !peers_init(&pt, Peer_Table_Params{0, SEC, 0}))
	// Even the largest table never has an index of 0xFFFFFF: indexes are below
	// the capacity. (Checked with a small table; the bound is the capacity.)
	small := make_table(t, 100)
	defer free_table(small)
	for _ in 0 ..< 100 {
		h, ok := peers_alloc(small, 0)
		testing.expect(t, ok)
		testing.expect(t, h.index < 100 && h.index != 0xFFFFFF)
	}
}

@(test)
test_peers_float :: proc(t: ^testing.T) {
	pt := make_table(t, 8)
	defer free_table(pt)
	h1 := add_peer(t, pt, "a", 1)
	h2 := add_peer(t, pt, "b", 2)
	old, err := peers_float(pt, h1, tkey(50))
	testing.expect_value(t, err, Peer_Error.None)
	testing.expect(t, old == tkey(1))
	k_old, k_new := tkey(1), tkey(50)
	_, p := peers_by_addr(pt, &k_old)
	testing.expect(t, p == nil)
	got, p2 := peers_by_addr(pt, &k_new)
	testing.expect(t, p2 != nil && got == h1)
	// Onto an address of another peer: refused, nothing moves.
	k2 := tkey(2)
	_, err = peers_float(pt, h1, k2)
	testing.expect_value(t, err, Peer_Error.Addr_In_Use)
	got, p2 = peers_by_addr(pt, &k_new)
	testing.expect(t, p2 != nil && got == h1)
	got, p2 = peers_by_addr(pt, &k2)
	testing.expect(t, p2 != nil && got == h2)
	// To its own address: fine.
	_, err = peers_float(pt, h1, k_new)
	testing.expect_value(t, err, Peer_Error.None)
	// A dead handle.
	peers_remove(pt, h1, 0)
	_, err = peers_float(pt, h1, tkey(77))
	testing.expect_value(t, err, Peer_Error.Bad_Handle)
}

@(test)
test_peers_identity_chain :: proc(t: ^testing.T) {
	pt := make_table(t, 16)
	defer free_table(pt)
	// Three sessions of one identity (duplicate-cn) and one of another.
	a := add_peer(t, pt, "alice", 1)
	b := add_peer(t, pt, "alice", 2)
	c := add_peer(t, pt, "alice", 3)
	d := add_peer(t, pt, "bob", 4)
	buf: [8]Peer_Handle
	testing.expect_value(t, peers_identity_handles(pt, "alice", buf[:]), 3)
	testing.expect_value(t, peers_identity_handles(pt, "bob", buf[:]), 1)
	testing.expect_value(t, peers_identity_handles(pt, "carol", buf[:]), 0)
	// A buffer that is too small still reports the true count.
	small: [2]Peer_Handle
	testing.expect_value(t, peers_identity_handles(pt, "alice", small[:]), 3)

	// Remove from the middle, the head and the tail of the chain.
	testing.expect(t, peers_remove(pt, b, 0))
	testing.expect_value(t, peers_identity_handles(pt, "alice", buf[:]), 2)
	testing.expect(t, peers_remove(pt, c, 0)) // the head (newest)
	testing.expect_value(t, peers_identity_handles(pt, "alice", buf[:]), 1)
	testing.expect_value(t, buf[0], a)
	testing.expect(t, peers_remove(pt, a, 0))
	testing.expect_value(t, peers_identity_handles(pt, "alice", buf[:]), 0)
	testing.expect_value(t, peers_identity_handles(pt, "bob", buf[:]), 1)
	testing.expect_value(t, buf[0], d)
}

@(test)
test_peers_next_active :: proc(t: ^testing.T) {
	pt := make_table(t, 8)
	defer free_table(pt)
	hs: [5]Peer_Handle
	for i in 0 ..< 5 {
		hs[i] = add_peer(t, pt, "x", i + 1)
	}
	peers_remove(pt, hs[1], 0)
	peers_remove(pt, hs[3], 0)
	seen := make([dynamic]u32, context.temp_allocator)
	from := u32(0)
	for {
		h, ok := peers_next_active(pt, from)
		if !ok {
			break
		}
		append(&seen, h.index)
		from = h.index + 1
	}
	testing.expect_value(t, len(seen), 3)
	if len(seen) == 3 {
		testing.expect(t, seen[0] == 0 && seen[1] == 2 && seen[2] == 4)
	}
}

// Random connects, disconnects and floats against a model.
@(test)
test_peers_model :: proc(t: ^testing.T) {
	Live :: struct {
		h:    Peer_Handle,
		name: string,
		addr: Addr_Key,
		a4:   [4]u8,
	}
	CAP :: 64
	DELAY :: 20 * SEC
	for seed in u64(1) ..= 6 {
		r := rng_make(seed)
		pt := make_table(t, CAP, DELAY, seed)
		defer free_table(pt)
		live := make([dynamic]Live, context.temp_allocator)
		dead := make([dynamic]Peer_Handle, context.temp_allocator)
		freed_at: [CAP]time.Duration
		ever_freed: [CAP]bool
		names := [?]string{"a", "b", "c", "d", "e", "f"}
		now := time.Duration(0)
		next_addr := 1
		for step in 0 ..< 6000 {
			now += time.Duration(rng_below(&r, 600)) * time.Millisecond
			switch rng_below(&r, 10) {
			case 0 ..< 5:
				h, ok := peers_alloc(pt, now)
				if !ok {
					// Only allowed to fail if every id is in use or waiting.
					in_use := peers_count(pt)
					waiting := 0
					for i in 0 ..< CAP {
						if ever_freed[i] && now - freed_at[i] < DELAY {
							waiting += 1
						}
					}
					testing.expectf(
						t,
						in_use + waiting >= CAP || (in_use == CAP),
						"alloc failed with %d in use, %d waiting",
						in_use,
						waiting,
					)
					break
				}
				testing.expect(t, h.index < CAP && h.index != 0xFFFFFF)
				if ever_freed[h.index] {
					testing.expectf(
						t,
						now - freed_at[h.index] >= DELAY,
						"id %d reused after %v",
						h.index,
						now - freed_at[h.index],
					)
				}
				name := names[rng_below(&r, len(names))]
				n := next_addr
				next_addr += 1
				addr := tkey(n)
				a4 := [4]u8{10, 9, u8(n >> 8), u8(n)}
				err := peers_commit(pt, h, name, addr, a4, nil, u64(n), now)
				testing.expect_value(t, err, Peer_Error.None)
				append(&live, Live{h, name, addr, a4})
			case 5 ..< 8:
				if len(live) == 0 {
					break
				}
				i := rng_below(&r, len(live))
				l := live[i]
				testing.expect(t, peers_remove(pt, l.h, now))
				freed_at[l.h.index] = now
				ever_freed[l.h.index] = true
				append(&dead, l.h)
				unordered_remove(&live, i)
			case 8:
				if len(live) == 0 {
					break
				}
				i := rng_below(&r, len(live))
				n := next_addr
				next_addr += 1
				nk := tkey(n)
				_, err := peers_float(pt, live[i].h, nk)
				testing.expect_value(t, err, Peer_Error.None)
				live[i].addr = nk
			case 9:
				// A stale handle never works.
				if len(dead) > 0 {
					d := dead[rng_below(&r, len(dead))]
					testing.expect(t, peers_get(pt, d) == nil)
					testing.expect(t, !peers_remove(pt, d, now))
				}
			}
			if step % 53 == 0 {
				testing.expect_value(t, peers_count(pt), len(live))
				for l in live {
					p := peers_get(pt, l.h)
					testing.expect(t, p != nil)
					if p == nil {
						continue
					}
					testing.expect_value(t, p.identity, l.name)
					h1, p1 := peers_by_id(pt, l.h.index)
					testing.expect(t, p1 == p && h1 == l.h)
					k := l.addr
					h2, p2 := peers_by_addr(pt, &k)
					testing.expect(t, p2 == p && h2 == l.h)
					h3, p3 := peers_by_vpn4(pt, l.a4)
					testing.expect(t, p3 == p && h3 == l.h)
				}
				// Per identity counts.
				for nm in names {
					want := 0
					for l in live {
						if l.name == nm {
							want += 1
						}
					}
					buf: [CAP]Peer_Handle
					testing.expect_value(t, peers_identity_handles(pt, nm, buf[:]), want)
				}
			}
		}
		// Empty the table: nothing is left in any index.
		for l in live {
			testing.expect(t, peers_remove(pt, l.h, now))
		}
		testing.expect_value(t, peers_count(pt), 0)
		testing.expect_value(t, pt.by_addr.count, u32(0))
		testing.expect_value(t, pt.by_vpn4.count, u32(0))
		testing.expect_value(t, pt.by_ident.count, u32(0))
	}
}

@(test)
test_peers_memory_per_peer :: proc(t: ^testing.T) {
	pt := make_table(t, 1000)
	defer free_table(pt)
	per := f64(peers_memory(pt)) / 1000
	testing.expectf(t, per < 220, "bytes per peer slot: %v", per)
}
