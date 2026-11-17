// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"

mask_v4 :: proc(a: [4]u8, p: int) -> [4]u8 {
	v := key4(a) & mask4_of(u32(p))
	return {u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v)}
}

mask_v6 :: proc(a: [16]u8, p: int) -> (r: [16]u8) {
	for i in 0 ..< 16 {
		keep := clamp(p - 8 * i, 0, 8)
		m := u8(0xff) << u8(8 - keep) if keep < 8 else u8(0xff)
		r[i] = a[i] & m
	}
	return
}

@(test)
test_route_v4_basic :: proc(t: ^testing.T) {
	rt: Route_Table
	testing.expect(t, route_table_init(&rt, 100, 100))
	defer route_table_destroy(&rt)

	testing.expect_value(t, route_add4(&rt, {10, 8, 0, 5}, 32, 7), Route_Error.None)
	testing.expect_value(t, route_add4(&rt, {192, 168, 10, 0}, 24, 7), Route_Error.None)
	testing.expect_value(t, route_add4(&rt, {192, 168, 10, 64}, 26, 9), Route_Error.None)
	testing.expect_value(t, route_add4(&rt, {0, 0, 0, 0}, 0, 3), Route_Error.None)

	o, p, ok := route_lookup4(&rt, {10, 8, 0, 5})
	testing.expect(t, ok && o == 7 && p == 32)
	o, p, ok = route_lookup4(&rt, {192, 168, 10, 99}) // in the /26
	testing.expect(t, ok && o == 9 && p == 26)
	o, p, ok = route_lookup4(&rt, {192, 168, 10, 5}) // only the /24
	testing.expect(t, ok && o == 7 && p == 24)
	o, p, ok = route_lookup4(&rt, {8, 8, 8, 8}) // the default route
	testing.expect(t, ok && o == 3 && p == 0)

	// Without the default route the same address has no owner.
	testing.expect(t, route_remove4(&rt, {0, 0, 0, 0}, 0, 3))
	_, _, ok = route_lookup4(&rt, {8, 8, 8, 8})
	testing.expect(t, !ok)
}

@(test)
test_route_v4_errors :: proc(t: ^testing.T) {
	rt: Route_Table
	testing.expect(t, route_table_init(&rt, 4, 4))
	defer route_table_destroy(&rt)
	testing.expect_value(t, route_add4(&rt, {10, 0, 0, 0}, 33, 1), Route_Error.Bad_Prefix)
	testing.expect_value(t, route_add4(&rt, {10, 0, 0, 1}, 24, 1), Route_Error.Host_Bits)
	testing.expect_value(t, route_add4(&rt, {10, 0, 0, 0}, 24, NONE), Route_Error.Bad_Prefix)
	testing.expect_value(t, route_add4(&rt, {10, 0, 0, 0}, 24, 1), Route_Error.None)
	testing.expect_value(t, route_add4(&rt, {10, 0, 0, 0}, 24, 1), Route_Error.Duplicate)
	testing.expect_value(t, route_add4(&rt, {10, 0, 0, 0}, 24, 2), Route_Error.Conflict)
	// Same network, other length: a different route.
	testing.expect_value(t, route_add4(&rt, {10, 0, 0, 0}, 16, 2), Route_Error.None)
	// Another owner cannot remove it.
	testing.expect(t, !route_remove4(&rt, {10, 0, 0, 0}, 24, 2))
	testing.expect(t, route_remove4(&rt, {10, 0, 0, 0}, 24, 1))
	testing.expect(t, !route_remove4(&rt, {10, 0, 0, 0}, 24, 1))
	// The table is full at its maximum.
	testing.expect_value(t, route_add4(&rt, {11, 0, 0, 0}, 8, 1), Route_Error.None)
	testing.expect_value(t, route_add4(&rt, {12, 0, 0, 0}, 8, 1), Route_Error.None)
	testing.expect_value(t, route_add4(&rt, {13, 0, 0, 0}, 8, 1), Route_Error.None)
	testing.expect_value(t, route_add4(&rt, {14, 0, 0, 0}, 8, 1), Route_Error.Full)
	testing.expect_value(t, route_count4(&rt), 4)
}

@(test)
test_route_v6_basic :: proc(t: ^testing.T) {
	rt: Route_Table
	testing.expect(t, route_table_init(&rt, 16, 16))
	defer route_table_destroy(&rt)
	a := v6("fd00:8::5")
	n1 := v6("fd00:30::")
	n2 := v6("fd00:30:0:1::")
	n3 := v6("fd00:30:0:1:8000::")
	testing.expect_value(t, route_add6(&rt, a, 128, 1), Route_Error.None)
	testing.expect_value(t, route_add6(&rt, n1, 32, 2), Route_Error.None)
	testing.expect_value(t, route_add6(&rt, n2, 64, 3), Route_Error.None)
	testing.expect_value(t, route_add6(&rt, n3, 65, 4), Route_Error.None)
	testing.expect_value(t, route_add6(&rt, v6("::"), 0, 9), Route_Error.None)

	o, p, ok := route_lookup6(&rt, &a)
	testing.expect(t, ok && o == 1 && p == 128)
	x := v6("fd00:30:0:1:8000::99") // inside the /65
	o, p, ok = route_lookup6(&rt, &x)
	testing.expect(t, ok && o == 4 && p == 65)
	x = v6("fd00:30:0:1:1::99") // in the /64, not in the /65
	o, p, ok = route_lookup6(&rt, &x)
	testing.expect(t, ok && o == 3 && p == 64)
	x = v6("fd00:30:5::1") // only the /32
	o, p, ok = route_lookup6(&rt, &x)
	testing.expect(t, ok && o == 2 && p == 32)
	x = v6("2001:db8::1") // default
	o, p, ok = route_lookup6(&rt, &x)
	testing.expect(t, ok && o == 9 && p == 0)

	bad := v6("fd00:30::1")
	testing.expect_value(t, route_add6(&rt, bad, 32, 1), Route_Error.Host_Bits)
	testing.expect_value(t, route_add6(&rt, n1, 129, 1), Route_Error.Bad_Prefix)
	testing.expect_value(t, route_add6(&rt, n1, 32, 5), Route_Error.Conflict)
	testing.expect_value(t, route_add6(&rt, n1, 32, 2), Route_Error.Duplicate)
	testing.expect(t, route_remove6(&rt, n3, 65, 4))
	x = v6("fd00:30:0:1:8000::99")
	o, p, ok = route_lookup6(&rt, &x)
	testing.expect(t, ok && o == 3 && p == 64)
}

// Random prefixes in a small address space (so they overlap a lot) against a
// brute-force search of a plain list.
@(test)
test_route_v4_vs_brute_force :: proc(t: ^testing.T) {
	Entry :: struct {
		net:    [4]u8,
		prefix: int,
		owner:  u32,
	}
	for seed in u64(1) ..= 10 {
		r := rng_make(seed)
		rt: Route_Table
		testing.expect(t, route_table_init(&rt, 600, 8, u32(seed)))
		defer route_table_destroy(&rt)
		list := make([dynamic]Entry, context.temp_allocator)
		random_net :: proc(r: ^Rng) -> ([4]u8, int) {
			// Addresses in 10.0.0.0/12 with lengths from 8 to 32, so many overlap.
			p := 8 + rng_below(r, 25)
			a := [4]u8{10, u8(rng_below(r, 16)), u8(rng_below(r, 256)), u8(rng_below(r, 256))}
			return mask_v4(a, p), p
		}
		for step in 0 ..< 4000 {
			switch rng_below(&r, 3) {
			case 0, 1:
				net, p := random_net(&r)
				owner := u32(rng_below(&r, 50))
				err := route_add4(&rt, net, u8(p), owner)
				exists := -1
				for e, i in list {
					if e.net == net && e.prefix == p {
						exists = i
					}
				}
				switch {
				case exists >= 0 && list[exists].owner == owner:
					testing.expect_value(t, err, Route_Error.Duplicate)
				case exists >= 0:
					testing.expect_value(t, err, Route_Error.Conflict)
				case len(list) >= 600:
					testing.expect_value(t, err, Route_Error.Full)
				case:
					testing.expect_value(t, err, Route_Error.None)
					append(&list, Entry{net, p, owner})
				}
			case 2:
				if len(list) == 0 {
					break
				}
				i := rng_below(&r, len(list))
				e := list[i]
				testing.expect(t, route_remove4(&rt, e.net, u8(e.prefix), e.owner))
				unordered_remove(&list, i)
			}
			if step % 20 == 0 {
				testing.expect_value(t, route_count4(&rt), len(list))
				for _ in 0 ..< 30 {
					q := [4]u8{10, u8(rng_below(&r, 16)), u8(rng_below(&r, 256)), u8(rng_below(&r, 256))}
					best := -1
					best_len := -1
					for e, i in list {
						if mask_v4(q, e.prefix) == e.net && e.prefix > best_len {
							best, best_len = i, e.prefix
						}
					}
					o, p, ok := route_lookup4(&rt, q)
					testing.expect_value(t, ok, best >= 0)
					if ok && best >= 0 {
						testing.expect_value(t, o, list[best].owner)
						testing.expect_value(t, int(p), best_len)
					}
				}
			}
		}
		// Remove everything: the table is empty again.
		for e in list {
			testing.expect(t, route_remove4(&rt, e.net, u8(e.prefix), e.owner))
		}
		testing.expect_value(t, route_count4(&rt), 0)
		testing.expect_value(t, rt.lens4, u64(0))
	}
}

@(test)
test_route_v6_vs_brute_force :: proc(t: ^testing.T) {
	Entry :: struct {
		net:    [16]u8,
		prefix: int,
		owner:  u32,
	}
	for seed in u64(1) ..= 8 {
		r := rng_make(seed + 100)
		rt: Route_Table
		testing.expect(t, route_table_init(&rt, 8, 500, u32(seed)))
		defer route_table_destroy(&rt)
		list := make([dynamic]Entry, context.temp_allocator)
		base := v6("fd00:1234::")
		random_addr :: proc(r: ^Rng, base: [16]u8) -> (a: [16]u8) {
			a = base
			// Vary bytes 4..8 a little and the rest widely.
			a[4] = u8(rng_below(r, 3))
			a[5] = u8(rng_below(r, 4))
			a[6] = u8(rng_below(r, 256))
			for i in 7 ..< 16 {
				a[i] = u8(rng_below(r, 256)) if rng_below(r, 3) == 0 else 0
			}
			return
		}
		for step in 0 ..< 3000 {
			switch rng_below(&r, 3) {
			case 0, 1:
				p := 32 + rng_below(&r, 97)
				net := mask_v6(random_addr(&r, base), p)
				owner := u32(rng_below(&r, 50))
				err := route_add6(&rt, net, u8(p), owner)
				exists := -1
				for e, i in list {
					if e.net == net && e.prefix == p {
						exists = i
					}
				}
				switch {
				case exists >= 0 && list[exists].owner == owner:
					testing.expect_value(t, err, Route_Error.Duplicate)
				case exists >= 0:
					testing.expect_value(t, err, Route_Error.Conflict)
				case len(list) >= 500:
					testing.expect_value(t, err, Route_Error.Full)
				case:
					testing.expect_value(t, err, Route_Error.None)
					append(&list, Entry{net, p, owner})
				}
			case 2:
				if len(list) == 0 {
					break
				}
				i := rng_below(&r, len(list))
				e := list[i]
				testing.expect(t, route_remove6(&rt, e.net, u8(e.prefix), e.owner))
				unordered_remove(&list, i)
			}
			if step % 20 == 0 {
				for _ in 0 ..< 30 {
					q := random_addr(&r, base)
					best := -1
					best_len := -1
					for e, i in list {
						if mask_v6(q, e.prefix) == e.net && e.prefix > best_len {
							best, best_len = i, e.prefix
						}
					}
					o, p, ok := route_lookup6(&rt, &q)
					testing.expect_value(t, ok, best >= 0)
					if ok && best >= 0 {
						testing.expect_value(t, o, list[best].owner)
						testing.expect_value(t, int(p), best_len)
					}
				}
			}
		}
		for e in list {
			testing.expect(t, route_remove6(&rt, e.net, u8(e.prefix), e.owner))
		}
		testing.expect_value(t, route_count6(&rt), 0)
		testing.expect_value(t, rt.lens6, [3]u64{})
	}
}

// 64k peers and a few thousand iroutes: every address resolves to its owner.
@(test)
test_route_64k_peers :: proc(t: ^testing.T) {
	N :: 65536
	rt: Route_Table
	testing.expect(t, route_table_init(&rt, N + 4096, N + 4096))
	defer route_table_destroy(&rt)
	for i in 0 ..< N {
		a := [4]u8{10, u8(8 + (i >> 16)), u8(i >> 8), u8(i)}
		testing.expect_value(t, route_add4(&rt, a, 32, u32(i)), Route_Error.None)
		testing.expect_value(t, route_add6(&rt, v6n(i), 128, u32(i)), Route_Error.None)
	}
	for i in 0 ..< 4096 {
		// 172.(16..31).x.0/24 -> owner i.
		testing.expect_value(t, route_add4(&rt, {172, u8(16 + (i >> 8)), u8(i), 0}, 24, u32(i)), Route_Error.None)
	}
	for i := 0; i < N; i += 7 {
		a := [4]u8{10, u8(8 + (i >> 16)), u8(i >> 8), u8(i)}
		o, p, ok := route_lookup4(&rt, a)
		testing.expect(t, ok && o == u32(i) && p == 32)
		a6 := v6n(i)
		o, p, ok = route_lookup6(&rt, &a6)
		testing.expect(t, ok && o == u32(i) && p == 128)
	}
	for i := 0; i < 4096; i += 13 {
		o, p, ok := route_lookup4(&rt, {172, u8(16 + (i >> 8)), u8(i), 77})
		testing.expect(t, ok && o == u32(i) && p == 24)
	}
	_, _, ok := route_lookup4(&rt, {11, 0, 0, 1})
	testing.expect(t, !ok)
}

@(test)
test_route_empty_table :: proc(t: ^testing.T) {
	rt: Route_Table
	testing.expect(t, route_table_init(&rt, 2, 2))
	defer route_table_destroy(&rt)
	_, _, ok := route_lookup4(&rt, {1, 2, 3, 4})
	testing.expect(t, !ok)
	a := v6("::1")
	_, _, ok = route_lookup6(&rt, &a)
	testing.expect(t, !ok)
	testing.expect(t, !route_remove4(&rt, {1, 2, 3, 0}, 24, 1))
	_, found := route_get4(&rt, {1, 2, 3, 0}, 24)
	testing.expect(t, !found)
}
