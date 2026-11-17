// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"
import "core:time"
import "noir:proto/config"

make_reg :: proc(t: ^testing.T, max_peers := 16, c2c := false, max_iroutes := 64) -> ^Registry {
	reg := new(Registry)
	ok := registry_init(reg, Registry_Params{max_peers, max_iroutes, 10 * SEC, 1, c2c})
	testing.expect(t, ok)
	return reg
}

free_reg :: proc(reg: ^Registry) {
	registry_destroy(reg)
	free(reg)
}

// Peer n: 10.8.0.n and fd00::n, plus iroutes.
connect_reg :: proc(
	t: ^testing.T,
	reg: ^Registry,
	name: string,
	n: int,
	ir4: []config.Iroute = nil,
	ir6: []config.Iroute6 = nil,
	now := time.Duration(0),
	loc := #caller_location,
) -> (
	h: Peer_Handle,
	rej: Reject_Reason,
) {
	ok: bool
	h, ok = registry_reserve(reg, now)
	testing.expect(t, ok, loc = loc)
	lease := Lease {
		kind4 = .Dynamic,
		kind6 = .Dynamic,
		addr4 = {10, 8, 0, u8(n)},
		addr6 = v6n(n),
	}
	rej = registry_commit(reg, h, name, tkey(n), lease, ir4, ir6, digest_of(u64(n)), true, u64(n), now)
	if rej != .None {
		registry_cancel(reg, h, now)
	}
	return
}

@(test)
test_registry_add_remove :: proc(t: ^testing.T) {
	reg := make_reg(t)
	defer free_reg(reg)
	h, rej := connect_reg(t, reg, "alice", 5, {{{192, 168, 5, 0}, 24}}, {{v6("fd00:55::"), 64}})
	testing.expect_value(t, rej, Reject_Reason.None)
	testing.expect_value(t, peers_count(&reg.peers), 1)
	// Routes: /32, /128, the iroute and the iroute6.
	testing.expect_value(t, route_count4(&reg.routes), 2)
	testing.expect_value(t, route_count6(&reg.routes), 2)
	o, _, ok := route_lookup4(&reg.routes, {192, 168, 5, 77})
	testing.expect(t, ok && o == h.index)

	lease, removed := registry_remove(reg, h, 1 * SEC)
	testing.expect(t, removed)
	testing.expect_value(t, lease.addr4, [4]u8{10, 8, 0, 5})
	testing.expect_value(t, peers_count(&reg.peers), 0)
	testing.expect_value(t, route_count4(&reg.routes), 0)
	testing.expect_value(t, route_count6(&reg.routes), 0)
	_, _, ok = route_lookup4(&reg.routes, {192, 168, 5, 77})
	testing.expect(t, !ok)
	// A second remove does nothing.
	_, removed = registry_remove(reg, h, 2 * SEC)
	testing.expect(t, !removed)
}

@(test)
test_registry_from_tun :: proc(t: ^testing.T) {
	reg := make_reg(t)
	defer free_reg(reg)
	a, _ := connect_reg(t, reg, "a", 2, {{{192, 168, 2, 0}, 24}}, {{v6("fd00:2::"), 48}})
	b, _ := connect_reg(t, reg, "b", 3)
	dest, v := registry_from_tun(reg, ip4_packet({8, 8, 8, 8}, {10, 8, 0, 3}))
	testing.expect_value(t, v, Verdict.To_Peer)
	testing.expect_value(t, dest, b)
	dest, v = registry_from_tun(reg, ip4_packet({8, 8, 8, 8}, {192, 168, 2, 9}))
	testing.expect_value(t, v, Verdict.To_Peer)
	testing.expect_value(t, dest, a)
	dest, v = registry_from_tun(reg, ip6_packet(v6("2001:db8::1"), v6n(3)))
	testing.expect_value(t, v, Verdict.To_Peer)
	testing.expect_value(t, dest, b)
	dest, v = registry_from_tun(reg, ip6_packet(v6("2001:db8::1"), v6("fd00:2:0:5::7")))
	testing.expect_value(t, v, Verdict.To_Peer)
	testing.expect_value(t, dest, a)
	// Nobody owns these.
	_, v = registry_from_tun(reg, ip4_packet({8, 8, 8, 8}, {10, 8, 0, 99}))
	testing.expect_value(t, v, Verdict.Drop_No_Route)
	_, v = registry_from_tun(reg, ip4_packet({8, 8, 8, 8}, {224, 0, 0, 1}))
	testing.expect_value(t, v, Verdict.Drop_No_Route)
	_, v = registry_from_tun(reg, ip6_packet(v6("2001:db8::1"), v6("ff02::1")))
	testing.expect_value(t, v, Verdict.Drop_No_Route)
	// Garbage.
	_, v = registry_from_tun(reg, nil)
	testing.expect_value(t, v, Verdict.Drop_Bad_Packet)
	_, v = registry_from_tun(reg, []u8{0x45, 0, 0})
	testing.expect_value(t, v, Verdict.Drop_Bad_Packet)
	testing.expect_value(t, reg.counters[.Drop_No_Route], u64(3))
	testing.expect_value(t, reg.counters[.Drop_Bad_Packet], u64(2))
	testing.expect_value(t, reg.counters[.To_Peer], u64(4))

	// After a disconnect the route is gone, even for the iroute.
	registry_remove(reg, a, 1 * SEC)
	_, v = registry_from_tun(reg, ip4_packet({8, 8, 8, 8}, {192, 168, 2, 9}))
	testing.expect_value(t, v, Verdict.Drop_No_Route)
}

@(test)
test_registry_source_check :: proc(t: ^testing.T) {
	reg := make_reg(t)
	defer free_reg(reg)
	a, _ := connect_reg(t, reg, "a", 2, {{{192, 168, 2, 0}, 24}}, {{v6("fd00:2::"), 48}})
	b, _ := connect_reg(t, reg, "b", 3)
	_ = b
	// Its own addresses and its iroutes are fine. (Without client-to-client
	// everything valid goes to the tun.)
	ok_src4 := [?][4]u8{{10, 8, 0, 2}, {192, 168, 2, 1}, {192, 168, 2, 254}}
	for s in ok_src4 {
		_, v := registry_from_peer(reg, a, ip4_packet(s, {8, 8, 8, 8}))
		testing.expectf(t, v == .To_Tun, "src %v: %v", s, v)
	}
	// Everyone else's addresses are not.
	bad_src4 := [?][4]u8{{10, 8, 0, 3}, {10, 8, 0, 4}, {10, 8, 0, 1}, {0, 0, 0, 0}, {192, 168, 3, 1}, {192, 168, 1, 255}, {8, 8, 8, 8}, {255, 255, 255, 255}}
	for s in bad_src4 {
		_, v := registry_from_peer(reg, a, ip4_packet(s, {8, 8, 8, 8}))
		testing.expectf(t, v == .Drop_Bad_Source, "src %v: %v", s, v)
	}
	// IPv6.
	_, v := registry_from_peer(reg, a, ip6_packet(v6n(2), v6("2001:db8::1")))
	testing.expect_value(t, v, Verdict.To_Tun)
	_, v = registry_from_peer(reg, a, ip6_packet(v6("fd00:2:0:9::1"), v6("2001:db8::1")))
	testing.expect_value(t, v, Verdict.To_Tun)
	for s in ([?]string{"fd00::3", "fd00:3::1", "fe80::1", "::", "2001:db8::1"}) {
		_, v = registry_from_peer(reg, a, ip6_packet(v6(s), v6("2001:db8::1")))
		testing.expectf(t, v == .Drop_Bad_Source, "src %v: %v", s, v)
	}
	// A peer that has no IPv6 may not send IPv6 at all.
	h, _ := registry_reserve(reg, 0)
	lease := Lease {
		kind4 = .Dynamic,
		addr4 = {10, 8, 0, 9},
	}
	testing.expect_value(t, registry_commit(reg, h, "v4only", tkey(9), lease, nil, nil, {}, false, 0, 0), Reject_Reason.None)
	_, v = registry_from_peer(reg, h, ip6_packet(v6n(9), v6("2001:db8::1")))
	testing.expect_value(t, v, Verdict.Drop_Bad_Source)
	_, v = registry_from_peer(reg, h, ip4_packet({10, 8, 0, 9}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.To_Tun)

	// Garbage and dead handles.
	_, v = registry_from_peer(reg, a, nil)
	testing.expect_value(t, v, Verdict.Drop_Bad_Packet)
	_, v = registry_from_peer(reg, a, []u8{0x75})
	testing.expect_value(t, v, Verdict.Drop_Bad_Packet)
	short4 := ip4_packet({10, 8, 0, 2}, {8, 8, 8, 8})[:19]
	_, v = registry_from_peer(reg, a, short4)
	testing.expect_value(t, v, Verdict.Drop_Bad_Packet)
	bad_ihl := ip4_packet({10, 8, 0, 2}, {8, 8, 8, 8})
	bad_ihl[0] = 0x44
	_, v = registry_from_peer(reg, a, bad_ihl)
	testing.expect_value(t, v, Verdict.Drop_Bad_Packet)
	short6 := ip6_packet(v6n(2), v6("2001:db8::1"))[:39]
	_, v = registry_from_peer(reg, a, short6)
	testing.expect_value(t, v, Verdict.Drop_Bad_Packet)
	registry_remove(reg, a, 1 * SEC)
	_, v = registry_from_peer(reg, a, ip4_packet({10, 8, 0, 2}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.Drop_Bad_Source)
	testing.expect(t, reg.counters[.Drop_Bad_Source] >= 13)
}

@(test)
test_registry_iroute_overlap_source :: proc(t: ^testing.T) {
	// a owns 192.168.0.0/16, b owns 192.168.5.0/24 inside it. a must not be
	// able to send from b's part.
	reg := make_reg(t)
	defer free_reg(reg)
	a, _ := connect_reg(t, reg, "a", 2, {{{192, 168, 0, 0}, 16}})
	b, _ := connect_reg(t, reg, "b", 3, {{{192, 168, 5, 0}, 24}})
	_, v := registry_from_peer(reg, a, ip4_packet({192, 168, 7, 1}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.To_Tun)
	_, v = registry_from_peer(reg, a, ip4_packet({192, 168, 5, 1}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.Drop_Bad_Source)
	_, v = registry_from_peer(reg, b, ip4_packet({192, 168, 5, 1}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.To_Tun)
	_, v = registry_from_peer(reg, b, ip4_packet({192, 168, 7, 1}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.Drop_Bad_Source)
}

@(test)
test_registry_client_to_client :: proc(t: ^testing.T) {
	for c2c in ([?]bool{false, true}) {
		reg := make_reg(t, c2c = c2c)
		defer free_reg(reg)
		a, _ := connect_reg(t, reg, "a", 2, {{{192, 168, 2, 0}, 24}})
		b, _ := connect_reg(t, reg, "b", 3)
		// a -> b (VPN address)
		dest, v := registry_from_peer(reg, a, ip4_packet({10, 8, 0, 2}, {10, 8, 0, 3}))
		if c2c {
			testing.expect_value(t, v, Verdict.To_Peer)
			testing.expect_value(t, dest, b)
		} else {
			testing.expect_value(t, v, Verdict.Drop_C2C)
		}
		// b -> a's network
		dest, v = registry_from_peer(reg, b, ip4_packet({10, 8, 0, 3}, {192, 168, 2, 5}))
		if c2c {
			testing.expect_value(t, v, Verdict.To_Peer)
			testing.expect_value(t, dest, a)
		} else {
			testing.expect_value(t, v, Verdict.Drop_C2C)
		}
		// IPv6 both ways.
		dest, v = registry_from_peer(reg, a, ip6_packet(v6n(2), v6n(3)))
		testing.expect_value(t, v, Verdict.To_Peer if c2c else Verdict.Drop_C2C)
		// To a destination nobody owns: the tun, always.
		_, v = registry_from_peer(reg, a, ip4_packet({10, 8, 0, 2}, {8, 8, 8, 8}))
		testing.expect_value(t, v, Verdict.To_Tun)
		_, v = registry_from_peer(reg, a, ip4_packet({10, 8, 0, 2}, {10, 8, 0, 77}))
		testing.expect_value(t, v, Verdict.To_Tun)
		// To itself: a loop, with and without c2c.
		_, v = registry_from_peer(reg, a, ip4_packet({10, 8, 0, 2}, {10, 8, 0, 2}))
		testing.expect_value(t, v, Verdict.Drop_Loop)
		_, v = registry_from_peer(reg, a, ip4_packet({192, 168, 2, 1}, {192, 168, 2, 9}))
		testing.expect_value(t, v, Verdict.Drop_Loop)
		// A spoofed source is dropped before the destination is looked at.
		_, v = registry_from_peer(reg, a, ip4_packet({10, 8, 0, 3}, {10, 8, 0, 3}))
		testing.expect_value(t, v, Verdict.Drop_Bad_Source)
	}
}

@(test)
test_registry_commit_conflicts_roll_back :: proc(t: ^testing.T) {
	reg := make_reg(t)
	defer free_reg(reg)
	a, _ := connect_reg(t, reg, "a", 2, {{{192, 168, 2, 0}, 24}}, {{v6("fd00:2::"), 48}})
	before4, before6 := route_count4(&reg.routes), route_count6(&reg.routes)
	count := peers_count(&reg.peers)

	// An iroute that another peer owns.
	_, rej := connect_reg(t, reg, "b", 3, {{{172, 16, 0, 0}, 16}, {{192, 168, 2, 0}, 24}})
	testing.expect_value(t, rej, Reject_Reason.Route_Conflict)
	// An iroute6 that another peer owns.
	_, rej = connect_reg(t, reg, "b6", 4, nil, {{v6("fd00:9::"), 48}, {v6("fd00:2::"), 48}})
	testing.expect_value(t, rej, Reject_Reason.Route_Conflict)
	h2, _ := connect_reg(t, reg, "c", 5, nil, {{v6("fd00:9::"), 48}})
	testing.expect(t, peers_get(&reg.peers, h2) != nil)
	registry_remove(reg, h2, 0)
	// Nothing of the failed attempts is left, and the reserved ids were returned.
	testing.expect_value(t, route_count4(&reg.routes), before4)
	testing.expect_value(t, route_count6(&reg.routes), before6)
	testing.expect_value(t, peers_count(&reg.peers), count)
	_, _, ok := route_lookup4(&reg.routes, {172, 16, 3, 3})
	testing.expect(t, !ok)
	_, _, ok = route_lookup4(&reg.routes, {10, 8, 0, 3})
	testing.expect(t, !ok)
	// The same VPN address as a live peer.
	h, ok2 := registry_reserve(reg, 0)
	testing.expect(t, ok2)
	lease := Lease {
		kind4 = .Dynamic,
		addr4 = {10, 8, 0, 2},
	}
	testing.expect_value(t, registry_commit(reg, h, "dup", tkey(30), lease, nil, nil, {}, false, 0, 0), Reject_Reason.Route_Conflict)
	registry_cancel(reg, h, 0)
	// The same transport address as a live peer.
	h, ok2 = registry_reserve(reg, 0)
	lease.addr4 = {10, 8, 0, 40}
	testing.expect_value(t, registry_commit(reg, h, "dup2", tkey(2), lease, nil, nil, {}, false, 0, 0), Reject_Reason.Route_Conflict)
	registry_cancel(reg, h, 0)
	_, _, found := route_lookup4(&reg.routes, {10, 8, 0, 40})
	testing.expect(t, !found)
	// Peer a is untouched.
	_, v := registry_from_tun(reg, ip4_packet({8, 8, 8, 8}, {192, 168, 2, 1}))
	testing.expect_value(t, v, Verdict.To_Peer)
	_ = a
}

@(test)
test_registry_repeated_iroute_is_one_route :: proc(t: ^testing.T) {
	reg := make_reg(t)
	defer free_reg(reg)
	h, rej := connect_reg(t, reg, "a", 2, {{{192, 168, 2, 0}, 24}, {{192, 168, 2, 0}, 24}, {{10, 8, 0, 2}, 32}})
	testing.expect_value(t, rej, Reject_Reason.None)
	// /32 of the peer, one /24 (the repeat and the peer's own /32 are not added again).
	testing.expect_value(t, route_count4(&reg.routes), 2)
	registry_remove(reg, h, 0)
	testing.expect_value(t, route_count4(&reg.routes), 0)
}

@(test)
test_registry_route_table_full :: proc(t: ^testing.T) {
	reg := make_reg(t, 8, false, 2)
	defer free_reg(reg)
	// Room is 8 + 2 routes. Peers use one each; one peer asks for too many iroutes.
	_, rej := connect_reg(t, reg, "a", 2, {{{192, 168, 1, 0}, 24}, {{192, 168, 2, 0}, 24}, {{192, 168, 3, 0}, 24}})
	testing.expect_value(t, rej, Reject_Reason.None) // 4 routes so far: fine
	for i in 0 ..< 6 {
		_, rej = connect_reg(t, reg, "x", 10 + i)
		testing.expect_value(t, rej, Reject_Reason.None)
	}
	_, rej = connect_reg(t, reg, "y", 20)
	testing.expect_value(t, rej, Reject_Reason.Too_Many_Routes)
	testing.expect_value(t, peers_count(&reg.peers), 7)
}

@(test)
test_registry_float_keeps_routes :: proc(t: ^testing.T) {
	reg := make_reg(t)
	defer free_reg(reg)
	a, _ := connect_reg(t, reg, "a", 2)
	old, err := registry_float(reg, a, tkey(80))
	testing.expect_value(t, err, Peer_Error.None)
	testing.expect(t, old == tkey(2))
	k := tkey(80)
	got, p := peers_by_addr(&reg.peers, &k)
	testing.expect(t, p != nil && got == a)
	_, v := registry_from_peer(reg, a, ip4_packet({10, 8, 0, 2}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.To_Tun)
}

@(test)
test_registry_live_keys :: proc(t: ^testing.T) {
	reg := make_reg(t)
	defer free_reg(reg)
	a, _ := connect_reg(t, reg, "a", 2)
	b, _ := connect_reg(t, reg, "b", 3)
	// A peer that did not connect by pin is not listed.
	h, _ := registry_reserve(reg, 0)
	lease := Lease {
		kind4 = .Dynamic,
		addr4 = {10, 8, 0, 9},
	}
	registry_commit(reg, h, "ca-client", tkey(9), lease, nil, nil, {}, false, 0, 0)
	registry_remove(reg, a, 1 * SEC)
	keys := registry_live_keys(reg)
	defer delete(keys)
	testing.expect_value(t, len(keys), 1)
	if len(keys) == 1 {
		testing.expect_value(t, keys[0].handle, b)
		testing.expect_value(t, keys[0].identity, "b")
		testing.expect_value(t, keys[0].spki, digest_of(3))
	}
}

@(test)
test_registry_ip_header_parse :: proc(t: ^testing.T) {
	h, ok := ip_header_parse(ip4_packet({1, 2, 3, 4}, {5, 6, 7, 8}))
	testing.expect(t, ok && !h.v6)
	testing.expect(t, h.src[0] == 1 && h.src[1] == 2 && h.src[2] == 3 && h.src[3] == 4)
	testing.expect(t, h.dst[0] == 5 && h.dst[1] == 6 && h.dst[2] == 7 && h.dst[3] == 8)
	h, ok = ip_header_parse(ip6_packet(v6("2001:db8::1"), v6("2001:db8::2")))
	testing.expect(t, ok && h.v6)
	testing.expect(t, h.src == v6("2001:db8::1") && h.dst == v6("2001:db8::2"))
	for first in ([?]u8{0x00, 0x10, 0x30, 0x50, 0x70, 0x90, 0xf0}) {
		p := ip4_packet({1, 2, 3, 4}, {5, 6, 7, 8})
		p[0] = first
		_, ok = ip_header_parse(p)
		testing.expectf(t, !ok, "first byte %x", first)
	}
}

// Random connects, disconnects and packets, with every verdict checked against
// a brute-force model.
@(test)
test_registry_model :: proc(t: ^testing.T) {
	Member :: struct {
		h:    Peer_Handle,
		n:    int,
		ir4:  [dynamic]config.Iroute,
	}
	for seed in u64(1) ..= 6 {
		r := rng_make(seed + 40)
		c2c := seed % 2 == 0
		reg := make_reg(t, 96, c2c, 200)
		defer free_reg(reg)
		live := make([dynamic]Member, context.temp_allocator)
		used_n := make(map[int]bool, context.temp_allocator)
		for step in 0 ..< 3000 {
			now := time.Duration(step) * 100 * time.Millisecond
			switch rng_below(&r, 6) {
			case 0, 1:
				// A new peer with up to 2 iroutes in 192.168.x.0/24 (x = 0..15).
				n := 2 + rng_below(&r, 60)
				if used_n[n] || len(live) >= 16 {
					break
				}
				irs := make([dynamic]config.Iroute, context.temp_allocator)
				for _ in 0 ..< rng_below(&r, 3) {
					append(&irs, config.Iroute{{192, 168, u8(rng_below(&r, 16)), 0}, 24})
				}
				h, rej := connect_reg(t, reg, "p", n, irs[:], nil, now)
				if rej == .None {
					m := Member{h, n, make([dynamic]config.Iroute, context.temp_allocator)}
					// Repeats within one peer's list are stored once.
					for ir in irs {
						dup := false
						for x in m.ir4 {
							dup ||= x == ir
						}
						if !dup {
							append(&m.ir4, ir)
						}
					}
					append(&live, m)
					used_n[n] = true
				} else {
					// A conflict means another live peer owns one of the prefixes.
					found := false
					for ir in irs {
						for m in live {
							for x in m.ir4 {
								found ||= x == ir
							}
						}
					}
					testing.expect(t, found || rej == .Too_Many_Routes || rej == .Route_Conflict)
				}
			case 2:
				if len(live) == 0 {
					break
				}
				i := rng_below(&r, len(live))
				_, ok := registry_remove(reg, live[i].h, now)
				testing.expect(t, ok)
				delete_key(&used_n, live[i].n)
				unordered_remove(&live, i)
			case:
				if len(live) == 0 {
					break
				}
				src_peer := live[rng_below(&r, len(live))]
				// Pick a source: own address, an own iroute, another peer's address, junk.
				src: [4]u8
				switch rng_below(&r, 4) {
				case 0:
					src = {10, 8, 0, u8(src_peer.n)}
				case 1:
					if len(src_peer.ir4) > 0 {
						ir := src_peer.ir4[rng_below(&r, len(src_peer.ir4))]
						src = {ir.network[0], ir.network[1], ir.network[2], u8(1 + rng_below(&r, 250))}
					} else {
						src = {10, 8, 0, u8(src_peer.n)}
					}
				case 2:
					src = {10, 8, 0, u8(2 + rng_below(&r, 60))}
				case:
					src = {192, 168, u8(rng_below(&r, 16)), u8(rng_below(&r, 256))}
				}
				dst: [4]u8
				switch rng_below(&r, 3) {
				case 0:
					dst = {10, 8, 0, u8(2 + rng_below(&r, 60))}
				case 1:
					dst = {192, 168, u8(rng_below(&r, 16)), u8(rng_below(&r, 256))}
				case:
					dst = {8, 8, 8, 8}
				}
				// The model.
				src_ok := false
				if src == {10, 8, 0, u8(src_peer.n)} {
					src_ok = true
				}
				owner_of :: proc(live: [dynamic]Member, a: [4]u8) -> int {
					// Longest prefix among peer addresses (/32) and iroutes (/24).
					for m, i in live {
						if a == {10, 8, 0, u8(m.n)} {
							return i
						}
					}
					for m, i in live {
						for ir in m.ir4 {
							if a[0] == ir.network[0] && a[1] == ir.network[1] && a[2] == ir.network[2] {
								return i
							}
						}
					}
					return -1
				}
				if !src_ok {
					for ir in src_peer.ir4 {
						if src[0] == ir.network[0] && src[1] == ir.network[1] && src[2] == ir.network[2] {
							src_ok = true
						}
					}
				}
				// An iroute /24 shared by two peers cannot exist (conflict), so the
				// owner of a source inside an iroute is unique.
				pkt := ip4_packet(src, dst)
				dest, v := registry_from_peer(reg, src_peer.h, pkt)
				want: Verdict
				want_dest := -1
				switch {
				case !src_ok:
					want = .Drop_Bad_Source
				case:
					o := owner_of(live, dst)
					self := -1
					for m, i in live {
						if m.h == src_peer.h {
							self = i
						}
					}
					switch {
					case o < 0:
						want = .To_Tun
					case o == self:
						want = .Drop_Loop
					case !c2c:
						want = .Drop_C2C
					case:
						want, want_dest = .To_Peer, o
					}
				}
				testing.expectf(t, v == want, "step %d: from %v src %v dst %v: got %v want %v", step, src_peer.n, src, dst, v, want)
				if v == .To_Peer && want_dest >= 0 {
					testing.expect_value(t, dest, live[want_dest].h)
				}
				// And from the tun.
				dest, v = registry_from_tun(reg, ip4_packet({8, 8, 8, 8}, dst))
				o := owner_of(live, dst)
				if o < 0 {
					testing.expect_value(t, v, Verdict.Drop_No_Route)
				} else {
					testing.expect_value(t, v, Verdict.To_Peer)
					testing.expect_value(t, dest, live[o].h)
				}
			}
		}
		for m in live {
			registry_remove(reg, m.h, 0)
		}
		testing.expect_value(t, route_count4(&reg.routes), 0)
		testing.expect_value(t, route_count6(&reg.routes), 0)
	}
}
