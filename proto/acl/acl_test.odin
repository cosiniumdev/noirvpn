// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

import "core:crypto/siphash"
import "core:log"
import "core:math/rand"
import "core:testing"

// ------------------------------------------------------- packet builders

A4 :: proc(a, b, c, d: u8) -> Addr {
	return map4([]u8{a, b, c, d})
}

A6 :: proc(last: u8) -> (x: Addr) {
	x[0], x[1] = 0xfd, 0x00
	x[15] = last
	return
}

// An IP packet with a transport header of `l4`. `frag`: 0 none, 1 first, 2 later.
ip_pkt :: proc(src_in, dst_in: Addr, v6: bool, proto: u8, l4: []u8, frag := 0, frag_id: u32 = 7) -> []u8 {
	src, dst := src_in, dst_in
	b: [dynamic]u8
	if !v6 {
		append(&b, 0x45, 0, 0, 0)
		append(&b, u8(frag_id >> 8), u8(frag_id))
		switch frag {
		case 1:
			append(&b, 0x20, 0)
		case 2:
			append(&b, 0x00, 0x10)
		case:
			append(&b, 0, 0)
		}
		append(&b, 64, proto, 0, 0)
		append(&b, ..src[12:16])
		append(&b, ..dst[12:16])
	} else {
		nh := proto if frag == 0 else 44
		append(&b, 0x60, 0, 0, 0, 0, 0, nh, 64)
		append(&b, ..src[:])
		append(&b, ..dst[:])
		if frag != 0 {
			off: u16 = 0 if frag == 1 else 0x100
			m: u16 = 1 if frag == 1 else 0
			fo := off << 3 | m
			append(&b, proto, 0, u8(fo >> 8), u8(fo))
			append(&b, u8(frag_id >> 24), u8(frag_id >> 16), u8(frag_id >> 8), u8(frag_id))
		}
	}
	append(&b, ..l4)
	return b[:]
}

tcp :: proc(src, dst: Addr, sport, dport: u16, flags: u8, v6 := false, frag := 0) -> []u8 {
	l4 := make([]u8, 20)
	l4[0], l4[1], l4[2], l4[3] = u8(sport >> 8), u8(sport), u8(dport >> 8), u8(dport)
	l4[12] = 0x50
	l4[13] = flags
	return ip_pkt(src, dst, v6, PROTO_TCP, l4, frag)
}

udp :: proc(src, dst: Addr, sport, dport: u16, v6 := false, frag := 0, frag_id: u32 = 7) -> []u8 {
	l4 := make([]u8, 8)
	l4[0], l4[1], l4[2], l4[3] = u8(sport >> 8), u8(sport), u8(dport >> 8), u8(dport)
	return ip_pkt(src, dst, v6, PROTO_UDP, l4, frag, frag_id)
}

echo :: proc(src, dst: Addr, id: u16, request: bool, v6 := false) -> []u8 {
	t: u8
	if v6 {
		t = 128 if request else 129
	} else {
		t = 8 if request else 0
	}
	l4 := []u8{t, 0, 0, 0, u8(id >> 8), u8(id), 0, 1}
	return ip_pkt(src, dst, v6, PROTO_ICMP6 if v6 else PROTO_ICMP, l4)
}

// An ICMP error from `from` to `to` about `inner`.
icmp_error :: proc(from, to: Addr, inner: []u8, v6 := false) -> []u8 {
	l4: [dynamic]u8
	if v6 {
		append(&l4, 2, 0, 0, 0, 0, 0, 0x05, 0x00) // packet too big
	} else {
		append(&l4, 3, 4, 0, 0, 0, 0, 0x05, 0x00) // fragmentation needed
	}
	append(&l4, ..inner[:min(len(inner), 28 if !v6 else 48)])
	return ip_pkt(from, to, v6, PROTO_ICMP6 if v6 else PROTO_ICMP, l4[:])
}

ME4 :: [4]u8{10, 8, 0, 2}
PEER4 :: [4]u8{10, 8, 0, 9}

me4 :: proc() -> Addr {return A4(10, 8, 0, 2)}
peer4 :: proc() -> Addr {return A4(10, 8, 0, 9)}
me6 :: proc() -> Addr {return A6(2)}
peer6 :: proc() -> Addr {return A6(9)}

SEED :: [16]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

setup :: proc(a: ^Acl, rules: []Rule, hosts := 0, max_flows := 1024) {
	init(a, rules, hosts, max_flows, SEED)
	set_tunnel(a, []Addr{me4(), me6()})
}

port_rule :: proc(lo: u16, hi: u16 = 0, protos := PROTOS_PORTS) -> Rule {
	return {target = .Tunnel, port_lo = lo, port_hi = hi if hi != 0 else lo, protos = protos}
}

// ------------------------------------------------------------------ parse

@(test)
test_parse_v4_tcp :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	p: Packet
	testing.expect(t, parse(tcp(me4(), peer4(), 40000, 443, TCP_SYN), &p))
	testing.expect_value(t, p.af, 4)
	testing.expect_value(t, p.proto, PROTO_TCP)
	testing.expect_value(t, p.sport, 40000)
	testing.expect_value(t, p.dport, 443)
	testing.expect_value(t, p.tcp_flags, TCP_SYN)
	testing.expect(t, p.src == me4() && p.dst == peer4())
	testing.expect_value(t, p.frag, Frag.None)
}

@(test)
test_parse_v6_ext_and_frag :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	p: Packet
	testing.expect(t, parse(udp(me6(), peer6(), 5000, 53, true, 1, 99), &p))
	testing.expect_value(t, p.frag, Frag.First)
	testing.expect_value(t, p.frag_id, 99)
	testing.expect_value(t, p.proto, PROTO_UDP)
	testing.expect_value(t, p.dport, 53)

	testing.expect(t, parse(udp(me6(), peer6(), 5000, 53, true, 2, 99), &p))
	testing.expect_value(t, p.frag, Frag.Later)
	testing.expect_value(t, p.proto, PROTO_UDP)
	testing.expect(t, !p.ports)

	// A hop-by-hop header before UDP.
	l4 := []u8{PROTO_UDP, 0, 0, 0, 0, 0, 0, 0, 0x13, 0x88, 0, 53, 0, 8, 0, 0}
	raw := ip_pkt(me6(), peer6(), true, 0, l4)
	testing.expect(t, parse(raw, &p))
	testing.expect_value(t, p.proto, PROTO_UDP)
	testing.expect_value(t, p.dport, 53)
}

@(test)
test_parse_bad :: proc(t: ^testing.T) {
	p: Packet
	testing.expect(t, !parse(nil, &p))
	testing.expect(t, !parse([]u8{0x45, 0, 0}, &p))
	testing.expect(t, !parse([]u8{0x4f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, &p))
	testing.expect(t, !parse([]u8{0x20, 0, 0, 0}, &p))
}

@(test)
test_parse_icmp_error_inner :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	inner := tcp(me4(), peer4(), 40000, 443, TCP_ACK)
	p: Packet
	testing.expect(t, parse(icmp_error(A4(192, 0, 2, 1), me4(), inner), &p))
	testing.expect_value(t, p.icmp, Icmp.Error)
	testing.expect(t, p.inner.ok)
	testing.expect_value(t, p.inner.proto, PROTO_TCP)
	testing.expect_value(t, p.inner.sport, 40000)
	testing.expect_value(t, p.inner.dport, 443)
	testing.expect(t, p.inner.src == me4())
}

// ---------------------------------------------------------------- filter

@(test)
test_reply_passes_unsolicited_drops :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, nil)
	// Nothing is allowed in, but replies pass.
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_SYN), 100)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_SYN | TCP_ACK), 100), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_ACK), 101), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40001, TCP_ACK), 101), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 5555, 22, TCP_SYN), 101), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 53, 9999), 101), Verdict.Drop_Rule)
	testing.expect_value(t, a.stats.in_denied, 3)

	outbound(&a, udp(me6(), peer6(), 5000, 53, true), 100)
	testing.expect_value(t, inbound(&a, udp(peer6(), me6(), 53, 5000, true), 100), Verdict.Pass)

	outbound(&a, echo(me4(), peer4(), 77, true), 100)
	testing.expect_value(t, inbound(&a, echo(peer4(), me4(), 77, false), 100), Verdict.Pass)
	testing.expect_value(t, inbound(&a, echo(peer4(), me4(), 78, false), 100), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, echo(peer4(), me4(), 5, true), 100), Verdict.Drop_Rule)
}

@(test)
test_tunnel_port_rule :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22), port_rule(8000, 8099, {.Tcp})})
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 5555, 22, TCP_SYN), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer6(), me6(), 5555, 22, TCP_SYN, true), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 5555, 22), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 5555, 8050, TCP_SYN), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 5555, 8050), 1), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 5555, 8100, TCP_SYN), 1), Verdict.Drop_Rule)
	// Port 22 of another address (a network behind the client).
	testing.expect_value(t, inbound(&a, tcp(peer4(), A4(192, 168, 1, 5), 5555, 22, TCP_SYN), 1), Verdict.Drop_Rule)
	// A port rule does not let ping in.
	testing.expect_value(t, inbound(&a, echo(peer4(), me4(), 1, true), 1), Verdict.Drop_Rule)
	testing.expect_value(t, a.stats.in_new, 4)
	// The client replies, and the rest of the connection passes.
	outbound(&a, tcp(me4(), peer4(), 22, 5555, TCP_SYN | TCP_ACK), 1)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 5555, 22, TCP_ACK), 2), Verdict.Pass)
	testing.expect_value(t, a.stats.in_new, 4)
}

@(test)
test_prefix_rules :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	net6 := A6(0)
	rules := []Rule {
		{target = .Prefix, addr = A4(192, 168, 50, 0), bits = 96 + 24, v4 = true, protos = PROTOS_ALL},
		{target = .Prefix, addr = net6, bits = 64, protos = {.Tcp}, port_lo = 443, port_hi = 443},
		{target = .Prefix, addr = A4(10, 8, 0, 2), bits = 128, v4 = true, protos = {.Icmp}},
	}
	a: Acl
	setup(&a, rules)
	testing.expect_value(t, inbound(&a, tcp(peer4(), A4(192, 168, 50, 7), 1, 9, TCP_SYN), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, echo(peer4(), A4(192, 168, 50, 7), 1, true), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), A4(192, 168, 51, 7), 1, 9, TCP_SYN), 1), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, tcp(peer6(), A6(77), 1, 443, TCP_SYN, true), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer6(), A6(77), 1, 444, TCP_SYN, true), 1), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, echo(peer4(), me4(), 9, true), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 1, 22, TCP_SYN), 1), Verdict.Drop_Rule)
	// An IPv6 packet to an address in the mapped range never matches an IPv4 rule.
	testing.expect_value(t, inbound(&a, tcp(peer6(), A4(192, 168, 50, 7), 1, 9, TCP_SYN, true), 1), Verdict.Drop_Bad)
}

@(test)
test_host_rule :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{{target = .Host, host = 0, port_lo = 445, port_hi = 445, protos = {.Tcp}}}, 1)
	nas := A4(192, 168, 1, 20)
	// Not looked up yet: nothing matches.
	testing.expect_value(t, inbound(&a, tcp(peer4(), nas, 1, 445, TCP_SYN), 1), Verdict.Drop_Rule)
	set_host(&a, 0, []Addr{A4(192, 168, 1, 21), nas})
	testing.expect_value(t, inbound(&a, tcp(peer4(), nas, 1, 445, TCP_SYN), 2), Verdict.Pass)
	// The address changes: the flow that exists stays, new ones are refused.
	set_host(&a, 0, []Addr{A4(192, 168, 1, 21)})
	testing.expect_value(t, inbound(&a, tcp(peer4(), nas, 1, 445, TCP_ACK), 3), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), nas, 2, 445, TCP_SYN), 3), Verdict.Drop_Rule)
}

@(test)
test_timeouts :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, nil)
	outbound(&a, udp(me4(), peer4(), 5000, 53), 100)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 53, 5000), 100 + TIMEOUT[.One] + 1), Verdict.Drop_Rule)
	outbound(&a, udp(me4(), peer4(), 5000, 53), 200)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 53, 5000), 200), Verdict.Pass)
	// Both sides seen: the longer timeout.
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 53, 5000), 200 + TIMEOUT[.One] + 5), Verdict.Pass)

	// A RST closes the flow; it ends after the short timeout.
	outbound(&a, tcp(me4(), peer4(), 40000, 80, TCP_SYN), 300)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 80, 40000, TCP_SYN | TCP_ACK), 300), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 80, 40000, TCP_RST), 301), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 80, 40000, TCP_ACK), 301 + TIMEOUT[.Closed] + 1), Verdict.Drop_Rule)

	// The sweep frees expired flows.
	outbound(&a, udp(me4(), peer4(), 6000, 53), 400)
	before := flows(&a)
	tick(&a, 400 + TIMEOUT[.One] + 1, len(a.table.slots))
	testing.expect(t, flows(&a) < before)
	testing.expect_value(t, flows(&a), 0)
}

@(test)
test_icmp_related :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, nil)
	router := A4(192, 0, 2, 1)
	sent := tcp(me4(), peer4(), 40000, 443, TCP_ACK)
	outbound(&a, sent, 1)
	testing.expect_value(t, inbound(&a, icmp_error(router, me4(), sent), 1), Verdict.Pass)
	other := tcp(me4(), peer4(), 40001, 443, TCP_ACK)
	testing.expect_value(t, inbound(&a, icmp_error(router, me4(), other), 1), Verdict.Drop_Rule)

	sent6 := udp(me6(), peer6(), 5000, 443, true)
	outbound(&a, sent6, 1)
	testing.expect_value(t, inbound(&a, icmp_error(A6(1), me6(), sent6, true), 1), Verdict.Pass)
}

@(test)
test_fragments :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(5000, 0, {.Udp})})
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 1, 5000, false, 1, 42), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 0, 0, false, 2, 42), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 0, 0, false, 2, 43), 1), Verdict.Drop_Frag)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 0, 0, false, 2, 42), 1 + FRAG_TIMEOUT + 1), Verdict.Drop_Frag)
	// The first fragment to a port that is closed.
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 1, 6000, false, 1, 50), 1), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, udp(peer4(), me4(), 0, 0, false, 2, 50), 1), Verdict.Drop_Frag)

	testing.expect_value(t, inbound(&a, udp(peer6(), me6(), 1, 5000, true, 1, 9000), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, udp(peer6(), me6(), 0, 0, true, 2, 9000), 1), Verdict.Pass)
}

@(test)
test_tunnel_change :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22)})
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_SYN), 1)
	outbound(&a, tcp(me6(), peer6(), 40000, 443, TCP_SYN, true), 1)
	testing.expect_value(t, flows(&a), 2)
	new4 := A4(10, 8, 0, 3)
	set_tunnel(&a, []Addr{new4, me6()})
	testing.expect_value(t, flows(&a), 1)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 1, 22, TCP_SYN), 2), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, tcp(peer4(), new4, 1, 22, TCP_SYN), 2), Verdict.Pass)
}

@(test)
test_full_table :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22)}, 0, 64)
	for i in 0 ..< 64 {
		outbound(&a, tcp(me4(), peer4(), u16(10000 + i), 443, TCP_SYN), 1)
	}
	testing.expect_value(t, flows(&a), 64)
	// Fail closed for a new inbound flow.
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 1, 22, TCP_SYN), 2), Verdict.Drop_Full)
	testing.expect_value(t, a.stats.in_full, 1)
	// A new outbound flow replaces an old one.
	outbound(&a, tcp(me4(), peer4(), 20000, 443, TCP_SYN), 2)
	testing.expect_value(t, flows(&a), 64)
	testing.expect_value(t, a.stats.evicted, 1)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 20000, TCP_SYN | TCP_ACK), 2), Verdict.Pass)
	// Expired flows make room for inbound ones again.
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 1, 22, TCP_SYN), 2 + TIMEOUT[.Syn] + 1), Verdict.Pass)
}

// Random inserts and deletes against a map: every key stays reachable after
// the backward-shift delete.
@(test)
test_table_against_map :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	tb: Table
	table_init(&tb, 512, SEED)
	ref := make(map[Flow_Key]bool)
	r := rand.create(5)
	gen := rand.default_random_generator(&r)
	for _ in 0 ..< 20000 {
		local, remote := me4(), peer4()
		k := key_make(4, PROTO_UDP, &local, &remote, u16(rand.uint32(gen) % 700), 53)
		h := key_hash(&tb, &k)
		slot := table_find(&tb, &k, h)
		testing.expect_value(t, slot >= 0, k in ref)
		if slot >= 0 {
			table_delete(&tb, slot)
			delete_key(&ref, k)
		} else if tb.count < tb.max {
			s, _ := table_insert(&tb, &k, h, 1, .In)
			testing.expect(t, s >= 0)
			ref[k] = true
		}
		testing.expect_value(t, tb.count, len(ref))
	}
	for k in ref {
		kk := k
		testing.expect(t, table_find(&tb, &kk, key_hash(&tb, &kk)) >= 0)
	}
}

// ------------------------------------------------- review findings (R1..R9)

// The state of the flow of an inbound packet `pkt`, for the tests.
flow_state_in :: proc(a: ^Acl, pkt: []u8) -> (s: State, found: bool) {
	p: Packet
	if !parse(pkt, &p) {
		return
	}
	k := key_make(p.af, p.proto, &p.dst, &p.src, p.dport, p.sport)
	slot := table_find(&a.table, &k, key_hash(&a.table, &k))
	if slot < 0 {
		return
	}
	return a.table.slots[slot].state, true
}

// R1: one inbound packet must not create a flow with the long timeout.
@(test)
test_r1_one_packet_is_not_established :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22)})
	// A lone ACK to an open port (a connection older than its flow, or a forged one).
	ack := tcp(peer4(), me4(), 5000, 22, TCP_ACK)
	testing.expect_value(t, inbound(&a, ack, 100), Verdict.Pass)
	s, _ := flow_state_in(&a, ack)
	testing.expect(t, s != .Est)
	tick(&a, 100 + TIMEOUT[.Syn] + 1, len(a.table.slots))
	testing.expect_value(t, flows(&a), 0)

	// A SYN that the host answers, and no third packet (a SYN flood).
	syn := tcp(peer4(), me4(), 5001, 22, TCP_SYN)
	testing.expect_value(t, inbound(&a, syn, 200), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 22, 5001, TCP_SYN | TCP_ACK), 200)
	s, _ = flow_state_in(&a, syn)
	testing.expect(t, s != .Est)
	tick(&a, 200 + 300, len(a.table.slots))
	testing.expect_value(t, flows(&a), 0)

	// The whole handshake: established, and still there after an hour.
	syn = tcp(peer4(), me4(), 5002, 22, TCP_SYN)
	testing.expect_value(t, inbound(&a, syn, 1000), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 22, 5002, TCP_SYN | TCP_ACK), 1000)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 5002, 22, TCP_ACK), 1000), Verdict.Pass)
	s, _ = flow_state_in(&a, syn)
	testing.expect_value(t, s, State.Est)
	tick(&a, 1000 + 3600, len(a.table.slots))
	testing.expect_value(t, flows(&a), 1)

	// A connection that is older than its flow: established when both sides go on.
	late := tcp(peer4(), me4(), 5003, 22, TCP_ACK)
	testing.expect_value(t, inbound(&a, late, 9000), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 22, 5003, TCP_ACK), 9000)
	testing.expect_value(t, inbound(&a, late, 9001), Verdict.Pass)
	s, _ = flow_state_in(&a, late)
	testing.expect_value(t, s, State.Est)
}

// R2: a full table gives up half-open flows before an established one.
@(test)
test_r2_evict_keeps_established :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22)}, 0, 64)
	// An established connection of the client, idle since t=1.
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_SYN), 1)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_SYN | TCP_ACK), 1), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_ACK), 1)
	// A peer fills the rest of the table with fresh SYNs to an open port.
	for i in 0 ..< 63 {
		testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), u16(1000 + i), 22, TCP_SYN), 100), Verdict.Pass)
	}
	testing.expect_value(t, flows(&a), 64)
	// New connections of the client each replace one flow.
	for i in 0 ..< 16 {
		outbound(&a, tcp(me4(), peer4(), u16(41000 + i), 443, TCP_SYN), 101)
	}
	testing.expect_value(t, a.stats.evicted, 16)
	// The idle connection is still known.
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_ACK), 102), Verdict.Pass)
}

// R3: a ping from the client lets in only the replies. A ping from the peer
// needs a rule.
@(test)
test_r3_ping_out_does_not_open_ping_in :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, nil)
	outbound(&a, echo(me4(), peer4(), 77, true), 100)
	testing.expect_value(t, inbound(&a, echo(peer4(), me4(), 77, true), 100), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, echo(peer4(), me4(), 77, false), 100), Verdict.Pass)
	outbound(&a, echo(me6(), peer6(), 78, true, true), 100)
	testing.expect_value(t, inbound(&a, echo(peer6(), me6(), 78, true, true), 100), Verdict.Drop_Rule)
	testing.expect_value(t, inbound(&a, echo(peer6(), me6(), 78, false, true), 100), Verdict.Pass)
	// An ICMP error about the ping of the client is still related.
	sent := echo(me4(), peer4(), 79, true)
	outbound(&a, sent, 100)
	testing.expect_value(t, inbound(&a, icmp_error(A4(192, 0, 2, 1), me4(), sent), 100), Verdict.Pass)
}

// R4: a SYN from the peer on the ports of a connection that was reset is a new
// connection: the rules decide.
@(test)
test_r4_syn_on_closed_flow_needs_rule :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, nil)
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_SYN), 100)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_SYN | TCP_ACK), 100), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_RST), 100), Verdict.Pass)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_SYN), 101), Verdict.Drop_Rule)
	// The client can use the ports again.
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_SYN), 102)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_SYN | TCP_ACK), 102), Verdict.Pass)
}

// An IPv6 packet from raw extension headers. `chain`: the bytes after the
// fixed header; `first_nh`: the type of the first of them.
ip6_raw :: proc(src_in, dst_in: Addr, first_nh: u8, chain: []u8) -> []u8 {
	src, dst := src_in, dst_in
	b: [dynamic]u8
	append(&b, 0x60, 0, 0, 0, 0, 0, first_nh, 64)
	append(&b, ..src[:])
	append(&b, ..dst[:])
	append(&b, ..chain)
	return b[:]
}

// R5: fragments of an IPv6 packet whose fragmented part starts with an
// extension header.
@(test)
test_r5_v6_fragment_after_options :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(5000, 0, {.Udp})})
	// Fragment header (next: destination options), the options (next: UDP), UDP.
	first := []u8 {
		60, 0, 0, 1, 0, 0, 0x23, 0x28,
		PROTO_UDP, 0, 1, 4, 0, 0, 0, 0,
		0, 1, 0x13, 0x88, 0, 16, 0, 0,
	}
	// Fragment header (the same next header, offset 3), then data that is not a header.
	later := []u8 {
		60, 0, 0, 24, 0, 0, 0x23, 0x28,
		0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4,
	}
	testing.expect_value(t, inbound(&a, ip6_raw(peer6(), me6(), 44, first), 1), Verdict.Pass)
	testing.expect_value(t, inbound(&a, ip6_raw(peer6(), me6(), 44, later), 1), Verdict.Pass)
	// Another identification does not pass.
	later[7] = 0x29
	testing.expect_value(t, inbound(&a, ip6_raw(peer6(), me6(), 44, later), 1), Verdict.Drop_Frag)
}

// R6: four extension headers before the transport header are read.
@(test)
test_r6_v6_four_extension_headers :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	chain := []u8 {
		43, 0, 0, 0, 0, 0, 0, 0, // hop-by-hop, next: routing
		60, 0, 0, 0, 0, 0, 0, 0, // routing, next: destination options
		60, 0, 1, 4, 0, 0, 0, 0, // destination options, next: destination options
		PROTO_UDP, 0, 1, 4, 0, 0, 0, 0,
		0x13, 0x88, 0, 53, 0, 8, 0, 0,
	}
	p: Packet
	testing.expect(t, parse(ip6_raw(peer6(), me6(), 0, chain), &p))
	testing.expect_value(t, p.proto, PROTO_UDP)
	testing.expect(t, p.ports)
	testing.expect_value(t, p.dport, 53)
}

// R7: an IPv6 packet with an IPv4-mapped address is not an IPv4 packet.
@(test)
test_r7_v6_mapped_address :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22)})
	pkt := tcp(peer6(), me4(), 5000, 22, TCP_SYN, true)
	testing.expect_value(t, inbound(&a, pkt, 1), Verdict.Drop_Bad)
	testing.expect_value(t, flows(&a), 0)
	pkt = tcp(peer4(), me6(), 5000, 22, TCP_SYN, true)
	testing.expect_value(t, inbound(&a, pkt, 1), Verdict.Drop_Bad)
}

// R8: first fragments from many sources with one identification do not all
// use one slot of the fragment table.
@(test)
test_r8_fragment_slots_spread :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(5000, 0, {.Udp})})
	for i in 0 ..< 200 {
		src := A4(10, 9, 0, u8(i))
		testing.expect_value(t, inbound(&a, udp(src, me4(), 1, 5000, false, 1, 42), 1), Verdict.Pass)
	}
	passed := 0
	for i in 0 ..< 200 {
		src := A4(10, 9, 0, u8(i))
		if inbound(&a, udp(src, me4(), 0, 0, false, 2, 42), 1) == .Pass {
			passed += 1
		}
	}
	testing.expectf(t, passed >= 100, "%d of 200 later fragments passed", passed)
}

// R9: the sweep goes around a large table in about half a minute.
@(test)
test_r9_sweep_covers_large_table :: proc(t: ^testing.T) {
	a: Acl
	init(&a, nil, 0, 200_000, SEED)
	defer destroy(&a)
	set_tunnel(&a, []Addr{me4()})
	pkt := tcp(me4(), peer4(), 0, 443, TCP_SYN)
	defer delete(pkt)
	for i in 0 ..< 1000 {
		pkt[20], pkt[21] = u8(i >> 8), u8(i)
		outbound(&a, pkt, 100)
	}
	testing.expect_value(t, flows(&a), 1000)
	for s in 0 ..< 40 {
		tick(&a, u32(100 + TIMEOUT[.Syn] + 1 + u32(s)))
	}
	testing.expect_value(t, flows(&a), 0)
}

// Random and damaged packets never read outside the buffer (a bounds check
// would stop the test), in both directions.
@(test)
test_fuzz_packets :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22), {target = .Prefix, addr = A6(0), bits = 64, protos = PROTOS_ALL}}, 0, 256)
	r := rand.create(11)
	gen := rand.default_random_generator(&r)
	seeds := [][]u8 {
		tcp(peer4(), me4(), 5000, 22, TCP_SYN),
		tcp(peer6(), me6(), 5000, 22, TCP_SYN, true),
		udp(peer6(), me6(), 1, 5000, true, 1, 9),
		udp(peer4(), me4(), 1, 5000, false, 2, 9),
		echo(peer4(), me4(), 3, true),
		icmp_error(A4(192, 0, 2, 1), me4(), tcp(me4(), peer4(), 40000, 443, TCP_ACK)),
		icmp_error(A6(1), me6(), udp(me6(), peer6(), 5000, 443, true), true),
	}
	buf: [128]u8
	for round in 0 ..< 200_000 {
		n: int
		if round % 4 == 0 {
			n = int(rand.uint32(gen) % 100)
			for i in 0 ..< n {
				buf[i] = u8(rand.uint32(gen))
			}
			if n > 0 && round % 8 == 0 {
				buf[0] = 0x45 if round % 16 == 0 else 0x60
			}
		} else {
			s := seeds[int(rand.uint32(gen)) % len(seeds)]
			n = copy(buf[:], s)
			// Damage up to three bytes, then cut the packet at a random length.
			for _ in 0 ..< int(rand.uint32(gen) % 4) {
				buf[int(rand.uint32(gen)) % n] = u8(rand.uint32(gen))
			}
			if rand.uint32(gen) % 3 == 0 {
				n = int(rand.uint32(gen)) % (n + 1)
			}
		}
		now := u32(round / 100)
		if round % 2 == 0 {
			inbound(&a, buf[:n], now)
		} else {
			outbound(&a, buf[:n], now)
		}
		tick(&a, now, 16)
	}
	testing.expect(t, flows(&a) <= 256)
	// Every flow that is left can be found from its key.
	count := 0
	for &e, i in a.table.slots {
		if e.used {
			count += 1
			testing.expect_value(t, table_find(&a.table, &e.key, e.hash), i)
		}
	}
	testing.expect_value(t, count, flows(&a))
}

// A random flow key: IPv4 for even rounds.
random_key :: proc(gen: rand.Generator, v4: bool) -> Flow_Key {
	local, remote: Addr
	if v4 {
		local = A4(u8(rand.uint32(gen)), u8(rand.uint32(gen)), u8(rand.uint32(gen)), u8(rand.uint32(gen)))
		remote = A4(u8(rand.uint32(gen)), u8(rand.uint32(gen)), u8(rand.uint32(gen)), u8(rand.uint32(gen)))
	} else {
		for i in 0 ..< 16 {
			local[i], remote[i] = u8(rand.uint32(gen)), u8(rand.uint32(gen))
		}
		// Not a mapped address.
		local[0], remote[0] = 0xfd, 0x20
	}
	return key_make(4 if v4 else 6, u8(rand.uint32(gen)), &local, &remote, u16(rand.uint32(gen)), u16(rand.uint32(gen)))
}

random_table :: proc(gen: rand.Generator) -> (tb: Table, seed: [16]u8) {
	for &b in seed {
		b = u8(rand.uint32(gen))
	}
	table_init(&tb, 16, seed)
	return
}

// The SipHash form of `k` from the library: SipHash-1-3 of the bytes that
// hash.odin names.
sip_reference :: proc(k: ^Flow_Key, seed: []u8) -> u32 {
	local, remote := k.laddr, k.raddr
	msg: [dynamic]u8
	if key_is_v4(k) {
		append(&msg, ..local[12:])
		append(&msg, ..remote[12:])
	} else {
		append(&msg, ..local[:])
		append(&msg, ..remote[:])
	}
	meta := transmute([8]u8)k.meta
	append(&msg, ..meta[:7])
	return u32(siphash.sum_bytes_1_3(msg[:], seed))
}

// Every build of the hash that this CPU can run gives the value of its
// reference: the library for SipHash, the plain code for the AES form.
@(test)
test_hash_builds :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	r := rand.create(3)
	gen := rand.default_random_generator(&r)
	variants, n := hash_variants()
	testing.expect(t, n >= 1)
	for round in 0 ..< 2000 {
		tb, seed := random_table(gen)
		k := random_key(gen, round % 2 == 0)
		for v in variants[:n] {
			want := key_hash_soft(&tb, &k) if v.aes else sip_reference(&k, seed[:])
			testing.expectf(t, v.hash(&tb, &k) == want, "build %s, round %d", v.name, round)
		}
		// The table uses the first build.
		testing.expect_value(t, key_hash(&tb, &k), variants[0].hash(&tb, &k))
	}
	for v in variants[:n] {
		log.infof("hash build: %s", v.name)
	}
}

// The plain code of the AES form: values from FIPS-197.
@(test)
test_soft_aes :: proc(t: ^testing.T) {
	sbox := soft_sbox()
	testing.expect_value(t, sbox[0x00], 0x63)
	testing.expect_value(t, sbox[0x01], 0x7c)
	testing.expect_value(t, sbox[0x53], 0xed)
	testing.expect_value(t, sbox[0xff], 0x16)
	seen: [256]bool
	for v in sbox {
		seen[v] = true
	}
	for ok in seen {
		testing.expect(t, ok)
	}
	testing.expect_value(t, soft_mix_column({0xdb, 0x13, 0x53, 0x45}), [4]u8{0x8e, 0x4d, 0xa1, 0xbc})
	testing.expect_value(t, soft_mix_column({0xf2, 0x0a, 0x22, 0x5c}), [4]u8{0x9f, 0xdc, 0x58, 0x9d})
	testing.expect_value(t, soft_mix_column({0xd4, 0xbf, 0x5d, 0x30}), [4]u8{0x04, 0x66, 0x81, 0xe5})
	// Round 1 of the cipher example (appendix B): the state after the first
	// key, the round key, and the state at the start of round 2.
	state := [16]u8{0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08}
	key := [16]u8{0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05}
	want := [16]u8{0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b, 0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a, 0x50, 0x49}
	got := transmute([16]u8)soft_round(&sbox, transmute(Block)state, transmute(Block)key)
	testing.expect_value(t, got, want)
}

// The round keys: SipHash-2-4 of a counter, all different.
@(test)
test_round_keys :: proc(t: ^testing.T) {
	seed := SEED
	tb: Table
	table_init(&tb, 16, seed)
	defer table_destroy(&tb)
	words := (^[size_of(Round_Keys) / 8]u64)(&tb.rk)
	testing.expect_value(t, len(words), 4 * (AES_ROUNDS + 1) * 2)
	for w, i in words {
		ctr := transmute([8]u8)u64(i)
		testing.expect_value(t, w, siphash.sum_bytes_2_4(ctr[:], seed[:]))
		for j in 0 ..< i {
			testing.expect(t, words[j] != w)
		}
	}
}

// Each bit of a flow key changes the hash, in every build.
@(test)
test_hash_uses_every_bit :: proc(t: ^testing.T) {
	r := rand.create(17)
	gen := rand.default_random_generator(&r)
	variants, n := hash_variants()
	for round in 0 ..< 200 {
		tb, _ := random_table(gen)
		defer table_destroy(&tb)
		v4 := round % 2 == 0
		k := random_key(gen, v4)
		bytes := (^[40]u8)(&k)
		for bit in 0 ..< 40 * 8 {
			at := bit / 8
			// Not part of an IPv4 key: the constant start of the addresses.
			// Not part of any key: the family, and the two bytes that stay 0.
			if (v4 && (at < 12 || (at >= 16 && at < 28))) || at == 36 || at >= 38 {
				continue
			}
			other := k
			(^[40]u8)(&other)[at] = bytes[at] ~ (1 << uint(bit % 8))
			for v in variants[:n] {
				if v.hash(&tb, &k) == v.hash(&tb, &other) {
					testing.expectf(t, false, "build %s: bit %d of an IPv%d key does not change the hash", v.name, bit, 4 if v4 else 6)
					return
				}
			}
		}
	}
}

// Flows that differ only in a port spread over the slots as random values do.
@(test)
test_hash_spread :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	variants, n := hash_variants()
	tb: Table
	table_init(&tb, 16, SEED)
	SLOTS :: 1024
	KEYS :: 1 << 16
	for v in variants[:n] {
		for af in ([2]u8{4, 6}) {
			local, remote := me4(), peer4()
			if af == 6 {
				local, remote = me6(), peer6()
			}
			count: [SLOTS]int
			for i in 0 ..< KEYS {
				k := key_make(af, PROTO_TCP, &local, &remote, 443, u16(i))
				count[v.hash(&tb, &k) % SLOTS] += 1
			}
			// 64 keys for each slot on average. The sum of squared errors over
			// the mean is near 1023, with a deviation of about 45.
			chi := f64(0)
			mean := f64(KEYS) / SLOTS
			for c in count {
				d := f64(c) - mean
				chi += d * d / mean
			}
			testing.expectf(t, chi > 800 && chi < 1250, "build %s, IPv%d: chi-square %.0f", v.name, af, chi)
		}
	}
}

@(test)
test_prefix_match_all_lengths :: proc(t: ^testing.T) {
	// The plain form: byte by byte.
	slow :: proc(x, net: ^Addr, bits: int) -> bool {
		for i in 0 ..< bits {
			m := u8(0x80) >> uint(i % 8)
			if x[i / 8] & m != net[i / 8] & m {
				return false
			}
		}
		return true
	}
	r := rand.create(9)
	gen := rand.default_random_generator(&r)
	for round in 0 ..< 20000 {
		x, net: Addr
		for i in 0 ..< 16 {
			net[i] = u8(rand.uint32(gen))
		}
		// Equal up to a random bit, then different.
		x = net
		if at := int(rand.uint32(gen) % 129); at < 128 {
			x[at / 8] ~= u8(0x80) >> uint(at % 8)
			if round % 3 == 0 {
				for i in at / 8 + 1 ..< 16 {
					x[i] = u8(rand.uint32(gen))
				}
			}
		}
		for bits in 0 ..= 128 {
			if prefix_match(&x, &net, bits) != slow(&x, &net, bits) {
				testing.expectf(t, false, "bits %d: %v against %v", bits, x, net)
				return
			}
		}
	}
}

// A connection that ended and the same ports again.
@(test)
test_ports_used_again :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, nil)
	// The client closes, then connects again from the same port.
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_SYN), 100)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_SYN | TCP_ACK), 100), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_ACK), 100)
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_FIN | TCP_ACK), 101)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_FIN | TCP_ACK), 101), Verdict.Pass)
	reply := tcp(peer4(), me4(), 443, 40000, TCP_SYN | TCP_ACK)
	s, _ := flow_state_in(&a, reply)
	testing.expect_value(t, s, State.Fin)
	// The peer cannot start the next connection on these ports.
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40000, TCP_SYN), 102), Verdict.Drop_Rule)
	testing.expect_value(t, flows(&a), 0)
	// The client can, and the new connection gets the long timeout.
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_SYN), 103)
	testing.expect_value(t, inbound(&a, reply, 103), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 40000, 443, TCP_ACK), 103)
	s, _ = flow_state_in(&a, reply)
	testing.expect_value(t, s, State.Est)

	// The same after a close with the flow still in the table.
	outbound(&a, tcp(me4(), peer4(), 40001, 443, TCP_SYN), 200)
	outbound(&a, tcp(me4(), peer4(), 40001, 443, TCP_FIN | TCP_ACK), 201)
	outbound(&a, tcp(me4(), peer4(), 40001, 443, TCP_SYN), 202)
	reply = tcp(peer4(), me4(), 443, 40001, TCP_SYN | TCP_ACK)
	testing.expect_value(t, inbound(&a, reply, 202), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 40001, 443, TCP_ACK), 202)
	s, _ = flow_state_in(&a, reply)
	testing.expect_value(t, s, State.Est)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, 40001, TCP_ACK), 202 + 3600), Verdict.Pass)
}

// A full table: a peer can replace half-open flows of peers, and no flow that
// the client started.
@(test)
test_full_table_inbound :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	a: Acl
	setup(&a, []Rule{port_rule(22)}, 0, 64)
	// 32 flows of the client, half-open, older than the rest.
	for i in 0 ..< 32 {
		outbound(&a, tcp(me4(), peer4(), u16(10000 + i), 443, TCP_SYN), 1)
	}
	// 31 SYNs to the open port, and one whole connection.
	for i in 0 ..< 31 {
		testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), u16(2000 + i), 22, TCP_SYN), 10 + u32(i % 5)), Verdict.Pass)
	}
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 3000, 22, TCP_SYN), 10), Verdict.Pass)
	outbound(&a, tcp(me4(), peer4(), 22, 3000, TCP_SYN | TCP_ACK), 10)
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 3000, 22, TCP_ACK), 10), Verdict.Pass)
	testing.expect_value(t, flows(&a), 64)
	// More SYNs: each one replaces a half-open flow of a peer.
	for i in 0 ..< 200 {
		testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), u16(4000 + i), 22, TCP_SYN), 20), Verdict.Pass)
	}
	testing.expect_value(t, flows(&a), 64)
	testing.expect_value(t, a.stats.evicted, 200)
	testing.expect_value(t, a.stats.in_full, 0)
	// The flows of the client and the whole connection are still there.
	for i in 0 ..< 32 {
		testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 443, u16(10000 + i), TCP_SYN | TCP_ACK), 21), Verdict.Pass)
	}
	testing.expect_value(t, inbound(&a, tcp(peer4(), me4(), 3000, 22, TCP_ACK), 21), Verdict.Pass)
	testing.expect_value(t, a.stats.in_new, 232)
}

// ---------------------------------------------------------- plain packets

// Is `pkt` a plain packet, as `parse` sees it?
plain_by_parse :: proc(pkt: []u8, p: ^Packet) -> bool {
	if !parse(pkt, p) || p.frag != .None {
		return false
	}
	if p.proto != PROTO_TCP && p.proto != PROTO_UDP {
		return false
	}
	if p.af == 4 {
		return pkt[0] == 0x45 && len(pkt) >= PLAIN4_MIN
	}
	return pkt[6] == p.proto && len(pkt) >= PLAIN6_MIN
}

// The same packet with a longer IP header: 4 bytes of IPv4 options, or an
// IPv6 destination options header. It has the same flow and is not plain.
not_plain :: proc(pkt: []u8) -> []u8 {
	b: [dynamic]u8
	if pkt[0] >> 4 == 4 {
		append(&b, ..pkt[:20])
		b[0] = 0x46
		append(&b, 1, 1, 1, 1)
		append(&b, ..pkt[20:])
	} else {
		append(&b, ..pkt[:40])
		b[6] = 60
		append(&b, pkt[6], 0, 1, 4, 0, 0, 0, 0)
		append(&b, ..pkt[40:])
	}
	return b[:]
}

// `plain_key` takes exactly the plain packets, and gives the key, the flags
// and the packet info of `parse`.
@(test)
test_plain_key_equals_parse :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	state := rand.create(20261119)
	gen := rand.default_random_generator(&state)
	plain, other := 0, 0
	for round in 0 ..< 60000 {
		v6 := rand.uint32(gen) & 1 != 0
		src := A6(u8(rand.uint32(gen))) if v6 else A4(10, 8, u8(rand.uint32(gen)), u8(rand.uint32(gen)))
		dst := A6(u8(rand.uint32(gen))) if v6 else A4(192, 0, 2, u8(rand.uint32(gen)))
		l4 := make([]u8, int(rand.uint32(gen) % 40))
		for &x in l4 {
			x = u8(rand.uint32(gen))
		}
		proto: u8
		switch rand.uint32(gen) % 8 {
		case 0 ..= 3:
			proto = PROTO_TCP
		case 4 ..= 6:
			proto = PROTO_UDP
		case:
			proto = u8(rand.uint32(gen))
		}
		pkt := ip_pkt(src, dst, v6, proto, l4, int(rand.uint32(gen) % 16) if rand.uint32(gen) % 8 == 0 else 0)
		switch rand.uint32(gen) % 8 {
		case 0:
			// One changed byte in the headers.
			if len(pkt) > 0 {
				pkt[int(rand.uint32(gen)) % min(len(pkt), 60)] = u8(rand.uint32(gen))
			}
		case 1:
			pkt = pkt[:int(rand.uint32(gen)) % (len(pkt) + 1)]
		case 2:
			if len(pkt) >= 40 {
				pkt = not_plain(pkt)
			}
		}

		p: Packet
		want := plain_by_parse(pkt, &p)
		k_in, k_out: Flow_Key
		f_in, ok_in := plain_key(pkt, false, &k_in)
		f_out, ok_out := plain_key(pkt, true, &k_out)
		if ok_in != want || ok_out != want {
			log.errorf("round %d: plain is %v and %v, want %v: % x", round, ok_in, ok_out, want, pkt)
			testing.fail(t)
			return
		}
		if !want {
			other += 1
			continue
		}
		plain += 1
		ref_in := key_make(p.af, p.proto, &p.dst, &p.src, p.dport, p.sport)
		ref_out := key_make(p.af, p.proto, &p.src, &p.dst, p.sport, p.dport)
		q := plain_packet(&k_in, f_in)
		same :=
			key_equal(&k_in, &ref_in) &&
			key_equal(&k_out, &ref_out) &&
			f_in == p.tcp_flags &&
			f_out == p.tcp_flags &&
			q.af == p.af &&
			q.proto == p.proto &&
			q.src == p.src &&
			q.dst == p.dst &&
			q.sport == p.sport &&
			q.dport == p.dport &&
			q.ports == p.ports &&
			q.tcp_flags == p.tcp_flags &&
			q.frag == p.frag &&
			q.frag_id == p.frag_id &&
			q.frag_proto == p.frag_proto &&
			q.icmp == p.icmp &&
			q.inner.ok == p.inner.ok
		if !same {
			log.errorf("round %d: the plain key is not the key of parse: % x", round, pkt)
			testing.fail(t)
			return
		}
	}
	testing.expect(t, plain > 10000)
	testing.expect(t, other > 10000)
}

// Random traffic through two filters: one gets plain packets, the other the
// same packets with a longer IP header. Verdicts, flows and counters are equal.
@(test)
test_plain_and_full_path_agree :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	state := rand.create(77)
	gen := rand.default_random_generator(&state)
	rules := []Rule{port_rule(22), port_rule(53, 0, Protos{.Udp})}
	a, b: Acl
	setup(&a, rules, 0, 32)
	setup(&b, rules, 0, 32)
	FLAGS := [?]u8{TCP_SYN, TCP_SYN | TCP_ACK, TCP_ACK, TCP_ACK, TCP_ACK, TCP_FIN | TCP_ACK, TCP_RST}
	LPORTS := [?]u16{22, 53, 80, 40000, 40001, 40002}
	now: u32 = 1000
	passed, dropped := 0, 0
	for round in 0 ..< 40000 {
		switch rand.uint32(gen) % 64 {
		case 0:
			now += rand.uint32(gen) % 200
		case 1 ..= 8:
			now += 1
			tick(&a, now)
			tick(&b, now)
		}
		v6 := rand.uint32(gen) % 4 == 0
		local := me6() if v6 else me4()
		remote := A6(u8(9 + rand.uint32(gen) % 3)) if v6 else A4(10, 8, 0, u8(9 + rand.uint32(gen) % 3))
		lport := LPORTS[rand.uint32(gen) % len(LPORTS)]
		rport := u16(5000 + rand.uint32(gen) % 12)
		out := rand.uint32(gen) % 3 == 0
		l4 := make([]u8, 20)
		proto: u8 = PROTO_TCP
		if rand.uint32(gen) % 4 == 0 {
			proto = PROTO_UDP
		} else {
			l4[13] = FLAGS[rand.uint32(gen) % len(FLAGS)]
		}
		sport, dport := lport, rport
		if !out {
			sport, dport = rport, lport
		}
		l4[0], l4[1], l4[2], l4[3] = u8(sport >> 8), u8(sport), u8(dport >> 8), u8(dport)
		pkt := ip_pkt(local if out else remote, remote if out else local, v6, proto, l4)
		long := not_plain(pkt)
		if out {
			outbound(&a, pkt, now)
			outbound(&b, long, now)
		} else {
			va, vb := inbound(&a, pkt, now), inbound(&b, long, now)
			if va != vb {
				log.errorf("round %d: plain %v, full %v: % x", round, va, vb, pkt)
				testing.fail(t)
				return
			}
			if va == .Pass {
				passed += 1
			} else {
				dropped += 1
			}
		}
		if flows(&a) != flows(&b) || a.stats != b.stats {
			log.errorf("round %d: flows %d and %d, counters %v and %v", round, flows(&a), flows(&b), a.stats, b.stats)
			testing.fail(t)
			return
		}
	}
	testing.expect(t, passed > 2000)
	testing.expect(t, dropped > 2000)
	testing.expect(t, a.stats.evicted > 0)
	testing.expect(t, a.stats.expired > 0)
	for e, i in a.table.slots {
		o := b.table.slots[i]
		testing.expect(t, e.used == o.used && (!e.used || (e.key == o.key && e.state == o.state && e.origin == o.origin && e.last == o.last)))
	}
}
