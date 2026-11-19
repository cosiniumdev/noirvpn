// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Benchmark for package acl: the work that `allow-inbound` adds to each packet
// of the client data path, one thread.
//
//	odin run proto/acl/bench -collection:noir=. -o:speed
//	odin run proto/acl/bench -collection:noir=. -o:speed -- -iters=5000000 -reps=5
//	odin run proto/acl/bench -collection:noir=. -o:speed -- -sizes=1,10000
//
// Options (after `--`):
//
//	-iters=2000000   operations per measurement
//	-reps=5          repeat each measurement and report the best (least noise)
//	-sizes=1,2,100,10000,100000   flows in the table
//
// What is measured, per packet, in ns:
//
//	parse ...             `acl.parse` alone
//	key hash ...          the keyed hash of one flow key, as the table calls it
//	hash build ...        each build of the hash that this CPU can run: the
//	                      time from one key to its hash (a lookup waits for it)
//	in / out, same flow   a bulk transfer: every packet is of the flow before it
//	tcp bulk, 2 in 1 out  a download: two data packets in, one ACK out
//	in / out, shuffled    known flows visited in a shuffled order
//	deny ...              a packet with no flow that no rule lets in (a port scan)
//	new in / out flow     the first packet of a flow: the rule check and the insert
//	out flow, full table  the insert when the table is full: one flow is replaced
//	tick                  one call of `acl.tick` (once a second) on live flows
//	sweep, per flow       `acl.tick` on a table where every flow is expired
//
// One packet buffer is used for each kind of packet, and only its address and
// port bytes change between flows. The packet is then always in the cache, as
// it is in the data path after the decryption, and the numbers show the cost
// of the table. Every verdict is added to a sink that is printed at the end,
// so the compiler cannot drop the work.
//
// Before the measurements, each build of the hash is checked against its
// reference (the plain code of the AES form, the library SipHash-1-3). A
// binary for another CPU family is checked this way on its own hardware.
package acl_bench

import "core:crypto/siphash"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"
import "noir:proto/acl"

Options :: struct {
	iters: int,
	reps:  int,
	sizes: []int,
}

DEFAULT_SIZES := [?]int{1, 2, 100, 10000, 100000}
RULE_COUNTS := [?]int{1, 16, 64, 256}

// The flow table of the default config (`acl-max-flows`).
DEFAULT_MAX_FLOWS :: 16384

parse_options :: proc() -> (o: Options) {
	o.iters = 2_000_000
	o.reps = 5
	o.sizes = DEFAULT_SIZES[:]
	for arg in os.args[1:] {
		switch {
		case strings.has_prefix(arg, "-iters="):
			o.iters = max(1000, strconv.parse_int(arg[len("-iters="):]) or_else 2_000_000)
		case strings.has_prefix(arg, "-reps="):
			o.reps = max(1, strconv.parse_int(arg[len("-reps="):]) or_else 5)
		case strings.has_prefix(arg, "-sizes="):
			list := make([dynamic]int)
			for part in strings.split(arg[len("-sizes="):], ",", context.temp_allocator) {
				n, ok := strconv.parse_int(part)
				if ok && n > 0 && n <= 4_000_000 {
					append(&list, n)
				}
			}
			o.sizes = list[:]
		case:
			fmt.eprintfln("unknown option %q", arg)
			os.exit(2)
		}
	}
	return
}

// Small deterministic generator, so runs repeat.
Rng :: struct {
	s: u64,
}

rng_next :: proc(r: ^Rng) -> u64 {
	r.s ~= r.s >> 12
	r.s ~= r.s << 25
	r.s ~= r.s >> 27
	return r.s * 0x2545F4914F6CDD1D
}

// ---------------------------------------------------------------- packets

ME4 :: [4]u8{10, 8, 0, 2}
PEER4 :: [4]u8{198, 18, 0, 0}
LPORT :: 40000
NOW :: 100

me6 :: proc() -> (a: [16]u8) {
	a[0], a[1], a[15] = 0xfd, 0x00, 2
	return
}

peer6 :: proc() -> (a: [16]u8) {
	a[0], a[1], a[2] = 0x20, 0x01, 0x0d
	return
}

put16 :: #force_inline proc "contextless" (b: []u8, i: int, v: u16) {
	b[i], b[i + 1] = u8(v >> 8), u8(v)
}

ip4 :: proc(b: []u8, src, dst: [4]u8, proto: u8) {
	b[0] = 0x45
	put16(b, 2, u16(len(b)))
	b[8], b[9] = 64, proto
	b[12], b[13], b[14], b[15] = src[0], src[1], src[2], src[3]
	b[16], b[17], b[18], b[19] = dst[0], dst[1], dst[2], dst[3]
}

tcp4 :: proc(src, dst: [4]u8, sport, dport: u16, flags: u8) -> (p: [40]u8) {
	ip4(p[:], src, dst, acl.PROTO_TCP)
	put16(p[:], 20, sport)
	put16(p[:], 22, dport)
	p[32], p[33] = 0x50, flags
	return
}

udp4 :: proc(src, dst: [4]u8, sport, dport: u16) -> (p: [28]u8) {
	ip4(p[:], src, dst, acl.PROTO_UDP)
	put16(p[:], 20, sport)
	put16(p[:], 22, dport)
	put16(p[:], 24, 8)
	return
}

tcp6 :: proc(src, dst: [16]u8, sport, dport: u16, flags: u8) -> (p: [60]u8) {
	p[0] = 0x60
	put16(p[:], 4, 20)
	p[6], p[7] = acl.PROTO_TCP, 64
	s, d := src, dst
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	put16(p[:], 40, sport)
	put16(p[:], 42, dport)
	p[52], p[53] = 0x50, flags
	return
}

// "Fragmentation needed" from a router about `inner` (28 bytes of it).
icmp_err4 :: proc(router, to: [4]u8, inner: []u8) -> (p: [56]u8) {
	ip4(p[:], router, to, acl.PROTO_ICMP)
	p[20], p[21] = 3, 4
	put16(p[:], 26, 1400)
	copy(p[28:], inner[:28])
	return
}

// A flow number as the bytes that differ between flows: the low half of the
// remote address, and the remote port.
flow_code :: proc(i: int) -> u32 {
	return u32(i / 60000) << 16 | u32(1024 + i % 60000)
}

// The remote side of flow `code` in an inbound IPv4 packet (source).
flow_in4 :: #force_inline proc "contextless" (pkt: []u8, code: u32) {
	pkt[14], pkt[15] = u8(code >> 24), u8(code >> 16)
	pkt[20], pkt[21] = u8(code >> 8), u8(code)
}

// The remote side of flow `code` in an outbound IPv4 packet (destination).
flow_out4 :: #force_inline proc "contextless" (pkt: []u8, code: u32) {
	pkt[18], pkt[19] = u8(code >> 24), u8(code >> 16)
	pkt[22], pkt[23] = u8(code >> 8), u8(code)
}

// ------------------------------------------------------------------ setup

Ctx :: struct {
	a:       acl.Acl,
	n:       int,
	// Flow codes in a shuffled order.
	order:   []u32,
	in4:     [40]u8, // data packet of flow 0 from the peer
	out4:    [40]u8, // ACK of flow 0 from the client
	in6:     [60]u8,
	out6:    [60]u8,
	udp:     [28]u8,
	err:     [56]u8,
	syn:     [40]u8, // SYN from the peer to port 22 of the client
	// Set by an operation that measures its own time.
	elapsed: time.Duration,
	pos:     int,
	next:    int, // the next new flow number (full table)
}

SEED :: [16]u8{0x3a, 0x91, 0x5c, 0x07, 0xe2, 0x4d, 0xb8, 0x16, 0x7f, 0xc3, 0x28, 0x9e, 0x51, 0xd4, 0x0b, 0x6a}

mapped :: proc(a: [4]u8) -> acl.Addr {
	b := a
	return acl.map4(b[:])
}

// A table with flows 0..n-1 in the established state (both sides seen), and
// one IPv6 flow. `max_flows` 0: the default table, or n if that is larger.
setup :: proc(n: int, rules: []acl.Rule, max_flows := 0) -> ^Ctx {
	c := new(Ctx)
	c.n = n
	limit := max_flows if max_flows > 0 else max(DEFAULT_MAX_FLOWS, n + 1)
	acl.init(&c.a, rules, 0, limit, SEED)
	acl.set_tunnel(&c.a, []acl.Addr{mapped(ME4), me6()})
	c.in4 = tcp4(PEER4, ME4, 1024, LPORT, acl.TCP_ACK)
	c.out4 = tcp4(ME4, PEER4, LPORT, 1024, acl.TCP_ACK)
	c.in6 = tcp6(peer6(), me6(), 443, LPORT, acl.TCP_ACK)
	c.out6 = tcp6(me6(), peer6(), LPORT, 443, acl.TCP_ACK)
	c.udp = udp4(PEER4, ME4, 53, LPORT)
	c.err = icmp_err4({192, 0, 2, 1}, ME4, c.out4[:])
	c.syn = tcp4(PEER4, ME4, 1024, 22, acl.TCP_SYN)
	c.order = make([]u32, n)
	for i in 0 ..< n {
		c.order[i] = flow_code(i)
	}
	r := Rng{0x9E3779B97F4A7C15}
	for i := n - 1; i > 0; i -= 1 {
		j := int(rng_next(&r) % u64(i + 1))
		c.order[i], c.order[j] = c.order[j], c.order[i]
	}
	fill(c, n)
	c.next = n
	return c
}

// Adds flows 0..n-1: a packet out, then one in.
fill :: proc(c: ^Ctx, n: int) {
	o, i := c.out4, c.in4
	for k in 0 ..< n {
		code := flow_code(k)
		flow_out4(o[:], code)
		flow_in4(i[:], code)
		acl.outbound(&c.a, o[:], NOW)
		if acl.inbound(&c.a, i[:], NOW) != .Pass {
			fmt.eprintln("bench: the reply of a flow did not pass")
			os.exit(1)
		}
	}
	if max_room := c.a.table.max; n < max_room {
		acl.outbound(&c.a, c.out6[:], NOW)
		acl.inbound(&c.a, c.in6[:], NOW)
	}
}

teardown :: proc(c: ^Ctx) {
	acl.destroy(&c.a)
	delete(c.order)
	free(c)
}

// ------------------------------------------------------------- operations
// Each runs `n` times and returns a sum.

op_parse_tcp4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.in4
	p: acl.Packet
	for i in 0 ..< n {
		put16(pkt[:], 22, u16(i))
		acl.parse(pkt[:], &p)
		sink += u64(p.dport)
	}
	return
}

op_parse_tcp6 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.in6
	p: acl.Packet
	for i in 0 ..< n {
		put16(pkt[:], 42, u16(i))
		acl.parse(pkt[:], &p)
		sink += u64(p.dport)
	}
	return
}

op_parse_udp4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.udp
	p: acl.Packet
	for i in 0 ..< n {
		put16(pkt[:], 22, u16(i))
		acl.parse(pkt[:], &p)
		sink += u64(p.dport)
	}
	return
}

op_parse_err4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.err
	p: acl.Packet
	for i in 0 ..< n {
		// The destination port of the packet inside.
		put16(pkt[:], 50, u16(i))
		acl.parse(pkt[:], &p)
		sink += u64(p.inner.dport)
	}
	return
}

op_hash4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	local, remote := mapped(ME4), mapped(PEER4)
	for i in 0 ..< n {
		k := acl.key_make(4, acl.PROTO_TCP, &local, &remote, LPORT, u16(i))
		sink += u64(acl.key_hash(&c.a.table, &k))
	}
	return
}

op_hash6 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	local, remote := me6(), peer6()
	for i in 0 ..< n {
		k := acl.key_make(6, acl.PROTO_TCP, &local, &remote, LPORT, u16(i))
		sink += u64(acl.key_hash(&c.a.table, &k))
	}
	return
}

// One build of the hash. Each key depends on the hash before it, so this is
// the time from the key to the hash (a lookup waits for it).
hash_build :: proc(c: ^Ctx, v: acl.Hash_Variant, af: u8, n: int) -> (sink: u64) {
	local, remote := mapped(ME4), mapped(PEER4)
	if af == 6 {
		local, remote = me6(), peer6()
	}
	h: u32
	for i in 0 ..< n {
		k := acl.key_make(af, acl.PROTO_TCP, &local, &remote, LPORT, u16(i) ~ u16(h))
		h = v.hash(&c.a.table, &k)
		sink += u64(h)
	}
	return
}

// Checks each build of the hash against its reference, for IPv4 and IPv6
// keys. Returns the number of wrong values.
hash_check :: proc(c: ^Ctx, v: acl.Hash_Variant, keys: int) -> (bad: int) {
	seed := SEED
	r := Rng{0xD1B54A32D192ED03}
	for i in 0 ..< keys {
		af := u8(4 if i % 2 == 0 else 6)
		local, remote: acl.Addr
		if af == 4 {
			x, y := rng_next(&r), rng_next(&r)
			local = mapped({u8(x), u8(x >> 8), u8(x >> 16), u8(x >> 24)})
			remote = mapped({u8(y), u8(y >> 8), u8(y >> 16), u8(y >> 24)})
		} else {
			for j in 0 ..< 2 {
				x, y := rng_next(&r), rng_next(&r)
				for b in 0 ..< 8 {
					local[j * 8 + b], remote[j * 8 + b] = u8(x >> uint(8 * b)), u8(y >> uint(8 * b))
				}
			}
			local[0], remote[0] = 0xfd, 0x20
		}
		z := rng_next(&r)
		k := acl.key_make(af, u8(z >> 32), &local, &remote, u16(z), u16(z >> 16))
		want: u32
		if v.aes {
			want = acl.key_hash_soft(&c.a.table, &k)
		} else {
			msg: [39]u8
			n := 0
			if af == 4 {
				n += copy(msg[n:], local[12:])
				n += copy(msg[n:], remote[12:])
			} else {
				n += copy(msg[n:], local[:])
				n += copy(msg[n:], remote[:])
			}
			meta := transmute([8]u8)k.meta
			n += copy(msg[n:], meta[:7])
			want = u32(siphash.sum_bytes_1_3(msg[:n], seed[:]))
		}
		if v.hash(&c.a.table, &k) != want {
			bad += 1
		}
	}
	return
}

op_in_same4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.in4
	for _ in 0 ..< n {
		sink += u64(acl.inbound(&c.a, pkt[:], NOW))
	}
	return
}

op_in_same6 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.in6
	for _ in 0 ..< n {
		sink += u64(acl.inbound(&c.a, pkt[:], NOW))
	}
	return
}

op_out_same4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.out4
	for _ in 0 ..< n {
		acl.outbound(&c.a, pkt[:], NOW)
		sink += u64(pkt[9])
	}
	return
}

op_bulk :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	i4, o4 := c.in4, c.out4
	for k := 0; k < n; k += 3 {
		sink += u64(acl.inbound(&c.a, i4[:], NOW))
		sink += u64(acl.inbound(&c.a, i4[:], NOW))
		acl.outbound(&c.a, o4[:], NOW)
	}
	return
}

op_in_shuffled :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.in4
	j := c.pos
	for _ in 0 ..< n {
		flow_in4(pkt[:], c.order[j])
		j += 1
		if j == c.n {
			j = 0
		}
		sink += u64(acl.inbound(&c.a, pkt[:], NOW))
	}
	c.pos = j
	return
}

op_out_shuffled :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.out4
	j := c.pos
	for _ in 0 ..< n {
		flow_out4(pkt[:], c.order[j])
		j += 1
		if j == c.n {
			j = 0
		}
		acl.outbound(&c.a, pkt[:], NOW)
		sink += u64(pkt[9])
	}
	c.pos = j
	return
}

// A SYN to a port that no rule opens, from a new source each time.
op_deny :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.syn
	put16(pkt[:], 22, 23)
	for i in 0 ..< n {
		flow_in4(pkt[:], u32(i))
		sink += u64(acl.inbound(&c.a, pkt[:], NOW))
	}
	return
}

// The number of new flows of one round of the table operations.
round_size :: proc(c: ^Ctx) -> int {
	return max(c.n, 1000)
}

// New inbound flows that the rule `:22` lets in, into an empty table.
op_new_in :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.syn
	size := round_size(c)
	for done := 0; done < n; done += size {
		acl.reset(&c.a)
		t0 := time.tick_now()
		for i in 0 ..< size {
			flow_in4(pkt[:], flow_code(i))
			sink += u64(acl.inbound(&c.a, pkt[:], NOW))
		}
		c.elapsed += time.tick_since(t0)
	}
	return
}

// New outbound flows into an empty table.
op_new_out :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.out4
	size := round_size(c)
	for done := 0; done < n; done += size {
		acl.reset(&c.a)
		t0 := time.tick_now()
		for i in 0 ..< size {
			flow_out4(pkt[:], flow_code(i))
			acl.outbound(&c.a, pkt[:], NOW)
		}
		c.elapsed += time.tick_since(t0)
		sink += u64(acl.flows(&c.a))
	}
	return
}

// New outbound flows into a full table: each one replaces a flow.
op_out_full :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pkt := c.out4
	if acl.flows(&c.a) < c.a.table.max {
		acl.reset(&c.a)
		fill(c, c.a.table.max)
		c.next = c.a.table.max
	}
	for _ in 0 ..< n {
		flow_out4(pkt[:], flow_code(c.next))
		c.next += 1
		if c.next >= 4_000_000 {
			c.next = c.a.table.max
		}
		acl.outbound(&c.a, pkt[:], NOW)
	}
	sink += c.a.stats.evicted
	return
}

// One `tick` on a table of live flows: a share of the slots.
op_tick :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	if acl.flows(&c.a) < c.n {
		acl.reset(&c.a)
		fill(c, c.n)
	}
	for _ in 0 ..< n {
		acl.tick(&c.a, NOW)
		sink += u64(acl.flows(&c.a))
	}
	return
}

// `tick` on a table where every flow is expired, until the table is empty.
op_sweep :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	size := round_size(c)
	for done := 0; done < n; done += size {
		acl.reset(&c.a)
		fill(c, min(size, c.a.table.max))
		late := u32(NOW + 2 * 24 * 3600)
		t0 := time.tick_now()
		for acl.flows(&c.a) > 0 {
			acl.tick(&c.a, late)
		}
		c.elapsed += time.tick_since(t0)
		sink += c.a.stats.expired
	}
	return
}

Op :: struct {
	name:  string,
	run:   proc(c: ^Ctx, n: int) -> u64,
	scale: int, // iterations are iters / scale (slow operations)
}

PARSE_OPS := [?]Op {
	{"parse v4 tcp", op_parse_tcp4, 1},
	{"parse v6 tcp", op_parse_tcp6, 1},
	{"parse v4 udp", op_parse_udp4, 1},
	{"parse v4 icmp error", op_parse_err4, 1},
	{"key hash v4", op_hash4, 1},
	{"key hash v6", op_hash6, 1},
}

FLOW_OPS := [?]Op {
	{"in, same flow v4", op_in_same4, 1},
	{"in, same flow v6", op_in_same6, 1},
	{"out, same flow v4", op_out_same4, 1},
	{"tcp bulk, 2 in 1 out", op_bulk, 1},
	{"in, shuffled", op_in_shuffled, 1},
	{"out, shuffled", op_out_shuffled, 1},
}

TABLE_OPS := [?]Op {
	{"new in flow (rule :22)", op_new_in, 1},
	{"new out flow", op_new_out, 1},
	{"out flow, full table", op_out_full, 1},
	{"tick", op_tick, 200},
	{"sweep, per flow", op_sweep, 1},
}

// The best time of one operation, in ns.
measure :: proc(o: ^Options, c: ^Ctx, op: Op, sink: ^u64) -> f64 {
	iters := max(o.iters / op.scale, 1)
	sink^ += op.run(c, max(iters / 10, 1))
	best := max(f64)
	for _ in 0 ..< o.reps {
		c.elapsed = 0
		t0 := time.tick_now()
		sink^ += op.run(c, iters)
		d := time.tick_since(t0)
		done := iters
		if c.elapsed != 0 {
			// The operation measured the part that counts, in whole rounds.
			d = c.elapsed
			size := round_size(c)
			done = (iters + size - 1) / size * size
		}
		best = min(best, f64(time.duration_nanoseconds(d)) / f64(done))
	}
	c.elapsed = 0
	return best
}

print_header :: proc(title: string, cols: []int) {
	fmt.println()
	fmt.printf("%-26s", title)
	for v in cols {
		fmt.printf("%10d", v)
	}
	fmt.println()
}

main :: proc() {
	o := parse_options()
	sink: u64
	fmt.printfln("noirvpn acl bench: %d iterations x %d reps (best), 1 thread", o.iters, o.reps)
	fmt.printfln("flow entry %d bytes, packet info %d bytes", size_of(acl.Entry), size_of(acl.Packet))
	{
		c := setup(1, nil)
		variants, count := acl.hash_variants()
		fmt.printf("hash builds (the table uses the first):")
		failed := false
		for v in variants[:count] {
			bad := hash_check(c, v, 20000)
			fmt.printf(" %s %s", v.name, "ok" if bad == 0 else "WRONG")
			failed |= bad != 0
		}
		fmt.println()
		teardown(c)
		if failed {
			fmt.eprintln("a build of the hash does not give the values of its reference")
			os.exit(1)
		}
	}

	// The parse and the hash do not depend on the table.
	{
		c := setup(1, nil)
		fmt.println()
		fmt.printfln("%-26s%10s", "ns/op", "")
		for op in PARSE_OPS {
			fmt.printfln("%-26s%10.1f", op.name, measure(&o, c, op, &sink))
		}
		variants, count := acl.hash_variants()
		for v in variants[:count] {
			for af in ([2]u8{4, 6}) {
				sink += hash_build(c, v, af, o.iters / 10)
				best := max(f64)
				for _ in 0 ..< o.reps {
					t0 := time.tick_now()
					sink += hash_build(c, v, af, o.iters)
					best = min(best, f64(time.duration_nanoseconds(time.tick_since(t0))) / f64(o.iters))
				}
				fmt.printfln("%-26s%10.1f", fmt.tprintf("hash build %s, v%d", v.name, af), best)
			}
		}
		teardown(c)
	}

	// Known flows.
	{
		res := make([][len(FLOW_OPS)]f64, len(o.sizes))
		for size, si in o.sizes {
			c := setup(size, nil)
			slots := len(c.a.table.slots)
			fmt.eprintfln("%d flows: table of %d slots, %.1f MiB", size, slots, f64(slots * size_of(acl.Entry)) / (1 << 20))
			for op, oi in FLOW_OPS {
				res[si][oi] = measure(&o, c, op, &sink)
			}
			teardown(c)
		}
		print_header("ns/packet, flows:", o.sizes)
		for op, oi in FLOW_OPS {
			fmt.printf("%-26s", op.name)
			for _, si in o.sizes {
				fmt.printf("%10.1f", res[si][oi])
			}
			fmt.println()
		}
	}

	// A packet that no rule lets in.
	{
		res: [2][len(RULE_COUNTS)]f64
		for count, ri in RULE_COUNTS {
			prefix := make([]acl.Rule, count)
			ports := make([]acl.Rule, count)
			for i in 0 ..< count {
				prefix[i] = {target = .Prefix, addr = mapped({10, 200, u8(i), 0}), bits = 96 + 24, v4 = true, protos = acl.PROTOS_ALL}
				ports[i] = {target = .Tunnel, port_lo = u16(1000 + i), port_hi = u16(1000 + i), protos = acl.PROTOS_PORTS}
			}
			for rules, k in ([2][]acl.Rule{prefix, ports}) {
				c := setup(1000, rules)
				res[k][ri] = measure(&o, c, Op{"deny", op_deny, 1}, &sink)
				teardown(c)
			}
			delete(prefix)
			delete(ports)
		}
		print_header("ns/packet, rules:", RULE_COUNTS[:])
		for name, k in ([2]string{"deny, prefix rules", "deny, :port rules"}) {
			fmt.printf("%-26s", name)
			for _, ri in RULE_COUNTS {
				fmt.printf("%10.1f", res[k][ri])
			}
			fmt.println()
		}
	}

	// New flows, a full table and the sweep. The table holds exactly `size` flows.
	{
		sizes := make([dynamic]int)
		for size in o.sizes {
			if size >= 1000 {
				append(&sizes, size)
			}
		}
		if len(sizes) > 0 {
			res := make([][len(TABLE_OPS)]f64, len(sizes))
			rule := []acl.Rule{{target = .Tunnel, port_lo = 22, port_hi = 22, protos = acl.PROTOS_PORTS}}
			for size, si in sizes {
				c := setup(size, rule, size)
				for op, oi in TABLE_OPS {
					res[si][oi] = measure(&o, c, op, &sink)
				}
				teardown(c)
			}
			print_header("ns/op, table of flows:", sizes[:])
			for op, oi in TABLE_OPS {
				fmt.printf("%-26s", op.name)
				for _, si in sizes {
					fmt.printf("%10.1f", res[si][oi])
				}
				fmt.println()
			}
		}
	}
	fmt.println()
	fmt.println("sink", sink)
}
