// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Benchmark for package server: the lookups the data path performs for every
// packet, at 1k, 10k and 64k peers, one thread.
//
//	odin run server/bench -collection:noir=. -o:speed
//	odin run server/bench -collection:noir=. -o:speed -- -iters=2000000 -reps=5
//	odin run server/bench -collection:noir=. -o:speed -- -sizes=1000,65000
//
// Options (after `--`):
//
//	-iters=1000000   operations per measurement
//	-reps=3          repeat each measurement and report the best (least noise)
//	-sizes=1000,10000,65000   peer counts
//
// What is measured, per operation, in ns:
//
//	peers by id / addr / addr (miss) / vpn4 / vpn6    the peer table alone
//	lpm4 peer / lpm4 iroute / lpm4 miss               the route table alone
//	lpm6 peer / lpm6 iroute / lpm6 miss
//	from_tun v4 / v6      `registry_from_tun`: header parse and route lookup
//	from_peer v4 / v6     `registry_from_peer`: source check and verdict
//	from_peer v4 c2c      the same with client-to-client on
//	pin lookup            `pin_table_find` for a peers file of the same size
//	pool alloc+release    one dynamic v4 lease and its release
//
// Lookups visit peers in a shuffled order, so the cache behaves as it would
// under traffic from many clients. Every result is added to a sink that is
// printed at the end, so the compiler cannot drop the work.
package server_bench

import "core:encoding/base64"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"
import "noir:proto/config"
import "noir:server"

Options :: struct {
	iters: int,
	reps:  int,
	sizes: []int,
}

DEFAULT_SIZES := [?]int{1000, 10000, 65000}

parse_options :: proc() -> (o: Options) {
	o.iters = 1_000_000
	o.reps = 3
	o.sizes = DEFAULT_SIZES[:]
	for arg in os.args[1:] {
		switch {
		case strings.has_prefix(arg, "-iters="):
			o.iters = max(1000, strconv.parse_int(arg[len("-iters="):]) or_else 1_000_000)
		case strings.has_prefix(arg, "-reps="):
			o.reps = max(1, strconv.parse_int(arg[len("-reps="):]) or_else 3)
		case strings.has_prefix(arg, "-sizes="):
			list := make([dynamic]int)
			for part in strings.split(arg[len("-sizes="):], ",", context.temp_allocator) {
				n, ok := strconv.parse_int(part)
				if ok && n > 0 && n < 0xFFFFFE {
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

PEER_BASE :: u32(0x0A000002) // 10.0.0.2

peer_vpn4 :: proc(i: int) -> [4]u8 {
	return config.ipv4_from_u32(PEER_BASE + u32(i))
}

peer_vpn6 :: proc(i: int) -> (a: [16]u8) {
	a[0], a[1] = 0xfd, 0x00
	a[12], a[13], a[14], a[15] = u8(i >> 24), u8(i >> 16), u8(i >> 8), u8(i)
	a[11] = 1
	return
}

peer_addr :: proc(i: int) -> server.Addr_Key {
	return server.addr_key_v4({172, u8(16 + (i >> 16) % 16), u8(i >> 8), u8(i)}, u16(10000 + i % 50000))
}

// Peer i (every IROUTE_EVERY-th) also owns the /24 172.16+..., and a /48.
IROUTE_EVERY :: 16

iroute4_of :: proc(k: int) -> [4]u8 {
	return {192, u8(16 + (k >> 8) % 16), u8(k), 0}
}

iroute6_of :: proc(k: int) -> (a: [16]u8) {
	a[0], a[1] = 0xfd, 0x01
	a[2], a[3] = u8(k >> 8), u8(k)
	return
}

BATCH :: 4096

Ctx :: struct {
	n:         int,
	reg_c2c:   ^server.Registry,
	reg:       ^server.Registry,
	handles:   []server.Peer_Handle,
	// Shuffled order of peers to visit.
	order:     []u32,
	addrs:     []server.Addr_Key,
	miss:      []server.Addr_Key,
	vpn4:      [][4]u8,
	vpn6:      [][16]u8,
	ir4:       [][4]u8, // an address inside some peer's iroute
	ir6:       [][16]u8,
	miss4:     [][4]u8,
	miss6:     [][16]u8,
	tun4:      [][]u8,
	tun6:      [][]u8,
	peer4:     [][]u8, // packets from peers (the source is the peer's own address)
	peer6:     [][]u8,
	peer_c2c:  [][]u8, // from peers, destination another peer
	pins:      ^server.Pin_Table,
	digests:   [][32]u8,
	pools:     server.Pools,
	cfg:       config.Config,
}

ip4_packet :: proc(src, dst: [4]u8) -> []u8 {
	p := make([]u8, 40)
	p[0] = 0x45
	s, d := src, dst
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

ip6_packet :: proc(src, dst: [16]u8) -> []u8 {
	p := make([]u8, 60)
	p[0] = 0x60
	s, d := src, dst
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	return p
}

build :: proc(n: int, c2c: bool) -> (reg: ^server.Registry, handles: []server.Peer_Handle) {
	reg = new(server.Registry)
	ok := server.registry_init(
		reg,
		server.Registry_Params {
			max_peers = n,
			max_iroutes = n / IROUTE_EVERY + 16,
			reuse_delay = 30 * time.Second,
			hash_seed = 0xBEEF,
			client_to_client = c2c,
		},
	)
	if !ok {
		fmt.eprintln("registry_init failed")
		os.exit(1)
	}
	handles = make([]server.Peer_Handle, n)
	for i in 0 ..< n {
		h, got := server.registry_reserve(reg, 0)
		if !got {
			fmt.eprintln("registry_reserve failed at", i)
			os.exit(1)
		}
		lease := server.Lease {
			kind4 = .Dynamic,
			kind6 = .Dynamic,
			addr4 = peer_vpn4(i),
			addr6 = peer_vpn6(i),
		}
		ir4: []config.Iroute
		ir6: []config.Iroute6
		if i % IROUTE_EVERY == 0 {
			k := i / IROUTE_EVERY
			ir4 = []config.Iroute{{iroute4_of(k), 24}}
			ir6 = []config.Iroute6{{iroute6_of(k), 48}}
		}
		name := fmt.tprintf("user-%d", i)
		rej := server.registry_commit(reg, h, name, peer_addr(i), lease, ir4, ir6, {}, false, u64(i), 0)
		if rej != .None {
			fmt.eprintln("registry_commit failed at", i, rej)
			os.exit(1)
		}
		handles[i] = h
		free_all(context.temp_allocator)
	}
	return
}

setup :: proc(n: int) -> ^Ctx {
	c := new(Ctx)
	c.n = n
	c.reg, c.handles = build(n, false)
	c.reg_c2c, _ = build(n, true)
	r := Rng{12345}
	c.order = make([]u32, BATCH)
	for &o in c.order {
		o = u32(rng_next(&r) % u64(n))
	}
	c.addrs = make([]server.Addr_Key, BATCH)
	c.miss = make([]server.Addr_Key, BATCH)
	c.vpn4 = make([][4]u8, BATCH)
	c.vpn6 = make([][16]u8, BATCH)
	c.ir4 = make([][4]u8, BATCH)
	c.ir6 = make([][16]u8, BATCH)
	c.miss4 = make([][4]u8, BATCH)
	c.miss6 = make([][16]u8, BATCH)
	c.tun4 = make([][]u8, BATCH)
	c.tun6 = make([][]u8, BATCH)
	c.peer4 = make([][]u8, BATCH)
	c.peer6 = make([][]u8, BATCH)
	c.peer_c2c = make([][]u8, BATCH)
	n_ir := (n + IROUTE_EVERY - 1) / IROUTE_EVERY
	ext4 := [4]u8{8, 8, 8, 8}
	ext6 := peer_vpn6(0)
	ext6[0], ext6[1] = 0x20, 0x01
	for b in 0 ..< BATCH {
		i := int(c.order[b])
		c.addrs[b] = peer_addr(i)
		c.miss[b] = server.addr_key_v4({203, 0, u8(113 + i % 7), u8(i)}, u16(20000 + i % 30000))
		c.vpn4[b] = peer_vpn4(i)
		c.vpn6[b] = peer_vpn6(i)
		k := int(rng_next(&r) % u64(n_ir))
		host4 := iroute4_of(k)
		host4[3] = u8(1 + b % 250)
		c.ir4[b] = host4
		host6 := iroute6_of(k)
		host6[15] = u8(1 + b % 250)
		c.ir6[b] = host6
		c.miss4[b] = {11, u8(b >> 8), u8(b), u8(i)}
		m6 := peer_vpn6(0)
		m6[1] = 0x77
		m6[15] = u8(i)
		c.miss6[b] = m6
		c.tun4[b] = ip4_packet(ext4, peer_vpn4(i))
		c.tun6[b] = ip6_packet(ext6, peer_vpn6(i))
		c.peer4[b] = ip4_packet(peer_vpn4(i), ext4)
		c.peer6[b] = ip6_packet(peer_vpn6(i), ext6)
		j := int(rng_next(&r) % u64(n))
		c.peer_c2c[b] = ip4_packet(peer_vpn4(i), peer_vpn4(j))
	}
	// A peers file of n entries.
	sb := strings.builder_make()
	c.digests = make([][32]u8, n)
	for i in 0 ..< n {
		d := &c.digests[i]
		for j in 0 ..< 4 {
			v := rng_next(&r)
			for x in 0 ..< 8 {
				d[j * 8 + x] = u8(v >> u64(8 * x))
			}
		}
		strings.write_string(&sb, "u")
		strings.write_int(&sb, i)
		strings.write_string(&sb, " sha256:")
		text, _ := base64.encode(d[:], allocator = context.temp_allocator)
		strings.write_string(&sb, text)
		strings.write_byte(&sb, '\n')
	}
	peers := config.peers_parse(strings.to_string(sb), "bench.txt")
	if !config.peers_ok(&peers) {
		fmt.eprintln("bench peers file:", config.format_diagnostics(peers.diags))
		os.exit(1)
	}
	c.pins = server.pin_table_make(peers)

	c.cfg = config.build(config.parse_text("server 10.0.0.0 255.0.0.0\ndev tun\n<cert>\nC\n</cert>\n<key>\nK\n</key>\npeer-keys p\n", "bench.conf"))
	if !server.pools_init(&c.pools, &c.cfg.server, 0, 1 << 20) {
		fmt.eprintln("pools_init failed")
		os.exit(1)
	}
	return c
}

// The measured operations. Each runs `n` times and returns a sum.

op_by_id :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pt := &c.reg.peers
	for i in 0 ..< n {
		_, p := server.peers_by_id(pt, c.order[i & (BATCH - 1)])
		sink += p.user
	}
	return
}

op_by_addr :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pt := &c.reg.peers
	for i in 0 ..< n {
		_, p := server.peers_by_addr(pt, &c.addrs[i & (BATCH - 1)])
		sink += p.user
	}
	return
}

op_by_addr_miss :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pt := &c.reg.peers
	for i in 0 ..< n {
		_, p := server.peers_by_addr(pt, &c.miss[i & (BATCH - 1)])
		if p != nil {
			sink += 1
		}
	}
	return
}

op_by_vpn4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pt := &c.reg.peers
	for i in 0 ..< n {
		_, p := server.peers_by_vpn4(pt, c.vpn4[i & (BATCH - 1)])
		sink += p.user
	}
	return
}

op_by_vpn6 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	pt := &c.reg.peers
	for i in 0 ..< n {
		_, p := server.peers_by_vpn6(pt, &c.vpn6[i & (BATCH - 1)])
		sink += p.user
	}
	return
}

op_lpm4_peer :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	rt := &c.reg.routes
	for i in 0 ..< n {
		o, _, _ := server.route_lookup4(rt, c.vpn4[i & (BATCH - 1)])
		sink += u64(o)
	}
	return
}

op_lpm4_iroute :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	rt := &c.reg.routes
	for i in 0 ..< n {
		o, _, _ := server.route_lookup4(rt, c.ir4[i & (BATCH - 1)])
		sink += u64(o)
	}
	return
}

op_lpm4_miss :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	rt := &c.reg.routes
	for i in 0 ..< n {
		o, _, ok := server.route_lookup4(rt, c.miss4[i & (BATCH - 1)])
		sink += u64(o) + u64(ok)
	}
	return
}

op_lpm6_peer :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	rt := &c.reg.routes
	for i in 0 ..< n {
		o, _, _ := server.route_lookup6(rt, &c.vpn6[i & (BATCH - 1)])
		sink += u64(o)
	}
	return
}

op_lpm6_iroute :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	rt := &c.reg.routes
	for i in 0 ..< n {
		o, _, _ := server.route_lookup6(rt, &c.ir6[i & (BATCH - 1)])
		sink += u64(o)
	}
	return
}

op_lpm6_miss :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	rt := &c.reg.routes
	for i in 0 ..< n {
		o, _, ok := server.route_lookup6(rt, &c.miss6[i & (BATCH - 1)])
		sink += u64(o) + u64(ok)
	}
	return
}

op_from_tun4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	for i in 0 ..< n {
		h, v := server.registry_from_tun(c.reg, c.tun4[i & (BATCH - 1)])
		sink += u64(h.index) + u64(v)
	}
	return
}

op_from_tun6 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	for i in 0 ..< n {
		h, v := server.registry_from_tun(c.reg, c.tun6[i & (BATCH - 1)])
		sink += u64(h.index) + u64(v)
	}
	return
}

op_from_peer4 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	for i in 0 ..< n {
		b := i & (BATCH - 1)
		h, v := server.registry_from_peer(c.reg, c.handles[c.order[b]], c.peer4[b])
		sink += u64(h.index) + u64(v)
	}
	return
}

op_from_peer6 :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	for i in 0 ..< n {
		b := i & (BATCH - 1)
		h, v := server.registry_from_peer(c.reg, c.handles[c.order[b]], c.peer6[b])
		sink += u64(h.index) + u64(v)
	}
	return
}

op_from_peer4_c2c :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	for i in 0 ..< n {
		b := i & (BATCH - 1)
		h, v := server.registry_from_peer(c.reg_c2c, c.handles[c.order[b]], c.peer_c2c[b])
		sink += u64(h.index) + u64(v)
	}
	return
}

op_pin :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	for i in 0 ..< n {
		e := server.pin_table_find(c.pins, c.digests[c.order[i & (BATCH - 1)]])
		if e != nil {
			sink += 1
		}
	}
	return
}

op_pool :: proc(c: ^Ctx, n: int) -> (sink: u64) {
	ps := &c.pools
	names: [64]string
	for i in 0 ..< len(names) {
		names[i] = fmt.aprintf("pool-user-%d", i)
	}
	defer for s in names {
		delete(s)
	}
	for i in 0 ..< n {
		l, err := server.pools_acquire(ps, names[i & 63], nil, nil, 0)
		if err == .None {
			sink += u64(l.slot4)
			server.pools_release(ps, l, 0)
		}
	}
	return
}

Op :: struct {
	name:  string,
	run:   proc(c: ^Ctx, n: int) -> u64,
	scale: int, // iterations are iters / scale (slow ops)
}

OPS := [?]Op {
	{"peers by id", op_by_id, 1},
	{"peers by addr", op_by_addr, 1},
	{"peers by addr (miss)", op_by_addr_miss, 1},
	{"peers by vpn4", op_by_vpn4, 1},
	{"peers by vpn6", op_by_vpn6, 1},
	{"lpm4 peer (/32)", op_lpm4_peer, 1},
	{"lpm4 iroute (/24)", op_lpm4_iroute, 1},
	{"lpm4 miss", op_lpm4_miss, 1},
	{"lpm6 peer (/128)", op_lpm6_peer, 1},
	{"lpm6 iroute (/48)", op_lpm6_iroute, 1},
	{"lpm6 miss", op_lpm6_miss, 1},
	{"from_tun v4", op_from_tun4, 1},
	{"from_tun v6", op_from_tun6, 1},
	{"from_peer v4", op_from_peer4, 1},
	{"from_peer v6", op_from_peer6, 1},
	{"from_peer v4 c2c", op_from_peer4_c2c, 1},
	{"pin lookup", op_pin, 1},
	{"pool alloc+release", op_pool, 4},
}

main :: proc() {
	opts := parse_options()
	fmt.printfln("noirvpn server bench: %d iterations x %d reps (best), 1 thread", opts.iters, opts.reps)
	results := make([][len(OPS)]f64, len(opts.sizes))
	sink: u64
	for size, si in opts.sizes {
		c := setup(size)
		for op, oi in OPS {
			iters := opts.iters / op.scale
			best := max(f64)
			// Warm up once.
			sink += op.run(c, iters / 10)
			for _ in 0 ..< opts.reps {
				t0 := time.tick_now()
				sink += op.run(c, iters)
				ns := f64(time.duration_nanoseconds(time.tick_diff(t0, time.tick_now()))) / f64(iters)
				best = min(best, ns)
			}
			results[si][oi] = best
		}
		reg_mem := server.registry_memory(c.reg)
		fmt.printfln(
			"%d peers: registry %d bytes (%.1f B/peer; peers %.1f, routes %.1f), pin table %d entries",
			size,
			reg_mem,
			f64(reg_mem) / f64(size),
			f64(server.peers_memory(&c.reg.peers)) / f64(size),
			f64(server.route_memory(&c.reg.routes)) / f64(size),
			server.pin_table_len(c.pins),
		)
	}
	fmt.println()
	fmt.printf("%-24s", "ns/op")
	for size in opts.sizes {
		fmt.printf("%10d", size)
	}
	fmt.println()
	for op, oi in OPS {
		fmt.printf("%-24s", op.name)
		for _, si in opts.sizes {
			fmt.printf("%10.1f", results[si][oi])
		}
		fmt.println()
	}
	fmt.println("sink", sink)
}
