// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package acl

// The inbound filter of the client (`allow-inbound`).
//
//	outbound packet --> flow table: add or refresh the flow --> pass
//	inbound packet  --> flow table hit -----------------------> pass
//	                    miss --> rules match --> add the flow -> pass
//	                                       else ------------------> drop
//
// Replies to flows that the client started, and ICMP errors about them, always
// pass. One `Acl` is used by one thread.

Proto_Bit :: enum u8 {
	Tcp,
	Udp,
	Icmp,
	Other,
}
Protos :: bit_set[Proto_Bit;u8]

PROTOS_PORTS :: Protos{.Tcp, .Udp}
PROTOS_ALL :: Protos{.Tcp, .Udp, .Icmp, .Other}

Target :: enum u8 {
	Prefix, // `addr`/`bits`
	Tunnel, // the tunnel addresses of the client (`:port`)
	Host,   // the addresses of a name, set by `set_host`
}

// One destination of an `allow-inbound` line.
Rule :: struct {
	target:  Target,
	addr:    Addr, // Prefix: IPv4 mapped, with `bits` counted from bit 0 of the mapped form
	bits:    u8,
	v4:      bool, // Prefix: the family
	host:    int, // Host: index in `Acl.hosts`
	port_lo: u16, // 0: any port
	port_hi: u16,
	protos:  Protos,
}

MAX_HOST_ADDRS :: 16

Host :: struct {
	addrs: [MAX_HOST_ADDRS]Addr,
	n:     int,
}

MAX_TUNNEL_ADDRS :: 4

FRAG_SLOTS :: 256
FRAG_TIMEOUT :: 30

Frag_Entry :: struct {
	src, dst: Addr,
	id:       u32,
	last:     u32,
	proto:    u8, // `Packet.frag_proto`
	used:     bool,
}

// The sweep looks at every slot of the table in about this many seconds.
SWEEP_SECONDS :: 32
SWEEP_MIN :: 1024

Verdict :: enum u8 {
	Pass,
	Drop_Rule, // no flow, and no rule lets it in
	Drop_Full, // the table has no room for a new inbound flow
	Drop_Bad,  // the IP header is short or broken
	Drop_Frag, // a later fragment of a packet whose first fragment did not pass
}

Stats :: struct {
	in_new:      u64, // new inbound flows a rule let in
	in_denied:   u64,
	in_full:     u64,
	in_bad:      u64,
	in_frag:     u64,
	evicted:     u64, // flows replaced to make room for a new flow
	expired:     u64,
}

Acl :: struct {
	rules:     []Rule,
	hosts:     []Host,
	tunnel:    [MAX_TUNNEL_ADDRS]Addr,
	tunnel_n:  int,
	table:     Table,
	frags:     [FRAG_SLOTS]Frag_Entry,
	last_in:   int, // slot of the last flow hit, or -1
	last_out:  int,
	stats:     Stats,
}

// `rules` is copied. `hosts`: the number of `Host` targets that the rules
// point to.
init :: proc(a: ^Acl, rules: []Rule, hosts: int, max_flows: int, seed: [16]u8, allocator := context.allocator) {
	a^ = {}
	a.rules = make([]Rule, len(rules), allocator)
	copy(a.rules, rules)
	a.hosts = make([]Host, hosts, allocator)
	table_init(&a.table, max_flows, seed, allocator)
	a.last_in, a.last_out = -1, -1
}

// Replaces the rules and the `Host` targets; both are copied. Flows that exist
// stay, so only new inbound flows see the new rules.
set_rules :: proc(a: ^Acl, rules: []Rule, hosts: []Host, allocator := context.allocator) {
	delete(a.rules, allocator)
	delete(a.hosts, allocator)
	a.rules = make([]Rule, len(rules), allocator)
	copy(a.rules, rules)
	a.hosts = make([]Host, len(hosts), allocator)
	copy(a.hosts, hosts)
}

destroy :: proc(a: ^Acl, allocator := context.allocator) {
	delete(a.rules, allocator)
	delete(a.hosts, allocator)
	table_destroy(&a.table, allocator)
	a^ = {}
}

// Sets the addresses of a `Host` target. A flow that exists stays.
set_host :: proc "contextless" (a: ^Acl, idx: int, addrs: []Addr) {
	if idx < 0 || idx >= len(a.hosts) {
		return
	}
	h := &a.hosts[idx]
	h.n = min(len(addrs), MAX_HOST_ADDRS)
	copy(h.addrs[:h.n], addrs[:h.n])
}

// Sets the tunnel addresses of the client. The flows of an address that goes
// away are freed.
set_tunnel :: proc "contextless" (a: ^Acl, addrs: []Addr) {
	n := min(len(addrs), MAX_TUNNEL_ADDRS)
	for i in 0 ..< a.tunnel_n {
		old := a.tunnel[i]
		kept := false
		for j in 0 ..< n {
			if addrs[j] == old {
				kept = true
			}
		}
		if !kept {
			forget_local(a, old)
		}
	}
	copy(a.tunnel[:n], addrs[:n])
	a.tunnel_n = n
}

// Frees every flow whose local address is `addr`.
forget_local :: proc "contextless" (a: ^Acl, addr: Addr) {
	t := &a.table
	i := 0
	for i < len(t.slots) {
		e := &t.slots[i]
		if e.used && e.key.laddr == addr {
			table_delete(t, i)
			continue
		}
		i += 1
	}
	a.last_in, a.last_out = -1, -1
}

// Frees all flows (a new session that starts with nothing).
reset :: proc "contextless" (a: ^Acl) {
	table_clear(&a.table)
	a.frags = {}
	a.last_in, a.last_out = -1, -1
}

// Frees expired flows; call it once a second. `budget`: slots to look at
// (0: a share of the table, see SWEEP_SECONDS).
tick :: proc "contextless" (a: ^Acl, now: u32, budget := 0) {
	n := budget
	if n <= 0 {
		n = max(SWEEP_MIN, len(a.table.slots) / SWEEP_SECONDS)
	}
	a.stats.expired += u64(table_sweep(&a.table, now, n))
}

flows :: proc "contextless" (a: ^Acl) -> int {
	return a.table.count
}

// --------------------------------------------------------------- outbound

// A packet from the client into the tunnel: records its flow. Outbound packets
// always pass.
//
//	plain packet --> the last flow again --> step
//	             else ---------------------> outbound_flow
//	other packet --> parse ----------------> outbound_flow
outbound :: proc "contextless" (a: ^Acl, pkt: []u8, now: u32) {
	k: Flow_Key = ---
	if flags, plain := plain_key(pkt, true, &k); plain {
		if c := a.last_out; c >= 0 {
			e := &a.table.slots[c]
			if holds(e, &k) {
				#force_inline step(e, flags, .Out, now)
				return
			}
		}
		outbound_flow(a, &k, flags, now)
		return
	}
	p: Packet
	if !parse(pkt, &p) || p.frag == .Later {
		return
	}
	if p.icmp == .Error || p.icmp == .Other {
		return
	}
	k = key_make(p.af, p.proto, &p.src, &p.dst, p.sport, p.dport)
	outbound_flow(a, &k, p.tcp_flags, now)
}

// Finds or adds the flow `k` of an outbound packet.
@(private)
outbound_flow :: proc "contextless" (a: ^Acl, k: ^Flow_Key, flags: u8, now: u32) {
	t := &a.table
	slot := a.last_out
	if slot < 0 || !holds(&t.slots[slot], k) {
		h := key_hash(t, k)
		slot = table_find(t, k, h)
		if slot < 0 {
			removed: Removed
			slot, removed = table_insert(t, k, h, now, .Out)
			count_removed(a, removed)
			if slot < 0 {
				return
			}
		}
		a.last_out = slot
	}
	step(&t.slots[slot], flags, .Out, now)
}

// Is slot `e` the flow `k`? The slot numbers that `last_in` and `last_out`
// keep can be stale after a delete, so each use checks the key.
@(private)
holds :: #force_inline proc "contextless" (e: ^Entry, k: ^Flow_Key) -> bool {
	return e.used && key_equal(&e.key, k)
}

@(private)
count_removed :: #force_inline proc "contextless" (a: ^Acl, removed: Removed) {
	switch removed {
	case .None:
	case .Expired:
		a.stats.expired += 1
	case .Evicted:
		a.stats.evicted += 1
	}
}

// ---------------------------------------------------------------- inbound

// A packet from the tunnel to the client.
//
//	plain packet --> the last flow again --> step, pass
//	             else ---------------------> inbound_flow
//	other packet --> inbound_full: parse --> inbound_flow
inbound :: proc "contextless" (a: ^Acl, pkt: []u8, now: u32) -> Verdict {
	k: Flow_Key = ---
	if flags, plain := plain_key(pkt, false, &k); plain {
		if c := a.last_in; c >= 0 {
			e := &a.table.slots[c]
			if holds(e, &k) && admits(e, flags, now) {
				#force_inline step(e, flags, .In, now)
				return .Pass
			}
		}
		return inbound_flow(a, &k, flags, nil, now)
	}
	return inbound_full(a, pkt, now)
}

// An inbound packet that is not plain.
@(private)
inbound_full :: proc "contextless" (a: ^Acl, pkt: []u8, now: u32) -> Verdict {
	p: Packet
	if !parse(pkt, &p) {
		a.stats.in_bad += 1
		return .Drop_Bad
	}
	if p.frag == .Later {
		if frag_find(a, &p, now) {
			return .Pass
		}
		a.stats.in_frag += 1
		return .Drop_Frag
	}
	if p.icmp == .Error || p.icmp == .Other {
		// An error about a flow of the table passes. Other ICMP that is not
		// echo: the rules decide, and no flow is kept.
		if p.icmp == .Error && p.inner.ok && related(a, &p, now) {
			return .Pass
		}
		if match(a, &p) {
			return pass_frag(a, &p, now)
		}
		a.stats.in_denied += 1
		return .Drop_Rule
	}
	k := key_make(p.af, p.proto, &p.dst, &p.src, p.dport, p.sport)
	if c := a.last_in; c >= 0 {
		e := &a.table.slots[c]
		if holds(e, &k) && admits(e, p.tcp_flags, now) {
			step(e, p.tcp_flags, .In, now)
			return pass_frag(a, &p, now)
		}
	}
	return inbound_flow(a, &k, p.tcp_flags, &p, now)
}

// Finds the flow `k` of an inbound packet, or asks the rules. `full`: the
// packet info, or nil for a plain packet.
@(private)
inbound_flow :: proc "contextless" (a: ^Acl, k: ^Flow_Key, flags: u8, full: ^Packet, now: u32) -> Verdict {
	t := &a.table
	h := key_hash(t, k)
	if slot := table_find(t, k, h); slot >= 0 {
		e := &t.slots[slot]
		if admits(e, flags, now) {
			a.last_in = slot
			step(e, flags, .In, now)
			return pass_frag(a, full, now)
		}
		// The packet is new: the rules decide.
		if expired(e, now) {
			a.stats.expired += 1
		}
		table_delete(t, slot)
	}
	p := full
	plain: Packet = ---
	if p == nil {
		plain = plain_packet(k, flags)
		p = &plain
	}
	if !match(a, p) {
		a.stats.in_denied += 1
		return .Drop_Rule
	}
	slot, removed := table_insert(t, k, h, now, .In)
	count_removed(a, removed)
	if slot < 0 {
		a.stats.in_full += 1
		return .Drop_Full
	}
	step(&t.slots[slot], flags, .In, now)
	a.stats.in_new += 1
	a.last_in = slot
	return pass_frag(a, full, now)
}

// Does flow `e` let in an inbound packet with the TCP flags `flags`? Not when
// the flow is expired, and not a SYN on a connection that ended: that is a new
// connection.
@(private)
admits :: #force_inline proc "contextless" (e: ^Entry, flags: u8, now: u32) -> bool {
	if expired(e, now) {
		return false
	}
	ended := e.state == .Closed || e.state == .Fin
	return !(ended && flags & (TCP_SYN | TCP_ACK) == TCP_SYN)
}

// An ICMP error about a flow in the table. The packet inside was sent by the
// client, so its source is the local side.
@(private)
related :: proc "contextless" (a: ^Acl, p: ^Packet, now: u32) -> bool {
	if p.inner.src != p.dst {
		return false
	}
	k := key_make(p.af, p.inner.proto, &p.inner.src, &p.inner.dst, p.inner.sport, p.inner.dport)
	slot := table_find(&a.table, &k, key_hash(&a.table, &k))
	return slot >= 0 && !expired(&a.table.slots[slot], now)
}

// Passes the packet, and records a first fragment. `p` is nil for a plain
// packet: that is never a fragment.
@(private)
pass_frag :: #force_inline proc "contextless" (a: ^Acl, p: ^Packet, now: u32) -> Verdict {
	if p != nil && p.frag == .First {
		frag_add(a, p, now)
	}
	return .Pass
}

// The state of a flow after one more packet. `f`: its TCP flags. `dir`: who
// sent it.
//
//	TCP:   Syn --other side--> Reply --first side, no SYN--> Est
//	       any --FIN--> Fin, any --RST--> Closed
//	       Fin, Closed --SYN from the client--> Syn
//	other: One --other side--> Both
@(private)
step :: proc "contextless" (e: ^Entry, f: u8, dir: Origin, now: u32) {
	tcp := key_proto(&e.key) == PROTO_TCP
	if expired(e, now) {
		// An old flow that is used again starts over.
		e.state = .Syn if tcp else .One
		e.origin = dir
	}
	e.last = now
	if !tcp {
		if dir != e.origin {
			e.state = .Both
		}
		return
	}
	switch {
	case f & TCP_RST != 0:
		e.state = .Closed
	case f & TCP_FIN != 0:
		if e.state != .Closed {
			e.state = .Fin
		}
	case e.state == .Est:
	case e.state == .Syn:
		if dir != e.origin {
			e.state = .Reply
		}
	case e.state == .Reply:
		if dir == e.origin && f & TCP_SYN == 0 {
			e.state = .Est
		}
	case f & (TCP_SYN | TCP_ACK) == TCP_SYN:
		// Fin or Closed: the same ports used for a new connection. An inbound
		// SYN does not get here (see `admits`).
		e.state = .Syn
		e.origin = dir
	}
}

// ------------------------------------------------------------------ rules

proto_bit :: #force_inline proc "contextless" (p: ^Packet) -> Proto_Bit {
	switch p.proto {
	case PROTO_TCP:
		return .Tcp
	case PROTO_UDP:
		return .Udp
	case PROTO_ICMP, PROTO_ICMP6:
		return .Icmp
	}
	return .Other
}

// Does a rule let in a new inbound packet `p`?
match :: proc "contextless" (a: ^Acl, p: ^Packet) -> bool {
	bit := proto_bit(p)
	for &r in a.rules {
		if bit not_in r.protos {
			continue
		}
		if r.port_lo != 0 {
			if (bit != .Tcp && bit != .Udp) || !p.ports || p.dport < r.port_lo || p.dport > r.port_hi {
				continue
			}
		}
		switch r.target {
		case .Prefix:
			if (p.af == 4) == r.v4 && prefix_match(&p.dst, &r.addr, int(r.bits)) {
				return true
			}
		case .Tunnel:
			for i in 0 ..< a.tunnel_n {
				if a.tunnel[i] == p.dst {
					return true
				}
			}
		case .Host:
			if r.host >= 0 && r.host < len(a.hosts) {
				h := &a.hosts[r.host]
				for i in 0 ..< h.n {
					if h.addrs[i] == p.dst {
						return true
					}
				}
			}
		}
	}
	return false
}

// Are the first `bits` bits (0..128) of `x` and `net` equal?
prefix_match :: proc "contextless" (x, net: ^Addr, bits: int) -> bool {
	xh, xl := words(x)
	nh, nl := words(net)
	if bits > 64 {
		return xh == nh && (xl ~ nl) >> uint(128 - bits) == 0
	}
	return bits <= 0 || (xh ~ nh) >> uint(64 - bits) == 0
}

// -------------------------------------------------------------- fragments

// The slot of a fragmented packet: the keyed hash of the table over the
// addresses, the identification and the protocol.
@(private)
frag_slot :: proc "contextless" (a: ^Acl, p: ^Packet) -> ^Frag_Entry {
	k := key_make(p.af, p.frag_proto, &p.dst, &p.src, u16(p.frag_id), u16(p.frag_id >> 16))
	return &a.frags[key_hash(&a.table, &k) % FRAG_SLOTS]
}

@(private)
frag_add :: proc "contextless" (a: ^Acl, p: ^Packet, now: u32) {
	f := frag_slot(a, p)
	f^ = {
		src   = p.src,
		dst   = p.dst,
		id    = p.frag_id,
		last  = now,
		proto = p.frag_proto,
		used  = true,
	}
}

@(private)
frag_find :: proc "contextless" (a: ^Acl, p: ^Packet, now: u32) -> bool {
	f := frag_slot(a, p)
	return f.used && f.id == p.frag_id && f.proto == p.frag_proto && f.src == p.src && f.dst == p.dst && now - f.last <= FRAG_TIMEOUT
}
