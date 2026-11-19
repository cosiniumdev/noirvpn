// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:crypto"
import cnet "core:net"
import "core:time"
import "noir:bus"
import "noir:proto/acl"
import "noir:proto/push"

// `allow-inbound` in the data path:
//
//	tun read (read_tun_plain, read_tun_vnet, guest_pump_push) -> acl_out: record the flow
//	session open -> write_tun -> acl_in: pass, or drop
//
// `d.acl` is nil when the config has no `allow-inbound`: then nothing is
// filtered. A `forward` port is a rule for the tunnel addresses.

// `acl.deny` events in one second; the others are counted in the next one.
ACL_DENY_EVENTS :: 10

Acl_State :: struct {
	a:            acl.Acl,
	// Seconds of the loop clock at the last sweep.
	swept:        u32,
	deny_sec:     u32,
	deny_left:    int,
	deny_skipped: u64,
	// Lookups of the host names (acl_lookup.odin).
	lk:           Acl_Lookup,
}

acl_attach :: proc(d: ^Daemon) {
	cl := d.cfg
	if len(cl.allow_inbound) == 0 {
		return
	}
	rules := acl_rule_list(cl)
	seed: [16]u8
	crypto.rand_bytes(seed[:])
	st := new(Acl_State)
	acl.init(&st.a, rules, len(cl.acl_hosts), cl.acl_max_flows, seed)
	acl_lookup_init(st, cl.acl_hosts)
	d.acl = st
	logf(.Info, "allow-inbound: %d rule(s), up to %d flows", len(rules), cl.acl_max_flows)
}

acl_detach :: proc(d: ^Daemon) {
	if d.acl == nil {
		return
	}
	acl_lookup_destroy(d, d.acl)
	acl.destroy(&d.acl.a)
	free(d.acl)
	d.acl = nil
}

// The tunnel addresses of this connection, for `:port` rules and forwards.
acl_set_tunnel :: proc(d: ^Daemon, po: ^push.Pushed_Options) {
	if d.acl == nil {
		return
	}
	addrs: [2]acl.Addr
	n := 0
	if ifc, ok := po.ifconfig.?; ok {
		addrs[n] = acl.map4(ifc.a[:])
		n += 1
	}
	if ifc6, ok := po.ifconfig6.?; ok {
		addrs[n] = ifc6.addr
		n += 1
	}
	acl.set_tunnel(&d.acl.a, addrs[:n])
	acl_lookup_now(d)
}

@(private = "file")
acl_now :: #force_inline proc(d: ^Daemon) -> u32 {
	return u32(now_of(d) / time.Second)
}

@(private = "file")
acl_sweep :: #force_inline proc(st: ^Acl_State, now: u32) {
	if now != st.swept {
		st.swept = now
		acl.tick(&st.a, now)
	}
}

// An outbound packet (from the tun device).
acl_out :: #force_inline proc(d: ^Daemon, pkt: []u8) {
	st := d.acl
	now := acl_now(d)
	acl_sweep(st, now)
	acl.outbound(&st.a, pkt, now)
}

// An inbound packet (for the tun device). False: drop it.
acl_in :: proc(d: ^Daemon, pkt: []u8) -> bool {
	st := d.acl
	now := acl_now(d)
	acl_sweep(st, now)
	v := acl.inbound(&st.a, pkt, now)
	if v == .Pass {
		return true
	}
	d.stats.drop_acl += 1
	acl_deny_event(d, st, pkt, v, now)
	return false
}

@(private = "file")
acl_deny_event :: proc(d: ^Daemon, st: ^Acl_State, pkt: []u8, v: acl.Verdict, now: u32) {
	if now != st.deny_sec {
		st.deny_sec = now
		st.deny_left = ACL_DENY_EVENTS
	}
	if st.deny_left == 0 {
		st.deny_skipped += 1
		return
	}
	w := ev_begin(d)
	if w == nil {
		return
	}
	st.deny_left -= 1
	p: acl.Packet
	acl.parse(pkt, &p)
	bus.kv_str(w, "reason", acl_verdict_name(v))
	bus.kv_str(w, "proto", acl_proto_name(p.proto))
	bus.kv_str(w, "src", acl_addr_text(p.src, p.af))
	bus.kv_str(w, "dst", acl_addr_text(p.dst, p.af))
	if p.ports && (p.proto == acl.PROTO_TCP || p.proto == acl.PROTO_UDP) {
		bus.kv_u64(w, "sport", u64(p.sport))
		bus.kv_u64(w, "dport", u64(p.dport))
	}
	bus.kv_u64(w, "skipped", st.deny_skipped)
	st.deny_skipped = 0
	ev_emit(d, "acl.deny")
}

acl_verdict_name :: proc(v: acl.Verdict) -> string {
	switch v {
	case .Pass:
		return "pass"
	case .Drop_Rule:
		return "no_rule"
	case .Drop_Full:
		return "table_full"
	case .Drop_Bad:
		return "bad_header"
	case .Drop_Frag:
		return "fragment"
	}
	return "?"
}

@(private = "file")
acl_proto_name :: proc(p: u8) -> string {
	switch p {
	case acl.PROTO_TCP:
		return "tcp"
	case acl.PROTO_UDP:
		return "udp"
	case acl.PROTO_ICMP, acl.PROTO_ICMP6:
		return "icmp"
	}
	return "other"
}

// The text of an address, in the temp allocator.
acl_addr_text :: proc(a: acl.Addr, af: u8) -> string {
	if af == 4 {
		return cnet.address_to_string(cnet.IP4_Address{a[12], a[13], a[14], a[15]}, context.temp_allocator)
	}
	return cnet.address_to_string(transmute(cnet.IP6_Address)a, context.temp_allocator)
}

acl_write_stats :: proc(w: ^bus.Writer, d: ^Daemon) {
	if d.acl == nil {
		return
	}
	bus.kv_u64(w, "acl_flows", u64(acl.flows(&d.acl.a)))
	bus.kv_u64(w, "acl_flows_max", u64(d.acl.a.table.max))
	write_u64_fields(w, &d.acl.a.stats, "acl_")
}
