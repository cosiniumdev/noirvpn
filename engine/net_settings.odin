// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import cnet "core:net"
import "noir:bus"
import "noir:client"
import "noir:platform/sysnet"

// Settings object of a guest engine. Pure proc: plan and host capabilities in,
// JSON out. The host applies it (`establish()` Android, `setTunnelNetworkSettings`
// iOS) and replies with `nvpn_settings_done`.
// Rules:
//  1. No server-pin route in the plan: the engine has no server address (its
//     sockets are outside the tunnel).
//  2. `caps.exclude_routes` false: send included minus excluded ranges, as a
//     prefix list.
//  3. A DNS server that no tunnel route covers gets a host route.
//  4. `caps.split_dns` false: every name goes to the tunnel servers (`dns_all`
//     true, `match_domains` empty).

// What the host can do (`caps_json` of `nvpn_engine_new`).
Caps :: struct {
	platform:       string, // "ios", "android", "macos" or "test" (static text)
	exclude_routes: bool,
	split_dns:      bool,
}

// A network: the address with the host bits cleared, and the prefix length.
// An IPv4 network uses the first 4 bytes.
Net :: struct {
	addr: [16]u8,
	bits: u8,
}

// The most prefixes that the cut of rule 2 gives for one family.
NET_LIST_MAX :: 4096

// ------------------------------------------------------------------ prefixes

@(private = "file")
bit_of :: proc "contextless" (a: [16]u8, i: int) -> u8 {
	return (a[i / 8] >> u8(7 - i % 8)) & 1
}

// `a` with every bit from `bits` on cleared.
net_masked :: proc "contextless" (a: [16]u8, bits: int) -> [16]u8 {
	out := a
	for i in 0 ..< 16 {
		keep := clamp(bits - i * 8, 0, 8)
		out[i] &= u8((u16(0xff00) >> u16(keep)) & 0xff)
	}
	return out
}

// True when `outer` holds every address of `inner`.
net_covers :: proc "contextless" (outer, inner: Net) -> bool {
	if outer.bits > inner.bits {
		return false
	}
	return net_masked(inner.addr, int(outer.bits)) == outer.addr
}

// Clears the host bits, sorts, and drops the repeats and the networks that
// another one of the list covers.
net_normalize :: proc(list: ^[dynamic]Net) {
	for &n in list {
		n.addr = net_masked(n.addr, int(n.bits))
	}
	// Insertion sort: the lists are short. By address, then the shorter first.
	for i in 1 ..< len(list) {
		x := list[i]
		j := i
		for j > 0 && net_less(x, list[j - 1]) {
			list[j] = list[j - 1]
			j -= 1
		}
		list[j] = x
	}
	k := 0
	for i in 0 ..< len(list) {
		n := list[i]
		covered := false
		for j in 0 ..< k {
			if net_covers(list[j], n) {
				covered = true
				break
			}
		}
		if !covered {
			list[k] = n
			k += 1
		}
	}
	resize(list, k)
}

@(private = "file")
net_less :: proc "contextless" (a, b: Net) -> bool {
	for i in 0 ..< 16 {
		if a.addr[i] != b.addr[i] {
			return a.addr[i] < b.addr[i]
		}
	}
	return a.bits < b.bits
}

// The part of `inc` that `exc` leaves, as prefixes (rule 2). `width` is 32 or
// 128. `out` is cleared first. False if the list stopped at NET_LIST_MAX entries.
net_subtract :: proc(inc, exc: []Net, width: int, out: ^[dynamic]Net) -> (complete: bool) {
	clear(out)
	work := make([dynamic]Net, context.temp_allocator)
	next := make([dynamic]Net, context.temp_allocator)
	complete = true
	for p in inc {
		clear(&work)
		append(&work, Net{net_masked(p.addr, int(p.bits)), p.bits})
		for e0 in exc {
			e := Net{net_masked(e0.addr, int(e0.bits)), e0.bits}
			clear(&next)
			for r in work {
				switch {
				case net_covers(e, r):
					// All of it is excluded.
				case net_covers(r, e):
					// Cut E out of R: keep the other half at every step down.
					cur := r
					for cur.bits < e.bits {
						b := int(cur.bits)
						mine := bit_of(e.addr, b)
						sib := cur
						sib.bits = u8(b + 1)
						sib.addr = net_masked(cur.addr, b + 1)
						if mine == 0 {
							sib.addr[b / 8] |= u8(0x80) >> u8(b % 8)
						} else {
							cur.addr[b / 8] |= u8(0x80) >> u8(b % 8)
						}
						cur.bits = u8(b + 1)
						cur.addr = net_masked(cur.addr, b + 1)
						append(&next, sib)
					}
				case:
					append(&next, r)
				}
			}
			work, next = next, work
		}
		for r in work {
			if len(out) >= NET_LIST_MAX {
				complete = false
				break
			}
			append(out, r)
		}
	}
	_ = width
	net_normalize(out)
	return
}

// ------------------------------------------------------------------ settings

Settings_In :: struct {
	plan:      ^client.Plan,
	caps:      Caps,
	// The networks of the host: they stay outside the tunnel.
	host_nets: []client.Host_Net,
	block6:    bool,
	// The address of the server, for `remote`.
	remote:    Maybe(cnet.Address),
	// Leave out `remote` and `notes`: the text is then the key that says if
	// two settings objects are the same.
	core_only: bool,
}

@(private = "file")
Lists :: struct {
	inc:   [2][dynamic]Net, // [0] IPv4, [1] IPv6
	exc:   [2][dynamic]Net,
	redir: [2]bool,
	notes: [dynamic]string,
}

@(private = "file")
lists_make :: proc() -> (l: Lists) {
	for i in 0 ..< 2 {
		l.inc[i] = make([dynamic]Net, context.temp_allocator)
		l.exc[i] = make([dynamic]Net, context.temp_allocator)
	}
	l.notes = make([dynamic]string, context.temp_allocator)
	return
}

@(private = "file")
net_of_addr :: proc(a: sysnet.Address, bits: u8) -> (n: Net, v6: bool) {
	switch v in a {
	case sysnet.IP4_Address:
		o := cast([4]u8)v
		copy(n.addr[:], o[:])
		n.bits = bits
	case sysnet.IP6_Address:
		n.addr = transmute([16]u8)v
		n.bits = bits
		v6 = true
	}
	return
}

net_text :: proc(n: Net, v6: bool) -> string {
	if v6 {
		return net_fmt(ip6_str(n.addr), n.bits)
	}
	return net_fmt(ip4_str({n.addr[0], n.addr[1], n.addr[2], n.addr[3]}), n.bits)
}

@(private = "file")
net_fmt :: proc(addr: string, bits: u8) -> string {
	buf := make([]u8, len(addr) + 5, context.temp_allocator)
	n := copy(buf, addr)
	buf[n] = '/'
	n += 1
	digits: [3]u8
	k := 0
	v := int(bits)
	for {
		digits[k] = u8('0' + v % 10)
		k += 1
		v /= 10
		if v == 0 {
			break
		}
	}
	for k > 0 {
		k -= 1
		buf[n] = digits[k]
		n += 1
	}
	return string(buf[:n])
}

@(private = "file")
addr_text_of :: proc(a: sysnet.Address) -> string {
	return cnet.address_to_string(a, context.temp_allocator)
}

// Writes the settings object into `w`, which holds nothing yet.
settings_write :: proc(w: ^bus.Writer, in_: Settings_In) {
	plan := in_.plan
	l := lists_make()
	l.redir = {plan.redirect4, plan.redirect6}
	for s in plan.steps {
		if s.kind == .Add_Addr {
			// Subnet of the tunnel address. A kernel adds this route when it sets the
			// address; a Network Extension or VpnService does not, so add it here.
			// Skipped if the plan says no prefix route
			// (the subnet is a host network), and for a lone address (/32, /128).
			n, v6 := net_of_addr(s.addr, s.prefix_len)
			width: u8 = 128 if v6 else 32
			if !s.no_prefix_route && s.prefix_len < width {
				append(&l.inc[1 if v6 else 0], n)
			}
			continue
		}
		if s.kind != .Add_Route {
			continue
		}
		switch s.why {
		case .Server_Pin, .Redirect_Low, .Redirect_High, .Redirect_Default:
			// The pin is not used (rule 1). The host adds the default route.
			continue
		case .None, .Config_Route, .Pushed_Route:
		}
		n, v6 := net_of_addr(s.route.dst, s.route.dst_len)
		f := 1 if v6 else 0
		if s.on_tun {
			append(&l.inc[f], n)
		} else {
			append(&l.exc[f], n)
		}
	}
	for h in in_.host_nets {
		f := 1 if h.v6 else 0
		append(&l.exc[f], Net{h.addr, h.bits})
	}
	// Rule 3: a DNS server that no route covers.
	if plan.has_dns {
		for sv in plan.dns.servers {
			_, is6 := sv.address.(sysnet.IP6_Address)
			n, v6 := net_of_addr(sv.address, 128 if is6 else 32)
			f := 1 if v6 else 0
			if l.redir[f] {
				continue
			}
			own: Net
			have_own := false
			if v6 {
				if a, ok := plan.addr6.?; ok {
					own, _ = net_of_addr(a, plan.prefix6)
					have_own = true
				}
			} else if a, ok := plan.addr4.?; ok {
				own, _ = net_of_addr(a, plan.prefix4)
				have_own = true
			}
			covered := have_own && net_covers(Net{net_masked(own.addr, int(own.bits)), own.bits}, n)
			for r in l.inc[f] {
				if net_covers(Net{net_masked(r.addr, int(r.bits)), r.bits}, n) {
					covered = true
				}
			}
			if !covered {
				append(&l.inc[f], n)
				append(&l.notes, "a DNS server is outside the routes of the tunnel, so a host route was added for it")
			}
		}
	}
	// Rule 2.
	for f in 0 ..< 2 {
		net_normalize(&l.exc[f])
		if in_.caps.exclude_routes || len(l.exc[f]) == 0 {
			net_normalize(&l.inc[f])
			continue
		}
		width := 128 if f == 1 else 32
		base := make([dynamic]Net, context.temp_allocator)
		append(&base, ..l.inc[f][:])
		if l.redir[f] {
			append(&base, Net{})
			l.redir[f] = false
		}
		out := make([dynamic]Net, context.temp_allocator)
		if !net_subtract(base[:], l.exc[f][:], width, &out) {
			append(&l.notes, "the list of routes was shortened because it had too many prefixes")
		}
		l.inc[f] = out
		clear(&l.exc[f])
		append(&l.notes, "this system cannot exclude routes, so the routes are the included ranges minus the excluded ranges")
	}

	bus.begin_obj(w)
	if a, ok := plan.addr4.?; ok {
		bus.kv_str(w, "addr4", ip4_str(cast([4]u8)a))
		bus.kv_int(w, "prefix4", i64(plan.prefix4))
	}
	if a, ok := plan.addr6.?; ok {
		bus.kv_str(w, "addr6", ip6_str(transmute([16]u8)a))
		bus.kv_int(w, "prefix6", i64(plan.prefix6))
	}
	if plan.mtu > 0 {
		bus.kv_int(w, "mtu", i64(plan.mtu))
	}
	write_nets(w, "routes4", l.inc[0][:], false)
	write_nets(w, "routes6", l.inc[1][:], true)
	write_nets(w, "exclude4", l.exc[0][:], false)
	write_nets(w, "exclude6", l.exc[1][:], true)
	bus.kv_bool(w, "redirect4", l.redir[0])
	bus.kv_bool(w, "redirect6", l.redir[1])
	bus.kv_arr(w, "dns_servers")
	match := 0
	all := false
	if plan.has_dns {
		for sv in plan.dns.servers {
			bus.val_str(w, addr_text_of(sv.address))
		}
		match = len(plan.dns.routing_domains)
		all = plan.dns.default_route
	}
	bus.end(w)
	bus.kv_arr(w, "search_domains")
	if plan.has_dns {
		for d in plan.dns.search_domains {
			bus.val_str(w, d)
		}
	}
	bus.end(w)
	bus.kv_arr(w, "match_domains")
	if plan.has_dns && in_.caps.split_dns {
		for d in plan.dns.routing_domains {
			bus.val_str(w, d)
		}
	}
	bus.end(w)
	if !in_.caps.split_dns {
		all = true
	}
	_ = match
	bus.kv_bool(w, "dns_all", all)
	bus.kv_bool(w, "block6", in_.block6)
	if !in_.core_only {
		if r, ok := in_.remote.?; ok {
			bus.kv_str(w, "remote", addr_text_of(r))
		}
		bus.kv_arr(w, "notes")
		for n in plan.notes {
			if plan_note_for_user(n.kind) {
				bus.val_str(w, n.text)
			}
		}
		for n in l.notes {
			bus.val_str(w, n)
		}
		bus.end(w)
	}
	bus.end(w)
}

@(private = "file")
write_nets :: proc(w: ^bus.Writer, key: string, list: []Net, v6: bool) {
	bus.kv_arr(w, key)
	for n in list {
		bus.val_str(w, net_text(n, v6))
	}
	bus.end(w)
}
