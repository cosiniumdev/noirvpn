// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package sysnet

import "core:math/bits"
import cnet "core:net"
import "core:strconv"
import "core:strings"
import "core:sys/posix"

// Readers of the output of ifconfig(8), route(8) and netstat(1) on macOS, and
// builders of the command lines that change things. No state, no commands run,
// so tests feed them text that real commands printed.
//
// Commands run with LC_ALL=C and -n (numbers). The layout of these
// tools has not changed in many macOS releases, but Apple does not document it:
// every reader skips what it does not know.

// The interface index of a name, 0 if there is no such interface.
Index_Of :: proc(name: string) -> u32

// The real `Index_Of`: if_nametoindex(3).
name_to_index :: proc(name: string) -> u32 {
	if len(name) == 0 || len(name) >= IFNAMSIZ {
		return 0
	}
	cname := strings.clone_to_cstring(name, context.temp_allocator)
	return u32(posix.if_nametoindex(cname))
}

// The name of an interface index (if_indextoname(3)). `buf` is the storage.
index_to_name :: proc(index: u32, buf: []u8) -> (name: string, ok: bool) {
	if index == 0 || len(buf) < IFNAMSIZ {
		return "", false
	}
	cname := posix.if_indextoname(u32(index), raw_data(buf))
	if cname == nil {
		return "", false
	}
	return string(cname), true
}

// ---- small helpers ----

// `%zone` removed from an address text (`fe80::1%en0` is `fe80::1`).
@(private)
strip_zone :: proc(s: string) -> string {
	if i := strings.index_byte(s, '%'); i >= 0 {
		return s[:i]
	}
	return s
}

@(private)
parse_addr_text :: proc(s: string) -> (a: Address, ok: bool) {
	t := strip_zone(s)
	if a6, ok6 := cnet.parse_ip6_address(t); ok6 {
		return a6, true
	}
	if a4, ok4 := cnet.parse_ip4_address(t); ok4 {
		return a4, true
	}
	return nil, false
}

// The number of leading one bits of a netmask given as an address. False if
// the ones are not contiguous.
@(private)
mask_to_prefix :: proc(m: Address) -> (n: u8, ok: bool) {
	bytes: [16]u8
	size := 0
	switch v in m {
	case IP4_Address:
		v4 := v
		copy(bytes[:], v4[:])
		size = 4
	case IP6_Address:
		bytes = transmute([16]u8)v
		size = 16
	case:
		return 0, false
	}
	ones := 0
	seen_zero := false
	for i in 0 ..< size {
		b := bytes[i]
		for bit in 0 ..< 8 {
			if b & (0x80 >> uint(bit)) != 0 {
				if seen_zero {
					return 0, false
				}
				ones += 1
			} else {
				seen_zero = true
			}
		}
	}
	return u8(ones), true
}

// `0xffffff00` as a prefix length.
@(private)
hex_mask_prefix :: proc(s: string) -> (n: u8, ok: bool) {
	t := s
	if strings.has_prefix(t, "0x") || strings.has_prefix(t, "0X") {
		t = t[2:]
	}
	v, pok := strconv.parse_u64_of_base(t, 16)
	if !pok || v > 0xffff_ffff {
		return 0, false
	}
	m := u32(v)
	ones := int(bits.count_ones(m))
	// Contiguous: the ones are the leading bits.
	if ones > 0 && ones < 32 && m != ~u32(0) << u32(32 - ones) {
		return 0, false
	}
	return u8(ones), true
}

@(private)
flags_from_ifconfig :: proc(v: u32) -> (f: Link_Flags) {
	// IFF_* of <net/if.h> on macOS.
	if v & 0x1 != 0 {
		f += {.Up}
	}
	if v & 0x2 != 0 {
		f += {.Broadcast}
	}
	if v & 0x8 != 0 {
		f += {.Loopback}
	}
	if v & 0x10 != 0 {
		f += {.Point_To_Point}
	}
	if v & 0x40 != 0 {
		f += {.Running, .Lower_Up}
	}
	if v & 0x80 != 0 {
		f += {.No_ARP}
	}
	if v & 0x8000 != 0 {
		f += {.Multicast}
	}
	return
}

// The scope number of an address (the Linux numbers, as `Addr_Info.scope` says).
@(private)
scope_of :: proc(a: Address) -> u8 {
	switch v in a {
	case IP4_Address:
		if v[0] == 127 {
			return 254 // host
		}
		if v[0] == 169 && v[1] == 254 {
			return 253 // link
		}
	case IP6_Address:
		b := transmute([16]u8)v
		loopback := true
		for i in 0 ..< 15 {
			if b[i] != 0 {
				loopback = false
			}
		}
		if loopback && b[15] == 1 {
			return 254
		}
		if b[0] == 0xfe && b[1] & 0xc0 == 0x80 {
			return 253
		}
	}
	return 0
}

// ---- ifconfig ----

// Reads `ifconfig -a` (or `ifconfig NAME`) output. Links go to `links`, every
// inet and inet6 address to `addrs` with its link index. Neither list is
// cleared first.
parse_ifconfig :: proc(text: string, links: ^[dynamic]Link_Info, addrs: ^[dynamic]Addr_Info, index_of: Index_Of) {
	current: u32
	rest := text
	for line in strings.split_lines_iterator(&rest) {
		if len(line) == 0 {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			current = 0
			colon := strings.index_byte(line, ':')
			if colon <= 0 || !strings.contains(line, "flags=") {
				continue
			}
			l: Link_Info
			name := line[:colon]
			l.index = index_of(name)
			if l.index == 0 {
				continue // gone since the command ran
			}
			l.name_len = min(len(name), IFNAMSIZ - 1)
			copy(l.name_buf[:l.name_len], name)
			if i := strings.index(line, "flags="); i >= 0 {
				v := line[i + len("flags="):]
				end := 0
				for end < len(v) && v[end] != '<' && v[end] != ' ' {
					end += 1
				}
				if fv, ok := strconv.parse_u64_of_base(v[:end], 16); ok {
					l.flags = flags_from_ifconfig(u32(fv))
				}
			}
			if i := strings.index(line, " mtu "); i >= 0 {
				v := line[i + len(" mtu "):]
				end := 0
				for end < len(v) && v[end] >= '0' && v[end] <= '9' {
					end += 1
				}
				if mv, ok := strconv.parse_u64_of_base(v[:end], 10); ok {
					l.mtu = u32(mv)
				}
			}
			if strings.has_prefix(name, "utun") {
				l.kind_len = copy(l.kind_buf[:], "tun")
			}
			append(links, l)
			current = l.index
			continue
		}
		if current == 0 {
			continue
		}
		fields := strings.fields(line, context.temp_allocator)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "inet":
			a, ok := parse_addr_text(fields[1])
			if !ok {
				continue
			}
			info := Addr_Info {
				index   = current,
				address = a,
				scope   = scope_of(a),
			}
			info.prefix_len = 32
			for i := 2; i + 1 < len(fields); i += 1 {
				switch fields[i] {
				case "-->":
					if p, pok := parse_addr_text(fields[i + 1]); pok {
						info.peer = p
					}
				case "netmask":
					if n, nok := hex_mask_prefix(fields[i + 1]); nok {
						info.prefix_len = n
					}
				}
			}
			append(addrs, info)
		case "inet6":
			a, ok := parse_addr_text(fields[1])
			if !ok {
				continue
			}
			info := Addr_Info {
				index   = current,
				address = a,
				scope   = scope_of(a),
			}
			info.prefix_len = 128
			for i := 2; i + 1 < len(fields); i += 1 {
				switch fields[i] {
				case "-->":
					if p, pok := parse_addr_text(fields[i + 1]); pok {
						info.peer = p
					}
				case "prefixlen":
					if n, nok := strconv.parse_u64_of_base(fields[i + 1], 10); nok && n <= 128 {
						info.prefix_len = u8(n)
					}
				}
			}
			append(addrs, info)
		}
	}
}

// ---- route get ----

// Reads the output of `route -n get DEST`. `v6` says which family was asked:
// `default` and the mask `default` mean different lengths of zero bits there.
parse_route_get :: proc(text: string, v6: bool, index_of: Index_Of) -> (r: Route, ok: bool) {
	have_dst := false
	have_mask := false
	dst_default := false
	rest := text
	for line in strings.split_lines_iterator(&rest) {
		colon := strings.index_byte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.trim_space(line[:colon])
		val := strings.trim_space(line[colon + 1:])
		switch key {
		case "destination":
			if val == "default" {
				dst_default = true
				r.dst = IP6_Address{} if v6 else IP4_Address{}
				have_dst = true
			} else if a, aok := parse_addr_text(val); aok {
				r.dst = a
				have_dst = true
			}
		case "mask":
			have_mask = true
			if val == "default" {
				r.dst_len = 0
			} else if a, aok := parse_addr_text(val); aok {
				if n, nok := mask_to_prefix(a); nok {
					r.dst_len = n
				}
			}
		case "gateway":
			// `link#12` and link-level addresses mean "on the interface".
			if a, aok := parse_addr_text(val); aok {
				r.gateway = a
			}
		case "interface":
			r.ifindex = index_of(val)
		case "flags":
			if strings.contains(val, "BLACKHOLE") {
				r.kind = .Blackhole
			} else if strings.contains(val, "REJECT") {
				r.kind = .Unreachable
			}
		}
	}
	if !have_dst {
		return {}, false
	}
	if !have_mask && !dst_default {
		_, is6 := r.dst.(IP6_Address)
		r.dst_len = 128 if is6 else 32
	}
	if dst_default {
		r.dst_len = 0
	}
	if v6 {
		r.family = .V6
	}
	return r, true
}

// ---- netstat ----

// Reads `netstat -rn -f inet` or `-f inet6` output into `out` (not cleared
// first). With `proto1`, only routes with flag `1` (RTF_PROTO1, the mark of
// our routes) are taken, with `protocol` as protocol number. Cloned entries
// (`W`) are left out.
parse_netstat :: proc(text: string, family: Family, index_of: Index_Of, out: ^[dynamic]Route, proto1: bool, protocol: u8) {
	rest := text
	for line in strings.split_lines_iterator(&rest) {
		fields := strings.fields(line, context.temp_allocator)
		if len(fields) < 4 {
			continue
		}
		switch fields[0] {
		case "Destination", "Routing", "Internet:", "Internet6:":
			continue
		}
		dest, gw, flags, netif := fields[0], fields[1], fields[2], fields[3]
		if strings.contains(flags, "W") {
			continue
		}
		tagged := strings.contains(flags, "1")
		if proto1 && !tagged {
			continue
		}
		host := strings.contains(flags, "H")
		r: Route
		if family == .V6 {
			r.family = .V6
		}
		ok: bool
		r.dst, r.dst_len, ok = parse_netstat_dest(dest, family, host)
		if !ok {
			continue
		}
		if a, aok := parse_addr_text(gw); aok {
			// A gateway of the other family is not a gateway of this route.
			_, a6 := a.(IP6_Address)
			if a6 == (family == .V6) {
				r.gateway = a
			}
		}
		r.ifindex = index_of(netif)
		if strings.contains(flags, "B") {
			r.kind = .Blackhole
		} else if strings.contains(flags, "R") {
			r.kind = .Unreachable
		}
		if tagged {
			r.protocol = protocol
		}
		append(out, r)
	}
}

// The destination column: `default`, `10.100/16`, `127`, `10.0.0.7/32`,
// `fe80::%lo0/64`, `::1`.
@(private)
parse_netstat_dest :: proc(s: string, family: Family, host: bool) -> (a: Address, n: u8, ok: bool) {
	if s == "default" {
		return default_dst(family), 0, true
	}
	text := s
	explicit := -1
	if i := strings.index_byte(text, '/'); i >= 0 {
		v, vok := strconv.parse_u64_of_base(text[i + 1:], 10)
		if !vok || v > 128 {
			return nil, 0, false
		}
		explicit = int(v)
		text = text[:i]
	}
	text = strip_zone(text)
	if family == .V6 {
		a6, a6ok := cnet.parse_ip6_address(text)
		if !a6ok {
			return nil, 0, false
		}
		if explicit >= 0 {
			return a6, u8(explicit), true
		}
		return a6, 128, true
	}
	// IPv4 networks drop the zero octets at the end (`10.100` is 10.100.0.0).
	parts := strings.split(text, ".", context.temp_allocator)
	if len(parts) == 0 || len(parts) > 4 {
		return nil, 0, false
	}
	oct: [4]u8
	for p, i in parts {
		v, vok := strconv.parse_u64_of_base(p, 10)
		if !vok || v > 255 {
			return nil, 0, false
		}
		oct[i] = u8(v)
	}
	switch {
	case explicit >= 0:
		if explicit > 32 {
			return nil, 0, false
		}
		n = u8(explicit)
	case host:
		n = 32
	case:
		// No length: the classful size of what was written.
		n = u8(8 * len(parts))
	}
	return IP4_Address(oct), n, true
}

// ---- command lines ----

// The interface of a name that starts with `utun`: a point-to-point tunnel
// with no link layer, so a route through it never has a gateway to resolve.
@(private)
is_utun :: proc(name: string) -> bool {
	return strings.has_prefix(name, "utun")
}

@(private)
addr_text :: proc(a: Address) -> string {
	return cnet.address_to_string(a, context.temp_allocator)
}

@(private)
is_link_local6 :: proc(a: Address) -> bool {
	if v, ok := a.(IP6_Address); ok {
		b := transmute([16]u8)v
		return b[0] == 0xfe && b[1] & 0xc0 == 0x80
	}
	return false
}

@(private)
v4_mask_text :: proc(prefix_len: u8) -> string {
	m: u32
	if prefix_len > 0 {
		m = ~u32(0) << u32(32 - min(prefix_len, 32))
	}
	return strings.clone(
		cnet.address_to_string(IP4_Address{u8(m >> 24), u8(m >> 16), u8(m >> 8), u8(m)}, context.temp_allocator),
		context.temp_allocator,
	)
}

// `ifconfig` arguments that add an address. `peer` is the other end of a
// point-to-point address. A utun interface always has one: without a peer the
// address itself is used (what a subnet topology needs).
build_addr_add :: proc(ifname: string, addr: Address, prefix_len: u8, peer: Maybe(Address)) -> (argv: []string, err: Error) {
	out := make([dynamic]string, context.temp_allocator)
	append(&out, IFCONFIG, ifname)
	switch v in addr {
	case IP4_Address:
		if prefix_len > 32 {
			return nil, .Invalid
		}
		append(&out, "inet", addr_text(addr))
		if p, ok := peer.?; ok {
			if _, p4 := p.(IP4_Address); !p4 {
				return nil, .Invalid
			}
			append(&out, addr_text(p))
		} else if is_utun(ifname) {
			append(&out, addr_text(addr))
		}
		append(&out, "netmask", v4_mask_text(prefix_len), "alias")
	case IP6_Address:
		if prefix_len > 128 {
			return nil, .Invalid
		}
		append(&out, "inet6", addr_text(addr), "prefixlen", fmt_u8(prefix_len), "alias")
	case:
		return nil, .Invalid
	}
	return out[:], .None
}

// The arguments of `ifconfig` that remove an address.
build_addr_del :: proc(ifname: string, addr: Address) -> (argv: []string, err: Error) {
	out := make([dynamic]string, context.temp_allocator)
	append(&out, IFCONFIG, ifname)
	switch v in addr {
	case IP4_Address:
		append(&out, "inet", addr_text(addr), "-alias")
	case IP6_Address:
		append(&out, "inet6", addr_text(addr), "-alias")
	case:
		return nil, .Invalid
	}
	return out[:], .None
}

@(private)
fmt_u8 :: proc(v: u8) -> string {
	buf: [4]u8
	return strings.clone(strconv.write_uint(buf[:], u64(v), 10), context.temp_allocator)
}

// Which command a route line is for.
Route_Verb :: enum {
	Add,
	Delete,
	Change,
}

// `route` arguments for a route. A delete names only the destination.
// `ifname` is the name of `r.ifindex` ("" if none or gone).
// - Out of a utun: on-link, no gateway (point-to-point, no next hop).
// - Gateway elsewhere: `-ifp` names the interface, so two interfaces on one
//   subnet cannot swap places.
// - No gateway: `-interface`.
// - Protocol number: `-proto1`, so `route_list_protocol` finds it.
build_route :: proc(verb: Route_Verb, r: Route, ifname: string) -> (argv: []string, err: Error) {
	out := make([dynamic]string, context.temp_allocator)
	append(&out, ROUTE, "-n")
	switch verb {
	case .Add:
		append(&out, "add")
	case .Delete:
		append(&out, "delete")
	case .Change:
		append(&out, "change")
	}
	v6: bool
	max_len: u8 = 32
	switch _ in r.dst {
	case IP4_Address:
	case IP6_Address:
		v6 = true
		max_len = 128
	case:
		// A nil destination is the default route of `r.family`.
		v6 = r.family == .V6
		max_len = 128 if v6 else 32
	}
	if r.dst_len > max_len {
		return nil, .Invalid
	}
	dst := r.dst if r.dst != nil else default_dst(r.family)
	append(&out, "-inet6" if v6 else "-inet")
	switch {
	case r.dst_len == 0:
		append(&out, "default")
	case r.dst_len == max_len:
		append(&out, "-host", addr_text(dst))
	case v6:
		append(&out, "-net", addr_text(dst), "-prefixlen", fmt_u8(r.dst_len))
	case:
		append(&out, "-net", strings.concatenate({addr_text(dst), "/", fmt_u8(r.dst_len)}, context.temp_allocator))
	}

	if verb == .Delete {
		// The destination names the route. The next hop is not needed, and a
		// gateway that is not reachable any more could only get in the way.
		if r.kind == .Local || r.kind == .Other {
			return nil, .Unsupported
		}
		return out[:], .None
	}
	switch r.kind {
	case .Unicast:
		gw, has_gw := r.gateway.?
		if has_gw {
			if _, g6 := gw.(IP6_Address); g6 != v6 {
				return nil, .Invalid
			}
		}
		switch {
		case ifname != "" && (!has_gw || is_utun(ifname)):
			append(&out, "-interface", ifname)
		case has_gw:
			text := addr_text(gw)
			if is_link_local6(gw) && ifname != "" {
				text = strings.concatenate({text, "%", ifname}, context.temp_allocator)
			}
			append(&out, text)
			if ifname != "" {
				append(&out, "-ifp", ifname)
			}
		case:
			return nil, .Invalid
		}
	case .Blackhole:
		append(&out, "::1" if v6 else "127.0.0.1", "-blackhole")
	case .Unreachable, .Prohibit:
		append(&out, "::1" if v6 else "127.0.0.1", "-reject")
	case .Local, .Other:
		return nil, .Unsupported
	}
	if r.protocol != 0 {
		append(&out, "-proto1")
	}
	return out[:], .None
}

// The arguments of `route` that look up a destination (`default` for the
// default route of a family).
build_route_get :: proc(dst: Address, family: Family, default: bool) -> []string {
	out := make([dynamic]string, context.temp_allocator)
	append(&out, ROUTE, "-n", "get")
	if family == .V6 {
		append(&out, "-inet6")
	}
	if default {
		append(&out, "default")
	} else {
		append(&out, addr_text(dst))
	}
	return out[:]
}
