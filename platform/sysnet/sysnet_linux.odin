// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import "core:mem"
import "core:sys/linux"
import "noir:platform/netlink"

// One netlink socket and its receive buffer.
Conn :: struct {
	nl:        netlink.Socket,
	rx:        []u8,
	allocator: mem.Allocator,
}

// Open a connection. `rx_size` is the receive buffer: it must hold the largest
// reply datagram. 32 KiB is what the kernel recommends for dumps.
open :: proc(allocator := context.allocator, rx_size := 32768) -> (c: Conn, err: Error) {
	nl, nerr := netlink.open(netlink.NETLINK_ROUTE)
	if nerr != .None {
		return {}, map_nl_error(nl.errno, nerr)
	}
	rx, aerr := make([]u8, rx_size, allocator)
	if aerr != nil {
		netlink.close(&nl)
		return {}, .No_Buffer
	}
	return {nl = nl, rx = rx, allocator = allocator}, .None
}

close :: proc(c: ^Conn) {
	netlink.close(&c.nl)
	delete(c.rx, c.allocator)
	c.rx = nil
}

// The kernel's own explanation of the last failure, when it gave one.
last_error_text :: proc(c: ^Conn) -> string {
	return netlink.ext_message(&c.nl)
}

// The errno of the last failure.
last_errno :: proc(c: ^Conn) -> linux.Errno {
	return c.nl.errno
}

@(private)
map_errno :: proc "contextless" (e: linux.Errno) -> Error {
	#partial switch e {
	case .NONE:
		return .None
	case .EEXIST:
		return .Exists
	case .ENOENT, .ESRCH, .ENODEV, .EADDRNOTAVAIL:
		return .Not_Found
	case .EPERM, .EACCES:
		return .Permission
	case .EOPNOTSUPP, .EAFNOSUPPORT, .EPROTONOSUPPORT, .ENOSYS:
		return .Unsupported
	case .EINVAL:
		return .Invalid
	case .ENETUNREACH:
		return .Network_Unreachable
	case .ENOBUFS, .ENOMEM:
		return .No_Buffer
	case .EBUSY:
		return .Busy
	}
	return .Other
}

@(private)
map_nl_error :: proc "contextless" (errno: linux.Errno, err: netlink.Error) -> Error {
	switch err {
	case .None:
		return .None
	case .Kernel:
		if e := map_errno(errno); e != .None {
			return e
		}
		return .Other
	case .Io:
		return map_errno(errno) if errno == .EPERM || errno == .EACCES || errno == .EAFNOSUPPORT else .Io
	case .Timeout:
		return .Timeout
	case .Buffer_Too_Small, .Oversize, .Truncated, .Unexpected, .Dump_Interrupted:
		return .Protocol
	}
	return .Other
}

// ---- address helpers ----

// The bytes and family of an address.
@(private)
addr_bytes :: proc "contextless" (a: Address) -> (b: [16]u8, n: int, family: u8, ok: bool) {
	switch v in a {
	case IP4_Address:
		o := cast([4]u8)v
		copy(b[:], o[:])
		return b, 4, netlink.AF_INET, true
	case IP6_Address:
		return transmute([16]u8)v, 16, netlink.AF_INET6, true
	}
	return {}, 0, 0, false
}

@(private)
addr_from_bytes :: proc "contextless" (data: []u8, family: u8) -> (a: Address, ok: bool) {
	switch family {
	case netlink.AF_INET:
		if len(data) != 4 {
			return nil, false
		}
		return IP4_Address{data[0], data[1], data[2], data[3]}, true
	case netlink.AF_INET6:
		if len(data) != 16 {
			return nil, false
		}
		b: [16]u8
		copy(b[:], data)
		return IP6_Address(transmute([8]u16be)b), true
	}
	return nil, false
}

@(private)
family_byte :: proc "contextless" (f: Family) -> u8 {
	return netlink.AF_INET if f == .V4 else netlink.AF_INET6
}

@(private)
max_prefix :: proc "contextless" (family: u8) -> u8 {
	return 32 if family == netlink.AF_INET else 128
}

// ---- message builders (pure: no socket, so they can be tested by bytes) ----

@(private)
finish_build :: proc(b: ^netlink.Builder) -> (msg: []u8, err: Error) {
	out, nerr := netlink.finish(b)
	if nerr != .None {
		return nil, .Protocol
	}
	return out, .None
}

// RTM_NEWLINK to change flags, MTU and/or transmit queue length of a link.
build_link_set :: proc(
	buf: []u8,
	seq: u32,
	index: u32,
	flags: Link_Flags,
	change: Link_Flags,
	mtu: Maybe(u32),
	txqlen: Maybe(u32) = nil,
) -> (
	msg: []u8,
	err: Error,
) {
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(&b, netlink.RTM_NEWLINK, netlink.NLM_F_REQUEST | netlink.NLM_F_ACK, seq)
	netlink.put_struct(
		&b,
		netlink.Ifinfomsg{index = i32(index), flags = transmute(u32)flags, change = transmute(u32)change},
	)
	if m, has := mtu.?; has {
		netlink.put_u32(&b, netlink.IFLA_MTU, m)
	}
	if q, has := txqlen.?; has {
		netlink.put_u32(&b, netlink.IFLA_TXQLEN, q)
	}
	return finish_build(&b)
}

// RTM_GETLINK for one link, by index (if not 0) or by name.
build_link_get :: proc(buf: []u8, seq: u32, index: u32, name: string) -> (msg: []u8, err: Error) {
	if index == 0 && (len(name) == 0 || len(name) >= IFNAMSIZ) {
		return nil, .Invalid
	}
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(&b, netlink.RTM_GETLINK, netlink.NLM_F_REQUEST | netlink.NLM_F_ACK, seq)
	netlink.put_struct(&b, netlink.Ifinfomsg{index = i32(index)})
	if index == 0 {
		netlink.put_str(&b, netlink.IFLA_IFNAME, name)
	}
	return finish_build(&b)
}

// RTM_GETLINK dump of all links.
build_link_dump :: proc(buf: []u8, seq: u32) -> (msg: []u8, err: Error) {
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(&b, netlink.RTM_GETLINK, netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP, seq)
	netlink.put_struct(&b, netlink.Ifinfomsg{})
	return finish_build(&b)
}

// RTM_NEWLINK that creates a link of kind "ovpn" (the kernel DCO device).
// `mode` is `netlink.OVPN_MODE_P2P` or `netlink.OVPN_MODE_MP`.
build_link_add_ovpn :: proc(buf: []u8, seq: u32, name: string, mode: u8) -> (msg: []u8, err: Error) {
	if len(name) == 0 || len(name) >= IFNAMSIZ {
		return nil, .Invalid
	}
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(
		&b,
		netlink.RTM_NEWLINK,
		netlink.NLM_F_REQUEST | netlink.NLM_F_ACK | netlink.NLM_F_CREATE | netlink.NLM_F_EXCL,
		seq,
	)
	netlink.put_struct(&b, netlink.Ifinfomsg{})
	netlink.put_str(&b, netlink.IFLA_IFNAME, name)
	info := netlink.nest_begin(&b, netlink.IFLA_LINKINFO)
	netlink.put_str(&b, netlink.IFLA_INFO_KIND, "ovpn")
	data := netlink.nest_begin(&b, netlink.IFLA_INFO_DATA)
	netlink.put_u8(&b, netlink.IFLA_OVPN_MODE, mode)
	netlink.nest_end(&b, data)
	netlink.nest_end(&b, info)
	return finish_build(&b)
}

// RTM_DELLINK.
build_link_del :: proc(buf: []u8, seq: u32, index: u32) -> (msg: []u8, err: Error) {
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(&b, netlink.RTM_DELLINK, netlink.NLM_F_REQUEST | netlink.NLM_F_ACK, seq)
	netlink.put_struct(&b, netlink.Ifinfomsg{index = i32(index)})
	return finish_build(&b)
}

// RTM_NEWADDR or RTM_DELADDR.
build_addr :: proc(
	buf: []u8,
	add: bool,
	seq: u32,
	index: u32,
	addr: Address,
	prefix_len: u8,
	opts: Addr_Options,
) -> (
	msg: []u8,
	err: Error,
) {
	local, local_n, family, ok := addr_bytes(addr)
	if !ok || prefix_len > max_prefix(family) {
		return nil, .Invalid
	}
	peer: [16]u8
	peer_n := 0
	if p, has := opts.peer.?; has {
		pb, pn, pfamily, pok := addr_bytes(p)
		if !pok || pfamily != family {
			return nil, .Invalid
		}
		peer, peer_n = pb, pn
	}

	b: netlink.Builder
	netlink.builder_init(&b, buf)
	if add {
		netlink.msg_begin(
			&b,
			netlink.RTM_NEWADDR,
			netlink.NLM_F_REQUEST | netlink.NLM_F_ACK | netlink.NLM_F_CREATE | netlink.NLM_F_EXCL,
			seq,
		)
	} else {
		netlink.msg_begin(&b, netlink.RTM_DELADDR, netlink.NLM_F_REQUEST | netlink.NLM_F_ACK, seq)
	}
	netlink.put_struct(&b, netlink.Ifaddrmsg{family = family, prefixlen = prefix_len, index = index})
	// IFA_LOCAL is our address. IFA_ADDRESS is the peer on a point-to-point
	// link, else the same address again.
	netlink.put_attr(&b, netlink.IFA_LOCAL, local[:local_n])
	if peer_n > 0 {
		netlink.put_attr(&b, netlink.IFA_ADDRESS, peer[:peer_n])
	} else {
		netlink.put_attr(&b, netlink.IFA_ADDRESS, local[:local_n])
	}
	if add && opts.no_prefix_route {
		// IFA_F_NOPREFIXROUTE is 0x200: too big for the 8-bit header field.
		netlink.put_u32(&b, netlink.IFA_FLAGS, netlink.IFA_F_NOPREFIXROUTE)
	}
	return finish_build(&b)
}

// RTM_GETADDR dump. `index` 0 means all links; the kernel filters when it can
// and the reader filters again.
build_addr_dump :: proc(buf: []u8, seq: u32, index: u32, family: Maybe(Family)) -> (msg: []u8, err: Error) {
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(&b, netlink.RTM_GETADDR, netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP, seq)
	fam: u8 = netlink.AF_UNSPEC
	if f, has := family.?; has {
		fam = family_byte(f)
	}
	netlink.put_struct(&b, netlink.Ifaddrmsg{family = fam, index = index})
	return finish_build(&b)
}

@(private)
route_family :: proc "contextless" (r: ^Route) -> u8 {
	switch _ in r.dst {
	case IP4_Address:
		return netlink.AF_INET
	case IP6_Address:
		return netlink.AF_INET6
	}
	return family_byte(r.family)
}

// RTM_NEWROUTE or RTM_DELROUTE. `replace` causes an add to overwrite a route with
// the same key instead of failing with `.Exists`.
build_route :: proc(buf: []u8, add: bool, replace: bool, seq: u32, r: Route) -> (msg: []u8, err: Error) {
	r := r
	family := route_family(&r)
	if r.dst_len > max_prefix(family) {
		return nil, .Invalid
	}
	dst: [16]u8
	dst_n := 0
	if r.dst_len > 0 {
		db, dn, dfamily, dok := addr_bytes(r.dst)
		if !dok || dfamily != family {
			return nil, .Invalid
		}
		dst, dst_n = db, dn
	}
	gw: [16]u8
	gw_n := 0
	if g, has := r.gateway.?; has {
		gb, gn, gfamily, gok := addr_bytes(g)
		if !gok || gfamily != family {
			return nil, .Invalid
		}
		gw, gw_n = gb, gn
	}

	// Table: below 256 it goes in the header; above it, the header says
	// "compat" and the RTA_TABLE attribute carries the number.
	table := r.table
	if table == 0 {
		table = netlink.RT_TABLE_MAIN
	}
	hdr_table: u8 = u8(table) if table < 256 else netlink.RT_TABLE_COMPAT

	protocol := r.protocol
	if protocol == 0 && add {
		protocol = netlink.RTPROT_STATIC
	}
	rtn: u8
	switch r.kind {
	case .Unicast:
		rtn = netlink.RTN_UNICAST
	case .Blackhole:
		rtn = netlink.RTN_BLACKHOLE
	case .Unreachable:
		rtn = netlink.RTN_UNREACHABLE
	case .Prohibit:
		rtn = netlink.RTN_PROHIBIT
	case .Local:
		rtn = netlink.RTN_LOCAL
	case .Other:
		return nil, .Invalid
	}
	// A gateway route has universe scope; a device-only route has link scope.
	scope: u8 = netlink.RT_SCOPE_UNIVERSE
	if gw_n == 0 && r.kind == .Unicast {
		scope = netlink.RT_SCOPE_LINK
	}
	if !add {
		// Deleting: let the kernel match on the key fields only.
		scope = netlink.RT_SCOPE_NOWHERE
		rtn = netlink.RTN_UNSPEC if r.kind == .Unicast else rtn
	}
	flags: u32
	if r.onlink {
		flags |= netlink.RTNH_F_ONLINK
	}

	b: netlink.Builder
	netlink.builder_init(&b, buf)
	if add {
		nl_flags: u16 = netlink.NLM_F_REQUEST | netlink.NLM_F_ACK | netlink.NLM_F_CREATE
		nl_flags |= netlink.NLM_F_REPLACE if replace else netlink.NLM_F_EXCL
		netlink.msg_begin(&b, netlink.RTM_NEWROUTE, nl_flags, seq)
	} else {
		netlink.msg_begin(&b, netlink.RTM_DELROUTE, netlink.NLM_F_REQUEST | netlink.NLM_F_ACK, seq)
	}
	netlink.put_struct(
		&b,
		netlink.Rtmsg {
			family = family,
			dst_len = r.dst_len,
			table = hdr_table,
			protocol = protocol,
			scope = scope,
			type = rtn,
			flags = flags,
		},
	)
	if dst_n > 0 {
		netlink.put_attr(&b, netlink.RTA_DST, dst[:dst_n])
	}
	if gw_n > 0 {
		netlink.put_attr(&b, netlink.RTA_GATEWAY, gw[:gw_n])
	}
	if r.ifindex != 0 {
		netlink.put_u32(&b, netlink.RTA_OIF, r.ifindex)
	}
	if m, has := r.metric.?; has {
		netlink.put_u32(&b, netlink.RTA_PRIORITY, m)
	}
	if table >= 256 {
		netlink.put_u32(&b, netlink.RTA_TABLE, table)
	}
	return finish_build(&b)
}

// RTM_GETROUTE dump of one family.
build_route_dump :: proc(buf: []u8, seq: u32, family: Family) -> (msg: []u8, err: Error) {
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(&b, netlink.RTM_GETROUTE, netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP, seq)
	netlink.put_struct(&b, netlink.Rtmsg{family = family_byte(family)})
	return finish_build(&b)
}

// RTM_GETROUTE for one destination: asks which route the kernel would use.
build_route_lookup :: proc(buf: []u8, seq: u32, dst: Address) -> (msg: []u8, err: Error) {
	db, dn, family, ok := addr_bytes(dst)
	if !ok {
		return nil, .Invalid
	}
	b: netlink.Builder
	netlink.builder_init(&b, buf)
	netlink.msg_begin(&b, netlink.RTM_GETROUTE, netlink.NLM_F_REQUEST | netlink.NLM_F_ACK, seq)
	netlink.put_struct(&b, netlink.Rtmsg{family = family, dst_len = max_prefix(family) if dn > 0 else 0})
	netlink.put_attr(&b, netlink.RTA_DST, db[:dn])
	return finish_build(&b)
}

// ---- parsers ----

// Reads an RTM_NEWLINK message payload.
parse_link :: proc(payload: []u8) -> (l: Link_Info, ok: bool) {
	ifi, rest := netlink.read_struct(payload, netlink.Ifinfomsg) or_return
	l.index = u32(ifi.index)
	l.flags = transmute(Link_Flags)ifi.flags
	it := netlink.attr_iter(rest)
	for a in netlink.attr_next(&it) {
		switch a.type {
		case netlink.IFLA_IFNAME:
			s := netlink.attr_str(a)
			l.name_len = min(len(s), IFNAMSIZ)
			copy(l.name_buf[:], s[:l.name_len])
		case netlink.IFLA_MTU:
			l.mtu, _ = netlink.attr_u32(a)
		case netlink.IFLA_LINKINFO:
			info := netlink.attr_iter(a.data)
			for x in netlink.attr_next(&info) {
				if x.type == netlink.IFLA_INFO_KIND {
					k := netlink.attr_str(x)
					l.kind_len = min(len(k), IFNAMSIZ)
					copy(l.kind_buf[:], k[:l.kind_len])
				}
			}
		}
	}
	return l, true
}

// Reads an RTM_NEWADDR message payload.
parse_addr :: proc(payload: []u8) -> (info: Addr_Info, ok: bool) {
	ifa, rest := netlink.read_struct(payload, netlink.Ifaddrmsg) or_return
	info.index = ifa.index
	info.prefix_len = ifa.prefixlen
	info.flags = u32(ifa.flags)
	info.scope = ifa.scope
	local, addr: Address
	it := netlink.attr_iter(rest)
	for a in netlink.attr_next(&it) {
		switch a.type {
		case netlink.IFA_LOCAL:
			local, _ = addr_from_bytes(a.data, ifa.family)
		case netlink.IFA_ADDRESS:
			addr, _ = addr_from_bytes(a.data, ifa.family)
		case netlink.IFA_FLAGS:
			if f, fok := netlink.attr_u32(a); fok {
				info.flags = f
			}
		}
	}
	// IFA_LOCAL is the address when present, and then IFA_ADDRESS is the peer
	// (or the same address again). With only IFA_ADDRESS, that is the address.
	if local != nil {
		info.address = local
		if addr != nil && addr != local {
			info.peer = addr
		}
	} else {
		info.address = addr
	}
	return info, info.address != nil
}

// Reads an RTM_NEWROUTE message payload.
parse_route :: proc(payload: []u8) -> (r: Route, ok: bool) {
	rtm, rest := netlink.read_struct(payload, netlink.Rtmsg) or_return
	r.dst_len = rtm.dst_len
	r.table = u32(rtm.table)
	r.protocol = rtm.protocol
	r.scope = rtm.scope
	r.onlink = rtm.flags & netlink.RTNH_F_ONLINK != 0
	switch rtm.type {
	case netlink.RTN_BLACKHOLE:
		r.kind = .Blackhole
	case netlink.RTN_UNREACHABLE:
		r.kind = .Unreachable
	case netlink.RTN_PROHIBIT:
		r.kind = .Prohibit
	case netlink.RTN_LOCAL:
		r.kind = .Local
	case netlink.RTN_UNICAST, netlink.RTN_UNSPEC:
		r.kind = .Unicast
	case:
		r.kind = .Other
	}
	switch rtm.family {
	case netlink.AF_INET:
		r.family = .V4
		r.dst = IP4_Address{}
	case netlink.AF_INET6:
		r.family = .V6
		r.dst = IP6_Address{}
	case:
		return {}, false
	}
	it := netlink.attr_iter(rest)
	for a in netlink.attr_next(&it) {
		switch a.type {
		case netlink.RTA_DST:
			if v, vok := addr_from_bytes(a.data, rtm.family); vok {
				r.dst = v
			}
		case netlink.RTA_GATEWAY:
			if v, vok := addr_from_bytes(a.data, rtm.family); vok {
				r.gateway = v
			}
		case netlink.RTA_PREFSRC:
			if v, vok := addr_from_bytes(a.data, rtm.family); vok {
				r.prefsrc = v
			}
		case netlink.RTA_OIF:
			r.ifindex, _ = netlink.attr_u32(a)
		case netlink.RTA_PRIORITY:
			if v, vok := netlink.attr_u32(a); vok {
				r.metric = v
			}
		case netlink.RTA_TABLE:
			if v, vok := netlink.attr_u32(a); vok {
				r.table = v
			}
		}
	}
	return r, true
}

// ---- operations ----

// Send a request that only needs an ACK.
@(private)
transact :: proc(c: ^Conn, msg: []u8) -> Error {
	// Run the request first: the errno is only set once it has failed.
	nerr := netlink.transact(&c.nl, msg, c.rx)
	return map_nl_error(c.nl.errno, nerr)
}

// Look up one link by name.
link_get :: proc(c: ^Conn, name: string) -> (l: Link_Info, err: Error) {
	return link_query(c, 0, name)
}

// Look up one link by index.
link_get_by_index :: proc(c: ^Conn, index: u32) -> (l: Link_Info, err: Error) {
	return link_query(c, index, "")
}

@(private)
link_query :: proc(c: ^Conn, index: u32, name: string) -> (l: Link_Info, err: Error) {
	buf: [128]u8
	msg := build_link_get(buf[:], netlink.next_seq(&c.nl), index, name) or_return

	Found :: struct {
		link: Link_Info,
		ok:   bool,
	}
	found: Found
	handler :: proc(user: rawptr, m: netlink.Msg) {
		f := (^Found)(user)
		if m.hdr.type == netlink.RTM_NEWLINK && !f.ok {
			f.link, f.ok = parse_link(m.payload)
		}
	}
	nerr := netlink.request(&c.nl, msg, c.rx, handler, &found)
	if nerr != .None {
		return {}, map_nl_error(c.nl.errno, nerr)
	}
	if !found.ok {
		return {}, .Protocol
	}
	return found.link, .None
}

// Collect all links into `out`.
link_list :: proc(c: ^Conn, out: ^[dynamic]Link_Info) -> Error {
	Collect :: struct {
		out: ^[dynamic]Link_Info,
		oom: bool,
	}
	handler :: proc(user: rawptr, m: netlink.Msg) {
		col := (^Collect)(user)
		if m.hdr.type != netlink.RTM_NEWLINK {
			return
		}
		if l, ok := parse_link(m.payload); ok {
			if _, err := append(col.out, l); err != nil {
				col.oom = true
			}
		}
	}
	for _ in 0 ..< 3 {
		clear(out)
		buf: [32]u8
		msg := build_link_dump(buf[:], netlink.next_seq(&c.nl)) or_return
		col := Collect {
			out = out,
		}
		nerr := netlink.request(&c.nl, msg, c.rx, handler, &col)
		if col.oom {
			return .No_Buffer
		}
		if nerr == .Dump_Interrupted {
			continue
		}
		return map_nl_error(c.nl.errno, nerr)
	}
	return .Busy
}

// Set a link administratively up (like `ip link set up`).
link_set_up :: proc(c: ^Conn, index: u32) -> Error {
	buf: [64]u8
	msg := build_link_set(buf[:], netlink.next_seq(&c.nl), index, {.Up}, {.Up}, nil) or_return
	return transact(c, msg)
}

link_set_down :: proc(c: ^Conn, index: u32) -> Error {
	buf: [64]u8
	msg := build_link_set(buf[:], netlink.next_seq(&c.nl), index, {}, {.Up}, nil) or_return
	return transact(c, msg)
}

link_set_mtu :: proc(c: ^Conn, index: u32, mtu: u32) -> Error {
	buf: [64]u8
	msg := build_link_set(buf[:], netlink.next_seq(&c.nl), index, {}, {}, mtu) or_return
	return transact(c, msg)
}

// Set the transmit queue length (like `ip link set txqueuelen`). For a tun
// device it is how many packets the kernel holds for the reader.
link_set_txqlen :: proc(c: ^Conn, index: u32, qlen: u32) -> Error {
	buf: [64]u8
	msg := build_link_set(buf[:], netlink.next_seq(&c.nl), index, {}, {}, nil, qlen) or_return
	return transact(c, msg)
}

// Delete a link (software devices). A `tun` from `tun.open` goes away when its
// descriptor closes; this is for kernel-created devices such as the `ovpn` DCO
// interface.
link_delete :: proc(c: ^Conn, index: u32) -> Error {
	buf: [64]u8
	msg := build_link_del(buf[:], netlink.next_seq(&c.nl), index) or_return
	return transact(c, msg)
}

// Create a link of kind "ovpn", return its index. `mp`: multi-peer device (a
// server), else point-to-point (a client). `.Exists` if the name is taken.
link_add_ovpn :: proc(c: ^Conn, name: string, mp: bool) -> (index: u32, err: Error) {
	buf: [128]u8
	mode := u8(netlink.OVPN_MODE_MP) if mp else u8(netlink.OVPN_MODE_P2P)
	msg := build_link_add_ovpn(buf[:], netlink.next_seq(&c.nl), name, mode) or_return
	transact(c, msg) or_return
	l := link_get(c, name) or_return
	return l.index, .None
}

// Add an address with a prefix length (`10.8.0.2/24`). `.Exists` if the same
// address is there. Unless `opts.no_prefix_route` is set, the kernel adds the
// connected route itself once the link is up.
addr_add :: proc(c: ^Conn, index: u32, addr: Address, prefix_len: u8, opts: Addr_Options = {}) -> Error {
	buf: [128]u8
	msg := build_addr(buf[:], true, netlink.next_seq(&c.nl), index, addr, prefix_len, opts) or_return
	return transact(c, msg)
}

// Remove an address. `.Not_Found` if it is not there.
addr_del :: proc(c: ^Conn, index: u32, addr: Address, prefix_len: u8, opts: Addr_Options = {}) -> Error {
	buf: [128]u8
	msg := build_addr(buf[:], false, netlink.next_seq(&c.nl), index, addr, prefix_len, opts) or_return
	return transact(c, msg)
}

// Collect the addresses of one link (`index` 0: all links), optionally of one
// family, into `out`.
addr_list :: proc(c: ^Conn, index: u32, family: Maybe(Family), out: ^[dynamic]Addr_Info) -> Error {
	Collect :: struct {
		out:   ^[dynamic]Addr_Info,
		index: u32,
		oom:   bool,
	}
	handler :: proc(user: rawptr, m: netlink.Msg) {
		col := (^Collect)(user)
		if m.hdr.type != netlink.RTM_NEWADDR {
			return
		}
		info, ok := parse_addr(m.payload)
		if !ok || (col.index != 0 && info.index != col.index) {
			return
		}
		if _, err := append(col.out, info); err != nil {
			col.oom = true
		}
	}
	for _ in 0 ..< 3 {
		clear(out)
		buf: [64]u8
		msg := build_addr_dump(buf[:], netlink.next_seq(&c.nl), index, family) or_return
		col := Collect {
			out   = out,
			index = index,
		}
		nerr := netlink.request(&c.nl, msg, c.rx, handler, &col)
		if col.oom {
			return .No_Buffer
		}
		if nerr == .Dump_Interrupted {
			continue // the data changed during the dump: ask again
		}
		return map_nl_error(c.nl.errno, nerr)
	}
	return .Busy
}

// Add a route. `.Exists` if one with the same key is already there, unless
// `replace` is set.
route_add :: proc(c: ^Conn, r: Route, replace := false) -> Error {
	buf: [256]u8
	msg := build_route(buf[:], true, replace, netlink.next_seq(&c.nl), r) or_return
	return transact(c, msg)
}

// Delete a route. Give the fields that identify it: destination and prefix
// length, the table, and metric/gateway/interface if the destination is
// routed more than one way. `.Not_Found` if none.
route_del :: proc(c: ^Conn, r: Route) -> Error {
	buf: [256]u8
	msg := build_route(buf[:], false, false, netlink.next_seq(&c.nl), r) or_return
	return transact(c, msg)
}

// Collect the routes of one family and one table (0 for the main table) into
// `out`. `ifindex` 0 means any interface.
route_list :: proc(c: ^Conn, family: Family, table: u32, ifindex: u32, out: ^[dynamic]Route) -> Error {
	Collect :: struct {
		out:     ^[dynamic]Route,
		table:   u32,
		ifindex: u32,
		oom:     bool,
	}
	handler :: proc(user: rawptr, m: netlink.Msg) {
		col := (^Collect)(user)
		if m.hdr.type != netlink.RTM_NEWROUTE {
			return
		}
		r, ok := parse_route(m.payload)
		if !ok || r.table != col.table || (col.ifindex != 0 && r.ifindex != col.ifindex) {
			return
		}
		if _, err := append(col.out, r); err != nil {
			col.oom = true
		}
	}
	want_table := table if table != 0 else netlink.RT_TABLE_MAIN
	for _ in 0 ..< 3 {
		clear(out)
		buf: [64]u8
		msg := build_route_dump(buf[:], netlink.next_seq(&c.nl), family) or_return
		col := Collect {
			out     = out,
			table   = want_table,
			ifindex = ifindex,
		}
		nerr := netlink.request(&c.nl, msg, c.rx, handler, &col)
		if col.oom {
			return .No_Buffer
		}
		if nerr == .Dump_Interrupted {
			continue
		}
		return map_nl_error(c.nl.errno, nerr)
	}
	return .Busy
}

// Collect routes of one family with routing protocol number `protocol`
// (RTPROT_*), in every routing table. Finds routes a crashed client left
// behind (it adds its routes with a private number).
route_list_protocol :: proc(c: ^Conn, family: Family, protocol: u8, out: ^[dynamic]Route) -> Error {
	Collect :: struct {
		out:      ^[dynamic]Route,
		protocol: u8,
		oom:      bool,
	}
	handler :: proc(user: rawptr, m: netlink.Msg) {
		col := (^Collect)(user)
		if m.hdr.type != netlink.RTM_NEWROUTE {
			return
		}
		r, ok := parse_route(m.payload)
		if !ok || r.protocol != col.protocol {
			return
		}
		if _, err := append(col.out, r); err != nil {
			col.oom = true
		}
	}
	for _ in 0 ..< 3 {
		clear(out)
		buf: [64]u8
		msg := build_route_dump(buf[:], netlink.next_seq(&c.nl), family) or_return
		col := Collect {
			out      = out,
			protocol = protocol,
		}
		nerr := netlink.request(&c.nl, msg, c.rx, handler, &col)
		if col.oom {
			return .No_Buffer
		}
		if nerr == .Dump_Interrupted {
			continue
		}
		return map_nl_error(c.nl.errno, nerr)
	}
	return .Busy
}

// The route the system uses for default traffic: the main-table route with
// destination length 0 and the lowest metric. `.Not_Found` if there is none.
route_get_default :: proc(c: ^Conn, family: Family) -> (r: Route, err: Error) {
	routes := make([dynamic]Route, 0, 16, c.allocator)
	defer delete(routes)
	route_list(c, family, 0, 0, &routes) or_return
	found := false
	for cand in routes {
		if cand.dst_len != 0 || cand.kind != .Unicast {
			continue
		}
		if !found || metric_of(cand) < metric_of(r) {
			r = cand
			found = true
		}
	}
	if !found {
		return {}, .Not_Found
	}
	return r, .None
}

@(private)
metric_of :: proc "contextless" (r: Route) -> u32 {
	m, _ := r.metric.?
	return m
}

// Ask which route the kernel would use for `dst` (like `ip route get`). The
// result has the gateway (nil if `dst` is directly connected), the output
// interface and the preferred source address. For `redirect-gateway`: look up
// the VPN server first, then pin it through that gateway and interface.
route_lookup :: proc(c: ^Conn, dst: Address) -> (r: Route, err: Error) {
	buf: [128]u8
	msg := build_route_lookup(buf[:], netlink.next_seq(&c.nl), dst) or_return

	Found :: struct {
		route: Route,
		ok:    bool,
	}
	found: Found
	handler :: proc(user: rawptr, m: netlink.Msg) {
		f := (^Found)(user)
		if m.hdr.type == netlink.RTM_NEWROUTE && !f.ok {
			f.route, f.ok = parse_route(m.payload)
		}
	}
	nerr := netlink.request(&c.nl, msg, c.rx, handler, &found)
	if nerr != .None {
		return {}, map_nl_error(c.nl.errno, nerr)
	}
	if !found.ok {
		return {}, .Protocol
	}
	return found.route, .None
}
