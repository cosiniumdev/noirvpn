// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import "core:mem"
import win "core:sys/windows"

// Windows: the IP Helper API (netioapi.h). Calls need an administrator token or
// SYSTEM, except lookups.
//
// Differences from Linux:
//   - A link is an interface with an IPv4 or IPv6 part. Its name is the alias
//     ("Ethernet", "noirvpn"). `Link_Info.luid` is the NET_LUID other Windows
//     APIs take.
//   - `.Up` means "connected" (media sense). `link_set_up` and `link_set_down`
//     do nothing: a wintun adapter is up while its session runs.
//   - MTU is per family (NlMtu). `link_set_mtu` sets both; skips IPv6 below 1280.
//   - One routing table: `table` must be 0 or 254 (main), reads back as 254.
//     Only `.Unicast` routes. A route without `ifindex` takes the interface of
//     the best route to its gateway.
//   - Deciding metric = route metric + interface metric (`link_set_metric`).
//   - `Addr_Options` has no effect: no point-to-point addresses, and Windows
//     always adds the on-link prefix route.
//   - Changes go to the active store only and are lost at reboot.
//   - `link_kind` is "tun" for a wintun-type adapter (IF_TYPE_PROP_VIRTUAL),
//     else empty.

// Routing table number that routes on Windows read back with.
MAIN_TABLE :: 254

Conn :: struct {
	allocator: mem.Allocator,
	// The Win32 error of the last failure (0: none).
	err:       u32,
	text_buf:  [512]u8,
}

// Open a connection. There is nothing to open on Windows; `rx_size` is
// ignored.
open :: proc(allocator := context.allocator, rx_size := 32768) -> (c: Conn, err: Error) {
	c.allocator = allocator
	return c, .None
}

close :: proc(c: ^Conn) {
	c.err = 0
}

// The system's text for the last failure ("Element not found.").
last_error_text :: proc(c: ^Conn) -> string {
	if c.err == 0 {
		return ""
	}
	wbuf: [256]u16
	n := win.FormatMessageW(
		win.FORMAT_MESSAGE_FROM_SYSTEM | win.FORMAT_MESSAGE_IGNORE_INSERTS,
		nil,
		c.err,
		0,
		raw_data(wbuf[:]),
		len(wbuf),
		nil,
	)
	for n > 0 && (wbuf[n - 1] == '\r' || wbuf[n - 1] == '\n' || wbuf[n - 1] == ' ') {
		n -= 1
	}
	if n == 0 {
		return ""
	}
	return win.utf16_to_utf8(c.text_buf[:], wbuf[:n])
}

// The Win32 error of the last failure.
last_error :: proc(c: ^Conn) -> u32 {
	return c.err
}

@(private)
map_win_error :: proc "contextless" (e: u32) -> Error {
	switch e {
	case 0:
		return .None
	case ERROR_OBJECT_ALREADY_EXISTS, ERROR_ALREADY_EXISTS:
		return .Exists
	case ERROR_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND:
		return .Not_Found
	case ERROR_ACCESS_DENIED:
		return .Permission
	case ERROR_NOT_SUPPORTED:
		return .Unsupported
	case ERROR_INVALID_PARAMETER:
		return .Invalid
	case ERROR_NETWORK_UNREACHABLE, ERROR_HOST_UNREACHABLE:
		return .Network_Unreachable
	case ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY, ERROR_INSUFFICIENT_BUFFER:
		return .No_Buffer
	}
	return .Other
}

@(private)
ERROR_ALREADY_EXISTS :: 183
@(private)
ERROR_OUTOFMEMORY :: 14

@(private)
check :: proc "contextless" (c: ^Conn, e: u32) -> Error {
	c.err = e
	return map_win_error(e)
}

// ---- addresses ----

@(private)
to_inet :: proc "contextless" (a: Address) -> (s: SOCKADDR_INET, ok: bool) {
	switch v in a {
	case IP4_Address:
		s.v4.sin_family = AF_INET
		s.v4.sin_addr.s_addr = transmute(u32)v
		return s, true
	case IP6_Address:
		s.v6.sin6_family = AF_INET6
		s.v6.sin6_addr.s6_addr = transmute([16]u8)v
		return s, true
	}
	return {}, false
}

@(private)
from_inet :: proc "contextless" (s: SOCKADDR_INET) -> (a: Address, ok: bool) {
	switch s.family {
	case AF_INET:
		return transmute(IP4_Address)s.v4.sin_addr.s_addr, true
	case AF_INET6:
		return transmute(IP6_Address)s.v6.sin6_addr.s6_addr, true
	}
	return nil, false
}

@(private)
win_family :: proc "contextless" (f: Family) -> u16 {
	return AF_INET if f == .V4 else AF_INET6
}

@(private)
addr_family :: proc "contextless" (a: Address) -> (f: u16, bits: u8) {
	switch _ in a {
	case IP4_Address:
		return AF_INET, 32
	case IP6_Address:
		return AF_INET6, 128
	}
	return AF_UNSPEC, 0
}

@(private)
is_zero :: proc "contextless" (a: Address) -> bool {
	switch v in a {
	case IP4_Address:
		return v == {}
	case IP6_Address:
		return v == {}
	}
	return true
}

@(private)
addr_scope :: proc "contextless" (a: Address) -> u8 {
	switch v in a {
	case IP4_Address:
		if v[0] == 127 {
			return 254 // host
		}
		if v[0] == 169 && v[1] == 254 {
			return 253 // link
		}
	case IP6_Address:
		if v == {0, 0, 0, 0, 0, 0, 0, 1} {
			return 254
		}
		if u16(v[0]) & 0xffc0 == 0xfe80 {
			return 253
		}
	}
	return 0
}

// ---- links ----

@(private)
interface_row :: proc(luid: NET_LUID, family: u16) -> (row: MIB_IPINTERFACE_ROW, e: u32) {
	InitializeIpInterfaceEntry(&row)
	row.family = family
	row.luid = luid
	e = GetIpInterfaceEntry(&row)
	return
}

@(private)
set_interface_row :: proc(row: ^MIB_IPINTERFACE_ROW) -> u32 {
	if row.family == AF_INET {
		// SetIpInterfaceEntry refuses an IPv4 row with a site prefix.
		row.site_prefix_len = 0
	}
	return SetIpInterfaceEntry(row)
}

@(private)
index_to_luid :: proc(c: ^Conn, index: u32) -> (luid: NET_LUID, err: Error) {
	if index == 0 {
		return 0, .Invalid
	}
	if e := ConvertInterfaceIndexToLuid(index, &luid); e != 0 {
		c.err = e
		return 0, .Not_Found
	}
	return luid, .None
}

@(private)
link_query :: proc(c: ^Conn, luid: NET_LUID) -> (l: Link_Info, err: Error) {
	luid := luid
	index: u32
	if e := ConvertInterfaceLuidToIndex(&luid, &index); e != 0 {
		c.err = e
		return {}, .Not_Found
	}
	l.index = index
	l.luid = luid
	alias: [IF_MAX_STRING_SIZE + 1]u16
	if ConvertInterfaceLuidToAlias(&luid, raw_data(alias[:]), len(alias)) == 0 {
		n := 0
		for n < len(alias) && alias[n] != 0 {
			n += 1
		}
		utf8: [IF_MAX_STRING_SIZE * 3]u8
		s := win.utf16_to_utf8(utf8[:], alias[:n])
		k := min(len(s), IFNAMSIZ - 1)
		// Do not cut a character in two.
		for k > 0 && k < len(s) && s[k] & 0xC0 == 0x80 {
			k -= 1
		}
		copy(l.name_buf[:], s[:k])
		l.name_len = k
	}
	have_mtu := false
	for fam in ([]u16{AF_INET, AF_INET6}) {
		row, e := interface_row(luid, fam)
		if e != 0 {
			continue
		}
		if !have_mtu {
			l.mtu = row.nl_mtu
			have_mtu = true
		}
		if row.connected {
			l.flags += {.Up, .Running, .Lower_Up}
		}
	}
	if luid >> 48 == IF_TYPE_SOFTWARE_LOOPBACK {
		l.flags += {.Loopback}
	}
	if luid >> 48 == IF_TYPE_PROP_VIRTUAL {
		// A wintun adapter: the kind of a tun device on Linux.
		l.kind_len = copy(l.kind_buf[:], "tun")
	}
	c.err = 0
	return l, .None
}

// Look up one link by its alias.
link_get :: proc(c: ^Conn, name: string) -> (l: Link_Info, err: Error) {
	if len(name) == 0 {
		return {}, .Invalid
	}
	luid: NET_LUID
	if e := ConvertInterfaceAliasToLuid(win.utf8_to_wstring(name, context.temp_allocator), &luid); e != 0 {
		c.err = e
		return {}, .Not_Found
	}
	return link_query(c, luid)
}

// Look up one link by index.
link_get_by_index :: proc(c: ^Conn, index: u32) -> (l: Link_Info, err: Error) {
	luid := index_to_luid(c, index) or_return
	return link_query(c, luid)
}

// Collect all links with an IPv4 or IPv6 part into `out`.
link_list :: proc(c: ^Conn, out: ^[dynamic]Link_Info) -> Error {
	t: ^MIB_IPINTERFACE_TABLE
	if e := GetIpInterfaceTable(AF_UNSPEC, &t); e != 0 {
		return check(c, e)
	}
	defer FreeMibTable(t)
	rows := ([^]MIB_IPINTERFACE_ROW)(&t.table[0])[:t.count]
	outer: for row, i in rows {
		for prev in rows[:i] {
			if prev.luid == row.luid {
				continue outer
			}
		}
		l, err := link_query(c, row.luid)
		if err != .None {
			continue
		}
		if _, aerr := append(out, l); aerr != nil {
			return .No_Buffer
		}
	}
	return .None
}

// Nothing to do on Windows (see the top of this file).
link_set_up :: proc(c: ^Conn, index: u32) -> Error {
	_ = index_to_luid(c, index) or_return
	return .None
}

// Nothing to do on Windows (see the top of this file).
link_set_down :: proc(c: ^Conn, index: u32) -> Error {
	_ = index_to_luid(c, index) or_return
	return .None
}

// Windows has no transmit queue length: nothing to do.
link_set_txqlen :: proc(c: ^Conn, index: u32, qlen: u32) -> Error {
	_ = index_to_luid(c, index) or_return
	return .None
}

// Set the MTU of both families. IPv6 is skipped below 1280 and where the
// interface has no IPv6.
link_set_mtu :: proc(c: ^Conn, index: u32, mtu: u32) -> Error {
	luid := index_to_luid(c, index) or_return
	done := 0
	last := u32(ERROR_NOT_FOUND)
	for fam in ([]u16{AF_INET, AF_INET6}) {
		if fam == AF_INET6 && mtu < 1280 {
			continue
		}
		row, e := interface_row(luid, fam)
		if e != 0 {
			continue
		}
		row.nl_mtu = mtu
		if e = set_interface_row(&row); e != 0 {
			last = e
			continue
		}
		done += 1
	}
	if done == 0 {
		return check(c, last)
	}
	c.err = 0
	return .None
}

// Set the interface metric of both families. Windows adds it to every route
// metric of the interface, and asks the DNS servers of the interface with the
// lowest metric first. 0 turns the automatic metric back on.
link_set_metric :: proc(c: ^Conn, index: u32, metric: u32) -> Error {
	luid := index_to_luid(c, index) or_return
	done := 0
	last := u32(ERROR_NOT_FOUND)
	for fam in ([]u16{AF_INET, AF_INET6}) {
		row, e := interface_row(luid, fam)
		if e != 0 {
			continue
		}
		row.use_automatic_metric = metric == 0
		row.metric = metric
		if e = set_interface_row(&row); e != 0 {
			last = e
			continue
		}
		done += 1
	}
	if done == 0 {
		return check(c, last)
	}
	c.err = 0
	return .None
}

// The interface metric of one family.
link_get_metric :: proc(c: ^Conn, index: u32, family: Family) -> (metric: u32, err: Error) {
	luid := index_to_luid(c, index) or_return
	row, e := interface_row(luid, win_family(family))
	if e != 0 {
		return 0, check(c, e)
	}
	return row.metric, .None
}

// True if the interface has a part for this family (IPv6 can be off per
// interface).
@(private)
family_present :: proc(index: u32, family: u16) -> bool {
	luid: NET_LUID
	if ConvertInterfaceIndexToLuid(index, &luid) != 0 {
		return false
	}
	_, e := interface_row(luid, family)
	return e == 0
}

// ---- addresses ----

// DAD state "preferred": the address is usable at once.
@(private)
IP_DAD_STATE_PREFERRED :: 4

@(private)
addr_row :: proc(index: u32, addr: Address, prefix_len: u8) -> (row: MIB_UNICASTIPADDRESS_ROW, err: Error) {
	_, bits := addr_family(addr)
	sa, ok := to_inet(addr)
	if !ok || prefix_len > bits || index == 0 {
		return {}, .Invalid
	}
	InitializeUnicastIpAddressEntry(&row)
	row.address = sa
	row.index = index
	row.on_link_prefix_len = prefix_len
	row.dad_state = IP_DAD_STATE_PREFERRED
	return row, .None
}

// Add an address to a link. `.Exists` if it is there already. `.Unsupported`
// for IPv6 when the interface has no IPv6.
addr_add :: proc(c: ^Conn, index: u32, addr: Address, prefix_len: u8, opts: Addr_Options = {}) -> Error {
	row := addr_row(index, addr, prefix_len) or_return
	e := CreateUnicastIpAddressEntry(&row)
	if e != 0 {
		if fam, _ := addr_family(addr); fam == AF_INET6 && !family_present(index, AF_INET6) && family_present(index, AF_INET) {
			c.err = e
			return .Unsupported
		}
	}
	return check(c, e)
}

// Remove an address. `.Not_Found` if it is not there.
addr_del :: proc(c: ^Conn, index: u32, addr: Address, prefix_len: u8, opts: Addr_Options = {}) -> Error {
	row := addr_row(index, addr, prefix_len) or_return
	e := DeleteUnicastIpAddressEntry(&row)
	// A missing address gives ERROR_INVALID_PARAMETER.
	if e != 0 && !has_address(index, addr) {
		c.err = e
		return .Not_Found
	}
	return check(c, e)
}

// Collect the addresses of one link (`index` 0: all links), optionally of one
// family, into `out`.
addr_list :: proc(c: ^Conn, index: u32, family: Maybe(Family), out: ^[dynamic]Addr_Info) -> Error {
	fam := u16(AF_UNSPEC)
	if f, ok := family.?; ok {
		fam = win_family(f)
	}
	t: ^MIB_UNICASTIPADDRESS_TABLE
	if e := GetUnicastIpAddressTable(fam, &t); e != 0 {
		return check(c, e)
	}
	defer FreeMibTable(t)
	for row in ([^]MIB_UNICASTIPADDRESS_ROW)(&t.table[0])[:t.count] {
		if index != 0 && row.index != index {
			continue
		}
		a, ok := from_inet(row.address)
		if !ok {
			continue
		}
		info := Addr_Info {
			index      = row.index,
			address    = a,
			prefix_len = row.on_link_prefix_len,
			scope      = addr_scope(a),
		}
		if _, aerr := append(out, info); aerr != nil {
			return .No_Buffer
		}
	}
	c.err = 0
	return .None
}

// True if `a` is an address of the interface `index` (0: of any interface).
@(private)
has_address :: proc(index: u32, a: Address) -> bool {
	fam, _ := addr_family(a)
	t: ^MIB_UNICASTIPADDRESS_TABLE
	if GetUnicastIpAddressTable(fam, &t) != 0 {
		return false
	}
	defer FreeMibTable(t)
	for row in ([^]MIB_UNICASTIPADDRESS_ROW)(&t.table[0])[:t.count] {
		if index != 0 && row.index != index {
			continue
		}
		if b, ok := from_inet(row.address); ok && b == a {
			return true
		}
	}
	return false
}

// ---- routes ----

@(private)
route_row :: proc(c: ^Conn, r: Route) -> (row: MIB_IPFORWARD_ROW2, err: Error) {
	if r.table != 0 && r.table != MAIN_TABLE {
		return {}, .Unsupported
	}
	if r.kind != .Unicast {
		return {}, .Unsupported
	}
	dst := r.dst if r.dst != nil else default_dst(r.family)
	fam, bits := addr_family(dst)
	if r.dst_len > bits {
		return {}, .Invalid
	}
	InitializeIpForwardEntry(&row)
	row.destination.prefix, _ = to_inet(dst)
	row.destination.prefix_len = r.dst_len
	if gw, has := r.gateway.?; has {
		if gfam, _ := addr_family(gw); gfam != fam {
			return {}, .Invalid
		}
		row.next_hop, _ = to_inet(gw)
	} else {
		row.next_hop.family = fam
	}
	row.index = r.ifindex
	if r.ifindex == 0 {
		gw, has := r.gateway.?
		if !has {
			return {}, .Invalid
		}
		best: MIB_IPFORWARD_ROW2
		src: SOCKADDR_INET
		gsa, _ := to_inet(gw)
		if e := GetBestRoute2(nil, 0, nil, &gsa, 0, &best, &src); e != 0 {
			return {}, check(c, e)
		}
		row.index = best.index
	}
	row.metric = r.metric.? or_else 0
	row.protocol = u32(r.protocol) if r.protocol != 0 else MIB_IPPROTO_NETMGMT
	return row, .None
}

@(private)
route_from_row :: proc "contextless" (row: ^MIB_IPFORWARD_ROW2) -> (r: Route, ok: bool) {
	dst := from_inet(row.destination.prefix) or_return
	r.dst = dst
	r.family = .V4 if row.destination.prefix.family == AF_INET else .V6
	r.dst_len = row.destination.prefix_len
	if gw, gok := from_inet(row.next_hop); gok && !is_zero(gw) {
		r.gateway = gw
	}
	r.ifindex = row.index
	r.metric = row.metric
	r.table = MAIN_TABLE
	r.protocol = u8(row.protocol) if row.protocol <= 255 else 255
	r.kind = .Local if row.loopback || row.luid >> 48 == IF_TYPE_SOFTWARE_LOOPBACK else .Unicast
	return r, true
}

// Add a route. `.Exists` if the same destination, gateway and interface are
// there already; with `replace` such a route gets the new metric instead.
route_add :: proc(c: ^Conn, r: Route, replace := false) -> Error {
	row := route_row(c, r) or_return
	e := CreateIpForwardEntry2(&row)
	if e == ERROR_OBJECT_ALREADY_EXISTS && replace {
		e = SetIpForwardEntry2(&row)
	}
	if e != 0 && row.destination.prefix.family == AF_INET6 && !family_present(row.index, AF_INET6) {
		c.err = e
		return .Unsupported
	}
	return check(c, e)
}

// Remove a route (matched on destination, gateway and interface).
route_del :: proc(c: ^Conn, r: Route) -> Error {
	row := route_row(c, r) or_return
	return check(c, DeleteIpForwardEntry2(&row))
}

@(private)
route_table :: proc(c: ^Conn, family: Family) -> (rows: []MIB_IPFORWARD_ROW2, t: ^MIB_IPFORWARD_TABLE2, err: Error) {
	if e := GetIpForwardTable2(win_family(family), &t); e != 0 {
		return nil, nil, check(c, e)
	}
	return ([^]MIB_IPFORWARD_ROW2)(&t.table[0])[:t.count], t, .None
}

// Collect the routes of one family into `out`. `table` 0 or 254 is the only
// table (any other gives nothing); `ifindex` 0 means every interface.
route_list :: proc(c: ^Conn, family: Family, table: u32, ifindex: u32, out: ^[dynamic]Route) -> Error {
	if table != 0 && table != MAIN_TABLE {
		return .None
	}
	rows, t := route_table(c, family) or_return
	defer FreeMibTable(t)
	for &row in rows {
		if ifindex != 0 && row.index != ifindex {
			continue
		}
		r, ok := route_from_row(&row)
		if !ok {
			continue
		}
		if _, aerr := append(out, r); aerr != nil {
			return .No_Buffer
		}
	}
	return .None
}

// Collect the routes added with `protocol` (see `Route.protocol`).
route_list_protocol :: proc(c: ^Conn, family: Family, protocol: u8, out: ^[dynamic]Route) -> Error {
	rows, t := route_table(c, family) or_return
	defer FreeMibTable(t)
	for &row in rows {
		if row.protocol != u32(protocol) {
			continue
		}
		r, ok := route_from_row(&row)
		if !ok {
			continue
		}
		if _, aerr := append(out, r); aerr != nil {
			return .No_Buffer
		}
	}
	return .None
}

// The route for default traffic: destination length 0 on a connected
// interface, with the lowest route plus interface metric. `.Not_Found` if none.
route_get_default :: proc(c: ^Conn, family: Family) -> (r: Route, err: Error) {
	rows, t := route_table(c, family) or_return
	defer FreeMibTable(t)
	found := false
	best := u64(0)
	for &row in rows {
		if row.destination.prefix_len != 0 {
			continue
		}
		irow, e := interface_row(row.luid, row.destination.prefix.family)
		if e != 0 || !irow.connected {
			continue
		}
		cand, ok := route_from_row(&row)
		if !ok || cand.kind != .Unicast {
			continue
		}
		m := u64(row.metric) + u64(irow.metric)
		if !found || m < best {
			r = cand
			best = m
			found = true
		}
	}
	if !found {
		return {}, .Not_Found
	}
	return r, .None
}

// Ask which route the system would use for `dst`. The result has the gateway
// (nil if `dst` is on-link), the output interface and the preferred source
// address. An address of this machine gives `.Local`.
route_lookup :: proc(c: ^Conn, dst: Address) -> (r: Route, err: Error) {
	dsa, ok := to_inet(dst)
	if !ok {
		return {}, .Invalid
	}
	row: MIB_IPFORWARD_ROW2
	src: SOCKADDR_INET
	if e := GetBestRoute2(nil, 0, nil, &dsa, 0, &row, &src); e != 0 {
		if e == ERROR_NOT_FOUND {
			c.err = e
			return {}, .Network_Unreachable
		}
		return {}, check(c, e)
	}
	r, _ = route_from_row(&row)
	if s, sok := from_inet(src); sok && !is_zero(s) {
		r.prefsrc = s
	}
	if has_address(0, dst) {
		r.kind = .Local
	}
	c.err = 0
	return r, .None
}
