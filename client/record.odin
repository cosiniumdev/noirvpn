// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:fmt"
import "core:mem"
import cnet "core:net"
import "core:strconv"
import "core:strings"
import "noir:platform/sysnet"

// The clean-up record of a daemon.
//
// Each daemon writes what it changes (devices, added routes, DNS changes) into
// one record in the state folder and holds a lock on it while it runs. A
// starting daemon reverts only records whose lock it can take (owner is dead).
//
//	record_open        create the folder, the lock and an empty record
//	record_cleanup     revert the records of dead daemons, then the fallback
//	record_set_* and record_add_*, record_write   after each change
//	record_close       at the end, after the teardown
//
// Files of one record, in the state folder:
//
//	<id>.lock   empty, locked by the owner for its whole life
//	<id>.rec    the record text, replaced with a write to <id>.tmp, fsync, rename
//
// `<id>` is the pid and start time of the owner. The lock has its own file
// because a rename creates a new file and a lock does not move with it.
//
// Format (version 1), one item a line:
//
//	noirvpn-state 1
//	pid 4242
//	name office
//	role client
//	dev 7 tun0
//	route 4 198.51.100.7/32 192.0.2.1 254 - 2 eth0
//	route 4 0.0.0.0/1 - 254 - 7 tun0
//	dns resolvconf tun0 record tun0.noirvpn
//	end
//
// Route line: family, destination and prefix, gateway, table, metric, device
// index, device name. `-` means "none". The name and a device name are the rest
// of the line. A record without the `end` line is cut short and is not used.

RECORD_MAGIC :: "noirvpn-state"
RECORD_VERSION :: 1
// A record above this size is not read.
RECORD_MAX_SIZE :: 64 * 1024

Record_Role :: enum u8 {
	Client,
	Server,
}

// A device of the daemon. A live record protects every route on its devices.
Record_Dev :: struct {
	ifindex: u32,
	name:    string,
}

// A route that the daemon added (or is about to add). `route.ifindex` is set.
Record_Route :: struct {
	route: sysnet.Route,
	dev:   string,
}

// A DNS change: the backend (`sysnet.dns_backend_name`), the interface, and
// for the reader what it changed (`sysnet.dns_record_detail`).
Record_DNS :: struct {
	backend: string,
	ifname:  string,
	detail:  string,
}

// The content of a record. Its strings belong to `allocator`.
Record :: struct {
	pid:       int,
	name:      string,
	role:      Record_Role,
	devs:      [dynamic]Record_Dev,
	routes:    [dynamic]Record_Route,
	dns:       [dynamic]Record_DNS,
	allocator: mem.Allocator,
}

Record_Error :: enum u8 {
	None,
	// The text ends before the `end` line.
	Truncated,
	// The first line is not `noirvpn-state 1`.
	Bad_Version,
	// A line that is not of the format.
	Bad_Line,
	// The file is too large, not a regular file, or not ours.
	Refused,
	Io,
}

record_init :: proc(r: ^Record, allocator := context.allocator) {
	r^ = {}
	r.allocator = allocator
	r.devs = make([dynamic]Record_Dev, allocator)
	r.routes = make([dynamic]Record_Route, allocator)
	r.dns = make([dynamic]Record_DNS, allocator)
}

record_destroy :: proc(r: ^Record) {
	record_clear(r)
	delete(r.name, r.allocator)
	delete(r.devs)
	delete(r.routes)
	delete(r.dns)
	r^ = {}
}

// Removes the devices, routes and DNS changes. The pid, name and role stay.
record_clear :: proc(r: ^Record) {
	for d in r.devs {
		delete(d.name, r.allocator)
	}
	for rt in r.routes {
		delete(rt.dev, r.allocator)
	}
	for d in r.dns {
		delete(d.backend, r.allocator)
		delete(d.ifname, r.allocator)
		delete(d.detail, r.allocator)
	}
	clear(&r.devs)
	clear(&r.routes)
	clear(&r.dns)
}

record_is_empty :: proc(r: ^Record) -> bool {
	return len(r.devs) == 0 && len(r.routes) == 0 && len(r.dns) == 0
}

// The table number as the system lists it: 0 is the main table.
@(private)
table_of :: proc "contextless" (t: u32) -> u32 {
	return t if t != 0 else 254
}

@(private)
family_of :: proc "contextless" (r: sysnet.Route) -> sysnet.Family {
	switch _ in r.dst {
	case sysnet.IP4_Address:
		return .V4
	case sysnet.IP6_Address:
		return .V6
	}
	return r.family
}

@(private)
dst_of :: proc "contextless" (r: sysnet.Route) -> sysnet.Address {
	return r.dst if r.dst != nil else sysnet.default_dst(r.family)
}

// The same route: family, destination, prefix, table, gateway and device. The
// metric counts only when both sides have one (IPv6 lists 1024 for "none").
record_route_match :: proc(a, b: sysnet.Route) -> bool {
	if family_of(a) != family_of(b) || a.dst_len != b.dst_len || dst_of(a) != dst_of(b) {
		return false
	}
	if table_of(a.table) != table_of(b.table) || a.ifindex != b.ifindex {
		return false
	}
	ga, ha := a.gateway.?
	gb, hb := b.gateway.?
	if ha != hb || (ha && ga != gb) {
		return false
	}
	ma, hma := a.metric.?
	mb, hmb := b.metric.?
	if hma && hmb && ma != mb {
		return false
	}
	return true
}

// Adds a device once.
record_add_dev :: proc(r: ^Record, ifindex: u32, name: string) {
	if ifindex == 0 {
		return
	}
	for d in r.devs {
		if d.ifindex == ifindex {
			return
		}
	}
	append(&r.devs, Record_Dev{ifindex = ifindex, name = clean_text(name, r.allocator)})
}

// Adds a route once. `dev` is the name of its device ("" if not known).
record_add_route :: proc(r: ^Record, route: sysnet.Route, dev: string) {
	for e in r.routes {
		if record_route_match(e.route, route) {
			return
		}
	}
	rt := route
	rt.table = table_of(rt.table)
	rt.prefsrc = nil
	append(&r.routes, Record_Route{route = rt, dev = clean_text(dev, r.allocator)})
}

// Adds a DNS change once.
record_add_dns :: proc(r: ^Record, backend, ifname, detail: string) {
	for d in r.dns {
		if d.backend == backend && d.ifname == ifname {
			return
		}
	}
	append(
		&r.dns,
		Record_DNS {
			backend = clean_word(backend, r.allocator),
			ifname = clean_word(ifname, r.allocator),
			detail = clean_text(detail, r.allocator),
		},
	)
}

// The routes that `nc` added. The device names come from the devices of the
// record, else from the system.
record_add_netcfg :: proc(r: ^Record, nc: ^Netcfg) {
	for u in nc.undo {
		if u.kind == .Route {
			record_add_route(r, u.route, record_dev_name(r, nc.conn, u.route.ifindex))
		}
	}
}

// The route steps of `plan` before they run: a daemon that starts in the
// meantime then sees them as this daemon's. `ifindex` is the tunnel device.
record_add_plan :: proc(r: ^Record, plan: ^Plan, conn: ^sysnet.Conn, ifindex: u32) {
	for s in plan.steps {
		if s.kind != .Add_Route {
			continue
		}
		rt := s.route
		if s.on_tun {
			rt.ifindex = ifindex
		}
		record_add_route(r, rt, record_dev_name(r, conn, rt.ifindex))
	}
}

@(private)
record_dev_name :: proc(r: ^Record, conn: ^sysnet.Conn, ifindex: u32) -> string {
	for d in r.devs {
		if d.ifindex == ifindex {
			return d.name
		}
	}
	if conn != nil && ifindex != 0 {
		if l, err := sysnet.link_get_by_index(conn, ifindex); err == .None {
			return strings.clone(sysnet.link_name(&l), context.temp_allocator)
		}
	}
	return ""
}

// Text for the rest of a line: control bytes become '?'.
@(private)
clean_text :: proc(s: string, allocator: mem.Allocator) -> string {
	out := make([]u8, len(s), allocator)
	for i in 0 ..< len(s) {
		c := s[i]
		out[i] = '?' if c < 0x20 || c == 0x7f else c
	}
	return string(out)
}

// One word of a line: spaces become '?' too.
@(private)
clean_word :: proc(s: string, allocator: mem.Allocator) -> string {
	out := transmute([]u8)clean_text(s, allocator)
	for &c in out {
		if c == ' ' {
			c = '?'
		}
	}
	return string(out)
}

// ---- the text ----

record_encode :: proc(r: ^Record, allocator := context.allocator) -> string {
	sb := strings.builder_make(allocator)
	fmt.sbprintf(&sb, "%s %d\n", RECORD_MAGIC, RECORD_VERSION)
	fmt.sbprintf(&sb, "pid %d\n", r.pid)
	fmt.sbprintf(&sb, "name %s\n", r.name)
	fmt.sbprintf(&sb, "role %s\n", "server" if r.role == .Server else "client")
	for d in r.devs {
		fmt.sbprintf(&sb, "dev %d %s\n", d.ifindex, d.name if d.name != "" else "-")
	}
	for e in r.routes {
		rt := e.route
		fam := family_of(rt)
		strings.write_string(&sb, "route ")
		strings.write_string(&sb, "4 " if fam == .V4 else "6 ")
		strings.write_string(&sb, cnet.address_to_string(dst_of(rt), context.temp_allocator))
		fmt.sbprintf(&sb, "/%d ", rt.dst_len)
		if gw, ok := rt.gateway.?; ok {
			strings.write_string(&sb, cnet.address_to_string(gw, context.temp_allocator))
		} else {
			strings.write_byte(&sb, '-')
		}
		fmt.sbprintf(&sb, " %d ", table_of(rt.table))
		if m, ok := rt.metric.?; ok {
			fmt.sbprintf(&sb, "%d", m)
		} else {
			strings.write_byte(&sb, '-')
		}
		fmt.sbprintf(&sb, " %d %s\n", rt.ifindex, e.dev if e.dev != "" else "-")
	}
	for d in r.dns {
		fmt.sbprintf(&sb, "dns %s %s %s\n", d.backend, d.ifname, d.detail if d.detail != "" else "-")
	}
	strings.write_string(&sb, "end\n")
	return strings.to_string(sb)
}

// Reads a record. On an error the record is empty and `r` needs no destroy.
record_decode :: proc(text: string, allocator := context.allocator) -> (r: Record, err: Record_Error) {
	record_init(&r, allocator)
	if err = decode_into(&r, text); err != .None {
		record_destroy(&r)
	}
	return
}

// Reads a record like `record_decode`. A text cut before its `end` line gives
// `.Truncated`, with the complete lines before the cut in `r`. That `r` needs
// a destroy.
record_decode_partial :: proc(text: string, allocator := context.allocator) -> (r: Record, err: Record_Error) {
	record_init(&r, allocator)
	if err = decode_into(&r, text); err != .None && err != .Truncated {
		record_destroy(&r)
	}
	return
}

@(private)
decode_into :: proc(r: ^Record, text: string) -> Record_Error {
	rest := text
	first := true
	ended := false
	for len(rest) > 0 {
		nl := strings.index_byte(rest, '\n')
		if nl < 0 {
			// The last line has no newline: the write was cut.
			return .Truncated
		}
		line := rest[:nl]
		rest = rest[nl + 1:]
		if ended {
			return .Bad_Line
		}
		if first {
			first = false
			magic, ver, ok := split_word(line)
			if !ok || magic != RECORD_MAGIC {
				return .Bad_Line
			}
			v, vok := strconv.parse_int(ver, 10)
			if !vok || v != RECORD_VERSION {
				return .Bad_Version
			}
			continue
		}
		key, value, _ := split_word(line)
		switch key {
		case "end":
			if value != "" {
				return .Bad_Line
			}
			ended = true
		case "pid":
			n, ok := strconv.parse_int(value, 10)
			if !ok || n <= 0 {
				return .Bad_Line
			}
			r.pid = n
		case "name":
			delete(r.name, r.allocator)
			r.name = strings.clone(value, r.allocator)
		case "role":
			switch value {
			case "client":
				r.role = .Client
			case "server":
				r.role = .Server
			case:
				return .Bad_Line
			}
		case "dev":
			idx, name, ok := split_word(value)
			n, nok := strconv.parse_u64(idx, 10)
			if !ok || !nok || n == 0 || n > u64(max(u32)) || name == "" {
				return .Bad_Line
			}
			record_add_dev(r, u32(n), "" if name == "-" else name)
		case "route":
			rt, dev, ok := parse_route(value)
			if !ok {
				return .Bad_Line
			}
			record_add_route(r, rt, dev)
		case "dns":
			backend, r1, ok1 := split_word(value)
			ifname, detail, ok2 := split_word(r1)
			if !ok1 || !ok2 || backend == "" || ifname == "" || detail == "" {
				return .Bad_Line
			}
			record_add_dns(r, backend, ifname, "" if detail == "-" else detail)
		case:
			return .Bad_Line
		}
	}
	if !ended {
		return .Truncated
	}
	return .None
}

// The first word of `s` and the rest after one space. `ok` is false when
// there is no space.
@(private)
split_word :: proc(s: string) -> (word, rest: string, ok: bool) {
	i := strings.index_byte(s, ' ')
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i + 1:], true
}

@(private)
parse_route :: proc(s: string) -> (rt: sysnet.Route, dev: string, ok: bool) {
	fields: [6]string
	rest := s
	for i in 0 ..< 6 {
		fields[i], rest = split_word(rest) or_return
	}
	if rest == "" {
		return {}, "", false
	}
	dev = "" if rest == "-" else rest
	v6: bool
	switch fields[0] {
	case "4":
	case "6":
		v6 = true
	case:
		return {}, "", false
	}
	slash := strings.index_byte(fields[1], '/')
	if slash < 0 {
		return {}, "", false
	}
	bits, bok := strconv.parse_u64(fields[1][slash + 1:], 10)
	if !bok || bits > (128 if v6 else 32) {
		return {}, "", false
	}
	rt.dst_len = u8(bits)
	rt.dst = parse_addr(fields[1][:slash], v6) or_return
	rt.family = .V6 if v6 else .V4
	if fields[2] != "-" {
		rt.gateway = parse_addr(fields[2], v6) or_return
	}
	table, tok := strconv.parse_u64(fields[3], 10)
	if !tok || table > u64(max(u32)) {
		return {}, "", false
	}
	rt.table = u32(table)
	if fields[4] != "-" {
		m, mok := strconv.parse_u64(fields[4], 10)
		if !mok || m > u64(max(u32)) {
			return {}, "", false
		}
		rt.metric = u32(m)
	}
	idx, iok := strconv.parse_u64(fields[5], 10)
	if !iok || idx > u64(max(u32)) {
		return {}, "", false
	}
	rt.ifindex = u32(idx)
	rt.protocol = ROUTE_PROTOCOL
	return rt, dev, true
}

@(private)
parse_addr :: proc(s: string, v6: bool) -> (a: sysnet.Address, ok: bool) {
	if v6 {
		a6 := cnet.parse_ip6_address(s) or_return
		return a6, true
	}
	a4 := cnet.parse_ip4_address(s) or_return
	return a4, true
}

// ---- what to revert ----

// A device of the system, as the clean-up needs it.
Record_Link :: struct {
	index:  u32,
	name:   string,
	// A tun or ovpn device: it exists only while a process holds it, or it
	// is the device of a DCO service.
	tunnel: bool,
}

Cleanup_Why :: enum u8 {
	// A record of a dead daemon lists the route.
	Dead_Record,
	// No record lists the route (the fallback rule).
	Unlisted,
}

Cleanup_Step :: struct {
	route: sysnet.Route,
	why:   Cleanup_Why,
}

// True when a live record holds the device of the route or lists the route.
record_route_protected :: proc(r: sysnet.Route, live: []^Record) -> bool {
	for l in live {
		for d in l.devs {
			if d.ifindex == r.ifindex {
				return true
			}
		}
		for e in l.routes {
			if record_route_match(e.route, r) {
				return true
			}
		}
	}
	return false
}

// The routes to remove. `routes` are the routes with `ROUTE_PROTOCOL` on the
// system, `links` its devices. Remove a route if no live record protects it and:
//   - a dead record lists it or its device (a device can outlive its daemon,
//     e.g. a DCO service device), or
//   - no record lists it (fallback): every live record could be read
//     (`live_unknown` false) and its device is not a tunnel device.
// A tunnel device lives only as long as its process, so an unlisted route on
// one belongs to a live process (e.g. an older noirvpn without records). The
// fallback removes the server route through the old gateway, which an older
// version leaves after a crash.
record_cleanup_plan :: proc(
	routes: []sysnet.Route,
	links: []Record_Link,
	live: []^Record,
	dead: []^Record,
	live_unknown: bool,
	allocator := context.allocator,
) -> []Cleanup_Step {
	out := make([dynamic]Cleanup_Step, allocator)
	outer: for r in routes {
		if record_route_protected(r, live) {
			continue
		}
		for d in dead {
			for e in d.routes {
				if record_route_match(e.route, r) {
					append(&out, Cleanup_Step{route = r, why = .Dead_Record})
					continue outer
				}
			}
			for dv in d.devs {
				if dv.ifindex == r.ifindex {
					append(&out, Cleanup_Step{route = r, why = .Dead_Record})
					continue outer
				}
			}
		}
		if live_unknown {
			continue
		}
		tunnel := false
		for l in links {
			if l.index == r.ifindex {
				tunnel = l.tunnel
				break
			}
		}
		if !tunnel {
			append(&out, Cleanup_Step{route = r, why = .Unlisted})
		}
	}
	return out[:]
}

// True if the DNS change `c` of the dead record `owner` must stay, when:
//   - a live record has a DNS change or device for the same interface
//   - it uses the same backend and that backend is one file for the whole
//     system (`sysnet.dns_backend_shared`)
//   - a device with that name exists that is not the device of `owner` (a new
//     device with the old name)
record_dns_protected :: proc(c: Record_DNS, owner: ^Record, live: []^Record, links: []Record_Link) -> bool {
	shared := sysnet.dns_backend_shared(c.backend)
	for l in live {
		for d in l.dns {
			if d.ifname == c.ifname || (shared && d.backend == c.backend) {
				return true
			}
		}
		for d in l.devs {
			if d.name == c.ifname {
				return true
			}
		}
	}
	for k in links {
		if k.name != c.ifname {
			continue
		}
		if owner == nil {
			return true
		}
		mine := false
		for d in owner.devs {
			if d.ifindex == k.index {
				mine = true
			}
		}
		if !mine {
			return true
		}
	}
	return false
}

// True when a device named `name` exists.
@(private)
link_named :: proc(links: []Record_Link, name: string) -> bool {
	for k in links {
		if k.name == name {
			return true
		}
	}
	return false
}

// ---- the clean-up at start ----

Cleanup_Report :: struct {
	// Records of dead daemons that were reverted.
	records:      int,
	// Records that could not be read: cut short, a bad version, or refused.
	bad_records:  int,
	// Routes removed because a dead record listed them.
	routes:       int,
	// Routes removed by the fallback rule.
	unlisted:     int,
	// DNS changes reverted.
	dns:          int,
	// The fallback did not run: a live record could not be read.
	live_unknown: bool,
	// The first error, for the log.
	err:          sysnet.Error,
	dns_err:      sysnet.DNS_Error,
}

// Clean-up at start. `own` is the open record of this daemon. `dns_hint` is the
// interface name whose DNS leftovers of an older version are removed ("" for
// none). Order matters: read the routes before the records. A route a daemon
// adds after the read is not seen. A route it added before is in its record (a
// daemon writes a route into its record before it adds it).
record_cleanup :: proc(own: ^Record_File, conn: ^sysnet.Conn, env: sysnet.DNS_Env, dns_hint: string) -> (rep: Cleanup_Report) {
	routes := make([dynamic]sysnet.Route, context.temp_allocator)
	for fam in ([]sysnet.Family{.V4, .V6}) {
		// The list call starts from an empty list.
		part := make([dynamic]sysnet.Route, context.temp_allocator)
		lerr := sysnet.route_list_protocol(conn, fam, ROUTE_PROTOCOL, &part)
		if lerr == .Unsupported && fam == .V6 {
			continue
		}
		if lerr != .None {
			rep.err = lerr
			return rep
		}
		append(&routes, ..part[:])
	}
	sys_links := make([dynamic]sysnet.Link_Info, context.temp_allocator)
	if lerr := sysnet.link_list(conn, &sys_links); lerr != .None {
		rep.err = lerr
		return rep
	}
	links := make([]Record_Link, len(sys_links), context.temp_allocator)
	for &l, i in sys_links {
		kind := sysnet.link_kind(&l)
		links[i] = Record_Link {
			index  = l.index,
			name   = strings.clone(sysnet.link_name(&l), context.temp_allocator),
			tunnel = kind == "tun" || kind == "ovpn",
		}
	}

	scan := record_scan(own, context.temp_allocator)
	defer record_scan_destroy(&scan)
	rep.bad_records = scan.bad
	rep.live_unknown = scan.live_unknown
	live := make([dynamic]^Record, context.temp_allocator)
	append(&live, &own.rec)
	for &f in scan.live {
		append(&live, &f.rec)
	}
	dead := make([dynamic]^Record, context.temp_allocator)
	for &f in scan.dead {
		if !f.bad {
			append(&dead, &f.rec)
		}
	}

	steps := record_cleanup_plan(routes[:], links, live[:], dead[:], scan.live_unknown, context.temp_allocator)
	for s in steps {
		derr := sysnet.route_del(conn, s.route)
		switch derr {
		case .None:
			if s.why == .Dead_Record {
				rep.routes += 1
			} else {
				rep.unlisted += 1
			}
		case .Not_Found:
		case .Exists, .Permission, .Unsupported, .Invalid, .Network_Unreachable, .No_Buffer, .Busy, .Timeout, .Io, .Protocol, .Other:
			if rep.err == .None {
				rep.err = derr
			}
		}
	}

	for d in dead {
		for c in d.dns {
			if record_dns_protected(c, d, live[:], links) {
				continue
			}
			backend, ok := sysnet.dns_backend_parse(c.backend)
			if !ok {
				continue
			}
			_, derr := sysnet.dns_cleanup_dead(env, backend, c.ifname, link_named(links, c.ifname))
			if derr == .None {
				rep.dns += 1
			} else if rep.dns_err == .None {
				rep.dns_err = derr
			}
		}
	}
	if !scan.live_unknown {
		n, derr := record_dns_fallback(env, live[:], links, dns_hint)
		rep.dns += n
		if derr != .None && rep.dns_err == .None {
			rep.dns_err = derr
		}
	}
	for d in dead {
		// An empty record is the one that a daemon without root leaves at a
		// clean stop: there was nothing to revert.
		if len(d.devs) > 0 || len(d.routes) > 0 || len(d.dns) > 0 {
			rep.records += 1
		}
	}
	for &f in scan.dead {
		record_forget(own, &f)
	}
	return rep
}

// The text of a clean-up report for the log, "" when nothing happened.
cleanup_report_text :: proc(rep: Cleanup_Report, allocator := context.temp_allocator) -> string {
	if rep.records == 0 && rep.routes == 0 && rep.unlisted == 0 && rep.dns == 0 {
		return ""
	}
	return fmt.aprintf(
		"clean-up at start: %d record(s) of stopped daemons, %d route(s) of them, %d route(s) of no record, %d DNS change(s) reverted",
		rep.records,
		rep.routes,
		rep.unlisted,
		rep.dns,
		allocator = allocator,
	)
}
