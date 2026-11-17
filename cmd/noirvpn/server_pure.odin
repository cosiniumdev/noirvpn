// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:mem"
import "noir:client"
import cnet "core:net"
import net "noir:platform/net"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/session"
import "noir:server"

// Parts of the server daemon that need no sockets and no clock, so tests can
// run them alone: address conversions, the TCP write queue and its
// backpressure rule, keepalive lines of a push list, the kernel plan for the
// tunnel and its routes, and a few small decisions.

// ------------------------------------------------------------- addresses

// The key the peer table uses for a transport address. `sock` is the index of
// the listening socket, so two sockets never share a key.
endpoint_key :: proc "contextless" (ep: net.Endpoint, sock: u8) -> server.Addr_Key {
	switch a in ep.address {
	case net.IP4_Address:
		return server.addr_key_v4(cast([4]u8)a, u16(ep.port), sock)
	case net.IP6_Address:
		return server.addr_key_v6(transmute([16]u8)a, u16(ep.port), sock)
	}
	return {}
}

// The reverse of `endpoint_peer_addr`. False for a malformed address.
peer_addr_endpoint :: proc "contextless" (b: []u8) -> (ep: net.Endpoint, ok: bool) {
	switch {
	case len(b) == 7 && b[0] == 4:
		ep.address = net.IP4_Address{b[1], b[2], b[3], b[4]}
		ep.port = int(u16(b[5]) << 8 | u16(b[6]))
		return ep, true
	case len(b) == 19 && b[0] == 6:
		raw: [16]u8
		copy(raw[:], b[1:17])
		ep.address = transmute(net.IP6_Address)raw
		ep.port = int(u16(b[17]) << 8 | u16(b[18]))
		return ep, true
	}
	return {}, false
}

// The peer table key of a session address.
peer_addr_key :: proc "contextless" (b: []u8, sock: u8) -> (k: server.Addr_Key, ok: bool) {
	ep, eok := peer_addr_endpoint(b)
	if !eok {
		return {}, false
	}
	return endpoint_key(ep, sock), true
}

// An endpoint as text: `1.2.3.4:5678` or `[::1]:5678`.
endpoint_text :: proc(ep: net.Endpoint, allocator := context.temp_allocator) -> string {
	return cnet.endpoint_to_string(ep, allocator)
}

// An IPv4 address as text.
ip4_text :: proc(a: [4]u8, allocator := context.temp_allocator) -> string {
	return fmt.aprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3], allocator = allocator)
}

// An IPv6 address as text (the full form, without `::` shortening).
ip6_text :: proc(a: [16]u8, allocator := context.temp_allocator) -> string {
	w :: proc "contextless" (a: [16]u8, i: int) -> u16 {
		return u16(a[i]) << 8 | u16(a[i + 1])
	}
	return fmt.aprintf(
		"%x:%x:%x:%x:%x:%x:%x:%x",
		w(a, 0), w(a, 2), w(a, 4), w(a, 6), w(a, 8), w(a, 10), w(a, 12), w(a, 14),
		allocator = allocator,
	) // fmt: skip
}

// ---------------------------------------------------------- TCP write queue

// Bytes waiting to be written to one TCP client. A flat buffer with head and
// tail: take from the head, append at the tail, move down only when the tail
// reaches the end. Starts at `size`; `txq_grow` can enlarge it up to `limit`.
Txq :: struct {
	buf:   []u8,
	head:  int,
	tail:  int,
	limit: int,
}

// `limit` is the largest size the buffer may grow to; less than `size` (or
// none) means it never grows.
txq_init :: proc(q: ^Txq, size: int, limit := 0, allocator := context.allocator) -> bool {
	b, err := make([]u8, size, allocator)
	if err != nil {
		return false
	}
	q^ = {
		buf   = b,
		limit = max(limit, size),
	}
	return true
}

// Allocates the buffer as `size` bytes, keeping the waiting bytes. False (nothing
// changed) if `size` is not larger than now, is above the limit, or memory is short.
txq_grow :: proc(q: ^Txq, size: int, allocator := context.allocator) -> bool {
	if size <= len(q.buf) || size > q.limit {
		return false
	}
	b, err := make([]u8, size, allocator)
	if err != nil {
		return false
	}
	n := q.tail - q.head
	copy(b, q.buf[q.head:q.tail])
	delete(q.buf, allocator)
	q.buf = b
	q.head, q.tail = 0, n
	return true
}

txq_destroy :: proc(q: ^Txq, allocator := context.allocator) {
	delete(q.buf, allocator)
	q^ = {}
}

txq_pending :: proc "contextless" (q: ^Txq) -> int {
	return q.tail - q.head
}

// Adds bytes at the tail. False if they do not fit, even after moving the
// queue down; nothing is added then.
txq_append :: proc(q: ^Txq, data: []u8) -> bool {
	if q.tail + len(data) > len(q.buf) {
		if q.head > 0 {
			copy(q.buf, q.buf[q.head:q.tail])
			q.tail -= q.head
			q.head = 0
		}
		if q.tail + len(data) > len(q.buf) {
			return false
		}
	}
	copy(q.buf[q.tail:], data)
	q.tail += len(data)
	return true
}

// The bytes to write now.
txq_front :: proc "contextless" (q: ^Txq) -> []u8 {
	return q.buf[q.head:q.tail]
}

// `n` bytes were written.
txq_consume :: proc "contextless" (q: ^Txq, n: int) {
	q.head += n
	if q.head >= q.tail {
		q.head, q.tail = 0, 0
	}
}

// What to do with a packet for a TCP client whose queue may be full.
Tx_Verdict :: enum u8 {
	Accept,
	// A tunnel packet while the queue is above the high-water mark: drop it
	// (the TCP inside the tunnel sees a loss and slows down).
	Drop,
	// A control packet that does not fit at all: the peer is not reading, close
	// the connection.
	Overflow,
}

// Tunnel packets are accepted up to 3/4 of the queue, control packets up to all
// of it. A slow reader loses data packets first; its control channel
// (keepalives, rekeys) keeps room.
tcp_tx_policy :: proc "contextless" (pending, capacity, n: int, is_data: bool) -> Tx_Verdict {
	if is_data {
		if pending + n > capacity / 4 * 3 {
			return .Drop
		}
		return .Accept
	}
	if pending + n > capacity {
		return .Overflow
	}
	return .Accept
}

// The size a queue needs so `tcp_tx_policy` accepts `n` more bytes: `capacity`
// doubled until they fit, but not above `limit`. It is `capacity` when they fit
// already, or would not fit even at the limit (the verdict is then `Drop` or
// `Overflow`).
tcp_tx_want_capacity :: proc "contextless" (pending, capacity, limit, n: int, is_data: bool) -> int {
	c := capacity
	for c < limit && tcp_tx_policy(pending, c, n, is_data) != .Accept {
		c = min(c * 2, limit)
	}
	return c
}

// ----------------------------------------------------------- keepalive lines

// The push list holds `ping N` and `ping-restart N` lines (from `keepalive`).
// The session takes them as typed fields, so they are removed from the list.
// `rest` is a new slice of the same strings. A line that is not a number stays.
split_keepalive :: proc(
	lines: []string,
	allocator := context.temp_allocator,
) -> (
	rest: []string,
	ping: Maybe(int),
	ping_restart: Maybe(int),
) {
	out := make([dynamic]string, 0, len(lines), allocator)
	for l in lines {
		name, arg := first_word(l)
		switch name {
		case "ping":
			if v, ok := parse_seconds(arg); ok {
				ping = v
				continue
			}
		case "ping-restart":
			if v, ok := parse_seconds(arg); ok {
				ping_restart = v
				continue
			}
		}
		append(&out, l)
	}
	return out[:], ping, ping_restart
}

@(private = "file")
first_word :: proc "contextless" (s: string) -> (word, rest: string) {
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i += 1
	}
	j := i
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j += 1
	}
	return s[:i], s[j:]
}

@(private = "file")
parse_seconds :: proc "contextless" (s: string) -> (v: int, ok: bool) {
	if len(s) == 0 || len(s) > 6 {
		return 0, false
	}
	for c in transmute([]u8)s {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v * 10 + int(c - '0')
	}
	return v, true
}

// ------------------------------------------------------------- kernel plan

// What the server changes in the kernel for its tunnel: the MTU, the server's
// own addresses, the link up, and one route to the tunnel per `route` and
// `route-ipv6` line. Client addresses are not routes: the daemon routes by its
// peer table; the kernel needs only the tunnel network, which the address gives.
// Pure: nothing is applied here. `plan_destroy` frees the result.
server_plan :: proc(cfg: ^config.Server_Config, mtu: int, allocator := context.allocator) -> client.Plan {
	p := client.Plan {
		allocator = allocator,
		steps     = make([dynamic]client.Step, allocator),
		notes     = make([dynamic]client.Note, allocator),
		mtu       = u32(mtu),
	}
	append(&p.steps, client.Step{kind = .Set_Mtu, mtu = u32(mtu)})
	n := cfg.net
	a4 := sysnet.IP4_Address(n.server_addr)
	append(&p.steps, client.Step{kind = .Add_Addr, addr = a4, prefix_len = n.prefix})
	p.addr4, p.prefix4 = a4, n.prefix
	if n6, ok := cfg.net6.?; ok {
		a6 := transmute(sysnet.IP6_Address)n6.server_addr
		append(&p.steps, client.Step{kind = .Add_Addr, addr = a6, prefix_len = n6.bits, critical = false})
		p.addr6, p.prefix6 = a6, n6.bits
	}
	append(&p.steps, client.Step{kind = .Link_Up})

	skip :: proc(p: ^client.Plan, format: string, args: ..any) {
		text := fmt.aprintf(format, ..args, allocator = p.allocator)
		append(&p.notes, client.Note{kind = .Adjusted, text = text})
	}
	for r in cfg.routes {
		net4, ok := config.ipv4_parse(r.network)
		if !ok {
			skip(&p, "route %s: not an IPv4 network (host names are not resolved), skipped", r.network)
			continue
		}
		bits := 32
		if r.netmask != "" {
			mask, mok := config.ipv4_parse(r.netmask)
			pre, pok := config.ipv4_mask_prefix(mask)
			if !mok || !pok {
				skip(&p, "route %s: bad netmask %s, skipped", r.network, r.netmask)
				continue
			}
			bits = pre
		}
		step := client.Step {
			kind = .Add_Route,
			why = .Config_Route,
			on_tun = true,
			route = sysnet.Route{dst = sysnet.IP4_Address(net4), dst_len = u8(bits), protocol = client.ROUTE_PROTOCOL},
		}
		if !route_gateway(&step, r.gateway, false) {
			skip(&p, "route %s: gateway %s is not usable on the server, skipped", r.network, r.gateway)
			continue
		}
		if r.metric >= 0 {
			step.route.metric = u32(r.metric)
		}
		append(&p.steps, step)
	}
	for r in cfg.routes6 {
		addr, bits, ok := config.ipv6_parse_cidr(r.prefix)
		if !ok {
			skip(&p, "route-ipv6 %s: not a prefix, skipped", r.prefix)
			continue
		}
		step := client.Step {
			kind = .Add_Route,
			why = .Config_Route,
			on_tun = true,
			route = sysnet.Route{dst = transmute(sysnet.IP6_Address)addr, dst_len = u8(bits), protocol = client.ROUTE_PROTOCOL},
		}
		if !route_gateway(&step, r.gateway, true) {
			skip(&p, "route-ipv6 %s: gateway %s is not usable on the server, skipped", r.prefix, r.gateway)
			continue
		}
		if r.metric >= 0 {
			step.route.metric = u32(r.metric)
		}
		append(&p.steps, step)
	}
	return p
}

// Kernel plan of the second tun device of a mixed server (`datapath udco` with a
// `tls-server` listener). This process serves the tls clients through it. The
// device has the server's tunnel addresses as host addresses (/32 and /128), so
// it creates no subnet route: the subnet stays on the DCO service's device, and
// each tls client gets a host route to this one (`peer_routes`).
tls_tun_plan :: proc(cfg: ^config.Server_Config, mtu: int, allocator := context.allocator) -> client.Plan {
	p := client.Plan {
		allocator = allocator,
		steps     = make([dynamic]client.Step, allocator),
		notes     = make([dynamic]client.Note, allocator),
		mtu       = u32(mtu),
	}
	append(&p.steps, client.Step{kind = .Set_Mtu, mtu = u32(mtu)})
	a4 := sysnet.IP4_Address(cfg.net.server_addr)
	append(&p.steps, client.Step{kind = .Add_Addr, addr = a4, prefix_len = 32})
	p.addr4, p.prefix4 = a4, 32
	if n6, ok := cfg.net6.?; ok {
		a6 := transmute(sysnet.IP6_Address)n6.server_addr
		append(&p.steps, client.Step{kind = .Add_Addr, addr = a6, prefix_len = 128, critical = false})
		p.addr6, p.prefix6 = a6, 128
	}
	append(&p.steps, client.Step{kind = .Link_Up})
	return p
}

// Kernel routes one client needs on a device.
//   host   - a host route per tunnel address (/32 and /128) straight to the
//            device (daemon client: the kernel sends its packets here)
//   always - one route per network behind the client (`iroute`), through the
//            client's tunnel address; it replaces the gatewayless route that
//            the `route` option created
// The caller frees the slice.
peer_routes :: proc(
	ifindex: u32,
	vpn4: Maybe([4]u8),
	vpn6: Maybe([16]u8),
	ir4: []config.Iroute,
	ir6: []config.Iroute6,
	host: bool,
	allocator := context.allocator,
) -> []sysnet.Route {
	list := make([dynamic]sysnet.Route, allocator)
	if a, ok := vpn4.?; ok {
		if host {
			append(&list, sysnet.Route{dst = sysnet.IP4_Address(a), dst_len = 32, ifindex = ifindex, protocol = client.ROUTE_PROTOCOL})
		}
		for ir in ir4 {
			append(&list, sysnet.Route{
				dst      = sysnet.IP4_Address(ir.network),
				dst_len  = ir.prefix,
				gateway  = sysnet.Address(sysnet.IP4_Address(a)),
				ifindex  = ifindex,
				protocol = client.ROUTE_PROTOCOL,
			})
		}
	}
	if a, ok := vpn6.?; ok {
		if host {
			append(&list, sysnet.Route{dst = transmute(sysnet.IP6_Address)a, dst_len = 128, ifindex = ifindex, protocol = client.ROUTE_PROTOCOL})
		}
		for ir in ir6 {
			append(&list, sysnet.Route{
				dst      = transmute(sysnet.IP6_Address)ir.prefix,
				dst_len  = ir.bits,
				gateway  = sysnet.Address(transmute(sysnet.IP6_Address)a),
				ifindex  = ifindex,
				protocol = client.ROUTE_PROTOCOL,
			})
		}
	}
	return list[:]
}

// Kernel routes of the networks behind a client (`iroute`) when this process
// serves the tunnel device: each goes to the device with no gateway, as the
// `route` option creates it. IPv6 networks are skipped for a client with no IPv6
// address, IPv4 ones for a client with no IPv4 address. The caller frees the slice.
iroute_device_routes :: proc(
	ifindex: u32,
	has4, has6: bool,
	ir4: []config.Iroute,
	ir6: []config.Iroute6,
	allocator := context.allocator,
) -> []sysnet.Route {
	list := make([dynamic]sysnet.Route, allocator)
	if has4 {
		for ir in ir4 {
			append(&list, sysnet.Route{dst = sysnet.IP4_Address(ir.network), dst_len = ir.prefix, ifindex = ifindex, protocol = client.ROUTE_PROTOCOL})
		}
	}
	if has6 {
		for ir in ir6 {
			append(&list, sysnet.Route{dst = transmute(sysnet.IP6_Address)ir.prefix, dst_len = ir.bits, ifindex = ifindex, protocol = client.ROUTE_PROTOCOL})
		}
	}
	return list[:]
}

// One route change for `iroutes_add` and `iroutes_remove`.
Iroute_Op :: #type proc(user: rawptr, r: sysnet.Route, add: bool) -> sysnet.Error

Iroute_Failure :: struct {
	route: sysnet.Route,
	err:   sysnet.Error,
}

Iroute_Counts :: struct {
	added:   int, // routes that this call created (they are in `held`)
	existed: int, // routes that the kernel had already (left alone, not in `held`)
	failed:  int, // other errors (in `failures`)
	capped:  int, // routes left out because `limit` is reached
}

// Adds the routes with no replace. An existing route is left alone and not
// kept, so it is not removed later. A route that was created goes to `held`.
// At most `limit` routes are tried.
iroutes_add :: proc(
	routes: []sysnet.Route,
	limit: int,
	op: Iroute_Op,
	user: rawptr,
	held: ^[dynamic]sysnet.Route,
	failures: ^[dynamic]Iroute_Failure,
) -> (n: Iroute_Counts) {
	for r, i in routes {
		if i >= limit {
			n.capped = len(routes) - i
			break
		}
		err := op(user, r, true)
		if err == .None {
			append(held, r)
			n.added += 1
		} else if err == .Exists {
			n.existed += 1
		} else {
			append(failures, Iroute_Failure{r, err})
			n.failed += 1
		}
	}
	return
}

// Removes what `iroutes_add` kept, last first. A route that is gone already is no
// failure. `held` is empty at the end.
iroutes_remove :: proc(held: ^[dynamic]sysnet.Route, op: Iroute_Op, user: rawptr, failures: ^[dynamic]Iroute_Failure) {
	for i := len(held^) - 1; i >= 0; i -= 1 {
		r := held[i]
		if err := op(user, r, false); err != .None && err != .Not_Found {
			append(failures, Iroute_Failure{r, err})
		}
	}
	clear(held)
}

// Where a route goes: no gateway or `vpn_gateway` - to the tunnel device; an
// address - through that gateway. Other words (`net_gateway`, host names) are
// not usable here.
@(private = "file")
route_gateway :: proc(step: ^client.Step, gw: string, v6: bool) -> bool {
	switch gw {
	case "", "vpn_gateway":
		return true
	case "net_gateway", "remote_host":
		return false
	}
	if v6 {
		a, ok := config.ipv6_parse(gw)
		if !ok {
			return false
		}
		step.route.gateway = sysnet.Address(transmute(sysnet.IP6_Address)a)
		return true
	}
	a, ok := config.ipv4_parse(gw)
	if !ok {
		return false
	}
	step.route.gateway = sysnet.Address(sysnet.IP4_Address(a))
	return true
}

// --------------------------------------------------------------- small rules

// How the server ends sessions when it stops: with `explicit-exit-notify`
// clients are told to restart (they find the server again), otherwise to exit.
shutdown_close_kind :: proc "contextless" (explicit_exit_notify: int) -> session.Close_Kind {
	return .Restart if explicit_exit_notify > 0 else .Exit
}

// Adds the counters of one session to a running total.
counters_add :: proc "contextless" (total: ^session.Counters, c: session.Counters) {
	#assert(size_of(session.Counters) % size_of(u64) == 0)
	N :: size_of(session.Counters) / size_of(u64)
	a := (^[N]u64)(total)
	b := transmute([N]u64)c
	for i in 0 ..< N {
		a[i] += b[i]
	}
}

// The tun MTU of the server: `tun-mtu` or the default. Pushed to clients that
// announce IV_MTU, and set on the tunnel.
server_tun_mtu :: proc "contextless" (cfg: ^config.Server_Config) -> int {
	if cfg.link.tun_mtu > 0 {
		return cfg.link.tun_mtu
	}
	return DEFAULT_TUN_MTU
}

// How many listening sockets and TCP connections a config needs, in total:
// the size of the connection table (`max-clients` plus room for handshakes).
conn_table_size :: proc "contextless" (max_clients: int) -> int {
	return max_clients + max(256, max_clients / 2)
}

// A zeroed copy of memory, used to wipe key material.
wipe :: proc(b: []u8) {
	if len(b) > 0 {
		mem.zero_explicit(raw_data(b), len(b))
	}
}
