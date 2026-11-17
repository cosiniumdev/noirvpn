// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:testing"
import "noir:client"
import "noir:platform/dco"
import net "noir:platform/net"
import "noir:proto/config"
import "noir:proto/session"
import "noir:platform/sysnet"

// ---- addresses ----

@(test)
test_endpoint_peer_addr_round_trip :: proc(t: ^testing.T) {
	ep4 := net.Endpoint {
		address = net.IP4_Address{192, 0, 2, 7},
		port    = 51234,
	}
	a := endpoint_peer_addr(ep4)
	testing.expect_value(t, a.n, 7)
	back, ok := peer_addr_endpoint(session.peer_addr_bytes(&a))
	testing.expect(t, ok)
	testing.expect_value(t, back.port, 51234)
	testing.expect_value(t, back.address, net.Address(net.IP4_Address{192, 0, 2, 7}))

	raw := [16]u8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ep6 := net.Endpoint {
		address = transmute(net.IP6_Address)raw,
		port    = 1194,
	}
	a6 := endpoint_peer_addr(ep6)
	testing.expect_value(t, a6.n, 19)
	back6, ok6 := peer_addr_endpoint(session.peer_addr_bytes(&a6))
	testing.expect(t, ok6)
	testing.expect_value(t, back6.port, 1194)
	testing.expect_value(t, transmute([16]u8)back6.address.(net.IP6_Address), raw)
}

@(test)
test_peer_addr_endpoint_rejects_bad :: proc(t: ^testing.T) {
	_, ok := peer_addr_endpoint(nil)
	testing.expect(t, !ok)
	_, ok = peer_addr_endpoint([]u8{4, 1, 2, 3, 4, 0}) // one byte short
	testing.expect(t, !ok)
	_, ok = peer_addr_endpoint([]u8{5, 1, 2, 3, 4, 0, 1}) // not a family
	testing.expect(t, !ok)
	_, ok = peer_addr_endpoint([]u8{6, 1, 2, 3, 4, 5, 6, 7}) // v6 too short
	testing.expect(t, !ok)
}

@(test)
test_endpoint_key_separates_sockets :: proc(t: ^testing.T) {
	ep := net.Endpoint {
		address = net.IP4_Address{10, 0, 0, 1},
		port    = 1000,
	}
	a := endpoint_key(ep, 0)
	b := endpoint_key(ep, 1)
	testing.expect(t, a != b)
	testing.expect(t, a == endpoint_key(ep, 0))
	ep.port = 1001
	testing.expect(t, a != endpoint_key(ep, 0))
	// The same bytes through the session form give the same key.
	pa := endpoint_peer_addr(ep)
	k, ok := peer_addr_key(session.peer_addr_bytes(&pa), 0)
	testing.expect(t, ok)
	testing.expect(t, k == endpoint_key(ep, 0))
}

@(test)
test_address_text :: proc(t: ^testing.T) {
	testing.expect_value(t, ip4_text({10, 8, 0, 2}), "10.8.0.2")
	raw := [16]u8{0xfd, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x02}
	testing.expect_value(t, ip6_text(raw), "fd00:8:0:0:0:0:0:a02")
}

// ---- the TCP write queue ----

@(test)
test_txq_append_consume :: proc(t: ^testing.T) {
	q: Txq
	testing.expect(t, txq_init(&q, 16))
	defer txq_destroy(&q)
	testing.expect_value(t, txq_pending(&q), 0)
	testing.expect(t, txq_append(&q, []u8{1, 2, 3, 4, 5, 6}))
	testing.expect(t, txq_append(&q, []u8{7, 8}))
	testing.expect_value(t, txq_pending(&q), 8)
	testing.expect_value(t, len(txq_front(&q)), 8)
	txq_consume(&q, 3)
	testing.expect_value(t, txq_pending(&q), 5)
	testing.expect_value(t, txq_front(&q)[0], u8(4))
	txq_consume(&q, 5)
	testing.expect_value(t, txq_pending(&q), 0)
	// An empty queue goes back to the start.
	testing.expect_value(t, q.head, 0)
	testing.expect_value(t, q.tail, 0)
}

@(test)
test_txq_moves_down_when_the_tail_reaches_the_end :: proc(t: ^testing.T) {
	q: Txq
	testing.expect(t, txq_init(&q, 10))
	defer txq_destroy(&q)
	testing.expect(t, txq_append(&q, []u8{0, 1, 2, 3, 4, 5, 6, 7}))
	txq_consume(&q, 6) // 2 left: 6, 7
	// 4 more do not fit behind the tail (8 + 4 > 10) but fit after moving down.
	testing.expect(t, txq_append(&q, []u8{8, 9, 10, 11}))
	testing.expect_value(t, txq_pending(&q), 6)
	f := txq_front(&q)
	testing.expect_value(t, f[0], u8(6))
	testing.expect_value(t, f[5], u8(11))
	// What does not fit at all is refused and changes nothing.
	testing.expect(t, !txq_append(&q, []u8{1, 2, 3, 4, 5}))
	testing.expect_value(t, txq_pending(&q), 6)
	testing.expect(t, txq_append(&q, []u8{1, 2, 3, 4}))
	testing.expect_value(t, txq_pending(&q), 10)
}

@(test)
test_tcp_tx_policy :: proc(t: ^testing.T) {
	// Tunnel packets: accepted up to 3/4 of the queue.
	testing.expect_value(t, tcp_tx_policy(0, 1000, 100, true), Tx_Verdict.Accept)
	testing.expect_value(t, tcp_tx_policy(650, 1000, 100, true), Tx_Verdict.Accept)
	testing.expect_value(t, tcp_tx_policy(651, 1000, 100, true), Tx_Verdict.Drop)
	testing.expect_value(t, tcp_tx_policy(900, 1000, 50, true), Tx_Verdict.Drop)
	// Control packets: up to all of it, then the peer is closed.
	testing.expect_value(t, tcp_tx_policy(900, 1000, 100, false), Tx_Verdict.Accept)
	testing.expect_value(t, tcp_tx_policy(901, 1000, 100, false), Tx_Verdict.Overflow)
	testing.expect_value(t, tcp_tx_policy(1000, 1000, 1, false), Tx_Verdict.Overflow)
}

@(test)
test_txq_grow :: proc(t: ^testing.T) {
	q: Txq
	testing.expect(t, txq_init(&q, 16, 64))
	defer txq_destroy(&q)
	testing.expect_value(t, len(q.buf), 16)
	testing.expect_value(t, q.limit, 64)
	data: [40]u8
	for i in 0 ..< len(data) {
		data[i] = u8(i)
	}
	testing.expect(t, txq_append(&q, data[:12]))
	txq_consume(&q, 5) // waiting: 5 .. 11, with the head not at the start
	testing.expect(t, !txq_append(&q, data[12:40]))
	// Not larger than now, or above the limit: refused, nothing changed.
	testing.expect(t, !txq_grow(&q, 16))
	testing.expect(t, !txq_grow(&q, 8))
	testing.expect(t, !txq_grow(&q, 65))
	testing.expect_value(t, len(q.buf), 16)
	testing.expect_value(t, txq_pending(&q), 7)
	// Growing keeps the waiting bytes in order, moved to the start.
	testing.expect(t, txq_grow(&q, 32))
	testing.expect_value(t, len(q.buf), 32)
	testing.expect_value(t, q.head, 0)
	testing.expect_value(t, txq_pending(&q), 7)
	testing.expect(t, txq_append(&q, data[12:30]))
	f := txq_front(&q)
	testing.expect_value(t, len(f), 25)
	for i in 0 ..< len(f) {
		testing.expect_value(t, f[i], u8(i + 5))
	}
	testing.expect(t, txq_grow(&q, 64))
	testing.expect_value(t, string(txq_front(&q)), string(data[5:30]))

	// No limit given: the queue never grows.
	fixed: Txq
	testing.expect(t, txq_init(&fixed, 16))
	defer txq_destroy(&fixed)
	testing.expect(t, !txq_grow(&fixed, 32))
	testing.expect_value(t, len(fixed.buf), 16)
}

@(test)
test_tcp_tx_want_capacity :: proc(t: ^testing.T) {
	K :: 1024
	// It fits already: the same size, no growth.
	testing.expect_value(t, tcp_tx_want_capacity(0, 128 * K, 1024 * K, 1500, true), 128 * K)
	testing.expect_value(t, tcp_tx_want_capacity(96 * K - 1500, 128 * K, 1024 * K, 1500, true), 128 * K)
	// One byte over the data mark (3/4): doubles once.
	testing.expect_value(t, tcp_tx_want_capacity(96 * K - 1499, 128 * K, 1024 * K, 1500, true), 256 * K)
	// More than one doubling for a large request.
	testing.expect_value(t, tcp_tx_want_capacity(90 * K, 128 * K, 1024 * K, 280 * K, true), 512 * K)
	// The cap: never above the limit, even if the packet still does not fit.
	testing.expect_value(t, tcp_tx_want_capacity(760 * K, 128 * K, 1024 * K, 20 * K, true), 1024 * K)
	testing.expect_value(t, tcp_tx_want_capacity(0, 128 * K, 1024 * K, 2000 * K, true), 1024 * K)
	// A queue that is at its limit stays.
	testing.expect_value(t, tcp_tx_want_capacity(0, 1024 * K, 1024 * K, 2000 * K, true), 1024 * K)
	// Control packets use the whole size.
	testing.expect_value(t, tcp_tx_want_capacity(128 * K - 100, 128 * K, 1024 * K, 100, false), 128 * K)
	testing.expect_value(t, tcp_tx_want_capacity(128 * K - 99, 128 * K, 1024 * K, 100, false), 256 * K)
	// A limit that is the size: no growth.
	testing.expect_value(t, tcp_tx_want_capacity(100 * K, 128 * K, 128 * K, 1500, true), 128 * K)
}

// A cut super-packet is queued whole or not at all: the decision is reached once,
// for the sum of its packets, with the size the queue may grow to.
@(test)
test_tcp_super_packet_admission :: proc(t: ^testing.T) {
	K :: 1024
	fits :: proc(pending, capacity, limit, total: int) -> bool {
		want := tcp_tx_want_capacity(pending, capacity, limit, total, true)
		return tcp_tx_policy(pending, want, total, true) == .Accept
	}
	// 45 packets of 1480 bytes: an empty 128 KiB queue takes them without growing.
	total := 45 * 1480
	testing.expect(t, fits(0, 128 * K, 1024 * K, total))
	testing.expect_value(t, tcp_tx_want_capacity(0, 128 * K, 1024 * K, total, true), 128 * K)
	// 60 KiB waiting: over the mark of 128 KiB, so the queue must grow, and then it fits.
	testing.expect(t, tcp_tx_policy(60 * K, 128 * K, total, true) == .Drop)
	testing.expect(t, fits(60 * K, 128 * K, 1024 * K, total))
	testing.expect_value(t, tcp_tx_want_capacity(60 * K, 128 * K, 1024 * K, total, true), 256 * K)
	// 710 KiB waiting: no size up to the limit takes 65 KiB more (768 KiB is the mark of 1 MiB).
	testing.expect(t, !fits(710 * K, 128 * K, 1024 * K, total))
	testing.expect(t, !fits(710 * K, 1024 * K, 1024 * K, total))
	// Just under, and just over, the last mark.
	testing.expect(t, fits(768 * K - total, 1024 * K, 1024 * K, total))
	testing.expect(t, !fits(768 * K - total + 1, 1024 * K, 1024 * K, total))
	// With no growth allowed (limit = size) the same total does not fit at 60 KiB.
	testing.expect(t, !fits(60 * K, 128 * K, 128 * K, total))
}

// ---- keepalive lines ----

@(test)
test_split_keepalive :: proc(t: ^testing.T) {
	lines := []string{"route 10.1.0.0 255.255.0.0", "ping 10", "ping-restart 60", "dhcp-option DNS 10.8.0.1"}
	rest, ping, restart := split_keepalive(lines)
	testing.expect_value(t, len(rest), 2)
	testing.expect_value(t, rest[0], "route 10.1.0.0 255.255.0.0")
	testing.expect_value(t, rest[1], "dhcp-option DNS 10.8.0.1")
	testing.expect_value(t, ping.?, 10)
	testing.expect_value(t, restart.?, 60)
}

@(test)
test_split_keepalive_leaves_odd_lines :: proc(t: ^testing.T) {
	// A word that only starts like the option, a missing number, and a word that is not a number stay in the list.
	lines := []string{"ping-timeout 5", "ping", "ping abc", "pingx 3", "ping 5 6"}
	rest, ping, restart := split_keepalive(lines)
	testing.expect_value(t, len(rest), 5)
	_, has_ping := ping.?
	_, has_restart := restart.?
	testing.expect(t, !has_ping)
	testing.expect(t, !has_restart)
}

@(test)
test_split_keepalive_none :: proc(t: ^testing.T) {
	rest, ping, restart := split_keepalive(nil)
	testing.expect_value(t, len(rest), 0)
	_, has_ping := ping.?
	_, has_restart := restart.?
	testing.expect(t, !has_ping && !has_restart)
}

// ---- the kernel plan ----

@(private = "file")
join2 :: proc(a, b: string) -> string {
	buf := make([]u8, len(a) + len(b), context.temp_allocator)
	copy(buf, a)
	copy(buf[len(a):], b)
	return string(buf)
}

@(private = "file")
server_cfg :: proc(extra: string) -> (cfg: config.Config) {
	text := join2("mode server\nserver 10.8.0.0 255.255.255.0\ncert c.crt\nkey c.key\npeer-keys /nonexistent/peers\n", extra)
	return config.build(config.parse_text(text, "test.conf"))
}

@(private = "file")
count_steps :: proc(p: ^client.Plan, kind: client.Step_Kind) -> (n: int) {
	for s in p.steps {
		if s.kind == kind {
			n += 1
		}
	}
	return
}

@(test)
test_server_plan_basic :: proc(t: ^testing.T) {
	cfg := server_cfg("")
	defer config.destroy(&cfg)
	testing.expect(t, cfg.role == .Server)
	p := server_plan(&cfg.server, 1400)
	defer client.plan_destroy(&p)
	testing.expect_value(t, count_steps(&p, .Set_Mtu), 1)
	testing.expect_value(t, count_steps(&p, .Add_Addr), 1)
	testing.expect_value(t, count_steps(&p, .Link_Up), 1)
	testing.expect_value(t, count_steps(&p, .Add_Route), 0)
	testing.expect_value(t, p.mtu, u32(1400))
	testing.expect_value(t, p.prefix4, u8(24))
	// The MTU comes first and the link goes up last.
	testing.expect_value(t, p.steps[0].kind, client.Step_Kind.Set_Mtu)
	testing.expect_value(t, p.steps[len(p.steps) - 1].kind, client.Step_Kind.Link_Up)
	a, ok := p.addr4.?
	testing.expect(t, ok)
	testing.expect_value(t, a, sysnet.IP4_Address{10, 8, 0, 1})
}

@(test)
test_server_plan_routes :: proc(t: ^testing.T) {
	cfg := server_cfg("route 192.168.50.0 255.255.255.0\nroute 172.16.0.0 255.240.0.0 10.8.0.9 5\nroute 10.99.0.7\n")
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	p := server_plan(&cfg.server, 1400)
	defer client.plan_destroy(&p)
	testing.expect_value(t, count_steps(&p, .Add_Route), 3)
	first: ^client.Step
	for &s in p.steps {
		if s.kind == .Add_Route {
			first = &s
			break
		}
	}
	testing.expect(t, first != nil)
	testing.expect(t, first.on_tun)
	testing.expect_value(t, first.route.dst_len, u8(24))
	testing.expect_value(t, first.route.protocol, client.ROUTE_PROTOCOL)
	// The route with a gateway and a metric keeps both; a bare host gets /32.
	gw, metric, host32 := false, Maybe(u32){}, false
	for s in p.steps {
		if s.kind != .Add_Route {
			continue
		}
		if s.route.dst_len == 12 {
			_, gw = s.route.gateway.?
			metric = s.route.metric
		}
		if s.route.dst_len == 32 {
			host32 = true
		}
	}
	testing.expect(t, gw)
	testing.expect_value(t, metric, Maybe(u32)(5))
	testing.expect(t, host32)
}

@(test)
test_server_plan_v6 :: proc(t: ^testing.T) {
	cfg := server_cfg("server-ipv6 fd00:8::/64\nroute-ipv6 fd00:99::/64\n")
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	p := server_plan(&cfg.server, 1400)
	defer client.plan_destroy(&p)
	testing.expect_value(t, count_steps(&p, .Add_Addr), 2)
	testing.expect_value(t, count_steps(&p, .Add_Route), 1)
	testing.expect_value(t, p.prefix6, u8(64))
	_, has6 := p.addr6.?
	testing.expect(t, has6)
	// The IPv6 address is not critical: a host without IPv6 still serves IPv4.
	for s in p.steps {
		if s.kind == .Add_Addr && s.prefix_len == 64 {
			testing.expect(t, !s.critical)
		}
	}
}

@(test)
test_server_plan_skips_unusable_routes :: proc(t: ^testing.T) {
	cfg := server_cfg("route 192.168.1.0 255.255.255.0 net_gateway\nroute 192.168.2.0 255.255.255.0 vpn_gateway\n")
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	p := server_plan(&cfg.server, 1400)
	defer client.plan_destroy(&p)
	// net_gateway means the client's old gateway: it has no meaning on a server.
	testing.expect_value(t, count_steps(&p, .Add_Route), 1)
	testing.expect_value(t, len(p.notes), 1)
}

// ---- small rules ----

@(test)
test_shutdown_close_kind :: proc(t: ^testing.T) {
	testing.expect_value(t, shutdown_close_kind(0), session.Close_Kind.Exit)
	testing.expect_value(t, shutdown_close_kind(1), session.Close_Kind.Restart)
	testing.expect_value(t, shutdown_close_kind(3), session.Close_Kind.Restart)
}

@(test)
test_counters_add :: proc(t: ^testing.T) {
	a := session.Counters {
		link_rx_pkts = 3,
		data_tx      = 5,
		drop_data_tag = 1,
		events_dropped = 2,
	}
	b := session.Counters {
		link_rx_pkts = 4,
		data_tx      = 10,
		drop_data_tag = 0,
		events_dropped = 1,
		rekeys       = 7,
	}
	total: session.Counters
	counters_add(&total, a)
	counters_add(&total, b)
	testing.expect_value(t, total.link_rx_pkts, u64(7))
	testing.expect_value(t, total.data_tx, u64(15))
	testing.expect_value(t, total.drop_data_tag, u64(1))
	testing.expect_value(t, total.events_dropped, u64(3))
	testing.expect_value(t, total.rekeys, u64(7))
}

@(test)
test_server_tun_mtu :: proc(t: ^testing.T) {
	cfg := server_cfg("")
	defer config.destroy(&cfg)
	testing.expect_value(t, server_tun_mtu(&cfg.server), DEFAULT_TUN_MTU)
	cfg2 := server_cfg("tun-mtu 1300\n")
	defer config.destroy(&cfg2)
	testing.expect_value(t, server_tun_mtu(&cfg2.server), 1300)
}

@(test)
test_conn_table_size :: proc(t: ^testing.T) {
	testing.expect_value(t, conn_table_size(1024), 1024 + 512)
	testing.expect_value(t, conn_table_size(10), 10 + 256)
	testing.expect(t, conn_table_size(1) > 1)
}

@(test)
test_wipe :: proc(t: ^testing.T) {
	b := []u8{1, 2, 3, 4}
	wipe(b)
	testing.expect_value(t, b[0] | b[1] | b[2] | b[3], u8(0))
	wipe(nil)
}

// ---- the server settings ----

@(test)
test_server_settings_needs_files :: proc(t: ^testing.T) {
	cfg := server_cfg("")
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	s: Server_Settings
	defer server_settings_destroy(&s)
	// c.crt and c.key do not exist: the settings cannot be loaded.
	testing.expect(t, !server_settings_load(&s, &cfg))
	testing.expect(t, len(s.errors) >= 1)
}

@(test)
test_server_settings_warns_about_unused_options :: proc(t: ^testing.T) {
	cfg := server_cfg("mtu-disc yes\nclient-connect /bin/true\n")
	defer config.destroy(&cfg)
	s: Server_Settings
	defer server_settings_destroy(&s)
	_ = server_settings_load(&s, &cfg)
	found_option, found_script := false, false
	for w in s.warnings {
		if len(w) >= 8 && w[:8] == "mtu-disc" {
			found_option = true
		}
		if len(w) >= 14 && w[:14] == "client-connect" {
			found_script = true
		}
	}
	testing.expect(t, found_option)
	testing.expect(t, found_script)
}

@(test)
test_server_settings_peers_file :: proc(t: ^testing.T) {
	cfg := server_cfg("")
	defer config.destroy(&cfg)
	s: Server_Settings
	defer server_settings_destroy(&s)
	server_settings_check_peers(&s, &cfg.server)
	testing.expect(t, len(s.errors) >= 1)
}

@(test)
test_tls_tun_plan :: proc(t: ^testing.T) {
	cfg := server_cfg("server-ipv6 fd00:8::/64\n")
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	p := tls_tun_plan(&cfg.server, 1400)
	defer client.plan_destroy(&p)
	// The server's own addresses as host addresses, no subnet and no routes.
	testing.expect_value(t, count_steps(&p, .Set_Mtu), 1)
	testing.expect_value(t, count_steps(&p, .Add_Addr), 2)
	testing.expect_value(t, count_steps(&p, .Add_Route), 0)
	testing.expect_value(t, p.prefix4, u8(32))
	testing.expect_value(t, p.prefix6, u8(128))
	a, ok := p.addr4.?
	testing.expect(t, ok)
	testing.expect_value(t, a, sysnet.IP4_Address{10, 8, 0, 1})
	testing.expect_value(t, p.steps[0].kind, client.Step_Kind.Set_Mtu)
	testing.expect_value(t, p.steps[len(p.steps) - 1].kind, client.Step_Kind.Link_Up)
	// IPv4 only.
	cfg4 := server_cfg("")
	defer config.destroy(&cfg4)
	p4 := tls_tun_plan(&cfg4.server, 1500)
	defer client.plan_destroy(&p4)
	testing.expect_value(t, count_steps(&p4, .Add_Addr), 1)
	testing.expect_value(t, p4.mtu, u32(1500))
}

@(test)
test_peer_routes :: proc(t: ^testing.T) {
	ir4 := []config.Iroute{{network = {192, 168, 77, 0}, prefix = 24}}
	ir6 := []config.Iroute6{{prefix = {0xfd, 0, 0, 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = 64}}
	v4 := Maybe([4]u8)([4]u8{10, 8, 0, 6})
	v6 := Maybe([16]u8)([16]u8{0xfd, 0, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6})
	// A client of the daemon: two host routes, then the iroutes through the client.
	r := peer_routes(7, v4, v6, ir4, ir6, true, context.temp_allocator)
	testing.expect_value(t, len(r), 4)
	testing.expect_value(t, r[0].dst_len, u8(32))
	_, has_gw := r[0].gateway.?
	testing.expect(t, !has_gw)
	testing.expect_value(t, r[0].ifindex, u32(7))
	testing.expect_value(t, r[1].dst_len, u8(24))
	gw, has_gw1 := r[1].gateway.?
	testing.expect(t, has_gw1)
	testing.expect_value(t, gw, sysnet.Address(sysnet.IP4_Address{10, 8, 0, 6}))
	testing.expect_value(t, r[2].dst_len, u8(128))
	testing.expect_value(t, r[3].dst_len, u8(64))
	testing.expect_value(t, r[3].protocol, client.ROUTE_PROTOCOL)
	// A client of the service: the iroutes only.
	r = peer_routes(3, v4, v6, ir4, ir6, false, context.temp_allocator)
	testing.expect_value(t, len(r), 2)
	// An IPv4-only client has no IPv6 routes, whatever its iroutes say.
	r = peer_routes(3, v4, nil, ir4, ir6, true, context.temp_allocator)
	testing.expect_value(t, len(r), 2)
	r = peer_routes(3, nil, nil, ir4, ir6, true, context.temp_allocator)
	testing.expect_value(t, len(r), 0)
}

// ---- the local address of a client (multihome) ----

@(test)
test_srv_local_keeps_the_interface_only_when_asked :: proc(t: ^testing.T) {
	cfg: config.Server_Config
	d: Srv
	d.cfg = &cfg
	l := net.local_of_address(net.IP4_Address{192, 0, 2, 9})
	l.ifindex = 7
	testing.expect_value(t, srv_local(&d, l).ifindex, u32(0))
	testing.expect_value(t, srv_local(&d, l).len, u8(4))
	cfg.multihome_same_iface = true
	testing.expect_value(t, srv_local(&d, l).ifindex, u32(7))
}

@(test)
test_conn_follow_local :: proc(t: ^testing.T) {
	d: Srv
	c := new(Conn)
	defer free(c)
	c.proto = .Udp
	c.ep = net.Endpoint {
		address = net.IP4_Address{198, 51, 100, 2},
		port    = 4000,
	}
	a := net.local_of_address(net.IP4_Address{192, 0, 2, 9})
	b := net.local_of_address(net.IP4_Address{192, 0, 2, 10})
	c.local = a
	// The same address, and no address: nothing changes.
	conn_follow_local(&d, c, a)
	conn_follow_local(&d, c, net.Local{})
	testing.expect_value(t, c.local, a)
	// Another address of the host: the conn follows.
	conn_follow_local(&d, c, b)
	testing.expect_value(t, c.local, b)
	// A TCP conn keeps what its socket has.
	c.proto = .Tcp
	conn_follow_local(&d, c, a)
	testing.expect_value(t, c.local, b)
}

@(test)
test_srv_dco_local :: proc(t: ^testing.T) {
	c := new(Conn)
	defer free(c)
	// A wildcard listener and no local: nothing to say.
	ln := Listener {
		ep = net.Endpoint{address = net.IP6_Address{}, port = 1194},
	}
	_, ok := srv_dco_local(c, &ln)
	testing.expect(t, !ok)
	// The local of the conn, with the port of the listener.
	c.local = net.local_of_address(net.IP4_Address{192, 0, 2, 9})
	sa, ok2 := srv_dco_local(c, &ln)
	testing.expect(t, ok2)
	fam, ip, port, pok := dco.sockaddr_parse(&sa)
	testing.expect(t, pok)
	testing.expect_value(t, fam, dco.AF_INET)
	testing.expect_value(t, [4]u8{ip[0], ip[1], ip[2], ip[3]}, [4]u8{192, 0, 2, 9})
	testing.expect_value(t, port, u16(1194))
	// A listener that is bound to a host address and a conn with no local: the listener's.
	c.local = {}
	ln.have_host = true
	ln.ep = net.Endpoint {
		address = net.IP4_Address{192, 0, 2, 1},
		port    = 1194,
	}
	sa, ok2 = srv_dco_local(c, &ln)
	testing.expect(t, ok2)
	_, ip, _, _ = dco.sockaddr_parse(&sa)
	testing.expect_value(t, ip[3], u8(1))
}

// ---- the kernel routes of the iroutes (userspace data path) ----

@(test)
test_iroute_device_routes :: proc(t: ^testing.T) {
	ir4 := []config.Iroute{{network = {192, 168, 77, 0}, prefix = 24}, {network = {10, 9, 0, 0}, prefix = 16}}
	ir6 := []config.Iroute6{{prefix = {0xfd, 0, 0, 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits = 64}}
	r := iroute_device_routes(7, true, true, ir4, ir6, context.temp_allocator)
	testing.expect_value(t, len(r), 3)
	for x in r {
		_, has_gw := x.gateway.?
		testing.expect(t, !has_gw)
		testing.expect_value(t, x.ifindex, u32(7))
		testing.expect_value(t, x.protocol, client.ROUTE_PROTOCOL)
		_, has_metric := x.metric.?
		testing.expect(t, !has_metric)
	}
	testing.expect_value(t, r[0].dst_len, u8(24))
	testing.expect_value(t, r[1].dst_len, u8(16))
	testing.expect_value(t, r[2].dst_len, u8(64))
	// A client with one address family gets the routes of that family only.
	testing.expect_value(t, len(iroute_device_routes(7, true, false, ir4, ir6, context.temp_allocator)), 2)
	testing.expect_value(t, len(iroute_device_routes(7, false, true, ir4, ir6, context.temp_allocator)), 1)
	testing.expect_value(t, len(iroute_device_routes(7, false, false, ir4, ir6, context.temp_allocator)), 0)
	testing.expect_value(t, len(iroute_device_routes(7, true, true, nil, nil, context.temp_allocator)), 0)
}

@(private = "file")
Fake_Kernel :: struct {
	have:     [dynamic]u8, // the dst_len of each route that is "in the kernel"
	calls:    int,
	fail_len: u8, // adds of this dst_len fail with Permission
}

@(private = "file")
fake_op :: proc(user: rawptr, r: sysnet.Route, add: bool) -> sysnet.Error {
	k := (^Fake_Kernel)(user)
	k.calls += 1
	idx := -1
	for x, i in k.have {
		if x == r.dst_len {
			idx = i
		}
	}
	if add {
		if r.dst_len == k.fail_len {
			return .Permission
		}
		if idx >= 0 {
			return .Exists
		}
		append(&k.have, r.dst_len)
		return .None
	}
	if idx < 0 {
		return .Not_Found
	}
	ordered_remove(&k.have, idx)
	return .None
}

@(test)
test_iroutes_add_remove_bookkeeping :: proc(t: ^testing.T) {
	routes := []sysnet.Route{
		{dst = sysnet.IP4_Address{10, 1, 0, 0}, dst_len = 24},
		{dst = sysnet.IP4_Address{10, 2, 0, 0}, dst_len = 16},
		{dst = sysnet.IP4_Address{10, 3, 0, 0}, dst_len = 20},
		{dst = sysnet.IP4_Address{10, 4, 0, 0}, dst_len = 12},
	}
	k: Fake_Kernel
	k.have.allocator = context.temp_allocator
	k.fail_len = 20
	append(&k.have, u8(16)) // a `route` line of the config created this one
	held := make([dynamic]sysnet.Route, context.temp_allocator)
	failures := make([dynamic]Iroute_Failure, context.temp_allocator)
	n := iroutes_add(routes, 100, fake_op, &k, &held, &failures)
	// 24 and 12 added, 16 existed, 20 failed.
	testing.expect_value(t, n.added, 2)
	testing.expect_value(t, n.existed, 1)
	testing.expect_value(t, n.failed, 1)
	testing.expect_value(t, n.capped, 0)
	testing.expect_value(t, len(held), 2)
	testing.expect_value(t, len(failures), 1)
	testing.expect_value(t, failures[0].err, sysnet.Error.Permission)
	testing.expect_value(t, failures[0].route.dst_len, u8(20))
	testing.expect_value(t, len(k.have), 3)
	// Removal: only what was added. The route of the config stays.
	clear(&failures)
	iroutes_remove(&held, fake_op, &k, &failures)
	testing.expect_value(t, len(held), 0)
	testing.expect_value(t, len(failures), 0)
	testing.expect_value(t, len(k.have), 1)
	testing.expect_value(t, k.have[0], u8(16))
	// A second removal does nothing.
	calls := k.calls
	iroutes_remove(&held, fake_op, &k, &failures)
	testing.expect_value(t, k.calls, calls)
}

@(test)
test_iroutes_add_limit_and_gone_routes :: proc(t: ^testing.T) {
	routes := []sysnet.Route{
		{dst = sysnet.IP4_Address{10, 1, 0, 0}, dst_len = 24},
		{dst = sysnet.IP4_Address{10, 2, 0, 0}, dst_len = 16},
		{dst = sysnet.IP4_Address{10, 3, 0, 0}, dst_len = 20},
	}
	k: Fake_Kernel
	k.have.allocator = context.temp_allocator
	held := make([dynamic]sysnet.Route, context.temp_allocator)
	failures := make([dynamic]Iroute_Failure, context.temp_allocator)
	n := iroutes_add(routes, 2, fake_op, &k, &held, &failures)
	testing.expect_value(t, n.added, 2)
	testing.expect_value(t, n.capped, 1)
	testing.expect_value(t, len(k.have), 2)
	// Someone removed a route already: no failure at removal.
	clear(&k.have)
	iroutes_remove(&held, fake_op, &k, &failures)
	testing.expect_value(t, len(failures), 0)
	testing.expect_value(t, len(held), 0)
}

@(test)
listen_v6_mode_is_dual_stack_without_a_host :: proc(t: ^testing.T) {
	testing.expect_value(t, listen_v6_mode({proto = .Udp, family = .V6}), net.V6_Mode.Dual_Stack)
	testing.expect_value(t, listen_v6_mode({proto = .Tcp, family = .V6}), net.V6_Mode.Dual_Stack)
	testing.expect_value(t, listen_v6_mode({proto = .Udp, family = .Any}), net.V6_Mode.Dual_Stack)
	testing.expect_value(t, listen_v6_mode({host = "2001:db8::1", proto = .Udp, family = .V6}), net.V6_Mode.V6_Only)
	testing.expect_value(t, listen_v6_mode({host = "2001:db8::1", proto = .Udp, family = .Any}), net.V6_Mode.Dual_Stack)
}

@(test)
test_mtu_warned_take :: proc(t: ^testing.T) {
	list: [2]Mtu_Warned
	n := 0
	v6_epoch := Mtu_Warned{v6 = true, overhead = 28}
	// The first client of a kind warns, the next ones of that kind do not.
	testing.expect(t, mtu_warned_take(list[:], &n, v6_epoch))
	testing.expect(t, !mtu_warned_take(list[:], &n, v6_epoch))
	// Another data format or address family is another kind.
	testing.expect(t, mtu_warned_take(list[:], &n, {v6 = true, overhead = 24}))
	testing.expect(t, !mtu_warned_take(list[:], &n, {v6 = true, overhead = 24}))
	testing.expect_value(t, n, 2)
	// A full list keeps no more kinds, so such a kind warns each time.
	testing.expect(t, mtu_warned_take(list[:], &n, {v6 = false, overhead = 28}))
	testing.expect(t, mtu_warned_take(list[:], &n, {v6 = false, overhead = 28}))
	testing.expect_value(t, n, 2)
}
