// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:testing"
import "noir:platform/dco"
import "noir:proto/config"

// `block-ipv6`: the version test, the counters, the message to the DCO service and
// the choice of the data path for a backend that cannot drop IPv6.

V4_PKT := [?]u8{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1}
V6_PKT := [?]u8{0x60, 0, 0, 0, 0, 8, 58, 64}

@(test)
test_is_ipv6 :: proc(t: ^testing.T) {
	testing.expect(t, is_ipv6(V6_PKT[:]))
	testing.expect(t, is_ipv6([]u8{0x6f}))
	testing.expect(t, is_ipv6([]u8{0x60}))
	testing.expect(t, !is_ipv6(V4_PKT[:]))
	testing.expect(t, !is_ipv6([]u8{0x45}))
	testing.expect(t, !is_ipv6([]u8{0x06}))
	testing.expect(t, !is_ipv6([]u8{}))
	testing.expect(t, !is_ipv6(nil))
}

@(test)
test_client_write_tun_drops_ipv6 :: proc(t: ^testing.T) {
	// The tun device is not open: a packet that gets past the test is counted as
	// "arrived with no tun device", so the counters tell which packet was dropped.
	d: Daemon
	d.block6 = true
	write_tun(&d, V6_PKT[:])
	testing.expect_value(t, d.stats.drop_block6_rx, u64(1))
	testing.expect_value(t, d.stats.drop_rx_not_up, u64(0))
	write_tun(&d, V4_PKT[:])
	testing.expect_value(t, d.stats.drop_block6_rx, u64(1))
	testing.expect_value(t, d.stats.drop_rx_not_up, u64(1))
	// An empty packet is not IPv6.
	write_tun(&d, []u8{})
	testing.expect_value(t, d.stats.drop_block6_rx, u64(1))
	testing.expect_value(t, d.stats.drop_rx_not_up, u64(2))

	// Without the option an IPv6 packet goes on to the tun device.
	d = {}
	write_tun(&d, V6_PKT[:])
	testing.expect_value(t, d.stats.drop_block6_rx, u64(0))
	testing.expect_value(t, d.stats.drop_rx_not_up, u64(1))
}

@(test)
test_server_on_tunnel_drops_ipv6 :: proc(t: ^testing.T) {
	cfg: config.Server_Config
	cfg.block_ipv6 = true
	d: Srv
	d.cfg = &cfg
	c: Conn
	srv_on_tunnel(&d, &c, V6_PKT[:])
	srv_on_tunnel(&d, &c, V6_PKT[:])
	testing.expect_value(t, d.stats.drop_block6_rx, u64(2))
	testing.expect_value(t, c.drops, u64(2))
	testing.expect_value(t, d.stats.tun_write_pkts, u64(0))
}

// ------------------------------------------------------------ the service

@(test)
test_dco_filter_capability :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	testing.expect(t, !dco_filter_ok(&r.link))
	r.link.be.caps = dco.CAP_TCP | dco.CAP_KEY_TABLE
	testing.expect(t, !dco_filter_ok(&r.link))
	r.link.be.caps |= dco.CAP_BLOCK_IPV6
	testing.expect(t, dco_filter_ok(&r.link))
	r.link.up = false
	testing.expect(t, !dco_filter_ok(&r.link))
}

@(test)
test_dco_filter_message_and_counters :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_BLOCK_IPV6)
	defer rig_free(&r)
	r.be.open_idx = 7
	_, ok, _ := dco_try_open(&r.link, "tun0", .P2p)
	testing.expect(t, ok)

	// Nothing to poll while the filter is off.
	rx, tx := dco_filter_poll(&r.link)
	testing.expect(t, rx == 0 && tx == 0)
	testing.expect_value(t, rig_text(&r), "OPEN")

	// On: the flag goes out, and the reply has the counters since OPEN.
	r.be.filter = {
		rx_v6 = 2,
		tx_v6 = 5,
	}
	rx, tx, _ = dco_filter_call(&r.link, true)
	testing.expect_value(t, r.be.filter_flags, u32(dco.FILTER_IPV6))
	testing.expect(t, r.link.filtered)
	testing.expect(t, rx == 2 && tx == 5)

	// The service counts on: the poll reports what is new.
	r.be.filter = {
		rx_v6 = 3,
		tx_v6 = 9,
	}
	rx, tx = dco_filter_poll(&r.link)
	testing.expect(t, rx == 1 && tx == 4)
	rx, tx = dco_filter_poll(&r.link)
	testing.expect(t, rx == 0 && tx == 0)
	// A counter that goes down reads as no change.
	r.be.filter = {
		rx_v6 = 1,
		tx_v6 = 9,
	}
	rx, tx = dco_filter_poll(&r.link)
	testing.expect(t, rx == 0 && tx == 0)

	// Off: flags 0.
	_, _, st := dco_filter_call(&r.link, false)
	testing.expect_value(t, st, 0)
	testing.expect_value(t, r.be.filter_flags, u32(0))
	testing.expect(t, !r.link.filtered)

	// A new device starts with no filter and counters from 0.
	_, _, st = dco_filter_call(&r.link, true)
	_, ok, _ = dco_try_open(&r.link, "tun0", .P2p)
	testing.expect(t, ok)
	testing.expect(t, !r.link.filtered)
	testing.expect(t, r.link.filter_last == {})

	// A refusal is reported and the state stays.
	r.be.fail["SET_FILTER"] = dco.EINVAL
	_, _, st = dco_filter_call(&r.link, true)
	testing.expect_value(t, st, dco.EINVAL)
	testing.expect(t, !r.link.filtered)
}

@(test)
test_dco_client_filter_follows_block6 :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r, dco.CAP_BLOCK_IPV6)
	defer rig_free(&r)
	r.link.dev = true
	d: Daemon
	d.dco.link = r.link
	d.dco.link.be = fake_be(&r.be)
	d.dco.link.be.caps = dco.CAP_BLOCK_IPV6

	// The message goes out once for the state that is wanted.
	r.be.filter = {
		rx_v6 = 1,
		tx_v6 = 2,
	}
	testing.expect(t, dco_client_filter(&d, true))
	testing.expect(t, dco_client_filter(&d, true))
	testing.expect_value(t, rig_text(&r), "SET_FILTER")
	testing.expect_value(t, r.be.filter_flags, u32(dco.FILTER_IPV6))
	testing.expect_value(t, d.stats.drop_block6_rx, u64(1))
	testing.expect_value(t, d.stats.drop_block6_tx, u64(2))

	// A connection without the option turns it off again (persist-tun keeps the device).
	testing.expect(t, dco_client_filter(&d, false))
	testing.expect_value(t, r.be.filter_flags, u32(0))
	testing.expect_value(t, len(r.be.calls), 2)
	// Off and off: no message.
	testing.expect(t, dco_client_filter(&d, false))
	testing.expect_value(t, len(r.be.calls), 2)

	// The service refuses: false, and the caller ends the attempt.
	r.be.fail["SET_FILTER"] = dco.EIO
	testing.expect(t, !dco_client_filter(&d, true))
}

@(test)
test_dco_attempt_block6_service_without_the_capability :: proc(t: ^testing.T) {
	for mode in ([]config.Datapath{.Udco, .Auto}) {
		cfg: config.Client_Config
		d: Daemon
		choice_init(&d, &cfg, mode)
		cfg.block_ipv6 = true
		dial_status = 0
		dial_caps = dco.CAP_TCP
		// The service cannot drop IPv6: the attempt runs here, and the log says so once.
		testing.expect(t, !dco_for_attempt(&d, .Udp, false))
		testing.expect(t, d.dco.filter_warned)
		testing.expect(t, !dco_for_attempt(&d, .Tcp, false))
		// With the capability the service takes the attempt.
		d.dco.link.be.caps |= dco.CAP_BLOCK_IPV6
		testing.expect(t, dco_for_attempt(&d, .Udp, false))
		testing.expect(t, dco_for_attempt(&d, .Tcp, false))
		// Without the option the capability does not matter.
		cfg.block_ipv6 = false
		d.dco.link.be.caps = dco.CAP_TCP
		testing.expect(t, dco_for_attempt(&d, .Udp, false))
	}
}

@(test)
test_dco_attempt_pushed_block6 :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	choice_init(&d, &cfg, .Udco)
	dial_status = 0
	dial_caps = dco.CAP_TCP
	// The first attempt does not know about the push.
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	// The tunnel came up with a pushed block-ipv6 (`handle_up`): later attempts run here.
	d.dco.pushed_block6 = true
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, d.dco.filter_warned)
	// A later tunnel-up without the push: the service is used again.
	d.dco.pushed_block6 = false
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	// A service with the capability takes the pushed rule.
	d.dco.pushed_block6 = true
	d.dco.link.be.caps |= dco.CAP_BLOCK_IPV6
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
}

@(test)
test_dco_client_init_block6_leaves_the_kernel_out :: proc(t: ^testing.T) {
	// `dco`: the kernel cannot drop IPv6, so nobody is asked and the run is here.
	probe_begin(0, 0)
	defer probe_end()
	cfg: config.Client_Config
	cfg.block_ipv6 = true
	cfg.dco_socket = "/nonexistent/dco.sock"
	d: Daemon
	d.cfg = &cfg
	cfg.datapath = .Dco
	testing.expect(t, dco_client_init(&d))
	testing.expect(t, !d.dco.want && !d.dco.link.up)
	testing.expect_value(t, len(probe.order), 0)

	// `auto`: only the service is asked, even when the kernel is there. No service: here.
	probe.service_st = dco.ENOENT
	d = {}
	d.cfg = &cfg
	cfg.datapath = .Auto
	testing.expect(t, dco_client_init(&d))
	testing.expect(t, !d.dco.want && !d.dco.link.up)
	testing.expect_value(t, len(probe.order), 1)
	testing.expect_value(t, probe.order[0], dco.Backend_Kind.Service)
}

@(test)
test_dco_client_init_only_tls_remotes_ask_no_backend :: proc(t: ^testing.T) {
	probe_begin(0, 0)
	defer probe_end()
	cfg: config.Client_Config
	cfg.dco_socket = "/nonexistent/dco.sock"
	tls := []config.Connection{{link = {proto = .Tcp, tls = true}, host = "a"}, {link = {proto = .Tcp, tls = true}, host = "b"}}
	cfg.connections = tls
	for mode in ([]config.Datapath{.Udco, .Dco, .Auto}) {
		d: Daemon
		d.cfg = &cfg
		cfg.datapath = mode
		testing.expect(t, dco_client_init(&d))
		testing.expect(t, !d.dco.want && !d.dco.link.up)
		testing.expect_value(t, len(probe.order), 0)
	}

	// One plain remote is enough to ask for a backend.
	mixed := []config.Connection{{link = {proto = .Tcp, tls = true}, host = "a"}, {link = {proto = .Udp}, host = "b"}}
	cfg.connections = mixed
	probe.service_st = dco.ENOENT
	d: Daemon
	d.cfg = &cfg
	cfg.datapath = .Auto
	testing.expect(t, dco_client_init(&d))
	testing.expect(t, len(probe.order) > 0)
}

@(test)
test_srv_dco_init_block6 :: proc(t: ^testing.T) {
	listens := []config.Listen{{port = 1194, proto = .Udp}}
	cfg: config.Server_Config
	cfg.listens = listens
	cfg.dco_socket = "/nonexistent/dco.sock"
	cfg.dev = "nvb1"
	cfg.block_ipv6 = true

	// `dco`: the kernel cannot drop IPv6. Nobody is asked, and the run is in this process.
	probe_begin(0, 0)
	defer probe_end()
	d: Srv
	d.cfg = &cfg
	d.dco.no_watch = true
	cfg.datapath = .Dco
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on && !d.dco.link.up)
	testing.expect_value(t, len(probe.order), 0)

	// `udco`, a service without the capability: the connection is closed, the run is here.
	cfg.datapath = .Udco
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on && !d.dco.link.up)
	testing.expect_value(t, len(probe.order), 1)
	testing.expect_value(t, len(probe.kbe.calls), 0)

	// `auto`: the kernel is left out even when it is there; the service without the
	// capability is no use either.
	cfg.datapath = .Auto
	clear(&probe.order)
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on)
	testing.expect_value(t, len(probe.order), 1)
	testing.expect_value(t, probe.order[0], dco.Backend_Kind.Service)

	// A service with the capability: the device is created, and the filter goes on at once.
	probe.service_caps = dco.CAP_BLOCK_IPV6
	clear(&probe.order)
	delete(probe.kbe.calls)
	probe.kbe.calls = nil
	for mode in ([]config.Datapath{.Udco, .Auto}) {
		cfg.datapath = mode
		d = {}
		d.cfg = &cfg
		d.dco.no_watch = true
		testing.expect(t, srv_dco_init(&d))
		testing.expect(t, d.dco.on)
		testing.expect_value(t, d.dco.kind, dco.Backend_Kind.Service)
		testing.expect(t, d.dco.link.filtered)
		testing.expect_value(t, probe.kbe.filter_flags, u32(dco.FILTER_IPV6))
		testing.expect_value(t, probe.kbe.calls[0].what, "OPEN")
		testing.expect_value(t, probe.kbe.calls[1].what, "SET_FILTER")
		delete(probe.kbe.calls)
		probe.kbe.calls = nil
	}

	// The service refuses the filter: the run is here, with no service.
	probe.kbe.fail["SET_FILTER"] = dco.EINVAL
	cfg.datapath = .Udco
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on && !d.dco.link.up)

	// Without the option the capability is not used.
	delete_key(&probe.kbe.fail, "SET_FILTER")
	cfg.block_ipv6 = false
	delete(probe.kbe.calls)
	probe.kbe.calls = nil
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, d.dco.on && !d.dco.link.filtered)
	testing.expect_value(t, len(probe.kbe.calls), 1)
}

@(test)
test_srv_dco_attach_early :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	r.link.dev = true
	d: Srv
	d.dco.link = r.link
	d.dco.link.be = fake_be(&r.be)
	// A `tls-server` listener first: the UDP one is the socket of the data channel.
	d.listeners[0] = {proto = .Tcp, tls = true}
	d.listeners[0].sock.fd = 4
	d.listeners[1] = {proto = .Udp}
	d.listeners[1].sock.fd = 9
	d.n_listen = 2
	srv_dco_attach_early(&d)
	testing.expect_value(t, len(r.be.calls), 1)
	if len(r.be.calls) == 1 {
		testing.expect_value(t, r.be.calls[0].what, "ATTACH")
		testing.expect_value(t, r.be.calls[0].peer_id, 9)
	}
	// A failure is only a log line.
	r.be.fail["ATTACH"] = dco.EINVAL
	srv_dco_attach_early(&d)
	testing.expect_value(t, len(r.be.calls), 2)

	// Nothing for a TCP server, a backend without the call, or no device.
	clear(&r.be.calls)
	d.dco.tcp = true
	srv_dco_attach_early(&d)
	d.dco.tcp = false
	d.dco.link.dev = false
	srv_dco_attach_early(&d)
	d.dco.link.dev = true
	d.dco.link.be.attach = nil
	srv_dco_attach_early(&d)
	testing.expect_value(t, len(r.be.calls), 0)
}
