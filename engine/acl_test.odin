// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:testing"
import "noir:platform/event"
import "noir:proto/acl"
import "noir:proto/config"
import "noir:proto/push"

// TCP SYN from 10.8.0.9:5555 to 10.8.0.2:<port>, no options.
@(private = "file")
syn_to :: proc(port: u16, flags: u8 = 0x02) -> [40]u8 {
	p: [40]u8
	hdr := [20]u8{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 8, 0, 9, 10, 8, 0, 2}
	copy(p[:], hdr[:])
	p[20], p[21] = 0x15, 0xb3
	p[22], p[23] = u8(port >> 8), u8(port)
	p[32] = 0x50
	p[33] = flags
	return p
}

@(test)
test_write_tun_acl :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	cfg.allow_inbound = []acl.Rule{{target = .Tunnel, port_lo = 22, port_hi = 22, protos = acl.PROTOS_PORTS}}
	cfg.forwards = []config.Forward{{port = 8080, protos = {.Tcp}, host = "127.0.0.1", host_port = 80}}
	cfg.acl_max_flows = 256
	d: Daemon
	d.cfg = &cfg
	acl_attach(&d)
	defer acl_detach(&d)
	if !testing.expect(t, d.acl != nil) {
		return
	}
	po: push.Pushed_Options
	po.ifconfig = push.Ifconfig{a = {10, 8, 0, 2}, b = {255, 255, 255, 0}}
	acl_set_tunnel(&d, &po)

	// The tun device is not open: a packet that passes the filter is counted as
	// "arrived with no tun device".
	p22 := syn_to(22)
	write_tun(&d, p22[:])
	testing.expect_value(t, d.stats.drop_acl, 0)
	testing.expect_value(t, d.stats.drop_rx_not_up, 1)
	p23 := syn_to(23)
	write_tun(&d, p23[:])
	testing.expect_value(t, d.stats.drop_acl, 1)
	testing.expect_value(t, d.stats.drop_rx_not_up, 1)
	// The forward port passes.
	p8080 := syn_to(8080)
	write_tun(&d, p8080[:])
	testing.expect_value(t, d.stats.drop_acl, 1)
	testing.expect_value(t, d.stats.drop_rx_not_up, 2)
	testing.expect_value(t, d.acl.a.stats.in_new, 2)
}

@(test)
test_acl_off_without_allow_inbound :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	cfg.forwards = []config.Forward{{port = 8080, protos = {.Tcp}, host = "127.0.0.1", host_port = 80}}
	d: Daemon
	d.cfg = &cfg
	acl_attach(&d)
	testing.expect(t, d.acl == nil)
	p := syn_to(23)
	write_tun(&d, p[:])
	testing.expect_value(t, d.stats.drop_acl, 0)
	testing.expect_value(t, d.stats.drop_rx_not_up, 1)
}

// A host rule gets the addresses of its name from the helper thread, through
// the loop timer.
@(test)
test_acl_host_lookup :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	cfg.allow_inbound = []acl.Rule{{target = .Host, host = 0, port_lo = 22, port_hi = 22, protos = {.Tcp}}}
	cfg.acl_hosts = []string{"localhost"}
	cfg.acl_max_flows = 256
	cfg.acl_resolve_interval = 300
	d: Daemon
	d.cfg = &cfg
	if !testing.expect(t, event.init(&d.loop) == .None) {
		return
	}
	defer event.destroy(&d.loop)
	acl_attach(&d)
	defer acl_detach(&d)
	po: push.Pushed_Options
	acl_set_tunnel(&d, &po)
	testing.expect(t, d.acl.lk.pending)
	for i := 0; i < 20 && d.acl.a.hosts[0].n == 0; i += 1 {
		event.wait(&d.loop)
	}
	h := &d.acl.a.hosts[0]
	testing.expect(t, h.n > 0)
	testing.expect(t, !d.acl.lk.pending)
	// The next round waits for the interval.
	testing.expect(t, d.acl.lk.timer.on)
	lo := false
	for a in h.addrs[:h.n] {
		lo ||= a == acl.map4([]u8{127, 0, 0, 1})
	}
	testing.expect(t, lo)
	// 127.0.0.1:22 is now open: a SYN from the tunnel to it passes.
	p := syn_to(22)
	p[16], p[17], p[18], p[19] = 127, 0, 0, 1
	write_tun(&d, p[:])
	testing.expect_value(t, d.stats.drop_acl, 0)
}
