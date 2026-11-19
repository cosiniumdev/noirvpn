// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:fmt"
import "core:strings"
import "core:testing"
import "noir:proto/acl"

@(test)
test_acl_defaults :: proc(t: ^testing.T) {
	cfg := load_client("")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	c := &cfg.client
	testing.expect_value(t, len(c.allow_inbound), 0)
	testing.expect_value(t, len(c.forwards), 0)
	testing.expect_value(t, c.acl_max_flows, ACL_MAX_FLOWS_DEFAULT)
	testing.expect_value(t, c.acl_resolve_interval, ACL_RESOLVE_DEFAULT)
	testing.expect_value(t, c.forward_max_conns, FORWARD_MAX_CONNS_DEFAULT)
}

@(test)
test_acl_dest_forms :: proc(t: ^testing.T) {
	cfg := load_client(
		"allow-inbound :22 :8000-8099 tcp\n" +
		"allow-inbound 10.20.0.5 10.20.0.0/16 192.168.1.0/255.255.255.0\n" +
		"allow-inbound 10.20.0.5:443 [fd00::5]:443 fd00::/64 fd00::7\n" +
		"allow-inbound nas.lan tcp icmp\n" +
		"allow-inbound nas.lan:445 NAS.lan:139 tcp\n" +
		"allow-inbound 10.9.0.0/16:53 udp\n",
	)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	r := cfg.client.allow_inbound
	if !testing.expect_value(t, len(r), 13) {
		return
	}
	testing.expect_value(t, r[0].target, acl.Target.Tunnel)
	testing.expect_value(t, r[0].port_lo, 22)
	testing.expect_value(t, r[0].protos, acl.Protos{.Tcp})
	testing.expect_value(t, r[1].port_lo, 8000)
	testing.expect_value(t, r[1].port_hi, 8099)

	testing.expect_value(t, r[2].target, acl.Target.Prefix)
	testing.expect(t, r[2].v4)
	testing.expect_value(t, r[2].bits, 128)
	testing.expect_value(t, r[2].protos, acl.PROTOS_ALL)
	testing.expect(t, r[2].addr == acl.map4([]u8{10, 20, 0, 5}))
	testing.expect_value(t, r[3].bits, 96 + 16)
	testing.expect_value(t, r[4].bits, 96 + 24)

	testing.expect_value(t, r[5].port_lo, 443)
	testing.expect_value(t, r[5].protos, acl.PROTOS_PORTS)
	testing.expect(t, !r[6].v4)
	testing.expect_value(t, r[6].bits, 128)
	testing.expect_value(t, r[6].port_lo, 443)
	testing.expect_value(t, r[7].bits, 64)
	testing.expect_value(t, r[7].port_lo, 0)
	testing.expect_value(t, r[8].bits, 128)

	// One name, one host slot; the case of the name does not matter.
	testing.expect_value(t, r[9].target, acl.Target.Host)
	testing.expect_value(t, len(cfg.client.acl_hosts), 1)
	testing.expect_value(t, r[9].host, 0)
	testing.expect_value(t, r[11].host, 0)
	testing.expect_value(t, r[9].protos, acl.Protos{.Tcp, .Icmp})
	testing.expect_value(t, r[12].port_lo, 53)
	testing.expect_value(t, r[12].bits, 96 + 16)
	testing.expect_value(t, r[12].protos, acl.Protos{.Udp})
}

@(test)
test_acl_errors :: proc(t: ^testing.T) {
	cases := []struct {
		line: string,
		part: string,
	} {
		{"allow-inbound tcp", "needs a destination"},
		{"allow-inbound :22 tcp :23", "after all the destinations"},
		{"allow-inbound :0", "port from 1 to 65535"},
		{"allow-inbound :9-8", "port from 1 to 65535"},
		{"allow-inbound 10.0.0.1:", "port from 1 to 65535"},
		{"allow-inbound 10.0.0.1/8", "bits set after"},
		{"allow-inbound fd00::1/64", "bits set after"},
		{"allow-inbound 10.0.0.256", "not an address"},
		{"allow-inbound [fd00::1", "closing ]"},
		{"allow-inbound [fd00::1]443", ":port after"},
		{"allow-inbound [nas.lan]:22", "IPv6"},
		{"allow-inbound bad!name", "not an address"},
		{"allow-inbound :22 icmp", "icmp has no ports"},
		{"forward 8080 127.0.0.1:80", "needs 3 to 5"},
		{"forward 8080 tcp 127.0.0.1:80", "forward <port>"},
		{"forward 0 to 127.0.0.1:80", "from 1 to 65535"},
		{"forward 8080 icmp to 127.0.0.1:80", "tcp or udp"},
		{"forward 8080 to 127.0.0.1", "host:port"},
		{"forward 8080 to ::1:80", "brackets"},
		{"forward 8080 to [::1]80", "[address]:port"},
		{"forward 8080 to 127.0.0.1:99999", "target port"},
		{"acl-max-flows 10", "number of flows"},
		{"acl-resolve-interval 1", "interval"},
	}
	for c in cases {
		cfg := load_client(c.line)
		expect_error(t, cfg.diags, FIRST_EXTRA_LINE, c.part)
		destroy(&cfg)
	}
}

@(test)
test_forward_forms :: proc(t: ^testing.T) {
	cfg := load_client(
		"forward 8080 to 127.0.0.1:80\n" +
		"forward 5353 udp to dns.lan:53\n" +
		"forward 8443 tcp udp to [fd00::5]:443\n" +
		"forward 5353 tcp to dns.lan:53\n",
	)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	f := cfg.client.forwards
	if !testing.expect_value(t, len(f), 4) {
		return
	}
	testing.expect_value(t, f[0].port, 8080)
	testing.expect_value(t, f[0].protos, acl.Protos{.Tcp})
	testing.expect_value(t, f[0].host, "127.0.0.1")
	testing.expect_value(t, f[0].host_port, 80)
	testing.expect_value(t, f[1].protos, acl.Protos{.Udp})
	testing.expect_value(t, f[1].host, "dns.lan")
	testing.expect_value(t, f[2].protos, acl.Protos{.Tcp, .Udp})
	testing.expect_value(t, f[2].host, "fd00::5")
	testing.expect_value(t, f[2].host_port, 443)
}

@(test)
test_forward_duplicate :: proc(t: ^testing.T) {
	cfg := load_client("forward 8080 to 127.0.0.1:80\nforward 8080 tcp udp to 127.0.0.1:81")
	defer destroy(&cfg)
	expect_error(t, cfg.diags, FIRST_EXTRA_LINE + 1, "already forwarded")
}

@(test)
test_acl_limits_warn_alone :: proc(t: ^testing.T) {
	cfg := load_client("acl-max-flows 4096\nforward-max-conns 10")
	defer destroy(&cfg)
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE, "without allow-inbound")
	expect_warning(t, cfg.diags, FIRST_EXTRA_LINE + 1, "without forward")
	testing.expect_value(t, cfg.client.acl_max_flows, 4096)
}

// The server is told that a client ignores them (the client parser of pushed
// options has no case for them).
@(test)
test_acl_not_pushable :: proc(t: ^testing.T) {
	cfg := load_server("push \"allow-inbound 0.0.0.0/0\"\npush \"forward 80 to 127.0.0.1:80\"")
	defer destroy(&cfg)
	expect_warning(t, cfg.diags, 12, "cannot be pushed")
	expect_warning(t, cfg.diags, 13, "cannot be pushed")
}

@(test)
test_acl_dest_text :: proc(t: ^testing.T) {
	cfg := load_client(
		"allow-inbound :22 :8000-8099 tcp\n" +
		"allow-inbound 10.20.0.5 10.20.0.0/16 192.168.1.0/255.255.255.0\n" +
		"allow-inbound 10.20.0.5:443 [fd00::5]:443 fd00::/64 fd00::7\n" +
		"allow-inbound nas.lan tcp icmp\n" +
		"allow-inbound nas.lan:445 NAS.lan:139 tcp\n" +
		"allow-inbound 10.9.0.0/16:53 [fd00::/64]:80-90 udp\n" +
		"allow-inbound 0.0.0.0/0 ::/0 ::1 icmp\n",
	)
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	want := []string {
		":22",
		":8000-8099",
		"10.20.0.5",
		"10.20.0.0/16",
		"192.168.1.0/24",
		"10.20.0.5:443",
		"[fd00::5]:443",
		"fd00::/64",
		"fd00::7",
		"nas.lan",
		"nas.lan:445",
		"nas.lan:139",
		"10.9.0.0/16:53",
		"[fd00::/64]:80-90",
		"0.0.0.0/0",
		"::/0",
		"::1",
	}
	r := cfg.client.allow_inbound
	if !testing.expect_value(t, len(r), len(want)) {
		return
	}
	for w, i in want {
		got := acl_dest_text(r[i], cfg.client.acl_hosts, context.temp_allocator)
		testing.expectf(t, got == w, "rule %d: %q, want %q", i, got, w)
		// The text gives the same rule again.
		back := load_client(fmt.tprintf("allow-inbound %s", got))
		testing.expectf(t, len(back.client.allow_inbound) == 1, "rule %d: %q does not parse again", i, got)
		if len(back.client.allow_inbound) == 1 {
			x := back.client.allow_inbound[0]
			y := r[i]
			x.protos, y.protos = {}, {}
			x.host, y.host = 0, 0
			testing.expectf(t, x == y, "rule %d: %q gives another rule", i, got)
		}
		destroy(&back)
	}
	words: [4]string
	testing.expect_value(t, len(acl_proto_words(r[0].protos, &words)), 1)
	testing.expect_value(t, words[0], "tcp")
	all := acl_proto_words(acl.PROTOS_ALL, &words)
	testing.expect_value(t, len(all), 4)
	testing.expect_value(t, all[3], "other")
}

@(test)
test_forward_target_text :: proc(t: ^testing.T) {
	cfg := load_client("forward 8080 to 127.0.0.1:80\nforward 5353 udp to dns.lan:53\nforward 2222 tcp udp to [fd00::5]:22\n")
	defer destroy(&cfg)
	expect_clean(t, cfg.diags)
	f := cfg.client.forwards
	if !testing.expect_value(t, len(f), 3) {
		return
	}
	testing.expect_value(t, forward_target_text(f[0], context.temp_allocator), "127.0.0.1:80")
	testing.expect_value(t, forward_target_text(f[1], context.temp_allocator), "dns.lan:53")
	testing.expect_value(t, forward_target_text(f[2], context.temp_allocator), "[fd00::5]:22")
}

@(test)
test_acl_line_problem :: proc(t: ^testing.T) {
	good := []string {
		"allow-inbound :22 tcp",
		"allow-inbound 0.0.0.0/0 ::/0 icmp",
		"allow-inbound nas.lan:445",
		"  allow-inbound [fd00::5]:443 udp  ",
		"forward 8080 to 127.0.0.1:80",
		"forward 5353 udp to dns.lan:53",
	}
	for line in good {
		p := acl_line_problem(line, context.temp_allocator)
		testing.expectf(t, p == "", "%q: %q", line, p)
	}
	bad := []struct {
		line, part: string,
	} {
		{"allow-inbound :22:23", "port"},
		{"allow-inbound 10.0.0.5:22 icmp", "icmp has no ports"},
		{"allow-inbound", "needs a destination"},
		{"allow-inbound 10.0.0.300", "not an address"},
		{"forward 8080", "must be"},
		{"forward 8080 icmp to a.lan:1", "must be tcp or udp"},
		{"route 10.0.0.0 255.0.0.0", "allow-inbound or forward"},
		{"allow-inbound :22\nallow-inbound :23", "one line"},
		{"", "one line"},
	}
	for c in bad {
		p := acl_line_problem(c.line, context.temp_allocator)
		testing.expectf(t, strings.contains(p, c.part), "%q: %q, want %q in it", c.line, p, c.part)
		testing.expectf(t, !strings.has_prefix(p, "allow-inbound:") && !strings.has_prefix(p, "forward:"), "%q: the option name stays in %q", c.line, p)
	}
}
