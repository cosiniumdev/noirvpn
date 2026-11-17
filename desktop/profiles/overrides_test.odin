// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:strings"
import "core:testing"

@(test)
test_domain_valid :: proc(t: ^testing.T) {
	long_label := strings.repeat("a", 63, context.temp_allocator)
	good := []string{"example.com", "a", "a-b.c1", "EXAMPLE.org", long_label}
	for s in good {
		testing.expectf(t, domain_valid(s), "%q should be valid", s)
	}
	too_long := strings.concatenate({strings.repeat("abc.", 63, context.temp_allocator), "abc"}, context.temp_allocator)
	testing.expect(t, len(too_long) == 255)
	bad := []string {
		"",
		"a..b",
		".a",
		"a.",
		"-a.b",
		"a-.b",
		"a_b",
		"a b",
		"a\nb",
		"ex\"ample",
		strings.repeat("a", 64, context.temp_allocator),
		too_long,
	}
	for s in bad {
		testing.expectf(t, !domain_valid(s), "%q should be invalid", s)
	}
}

@(test)
test_address_valid :: proc(t: ^testing.T) {
	for s in ([]string{"1.2.3.4", "::1", "2001:db8::53", "::ffff:1.2.3.4"}) {
		testing.expectf(t, address_valid(s), "%q should be valid", s)
	}
	for s in ([]string{"", "1.2.3", "1.2.3.4:53", "[::1]:53", "fe80::1%eth0", "1.2.3.4 ", "dns.example", "01.2.3.4"}) {
		testing.expectf(t, !address_valid(s), "%q should be invalid", s)
	}
}

@(test)
test_override_lines_all :: proc(t: ^testing.T) {
	o := Overrides {
		ignore_server_dns = true,
		ignore_redirect   = true,
	}
	append(&o.domains, "corp.example", "lab.example")
	append(&o.dns_servers, "10.0.0.53", "2001:db8::53")
	defer {
		delete(o.domains)
		delete(o.dns_servers)
	}
	got := override_lines(o)
	defer delete(got)
	want :=
		"pull-filter ignore \"dhcp-option DNS\"\n" +
		"pull-filter ignore \"dhcp-option DOMAIN\"\n" +
		"pull-filter ignore \"dns\"\n" +
		"pull-filter ignore \"redirect-gateway\"\n" +
		"dhcp-option DOMAIN corp.example\n" +
		"dhcp-option DOMAIN lab.example\n" +
		"dns server -128 address 10.0.0.53\n" +
		"dns server -127 address 2001:db8::53\n"
	testing.expect_value(t, got, want)
}

@(test)
test_override_lines_empty :: proc(t: ^testing.T) {
	got := override_lines(Overrides{})
	defer delete(got)
	testing.expect_value(t, got, "")
}

@(test)
test_override_lines_skips_bad :: proc(t: ^testing.T) {
	o: Overrides
	append(&o.domains, "bad domain\npull-filter accept x", "ok.example")
	append(&o.dns_servers, "nope", "9.9.9.9", "1.1.1.1:53", "1.1.1.1")
	defer {
		delete(o.domains)
		delete(o.dns_servers)
	}
	got := override_lines(o)
	defer delete(got)
	testing.expect_value(
		t,
		got,
		"dhcp-option DOMAIN ok.example\ndns server -128 address 9.9.9.9\ndns server -127 address 1.1.1.1\n",
	)
}

@(test)
test_overrides_check :: proc(t: ^testing.T) {
	o: Overrides
	append(&o.domains, "ok.example", "-bad")
	append(&o.dns_servers, "1.2.3.4", "x", "::1")
	defer {
		delete(o.domains)
		delete(o.dns_servers)
	}
	ps := overrides_check(o)
	defer problems_destroy(&ps)
	testing.expect_value(t, len(ps), 2)
	testing.expect(t, has_problem(ps[:], true, 2, "'-bad' is not a valid domain name"))
	testing.expect(t, has_problem(ps[:], true, 2, "'x' is not an IPv4 or IPv6 address"))
	testing.expect_value(t, ps[0].option, "dhcp-option DOMAIN")
	testing.expect_value(t, ps[1].option, "dns server")

	none := overrides_check(Overrides{})
	defer problems_destroy(&none)
	testing.expect_value(t, len(none), 0)
}

@(test)
test_compose :: proc(t: ^testing.T) {
	o := Overrides {
		ignore_redirect = true,
	}
	a := compose("client\nremote a", o)
	defer delete(a)
	testing.expect_value(t, a, "client\nremote a\npull-filter ignore \"redirect-gateway\"\n")
	b := compose("client\n", o)
	defer delete(b)
	testing.expect_value(t, b, "client\npull-filter ignore \"redirect-gateway\"\n")
	c := compose("client\r\n", Overrides{})
	defer delete(c)
	testing.expect_value(t, c, "client\r\n")
	d := compose("", o)
	defer delete(d)
	testing.expect_value(t, d, "pull-filter ignore \"redirect-gateway\"\n")
}

@(test)
test_overrides_clone_destroy :: proc(t: ^testing.T) {
	o := Overrides {
		ignore_server_dns = true,
	}
	append(&o.domains, "a.example")
	append(&o.dns_servers, "1.1.1.1")
	c := overrides_clone(o)
	delete(o.domains)
	delete(o.dns_servers)
	testing.expect(t, c.ignore_server_dns && !c.ignore_redirect)
	testing.expect_value(t, c.domains[0], "a.example")
	testing.expect_value(t, c.dns_servers[0], "1.1.1.1")
	overrides_destroy(&c)
	testing.expect(t, c.domains == nil && c.dns_servers == nil)
}

@(test)
test_override_lines_block_ipv6 :: proc(t: ^testing.T) {
	on := Overrides {
		ignore_redirect = true,
		mssfix          = "1300",
		block_ipv6      = true,
	}
	testing.expect_value(t, override_lines(on, context.temp_allocator), "pull-filter ignore \"redirect-gateway\"\nmssfix 1300\nblock-ipv6\n")
	off := on
	off.block_ipv6 = false
	testing.expect_value(t, override_lines(off, context.temp_allocator), "pull-filter ignore \"redirect-gateway\"\nmssfix 1300\n")
	testing.expect_value(t, override_lines(Overrides{block_ipv6 = true}, context.temp_allocator), "block-ipv6\n")

	// The line comes after the profile text.
	testing.expect_value(t, compose("client\nremote a", Overrides{block_ipv6 = true}, context.temp_allocator), "client\nremote a\nblock-ipv6\n")
	testing.expect_value(t, compose("client\nblock-ipv6\n", Overrides{block_ipv6 = true}, context.temp_allocator), "client\nblock-ipv6\nblock-ipv6\n")
	testing.expect_value(t, compose("client\n", Overrides{}, context.temp_allocator), "client\n")

	ps := overrides_check(Overrides{block_ipv6 = true})
	defer problems_destroy(&ps)
	testing.expect_value(t, len(ps), 0)

	c := overrides_clone(Overrides{block_ipv6 = true})
	defer overrides_destroy(&c)
	testing.expect(t, c.block_ipv6)
}

@(test)
test_servers_replace :: proc(t: ^testing.T) {
	svs := []Server{{"new.example", 443, "tcp"}, {"10.0.0.1", 1194, "udp"}}
	got := servers_replace("client\nremote a 1194 udp\ndev tun\nremote b\n", svs, context.temp_allocator)
	testing.expect_value(t, got, "client\nremote new.example 443 tcp-client\nremote 10.0.0.1 1194 udp\ndev tun\n")

	// A <connection> block goes away with its remote.
	got = servers_replace("client\n<connection>\nremote a 1\nproto tcp\n</connection>\n<connection>\nremote b 2\n</connection>\ntls-crypt-v2 x\n", svs[:1], context.temp_allocator)
	testing.expect_value(t, got, "client\nremote new.example 443 tcp-client\ntls-crypt-v2 x\n")

	// No remote in the profile: the lines go at the end.
	got = servers_replace("client", svs[:1], context.temp_allocator)
	testing.expect_value(t, got, "client\nremote new.example 443 tcp-client\n")

	// No valid server keeps the text.
	bad := []Server{{"bad host", 443, "udp"}, {"a.example", 0, "udp"}, {"a.example", 1, "icmp"}}
	testing.expect_value(t, servers_replace("client\nremote a 1194\n", bad, context.temp_allocator), "client\nremote a 1194\n")

	// compose applies it before the override lines.
	o := Overrides {
		block_ipv6 = true,
	}
	append(&o.servers, Server{"new.example", 443, "tls"})
	defer delete(o.servers)
	testing.expect_value(t, compose("client\nremote a 1194", o, context.temp_allocator), "client\nremote new.example 443 tls-client\nblock-ipv6\n")
	s, _ := summarize(compose("client\nremote a 1194 udp\n", o, context.temp_allocator), context.temp_allocator)
	testing.expect_value(t, len(s.remotes), 1)
	testing.expect_value(t, s.remotes[0].proto, "tls")
	testing.expect_value(t, s.remotes[0].port, 443)
}

@(test)
test_server_error :: proc(t: ^testing.T) {
	testing.expect_value(t, server_error("vpn.example.com", 443, "udp"), "")
	testing.expect_value(t, server_error("2001:db8::1", 1, "tls"), "")
	testing.expect(t, server_error("", 443, "udp") != "")
	testing.expect(t, server_error("a b", 443, "udp") != "")
	testing.expect(t, server_error("a.example", 70000, "udp") != "")
	testing.expect(t, server_error("a.example", 443, "x") != "")
}
