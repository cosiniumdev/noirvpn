// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:strings"
import "core:testing"
import "noir:proto/config"

filters :: proc(text: string) -> []config.Pull_Filter {
	// "accept route", "ignore dhcp-option DNS", "reject redirect-gateway": one rule per line.
	list := make([dynamic]config.Pull_Filter, context.temp_allocator)
	rest := text
	for len(rest) > 0 {
		line: string
		nl := strings.index_byte(rest, '\n')
		if nl < 0 {
			line, rest = rest, ""
		} else {
			line, rest = rest[:nl], rest[nl + 1:]
		}
		if line == "" {
			continue
		}
		sp := strings.index_byte(line, ' ')
		f := config.Pull_Filter {
			text = line[sp + 1:],
		}
		switch line[:sp] {
		case "accept":
			f.action = .Accept
		case "ignore":
			f.action = .Ignore
		case "reject":
			f.action = .Reject
		}
		append(&list, f)
	}
	return list[:]
}

@(test)
pull_filter_match_rules :: proc(t: ^testing.T) {
	rules := filters("ignore dhcp-option DNS\naccept route 10.\nignore route\nreject redirect-gateway")
	cases := []struct {
		option: string,
		want:   Pull_Verdict,
	} {
		{"dhcp-option DNS 1.1.1.1", .Ignore},
		{"dhcp-option DNS6 fd00::1", .Ignore}, // a prefix match: DNS6 starts with DNS
		{"dhcp-option DOMAIN corp", .Accept},
		// The first matching rule decides: accept comes before the ignore.
		{"route 10.1.0.0 255.255.0.0", .Accept},
		{"route 192.168.0.0 255.255.0.0", .Ignore},
		{"route-ipv6 fd00::/64", .Ignore}, // `route` is a prefix of `route-ipv6`
		{"redirect-gateway def1", .Reject},
		{"  redirect-gateway def1", .Reject},
		{"topology subnet", .Accept},
		{"", .Accept},
	}
	for c in cases {
		testing.expectf(t, pull_filter_match(rules, c.option) == c.want, "%q: want %v", c.option, c.want)
	}
	testing.expect_value(t, pull_filter_match(nil, "route 1.2.3.4"), Pull_Verdict.Accept)
}

@(test)
pull_filter_drops_options :: proc(t: ^testing.T) {
	rules := filters("ignore route\nignore dhcp-option")
	in_text := "route 10.0.0.0 255.0.0.0,topology subnet,dhcp-option DNS 10.8.0.1,ifconfig 10.8.0.6 255.255.255.0,route 10.2.0.0 255.255.0.0,push-continuation 1"
	res, ok := pull_filter_options(rules, in_text)
	testing.expect(t, ok)
	defer delete(res.options)
	testing.expect_value(t, res.options, "topology subnet,ifconfig 10.8.0.6 255.255.255.0,push-continuation 1")
	testing.expect_value(t, res.ignored, 3)
	testing.expect(t, res.rejected == nil)
}

@(test)
pull_filter_reject_is_reported :: proc(t: ^testing.T) {
	rules := filters("reject redirect-gateway\nignore route")
	res, ok := pull_filter_options(rules, "route 10.0.0.0 255.0.0.0,redirect-gateway def1,topology subnet")
	testing.expect(t, ok)
	defer delete(res.options)
	bad, has := res.rejected.?
	testing.expect(t, has)
	testing.expect_value(t, bad, "redirect-gateway def1")
	testing.expect_value(t, res.options, "topology subnet")
	testing.expect_value(t, res.ignored, 1)
}

@(test)
pull_filter_never_touches_push_continuation :: proc(t: ^testing.T) {
	// A rule with an empty text matches everything.
	rules := filters("ignore ")
	res, ok := pull_filter_options(rules, "route 1.2.3.4,push-continuation 2")
	testing.expect(t, ok)
	defer delete(res.options)
	testing.expect_value(t, res.options, "push-continuation 2")
	testing.expect_value(t, res.ignored, 1)
}

@(test)
pull_filter_no_rules_copies_the_text :: proc(t: ^testing.T) {
	text := "route 1.2.3.4,,topology subnet"
	res, ok := pull_filter_options(nil, text)
	testing.expect(t, ok)
	defer delete(res.options)
	testing.expect_value(t, res.options, text)
	testing.expect(t, raw_data(res.options) != raw_data(text))
	empty, eok := pull_filter_options(filters("ignore route"), "")
	testing.expect(t, eok)
	testing.expect_value(t, empty.options, "")
}

@(test)
pull_filter_from_a_real_config :: proc(t: ^testing.T) {
	cfg := load_client("remote a.example", "pull-filter ignore \"dhcp-option DNS\"\npull-filter reject redirect-gateway\npull-filter accept route")
	defer config.destroy(&cfg)
	if !expect_config_ok(t, &cfg) {
		return
	}
	testing.expect_value(t, len(cfg.client.pull_filters), 3)
	res, _ := pull_filter_options(cfg.client.pull_filters, "dhcp-option DNS 1.1.1.1,route 10.0.0.0 255.0.0.0,redirect-gateway")
	defer delete(res.options)
	testing.expect_value(t, res.options, "route 10.0.0.0 255.0.0.0")
	testing.expect(t, res.rejected != nil)
}
