// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:encoding/json"
import "core:strings"
import "core:testing"
import "noir:bus"
import "noir:client"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/push"

@(private = "file")
DNS_BASE :: "client\nremote vpn.example 1194 udp\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"

@(private = "file")
PUSHED_DNS :: "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1,dhcp-option DNS 10.8.0.2,dns server 5 address 10.8.0.1,dns server 9 address 10.8.0.9,dns server 9 transport DoH,dns search-domains corp.example,dhcp-option DOMAIN old.example"

// The two DNS lists of the settings event, as text joined by spaces.
@(private = "file")
dns_lists_for :: proc(t: ^testing.T, conf: string) -> (servers, domains: string) {
	cfg := config.build(config.parse_text(strings.concatenate({DNS_BASE, conf}, context.temp_allocator), "test.conf"))
	defer config.destroy(&cfg)
	testing.expect(t, config.ok(&cfg))
	po: push.Pushed_Options
	testing.expect_value(t, push.pushed_options_parse(&po, PUSHED_DNS), push.Error.None)
	defer push.pushed_options_destroy(&po)
	plan, err := client.plan_build(client.Plan_Input{cfg = &cfg.client, pushed = &po, server = sysnet.Address(sysnet.IP4_Address{203, 0, 113, 7})})
	defer client.plan_destroy(&plan)
	testing.expect_value(t, err, client.Plan_Error.None)

	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)
	bus.begin_obj(&w)
	client_dns_lists(&w, len(cfg.client.dns_options) > 0, &plan, &po)
	bus.end(&w)
	v, perr := json.parse(transmute([]u8)bus.writer_string(&w), .JSON, true, context.temp_allocator)
	testing.expect_value(t, perr, json.Error.None)
	obj := v.(json.Object)
	join :: proc(a: json.Value) -> string {
		parts := make([dynamic]string, context.temp_allocator)
		for e in a.(json.Array) {
			append(&parts, string(e.(json.String)))
		}
		return strings.join(parts[:], " ", context.temp_allocator)
	}
	return join(obj["dns_servers"]), join(obj["dns_domains"])
}

@(test)
test_tunnel_settings_dns_lists :: proc(t: ^testing.T) {
	// No local DNS line: the pushed lists, as they were pushed.
	servers, domains := dns_lists_for(t, "")
	testing.expect_value(t, servers, "10.8.0.2 10.8.0.1 10.8.0.9")
	testing.expect_value(t, domains, "old.example corp.example")
	// Local lines: the merged lists that the plan applies.
	servers, domains = dns_lists_for(t, "dns server 0 address 192.0.2.53\ndhcp-option DOMAIN home.example\n")
	testing.expect_value(t, servers, "192.0.2.53 10.8.0.1")
	testing.expect_value(t, domains, "corp.example home.example old.example")
}
