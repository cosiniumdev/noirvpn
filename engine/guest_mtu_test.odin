// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:testing"
import "noir:client"
import "noir:proto/config"
import "noir:proto/mss"
import "noir:proto/push"

@(private = "file")
BASE :: "topology subnet,ifconfig 10.8.0.6 255.255.255.0,route-gateway 10.8.0.1"

// Builds the plan of a guest for the push text and the profile value.
@(private = "file")
build :: proc(t: ^testing.T, push_text: string, conn_mtu: int) -> (plan: client.Plan, ok: bool) {
	cfg := config.build(config.parse_text("client\nremote vpn.example 1194 udp\nca /nonexistent/ca.crt\n", "test.conf"))
	defer config.destroy(&cfg)
	po: push.Pushed_Options
	testing.expect_value(t, push.pushed_options_parse(&po, push_text), push.Error.None)
	defer push.pushed_options_destroy(&po)
	input := client.Plan_Input {
		cfg    = &cfg.client,
		pushed = &po,
	}
	err: client.Plan_Error
	plan, err = guest_plan_build(input, conn_mtu)
	testing.expect_value(t, err, client.Plan_Error.None)
	return plan, err == .None
}

@(private = "file")
lowered_notes :: proc(plan: ^client.Plan) -> (n: int, text: string) {
	for note in plan.notes {
		if note.kind == .Adjusted {
			n += 1
			text = note.text
		}
	}
	return
}

@(test)
test_guest_mtu_pushed_1500 :: proc(t: ^testing.T) {
	plan, ok := build(t, BASE + ",tun-mtu 1500", 0)
	if !ok {
		return
	}
	defer client.plan_destroy(&plan)
	testing.expect_value(t, plan.mtu, u32(1428))
	n, text := lowered_notes(&plan)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, text, "tun-mtu 1500 lowered to 1428 (the largest on mobile)")
}

@(test)
test_guest_mtu_profile_small_stays :: proc(t: ^testing.T) {
	plan, ok := build(t, BASE, 1400)
	if !ok {
		return
	}
	defer client.plan_destroy(&plan)
	testing.expect_value(t, plan.mtu, u32(1400))
	n, _ := lowered_notes(&plan)
	testing.expect_value(t, n, 0)
}

@(test)
test_guest_mtu_profile_9000 :: proc(t: ^testing.T) {
	plan, ok := build(t, BASE, 9000)
	if !ok {
		return
	}
	defer client.plan_destroy(&plan)
	testing.expect_value(t, plan.mtu, u32(1428))
	n, text := lowered_notes(&plan)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, text, "tun-mtu 9000 lowered to 1428 (the largest on mobile)")
}

// The engine default is 1400, which is below the cap: it stays.
@(test)
test_guest_mtu_default :: proc(t: ^testing.T) {
	plan, ok := build(t, BASE, 0)
	if !ok {
		return
	}
	defer client.plan_destroy(&plan)
	testing.expect_value(t, plan.mtu, u32(DEFAULT_TUN_MTU))
	testing.expect(t, DEFAULT_TUN_MTU <= GUEST_MAX_MTU)
	n, _ := lowered_notes(&plan)
	testing.expect_value(t, n, 0)
}

@(test)
test_guest_mtu_pushed_1300 :: proc(t: ^testing.T) {
	plan, ok := build(t, BASE + ",tun-mtu 1300", 1428)
	if !ok {
		return
	}
	defer client.plan_destroy(&plan)
	testing.expect_value(t, plan.mtu, u32(1300))
	n, _ := lowered_notes(&plan)
	testing.expect_value(t, n, 0)
}

@(test)
test_guest_mtu_pushed_wins_over_profile :: proc(t: ^testing.T) {
	plan, ok := build(t, BASE + ",tun-mtu 1500", 1400)
	if !ok {
		return
	}
	defer client.plan_destroy(&plan)
	testing.expect_value(t, plan.mtu, u32(1428))
}

// The plan and the clamp read the same decision.
@(test)
test_guest_mtu_decision :: proc(t: ^testing.T) {
	testing.expect_value(t, guest_mtu(1500, 0), Guest_Mtu{mtu = 1428, wanted = 1500, lowered = true})
	testing.expect_value(t, guest_mtu(nil, 9000), Guest_Mtu{mtu = 1428, wanted = 9000, lowered = true})
	testing.expect_value(t, guest_mtu(1428, 0), Guest_Mtu{mtu = 1428, wanted = 1428})
	testing.expect_value(t, guest_mtu(1300, 1500), Guest_Mtu{mtu = 1300, wanted = 1300})
	testing.expect_value(t, guest_mtu(nil, 0).mtu, DEFAULT_TUN_MTU)
}

@(test)
test_guest_mtu_mss_from_cap :: proc(t: ^testing.T) {
	cfg := config.build(config.parse_text("client\nremote vpn.example 1194 udp\nca /nonexistent/ca.crt\n", "test.conf"))
	defer config.destroy(&cfg)
	d: Daemon
	d.cfg = &cfg.client
	po: push.Pushed_Options
	po.tun_mtu = 1500
	// The daemon: 1500 stays.
	testing.expect_value(t, client_tun_mtu(&d, &po), 1500)
	// A guest: the cap, and the clamp is computed from it.
	g: Guest
	d.guest = &g
	testing.expect_value(t, client_tun_mtu(&d, &po), 1428)
	overhead := 4 + 4 + 16
	want := mss.mss_ipv4({}, 1428, false, false, overhead)
	testing.expect_value(t, mss.mss_ipv4({}, client_tun_mtu(&d, &po), false, false, overhead), want)
	testing.expect_value(t, want, 1428 - 40)
	// The daemon clamp for 1500 is the `mssfix 1492 mtu` form: a different value.
	testing.expect(t, mss.mss_ipv4({}, 1500, false, false, overhead) != want)
	po.tun_mtu = 1300
	testing.expect_value(t, client_tun_mtu(&d, &po), 1300)
}

// The settings of a guest accept a large tun-mtu (it is lowered later); the
// daemon and the service still refuse it.
@(test)
test_guest_mtu_settings_check :: proc(t: ^testing.T) {
	text := "client\nremote vpn.example 1194 udp\nca /nonexistent/ca.crt\ntun-mtu 9000\n"
	for ask in ([]Key_Ask{.Guest, .Profile}) {
		cfg := config.build(config.parse_text(text, "test.conf"))
		s: Settings
		_ = settings_load(&s, &cfg, ask)
		found := false
		for e in s.errors {
			if len(e) >= 7 && string(e[:7]) == "tun-mtu" {
				found = true
			}
		}
		testing.expectf(t, found == (ask != .Guest), "ask %v: tun-mtu error %v", ask, found)
		settings_destroy(&s)
		config.destroy(&cfg)
	}
}
