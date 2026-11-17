// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:fmt"
import "core:strings"
import "core:testing"
import "noir:proto/config"
import "noir:proto/push"

// A server config, its pools, a pin store and an in-memory ccd directory.
CP_Fixture :: struct {
	cfg:   config.Config,
	pools: Pools,
	pins:  Pin_Store,
	files: Mem_Files,
	env:   Params_Env,
}

CP_BASE :: SERVER_BASE + "client-config-dir /ccd\nkeepalive 10 60\npush \"route 10.9.0.0 255.255.255.0\"\n"

cp_fixture :: proc(t: ^testing.T, extra := "", peers := "", base := CP_BASE) -> (f: ^CP_Fixture, ok: bool) {
	f = new(CP_Fixture)
	f.cfg, ok = make_cfg(t, base, extra)
	if !ok {
		free(f)
		return nil, false
	}
	f.files = make(Mem_Files)
	testing.expect(t, pools_init(&f.pools, &f.cfg.server, 0))
	if peers != "" {
		pin_store_init(&f.pins, make_pins(t, peers))
		f.env.pins = &f.pins
	}
	f.env.cfg = &f.cfg.server
	f.env.pools = &f.pools
	f.env.loader = mem_loader
	f.env.loader_data = &f.files
	return f, true
}

cp_destroy :: proc(f: ^CP_Fixture) {
	if f.env.pins != nil {
		pin_table_destroy(pin_store_current(&f.pins))
	}
	delete(f.files)
	pools_destroy(&f.pools)
	config.destroy(&f.cfg)
	free(f)
}

cp_build :: proc(f: ^CP_Fixture, name: string, spki := [32]u8{}, pinned := false) -> (Assignment, Reject, string) {
	return client_params_build(&f.env, Connect_Request{identity = name, spki = spki, pinned = pinned, peer_id = 7}, 0)
}

push_has :: proc(a: ^Assignment, line: string) -> bool {
	for l in a.push {
		if l == line {
			return true
		}
	}
	return false
}

push_index :: proc(a: ^Assignment, line: string) -> int {
	for l, i in a.push {
		if l == line {
			return i
		}
	}
	return -1
}

pools_held :: proc(f: ^CP_Fixture) -> int {
	return pool_used(&f.pools.v4) + pool_used(&f.pools.v6) + len(f.pools.static4) + len(f.pools.static6)
}

@(test)
test_cp_plain_client :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect(t, a.has4 && !a.has6)
	testing.expect_value(t, a.addr4, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, a.netmask4, [4]u8{255, 255, 255, 0})
	testing.expect_value(t, a.gateway4, [4]u8{10, 8, 0, 1})
	testing.expect_value(t, a.peer_id, u32(7))
	testing.expect(t, !a.had_ccd)
	// The server's own push lines, in config order.
	testing.expect_value(t, len(a.push), 3)
	testing.expect(t, push_has(&a, "route 10.9.0.0 255.255.255.0"))
	testing.expect(t, push_has(&a, "ping 10"))
	testing.expect(t, push_has(&a, "ping-restart 60"))
	testing.expect_value(t, len(a.iroutes4), 0)
	testing.expect_value(t, pools_held(f), 1)
	pools_release(&f.pools, a.lease, 0)
	testing.expect_value(t, pools_held(f), 0)
}

@(test)
test_cp_ccd_static_and_push :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] =
		"ifconfig-push 10.8.0.77 255.255.255.0\n" +
		"push \"route 172.16.0.0 255.255.0.0\"\n" +
		"iroute 192.168.5.0 255.255.255.0\n" +
		"session-timeout 3600\n"
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect(t, a.had_ccd)
	testing.expect_value(t, a.addr4, [4]u8{10, 8, 0, 77})
	testing.expect_value(t, a.lease.kind4, Lease_Kind.Static_In_Range)
	testing.expect_value(t, a.session_timeout, 3600)
	testing.expect_value(t, len(a.iroutes4), 1)
	// Server lines come first, then the ccd lines.
	testing.expect(t, push_index(&a, "route 10.9.0.0 255.255.255.0") < push_index(&a, "route 172.16.0.0 255.255.0.0"))
	testing.expect(t, push_index(&a, "route 172.16.0.0 255.255.0.0") >= 0)
	// Another client is not touched by alice's file.
	b, rej2, _ := cp_build(f, "bob")
	defer assignment_destroy(&b)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	testing.expect(t, !b.had_ccd)
	testing.expect(t, !push_has(&b, "route 172.16.0.0 255.255.0.0"))
	testing.expect_value(t, b.addr4, [4]u8{10, 8, 0, 2})
}

@(test)
test_cp_ccd_default_and_exclusive :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "ccd-exclusive\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	_, rej, _ := cp_build(f, "alice")
	testing.expect_value(t, rej.reason, Reject_Reason.Ccd_Required)
	testing.expect_value(t, rej.kind, Reject_Kind.Auth_Failed)
	testing.expect_value(t, pools_held(f), 0)
	// A DEFAULT file counts as a file for everybody.
	f.files["/ccd/DEFAULT"] = "push \"dhcp-option DOMAIN example.com\"\n"
	a, rej2, _ := cp_build(f, "alice")
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	testing.expect(t, a.had_ccd)
	testing.expect(t, push_has(&a, "dhcp-option DOMAIN example.com"))
	assignment_destroy(&a)
	// A file for the name wins over DEFAULT.
	f.files["/ccd/bob"] = "push \"dhcp-option DOMAIN bob.example\"\n"
	b, rej3, _ := cp_build(f, "bob")
	defer assignment_destroy(&b)
	testing.expect_value(t, rej3.reason, Reject_Reason.None)
	testing.expect(t, push_has(&b, "dhcp-option DOMAIN bob.example"))
	testing.expect(t, !push_has(&b, "dhcp-option DOMAIN example.com"))
}

// The file of a name is found by the exact name, then by the name in lower case.
@(test)
test_cp_ccd_lower_case_fallback :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = "push \"dhcp-option DOMAIN lower.example\"\n"
	a, rej, _ := cp_build(f, "Alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect(t, a.had_ccd)
	testing.expect(t, push_has(&a, "dhcp-option DOMAIN lower.example"))
	// The exact name wins over the lower case one.
	f.files["/ccd/Bob"] = "push \"dhcp-option DOMAIN exact.example\"\n"
	f.files["/ccd/bob"] = "push \"dhcp-option DOMAIN lower.example\"\n"
	b, rej2, _ := cp_build(f, "Bob")
	defer assignment_destroy(&b)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	testing.expect(t, push_has(&b, "dhcp-option DOMAIN exact.example"))
	testing.expect(t, !push_has(&b, "dhcp-option DOMAIN lower.example"))
	// An error in the file names the file that was read.
	f.files["/ccd/carol"] = "bogus-option 1\n"
	_, rej3, text := cp_build(f, "CAROL")
	testing.expect_value(t, rej3.reason, Reject_Reason.Config_Error)
	testing.expect(t, strings.contains(text, "/ccd/carol"), text)
}

@(test)
test_cp_without_ccd_dir_ignores_files :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, base = SERVER_BASE)
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = "disable\n"
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect(t, !a.had_ccd)
}

@(test)
test_cp_disable :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "", peers_text(
		strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator),
		strings.concatenate({"bob ", pin_text(2), " disabled"}, context.temp_allocator),
	))
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/carol"] = "disable\n"
	_, rej, _ := cp_build(f, "carol")
	testing.expect_value(t, rej.reason, Reject_Reason.Client_Disabled)
	_, rej, _ = cp_build(f, "bob", digest_of(2), true)
	testing.expect_value(t, rej.reason, Reject_Reason.Client_Disabled)
	// Not pinned: the peers file is not consulted.
	a, rej2, _ := cp_build(f, "bob", digest_of(2), false)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	assignment_destroy(&a)
	a, rej2, _ = cp_build(f, "alice", digest_of(1), true)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	assignment_destroy(&a)
}

@(test)
test_cp_peers_entry_beats_ccd :: proc(t: ^testing.T) {
	peers := peers_text(
		strings.concatenate(
			{"alice ", pin_text(1), " ifconfig-push=10.8.0.9 iroute=192.168.7.0/24 iroute=192.168.5.0/24"},
			context.temp_allocator,
		),
	)
	f, ok := cp_fixture(t, "", peers)
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = "ifconfig-push 10.8.0.77 255.255.255.0\niroute 192.168.5.0 255.255.255.0\niroute 192.168.6.0 255.255.255.0\n"
	a, rej, _ := cp_build(f, "alice", digest_of(1), true)
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect_value(t, a.addr4, [4]u8{10, 8, 0, 9})
	// ccd and peers file iroutes together, repeats once: .5 (twice), .6, .7.
	testing.expect_value(t, len(a.iroutes4), 3)
	// The same client by name only (not pinned): the ccd address.
	pools_release(&f.pools, a.lease, 0)
	b, rej2, _ := cp_build(f, "alice")
	defer assignment_destroy(&b)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	testing.expect_value(t, b.addr4, [4]u8{10, 8, 0, 77})
	testing.expect_value(t, len(b.iroutes4), 2)
}

@(test)
test_cp_push_reset_keeps_the_tunnel_alive :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "push \"dhcp-option DNS 1.1.1.1\"\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = "push-reset\npush \"route 172.16.0.0 255.255.0.0\"\n"
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	// The server's route and dns lines are gone; ping stays; the ccd line is in.
	testing.expect(t, !push_has(&a, "route 10.9.0.0 255.255.255.0"))
	testing.expect(t, !push_has(&a, "dhcp-option DNS 1.1.1.1"))
	testing.expect(t, push_has(&a, "ping 10"))
	testing.expect(t, push_has(&a, "ping-restart 60"))
	testing.expect(t, push_has(&a, "route 172.16.0.0 255.255.0.0"))
	// The tunnel essentials do not depend on the list.
	pp := push.Push_Reply_Params{}
	assignment_push_params(&a, &pp)
	testing.expect(t, pp.ifconfig != nil)
	testing.expect(t, pp.route_gateway != nil)
	testing.expect_value(t, pp.topology, push.Topology.Subnet)
	id, has_id := pp.peer_id.?
	testing.expect(t, has_id && id == 7)
}

@(test)
test_cp_push_remove_is_substring :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "push \"dhcp-option DNS 1.1.1.1\"\npush \"route 10.20.0.0 255.255.0.0\"\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = "push-remove route\n"
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	for l in a.push {
		testing.expectf(t, !strings.contains(l, "route"), "line %q was not removed", l)
	}
	testing.expect(t, push_has(&a, "dhcp-option DNS 1.1.1.1"))
	testing.expect(t, push_has(&a, "ping 10"))
	// It also removes the ccd file's own lines.
	f.files["/ccd/bob"] = "push \"route 1.2.3.0 255.255.255.0\"\npush-remove 1.2.3\n"
	b, _, _ := cp_build(f, "bob")
	defer assignment_destroy(&b)
	testing.expect(t, !push_has(&b, "route 1.2.3.0 255.255.255.0"))
	testing.expect(t, push_has(&b, "route 10.9.0.0 255.255.255.0"))
}

@(test)
test_cp_structural_lines_are_dropped :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = `push "ifconfig 1.2.3.4 5.6.7.8"
push "topology subnet"
push "peer-id 99"
push "route-gateway 1.2.3.4"
push "ifconfig-ipv6 fd00::5/64 fd00::1"
push "tun-ipv6"
push "route 172.16.0.0 255.255.0.0"
`
	a, rej, detail := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expectf(t, rej.reason == .None, "%v %s", rej.reason, detail)
	for l in a.push {
		name := push_name(l)
		testing.expectf(t, !is_structural(name), "structural line %q is in the list", l)
	}
	testing.expect(t, push_has(&a, "route 172.16.0.0 255.255.0.0"))
}

@(test)
test_cp_unsendable_push_lines_are_dropped_with_a_note :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	// A comma cannot be in a PUSH_REPLY option. The config package may already
	// refuse it; then the client is refused with a config error, never sent a
	// broken reply.
	f.files["/ccd/alice"] = "push \"dhcp-option DOMAIN a,b\"\npush \"route 172.16.0.0 255.255.0.0\"\n"
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	if rej.reason == .None {
		for l in a.push {
			testing.expect(t, !strings.contains(l, ","))
		}
		testing.expect(t, len(a.notes) > 0)
	} else {
		testing.expect_value(t, rej.reason, Reject_Reason.Config_Error)
		testing.expect_value(t, pools_held(f), 0)
	}
}

@(test)
test_cp_ifconfig_push_notes :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = "ifconfig-push 10.8.0.20 255.255.255.252\n"
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect_value(t, a.addr4, [4]u8{10, 8, 0, 20})
	testing.expect_value(t, a.netmask4, [4]u8{255, 255, 255, 0}) // the server's
	testing.expect(t, len(a.notes) == 1 && strings.contains(a.notes[0], "netmask"))
}

@(test)
test_cp_bad_static_addresses :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	bad := [?]string{"10.8.0.1", "10.8.0.0", "10.8.0.255", "10.9.0.5", "192.168.1.1"}
	for addr in bad {
		f.files["/ccd/alice"] = fmt.tprintf("ifconfig-push %s 255.255.255.0\n", addr)
		_, rej, _ := cp_build(f, "alice")
		testing.expectf(t, rej.reason == .Bad_Static_Address, "%s: %v", addr, rej.reason)
		testing.expect_value(t, pools_held(f), 0)
	}
	// A host name in place of an address.
	f.files["/ccd/alice"] = "ifconfig-push alice.example 255.255.255.0\n"
	_, rej, detail := cp_build(f, "alice")
	testing.expect_value(t, rej.reason, Reject_Reason.Bad_Static_Address)
	testing.expect(t, detail != "")
	// Two clients, one address.
	f.files["/ccd/alice"] = "ifconfig-push 10.8.0.50 255.255.255.0\n"
	f.files["/ccd/bob"] = "ifconfig-push 10.8.0.50 255.255.255.0\n"
	a, rej2, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	_, rej2, _ = cp_build(f, "bob")
	testing.expect_value(t, rej2.reason, Reject_Reason.Address_In_Use)
	testing.expect_value(t, rej2.kind, Reject_Kind.Auth_Failed_Temp)
	testing.expect_value(t, pools_held(f), 1)
}

@(test)
test_cp_iroute_rules :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "server-ipv6 fd00:8::/64\nmax-routes-per-client 3\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	try :: proc(t: ^testing.T, f: ^CP_Fixture, ccd: string, want: Reject_Reason, loc := #caller_location) {
		f.files["/ccd/alice"] = ccd
		a, rej, detail := cp_build(f, "alice")
		testing.expectf(t, rej.reason == want, "%q: got %v want %v (%s)", ccd, rej.reason, want, detail, loc = loc)
		if rej.reason == .None {
			// Hand the lease back: the next try starts clean.
			pools_release(&f.pools, a.lease, 0)
			assignment_destroy(&a)
		} else {
			testing.expect_value(t, pools_held(f), 0, loc = loc)
		}
	}
	try(t, f, "iroute 192.168.5.0 255.255.255.0\n", .None)
	try(t, f, "iroute-ipv6 fd00:99::/48\n", .None)
	// Inside the server network, or containing it.
	try(t, f, "iroute 10.8.0.0 255.255.255.0\n", .Bad_Iroute)
	try(t, f, "iroute 10.8.0.128 255.255.255.128\n", .Bad_Iroute)
	try(t, f, "iroute 10.0.0.0 255.0.0.0\n", .Bad_Iroute)
	try(t, f, "iroute 0.0.0.0 0.0.0.0\n", .Bad_Iroute)
	try(t, f, "iroute 10.9.0.0 255.255.255.0\n", .None) // next to it: fine
	try(t, f, "iroute-ipv6 fd00:8::/64\n", .Bad_Iroute)
	try(t, f, "iroute-ipv6 fd00:8:0:0:5::/80\n", .Bad_Iroute)
	try(t, f, "iroute-ipv6 fd00::/16\n", .Bad_Iroute)
	// Count.
	try(t, f, "iroute 192.168.1.0 255.255.255.0\niroute 192.168.2.0 255.255.255.0\niroute-ipv6 fd00:99::/48\n", .None)
	try(t, f, "iroute 192.168.1.0 255.255.255.0\niroute 192.168.2.0 255.255.255.0\niroute 192.168.3.0 255.255.255.0\niroute 192.168.4.0 255.255.255.0\n", .Too_Many_Routes)
	// The same line twice is one route.
	try(t, f, "iroute 192.168.1.0 255.255.255.0\niroute 192.168.1.0 255.255.255.0\niroute 192.168.1.0 255.255.255.0\niroute 192.168.1.0 255.255.255.0\n", .None)
	// A larger limit in the file itself.
	try(t, f, "max-routes-per-client 5\niroute 192.168.1.0 255.255.255.0\niroute 192.168.2.0 255.255.255.0\niroute 192.168.3.0 255.255.255.0\niroute 192.168.4.0 255.255.255.0\n", .None)
}

@(test)
test_cp_nopool :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, base = "server 10.8.0.0 255.255.255.0 nopool\n" + CP_BASE[len("server 10.8.0.0 255.255.255.0\n"):])
	if !ok {
		return
	}
	defer cp_destroy(f)
	_, rej, detail := cp_build(f, "alice")
	testing.expect_value(t, rej.reason, Reject_Reason.Pool_Exhausted)
	testing.expect(t, strings.contains(detail, "nopool"))
	f.files["/ccd/alice"] = "ifconfig-push 10.8.0.30 255.255.255.0\n"
	a, rej2, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	testing.expect_value(t, a.addr4, [4]u8{10, 8, 0, 30})
}

@(test)
test_cp_pool_exhausted :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "ifconfig-pool 10.8.0.10 10.8.0.12\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	for i in 0 ..< 3 {
		a, rej, _ := cp_build(f, fmt.tprintf("c%d", i))
		testing.expect_value(t, rej.reason, Reject_Reason.None)
		defer assignment_destroy(&a)
		_ = a
	}
	_, rej, _ := cp_build(f, "c4")
	testing.expect_value(t, rej.reason, Reject_Reason.Pool_Exhausted)
	testing.expect_value(t, rej.kind, Reject_Kind.Auth_Failed_Temp)
}

@(test)
test_cp_ccd_errors :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	bad := [?]string {
		"iroute not-an-address 255.255.255.0\n",
		"unknown-directive 1\n",
		"ifconfig-push\n",
		"push \"unterminated\n",
		"remote 1.2.3.4\n", // a client option in a ccd file
		"iroute 192.168.5.0 255.255.255.0 extra extra\n",
	}
	for text in bad {
		f.files["/ccd/alice"] = text
		_, rej, detail := cp_build(f, "alice")
		testing.expectf(t, rej.reason == .Config_Error, "%q: %v", text, rej.reason)
		testing.expectf(t, detail != "", "%q: no detail", text)
		testing.expect_value(t, pools_held(f), 0)
	}
}

@(test)
test_cp_ccd_too_big_is_not_read :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t)
	if !ok {
		return
	}
	defer cp_destroy(f)
	big := strings.repeat("# padding padding padding padding\n", MAX_CCD_SIZE / 30 + 10, context.temp_allocator)
	f.files["/ccd/alice"] = big
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect(t, !a.had_ccd)
}

@(test)
test_cp_ipv6 :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect(t, a.has6)
	testing.expect_value(t, a.addr6, v6("fd00:8::2"))
	testing.expect_value(t, a.prefix6, u8(64))
	testing.expect_value(t, a.gateway6, v6("fd00:8::1"))
	// `tun-ipv6` goes first in the list.
	testing.expect(t, len(a.push) > 0 && a.push[0] == "tun-ipv6")

	// Static IPv6 from the ccd file, with a prefix length that is ignored.
	f.files["/ccd/bob"] = "ifconfig-ipv6-push fd00:8::99/112\n"
	b, rej2, _ := cp_build(f, "bob")
	defer assignment_destroy(&b)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	testing.expect_value(t, b.addr6, v6("fd00:8::99"))
	testing.expect_value(t, b.prefix6, u8(64))
	testing.expect(t, len(b.notes) == 1 && strings.contains(b.notes[0], "prefix"))
	// Outside the prefix: refused.
	f.files["/ccd/carol"] = "ifconfig-ipv6-push fd00:9::99/64\n"
	_, rej3, _ := cp_build(f, "carol")
	testing.expect_value(t, rej3.reason, Reject_Reason.Bad_Static_Address)
}

@(test)
test_cp_push_params_to_reply :: proc(t: ^testing.T) {
	f, ok := cp_fixture(t, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	f.files["/ccd/alice"] = "push \"dhcp-option DOMAIN example.com\"\n"
	a, rej, _ := cp_build(f, "alice")
	defer assignment_destroy(&a)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	p: push.Push_Reply_Params
	assignment_push_params(&a, &p)
	msgs, err := push.push_reply_build(&p)
	defer push.push_messages_destroy(msgs)
	testing.expect_value(t, err, push.Error.None)
	all := strings.join(msgs[:], ",", context.temp_allocator)
	for want in ([]string{
		"ifconfig 10.8.0.2 255.255.255.0",
		"route-gateway 10.8.0.1",
		"topology subnet",
		"peer-id 7",
		"ifconfig-ipv6 fd00:8::2/64 fd00:8::1",
		"tun-ipv6",
		"ping 10",
		"ping-restart 60",
		"route 10.9.0.0 255.255.255.0",
		"dhcp-option DOMAIN example.com",
	}) {
		testing.expectf(t, strings.contains(all, want), "%q is not in the reply: %s", want, all)
	}
	// Each of ping and ping-restart once.
	testing.expect_value(t, strings.count(all, "ping 10"), 1)
	testing.expect_value(t, strings.count(all, "ping-restart 60"), 1)
	testing.expect_value(t, strings.count(all, "peer-id"), 1)
}

@(test)
test_cp_failures_hold_nothing :: proc(t: ^testing.T) {
	// Every refusal leaves the pools as they were; sticky memory of a name that
	// was refused is not created either.
	f, ok := cp_fixture(t, "server-ipv6 fd00:8::/64\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	ccds := [?]string {
		"disable\n",
		"iroute 10.8.0.0 255.255.255.0\n",
		"ifconfig-push 10.8.0.1 255.255.255.0\n",
		"ifconfig-ipv6-push fd00:9::1/64\n",
		"bogus\n",
		"ifconfig-push 10.8.0.5 255.255.255.0\nifconfig-ipv6-push fd00:9::1/64\n",
	}
	for c in ccds {
		f.files["/ccd/alice"] = c
		_, rej, _ := cp_build(f, "alice")
		testing.expectf(t, rej.reason != .None, "%q was accepted", c)
		testing.expect_value(t, pools_held(f), 0)
		testing.expect_value(t, pool_remembered(&f.pools.v4), 0)
		testing.expect_value(t, pool_remembered(&f.pools.v6), 0)
	}
}

// Random ccd files from a set of lines: whatever the combination, the result
// is either a clean refusal that holds nothing, or an assignment that obeys the
// rules (no structural line, no comma, nothing removed that was asked to go,
// ping kept, essentials present).
@(test)
test_cp_random_ccd_combinations :: proc(t: ^testing.T) {
	lines := [?]string {
		"push-reset",
		"push-remove route",
		"push-remove DNS",
		"push \"dhcp-option DNS 9.9.9.9\"",
		"push \"route 172.16.0.0 255.255.0.0\"",
		"push \"topology subnet\"",
		"push \"ifconfig 1.1.1.1 2.2.2.2\"",
		"push \"ping 99\"",
		"push \"peer-id 3\"",
		"iroute 192.168.5.0 255.255.255.0",
		"iroute 192.168.6.0 255.255.255.0",
		"iroute 10.8.0.0 255.255.255.0",
		"iroute-ipv6 fd00:99::/48",
		"ifconfig-push 10.8.0.50 255.255.255.0",
		"ifconfig-push 10.8.0.1 255.255.255.0",
		"ifconfig-ipv6-push fd00:8::50/64",
		"session-timeout 120",
		"max-routes-per-client 2",
		"disable",
	}
	f, ok := cp_fixture(t, "server-ipv6 fd00:8::/64\npush \"dhcp-option DNS 1.1.1.1\"\n")
	if !ok {
		return
	}
	defer cp_destroy(f)
	r := rng_make(2024)
	for _ in 0 ..< 600 {
		sb := strings.builder_make(context.temp_allocator)
		has := [len(lines)]bool{}
		last_static := -1 // the last ifconfig-push line wins
		for _ in 0 ..< rng_below(&r, 6) {
			i := rng_below(&r, len(lines))
			has[i] = true
			if i == 13 || i == 14 {
				last_static = i
			}
			strings.write_string(&sb, lines[i])
			strings.write_byte(&sb, '\n')
		}
		f.files["/ccd/alice"] = strings.to_string(sb)
		a, rej, _ := cp_build(f, "alice")
		if rej.reason != .None {
			testing.expect_value(t, pools_held(f), 0)
			// The reasons that can come from a ccd file.
			allowed := rej.reason == .Client_Disabled || rej.reason == .Bad_Iroute || rej.reason == .Bad_Static_Address || rej.reason == .Too_Many_Routes
			testing.expectf(t, allowed, "%q: %v", strings.to_string(sb), rej.reason)
			continue
		}
		testing.expect(t, !has[18]) // `disable`
		testing.expect(t, !has[11]) // bad iroute
		testing.expect(t, last_static != 14) // bad static address
		for l, i in a.push {
			// The first line is the `tun-ipv6` that the assignment adds itself.
			testing.expect(t, i == 0 || !is_structural(push_name(l)))
			testing.expect(t, !strings.contains(l, ","))
		}
		testing.expect(t, push_has(&a, "ping 10"))
		testing.expect(t, push_has(&a, "ping-restart 60"))
		if has[1] {
			for l in a.push {
				testing.expect(t, !strings.contains(l, "route"))
			}
		}
		if has[2] {
			for l in a.push {
				testing.expect(t, !strings.contains(l, "DNS"))
			}
		}
		if has[0] {
			// push-reset: the server's DNS line is gone.
			testing.expect(t, !push_has(&a, "dhcp-option DNS 1.1.1.1"))
			testing.expect(t, !push_has(&a, "route 10.9.0.0 255.255.255.0"))
		}
		testing.expect(t, a.has4 && a.has6)
		testing.expect_value(t, len(a.push) > 0 && a.push[0] == "tun-ipv6", true)
		pools_release(&f.pools, a.lease, 0)
		assignment_destroy(&a)
	}
	testing.expect_value(t, pools_held(f), 0)
}
