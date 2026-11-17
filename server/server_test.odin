// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:proto/config"

// End-to-end flows through `Server`, the way the daemon calls it.

Srv_Fixture :: struct {
	cfg:   config.Config,
	srv:   Server,
	files: Mem_Files,
}

SRV_BASE :: PINNED_BASE + "server-ipv6 fd00:8::/64\nclient-config-dir /ccd\n"

// Users: alice 1 and 2 (two devices), bob 3, carol 4 (disabled), dave 5
// (static address and an iroute), erin 6..: plain.
srv_peers :: proc() -> string {
	return peers_text(
		strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator),
		strings.concatenate({"alice ", pin_text(2)}, context.temp_allocator),
		strings.concatenate({"bob ", pin_text(3)}, context.temp_allocator),
		strings.concatenate({"carol ", pin_text(4), " disabled"}, context.temp_allocator),
		strings.concatenate(
			{"dave ", pin_text(5), " ifconfig-push=10.8.0.9 iroute=192.168.50.0/24 iroute-ipv6=fd00:50::/48"},
			context.temp_allocator,
		),
		strings.concatenate({"erin ", pin_text(6)}, context.temp_allocator),
		strings.concatenate({"frank ", pin_text(7)}, context.temp_allocator),
		strings.concatenate({"gina ", pin_text(8)}, context.temp_allocator),
		// hank: two keys that name the same network.
		strings.concatenate({"hank ", pin_text(9), " iroute=192.168.60.0/24"}, context.temp_allocator),
		strings.concatenate({"hank ", pin_text(10), " iroute=192.168.60.0/24"}, context.temp_allocator),
		// ivy: two keys with an address each; own networks.
		strings.concatenate({"ivy ", pin_text(11), " ifconfig-push=10.8.0.41 iroute=192.168.61.0/24"}, context.temp_allocator),
		strings.concatenate({"ivy ", pin_text(12), " ifconfig-push=10.8.0.42 iroute=192.168.62.0/24"}, context.temp_allocator),
		// jan: two keys; the file client-config-dir/jan gives the name an address.
		strings.concatenate({"jan ", pin_text(13)}, context.temp_allocator),
		strings.concatenate({"jan ", pin_text(14)}, context.temp_allocator),
	)
}

srv_fixture :: proc(t: ^testing.T, extra := "", base := SRV_BASE, params := Server_Params{}) -> (f: ^Srv_Fixture, ok: bool) {
	f = new(Srv_Fixture)
	f.cfg, ok = make_cfg(t, base, extra)
	if !ok {
		free(f)
		return nil, false
	}
	f.files = make(Mem_Files)
	p := params
	p.loader = mem_loader
	p.loader_data = &f.files
	p.hash_seed = 0x1234
	testing.expect(t, server_init(&f.srv, &f.cfg.server, make_pins(t, srv_peers()), p))
	return f, true
}

srv_destroy :: proc(f: ^Srv_Fixture) {
	server_destroy(&f.srv)
	delete(f.files)
	config.destroy(&f.cfg)
	free(f)
}

Joined :: struct {
	a:  Assignment,
	h:  Peer_Handle,
	ok: bool,
	// Set when it was refused.
	rej: Reject,
}

// authorize, kick, connect.
srv_join :: proc(t: ^testing.T, f: ^Srv_Fixture, key: u64, now: time.Duration, src := -1) -> (j: Joined) {
	s := src if src >= 0 else int(key)
	d := server_authorize(&f.srv, Auth_Input{key = peer_key(key), has_key = true, proof = .Chain, src = tkey(s)}, now)
	if d.kind != .Accept {
		j.rej = d.reject
		return
	}
	for i in 0 ..< d.n_kicks {
		testing.expect(t, server_disconnect(&f.srv, d.kicks[i], now))
	}
	rej: Reject
	j.a, j.h, rej, _ = server_connect(&f.srv, &d, tkey(s), key, now)
	j.rej = rej
	j.ok = rej.reason == .None
	return
}

srv_leave :: proc(t: ^testing.T, f: ^Srv_Fixture, j: ^Joined, now: time.Duration) {
	testing.expect(t, server_disconnect(&f.srv, j.h, now))
	assignment_destroy(&j.a)
	j^ = {}
}

@(test)
test_server_connect_disconnect :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	j := srv_join(t, f, 1, 0)
	testing.expect(t, j.ok)
	testing.expect_value(t, j.a.addr4, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, j.a.addr6, v6("fd00:8::2"))
	testing.expect_value(t, j.a.peer_id, j.h.index)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 1)

	// Lookups.
	k := tkey(1)
	h, p := peers_by_addr(&f.srv.reg.peers, &k)
	testing.expect(t, p != nil && h == j.h)
	h, p = peers_by_id(&f.srv.reg.peers, j.a.peer_id)
	testing.expect(t, p != nil && p.user == 1)
	testing.expect_value(t, p.identity, "alice")

	// Data path.
	dest, v := registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, {10, 8, 0, 2}))
	testing.expect(t, v == .To_Peer && dest == j.h)
	_, v = registry_from_peer(&f.srv.reg, j.h, ip4_packet({10, 8, 0, 2}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.To_Tun)
	_, v = registry_from_peer(&f.srv.reg, j.h, ip6_packet(v6("fd00:8::2"), v6("2001:db8::1")))
	testing.expect_value(t, v, Verdict.To_Tun)

	old_id := j.a.peer_id
	old_h := j.h
	srv_leave(t, f, &j, 1 * SEC)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 0)
	_, p = peers_by_id(&f.srv.reg.peers, old_id)
	testing.expect(t, p == nil)
	_, p = peers_by_addr(&f.srv.reg.peers, &k)
	testing.expect(t, p == nil)
	_, v = registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, {10, 8, 0, 2}))
	testing.expect_value(t, v, Verdict.Drop_No_Route)
	// A second disconnect of the same handle does nothing.
	testing.expect(t, !server_disconnect(&f.srv, old_h, 2 * SEC))

	// The next client does not get the old peer-id (it waits its delay).
	j2 := srv_join(t, f, 3, 2 * SEC)
	testing.expect(t, j2.ok)
	testing.expect(t, j2.a.peer_id != old_id)
	srv_leave(t, f, &j2, 3 * SEC)
}

@(test)
test_server_sticky_reconnect :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 1, 0)
	b := srv_join(t, f, 3, 0)
	testing.expect_value(t, a.a.addr4, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, b.a.addr4, [4]u8{10, 8, 0, 3})
	srv_leave(t, f, &a, 5 * SEC)
	c := srv_join(t, f, 6, 6 * SEC)
	testing.expect_value(t, c.a.addr4, [4]u8{10, 8, 0, 4}) // not alice's .2
	a2 := srv_join(t, f, 1, 7 * SEC)
	testing.expect_value(t, a2.a.addr4, [4]u8{10, 8, 0, 2}) // alice gets hers back
	testing.expect_value(t, a2.a.addr6, v6("fd00:8::2"))
	srv_leave(t, f, &a2, 8 * SEC)
	srv_leave(t, f, &b, 8 * SEC)
	srv_leave(t, f, &c, 8 * SEC)
}

@(test)
test_server_same_key_replaces_first :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a1 := srv_join(t, f, 1, 0)
	testing.expect(t, a1.ok)
	// The same key connects again: the first session is kicked, and the new
	// one takes over the same addresses.
	d := server_authorize(&f.srv, Auth_Input{key = peer_key(1), has_key = true, proof = .Chain, src = tkey(2)}, 1 * SEC)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], a1.h)
	testing.expect(t, server_disconnect(&f.srv, d.kicks[0], 1 * SEC))
	assignment_destroy(&a1.a)
	a2, h2, rej, _ := server_connect(&f.srv, &d, tkey(2), 2, 1 * SEC)
	defer assignment_destroy(&a2)
	testing.expect_value(t, rej.reason, Reject_Reason.None)
	testing.expect_value(t, a2.addr4, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 1)
	// The old handle is dead; the old transport address is gone.
	k := tkey(1)
	_, p := peers_by_addr(&f.srv.reg.peers, &k)
	testing.expect(t, p == nil)
	testing.expect(t, peers_get(&f.srv.reg.peers, a1.h) == nil)
	testing.expect(t, peers_get(&f.srv.reg.peers, h2) != nil)
	testing.expect(t, server_disconnect(&f.srv, h2, 2 * SEC))
}

@(test)
test_server_second_key_of_a_name_runs_beside_first :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a1 := srv_join(t, f, 1, 0)
	a2 := srv_join(t, f, 2, 1 * SEC)
	testing.expect(t, a1.ok && a2.ok)
	testing.expect(t, a1.a.addr4 != a2.a.addr4)
	testing.expect(t, a1.a.addr6 != a2.a.addr6)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 2)
	// Each key reconnecting replaces only its own session.
	d := server_authorize(&f.srv, Auth_Input{key = peer_key(2), has_key = true, proof = .Chain, src = tkey(9)}, 2 * SEC)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], a2.h)
	srv_leave(t, f, &a1, 3 * SEC)
	srv_leave(t, f, &a2, 3 * SEC)
}

@(test)
test_server_duplicate_cn :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t, "duplicate-cn\n")
	if !ok {
		return
	}
	defer srv_destroy(f)
	a1 := srv_join(t, f, 1, 0)
	a2 := srv_join(t, f, 2, 0)
	testing.expect(t, a1.ok && a2.ok)
	testing.expect(t, a1.a.addr4 != a2.a.addr4)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 2)
	// Same key twice: also allowed.
	a3 := srv_join(t, f, 1, 0, 100)
	testing.expect(t, a3.ok)
	srv_leave(t, f, &a1, 1 * SEC)
	srv_leave(t, f, &a2, 1 * SEC)
	srv_leave(t, f, &a3, 1 * SEC)
}

@(test)
test_server_max_clients :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t, "max-clients 5\n")
	if !ok {
		return
	}
	defer srv_destroy(f)
	js: [5]Joined
	keys := [?]u64{1, 3, 5, 6, 7}
	for k, i in keys {
		js[i] = srv_join(t, f, k, 0)
		testing.expectf(t, js[i].ok, "client %d", k)
	}
	// The server is full: gina does not fit.
	g := srv_join(t, f, 8, 0)
	testing.expect(t, !g.ok)
	testing.expect_value(t, g.rej.reason, Reject_Reason.Max_Clients)
	// alice's key reconnects and replaces her first session, so it fits.
	extra := srv_join(t, f, 1, 0, 20)
	testing.expect(t, extra.ok)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 5)
	assignment_destroy(&js[0].a)
	js[0] = extra
	// Free one place, and gina gets in.
	srv_leave(t, f, &js[1], 1 * SEC)
	g = srv_join(t, f, 8, 1 * SEC)
	testing.expect(t, g.ok)
	srv_leave(t, f, &g, 2 * SEC)
	for &j in js {
		if j.ok {
			srv_leave(t, f, &j, 2 * SEC)
		}
	}
}

@(test)
test_server_max_clients_refuses_new_identity :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t, "max-clients 2\n")
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 1, 0)
	b := srv_join(t, f, 3, 0)
	c := srv_join(t, f, 6, 0)
	testing.expect(t, a.ok && b.ok && !c.ok)
	testing.expect_value(t, c.rej.reason, Reject_Reason.Max_Clients)
	testing.expect_value(t, c.rej.kind, Reject_Kind.Auth_Failed_Temp)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 2)
	srv_leave(t, f, &a, 1 * SEC)
	srv_leave(t, f, &b, 1 * SEC)
}

@(test)
test_server_static_address_is_kept_for_its_owner :: proc(t: ^testing.T) {
	// dave's 10.8.0.9 is in the dynamic range. Dynamic clients skip it even
	// before dave has ever connected.
	f, ok := srv_fixture(t, "ifconfig-pool 10.8.0.5 10.8.0.12\n")
	if !ok {
		return
	}
	defer srv_destroy(f)
	js := make([dynamic]Joined, context.temp_allocator)
	// Five clients, taking .5 to .8 and then .10 (not .9).
	for k in ([?]u64{1, 3, 6, 7, 8}) {
		j := srv_join(t, f, k, 0)
		testing.expect(t, j.ok)
		testing.expect(t, j.a.addr4 != [4]u8{10, 8, 0, 9})
		append(&js, j)
	}
	d := srv_join(t, f, 5, 0)
	testing.expect(t, d.ok)
	testing.expect_value(t, d.a.addr4, [4]u8{10, 8, 0, 9})
	testing.expect_value(t, len(d.a.iroutes4), 1)
	testing.expect_value(t, len(d.a.iroutes6), 1)
	// Traffic to dave's network goes to him.
	dest, v := registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, {192, 168, 50, 7}))
	testing.expect(t, v == .To_Peer && dest == d.h)
	dest, v = registry_from_tun(&f.srv.reg, ip6_packet(v6("2001:db8::1"), v6("fd00:50:0:1::5")))
	testing.expect(t, v == .To_Peer && dest == d.h)
	// And he may send from it.
	_, v = registry_from_peer(&f.srv.reg, d.h, ip4_packet({192, 168, 50, 99}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.To_Tun)
	// Nobody else may.
	_, v = registry_from_peer(&f.srv.reg, js[0].h, ip4_packet({192, 168, 50, 99}, {8, 8, 8, 8}))
	testing.expect_value(t, v, Verdict.Drop_Bad_Source)
	srv_leave(t, f, &d, 1 * SEC)
	// The route is gone with him.
	_, v = registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, {192, 168, 50, 7}))
	testing.expect_value(t, v, Verdict.Drop_No_Route)
	for &j in js {
		srv_leave(t, f, &j, 1 * SEC)
	}
}

@(test)
test_server_refused_connects_hold_nothing :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	f.files["/ccd/bob"] = "disable\n"
	f.files["/ccd/erin"] = "iroute 10.8.0.0 255.255.255.0\n"
	f.files["/ccd/frank"] = "bogus-option\n"
	j := srv_join(t, f, 3, 0)
	testing.expect_value(t, j.rej.reason, Reject_Reason.Client_Disabled)
	j = srv_join(t, f, 6, 0)
	testing.expect_value(t, j.rej.reason, Reject_Reason.Bad_Iroute)
	j = srv_join(t, f, 7, 0)
	testing.expect_value(t, j.rej.reason, Reject_Reason.Config_Error)
	j = srv_join(t, f, 4, 0) // carol: disabled in the peers file
	testing.expect_value(t, j.rej.reason, Reject_Reason.Key_Disabled)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 0)
	testing.expect_value(t, pool_used(&f.srv.pools.v4), 0)
	testing.expect_value(t, pool_used(&f.srv.pools.v6), 0)
	testing.expect_value(t, route_count4(&f.srv.reg.routes), 0)
	testing.expect_value(t, route_count6(&f.srv.reg.routes), 0)
	// An accepted decision handed to `server_connect` twice is not a way to
	// get two peers: the second call after a refusal and a decision that
	// is not Accept both fail.
	d := Decision{}
	_, _, rej, _ := server_connect(&f.srv, &d, tkey(1), 0, 0)
	testing.expect_value(t, rej.reason, Reject_Reason.Internal)
}

@(test)
test_server_same_transport_address_is_refused :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 1, 0)
	// bob arrives from alice's address: one transport address, one peer.
	b := srv_join(t, f, 3, 0, 1)
	testing.expect(t, !b.ok)
	testing.expect_value(t, b.rej.reason, Reject_Reason.Route_Conflict)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 1)
	testing.expect_value(t, pool_used(&f.srv.pools.v4), 1)
	srv_leave(t, f, &a, 1 * SEC)
}

@(test)
test_server_float :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 1, 0)
	b := srv_join(t, f, 3, 0)
	old, err := server_float(&f.srv, a.h, tkey(500))
	testing.expect_value(t, err, Peer_Error.None)
	testing.expect(t, old == tkey(1))
	k_old, k_new := tkey(1), tkey(500)
	_, p := peers_by_addr(&f.srv.reg.peers, &k_old)
	testing.expect(t, p == nil)
	h, p2 := peers_by_addr(&f.srv.reg.peers, &k_new)
	testing.expect(t, p2 != nil && h == a.h)
	// Floating onto another peer's address fails and changes nothing.
	k_b := tkey(3)
	_, err = server_float(&f.srv, a.h, k_b)
	testing.expect_value(t, err, Peer_Error.Addr_In_Use)
	h, p2 = peers_by_addr(&f.srv.reg.peers, &k_new)
	testing.expect(t, p2 != nil && h == a.h)
	// Routes are as before.
	dest, v := registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, {10, 8, 0, 2}))
	testing.expect(t, v == .To_Peer && dest == a.h)
	// A dead handle cannot float.
	dead := a.h
	srv_leave(t, f, &a, 1 * SEC)
	_, err = server_float(&f.srv, dead, tkey(600))
	testing.expect_value(t, err, Peer_Error.Bad_Handle)
	srv_leave(t, f, &b, 1 * SEC)
}

@(test)
test_server_client_to_client :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t, "client-to-client\n")
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 1, 0)
	d := srv_join(t, f, 5, 0)
	dest, v := registry_from_peer(&f.srv.reg, a.h, ip4_packet({10, 8, 0, 2}, {10, 8, 0, 9}))
	testing.expect(t, v == .To_Peer && dest == d.h)
	dest, v = registry_from_peer(&f.srv.reg, a.h, ip4_packet({10, 8, 0, 2}, {192, 168, 50, 4}))
	testing.expect(t, v == .To_Peer && dest == d.h)
	dest, v = registry_from_peer(&f.srv.reg, d.h, ip6_packet(v6("fd00:50::9"), v6("fd00:8::2")))
	testing.expect(t, v == .To_Peer && dest == a.h)
	srv_leave(t, f, &a, 1 * SEC)
	_, v = registry_from_peer(&f.srv.reg, d.h, ip4_packet({10, 8, 0, 9}, {10, 8, 0, 2}))
	testing.expect_value(t, v, Verdict.To_Tun) // alice is gone: nobody owns it
	srv_leave(t, f, &d, 1 * SEC)
}

@(test)
test_server_external_auth :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t, "auth-external 5\n")
	if !ok {
		return
	}
	defer srv_destroy(f)
	in_ := Auth_Input{key = peer_key(3), has_key = true, proof = .Chain, src = tkey(3)}
	d := server_authorize(&f.srv, in_, 0)
	testing.expect_value(t, d.kind, Decision_Kind.Pending_External)
	// Not accepted yet: server_connect refuses it.
	_, _, rej, _ := server_connect(&f.srv, &d, tkey(3), 3, 0)
	testing.expect_value(t, rej.reason, Reject_Reason.Internal)
	d = server_resume(&f.srv, d)
	testing.expect_value(t, d.kind, Decision_Kind.Accept)
	a, h, rej2, _ := server_connect(&f.srv, &d, tkey(3), 3, 0)
	testing.expect_value(t, rej2.reason, Reject_Reason.None)
	assignment_destroy(&a)
	testing.expect(t, server_disconnect(&f.srv, h, 1 * SEC))
	// A denial and a timeout.
	r := server_deny_external(&f.srv, false)
	testing.expect_value(t, r.reason, Reject_Reason.External_Denied)
	testing.expect_value(t, r.kind, Reject_Kind.Auth_Failed)
	r = server_deny_external(&f.srv, true)
	testing.expect_value(t, r.reason, Reject_Reason.External_Timeout)
	testing.expect_value(t, r.kind, Reject_Kind.Auth_Failed_Temp)
	testing.expect_value(t, f.srv.auth.stats.rejected[.External_Denied], u64(1))
}

@(test)
test_server_reload_kicks_and_reserves :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 1, 0)
	b := srv_join(t, f, 3, 0)
	e := srv_join(t, f, 6, 0)
	d := srv_join(t, f, 5, 0)
	testing.expect(t, a.ok && b.ok && e.ok && d.ok)

	// New file: bob removed; erin disabled; dave renamed; alice unchanged with
	// a static address given to her (10.8.0.30: a reservation, no kick).
	new_text := peers_text(
		strings.concatenate({"alice ", pin_text(1), " ifconfig-push=10.8.0.30"}, context.temp_allocator),
		strings.concatenate({"erin ", pin_text(6), " disabled"}, context.temp_allocator),
		strings.concatenate({"davina ", pin_text(5), " ifconfig-push=10.8.0.9"}, context.temp_allocator),
		strings.concatenate({"zed ", pin_text(20)}, context.temp_allocator),
	)
	t2 := make_pins(t, new_text)
	r := server_reload_peers(&f.srv, t2)
	defer reload_result_destroy(&r)
	testing.expect_value(t, len(r.kicks), 3)
	killed := make(map[u32]Kick_Reason, context.temp_allocator)
	for k in r.kicks {
		killed[k.handle.index] = k.reason
	}
	testing.expect_value(t, killed[b.h.index], Kick_Reason.Key_Removed)
	testing.expect_value(t, killed[e.h.index], Kick_Reason.Key_Disabled)
	testing.expect_value(t, killed[d.h.index], Kick_Reason.Identity_Changed)
	for k in r.kicks {
		testing.expect(t, server_disconnect(&f.srv, k.handle, 5 * SEC))
	}
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 1)
	assignment_destroy(&b.a)
	assignment_destroy(&e.a)
	assignment_destroy(&d.a)
	testing.expect(t, len(r.changes) >= 4)

	// New decisions use the new file.
	j := srv_join(t, f, 3, 6 * SEC)
	testing.expect_value(t, j.rej.reason, Reject_Reason.Key_Not_Pinned)
	j = srv_join(t, f, 6, 6 * SEC)
	testing.expect_value(t, j.rej.reason, Reject_Reason.Key_Disabled)
	z := srv_join(t, f, 20, 6 * SEC)
	testing.expect(t, z.ok)
	// 10.8.0.30 is alice's: a dynamic client does not get it (it is far from
	// where the pool starts, so check the reservation flag directly).
	slot, in_range := pool_slot_of(&f.srv.pools.v4, u128(config.ipv4_to_u32([4]u8{10, 8, 0, 30})))
	testing.expect(t, in_range)
	testing.expect(t, .Reserved_Pin in f.srv.pools.v4.slots[slot].flags)
	srv_leave(t, f, &z, 7 * SEC)
	srv_leave(t, f, &a, 7 * SEC)
}

@(test)
test_server_reload_drops_reservations :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	slot, _ := pool_slot_of(&f.srv.pools.v4, u128(config.ipv4_to_u32([4]u8{10, 8, 0, 9})))
	testing.expect(t, .Reserved_Pin in f.srv.pools.v4.slots[slot].flags)
	t2 := make_pins(t, strings.concatenate({"alice ", pin_text(1), "\n"}, context.temp_allocator))
	r := server_reload_peers(&f.srv, t2)
	defer reload_result_destroy(&r)
	testing.expect(t, .Reserved_Pin not_in f.srv.pools.v4.slots[slot].flags)
	testing.expect_value(t, len(r.kicks), 0)
}

@(test)
test_server_id_exhaustion :: proc(t: ^testing.T) {
	// max-clients 2, 2 spare ids, a long reuse delay: churn uses up the ids.
	f, ok := srv_fixture(t, "max-clients 2\n", params = Server_Params{id_headroom = 2, id_reuse_delay = 100 * SEC})
	if !ok {
		return
	}
	defer srv_destroy(f)
	seen := 0
	for i in 0 ..< 10 {
		j := srv_join(t, f, 1, time.Duration(i) * SEC)
		if !j.ok {
			testing.expect_value(t, j.rej.reason, Reject_Reason.Id_Exhausted)
			testing.expect_value(t, j.rej.kind, Reject_Kind.Auth_Failed_Temp)
			break
		}
		seen += 1
		srv_leave(t, f, &j, time.Duration(i) * SEC)
	}
	testing.expect_value(t, seen, 4) // 2 + 2 ids
	// After the delay it works again.
	j := srv_join(t, f, 1, 200 * SEC)
	testing.expect(t, j.ok)
	srv_leave(t, f, &j, 201 * SEC)
	testing.expect_value(t, pool_used(&f.srv.pools.v4), 0)
}

@(test)
test_server_connect_freq :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t, "connect-freq 2 10\nduplicate-cn\n")
	if !ok {
		return
	}
	defer srv_destroy(f)
	src := addr_key_v4({203, 0, 113, 5}, 1000)
	in_ := Auth_Input{key = peer_key(1), has_key = true, proof = .Chain, src = src}
	d1 := server_authorize(&f.srv, in_, 0)
	d2 := server_authorize(&f.srv, in_, 0)
	d3 := server_authorize(&f.srv, in_, 0)
	testing.expect_value(t, d1.kind, Decision_Kind.Accept)
	testing.expect_value(t, d2.kind, Decision_Kind.Accept)
	testing.expect_value(t, d3.reject.reason, Reject_Reason.Rate_Limited)
	testing.expect_value(t, f.srv.auth.stats.rejected[.Rate_Limited], u64(1))
}

Live :: struct {
	j:    Joined,
	key:  u64,
	name: string,
}

// Drops model entries whose session the server has removed (kicks).
prune :: proc(f: ^Srv_Fixture, live: ^[dynamic]Live) {
	for i := len(live) - 1; i >= 0; i -= 1 {
		if peers_get(&f.srv.reg.peers, live[i].j.h) == nil {
			assignment_destroy(&live[i].j.a)
			unordered_remove(live, i)
		}
	}
}

// Random joins, leaves, floats and reloads. After every step the tables agree
// with a plain model, and at the end everything is released.
@(test)
test_server_random_churn :: proc(t: ^testing.T) {
	for seed in u64(1) ..= 4 {
		r := rng_make(seed + 500)
		f, ok := srv_fixture(t, "max-clients 5\nifconfig-pool 10.8.0.2 10.8.0.8\n")
		if !ok {
			return
		}
		defer srv_destroy(f)
		live := make([dynamic]Live, context.temp_allocator)
		now := time.Duration(0)
		float_n := 1000
		for step in 0 ..< 1500 {
			now += time.Duration(rng_below(&r, 700)) * time.Millisecond
			switch rng_below(&r, 8) {
			case 0, 1, 2:
				key := u64(1 + rng_below(&r, 8))
				// A key already live with a different src: server_join uses key as src.
				already := false
				for l in live {
					already ||= l.key == key
				}
				if already {
					break
				}
				j := srv_join(t, f, key, now)
				if j.ok {
					append(&live, Live{j, key, identity_of(key)})
				} else {
					testing.expectf(t, j.rej.reason != .None, "no reason")
				}
				// Kicked sessions of the same identity are gone from the server.
				prune(f, &live)
			case 3, 4:
				if len(live) == 0 {
					break
				}
				i := rng_below(&r, len(live))
				srv_leave(t, f, &live[i].j, now)
				unordered_remove(&live, i)
			case 5:
				if len(live) == 0 {
					break
				}
				i := rng_below(&r, len(live))
				float_n += 1
				_, err := server_float(&f.srv, live[i].j.h, tkey(float_n))
				testing.expect_value(t, err, Peer_Error.None)
			case 6:
				// Reload with a random subset of the keys, some disabled.
				sb := strings.builder_make(context.temp_allocator)
				for k in 1 ..= 8 {
					if k == 4 {
						continue
					}
					if rng_below(&r, 4) == 0 {
						continue
					}
					dis := " disabled" if rng_below(&r, 6) == 0 else ""
					fmt.sbprintf(&sb, "%s %s%s\n", identity_of(u64(k)), pin_text(u64(k)), dis)
				}
				nt := make_pins(t, strings.to_string(sb))
				rr := server_reload_peers(&f.srv, nt)
				for k in rr.kicks {
					testing.expect(t, server_disconnect(&f.srv, k.handle, now))
				}
				reload_result_destroy(&rr)
				prune(f, &live)
			case 7:
				// Packets: from the tun to each live client's address.
				for l in live {
					dest, v := registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, l.j.a.addr4))
					testing.expect(t, v == .To_Peer && dest == l.j.h)
				}
			}
			if step % 10 == 0 {
				testing.expect_value(t, peers_count(&f.srv.reg.peers), len(live))
				// dave's address is outside the pool range: counted in `static4`.
				testing.expect_value(t, pool_used(&f.srv.pools.v4) + len(f.srv.pools.static4), len(live))
				testing.expect_value(t, pool_used(&f.srv.pools.v6), len(live))
				// One /32 and one /128 for each (dave's iroutes aside).
				n4, n6 := len(live), len(live)
				for l in live {
					n4 += len(l.j.a.iroutes4)
					n6 += len(l.j.a.iroutes6)
				}
				testing.expect_value(t, route_count4(&f.srv.reg.routes), n4)
				testing.expect_value(t, route_count6(&f.srv.reg.routes), n6)
				// No two live clients share an address.
				seen := make(map[[4]u8]bool, context.temp_allocator)
				for l in live {
					testing.expect(t, l.j.a.addr4 not_in seen)
					seen[l.j.a.addr4] = true
				}
			}
		}
		for &l in live {
			srv_leave(t, f, &l.j, now)
		}
		testing.expect_value(t, peers_count(&f.srv.reg.peers), 0)
		testing.expect_value(t, pool_used(&f.srv.pools.v4), 0)
		testing.expect_value(t, route_count4(&f.srv.reg.routes), 0)
		testing.expect_value(t, route_count6(&f.srv.reg.routes), 0)
		testing.expect_value(t, len(f.srv.pools.static4), 0)
	}
}

identity_of :: proc(key: u64) -> string {
	switch key {
	case 1, 2:
		return "alice"
	case 3:
		return "bob"
	case 4:
		return "carol"
	case 5:
		return "dave"
	case 6:
		return "erin"
	case 7:
		return "frank"
	}
	return "gina"
}

@(test)
test_server_two_keys_same_iroute_second_refused :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 9, 0)
	testing.expect(t, a.ok)
	b := srv_join(t, f, 10, 0)
	testing.expect(t, !b.ok)
	testing.expect_value(t, b.rej.reason, Reject_Reason.Route_Conflict)
	// The first session is not touched.
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 1)
	srv_leave(t, f, &a, 1 * SEC)
}

@(test)
test_server_two_keys_each_with_own_address_and_iroute :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 11, 0)
	b := srv_join(t, f, 12, 0)
	testing.expect(t, a.ok && b.ok)
	testing.expect_value(t, a.a.addr4, [4]u8{10, 8, 0, 41})
	testing.expect_value(t, b.a.addr4, [4]u8{10, 8, 0, 42})
	dest, v := registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, {192, 168, 62, 5}))
	testing.expect(t, v == .To_Peer && dest == b.h)
	dest, v = registry_from_tun(&f.srv.reg, ip4_packet({8, 8, 8, 8}, {192, 168, 61, 5}))
	testing.expect(t, v == .To_Peer && dest == a.h)
	// A key that connects again replaces only its own session.
	d := server_authorize(&f.srv, Auth_Input{key = peer_key(11), has_key = true, proof = .Chain, src = tkey(50)}, 1 * SEC)
	testing.expect_value(t, d.n_kicks, 1)
	testing.expect_value(t, d.kicks[0], a.h)
	srv_leave(t, f, &a, 2 * SEC)
	srv_leave(t, f, &b, 2 * SEC)
}

@(test)
test_server_two_keys_with_one_ccd_address_second_refused :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	f.files["/ccd/jan"] = "ifconfig-push 10.8.0.50 255.255.255.0\n"
	a := srv_join(t, f, 13, 0)
	testing.expect(t, a.ok)
	testing.expect_value(t, a.a.addr4, [4]u8{10, 8, 0, 50})
	b := srv_join(t, f, 14, 0)
	testing.expect(t, !b.ok)
	testing.expect_value(t, b.rej.reason, Reject_Reason.Address_In_Use)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 1)
	// The same key again still replaces its own session.
	c := srv_join(t, f, 13, 1 * SEC, 77)
	testing.expect(t, c.ok)
	srv_leave(t, f, &c, 2 * SEC)
	assignment_destroy(&a.a)
}

@(test)
test_server_reload_ends_only_the_removed_key :: proc(t: ^testing.T) {
	f, ok := srv_fixture(t)
	if !ok {
		return
	}
	defer srv_destroy(f)
	a := srv_join(t, f, 11, 0)
	b := srv_join(t, f, 12, 0)
	testing.expect(t, a.ok && b.ok)
	// ivy's second key is removed; the first gets a new option line.
	t2 := make_pins(
		t,
		peers_text(strings.concatenate({"ivy ", pin_text(11), " ifconfig-push=10.8.0.43"}, context.temp_allocator)),
	)
	r := server_reload_peers(&f.srv, t2)
	defer reload_result_destroy(&r)
	testing.expect_value(t, len(r.kicks), 1)
	testing.expect_value(t, r.kicks[0].handle, b.h)
	testing.expect_value(t, r.kicks[0].reason, Kick_Reason.Key_Removed)
	testing.expect(t, server_disconnect(&f.srv, b.h, 3 * SEC))
	assignment_destroy(&b.a)
	testing.expect_value(t, peers_count(&f.srv.reg.peers), 1)
	srv_leave(t, f, &a, 4 * SEC)
}
