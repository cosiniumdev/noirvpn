// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import cnet "core:net"
import "core:testing"
import "core:time"
import "noir:proto/config"

SEC :: time.Second

A1 :: cnet.Address(cnet.IP4_Address{192, 0, 2, 1})
A2 :: cnet.Address(cnet.IP4_Address{192, 0, 2, 2})
A3 :: cnet.Address(cnet.IP4_Address{192, 0, 2, 3})
V6A :: cnet.Address(cnet.IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1})
V6B :: cnet.Address(cnet.IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 2})

// A policy on a config built from `remotes` and `extra`.
Fixture :: struct {
	cfg: config.Config,
	p:   Policy,
}

fixture_make :: proc(t: ^testing.T, remotes: string, extra := "", seed: u64 = 1) -> (f: ^Fixture, ok: bool) {
	f = new(Fixture)
	f.cfg = load_client(remotes, extra)
	if !expect_config_ok(t, &f.cfg) {
		config.destroy(&f.cfg)
		free(f)
		return nil, false
	}
	err := policy_init(&f.p, &f.cfg.client, seed)
	testing.expect_value(t, err, nil)
	return f, true
}

fixture_destroy :: proc(f: ^Fixture) {
	policy_destroy(&f.p)
	config.destroy(&f.cfg)
	free(f)
}

// Run the actions that need no outcome. Fails the test if `want` is not the
// next action kind.
expect_action :: proc(
	t: ^testing.T,
	p: ^Policy,
	now: time.Duration,
	kind: Action_Kind,
	loc := #caller_location,
) -> (
	a: Action,
	ok: bool,
) {
	a = policy_next(p, now)
	testing.expectf(t, a.kind == kind, "want action %v, got %v (entry %d)", kind, a.kind, a.entry, loc = loc)
	return a, a.kind == kind
}

// ---- remote order and back-off arithmetic ----

@(test)
backoff_table :: proc(t: ^testing.T) {
	cases := []struct {
		base, max_wait, fails: int,
		want:                  int,
	} {
		// Default 1 s, cap 300 s: flat for 5 failures, then doubling.
		{1, 300, 1, 1},
		{1, 300, 5, 1},
		{1, 300, 6, 2},
		{1, 300, 7, 4},
		{1, 300, 8, 8},
		{1, 300, 12, 128},
		{1, 300, 13, 256},
		{1, 300, 14, 300},
		{1, 300, 1000, 300},
		{5, 20, 5, 5},
		{5, 20, 6, 10},
		{5, 20, 7, 20},
		{5, 20, 8, 20},
		// A cap below the base is read as the base.
		{10, 3, 1, 10},
		{10, 3, 9, 10},
		// No wait at all.
		{0, 300, 1, 0},
		{0, 300, 50, 0},
		{-1, 300, 1, 0},
		// Huge failure counts do not overflow.
		{1, 1 << 40, 100000, 1 << 40},
	}
	for c in cases {
		got := backoff_seconds(c.base, c.max_wait, c.fails)
		testing.expectf(t, got == c.want, "backoff(%d, %d, %d) = %d, want %d", c.base, c.max_wait, c.fails, got, c.want)
	}
}

@(test)
remote_order_plain :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example 1194 udp\nremote b.example 443 tcp\nremote c.example")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	testing.expect_value(t, len(f.p.order), 3)
	testing.expect_value(t, f.p.order[0], 0)
	testing.expect_value(t, f.p.order[1], 1)
	testing.expect_value(t, f.p.order[2], 2)
	// Seeds do not matter without remote-random.
	order, err := remote_order(&f.cfg.client, 99999)
	defer delete(order)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(order), 3)
	testing.expect_value(t, order[0], 0)
}

@(test)
remote_order_random_is_a_repeatable_permutation :: proc(t: ^testing.T) {
	remotes := "remote a 1\nremote b 2\nremote c 3\nremote d 4\nremote e 5\nremote f 6\nremote g 7\nremote h 8"
	f, ok := fixture_make(t, remotes, "remote-random")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	differs := false
	for seed in 1 ..= 20 {
		a, aerr := remote_order(&f.cfg.client, u64(seed))
		b, berr := remote_order(&f.cfg.client, u64(seed))
		defer delete(a)
		defer delete(b)
		testing.expect_value(t, aerr, nil)
		testing.expect_value(t, berr, nil)
		testing.expect_value(t, len(a), 8)
		// Same seed, same order.
		for i in 0 ..< 8 {
			testing.expect_value(t, a[i], b[i])
		}
		// A permutation: every index once.
		seen: [8]bool
		for v in a {
			testing.expect(t, v >= 0 && v < 8 && !seen[v])
			seen[v] = true
		}
		if a[0] != 0 || a[1] != 1 {
			differs = true
		}
	}
	testing.expect(t, differs, "remote-random should change the order for some seed")
}

@(test)
remote_order_proto_force :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a 1194 udp\nremote b 443 tcp\nremote c 1194 udp\nremote d 8443 tcp", "proto-force tcp")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	testing.expect_value(t, len(f.p.order), 2)
	testing.expect_value(t, f.p.order[0], 1)
	testing.expect_value(t, f.p.order[1], 3)
}

@(test)
policy_stops_when_no_remote_matches :: proc(t: ^testing.T) {
	// The config parser refuses this combination, so build the config by hand.
	conns := []config.Connection{{host = "a.example", rport = 1194, proto = .Udp}}
	cfg := config.Client_Config {
		connections = conns,
		proto_force = config.Proto.Tcp,
	}
	p: Policy
	testing.expect_value(t, policy_init(&p, &cfg, 1), nil)
	defer policy_destroy(&p)
	a := policy_next(&p, 0)
	testing.expect_value(t, a.kind, Action_Kind.Stop)
	testing.expect_value(t, a.stop, Stop_Reason.No_Remote)
	// Outcomes after a stop change nothing.
	policy_outcome(&p, .Connected, 0)
	testing.expect_value(t, policy_next(&p, 0).kind, Action_Kind.Stop)
}

// ---- one remote, several addresses ----

@(test)
policy_walks_the_addresses_then_waits :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote vpn.example 1194 udp")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	now := time.Duration(0)

	a, _ := expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.host, "vpn.example")
	testing.expect_value(t, a.port, u16(1194))
	testing.expect_value(t, a.proto, config.Proto.Udp)
	testing.expect_value(t, a.family, config.Family.Any)
	// Asking again changes nothing.
	b := policy_next(p, now)
	testing.expect_value(t, b, a)

	policy_resolved(p, {A1, V6A, A2}, true, now)
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, A1)
	testing.expect_value(t, a.endpoint.port, 1194)
	testing.expect_value(t, a.attempt_timeout, 120 * SEC)

	// First address fails: wait 1 s, then the second address.
	policy_outcome(p, .Handshake_Timeout, now)
	w, _ := expect_action(t, p, now, .Wait)
	testing.expect_value(t, w.wake_at, 1 * SEC)
	now = 1 * SEC
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, V6A)

	policy_outcome(p, .Connect_Failed, now)
	now += 1 * SEC
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, A2)

	// Last address fails: the whole name is resolved again.
	policy_outcome(p, .Handshake_Failed, now)
	now += 1 * SEC
	a, _ = expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 0)
}

@(test)
policy_wait_is_exact :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote vpn.example", "connect-retry 7")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	policy_resolved(p, {A1}, true, 100 * SEC)
	policy_outcome(p, .Connect_Failed, 100 * SEC)
	w := policy_next(p, 100 * SEC)
	testing.expect_value(t, w.kind, Action_Kind.Wait)
	testing.expect_value(t, w.wake_at, 107 * SEC)
	testing.expect_value(t, policy_next(p, 106 * SEC + 999 * time.Millisecond).kind, Action_Kind.Wait)
	testing.expect_value(t, policy_next(p, 107 * SEC).kind, Action_Kind.Resolve)
}

@(test)
policy_backoff_grows_and_success_resets_it :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote vpn.example", "connect-retry 5 20")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	now := time.Duration(0)

	// 5, 5, 5, 5, 5, 10, 20, 20, 20 seconds.
	want := []int{5, 5, 5, 5, 5, 10, 20, 20, 20}
	for secs, i in want {
		policy_resolved(p, {A1}, true, now)
		policy_outcome(p, .Handshake_Timeout, now)
		w := policy_next(p, now)
		testing.expectf(t, w.kind == .Wait, "step %d: want Wait, got %v", i, w.kind)
		testing.expectf(t, w.wake_at - now == time.Duration(secs) * SEC, "step %d: waited %v, want %d s", i, w.wake_at - now, secs)
		now = w.wake_at
	}

	// A success, then a failure: back to the base wait.
	policy_resolved(p, {A1}, true, now)
	policy_outcome(p, .Connected, now)
	testing.expect_value(t, p.state[0].fails, 0)
	policy_outcome(p, .Ping_Restart, now)
	w := policy_next(p, now)
	testing.expect_value(t, w.kind, Action_Kind.Wait)
	testing.expect_value(t, w.wake_at - now, 5 * SEC)
}

// ---- several remotes ----

@(test)
policy_moves_to_the_next_remote :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example 1194 udp\nremote b.example 443 tcp\nremote c.example 1195 udp4")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	now := time.Duration(0)

	a, _ := expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 0)
	policy_resolved(p, {A1}, true, now)
	policy_outcome(p, .Connect_Failed, now)
	now += 1 * SEC

	a, _ = expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 1)
	testing.expect_value(t, a.host, "b.example")
	testing.expect_value(t, a.proto, config.Proto.Tcp)
	testing.expect_value(t, a.port, u16(443))
	policy_resolved(p, {A2}, true, now)
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.entry, 1)
	policy_outcome(p, .Connect_Failed, now)
	now += 1 * SEC

	a, _ = expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 2)
	testing.expect_value(t, a.family, config.Family.V4)
	policy_resolved(p, {A3}, true, now)
	policy_outcome(p, .Connect_Failed, now)
	now += 1 * SEC

	// Round the list: back to the first.
	a, _ = expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 0)
}

@(test)
policy_uses_connection_blocks :: proc(t: ^testing.T) {
	remotes := `<connection>
remote a.example 1194 udp
connect-retry 3
connect-timeout 30
</connection>
<connection>
remote b.example 443 tcp
connect-retry 9
</connection>`
	f, ok := fixture_make(t, remotes)
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	policy_resolved(p, {A1}, true, 0)
	a := policy_next(p, 0)
	testing.expect_value(t, a.attempt_timeout, 30 * SEC)
	policy_outcome(p, .Connect_Failed, 0)
	// The wait comes from the remote that failed.
	testing.expect_value(t, policy_next(p, 0).wake_at, 3 * SEC)
	policy_resolved(p, {A2}, true, 3 * SEC)
	policy_outcome(p, .Connect_Failed, 3 * SEC)
	testing.expect_value(t, policy_next(p, 3 * SEC).wake_at, 12 * SEC)
}

@(test)
policy_connect_retry_max_counts_passes_per_remote :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example\nremote b.example", "connect-retry 0\nconnect-retry-max 2")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	attempts := 0
	order: [8]int
	for {
		a := policy_next(p, 0)
		if a.kind == .Stop {
			testing.expect_value(t, a.stop, Stop_Reason.Retries_Exhausted)
			break
		}
		if a.kind == .Resolve {
			policy_resolved(p, {A1}, true, 0)
			continue
		}
		testing.expect_value(t, a.kind, Action_Kind.Connect)
		if attempts < len(order) {
			order[attempts] = a.entry
		}
		attempts += 1
		policy_outcome(p, .Handshake_Timeout, 0)
		if attempts > 20 {
			break
		}
	}
	// Each remote twice, alternating.
	testing.expect_value(t, attempts, 4)
	testing.expect_value(t, order[0], 0)
	testing.expect_value(t, order[1], 1)
	testing.expect_value(t, order[2], 0)
	testing.expect_value(t, order[3], 1)
}

@(test)
policy_connect_retry_max_one_tries_every_address_once :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 0\nconnect-retry-max 1")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	policy_resolved(p, {A1, A2}, true, 0)
	testing.expect_value(t, policy_next(p, 0).endpoint.address, A1)
	policy_outcome(p, .Connect_Failed, 0)
	testing.expect_value(t, policy_next(p, 0).endpoint.address, A2)
	policy_outcome(p, .Connect_Failed, 0)
	a := policy_next(p, 0)
	testing.expect_value(t, a.kind, Action_Kind.Stop)
	testing.expect_value(t, a.stop, Stop_Reason.Retries_Exhausted)
}

@(test)
policy_success_gives_the_tries_back :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 0\nconnect-retry-max 2")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	for _ in 0 ..< 5 {
		policy_resolved(p, {A1}, true, 0)
		policy_outcome(p, .Connected, 0)
		policy_outcome(p, .Ping_Restart, 0)
		testing.expect_value(t, policy_next(p, 0).kind, Action_Kind.Resolve)
	}
}

@(test)
policy_remote_random_follows_the_shuffled_order :: proc(t: ^testing.T) {
	remotes := "remote a 1\nremote b 2\nremote c 3\nremote d 4\nremote e 5\nremote f 6"
	f, ok := fixture_make(t, remotes, "remote-random\nconnect-retry 0", 7)
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	expected, _ := remote_order(&f.cfg.client, 7)
	defer delete(expected)
	for want in expected {
		a := policy_next(p, 0)
		testing.expect_value(t, a.kind, Action_Kind.Resolve)
		testing.expect_value(t, a.entry, want)
		policy_resolved(p, {A1}, true, 0)
		policy_outcome(p, .Connect_Failed, 0)
	}
	// The shuffled order is kept for the next round.
	testing.expect_value(t, policy_next(p, 0).entry, expected[0])
}

// ---- outcomes ----

@(test)
policy_auth_failed_stops_unless_auth_retry :: proc(t: ^testing.T) {
	{
		f, ok := fixture_make(t, "remote a.example")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, {A1}, true, 0)
		policy_outcome(&f.p, .Auth_Failed, 0)
		a := policy_next(&f.p, 0)
		testing.expect_value(t, a.kind, Action_Kind.Stop)
		testing.expect_value(t, a.stop, Stop_Reason.Auth_Failed)
	}
	for mode in ([]string{"auth-retry nointeract", "auth-retry interact"}) {
		f, ok := fixture_make(t, "remote a.example\nremote b.example", mode)
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, {A1, A2}, true, 0)
		policy_outcome(&f.p, .Auth_Failed, 0)
		// Same remote, same address, after the wait.
		w := policy_next(&f.p, 0)
		testing.expect_value(t, w.kind, Action_Kind.Wait)
		a := policy_next(&f.p, w.wake_at)
		testing.expect_value(t, a.kind, Action_Kind.Connect)
		testing.expect_value(t, a.entry, 0)
		testing.expect_value(t, a.endpoint.address, A1)
	}
}

@(test)
policy_auth_failed_temp_flags :: proc(t: ^testing.T) {
	remotes := "remote a.example\nremote b.example"
	cases := []struct {
		name:       string,
		info:       Outcome_Info,
		wait:       time.Duration,
		want_entry: int,
		want_addr:  cnet.Address,
		connect:    bool, // a Connect action (same entry) rather than a Resolve
	} {
		{"no flags: next address", {}, 2 * SEC, 0, A2, true},
		{"backoff 30, advance remote", {backoff_secs = 30, advance = .Remote}, 30 * SEC, 1, nil, false},
		{"advance no: same address", {advance = .No}, 2 * SEC, 0, A1, true},
		{"advance addr", {advance = .Addr, backoff_secs = 10}, 10 * SEC, 0, A2, true},
	}
	for c in cases {
		f, ok := fixture_make(t, remotes)
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, {A1, A2}, true, 0)
		policy_outcome(&f.p, .Auth_Failed_Temp, 0, c.info)
		w := policy_next(&f.p, 0)
		testing.expectf(t, w.kind == .Wait && w.wake_at == c.wait, "%s: wait %v", c.name, w)
		a := policy_next(&f.p, c.wait)
		if c.connect {
			testing.expectf(t, a.kind == .Connect && a.entry == c.want_entry && a.endpoint.address == c.want_addr, "%s: %v", c.name, a)
		} else {
			testing.expectf(t, a.kind == .Resolve && a.entry == c.want_entry, "%s: %v", c.name, a)
		}
	}
}

@(test)
policy_temp_wait_grows :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 1")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	want := []time.Duration{2 * SEC, 4 * SEC, 8 * SEC, 16 * SEC, 32 * SEC, 60 * SEC, 60 * SEC, 60 * SEC}
	now := time.Duration(0)
	for w, i in want {
		a := policy_next(&f.p, now)
		if a.kind == .Wait {
			now = a.wake_at
			a = policy_next(&f.p, now)
		}
		testing.expectf(t, a.kind == .Resolve, "round %d: %v", i, a)
		policy_resolved(&f.p, {A1}, true, now)
		policy_outcome(&f.p, .Auth_Failed_Temp, now)
		a = policy_next(&f.p, now)
		testing.expectf(t, a.kind == .Wait && a.wake_at - now == w, "round %d: wait %v, want %v", i, a.wake_at - now, w)
	}
}

@(test)
policy_temp_hint_is_floor :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 1")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	now := time.Duration(0)
	// A hint of 10 s: the wait is 10 s, then the growth passes it.
	want := []time.Duration{10 * SEC, 10 * SEC, 10 * SEC, 16 * SEC, 32 * SEC}
	for w, i in want {
		a := policy_next(&f.p, now)
		if a.kind == .Wait {
			now = a.wake_at
			a = policy_next(&f.p, now)
		}
		policy_resolved(&f.p, {A1}, true, now)
		policy_outcome(&f.p, .Auth_Failed_Temp, now, Outcome_Info{backoff_secs = 10, advance = .No})
		a = policy_next(&f.p, now)
		testing.expectf(t, a.kind == .Wait && a.wake_at - now == w, "round %d: wait %v, want %v", i, a.wake_at - now, w)
	}
	// A success resets the growth.
	now += 100 * SEC
	policy_next(&f.p, now)
	policy_outcome(&f.p, .Connected, now)
	testing.expect_value(t, f.p.temp_runs, 0)
	policy_outcome(&f.p, .Auth_Failed_Temp, now + 1 * SEC)
	a := policy_next(&f.p, now + 1 * SEC)
	testing.expectf(t, a.kind == .Wait && a.wake_at - (now + 1 * SEC) == 2 * SEC, "after success: %v", a)
	// A huge hint is capped.
	now += 10 * SEC
	policy_next(&f.p, now)
	policy_resolved(&f.p, {A1}, true, now)
	policy_outcome(&f.p, .Auth_Failed_Temp, now, Outcome_Info{backoff_secs = 0x7FFFFFFF, advance = .No})
	a = policy_next(&f.p, now)
	testing.expectf(t, a.kind == .Wait && a.wake_at - now == TEMP_HINT_MAX_SECS * SEC, "capped hint: %v", a)
}

@(test)
policy_server_restart :: proc(t: ^testing.T) {
	remotes := "remote a.example\nremote b.example"
	// RESTART: same server again, after the base wait. Not a failure.
	{
		f, ok := fixture_make(t, remotes, "connect-retry 4")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, {A1, A2}, true, 0)
		policy_outcome(&f.p, .Connected, 0)
		policy_outcome(&f.p, .Server_Restart, 10 * SEC)
		testing.expect_value(t, f.p.state[0].fails, 0)
		testing.expect_value(t, f.p.state[0].tries, 0)
		w := policy_next(&f.p, 10 * SEC)
		testing.expect_value(t, w.kind, Action_Kind.Wait)
		testing.expect_value(t, w.wake_at, 14 * SEC)
		a := policy_next(&f.p, 14 * SEC)
		testing.expect_value(t, a.kind, Action_Kind.Connect)
		testing.expect_value(t, a.entry, 0)
		testing.expect_value(t, a.endpoint.address, A1)
	}
	// RESTART,[N]: the next remote.
	{
		f, ok := fixture_make(t, remotes)
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, {A1, A2}, true, 0)
		policy_outcome(&f.p, .Connected, 0)
		policy_outcome(&f.p, .Server_Restart, 0, {next_remote = true})
		a := policy_next(&f.p, 1 * SEC)
		testing.expect_value(t, a.kind, Action_Kind.Resolve)
		testing.expect_value(t, a.entry, 1)
	}
	// RESTART never counts toward connect-retry-max.
	{
		f, ok := fixture_make(t, "remote a.example", "connect-retry 0\nconnect-retry-max 1")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		for _ in 0 ..< 10 {
			policy_resolved(&f.p, {A1}, true, 0)
			policy_outcome(&f.p, .Server_Restart, 0)
			testing.expect_value(t, policy_next(&f.p, 0).kind, Action_Kind.Connect)
		}
	}
}

@(test)
policy_stopping_outcomes :: proc(t: ^testing.T) {
	cases := []struct {
		outcome: Outcome,
		reason:  Stop_Reason,
	} {
		{.Server_Halt, .Halted},
		{.Local_Stop, .Local_Stop},
		{.Inactive, .Inactive},
		{.Session_Timeout, .Session_Timeout},
	}
	for c in cases {
		f, ok := fixture_make(t, "remote a.example")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, {A1}, true, 0)
		policy_outcome(&f.p, c.outcome, 0)
		a := policy_next(&f.p, 100 * SEC)
		testing.expectf(t, a.kind == .Stop && a.stop == c.reason, "%v: %v", c.outcome, a)
		reason, stopped := policy_stopped(&f.p)
		testing.expect(t, stopped)
		testing.expect_value(t, reason, c.reason)
	}
}

@(test)
policy_local_restart_has_no_wait :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 30")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	policy_resolved(&f.p, {A1}, true, 0)
	policy_outcome(&f.p, .Connected, 0)
	policy_outcome(&f.p, .Local_Restart, 5 * SEC)
	a := policy_next(&f.p, 5 * SEC)
	testing.expect_value(t, a.kind, Action_Kind.Connect)
	testing.expect_value(t, a.endpoint.address, A1)
}

@(test)
policy_datapath_failed_retries_at_once_and_is_no_try :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 30\nconnect-retry-max 1")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	policy_resolved(&f.p, {A1, A2}, true, 0)
	policy_next(&f.p, 0)
	// The service failed: the same server again, no wait, and no try used up (the
	// remote has one try only).
	policy_outcome(&f.p, .Datapath_Failed, 5 * SEC)
	testing.expect_value(t, f.p.state[0].fails, 0)
	testing.expect_value(t, f.p.state[0].tries, 0)
	a := policy_next(&f.p, 5 * SEC)
	testing.expect_value(t, a.kind, Action_Kind.Connect)
	testing.expect_value(t, a.endpoint.address, A1)
}

@(test)
policy_every_failure_outcome_takes_the_same_path :: proc(t: ^testing.T) {
	for outcome in ([]Outcome{.Connect_Failed, .Handshake_Timeout, .Handshake_Failed, .Push_Rejected, .Ping_Restart}) {
		f, ok := fixture_make(t, "remote a.example")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, {A1, A2}, true, 0)
		policy_outcome(&f.p, outcome, 0)
		testing.expect_value(t, f.p.state[0].fails, 1)
		a := policy_next(&f.p, 1 * SEC)
		testing.expectf(t, a.kind == .Connect && a.endpoint.address == A2, "%v: %v", outcome, a)
	}
}

// ---- name resolution ----

@(test)
policy_family_filter :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example 1194 udp4\nremote b.example 1194 udp6")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	// `udp4` drops the IPv6 addresses.
	policy_resolved(p, {V6A, A1, V6B, A2}, true, 0)
	testing.expect_value(t, policy_next(p, 0).endpoint.address, A1)
	policy_outcome(p, .Connect_Failed, 0)
	testing.expect_value(t, policy_next(p, 1 * SEC).endpoint.address, A2)
	policy_outcome(p, .Connect_Failed, 1 * SEC)
	// Next remote is `udp6`: only IPv4 results is a failed look-up.
	a := policy_next(p, 2 * SEC)
	testing.expect_value(t, a.kind, Action_Kind.Resolve)
	testing.expect_value(t, a.entry, 1)
	testing.expect_value(t, a.family, config.Family.V6)
	policy_resolved(p, {A1}, true, 2 * SEC)
	testing.expect_value(t, f.p.state[1].fails, 1)
	w := policy_next(p, 2 * SEC)
	testing.expect_value(t, w.kind, Action_Kind.Wait)
	a = policy_next(p, 3 * SEC)
	testing.expect_value(t, a.kind, Action_Kind.Resolve)
	testing.expect_value(t, a.entry, 0)
}

@(test)
policy_resolve_failure_infinite_retry :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	now := time.Duration(0)
	// Default `resolv-retry infinite`: it never gives up, however long it takes.
	for _ in 0 ..< 50 {
		a, _ := expect_action(t, p, now, .Resolve)
		_ = a
		policy_resolved(p, nil, false, now)
		w := policy_next(p, now)
		testing.expect_value(t, w.kind, Action_Kind.Wait)
		now = w.wake_at + 1000 * SEC
	}
	testing.expect_value(t, policy_next(p, now).kind, Action_Kind.Resolve)
}

@(test)
policy_resolve_failure_with_a_time_limit :: proc(t: ^testing.T) {
	// One remote: it is retried for 10 s, then the policy stops.
	{
		f, ok := fixture_make(t, "remote a.example", "resolv-retry 10\nconnect-retry 4")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		p := &f.p
		policy_resolved(p, nil, false, 0) // first failure at t = 0
		w := policy_next(p, 0)
		testing.expect_value(t, w.kind, Action_Kind.Wait)
		testing.expect_value(t, w.wake_at, 4 * SEC)
		policy_resolved(p, nil, false, 4 * SEC)
		testing.expect_value(t, policy_next(p, 8 * SEC).kind, Action_Kind.Resolve)
		policy_resolved(p, nil, false, 8 * SEC)
		testing.expect_value(t, policy_next(p, 12 * SEC).kind, Action_Kind.Resolve)
		policy_resolved(p, nil, false, 12 * SEC) // 12 s after the first failure: over 10
		a := policy_next(p, 100 * SEC)
		testing.expect_value(t, a.kind, Action_Kind.Stop)
		testing.expect_value(t, a.stop, Stop_Reason.Resolve_Failed)
	}
	// `resolv-retry 0`: no retry at all.
	{
		f, ok := fixture_make(t, "remote a.example", "resolv-retry 0")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		policy_resolved(&f.p, nil, false, 0)
		a := policy_next(&f.p, 0)
		testing.expect_value(t, a.kind, Action_Kind.Stop)
		testing.expect_value(t, a.stop, Stop_Reason.Resolve_Failed)
	}
	// Two remotes: the one that cannot be resolved is skipped from then on.
	{
		f, ok := fixture_make(t, "remote a.example\nremote b.example", "resolv-retry 0\nconnect-retry 0")
		if !ok {
			return
		}
		defer fixture_destroy(f)
		p := &f.p
		policy_resolved(p, nil, false, 0)
		a := policy_next(p, 0)
		testing.expect_value(t, a.kind, Action_Kind.Resolve)
		testing.expect_value(t, a.entry, 1)
		policy_resolved(p, {A1}, true, 0)
		policy_outcome(p, .Connect_Failed, 0)
		// Round the list again: still b only.
		a = policy_next(p, 0)
		testing.expect_value(t, a.kind, Action_Kind.Resolve)
		testing.expect_value(t, a.entry, 1)
		// A success brings the dead remote back.
		policy_resolved(p, {A1}, true, 0)
		policy_outcome(p, .Connected, 0)
		testing.expect(t, !p.state[0].dead)
	}
}

@(test)
policy_resolve_success_clears_the_failure_streak :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "resolv-retry 10\nconnect-retry 1")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	policy_resolved(p, nil, false, 0)
	policy_resolved(p, {A1}, true, 5 * SEC)
	policy_outcome(p, .Connect_Failed, 5 * SEC)
	// The streak is over. A later failed look-up goes on with the address that is known.
	testing.expect_value(t, policy_resolved(p, nil, false, 100 * SEC), true)
	testing.expect_value(t, policy_next(p, 101 * SEC).kind, Action_Kind.Connect)
}

@(test)
policy_proxy_resolves_and_connects_to_the_proxy :: proc(t: ^testing.T) {
	// The first remote is direct, the second goes through a proxy, and the
	// family filter of the remote still applies to the proxy's addresses.
	f, ok := fixture_make(
		t,
		"<connection>\nremote a.example 443 tcp-client\n</connection>\n<connection>\nremote b.example 443 tls4-client\nhttp-proxy proxy.example 3128\n</connection>",
	)
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	a, _ := expect_action(t, p, 0, .Resolve)
	testing.expect_value(t, a.host, "a.example")
	testing.expect_value(t, a.port, u16(443))
	testing.expect(t, !a.via_proxy)
	policy_resolved(p, {A1}, true, 0)
	a, _ = expect_action(t, p, 0, .Connect)
	testing.expect(t, !a.via_proxy)
	testing.expect_value(t, a.endpoint.port, 443)
	policy_outcome(p, .Connect_Failed, 0)
	a, _ = expect_action(t, p, 1 * SEC, .Resolve)
	testing.expect_value(t, a.entry, 1)
	testing.expect_value(t, a.host, "proxy.example")
	testing.expect_value(t, a.port, u16(3128))
	testing.expect(t, a.via_proxy)
	// An IPv6 address of the proxy does not fit a `tls4-client` remote.
	policy_resolved(p, {V6A, A2}, true, 1 * SEC)
	a, _ = expect_action(t, p, 1 * SEC, .Connect)
	testing.expect(t, a.via_proxy)
	testing.expect_value(t, a.endpoint.address, A2)
	testing.expect_value(t, a.endpoint.port, 3128)
	testing.expect_value(t, a.proto, config.Proto.Tcp)
}

// ---- a failed look-up uses the addresses of the last one that worked ----

@(test)
policy_failed_lookup_uses_the_last_addresses :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote vpn.example", "connect-retry 5\nresolv-retry 30")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	now := time.Duration(0)

	// No address is known yet: a failed look-up is a failed attempt.
	testing.expect_value(t, policy_resolved(p, nil, false, now), false)
	w, _ := expect_action(t, p, now, .Wait)
	now = w.wake_at

	// The name resolves and the tunnel comes up. The success keeps the addresses.
	expect_action(t, p, now, .Resolve)
	testing.expect_value(t, policy_resolved(p, {A1, A2}, true, now), false)
	policy_outcome(p, .Connected, now)
	policy_outcome(p, .Ping_Restart, now)
	w, _ = expect_action(t, p, now, .Wait)
	now = w.wake_at

	// The first attempts after the loss use the addresses of the session, with no look-up.
	// They fail, until the policy looks the name up again.
	steps := 0
	for ; steps < 10; steps += 1 {
		a := policy_next(p, now)
		if a.kind == .Resolve {
			break
		}
		if a.kind == .Wait {
			now = a.wake_at
		} else {
			testing.expect_value(t, a.kind, Action_Kind.Connect)
			policy_outcome(p, .Connect_Failed, now)
		}
	}
	testing.expect(t, steps < 10)

	// The next pass looks the name up again. It fails (the name server is behind the dead
	// tunnel): the old addresses, in their order.
	expect_action(t, p, now, .Resolve)
	testing.expect_value(t, policy_resolved(p, nil, false, now), true)
	a, _ := expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, A1)
	policy_outcome(p, .Connect_Failed, now)
	w, _ = expect_action(t, p, now, .Wait)
	now = w.wake_at
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, A2)

	// It never counts against `resolv-retry`: long after the limit the remote is still tried.
	policy_outcome(p, .Connect_Failed, now)
	now += 600 * SEC
	expect_action(t, p, now, .Resolve)
	testing.expect_value(t, policy_resolved(p, {}, true, now), true)
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, A1)
	_, stopped := policy_stopped(p)
	testing.expect(t, !stopped)

	// A look-up that works again replaces them.
	policy_outcome(p, .Connect_Failed, now)
	w, _ = expect_action(t, p, now, .Wait)
	now = w.wake_at
	expect_action(t, p, now, .Connect)
	policy_outcome(p, .Connect_Failed, now)
	w, _ = expect_action(t, p, now, .Wait)
	now = w.wake_at
	expect_action(t, p, now, .Resolve)
	testing.expect_value(t, policy_resolved(p, {A3}, true, now), false)
	policy_outcome(p, .Connect_Failed, now)
	w, _ = expect_action(t, p, now, .Wait)
	now = w.wake_at
	expect_action(t, p, now, .Resolve)
	testing.expect_value(t, policy_resolved(p, nil, false, now), true)
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, A3)
}

@(test)
policy_kept_addresses_are_per_remote_and_filtered :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example 1194 udp4\nremote b.example 1194 udp")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	now := time.Duration(0)

	// a.example is udp4: only the IPv4 address is kept.
	expect_action(t, p, now, .Resolve)
	policy_resolved(p, {V6A, A1}, true, now)
	policy_outcome(p, .Connect_Failed, now)
	now += 1 * SEC

	// b.example never resolved: its failed look-up has nothing to use.
	a, _ := expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 1)
	testing.expect_value(t, policy_resolved(p, nil, false, now), false)
	now += 1 * SEC

	// Back on a.example: the failed look-up gives the one IPv4 address.
	a, _ = expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 0)
	testing.expect_value(t, policy_resolved(p, nil, false, now), true)
	a, _ = expect_action(t, p, now, .Connect)
	testing.expect_value(t, a.endpoint.address, A1)
	policy_outcome(p, .Connect_Failed, now)
	now += 1 * SEC
	a, _ = expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, 1)
}

// ---- a stopped policy is set ready again (the service mode) ----

@(test)
policy_rearm_after_every_kind_of_stop :: proc(t: ^testing.T) {
	stops := []struct {
		outcome: Outcome,
		reason:  Stop_Reason,
		extra:   string,
	} {
		{.Auth_Failed, .Auth_Failed, "auth-retry none"},
		{.Server_Halt, .Halted, ""},
		{.Inactive, .Inactive, ""},
		{.Session_Timeout, .Session_Timeout, ""},
		{.Local_Stop, .Local_Stop, ""},
	}
	for s in stops {
		f, ok := fixture_make(t, "remote a.example", s.extra)
		if !ok {
			return
		}
		p := &f.p
		policy_resolved(p, {A1}, true, 0)
		policy_outcome(p, s.outcome, 0)
		reason, stopped := policy_stopped(p)
		testing.expect(t, stopped)
		testing.expect_value(t, reason, s.reason)
		testing.expect_value(t, policy_next(p, 10 * SEC).kind, Action_Kind.Stop)
		// A stopped policy stays stopped until it is set ready again.
		policy_outcome(p, .Local_Restart, 10 * SEC)
		testing.expect_value(t, policy_next(p, 10 * SEC).kind, Action_Kind.Stop)

		policy_rearm(p)
		_, stopped = policy_stopped(p)
		testing.expect(t, !stopped)
		expect_action(t, p, 10 * SEC, .Resolve)
		fixture_destroy(f)
	}
}

@(test)
policy_rearm_after_used_up_retries :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example 1194 udp\nremote b.example 1194 udp", "connect-retry-max 1\nconnect-retry 1")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	now := time.Duration(0)
	for _ in 0 ..< 2 {
		expect_action(t, p, now, .Resolve)
		policy_resolved(p, {A1}, true, now)
		expect_action(t, p, now, .Connect)
		policy_outcome(p, .Connect_Failed, now)
		w := policy_next(p, now)
		if w.kind == .Wait {
			now = w.wake_at
		}
	}
	reason, stopped := policy_stopped(p)
	testing.expect(t, stopped)
	testing.expect_value(t, reason, Stop_Reason.Retries_Exhausted)

	policy_rearm(p)
	// The tries and the back-off start again, and the first remote is next.
	a, _ := expect_action(t, p, now, .Resolve)
	testing.expect_value(t, a.entry, p.order[0])
	testing.expect_value(t, p.state[0].tries, 0)
	testing.expect_value(t, p.state[0].fails, 0)
	testing.expect_value(t, p.wait_until, time.Duration(0))
}

@(test)
policy_rearm_keeps_the_known_addresses :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote vpn.example", "connect-retry 5\nresolv-retry 30")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	policy_resolved(p, {A1, A2}, true, 0)
	policy_outcome(p, .Connected, 0)
	policy_outcome(p, .Local_Stop, 1 * SEC)
	testing.expect_value(t, policy_next(p, 2 * SEC).kind, Action_Kind.Stop)

	policy_rearm(p)
	expect_action(t, p, 2 * SEC, .Resolve)
	// The name server is not reachable now: the addresses of the good look-up are used.
	testing.expect_value(t, policy_resolved(p, nil, false, 2 * SEC), true)
	a, _ := expect_action(t, p, 2 * SEC, .Connect)
	testing.expect_value(t, a.endpoint.address, A1)
}

@(test)
policy_rearm_of_a_policy_that_is_not_stopped :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 5")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	p := &f.p
	policy_resolved(p, {A1}, true, 0)
	policy_outcome(p, .Connect_Failed, 0)
	expect_action(t, p, 0, .Wait)
	policy_rearm(p)
	expect_action(t, p, 0, .Resolve)
}

@(test)
policy_rearm_without_a_remote_stays_stopped :: proc(t: ^testing.T) {
	// The base config of a service has no remote: nothing to connect to.
	cfg := config.Client_Config{}
	p: Policy
	testing.expect_value(t, policy_init(&p, &cfg, 1), nil)
	defer policy_destroy(&p)
	policy_rearm(&p)
	reason, stopped := policy_stopped(&p)
	testing.expect(t, stopped)
	testing.expect_value(t, reason, Stop_Reason.No_Remote)
}

@(test)
policy_exit_backoff :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 1")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	// A loop of short sessions that each end with EXIT: 5, 10, 20, 40, 60, 60 s.
	now := time.Duration(0)
	want := []int{5, 10, 20, 40, 60, 60}
	for w in want {
		policy_resolved(&f.p, {A1}, true, now)
		policy_outcome(&f.p, .Connected, now)
		now += 2 * SEC
		policy_outcome(&f.p, .Remote_Exit, now)
		a := policy_next(&f.p, now)
		testing.expect_value(t, a.kind, Action_Kind.Wait)
		testing.expect_value(t, a.wake_at, now + time.Duration(w) * SEC)
		now = a.wake_at
	}
	// A session that stays up for a minute resets the wait to the base.
	policy_resolved(&f.p, {A1}, true, now)
	policy_outcome(&f.p, .Connected, now)
	now += 61 * SEC
	policy_outcome(&f.p, .Remote_Exit, now)
	a := policy_next(&f.p, now)
	testing.expect_value(t, a.wake_at, now + 1 * SEC)
	now = a.wake_at
	// The next short one starts again at 5 s.
	policy_resolved(&f.p, {A1}, true, now)
	policy_outcome(&f.p, .Connected, now)
	now += 1 * SEC
	policy_outcome(&f.p, .Remote_Exit, now)
	a = policy_next(&f.p, now)
	testing.expect_value(t, a.wake_at, now + 5 * SEC)
}

@(test)
policy_exit_backoff_keeps_a_longer_connect_retry :: proc(t: ^testing.T) {
	f, ok := fixture_make(t, "remote a.example", "connect-retry 30")
	if !ok {
		return
	}
	defer fixture_destroy(f)
	policy_resolved(&f.p, {A1}, true, 0)
	policy_outcome(&f.p, .Connected, 0)
	policy_outcome(&f.p, .Remote_Exit, 1 * SEC)
	testing.expect_value(t, policy_next(&f.p, 1 * SEC).wake_at, 31 * SEC)
}
