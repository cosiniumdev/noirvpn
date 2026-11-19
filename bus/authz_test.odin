// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:testing"
import "noir:proto/config"

@(private = "file")
fake_resolver :: proc(kind: config.Bus_Id_Kind, name: string) -> (id: u32, ok: bool) {
	switch kind {
	case .Uid:
		switch name {
		case "alice":
			return 1000, true
		case "ctl":
			return 1001, true
		}
	case .Gid:
		switch name {
		case "wheel":
			return 10, true
		case "noirvpn":
			return 970, true
		}
	case .Sid:
	}
	return 0, false
}

// The rules as Unix reads them, on any system.
@(private = "file")
unix_policy :: proc(allow: []config.Bus_Allow, euid: u32, resolve: Resolver = fake_resolver) -> (Policy, [dynamic]string) {
	return policy_build(allow, euid, false, resolve, nil)
}

@(private = "file")
creds :: proc(uid, gid: u32) -> Peer_Creds {
	return {uid = uid, gid = gid}
}

@(test)
role_implications :: proc(t: ^testing.T) {
	testing.expect_value(t, roles_effective({}), Roles{})
	testing.expect_value(t, roles_effective({.Read}), Roles{.Read})
	testing.expect_value(t, roles_effective({.Operator}), Roles{.Operator, .Read})
	testing.expect_value(t, roles_effective({.Auth}), Roles{.Auth, .Read})
	testing.expect_value(t, roles_effective({.Admin}), ALL_ROLES)
	// Operator does not imply auth, auth does not imply operator.
	testing.expect(t, !roles_allow({.Operator}, .Auth))
	testing.expect(t, !roles_allow({.Auth}, .Operator))
	testing.expect(t, !roles_allow({.Read}, .Operator))
	testing.expect(t, roles_allow({.Admin}, .Auth))
	testing.expect(t, !roles_allow({}, .Read))
}

@(test)
op_table_matches_design :: proc(t: ^testing.T) {
	Want :: struct {
		op:       string,
		role:     Role,
		mutating: bool,
		scope:    Scope,
	}
	want := []Want {
		{"status", .Read, false, .Both},
		{"peers.list", .Read, false, .Server},
		{"peer.get", .Read, false, .Server},
		{"stats.get", .Read, false, .Both},
		{"peer.kick", .Operator, true, .Server},
		{"peers.reload", .Operator, true, .Server},
		{"passwords.reload", .Operator, true, .Server},
		{"log.level", .Operator, true, .Both},
		{"auth.decide", .Auth, true, .Server},
		{"auth.credentials", .Auth, false, .Server},
		{"daemon.reload", .Admin, true, .Both},
		{"daemon.shutdown", .Admin, true, .Both},
		{"connect", .Operator, true, .Client},
		{"disconnect", .Operator, true, .Client},
		{"auth.supply", .Operator, true, .Client},
		{"profile.set", .Operator, true, .Client},
		{"profile.check", .Operator, false, .Client},
		{"profile.clear", .Operator, true, .Client},
		{"acl.get", .Read, false, .Client},
		{"acl.reload", .Operator, true, .Client},
	}
	testing.expect_value(t, len(OPS), len(want))
	for w in want {
		info, ok := op_lookup(w.op)
		testing.expectf(t, ok, "%s missing", w.op)
		if ok {
			testing.expect_value(t, info.role, w.role)
			testing.expect_value(t, info.mutating, w.mutating)
			testing.expect_value(t, info.scope, w.scope)
			testing.expect(t, valid_name(w.op, MAX_OP_LEN))
		}
	}
	_, found := op_lookup("nope")
	testing.expect(t, !found)
	// Read-only ops never mutate.
	for o in OPS {
		if o.role == .Read {
			testing.expectf(t, !o.mutating, "%s is read but mutating", o.name)
		}
	}
}

@(test)
op_request_marks :: proc(t: ^testing.T) {
	// Only the operations that take a profile accept a big request.
	big := []string{"profile.set", "profile.check"}
	secret := []string{"profile.set", "profile.check", "auth.supply", "auth.decide"}
	for o in OPS {
		want_big, want_secret := false, false
		for n in big {
			want_big ||= n == o.name
		}
		for n in secret {
			want_secret ||= n == o.name
		}
		testing.expectf(t, o.big_request == want_big, "%s: big_request is %v", o.name, o.big_request)
		testing.expectf(t, o.secret == want_secret, "%s: secret is %v", o.name, o.secret)
	}
	testing.expect(t, MAX_PROFILE_REQUEST_SIZE > MAX_REQUEST_SIZE)
	testing.expect_value(t, MAX_PROFILE_REQUEST_SIZE, 262144)
	testing.expect_value(t, MAX_REQUEST_SIZE, 65536)
}

@(test)
op_modes :: proc(t: ^testing.T) {
	kick, _ := op_lookup("peer.kick")
	conn, _ := op_lookup("connect")
	status, _ := op_lookup("status")
	pset, _ := op_lookup("profile.set")
	testing.expect(t, op_in_mode(pset, .Client))
	testing.expect(t, !op_in_mode(pset, .Server))
	testing.expect(t, op_in_mode(kick, .Server))
	testing.expect(t, !op_in_mode(kick, .Client))
	testing.expect(t, op_in_mode(conn, .Client))
	testing.expect(t, !op_in_mode(conn, .Server))
	testing.expect(t, op_in_mode(status, .Server) && op_in_mode(status, .Client))
}

@(test)
policy_default_is_root_and_self :: proc(t: ^testing.T) {
	p, unresolved := unix_policy(nil, 1234)
	defer policy_destroy(&p)
	defer delete(unresolved)
	testing.expect_value(t, len(unresolved), 0)
	testing.expect(t, allowed(&p, creds(0, 0), "daemon.shutdown"))
	testing.expect(t, allowed(&p, creds(1234, 99), "daemon.shutdown"))
	testing.expect(t, allowed(&p, creds(1234, 99), "auth.decide"))
	testing.expect(t, !allowed(&p, creds(1235, 1234), "status"))
	testing.expect(t, !allowed(&p, creds(1000, 0), "status")) // gid 0 does not count
	// A daemon running as root has one rule only.
	p2, u2 := unix_policy(nil, 0)
	defer policy_destroy(&p2)
	defer delete(u2)
	testing.expect_value(t, len(p2.rules), 1)
}

@(test)
policy_uid_and_gid_rules :: proc(t: ^testing.T) {
	rules := []config.Bus_Allow {
		{kind = .Uid, id = 1000, roles = {.Read, .Operator}},
		{kind = .Gid, id = 970, roles = {.Auth}},
		{kind = .Uid, id = 2000, roles = {.Admin}},
	}
	p, unresolved := unix_policy(rules, 5)
	defer policy_destroy(&p)
	defer delete(unresolved)

	// uid match.
	testing.expect(t, allowed(&p, creds(1000, 1), "status"))
	testing.expect(t, allowed(&p, creds(1000, 1), "peer.kick"))
	testing.expect(t, !allowed(&p, creds(1000, 1), "auth.decide"))
	testing.expect(t, !allowed(&p, creds(1000, 1), "daemon.shutdown"))
	// gid match.
	testing.expect(t, allowed(&p, creds(3000, 970), "auth.decide"))
	testing.expect(t, allowed(&p, creds(3000, 970), "status")) // auth implies read
	testing.expect(t, !allowed(&p, creds(3000, 970), "peer.kick"))
	// Both match: union.
	testing.expect(t, allowed(&p, creds(1000, 970), "auth.decide"))
	testing.expect(t, allowed(&p, creds(1000, 970), "peer.kick"))
	// Admin.
	for o in OPS {
		testing.expect(t, allowed(&p, creds(2000, 0), o.name))
	}
	// Nobody else, and not even root or the daemon's own uid: once there are
	// rules, only the rules count.
	testing.expect(t, !allowed(&p, creds(0, 0), "status"))
	testing.expect(t, !allowed(&p, creds(5, 5), "status"))
	// Unknown ops are never allowed.
	testing.expect(t, !allowed(&p, creds(2000, 0), "no.such.op"))
	// A uid rule does not match the same number as a gid and the other way round.
	testing.expect(t, !allowed(&p, creds(970, 1), "auth.decide"))
	testing.expect(t, !allowed(&p, creds(1, 1000), "status"))
}

@(test)
gid_rules_match_group_members :: proc(t: ^testing.T) {
	rules := []config.Bus_Allow {
		{kind = .Uid, id = 1000, roles = {.Read}},
		{kind = .Gid, id = 970, roles = {.Operator}},
		{kind = .Gid, id = 971, roles = {.Auth}},
		{kind = .Gid, id = 972, roles = {.Read}},
	}
	p, unresolved := unix_policy(rules, 5)
	defer policy_destroy(&p)
	defer delete(unresolved)
	// User 1000 is in 970, user 3000 is in 971, nobody is in 972.
	member :: proc(uid, gid: u32) -> bool {
		return (uid == 1000 && gid == 970) || (uid == 3000 && gid == 971)
	}
	pending := make([dynamic]Rule)
	defer delete(pending)

	// 1000 with another gid: read from the uid rule, operator from the group.
	have := roles_for(&p, 1000, 1)
	roles_group_rules(&p, 1, have, &pending)
	// The rule of 972 adds nothing to read, so it is not asked about.
	testing.expect_value(t, len(pending), 2)
	got := roles_with_groups(have, 1000, pending[:], member)
	testing.expect(t, roles_allow(got, .Operator))
	testing.expect(t, !roles_allow(got, .Auth))
	testing.expect(t, !roles_allow(got, .Admin))

	// 3000 has no direct rule: auth (and read) from the group 971.
	have = roles_for(&p, 3000, 1)
	testing.expect_value(t, have, Roles{})
	roles_group_rules(&p, 1, have, &pending)
	testing.expect_value(t, len(pending), 3)
	got = roles_with_groups(have, 3000, pending[:], member)
	testing.expect(t, roles_allow(got, .Auth))
	testing.expect(t, roles_allow(got, .Read))
	testing.expect(t, !roles_allow(got, .Operator))

	// A user in no group gets nothing, and so does everyone with no lookup.
	have = roles_for(&p, 4000, 1)
	roles_group_rules(&p, 1, have, &pending)
	testing.expect_value(t, roles_with_groups(have, 4000, pending[:], member), Roles{})
	testing.expect_value(t, roles_with_groups(have, 3000, pending[:], nil), Roles{})

	// The gid of the socket matches as before: that rule is not asked about.
	have = roles_for(&p, 4000, 970)
	testing.expect(t, roles_allow(have, .Operator))
	roles_group_rules(&p, 970, have, &pending)
	for r in pending {
		testing.expect(t, r.id != 970)
	}
}

@(test)
policy_names_are_resolved :: proc(t: ^testing.T) {
	rules := []config.Bus_Allow {
		{kind = .Uid, name = "alice", roles = {.Operator}},
		{kind = .Gid, name = "wheel", roles = {.Admin}},
		{kind = .Uid, name = "nobody-here", roles = {.Read}},
		{kind = .Gid, name = "alice", roles = {.Read}}, // "alice" is a user, not a group
	}
	p, unresolved := unix_policy(rules, 5)
	defer policy_destroy(&p)
	defer delete(unresolved)
	testing.expect_value(t, len(unresolved), 2)
	testing.expect_value(t, len(p.rules), 2)
	testing.expect(t, allowed(&p, creds(1000, 1), "peer.kick"))
	testing.expect(t, allowed(&p, creds(1, 10), "daemon.reload"))
	testing.expect(t, !allowed(&p, creds(1, 1), "status"))
}

@(test)
policy_with_only_unresolved_names_denies_all :: proc(t: ^testing.T) {
	rules := []config.Bus_Allow{{kind = .Uid, name = "ghost", roles = {.Admin}}}
	p, unresolved := unix_policy(rules, 5)
	defer policy_destroy(&p)
	defer delete(unresolved)
	testing.expect_value(t, len(unresolved), 1)
	// Not the default policy: an empty one.
	testing.expect_value(t, len(p.rules), 0)
	testing.expect(t, !allowed(&p, creds(0, 0), "status"))
}

@(test)
policy_clone_is_independent :: proc(t: ^testing.T) {
	p, u := unix_policy(nil, 5)
	defer delete(u)
	c := policy_clone(p)
	policy_destroy(&p)
	defer policy_destroy(&c)
	testing.expect(t, allowed(&c, creds(0, 0), "status"))
}
