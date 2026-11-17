// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:testing"
import "noir:proto/config"

@(test)
sid_text_round_trip :: proc(t: ^testing.T) {
	for text in ([]string{"S-1-5-18", "S-1-5-32-544", "S-1-5-21-3623811015-3361044348-30300820-1013", "S-1-16-12288", "S-1-0x123456789ABC-7"}) {
		s, ok := sid_parse(text)
		testing.expectf(t, ok, "%s parses", text)
		back := sid_string(s, context.temp_allocator)
		if text[4] == '0' {
			testing.expect_value(t, back, "S-1-0x123456789abc-7")
		} else {
			testing.expect_value(t, back, text)
		}
	}
	sys, _ := sid_parse("S-1-5-18")
	testing.expect_value(t, sys.len, 12)
	testing.expect_value(t, sys.data[1], 1)
	testing.expect_value(t, sys.data[7], 5)
	testing.expect_value(t, sys.data[8], 18)
	b, bok := sid_from_bytes(sid_bytes(&sys))
	testing.expect(t, bok && sid_equal(b, sys))

	for bad in ([]string{"", "S-1", "S-1-5", "S-2-5-18", "X-1-5-18", "S-1-5-18-", "S-1-5--18", "S-1-5-4294967296", "S-1-281474976710656-1", "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16", "S-1-5-1a"}) {
		_, ok := sid_parse(bad)
		testing.expectf(t, !ok, "'%s' is refused", bad)
	}
	_, ok := sid_from_bytes({1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0})
	testing.expect(t, !ok)
}

@(private = "file")
fake_sid_resolver :: proc(name: string) -> (sid: Sid, ok: bool) {
	if name == `BUILTIN\Users` {
		return sid_parse("S-1-5-32-545")
	}
	return {}, false
}

@(private = "file")
no_ids :: proc(kind: config.Bus_Id_Kind, name: string) -> (id: u32, ok: bool) {
	return 0, false
}

@(test)
windows_policy_default :: proc(t: ^testing.T) {
	p, u := policy_build(nil, 0, true, no_ids, fake_sid_resolver)
	defer policy_destroy(&p)
	defer delete(u)
	system := must_sid(SID_LOCAL_SYSTEM)
	admins := must_sid(SID_ADMINISTRATORS)
	user := must_sid("S-1-5-21-1-2-3-1001")
	users := must_sid("S-1-5-32-545")
	testing.expect_value(t, roles_for_sids(&p, system, nil), ALL_ROLES)
	testing.expect_value(t, roles_for_sids(&p, user, {users, admins}), ALL_ROLES)
	// The Administrators group of a user who is not elevated is deny-only:
	// the token reader leaves it out, so there is no role.
	testing.expect_value(t, roles_for_sids(&p, user, {users}), Roles{})
	// uid and gid rules do not count on Windows: the default stays.
	allow := []config.Bus_Allow{{kind = .Uid, id = 0, roles = {.Admin}}}
	p2, u2 := policy_build(allow, 0, true, no_ids, fake_sid_resolver)
	defer policy_destroy(&p2)
	defer delete(u2)
	testing.expect_value(t, len(p2.rules), 2)
	testing.expect_value(t, roles_for_sids(&p2, system, nil), ALL_ROLES)
}

@(test)
windows_policy_rules :: proc(t: ^testing.T) {
	allow := []config.Bus_Allow {
		{kind = .Sid, name = "S-1-5-21-1-2-3-1001", roles = {.Operator}},
		{kind = .Sid, name = `BUILTIN\Users`, roles = {.Read}},
		{kind = .Sid, name = "S-1-5-32-544", roles = {.Admin}},
		{kind = .Sid, name = "nobody", roles = {.Read}},
		{kind = .Sid, name = "S-1-5-x", roles = {.Read}},
		{kind = .Gid, id = 10, roles = {.Admin}},
	}
	p, u := policy_build(allow, 0, true, no_ids, fake_sid_resolver)
	defer policy_destroy(&p)
	defer delete(u)
	testing.expect_value(t, len(u), 2)
	testing.expect_value(t, len(p.rules), 3)
	alice := must_sid("S-1-5-21-1-2-3-1001")
	bob := must_sid("S-1-5-21-1-2-3-1002")
	users := must_sid("S-1-5-32-545")
	admins := must_sid(SID_ADMINISTRATORS)
	testing.expect_value(t, roles_for_sids(&p, alice, {users}), Roles{.Operator, .Read})
	testing.expect_value(t, roles_for_sids(&p, bob, {users}), Roles{.Read})
	testing.expect_value(t, roles_for_sids(&p, bob, nil), Roles{})
	testing.expect_value(t, roles_for_sids(&p, bob, {admins}), ALL_ROLES)
	// LocalSystem has no default once there are rules.
	testing.expect_value(t, roles_for_sids(&p, must_sid(SID_LOCAL_SYSTEM), nil), Roles{})
	// The SIDs for the access list of the pipes, each once.
	sids := policy_sids(&p, context.temp_allocator)
	testing.expect_value(t, len(sids), 3)
	// The sid rules give nothing to a uid.
	testing.expect_value(t, roles_for(&p, 0, 0), Roles{})
}

@(test)
unix_ignores_sid_rules :: proc(t: ^testing.T) {
	allow := []config.Bus_Allow{{kind = .Sid, name = "S-1-5-18", roles = {.Admin}}, {kind = .Sid, name = "bad", roles = {.Read}}}
	p, u := policy_build(allow, 1000, false, no_ids, nil)
	defer policy_destroy(&p)
	defer delete(u)
	// Not counted: the Unix default applies, and nothing is unresolved.
	testing.expect_value(t, len(u), 0)
	testing.expect_value(t, roles_for(&p, 1000, 1000), ALL_ROLES)
	testing.expect_value(t, roles_for_sids(&p, must_sid(SID_LOCAL_SYSTEM), nil), Roles{})
}
