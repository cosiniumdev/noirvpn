// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Who may call what. The daemon builds a `Policy` once from the `bus-allow`
// lines. The control server asks it for the roles of each request sender.
// Checked: the uid and ONE gid that nng reads from the socket (the effective
// group of the peer process at connect).
//   - A `gid` rule matches that gid, or a user in the group database
//     (`Member_Check`), so a supplementary group needs no `sg`.
//   - Roles are the union of all matching rules.
// Windows uses `sid` rules (user SID of the client token or an enabled group).
// Each system ignores the other kind (uid/gid on Windows, sid on Unix).

import "core:mem"
import "noir:proto/config"

Rule :: struct {
	kind:  config.Bus_Id_Kind,
	id:    u32,
	// Only for `.Sid`.
	sid:   Sid,
	roles: Roles,
}

// Turns a Windows account name into a SID. Returns false if unknown.
Sid_Resolver :: proc(name: string) -> (sid: Sid, ok: bool)

Policy :: struct {
	rules:     [dynamic]Rule,
	allocator: mem.Allocator,
}

// Turns a user or group name into a number. Returns false if unknown.
Resolver :: proc(kind: config.Bus_Id_Kind, name: string) -> (id: u32, ok: bool)

// Build the policy from the config.
//   - No `bus-allow` lines: admin for uid 0 and the daemon's euid, nobody else.
//     Windows: admin for LocalSystem and Administrators.
//   - Some lines: only those count (add `bus-allow uid 0 admin` to keep root).
//     Lines of the other system's kind do not count.
// Names are looked up with `resolve` (`resolve_sid` on Windows). A name not
// found, or a bad SID, is left out and returned in `unresolved` (config
// strings, not copies; free the slice). The daemon should fail at startup:
// the rule would silently grant nothing.
policy_from_config :: proc(
	allow: []config.Bus_Allow,
	euid: u32,
	resolve: Resolver = default_resolver,
	allocator := context.allocator,
	resolve_sid: Sid_Resolver = default_sid_resolver,
) -> (
	p: Policy,
	unresolved: [dynamic]string,
) {
	return policy_build(allow, euid, ODIN_OS == .Windows, resolve, resolve_sid, allocator)
}

// `policy_from_config` for the rules of Unix (`windows` false) or of Windows.
policy_build :: proc(
	allow: []config.Bus_Allow,
	euid: u32,
	windows: bool,
	resolve: Resolver,
	resolve_sid: Sid_Resolver,
	allocator := context.allocator,
) -> (
	p: Policy,
	unresolved: [dynamic]string,
) {
	p.allocator = allocator
	p.rules = make([dynamic]Rule, allocator)
	unresolved = make([dynamic]string, allocator)
	for a in allow {
		if (a.kind == .Sid) != windows {
			continue
		}
		if a.kind == .Sid {
			sid: Sid
			found: bool
			if looks_like_sid(a.name) {
				sid, found = sid_parse(a.name)
			} else if resolve_sid != nil {
				sid, found = resolve_sid(a.name)
			}
			if !found {
				append(&unresolved, a.name)
				continue
			}
			append(&p.rules, Rule{kind = .Sid, sid = sid, roles = a.roles})
			continue
		}
		id := a.id
		if a.name != "" {
			found: bool
			id, found = resolve(a.kind, a.name)
			if !found {
				append(&unresolved, a.name)
				continue
			}
		}
		append(&p.rules, Rule{kind = a.kind, id = id, roles = a.roles})
	}
	if len(p.rules) > 0 || len(unresolved) > 0 {
		return
	}
	if windows {
		append(&p.rules, Rule{kind = .Sid, sid = must_sid(SID_LOCAL_SYSTEM), roles = {.Admin}})
		append(&p.rules, Rule{kind = .Sid, sid = must_sid(SID_ADMINISTRATORS), roles = {.Admin}})
		return
	}
	append(&p.rules, Rule{kind = .Uid, id = 0, roles = {.Admin}})
	if euid != 0 {
		append(&p.rules, Rule{kind = .Uid, id = euid, roles = {.Admin}})
	}
	return
}

policy_destroy :: proc(p: ^Policy) {
	delete(p.rules)
	p^ = {}
}

// A copy that owns its rules, for handing a policy to the bus.
policy_clone :: proc(p: Policy, allocator := context.allocator) -> (c: Policy) {
	c.allocator = allocator
	c.rules = make([dynamic]Rule, 0, len(p.rules), allocator)
	append(&c.rules, ..p.rules[:])
	return
}

// The roles a client holds, with implied roles added (admin is everything,
// operator and auth include read).
roles_for :: proc(p: ^Policy, uid, gid: u32) -> (r: Roles) {
	for rule in p.rules {
		switch rule.kind {
		case .Uid:
			if rule.id == uid {
				r += rule.roles
			}
		case .Gid:
			if rule.id == gid {
				r += rule.roles
			}
		case .Sid:
		}
	}
	return roles_effective(r)
}

// The roles of a Windows client: the `sid` rules that match the user SID or
// one of `groups`. Only enabled groups may be in `groups` (a deny-only
// Administrators group must not give admin).
roles_for_sids :: proc(p: ^Policy, user: Sid, groups: []Sid) -> (r: Roles) {
	for rule in p.rules {
		if rule.kind != .Sid {
			continue
		}
		if sid_equal(rule.sid, user) {
			r += rule.roles
			continue
		}
		for g in groups {
			if sid_equal(rule.sid, g) {
				r += rule.roles
				break
			}
		}
	}
	return roles_effective(r)
}

// The SIDs of the `sid` rules, for the access list of the pipes. Allocated
// with `allocator`; a SID is listed once.
policy_sids :: proc(p: ^Policy, allocator := context.allocator) -> [dynamic]Sid {
	out := make([dynamic]Sid, allocator)
	next: for rule in p.rules {
		if rule.kind != .Sid {
			continue
		}
		for s in out {
			if sid_equal(s, rule.sid) {
				continue next
			}
		}
		append(&out, rule.sid)
	}
	return out
}

// True if the user `uid` is a member of the group `gid` in the group database
// of the system. The host calls it from a worker thread, with no lock held.
Member_Check :: proc(uid, gid: u32) -> bool

// The `gid` rules that the gid of the peer does not match and that would add a
// role to `have`. The caller asks `Member_Check` for each of them, outside the
// lock of the host (a lookup can read files).
roles_group_rules :: proc(p: ^Policy, gid: u32, have: Roles, out: ^[dynamic]Rule) {
	clear(out)
	for rule in p.rules {
		if rule.kind == .Gid && rule.id != gid && rule.roles - have != {} {
			append(out, rule)
		}
	}
}

// Adds the roles of the `gid` rules in `rules` whose group has `uid` as a member.
roles_with_groups :: proc(have: Roles, uid: u32, rules: []Rule, member: Member_Check) -> Roles {
	r := have
	if member == nil {
		return r
	}
	for rule in rules {
		if rule.roles - roles_effective(r) == {} {
			continue
		}
		if member(uid, rule.id) {
			r += rule.roles
		}
	}
	return roles_effective(r)
}

// May this client call this operation? False for an unknown operation. Only
// the uid and the gid of the socket count here. The host also asks for the
// groups of the user.
allowed :: proc(p: ^Policy, creds: Peer_Creds, op: string) -> bool {
	info, found := op_lookup(op)
	if !found {
		return false
	}
	return roles_allow(roles_for(p, creds.uid, creds.gid), info.role)
}
