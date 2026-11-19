// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:strings"
import "noir:bus"
import "noir:proto/acl"
import "noir:proto/config"
import "noir:proto/push"
import "noir:proto/session"

// The `allow-inbound` and `forward` rules on the bus, and a reload of them from
// the config file.
//
//	acl.get                      -> op_acl_get: the rules in force and their source
//	acl.reload, daemon.reload    -> the host reads the config file -> acl_reload
//	    the base lines: owned copies (Acl_Own) that the base config points to
//	    acl_merge: the base lines, else the lines of the profile (service, A8)
//	    the filter: rules in place, or a new filter, or none
//	    the relay: closed and opened again when the forward lines changed
//
// The base config is `d.cfgw.client`: the config file, or the base config of a
// service. A config file daemon has `d.cfg` on it; a service has `d.cfg` on
// the profile while one is loaded.

// The lines of the last reload. Before the first reload the base config points
// into the memory of its own build.
Acl_Own :: struct {
	rules:    []acl.Rule,
	hosts:    []string, // each one allocated
	forwards: []config.Forward, // each host allocated
}

// What a reload changed.
Acl_Change :: struct {
	rules:     bool, // the allow-inbound lines
	forwards:  bool,
	interval:  bool, // acl-resolve-interval
	max_conns: bool, // forward-max-conns
	closed:    int, // relay connections that the change closed
	max_flows: bool, // acl-max-flows is different: it needs a restart
}

acl_change_any :: proc(ch: Acl_Change) -> bool {
	return ch.rules || ch.forwards
}

acl_own_destroy :: proc(o: ^Acl_Own) {
	acl_own_rules_free(o)
	acl_own_forwards_free(o)
}

@(private = "file")
acl_own_rules_free :: proc(o: ^Acl_Own) {
	for h in o.hosts {
		delete(h)
	}
	delete(o.hosts)
	delete(o.rules)
	o.rules, o.hosts = nil, nil
}

@(private = "file")
acl_own_forwards_free :: proc(o: ^Acl_Own) {
	for f in o.forwards {
		delete(f.host)
	}
	delete(o.forwards)
	o.forwards = nil
}

// The filter and the relay of `d.cfg` exist: a config file daemon, or a
// service with a profile.
@(private = "file")
acl_active :: proc(d: ^Daemon) -> bool {
	return !d.service || d.prof_loaded
}

// The rules of a service profile: the base config wins when it has
// `allow-inbound` (A8). The forwards are always those of the base config.
acl_merge :: proc(d: ^Daemon) {
	if !d.service || !d.prof_loaded {
		return
	}
	cl := d.cfg
	base := &d.cfgw.client
	if len(base.allow_inbound) > 0 {
		cl.allow_inbound, cl.acl_hosts = base.allow_inbound, base.acl_hosts
	} else {
		cl.allow_inbound, cl.acl_hosts = d.prof_allow, d.prof_acl_hosts
	}
	cl.acl_resolve_interval = base.acl_resolve_interval
	cl.forwards, cl.forward_max_conns = base.forwards, base.forward_max_conns
}

// "config" or "profile": where the rules in force come from.
@(private = "file")
acl_source :: proc(d: ^Daemon) -> string {
	if d.service && d.prof_loaded && len(d.cfgw.client.allow_inbound) == 0 && len(d.prof_allow) > 0 {
		return "profile"
	}
	return "config"
}

// The destinations of the profile that the base config overrides.
@(private = "file")
acl_profile_ignored :: proc(d: ^Daemon) -> int {
	if d.service && d.prof_loaded && len(d.cfgw.client.allow_inbound) > 0 {
		return len(d.prof_allow)
	}
	return 0
}

// The rules are in force, and the connection runs on a data path outside this
// process, so the filter sees no packets until the next connection.
acl_pending :: proc(d: ^Daemon) -> bool {
	if len(d.cfg.allow_inbound) == 0 || d.state == .Idle {
		return false
	}
	name, ok := client_datapath(d)
	return ok && name != "userspace"
}

// ------------------------------------------------------------------- acl.get

op_acl_get :: proc(d: ^Daemon, r: ^Reply) {
	w := r.w
	cl := d.cfg
	filter := len(cl.allow_inbound) > 0
	src := acl_source(d)
	bus.kv_bool(w, "filter", filter)
	bus.kv_str_or_null(w, "source", src, filter)
	bus.kv_u64(w, "profile_ignored", u64(acl_profile_ignored(d)))
	bus.kv_bool(w, "pending", acl_pending(d))
	if d.acl != nil {
		bus.kv_u64(w, "denied", d.acl.a.stats.in_denied)
	} else {
		bus.kv_null(w, "denied")
	}
	words: [4]string
	bus.kv_arr(w, "rules")
	for rule in cl.allow_inbound {
		bus.begin_obj(w)
		bus.kv_str(w, "dest", config.acl_dest_text(rule, cl.acl_hosts, context.temp_allocator))
		bus.kv_arr(w, "protos")
		for p in config.acl_proto_words(rule.protos, &words) {
			bus.val_str(w, p)
		}
		bus.end(w)
		bus.kv_str(w, "source", src)
		if rule.target == .Host {
			bus.kv_arr(w, "addresses")
			if d.acl != nil && rule.host >= 0 && rule.host < len(d.acl.a.hosts) {
				h := &d.acl.a.hosts[rule.host]
				for a in h.addrs[:h.n] {
					bus.val_str(w, acl_addr_text(a, 4 if acl_is_mapped4(a) else 6))
				}
			}
			bus.end(w)
		}
		bus.end(w)
	}
	bus.end(w)
	bus.kv_arr(w, "forwards")
	for f in cl.forwards {
		bus.begin_obj(w)
		bus.kv_u64(w, "port", u64(f.port))
		bus.kv_arr(w, "protos")
		for p in config.acl_proto_words(f.protos, &words) {
			bus.val_str(w, p)
		}
		bus.end(w)
		bus.kv_str(w, "target", config.forward_target_text(f, context.temp_allocator))
		bus.end(w)
	}
	bus.end(w)
	reply_ok(r)
}

// ---------------------------------------------------------------- the reload

// Applies the `allow-inbound`, `forward`, `acl-resolve-interval` and
// `forward-max-conns` lines of `new`, a client config that the host read from
// the config file again. Flows that exist stay. `acl-max-flows` keeps its value.
acl_reload :: proc(d: ^Daemon, new: ^config.Client_Config) -> (ch: Acl_Change) {
	base := &d.cfgw.client
	ch.rules = !acl_rules_equal(base.allow_inbound, base.acl_hosts, new.allow_inbound, new.acl_hosts)
	ch.forwards = !acl_forwards_equal(base.forwards, new.forwards)
	ch.max_flows = base.acl_max_flows != new.acl_max_flows
	ch.interval = base.acl_resolve_interval != new.acl_resolve_interval
	ch.max_conns = base.forward_max_conns != new.forward_max_conns
	base.acl_resolve_interval = new.acl_resolve_interval
	base.forward_max_conns = new.forward_max_conns

	old := d.acl_own
	if ch.rules {
		d.acl_own.rules = make([]acl.Rule, len(new.allow_inbound))
		copy(d.acl_own.rules, new.allow_inbound)
		d.acl_own.hosts = make([]string, len(new.acl_hosts))
		for h, i in new.acl_hosts {
			d.acl_own.hosts[i] = strings.clone(h)
		}
		base.allow_inbound, base.acl_hosts = d.acl_own.rules, d.acl_own.hosts
	}
	if ch.forwards {
		d.acl_own.forwards = make([]config.Forward, len(new.forwards))
		for f, i in new.forwards {
			d.acl_own.forwards[i] = f
			d.acl_own.forwards[i].host = strings.clone(f.host)
		}
		base.forwards = d.acl_own.forwards
	}
	acl_merge(d)

	if acl_active(d) {
		if ch.rules || ch.forwards {
			acl_filter_apply(d)
		}
		if ch.forwards {
			ch.closed = forward_conns(d)
			forward_detach(d)
			forward_attach(d)
			if po := acl_live_pushed(d); po != nil {
				forward_up(d, po)
			}
		} else if d.fwd != nil {
			d.fwd.max = max(d.cfg.forward_max_conns, 1)
		}
	}
	// The filter and the relay hold no pointer into the old copies now.
	if ch.rules {
		acl_own_rules_free(&old)
	}
	if ch.forwards {
		acl_own_forwards_free(&old)
	}

	cl := d.cfg
	logf(
		.Notice,
		"reload: allow-inbound %d rule(s)%s, forward %d line(s)%s",
		len(cl.allow_inbound),
		" (changed)" if ch.rules else "",
		len(cl.forwards),
		" (changed)" if ch.forwards else "",
	)
	if ch.closed > 0 {
		logf(.Notice, "reload: the forward lines changed, so %d relay connection(s) closed", ch.closed)
	}
	if ch.max_flows {
		logf(.Notice, "reload: acl-max-flows changed, so a restart is needed")
	}
	if acl_pending(d) {
		logf(.Notice, "reload: the connection runs on %s, so allow-inbound applies at the next connection", daemon_datapath(d))
	}
	if acl_change_any(ch) {
		acl_ev_rules(d)
	}
	return
}

// The relay connections and UDP sessions that are open.
@(private = "file")
forward_conns :: proc(d: ^Daemon) -> int {
	if d.fwd == nil {
		return 0
	}
	return len(d.fwd.conns) + len(d.fwd.udp)
}

// The names for the `reloaded` list of `daemon.reload`.
acl_change_names :: proc(ch: Acl_Change, out: ^[dynamic]string) {
	if ch.rules {
		append(out, "allow-inbound")
	}
	if ch.forwards {
		append(out, "forward")
	}
	if ch.interval {
		append(out, "acl-resolve-interval")
	}
	if ch.max_conns {
		append(out, "forward-max-conns")
	}
}

// The pushed options of a tunnel that is up, else nil.
@(private = "file")
acl_live_pushed :: proc(d: ^Daemon) -> ^push.Pushed_Options {
	if d.up && d.s_ok {
		return session.session_pushed(&d.s)
	}
	return nil
}

// Makes the filter match `d.cfg`: new rules in place, a new filter, or none.
@(private = "file")
acl_filter_apply :: proc(d: ^Daemon) {
	cl := d.cfg
	want := len(cl.allow_inbound) > 0
	switch {
	case !want:
		if d.acl != nil {
			acl_detach(d)
			logf(.Notice, "reload: no allow-inbound line, so every connection from the tunnel passes")
		}
	case d.acl == nil:
		acl_attach(d)
		if po := acl_live_pushed(d); po != nil && d.acl != nil {
			// A flow that the client started before is added again by its next
			// outbound packet.
			acl_set_tunnel(d, po)
		}
	case:
		acl_rules_replace(d)
	}
}

// The new rules of `d.cfg` in the filter that exists. A name that stays keeps
// its addresses; a new list of names starts a new round of lookups.
@(private = "file")
acl_rules_replace :: proc(d: ^Daemon) {
	st := d.acl
	cl := d.cfg
	rules := acl_rule_list(cl)
	hosts := make([]acl.Host, len(cl.acl_hosts), context.temp_allocator)
	same := len(cl.acl_hosts) == len(st.lk.names)
	for name, i in cl.acl_hosts {
		for old, j in st.lk.names {
			if strings.equal_fold(old, name) && j < len(st.a.hosts) {
				hosts[i] = st.a.hosts[j]
			}
		}
		same = same && strings.equal_fold(st.lk.names[i], name)
	}
	acl.set_rules(&st.a, rules, hosts)
	if !same {
		acl_lookup_destroy(d, st)
		acl_lookup_init(st, cl.acl_hosts)
		if d.up {
			acl_lookup_now(d)
		}
	}
	logf(.Info, "allow-inbound: %d rule(s) in place of the old ones; flows that exist stay", len(rules))
}

// The rules of the filter: the `allow-inbound` destinations, and one rule for
// the tunnel addresses for each forward port. In the temp allocator.
acl_rule_list :: proc(cl: ^config.Client_Config) -> []acl.Rule {
	rules := make([dynamic]acl.Rule, 0, len(cl.allow_inbound) + len(cl.forwards), context.temp_allocator)
	append(&rules, ..cl.allow_inbound)
	for f in cl.forwards {
		append(&rules, acl.Rule{target = .Tunnel, port_lo = f.port, port_hi = f.port, protos = f.protos})
	}
	return rules[:]
}

@(private = "file")
acl_rules_equal :: proc(a: []acl.Rule, ah: []string, b: []acl.Rule, bh: []string) -> bool {
	if len(a) != len(b) {
		return false
	}
	for ra, i in a {
		x, y := ra, b[i]
		if x.target == .Host && y.target == .Host {
			if x.host < 0 || x.host >= len(ah) || y.host < 0 || y.host >= len(bh) || !strings.equal_fold(ah[x.host], bh[y.host]) {
				return false
			}
			x.host, y.host = 0, 0
		}
		if x != y {
			return false
		}
	}
	return true
}

@(private = "file")
acl_forwards_equal :: proc(a, b: []config.Forward) -> bool {
	if len(a) != len(b) {
		return false
	}
	for x, i in a {
		y := b[i]
		if x.port != y.port || x.protos != y.protos || x.host_port != y.host_port || x.host != y.host {
			return false
		}
	}
	return true
}

// The event `acl.rules`: a reload changed the rules or the forwards.
@(private = "file")
acl_ev_rules :: proc(d: ^Daemon) {
	w := ev_begin(d)
	if w == nil {
		return
	}
	cl := d.cfg
	filter := len(cl.allow_inbound) > 0
	bus.kv_bool(w, "filter", filter)
	bus.kv_str_or_null(w, "source", acl_source(d), filter)
	bus.kv_u64(w, "rules", u64(len(cl.allow_inbound)))
	bus.kv_u64(w, "forwards", u64(len(cl.forwards)))
	bus.kv_bool(w, "pending", acl_pending(d))
	ev_emit(d, "acl.rules")
}

// The result of `acl.reload`, after `acl_reload`.
acl_write_reload :: proc(w: ^bus.Writer, d: ^Daemon, ch: Acl_Change) {
	cl := d.cfg
	bus.kv_bool(w, "changed", acl_change_any(ch))
	bus.kv_bool(w, "filter", len(cl.allow_inbound) > 0)
	bus.kv_u64(w, "rules", u64(len(cl.allow_inbound)))
	bus.kv_u64(w, "forwards", u64(len(cl.forwards)))
	bus.kv_bool(w, "pending", acl_pending(d))
	bus.kv_u64(w, "closed", u64(ch.closed))
	bus.kv_arr(w, "ignored")
	if ch.max_flows {
		bus.val_str(w, "acl-max-flows")
	}
	bus.end(w)
}

// The `details` of a config file with errors, as `profile.check` gives them,
// in the temp allocator. At most `PROBLEMS_MAX` entries.
acl_config_details :: proc(diags: []config.Diagnostic, fallback: string) -> []u8 {
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_arr(&w)
	n := 0
	for g in diags {
		if g.severity != .Error || n == PROBLEMS_MAX {
			continue
		}
		option, reason := "", g.message
		if i := strings.index(g.message, ": "); i > 0 && strings.index_byte(g.message[:i], ' ') < 0 {
			option, reason = g.message[:i], g.message[i + 2:]
		}
		bus.begin_obj(&w)
		bus.kv_int(&w, "line", i64(g.line))
		bus.kv_str(&w, "option", option)
		bus.kv_str(&w, "class", "invalid")
		bus.kv_str(&w, "reason", reason)
		bus.kv_str(&w, "file", g.file)
		bus.end(&w)
		n += 1
	}
	if n == 0 {
		bus.begin_obj(&w)
		bus.kv_int(&w, "line", 0)
		bus.kv_str(&w, "option", "")
		bus.kv_str(&w, "class", "invalid")
		bus.kv_str(&w, "reason", fallback)
		bus.end(&w)
	}
	bus.end(&w)
	return bus.writer_bytes(&w)
}
