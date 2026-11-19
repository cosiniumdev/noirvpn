// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import cnet "core:net"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "noir:platform/event"
import "noir:proto/acl"

// The names of the `allow-inbound` host rules, looked up on a helper thread:
//
//	tunnel up -> round: the thread looks up every name -> results
//	loop timer (1 s while a round runs) -> acl.set_host for each name
//	next round after `acl-resolve-interval` seconds
//
// The first round starts when the tunnel is up, so the name servers of the
// tunnel can answer. A failed lookup keeps the last addresses.

Acl_Host_Res :: struct {
	addrs: [acl.MAX_HOST_ADDRS]acl.Addr,
	n:     int,
	ok:    bool,
}

Acl_Lookup :: struct {
	th:      ^thread.Thread,
	sema:    sync.Sema,
	mu:      sync.Mutex,
	// Read-only while the thread runs.
	names:   []string,
	// Under `mu`.
	stop:    bool,
	net:     u64, // Android: the network of the round
	done:    bool,
	res:     []Acl_Host_Res,
	// Loop thread only.
	started: bool,
	pending: bool, // a round runs
	timer:   Timer,
	failed:  []bool, // the last lookup of the name failed (warned once)
}

@(private = "file")
LOOKUP_POLL :: time.Second

acl_lookup_init :: proc(st: ^Acl_State, names: []string) {
	lk := &st.lk
	// Copies: a reload frees the strings of the config.
	lk.names = make([]string, len(names))
	for n, i in names {
		lk.names[i] = strings.clone(n)
	}
	lk.res = make([]Acl_Host_Res, len(names))
	lk.failed = make([]bool, len(names))
}

acl_lookup_destroy :: proc(d: ^Daemon, st: ^Acl_State) {
	lk := &st.lk
	timer_clear(d, &lk.timer)
	if lk.started {
		sync.mutex_lock(&lk.mu)
		lk.stop = true
		sync.mutex_unlock(&lk.mu)
		sync.sema_post(&lk.sema)
		// A lookup in progress ends first (at most the resolver timeout).
		thread.join(lk.th)
		thread.destroy(lk.th)
	}
	for n in lk.names {
		delete(n)
	}
	delete(lk.names)
	delete(lk.res)
	delete(lk.failed)
	lk^ = {}
}

// Starts a round now, unless one runs. Called at each tunnel-up.
acl_lookup_now :: proc(d: ^Daemon) {
	st := d.acl
	if st == nil || len(st.lk.names) == 0 || st.lk.pending {
		return
	}
	lk := &st.lk
	if !lk.started {
		lk.th = thread.create_and_start_with_data(lk, acl_lookup_main)
		lk.started = true
	}
	sync.mutex_lock(&lk.mu)
	lk.net = d.guest.net_handle if d.guest != nil else 0
	sync.mutex_unlock(&lk.mu)
	sync.sema_post(&lk.sema)
	lk.pending = true
	timer_set(d, &lk.timer, now_of(d) + LOOKUP_POLL, on_acl_lookup_timer)
}

@(private = "file")
acl_lookup_main :: proc(data: rawptr) {
	lk := (^Acl_Lookup)(data)
	out := make([]Acl_Host_Res, len(lk.names))
	defer delete(out)
	for {
		sync.sema_wait(&lk.sema)
		sync.mutex_lock(&lk.mu)
		stop, network := lk.stop, lk.net
		sync.mutex_unlock(&lk.mu)
		if stop {
			return
		}
		for name, i in lk.names {
			out[i] = {}
			addrs, ok := guest_lookup(Res_Job{host = name, family = .Any, net = network})
			out[i].ok = ok && len(addrs) > 0
			for a in addrs {
				if out[i].n == acl.MAX_HOST_ADDRS {
					break
				}
				switch v in a {
				case cnet.IP4_Address:
					b := v
					out[i].addrs[out[i].n] = acl.map4(b[:])
				case cnet.IP6_Address:
					out[i].addrs[out[i].n] = transmute(acl.Addr)v
				}
				out[i].n += 1
			}
			delete(addrs)
		}
		sync.mutex_lock(&lk.mu)
		copy(lk.res, out)
		lk.done = true
		sync.mutex_unlock(&lk.mu)
	}
}

@(private = "file")
on_acl_lookup_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	st := d.acl
	if st == nil {
		return
	}
	lk := &st.lk
	lk.timer.on = false
	if !lk.pending {
		acl_lookup_now(d)
		return
	}
	sync.mutex_lock(&lk.mu)
	done := lk.done
	res := make([]Acl_Host_Res, len(lk.res), context.temp_allocator)
	if done {
		copy(res, lk.res)
		lk.done = false
	}
	sync.mutex_unlock(&lk.mu)
	if !done {
		timer_set(d, &lk.timer, now_of(d) + LOOKUP_POLL, on_acl_lookup_timer)
		return
	}
	lk.pending = false
	for &r, i in res {
		name := lk.names[i]
		if !r.ok {
			if !lk.failed[i] {
				logf(.Warn, "allow-inbound: cannot look up %s, so its rules keep the addresses of the last lookup", name)
				lk.failed[i] = true
			}
			continue
		}
		lk.failed[i] = false
		h := &st.a.hosts[i]
		if h.n == r.n && slice_equal(h.addrs[:h.n], r.addrs[:r.n]) {
			continue
		}
		acl.set_host(&st.a, i, r.addrs[:r.n])
		logf(.Info, "allow-inbound: %s has %d address(es): %s", name, r.n, acl_addrs_text(r.addrs[:r.n]))
	}
	interval := time.Duration(d.cfg.acl_resolve_interval) * time.Second
	timer_set(d, &lk.timer, now_of(d) + interval, on_acl_lookup_timer)
}

@(private = "file")
slice_equal :: proc(a, b: []acl.Addr) -> bool {
	if len(a) != len(b) {
		return false
	}
	for x, i in a {
		if x != b[i] {
			return false
		}
	}
	return true
}

acl_is_mapped4 :: proc "contextless" (a: acl.Addr) -> bool {
	for i in 0 ..< 10 {
		if a[i] != 0 {
			return false
		}
	}
	return a[10] == 0xff && a[11] == 0xff
}

// "a, b, c" in the temp allocator.
@(private = "file")
acl_addrs_text :: proc(addrs: []acl.Addr) -> string {
	b := make([dynamic]u8, context.temp_allocator)
	for a, i in addrs {
		if i > 0 {
			append(&b, ", ")
		}
		append(&b, acl_addr_text(a, 4 if acl_is_mapped4(a) else 6))
	}
	return string(b[:])
}
