// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import cnet "core:net"
import "core:sync"
import "core:thread"
import "core:time"
import "noir:platform/event"

// The host names of the `forward` targets, looked up on a helper thread of the
// relay (the thread is not the one of `acl_lookup.odin`):
//
//	a connection or session needs a name -> fwd_resolve: the line is asked for
//	helper thread: guest_lookup -> result in `res`
//	loop timer (FWD_LOOKUP_POLL while a lookup runs) -> fwd_on_look
//	    -> the result is kept for `lookup_ttl`, and the waiting connections go on
//	    -> or they fail (a failed lookup is not kept)
//
// The event loop has no hook that a wake-up from another thread can run, so the
// loop polls with a short timer while a lookup is pending.

FWD_LOOKUP_POLL :: 5 * time.Millisecond

Fwd_Res :: struct {
	addrs: [FWD_MAX_ADDRS]cnet.Address,
	n:     int,
	ok:    bool,
	done:  bool,
}

Fwd_Lookup :: struct {
	th:      ^thread.Thread,
	sema:    sync.Sema,
	mu:      sync.Mutex,
	started: bool,
	// Under `mu`.
	stop:    bool,
	req:     []bool,
	res:     []Fwd_Res,
}

fwd_lookup_init :: proc(fw: ^Fwd) {
	fw.lk.req = make([]bool, len(fw.lines))
	fw.lk.res = make([]Fwd_Res, len(fw.lines))
}

fwd_lookup_destroy :: proc(fw: ^Fwd) {
	lk := &fw.lk
	timer_clear(fw.d, &fw.t_look)
	if lk.started {
		sync.mutex_lock(&lk.mu)
		lk.stop = true
		sync.mutex_unlock(&lk.mu)
		sync.sema_post(&lk.sema)
		// A lookup in progress ends first (at most the resolver timeout).
		thread.join(lk.th)
		thread.destroy(lk.th)
	}
	delete(lk.req)
	delete(lk.res)
	lk^ = {}
}

// Asks for the addresses of the name of line `i`. Connections that arrive while
// the lookup runs wait for it.
fwd_resolve :: proc(fw: ^Fwd, i: int) {
	line := &fw.lines[i]
	if line.pending {
		return
	}
	lk := &fw.lk
	line.pending = true
	fw.lookups += 1
	if !lk.started {
		lk.th = thread.create_and_start_with_data(fw, fwd_lookup_main)
		lk.started = true
	}
	sync.mutex_lock(&lk.mu)
	lk.req[i] = true
	sync.mutex_unlock(&lk.mu)
	sync.sema_post(&lk.sema)
	timer_set(fw.d, &fw.t_look, now_of(fw.d) + FWD_LOOKUP_POLL, fwd_on_look)
}

@(private = "file")
fwd_lookup_main :: proc(data: rawptr) {
	fw := (^Fwd)(data)
	lk := &fw.lk
	for {
		sync.sema_wait(&lk.sema)
		for {
			job := -1
			sync.mutex_lock(&lk.mu)
			stop := lk.stop
			if !stop {
				for r, i in lk.req {
					if r {
						job = i
						lk.req[i] = false
						break
					}
				}
			}
			sync.mutex_unlock(&lk.mu)
			if stop {
				return
			}
			if job < 0 {
				break
			}
			f := fw.lines[job].f
			res: Fwd_Res
			addrs, ok := guest_lookup(Res_Job{host = f.host, port = f.host_port, family = .Any})
			res.ok = ok && len(addrs) > 0
			for a in addrs {
				if res.n == FWD_MAX_ADDRS {
					break
				}
				res.addrs[res.n] = a
				res.n += 1
			}
			delete(addrs)
			res.done = true
			sync.mutex_lock(&lk.mu)
			lk.res[job] = res
			sync.mutex_unlock(&lk.mu)
		}
	}
}

// Takes the results of finished lookups. The waiting connections go on, or fail.
@(private = "file")
fwd_on_look :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	fw := d.fwd
	if fw == nil {
		return
	}
	fw.t_look.on = false
	lk := &fw.lk
	now := now_of(d)
	waiting := false
	for &line, i in fw.lines {
		if !line.pending {
			continue
		}
		sync.mutex_lock(&lk.mu)
		r := lk.res[i]
		lk.res[i].done = false
		sync.mutex_unlock(&lk.mu)
		if !r.done {
			waiting = true
			continue
		}
		line.pending = false
		if r.ok {
			line.addrs = r.addrs
			line.n = r.n
			line.until = now + fw.lookup_ttl
		} else {
			logf(.Debug, "forward: cannot look up %s", line.f.host)
		}
		fwd_lookup_done(fw, i, r.ok)
	}
	if waiting {
		timer_set(d, &fw.t_look, now + FWD_LOOKUP_POLL, fwd_on_look)
	}
}

// The lookup of line `i` ended: the connections and sessions that wait for it.
@(private = "file")
fwd_lookup_done :: proc(fw: ^Fwd, i: int, ok: bool) {
	for k := len(fw.conns) - 1; k >= 0; k -= 1 {
		c := fw.conns[k]
		if c.line != i || c.state != .Resolving {
			continue
		}
		if ok {
			fwd_conn_start(c)
		} else {
			fwd_conn_close(c, .Lookup_Failed)
		}
	}
	for k := len(fw.udp) - 1; k >= 0; k -= 1 {
		s := fw.udp[k]
		if s.line != i || s.open {
			continue
		}
		if ok {
			fwd_udp_open(s)
		} else {
			fwd_udp_close(s, .Lookup_Failed)
		}
	}
}
