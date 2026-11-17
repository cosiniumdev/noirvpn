// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "base:intrinsics"
import "core:mem"
import "core:os"
import "core:sync"
import "core:thread"
import "core:time"
import "noir:bus"
import "noir:platform/event"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/session"
import "noir:server"

// The hash file check (`peer-passwords`).
//
//   login   srv_auth_request: decision `Pending_Password`
//             -> srv_pw_begin: password copied to a job and wiped in the
//                session; the session waits (`c.pw_wait`)
//             -> a worker thread runs PBKDF2 and compares
//             -> srv_pw_drain (event loop): pass, or fail and wait PW_DELAY
//             -> srv_pw_pass: `server_password_passed`, then login or park
//   rekey   srv_rekey_request: the same check for the session's user name
//   reload  srv_pw_reload: new table; sessions of removed or changed users end
//
// - PBKDF2 never runs on the event loop; at most PW_WORKERS checks run at once.
// - Logins and rekeys have own queues and bounds, so a login flood cannot fill
//   the place of a rekey. With both queues loaded: 3 logins, then 1 rekey. An
//   empty queue gives way to the other.
// - A full queue refuses a new check as a temporary failure.
// - An unknown user (or no file) gets a decoy check of the cost of the file's
//   lines, so the time does not tell.
// - A failed check waits PW_DELAY on a timer (no worker held) before refusal.
//
// The password is in a job from `srv_pw_begin` until the worker has compared.
// The worker wipes it; so does the cancel of a queued job. It is never logged
// and never on the bus.

PW_WORKERS_MAX :: 8
// Checks that wait, for each kind.
PW_LOGIN_QUEUE_MAX :: 64
PW_REKEY_QUEUE_MAX :: 256
// With both queues loaded: this many logins, then one rekey.
PW_LOGINS_PER_REKEY :: 3
// A failed check is refused this long after it ends.
PW_DELAY :: 2 * time.Second
// The file is looked at this often.
PW_POLL :: 1 * time.Second

Pw_Job_State :: enum u8 {
	Queued,
	Running,
	Done,
}

Pw_Job :: struct {
	next:       ^Pw_Job,
	state:      Pw_Job_State, // under the lock
	cancelled:  bool, // under the lock: the session is gone, the result is not wanted
	rekey:      bool,
	cidx:       u32,
	sess:       u64,
	password:   [push.PASSWORD_MAX_LEN]u8,
	password_n: int,
	decoy:      bool,
	iterations: int,
	salt:       [server.PW_SALT_MAX]u8,
	salt_n:     int,
	hash:       [server.PW_HASH_MAX]u8,
	hash_n:     int,
	ok:         bool,
	// The entry the check ran against: the name as the file spells it, and a
	// digest of its line. Empty for a decoy.
	form:       server.Identity,
	line:       [32]u8,
}

Pw_Queue :: struct {
	head, tail: ^Pw_Job,
	n:          int,
}

pq_push :: proc(q: ^Pw_Queue, j: ^Pw_Job) {
	j.next = nil
	if q.tail != nil {
		q.tail.next = j
	} else {
		q.head = j
	}
	q.tail = j
	q.n += 1
}

pq_pop :: proc(q: ^Pw_Queue) -> ^Pw_Job {
	j := q.head
	if j == nil {
		return nil
	}
	q.head = j.next
	if q.head == nil {
		q.tail = nil
	}
	j.next = nil
	q.n -= 1
	return j
}

// Takes `j` out of the queue. False when it is not in it.
pq_remove :: proc(q: ^Pw_Queue, j: ^Pw_Job) -> bool {
	prev: ^Pw_Job
	for it := q.head; it != nil; it = it.next {
		if it == j {
			if prev == nil {
				q.head = it.next
			} else {
				prev.next = it.next
			}
			if q.tail == it {
				q.tail = prev
			}
			it.next = nil
			q.n -= 1
			return true
		}
		prev = it
	}
	return false
}

Pw_State :: struct {
	on:         bool, // `peer-passwords` is set
	path:       string, // borrowed from the config
	table:      ^server.Pw_Table, // nil: no file (every check fails)
	lost:       bool,
	loaded:     Crl_Stat,
	last_ns:    i64,
	t_poll:     Timer,
	// The checks that run or wait, counted on the event loop.
	waiting:    int,
	// The pool.
	loop:       ^event.Loop,
	mu:         sync.Mutex,
	sema:       sync.Sema,
	logins:     Pw_Queue,
	rekeys:     Pw_Queue,
	login_run:  int, // logins picked in a row while a rekey waited
	done:       Pw_Queue,
	done_n:     int, // atomic: jobs in `done`
	stopping:   bool, // under the lock
	threads:    [PW_WORKERS_MAX]^thread.Thread,
	n_threads:  int,
}

// ------------------------------------------------------------------ the file

// Reads and parses the hash file. A table (with warnings) or nil and the
// reason (temp allocated). A file that is too large is not read.
pw_read_file :: proc(path: string) -> (t: ^server.Pw_Table, why: string) {
	st := crl_stat(path)
	if !st.ok {
		return nil, crl_stat_why(path)
	}
	if st.size > server.PW_FILE_MAX {
		return nil, "the file is too large"
	}
	data, err := os.read_entire_file(path, context.allocator)
	if err != nil {
		delete(data)
		return nil, crl_stat_why(path)
	}
	defer delete(data)
	if len(data) > server.PW_FILE_MAX {
		return nil, "the file is too large"
	}
	return server.pw_parse(string(data)), ""
}

pw_log_warnings :: proc(t: ^server.Pw_Table, path: string) {
	for w in t.warnings {
		logf(.Warn, "peer-passwords %s: %s", path, w)
	}
	if hidden := t.skipped + t.duplicates - len(t.warnings); hidden > 0 {
		logf(.Warn, "peer-passwords %s: %d more line(s) were skipped and are not listed", path, hidden)
	}
}

// ------------------------------------------------------------------- start

// Reads the file and starts the worker threads. False: the daemon cannot start
// (threads). An unreadable file is no error: every check fails until it can be read.
srv_pw_start :: proc(d: ^Srv) -> bool {
	p := &d.pw
	p.loop = &d.loop
	p.path = d.cfg.peer_passwords
	if p.path == "" {
		return true
	}
	p.on = true
	p.last_ns = time.tick_now()._nsec
	p.loaded = crl_stat(p.path)
	t, why := pw_read_file(p.path)
	if t == nil {
		p.lost = true
		logf(.Warn, "peer-passwords %s: cannot read the file: %s, so every password login will be refused until it can be loaded", p.path, why)
	} else {
		p.table = t
		pw_log_warnings(t, p.path)
		logf(.Notice, "peer-passwords %s: %d user(s)", p.path, server.pw_len(t))
	}
	if !pw_pool_start(p, min(PW_WORKERS_MAX, max(2, os.get_processor_core_count()))) {
		logf(.Error, "cannot start the password check threads")
		srv_pw_stop(d)
		return false
	}
	return true
}

// Starts `n` worker threads (at most PW_WORKERS_MAX).
pw_pool_start :: proc(p: ^Pw_State, n: int) -> bool {
	for _ in 0 ..< min(n, PW_WORKERS_MAX) {
		th := thread.create(pw_worker_main)
		if th == nil {
			return false
		}
		th.data = p
		p.threads[p.n_threads] = th
		p.n_threads += 1
		thread.start(th)
	}
	return true
}

// Stops the threads (a running check ends first) and frees what is left.
// Call it after the last session is gone.
srv_pw_stop :: proc(d: ^Srv) {
	p := &d.pw
	stimer_clear(&d.loop, &p.t_poll)
	pw_pool_stop(p)
	server.pw_destroy(p.table)
	p.table = nil
}

pw_pool_stop :: proc(p: ^Pw_State) {
	sync.mutex_lock(&p.mu)
	p.stopping = true
	sync.mutex_unlock(&p.mu)
	for _ in 0 ..< p.n_threads {
		sync.sema_post(&p.sema)
	}
	for i in 0 ..< p.n_threads {
		thread.join(p.threads[i])
		thread.destroy(p.threads[i])
		p.threads[i] = nil
	}
	p.n_threads = 0
	for q in ([]^Pw_Queue{&p.logins, &p.rekeys, &p.done}) {
		for j := pq_pop(q); j != nil; j = pq_pop(q) {
			pw_job_free(j)
		}
	}
	p.done_n = 0
}

pw_job_free :: proc(j: ^Pw_Job) {
	mem.zero_explicit(&j.password, size_of(j.password))
	free(j)
}

// ------------------------------------------------------------------ workers

@(private = "file")
pw_worker_main :: proc(t: ^thread.Thread) {
	p := (^Pw_State)(t.data)
	for {
		sync.sema_wait(&p.sema)
		sync.mutex_lock(&p.mu)
		j := pw_next(p)
		if j == nil {
			stop := p.stopping
			sync.mutex_unlock(&p.mu)
			if stop {
				return
			}
			continue // the job was cancelled while it waited
		}
		j.state = .Running
		skip := j.cancelled
		sync.mutex_unlock(&p.mu)
		if !skip {
			pw_compute(j)
		} else {
			mem.zero_explicit(&j.password, size_of(j.password))
		}
		sync.mutex_lock(&p.mu)
		j.state = .Done
		pq_push(&p.done, j)
		sync.mutex_unlock(&p.mu)
		intrinsics.atomic_add(&p.done_n, 1)
		event.wake(p.loop)
	}
}

// The next job to run. With both queues loaded: PW_LOGINS_PER_REKEY logins,
// then one rekey. The caller holds the lock.
pw_next :: proc(p: ^Pw_State) -> ^Pw_Job {
	if p.rekeys.head == nil {
		p.login_run = 0
		return pq_pop(&p.logins)
	}
	if p.logins.head == nil || p.login_run >= PW_LOGINS_PER_REKEY {
		p.login_run = 0
		return pq_pop(&p.rekeys)
	}
	p.login_run += 1
	return pq_pop(&p.logins)
}

// The check itself. Wipes the password. The result is in `j.ok`.
pw_compute :: proc "contextless" (j: ^Pw_Job) {
	out: [server.PW_HASH_MAX]u8
	n := j.hash_n
	good := ossl.pbkdf2_sha256(j.password[:j.password_n], j.salt[:j.salt_n], j.iterations, out[:n])
	j.ok = good && !j.decoy && ossl.ct_equal(out[:n], j.hash[:j.hash_n])
	mem.zero_explicit(&out, size_of(out))
	mem.zero_explicit(&j.password, size_of(j.password))
	j.password_n = 0
}

// Queues a job. False when the queue is full.
pw_submit :: proc(p: ^Pw_State, j: ^Pw_Job) -> bool {
	sync.mutex_lock(&p.mu)
	q := &p.rekeys if j.rekey else &p.logins
	if q.n >= (PW_REKEY_QUEUE_MAX if j.rekey else PW_LOGIN_QUEUE_MAX) || p.stopping {
		sync.mutex_unlock(&p.mu)
		return false
	}
	j.state = .Queued
	pq_push(q, j)
	sync.mutex_unlock(&p.mu)
	sync.sema_post(&p.sema)
	return true
}

// The session is gone. A job that waits is removed and freed now; one that
// runs, or is done and not read yet, is marked and freed when it is read.
pw_cancel :: proc(p: ^Pw_State, j: ^Pw_Job) {
	sync.mutex_lock(&p.mu)
	j.cancelled = true
	removed := false
	if j.state == .Queued {
		removed = pq_remove(&p.logins, j) || pq_remove(&p.rekeys, j)
	}
	sync.mutex_unlock(&p.mu)
	if removed {
		pw_job_free(j)
	}
}

// ---------------------------------------------------------------- the check

// A session waits for its check (or for the refusal after a failed one).
conn_waits :: proc "contextless" (c: ^Conn) -> bool {
	return c.parked || c.pw_wait
}

// Starts a check of `req.username` and `req.password` for the session. `user`
// is the name to look up. On a login `dec` is the decision. The session waits
// for the result. Refuses the client when the queue is full.
srv_pw_begin :: proc(d: ^Srv, c: ^Conn, req: ^session.Auth_Request, user: string, dec: ^server.Decision, rekey: bool) {
	p := &d.pw
	j := new(Pw_Job)
	j.rekey = rekey
	j.cidx = c.slot
	j.sess = c.sess
	j.password_n = copy(j.password[:], req.password)
	// The only copy of the password is the job's now.
	session.session_server_wipe_password(&c.s)
	e := server.pw_find(p.table, user)
	if e == nil {
		j.decoy = true
		j.iterations, j.salt_n, j.hash_n = server.pw_decoy(p.table)
	} else {
		j.iterations = e.iterations
		j.salt_n = int(e.salt_n)
		j.hash_n = int(e.hash_n)
		copy(j.salt[:], e.salt[:e.salt_n])
		copy(j.hash[:], e.hash[:e.hash_n])
		j.form, _ = server.identity_make(e.user)
		j.line = server.pw_entry_digest(e)
	}
	d.stats.pw_checks += 1
	if !pw_submit(p, j) {
		pw_job_free(j)
		d.stats.pw_busy += 1
		rej := server.server_deny_password_busy(&d.srv)
		logf(.Notice, "client %s: the password check queue is full", conn_label(c))
		pw_refuse(d, c, rej, rekey, "the password check queue is full")
		return
	}
	now := now_srv(d)
	secs := max(d.cfg.tls.hand_window - 4, 1)
	c.pw_wait = true
	c.pw_delay = false
	c.pw_rekey = rekey
	c.pw_job = j
	c.park_until = now + time.Duration(secs) * time.Second
	if dec != nil {
		c.pw_dec = dec^
	}
	p.waiting += 1
	conn_arm_timer(d, c)
}

// The refusal of a login or of a rekey. `c` may be gone afterwards.
pw_refuse :: proc(d: ^Srv, c: ^Conn, rej: server.Reject, rekey: bool, detail: string) {
	if rekey {
		c.end = .Reauth_Refused
	}
	srv_refuse(d, c, rej, detail)
	srv_settle(d, c)
}

// The check is over (any outcome).
pw_unwait :: proc(d: ^Srv, c: ^Conn) {
	if !c.pw_wait {
		return
	}
	c.pw_wait = false
	c.pw_delay = false
	d.pw.waiting -= 1
}

// The session ends, or the daemon stops: drop the job and the wait.
srv_pw_cancel :: proc(d: ^Srv, c: ^Conn) {
	if c.pw_job != nil {
		pw_cancel(&d.pw, c.pw_job)
		c.pw_job = nil
	}
	if c.pw_wait {
		login := !c.pw_rekey
		pw_unwait(d, c)
		c.pw_dec = {}
		if login && !c.up {
			srv_ev_auth_fail(d, c, "client_left", "the client left during the password check")
		}
	}
}

// Reads the finished checks. Called on every turn of the event loop.
srv_pw_drain :: proc(d: ^Srv) {
	p := &d.pw
	if intrinsics.atomic_load(&p.done_n) == 0 {
		return
	}
	sync.mutex_lock(&p.mu)
	list: Pw_Queue
	for j := pq_pop(&p.done); j != nil; j = pq_pop(&p.done) {
		pq_push(&list, j)
	}
	sync.mutex_unlock(&p.mu)
	for j := pq_pop(&list); j != nil; j = pq_pop(&list) {
		intrinsics.atomic_sub(&p.done_n, 1)
		srv_pw_result(d, j)
	}
}

// One finished check.
srv_pw_result :: proc(d: ^Srv, j: ^Pw_Job) {
	defer pw_job_free(j)
	if j.cancelled {
		return
	}
	c := conn_alive(d, j.cidx, j.sess)
	if c == nil || !c.pw_wait || c.pw_job != j {
		return
	}
	c.pw_job = nil
	ok := j.ok
	if ok {
		// The file may have changed while the check ran: the entry must still be
		// the one the check used.
		cur := server.pw_find(d.pw.table, server.identity_str(&j.form))
		if cur == nil || server.pw_entry_digest(cur) != j.line {
			ok = false
		}
	}
	if !ok {
		d.stats.pw_failed += 1
		c.pw_delay = true
		c.park_until = now_srv(d) + PW_DELAY
		conn_arm_timer(d, c)
		return
	}
	srv_pw_pass(d, c, j)
}

// The check passed.
srv_pw_pass :: proc(d: ^Srv, c: ^Conn, j: ^Pw_Job) {
	rekey := c.pw_rekey
	pw_unwait(d, c)
	c.pw_user = j.form
	c.pw_line = j.line
	c.pw_has = true
	// From now on this session is asked at every renegotiation.
	session.session_server_set_reauth(&c.s, true)
	if rekey {
		c.proofs += {.Password}
		if err := session.session_server_accept(&c.s, nil, now_srv(d)); err != .None {
			logf(.Error, "client %s: cannot accept the renegotiation: %v", conn_label(c), err)
		}
		srv_settle(d, c)
		return
	}
	dec := c.pw_dec
	c.pw_dec = {}
	r := server.server_password_passed(&d.srv, dec, server.identity_str(&j.form), d.parked + d.pw.waiting)
	c.proofs = r.proofs
	if r.kind == .Reject {
		srv_refuse(d, c, r.reject, "")
		srv_settle(d, c)
		return
	}
	// The login of this session, as the session has it. The password is wiped.
	req := &d.areq
	defer d.areq = {}
	if !session.session_auth_request(&c.s, req) {
		srv_refuse(d, c, server.reject_make(.Internal), "")
		srv_settle(d, c)
		return
	}
	switch r.kind {
	case .Pending_External:
		srv_park(d, c, req, &r)
	case .Accept:
		srv_login(d, c, &r, "")
		srv_settle(d, c)
	case .Reject, .Pending_Password:
		srv_refuse(d, c, server.reject_make(.Internal), "")
		srv_settle(d, c)
	}
}

// The wait of a check is over: the delay of a failed check, or the deadline.
srv_pw_timer :: proc(d: ^Srv, c: ^Conn) {
	rekey := c.pw_rekey
	if c.pw_delay {
		pw_unwait(d, c)
		c.pw_dec = {}
		pw_refuse(d, c, server.server_deny_password(&d.srv), rekey, "")
		return
	}
	// The check is too slow.
	if c.pw_job != nil {
		pw_cancel(&d.pw, c.pw_job)
		c.pw_job = nil
	}
	pw_unwait(d, c)
	c.pw_dec = {}
	d.stats.pw_busy += 1
	pw_refuse(d, c, server.server_deny_password_busy(&d.srv), rekey, "no result in time")
}

// ----------------------------------------------------------------- the login

// A login that needs the hash file: the user name is the one the client sent.
srv_pw_login :: proc(d: ^Srv, c: ^Conn, req: ^session.Auth_Request, dec: ^server.Decision) {
	srv_pw_begin(d, c, req, req.username, dec, false)
}

Rekey_Action :: enum u8 {
	Accept, // nothing to check: the new key goes live
	Check, // the hash file check, for the name in `user`
	Refuse_Name, // another user name than the session has
	Refuse_Missing, // a password session sent no password
}

// What a renegotiation needs:
//   has                    - the session passed a hash file check; `pw_user` is its name
//   named                  - the session has a name (`name`)
//   req_user, req_password - the request
//   on                     - the daemon has a hash file
// A session that passed a check is checked again with its own name. A
// certificate session that sends a password where the login had none is checked
// with its certificate name. Any other renegotiation goes through.
pw_rekey_plan :: proc "contextless" (has: bool, pw_user: string, named: bool, name: string, on: bool, req_user, req_password: string) -> (act: Rekey_Action, user: string) {
	switch {
	case has:
		user = pw_user
	case req_password != "" && on && named:
		user = name
	case:
		return .Accept, ""
	}
	switch {
	case !server.name_equal(req_user, user):
		return .Refuse_Name, user
	case req_password == "":
		return .Refuse_Missing, user
	}
	return .Check, user
}

srv_rekey_request :: proc(d: ^Srv, c: ^Conn, req: ^session.Auth_Request) {
	if c.idsrc == .Controller {
		srv_web_rekey(d, c, req)
		return
	}
	name := server.identity_str(&c.name) if c.named else ""
	act, user := pw_rekey_plan(c.pw_has, server.identity_str(&c.pw_user), c.named, name, d.pw.on, req.username, req.password)
	switch act {
	case .Accept:
		session.session_server_wipe_password(&c.s)
		if err := session.session_server_accept(&c.s, nil, now_srv(d)); err != .None {
			logf(.Error, "client %s: cannot accept the renegotiation: %v", conn_label(c), err)
		}
		srv_settle(d, c)
	case .Refuse_Name:
		logf(.Notice, "client %s: the renegotiation uses a different user name than the session", conn_label(c))
		session.session_server_wipe_password(&c.s)
		pw_refuse(d, c, server.reject_make(.Username_Mismatch), true, "")
	case .Refuse_Missing:
		pw_refuse(d, c, server.reject_make(.Password_Missing), true, "")
	case .Check:
		srv_pw_begin(d, c, req, user, nil, true)
	}
}

// ------------------------------------------------------------------ reload

Pw_Report :: struct {
	users, added, removed, changed, ended: int,
	lost:                                  bool,
}

// Reads the file again and applies it: sessions of removed users end for good
// (HALT), sessions of users with a new hash end with RESTART. An unreadable
// file causes every check to fail and ends no session.
srv_pw_reload :: proc(d: ^Srv) -> (rep: Pw_Report) {
	p := &d.pw
	cur := crl_stat(p.path)
	p.last_ns = time.tick_now()._nsec
	t, why := pw_read_file(p.path)
	if t == nil {
		if !p.lost {
			logf(.Error, "peer-passwords %s: cannot read the file: %s, so every password check will fail until it can be loaded", p.path, why)
		}
		p.lost = true
		p.loaded = cur
		server.pw_destroy(p.table)
		p.table = nil
		rep.lost = true
		return
	}
	pw_log_warnings(t, p.path)
	was_lost := p.lost
	p.lost = false
	p.loaded = cur
	old := p.table
	p.table = t
	rep.users = server.pw_len(t)
	changes := server.pw_diff(old, t)
	for ch in changes {
		switch ch.kind {
		case .Added:
			rep.added += 1
		case .Removed:
			rep.removed += 1
		case .Changed:
			rep.changed += 1
		}
	}
	server.pw_changes_destroy(&changes)
	server.pw_destroy(old)
	if was_lost {
		logf(.Notice, "peer-passwords %s: loaded again", p.path)
	}
	logf(.Notice, "reload: peer-passwords %s: %d user(s), %d added, %d removed, %d changed", p.path, rep.users, rep.added, rep.removed, rep.changed)
	rep.ended = srv_pw_apply(d)
	return
}

Pw_Fate :: enum u8 {
	Keep,
	Gone, // the user is not in the table
	Changed, // the user has another hash line
}

// What a reload means for a session that passed a check as `user` with a hash
// line of digest `line`.
pw_fate :: proc(t: ^server.Pw_Table, user: string, line: [32]u8) -> Pw_Fate {
	e := server.pw_find(t, user)
	switch {
	case e == nil:
		return .Gone
	case server.pw_entry_digest(e) != line:
		return .Changed
	}
	return .Keep
}

// Ends the sessions whose user is gone from the table or has another hash.
srv_pw_apply :: proc(d: ^Srv) -> (ended: int) {
	for slot in 0 ..< len(d.conns) {
		c := d.conns[slot]
		if c == nil || !c.pw_has || c.closing || c.releasing {
			continue
		}
		switch pw_fate(d.pw.table, server.identity_str(&c.pw_user), c.pw_line) {
		case .Keep:
		case .Gone:
			logf(.Notice, "reload: ending the session of %s: the user is not in the password file", conn_label(c))
			c.detail_n = copy(c.detail[:], "user removed from the password file")
			d.stats.kicks += 1
			ended += 1
			conn_close(d, c, .Halt, .Password_Gone)
		case .Changed:
			logf(.Notice, "reload: ending the session of %s: the password changed", conn_label(c))
			c.detail_n = copy(c.detail[:], "password changed")
			d.stats.kicks += 1
			ended += 1
			conn_close(d, c, .Restart, .Password_Changed)
		}
	}
	srv_flush_all(d)
	return
}

// The timer that looks at the file once a second.
on_srv_pw_poll :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Srv)(user)
	d.pw.t_poll.on = false
	if d.finished || d.stopping {
		return
	}
	cur := crl_stat(d.pw.path)
	if crl_decide(d.pw.loaded, d.pw.lost, cur) != .Keep {
		srv_pw_reload(d)
	}
	srv_pw_arm(d)
}

srv_pw_arm :: proc(d: ^Srv) {
	if !d.pw.on || d.finished {
		return
	}
	stimer_set(&d.loop, &d.pw.t_poll, now_srv(d) + PW_POLL, on_srv_pw_poll, d)
}

// ------------------------------------------------------------------- the bus

// `passwords.reload`.
srv_op_passwords_reload :: proc(d: ^Srv, req: ^bus.Request) {
	if srv_busy_stopping(d, req) {
		return
	}
	if !d.pw.on {
		bus_err(req, .Conflict, "no password file is configured (peer-passwords)")
		return
	}
	rep := srv_pw_reload(d)
	if rep.lost {
		bus_err(req, .Internal, "the password file cannot be read; every password check fails until it can")
		return
	}
	w := bus_res()
	bus.kv_int(w, "users", i64(rep.users))
	bus.kv_int(w, "added", i64(rep.added))
	bus.kv_int(w, "removed", i64(rep.removed))
	bus.kv_int(w, "changed", i64(rep.changed))
	bus.kv_int(w, "ended", i64(rep.ended))
	bus_ok(req)
}
