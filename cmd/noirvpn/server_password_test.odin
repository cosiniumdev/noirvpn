// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "base:intrinsics"
import "core:testing"
import "core:time"
import "noir:platform/event"
import "noir:proto/ossl"
import "noir:server"

@(private = "file")
make_job :: proc(password: string, salt, good_password: string, its: int, rekey := false, decoy := false) -> ^Pw_Job {
	j := new(Pw_Job)
	j.rekey = rekey
	j.password_n = copy(j.password[:], password)
	j.salt_n = copy(j.salt[:], salt)
	j.iterations = its
	j.hash_n = 32
	j.decoy = decoy
	ossl.pbkdf2_sha256(transmute([]u8)good_password, j.salt[:j.salt_n], its, j.hash[:32])
	return j
}

@(private = "file")
wait_done :: proc(p: ^Pw_State, n: int) -> bool {
	for _ in 0 ..< 400 {
		if intrinsics.atomic_load(&p.done_n) >= n {
			return true
		}
		time.sleep(10 * time.Millisecond)
	}
	return false
}

@(test)
test_pw_queue_order_and_remove :: proc(t: ^testing.T) {
	q: Pw_Queue
	a, b, c := new(Pw_Job), new(Pw_Job), new(Pw_Job)
	defer free(a)
	defer free(b)
	defer free(c)
	pq_push(&q, a)
	pq_push(&q, b)
	pq_push(&q, c)
	testing.expect_value(t, q.n, 3)
	testing.expect(t, pq_remove(&q, b))
	testing.expect(t, !pq_remove(&q, b))
	testing.expect(t, pq_pop(&q) == a)
	testing.expect(t, pq_pop(&q) == c)
	testing.expect(t, pq_pop(&q) == nil)
	testing.expect_value(t, q.n, 0)
	// Removing the last one moves the tail.
	pq_push(&q, a)
	pq_push(&q, b)
	testing.expect(t, pq_remove(&q, b))
	pq_push(&q, c)
	testing.expect(t, pq_pop(&q) == a)
	testing.expect(t, pq_pop(&q) == c)
}

// With both queues loaded: 3 logins, then 1 rekey, each queue in the order the jobs came.
@(test)
test_pw_pick_order_with_both_queues :: proc(t: ^testing.T) {
	p := new(Pw_State)
	defer free(p)
	logins, rekeys: [8]^Pw_Job
	for i in 0 ..< 8 {
		logins[i] = make_job("x", "s", "x", 1)
		rekeys[i] = make_job("x", "s", "x", 1, rekey = true)
		testing.expect(t, pw_submit(p, rekeys[i]))
		testing.expect(t, pw_submit(p, logins[i]))
	}
	// L L L R L L L R L L R R R R R R: the logins run out after 8.
	want := [16]^Pw_Job{logins[0], logins[1], logins[2], rekeys[0], logins[3], logins[4], logins[5], rekeys[1], logins[6], logins[7], rekeys[2], rekeys[3], rekeys[4], rekeys[5], rekeys[6], rekeys[7]}
	for i in 0 ..< 16 {
		j := pw_next(p)
		testing.expectf(t, j == want[i], "pick %d", i)
		pw_job_free(j)
	}
	testing.expect(t, pw_next(p) == nil)
}

// A queue that is empty gives way to the other one, and the count starts again.
@(test)
test_pw_pick_serves_the_only_queue :: proc(t: ^testing.T) {
	p := new(Pw_State)
	defer free(p)
	for _ in 0 ..< 5 {
		testing.expect(t, pw_submit(p, make_job("x", "s", "x", 1)))
	}
	for _ in 0 ..< 5 {
		j := pw_next(p)
		testing.expect(t, j != nil && !j.rekey)
		pw_job_free(j)
	}
	for _ in 0 ..< 3 {
		testing.expect(t, pw_submit(p, make_job("x", "s", "x", 1, rekey = true)))
	}
	for _ in 0 ..< 3 {
		j := pw_next(p)
		testing.expect(t, j != nil && j.rekey)
		pw_job_free(j)
	}
	testing.expect(t, pw_next(p) == nil)
}

// Each queue has its own bound, and a full one does not refuse the other kind.
@(test)
test_pw_bounds_are_separate :: proc(t: ^testing.T) {
	p := new(Pw_State)
	defer free(p)
	for _ in 0 ..< PW_LOGIN_QUEUE_MAX {
		testing.expect(t, pw_submit(p, make_job("x", "s", "x", 1)))
	}
	extra := make_job("x", "s", "x", 1)
	testing.expect(t, !pw_submit(p, extra))
	pw_job_free(extra)
	// The login queue is full: rekeys still get in, up to their own bound.
	for _ in 0 ..< PW_REKEY_QUEUE_MAX {
		testing.expect(t, pw_submit(p, make_job("x", "s", "x", 1, rekey = true)))
	}
	extra = make_job("x", "s", "x", 1, rekey = true)
	testing.expect(t, !pw_submit(p, extra))
	pw_job_free(extra)
	testing.expect_value(t, p.logins.n, PW_LOGIN_QUEUE_MAX)
	testing.expect_value(t, p.rekeys.n, PW_REKEY_QUEUE_MAX)
	// A cancel of a job that waits frees its place, and a new job of that kind fits.
	victim := p.logins.head.next
	pw_cancel(p, victim)
	testing.expect_value(t, p.logins.n, PW_LOGIN_QUEUE_MAX - 1)
	testing.expect(t, pw_submit(p, make_job("x", "s", "x", 1)))
	// A full rekey queue does not refuse a login.
	pw_job_free(pw_next(p))
	testing.expect(t, pw_submit(p, make_job("x", "s", "x", 1)))
	for j := pw_next(p); j != nil; j = pw_next(p) {
		pw_job_free(j)
	}
}

@(test)
test_pw_compute_right_wrong_and_decoy :: proc(t: ^testing.T) {
	j := make_job("secret", "salty", "secret", 100)
	pw_compute(j)
	testing.expect(t, j.ok)
	// The password is wiped when the check is done.
	testing.expect_value(t, j.password_n, 0)
	for b in j.password {
		testing.expect_value(t, b, u8(0))
	}
	free(j)
	j = make_job("guess", "salty", "secret", 100)
	pw_compute(j)
	testing.expect(t, !j.ok)
	free(j)
	// A decoy never passes, even with the matching password.
	j = make_job("secret", "salty", "secret", 100, decoy = true)
	pw_compute(j)
	testing.expect(t, !j.ok)
	free(j)
}

@(test)
test_pw_workers_give_results :: proc(t: ^testing.T) {
	loop: event.Loop
	testing.expect_value(t, event.init(&loop), event.Error.None)
	defer event.destroy(&loop)
	p := new(Pw_State)
	defer free(p)
	p.loop = &loop
	testing.expect(t, pw_pool_start(p, 3))
	good := make_job("pw1", "salt", "pw1", 50)
	bad := make_job("nope", "salt", "pw1", 50)
	testing.expect(t, pw_submit(p, good))
	testing.expect(t, pw_submit(p, bad))
	testing.expect(t, wait_done(p, 2))
	seen_good, seen_bad := false, false
	for j := pq_pop(&p.done); j != nil; j = pq_pop(&p.done) {
		switch j {
		case good:
			seen_good = j.ok
		case bad:
			seen_bad = !j.ok
		}
		pw_job_free(j)
	}
	testing.expect(t, seen_good, "the right password failed")
	testing.expect(t, seen_bad, "the wrong password passed")
	pw_pool_stop(p)
	testing.expect_value(t, p.n_threads, 0)
}

// A cancel while the job waits for a busy worker: the job never runs.
@(test)
test_pw_cancel_stops_a_queued_job :: proc(t: ^testing.T) {
	loop: event.Loop
	testing.expect_value(t, event.init(&loop), event.Error.None)
	defer event.destroy(&loop)
	p := new(Pw_State)
	defer free(p)
	p.loop = &loop
	// No threads yet: the job waits in the queue.
	j := make_job("pw", "salt", "pw", 10)
	testing.expect(t, pw_submit(p, j))
	pw_cancel(p, j)
	testing.expect_value(t, p.logins.n, 0)
	testing.expect(t, pw_pool_start(p, 1))
	// The thread wakes for the post that is left, finds nothing, and waits again.
	time.sleep(30 * time.Millisecond)
	testing.expect_value(t, intrinsics.atomic_load(&p.done_n), 0)
	pw_pool_stop(p)
}

@(test)
test_pw_rekey_plan :: proc(t: ^testing.T) {
	// A password session: the same user name and a password are checked.
	act, user := pw_rekey_plan(true, "Alice", true, "alice", true, "alice", "pw")
	testing.expect_value(t, act, Rekey_Action.Check)
	testing.expect_value(t, user, "Alice")
	act, _ = pw_rekey_plan(true, "Alice", true, "alice", true, "ALICE", "pw")
	testing.expect_value(t, act, Rekey_Action.Check)
	act, _ = pw_rekey_plan(true, "Alice", true, "alice", true, "bob", "pw")
	testing.expect_value(t, act, Rekey_Action.Refuse_Name)
	act, _ = pw_rekey_plan(true, "Alice", true, "alice", true, "alice", "")
	testing.expect_value(t, act, Rekey_Action.Refuse_Missing)
	// A password session without a user name is refused too.
	act, _ = pw_rekey_plan(true, "Alice", true, "alice", true, "", "pw")
	testing.expect_value(t, act, Rekey_Action.Refuse_Name)
	// A certificate session that never sent a password goes through.
	act, _ = pw_rekey_plan(false, "", true, "cert-cn", true, "", "")
	testing.expect_value(t, act, Rekey_Action.Accept)
	// A password that the login did not have: apply the table with the certificate name.
	act, user = pw_rekey_plan(false, "", true, "cert-cn", true, "cert-cn", "pw")
	testing.expect_value(t, act, Rekey_Action.Check)
	testing.expect_value(t, user, "cert-cn")
	act, _ = pw_rekey_plan(false, "", true, "cert-cn", true, "other", "pw")
	testing.expect_value(t, act, Rekey_Action.Refuse_Name)
	// No hash file: the password is not looked at.
	act, _ = pw_rekey_plan(false, "", true, "cert-cn", false, "cert-cn", "pw")
	testing.expect_value(t, act, Rekey_Action.Accept)
}

@(test)
test_pw_fate_after_reload :: proc(t: ^testing.T) {
	line := "pbkdf2-sha256:1000:AAECAwQFBgcICQoLDA0ODw==:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	other := "pbkdf2-sha256:2000:AAECAwQFBgcICQoLDA0ODw==:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	old := server.pw_parse(mem_concat("Alice\t", line, "\nbob\t", line, "\ncarol\t", line, "\n"))
	defer server.pw_destroy(old)
	digest := server.pw_entry_digest(server.pw_find(old, "alice"))
	next := server.pw_parse(mem_concat("alice\t", line, "\nbob\t", other, "\n"))
	defer server.pw_destroy(next)
	testing.expect_value(t, pw_fate(next, "Alice", digest), Pw_Fate.Keep)
	testing.expect_value(t, pw_fate(next, "bob", digest), Pw_Fate.Changed)
	testing.expect_value(t, pw_fate(next, "carol", digest), Pw_Fate.Gone)
	// No table: every session is gone (only used when a file is read, never when it is lost).
	testing.expect_value(t, pw_fate(nil, "alice", digest), Pw_Fate.Gone)
}

@(private = "file")
mem_concat :: proc(parts: ..string) -> string {
	n := 0
	for p in parts {
		n += len(p)
	}
	b := make([]u8, n, context.temp_allocator)
	i := 0
	for p in parts {
		i += copy(b[i:], p)
	}
	return string(b)
}

@(test)
test_pw_read_file :: proc(t: ^testing.T) {
	tab, why := pw_read_file("/nonexistent/noirvpn-passwords")
	testing.expect(t, tab == nil)
	testing.expect(t, why != "")
}
