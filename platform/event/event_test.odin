// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package event

import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"

// Tests of the loop with pipes, eventfds and short real timers. Time limits
// are loose so a slow machine does not fail them.

// Collects what handlers saw.
@(private = "file")
Log :: struct {
	order:   [32]int,
	n:       int,
	ready:   [32]Ready,
	loop:    ^Loop,
	extra:   [4]i32, // descriptors or ids a handler needs
	count:   int,
	timer:   Timer_Id,
}

@(private = "file")
record :: proc(l: ^Log, tag: int, ready: Ready = {}) {
	if l.n < len(l.order) {
		l.order[l.n] = tag
		l.ready[l.n] = ready
		l.n += 1
	}
}

@(private = "file")
Pipe :: struct {
	r, w: linux.Fd,
}

@(private = "file")
make_pipe :: proc(t: ^testing.T) -> Pipe {
	fds: [2]linux.Fd
	err := linux.pipe2(&fds, {.NONBLOCK, .CLOEXEC})
	testing.expect_value(t, err, linux.Errno.NONE)
	return {fds[0], fds[1]}
}

@(private = "file")
close_pipe :: proc(p: Pipe) {
	linux.close(p.r)
	linux.close(p.w)
}

@(private = "file")
put_byte :: proc(fd: linux.Fd) {
	b := [1]u8{'x'}
	linux.write(fd, b[:])
}

@(private = "file")
take_all :: proc(fd: linux.Fd) -> int {
	buf: [64]u8
	n, _ := linux.read(fd, buf[:])
	return n
}

@(private = "file")
ms :: proc(n: i64) -> time.Duration {
	return time.Duration(n) * time.Millisecond
}

@(private = "file")
new_loop :: proc(t: ^testing.T) -> (loop: Loop, ok: bool) {
	err := init(&loop)
	testing.expect_value(t, err, Error.None)
	return loop, err == .None
}

// ---- timers on the real clock ----

@(test)
timers_fire_in_order :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	Cell :: struct {
		log:   ^Log,
		label: int,
	}
	handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		c := (^Cell)(user)
		record(c.log, c.label)
	}

	// Armed out of order. Two share the same delay: arming order wins.
	log: Log
	cells := [4]Cell{{&log, 30}, {&log, 10}, {&log, 21}, {&log, 22}}
	delays := [4]i64{30, 10, 20, 20}
	for i in 0 ..< 4 {
		_, err := timer_add(&loop, ms(delays[i]), handler, &cells[i])
		testing.expect_value(t, err, Error.None)
	}

	deadline := now() + 2 * time.Second
	for log.n < 4 && now() < deadline {
		_, err := wait(&loop, deadline)
		testing.expect_value(t, err, Error.None)
	}
	testing.expect_value(t, log.n, 4)
	testing.expect_value(t, log.order[0], 10)
	testing.expect_value(t, log.order[1], 21)
	testing.expect_value(t, log.order[2], 22)
	testing.expect_value(t, log.order[3], 30)
}

@(test)
timer_does_not_fire_early :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	Fired :: struct {
		at:    time.Duration,
		fired: bool,
	}
	f: Fired
	handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		f := (^Fired)(user)
		f.at = now()
		f.fired = true
	}
	update_time(&loop)
	start := now()
	timer_add(&loop, ms(40), handler, &f)
	deadline := start + 2 * time.Second
	for !f.fired && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect(t, f.fired)
	testing.expect(t, f.at - start >= ms(40), "timer fired early")
	testing.expect(t, f.at - start < ms(1500), "timer fired very late")
}

@(test)
wait_until_returns_at_the_limit :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	start := now()
	n, err := wait(&loop, start + ms(50))
	elapsed := now() - start
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 0)
	testing.expect(t, elapsed >= ms(50), "returned before `until`")
	testing.expect(t, elapsed < ms(1500), "returned very late")

	// A limit in the past does not block.
	start = now()
	wait(&loop, start - ms(5))
	testing.expect(t, now() - start < ms(500))
}

@(test)
wait_stops_at_the_earliest_timer :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	Count :: struct {
		n: int,
	}
	c: Count
	handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		(^Count)(user).n += 1
	}
	update_time(&loop)
	timer_add(&loop, ms(30), handler, &c)
	start := now()
	// `until` is far away: the 30 ms timer ends the wait.
	n, _ := wait(&loop, start + 10 * time.Second)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, c.n, 1)
	testing.expect(t, now() - start < 2 * time.Second)
}

@(test)
periodic_timer_cancels_itself :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	log: Log
	log.loop = &loop
	handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		l := (^Log)(user)
		l.count += 1
		if l.count == 3 {
			timer_cancel(loop, id)
		}
	}
	id, _ := timer_add(&loop, ms(10), handler, &log, interval = ms(10))
	deadline := now() + 2 * time.Second
	for log.count < 3 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect_value(t, log.count, 3)
	// It is gone: more waiting changes nothing.
	wait(&loop, now() + ms(60))
	testing.expect_value(t, log.count, 3)
	testing.expect(t, !timer_cancel(&loop, id))
	_, has := timer_next(&loop)
	testing.expect(t, !has)
}

@(test)
handler_can_cancel_another_due_timer :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	log: Log
	log.loop = &loop
	first :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		l := (^Log)(user)
		record(l, 1)
		timer_cancel(loop, l.timer) // the second one is due in this same round
	}
	second :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		record((^Log)(user), 2)
	}
	third :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		record((^Log)(user), 3)
	}
	update_time(&loop)
	// Same loop time and delays so both are due together.
	timer_add(&loop, ms(10), first, &log)
	log.timer, _ = timer_add(&loop, ms(10), second, &log)
	timer_add(&loop, ms(10), third, &log)
	// Wait until all three are due, then run one round.
	time.sleep(ms(30))
	wait(&loop, now())
	testing.expect_value(t, log.n, 2)
	testing.expect_value(t, log.order[0], 1)
	testing.expect_value(t, log.order[1], 3)
}

@(test)
timer_armed_by_handler_waits_for_next_round :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	log: Log
	handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		l := (^Log)(user)
		l.count += 1
		if l.count < 100 {
			// Zero delay: due at once, but must not run in this same `wait`.
			timer_add(loop, 0, handler, user)
		}
	}
	update_time(&loop)
	timer_add(&loop, 0, handler, &log)
	n, _ := wait(&loop, now())
	testing.expect_value(t, n, 1)
	testing.expect_value(t, log.count, 1)
	n, _ = wait(&loop, now())
	testing.expect_value(t, n, 1)
	testing.expect_value(t, log.count, 2)
}

@(test)
timer_reset_postpones :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	log: Log
	handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		(^Log)(user).count += 1
	}
	update_time(&loop)
	id, _ := timer_add(&loop, ms(30), handler, &log)
	time.sleep(ms(20))
	update_time(&loop)
	testing.expect(t, timer_reset(&loop, id, ms(60))) // now due ~60 ms from here
	start := now()
	wait(&loop, start + ms(40))
	testing.expect_value(t, log.count, 0)
	deadline := start + 2 * time.Second
	for log.count == 0 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect_value(t, log.count, 1)
	testing.expect(t, now() - start >= ms(55), "fired too early after reset")
}

// ---- descriptors ----

@(private = "file")
read_handler :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
	l := (^Log)(user)
	record(l, int(fd), ready)
}

@(test)
pipe_read_readiness_is_level_triggered :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	p := make_pipe(t)
	defer close_pipe(p)

	log: Log
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read}, read_handler, &log), Error.None)

	// Nothing to read yet.
	n, _ := wait(&loop, now() + ms(10))
	testing.expect_value(t, n, 0)

	put_byte(p.w)
	n, _ = wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
	testing.expect_value(t, log.n, 1)
	testing.expect_value(t, log.order[0], int(p.r))
	testing.expect(t, .Read in log.ready[0])
	testing.expect(t, .Write not_in log.ready[0])

	// The handler did not drain it: level triggered reports it again.
	n, _ = wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)

	// Drained: quiet again.
	take_all(p.r)
	n, _ = wait(&loop, now() + ms(10))
	testing.expect_value(t, n, 0)
}

@(test)
pipe_edge_triggered_reports_once :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	p := make_pipe(t)
	defer close_pipe(p)

	log: Log
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read, .Edge}, read_handler, &log), Error.None)

	put_byte(p.w)
	n, _ := wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
	// Not drained, but no new data: no new event.
	n, _ = wait(&loop, now() + ms(20))
	testing.expect_value(t, n, 0)
	// New data is a new edge.
	put_byte(p.w)
	n, _ = wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
}

@(test)
write_interest_and_modify :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	p := make_pipe(t)
	defer close_pipe(p)

	log: Log
	// An empty pipe's write end is writable at once.
	testing.expect_value(t, add_fd(&loop, i32(p.w), {.Write}, read_handler, &log), Error.None)
	n, _ := wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
	testing.expect(t, .Write in log.ready[0])

	// Drop write interest: quiet.
	testing.expect_value(t, modify_fd(&loop, i32(p.w), {}), Error.None)
	n, _ = wait(&loop, now() + ms(20))
	testing.expect_value(t, n, 0)

	// And back.
	testing.expect_value(t, modify_fd(&loop, i32(p.w), {.Write}), Error.None)
	n, _ = wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)

	testing.expect_value(t, modify_fd(&loop, 999, {.Read}), Error.Not_Found)
}

@(test)
hangup_is_reported :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	p := make_pipe(t)
	defer linux.close(p.r)

	log: Log
	add_fd(&loop, i32(p.r), {.Read}, read_handler, &log)
	linux.close(p.w) // the writer goes away
	n, _ := wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
	testing.expect(t, .Hangup in log.ready[0])
}

@(test)
add_remove_errors :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	p := make_pipe(t)
	defer close_pipe(p)

	log: Log
	testing.expect_value(t, add_fd(&loop, -1, {.Read}, read_handler, &log), Error.Bad_Fd)
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read}, read_handler, &log), Error.None)
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read}, read_handler, &log), Error.Exists)
	testing.expect_value(t, remove_fd(&loop, i32(p.r)), Error.None)
	testing.expect_value(t, remove_fd(&loop, i32(p.r)), Error.Not_Found)
	testing.expect_value(t, remove_fd(&loop, 5000), Error.Not_Found)
	// It can be added again.
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read}, read_handler, &log), Error.None)

	// A removed descriptor reports nothing.
	remove_fd(&loop, i32(p.r))
	put_byte(p.w)
	n, _ := wait(&loop, now() + ms(20))
	testing.expect_value(t, n, 0)
}

@(test)
closing_before_remove_is_fine :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	p := make_pipe(t)
	defer linux.close(p.w)

	log: Log
	add_fd(&loop, i32(p.r), {.Read}, read_handler, &log)
	linux.close(p.r)
	testing.expect_value(t, remove_fd(&loop, i32(p.r)), Error.None)
}

@(test)
regular_file_cannot_be_registered :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	fd, e := linux.open("/dev/null", {})
	testing.expect_value(t, e, linux.Errno.NONE)
	defer linux.close(fd)
	// epoll refuses regular files and /dev/null (it has no poll support).
	log: Log
	testing.expect_value(t, add_fd(&loop, i32(fd), {.Read}, read_handler, &log), Error.Register_Failed)
}

@(test)
handler_removes_a_pending_descriptor :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	a := make_pipe(t)
	defer close_pipe(a)
	b := make_pipe(t)
	defer close_pipe(b)

	log: Log
	log.loop = &loop
	log.extra[0] = i32(b.r)
	handler :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
		l := (^Log)(user)
		record(l, int(fd))
		// Both were ready in this batch. Remove the other one.
		other := l.extra[0] if fd != l.extra[0] else l.extra[1]
		remove_fd(loop, other)
	}
	log.extra[1] = i32(a.r)
	add_fd(&loop, i32(a.r), {.Read}, handler, &log)
	add_fd(&loop, i32(b.r), {.Read}, handler, &log)
	put_byte(a.w)
	put_byte(b.w)
	n, _ := wait(&loop, now() + ms(500))
	// Only the first handler ran; it removed the second one.
	testing.expect_value(t, n, 1)
	testing.expect_value(t, log.n, 1)
}

@(test)
reused_descriptor_number_does_not_get_stale_events :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	a := make_pipe(t)
	defer close_pipe(a)
	b := make_pipe(t)
	defer close_pipe(b)

	Ctx :: struct {
		log:      Log,
		b:        Pipe,
		new_w:    linux.Fd,
	}
	ctx: Ctx
	ctx.b = b

	stale :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
		record(&(^Ctx)(user).log, 1000 + int(fd)) // must not run: nothing was written to the new pipe
	}
	first :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
		c := (^Ctx)(user)
		record(&c.log, int(fd))
		take_all(linux.Fd(fd)) // level triggered: drain it or it is reported again
		// The other pipe's event is already in this batch. Replace its read
		// end with a new pipe's read end. dup3 swaps the file under the same
		// number in one step, so no other test thread can take the number.
		remove_fd(loop, i32(c.b.r))
		fds: [2]linux.Fd
		linux.pipe2(&fds, {.NONBLOCK, .CLOEXEC})
		linux.dup3(fds[0], c.b.r, {.CLOEXEC})
		linux.close(fds[0])
		c.new_w = fds[1]
		add_fd(loop, i32(c.b.r), {.Read}, stale, c)
	}
	add_fd(&loop, i32(a.r), {.Read}, first, &ctx)
	add_fd(&loop, i32(b.r), {.Read}, stale, &ctx)
	put_byte(a.w)
	put_byte(b.w)
	n, _ := wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
	testing.expect_value(t, ctx.log.n, 1)
	testing.expect_value(t, ctx.log.order[0], int(a.r))

	// The new registration itself works: data on the new pipe is delivered.
	put_byte(ctx.new_w)
	n, _ = wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
	testing.expect_value(t, ctx.log.n, 2)
	testing.expect_value(t, ctx.log.order[1], 1000 + int(b.r))
	linux.close(ctx.new_w)
}

@(test)
eventfd_counts_as_readable :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	efd, e := linux.eventfd(0, {.NONBLOCK, .CLOEXEC})
	testing.expect_value(t, e, linux.Errno.NONE)
	defer linux.close(efd)

	log: Log
	add_fd(&loop, i32(efd), {.Read}, read_handler, &log)
	n, _ := wait(&loop, now() + ms(10))
	testing.expect_value(t, n, 0)
	v := u64(5)
	linux.write(efd, ([^]u8)(&v)[:8])
	n, _ = wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 1)
	testing.expect_value(t, log.order[0], int(efd))
}

// ---- other threads ----

@(test)
wake_from_another_thread :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	th := thread.create_and_start_with_poly_data(&loop, proc(loop: ^Loop) {
		time.sleep(30 * time.Millisecond)
		wake(loop)
	})
	start := now()
	n, err := wait(&loop) // no timers, no limit: only the wake-up ends it
	elapsed := now() - start
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 0)
	testing.expect(t, elapsed >= ms(20), "woke before the other thread called wake")
	testing.expect(t, elapsed < ms(1500))
}

@(test)
wake_before_wait_is_not_lost :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)
	wake(&loop)
	start := now()
	wait(&loop) // returns at once
	testing.expect(t, now() - start < ms(500))
}

@(test)
stop_from_another_thread_ends_run :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	th := thread.create_and_start_with_poly_data(&loop, proc(loop: ^Loop) {
		time.sleep(30 * time.Millisecond)
		stop(loop)
	})
	err := run(&loop)
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, err, Error.None)

	// `run` cleared the flag: the loop can run again.
	th2 := thread.create_and_start_with_poly_data(&loop, proc(loop: ^Loop) {
		time.sleep(10 * time.Millisecond)
		stop(loop)
	})
	err = run(&loop)
	thread.join(th2)
	thread.destroy(th2)
	testing.expect_value(t, err, Error.None)
}

@(test)
many_descriptors_grow_the_table :: proc(t: ^testing.T) {
	loop, ok := new_loop(t)
	if !ok {
		return
	}
	defer destroy(&loop)

	// 100 pipes: descriptor numbers go well past the first table size.
	N :: 100
	pipes: [N]Pipe
	log: Log
	for i in 0 ..< N {
		pipes[i] = make_pipe(t)
		testing.expect_value(t, add_fd(&loop, i32(pipes[i].r), {.Read}, read_handler, &log), Error.None)
	}
	defer for p in pipes {
		close_pipe(p)
	}
	put_byte(pipes[N - 1].w)
	put_byte(pipes[0].w)
	n, _ := wait(&loop, now() + ms(500))
	testing.expect_value(t, n, 2)
	for i in 0 ..< n {
		fd := log.order[i]
		testing.expect(t, fd == int(pipes[0].r) || fd == int(pipes[N - 1].r))
	}
}
