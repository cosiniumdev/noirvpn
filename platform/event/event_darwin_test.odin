// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package event

import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"

// Tests of the kqueue loop with pipes and short real timers. The cases are
// the ones of event_test.odin that depend on the system calls.

@(private = "file")
Pipe :: struct {
	r, w: posix.FD,
}

@(private = "file")
make_pipe :: proc(t: ^testing.T) -> (p: Pipe) {
	fds: [2]posix.FD
	testing.expect_value(t, posix.pipe(&fds), posix.result.OK)
	for fd in fds {
		fl := posix.fcntl(fd, .GETFL)
		posix.fcntl(fd, .SETFL, fl | posix.O_NONBLOCK)
	}
	return {fds[0], fds[1]}
}

@(private = "file")
put_byte :: proc(fd: posix.FD) {
	b := [1]u8{1}
	posix.write(fd, raw_data(b[:]), 1)
}

@(private = "file")
take_all :: proc(fd: posix.FD) -> int {
	buf: [64]u8
	total := 0
	for {
		n := posix.read(fd, raw_data(buf[:]), len(buf))
		if n <= 0 {
			break
		}
		total += int(n)
	}
	return total
}

@(private = "file")
Seen :: struct {
	calls:  int,
	ready:  Ready,
	fd:     i32,
	drain:  bool,
	timers: int,
}

@(private = "file")
on_fd :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
	s := (^Seen)(user)
	s.calls += 1
	s.ready += ready
	s.fd = fd
	if s.drain {
		take_all(posix.FD(fd))
	}
}

@(private = "file")
on_timer :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
	(^Seen)(user).timers += 1
}

@(test)
darwin_read_ready :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	p := make_pipe(t)
	defer posix.close(p.r)
	defer posix.close(p.w)

	s := Seen {
		drain = true,
	}
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read}, on_fd, &s), Error.None)
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read}, on_fd, &s), Error.Exists)

	n, err := wait(&loop, now() + 5 * time.Millisecond)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 0)

	put_byte(p.w)
	n, err = wait(&loop, now() + time.Second)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, s.fd, i32(p.r))
	testing.expect(t, .Read in s.ready)
	testing.expect(t, .Hangup not_in s.ready)
}

@(test)
darwin_level_triggered :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	p := make_pipe(t)
	defer posix.close(p.r)
	defer posix.close(p.w)

	s: Seen // does not drain
	add_fd(&loop, i32(p.r), {.Read}, on_fd, &s)
	put_byte(p.w)
	wait(&loop, now() + time.Second)
	wait(&loop, now() + time.Second)
	testing.expect_value(t, s.calls, 2)
}

@(test)
darwin_edge_triggered :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	p := make_pipe(t)
	defer posix.close(p.r)
	defer posix.close(p.w)

	s: Seen // does not drain
	add_fd(&loop, i32(p.r), {.Read, .Edge}, on_fd, &s)
	put_byte(p.w)
	wait(&loop, now() + time.Second)
	wait(&loop, now() + 10 * time.Millisecond)
	testing.expect_value(t, s.calls, 1)
}

@(test)
darwin_write_and_modify :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	p := make_pipe(t)
	defer posix.close(p.r)
	defer posix.close(p.w)

	s: Seen
	add_fd(&loop, i32(p.w), {.Write}, on_fd, &s)
	wait(&loop, now() + time.Second)
	testing.expect(t, .Write in s.ready)
	testing.expect(t, .Read not_in s.ready)

	// Back to nothing: no more calls.
	testing.expect_value(t, modify_fd(&loop, i32(p.w), {}), Error.None)
	calls := s.calls
	wait(&loop, now() + 10 * time.Millisecond)
	testing.expect_value(t, s.calls, calls)

	testing.expect_value(t, modify_fd(&loop, 999, {.Read}), Error.Not_Found)
}

@(test)
darwin_hangup :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	p := make_pipe(t)
	defer posix.close(p.r)

	s: Seen
	add_fd(&loop, i32(p.r), {.Read}, on_fd, &s)
	posix.close(p.w)
	wait(&loop, now() + time.Second)
	testing.expect(t, .Hangup in s.ready)
}

@(test)
darwin_remove_fd :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	p := make_pipe(t)
	defer posix.close(p.r)
	defer posix.close(p.w)

	s: Seen
	add_fd(&loop, i32(p.r), {.Read}, on_fd, &s)
	put_byte(p.w)
	testing.expect_value(t, remove_fd(&loop, i32(p.r)), Error.None)
	testing.expect_value(t, remove_fd(&loop, i32(p.r)), Error.Not_Found)
	wait(&loop, now() + 10 * time.Millisecond)
	testing.expect_value(t, s.calls, 0)

	// It can be added again.
	testing.expect_value(t, add_fd(&loop, i32(p.r), {.Read}, on_fd, &s), Error.None)
	wait(&loop, now() + time.Second)
	testing.expect_value(t, s.calls, 1)
}

@(test)
darwin_removed_after_close :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	p := make_pipe(t)
	defer posix.close(p.w)

	s: Seen
	add_fd(&loop, i32(p.r), {.Read}, on_fd, &s)
	posix.close(p.r)
	// Closing took it out of the kernel's set; remove_fd still cleans our table.
	testing.expect_value(t, remove_fd(&loop, i32(p.r)), Error.None)
}

@(test)
darwin_bad_fd :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	testing.expect_value(t, add_fd(&loop, -1, {.Read}, on_fd), Error.Bad_Fd)
	// A regular file's descriptor is fine for kqueue, a closed one is not.
	testing.expect_value(t, add_fd(&loop, 500, {.Read}, on_fd), Error.Register_Failed)
}

@(test)
darwin_timer_fires :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)

	s: Seen
	start := now()
	_, terr := timer_add(&loop, 20 * time.Millisecond, on_timer, &s)
	testing.expect_value(t, terr, Error.None)
	n, err := wait(&loop)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, s.timers, 1)
	testing.expect(t, now() - start >= 20 * time.Millisecond)
}

@(test)
darwin_until_deadline :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	start := now()
	n, err := wait(&loop, start + 30 * time.Millisecond)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 0)
	testing.expect(t, now() - start >= 30 * time.Millisecond)
}

@(private = "file")
wake_later :: proc(l: ^Loop) {
	time.sleep(20 * time.Millisecond)
	wake(l)
}

@(test)
darwin_wake_from_thread :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	th := thread.create_and_start_with_poly_data(&loop, wake_later)
	defer thread.destroy(th)
	start := now()
	n, err := wait(&loop, start + 5 * time.Second)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 0)
	testing.expect(t, now() - start < 2 * time.Second)
	thread.join(th)
}

@(test)
darwin_wake_before_wait :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	wake(&loop)
	start := now()
	wait(&loop, start + 5 * time.Second)
	testing.expect(t, now() - start < time.Second)
	// And the wake-up was used up.
	start = now()
	wait(&loop, start + 30 * time.Millisecond)
	testing.expect(t, now() - start >= 30 * time.Millisecond)
}

@(private = "file")
stop_later :: proc(l: ^Loop) {
	time.sleep(20 * time.Millisecond)
	stop(l)
}

@(test)
darwin_run_and_stop :: proc(t: ^testing.T) {
	loop: Loop
	testing.expect_value(t, init(&loop), Error.None)
	defer destroy(&loop)
	th := thread.create_and_start_with_poly_data(&loop, stop_later)
	defer thread.destroy(th)
	testing.expect_value(t, run(&loop), Error.None)
	thread.join(th)
}
