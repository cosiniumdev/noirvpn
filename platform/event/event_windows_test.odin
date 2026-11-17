// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package event

import win "core:sys/windows"
import "core:testing"
import "core:thread"
import "core:time"

// The Windows backend: sockets through WSAEventSelect and WSAPoll, handles,
// wake-ups. The timer tests in timers_test.odin run here too.

@(private = "file")
Count :: struct {
	n:     int,
	ready: Ready,
	fds:   [8]i32,
}

// A small UDP pair on loopback with raw Winsock calls (platform/net tests
// import this package, so the tests here cannot import platform/net).
@(private = "file")
Udp_Pair :: struct {
	rx, tx: i32,
	to:     win.sockaddr_in,
}

@(private = "file")
udp_socket :: proc() -> i32 {
	s := win.socket(win.AF_INET, win.SOCK_DGRAM, win.IPPROTO_UDP)
	on := u32(1)
	win.ioctlsocket(s, transmute(i32)u32(win.FIONBIO), &on)
	return i32(u32(uintptr(s)))
}

@(private = "file")
sk :: proc(fd: i32) -> win.SOCKET {
	return win.SOCKET(uintptr(u32(fd)))
}

@(private = "file")
udp_pair :: proc(t: ^testing.T) -> (p: Udp_Pair, ok: bool) {
	p.rx = udp_socket()
	p.tx = udp_socket()
	sa: win.SOCKADDR_STORAGE_LH
	sin := (^win.sockaddr_in)(&sa)
	sin.sin_family = u16(win.AF_INET)
	sin.sin_addr.s_addr = transmute(u32)[4]u8{127, 0, 0, 1}
	r := win.bind(sk(p.rx), &sa, size_of(win.sockaddr_in))
	testing.expect_value(t, r, 0)
	n := i32(size_of(sa))
	win.getsockname(sk(p.rx), &sa, &n)
	p.to = sin^
	return p, r == 0
}

@(private = "file")
send_one :: proc(p: Udp_Pair) -> bool {
	msg := [3]u8{1, 2, 3}
	sa: win.SOCKADDR_STORAGE_LH
	(^win.sockaddr_in)(&sa)^ = p.to
	return win.sendto(sk(p.tx), &msg[0], 3, 0, &sa, size_of(win.sockaddr_in)) == 3
}

@(private = "file")
pair_close :: proc(p: Udp_Pair) {
	win.closesocket(sk(p.rx))
	win.closesocket(sk(p.tx))
}

@(private = "file")
new_win_loop :: proc(t: ^testing.T) -> (loop: Loop, ok: bool) {
	err := init(&loop)
	testing.expect_value(t, err, Error.None)
	return loop, err == .None
}

// Reads one datagram per call, so the rest must be reported again.
@(private = "file")
read_one :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
	c := (^Count)(user)
	if c.n < len(c.fds) {
		c.fds[c.n] = fd
	}
	c.n += 1
	c.ready += ready
	buf: [64]u8
	win.recv(sk(fd), &buf[0], len(buf), 0)
}

@(private = "file")
ms :: proc(n: i64) -> time.Duration {
	return time.Duration(n) * time.Millisecond
}

@(test)
socket_read_is_level_triggered :: proc(t: ^testing.T) {
	p, ok := udp_pair(t)
	if !ok {
		return
	}
	defer pair_close(p)
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)

	c: Count
	testing.expect_value(t, add_fd(&loop, p.rx, {.Read}, read_one, &c), Error.None)
	testing.expect_value(t, add_fd(&loop, p.rx, {.Read}, read_one, &c), Error.Exists)

	n, err := wait(&loop, now() + ms(30))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 0)

	for _ in 0 ..< 3 {
		testing.expect(t, send_one(p))
	}
	deadline := now() + 2 * time.Second
	for c.n < 3 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect_value(t, c.n, 3)
	testing.expect(t, .Read in c.ready)

	// Drained: nothing more.
	n, _ = wait(&loop, now() + ms(30))
	testing.expect_value(t, n, 0)
	testing.expect_value(t, c.n, 3)
	testing.expect_value(t, remove_fd(&loop, p.rx), Error.None)
	testing.expect_value(t, remove_fd(&loop, p.rx), Error.Not_Found)
}

@(private = "file")
note_write :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
	c := (^Count)(user)
	c.n += 1
	c.ready += ready
}

@(test)
write_interest_is_level_triggered :: proc(t: ^testing.T) {
	p, ok := udp_pair(t)
	if !ok {
		return
	}
	defer pair_close(p)
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)

	c: Count
	testing.expect_value(t, add_fd(&loop, p.tx, {.Write}, note_write, &c), Error.None)
	for _ in 0 ..< 3 {
		wait(&loop, now() + time.Second)
	}
	testing.expect_value(t, c.n, 3)
	testing.expect(t, .Write in c.ready)

	testing.expect_value(t, modify_fd(&loop, p.tx, {.Read}), Error.None)
	c = {}
	n, _ := wait(&loop, now() + ms(30))
	testing.expect_value(t, n, 0)
	testing.expect_value(t, c.n, 0)
}

@(private = "file")
Remover :: struct {
	other: i32,
	calls: int,
}

@(private = "file")
remove_other :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr) {
	r := (^Remover)(user)
	r.calls += 1
	remove_fd(loop, r.other)
}

@(test)
handler_removes_another_ready_socket :: proc(t: ^testing.T) {
	a, ok := udp_pair(t)
	if !ok {
		return
	}
	defer pair_close(a)
	b, ok2 := udp_pair(t)
	if !ok2 {
		return
	}
	defer pair_close(b)
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)

	// Both are writable at once: whichever runs first removes the other.
	ra := Remover {
		other = b.tx,
	}
	rb := Remover {
		other = a.tx,
	}
	add_fd(&loop, a.tx, {.Write}, remove_other, &ra)
	add_fd(&loop, b.tx, {.Write}, remove_other, &rb)
	n, _ := wait(&loop, now() + time.Second)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, ra.calls + rb.calls, 1)
}

@(test)
closed_socket_is_not_reported :: proc(t: ^testing.T) {
	p, ok := udp_pair(t)
	if !ok {
		return
	}
	defer win.closesocket(sk(p.rx))
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	c: Count
	add_fd(&loop, p.tx, {.Read, .Write}, note_write, &c)
	win.closesocket(sk(p.tx))
	n, err := wait(&loop, now() + ms(30))
	testing.expect_value(t, err, Error.None)
	// Another test may get the same SOCKET value at once. The loop cannot
	// tell that socket from the closed one and reports it.
	kind: i32
	kind_len := i32(size_of(kind))
	SO_TYPE :: 0x1008
	reused := win.getsockopt(sk(p.tx), win.SOL_SOCKET, SO_TYPE, ([^]u8)(&kind), &kind_len) == 0
	if !reused {
		testing.expect_value(t, n, 0)
	}
	testing.expect_value(t, remove_fd(&loop, p.tx), Error.None)
}

@(private = "file")
count_handle :: proc(loop: ^Loop, h: win.HANDLE, user: rawptr) {
	(^int)(user)^ += 1
}

@(test)
manual_reset_event_is_level_triggered :: proc(t: ^testing.T) {
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	ev := win.CreateEventW(nil, true, false, nil)
	defer win.CloseHandle(ev)

	calls := 0
	testing.expect_value(t, add_handle(&loop, ev, count_handle, &calls), Error.None)
	testing.expect_value(t, add_handle(&loop, ev, count_handle, &calls), Error.Exists)
	n, _ := wait(&loop, now() + ms(20))
	testing.expect_value(t, n, 0)

	win.SetEvent(ev)
	wait(&loop, now() + time.Second)
	wait(&loop, now() + time.Second)
	testing.expect_value(t, calls, 2)

	win.ResetEvent(ev)
	n, _ = wait(&loop, now() + ms(20))
	testing.expect_value(t, n, 0)
	testing.expect_value(t, remove_handle(&loop, ev), Error.None)
	testing.expect_value(t, remove_handle(&loop, ev), Error.Not_Found)
}

@(test)
auto_reset_event_once_then_handle_again :: proc(t: ^testing.T) {
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	ev := win.CreateEventW(nil, false, false, nil)
	defer win.CloseHandle(ev)

	calls := 0
	add_handle(&loop, ev, count_handle, &calls)
	win.SetEvent(ev)
	wait(&loop, now() + time.Second)
	testing.expect_value(t, calls, 1)
	n, _ := wait(&loop, now() + ms(20))
	testing.expect_value(t, n, 0)

	testing.expect_value(t, handle_again(&loop, ev), Error.None)
	start := now()
	n, _ = wait(&loop, now() + time.Second)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, calls, 2)
	testing.expect(t, now() - start < ms(500), "handle_again must not wait")
}

@(test)
registrations_are_limited :: proc(t: ^testing.T) {
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	events: [MAX_REGISTRATIONS + 1]win.HANDLE
	for &e in events {
		e = win.CreateEventW(nil, true, false, nil)
	}
	defer for e in events {
		win.CloseHandle(e)
	}
	calls := 0
	for e in events[:MAX_REGISTRATIONS] {
		testing.expect_value(t, add_handle(&loop, e, count_handle, &calls), Error.None)
	}
	testing.expect_value(t, add_handle(&loop, events[MAX_REGISTRATIONS], count_handle, &calls), Error.Register_Failed)

	// The last one in the wait list is seen.
	win.SetEvent(events[MAX_REGISTRATIONS - 1])
	n, _ := wait(&loop, now() + time.Second)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, add_handle(&loop, nil, count_handle, &calls), Error.Bad_Fd)
}

@(test)
wake_from_another_thread :: proc(t: ^testing.T) {
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	th := thread.create_and_start_with_data(&loop, proc(data: rawptr) {
		time.sleep(50 * time.Millisecond)
		wake((^Loop)(data))
	})
	start := now()
	n, err := wait(&loop)
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 0)
	testing.expect(t, now() - start < 5 * time.Second)
}

@(test)
wake_before_wait_is_not_lost :: proc(t: ^testing.T) {
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	wake(&loop)
	start := now()
	wait(&loop)
	testing.expect(t, now() - start < time.Second)
}

@(test)
short_timer_is_precise :: proc(t: ^testing.T) {
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	At :: struct {
		at: time.Duration,
	}
	at: At
	handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {
		(^At)(user).at = now()
	}
	start := now()
	timer_add_at(&loop, start + 3 * time.Millisecond, handler, &at)
	for at.at == 0 && now() - start < time.Second {
		wait(&loop)
	}
	took := at.at - start
	testing.expect(t, took >= 3 * time.Millisecond, "timer fired early")
	if loop.timer != nil {
		// With the high resolution timer the wait ends below the 15.6 ms tick.
		testing.expectf(t, took < 12 * time.Millisecond, "timer late: %v", took)
	}
}

@(test)
clock_is_monotonic_and_moves :: proc(t: ^testing.T) {
	a := now()
	time.sleep(5 * time.Millisecond)
	b := now()
	testing.expect(t, b - a >= 4 * time.Millisecond)
	testing.expect(t, b - a < time.Second)
}
