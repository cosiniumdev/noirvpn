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

// With a socket in the loop the wait list is full: the wake event, the timer,
// the event of the sockets and `MAX_HANDLES` handles.
@(test)
handles_are_limited :: proc(t: ^testing.T) {
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
	events: [MAX_HANDLES + 1]win.HANDLE
	for &e in events {
		e = win.CreateEventW(nil, true, false, nil)
	}
	defer for e in events {
		win.CloseHandle(e)
	}
	calls := 0
	for e in events[:MAX_HANDLES] {
		testing.expect_value(t, add_handle(&loop, e, count_handle, &calls), Error.None)
	}
	testing.expect_value(t, add_handle(&loop, events[MAX_HANDLES], count_handle, &calls), Error.Register_Failed)

	// The last one in the wait list is seen.
	win.SetEvent(events[MAX_HANDLES - 1])
	n, _ := wait(&loop, now() + time.Second)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, calls, 1)
	testing.expect_value(t, c.n, 0)
	testing.expect_value(t, add_handle(&loop, nil, count_handle, &calls), Error.Bad_Fd)

	// The socket is seen with every handle slot in use.
	win.ResetEvent(events[MAX_HANDLES - 1])
	testing.expect(t, send_one(p))
	deadline := now() + 2 * time.Second
	for c.n == 0 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect_value(t, c.n, 1)
	testing.expect_value(t, calls, 1)
}

// More sockets than one wait takes objects. Each one is reported.
@(test)
many_sockets_in_one_loop :: proc(t: ^testing.T) {
	N :: 200
	loop, lok := new_win_loop(t)
	if !lok {
		return
	}
	defer destroy(&loop)
	pairs: [N]Udp_Pair
	counts: [N]Count
	made := 0
	defer for p in pairs[:made] {
		pair_close(p)
	}
	for i in 0 ..< N {
		p, ok := udp_pair(t)
		if !ok {
			return
		}
		pairs[i] = p
		made += 1
		testing.expect_value(t, add_fd(&loop, p.rx, {.Read}, read_one, &counts[i]), Error.None)
	}
	testing.expect_value(t, loop.nsock, N)
	n, _ := wait(&loop, now() + ms(30))
	testing.expect_value(t, n, 0)

	// The first, one in the middle and the last.
	some := [3]int{0, N / 2, N - 1}
	for i in some {
		testing.expect(t, send_one(pairs[i]))
	}
	got := 0
	deadline := now() + 2 * time.Second
	for got < len(some) && now() < deadline {
		k, _ := wait(&loop, deadline)
		got += k
	}
	testing.expect_value(t, got, len(some))
	for i in some {
		testing.expect_value(t, counts[i].n, 1)
		testing.expect_value(t, counts[i].fds[0], pairs[i].rx)
	}

	// All at one time.
	for p in pairs {
		testing.expect(t, send_one(p))
	}
	got = 0
	deadline = now() + 2 * time.Second
	for got < N && now() < deadline {
		k, _ := wait(&loop, deadline)
		got += k
	}
	testing.expect_value(t, got, N)
	for i in 0 ..< N {
		want := 2 if i == 0 || i == N / 2 || i == N - 1 else 1
		testing.expect_value(t, counts[i].n, want)
	}
	n, _ = wait(&loop, now() + ms(30))
	testing.expect_value(t, n, 0)

	// A removed socket is not reported, the others are.
	testing.expect_value(t, remove_fd(&loop, pairs[1].rx), Error.None)
	testing.expect(t, send_one(pairs[1]))
	testing.expect(t, send_one(pairs[2]))
	deadline = now() + 2 * time.Second
	for counts[2].n < 2 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect_value(t, counts[2].n, 2)
	testing.expect_value(t, counts[1].n, 1)
}

// The table does not grow when sockets come and go.
@(test)
socket_slots_are_reused :: proc(t: ^testing.T) {
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
	c: Count
	for _ in 0 ..< 500 {
		testing.expect_value(t, add_fd(&loop, a.rx, {.Read}, read_one, &c), Error.None)
		testing.expect_value(t, add_fd(&loop, b.rx, {.Read, .Write}, read_one, &c), Error.None)
		testing.expect_value(t, remove_fd(&loop, a.rx), Error.None)
		testing.expect_value(t, remove_fd(&loop, b.rx), Error.None)
	}
	testing.expect(t, len(loop.socks) <= 2)
	testing.expect_value(t, loop.nsock, 0)
	testing.expect_value(t, loop.nenum, 0)

	testing.expect_value(t, add_fd(&loop, a.rx, {.Read}, read_one, &c), Error.None)
	testing.expect_value(t, modify_fd(&loop, a.rx, {.Read, .Write}), Error.None)
	testing.expect_value(t, loop.nenum, 1)
	testing.expect_value(t, modify_fd(&loop, a.rx, {.Read}), Error.None)
	testing.expect_value(t, loop.nenum, 0)
	testing.expect_value(t, modify_fd(&loop, b.rx, {.Read}), Error.Not_Found)
	testing.expect(t, send_one(a))
	testing.expect(t, send_one(b))
	deadline := now() + 2 * time.Second
	for c.n == 0 && now() < deadline {
		wait(&loop, deadline)
	}
	n, _ := wait(&loop, now() + ms(30))
	testing.expect_value(t, n, 0)
	testing.expect_value(t, c.n, 1)
	testing.expect_value(t, c.fds[0], a.rx)
}

// Edge triggered: data that the handler does not read is not reported again.
@(test)
edge_read_is_reported_once :: proc(t: ^testing.T) {
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
	testing.expect_value(t, add_fd(&loop, p.rx, {.Read, .Edge}, note_write, &c), Error.None)
	testing.expect(t, send_one(p))
	deadline := now() + 2 * time.Second
	for c.n == 0 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect_value(t, c.n, 1)
	testing.expect(t, .Read in c.ready)
	n, _ := wait(&loop, now() + ms(50))
	testing.expect_value(t, n, 0)
	testing.expect_value(t, c.n, 1)

	// After a read, new data is a new report.
	buf: [64]u8
	testing.expect_value(t, win.recv(sk(p.rx), &buf[0], len(buf), 0), 3)
	testing.expect(t, send_one(p))
	deadline = now() + 2 * time.Second
	for c.n < 2 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect_value(t, c.n, 2)
}

// A connect to a port with no listener is reported as an error, with other
// sockets in the loop.
@(test)
failed_connect_is_reported :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	// A port that was free a moment ago.
	sa: win.SOCKADDR_STORAGE_LH
	sin := (^win.sockaddr_in)(&sa)
	sin.sin_family = u16(win.AF_INET)
	sin.sin_addr.s_addr = transmute(u32)[4]u8{127, 0, 0, 1}
	probe := win.socket(win.AF_INET, win.SOCK_STREAM, win.IPPROTO_TCP)
	if !testing.expect_value(t, win.bind(probe, &sa, size_of(win.sockaddr_in)), 0) {
		return
	}
	n := i32(size_of(sa))
	win.getsockname(probe, &sa, &n)
	win.closesocket(probe)

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
	idle, c: Count
	testing.expect_value(t, add_fd(&loop, p.rx, {.Read}, read_one, &idle), Error.None)

	s := win.socket(win.AF_INET, win.SOCK_STREAM, win.IPPROTO_TCP)
	defer win.closesocket(s)
	on := u32(1)
	win.ioctlsocket(s, transmute(i32)u32(win.FIONBIO), &on)
	fd := i32(u32(uintptr(s)))
	// In progress: the result comes through the loop.
	win.connect(s, &sa, size_of(win.sockaddr_in))
	testing.expect_value(t, add_fd(&loop, fd, {.Read, .Write}, note_write, &c), Error.None)
	deadline := now() + 20 * time.Second
	for c.n == 0 && now() < deadline {
		wait(&loop, deadline)
	}
	testing.expect(t, c.n > 0, "the failed connect was not reported")
	testing.expect(t, .Error in c.ready)
	testing.expect_value(t, idle.n, 0)
	testing.expect_value(t, remove_fd(&loop, fd), Error.None)
}

@(private = "file")
Tcp_Pair :: struct {
	listener, client, server: win.SOCKET,
}

// A connected TCP pair on loopback, accepted through the loop: the waiting
// connection is a read report of the listener.
@(private = "file")
tcp_pair :: proc(t: ^testing.T, loop: ^Loop) -> (p: Tcp_Pair, ok: bool) {
	p.client, p.server = win.INVALID_SOCKET, win.INVALID_SOCKET
	sa: win.SOCKADDR_STORAGE_LH
	sin := (^win.sockaddr_in)(&sa)
	sin.sin_family = u16(win.AF_INET)
	sin.sin_addr.s_addr = transmute(u32)[4]u8{127, 0, 0, 1}
	p.listener = win.socket(win.AF_INET, win.SOCK_STREAM, win.IPPROTO_TCP)
	if !testing.expect_value(t, win.bind(p.listener, &sa, size_of(win.sockaddr_in)), 0) {
		return
	}
	win.listen(p.listener, 4)
	n := i32(size_of(sa))
	win.getsockname(p.listener, &sa, &n)
	lfd := i32(u32(uintptr(p.listener)))
	c: Count
	// The listener leaves the loop before `c` goes away.
	testing.expect_value(t, add_fd(loop, lfd, {.Read}, note_write, rawptr(&c)), Error.None)
	k, _ := wait(loop, now() + ms(30))
	testing.expect_value(t, k, 0)

	p.client = win.socket(win.AF_INET, win.SOCK_STREAM, win.IPPROTO_TCP)
	if !testing.expect_value(t, win.connect(p.client, &sa, size_of(win.sockaddr_in)), 0) {
		return
	}
	deadline := now() + 2 * time.Second
	for c.n == 0 && now() < deadline {
		wait(loop, deadline)
	}
	testing.expect(t, .Read in c.ready, "the waiting connection was not reported")
	p.server = win.accept(p.listener, nil, nil)
	testing.expect_value(t, remove_fd(loop, lfd), Error.None)
	return p, testing.expect(t, p.server != win.INVALID_SOCKET)
}

@(private = "file")
tcp_pair_close :: proc(p: Tcp_Pair) {
	for s in ([3]win.SOCKET{p.listener, p.client, p.server}) {
		if s != win.INVALID_SOCKET {
			win.closesocket(s)
		}
	}
}

// A socket that is watched for data only: the close of the peer and a reset
// are reported, and nothing is reported while the connection is idle.
@(test)
peer_close_is_reported :: proc(t: ^testing.T) {
	for reset in ([2]bool{false, true}) {
		loop, lok := new_win_loop(t)
		if !lok {
			return
		}
		defer destroy(&loop)
		p, ok := tcp_pair(t, &loop)
		if !ok {
			tcp_pair_close(p)
			return
		}
		sfd := i32(u32(uintptr(p.server)))
		c: Count
		testing.expect_value(t, add_fd(&loop, sfd, {.Read}, note_write, &c), Error.None)
		n, _ := wait(&loop, now() + ms(30))
		testing.expect_value(t, n, 0)

		msg := [3]u8{1, 2, 3}
		testing.expect_value(t, win.send(p.client, &msg[0], 3, 0), 3)
		deadline := now() + 2 * time.Second
		for c.n == 0 && now() < deadline {
			wait(&loop, deadline)
		}
		testing.expect(t, .Read in c.ready)
		buf: [64]u8
		testing.expect_value(t, win.recv(p.server, &buf[0], len(buf), 0), 3)
		c = {}
		n, _ = wait(&loop, now() + ms(30))
		testing.expect_value(t, n, 0)

		if reset {
			// No wait at close: the peer gets a reset.
			lg := win.LINGER {
				l_onoff = 1,
			}
			win.setsockopt(p.client, win.SOL_SOCKET, win.SO_LINGER, &lg, size_of(lg))
		}
		win.closesocket(p.client)
		p.client = win.INVALID_SOCKET
		deadline = now() + 2 * time.Second
		for c.n == 0 && now() < deadline {
			wait(&loop, deadline)
		}
		testing.expect(t, c.ready & {.Read, .Hangup, .Error} != {}, "the end of the connection was not reported")
		got := win.recv(p.server, &buf[0], len(buf), 0)
		if reset {
			testing.expect(t, got < 0, "no error after a reset")
		} else {
			testing.expect_value(t, got, 0)
		}
		testing.expect_value(t, remove_fd(&loop, sfd), Error.None)
		tcp_pair_close(p)
	}
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
