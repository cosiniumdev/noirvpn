// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package event

import "base:intrinsics"
import "core:mem"
import win "core:sys/windows"
import "core:time"

// Event loop on WaitForMultipleObjects. One wait takes at most 64 objects:
// the wake event, the timer and `MAX_REGISTRATIONS` registrations (enough for
// a client).
//
// Sockets: `add_fd` (SOCKET value as an i32), each with its own WSA event
// through WSAEventSelect. Level triggering: before blocking and after waking,
// the loop asks WSAPoll which sockets are ready, so a socket with data left is
// reported again.
//
// Other objects (wintun read event, overlapped pipe event): `add_handle`,
// reported when signaled. The wait resets an auto-reset event, so a handler
// that stops before its source is empty calls `handle_again`.
Loop :: struct {
	allocator:  mem.Allocator,
	regs:       [MAX_REGISTRATIONS]Registration,
	timers:     Timer_Heap,
	now:        time.Duration, // cached clock
	stop_flag:  bool, // set by `stop`, possibly from another thread
	wake_event: win.HANDLE, // auto-reset event; `wake` signals it
	timer:      win.HANDLE, // high resolution waitable timer, nil if the system has none
	gen:        u32,
	// Scratch for one `wait`.
	handles:    [MAXIMUM_WAIT_OBJECTS]win.HANDLE,
	owners:     [MAXIMUM_WAIT_OBJECTS]i32, // registration index of each handle, -1 for none
	polls:      [MAX_REGISTRATIONS]win.WSA_POLLFD,
	poll_regs:  [MAX_REGISTRATIONS]i32,
	ready:      [MAX_REGISTRATIONS]Pending,
}

// The limit of WaitForMultipleObjects.
MAXIMUM_WAIT_OBJECTS :: 64

// The most registrations (sockets and handles together) in one loop.
MAX_REGISTRATIONS :: MAXIMUM_WAIT_OBJECTS - 2

// Called when a handle registered with `add_handle` is signaled.
Handle_Handler :: proc(loop: ^Loop, handle: win.HANDLE, user: rawptr)

@(private)
Reg_Kind :: enum u8 {
	Free,
	Socket,
	Handle,
}

@(private)
Registration :: struct {
	kind:     Reg_Kind,
	fd:       i32, // Socket
	object:   win.HANDLE, // what the loop waits on: the WSA event of a socket, or the caller's handle
	interest: Interest,
	handler:  Fd_Handler,
	hhandler: Handle_Handler,
	user:     rawptr,
	gen:      u32,
	again:    bool, // Handle: report on the next wait without a signal
}

@(private)
Pending :: struct {
	index: i32,
	gen:   u32,
	ready: Ready,
}

@(private)
Query_Time :: proc "system" (t: ^u64)

// QueryUnbiasedInterruptTimePrecise (KernelBase.dll, Windows 10): 100 ns
// units, without time in sleep or hibernation, like CLOCK_MONOTONIC.
@(private)
query_unbiased: Query_Time

@(private)
qpc_freq: i64

@(init, private)
clock_init :: proc "contextless" () {
	kb := win.GetModuleHandleW(win.L("kernelbase.dll"))
	if kb != nil {
		query_unbiased = Query_Time(win.GetProcAddress(kb, "QueryUnbiasedInterruptTimePrecise"))
	}
	f: win.LARGE_INTEGER
	win.QueryPerformanceFrequency(&f)
	qpc_freq = i64(f)
	win.ensure_winsock_initialized()
}

// Monotonic clock, nanoseconds since an arbitrary point, without sleep or
// hibernation time (QueryUnbiasedInterruptTimePrecise). Falls back to
// QueryPerformanceCounter without that call.
now :: proc "contextless" () -> time.Duration {
	if query_unbiased != nil {
		t: u64
		query_unbiased(&t)
		return time.Duration(i64(t) * 100)
	}
	c: win.LARGE_INTEGER
	win.QueryPerformanceCounter(&c)
	v := i64(c)
	if qpc_freq <= 0 {
		return time.Duration(v)
	}
	sec := v / qpc_freq
	rest := v % qpc_freq
	return time.Duration(sec * i64(time.Second) + rest * i64(time.Second) / qpc_freq)
}

// Set up a loop. Free it with `destroy`.
init :: proc(loop: ^Loop, allocator := context.allocator) -> Error {
	loop^ = {
		allocator = allocator,
	}
	timers_init(loop, allocator)
	loop.wake_event = win.CreateEventW(nil, false, false, nil)
	if loop.wake_event == nil {
		destroy(loop)
		return .System
	}
	// Windows 10 1803 and later. Without it the wait timeout is in
	// milliseconds and rounded to the system tick.
	loop.timer = win.CreateWaitableTimerExW(nil, nil, win.CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, win.TIMER_ALL_ACCESS)
	loop.now = now()
	return .None
}

destroy :: proc(loop: ^Loop) {
	for &r in loop.regs {
		if r.kind == .Socket {
			release_socket(&r)
		}
	}
	if loop.wake_event != nil {
		win.CloseHandle(loop.wake_event)
	}
	if loop.timer != nil {
		win.CloseHandle(loop.timer)
	}
	heap_destroy(&loop.timers)
	loop^ = {}
}

// Refresh the cached time (for a handler that ran for a long time).
update_time :: proc(loop: ^Loop) {
	loop.now = now()
}

@(private)
socket_of :: proc "contextless" (fd: i32) -> win.SOCKET {
	return win.SOCKET(uintptr(u32(fd)))
}

@(private)
network_events :: proc "contextless" (interest: Interest) -> i32 {
	ev: i32 = win.FD_CLOSE | win.FD_CONNECT
	if .Read in interest {
		ev |= win.FD_READ | win.FD_ACCEPT
	}
	if .Write in interest {
		ev |= win.FD_WRITE
	}
	return ev
}

@(private)
find_socket :: proc(loop: ^Loop, fd: i32) -> int {
	for &r, i in loop.regs {
		if r.kind == .Socket && r.fd == fd {
			return i
		}
	}
	return -1
}

@(private)
find_handle :: proc(loop: ^Loop, h: win.HANDLE) -> int {
	for &r, i in loop.regs {
		if r.kind == .Handle && r.object == h {
			return i
		}
	}
	return -1
}

@(private)
free_slot_index :: proc(loop: ^Loop) -> int {
	for &r, i in loop.regs {
		if r.kind == .Free {
			return i
		}
	}
	return -1
}

@(private)
release_socket :: proc(r: ^Registration) {
	// Fails when the socket was closed already: nothing is left to undo then.
	win.WSAEventSelect(socket_of(r.fd), nil, 0)
	win.WSACloseEvent(r.object)
}

// Start watching a socket (`Socket.fd` of platform/net). The loop does not
// own it: close it after `remove_fd`. After `remove_fd` the socket stays
// non-blocking (Winsock rule for WSAEventSelect).
add_fd :: proc(loop: ^Loop, fd: i32, interest: Interest, handler: Fd_Handler, user: rawptr = nil) -> Error {
	if fd < 0 {
		return .Bad_Fd
	}
	if find_socket(loop, fd) >= 0 {
		return .Exists
	}
	i := free_slot_index(loop)
	if i < 0 {
		return .Register_Failed
	}
	ev := win.WSACreateEvent()
	if ev == nil {
		return .System
	}
	if win.WSAEventSelect(socket_of(fd), ev, network_events(interest)) != 0 {
		win.WSACloseEvent(ev)
		return .Register_Failed
	}
	loop.gen += 1
	loop.regs[i] = {
		kind     = .Socket,
		fd       = fd,
		object   = ev,
		interest = interest,
		handler  = handler,
		user     = user,
		gen      = loop.gen,
	}
	return .None
}

// Change what a registered socket is watched for.
modify_fd :: proc(loop: ^Loop, fd: i32, interest: Interest) -> Error {
	i := find_socket(loop, fd)
	if i < 0 {
		return .Not_Found
	}
	r := &loop.regs[i]
	if win.WSAEventSelect(socket_of(fd), r.object, network_events(interest)) != 0 {
		return .Register_Failed
	}
	r.interest = interest
	return .None
}

// Stop watching a socket. Events already collected for it in this `wait` are
// dropped. It is fine to call this after the socket was closed.
remove_fd :: proc(loop: ^Loop, fd: i32) -> Error {
	i := find_socket(loop, fd)
	if i < 0 {
		return .Not_Found
	}
	release_socket(&loop.regs[i])
	loop.regs[i] = {}
	return .None
}

// Start watching a waitable handle (event, process, thread). The handler runs
// when it is signaled. The loop does not own the handle. A manual-reset event
// is reported on every `wait` while it stays set.
add_handle :: proc(loop: ^Loop, h: win.HANDLE, handler: Handle_Handler, user: rawptr = nil) -> Error {
	if h == nil || h == win.INVALID_HANDLE_VALUE {
		return .Bad_Fd
	}
	if find_handle(loop, h) >= 0 {
		return .Exists
	}
	i := free_slot_index(loop)
	if i < 0 {
		return .Register_Failed
	}
	loop.gen += 1
	loop.regs[i] = {
		kind     = .Handle,
		object   = h,
		hhandler = handler,
		user     = user,
		gen      = loop.gen,
	}
	return .None
}

// Stop watching a handle. Events already collected for it are dropped.
remove_handle :: proc(loop: ^Loop, h: win.HANDLE) -> Error {
	i := find_handle(loop, h)
	if i < 0 {
		return .Not_Found
	}
	loop.regs[i] = {}
	return .None
}

// Report the handle again on the next `wait`, signaled or not. For a handler
// of an auto-reset event that stopped early (a batch limit): the event will
// not be signaled for the data left.
handle_again :: proc(loop: ^Loop, h: win.HANDLE) -> Error {
	i := find_handle(loop, h)
	if i < 0 {
		return .Not_Found
	}
	loop.regs[i].again = true
	return .None
}

// Collect what is ready now, without blocking. `signaled`: the registration
// whose handle the last wait returned, or -1. Returns the number of entries
// in `loop.ready`.
@(private)
collect :: proc(loop: ^Loop, signaled: int) -> (n: int, err: Error) {
	np := 0
	for &r, i in loop.regs {
		switch r.kind {
		case .Free:
		case .Handle:
			hit := r.again || i == signaled
			if !hit {
				hit = win.WaitForSingleObject(r.object, 0) == win.WAIT_OBJECT_0
			}
			if hit {
				r.again = false
				loop.ready[n] = {
					index = i32(i),
					gen   = r.gen,
					ready = {.Read},
				}
				n += 1
			}
		case .Socket:
			ne: win.WSANETWORKEVENTS
			ready: Ready
			// Resets the WSA event and returns the events recorded since the
			// last call.
			if win.WSAEnumNetworkEvents(socket_of(r.fd), r.object, &ne) == 0 {
				ev := ne.lNetworkEvents
				if .Edge in r.interest {
					if ev & (win.FD_READ | win.FD_ACCEPT) != 0 && .Read in r.interest {
						ready += {.Read}
					}
					if ev & win.FD_WRITE != 0 && .Write in r.interest {
						ready += {.Write}
					}
				}
				if ev & win.FD_CONNECT != 0 {
					if ne.iErrorCode[FD_CONNECT_BIT] != 0 {
						ready += {.Error, .Write}
					} else if .Edge in r.interest && .Write in r.interest {
						ready += {.Write}
					}
				}
				if ev & win.FD_CLOSE != 0 {
					ready += {.Hangup}
					if ne.iErrorCode[FD_CLOSE_BIT] != 0 {
						ready += {.Error}
					}
				}
			} else if win.WSAGetLastError() == win.WSAENOTSOCK {
				// Closed before `remove_fd`: report nothing, as epoll does.
				continue
			} else {
				ready += {.Error}
			}
			if ready != {} {
				loop.ready[n] = {
					index = i32(i),
					gen   = r.gen,
					ready = ready,
				}
				n += 1
			}
			if .Edge not_in r.interest {
				events: i16
				if .Read in r.interest {
					events |= win.POLLRDNORM
				}
				if .Write in r.interest {
					events |= win.POLLWRNORM
				}
				loop.polls[np] = {
					fd     = socket_of(r.fd),
					events = events,
				}
				loop.poll_regs[np] = i32(i)
				np += 1
			}
		}
	}
	if np == 0 {
		return n, .None
	}
	if win.WSAPoll(&loop.polls[0], u32(np), 0) < 0 {
		return n, .System
	}
	for p, k in loop.polls[:np] {
		if p.revents == 0 {
			continue
		}
		ready: Ready
		if p.revents & win.POLLRDNORM != 0 {
			ready += {.Read}
		}
		if p.revents & win.POLLWRNORM != 0 {
			ready += {.Write}
		}
		if p.revents & win.POLLERR != 0 {
			ready += {.Error}
		}
		if p.revents & win.POLLHUP != 0 {
			ready += {.Hangup}
		}
		if p.revents & win.POLLNVAL != 0 {
			ready += {.Error}
		}
		if ready == {} {
			continue
		}
		idx := loop.poll_regs[k]
		merged := false
		for &e in loop.ready[:n] {
			if e.index == idx {
				e.ready += ready
				merged = true
				break
			}
		}
		if !merged {
			loop.ready[n] = {
				index = idx,
				gen   = loop.regs[idx].gen,
				ready = ready,
			}
			n += 1
		}
	}
	return n, .None
}

// Bit numbers of the error codes in WSANETWORKEVENTS.
@(private)
FD_CONNECT_BIT :: 4
@(private)
FD_CLOSE_BIT :: 5

// Block until a handle is signaled or `deadline` passes. Returns the
// registration whose handle woke the wait, or -1.
@(private)
block :: proc(loop: ^Loop, deadline: time.Duration) -> (signaled: int, err: Error) {
	for {
		count := 0
		loop.handles[count] = loop.wake_event
		loop.owners[count] = -1
		count += 1
		timer_slot := -1
		timeout := win.INFINITE
		t := now()
		if deadline != FOREVER {
			if deadline <= t {
				return -1, .None
			}
			left := i64(deadline - t)
			if loop.timer != nil {
				// Negative: a relative time, in 100 ns units. Round up.
				due := win.LARGE_INTEGER(-((left + 99) / 100))
				if win.SetWaitableTimerEx(loop.timer, &due, 0, nil, nil, nil, 0) {
					timer_slot = count
					loop.handles[count] = loop.timer
					loop.owners[count] = -1
					count += 1
				}
			}
			if timer_slot < 0 {
				// Round up so we never wake before the deadline.
				ms := (left + i64(time.Millisecond) - 1) / i64(time.Millisecond)
				timeout = win.DWORD(min(ms, i64(max(u32) - 1)))
			}
		}
		for &r, i in loop.regs {
			if r.kind != .Free {
				loop.handles[count] = r.object
				loop.owners[count] = i32(i)
				count += 1
			}
		}
		res := win.WaitForMultipleObjects(win.DWORD(count), &loop.handles[0], false, timeout)
		if res == win.WAIT_FAILED {
			return -1, .System
		}
		if res == win.WAIT_TIMEOUT || int(res) == timer_slot {
			if deadline != FOREVER && now() < deadline {
				// Early by the tick rounding, or a stale timer signal.
				continue
			}
			return -1, .None
		}
		if res >= win.WAIT_OBJECT_0 && res < win.WAIT_OBJECT_0 + win.DWORD(count) {
			idx := int(res - win.WAIT_OBJECT_0)
			return int(loop.owners[idx]), .None
		}
		// WAIT_ABANDONED_n: a mutex. Treat it as signaled.
		return -1, .None
	}
}

// Wait for events, then run handlers: sockets and handles first, then due
// timers. Blocks until the first of: a socket or handle is ready, a timer is
// due, absolute time `until` (on the `now()` clock) is reached, `wake` or
// `stop`. A ready socket is reported again on the next call, unless
// registered edge triggered.
//
// Returns the number of handlers run. 0: timeout or wake-up.
wait :: proc(loop: ^Loop, until: time.Duration = FOREVER) -> (handled: int, err: Error) {
	loop.now = now()
	deadline := until
	if next, ok := heap_peek(&loop.timers); ok && next < deadline {
		deadline = next
	}

	n := collect(loop, -1) or_return
	if n == 0 && deadline > loop.now {
		signaled := block(loop, deadline) or_return
		n = collect(loop, signaled) or_return
	}
	loop.now = now()

	for p in loop.ready[:n] {
		r := loop.regs[p.index] // a copy: the handler may change the table
		if r.gen != p.gen {
			continue // removed, or the slot was reused, during this dispatch
		}
		switch r.kind {
		case .Free:
			continue
		case .Socket:
			r.handler(loop, r.fd, p.ready, r.user)
		case .Handle:
			r.hhandler(loop, r.object, r.user)
		}
		handled += 1
	}

	handled += run_timers(loop)
	return handled, .None
}

// Run until `stop` is called.
run :: proc(loop: ^Loop) -> Error {
	for !intrinsics.atomic_load(&loop.stop_flag) {
		_, err := wait(loop)
		if err != .None {
			return err
		}
	}
	intrinsics.atomic_store(&loop.stop_flag, false)
	return .None
}

// Ask `run` to return, and wake the loop so it notices. Safe from any thread.
stop :: proc(loop: ^Loop) {
	intrinsics.atomic_store(&loop.stop_flag, true)
	wake(loop)
}

// Cause a blocked `wait` to return. Safe from any thread. A wake-up that arrives
// before the next `wait` is not lost.
wake :: proc "contextless" (loop: ^Loop) {
	win.SetEvent(loop.wake_event)
}
