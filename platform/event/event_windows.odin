// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package event

import "base:intrinsics"
import "core:mem"
import win "core:sys/windows"
import "core:time"

// Event loop on WaitForMultipleObjects. One wait takes at most 64 objects:
// the wake event, the timer, one event for all sockets and `MAX_HANDLES`
// handles.
//
// Sockets: `add_fd` (SOCKET value as an i32). All sockets of a loop use one
// WSA event (WSAEventSelect). That event only ends the wait, so the number of
// sockets has no fixed limit. Level triggering: before blocking and after
// waking, the loop asks WSAPoll which sockets are ready, so a socket with
// data left is reported again. That is one call for all sockets.
//
// The events that Winsock recorded for a socket (WSAEnumNetworkEvents) are
// read only for an edge triggered socket and for a socket with write
// interest. There they report a failed connect, which WSAPoll reports only
// since Windows 10 2004. A socket that only waits for data costs no system
// call of its own.
//
// Other objects (wintun read event, overlapped pipe event): `add_handle`,
// reported when signaled. The wait resets an auto-reset event, so a handler
// that stops before its source is empty calls `handle_again`.
Loop :: struct {
	allocator:  mem.Allocator,
	hregs:      [MAX_HANDLES]Registration, // handles
	socks:      [dynamic]Registration, // sockets; the free slots are a list through `fd`
	sock_free:  i32, // first free slot of `socks`, -1 for none
	by_fd:      map[i32]i32, // socket -> slot of `socks`
	nsock:      int, // registered sockets
	nenum:      int, // of them, sockets whose recorded events are read
	sock_event: win.HANDLE, // manual-reset WSA event of all sockets
	timers:     Timer_Heap,
	now:        time.Duration, // cached clock
	stop_flag:  bool, // set by `stop`, possibly from another thread
	wake_event: win.HANDLE, // auto-reset event; `wake` signals it
	timer:      win.HANDLE, // high resolution waitable timer, nil if the system has none
	gen:        u32,
	// Scratch for one `wait`.
	handles:    [MAXIMUM_WAIT_OBJECTS]win.HANDLE,
	owners:     [MAXIMUM_WAIT_OBJECTS]i32, // what each handle is: a slot of `hregs`, or a SIG value
	polls:      [dynamic]win.WSA_POLLFD,
	poll_regs:  [dynamic]i32,
	ready:      [dynamic]Pending,
}

// The limit of WaitForMultipleObjects.
MAXIMUM_WAIT_OBJECTS :: 64

// The most handles of `add_handle` in one loop. Sockets have no limit.
MAX_HANDLES :: MAXIMUM_WAIT_OBJECTS - 3

// What ended a wait, when it was not a handle of `hregs`.
@(private)
SIG_NONE :: -1 // the wake event, the timer or the timeout
@(private)
SIG_SOCKETS :: -2 // the event of the sockets

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
	fd:       i32, // Socket; in a free slot of `socks`, the next free slot or -1
	object:   win.HANDLE, // Handle: the caller's handle
	interest: Interest,
	handler:  Fd_Handler,
	hhandler: Handle_Handler,
	user:     rawptr,
	gen:      u32,
	again:    bool, // Handle: report on the next wait without a signal
	slot:     i32, // Socket: its entry of `ready` in the current collect, -1 for none
}

@(private)
Pending :: struct {
	index:  i32,
	gen:    u32,
	ready:  Ready,
	handle: bool, // `index` is a slot of `hregs`; if not, of `socks`
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
		sock_free = -1,
	}
	loop.socks.allocator = allocator
	loop.polls.allocator = allocator
	loop.poll_regs.allocator = allocator
	loop.ready.allocator = allocator
	loop.by_fd.allocator = allocator
	timers_init(loop, allocator)
	loop.wake_event = win.CreateEventW(nil, false, false, nil)
	loop.sock_event = win.WSACreateEvent()
	if loop.wake_event == nil || loop.sock_event == nil {
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
	for &r in loop.socks {
		if r.kind == .Socket {
			release_socket(&r)
		}
	}
	if loop.wake_event != nil {
		win.CloseHandle(loop.wake_event)
	}
	if loop.sock_event != nil {
		win.WSACloseEvent(loop.sock_event)
	}
	if loop.timer != nil {
		win.CloseHandle(loop.timer)
	}
	heap_destroy(&loop.timers)
	delete(loop.socks)
	delete(loop.polls)
	delete(loop.poll_regs)
	delete(loop.ready)
	delete(loop.by_fd)
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

// True for a socket whose recorded events the loop reads (see `Loop`).
@(private)
reads_events :: proc "contextless" (interest: Interest) -> bool {
	return .Edge in interest || .Write in interest
}

@(private)
find_handle :: proc(loop: ^Loop, h: win.HANDLE) -> int {
	for &r, i in loop.hregs {
		if r.kind == .Handle && r.object == h {
			return i
		}
	}
	return -1
}

// Takes a free slot of `socks`, or adds one. Returns -1 with no memory.
@(private)
sock_slot_take :: proc(loop: ^Loop) -> i32 {
	i := loop.sock_free
	if i >= 0 {
		loop.sock_free = loop.socks[i].fd
		return i
	}
	if _, err := append(&loop.socks, Registration{}); err != nil {
		return -1
	}
	return i32(len(loop.socks) - 1)
}

@(private)
sock_slot_give :: proc(loop: ^Loop, i: i32) {
	loop.socks[i] = {
		fd = loop.sock_free,
	}
	loop.sock_free = i
}

@(private)
release_socket :: proc(r: ^Registration) {
	// Fails when the socket was closed already: nothing is left to undo then.
	win.WSAEventSelect(socket_of(r.fd), nil, 0)
}

// Start watching a socket (`Socket.fd` of platform/net). The loop does not
// own it: close it after `remove_fd`. After `remove_fd` the socket stays
// non-blocking (Winsock rule for WSAEventSelect).
add_fd :: proc(loop: ^Loop, fd: i32, interest: Interest, handler: Fd_Handler, user: rawptr = nil) -> Error {
	if fd < 0 {
		return .Bad_Fd
	}
	if fd in loop.by_fd {
		return .Exists
	}
	i := sock_slot_take(loop)
	if i < 0 {
		return .Out_Of_Memory
	}
	loop.by_fd[fd] = i
	if fd not_in loop.by_fd {
		sock_slot_give(loop, i)
		return .Out_Of_Memory
	}
	if win.WSAEventSelect(socket_of(fd), loop.sock_event, network_events(interest)) != 0 {
		delete_key(&loop.by_fd, fd)
		sock_slot_give(loop, i)
		return .Register_Failed
	}
	loop.gen += 1
	loop.socks[i] = {
		kind     = .Socket,
		fd       = fd,
		interest = interest,
		handler  = handler,
		user     = user,
		gen      = loop.gen,
		slot     = -1,
	}
	loop.nsock += 1
	if reads_events(interest) {
		loop.nenum += 1
	}
	return .None
}

// Change what a registered socket is watched for.
modify_fd :: proc(loop: ^Loop, fd: i32, interest: Interest) -> Error {
	i, found := loop.by_fd[fd]
	if !found {
		return .Not_Found
	}
	r := &loop.socks[i]
	if win.WSAEventSelect(socket_of(fd), loop.sock_event, network_events(interest)) != 0 {
		return .Register_Failed
	}
	if reads_events(r.interest) {
		loop.nenum -= 1
	}
	if reads_events(interest) {
		loop.nenum += 1
	}
	r.interest = interest
	return .None
}

// Stop watching a socket. Events already collected for it in this `wait` are
// dropped. It is fine to call this after the socket was closed.
remove_fd :: proc(loop: ^Loop, fd: i32) -> Error {
	i, found := loop.by_fd[fd]
	if !found {
		return .Not_Found
	}
	r := &loop.socks[i]
	release_socket(r)
	if reads_events(r.interest) {
		loop.nenum -= 1
	}
	loop.nsock -= 1
	delete_key(&loop.by_fd, fd)
	sock_slot_give(loop, i)
	return .None
}

// Start watching a waitable handle (event, process, thread). The handler runs
// when it is signaled. The loop does not own the handle. A manual-reset event
// is reported on every `wait` while it stays set. A loop takes `MAX_HANDLES`
// handles.
add_handle :: proc(loop: ^Loop, h: win.HANDLE, handler: Handle_Handler, user: rawptr = nil) -> Error {
	if h == nil || h == win.INVALID_HANDLE_VALUE {
		return .Bad_Fd
	}
	if find_handle(loop, h) >= 0 {
		return .Exists
	}
	i := -1
	for &r, k in loop.hregs {
		if r.kind == .Free {
			i = k
			break
		}
	}
	if i < 0 {
		return .Register_Failed
	}
	loop.gen += 1
	loop.hregs[i] = {
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
	loop.hregs[i] = {}
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
	loop.hregs[i].again = true
	return .None
}

// Collect what is ready now, without blocking. `signaled`: what ended the
// last wait (a slot of `hregs` or a SIG value). Returns the number of entries
// in `loop.ready`.
@(private)
collect :: proc(loop: ^Loop, signaled: int) -> (n: int, err: Error) {
	// The scratch lists grow here. A handler can call `add_fd`, and `wait`
	// reads `ready` at that time.
	if want := cap(loop.socks); len(loop.polls) < want {
		if resize(&loop.ready, want + MAX_HANDLES) != nil || resize(&loop.poll_regs, want) != nil || resize(&loop.polls, want) != nil {
			return 0, .Out_Of_Memory
		}
	}
	if len(loop.ready) < MAX_HANDLES && resize(&loop.ready, MAX_HANDLES) != nil {
		return 0, .Out_Of_Memory
	}

	for &r, i in loop.hregs {
		if r.kind != .Handle {
			continue
		}
		hit := r.again || i == signaled
		if !hit {
			hit = win.WaitForSingleObject(r.object, 0) == win.WAIT_OBJECT_0
		}
		if hit {
			r.again = false
			loop.ready[n] = {
				index  = i32(i),
				gen    = r.gen,
				ready  = {.Read},
				handle = true,
			}
			n += 1
		}
	}
	if loop.nsock == 0 {
		return n, .None
	}

	// `fresh`: Winsock recorded an event since the last reset. The reset
	// comes before the reads, so an event that arrives later sets the event
	// again and is not lost.
	fresh := signaled == SIG_SOCKETS
	if !fresh && loop.nenum > 0 {
		fresh = win.WaitForSingleObject(loop.sock_event, 0) == win.WAIT_OBJECT_0
	}
	if fresh {
		win.ResetEvent(loop.sock_event)
	}
	np := 0
	for &r, i in loop.socks {
		if r.kind != .Socket {
			continue
		}
		r.slot = -1
		if fresh && reads_events(r.interest) {
			ne: win.WSANETWORKEVENTS
			ready: Ready
			// Returns the events recorded since the last call.
			if win.WSAEnumNetworkEvents(socket_of(r.fd), nil, &ne) == 0 {
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
				r.slot = i32(n)
				loop.ready[n] = {
					index = i32(i),
					gen   = r.gen,
					ready = ready,
				}
				n += 1
			}
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
	if np == 0 {
		return n, .None
	}
	if win.WSAPoll(&loop.polls[0], u32(np), 0) < 0 {
		if win.WSAGetLastError() != win.WSAENOTSOCK {
			return n, .System
		}
		// A socket of the list was closed before `remove_fd`. Ask for each
		// socket alone, so that the others are still reported.
		for &p in loop.polls[:np] {
			p.revents = 0
			if win.WSAPoll(&p, 1, 0) < 0 {
				p.revents = 0
			}
		}
	}
	for p, k in loop.polls[:np] {
		// POLLNVAL: closed before `remove_fd`. Report nothing, as epoll does.
		if p.revents == 0 || p.revents & win.POLLNVAL != 0 {
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
		if ready == {} {
			continue
		}
		idx := loop.poll_regs[k]
		r := &loop.socks[idx]
		if r.slot >= 0 {
			loop.ready[r.slot].ready += ready
		} else {
			loop.ready[n] = {
				index = idx,
				gen   = r.gen,
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

// Block until a handle is signaled or `deadline` passes. Returns what ended
// the wait: a slot of `hregs`, or a SIG value.
@(private)
block :: proc(loop: ^Loop, deadline: time.Duration) -> (signaled: int, err: Error) {
	for {
		count := 0
		loop.handles[count] = loop.wake_event
		loop.owners[count] = SIG_NONE
		count += 1
		timer_slot := -1
		timeout := win.INFINITE
		t := now()
		if deadline != FOREVER {
			if deadline <= t {
				return SIG_NONE, .None
			}
			left := i64(deadline - t)
			if loop.timer != nil {
				// Negative: a relative time, in 100 ns units. Round up.
				due := win.LARGE_INTEGER(-((left + 99) / 100))
				if win.SetWaitableTimerEx(loop.timer, &due, 0, nil, nil, nil, 0) {
					timer_slot = count
					loop.handles[count] = loop.timer
					loop.owners[count] = SIG_NONE
					count += 1
				}
			}
			if timer_slot < 0 {
				// Round up so we never wake before the deadline.
				ms := (left + i64(time.Millisecond) - 1) / i64(time.Millisecond)
				timeout = win.DWORD(min(ms, i64(max(u32) - 1)))
			}
		}
		if loop.nsock > 0 {
			loop.handles[count] = loop.sock_event
			loop.owners[count] = SIG_SOCKETS
			count += 1
		}
		for &r, i in loop.hregs {
			if r.kind == .Handle {
				loop.handles[count] = r.object
				loop.owners[count] = i32(i)
				count += 1
			}
		}
		res := win.WaitForMultipleObjects(win.DWORD(count), &loop.handles[0], false, timeout)
		if res == win.WAIT_FAILED {
			return SIG_NONE, .System
		}
		if res == win.WAIT_TIMEOUT || int(res) == timer_slot {
			if deadline != FOREVER && now() < deadline {
				// Early by the tick rounding, or a stale timer signal.
				continue
			}
			return SIG_NONE, .None
		}
		if res >= win.WAIT_OBJECT_0 && res < win.WAIT_OBJECT_0 + win.DWORD(count) {
			idx := int(res - win.WAIT_OBJECT_0)
			return int(loop.owners[idx]), .None
		}
		// WAIT_ABANDONED_n: a mutex. Treat it as signaled.
		return SIG_NONE, .None
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

	n := collect(loop, SIG_NONE) or_return
	if n == 0 && deadline > loop.now {
		for {
			signaled := block(loop, deadline) or_return
			n = collect(loop, signaled) or_return
			// The event of the sockets can be set with nothing to report: an
			// event that was reported before, or one that no socket is
			// watched for. Wait again.
			if n > 0 || signaled != SIG_SOCKETS {
				break
			}
		}
	}
	loop.now = now()

	for k in 0 ..< n {
		p := loop.ready[k]
		// A copy of the registration: the handler may change the tables. A
		// different `gen`: removed, or the slot was reused, in this dispatch.
		if p.handle {
			r := loop.hregs[p.index]
			if r.gen != p.gen || r.kind != .Handle {
				continue
			}
			r.hhandler(loop, r.object, r.user)
		} else {
			r := loop.socks[p.index]
			if r.gen != p.gen || r.kind != .Socket {
				continue
			}
			r.handler(loop, r.fd, p.ready, r.user)
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
