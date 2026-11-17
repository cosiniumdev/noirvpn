// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package event

import "base:intrinsics"
import "core:mem"
import "core:sys/linux"
import "core:time"

// The event loop on epoll. Level triggered by default (see README.md).
Loop :: struct {
	epfd:      linux.Fd,
	wake_fd:   linux.Fd, // eventfd; `wake` writes to it
	allocator: mem.Allocator,
	fds:       [dynamic]Fd_Entry, // indexed by descriptor number
	timers:    Timer_Heap,
	now:       time.Duration, // cached clock
	stop_flag: bool, // set by `stop`, possibly from another thread
	events:    [MAX_EVENTS]linux.EPoll_Event,
}

// epoll data for the wake eventfd. No real descriptor number has all bits set.
@(private)
WAKE_KEY :: max(u64)

// The monotonic clock, in nanoseconds since an arbitrary point. It is the
// clock epoll_wait timeouts use. Cost: one system call.
now :: proc "contextless" () -> time.Duration {
	ts, _ := linux.clock_gettime(.MONOTONIC)
	return time.Duration(i64(ts.time_sec) * i64(time.Second) + i64(ts.time_nsec))
}

// Set up a loop. Free it with `destroy`.
init :: proc(loop: ^Loop, allocator := context.allocator) -> Error {
	loop^ = {
		allocator = allocator,
		fds       = make([dynamic]Fd_Entry, allocator),
		epfd      = -1,
		wake_fd   = -1,
	}
	timers_init(loop, allocator)

	epfd, e := linux.epoll_create1({.FDCLOEXEC})
	if e != .NONE {
		destroy(loop)
		return .System
	}
	loop.epfd = epfd

	wake, e2 := linux.eventfd(0, {.NONBLOCK, .CLOEXEC})
	if e2 != .NONE {
		destroy(loop)
		return .System
	}
	loop.wake_fd = wake

	ev := linux.EPoll_Event {
		events = {.IN},
		data = {u64 = WAKE_KEY},
	}
	if linux.epoll_ctl(loop.epfd, .ADD, wake, &ev) != .NONE {
		destroy(loop)
		return .System
	}
	loop.now = now()
	return .None
}

destroy :: proc(loop: ^Loop) {
	if loop.wake_fd >= 0 {
		linux.close(loop.wake_fd)
	}
	if loop.epfd >= 0 {
		linux.close(loop.epfd)
	}
	delete(loop.fds)
	heap_destroy(&loop.timers)
	loop^ = {
		epfd    = -1,
		wake_fd = -1,
	}
}

// Refresh the cached time (for a handler that ran for a long time).
update_time :: proc(loop: ^Loop) {
	loop.now = now()
}

// Start watching a descriptor. The loop does not own it: close it after
// `remove_fd` (closing first also works: the kernel drops it from epoll).
add_fd :: proc(loop: ^Loop, fd: i32, interest: Interest, handler: Fd_Handler, user: rawptr = nil) -> Error {
	if fd < 0 {
		return .Bad_Fd
	}
	if int(fd) < len(loop.fds) && loop.fds[fd].active {
		return .Exists
	}
	if int(fd) >= len(loop.fds) {
		if err := resize(&loop.fds, int(fd) + 1); err != nil {
			return .Out_Of_Memory
		}
	}
	entry := &loop.fds[fd]
	gen := entry.gen + 1
	ev := linux.EPoll_Event {
		events = epoll_events(interest),
		data = {u64 = u64(gen) << 32 | u64(u32(fd))},
	}
	if linux.epoll_ctl(loop.epfd, .ADD, linux.Fd(fd), &ev) != .NONE {
		return .Register_Failed
	}
	entry^ = {
		handler  = handler,
		user     = user,
		gen      = gen,
		interest = interest,
		active   = true,
	}
	return .None
}

// Change what a registered descriptor is watched for.
modify_fd :: proc(loop: ^Loop, fd: i32, interest: Interest) -> Error {
	if fd < 0 || int(fd) >= len(loop.fds) || !loop.fds[fd].active {
		return .Not_Found
	}
	entry := &loop.fds[fd]
	ev := linux.EPoll_Event {
		events = epoll_events(interest),
		data = {u64 = u64(entry.gen) << 32 | u64(u32(fd))},
	}
	if linux.epoll_ctl(loop.epfd, .MOD, linux.Fd(fd), &ev) != .NONE {
		return .Register_Failed
	}
	entry.interest = interest
	return .None
}

// Stop watching a descriptor. Events already taken from the kernel for it
// are dropped. It is fine to call this after the descriptor was closed.
remove_fd :: proc(loop: ^Loop, fd: i32) -> Error {
	if fd < 0 || int(fd) >= len(loop.fds) || !loop.fds[fd].active {
		return .Not_Found
	}
	// EBADF/ENOENT: already closed, nothing to remove from the kernel side.
	linux.epoll_ctl(loop.epfd, .DEL, linux.Fd(fd), nil)
	entry := &loop.fds[fd]
	entry.active = false
	entry.handler = nil
	entry.user = nil
	return .None
}

// Wait for events, then run handlers: descriptors first, then due timers.
// Blocks until the first of: a descriptor is ready, a timer is due, absolute
// time `until` (on the `now()` clock) is reached, `wake` or `stop`, a signal.
// A ready descriptor is reported again on the next call, unless registered
// edge triggered.
//
// Returns the number of handlers run. 0: timeout, wake-up or signal.
wait :: proc(loop: ^Loop, until: time.Duration = FOREVER) -> (handled: int, err: Error) {
	t := now()
	loop.now = t

	deadline := until
	if next, ok := heap_peek(&loop.timers); ok && next < deadline {
		deadline = next
	}
	timeout_ms: i32 = -1
	if deadline != FOREVER {
		if deadline <= t {
			timeout_ms = 0
		} else {
			// Round up so we never wake before the deadline.
			ms := (i64(deadline - t) + i64(time.Millisecond) - 1) / i64(time.Millisecond)
			timeout_ms = i32(min(ms, i64(max(i32))))
		}
	}

	n, e := linux.epoll_wait(loop.epfd, raw_data(loop.events[:]), MAX_EVENTS, timeout_ms)
	if e == .EINTR {
		n = 0
	} else if e != .NONE {
		return 0, .System
	}
	loop.now = now()

	for i in 0 ..< int(n) {
		ev := loop.events[i]
		key := ev.data.u64
		if key == WAKE_KEY {
			drain_wake(loop)
			continue
		}
		fd := int(u32(key))
		if fd >= len(loop.fds) {
			continue
		}
		entry := loop.fds[fd] // a copy: the handler may change the table
		if !entry.active || entry.gen != u32(key >> 32) {
			continue // removed, or the number was reused, during this dispatch
		}
		ready: Ready
		if .IN in ev.events {
			ready += {.Read}
		}
		if .OUT in ev.events {
			ready += {.Write}
		}
		if .ERR in ev.events {
			ready += {.Error}
		}
		if .HUP in ev.events {
			ready += {.Hangup}
		}
		entry.handler(loop, i32(fd), ready, entry.user)
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

// Cause a blocked `wait` to return. Safe from any thread. Wake-ups that arrive
// before the next `wait` are not lost.
wake :: proc "contextless" (loop: ^Loop) {
	one := u64(1)
	linux.write(loop.wake_fd, ([^]u8)(&one)[:size_of(u64)])
}

@(private)
drain_wake :: proc(loop: ^Loop) {
	buf: [8]u8
	linux.read(loop.wake_fd, buf[:])
}

@(private)
epoll_events :: proc "contextless" (interest: Interest) -> linux.EPoll_Event_Set {
	ev: linux.EPoll_Event_Set
	if .Read in interest {
		ev += {.IN}
	}
	if .Write in interest {
		ev += {.OUT}
	}
	if .Edge in interest {
		ev += {.ET}
	}
	return ev
}
