// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package event

import "base:intrinsics"
import "base:runtime"
import "core:c"
import "core:mem"
import "core:sys/kqueue"
import "core:sys/posix"
import "core:time"

// Event loop on kqueue (macOS). Same names and rules as event_linux.odin.
// Differences:
//   - One kqueue filter per direction, so a readable and writable descriptor
//     gives two kernel events. `wait` merges them into one handler call.
//   - `Hangup` is EV_EOF. `Error` is EV_ERROR on the registration, or EV_EOF
//     with a socket error in `fflags`.
//   - `wake` is an EVFILT_USER event: no descriptor, safe from any thread
//     (kevent may be called from many threads on one kqueue).
//   - Clock is CLOCK_UPTIME_RAW (what kevent timeouts count on). It stops
//     while the machine sleeps.

foreign import system "system:System"

@(default_calling_convention = "c")
foreign system {
	clock_gettime_nsec_np :: proc(clock_id: u32) -> u64 ---
}

@(private)
CLOCK_UPTIME_RAW :: 8

Loop :: struct {
	kq:        kqueue.KQ,
	allocator: mem.Allocator,
	fds:       [dynamic]Fd_Entry, // indexed by descriptor number
	timers:    Timer_Heap,
	now:       time.Duration, // cached clock
	stop_flag: bool, // set by `stop`, possibly from another thread
	events:    [MAX_EVENTS]kqueue.KEvent,
}

// The ident of the EVFILT_USER event that `wake` triggers. It cannot clash
// with a descriptor: that namespace is separate for each filter.
@(private)
WAKE_IDENT :: 1

// The monotonic clock, in nanoseconds since an arbitrary point. It is the
// clock kevent timeouts use.
now :: proc "contextless" () -> time.Duration {
	return time.Duration(i64(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)))
}

// Set up a loop. Free it with `destroy`.
init :: proc(loop: ^Loop, allocator := context.allocator) -> Error {
	loop^ = {
		allocator = allocator,
		fds       = make([dynamic]Fd_Entry, allocator),
		kq        = -1,
	}
	timers_init(loop, allocator)

	kq, err := kqueue.kqueue()
	if err != .NONE {
		destroy(loop)
		return .System
	}
	loop.kq = kq
	posix.fcntl(kq, .SETFD, posix.FD_CLOEXEC)

	// The wake-up event: EV_CLEAR resets it when `wait` has taken it.
	change := [1]kqueue.KEvent{{ident = WAKE_IDENT, filter = .User, flags = {.Add, .Clear}}}
	if _, kerr := kqueue.kevent(kq, change[:], nil, nil); kerr != .NONE {
		destroy(loop)
		return .System
	}
	loop.now = now()
	return .None
}

destroy :: proc(loop: ^Loop) {
	if loop.kq >= 0 {
		posix.close(loop.kq)
	}
	delete(loop.fds)
	heap_destroy(&loop.timers)
	loop^ = {
		kq = -1,
	}
}

// Refresh the cached time (for a handler that ran for a long time).
update_time :: proc(loop: ^Loop) {
	loop.now = now()
}

// The packed `udata` of a registration: generation and descriptor.
@(private)
tag_of :: proc "contextless" (gen: u32, fd: i32) -> rawptr {
	return rawptr(uintptr(u64(gen) << 32 | u64(u32(fd))))
}

// Registers (or changes) the filters of `fd` to match `interest`. Unwanted
// filters are deleted. Deleting a filter that is not there is not an error.
@(private)
apply_interest :: proc(loop: ^Loop, fd: i32, interest: Interest, gen: u32, previous: Interest, fresh: bool) -> bool {
	changes: [2]kqueue.KEvent
	n := 0
	tag := tag_of(gen, fd)
	flags := kqueue.Flags{.Add, .Enable}
	if .Edge in interest {
		flags += {.Clear}
	}
	if .Read in interest {
		changes[n] = {
			ident  = uintptr(fd),
			filter = .Read,
			flags  = flags,
			udata  = tag,
		}
		n += 1
	} else if !fresh && .Read in previous {
		changes[n] = {
			ident  = uintptr(fd),
			filter = .Read,
			flags  = {.Delete},
		}
		n += 1
	}
	if .Write in interest {
		changes[n] = {
			ident  = uintptr(fd),
			filter = .Write,
			flags  = flags,
			udata  = tag,
		}
		n += 1
	} else if !fresh && .Write in previous {
		changes[n] = {
			ident  = uintptr(fd),
			filter = .Write,
			flags  = {.Delete},
		}
		n += 1
	}
	if n == 0 {
		return true
	}
	// With EV_RECEIPT every change gives back an event with the result in `data`,
	// so a refused registration is seen here.
	for i in 0 ..< n {
		changes[i].flags += {.Receipt}
	}
	results: [2]kqueue.KEvent
	got, err := kqueue.kevent(loop.kq, changes[:n], results[:n], nil)
	if err != .NONE {
		return false
	}
	for i in 0 ..< int(got) {
		if .Error in results[i].flags && results[i].data != 0 {
			return false
		}
	}
	return true
}

// Start watching a descriptor. The loop does not own it: close it after
// `remove_fd` (closing first also works: the kernel drops it from kqueue).
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
	if !apply_interest(loop, fd, interest, gen, {}, true) {
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
	if !apply_interest(loop, fd, interest, entry.gen, entry.interest, false) {
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
	entry := &loop.fds[fd]
	// ENOENT/EBADF: already closed or never registered for that direction.
	// EV_RECEIPT keeps the result in the event list, so the call does not fail.
	changes := [2]kqueue.KEvent {
		{ident = uintptr(fd), filter = .Read, flags = {.Delete, .Receipt}},
		{ident = uintptr(fd), filter = .Write, flags = {.Delete, .Receipt}},
	}
	results: [2]kqueue.KEvent
	_, _ = kqueue.kevent(loop.kq, changes[:], results[:], nil)
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
	ts: posix.timespec
	timeout: ^posix.timespec
	if deadline != FOREVER {
		timeout = &ts
		if deadline > t {
			// Round up to a whole millisecond so we never wake before the deadline.
			ms := (i64(deadline - t) + i64(time.Millisecond) - 1) / i64(time.Millisecond)
			ms = min(ms, i64(max(i32)))
			ts.tv_sec = posix.time_t(ms / 1000)
			ts.tv_nsec = c.long((ms % 1000) * 1_000_000)
		}
	}

	n, e := kqueue.kevent(loop.kq, nil, loop.events[:], timeout)
	if e == .EINTR {
		n = 0
	} else if e != .NONE {
		return 0, .System
	}
	loop.now = now()

	count := int(n)
	for i in 0 ..< count {
		ev := &loop.events[i]
		if ev.filter == .User {
			continue // the wake-up: nothing to drain, EV_CLEAR did it
		}
		if ev.filter != .Read && ev.filter != .Write {
			continue
		}
		key := u64(uintptr(ev.udata))
		fd := int(ev.ident)
		if fd >= len(loop.fds) {
			continue
		}
		ready: Ready
		// Merge the other events of the same descriptor into this one.
		for j in i ..< count {
			o := &loop.events[j]
			if o.ident != ev.ident || (o.filter != .Read && o.filter != .Write) {
				continue
			}
			if o.filter == .Read {
				ready += {.Read}
			} else {
				ready += {.Write}
			}
			if .Error in o.flags {
				ready += {.Error}
			}
			if .EOF in o.flags {
				ready += {.Hangup}
				// A socket with a pending error reports it in `fflags`.
				if transmute(u32)o.fflags != 0 {
					ready += {.Error}
				}
			}
			if j != i {
				// Taken: the loop above skips it.
				o.filter = .User
			}
		}
		entry := loop.fds[fd] // a copy: the handler may change the table
		if !entry.active || entry.gen != u32(key >> 32) {
			continue // removed, or the number was reused, during this dispatch
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

// Cause a blocked `wait` to return. Safe from any thread. A wake-up before the
// next `wait` is kept: the event stays triggered until `wait` takes it.
wake :: proc "contextless" (loop: ^Loop) {
	context = runtime.default_context()
	change := [1]kqueue.KEvent{{ident = WAKE_IDENT, filter = .User, fflags = {user = {.Trigger}}}}
	_, _ = kqueue.kevent(loop.kq, change[:], nil, nil)
}
