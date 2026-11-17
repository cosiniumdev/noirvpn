// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package event: single-thread event loop for descriptor readiness and
// timers, with one blocking call, `wait`. Linux uses epoll (README.md says why
// not core:nbio).
//
// Rules:
//   - One thread owns a loop. Only `wake` and `stop` work from other threads.
//   - Handlers run on that thread, inside `wait`. They may add or remove
//     descriptors and timers, their own included.
//   - Waiting and dispatch do not allocate. Adding may grow a table.
//
// Time: `time.Duration` on the monotonic clock (ns since an arbitrary point,
// same in every thread, no suspend time). `now()` costs a system call (no
// vDSO from Odin), so the loop caches it: relative delays count from the last
// wake-up. Use `now()` for absolute deadlines.
package event

import "core:mem"
import "core:time"

// Pass as `until` to `wait` for "no limit".
FOREVER :: time.Duration(max(i64))

Error :: enum {
	None,
	// epoll_create1, eventfd or epoll_wait failed.
	System,
	// The file descriptor is negative.
	Bad_Fd,
	// The file descriptor is already registered.
	Exists,
	// The file descriptor is not registered.
	Not_Found,
	// epoll_ctl refused (for example a regular file, which epoll cannot watch).
	Register_Failed,
	Out_Of_Memory,
}

// What a handler is told.
Ready_Kind :: enum {
	Read,
	Write,
	// An error is pending on the descriptor (read SO_ERROR on a socket).
	Error,
	// The other side closed. Data may still be readable: read until it fails.
	Hangup,
}
Ready :: bit_set[Ready_Kind]

// What a registration asks for. Errors and hangups are always reported.
Interest_Kind :: enum {
	Read,
	Write,
	// Edge triggered: report only when the state changes, so the handler must
	// read or write until the call would block. Default is level triggered.
	Edge,
}
Interest :: bit_set[Interest_Kind]

// Called when a registered descriptor is ready.
Fd_Handler :: proc(loop: ^Loop, fd: i32, ready: Ready, user: rawptr)

// Called when a timer expires. For a one-shot timer `id` is already invalid.
Timer_Handler :: proc(loop: ^Loop, id: Timer_Id, user: rawptr)

// Names one timer. Zero is never a valid id. An id for a timer that fired
// (one-shot) or was cancelled stays invalid: using it is safe and does nothing.
Timer_Id :: distinct u64

// Largest number of readiness events taken from the kernel per `wait`.
MAX_EVENTS :: 64

// ---- timers (heap) ----

// Timer queue ordered by deadline. Equal deadlines fire in arming order.
// Add, cancel and reset are O(log n). Exposed for tests without a clock; the
// loop owns one.
Timer_Heap :: struct {
	slots:     [dynamic]Timer,
	heap:      [dynamic]u32, // slot numbers, in heap order
	free_head: i32, // first free slot, or -1
	seq:       u64, // arming counter, breaks ties between equal deadlines
}

@(private)
Timer :: struct {
	deadline:  time.Duration,
	seq:       u64,
	interval:  time.Duration, // 0 for a one-shot timer
	handler:   Timer_Handler,
	user:      rawptr,
	heap_pos:  i32, // index in `heap`, or -1 when the slot is free
	gen:       u32,
	next_free: i32,
}

heap_init :: proc(h: ^Timer_Heap, allocator := context.allocator) {
	h^ = {
		slots     = make([dynamic]Timer, allocator),
		heap      = make([dynamic]u32, allocator),
		free_head = -1,
	}
}

heap_destroy :: proc(h: ^Timer_Heap) {
	delete(h.slots)
	delete(h.heap)
	h^ = {}
}

heap_len :: proc(h: ^Timer_Heap) -> int {
	return len(h.heap)
}

// Arm a timer. `interval` > 0 causes it to repeat.
heap_add :: proc(
	h: ^Timer_Heap,
	deadline: time.Duration,
	handler: Timer_Handler,
	user: rawptr,
	interval: time.Duration = 0,
) -> (
	id: Timer_Id,
	ok: bool,
) {
	slot: u32
	if h.free_head >= 0 {
		slot = u32(h.free_head)
		h.free_head = h.slots[slot].next_free
	} else {
		if _, err := append(&h.slots, Timer{gen = 1}); err != nil {
			return 0, false
		}
		slot = u32(len(h.slots) - 1)
	}
	if _, err := append(&h.heap, slot); err != nil {
		// Give the slot back.
		h.slots[slot].next_free = h.free_head
		h.free_head = i32(slot)
		return 0, false
	}
	h.seq += 1
	t := &h.slots[slot]
	t.deadline = deadline
	t.seq = h.seq
	t.interval = interval
	t.handler = handler
	t.user = user
	t.heap_pos = i32(len(h.heap) - 1)
	heap_sift_up(h, int(t.heap_pos))
	return make_id(slot, t.gen), true
}

// Remove a timer. False if the id is not valid (fired, cancelled, unknown).
heap_cancel :: proc(h: ^Timer_Heap, id: Timer_Id) -> bool {
	slot, ok := lookup(h, id)
	if !ok {
		return false
	}
	heap_remove_at(h, int(h.slots[slot].heap_pos))
	free_slot(h, slot)
	return true
}

// Move a pending timer to a new deadline. It keeps its handler and interval.
heap_reset :: proc(h: ^Timer_Heap, id: Timer_Id, deadline: time.Duration) -> bool {
	slot, ok := lookup(h, id)
	if !ok {
		return false
	}
	t := &h.slots[slot]
	t.deadline = deadline
	h.seq += 1
	t.seq = h.seq
	pos := int(t.heap_pos)
	heap_sift_down(h, pos)
	heap_sift_up(h, int(t.heap_pos))
	return true
}

// Deadline of the earliest timer.
heap_peek :: proc(h: ^Timer_Heap) -> (deadline: time.Duration, ok: bool) {
	if len(h.heap) == 0 {
		return 0, false
	}
	return h.slots[h.heap[0]].deadline, true
}

// A timer taken off the queue because it is due.
Due :: struct {
	id:      Timer_Id,
	handler: Timer_Handler,
	user:    rawptr,
}

// Take the earliest timer if its deadline is `<= now` and its arming number
// is `<= max_seq` (timers armed by handlers during one dispatch wait for the
// next `wait`). A one-shot timer is freed. A repeating timer is re-armed
// first: the next deadline keeps its phase and skips missed periods.
heap_pop_due :: proc(h: ^Timer_Heap, now: time.Duration, max_seq: u64) -> (due: Due, ok: bool) {
	if len(h.heap) == 0 {
		return {}, false
	}
	slot := h.heap[0]
	t := &h.slots[slot]
	if t.deadline > now || t.seq > max_seq {
		return {}, false
	}
	due = {
		id      = make_id(slot, t.gen),
		handler = t.handler,
		user    = t.user,
	}
	if t.interval > 0 {
		next := t.deadline + t.interval
		if next <= now {
			next += ((now - next) / t.interval + 1) * t.interval
		}
		t.deadline = next
		h.seq += 1
		t.seq = h.seq
		heap_sift_down(h, 0)
	} else {
		heap_remove_at(h, 0)
		free_slot(h, slot)
	}
	return due, true
}

@(private)
make_id :: proc "contextless" (slot: u32, gen: u32) -> Timer_Id {
	return Timer_Id(u64(gen) << 32 | u64(slot + 1))
}

@(private)
lookup :: proc(h: ^Timer_Heap, id: Timer_Id) -> (slot: u32, ok: bool) {
	low := u32(u64(id))
	if low == 0 || int(low) > len(h.slots) {
		return 0, false
	}
	slot = low - 1
	t := &h.slots[slot]
	if t.heap_pos < 0 || t.gen != u32(u64(id) >> 32) {
		return 0, false
	}
	return slot, true
}

@(private)
free_slot :: proc(h: ^Timer_Heap, slot: u32) {
	t := &h.slots[slot]
	t.heap_pos = -1
	t.handler = nil
	t.user = nil
	t.gen += 1
	if t.gen == 0 {
		t.gen = 1
	}
	t.next_free = h.free_head
	h.free_head = i32(slot)
}

@(private)
heap_less :: proc(h: ^Timer_Heap, a, b: int) -> bool {
	ta := &h.slots[h.heap[a]]
	tb := &h.slots[h.heap[b]]
	if ta.deadline != tb.deadline {
		return ta.deadline < tb.deadline
	}
	return ta.seq < tb.seq
}

@(private)
heap_swap :: proc(h: ^Timer_Heap, a, b: int) {
	h.heap[a], h.heap[b] = h.heap[b], h.heap[a]
	h.slots[h.heap[a]].heap_pos = i32(a)
	h.slots[h.heap[b]].heap_pos = i32(b)
}

@(private)
heap_sift_up :: proc(h: ^Timer_Heap, pos: int) {
	i := pos
	for i > 0 {
		parent := (i - 1) / 2
		if !heap_less(h, i, parent) {
			break
		}
		heap_swap(h, i, parent)
		i = parent
	}
}

@(private)
heap_sift_down :: proc(h: ^Timer_Heap, pos: int) {
	i := pos
	n := len(h.heap)
	for {
		l := 2 * i + 1
		if l >= n {
			break
		}
		smallest := l
		if r := l + 1; r < n && heap_less(h, r, l) {
			smallest = r
		}
		if !heap_less(h, smallest, i) {
			break
		}
		heap_swap(h, i, smallest)
		i = smallest
	}
}

// Remove the entry at heap position `pos` (the slot is freed by the caller).
@(private)
heap_remove_at :: proc(h: ^Timer_Heap, pos: int) {
	last := len(h.heap) - 1
	if pos != last {
		heap_swap(h, pos, last)
	}
	pop(&h.heap)
	if pos < len(h.heap) {
		heap_sift_down(h, pos)
		heap_sift_up(h, pos)
	}
}

// ---- loop ----

// One entry per file descriptor number, indexed by the descriptor.
@(private)
Fd_Entry :: struct {
	handler:  Fd_Handler,
	user:     rawptr,
	gen:      u32, // bumped on every registration, so stale events are dropped
	interest: Interest,
	active:   bool,
}

// Create the timer part of a loop (the OS part is in event_linux.odin).
@(private)
timers_init :: proc(loop: ^Loop, allocator: mem.Allocator) {
	heap_init(&loop.timers, allocator)
}

// Arm a timer `delay` after the loop's cached time. `interval` > 0 repeats it.
timer_add :: proc(
	loop: ^Loop,
	delay: time.Duration,
	handler: Timer_Handler,
	user: rawptr = nil,
	interval: time.Duration = 0,
) -> (
	id: Timer_Id,
	err: Error,
) {
	return timer_add_at(loop, loop.now + max(delay, 0), handler, user, interval)
}

// Arm a timer for an absolute time on the `now()` clock.
timer_add_at :: proc(
	loop: ^Loop,
	deadline: time.Duration,
	handler: Timer_Handler,
	user: rawptr = nil,
	interval: time.Duration = 0,
) -> (
	id: Timer_Id,
	err: Error,
) {
	ok: bool
	id, ok = heap_add(&loop.timers, deadline, handler, user, interval)
	if !ok {
		return 0, .Out_Of_Memory
	}
	return id, .None
}

// Cancel a timer. False if it already fired or was cancelled.
timer_cancel :: proc(loop: ^Loop, id: Timer_Id) -> bool {
	return heap_cancel(&loop.timers, id)
}

// Move a pending timer to fire `delay` after the loop's cached time. No
// allocation, so it is cheap enough for a per-packet keepalive reset.
timer_reset :: proc(loop: ^Loop, id: Timer_Id, delay: time.Duration) -> bool {
	return heap_reset(&loop.timers, id, loop.now + max(delay, 0))
}

// Move a pending timer to an absolute time.
timer_reset_at :: proc(loop: ^Loop, id: Timer_Id, deadline: time.Duration) -> bool {
	return heap_reset(&loop.timers, id, deadline)
}

// Deadline of the earliest timer, if there is one.
timer_next :: proc(loop: ^Loop) -> (deadline: time.Duration, ok: bool) {
	return heap_peek(&loop.timers)
}

// The loop's cached time: when it last woke up. Updated by `wait` and
// `update_time`.
loop_time :: proc(loop: ^Loop) -> time.Duration {
	return loop.now
}

// Run due timers. Called by `wait` after the descriptors.
@(private)
run_timers :: proc(loop: ^Loop) -> (n: int) {
	limit := loop.timers.seq
	for {
		due, ok := heap_pop_due(&loop.timers, loop.now, limit)
		if !ok {
			break
		}
		due.handler(loop, due.id, due.user)
		n += 1
	}
	return n
}
