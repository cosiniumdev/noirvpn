// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package event

import "core:testing"
import "core:time"

// Tests of the timer queue with explicit times: no clock, no sleeping.

@(private = "file")
noop :: proc(loop: ^Loop, id: Timer_Id, user: rawptr) {}

@(private = "file")
ms :: proc(n: i64) -> time.Duration {
	return time.Duration(n) * time.Millisecond
}

@(private = "file")
tag :: proc(i: int) -> rawptr {
	return rawptr(uintptr(i))
}

// Pops everything due at `now`, returning the user tags in order.
@(private = "file")
drain :: proc(h: ^Timer_Heap, now: time.Duration, out: []int) -> int {
	n := 0
	for {
		due, ok := heap_pop_due(h, now, max(u64))
		if !ok {
			break
		}
		out[n] = int(uintptr(due.user))
		n += 1
	}
	return n
}

@(test)
heap_pops_in_deadline_order :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	heap_add(&h, ms(50), noop, tag(5))
	heap_add(&h, ms(10), noop, tag(1))
	heap_add(&h, ms(30), noop, tag(3))
	heap_add(&h, ms(20), noop, tag(2))
	heap_add(&h, ms(40), noop, tag(4))

	d, ok := heap_peek(&h)
	testing.expect(t, ok)
	testing.expect_value(t, d, ms(10))

	// Nothing is due before 10 ms.
	out: [8]int
	testing.expect_value(t, drain(&h, ms(9), out[:]), 0)
	n := drain(&h, ms(35), out[:])
	testing.expect_value(t, n, 3)
	testing.expect_value(t, out[0], 1)
	testing.expect_value(t, out[1], 2)
	testing.expect_value(t, out[2], 3)
	n = drain(&h, ms(100), out[:])
	testing.expect_value(t, n, 2)
	testing.expect_value(t, out[0], 4)
	testing.expect_value(t, out[1], 5)
	testing.expect_value(t, heap_len(&h), 0)
	_, ok = heap_peek(&h)
	testing.expect(t, !ok)
}

@(test)
heap_equal_deadlines_fire_in_arming_order :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	for i in 0 ..< 20 {
		heap_add(&h, ms(10), noop, tag(i))
	}
	out: [32]int
	n := drain(&h, ms(10), out[:])
	testing.expect_value(t, n, 20)
	for i in 0 ..< n {
		testing.expect_value(t, out[i], i)
	}
}

@(test)
heap_cancel_and_stale_ids :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	a, _ := heap_add(&h, ms(10), noop, tag(1))
	b, _ := heap_add(&h, ms(20), noop, tag(2))
	c, _ := heap_add(&h, ms(30), noop, tag(3))
	testing.expect(t, a != 0 && b != 0 && c != 0)

	testing.expect(t, heap_cancel(&h, b))
	testing.expect(t, !heap_cancel(&h, b), "second cancel must fail")
	testing.expect(t, !heap_cancel(&h, 0))
	testing.expect(t, !heap_cancel(&h, Timer_Id(0xffff_ffff)))
	testing.expect_value(t, heap_len(&h), 2)

	// The slot of `b` is reused. The old id stays dead.
	d, _ := heap_add(&h, ms(25), noop, tag(4))
	testing.expect(t, d != b)
	testing.expect(t, !heap_cancel(&h, b))
	testing.expect(t, !heap_reset(&h, b, ms(1)))

	out: [8]int
	n := drain(&h, ms(100), out[:])
	testing.expect_value(t, n, 3)
	testing.expect_value(t, out[0], 1)
	testing.expect_value(t, out[1], 4)
	testing.expect_value(t, out[2], 3)

	// A fired timer's id is dead too.
	testing.expect(t, !heap_cancel(&h, a))
}

@(test)
heap_cancel_head_and_tail :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	ids: [10]Timer_Id
	for i in 0 ..< 10 {
		ids[i], _ = heap_add(&h, ms(i64(i + 1) * 10), noop, tag(i))
	}
	testing.expect(t, heap_cancel(&h, ids[0])) // the earliest
	testing.expect(t, heap_cancel(&h, ids[9])) // the latest
	testing.expect(t, heap_cancel(&h, ids[4]))
	out: [16]int
	n := drain(&h, ms(1000), out[:])
	want := [?]int{1, 2, 3, 5, 6, 7, 8}
	testing.expect_value(t, n, len(want))
	for i in 0 ..< min(n, len(want)) {
		testing.expect_value(t, out[i], want[i])
	}
}

@(test)
heap_reset_moves_timers :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	a, _ := heap_add(&h, ms(10), noop, tag(1))
	b, _ := heap_add(&h, ms(20), noop, tag(2))
	heap_add(&h, ms(30), noop, tag(3))

	// Push the earliest back past the others, pull the middle one forward.
	testing.expect(t, heap_reset(&h, a, ms(40)))
	testing.expect(t, heap_reset(&h, b, ms(5)))
	d, _ := heap_peek(&h)
	testing.expect_value(t, d, ms(5))

	out: [8]int
	n := drain(&h, ms(100), out[:])
	testing.expect_value(t, n, 3)
	testing.expect_value(t, out[0], 2)
	testing.expect_value(t, out[1], 3)
	testing.expect_value(t, out[2], 1)
}

@(test)
heap_reset_to_same_deadline_goes_last :: proc(t: ^testing.T) {
	// Re-arming counts as arming again: it queues behind timers already there.
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	a, _ := heap_add(&h, ms(10), noop, tag(1))
	heap_add(&h, ms(10), noop, tag(2))
	heap_reset(&h, a, ms(10))
	out: [4]int
	n := drain(&h, ms(10), out[:])
	testing.expect_value(t, n, 2)
	testing.expect_value(t, out[0], 2)
	testing.expect_value(t, out[1], 1)
}

@(test)
heap_periodic_keeps_phase_and_skips_missed :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	id, _ := heap_add(&h, ms(100), noop, tag(1), interval = ms(100))

	// Due at 100: fires, next at 200.
	due, ok := heap_pop_due(&h, ms(100), max(u64))
	testing.expect(t, ok)
	testing.expect_value(t, due.id, id)
	d, _ := heap_peek(&h)
	testing.expect_value(t, d, ms(200))

	// The loop was stuck until 530: one run, next at 600.
	_, ok = heap_pop_due(&h, ms(530), max(u64))
	testing.expect(t, ok)
	d, _ = heap_peek(&h)
	testing.expect_value(t, d, ms(600))
	_, ok = heap_pop_due(&h, ms(530), max(u64))
	testing.expect(t, !ok)

	// Still valid, and cancellable.
	testing.expect(t, heap_cancel(&h, id))
}

@(test)
heap_max_seq_holds_back_new_timers :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	heap_add(&h, ms(10), noop, tag(1))
	limit := h.seq
	// Armed "during dispatch": already past due, but newer than the limit.
	heap_add(&h, ms(0), noop, tag(2))
	_, ok := heap_pop_due(&h, ms(50), limit)
	testing.expect(t, !ok)
	// The next round (a new limit) takes both, earliest deadline first.
	out: [4]int
	n := drain(&h, ms(50), out[:])
	testing.expect_value(t, n, 2)
	testing.expect_value(t, out[0], 2)
	testing.expect_value(t, out[1], 1)
}

@(test)
heap_many_random_deadlines_sorted :: proc(t: ^testing.T) {
	h: Timer_Heap
	heap_init(&h)
	defer heap_destroy(&h)

	// A fixed pseudo-random sequence, so a failure is repeatable.
	x := u64(0x9e3779b97f4a7c15)
	next :: proc(x: ^u64) -> u64 {
		x^ = x^ * 6364136223846793005 + 1442695040888963407
		return x^ >> 33
	}
	N :: 2000
	ids: [N]Timer_Id
	for i in 0 ..< N {
		ids[i], _ = heap_add(&h, time.Duration(next(&x) % 5000), noop, tag(i))
	}
	// Cancel every third and reset every fifth survivor.
	cancelled := 0
	for i in 0 ..< N {
		if i % 3 == 0 {
			testing.expect(t, heap_cancel(&h, ids[i]))
			cancelled += 1
		} else if i % 5 == 0 {
			testing.expect(t, heap_reset(&h, ids[i], time.Duration(next(&x) % 5000)))
		}
	}
	testing.expect_value(t, heap_len(&h), N - cancelled)

	last := time.Duration(-1)
	count := 0
	for {
		d, ok := heap_peek(&h)
		if !ok {
			break
		}
		due, pok := heap_pop_due(&h, max(time.Duration), max(u64))
		testing.expect(t, pok)
		testing.expect(t, d >= last, "deadlines out of order")
		last = d
		_ = due
		count += 1
	}
	testing.expect_value(t, count, N - cancelled)
}
