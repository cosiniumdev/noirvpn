// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:testing"

@(test)
send_counter_basics :: proc(t: ^testing.T) {
	c: Send_Counter
	send_counter_init(&c)
	id, tm, err := send_counter_next(&c, 1700000000)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, id, 1)
	testing.expect_value(t, tm, SPEC_TIME)
	// Time is fixed at the first packet.
	id, tm, err = send_counter_next(&c, 1700000999)
	testing.expect_value(t, id, 2)
	testing.expect_value(t, tm, SPEC_TIME)

	// Start id 0x0f000000: first wire id 0x0f000001.
	send_counter_init(&c, EARLY_NEG_START)
	id, _, err = send_counter_next(&c, 5)
	testing.expect_value(t, id, 0x0f000001)
	id, _, err = send_counter_next(&c, 5)
	testing.expect_value(t, id, 0x0f000002)

	// Negative and huge clocks are clamped, not wrapped.
	send_counter_init(&c)
	_, tm, _ = send_counter_next(&c, -50)
	testing.expect_value(t, tm, 0)
	send_counter_init(&c)
	_, tm, _ = send_counter_next(&c, 1 << 40)
	testing.expect_value(t, tm, 0xffffffff)
}

@(test)
send_counter_rollover :: proc(t: ^testing.T) {
	c := Send_Counter {
		id       = max(u32) - 1,
		time     = 1000,
		time_set = true,
	}
	id, tm, err := send_counter_next(&c, 1000)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, id, max(u32))
	testing.expect_value(t, tm, 1000)
	// Same second: refuse.
	_, _, err = send_counter_next(&c, 1000)
	testing.expect_value(t, err, Error.Counter_Exhausted)
	_, _, err = send_counter_next(&c, 999)
	testing.expect_value(t, err, Error.Counter_Exhausted)
	// A later second: time moves, id restarts at 1.
	id, tm, err = send_counter_next(&c, 1001)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, id, 1)
	testing.expect_value(t, tm, 1001)
}

@(test)
replay_window_rules :: proc(t: ^testing.T) {
	r: Replay_Window

	// Id 0 is never valid.
	testing.expect(t, !replay_check(&r, 0, 100))
	testing.expect(t, !replay_accept(&r, 0, 100))

	// Fresh: first packet, then the same one again.
	testing.expect(t, replay_accept(&r, 1, 100))
	testing.expect(t, !replay_accept(&r, 1, 100))
	// check does not commit.
	testing.expect(t, replay_check(&r, 2, 100))
	testing.expect(t, replay_check(&r, 2, 100))
	testing.expect(t, replay_accept(&r, 2, 100))
	testing.expect(t, !replay_check(&r, 2, 100))

	// Out of order inside the window.
	testing.expect(t, replay_accept(&r, 10, 100))
	testing.expect(t, replay_accept(&r, 5, 100))
	testing.expect(t, !replay_accept(&r, 5, 100))
	testing.expect(t, replay_accept(&r, 9, 100))
	testing.expect(t, !replay_accept(&r, 10, 100))
	testing.expect(t, replay_accept(&r, 3, 100))

	// An older time is refused, a newer time resets the window.
	testing.expect(t, !replay_accept(&r, 11, 99))
	testing.expect(t, replay_accept(&r, 1, 101))
	testing.expect(t, !replay_accept(&r, 1, 101))
	testing.expect(t, !replay_accept(&r, 2, 100)) // old time again
	testing.expect(t, replay_accept(&r, 2, 101))

	// Window edge: after id 100 at time 200, id 37 is the oldest accepted (distance 63).
	replay_reset(&r)
	testing.expect(t, replay_accept(&r, 100, 200))
	testing.expect(t, !replay_accept(&r, 36, 200)) // distance 64
	testing.expect(t, replay_accept(&r, 37, 200)) // distance 63
	testing.expect(t, !replay_accept(&r, 37, 200))
	// Jump far ahead: everything before falls out of the window.
	testing.expect(t, replay_accept(&r, 1000, 200))
	testing.expect(t, !replay_accept(&r, 100, 200))
	testing.expect(t, !replay_accept(&r, 936, 200)) // distance 64
	testing.expect(t, replay_accept(&r, 937, 200))
	// A jump of exactly the window size keeps the old max out.
	replay_reset(&r)
	testing.expect(t, replay_accept(&r, 5, 1))
	testing.expect(t, replay_accept(&r, 69, 1)) // +64
	testing.expect(t, !replay_accept(&r, 5, 1))
	testing.expect(t, replay_accept(&r, 6, 1))
	// A jump of 63 keeps the old max id inside.
	replay_reset(&r)
	testing.expect(t, replay_accept(&r, 5, 1))
	testing.expect(t, replay_accept(&r, 68, 1))
	testing.expect(t, !replay_accept(&r, 5, 1)) // seen, and still inside the window
	testing.expect(t, !replay_accept(&r, 4, 1)) // distance 64
	testing.expect(t, replay_accept(&r, 6, 1)) // distance 62

	// Start of time: a packet with time 0 and a valid id is fine on a fresh window.
	replay_reset(&r)
	testing.expect(t, replay_accept(&r, 1, 0))
	testing.expect(t, !replay_accept(&r, 1, 0))

	// The id near the top of the u32 range.
	replay_reset(&r)
	testing.expect(t, replay_accept(&r, max(u32), 7))
	testing.expect(t, replay_accept(&r, max(u32) - 1, 7))
	testing.expect(t, !replay_accept(&r, max(u32), 7))
}

// Reference model: remember every accepted (time, id) pair. Accept a packet if
// it is not a duplicate, its time is not below the newest, and (at the newest
// time) its id is within 64 of the largest id.
@(test)
replay_window_matches_reference_model :: proc(t: ^testing.T) {
	rng := Rng{777}
	for round in 0 ..< 50 {
		r: Replay_Window
		seen: map[[2]u32]bool
		seen.allocator = context.temp_allocator
		max_time: u32
		max_id: u32
		for _ in 0 ..< 400 {
			tm := max_time + u32(rng_below(&rng, 4) == 0 ? rng_below(&rng, 3) : 0)
			if rng_below(&rng, 20) == 0 && tm > 0 {
				tm -= 1
			}
			id: u32
			switch rng_below(&rng, 4) {
			case 0:
				id = u32(rng_below(&rng, 5))
			case 1:
				id = max_id + u32(rng_below(&rng, 3))
			case 2:
				id = max_id - min(max_id, u32(rng_below(&rng, 80)))
			case:
				id = max_id + u32(rng_below(&rng, 100))
			}

			want: bool
			switch {
			case id == 0 || tm < max_time:
				want = false
			case tm > max_time:
				want = true
			case id > max_id:
				want = true
			case:
				want = max_id - id < REPLAY_WINDOW && !seen[{tm, id}]
			}
			got := replay_accept(&r, id, tm)
			testing.expectf(t, got == want, "round %d: (id %d, time %d) max (%d, %d): got %v want %v", round, id, tm, max_id, max_time, got, want)
			if want {
				seen[{tm, id}] = true
				if tm > max_time {
					max_time = tm
					max_id = id
				} else if id > max_id {
					max_id = id
				}
			}
		}
	}
}
