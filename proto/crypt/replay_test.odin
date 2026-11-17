// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "core:testing"

@(private = "file")
fresh :: proc(size: int = 64) -> (r: Replay_Window) {
	replay_init(&r, size)
	return
}

@(test)
replay_in_order_and_duplicates :: proc(t: ^testing.T) {
	r := fresh()
	for id in 1 ..= 200 {
		testing.expectf(t, replay_accept(&r, u64(id)), "id %d fresh", id)
		testing.expectf(t, !replay_accept(&r, u64(id)), "id %d duplicate", id)
	}
	testing.expect_value(t, r.top, 200)
}

@(test)
replay_zero_is_never_valid :: proc(t: ^testing.T) {
	r := fresh()
	testing.expect(t, !replay_check(&r, 0), "0 on a fresh window")
	replay_accept(&r, 5)
	testing.expect(t, !replay_check(&r, 0), "0 after traffic")
	replay_commit(&r, 0)
	testing.expect_value(t, r.top, 5)
	// An uninitialised window accepts nothing.
	blank: Replay_Window
	testing.expect(t, !replay_check(&blank, 1), "no window")
}

@(test)
replay_gap_and_reorder :: proc(t: ^testing.T) {
	r := fresh()
	testing.expect(t, replay_accept(&r, 1), "1")
	testing.expect(t, replay_accept(&r, 2), "2")
	testing.expect(t, replay_accept(&r, 5), "5 (gap of 2)")
	// The gap is filled out of order, each once.
	testing.expect(t, replay_accept(&r, 4), "4")
	testing.expect(t, replay_accept(&r, 3), "3")
	testing.expect(t, !replay_accept(&r, 3), "3 again")
	testing.expect(t, !replay_accept(&r, 4), "4 again")
	testing.expect(t, !replay_accept(&r, 5), "5 again")
	testing.expect(t, replay_accept(&r, 6), "6")
	testing.expect_value(t, r.top, 6)
}

@(test)
replay_window_edges :: proc(t: ^testing.T) {
	// Size 64: with top 100, ids 37..100 are in the window, 36 and below are too old.
	r := fresh(64)
	testing.expect(t, replay_accept(&r, 100), "100")
	testing.expect(t, replay_check(&r, 37), "100 - 37 = 63: the oldest id that is still inside")
	testing.expect(t, !replay_check(&r, 36), "100 - 36 = 64: too old")
	testing.expect(t, replay_accept(&r, 37), "37 accepted once")
	testing.expect(t, !replay_accept(&r, 37), "37 twice")
	testing.expect(t, !replay_accept(&r, 36), "36 too old")
	testing.expect(t, !replay_accept(&r, 1), "1 too old")
	// The window moves up by one: 37 falls out, 38 is the oldest.
	testing.expect(t, replay_accept(&r, 101), "101")
	testing.expect(t, !replay_check(&r, 37), "37 now out of the window")
	testing.expect(t, replay_check(&r, 38), "38 still in, not seen")
	// Same edge for the larger sizes.
	for size in ([?]int{128, 256, 1024, 2048}) {
		w := fresh(size)
		testing.expect_value(t, replay_size(&w), size)
		replay_accept(&w, 5000)
		testing.expectf(t, replay_check(&w, u64(5000 - size + 1)), "size %d: inside", size)
		testing.expectf(t, !replay_check(&w, u64(5000 - size)), "size %d: too old", size)
	}
}

@(test)
replay_first_packet_can_be_high :: proc(t: ^testing.T) {
	r := fresh()
	testing.expect(t, replay_accept(&r, 1_000_000), "first id far above 1")
	testing.expect(t, !replay_accept(&r, 999_000), "older than the window")
	testing.expect(t, replay_accept(&r, 999_999), "inside the window")
	testing.expect(t, !replay_accept(&r, 1), "1 is long gone")
}

@(test)
replay_big_jump_clears_the_window :: proc(t: ^testing.T) {
	r := fresh()
	for id in 1 ..= 64 {
		replay_accept(&r, u64(id))
	}
	// A jump of more than the window: nothing from before may count as seen
	// or as fresh.
	testing.expect(t, replay_accept(&r, 500), "500")
	for id in 1 ..= 64 {
		testing.expectf(t, !replay_check(&r, u64(id)), "id %d from before the jump", id)
	}
	// An id that falls inside the new window but was never seen is fresh.
	testing.expect(t, replay_accept(&r, 450), "450 inside the new window")
	testing.expect(t, replay_accept(&r, 437), "437: 500 - 437 = 63")
	testing.expect(t, !replay_accept(&r, 436), "436 too old")
	// Jump by exactly the size: the old top falls out.
	r = fresh()
	replay_accept(&r, 10)
	testing.expect(t, replay_accept(&r, 10 + 64), "jump by the window size")
	testing.expect(t, !replay_check(&r, 10), "old top is out")
	testing.expect(t, replay_accept(&r, 11), "inside the window, never seen")
	// Jump by size - 1: the old top is the oldest id in the window, still seen.
	r = fresh()
	replay_accept(&r, 10)
	testing.expect(t, replay_accept(&r, 10 + 63), "jump by size - 1")
	testing.expect(t, !replay_check(&r, 10), "old top is in the window and seen")
}

@(test)
replay_ring_wrap :: proc(t: ^testing.T) {
	// Walk across many ring positions with a gap pattern, so that bits are reused.
	r := fresh(64)
	seen: map[u64]bool
	seen.allocator = context.temp_allocator
	id := u64(1)
	for _ in 0 ..< 1000 {
		testing.expectf(t, replay_accept(&r, id), "id %d", id)
		seen[id] = true
		id += 3 // always leaves two ids behind
	}
	// The ids that were skipped and are still inside the window are fresh,
	// once; those that are older are refused.
	top := r.top
	for back in u64(1) ..< 64 {
		skipped := top - back
		if skipped in seen {
			testing.expectf(t, !replay_check(&r, skipped), "id %d was seen", skipped)
		} else {
			testing.expectf(t, replay_check(&r, skipped), "id %d was never seen", skipped)
		}
	}
	testing.expect(t, !replay_check(&r, top - 64), "outside")
}

@(test)
replay_high_ids :: proc(t: ^testing.T) {
	// Baseline ids go up to 2^32 - 1, epoch counters up to 2^48 - 1. No wrap.
	for top in ([?]u64{0xFFFF_FFF0, 0xFFFF_FFFF, 0xFFFF_FFFF_FFFF}) {
		r := fresh()
		testing.expect(t, replay_accept(&r, top - 10), "start")
		testing.expect(t, replay_accept(&r, top), "top")
		testing.expect(t, !replay_accept(&r, top), "top twice")
		testing.expect(t, replay_accept(&r, top - 1), "just below")
		testing.expect(t, !replay_accept(&r, top - 10), "start twice")
		testing.expect(t, !replay_accept(&r, top - 64), "outside")
	}
	// The id one past 2^32 - 1 does not wrap around to a small id.
	r := fresh()
	replay_accept(&r, 0xFFFF_FFFF)
	testing.expect(t, replay_accept(&r, 0x1_0000_0000), "2^32 is a larger id")
	testing.expect(t, !replay_accept(&r, 1), "1 is not newer")
}

// A forged packet never reaches `replay_commit`. This is what the check and
// commit split is for: a check alone changes nothing.
@(test)
replay_check_does_not_change_anything :: proc(t: ^testing.T) {
	r := fresh()
	replay_accept(&r, 10)
	before := r
	for id in ([?]u64{0, 1, 9, 10, 11, 1000, 0xFFFF_FFFF_FFFF}) {
		replay_check(&r, id)
	}
	testing.expect(t, before == r, "replay_check changed the window")
	// Commit of an id the check refuses is ignored.
	replay_commit(&r, 10)
	replay_commit(&r, 0)
	testing.expect(t, before == r, "replay_commit of a refused id changed the window")
}

@(test)
replay_sizes :: proc(t: ^testing.T) {
	r: Replay_Window
	cases := [?][2]int{{0, 64}, {1, 64}, {64, 64}, {65, 128}, {100, 128}, {129, 256}, {2048, 2048}, {5000, 2048}, {65536, 2048}}
	for c in cases {
		replay_init(&r, c[0])
		testing.expectf(t, replay_size(&r) == c[1], "size %d gives %d", c[0], replay_size(&r))
	}
	replay_init(&r)
	testing.expect_value(t, replay_size(&r), REPLAY_DEFAULT_BITS)
	// Reset forgets ids, keeps the size.
	replay_init(&r, 256)
	replay_accept(&r, 77)
	replay_reset(&r)
	testing.expect_value(t, replay_size(&r), 256)
	testing.expect(t, replay_accept(&r, 77), "77 is fresh again")
}

// Compares the window with a plain model of the spec on random
// traffic with reordering, duplicates and jumps, for several window sizes.
@(test)
replay_matches_model :: proc(t: ^testing.T) {
	for size in ([?]int{64, 128, 2048}) {
		rng := Rng {
			s = 0x9E3779B97F4A7C15 + u64(size),
		}
		r := fresh(size)
		seen: map[u64]bool
		seen.allocator = context.temp_allocator
		top := u64(0)
		base := u64(1)
		mismatches := 0
		for _ in 0 ..< 20000 {
			// Mostly near the front, sometimes a repeat, an old id, or a big jump.
			id: u64
			switch rng_below(&rng, 20) {
			case 0:
				id = base + u64(rng_below(&rng, 5000)) // jump
			case 1, 2, 3:
				id = top - u64(min(int(top), rng_below(&rng, size + 20))) // around the window edge
			case 4:
				id = 0
			case:
				id = base + u64(rng_below(&rng, 8))
			}
			// Model.
			want: bool
			switch {
			case id == 0:
				want = false
			case id > top:
				want = true
			case top - id >= u64(size):
				want = false
			case:
				want = !seen[id]
			}
			got := replay_accept(&r, id)
			if got != want {
				mismatches += 1
			}
			if want {
				seen[id] = true
				top = max(top, id)
				base = max(base, top - 3) + 1
				if rng_below(&rng, 3) == 0 {
					base = top
				}
			}
		}
		testing.expectf(t, mismatches == 0, "window %d: %d decisions differ from the model", size, mismatches)
	}
}
