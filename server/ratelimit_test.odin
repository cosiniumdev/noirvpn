// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:testing"
import "core:time"

rkey :: proc(n: int) -> [16]u8 {
	return rate_key(addr_key_v4({10, u8(n >> 16), u8(n >> 8), u8(n)}, 1))
}

@(test)
test_rate_burst_then_refill :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	// 5 attempts per 10 seconds: a burst of 5, then one every 2 seconds.
	testing.expect(t, rate_limiter_init(&rl, Rate_Params{5, 10}))
	defer rate_limiter_destroy(&rl)
	k := rkey(1)
	for i in 0 ..< 5 {
		testing.expectf(t, rate_limiter_allow(&rl, k, 0), "attempt %d of the burst", i)
	}
	testing.expect(t, !rate_limiter_allow(&rl, k, 0))
	testing.expect(t, !rate_limiter_allow(&rl, k, 1999 * time.Millisecond))
	testing.expect(t, rate_limiter_allow(&rl, k, 2 * SEC))
	testing.expect(t, !rate_limiter_allow(&rl, k, 2 * SEC))
	// After a long pause the bucket is full again, and never fuller.
	testing.expect(t, rate_limiter_allow(&rl, k, 1000 * SEC))
	n := 1
	for rate_limiter_allow(&rl, k, 1000 * SEC) {
		n += 1
		if n > 50 {
			break
		}
	}
	testing.expect_value(t, n, 5)
}

@(test)
test_rate_sources_are_independent :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	testing.expect(t, rate_limiter_init(&rl, Rate_Params{1, 60}))
	defer rate_limiter_destroy(&rl)
	testing.expect(t, rate_limiter_allow(&rl, rkey(1), 0))
	testing.expect(t, !rate_limiter_allow(&rl, rkey(1), 1 * SEC))
	testing.expect(t, rate_limiter_allow(&rl, rkey(2), 1 * SEC))
	testing.expect(t, !rate_limiter_allow(&rl, rkey(2), 2 * SEC))
	testing.expect(t, rate_limiter_allow(&rl, rkey(1), 61 * SEC))
}

@(test)
test_rate_off :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	testing.expect(t, rate_limiter_init(&rl, Rate_Params{}))
	defer rate_limiter_destroy(&rl)
	for _ in 0 ..< 1000 {
		testing.expect(t, rate_limiter_allow(&rl, rkey(1), 0))
	}
	// Nothing is remembered when there is no per-source limit.
	testing.expect_value(t, rate_limiter_sources(&rl), 0)
}

@(test)
test_rate_bad_params :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	testing.expect(t, !rate_limiter_init(&rl, Rate_Params{5, 0}))
	testing.expect(t, !rate_limiter_init(&rl, Rate_Params{-1, 5}))
	testing.expect(t, !rate_limiter_init(&rl, Rate_Params{1, 1}, capacity = 0))
	testing.expect(t, !rate_limiter_init(&rl, Rate_Params{1, 1}, Rate_Params{3, 0}))
}

// The same decisions as a plain token bucket with a level in nanoseconds.
@(test)
test_rate_vs_reference_bucket :: proc(t: ^testing.T) {
	for seed in u64(1) ..= 6 {
		r := rng_make(seed)
		count := 1 + rng_below(&r, 20)
		secs := 1 + rng_below(&r, 30)
		rl: Rate_Limiter
		testing.expect(t, rate_limiter_init(&rl, Rate_Params{count, secs}, capacity = 64))
		defer rate_limiter_destroy(&rl)
		tau := i64(secs) * i64(SEC)
		step_ns := tau / i64(count)
		Ref :: struct {
			level: i64,
			last:  i64,
		}
		refs: [8]Ref
		for &x in refs {
			x.level = tau
		}
		now := i64(0)
		for _ in 0 ..< 5000 {
			now += i64(rng_below(&r, 3000)) * i64(time.Millisecond)
			k := rng_below(&r, len(refs))
			ref := &refs[k]
			ref.level = min(tau, ref.level + (now - ref.last))
			ref.last = now
			want := false
			if ref.level >= step_ns {
				ref.level -= step_ns
				want = true
			}
			got := rate_limiter_allow(&rl, rkey(k), time.Duration(now))
			testing.expectf(t, got == want, "count %d/%ds t=%d key %d: got %v want %v", count, secs, now, k, got, want)
		}
	}
}

@(test)
test_rate_memory_is_bounded :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	testing.expect(t, rate_limiter_init(&rl, Rate_Params{2, 10}, capacity = 100))
	defer rate_limiter_destroy(&rl)
	for i in 0 ..< 10000 {
		rate_limiter_allow(&rl, rkey(i), time.Duration(i) * time.Millisecond)
		testing.expect(t, rate_limiter_sources(&rl) <= 100)
	}
	testing.expect_value(t, rate_limiter_sources(&rl), 100)
	testing.expect_value(t, rl.evictions, u64(10000 - 100))
	testing.expect_value(t, int(rl.index.count), 100)
}

@(test)
test_rate_lru_keeps_recent :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	testing.expect(t, rate_limiter_init(&rl, Rate_Params{1, 1000}, capacity = 4))
	defer rate_limiter_destroy(&rl)
	// Four sources, each used once (their buckets are now empty).
	for i in 0 ..< 4 {
		testing.expect(t, rate_limiter_allow(&rl, rkey(i), 0))
	}
	// Touch source 0 again (refused, but it is now the most recent).
	testing.expect(t, !rate_limiter_allow(&rl, rkey(0), 1 * SEC))
	// A new source pushes out the oldest one, which is 1.
	testing.expect(t, rate_limiter_allow(&rl, rkey(100), 2 * SEC))
	testing.expect(t, !rate_limiter_allow(&rl, rkey(0), 3 * SEC)) // still remembered
	testing.expect(t, rate_limiter_allow(&rl, rkey(1), 4 * SEC)) // forgotten: fresh bucket
}

@(test)
test_rate_global_limit :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	testing.expect(t, rate_limiter_init(&rl, Rate_Params{100, 1}, Rate_Params{3, 10}))
	defer rate_limiter_destroy(&rl)
	// Different sources, but only three attempts in total per ten seconds.
	testing.expect(t, rate_limiter_allow(&rl, rkey(1), 0))
	testing.expect(t, rate_limiter_allow(&rl, rkey(2), 0))
	testing.expect(t, rate_limiter_allow(&rl, rkey(3), 0))
	testing.expect(t, !rate_limiter_allow(&rl, rkey(4), 0))
	// A refused attempt took nothing from the source bucket either.
	testing.expect(t, rate_limiter_allow(&rl, rkey(4), 4 * SEC))
}

@(test)
test_rate_global_only :: proc(t: ^testing.T) {
	rl: Rate_Limiter
	testing.expect(t, rate_limiter_init(&rl, Rate_Params{}, Rate_Params{2, 10}))
	defer rate_limiter_destroy(&rl)
	testing.expect(t, rate_limiter_allow(&rl, rkey(1), 0))
	testing.expect(t, rate_limiter_allow(&rl, rkey(1), 0))
	testing.expect(t, !rate_limiter_allow(&rl, rkey(1), 0))
	testing.expect(t, rate_limiter_allow(&rl, rkey(1), 5 * SEC))
}
