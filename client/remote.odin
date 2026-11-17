// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:mem"
import "noir:proto/config"

// A small deterministic generator (splitmix64). The caller supplies the seed,
// so tests repeat exactly and the policy needs no clock or system random.
Rng :: struct {
	state: u64,
}

rng_next :: proc "contextless" (r: ^Rng) -> u64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ~ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ~ (z >> 27)) * 0x94D049BB133111EB
	return z ~ (z >> 31)
}

// A number in [0, n). The bias of `% n` is far below anything that matters
// for a list of a few remotes.
rng_below :: proc "contextless" (r: ^Rng, n: int) -> int {
	if n <= 1 {
		return 0
	}
	return int(rng_next(r) % u64(n))
}

// The order in which the remotes are tried: indices into `cfg.connections`.
//   - `proto-force` keeps only the remotes that use that protocol.
//   - `remote-random` shuffles the list once, here. The order then stays fixed
//     for the life of the policy (man page: "initially randomize").
// The caller owns the result.
remote_order :: proc(
	cfg: ^config.Client_Config,
	seed: u64,
	allocator := context.allocator,
) -> (
	order: []int,
	err: mem.Allocator_Error,
) {
	list := make([dynamic]int, 0, len(cfg.connections), allocator) or_return
	for conn, i in cfg.connections {
		if pf, forced := cfg.proto_force.?; forced && conn.proto != pf {
			continue
		}
		append(&list, i)
	}
	if cfg.remote_random {
		r := Rng {
			state = seed,
		}
		// Fisher-Yates.
		for i := len(list) - 1; i > 0; i -= 1 {
			j := rng_below(&r, i + 1)
			list[i], list[j] = list[j], list[i]
		}
	}
	return list[:], nil
}

// Seconds to wait after the `fails`-th failure on one remote (counting from 1).
// `connect-retry n [max]`: wait `n` seconds between attempts. After 5 failed
// retries on one remote, the wait doubles with each further failure, up to
// `max` (default 300). A `max` below `base` is read as `base`.
backoff_seconds :: proc "contextless" (base, max_wait, fails: int) -> int {
	if base <= 0 {
		return 0
	}
	ceiling := max(max_wait, base)
	if fails <= BACKOFF_FREE_RETRIES {
		return base
	}
	secs := base
	for _ in 0 ..< fails - BACKOFF_FREE_RETRIES {
		secs *= 2
		if secs >= ceiling {
			return ceiling
		}
	}
	return secs
}

// Failures on one remote before the wait starts to grow.
BACKOFF_FREE_RETRIES :: 5
