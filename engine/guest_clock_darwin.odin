// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:time"

foreign import libsystem "system:System"

@(default_calling_convention = "c")
foreign libsystem {
	clock_gettime_nsec_np :: proc(clock_id: u32) -> u64 ---
}

// CLOCK_MONOTONIC_RAW counts the time of sleep. It is the same clock as
// `mach_continuous_time`. The clock of the loop (`CLOCK_UPTIME_RAW`) does not.
CLOCK_MONOTONIC_RAW :: 4

// A clock that counts the time the device sleeps.
sleep_clock :: proc() -> time.Duration {
	return time.Duration(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))
}
