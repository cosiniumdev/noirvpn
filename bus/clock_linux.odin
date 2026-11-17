// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:sys/linux"
import "core:time"

// Monotonic time for timeouts and the repeat-cache window. `time.tick_now`
// reads CLOCK_MONOTONIC_RAW, which NTP does not correct. On a virtual machine
// with a bad TSC calibration it was seen ~9 % off real time.
@(private)
mono_now :: proc "contextless" () -> time.Duration {
	t, _ := linux.clock_gettime(.MONOTONIC)
	return time.Duration(i64(t.time_sec) * 1e9 + i64(t.time_nsec))
}
