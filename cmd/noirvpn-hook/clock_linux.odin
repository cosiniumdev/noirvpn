// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:sys/linux"
import "core:time"

// Time for timeouts. `time.tick_now` reads CLOCK_MONOTONIC_RAW, which is not
// corrected by NTP and on some machines (a virtual machine with a bad TSC
// calibration, seen here) runs several percent slow. A command timeout must
// follow real time, so this reads CLOCK_MONOTONIC.
mono_now :: proc "contextless" () -> time.Duration {
	t, _ := linux.clock_gettime(.MONOTONIC)
	return time.Duration(i64(t.time_sec) * 1e9 + i64(t.time_nsec))
}
