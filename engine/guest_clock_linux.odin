// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:sys/linux"
import "core:time"

// A clock that counts the time the device sleeps: CLOCK_BOOTTIME. The
// clock of the loop (CLOCK_MONOTONIC) does not.
sleep_clock :: proc() -> time.Duration {
	ts, err := linux.clock_gettime(.BOOTTIME)
	if err != .NONE {
		return 0
	}
	return time.Duration(ts.time_sec) * time.Second + time.Duration(ts.time_nsec)
}
