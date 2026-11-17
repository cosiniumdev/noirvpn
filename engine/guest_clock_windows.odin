// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:time"

// Windows has no guest use: this clock does not see a sleep (0 means unknown).
sleep_clock :: proc() -> time.Duration {
	return 0
}
