// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
package bus

import "core:time"

@(private)
mono_now :: proc "contextless" () -> time.Duration {
	return time.Duration(time.tick_now()._nsec)
}
