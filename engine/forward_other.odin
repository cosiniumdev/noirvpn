// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
package engine

// The listeners of `forward` are bound to the tunnel address only.
fwd_device :: proc(d: ^Daemon) -> (name: string, limited: bool) {
	return "", false
}
