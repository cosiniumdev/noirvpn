// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

// True if the policy holds addresses of an earlier look-up of the current
// remote that worked. A guest engine uses them if a look-up is slow or fails
// while the system tunnel stays.
policy_has_known :: proc(p: ^Policy) -> bool {
	if p.phase != .Resolve || len(p.state) == 0 {
		return false
	}
	return p.state[policy_entry(p)].known_n > 0
}
