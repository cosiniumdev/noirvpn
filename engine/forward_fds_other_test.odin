// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
package engine

// Only Linux can tell (forward_fds_linux_test.odin).
fwd_test_sock_ino :: proc(fd: i32) -> u64 {
	return 0
}
