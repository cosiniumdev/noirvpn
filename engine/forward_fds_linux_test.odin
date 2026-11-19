// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package engine

import "core:sys/linux"

// The inode of the socket that descriptor `fd` refers to now, or 0 when the
// descriptor is not open. Socket inodes are not reused, so a test can tell a
// socket that stayed open from a descriptor number that another thread took.
fwd_test_sock_ino :: proc(fd: i32) -> u64 {
	st: linux.Stat
	if linux.fstat(linux.Fd(fd), &st) != .NONE {
		return 0
	}
	return u64(st.ino)
}
