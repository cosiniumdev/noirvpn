// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !freestanding
package config

import "core:io"
import "core:mem"
import "core:os"

// Reads a file with core:os. The size is capped so that a path like
// /dev/zero cannot use up memory.
os_loader :: proc(_: rawptr, path: string, allocator: mem.Allocator) -> (data: []u8, ok: bool) {
	f, err := os.open(path)
	if err != nil {
		return nil, false
	}
	defer os.close(f)
	buf := make([dynamic]u8, 0, 4096, allocator)
	chunk: [8192]u8
	for {
		n, rerr := os.read(f, chunk[:])
		if n > 0 {
			append(&buf, ..chunk[:n])
			if len(buf) > DEFAULT_MAX_FILE {
				return nil, false
			}
		}
		if rerr != nil {
			if rerr == io.Error.EOF {
				break
			}
			return nil, false
		}
		if n == 0 {
			break
		}
	}
	return buf[:], true
}

default_loader: Loader = os_loader
