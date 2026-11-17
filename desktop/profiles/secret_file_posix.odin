// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !windows
package profiles

import "core:c"
import "core:mem"
import "core:strings"
import "core:sys/posix"

// _secret_read opens the file with O_NOFOLLOW, and checks the open file
// (fstat), so the file that is checked is the file that is read.
@(private)
_secret_read :: proc(path: string, read: bool, allocator: mem.Allocator) -> (data: []u8, err: Secret_Error) {
	if !strings.has_prefix(path, "/") {
		return nil, .Relative
	}
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	// O_NONBLOCK: a FIFO does not block the open; it is refused below.
	fd := posix.open(cpath, {.NOFOLLOW, .CLOEXEC, .NOCTTY, .NONBLOCK})
	if fd < 0 {
		#partial switch posix.errno() {
		case .ENOENT, .ENOTDIR:
			return nil, .Missing
		case .ELOOP, .EMLINK:
			return nil, .Symlink
		}
		return nil, .Io
	}
	defer posix.close(fd)
	st: posix.stat_t
	if posix.fstat(fd, &st) != .OK {
		return nil, .Io
	}
	switch {
	case !posix.S_ISREG(st.st_mode):
		return nil, .Not_File
	case st.st_uid != posix.getuid():
		return nil, .Owner
	case st.st_mode & {.IRGRP, .IWGRP, .IXGRP, .IROTH, .IWOTH, .IXOTH} != {}:
		return nil, .Open_Mode
	case st.st_size > SECRET_FILE_MAX:
		return nil, .Too_Large
	}
	if !read {
		return nil, .None
	}
	buf := make([]u8, SECRET_FILE_MAX + 1, allocator)
	n := 0
	for n < len(buf) {
		rest := buf[n:]
		k := posix.read(fd, raw_data(rest), c.size_t(len(rest)))
		if k < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			mem.zero_explicit(raw_data(buf), len(buf))
			delete(buf, allocator)
			return nil, .Io
		}
		if k == 0 {
			break
		}
		n += int(k)
	}
	if n > SECRET_FILE_MAX {
		mem.zero_explicit(raw_data(buf), len(buf))
		delete(buf, allocator)
		return nil, .Too_Large
	}
	return buf[:n], .None
}

@(private)
_secret_warning :: proc(path: string) -> string {
	return ""
}
