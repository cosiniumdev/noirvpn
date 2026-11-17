// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package profiles

import "core:mem"
import "core:os"
import "core:strings"

// _secret_read checks the file type and size. Windows has no mode bits (the
// access list decides) and the app does not read it (secret_file_read warns).
@(private)
_secret_read :: proc(path: string, read: bool, allocator: mem.Allocator) -> (data: []u8, err: Secret_Error) {
	if !win_absolute(path) {
		return nil, .Relative
	}
	fi, e := os.lstat(path, context.temp_allocator)
	if e != nil {
		return nil, os.exists(path) ? .Io : .Missing
	}
	#partial switch fi.type {
	case .Regular:
	case .Symlink:
		return nil, .Symlink
	case:
		return nil, .Not_File
	}
	if fi.size > SECRET_FILE_MAX {
		return nil, .Too_Large
	}
	if !read {
		return nil, .None
	}
	f, oe := os.open(path)
	if oe != nil {
		return nil, .Io
	}
	defer os.close(f)
	buf := make([]u8, SECRET_FILE_MAX + 1, allocator)
	n := 0
	for n < len(buf) {
		k, re := os.read(f, buf[n:])
		if k <= 0 || re != nil {
			break
		}
		n += k
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
	return "Windows: the app does not check who else can open the file, so keep it in your own folder where no other user can access it."
}

@(private = "file")
win_absolute :: proc(path: string) -> bool {
	if strings.has_prefix(path, `\\`) {
		return true
	}
	return len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}
