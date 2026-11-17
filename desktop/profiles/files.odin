// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// File helpers: size-capped reads, real paths, safe writes.
//
//	write_file_atomic(path, data) -> bool
package profiles

import "core:crypto"
import "core:encoding/hex"
import "core:io"
import "core:mem"
import "core:os"
import "core:strings"

FILE_MAX :: 1024 * 1024

@(private)
FILE_MODE :: os.Permissions{.Read_User, .Write_User}
@(private)
DIR_MODE :: os.Permissions{.Read_User, .Write_User, .Execute_User}

@(private)
Read_Error :: enum u8 {
	None,
	Missing,
	Not_File,
	Too_Large,
	Io,
}

// Reads a regular file of at most `limit` bytes. `real` is the path after
// symlinks are followed, so that the caller can check where the file is.
@(private)
read_capped :: proc(
	path: string,
	limit: int,
	allocator: mem.Allocator,
) -> (
	data: []u8,
	real: string,
	err: Read_Error,
) {
	// A check before the open, so that a FIFO is never opened.
	pre, perr := os.stat(path, allocator)
	if perr != nil {
		return nil, "", perr == .Not_Exist ? .Missing : .Io
	}
	pre_type := pre.type
	os.file_info_delete(pre, allocator)
	if pre_type != .Regular {
		return nil, "", .Not_File
	}
	f, oerr := os.open(path)
	if oerr != nil {
		return nil, "", oerr == .Not_Exist ? .Missing : .Io
	}
	defer os.close(f)
	fi, serr := os.fstat(f, allocator)
	if serr != nil {
		return nil, "", .Io
	}
	defer os.file_info_delete(fi, allocator)
	if fi.type != .Regular {
		return nil, "", .Not_File
	}
	if fi.size > i64(limit) {
		return nil, "", .Too_Large
	}
	buf := make([dynamic]u8, 0, int(fi.size), allocator)
	chunk: [8192]u8
	for {
		n, rerr := os.read(f, chunk[:])
		if n > 0 {
			append(&buf, ..chunk[:n])
			if len(buf) > limit {
				delete(buf)
				return nil, "", .Too_Large
			}
		}
		if rerr != nil || n == 0 {
			if rerr != nil && rerr != io.Error.EOF {
				delete(buf)
				return nil, "", .Io
			}
			break
		}
	}
	return buf[:], strings.clone(fi.fullpath, allocator), .None
}

// The path of a directory after symlinks are followed, or "" on error.
@(private)
real_dir :: proc(path: string, allocator: mem.Allocator) -> string {
	f, err := os.open(path)
	if err != nil {
		return ""
	}
	defer os.close(f)
	fi, serr := os.fstat(f, allocator)
	if serr != nil {
		return ""
	}
	defer os.file_info_delete(fi, allocator)
	if fi.type != .Directory {
		return ""
	}
	return strings.clone(fi.fullpath, allocator)
}

// True when `path` is below `dir`. Both are real paths.
@(private)
path_inside :: proc(path, dir: string) -> bool {
	d := strings.trim_right(dir, "/\\")
	if len(path) <= len(d) + 1 || !os.is_path_separator(path[len(d)]) {
		return false
	}
	when ODIN_OS == .Windows {
		return strings.equal_fold(path[:len(d)], d)
	} else {
		return path[:len(d)] == d
	}
}

// Writes `data` to a new file next to `path` (mode 0600), syncs it and
// renames it over `path`.
write_file_atomic :: proc(path: string, data: []u8) -> bool {
	rnd: [6]u8
	crypto.rand_bytes(rnd[:])
	tag := hex.encode(rnd[:], context.temp_allocator)
	dir, base := os.split_path(path)
	if base == "" {
		return false
	}
	tmp_name := strings.concatenate({".", base, ".", string(tag), ".tmp"}, context.temp_allocator)
	tmp := tmp_name
	if dir != "" {
		joined, jerr := os.join_path({dir, tmp_name}, context.temp_allocator)
		if jerr != nil {
			return false
		}
		tmp = joined
	}
	f, err := os.open(tmp, {.Write, .Create, .Excl}, FILE_MODE)
	if err != nil {
		return false
	}
	_, werr := os.write(f, data)
	_ = os.sync(f)
	cerr := os.close(f)
	if werr != nil || cerr != nil || os.rename(tmp, path) != nil {
		_ = os.remove(tmp)
		return false
	}
	return true
}
