// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// The files of `auth-user-pass FILE` and `askpass FILE`.
// The service runs as root and never opens a path a profile names; the app reads
// the file as the user and passes the content with `auth.supply`. It reads a
// file only if all hold:
//   - path is absolute
//   - regular file, not a symbolic link
//   - owned by the current user (POSIX)
//   - no group or other permission (POSIX: mode 0600 or 0400)
//   - at most SECRET_FILE_MAX bytes
// Windows does not check owner or permissions (the access list decides);
// secret_file_read says so in `warning`.
//
//	secret_file_read(path, allocator) -> (data, problem, warning)  wipe data after use
//	secret_file_problem(path) -> string                            the same checks, without the read
//	secret_login(data) -> (user, pass, problem)                    the two lines of an auth-user-pass file
//	secret_first_line(data) -> string                              the passphrase of an askpass file
package profiles

import "core:fmt"
import "core:strings"

SECRET_FILE_MAX :: 4096

@(private)
Secret_Error :: enum u8 {
	None,
	Relative,
	Missing,
	Symlink,
	Not_File,
	Owner,
	Open_Mode, // the group or others have a permission
	Too_Large,
	Io,
}

// secret_problem_text is one sentence that names the problem and the fix.
@(private)
secret_problem_text :: proc(err: Secret_Error, path: string) -> string {
	switch err {
	case .None:
		return ""
	case .Relative:
		return fmt.tprintf("%s is not a full path. Enter the full path, starting from the root of the disk.", path)
	case .Missing:
		return fmt.tprintf("%s does not exist.", path)
	case .Symlink:
		return fmt.tprintf("%s is a symbolic link. Use the path of the actual file instead.", path)
	case .Not_File:
		return fmt.tprintf("%s is not a regular file.", path)
	case .Owner:
		return fmt.tprintf("%s belongs to another user. Use a file that you own.", path)
	case .Open_Mode:
		return fmt.tprintf("Other users can open %s. To fix this, run: chmod 600 %s", path, path)
	case .Too_Large:
		return fmt.tprintf("%s is larger than 4 KiB.", path)
	case .Io:
		return fmt.tprintf("%s could not be read.", path)
	}
	return ""
}

// secret_file_read reads the file at `path` after the checks. `problem` is ""
// on success; else a user sentence, and data is nil. Data holds a password:
// wipe it after use.
secret_file_read :: proc(path: string, allocator := context.allocator) -> (data: []u8, problem: string, warning: string) {
	d, err := _secret_read(path, true, allocator)
	if err != .None {
		return nil, secret_problem_text(err, path), ""
	}
	return d, "", _secret_warning(path)
}

// secret_file_problem does the checks and reads nothing. "" when the file can
// be used.
secret_file_problem :: proc(path: string) -> string {
	_, err := _secret_read(path, false, context.temp_allocator)
	return secret_problem_text(err, path)
}

// secret_login splits an auth-user-pass file: user on line 1, password on line
// 2. Results are slices of data.
secret_login :: proc(data: []u8, path: string) -> (user, pass: string, problem: string) {
	text := string(data)
	user = cut_line(&text)
	pass = cut_line(&text)
	if user == "" || pass == "" {
		return "", "", fmt.tprintf("%s must have the user name on the first line and the password on the second.", path)
	}
	return user, pass, ""
}

// secret_first_line is the first line of data, without its line end: the
// passphrase of an askpass file.
secret_first_line :: proc(data: []u8) -> string {
	text := string(data)
	return cut_line(&text)
}

@(private = "file")
cut_line :: proc(text: ^string) -> string {
	line := text^
	if i := strings.index_byte(line, '\n'); i >= 0 {
		line = line[:i]
		text^ = text^[i + 1:]
	} else {
		text^ = ""
	}
	return strings.trim_right(line, "\r")
}
