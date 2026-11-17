// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package main

// Starts the browser for a web sign-in: the program of the profile, or the
// opener of the desktop. No shell; the link is one argument.

import "core:c"
import "core:strings"
import "core:sys/posix"

when ODIN_OS == .Darwin {
	BROWSER_DEFAULT :: "open"
} else {
	BROWSER_DEFAULT :: "xdg-open"
}

// file_open opens a file in the desktop text editor (macOS `open -t`, else the
// opener of its type). file_reveal shows it in its folder. One path argument; no shell.
file_open :: proc(path: string) -> bool {
	when ODIN_OS == .Darwin {
		return browser_spawn({"open", "-t"}, path)
	} else {
		return browser_spawn({"xdg-open"}, path)
	}
}

file_reveal :: proc(path: string) -> bool {
	when ODIN_OS == .Darwin {
		return browser_spawn({"open", "-R"}, path)
	} else {
		// xdg-open cannot select a file: it opens the folder.
		dir := path
		if i := strings.last_index_byte(path, '/'); i > 0 {
			dir = path[:i]
		}
		return browser_spawn({"xdg-open"}, dir)
	}
}

// browser_spawn runs argv without waiting. The program runs in a grandchild,
// so no zombie stays. A close-on-exec pipe tells if the exec worked.
browser_spawn :: proc(words: []string, url: string) -> bool {
	argv := make([]cstring, len(words) + 2, context.temp_allocator)
	for w, i in words {
		argv[i] = strings.clone_to_cstring(w, context.temp_allocator)
	}
	argv[len(words)] = strings.clone_to_cstring(url, context.temp_allocator)
	argv[len(words) + 1] = nil
	fds: [2]posix.FD
	if posix.pipe(&fds) != .OK {
		return false
	}
	posix.fcntl(fds[1], .SETFD, c.int(posix.FD_CLOEXEC))
	pid := posix.fork()
	if pid == 0 {
		posix.close(fds[0])
		if posix.fork() != 0 {
			posix._exit(0)
		}
		posix.setsid()
		posix.execvp(argv[0], raw_data(argv))
		e := i32(posix.errno())
		posix.write(fds[1], ([^]byte)(&e), size_of(e))
		posix._exit(127)
	}
	posix.close(fds[1])
	if pid < 0 {
		posix.close(fds[0])
		return false
	}
	st: c.int
	posix.waitpid(pid, &st, {})
	e: i32
	n := posix.read(fds[0], ([^]byte)(&e), size_of(e))
	posix.close(fds[0])
	return n == 0
}
