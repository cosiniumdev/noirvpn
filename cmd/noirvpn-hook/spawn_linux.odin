// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:mem"
import "core:strings"
import "core:sys/linux"
import "core:time"

// Starts a command and waits for it, with Linux system calls (`fork`, `execve`,
// `waitid`). It calls the kernel directly, so it is the same in a static musl
// binary.
//
// - The program runs directly: `execve` with the arguments from the config.
// - The child gets its own session (`setsid`), so its whole process group can
//   be killed.
// - stdin is a pipe fed with the event; stdout and stderr go to our stderr.
// - Signal mask and SIGPIPE are reset to the defaults; every fd above 2 is closed.
//
// Everything the child needs is built before `fork`. After a `fork` in a
// multi-thread program the child may call only safe functions, so it runs
// system calls only.

// How often and how long to wait when `execve` says "text file busy".
TEXT_BUSY_TRIES :: 20
TEXT_BUSY_WAIT :: 10 * time.Millisecond

Run_Status :: enum u8 {
	// The command ended: see `code`, or `signal` when a signal killed it.
	Exited,
	Signaled,
	// It ran out of time and was killed.
	Timed_Out,
	// The runner is stopping and the command was killed.
	Cancelled,
	// It could not be started: see `errno`.
	Spawn_Failed,
}

Run_Result :: struct {
	status: Run_Status,
	// The exit code (Exited).
	code:   int,
	// The signal that ended it (Signaled, Timed_Out, Cancelled).
	signal: int,
	// Why the start failed (Spawn_Failed).
	errno:  linux.Errno,
}

// Run one command and wait for it.
//   argv, env    arguments and environment; argv[0] is the path
//   input        written to its stdin, then stdin is closed
//   timeout      kill the process group after this long
//   cancel       polled; when it returns true the command is killed
//   cancel_data  passed to `cancel`
run_command :: proc(
	argv, env: []string,
	input: []byte,
	timeout: time.Duration,
	cancel: proc(data: rawptr) -> bool,
	cancel_data: rawptr,
) -> Run_Result {
	// "Text file busy" can be a short race: another thread forked while the script
	// was open for writing, and its child has not run `execve` yet. Try a few more times.
	res: Run_Result
	for _ in 0 ..< TEXT_BUSY_TRIES {
		res = run_once(argv, env, input, timeout, cancel, cancel_data)
		if res.status != .Spawn_Failed || res.errno != .ETXTBSY {
			break
		}
		time.sleep(TEXT_BUSY_WAIT)
	}
	return res
}

@(private = "file")
run_once :: proc(
	argv, env: []string,
	input: []byte,
	timeout: time.Duration,
	cancel: proc(data: rawptr) -> bool,
	cancel_data: rawptr,
) -> Run_Result {
	if len(argv) == 0 {
		return Run_Result{status = .Spawn_Failed, errno = .ENOENT}
	}
	// Strings for the system call, allocated before the fork.
	arena: mem.Arena
	buf := make([]byte, arena_size(argv, env))
	defer delete(buf)
	mem.arena_init(&arena, buf)
	alloc := mem.arena_allocator(&arena)
	path, _ := strings.clone_to_cstring(argv[0], alloc)
	cargv := make([]cstring, len(argv) + 1, alloc)
	for a, i in argv {
		cargv[i], _ = strings.clone_to_cstring(a, alloc)
	}
	cenv := make([]cstring, len(env) + 1, alloc)
	for e, i in env {
		cenv[i], _ = strings.clone_to_cstring(e, alloc)
	}

	in_fds: [2]linux.Fd // the command's stdin: read end, write end
	err_fds: [2]linux.Fd // the child tells us when execve failed
	if e := linux.pipe2(&in_fds, {.CLOEXEC}); e != .NONE {
		return Run_Result{status = .Spawn_Failed, errno = e}
	}
	if e := linux.pipe2(&err_fds, {.CLOEXEC}); e != .NONE {
		linux.close(in_fds[0])
		linux.close(in_fds[1])
		return Run_Result{status = .Spawn_Failed, errno = e}
	}
	// The pipes must not sit on descriptors 0 to 2 (a runner started with a
	// closed stdin): the child's dup2 would not clear close-on-exec there.
	for fd in ([]^linux.Fd{&in_fds[0], &in_fds[1], &err_fds[0], &err_fds[1]}) {
		if fd^ < 3 {
			moved, e := linux.fcntl_dupfd_cloexec(fd^, .DUPFD_CLOEXEC, 3)
			if e == .NONE {
				linux.close(fd^)
				fd^ = moved
			}
		}
	}

	pid, ferr := linux.fork()
	if ferr != .NONE {
		close4(in_fds, err_fds)
		return Run_Result{status = .Spawn_Failed, errno = ferr}
	}
	if pid == 0 {
		child_exec(path, raw_data(cargv), raw_data(cenv), in_fds[0], err_fds[1])
	}

	// The parent.
	linux.close(in_fds[0])
	linux.close(err_fds[1])
	defer linux.close(err_fds[0])

	// The child reports a failed execve with one byte; a good execve closes
	// the pipe (close-on-exec) and the read gives zero bytes.
	one: [1]u8
	for {
		n, e := linux.read(err_fds[0], one[:])
		if e == .EINTR {
			continue
		}
		if e == .NONE && n == 1 {
			linux.close(in_fds[1])
			reap(pid)
			return Run_Result{status = .Spawn_Failed, errno = linux.Errno(one[0])}
		}
		break
	}
	return wait_for_child(pid, in_fds[1], input, timeout, cancel, cancel_data)
}

@(private = "file")
close4 :: proc(a, b: [2]linux.Fd) {
	linux.close(a[0])
	linux.close(a[1])
	linux.close(b[0])
	linux.close(b[1])
}

// Memory for the strings handed to execve, with room for the alignment.
@(private = "file")
arena_size :: proc(argv, env: []string) -> int {
	n := 64 + (len(argv) + len(env) + 2) * (size_of(cstring) + 16) + 3 * 16
	for a in argv {
		n += len(a) + 1 + 16
	}
	for e in env {
		n += len(e) + 1 + 16
	}
	return n
}

// Runs in the child after `fork`. Only system calls; never returns.
@(private = "file")
child_exec :: proc "contextless" (path: cstring, argv, envp: [^]cstring, stdin_fd, report_fd: linux.Fd) -> ! {
	// Our own session: a group of our own to kill, and no terminal.
	linux.setsid()
	// Default signals: nothing blocked, SIGPIPE back to its default.
	empty: u64
	linux.syscall(linux.SYS_rt_sigprocmask, int(2), &empty, rawptr(nil), 8) // SIG_SETMASK
	reset_sigpipe()
	// stdin from the pipe, stdout to our stderr (stderr stays).
	linux.dup2(stdin_fd, 0)
	linux.dup2(2, 1)
	// Close the fds above 2 except the report pipe. close_range with the
	// close-on-exec flag would do for the report pipe, but it has that flag
	// already, so close everything else.
	close_all_but(report_fd)
	linux.chdir("/")
	err := linux.execve(path, argv, envp)
	// Tell the parent why, then leave without running exit handlers.
	code := [1]u8{u8(err)}
	linux.write(report_fd, code[:])
	linux.exit_group(127)
}

@(private = "file")
reset_sigpipe :: proc "contextless" () {
	// The kernel's `struct sigaction`: handler, flags, restorer, mask (8 bytes).
	Kernel_Sigaction :: struct {
		handler:  uintptr,
		flags:    uint,
		restorer: uintptr,
		mask:     u64,
	}
	act := Kernel_Sigaction{} // SIG_DFL is 0
	linux.syscall(linux.SYS_rt_sigaction, int(13), &act, rawptr(nil), 8)
}

@(private = "file")
close_all_but :: proc "contextless" (keep: linux.Fd) {
	// Two ranges around `keep`.
	if keep > 3 {
		if linux.close_range(3, keep - 1, {}) == .ENOSYS {
			close_loop(3, keep - 1)
		}
	}
	// The kernel reads -1 as the highest descriptor.
	if linux.close_range(keep + 1, linux.Fd(-1), {}) == .ENOSYS {
		close_loop(keep + 1, 1023)
	}
}

@(private = "file")
close_loop :: proc "contextless" (lo, hi: linux.Fd) {
	for fd := lo; fd <= hi; fd += 1 {
		linux.close(fd)
	}
}

@(private = "file")
reap :: proc(pid: linux.Pid) {
	status: u32
	for {
		_, e := linux.wait4(pid, &status, {}, nil)
		if e != .EINTR {
			return
		}
	}
}

// Feed stdin, wait for the end, kill on timeout or cancel.
@(private = "file")
wait_for_child :: proc(
	pid: linux.Pid,
	stdin_w: linux.Fd,
	input: []byte,
	timeout: time.Duration,
	cancel: proc(data: rawptr) -> bool,
	cancel_data: rawptr,
) -> Run_Result {
	stdin_open := true
	close_stdin :: proc(fd: linux.Fd, open: ^bool) {
		if open^ {
			linux.close(fd)
			open^ = false
		}
	}
	// A write must never block us: the command may not read its stdin.
	if flags, e := linux.fcntl_getfl(stdin_w, .GETFL); e == .NONE {
		linux.fcntl_setfl(stdin_w, .SETFL, flags + {.NONBLOCK})
	}
	written := 0
	if len(input) == 0 {
		close_stdin(stdin_w, &stdin_open)
	}

	// A pidfd lets poll wake up when the command ends. Without one (an old
	// kernel) we look every few milliseconds.
	pidfd, perr := linux.pidfd_open(pid, {})
	have_pidfd := perr == .NONE
	defer if have_pidfd {
		linux.close(linux.Fd(pidfd))
	}

	start := mono_now()
	result: Run_Result
	killed_at: time.Duration
	stage := 0 // 0 running, 1 sent SIGTERM, 2 sent SIGKILL
	reason := Run_Status.Exited
	status: u32
	for {
		// Has it ended? (This also reaps it.)
		got, wait_err := linux.wait4(pid, &status, {.WNOHANG}, nil)
		if wait_err == .NONE && got == pid {
			break
		}
		if wait_err == .ECHILD {
			// Somebody else reaped it (SIGCHLD ignored): the status is lost.
			status = 0xff00
			break
		}

		elapsed := mono_now() - start
		if stage == 0 {
			if cancel != nil && cancel(cancel_data) {
				// The runner is stopping and the grace time is over: kill
				// at once.
				reason = .Cancelled
				kill_group(pid, .SIGKILL)
				stage = 2
			} else if elapsed >= timeout {
				reason = .Timed_Out
				kill_group(pid, .SIGTERM)
				killed_at = mono_now()
				stage = 1
			}
		} else if stage == 1 && mono_now() - killed_at >= KILL_DELAY {
			kill_group(pid, .SIGKILL)
			stage = 2
		}

		// Feed stdin while there is room.
		if stdin_open && written < len(input) {
			n, werr := linux.write(stdin_w, input[written:])
			switch {
			case werr == .NONE:
				written += n
			case werr == .EAGAIN, werr == .EINTR:
			case:
				// EPIPE: the command closed its stdin. Stop feeding.
				written = len(input)
			}
			if written >= len(input) {
				close_stdin(stdin_w, &stdin_open)
			}
		}

		// Sleep until something happens: the command ends, stdin has room, or
		// a short time passes (the deadlines and `cancel` are checked then).
		fds: [2]linux.Poll_Fd
		nfds := 0
		if have_pidfd {
			fds[nfds] = linux.Poll_Fd {
				fd     = linux.Fd(pidfd),
				events = {.IN},
			}
			nfds += 1
		}
		wait_ms: i32 = 50
		if stdin_open && written < len(input) {
			fds[nfds] = linux.Poll_Fd {
				fd     = stdin_w,
				events = {.OUT},
			}
			nfds += 1
		}
		if !have_pidfd {
			wait_ms = 5
		}
		linux.poll(fds[:nfds], wait_ms)
	}
	close_stdin(stdin_w, &stdin_open)

	// A command that ran out of time or was cancelled but ended by itself
	// before the signal took effect still counts as killed.
	switch {
	case reason == .Timed_Out || reason == .Cancelled:
		result.status = reason
		if linux.WIFSIGNALED(status) {
			result.signal = int(linux.WTERMSIG(status))
		}
	case linux.WIFSIGNALED(status):
		result.status = .Signaled
		result.signal = int(linux.WTERMSIG(status))
	case:
		result.status = .Exited
		result.code = int(linux.WEXITSTATUS(status))
	}
	return result
}

// Send a signal to the whole process group of the command (it called
// `setsid`, so its group id is its pid). If that fails, to the process.
@(private = "file")
kill_group :: proc(pid: linux.Pid, sig: linux.Signal) {
	if linux.kill(-pid, sig) != .NONE {
		linux.kill(pid, sig)
	}
}

// Ignore SIGPIPE in this process: writing to a command that closed its stdin
// must give EPIPE, not kill the runner. (A command gets the default back; see
// `child_exec`.)
ignore_sigpipe :: proc() {
	Kernel_Sigaction :: struct {
		handler:  uintptr,
		flags:    uint,
		restorer: uintptr,
		mask:     u64,
	}
	act := Kernel_Sigaction {
		handler = 1, // SIG_IGN
	}
	linux.syscall(linux.SYS_rt_sigaction, int(13), &act, rawptr(nil), 8)
}
