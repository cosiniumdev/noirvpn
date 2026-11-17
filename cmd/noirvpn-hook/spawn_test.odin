// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Real processes: /bin/sh scripts in a temp directory.

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:testing"
import "core:time"

SH_ENV :: []string{"PATH=/usr/bin:/bin"}

never :: proc(data: rawptr) -> bool {
	return false
}

// Run a script with the given stdin and a long timeout.
run_script :: proc(path: string, args: []string, env: []string, input: []byte, timeout := 20 * time.Second) -> Run_Result {
	argv := make([dynamic]string, context.temp_allocator)
	append(&argv, path)
	append(&argv, ..args)
	return run_command(argv[:], env, input, timeout, never, nil)
}

read_text :: proc(path: string) -> string {
	data, err := os.read_entire_file(path, context.temp_allocator)
	if err != nil {
		return ""
	}
	return string(data)
}

@(test)
exit_code_is_reported :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "exit")
	defer remove_dir(dir)
	ok := write_script(t, dir, "ok", "exit 0")
	bad := write_script(t, dir, "bad", "exit 3")
	r1 := run_script(ok, nil, SH_ENV, nil)
	testing.expect_value(t, r1.status, Run_Status.Exited)
	testing.expect_value(t, r1.code, 0)
	r2 := run_script(bad, nil, SH_ENV, nil)
	testing.expect_value(t, r2.status, Run_Status.Exited)
	testing.expect_value(t, r2.code, 3)
	// A command killed by a signal.
	sig := write_script(t, dir, "sig", "kill -9 $$")
	r3 := run_script(sig, nil, SH_ENV, nil)
	testing.expect_value(t, r3.status, Run_Status.Signaled)
	testing.expect_value(t, r3.signal, 9)
}

@(test)
arguments_and_environment_are_exactly_what_was_given :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "env")
	defer remove_dir(dir)
	out := fmt.tprintf("%s/out", dir)
	script := write_script(t, dir, "show", `printf '%s\n' "$#" "$1" "$2" > "$3"; env | sort > "$3.env"`)
	// Arguments with shell syntax in them reach the script as they are.
	args := []string{"a b", `$(touch /tmp/should-not-exist) ; echo`, out}
	r := run_script(script, args, {"PATH=/usr/bin:/bin", "NOIR_X=1", "ODD=va lue=x"}, nil)
	testing.expect_value(t, r.status, Run_Status.Exited)
	testing.expect_value(t, r.code, 0)
	testing.expect_value(t, read_text(out), "3\na b\n$(touch /tmp/should-not-exist) ; echo\n")
	env := read_text(fmt.tprintf("%s.env", out))
	// Only what was passed (the shell may add PWD, SHLVL, _, OLDPWD).
	testing.expect(t, strings.contains(env, "NOIR_X=1\n"), env)
	testing.expect(t, strings.contains(env, "ODD=va lue=x\n"), env)
	testing.expect(t, strings.contains(env, "PATH=/usr/bin:/bin\n"), env)
	for line in strings.split_lines(env, context.temp_allocator) {
		if line == "" {
			continue
		}
		name := line[:strings.index_byte(line, '=')]
		switch name {
		case "PATH", "NOIR_X", "ODD", "PWD", "SHLVL", "_", "OLDPWD":
		case:
			testing.expectf(t, false, "unexpected variable %s", name)
		}
	}
	testing.expect(t, !os.exists("/tmp/should-not-exist"))
}

@(test)
stdin_gets_the_input :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "stdin")
	defer remove_dir(dir)
	out := fmt.tprintf("%s/in", dir)
	script := write_script(t, dir, "cat", `cat > "$1"`)
	input := "{\"topic\":\"peer.connect\"}\n"
	r := run_script(script, {out}, SH_ENV, transmute([]byte)input)
	testing.expect_value(t, r.status, Run_Status.Exited)
	testing.expect_value(t, read_text(out), input)

	// More than a pipe holds (64 KiB): the writer must not block us.
	big := strings.repeat("0123456789abcdef", 16 * 1024, context.temp_allocator) // 256 KiB
	r2 := run_script(script, {out}, SH_ENV, transmute([]byte)big)
	testing.expect_value(t, r2.status, Run_Status.Exited)
	testing.expect_value(t, len(read_text(out)), len(big))
}

@(test)
command_that_ignores_stdin_does_not_hang_or_kill_us :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ignore_sigpipe()
	dir := make_dir(t, "nostdin")
	defer remove_dir(dir)
	script := write_script(t, dir, "deaf", "exit 0")
	big := strings.repeat("x", 512 * 1024, context.temp_allocator)
	start := time.now()
	for _ in 0 ..< 5 {
		r := run_script(script, nil, SH_ENV, transmute([]byte)big)
		testing.expect_value(t, r.status, Run_Status.Exited)
		testing.expect_value(t, r.code, 0)
	}
	testing.expect(t, time.since(start) < 10 * time.Second)
	// One that sleeps and never reads: the input does not block the timeout.
	sleeper := write_script(t, dir, "sleeper", "sleep 1; exit 0")
	r := run_script(sleeper, nil, SH_ENV, transmute([]byte)big)
	testing.expect_value(t, r.status, Run_Status.Exited)
}

@(test)
timeout_kills_the_whole_process_group :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "timeout")
	defer remove_dir(dir)
	pidfile := fmt.tprintf("%s/child.pid", dir)
	// The script starts a background child and then waits for it.
	script := write_script(t, dir, "slow", `sleep 60 &
echo $! > "$1"
wait`)
	start := time.now()
	r := run_script(script, {pidfile}, SH_ENV, nil, 500 * time.Millisecond)
	took := time.since(start)
	testing.expect_value(t, r.status, Run_Status.Timed_Out)
	testing.expect(t, took >= 500 * time.Millisecond && took < 5 * time.Second, fmt.tprintf("took %v", took))
	// The background child is gone too.
	text := strings.trim_space(read_text(pidfile))
	testing.expect(t, len(text) > 0, "no child pid written")
	pid := 0
	for ch in text {
		pid = pid * 10 + int(ch - '0')
	}
	if pid > 0 {
		// It may need a moment to be reaped by init.
		gone := wait_for(3 * time.Second, &pid, proc(ctx: rawptr) -> bool {
				p := (^int)(ctx)^
				return linux.kill(linux.Pid(p), nil) == .ESRCH || is_zombie(p)
			})
		testing.expect(t, gone, "the background child is still running")
	}
}

// A process that ended but was not collected yet (its parent is slow) is
// as good as gone.
is_zombie :: proc(pid: int) -> bool {
	text := read_text(fmt.tprintf("/proc/%d/stat", pid))
	i := strings.last_index_byte(text, ')')
	return i >= 0 && i + 2 < len(text) && text[i + 2] == 'Z'
}

@(test)
stubborn_command_is_killed_after_the_term_delay :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "stubborn")
	defer remove_dir(dir)
	// Ignores SIGTERM; only SIGKILL stops it.
	script := write_script(t, dir, "stubborn", `trap '' TERM
while :; do sleep 1; done`)
	start := time.now()
	r := run_script(script, nil, SH_ENV, nil, 300 * time.Millisecond)
	took := time.since(start)
	testing.expect_value(t, r.status, Run_Status.Timed_Out)
	testing.expect_value(t, r.signal, 9)
	testing.expect(t, took >= KILL_DELAY && took < 10 * time.Second, fmt.tprintf("took %v", took))
}

Cancel_State :: struct {
	start: time.Duration,
}

cancel_after_300ms :: proc(data: rawptr) -> bool {
	s := (^Cancel_State)(data)
	return mono_now() - s.start > 300 * time.Millisecond
}

@(test)
cancel_kills_at_once :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "cancel")
	defer remove_dir(dir)
	script := write_script(t, dir, "stubborn", `trap '' TERM
while :; do sleep 1; done`)
	st := Cancel_State {
		start = mono_now(),
	}
	start := time.now()
	r := run_command({script}, SH_ENV, nil, 60 * time.Second, cancel_after_300ms, &st)
	testing.expect_value(t, r.status, Run_Status.Cancelled)
	testing.expect_value(t, r.signal, 9)
	testing.expect(t, time.since(start) < 3 * time.Second)
}

@(test)
start_failures_are_reported :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	dir := make_dir(t, "fail")
	defer remove_dir(dir)
	r1 := run_script("/nonexistent/command", nil, SH_ENV, nil)
	testing.expect_value(t, r1.status, Run_Status.Spawn_Failed)
	testing.expect_value(t, r1.errno, linux.Errno.ENOENT)
	// A file that is not executable.
	plain := fmt.tprintf("%s/plain", dir)
	testing.expect(t, os.write_entire_file(plain, "#!/bin/sh\nexit 0\n") == nil)
	r2 := run_script(plain, nil, SH_ENV, nil)
	testing.expect_value(t, r2.status, Run_Status.Spawn_Failed)
	testing.expect_value(t, r2.errno, linux.Errno.EACCES)
	// A script with a bad interpreter.
	bad := write_script(t, dir, "bad", "exit 0")
	testing.expect(t, os.write_entire_file(bad, "#!/nonexistent/interpreter\n") == nil)
	r3 := run_script(bad, nil, SH_ENV, nil)
	testing.expect_value(t, r3.status, Run_Status.Spawn_Failed)
	testing.expect_value(t, r3.errno, linux.Errno.ENOENT)
	// No command at all.
	r4 := run_command(nil, nil, nil, time.Second, never, nil)
	testing.expect_value(t, r4.status, Run_Status.Spawn_Failed)
}

@(test)
command_gets_a_clean_process_state :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ignore_sigpipe()
	dir := make_dir(t, "state")
	defer remove_dir(dir)

	// A descriptor of ours that is not close-on-exec must not reach the command.
	// The command compares what its descriptor with the same number points
	// at (the shell has descriptors of its own).
	fds: [2]linux.Fd
	testing.expect_value(t, linux.pipe2(&fds, {}), linux.Errno.NONE)
	defer linux.close(fds[0])
	defer linux.close(fds[1])
	link_buf: [64]u8
	n, _ := linux.readlink(fmt.ctprintf("/proc/self/fd/%d", int(fds[1])), link_buf[:])
	link := string(link_buf[:n])
	testing.expect(t, strings.has_prefix(link, "pipe:["), link)
	out := fmt.tprintf("%s/fd", dir)
	script := write_script(
		t,
		dir,
		"fd",
		`if [ "$(readlink "/proc/$$/fd/$LEAK_FD")" = "$LEAK_LINK" ]; then echo leaked > "$1"; else echo closed > "$1"; fi`,
	)
	env := []string{"PATH=/usr/bin:/bin", fmt.tprintf("LEAK_FD=%d", int(fds[1])), fmt.tprintf("LEAK_LINK=%s", link)}
	r := run_script(script, {out}, env, nil)
	testing.expect_value(t, r.status, Run_Status.Exited)
	testing.expect_value(t, strings.trim_space(read_text(out)), "closed")

	// SIGPIPE is the default again in the command (we ignore it ourselves):
	// `yes` dies of it, with status 141.
	status_file := fmt.tprintf("%s/yes", dir)
	pipe := write_script(t, dir, "pipe", `( yes; echo $? > "$1" ) | head -n 1 > /dev/null`)
	r2 := run_script(pipe, {status_file}, SH_ENV, nil)
	testing.expect_value(t, r2.status, Run_Status.Exited)
	testing.expect_value(t, strings.trim_space(read_text(status_file)), "141")

	// The command runs in its own session, in the root directory.
	info := fmt.tprintf("%s/info", dir)
	where_ := write_script(t, dir, "where", `pwd > "$1"; ps -o sid= -p $$ >> "$1" 2>/dev/null || echo unknown >> "$1"`)
	r3 := run_script(where_, {info}, SH_ENV, nil)
	testing.expect_value(t, r3.status, Run_Status.Exited)
	lines := strings.split_lines(read_text(info), context.temp_allocator)
	testing.expect(t, len(lines) >= 1 && lines[0] == "/", fmt.tprintf("%v", lines))
}
