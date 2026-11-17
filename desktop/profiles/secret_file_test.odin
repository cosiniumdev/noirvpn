// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !windows
package profiles

import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"

@(private = "file")
chmod :: proc(path: string, mode: posix.mode_t) {
	posix.chmod(strings.clone_to_cstring(path, context.temp_allocator), mode)
}

@(test)
test_secret_file_rules :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	// The checks look at the file, not at its folder.
	good := test_write(t, dir, "login.txt", "alice\r\ncorrect horse\n")
	chmod(good, {.IRUSR, .IWUSR})
	data, problem, warning := secret_file_read(good)
	testing.expectf(t, problem == "" && warning == "", "%s", problem)
	user, pass, lp := secret_login(data, good)
	testing.expect_value(t, user, "alice")
	testing.expect_value(t, pass, "correct horse")
	testing.expect_value(t, lp, "")
	delete(data)

	chmod(good, {.IRUSR})
	testing.expect_value(t, secret_file_problem(good), "")

	// Open to the group or to others: refused, and the fix is named.
	chmod(good, {.IRUSR, .IWUSR, .IRGRP})
	data, problem, _ = secret_file_read(good)
	testing.expect(t, data == nil)
	testing.expectf(t, strings.contains(problem, "chmod 600 ") && strings.contains(problem, good), "%s", problem)
	chmod(good, {.IRUSR, .IWUSR, .IROTH})
	testing.expect(t, strings.contains(secret_file_problem(good), "chmod 600"))
	chmod(good, {.IRUSR, .IWUSR})

	// A relative path, a missing file, a link, a folder, a large file.
	testing.expect(t, strings.contains(secret_file_problem("login.txt"), "not a full path"))
	testing.expect(t, strings.contains(secret_file_problem(strings.concatenate({dir, "/none"}, context.temp_allocator)), "does not exist"))
	link := strings.concatenate({dir, "/link"}, context.temp_allocator)
	testing.expect(t, os.symlink(good, link) == nil)
	testing.expectf(t, strings.contains(secret_file_problem(link), "symbolic link"), "%s", secret_file_problem(link))
	sub := test_mkdir(t, dir, "sub")
	chmod(sub, {.IRUSR, .IWUSR, .IXUSR})
	testing.expect(t, strings.contains(secret_file_problem(sub), "not a regular file"))
	big := test_write(t, dir, "big.txt", strings.repeat("x", SECRET_FILE_MAX + 1, context.temp_allocator))
	chmod(big, {.IRUSR, .IWUSR})
	testing.expect(t, strings.contains(secret_file_problem(big), "larger than 4 KiB"))
	edge := test_write(t, dir, "edge.txt", strings.repeat("x", SECRET_FILE_MAX, context.temp_allocator))
	chmod(edge, {.IRUSR, .IWUSR})
	data, problem, _ = secret_file_read(edge)
	testing.expect(t, problem == "" && len(data) == SECRET_FILE_MAX)
	delete(data)

	// A file of another user (root), when there is one to try.
	if posix.getuid() != 0 && os.exists("/etc/hosts") {
		testing.expect(t, strings.contains(secret_file_problem("/etc/hosts"), "another user"))
	}

	// The content.
	one := test_write(t, dir, "one.txt", "alice\n")
	chmod(one, {.IRUSR, .IWUSR})
	data, problem, _ = secret_file_read(one)
	_, _, lp = secret_login(data, one)
	testing.expect(t, strings.contains(lp, "first line") && strings.contains(lp, "second"))
	testing.expect_value(t, secret_first_line(data), "alice")
	delete(data)
	testing.expect_value(t, secret_first_line(transmute([]u8)string("pass phrase\r\nrest")), "pass phrase")
}

@(test)
test_summary_secret_files :: proc(t: ^testing.T) {
	s, _ := summarize("client\nremote a.example\nauth-user-pass /home/a/login.txt\naskpass /home/a/key.txt\n")
	defer summary_destroy(&s)
	testing.expect_value(t, s.login_file, "/home/a/login.txt")
	testing.expect_value(t, s.pass_file, "/home/a/key.txt")
	testing.expect(t, s.user_pass && s.askpass && !s.login_inline)

	b, _ := summarize("client\nremote a.example\nauth-user-pass\naskpass\n")
	defer summary_destroy(&b)
	testing.expect(t, b.user_pass && b.askpass && b.login_file == "" && b.pass_file == "")

	i, _ := summarize("client\nremote a.example\n<auth-user-pass>\nalice\npw\n</auth-user-pass>\n")
	defer summary_destroy(&i)
	testing.expect(t, i.user_pass && i.login_inline && i.login_file == "" && !i.askpass)
}
