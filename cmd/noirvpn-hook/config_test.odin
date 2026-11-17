// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:strings"
import "core:testing"
import "core:time"
import "noir:bus"

// ---- words ----

tokens_of :: proc(t: ^testing.T, line: string) -> []string {
	words, err := tokenize(line, context.temp_allocator)
	testing.expectf(t, err == "", "%q: %s", line, err)
	return words[:]
}

@(test)
tokenize_splits_and_unquotes :: proc(t: ^testing.T) {
	w := tokens_of(t, `on peer.connect run /usr/bin/x  --flag   "two words" 'single \ "quoted"' a"b c"d`)
	want := []string{"on", "peer.connect", "run", "/usr/bin/x", "--flag", "two words", `single \ "quoted"`, "ab cd"}
	testing.expect_value(t, len(w), len(want))
	for s, i in want {
		if i < len(w) {
			testing.expect_value(t, w[i], s)
		}
	}
	// Escapes inside double quotes: a quote and a backslash.
	w2 := tokens_of(t, `x "a \"q\" b\\c \n"`)
	testing.expect_value(t, w2[1], `a "q" b\c \n`)
	// An empty argument.
	w3 := tokens_of(t, `x '' ""`)
	testing.expect_value(t, len(w3), 3)
	testing.expect_value(t, w3[1], "")
}

@(test)
tokenize_handles_comments :: proc(t: ^testing.T) {
	testing.expect_value(t, len(tokens_of(t, "")), 0)
	testing.expect_value(t, len(tokens_of(t, "   \t ")), 0)
	testing.expect_value(t, len(tokens_of(t, "# a comment")), 0)
	testing.expect_value(t, len(tokens_of(t, "   # a comment")), 0)
	w := tokens_of(t, "timeout 10 # seconds")
	testing.expect_value(t, len(w), 2)
	// A # inside a word is not a comment, and quotes protect it.
	w2 := tokens_of(t, `x a#b "#c" '#d'`)
	testing.expect_value(t, len(w2), 4)
	testing.expect_value(t, w2[1], "a#b")
	testing.expect_value(t, w2[2], "#c")
	testing.expect_value(t, w2[3], "#d")
}

@(test)
tokenize_rejects_open_quotes :: proc(t: ^testing.T) {
	_, e1 := tokenize(`x "abc`, context.temp_allocator)
	testing.expect(t, strings.contains(e1, "not closed"))
	_, e2 := tokenize(`x 'abc`, context.temp_allocator)
	testing.expect(t, strings.contains(e2, "not closed"))
}

// ---- the config file ----

parse_text :: proc(text: string) -> (Config, [dynamic]Config_Error) {
	c := config_default()
	errors := make([dynamic]Config_Error, context.temp_allocator)
	parse_config(&c, text, &errors)
	return c, errors
}

@(test)
config_file_is_read :: proc(t: ^testing.T) {
	text := `# hooks for the vpn server
timeout 20
max-queue 50
max-parallel 2
grace 7

on peer.connect run /usr/local/bin/on-connect --verbose "a b"
on peer.disconnect run /usr/local/bin/on-disconnect   # trailing comment
on * run /usr/bin/logger -t vpn
`
	c, errors := parse_text(text)
	defer config_destroy(&c)
	testing.expect_value(t, len(errors), 0)
	testing.expect_value(t, c.timeout, 20 * time.Second)
	testing.expect_value(t, c.max_queue, 50)
	testing.expect_value(t, c.max_parallel, 2)
	testing.expect_value(t, c.grace, 7 * time.Second)
	testing.expect_value(t, len(c.rules), 3)
	testing.expect_value(t, c.rules[0].prefix, "peer.connect")
	testing.expect_value(t, len(c.rules[0].argv), 3)
	testing.expect_value(t, c.rules[0].argv[0], "/usr/local/bin/on-connect")
	testing.expect_value(t, c.rules[0].argv[2], "a b")
	testing.expect_value(t, len(c.rules[1].argv), 1)
	testing.expect_value(t, c.rules[2].prefix, "")
	// `*` lets the subscriber ask for everything.
	prefixes := subscription_prefixes(&c)
	defer delete(prefixes)
	testing.expect_value(t, len(prefixes), 0)
}

@(test)
defaults_are_documented_values :: proc(t: ^testing.T) {
	c := config_default()
	testing.expect_value(t, c.timeout, 30 * time.Second)
	testing.expect_value(t, c.max_queue, 100)
	testing.expect_value(t, c.max_parallel, 4)
	testing.expect_value(t, c.grace, 5 * time.Second)
}

@(test)
subscription_follows_the_rules :: proc(t: ^testing.T) {
	c, _ := parse_text("on peer. run /bin/a\non auth.fail run /bin/b\n")
	defer config_destroy(&c)
	prefixes := subscription_prefixes(&c)
	defer delete(prefixes)
	testing.expect_value(t, len(prefixes), 2)
	testing.expect_value(t, prefixes[0], "peer.")
	testing.expect_value(t, prefixes[1], "auth.fail")
}

@(test)
config_errors_name_the_line :: proc(t: ^testing.T) {
	text := `timeout 20
bogus 1
on peer.connect run relative/cmd
on Peer run /bin/x
on peer.connect /bin/x
on peer.connect run
timeout abc
timeout 0
timeout 3601
max-queue 0
max-queue 10001
max-parallel 65
grace -1
timeout 1 2
on x run "/bin/unclosed
on peer.x run /bin/ok
`
	c, errors := parse_text(text)
	defer config_destroy(&c)
	Want :: struct {
		line: int,
		text: string,
	}
	wants := []Want {
		{2, "unknown setting 'bogus'"},
		{3, "absolute path"},
		{4, "not a topic prefix"},
		{5, "expected: on PREFIX run"},
		{6, "expected: on PREFIX run"},
		{7, "timeout needs"},
		{8, "timeout needs"},
		{9, "timeout needs"},
		{10, "max-queue needs"},
		{11, "max-queue needs"},
		{12, "max-parallel needs"},
		{13, "grace needs"},
		{14, "timeout accepts only one value"},
		{15, "not closed"},
	}
	testing.expect_value(t, len(errors), len(wants))
	for w, i in wants {
		if i < len(errors) {
			testing.expect_value(t, errors[i].line, w.line)
			testing.expectf(t, strings.contains(errors[i].msg, w.text), "line %d: '%s' lacks '%s'", w.line, errors[i].msg, w.text)
		}
	}
	// The good line after the bad ones is still read.
	testing.expect_value(t, len(c.rules), 1)
	testing.expect_value(t, c.rules[0].prefix, "peer.x")
	// A file with a NUL byte is refused whole.
	c2, e2 := parse_text("timeout 5\x00\n")
	defer config_destroy(&c2)
	testing.expect_value(t, len(e2), 1)
	testing.expect_value(t, len(c2.rules), 0)
}

@(test)
prefix_rules :: proc(t: ^testing.T) {
	for p in ([]string{"peer.", "peer.connect", "a", "x-y_z.9", "*"}) {
		_, ok := parse_prefix(p)
		testing.expect(t, ok, p)
	}
	for p in ([]string{"", "Peer", "peer connect", "peer/", strings.repeat("a", 49, context.temp_allocator)}) {
		_, ok := parse_prefix(p)
		testing.expectf(t, !ok, "accepted '%s'", p)
	}
}

@(test)
on_flag :: proc(t: ^testing.T) {
	c := config_default()
	defer config_destroy(&c)
	testing.expect_value(t, parse_on_flag(&c, "peer.connect=/usr/bin/x"), "")
	testing.expect_value(t, parse_on_flag(&c, "*=/usr/bin/y"), "")
	testing.expect(t, strings.contains(parse_on_flag(&c, "peer.connect"), "PREFIX=/absolute/command"))
	testing.expect(t, strings.contains(parse_on_flag(&c, "peer.connect=x"), "absolute path"))
	testing.expect(t, strings.contains(parse_on_flag(&c, "=/bin/x"), "not a topic prefix"))
	testing.expect(t, strings.contains(parse_on_flag(&c, "peer.connect="), "no command"))
	testing.expect_value(t, len(c.rules), 2)
	testing.expect_value(t, len(c.rules[0].argv), 1)
}

// A command is never run through a shell: shell syntax in the config is just
// characters of an argument.
@(test)
shell_syntax_stays_in_the_argument :: proc(t: ^testing.T) {
	c, errors := parse_text("on peer. run /bin/echo ;rm -rf / $(id) `id` | cat > /x\n")
	defer config_destroy(&c)
	testing.expect_value(t, len(errors), 0)
	testing.expect_value(t, len(c.rules[0].argv), 10)
	testing.expect_value(t, c.rules[0].argv[1], ";rm")
	testing.expect_value(t, c.rules[0].argv[4], "$(id)")
}

// ---- the command line ----

parse_opts :: proc(t: ^testing.T, argv: ..string) -> Options {
	o, err := parse_options(argv)
	msg, _ := err.(string)
	testing.expectf(t, err == nil, "%v: %s", argv, msg)
	return o
}

expect_bad_opts :: proc(t: ^testing.T, want: string, argv: ..string) {
	o, err := parse_options(argv)
	defer options_destroy(&o)
	msg, is_msg := err.(string)
	testing.expectf(t, is_msg, "%v: accepted", argv)
	testing.expectf(t, strings.contains(msg, want), "%v: '%s' lacks '%s'", argv, msg, want)
}

@(test)
options_are_parsed :: proc(t: ^testing.T) {
	o := parse_opts(t, "--name", "srv", "-c", "/etc/a.conf", "--config=/etc/b.conf", "--on", "peer.=/bin/x", "--timeout", "9", "--max-queue=5", "--max-parallel", "3", "--grace", "1", "--verb", "2", "--allow-root", "--check-config")
	defer options_destroy(&o)
	testing.expect_value(t, o.name, "srv")
	testing.expect_value(t, len(o.config_files), 2)
	testing.expect_value(t, o.config_files[1], "/etc/b.conf")
	testing.expect_value(t, len(o.on_rules), 1)
	testing.expect_value(t, o.timeout, "9")
	testing.expect_value(t, o.max_queue, "5")
	testing.expect_value(t, o.max_parallel, "3")
	testing.expect_value(t, o.grace, "1")
	testing.expect_value(t, o.verb, 2)
	testing.expect(t, o.allow_root && o.check_config)

	o2 := parse_opts(t)
	defer options_destroy(&o2)
	testing.expect_value(t, o2.verb, 1)
	testing.expect(t, !o2.allow_root)

	o3 := parse_opts(t, "--socket", "/run/x/a.events", "-h", "-V")
	defer options_destroy(&o3)
	testing.expect_value(t, o3.socket, "/run/x/a.events")
	testing.expect(t, o3.help && o3.version)
}

@(test)
bad_options_are_refused :: proc(t: ^testing.T) {
	expect_bad_opts(t, "unknown option", "--bogus")
	expect_bad_opts(t, "unexpected argument", "status")
	expect_bad_opts(t, "requires a value", "--config")
	expect_bad_opts(t, "requires a value", "--name")
	expect_bad_opts(t, "instance name", "--name", "a/b")
	expect_bad_opts(t, "cannot be used together", "--name", "a", "--socket", "/x")
	expect_bad_opts(t, "--verb", "--verb", "5")
	expect_bad_opts(t, "--verb", "--verb", "x")
	expect_bad_opts(t, "does not accept a value", "--allow-root=1")
	expect_bad_opts(t, "--socket requires a path", "--socket", "")
}

@(test)
command_line_settings_win_over_the_file :: proc(t: ^testing.T) {
	o := parse_opts(t, "--config", "a.conf", "--timeout", "7", "--on", "auth.fail=/bin/z")
	defer options_destroy(&o)
	errors := make([dynamic]Config_Error, context.temp_allocator)
	c := build_config(&o, {"timeout 20\nmax-parallel 8\non peer. run /bin/a\n"}, &errors)
	defer config_destroy(&c)
	testing.expect_value(t, len(errors), 0)
	testing.expect_value(t, c.timeout, 7 * time.Second)
	testing.expect_value(t, c.max_parallel, 8)
	// The rules of the file come first, then --on.
	testing.expect_value(t, len(c.rules), 2)
	testing.expect_value(t, c.rules[0].prefix, "peer.")
	testing.expect_value(t, c.rules[1].prefix, "auth.fail")

	// Errors say where they are.
	o2 := parse_opts(t, "--config", "bad.conf", "--max-queue", "0", "--on", "x")
	defer options_destroy(&o2)
	errors2 := make([dynamic]Config_Error, context.temp_allocator)
	c2 := build_config(&o2, {"timeout x\n"}, &errors2)
	defer config_destroy(&c2)
	testing.expect_value(t, len(errors2), 3)
	testing.expect(t, strings.has_prefix(errors2[0].msg, "bad.conf:1: "), errors2[0].msg)
	testing.expect(t, strings.contains(errors2[1].msg, "max-queue"))
	testing.expect(t, strings.contains(errors2[2].msg, "--on"))
}

// ---- the events socket ----

exists_in :: proc(path: string) -> bool {
	return path == "/run/noirvpn/srv.events" || path == "/tmp/noirvpn-1000/mine.events"
}

@(test)
events_socket_is_found :: proc(t: ^testing.T) {
	dirs := []string{"/run/noirvpn", "/tmp/noirvpn-1000"}
	found := []bus.Found{{name = "srv", url = "ipc:///run/noirvpn/srv.control", events_url = "ipc:///run/noirvpn/srv.events"}}

	o := parse_opts(t)
	defer options_destroy(&o)
	// The only daemon.
	url, waiting, err, _ := resolve_events(&o, found, dirs, exists_in)
	testing.expect_value(t, err, Resolve_Error.None)
	testing.expect_value(t, url, "ipc:///run/noirvpn/srv.events")
	testing.expect(t, !waiting)
	// None: wait for the default name in the first directory.
	url, waiting, err, _ = resolve_events(&o, nil, dirs, exists_in)
	testing.expect_value(t, err, Resolve_Error.None)
	testing.expect_value(t, url, "/run/noirvpn/noirvpn.events")
	testing.expect(t, waiting)
	// Several: say so.
	two := []bus.Found{found[0], {name = "cli", events_url = "ipc:///run/noirvpn/cli.events"}}
	detail: string
	_, _, err, detail = resolve_events(&o, two, dirs, exists_in)
	testing.expect_value(t, err, Resolve_Error.Ambiguous)
	testing.expect_value(t, detail, "srv, cli")

	// --name looks for NAME.events in the directories, in order.
	o2 := parse_opts(t, "--name", "mine")
	defer options_destroy(&o2)
	url, waiting, err, _ = resolve_events(&o2, two, dirs, exists_in)
	testing.expect_value(t, url, "/tmp/noirvpn-1000/mine.events")
	testing.expect(t, !waiting)
	o3 := parse_opts(t, "--name", "later")
	defer options_destroy(&o3)
	url, waiting, err, _ = resolve_events(&o3, nil, dirs, exists_in)
	testing.expect_value(t, url, "/run/noirvpn/later.events")
	testing.expect(t, waiting)

	// --socket is used as it is.
	o4 := parse_opts(t, "--socket", "ipc:///x/y.sock")
	defer options_destroy(&o4)
	url, waiting, err, _ = resolve_events(&o4, two, dirs, exists_in)
	testing.expect_value(t, url, "ipc:///x/y.sock")
	testing.expect(t, !waiting)
}

@(test)
exit_codes_are_distinct :: proc(t: ^testing.T) {
	testing.expect_value(t, int(Exit.Ok), 0)
	testing.expect_value(t, int(Exit.Config), 1)
	testing.expect_value(t, int(Exit.Usage), 2)
	testing.expect_value(t, int(Exit.System), 3)
	testing.expect_value(t, int(Exit.Bus), 4)
}

@(test)
root_needs_a_flag :: proc(t: ^testing.T) {
	testing.expect(t, may_run(1000, false))
	testing.expect(t, may_run(1000, true))
	testing.expect(t, !may_run(0, false))
	testing.expect(t, may_run(0, true))
}
