// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:time"

// The settings of the hook runner: what to run for which topic, and the
// limits. They come from a config file (README.md) and from the command line.

DEFAULT_TIMEOUT :: 30 * time.Second
DEFAULT_MAX_QUEUE :: 100
DEFAULT_MAX_PARALLEL :: 4
DEFAULT_GRACE :: 5 * time.Second

// After a command ran out of time it gets SIGTERM; this much later SIGKILL.
KILL_DELAY :: 2 * time.Second

MAX_TOPIC_PREFIX :: 48

Rule :: struct {
	// Events whose topic starts with this run the command. "" matches every
	// topic (written `*`).
	prefix: string,
	// The command and its arguments. `argv[0]` is an absolute path. The strings
	// are owned by the config.
	argv:   []string,
}

Config :: struct {
	rules:        [dynamic]Rule,
	// How long a command may run before its process group is killed.
	timeout:      time.Duration,
	// Events waiting for a free slot; the next one is dropped.
	max_queue:    int,
	// Commands running at one time.
	max_parallel: int,
	// At shutdown: how long running commands may finish before they are killed.
	grace:        time.Duration,
}

config_default :: proc() -> Config {
	return Config{timeout = DEFAULT_TIMEOUT, max_queue = DEFAULT_MAX_QUEUE, max_parallel = DEFAULT_MAX_PARALLEL, grace = DEFAULT_GRACE}
}

config_destroy :: proc(c: ^Config) {
	for r in c.rules {
		delete(r.prefix)
		for a in r.argv {
			delete(a)
		}
		delete(r.argv)
	}
	delete(c.rules)
	c^ = {}
}

Config_Error :: struct {
	// 1-based line in the file, or 0 for a command line option.
	line: int,
	msg:  string,
}

// A topic prefix: `*` (every topic, stored as "") or the characters of a
// topic name.
parse_prefix :: proc(s: string) -> (prefix: string, ok: bool) {
	if s == "*" {
		return "", true
	}
	if len(s) == 0 || len(s) > MAX_TOPIC_PREFIX {
		return "", false
	}
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', '0' ..= '9', '.', '_', '-':
		case:
			return "", false
		}
	}
	return s, true
}

// Split a config line into words, separated by spaces and tabs.
//   '...'  keeps everything inside literally
//   "..."  keeps everything, with `\"` and `\\` for a quote and a backslash
//   #      an unquoted word that starts with it begins a comment to line end
// The words use `allocator`.
tokenize :: proc(line: string, allocator := context.allocator) -> (words: [dynamic]string, err: string) {
	words.allocator = allocator
	b := strings.builder_make(allocator)
	defer strings.builder_destroy(&b)
	i := 0
	n := len(line)
	for i < n {
		c := line[i]
		if c == ' ' || c == '\t' || c == '\r' {
			i += 1
			continue
		}
		if c == '#' {
			break
		}
		strings.builder_reset(&b)
		for i < n && line[i] != ' ' && line[i] != '\t' && line[i] != '\r' {
			switch line[i] {
			case '\'':
				end := strings.index_byte(line[i + 1:], '\'')
				if end < 0 {
					for w in words {
						delete(w, allocator)
					}
					delete(words)
					return nil, "a ' quote is not closed"
				}
				strings.write_string(&b, line[i + 1:i + 1 + end])
				i += end + 2
			case '"':
				i += 1
				closed := false
				for i < n {
					if line[i] == '"' {
						closed = true
						i += 1
						break
					}
					if line[i] == '\\' && i + 1 < n && (line[i + 1] == '"' || line[i + 1] == '\\') {
						strings.write_byte(&b, line[i + 1])
						i += 2
						continue
					}
					strings.write_byte(&b, line[i])
					i += 1
				}
				if !closed {
					for w in words {
						delete(w, allocator)
					}
					delete(words)
					return nil, "a \" quote is not closed"
				}
			case:
				strings.write_byte(&b, line[i])
				i += 1
			}
		}
		append(&words, strings.clone(strings.to_string(b), allocator))
	}
	return words, ""
}

@(private = "file")
parse_whole :: proc(s: string, lo, hi: int) -> (v: int, ok: bool) {
	if len(s) == 0 || len(s) > 9 {
		return 0, false
	}
	for i in 0 ..< len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, parsed := strconv.parse_int(s, 10)
	if !parsed || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

// Settings that have a number: the checks shared by the file and the command line.
set_timeout :: proc(c: ^Config, s: string) -> (msg: string) {
	n, ok := parse_whole(s, 1, 3600)
	if !ok {
		return fmt.tprintf("timeout needs a whole number of seconds from 1 to 3600, but got '%s'", s)
	}
	c.timeout = time.Duration(n) * time.Second
	return ""
}

set_grace :: proc(c: ^Config, s: string) -> (msg: string) {
	n, ok := parse_whole(s, 0, 300)
	if !ok {
		return fmt.tprintf("grace needs a whole number of seconds from 0 to 300, but got '%s'", s)
	}
	c.grace = time.Duration(n) * time.Second
	return ""
}

set_max_queue :: proc(c: ^Config, s: string) -> (msg: string) {
	n, ok := parse_whole(s, 1, 10000)
	if !ok {
		return fmt.tprintf("max-queue needs a whole number from 1 to 10000, but got '%s'", s)
	}
	c.max_queue = n
	return ""
}

set_max_parallel :: proc(c: ^Config, s: string) -> (msg: string) {
	n, ok := parse_whole(s, 1, 64)
	if !ok {
		return fmt.tprintf("max-parallel needs a whole number from 1 to 64, but got '%s'", s)
	}
	c.max_parallel = n
	return ""
}

// Add a rule. `argv` must be a command with an absolute path; the strings
// are copied.
add_rule :: proc(c: ^Config, prefix_text: string, argv: []string) -> (msg: string) {
	prefix, ok := parse_prefix(prefix_text)
	if !ok {
		return fmt.tprintf("'%s' is not a topic prefix (a-z, 0-9, '.', '_', '-', at most %d characters, or *)", prefix_text, MAX_TOPIC_PREFIX)
	}
	if len(argv) == 0 || len(argv[0]) == 0 {
		return "no command was given"
	}
	if argv[0][0] != '/' {
		return fmt.tprintf("the command must be an absolute path, but got '%s'", argv[0])
	}
	for a in argv {
		if strings.contains_rune(a, 0) {
			return "a command argument contains a NUL byte"
		}
	}
	r := Rule {
		prefix = strings.clone(prefix),
		argv   = make([]string, len(argv)),
	}
	for a, i in argv {
		r.argv[i] = strings.clone(a)
	}
	append(&c.rules, r)
	return ""
}

// One line of a config file. Returns an error text, or "" (also for an empty
// line or a comment).
parse_config_line :: proc(c: ^Config, line: string) -> (msg: string) {
	words, terr := tokenize(line, context.temp_allocator)
	if terr != "" {
		return terr
	}
	if len(words) == 0 {
		return ""
	}
	key := words[0]
	args := words[1:]
	one :: proc(key: string, args: []string) -> (v: string, msg: string) {
		if len(args) != 1 {
			return "", fmt.tprintf("%s accepts only one value", key)
		}
		return args[0], ""
	}
	switch key {
	case "timeout":
		v, m := one(key, args)
		if m != "" {
			return m
		}
		return set_timeout(c, v)
	case "grace":
		v, m := one(key, args)
		if m != "" {
			return m
		}
		return set_grace(c, v)
	case "max-queue":
		v, m := one(key, args)
		if m != "" {
			return m
		}
		return set_max_queue(c, v)
	case "max-parallel":
		v, m := one(key, args)
		if m != "" {
			return m
		}
		return set_max_parallel(c, v)
	case "on":
		if len(args) < 3 || args[1] != "run" {
			return "expected: on PREFIX run /absolute/command [arguments...]"
		}
		return add_rule(c, args[0], args[2:])
	}
	return fmt.tprintf("unknown setting '%s'", key)
}

// A whole config file. Every bad line is reported; the good ones are kept.
parse_config :: proc(c: ^Config, text: string, errors: ^[dynamic]Config_Error) {
	if strings.contains_rune(text, 0) {
		append(errors, Config_Error{0, "the file contains a NUL byte"})
		return
	}
	line_no := 0
	rest := text
	for len(rest) > 0 {
		line_no += 1
		line: string
		if i := strings.index_byte(rest, '\n'); i >= 0 {
			line = rest[:i]
			rest = rest[i + 1:]
		} else {
			line = rest
			rest = ""
		}
		if m := parse_config_line(c, line); m != "" {
			append(errors, Config_Error{line_no, strings.clone(m, context.temp_allocator)})
		}
	}
}

// `--on PREFIX=/absolute/command` from the command line.
parse_on_flag :: proc(c: ^Config, spec: string) -> (msg: string) {
	eq := strings.index_byte(spec, '=')
	if eq < 0 {
		return fmt.tprintf("--on needs PREFIX=/absolute/command, but got '%s'", spec)
	}
	return add_rule(c, spec[:eq], []string{spec[eq + 1:]})
}

// Which prefixes the subscriber needs: none (everything) if a rule has `*`.
subscription_prefixes :: proc(c: ^Config, allocator := context.allocator) -> []string {
	out := make([dynamic]string, allocator)
	for r in c.rules {
		if r.prefix == "" {
			clear(&out)
			return out[:]
		}
		append(&out, r.prefix)
	}
	return out[:]
}
