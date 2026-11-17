// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:path/filepath"
import "core:strconv"
import "core:strings"
import "core:time"
import "noir:bus"

VERSION :: "noirvpnctl 0.1.0-dev"

DEFAULT_TIMEOUT :: 5 * time.Second
MAX_TIMEOUT :: 3600 * time.Second

// How many peers one `peers.list` request asks for when the user gave no
// --limit or --offset (the daemon allows 2000 and defaults to 500).
PEERS_PAGE :: 500

// The daemon refuses a login value longer than this (auth.supply).
SUPPLY_MAX :: 512

// The daemon cuts a kick reason at this many characters, and a deny reason too.
REASON_MAX :: 128

// The longest label of a profile, in bytes.
LABEL_MAX :: 128

// The largest profile file that the tool reads. The daemon refuses a request above
// 262144 bytes; this limit only keeps a wrong file name from filling the memory.
PROFILE_FILE_MAX :: 4 * 1024 * 1024

Kind :: enum u8 {
	None,
	Help,
	Version,
	Status,
	Stats,
	Peers,
	Peer,
	Kick,
	Reload_Peers,
	Reload_Passwords,
	Log_Level,
	Auth_Allow,
	Auth_Deny,
	Auth_Pending,
	Auth_Credentials,
	Reload,
	Shutdown,
	Connect,
	Disconnect,
	Auth_Supply,
	Events,
	Profile_Set,
	Profile_Check,
	Profile_Clear,
}

// Where a secret (password, challenge response) is read from. Never the
// command line.
Secret_Source :: enum u8 {
	None,
	Stdin,
	File,
}

// A mistake on the command line: the text for the user, or `nil` when the line
// is good.
Parse_Error :: union {
	string,
}

// The whole command line, parsed. The strings point into `argv`.
Command :: struct {
	// Global options (before the subcommand).
	name:          string,
	socket:        string,
	events_socket: string,
	json:          bool,
	timeout:       time.Duration,
	id:            string,
	// The subcommand and its arguments.
	kind:          Kind,
	session:       string,
	has_peer_id:   bool,
	peer_id:       i64,
	user:          string,
	// kick: the serial number of a client certificate (hex).
	serial:        string,
	// kick: the key of a pinned client, as the `pin` field of a peer shows it, or as the peers file has it.
	pin:           string,
	halt:          bool,
	reason:        string,
	has_reason:    bool,
	all:           bool,
	has_limit:     bool,
	limit:         i64,
	has_offset:    bool,
	offset:        i64,
	// `peers`: how many to ask for per request when fetching all of them.
	// A test can lower it.
	page_size:     i64,
	verb:          i64,
	push:          [dynamic]string,
	// `auth allow`: the name of a web sign-in and the lifetime of its token.
	auth_name:     string,
	has_lifetime:  bool,
	lifetime_s:    i64,
	// `auth pending`: the sign-in URL and its flags.
	url:           string,
	flags:         [dynamic]string,
	has_timeout_s: bool,
	timeout_s:     i64,
	username:      string,
	has_username:  bool,
	password_src:  Secret_Source,
	password_file: string,
	response_src:  Secret_Source,
	response_file: string,
	// The passphrase of the encrypted key of a service profile (`askpass`).
	key_pass_src:  Secret_Source,
	key_pass_file: string,
	// `events`: topic prefixes, stop after `count` events (0: never), and
	// wait for a daemon that is not there yet.
	prefixes:      [dynamic]string,
	count:         i64,
	wait:          bool,
	// `profile set` and `profile check`: the file, the display name, and
	// `--sso webauth` (a web sign-in can be shown, see `connect --follow`).
	file:          string,
	label:         string,
	sso:           bool,
	// `connect --follow`: print the states and a web sign-in link until up or stopped.
	follow:        bool,
}

command_destroy :: proc(c: ^Command) {
	delete(c.push)
	delete(c.flags)
	delete(c.prefixes)
	c^ = {}
}

// ---- reading the arguments ----

@(private = "file")
Args :: struct {
	argv: []string,
	i:    int,
}

// `-5` is a number.
@(private = "file")
is_negative_number :: proc(s: string) -> bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	for i in 1 ..< len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// One word of the command line, split into an option and its attached value
// (`--limit=5`) or a plain argument.
@(private = "file")
Word :: struct {
	text:      string,
	// The option name (`--limit`), or "" for a plain argument.
	opt:       string,
	value:     string,
	has_value: bool,
	// Everything after `--` is a plain argument.
	plain:     bool,
}

@(private = "file")
next_word :: proc(a: ^Args, only_plain: ^bool) -> (w: Word, ok: bool) {
	if a.i >= len(a.argv) {
		return {}, false
	}
	text := a.argv[a.i]
	a.i += 1
	w.text = text
	if only_plain^ {
		w.plain = true
		return w, true
	}
	if text == "--" {
		only_plain^ = true
		return next_word(a, only_plain)
	}
	if len(text) > 1 && text[0] == '-' && !is_negative_number(text) {
		w.opt = text
		if strings.has_prefix(text, "--") {
			if eq := strings.index_byte(text, '='); eq >= 0 {
				w.opt = text[:eq]
				w.value = text[eq + 1:]
				w.has_value = true
			}
		}
		return w, true
	}
	w.plain = true
	return w, true
}

// The value of an option: attached (`--limit=5`) or the next word.
@(private = "file")
option_value :: proc(a: ^Args, w: Word) -> (v: string, err: Parse_Error) {
	if w.has_value {
		return w.value, nil
	}
	if a.i >= len(a.argv) {
		return "", fmt.tprintf("%s requires a value", w.opt)
	}
	v = a.argv[a.i]
	a.i += 1
	return v, nil
}

// A flag takes no value.
@(private = "file")
option_flag :: proc(w: Word) -> Parse_Error {
	if w.has_value {
		return fmt.tprintf("%s does not accept a value", w.opt)
	}
	return nil
}

// Digits only.
parse_count :: proc(s: string, lo, hi: i64) -> (v: i64, ok: bool) {
	if len(s) == 0 || len(s) > 18 {
		return 0, false
	}
	for i in 0 ..< len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, parsed := strconv.parse_i64_of_base(s, 10)
	if !parsed || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

@(private = "file")
int_option :: proc(a: ^Args, w: Word, lo, hi: i64) -> (v: i64, err: Parse_Error) {
	s := option_value(a, w) or_return
	n, ok := parse_count(s, lo, hi)
	if !ok {
		return 0, fmt.tprintf("%s expects a whole number from %d to %d, but got '%s'", w.opt, lo, hi, s)
	}
	return n, nil
}

// Seconds as a number such as `5` or `0.5`, for the caller timeout.
parse_seconds :: proc(s: string) -> (d: time.Duration, ok: bool) {
	if len(s) == 0 || len(s) > 12 {
		return 0, false
	}
	for i in 0 ..< len(s) {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return 0, false
		}
	}
	f, parsed := strconv.parse_f64(s)
	if !parsed || f < 0.001 || f > f64(MAX_TIMEOUT / time.Second) {
		return 0, false
	}
	return time.Duration(f * f64(time.Second)), true
}

// A topic prefix for `events`: the characters of a topic name, up to 48.
valid_prefix :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > bus.MAX_TOPIC_LEN {
		return false
	}
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', '0' ..= '9', '.', '_', '-':
		case:
			return false
		}
	}
	return true
}

// An instance name as it appears in a socket file name.
valid_instance :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '_', '-':
		case:
			return false
		}
	}
	return true
}

// ---- the command line ----

// Parse the command line (without the program name). On a mistake `err` says
// what is wrong; `cmd` must still be destroyed.
parse_command :: proc(argv: []string) -> (cmd: Command, err: Parse_Error) {
	cmd.timeout = DEFAULT_TIMEOUT
	cmd.page_size = PEERS_PAGE
	a := Args {
		argv = argv,
	}
	plain := false
	sub := ""
	// Global options, up to the subcommand.
	for {
		w, ok := next_word(&a, &plain)
		if !ok {
			break
		}
		if w.plain {
			sub = w.text
			break
		}
		switch w.opt {
		case "-h", "--help":
			cmd.kind = .Help
			return cmd, nil
		case "-V", "--version":
			cmd.kind = .Version
			return cmd, nil
		case "--json":
			if e := option_flag(w); e != nil {
				return cmd, e
			}
			cmd.json = true
		case "--name":
			v := option_value(&a, w) or_return
			if !valid_instance(v) {
				return cmd, fmt.tprintf("--name: '%s' is not a valid instance name (use up to 40 letters, digits, '.', '_' or '-')", v)
			}
			cmd.name = v
		case "--socket":
			cmd.socket = option_value(&a, w) or_return
			if cmd.socket == "" {
				return cmd, "--socket requires a path"
			}
		case "--events-socket":
			cmd.events_socket = option_value(&a, w) or_return
			if cmd.events_socket == "" {
				return cmd, "--events-socket requires a path"
			}
		case "--timeout":
			v := option_value(&a, w) or_return
			d, d_ok := parse_seconds(v)
			if !d_ok {
				return cmd, fmt.tprintf("--timeout expects a number of seconds from 0.001 to 3600, but got '%s'", v)
			}
			cmd.timeout = d
		case "--id":
			v := option_value(&a, w) or_return
			if !bus.valid_id(v) {
				return cmd, "--id must be between 1 and 64 printable ASCII characters"
			}
			cmd.id = v
		case:
			return cmd, fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	if cmd.name != "" && cmd.socket != "" {
		return cmd, "--name and --socket cannot be used together"
	}
	if sub == "" {
		return cmd, "no command was given"
	}
	rest := Args {
		argv = argv,
		i    = a.i,
	}
	err = parse_sub(&cmd, sub, &rest, plain)
	return cmd, err
}

@(private = "file")
parse_sub :: proc(cmd: ^Command, sub: string, a: ^Args, was_plain: bool) -> Parse_Error {
	plain := was_plain
	// -h and --help work after any command.
	for i := a.i; i < len(a.argv) && !was_plain; i += 1 {
		if a.argv[i] == "--" {
			break
		}
		if a.argv[i] == "-h" || a.argv[i] == "--help" {
			cmd.kind = .Help
			return nil
		}
	}
	switch sub {
	case "help":
		cmd.kind = .Help
		return nil
	case "status":
		cmd.kind = .Status
		return parse_plain(cmd, a, &plain, 0, 0, "status does not accept any arguments")
	case "stats":
		cmd.kind = .Stats
		args, e := collect_plain(cmd, a, &plain)
		if e != nil {
			return e
		}
		defer delete(args)
		if len(args) > 1 {
			return "stats accepts at most one argument, which is a session"
		}
		if len(args) == 1 {
			cmd.session = args[0]
		}
	case "peers":
		return parse_peers(cmd, a, &plain)
	case "peer":
		return parse_peer(cmd, a, &plain)
	case "kick":
		return parse_kick(cmd, a, &plain)
	case "reload-peers":
		cmd.kind = .Reload_Peers
		return parse_plain(cmd, a, &plain, 0, 0, "reload-peers does not accept any arguments")
	case "reload-passwords":
		cmd.kind = .Reload_Passwords
		return parse_plain(cmd, a, &plain, 0, 0, "reload-passwords does not accept any arguments")
	case "log-level":
		cmd.kind = .Log_Level
		args, e := collect_plain(cmd, a, &plain)
		if e != nil {
			return e
		}
		defer delete(args)
		if len(args) != 1 {
			return "log-level requires one argument, which is the level from 0 to 4"
		}
		v, ok := parse_count(args[0], 0, 4)
		if !ok {
			return fmt.tprintf("log-level: the level must be from 0 to 4, but got '%s'", args[0])
		}
		cmd.verb = v
	case "auth":
		return parse_auth(cmd, a, &plain)
	case "reload":
		cmd.kind = .Reload
		return parse_plain(cmd, a, &plain, 0, 0, "reload does not accept any arguments")
	case "shutdown":
		cmd.kind = .Shutdown
		return parse_shutdown(cmd, a, &plain)
	case "connect":
		return parse_connect(cmd, a, &plain)
	case "disconnect":
		cmd.kind = .Disconnect
		return parse_plain(cmd, a, &plain, 0, 0, "disconnect does not accept any arguments")
	case "auth-supply":
		return parse_auth_supply(cmd, a, &plain)
	case "events":
		return parse_events(cmd, a, &plain)
	case "profile":
		return parse_profile(cmd, a, &plain)
	case:
		return fmt.tprintf("unknown command '%s'", sub)
	}
	return nil
}

// Plain arguments after the subcommand, with only `--json` allowed as an
// option. The caller frees the slice.
@(private = "file")
collect_plain :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> (args: [dynamic]string, err: Parse_Error) {
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			append(&args, w.text)
			continue
		}
		if w.opt == "--json" {
			if e := option_flag(w); e != nil {
				delete(args)
				return nil, e
			}
			cmd.json = true
			continue
		}
		delete(args)
		return nil, fmt.tprintf("unknown option '%s'", w.opt)
	}
	return args, nil
}

@(private = "file")
parse_plain :: proc(cmd: ^Command, a: ^Args, plain: ^bool, lo, hi: int, msg: string) -> Parse_Error {
	args, e := collect_plain(cmd, a, plain)
	if e != nil {
		return e
	}
	defer delete(args)
	if len(args) < lo || len(args) > hi {
		return msg
	}
	return nil
}

@(private = "file")
parse_peers :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	cmd.kind = .Peers
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			return "peers does not accept any arguments (use --all, --user, --limit or --offset instead)"
		}
		switch w.opt {
		case "--json":
			option_flag(w) or_return
			cmd.json = true
		case "--all":
			option_flag(w) or_return
			cmd.all = true
		case "--user":
			cmd.user = option_value(a, w) or_return
			if cmd.user == "" {
				return "--user requires a name"
			}
		case "--limit":
			cmd.limit = int_option(a, w, 1, 2000) or_return
			cmd.has_limit = true
		case "--offset":
			cmd.offset = int_option(a, w, 0, 1 << 40) or_return
			cmd.has_offset = true
		case:
			return fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	return nil
}

@(private = "file")
parse_peer :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	cmd.kind = .Peer
	n := 0
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			if cmd.session != "" {
				return "peer accepts only one session"
			}
			cmd.session = w.text
			n += 1
			continue
		}
		switch w.opt {
		case "--json":
			option_flag(w) or_return
			cmd.json = true
		case "--session":
			if cmd.session != "" {
				return "peer accepts only one session"
			}
			cmd.session = option_value(a, w) or_return
			n += 1
		case "--peer-id":
			cmd.peer_id = int_option(a, w, 0, 16777214) or_return
			cmd.has_peer_id = true
			n += 1
		case:
			return fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	if n != 1 || (cmd.session == "" && !cmd.has_peer_id) {
		return "peer requires exactly one of these: a session or --peer-id N"
	}
	return nil
}

@(private = "file")
parse_kick :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	cmd.kind = .Kick
	n := 0
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			if cmd.session != "" {
				return "kick accepts only one session"
			}
			cmd.session = w.text
			n += 1
			continue
		}
		switch w.opt {
		case "--json":
			option_flag(w) or_return
			cmd.json = true
		case "--session":
			if cmd.session != "" {
				return "kick accepts only one session"
			}
			cmd.session = option_value(a, w) or_return
			n += 1
		case "--peer-id":
			cmd.peer_id = int_option(a, w, 0, 16777214) or_return
			cmd.has_peer_id = true
			n += 1
		case "--user":
			cmd.user = option_value(a, w) or_return
			if cmd.user == "" {
				return "--user requires a name"
			}
			n += 1
		case "--serial":
			cmd.serial = option_value(a, w) or_return
			if cmd.serial == "" {
				return "--serial requires a serial number"
			}
		case "--pin":
			cmd.pin = option_value(a, w) or_return
			if cmd.pin == "" {
				return "--pin requires a key"
			}
		case "--halt":
			option_flag(w) or_return
			cmd.halt = true
		case "--reason":
			cmd.reason = option_value(a, w) or_return
			cmd.has_reason = true
			if len(cmd.reason) > REASON_MAX {
				return fmt.tprintf("--reason cannot be longer than %d characters", REASON_MAX)
			}
		case:
			return fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	// `--user` may go with `--serial` or `--pin` as one more condition.
	switch {
	case cmd.serial != "" && cmd.pin != "":
		return "kick --serial and --pin cannot be used together"
	case cmd.serial != "":
		if cmd.session != "" || cmd.has_peer_id {
			return "kick --serial can only be used alone or with --user, and cannot be combined with a session or --peer-id"
		}
	case cmd.pin != "":
		if cmd.session != "" || cmd.has_peer_id {
			return "kick --pin can only be used alone or with --user, and cannot be combined with a session or --peer-id"
		}
	case n != 1:
		return "kick requires exactly one of a session, --peer-id N, --user NAME, --serial HEX or --pin KEY"
	}
	return nil
}

@(private = "file")
parse_auth :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	w, ok := next_word(a, plain)
	if !ok || !w.plain {
		return "auth requires a subcommand: allow, deny, pending or credentials"
	}
	switch w.text {
	case "allow":
		cmd.kind = .Auth_Allow
	case "deny":
		cmd.kind = .Auth_Deny
	case "pending":
		cmd.kind = .Auth_Pending
	case "credentials":
		cmd.kind = .Auth_Credentials
	case:
		return fmt.tprintf("unknown auth subcommand '%s' (use allow, deny, pending or credentials)", w.text)
	}
	name := w.text
	for {
		w2, ok2 := next_word(a, plain)
		if !ok2 {
			break
		}
		if w2.plain {
			if cmd.session != "" {
				return fmt.tprintf("auth %s accepts only one session", name)
			}
			cmd.session = w2.text
			continue
		}
		switch w2.opt {
		case "--json":
			option_flag(w2) or_return
			cmd.json = true
		case "--push":
			if cmd.kind != .Auth_Allow {
				return "--push can only be used with auth allow"
			}
			line := option_value(a, w2) or_return
			if line == "" {
				return "--push requires an option line, such as 'ifconfig-push 10.8.0.50 255.255.255.0'"
			}
			append(&cmd.push, line)
		case "--name":
			if cmd.kind != .Auth_Allow {
				return "--name can only be used with auth allow"
			}
			cmd.auth_name = option_value(a, w2) or_return
			if cmd.auth_name == "" {
				return "--name requires a name"
			}
		case "--token-lifetime":
			if cmd.kind != .Auth_Allow {
				return "--token-lifetime can only be used with auth allow"
			}
			cmd.lifetime_s = int_option(a, w2, 60, 2592000) or_return
			cmd.has_lifetime = true
		case "--url":
			if cmd.kind != .Auth_Pending {
				return "--url can only be used with auth pending"
			}
			cmd.url = option_value(a, w2) or_return
			if cmd.url == "" {
				return "--url requires a URL"
			}
		case "--flag":
			if cmd.kind != .Auth_Pending {
				return "--flag can only be used with auth pending"
			}
			f := option_value(a, w2) or_return
			if f != "hidden" && f != "external" {
				return "--flag must be hidden or external"
			}
			append(&cmd.flags, f)
		case "--reason":
			if cmd.kind != .Auth_Deny {
				return "--reason can only be used with auth deny"
			}
			cmd.reason = option_value(a, w2) or_return
			cmd.has_reason = true
			if len(cmd.reason) > REASON_MAX {
				return fmt.tprintf("--reason cannot be longer than %d characters", REASON_MAX)
			}
		case "--timeout":
			if cmd.kind != .Auth_Pending {
				return "--timeout can only be used with auth pending"
			}
			cmd.timeout_s = int_option(a, w2, 1, 3600) or_return
			cmd.has_timeout_s = true
		case:
			return fmt.tprintf("unknown option '%s'", w2.opt)
		}
	}
	if cmd.session == "" {
		return fmt.tprintf("auth %s requires a session", name)
	}
	if len(cmd.flags) > 0 && cmd.url == "" {
		return "--flag requires --url"
	}
	return nil
}

@(private = "file")
parse_shutdown :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			return "shutdown does not accept any arguments, only the --timeout option"
		}
		switch w.opt {
		case "--json":
			option_flag(w) or_return
			cmd.json = true
		case "--timeout":
			cmd.timeout_s = int_option(a, w, 0, 60) or_return
			cmd.has_timeout_s = true
		case:
			return fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	return nil
}

@(private = "file")
parse_auth_supply :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	cmd.kind = .Auth_Supply
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			return "auth-supply does not accept any arguments, and it never reads a password from the command line (use --password-stdin or --password-file)"
		}
		switch w.opt {
		case "--json":
			option_flag(w) or_return
			cmd.json = true
		case "--username":
			cmd.username = option_value(a, w) or_return
			cmd.has_username = true
			if len(cmd.username) > SUPPLY_MAX {
				return fmt.tprintf("--username cannot be longer than %d bytes", SUPPLY_MAX)
			}
		case "--password-stdin":
			option_flag(w) or_return
			if cmd.password_src != .None {
				return "give the password only once, with either --password-stdin or --password-file"
			}
			cmd.password_src = .Stdin
		case "--password-file":
			if cmd.password_src != .None {
				return "give the password only once, with either --password-stdin or --password-file"
			}
			cmd.password_file = option_value(a, w) or_return
			cmd.password_src = .File
		case "--response-stdin":
			option_flag(w) or_return
			if cmd.response_src != .None {
				return "give the response only once, with either --response-stdin or --response-file"
			}
			cmd.response_src = .Stdin
		case "--response-file":
			if cmd.response_src != .None {
				return "give the response only once, with either --response-stdin or --response-file"
			}
			cmd.response_file = option_value(a, w) or_return
			cmd.response_src = .File
		case "--key-pass-stdin":
			option_flag(w) or_return
			if cmd.key_pass_src != .None {
				return "give the key passphrase only once, with either --key-pass-stdin or --key-pass-file"
			}
			cmd.key_pass_src = .Stdin
		case "--key-pass-file":
			if cmd.key_pass_src != .None {
				return "give the key passphrase only once, with either --key-pass-stdin or --key-pass-file"
			}
			cmd.key_pass_file = option_value(a, w) or_return
			cmd.key_pass_src = .File
		case "--password", "--response", "--key-pass":
			return fmt.tprintf("%s is not accepted because a secret must never appear on the command line (use %s-stdin or %s-file instead)", w.opt, w.opt, w.opt)
		case:
			return fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	if cmd.password_src == .Stdin && cmd.response_src == .Stdin {
		return "--password-stdin and --response-stdin cannot both read standard input, so use a file for one of them"
	}
	if cmd.key_pass_src == .Stdin && (cmd.password_src == .Stdin || cmd.response_src == .Stdin) {
		return "--key-pass-stdin and another -stdin option cannot both read standard input, so use a file for one of them"
	}
	if !cmd.has_username && cmd.password_src == .None && cmd.response_src == .None && cmd.key_pass_src == .None {
		return "auth-supply requires at least one of these: --username, --password-stdin/--password-file, --response-stdin/--response-file, --key-pass-stdin/--key-pass-file"
	}
	return nil
}

@(private = "file")
parse_connect :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	cmd.kind = .Connect
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			return "connect does not accept any arguments, only the --follow option"
		}
		switch w.opt {
		case "--json":
			option_flag(w) or_return
			cmd.json = true
		case "--follow", "-f":
			option_flag(w) or_return
			cmd.follow = true
		case:
			return fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	if cmd.follow && cmd.json {
		return "--follow prints plain text lines and cannot be used with --json"
	}
	return nil
}

@(private = "file")
parse_events :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	cmd.kind = .Events
	for {
		w, ok := next_word(a, plain)
		if !ok {
			break
		}
		if w.plain {
			if !valid_prefix(w.text) {
				return fmt.tprintf("'%s' is not a valid topic prefix (use up to 48 of a-z, 0-9, '.', '_' or '-')", w.text)
			}
			append(&cmd.prefixes, w.text)
			continue
		}
		switch w.opt {
		case "--json":
			option_flag(w) or_return
			cmd.json = true
		case "--wait", "-w":
			option_flag(w) or_return
			cmd.wait = true
		case "-n", "--count":
			cmd.count = int_option(a, w, 1, 1 << 40) or_return
		case:
			return fmt.tprintf("unknown option '%s'", w.opt)
		}
	}
	return nil
}

// `profile set FILE [--label NAME]`, `profile check FILE [--label NAME]` and `profile clear`.
@(private = "file")
parse_profile :: proc(cmd: ^Command, a: ^Args, plain: ^bool) -> Parse_Error {
	w, ok := next_word(a, plain)
	if !ok || !w.plain {
		return "profile requires a subcommand: set, check or clear"
	}
	switch w.text {
	case "set":
		cmd.kind = .Profile_Set
	case "check":
		cmd.kind = .Profile_Check
	case "clear":
		cmd.kind = .Profile_Clear
	case:
		return fmt.tprintf("unknown profile subcommand '%s' (use set, check or clear)", w.text)
	}
	name := w.text
	has_label := false
	for {
		w2, ok2 := next_word(a, plain)
		if !ok2 {
			break
		}
		if w2.plain {
			if cmd.kind == .Profile_Clear {
				return "profile clear does not accept any arguments"
			}
			if cmd.file != "" {
				return fmt.tprintf("profile %s accepts only one file", name)
			}
			cmd.file = w2.text
			continue
		}
		switch w2.opt {
		case "--json":
			option_flag(w2) or_return
			cmd.json = true
		case "--label":
			if cmd.kind == .Profile_Clear {
				return "--label can only be used with profile set and profile check"
			}
			cmd.label = option_value(a, w2) or_return
			has_label = true
		case "--sso":
			if cmd.kind == .Profile_Clear {
				return "--sso can only be used with profile set and profile check"
			}
			v := option_value(a, w2) or_return
			if v != "webauth" {
				return fmt.tprintf("--sso: webauth is the only supported method, but got '%s'", v)
			}
			cmd.sso = true
		case:
			return fmt.tprintf("unknown option '%s'", w2.opt)
		}
	}
	if cmd.kind == .Profile_Clear {
		return nil
	}
	if cmd.file == "" {
		return fmt.tprintf("profile %s requires a file", name)
	}
	if !has_label {
		cmd.label = filepath.stem(filepath.base(cmd.file))
		if cmd.label == "" {
			return "cannot derive a label from the file name, so give one with --label NAME"
		}
	}
	if len(cmd.label) > LABEL_MAX {
		return fmt.tprintf("the label cannot be longer than %d bytes", LABEL_MAX)
	}
	if cmd.label == "" {
		return "--label requires a name"
	}
	return nil
}

USAGE :: `noirvpnctl - control a running noirvpn daemon over its local bus

usage:
  noirvpnctl [global options] COMMAND [arguments]

global options (before the command):
  --name NAME          the daemon instance to talk to (its socket is NAME.control)
  --socket PATH        the control socket as a path or ipc:// URL, used instead of --name
  --events-socket PATH the events socket, if it is not NAME.events next to the control socket
  --json               print the raw reply (or the raw envelope for events)
  --timeout SECONDS    how long to wait for a reply (default 5)
  --id ID              use this request id (to repeat a request that timed out)
  -h, --help           show this help
  -V, --version        print the version

Without --name or --socket, noirvpnctl uses the only daemon it finds in /run/noirvpn
and $XDG_RUNTIME_DIR/noirvpn (or /tmp/noirvpn-UID).

commands, server and client:
  status                          show the mode, state and bus position
  stats [SESSION]                 show the counters (of one peer on a server)
  log-level LEVEL                 set the log level, 0 to 4
  reload                          reload the config and apply what can change at runtime
  shutdown [--timeout SECONDS]    stop the daemon, sending exit notices for up to
                                  SECONDS (0 to 60)

commands, server:
  peers [--all] [--user NAME] [--limit N] [--offset N]
                                  list the peers (every page, unless you give --limit
                                  or --offset)
  peer SESSION | --peer-id N      show one peer in detail
  kick SESSION | --peer-id N | --user NAME | --serial HEX [--user NAME]
       | --pin PIN [--user NAME]  [--halt] [--reason TEXT]
                                  disconnect a peer, or every session of a user name,
                                  of a client certificate (by its serial) or of a
                                  pinned key
  reload-peers                    reload the peers file
  reload-passwords                reload the password file
  auth allow SESSION [--push LINE]... [--name NAME] [--token-lifetime S]
                                  let a waiting login in, with extra push lines if given;
                                  a web sign-in requires --name, and --token-lifetime
                                  (60 to 2592000) gives it a session token
  auth deny SESSION [--reason TEXT]     refuse a waiting login
  auth pending SESSION [--timeout S] [--url URL] [--flag hidden|external]...
                                  keep a login waiting for S more seconds; --url sends
                                  a web sign-in link to a client that can display it
  auth credentials SESSION              show the user name and password a waiting client sent

commands, client:
  connect [--follow]              connect now; --follow prints each state change and any
                                  web sign-in link until the tunnel is up or stops
  disconnect                      disconnect and stay disconnected
  auth-supply [--username U] [--password-stdin | --password-file FILE]
              [--response-stdin | --response-file FILE]
              [--key-pass-stdin | --key-pass-file FILE]
                                  respond to a request for credentials, a challenge,
                                  or the key passphrase of a service profile

commands, client service (a daemon with client-service):
  profile set FILE [--label NAME] [--sso webauth]
                                     load a profile (the label defaults to the file name
                                     without its extension); --sso webauth lets the
                                     server request a web sign-in
  profile check FILE [--label NAME] [--sso webauth]
                                     check a profile without loading it
  profile clear                      remove the profile
  The file must contain its keys and certificates inline (<ca>, <cert>, <key>, ...).

follow the event stream:
  events [-n COUNT] [--wait] [PREFIX...]
                                  print one line for each event whose topic starts with
                                  a PREFIX (or every event if none is given); --wait
                                  waits for a daemon that has not started yet, and the
                                  command runs until SIGINT or SIGTERM

Exit codes: 0 ok, 1 error reply, 2 usage error, 3 daemon not running,
4 permission denied, 5 timeout (the request may still have been applied), 6 other failure.
`
