// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:mem"
import "core:strings"

// Rules for a profile from a user: an unprivileged process creates it, a root
// process applies it. `user_profile_build` holds the rules. `build` does not
// know them (it also builds server configs).

// What a profile may do with one option.
User_Class :: enum u8 {
	// The option works as in a config file.
	Allowed,
	// The option is accepted and has no effect.
	Ignored,
	// The option names a file, a directory or a program.
	Path,
	// The option is a setting of the service.
	Service,
	// The option is for a server.
	Server_Only,
	// The option is rejected by the option table, or it is only valid when pushed.
	Not_Supported,
}

// The options of the service. A profile cannot set them.
@(private, rodata)
USER_SERVICE := [?]string {
	"acl-max-flows",
	"acl-resolve-interval",
	"bus-allow",
	"bus-control",
	"bus-events",
	"client-service",
	"datapath",
	"dco-socket",
	"forward",
	"forward-max-conns",
	"group",
	"stats-interval",
	"user",
	"workers",
}

// Options whose argument is a file, directory or program the daemon would read,
// write or run, with no inline form. `log` and `log-append` are ignored in a
// config file but still refused here.
@(private, rodata)
USER_PATH := [?]string{"capath", "cd", "config", "log", "log-append", "writepid"}

// Options that change only the service process. Accepted, then removed before the
// build. `Ignored` rows of the option table need no entry.
@(private, rodata)
USER_IGNORED := [?]string{"disable-dco", "mlock", "verb"}

// Options that work in a profile as they do in a config file.
@(private, rodata)
USER_ALLOWED := [?]string {
	"allow-compression",
	"allow-inbound",
	"askpass",
	"auth",
	"auth-retry",
	"auth-user-pass",
	"bind",
	"block-ipv6",
	"ca",
	"cert",
	"client",
	"connect-retry",
	"connect-retry-max",
	"connect-timeout",
	"connection",
	"crl-verify",
	"data-ciphers",
	"data-ciphers-fallback",
	"dev",
	"dev-type",
	"dhcp-option",
	"dns",
	"explicit-exit-notify",
	"extra-certs",
	"float",
	"hand-window",
	"http-proxy",
	"http-proxy-option",
	"http-proxy-user-pass",
	"ifconfig",
	"ifconfig-ipv6",
	"ifconfig-noexec",
	"ignore-unknown-option",
	"inactive",
	"keepalive",
	"key",
	"key-direction",
	"local",
	"lport",
	"mark",
	"max-packet-size",
	"mode",
	"mssfix",
	"mtu-disc",
	"ncp-ciphers",
	"nobind",
	"peer-fingerprint",
	"persist-tun",
	"ping",
	"ping-exit",
	"ping-restart",
	"ping-timer-rem",
	"pq-mode",
	"port",
	"proto",
	"proto-force",
	"pull",
	"pull-filter",
	"push-peer-info",
	"rcvbuf",
	"redirect-gateway",
	"redirect-private",
	"remote",
	"remote-cert-eku",
	"remote-cert-ku",
	"remote-cert-tls",
	"remote-random",
	"reneg-bytes",
	"reneg-pkts",
	"reneg-sec",
	"replay-window",
	"resolv-retry",
	"route",
	"route-gateway",
	"route-ipv6",
	"route-ipv6-gateway",
	"route-metric",
	"route-noexec",
	"route-nopull",
	"route-table",
	"rport",
	"server-poll-timeout",
	"session-timeout",
	"sndbuf",
	"tls-auth",
	"tls-client",
	"tls-crypt",
	"tls-crypt-v2",
	"tls-groups",
	"tls-timeout",
	"tls-transport-hello",
	"tls-transport-sni",
	"tls-transport-strict",
	"tls-transport-ws",
	"tls-version-max",
	"tls-version-min",
	"topology",
	"tran-window",
	"tun-mtu",
	"txqueuelen",
	"verify-x509-name",
}

@(private)
in_list :: proc(list: []string, name: string) -> bool {
	for n in list {
		if n == name {
			return true
		}
	}
	return false
}

// True if the class of the row comes from the table. Such a row is in no
// explicit list, except an `Ignored` row that is refused as `Path` or `Service`.
@(private)
user_class_derived :: proc(opt: ^Option) -> (c: User_Class, ok: bool) {
	switch {
	case opt.disp == .Rejected:
		return .Not_Supported, true
	case opt.applies == .Server:
		return .Server_Only, true
	case .Push_Only in opt.flags:
		return .Not_Supported, true
	}
	return .Allowed, false
}

// The class of an option in a profile from a user. A row that has no class
// is refused (`Not_Supported`); a unit test checks that there is none.
user_class :: proc(opt: ^Option) -> User_Class {
	if c, ok := user_class_derived(opt); ok {
		return c
	}
	switch {
	case in_list(USER_PATH[:], opt.name):
		return .Path
	case in_list(USER_SERVICE[:], opt.name):
		return .Service
	case opt.disp == .Ignored, in_list(USER_IGNORED[:], opt.name):
		return .Ignored
	case in_list(USER_ALLOWED[:], opt.name):
		return .Allowed
	}
	return .Not_Supported
}

// One option that the profile procedure refused.
User_Problem :: struct {
	// 1-based line in the profile text, 0 if the problem has no line.
	line:   int,
	// The name of the option, "" if the problem is not about one option.
	option: string,
	// "path", "service", "server_only", "not_supported", "unknown", "invalid" or "network".
	class:  string,
	reason: string,
}

// One option that the profile procedure accepted.
User_Entry :: struct {
	name:    string,
	line:    int,
	// The disposition: false is "supported", true is "ignored".
	ignored: bool,
	// "", or why the option is ignored, or a warning of the build.
	note:    string,
}

// The result of `user_profile_build`. The slices and the strings in them live in
// the store of `cfg` and stay valid until `user_profile_destroy`.
User_Profile :: struct {
	cfg:      Config,
	entries:  []User_Entry,
	problems: []User_Problem,
	// No problem, `ok(&cfg)` holds and the role is client.
	ok:       bool,
}

// The most bytes of a reason or a note.
@(private)
USER_TEXT_MAX :: 200

@(private)
Classifier :: struct {
	alloc:          mem.Allocator,
	entries:        [dynamic]User_Entry,
	problems:       [dynamic]User_Problem,
	ignore_unknown: [dynamic]string,
	forward_compat: bool,
	mobile:         bool,
}

// Parses a profile from text and builds it with the user profile rules.
// - No file is read: `config` and `cd` are refused like other options.
// - Every option is checked; all problems come in one pass.
// - `Ignored` and refused options are removed before the build.
// - Only a client profile passes.
// The text is copied. The result holds secrets: free it with
// `user_profile_destroy` (it overwrites the memory).
user_profile_build :: proc(text: string, allocator := context.allocator) -> User_Profile {
	return user_profile_build_for(text, false, allocator)
}

// Options with no effect on mobile. On mobile they are `ignored` with the note
// "no effect on mobile".
@(rodata)
MOBILE_NO_EFFECT := [?]string{"dev", "dev-type", "route-table", "route-metric", "mark", "persist-tun", "ip-win32", "block-outside-dns", "register-dns", "datapath"}

MOBILE_NOTE :: "no effect on mobile"

// Like `user_profile_build`. With `mobile`, MOBILE_NO_EFFECT options and
// `askpass` with no argument are ignored (the app asks for the passphrase).
// The daemon and desktop service use `mobile` false.
user_profile_build_for :: proc(text: string, mobile: bool, allocator := context.allocator) -> User_Profile {
	parsed := parse_text(text, "profile", Parse_Options{no_files = true, wipeable = true}, allocator)
	n_parse := len(parsed.diags)
	c := Classifier {
		alloc  = store_allocator(parsed.store),
		mobile = mobile,
	}
	c.entries.allocator = c.alloc
	c.problems.allocator = c.alloc
	c.ignore_unknown.allocator = c.alloc
	scan_unknown_rules(&c, parsed.directives)
	parsed.directives = classify_list(&c, parsed.directives)
	n_class := len(c.problems)

	cfg := build(parsed)
	cfg.diags = drop_dev_diag(cfg.diags)
	p := User_Profile {
		cfg = cfg,
	}
	for dg, i in cfg.diags {
		if dg.severity == .Warning {
			add_note(&c, dg)
			continue
		}
		name, reason := split_message(dg.message)
		if i >= n_parse {
			if cfg.role == .None && strings.has_prefix(dg.message, "cannot tell whether") {
				continue
			}
			if n_class > 0 && !entry_present(&c, name, dg.line) {
				continue
			}
		}
		append(
			&c.problems,
			User_Problem {
				line = dg.line,
				option = name,
				class = "invalid",
				reason = clip(reason, c.alloc),
			},
		)
	}
	switch {
	case cfg.role == .Server:
		append(
			&c.problems,
			User_Problem {
				class = "server_only",
				reason = "this is a server config, but a profile must be a client config",
			},
		)
	case cfg.role == .None && len(c.problems) == 0:
		append(
			&c.problems,
			User_Problem{class = "invalid", reason = "the profile has no `client` directive; add one"},
		)
	}
	if cfg.role == .Client {
		network_rules(&c, &cfg)
	}
	sort_problems(c.problems[:])
	p.entries = c.entries[:]
	p.problems = c.problems[:]
	p.ok = len(p.problems) == 0 && ok(&p.cfg) && p.cfg.role == .Client
	return p
}

// The build asks for a name starting with `tun` (or `dev-type tun`). A profile
// may use any device name, so this diagnostic is removed (list changed in place).
@(private)
drop_dev_diag :: proc(diags: []Diagnostic) -> []Diagnostic {
	n := 0
	for dg in diags {
		if dg.severity == .Error && strings.has_prefix(dg.message, "device '") && strings.contains(dg.message, "is not a tun device") {
			continue
		}
		diags[n] = dg
		n += 1
	}
	return diags[:n]
}

// Profile rules for the host network: device name, local port, route table.
// Route and address rules are in the plan of the client.
@(private)
network_rules :: proc(c: ^Classifier, cfg: ^Config) {
	cl := &cfg.client
	dirs := cfg.parsed.directives
	if why := user_dev_problem(cl.dev); why != "" {
		problem(c, directive_line(dirs, "dev"), "dev", "network", why)
	}
	if cl.route_table == 253 || cl.route_table == 255 {
		reason := "route table 255 is the kernel's local table; use another number"
		if cl.route_table == 253 {
			reason = "route table 253 is the kernel's default table; use another number"
		}
		problem(c, directive_line(dirs, "route-table"), "route-table", "network", reason)
	}
	for conn in cl.connections {
		if user_binds_low_port(conn) {
			line, name := low_port_directive(dirs)
			problem(
				c,
				line,
				name,
				"network",
				"the client would bind to a local port below 1024; use port 1024 or above, or use `nobind` without a local port",
			)
			break
		}
	}
}

// Why a device name is not valid in a profile, or "". `tun` is the default name.
user_dev_problem :: proc(name: string) -> string {
	if len(name) == 0 || len(name) > USER_DEV_MAX {
		return "the device name must have 1 to 15 bytes"
	}
	for ch, i in transmute([]u8)name {
		switch ch {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9':
		case '-', '_', '.':
			if i == 0 {
				return "the device name must start with a letter or a digit"
			}
		case:
			return "the device name can only contain letters, digits, '-', '_' and '.'"
		}
	}
	return ""
}

// The most bytes of a device name (the limit of a Linux interface name).
USER_DEV_MAX :: 15

// True if the client binds its UDP or TCP socket to a local port below 1024.
// It binds only with a `local` address. `nobind` and port 0 take a system port.
@(private)
user_binds_low_port :: proc(conn: Connection) -> bool {
	if conn.local_host == "" || conn.nobind {
		return false
	}
	return conn.lport != 0 && conn.lport < 1024
}

// The last directive that sets a local port below 1024: its line and name. Line
// 0 when no directive says it.
@(private)
low_port_directive :: proc(dirs: []Directive) -> (line: int, name: string) {
	name = "local"
	scan :: proc(dirs: []Directive, line: ^int, name: ^string) {
		for &d in dirs {
			low := false
			switch d.name {
			case "lport", "port":
				low = len(d.args) == 1 && low_number(d.args[0])
			case "local":
				low = len(d.args) >= 2 && low_number(d.args[1])
			}
			if low {
				line^, name^ = d.line, d.name
			}
			scan(d.block, line, name)
		}
	}
	scan(dirs, &line, &name)
	return
}

@(private)
low_number :: proc(s: string) -> bool {
	n := 0
	if len(s) == 0 || len(s) > 5 {
		return false
	}
	for ch in transmute([]u8)s {
		if ch < '0' || ch > '9' {
			return false
		}
		n = n * 10 + int(ch - '0')
	}
	return n > 0 && n < 1024
}

// The line of the first directive of this name, 0 if there is none.
@(private)
directive_line :: proc(dirs: []Directive, name: string) -> int {
	for &d in dirs {
		if d.name == name {
			return d.line
		}
		if n := directive_line(d.block, name); n > 0 {
			return n
		}
	}
	return 0
}

// Overwrites the memory of the profile with zeros and frees it.
user_profile_destroy :: proc(p: ^User_Profile) {
	store_wipe(p.cfg.parsed.store)
	destroy(&p.cfg)
	p^ = {}
}

// Reads `ignore-unknown-option` and `setenv` lines, as the build does.
@(private)
scan_unknown_rules :: proc(c: ^Classifier, dirs: []Directive) {
	for &d in dirs {
		switch d.name {
		case "ignore-unknown-option":
			for a in d.args {
				append(&c.ignore_unknown, a)
			}
		case "setenv":
			if len(d.args) >= 2 && d.args[0] == "FORWARD_COMPATIBLE" && d.args[1] == "1" {
				c.forward_compat = true
			}
		}
	}
}

// Checks the directives of one list and removes the ones that the build must
// not see. Returns the shorter list. It works in place.
@(private)
classify_list :: proc(c: ^Classifier, dirs: []Directive) -> []Directive {
	n := 0
	for i in 0 ..< len(dirs) {
		if !classify(c, &dirs[i]) {
			continue
		}
		if dirs[i].block != nil {
			dirs[i].block = classify_list(c, dirs[i].block)
		}
		if n != i {
			dirs[n] = dirs[i]
		}
		n += 1
	}
	return dirs[:n]
}

// Checks one directive. Returns true if the build gets it.
@(private)
classify :: proc(c: ^Classifier, d: ^Directive) -> bool {
	eff := d
	inner: Directive
	via_setenv := false
	if d.name == "setenv" {
		if len(d.args) >= 2 && d.args[0] == "opt" {
			// Upstream applies `setenv opt NAME ARGS` as `NAME ARGS`.
			inner = Directive {
				name = d.args[1],
				args = d.args[2:],
				file = d.file,
				line = d.line,
			}
			eff = &inner
			via_setenv = true
		} else if len(d.args) >= 1 && d.args[0] == "IV_SSO" {
			append(&c.entries, User_Entry{"setenv", d.line, true, "no effect in a profile, because the app handles the web sign-in"})
			return false
		} else {
			// Other forms set an environment variable of the scripts. There are none.
			append(&c.entries, User_Entry{"setenv", d.line, true, "no effect, because there are no scripts"})
			return false
		}
	}
	opt := option_find(eff.name)
	if opt == nil {
		name := safe_name(eff.name)
		if via_setenv || in_list(c.ignore_unknown[:], eff.name) || c.forward_compat {
			append(&c.entries, User_Entry{name, d.line, true, "unknown option, which will be ignored"})
		} else {
			problem(c, d.line, name, "unknown", "unknown option")
		}
		return false
	}
	if c.mobile {
		if in_list(MOBILE_NO_EFFECT[:], opt.name) {
			append(&c.entries, User_Entry{opt.name, d.line, true, MOBILE_NOTE})
			return false
		}
		if opt.name == "askpass" && len(eff.args) == 0 && !eff.has_body {
			append(&c.entries, User_Entry{opt.name, d.line, true, "the app asks for the passphrase"})
			return false
		}
	}
	if opt.name == "disable-dco" && !c.mobile && !via_setenv {
		// A desktop service profile may turn DCO off for its own connections (the
		// "Use DCO" app switch). It cannot turn DCO on: the data path is a service setting.
		append(&c.entries, User_Entry{opt.name, d.line, false, DISABLE_DCO_NOTE})
		return true
	}
	switch user_class(opt) {
	case .Allowed:
		if reason, bad := file_form(opt, eff); bad {
			if !c.mobile && !via_setenv && (opt.name == "auth-user-pass" || opt.name == "askpass") {
				// The desktop app reads the file as the user and sends the content with
				// `auth.supply`. The service never opens the path: the build gets the
				// form with no file and waits for the login or passphrase over the bus.
				eff.args = eff.args[:0]
				append(&c.entries, User_Entry{opt.name, d.line, false, SECRET_FILE_NOTE})
				return true
			}
			problem(c, d.line, opt.name, "path", reason)
			return false
		}
		append(&c.entries, User_Entry{opt.name, d.line, false, ""})
		return true
	case .Ignored:
		note := opt.note if opt.disp == .Ignored else "no effect in a profile"
		append(&c.entries, User_Entry{opt.name, d.line, true, note})
		return false
	case .Path:
		problem(c, d.line, opt.name, "path", "a profile cannot refer to a file, a directory or a program")
	case .Service:
		problem(c, d.line, opt.name, "service", "this is a service setting, so a profile cannot change it")
	case .Server_Only:
		problem(c, d.line, opt.name, "server_only", "this is a server option, but a profile is for a client")
	case .Not_Supported:
		reason := opt.note
		if opt.disp != .Rejected {
			reason = "only the server can push this option; a profile cannot set it"
		}
		problem(c, d.line, opt.name, "not_supported", reason)
	}
	return false
}

// For an option that takes key material: true if the directive names a file
// instead of holding an inline block, or names a file in another form.
@(private)
file_form :: proc(opt: ^Option, d: ^Directive) -> (reason: string, bad: bool) {
	if d.has_body {
		return
	}
	a := d.args
	switch opt.name {
	case "peer-fingerprint":
		// The arguments are fingerprints.
		return
	case "askpass":
		if len(a) == 1 && a[0] != "stdin" {
			return "a profile cannot use a passphrase file", true
		}
		return
	case "auth-user-pass":
		if len(a) == 1 && a[0] != "username-only" {
			return FILE_REASON, true
		}
		return
	case "http-proxy":
		if len(a) >= 3 && a[2] != "auto" && a[2] != "auto-nct" && a[2] != "none" {
			return "a profile cannot use a credentials file; use an inline http-proxy-user-pass block", true
		}
		return
	}
	if .Inline in opt.flags && len(a) >= 1 {
		return FILE_REASON, true
	}
	return
}

// The note of `disable-dco` in a profile of the desktop service.
DISABLE_DCO_NOTE :: "the connections of this profile will handle packets in the service process instead of DCO"

// The note of `auth-user-pass FILE` and `askpass FILE` in a profile of the
// desktop service.
SECRET_FILE_NOTE :: "the desktop app reads this file and sends its content over the bus, so the service never opens it"

@(private)
FILE_REASON :: "a profile cannot use a file; give the content as an inline block"

@(private)
problem :: proc(c: ^Classifier, line: int, option, class, reason: string) {
	append(&c.problems, User_Problem{line, option, class, reason})
}

// The name of an unknown option, for a message. A stray line of key text can
// become an option name, so only a short name of plain characters is shown.
@(private)
safe_name :: proc(name: string) -> string {
	if len(name) == 0 || len(name) > 40 || name[0] == '-' {
		return "?"
	}
	for ch in transmute([]u8)name {
		switch ch {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '_', '.':
		case:
			return "?"
		}
	}
	return name
}

// Splits "name: text" into the name and the text. The name is "" if the message
// does not start with an option name.
@(private)
split_message :: proc(msg: string) -> (name, reason: string) {
	i := strings.index(msg, ": ")
	if i <= 0 || i > 40 {
		return "", msg
	}
	n := msg[:i]
	for ch in transmute([]u8)n {
		switch ch {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '_', '.':
		case:
			return "", msg
		}
	}
	return n, msg[i + 2:]
}

@(private)
clip :: proc(s: string, allocator: mem.Allocator) -> string {
	if len(s) <= USER_TEXT_MAX {
		return s
	}
	return strings.concatenate({s[:USER_TEXT_MAX], "..."}, allocator)
}

// True if an accepted option of this name is on this line.
@(private)
entry_present :: proc(c: ^Classifier, name: string, line: int) -> bool {
	if name == "" || line <= 0 {
		return false
	}
	for e in c.entries {
		if e.line == line && e.name == name && !e.ignored {
			return true
		}
	}
	return false
}

// A warning of the build becomes the note of the entry on its line.
@(private)
add_note :: proc(c: ^Classifier, dg: Diagnostic) {
	if dg.line <= 0 {
		return
	}
	_, text := split_message(dg.message)
	text = clip(text, c.alloc)
	for &e in c.entries {
		if e.line != dg.line || e.ignored {
			continue
		}
		if e.note == "" {
			e.note = text
		} else {
			e.note = strings.concatenate({e.note, "; ", text}, c.alloc)
		}
		return
	}
}

// Stable sort by line. Problems without a line come last.
@(private)
sort_problems :: proc(ps: []User_Problem) {
	less :: proc(a, b: User_Problem) -> bool {
		if a.line == b.line {
			return false
		}
		if a.line == 0 {
			return false
		}
		if b.line == 0 {
			return true
		}
		return a.line < b.line
	}
	for i in 1 ..< len(ps) {
		x := ps[i]
		j := i
		for j > 0 && less(x, ps[j - 1]) {
			ps[j] = ps[j - 1]
			j -= 1
		}
		ps[j] = x
	}
}
