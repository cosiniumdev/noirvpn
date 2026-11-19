// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:fmt"
import "core:mem"
import "noir:proto/acl"
import "core:strings"

// Where a directive is read: the main config (global), or a per-client file.
@(private)
Ctx_Kind :: enum u8 {
	Global,
	Ccd,
}

// Link settings plus what is needed to finish them after all directives are read.
@(private)
Link_State :: struct {
	s:              Link_Settings,
	key_dir:        Key_Dir,
	key_dir_set:    bool,
	// tls-auth was given a direction argument.
	auth_dir_given: bool,
	// Where the tls-auth was given (for messages).
	auth_pos:       ^Directive,
	// `http-proxy` and what goes with it. They come in any order, so they are
	// joined into `s.proxy` of each remote when the link is finished
	// (`finish_proxy`). The slice is never grown in place: a block starts from a
	// copy of the global state.
	px:             Http_Proxy,
	px_set:         bool,
	px_user_pass:   Key_Source,
	// A proxy option or credentials were given, with or without `http-proxy`.
	px_other:       ^Directive,
	// Where `http-proxy` was given (for messages).
	px_pos:         ^Directive,
}

// A `remote` line outside a `<connection>` block. Port and protocol default
// to the final global settings.
@(private)
Raw_Remote :: struct {
	host:      string,
	port:      u16,
	port_set:  bool,
	proto:     Proto,
	tls:       bool,
	proto_set: bool,
	family:    Family,
	pos:       ^Directive,
}

// One remote: a finished `<connection>` block, or a plain `remote` line.
@(private)
Conn_Entry :: struct {
	block: bool,
	conn:  Connection,
	raw:   Raw_Remote,
}

@(private)
Raw_Listen :: struct {
	host:      string,
	port:      u16,
	port_set:  bool,
	proto:     Proto,
	tls:       bool,
	proto_set: bool,
	family:    Family,
}

// All state while turning directives into settings.
@(private)
Build :: struct {
	alloc:            mem.Allocator,
	diags:            [dynamic]Diagnostic,
	role:             Role,
	ctx:              Ctx_Kind,
	common:           Common_Config,
	client:           Client_Config,
	server:           Server_Config,
	specific:         Client_Specific,
	g:                Link_State,
	// Connection blocks and plain remotes, in file order.
	entries:          [dynamic]Conn_Entry,
	listens:          [dynamic]Raw_Listen,
	routes:           [dynamic]Route,
	routes6:          [dynamic]Route6,
	pull_filters:     [dynamic]Pull_Filter,
	dns_options:      [dynamic]Raw_Option,
	push:             [dynamic]string,
	fingerprints:     [dynamic][32]u8,
	bus_allow:        [dynamic]Bus_Allow,
	remote_cert_ku:   [dynamic]u16,
	iroutes:          [dynamic]Iroute,
	iroutes6:         [dynamic]Iroute6,
	push_remove:      [dynamic]string,
	acl_rules:        [dynamic]acl.Rule,
	acl_hosts:        [dynamic]string,
	forwards:         [dynamic]Forward,
	// First directive of some kinds, for cross-checks at the end.
	first:            map[string]^Directive,
	ignore_unknown:   [dynamic]string,
	forward_compat:   bool,
	// Set-ness that a default must not overwrite.
	ping_restart_set: bool,
	ping_exit_set:    bool,
	datapath_set:     bool,
	disable_dco:      bool,
	mssfix_set:       bool,
	dev_type:         string,
	dev_set:          bool,
	auth_raw:         string,
	auth_pos:         ^Directive,
	ccd_seen_inline:  bool,
	// The "no `http-proxy`" warning was given.
	px_warned:        bool,
	// `client-service` is in the config.
	service:          bool,
}

// Turns parsed directives into typed settings. Takes ownership of `p`: its
// memory now belongs to the returned `Config`, which `destroy` frees.
build :: proc(p: Parsed) -> Config {
	p := p
	cfg := Config {
		parsed = p,
	}
	b := new_build(p.store, p.diags)
	b.role, _ = detect_role(&b, p.directives)
	if b.role == .None {
		if !has_error(&b) {
			file := ""
			if len(p.directives) > 0 {
				file = p.directives[0].file
			}
			add_diag(
				&b,
				.Error,
				file,
				0,
				"cannot tell whether this is a client or a server config; add `client` or `server`",
			)
		}
	}
	for i in 0 ..< len(cfg.parsed.directives) {
		d := &cfg.parsed.directives[i]
		if b.service && !service_option_ok(d.name) {
			berr(&b, d, "is a profile option, but a config with client-service can only hold service settings")
			continue
		}
		apply(&b, d, &b.g, nil)
	}
	finish(&b)
	cfg.role = b.role
	switch b.role {
	case .Client:
		cfg.client = b.client
		cfg.client.common = b.common
		cfg.client.service = b.service
	case .Server:
		cfg.server = b.server
		cfg.server.common = b.common
	case .None:
	}
	cfg.diags = b.diags[:]
	return cfg
}

// True for an option that a config with `client-service` may hold. An unknown
// name passes, so that the build reports it as unknown.
@(private)
service_option_ok :: proc(name: string) -> bool {
	switch name {
	case "client-service", "bus-allow", "bus-control", "bus-events", "verb", "stats-interval",
	     "workers", "datapath", "dco-socket", "disable-dco", "writepid", "config", "cd":
		return true
	case "allow-inbound", "forward", "acl-max-flows", "acl-resolve-interval", "forward-max-conns":
		// The rules of the service: they win over those of a profile.
		return true
	}
	return option_find(name) == nil
}

// Like `build`, for a client-config-dir file: only the options that are legal
// there are accepted. The result is in `Config.specific`.
build_client_specific :: proc(p: Parsed) -> Config {
	p := p
	cfg := Config {
		parsed = p,
		role   = .Server,
	}
	b := new_build(p.store, p.diags)
	b.role = .Server
	b.ctx = .Ccd
	for i in 0 ..< len(cfg.parsed.directives) {
		apply(&b, &cfg.parsed.directives[i], &b.g, nil)
	}
	b.specific.iroutes = b.iroutes[:]
	b.specific.iroutes6 = b.iroutes6[:]
	b.specific.push = b.push[:]
	b.specific.push_remove = b.push_remove[:]
	cfg.specific = b.specific
	cfg.diags = b.diags[:]
	return cfg
}

// Frees a `Config` and everything in it, including the parsed directives.
destroy :: proc(c: ^Config) {
	store_free(c.parsed.store)
	c^ = {}
}

// True if the config has no errors (warnings are fine).
ok :: proc(c: ^Config) -> bool {
	return !diags_have_error(c.diags)
}

@(private)
new_build :: proc(store: ^Store, parse_diags: []Diagnostic) -> (b: Build) {
	b.alloc = store_allocator(store)
	a := b.alloc
	b.diags = make([dynamic]Diagnostic, 0, len(parse_diags) + 8, a)
	append(&b.diags, ..parse_diags)
	b.entries.allocator = a
	b.listens.allocator = a
	b.routes.allocator = a
	b.routes6.allocator = a
	b.pull_filters.allocator = a
	b.dns_options.allocator = a
	b.push.allocator = a
	b.fingerprints.allocator = a
	b.bus_allow.allocator = a
	b.remote_cert_ku.allocator = a
	b.iroutes.allocator = a
	b.iroutes6.allocator = a
	b.push_remove.allocator = a
	b.acl_rules.allocator = a
	b.acl_hosts.allocator = a
	b.forwards.allocator = a
	b.ignore_unknown.allocator = a
	b.first = make(map[string]^Directive, 16, a)

	c := &b.common
	c.verb = 1
	c.dev = "tun"
	c.data_ciphers = default_ciphers(a)
	c.tls.hand_window = 60
	c.tls.tran_window = 3600
	c.tls.tls_timeout = 2
	c.tls.reneg_sec = 3600
	c.tls.reneg_sec_min = -1
	c.replay_window = 64
	c.replay_time = 15
	g := &b.g.s
	g.lport = 1194
	g.rport = 1194
	g.connect_retry = 1
	g.connect_retry_max_wait = 300
	g.connect_timeout = 120
	b.client.resolv_retry = -1
	b.client.route_metric = -1
	b.server.max_clients = 1024
	b.server.max_routes_per_client = 256
	b.server.connect_freq_initial = Rate_Limit{100, 10}
	return
}

@(private)
default_ciphers :: proc(a: mem.Allocator) -> []Cipher {
	out := make([]Cipher, 3, a)
	out[0], out[1], out[2] = .Aes_256_Gcm, .Aes_128_Gcm, .Chacha20_Poly1305
	return out
}

// ----------------------------------------------------------------------------
// Diagnostics

@(private)
add_diag :: proc(b: ^Build, sev: Severity, file: string, line: int, text: string) {
	append(&b.diags, Diagnostic{sev, file, line, text})
}

@(private)
has_error :: proc(b: ^Build) -> bool {
	return diags_have_error(b.diags[:])
}

// Adds a diagnostic about `d` with the option name in front.
@(private)
dmsg :: proc(b: ^Build, sev: Severity, d: ^Directive, format: string, args: ..any) {
	sb := strings.builder_make(b.alloc)
	strings.write_string(&sb, d.name)
	strings.write_string(&sb, ": ")
	fmt.sbprintf(&sb, format, ..args)
	add_diag(b, sev, d.file, d.line, strings.to_string(sb))
}

@(private)
berr :: proc(b: ^Build, d: ^Directive, format: string, args: ..any) {
	dmsg(b, .Error, d, format, ..args)
}

@(private)
bwarn :: proc(b: ^Build, d: ^Directive, format: string, args: ..any) {
	dmsg(b, .Warning, d, format, ..args)
}

// An error that is not about one directive.
@(private)
gerr :: proc(b: ^Build, d: ^Directive, format: string, args: ..any) {
	text := fmt.aprintf(format, ..args, allocator = b.alloc)
	if d != nil {
		add_diag(b, .Error, d.file, d.line, text)
	} else {
		add_diag(b, .Error, "", 0, text)
	}
}

@(private)
gwarn :: proc(b: ^Build, d: ^Directive, format: string, args: ..any) {
	text := fmt.aprintf(format, ..args, allocator = b.alloc)
	if d != nil {
		add_diag(b, .Warning, d.file, d.line, text)
	} else {
		add_diag(b, .Warning, "", 0, text)
	}
}

// Parses argument `i` as a number in [lo, hi].
@(private)
arg_num :: proc(
	b: ^Build,
	d: ^Directive,
	i: int,
	lo, hi: i64,
	what: string,
) -> (
	v: int,
	ok: bool,
) {
	n, nok := parse_range(d.args[i], lo, hi, lo < 0)
	if !nok {
		berr(b, d, "%s must be a number from %d to %d, but it is '%s'", what, lo, hi, d.args[i])
		return 0, false
	}
	return int(n), true
}

@(private)
arg_num64 :: proc(
	b: ^Build,
	d: ^Directive,
	i: int,
	lo, hi: i64,
	what: string,
) -> (
	v: i64,
	ok: bool,
) {
	n, nok := parse_range(d.args[i], lo, hi, lo < 0)
	if !nok {
		berr(b, d, "%s must be a number from %d to %d, but it is '%s'", what, lo, hi, d.args[i])
		return 0, false
	}
	return n, true
}

// Whole seconds: 0 to about one year.
MAX_SECONDS :: 366 * 24 * 3600

@(private)
arg_secs :: proc(b: ^Build, d: ^Directive, i: int, lo: i64, what: string) -> (v: int, ok: bool) {
	return arg_num(b, d, i, lo, MAX_SECONDS, what)
}

// A file name or an inline block, as a Key_Source.
@(private)
key_source_of :: proc(d: ^Directive, arg: int) -> Key_Source {
	if d.has_body {
		return Key_Source{data = d.body, is_inline = true}
	}
	return Key_Source{path = d.args[arg]}
}

// Remembers the first directive with this name.
@(private)
note_first :: proc(b: ^Build, d: ^Directive) {
	if d.name not_in b.first {
		b.first[d.name] = d
	}
}

// ----------------------------------------------------------------------------
// Role

// Looks at the markers in the directives. Reports a conflict if both appear.
@(private)
detect_role :: proc(b: ^Build, dirs: []Directive) -> (role: Role, conflict: bool) {
	client_at, server_at: ^Directive
	for i in 0 ..< len(dirs) {
		d := &dirs[i]
		switch d.name {
		case "client", "pull", "tls-client":
			if client_at == nil {
				client_at = d
			}
		case "client-service":
			b.service = true
			if client_at == nil {
				client_at = d
			}
		case "server", "server-ipv6", "tls-server":
			if server_at == nil {
				server_at = d
			}
		case "mode":
			if len(d.args) == 1 && d.args[0] == "server" && server_at == nil {
				server_at = d
			}
		case "ignore-unknown-option":
			for a in d.args {
				append(&b.ignore_unknown, a)
			}
		case "setenv":
			if len(d.args) >= 2 && d.args[0] == "FORWARD_COMPATIBLE" && d.args[1] == "1" {
				b.forward_compat = true
			} else if len(d.args) >= 2 && d.args[0] == "opt" {
				append(&b.ignore_unknown, d.args[1])
			}
		}
	}
	switch {
	case client_at != nil && server_at != nil:
		gerr(
			b,
			server_at,
			"this config has both client and server directives ('%s' at line %d, '%s' at line %d)",
			client_at.name,
			client_at.line,
			server_at.name,
			server_at.line,
		)
		return .None, true
	case client_at != nil:
		return .Client, false
	case server_at != nil:
		return .Server, false
	}
	return .None, false
}

// ----------------------------------------------------------------------------
// One directive

// Applies one directive. `ls` is the link state it changes and `blk` is
// non-nil inside a `<connection>` block.
@(private)
apply :: proc(b: ^Build, d: ^Directive, ls: ^Link_State, blk: ^Block) {
	opt := option_find(d.name)
	if opt == nil {
		unknown_option(b, d)
		return
	}
	if d.block != nil || d.name == "connection" {
		if blk != nil {
			berr(b, d, "a <connection> block cannot contain another <connection> block")
		} else if b.role == .Server {
			berr(b, d, "applies to clients only, but this is a server config")
		} else if b.ctx == .Ccd {
			berr(b, d, "cannot be used in a client config file")
		} else {
			handle_connection(b, d)
		}
		return
	}
	if opt.disp == .Rejected {
		berr(b, d, "not supported: %s", opt.note)
		return
	}
	if .Push_Only in opt.flags {
		berr(b, d, "can only be pushed by the server, not set in a config file")
		return
	}
	if b.ctx == .Ccd {
		if opt.disp != .Ignored &&
		   d.name != "config" &&
		   !(.Ccd in opt.flags || .Ccd_Only in opt.flags) {
			berr(b, d, "cannot be used in a client config file")
			return
		}
	} else if .Ccd_Only in opt.flags {
		berr(
			b,
			d,
			"can only be used in a client config file (client-config-dir) or in the peers file",
		)
		return
	}
	if b.role != .None {
		if (opt.applies == .Client && b.role == .Server) ||
		   (opt.applies == .Server && b.role == .Client) {
			berr(
				b,
				d,
				"applies to %ss only, but this is a %s config",
				applies_name(opt.applies),
				role_name(b.role),
			)
			return
		}
	}
	if d.has_body {
		if .Inline not_in opt.flags {
			berr(b, d, "cannot be given as an inline <%s> block", d.name)
			return
		}
	} else if !arity_ok(b, d, opt) {
		return
	}
	if blk != nil && .Connection not_in opt.flags && opt.disp != .Ignored {
		berr(b, d, "cannot be used inside a <connection> block")
		return
	}
	if opt.disp == .Ignored {
		if d.name != "setenv" || !setenv_special(b, d) {
			bwarn(b, d, "ignored: %s", opt.note)
		}
		return
	}
	handle(b, d, ls, blk)
}

@(private)
role_name :: proc(r: Role) -> string {
	switch r {
	case .None:
		return "unknown"
	case .Client:
		return "client"
	case .Server:
		return "server"
	}
	return "?"
}

@(private)
arity_ok :: proc(b: ^Build, d: ^Directive, opt: ^Option) -> bool {
	n := len(d.args)
	if n >= opt.min_args && (opt.max_args < 0 || n <= opt.max_args) {
		return true
	}
	switch {
	case opt.max_args < 0:
		berr(b, d, "needs at least %d argument%s, but the line has %d", opt.min_args, plural(opt.min_args), n)
	case opt.min_args == opt.max_args:
		berr(b, d, "needs %d argument%s, but the line has %d", opt.min_args, plural(opt.min_args), n)
		if n > opt.max_args {
			hint_comment(b, d)
		}
	case:
		berr(b, d, "needs %d to %d arguments, but the line has %d", opt.min_args, opt.max_args, n)
		if n > opt.max_args {
			hint_comment(b, d)
		}
	}
	return false
}

@(private)
plural :: proc(n: int) -> string {
	return "" if n == 1 else "s"
}

// If an extra argument looks like a trailing comment, say that comments only
// work at the start of a line.
@(private)
hint_comment :: proc(b: ^Build, d: ^Directive) {
	for a in d.args {
		if len(a) > 0 && (a[0] == '#' || a[0] == ';') {
			gwarn(
				b,
				d,
				"'%s' looks like a comment, but comments are only allowed at the start of a line",
				a,
			)
			return
		}
	}
}

@(private)
unknown_option :: proc(b: ^Build, d: ^Directive) {
	for n in b.ignore_unknown {
		if n == d.name {
			bwarn(b, d, "unknown option, which will be ignored because ignore-unknown-option lists it")
			return
		}
	}
	if b.forward_compat {
		bwarn(b, d, "unknown option, which will be ignored because of setenv FORWARD_COMPATIBLE 1")
		return
	}
	berr(b, d, "unknown option")
}

// `setenv opt <option> args` applies the option (an unknown one is not an
// error). `setenv FORWARD_COMPATIBLE 1` was handled earlier. Returns true if
// this setenv was one of the special forms (so no "ignored" warning).
@(private)
setenv_special :: proc(b: ^Build, d: ^Directive) -> bool {
	if len(d.args) >= 2 && d.args[0] == "FORWARD_COMPATIBLE" {
		return true
	}
	if len(d.args) == 2 && d.args[0] == "IV_SSO" {
		b.client.iv_sso = d.args[1]
		return true
	}
	if len(d.args) >= 2 && d.args[0] == "opt" {
		inner := Directive {
			name = d.args[1],
			args = d.args[2:],
			file = d.file,
			line = d.line,
		}
		if option_find(inner.name) != nil {
			p := new(Directive, b.alloc)
			p^ = inner
			apply(b, p, &b.g, nil)
		}
		return true
	}
	return false
}
