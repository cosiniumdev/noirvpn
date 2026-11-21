// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import "core:mem"
import "core:os"
import "core:strings"
import "core:time"

// macOS: settings use ifconfig(8) and route(8) and read their output. Odin's
// SDK has no ioctl numbers (SIOCAIFADDR and the like) or PF_ROUTE structs.
// Commands start with a full path, no shell, `LC_ALL=C`, `route -n`: nothing is
// looked up by name. sysnet_darwin_parse.odin reads the text (no state). Tests
// give `Conn.runner` a fake with canned output.
//
// Differences from Linux:
//   - A tun is a point-to-point utun. An address has a peer (the address
//     itself, for a subnet topology). `addr_add` adds the network route (the
//     kernel creates only the host route).
//   - A route into a utun is on-link. A route with a gateway
//     names its interface (`route -ifp`).
//   - No metrics, tables or route protocols. A protocol number sets RTF_PROTO1
//     (`route -proto1`); `route_list_protocol` finds it.
//   - `link_set_txqlen` is `.Unsupported`.
//   - Reads (`link_get`, `route_lookup` ...) take one command each: not for
//     the data path.
//   - A failed command's text is in `last_error_text`.

// The commands, with full paths.
@(private)
IFCONFIG :: "/sbin/ifconfig"
@(private)
ROUTE :: "/sbin/route"
@(private)
NETSTAT :: "/usr/sbin/netstat"

// The result of one command.
Command_Result :: struct {
	code: int,
	// Standard output and error. The runner allocates them from the temporary
	// allocator.
	out:  string,
	err:  string,
}

// Runs a command: `argv[0]` is a full path. `stdin` is its input (empty:
// none). `started` is false if the process could not start or wait. A nil
// `run` means the real runner (`run_command`). `data` is passed back on each call.
Command_Runner :: struct {
	data: rawptr,
	run:  proc(data: rawptr, argv: []string, stdin: string) -> (res: Command_Result, started: bool),
}

// How long a command may run.
COMMAND_TIMEOUT :: 20 * time.Second

// Starts `argv` (no shell) with `stdin` as a file, waits, returns its output.
// The child gets a small fixed environment.
// Input uses a temporary file, not a pipe: a write to a pipe whose reader
// exited raises SIGPIPE, which would end the daemon.
run_command :: proc(_: rawptr, argv: []string, stdin: string) -> (res: Command_Result, started: bool) {
	if len(argv) == 0 {
		return {}, false
	}
	in_file: ^os.File
	if len(stdin) > 0 {
		f, err := os.create_temp_file("", "noirvpn-cmd-*")
		if err != nil {
			return {}, false
		}
		defer {
			// The file owns its name: copy it before the file is closed.
			name := strings.clone(os.name(f), context.temp_allocator)
			_ = os.close(f)
			_ = os.remove(name)
		}
		if _, werr := os.write_string(f, stdin); werr != nil {
			return {}, false
		}
		if _, serr := os.seek(f, 0, .Start); serr != nil {
			return {}, false
		}
		in_file = f
		return run_with_stdin(argv, in_file)
	}
	return run_with_stdin(argv, nil)
}

@(private)
run_with_stdin :: proc(argv: []string, stdin: ^os.File) -> (res: Command_Result, started: bool) {
	env := [?]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	desc := os.Process_Desc {
		command = argv,
		env     = env[:],
		stdin   = stdin,
	}
	state, out, errout, err := os.process_exec(desc, context.temp_allocator)
	if err != nil || !state.exited {
		return {}, false
	}
	return Command_Result{code = state.exit_code, out = string(out), err = string(errout)}, true
}

// Runs a command with the runner of `runner` (or the real one).
@(private)
exec :: proc(runner: Command_Runner, argv: []string, stdin := "") -> (res: Command_Result, started: bool) {
	if runner.run != nil {
		return runner.run(runner.data, argv, stdin)
	}
	return run_command(nil, argv, stdin)
}

// The index lookup of `c`: its own, or the real interfaces.
@(private)
conn_index_of :: proc(c: ^Conn) -> Index_Of {
	return c.index_of if c.index_of != nil else name_to_index
}

// A connection to the system. There is nothing to keep open: it holds the
// runner of commands and the text of the last failure.
Conn :: struct {
	allocator: mem.Allocator,
	// Leave it empty for the real commands.
	runner:    Command_Runner,
	// Gives the interface index of a name in the command output. Leave it
	// empty for the real interfaces.
	index_of:  Index_Of,
	// The text of the last failed command (the first line of its error output).
	text_buf:  [256]u8,
	text_len:  int,
	// The exit code of the last failed command.
	code:      int,
}

// Open a connection. `rx_size` is ignored.
open :: proc(allocator := context.allocator, rx_size := 32768) -> (c: Conn, err: Error) {
	c.allocator = allocator
	return c, .None
}

close :: proc(c: ^Conn) {
	c.text_len = 0
	c.code = 0
}

// The text of the last failure ("route: writing to routing socket: not in table").
last_error_text :: proc(c: ^Conn) -> string {
	return string(c.text_buf[:c.text_len])
}

// The exit code of the last failed command.
last_exit_code :: proc(c: ^Conn) -> int {
	return c.code
}

// The error that the text of a failed command stands for.
classify_failure :: proc(text: string) -> Error {
	has :: proc(s, sub: string) -> bool {
		return strings.contains(s, sub)
	}
	switch {
	case has(text, "File exists"):
		return .Exists
	case has(text, "not in table"),
	     has(text, "No such process"),
	     has(text, "does not exist"),
	     has(text, "Can't assign requested address"),
	     has(text, "No such device"):
		return .Not_Found
	case has(text, "not permitted"), has(text, "Permission denied"), has(text, "must be root"), has(text, "superuser"):
		return .Permission
	case has(text, "Network is unreachable"), has(text, "No route to host"):
		return .Network_Unreachable
	case has(text, "not supported"), has(text, "Protocol not supported"), has(text, "Address family not supported"):
		return .Unsupported
	case has(text, "Invalid argument"), has(text, "usage:"):
		return .Invalid
	case has(text, "busy"), has(text, "Busy"):
		return .Busy
	case has(text, "No buffer space"), has(text, "routing table overflow"):
		return .No_Buffer
	}
	return .Other
}

// Runs a command and turns failure into an `Error`.
// - Changing command (`strict`): fails on any error output, whatever the exit
//   code. `ifconfig` exits 0 after a failed ioctl and only prints
//   "ifconfig: ioctl (set mtu): Operation not permitted".
// - Read-only command: fails on nonzero exit.
// - Both fail on exit 0 with a known `route` failure text.
@(private)
run :: proc(c: ^Conn, argv: []string, stdin := "", strict := false) -> (res: Command_Result, err: Error) {
	r, started := exec(c.runner, argv, stdin)
	if !started {
		c.text_len = copy(c.text_buf[:], "the command could not be run")
		c.code = -1
		return {}, .Io
	}
	text := strings.trim_space(r.err)
	if text == "" {
		text = strings.trim_space(r.out)
	}
	failed := r.code != 0 || (strict && strings.trim_space(r.err) != "")
	if !failed {
		// Success output never says these.
		if strings.contains(r.err, "not in table") || strings.contains(r.err, "File exists") {
			failed = true
		}
	}
	if !failed {
		return r, .None
	}
	if nl := strings.index_byte(text, '\n'); nl >= 0 {
		text = text[:nl]
	}
	c.text_len = copy(c.text_buf[:], text)
	c.code = r.code
	full := strings.concatenate({r.err, "\n", r.out}, context.temp_allocator)
	return r, classify_failure(full)
}

// ---- links ----

@(private)
name_of_index :: proc(index: u32, buf: []u8) -> (string, Error) {
	name, ok := index_to_name(index, buf)
	if !ok {
		return "", .Not_Found
	}
	return name, .None
}

// Look up one link by name.
link_get :: proc(c: ^Conn, name: string) -> (l: Link_Info, err: Error) {
	if !dns_valid_ifname(name) {
		return {}, .Invalid
	}
	if name_to_index(name) == 0 {
		return {}, .Not_Found
	}
	res := run(c, {IFCONFIG, name}) or_return
	links := make([dynamic]Link_Info, context.temp_allocator)
	addrs := make([dynamic]Addr_Info, context.temp_allocator)
	parse_ifconfig(res.out, &links, &addrs, conn_index_of(c))
	for &cand in links {
		if link_name(&cand) == name {
			return cand, .None
		}
	}
	return {}, .Protocol
}

// Look up one link by index.
link_get_by_index :: proc(c: ^Conn, index: u32) -> (l: Link_Info, err: Error) {
	buf: [IFNAMSIZ]u8
	name := name_of_index(index, buf[:]) or_return
	return link_get(c, name)
}

// Collect all links into `out`.
link_list :: proc(c: ^Conn, out: ^[dynamic]Link_Info) -> Error {
	res := run(c, {IFCONFIG, "-a"}) or_return
	addrs := make([dynamic]Addr_Info, context.temp_allocator)
	clear(out)
	parse_ifconfig(res.out, out, &addrs, conn_index_of(c))
	return .None
}

@(private)
ifconfig_link :: proc(c: ^Conn, index: u32, args: ..string) -> Error {
	buf: [IFNAMSIZ]u8
	name := name_of_index(index, buf[:]) or_return
	argv := make([dynamic]string, context.temp_allocator)
	append(&argv, IFCONFIG, name)
	append(&argv, ..args)
	_, err := run(c, argv[:], strict = true)
	return err
}

// Set a link administratively up (like `ifconfig NAME up`).
link_set_up :: proc(c: ^Conn, index: u32) -> Error {
	return ifconfig_link(c, index, "up")
}

link_set_down :: proc(c: ^Conn, index: u32) -> Error {
	return ifconfig_link(c, index, "down")
}

link_set_mtu :: proc(c: ^Conn, index: u32, mtu: u32) -> Error {
	if mtu < 68 || mtu > 65535 {
		return .Invalid
	}
	buf: [16]u8
	text := strings.clone(format_u32(buf[:], mtu), context.temp_allocator)
	return ifconfig_link(c, index, "mtu", text)
}

// macOS has no transmit queue length to set.
link_set_txqlen :: proc(c: ^Conn, index: u32, qlen: u32) -> Error {
	return .Unsupported
}

@(private)
format_u32 :: proc(buf: []u8, v: u32) -> string {
	i := len(buf)
	n := v
	if n == 0 {
		i -= 1
		buf[i] = '0'
	}
	for n > 0 {
		i -= 1
		buf[i] = u8('0' + n % 10)
		n /= 10
	}
	return string(buf[i:])
}

// ---- addresses ----

// Add an address with a prefix length (`10.8.0.2/24`).
// On a utun the address is point-to-point (peer `opts.peer` or itself), and
// the kernel creates only a host route. So the prefix route is added here,
// unless `opts.no_prefix_route` is set or the prefix is a whole address. For
// IPv6 the kernel adds the route; `no_prefix_route` removes it. Never returns
// `.Exists`: the system takes the same address twice.
addr_add :: proc(c: ^Conn, index: u32, addr: Address, prefix_len: u8, opts: Addr_Options = {}) -> Error {
	buf: [IFNAMSIZ]u8
	name := name_of_index(index, buf[:]) or_return
	argv := build_addr_add(name, addr, prefix_len, opts.peer) or_return
	run(c, argv, strict = true) or_return

	max_len: u8 = 128 if is_v6(addr) else 32
	if prefix_len >= max_len {
		return .None
	}
	net := masked(addr, prefix_len)
	prefix_route := Route {
		dst     = net,
		dst_len = prefix_len,
		ifindex = index,
	}
	if is_v6(addr) {
		if opts.no_prefix_route {
			// Best effort: the kernel may not have created one.
			if rargv, rerr := build_route(.Delete, prefix_route, name); rerr == .None {
				_, _ = run(c, rargv, strict = true)
			}
		}
		return .None
	}
	if opts.no_prefix_route || !is_utun(name) {
		return .None
	}
	rargv := build_route(.Add, prefix_route, name) or_return
	if _, rerr := run(c, rargv, strict = true); rerr != .None && rerr != .Exists {
		// Leave nothing half done.
		if dargv, derr := build_addr_del(name, addr); derr == .None {
			_, _ = run(c, dargv, strict = true)
		}
		return rerr
	}
	return .None
}

// Remove an address. `.Not_Found` if it is not there. The routes of the
// address go with it.
addr_del :: proc(c: ^Conn, index: u32, addr: Address, prefix_len: u8, opts: Addr_Options = {}) -> Error {
	buf: [IFNAMSIZ]u8
	name := name_of_index(index, buf[:]) or_return
	argv := build_addr_del(name, addr) or_return
	_, err := run(c, argv, strict = true)
	return err
}

// Collect the addresses of one link (`index` 0: all links), optionally of one
// family, into `out`.
addr_list :: proc(c: ^Conn, index: u32, family: Maybe(Family), out: ^[dynamic]Addr_Info) -> Error {
	argv := []string{IFCONFIG, "-a"}
	buf: [IFNAMSIZ]u8
	if index != 0 {
		name := name_of_index(index, buf[:]) or_return
		argv = []string{IFCONFIG, name}
	}
	res := run(c, argv) or_return
	links := make([dynamic]Link_Info, context.temp_allocator)
	all := make([dynamic]Addr_Info, context.temp_allocator)
	parse_ifconfig(res.out, &links, &all, conn_index_of(c))
	clear(out)
	for a in all {
		if index != 0 && a.index != index {
			continue
		}
		if f, ok := family.?; ok && (is_v6(a.address) != (f == .V6)) {
			continue
		}
		append(out, a)
	}
	return .None
}

@(private)
is_v6 :: proc "contextless" (a: Address) -> bool {
	_, v6 := a.(IP6_Address)
	return v6
}

// The address with the bits outside the prefix cleared.
@(private)
masked :: proc(a: Address, prefix_len: u8) -> Address {
	switch v in a {
	case IP4_Address:
		out := v
		for i in 0 ..< 4 {
			bits_here := int(prefix_len) - i * 8
			switch {
			case bits_here >= 8:
			case bits_here <= 0:
				out[i] = 0
			case:
				out[i] &= u8(0xff << uint(8 - bits_here))
			}
		}
		return out
	case IP6_Address:
		b := transmute([16]u8)v
		for i in 0 ..< 16 {
			bits_here := int(prefix_len) - i * 8
			switch {
			case bits_here >= 8:
			case bits_here <= 0:
				b[i] = 0
			case:
				b[i] &= u8(0xff << uint(8 - bits_here))
			}
		}
		return IP6_Address(transmute([8]u16be)b)
	}
	return a
}

// ---- routes ----

@(private)
route_ifname :: proc(r: Route, buf: []u8) -> string {
	if r.ifindex == 0 {
		return ""
	}
	name, _ := index_to_name(r.ifindex, buf)
	return name
}

// Add a route. `.Exists` if one with the same destination is there, unless
// `replace` is set (`route change`).
// A route through a utun has no gateway (see the top of the file). `metric`,
// `table` and `onlink` are ignored: macOS has none.
route_add :: proc(c: ^Conn, r: Route, replace := false) -> Error {
	buf: [IFNAMSIZ]u8
	name := route_ifname(r, buf[:])
	if r.ifindex != 0 && name == "" {
		return .Not_Found
	}
	argv := build_route(.Add, r, name) or_return
	_, err := run(c, argv, strict = true)
	if err == .Exists && replace {
		cargv := build_route(.Change, r, name) or_return
		_, err = run(c, cargv, strict = true)
	}
	return err
}

// Delete a route. Give the fields that identify it: destination and prefix
// length. `.Not_Found` if there is none.
route_del :: proc(c: ^Conn, r: Route) -> Error {
	buf: [IFNAMSIZ]u8
	name := route_ifname(r, buf[:]) // empty when the interface is gone: the destination names the route
	argv := build_route(.Delete, r, name) or_return
	_, err := run(c, argv, strict = true)
	return err
}

@(private)
list_routes :: proc(c: ^Conn, family: Family, proto1: bool, protocol: u8, out: ^[dynamic]Route) -> Error {
	res := run(c, {NETSTAT, "-rn", "-f", "inet6" if family == .V6 else "inet"}) or_return
	clear(out)
	parse_netstat(res.out, family, conn_index_of(c), out, proto1, protocol)
	return .None
}

// Collect the routes of one family into `out`. `table` must be 0 (macOS has one
// table). `ifindex` 0 means any interface.
route_list :: proc(c: ^Conn, family: Family, table: u32, ifindex: u32, out: ^[dynamic]Route) -> Error {
	if table != 0 {
		return .Invalid
	}
	all := make([dynamic]Route, context.temp_allocator)
	list_routes(c, family, false, 0, &all) or_return
	clear(out)
	for r in all {
		if ifindex == 0 || r.ifindex == ifindex {
			append(out, r)
		}
	}
	return .None
}

// Collect routes of one family that carry our mark (RTF_PROTO1, set by
// `route_add` for a route with a protocol number). They read back with
// `protocol` as the protocol number.
route_list_protocol :: proc(c: ^Conn, family: Family, protocol: u8, out: ^[dynamic]Route) -> Error {
	return list_routes(c, family, true, protocol, out)
}

// The route the system uses for default traffic: `route get default`.
// `.Not_Found` if there is none.
route_get_default :: proc(c: ^Conn, family: Family) -> (r: Route, err: Error) {
	res := run(c, build_route_get(default_dst(family), family, true)) or_return
	ok: bool
	r, ok = parse_route_get(res.out, family == .V6, conn_index_of(c))
	if !ok {
		return {}, .Protocol
	}
	if r.kind != .Unicast {
		return {}, .Not_Found
	}
	return r, .None
}

// Ask which route the system would use for `dst` (`route get`). The result has
// the gateway (nil if `dst` is directly connected) and the output interface.
// For `redirect-gateway`: look up the VPN server first, then pin it through
// that gateway and interface.
route_lookup :: proc(c: ^Conn, dst: Address) -> (r: Route, err: Error) {
	family := Family.V6 if is_v6(dst) else Family.V4
	res := run(c, build_route_get(dst, family, false)) or_return
	ok: bool
	r, ok = parse_route_get(res.out, family == .V6, conn_index_of(c))
	if !ok {
		return {}, .Protocol
	}
	return r, .None
}
