// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import "core:fmt"
import "core:mem"
import cnet "core:net"
import "core:os"
import "core:strings"

// DNS on macOS: the system configuration database, via scutil(8). One dynamic
// store key, `State:/Network/Service/noirvpn-<ifname>/DNS`, holds the tunnel's
// name servers and domains. configd reads it into its resolver list
// (`scutil --dns` shows it). Remove the key when the tunnel goes. A crash
// leaves it, so the clean-up records name it (`dns_record_detail`).
//
// Key contents:
//   - `ServerAddresses` - pushed name servers.
//   - `SearchDomains` - search domains.
//   - `SupplementalMatchDomains` - the routing domains, if any and
//     `default_route` is off (split DNS: only those names go to the servers).
//     Else the empty domain, which matches every name (what VPN clients on
//     macOS do).
//   - `ServerPort` - set if all servers have the same port, not 53. macOS
//     takes one port per resolver; a server with another port is dropped, with
//     a warning.
//
// After each change the system resolver caches are emptied
// (`dscacheutil -flushcache`, and SIGHUP to mDNSResponder).
// Commands run via `DNS_Env.runner` (default `run_command`): tests need no
// root and no scutil.

DNS_Backend :: enum {
	None,
	// The dynamic store through scutil.
	Scutil,
}

// Where the tools are. The strings must outlive every `DNS` created with them.
DNS_Env :: struct {
	scutil:       string,
	dscacheutil:  string,
	killall:      string,
	runner:       Command_Runner,
	// Use this backend and skip detection. `.None`: detect.
	force:        DNS_Backend,
}

// Every dynamic store key of ours is under this service name.
SCUTIL_SERVICE_PREFIX :: "noirvpn-"

// The paths of a normal macOS system.
dns_env_default :: proc() -> DNS_Env {
	return DNS_Env{scutil = "/usr/sbin/scutil", dscacheutil = "/usr/bin/dscacheutil", killall = "/usr/bin/killall"}
}

// One applied DNS configuration. Zero value = nothing applied.
DNS :: struct {
	env:       DNS_Env,
	backend:   DNS_Backend,
	active:    bool,
	allocator: mem.Allocator,
	ifname:    string,
	// The dynamic store key that was set.
	key:       string,
	// Things the backend could not do, for the log. Valid until the next apply.
	warnings:  [dynamic]string,
}

dns_destroy :: proc(d: ^DNS) {
	delete(d.ifname, d.allocator)
	delete(d.key, d.allocator)
	for w in d.warnings {
		delete(w, d.warnings.allocator)
	}
	delete(d.warnings)
	d^ = {}
}

// `.Scutil` when scutil is installed, else `.None`.
dns_detect :: proc(env: DNS_Env) -> DNS_Backend {
	if env.force != .None {
		return env.force
	}
	if env.runner.run != nil || os.is_file(env.scutil) {
		return .Scutil
	}
	return .None
}

// The dynamic store key of the DNS settings of the interface.
dns_store_key :: proc(ifname: string, allocator := context.allocator) -> string {
	return strings.concatenate({"State:/Network/Service/", SCUTIL_SERVICE_PREFIX, ifname, "/DNS"}, allocator)
}

// Runs a scutil script and returns what it printed.
// scutil reports every failure as a line on standard output and still exits 0
// ("  Permission denied", "  No such key", "set: too few arguments", an
// unknown command). A command that works prints nothing, except `list` and
// `get`. `scutil_failure` reads that text.
@(private)
scutil :: proc(env: DNS_Env, script: string) -> (out: string, err: DNS_Error) {
	argv := [?]string{env.scutil if env.scutil != "" else "/usr/sbin/scutil"}
	res, started := exec(env.runner, argv[:], script)
	if !started || res.code != 0 {
		return res.out, .Command_Failed
	}
	return res.out, .None
}

// What the output of a `set` or `remove` script says: `.None` for no output,
// `.Permission` for "Permission denied", else `.Command_Failed`. With
// `missing_ok`, a missing key ("No such key") is no failure: a remove has
// reached its goal.
@(private)
scutil_failure :: proc(out: string, missing_ok := false) -> DNS_Error {
	text := strings.trim_space(out)
	switch {
	case text == "":
		return .None
	case strings.contains(text, "Permission denied"), strings.contains(text, "Operation not permitted"):
		return .Permission
	case missing_ok && strings.contains(text, "No such key") && strings.count(text, "\n") == 0:
		return .None
	}
	return .Command_Failed
}

// Runs a script that changes the store and checks its output.
@(private)
scutil_change :: proc(env: DNS_Env, script: string, missing_ok := false) -> DNS_Error {
	out, err := scutil(env, script)
	if err != .None {
		return err
	}
	return scutil_failure(out, missing_ok)
}

// Empties the caches of the system resolver. Failures are not errors: the
// responses just stay cached for their time to live.
dns_flush_cache :: proc(env: DNS_Env) -> bool {
	ok := true
	if env.dscacheutil != "" {
		res, started := exec(env.runner, {env.dscacheutil, "-flushcache"})
		ok = ok && started && res.code == 0
	}
	if env.killall != "" {
		res, started := exec(env.runner, {env.killall, "-HUP", "mDNSResponder"})
		ok = ok && started && res.code == 0
	}
	return ok
}

// The text of the scutil commands that set the key. Pure.
dns_scutil_set_script :: proc(
	key: string,
	s: DNS_Settings,
	warnings: ^[dynamic]string,
	allocator := context.allocator,
) -> (
	script: string,
	err: DNS_Error,
) {
	sb := strings.builder_make(allocator)
	fmt.sbprintln(&sb, "open")
	fmt.sbprintln(&sb, "d.init")

	// One port for every server.
	port: u16
	port_set := false
	servers := make([dynamic]string, context.temp_allocator)
	for sv in s.servers {
		if port_set && sv.port != port {
			dns_warn(warnings, "dropped the name server %s because macOS uses one port for all name servers", cnet.address_to_string(sv.address, context.temp_allocator))
			continue
		}
		port = sv.port
		port_set = true
		append(&servers, cnet.address_to_string(sv.address, context.temp_allocator))
	}
	if len(servers) == 0 {
		strings.builder_destroy(&sb)
		return "", .Invalid
	}
	fmt.sbprintf(&sb, "d.add ServerAddresses *")
	for sv in servers {
		fmt.sbprintf(&sb, " %s", sv)
	}
	fmt.sbprintln(&sb)
	if port != 0 && port != 53 {
		fmt.sbprintfln(&sb, "d.add ServerPort # %d", port)
	}
	if len(s.search_domains) > 0 {
		fmt.sbprintf(&sb, "d.add SearchDomains *")
		for dom in s.search_domains {
			fmt.sbprintf(&sb, " %s", dom)
		}
		fmt.sbprintln(&sb)
	}
	if len(s.routing_domains) > 0 && !s.default_route {
		fmt.sbprintf(&sb, "d.add SupplementalMatchDomains *")
		for dom in s.routing_domains {
			fmt.sbprintf(&sb, " %s", dom)
		}
		fmt.sbprintln(&sb)
	} else {
		fmt.sbprintln(&sb, "d.add SupplementalMatchDomains * \"\"")
	}
	fmt.sbprintfln(&sb, "set %s", key)
	fmt.sbprintln(&sb, "quit")
	return strings.to_string(sb), .None
}

// Apply the settings for the interface named `ifname`. `d` is set up from
// scratch. On an error nothing stays applied.
dns_apply :: proc(
	d: ^DNS,
	env: DNS_Env,
	ifname: string,
	s: DNS_Settings,
	allocator := context.allocator,
) -> DNS_Error {
	if d.active {
		return .Invalid
	}
	d^ = {}
	d.env = env
	d.allocator = allocator
	d.warnings.allocator = allocator
	if !dns_valid_ifname(ifname) {
		return .Invalid
	}
	if err := dns_settings_check(s); err != .None {
		return err
	}
	d.backend = dns_detect(env)
	if d.backend == .None {
		return .Unsupported
	}
	d.ifname = strings.clone(ifname, allocator)
	d.key = dns_store_key(ifname, allocator)
	script, serr := dns_scutil_set_script(d.key, s, &d.warnings, context.temp_allocator)
	if serr != .None {
		dns_destroy_partial(d)
		return serr
	}
	if err := scutil_change(env, script); err != .None {
		dns_destroy_partial(d)
		return err
	}
	if !dns_flush_cache(env) {
		dns_warn(&d.warnings, "could not flush the DNS cache, so old responses may stay cached for a while")
	}
	d.active = true
	return .None
}

// Frees what a failed apply allocated, and keeps the warnings it gave.
@(private)
dns_destroy_partial :: proc(d: ^DNS) {
	delete(d.ifname, d.allocator)
	delete(d.key, d.allocator)
	d.ifname = ""
	d.key = ""
}

// Take the settings away again. After the call `d` holds nothing applied,
// whatever the result.
dns_revert :: proc(d: ^DNS) -> DNS_Error {
	if !d.active {
		return .Not_Applied
	}
	script := strings.concatenate({"open\nremove ", d.key, "\nquit\n"}, context.temp_allocator)
	err := scutil_change(d.env, script, missing_ok = true)
	_ = dns_flush_cache(d.env)
	d.active = false
	return err
}

// Does the key of `ifname` exist?
@(private)
store_key_exists :: proc(env: DNS_Env, ifname: string) -> bool {
	key := dns_store_key(ifname, context.temp_allocator)
	script := strings.concatenate({"open\nlist ", key, "\nquit\n"}, context.temp_allocator)
	out, err := scutil(env, script)
	return err == .None && strings.contains(out, key)
}

// Call once at start-up, before `dns_apply`, to undo what a crashed run left
// for `ifname`: its dynamic store key. Returns true if something was removed.
dns_cleanup_stale :: proc(env: DNS_Env, ifname: string) -> (restored: bool, err: DNS_Error) {
	if !dns_valid_ifname(ifname) {
		return false, .Invalid
	}
	if dns_detect(env) == .None || !store_key_exists(env, ifname) {
		return false, .None
	}
	key := dns_store_key(ifname, context.temp_allocator)
	script := strings.concatenate({"open\nremove ", key, "\nquit\n"}, context.temp_allocator)
	if serr := scutil_change(env, script, missing_ok = true); serr != .None {
		return false, serr
	}
	_ = dns_flush_cache(env)
	return true, .None
}

// The same for the key of one interface: the key is per interface, so it never
// touches another client's settings.
dns_cleanup_stale_record :: proc(env: DNS_Env, ifname: string) -> DNS_Error {
	_, err := dns_cleanup_stale(env, ifname)
	return err
}

// ---- the clean-up records of the daemons ----

// The name of a backend in a clean-up record.
dns_backend_name :: proc "contextless" (b: DNS_Backend) -> string {
	switch b {
	case .Scutil:
		return "scutil"
	case .None:
	}
	return "none"
}

dns_backend_parse :: proc(name: string) -> (b: DNS_Backend, ok: bool) {
	if name == "scutil" {
		return .Scutil, true
	}
	return .None, false
}

// The keys are per interface: two daemons never share one.
dns_backend_shared :: proc(name: string) -> bool {
	return false
}

// What the backend changes for `ifname`, for the reader of a record.
dns_record_detail :: proc(env: DNS_Env, b: DNS_Backend, ifname: string, allocator := context.temp_allocator) -> string {
	if b != .Scutil {
		return ""
	}
	return strings.concatenate({"key ", dns_store_key(ifname, context.temp_allocator)}, allocator)
}

// Reverts the DNS change of a daemon that is dead, from its record: the key of
// `ifname`, whether or not the interface is still there.
dns_cleanup_dead :: proc(env: DNS_Env, b: DNS_Backend, ifname: string, link_exists: bool) -> (restored: bool, err: DNS_Error) {
	if b != .Scutil {
		return false, .Invalid
	}
	return dns_cleanup_stale(env, ifname)
}
