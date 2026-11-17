// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import "core:fmt"
import "core:mem"
import cnet "core:net"
import "core:strings"

// DNS for the tunnel: pushed name servers and domains go to the system
// resolver while the tunnel is up, and are removed after.
//
// Linux has no single resolver API. Three backends, tried in order
// (`dns_detect`):
//  1. systemd-resolved, if `/run/systemd/resolve` exists and `resolvectl` is
//     installed. Per link (`resolvectl dns`, `resolvectl domain`);
//     `resolvectl revert` removes. `default_route` adds routing domain `~.`
//     (the link gets every query).
//  2. resolvconf(8) (openresolv or Debian's), if installed:
//     `resolvconf -a <if>.noirvpn` with the file on stdin, `-d` to remove.
//  3. `/etc/resolv.conf`, replaced atomically. The old file is saved beside it
//     and restored on revert. If somebody changed our file meanwhile, it stays
//     and `.Modified_By_Other` is returned.
//
// Commands: `core:os` process calls, no shell, argument list only. Everything
// that reaches a command line or file is checked first (`dns_valid_domain`,
// `dns_valid_ifname`). Addresses are typed.
// `DNS_Env` holds paths and the command runner (tests use temp files and a
// fake runner). One applied configuration is a `DNS`.
//
// Files: dns.odin (types, checks, text builders; no I/O), dns_backend.odin
// (detect, apply, revert), dns_linux.odin (real paths and runner).
// Windows: own `DNS_Env`, `DNS`, backend in dns_windows.odin (IP Helper API
// interface settings and NRPT rules).

// A name server. Port 0 means the default (53). Only systemd-resolved takes a
// port; the file backends drop such a server and say so in `DNS.warnings`.
DNS_Server :: struct {
	address: Address,
	port:    u16,
}

DNS_Settings :: struct {
	servers:         []DNS_Server,
	// Plain search domains: names are tried with these suffixes.
	search_domains:  []string,
	// Domains whose queries go to these servers (`~example.com` in
	// systemd-resolved). Backends without per-domain routing ignore them.
	routing_domains: []string,
	// Send every query to these servers (the routing domain `~.`). Meant for
	// `redirect-gateway`.
	default_route:   bool,
}

// Frees the slices and strings of a settings value created with `dns_settings_clone`
// (or built by the caller with the same allocator).
dns_settings_destroy :: proc(s: ^DNS_Settings, allocator := context.allocator) {
	delete(s.servers, allocator)
	for d in s.search_domains {
		delete(d, allocator)
	}
	delete(s.search_domains, allocator)
	for d in s.routing_domains {
		delete(d, allocator)
	}
	delete(s.routing_domains, allocator)
	s^ = {}
}

DNS_Error :: enum {
	None,
	// A bad interface name or domain, or no usable server.
	Invalid,
	// No way to apply the settings.
	Unsupported,
	// A command could not be started or returned a failure.
	Command_Failed,
	// A file could not be read, written or replaced.
	Io,
	Permission,
	// `/etc/resolv.conf` is not what we wrote: it was left alone.
	Modified_By_Other,
	// `dns_revert` without a successful `dns_apply`.
	Not_Applied,
	Out_Of_Memory,
}

// The first line of a resolv.conf written by us. Crash cleanup uses it to
// tell our file from somebody else's.
DNS_MARKER :: "# noirvpn:"

// glibc reads at most 3 name servers, 6 search domains, 256 bytes of search list.
RESOLV_MAX_SERVERS :: 3
RESOLV_MAX_SEARCH :: 6
RESOLV_MAX_SEARCH_BYTES :: 256

// ---- checks ----

// A domain name as it may appear on a command line and in resolv.conf: letters,
// digits, `-`, `_` and dots; labels of 1 to 63 bytes; at most 253 bytes; no
// leading `-`; one trailing dot allowed. "." alone is the root.
dns_valid_domain :: proc(s: string) -> bool {
	if s == "." {
		return true
	}
	n := len(s)
	if n == 0 || n > 253 || s[0] == '-' || s[0] == '.' {
		return false
	}
	label := 0
	for i in 0 ..< n {
		c := s[i]
		switch c {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '_':
			label += 1
			if label > 63 {
				return false
			}
		case '.':
			if label == 0 {
				return false // empty label ("a..b")
			}
			label = 0
		case:
			return false
		}
	}
	return true
}

// An interface name for a command line or a resolvconf record name.
dns_valid_ifname :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) >= IFNAMSIZ || s[0] == '-' || s[0] == '.' {
		return false
	}
	for c in transmute([]u8)s {
		switch c {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '_', '.':
		case:
			return false
		}
	}
	return true
}

// Check the whole settings value.
dns_settings_check :: proc(s: DNS_Settings) -> DNS_Error {
	if len(s.servers) == 0 {
		return .Invalid
	}
	for sv in s.servers {
		if sv.address == nil {
			return .Invalid
		}
	}
	for d in s.search_domains {
		if d == "." || !dns_valid_domain(d) {
			return .Invalid
		}
	}
	for d in s.routing_domains {
		if !dns_valid_domain(d) {
			return .Invalid
		}
	}
	return .None
}

// ---- text builders (pure) ----

// A server as `resolvectl dns` writes it: `1.2.3.4`, `1.2.3.4:853`,
// `2001:db8::1`, `[2001:db8::1]:853`.
dns_server_text :: proc(sv: DNS_Server, allocator := context.allocator) -> string {
	addr := cnet.address_to_string(sv.address, context.temp_allocator)
	if sv.port == 0 {
		return strings.clone(addr, allocator)
	}
	if _, v6 := sv.address.(IP6_Address); v6 {
		return fmt.aprintf("[%s]:%d", addr, sv.port, allocator = allocator)
	}
	return fmt.aprintf("%s:%d", addr, sv.port, allocator = allocator)
}

// Arguments of `resolvectl domain <ifname> ...` after the interface: search
// domains, routing domains with `~`, then `~.` for `default_route`. Strings are
// allocated from `allocator`.
dns_resolved_domains :: proc(s: DNS_Settings, allocator := context.allocator) -> []string {
	out := make([dynamic]string, 0, len(s.search_domains) + len(s.routing_domains) + 1, allocator)
	for d in s.search_domains {
		append(&out, strings.clone(d, allocator))
	}
	for d in s.routing_domains {
		append(&out, strings.concatenate({"~", d}, allocator))
	}
	if s.default_route {
		append(&out, strings.clone("~.", allocator))
	}
	return out[:]
}

// Text of a resolv.conf (or a resolvconf record). `with_marker` adds our header
// line. Servers with a port are dropped. Only the first 3 servers and 6 search
// domains (256 bytes) are written: glibc reads no more. Each drop adds a line
// to `warnings`.
dns_resolv_conf :: proc(
	ifname: string,
	s: DNS_Settings,
	with_marker: bool,
	warnings: ^[dynamic]string,
	allocator := context.allocator,
) -> (
	text: string,
	err: DNS_Error,
) {
	sb := strings.builder_make(allocator)
	if with_marker {
		fmt.sbprintf(&sb, "%s DNS for %s. The previous settings will be restored when the VPN disconnects.\n", DNS_MARKER, ifname)
	}
	written := 0
	for sv in s.servers {
		if sv.port != 0 {
			dns_warn(warnings, "dropped the name server %s:%d because this backend cannot use a custom port", cnet.address_to_string(sv.address, context.temp_allocator), sv.port)
			continue
		}
		if written >= RESOLV_MAX_SERVERS {
			dns_warn(warnings, "only the first %d name servers will be used", RESOLV_MAX_SERVERS)
			break
		}
		fmt.sbprintf(&sb, "nameserver %s\n", cnet.address_to_string(sv.address, context.temp_allocator))
		written += 1
	}
	if written == 0 {
		strings.builder_destroy(&sb)
		return "", .Invalid
	}
	if len(s.search_domains) > 0 {
		line := strings.builder_make(context.temp_allocator)
		count := 0
		for d in s.search_domains {
			if count >= RESOLV_MAX_SEARCH || strings.builder_len(line) + len(d) + 1 > RESOLV_MAX_SEARCH_BYTES {
				dns_warn(warnings, "the search domain list was cut after %d entries", count)
				break
			}
			strings.write_byte(&line, ' ')
			strings.write_string(&line, d)
			count += 1
		}
		fmt.sbprintf(&sb, "search%s\n", strings.to_string(line))
	}
	if len(s.routing_domains) > 0 || s.default_route {
		dns_warn(warnings, "routing domains are ignored because this backend sends every query to the same servers")
	}
	return strings.to_string(sb), .None
}

@(private)
dns_warn :: proc(warnings: ^[dynamic]string, format: string, args: ..any) {
	if warnings == nil {
		return
	}
	append(warnings, fmt.aprintf(format, ..args, allocator = warnings.allocator))
}

// Deep copy of a settings value.
dns_settings_clone :: proc(s: DNS_Settings, allocator := context.allocator) -> (c: DNS_Settings, err: mem.Allocator_Error) {
	c.default_route = s.default_route
	c.servers = make([]DNS_Server, len(s.servers), allocator) or_return
	copy(c.servers, s.servers)
	c.search_domains = make([]string, len(s.search_domains), allocator) or_return
	for d, i in s.search_domains {
		c.search_domains[i] = strings.clone(d, allocator) or_return
	}
	c.routing_domains = make([]string, len(s.routing_domains), allocator) or_return
	for d, i in s.routing_domains {
		c.routing_domains[i] = strings.clone(d, allocator) or_return
	}
	return c, nil
}
