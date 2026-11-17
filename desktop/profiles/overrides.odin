// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package profiles: profile store, `.ovpn` import and override lines of the
// desktop client. No UI code.
//
// This file: the overrides.
//
//	override_lines(o, allocator) -> string
//	overrides_check(o, allocator) -> [dynamic]Problem
//	compose(profile_text, o, allocator) -> string
//	server_error(host, port, proto) -> string
//	domain_valid(s) -> bool
//	address_valid(s) -> bool
//	mtu_error(s), mss_error(s) -> string
//	overrides_clone(o, allocator) -> Overrides
//	overrides_destroy(o, allocator)
//	problems_destroy(ps, allocator)
package profiles

import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"

DOMAIN_MAX :: 253
LABEL_MAX :: 63

// Local choices of the user. They become lines after the profile text.
Overrides :: struct {
	ignore_server_dns: bool `json:"ignore_server_dns"`,
	ignore_redirect:   bool `json:"ignore_redirect"`,
	domains:           [dynamic]string `json:"domains"`,
	dns_servers:       [dynamic]string `json:"dns_servers"`,
	// A later `tun-mtu` or `mssfix` line wins over the one of the profile,
	// outside <connection> blocks. "" keeps the value of the profile.
	tun_mtu:           string `json:"tun_mtu,omitempty"`,
	mssfix:            string `json:"mssfix,omitempty"`,
	block_ipv6:        bool `json:"block_ipv6"`,
	// The "Use DCO" switch is off (Linux): `disable-dco`, so the connections
	// of the profile run the data path in the service process.
	no_dco:            bool `json:"no_dco"`,
	// Replace every server of the profile. Empty keeps the servers of the
	// profile.
	servers:           [dynamic]Server `json:"servers"`,
}

// One server of the override. `proto` is "udp", "tcp" or "tls".
Server :: struct {
	host:  string `json:"host"`,
	port:  int `json:"port"`,
	proto: string `json:"proto"`,
}

// One finding of an import or check. `line` is the 1-based profile line (0 =
// none); for overrides, the 1-based list position. A fatal problem stops the import.
Problem :: struct {
	line:    int,
	option:  string,
	message: string,
	fatal:   bool,
}

// Letters, digits, '-' and '.'; labels of 1 to 63 bytes that do not start or
// end with '-'; at most 253 bytes.
domain_valid :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > DOMAIN_MAX {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i += 1 {
		if i < len(s) && s[i] != '.' {
			switch s[i] {
			case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-':
			case:
				return false
			}
			continue
		}
		label := s[start:i]
		if len(label) == 0 || len(label) > LABEL_MAX {
			return false
		}
		if label[0] == '-' || label[len(label) - 1] == '-' {
			return false
		}
		start = i + 1
	}
	return true
}

// A plain IPv4 or IPv6 address, with no port and no zone.
address_valid :: proc(s: string) -> bool {
	if s == "" {
		return false
	}
	if strings.index_byte(s, ':') >= 0 {
		if s[0] == '[' {
			return false
		}
		_, ok := net.parse_ip6_address(s)
		return ok
	}
	_, ok := net.parse_ip4_address(s)
	return ok
}

// "" for an empty or good tun-mtu value, else the message.
mtu_error :: proc(s: string) -> string {
	return number_error(s, MTU_MIN, MTU_MAX, false)
}

// "" for an empty or good mssfix value, else the message.
mss_error :: proc(s: string) -> string {
	return number_error(s, MSS_MIN, MSS_MAX, true)
}

// Own DNS servers take group numbers from OWN_DNS_FIRST up. The daemon sorts
// groups by number and pushes use 0 to 127, so own servers are asked first and
// a pushed group never replaces one.
OWN_DNS_FIRST :: -128
OWN_DNS_MAX :: 128

// The lines for the overrides, each ending with "\n". Bad domains and
// addresses are left out.
override_lines :: proc(o: Overrides, allocator := context.allocator) -> string {
	sb := strings.builder_make(allocator)
	if o.ignore_server_dns {
		strings.write_string(&sb, "pull-filter ignore \"dhcp-option DNS\"\n")
		strings.write_string(&sb, "pull-filter ignore \"dhcp-option DOMAIN\"\n")
		strings.write_string(&sb, "pull-filter ignore \"dns\"\n")
	}
	if o.ignore_redirect {
		strings.write_string(&sb, "pull-filter ignore \"redirect-gateway\"\n")
	}
	for d in o.domains {
		if domain_valid(d) {
			fmt.sbprintf(&sb, "dhcp-option DOMAIN %s\n", d)
		}
	}
	n := 0
	for a in o.dns_servers {
		if address_valid(a) && n < OWN_DNS_MAX {
			fmt.sbprintf(&sb, "dns server %d address %s\n", OWN_DNS_FIRST + n, a)
			n += 1
		}
	}
	if m := strings.trim_space(o.tun_mtu); m != "" && mtu_error(m) == "" {
		fmt.sbprintf(&sb, "tun-mtu %s\n", m)
	}
	if m := strings.trim_space(o.mssfix); m != "" && mss_error(m) == "" {
		fmt.sbprintf(&sb, "mssfix %s\n", m)
	}
	if o.block_ipv6 {
		strings.write_string(&sb, "block-ipv6\n")
	}
	if o.no_dco {
		strings.write_string(&sb, "disable-dco\n")
	}
	return strings.to_string(sb)
}

// The entries that override_lines leaves out. All problems are fatal.
overrides_check :: proc(o: Overrides, allocator := context.allocator) -> [dynamic]Problem {
	ps := make([dynamic]Problem, allocator)
	for d, i in o.domains {
		if !domain_valid(d) {
			problem_add(&ps, i + 1, "dhcp-option DOMAIN", true, allocator, "'%s' is not a valid domain name", d)
		}
	}
	for a, i in o.dns_servers {
		if !address_valid(a) {
			problem_add(&ps, i + 1, "dns server", true, allocator, "'%s' is not an IPv4 or IPv6 address", a)
		}
	}
	if len(o.dns_servers) > OWN_DNS_MAX {
		problem_add(&ps, OWN_DNS_MAX + 1, "dns server", true, allocator, "at most %d DNS servers", OWN_DNS_MAX)
	}
	for sv, i in o.servers {
		if msg := server_error(sv.host, sv.port, sv.proto); msg != "" {
			problem_add(&ps, i + 1, "remote", true, allocator, "%s", msg)
		}
	}
	if msg := mtu_error(o.tun_mtu); msg != "" {
		problem_add(&ps, 0, "tun-mtu", true, allocator, "%s", msg)
	}
	if msg := mss_error(o.mssfix); msg != "" {
		problem_add(&ps, 0, "mssfix", true, allocator, "%s", msg)
	}
	return ps
}

// "" for a good server entry, else the message.
server_error :: proc(host: string, port: int, proto: string) -> string {
	h := strings.trim_space(host)
	switch {
	case h == "":
		return "Enter the name or address of the server."
	case !domain_valid(h) && !address_valid(h):
		return "Use a host name or an IP address."
	case port < 1 || port > 65535:
		return "Use a port from 1 to 65535."
	case proto != "udp" && proto != "tcp" && proto != "tls":
		return "Use UDP, TCP or TLS."
	}
	return ""
}

// The text for `profile.set`: the profile with its servers replaced by the
// override servers (if any), a line end if missing, then the override lines.
compose :: proc(profile_text: string, o: Overrides, allocator := context.allocator) -> string {
	lines := override_lines(o, allocator)
	defer delete(lines, allocator)
	base := servers_replace(profile_text, o.servers[:], allocator)
	defer delete(base, allocator)
	sep := ""
	if base != "" && !strings.has_suffix(base, "\n") {
		sep = "\n"
	}
	return strings.concatenate({base, sep, lines}, allocator)
}

overrides_clone :: proc(o: Overrides, allocator := context.allocator) -> (c: Overrides) {
	c.ignore_server_dns = o.ignore_server_dns
	c.ignore_redirect = o.ignore_redirect
	c.domains = make([dynamic]string, 0, len(o.domains), allocator)
	for d in o.domains {
		append(&c.domains, strings.clone(d, allocator))
	}
	c.dns_servers = make([dynamic]string, 0, len(o.dns_servers), allocator)
	for a in o.dns_servers {
		append(&c.dns_servers, strings.clone(a, allocator))
	}
	c.tun_mtu = strings.clone(o.tun_mtu, allocator)
	c.mssfix = strings.clone(o.mssfix, allocator)
	c.block_ipv6 = o.block_ipv6
	c.no_dco = o.no_dco
	c.servers = make([dynamic]Server, 0, len(o.servers), allocator)
	for sv in o.servers {
		append(&c.servers, Server{strings.clone(sv.host, allocator), sv.port, strings.clone(sv.proto, allocator)})
	}
	return
}

overrides_destroy :: proc(o: ^Overrides, allocator := context.allocator) {
	for d in o.domains {
		delete(d, allocator)
	}
	delete(o.domains)
	for a in o.dns_servers {
		delete(a, allocator)
	}
	delete(o.dns_servers)
	delete(o.tun_mtu, allocator)
	delete(o.mssfix, allocator)
	for sv in o.servers {
		delete(sv.host, allocator)
		delete(sv.proto, allocator)
	}
	delete(o.servers)
	o^ = {}
}

problems_destroy :: proc(ps: ^[dynamic]Problem, allocator := context.allocator) {
	for p in ps {
		delete(p.option, allocator)
		delete(p.message, allocator)
	}
	delete(ps^)
	ps^ = nil
}

@(private)
problem_add :: proc(
	ps: ^[dynamic]Problem,
	line: int,
	option: string,
	fatal: bool,
	allocator: mem.Allocator,
	format: string,
	args: ..any,
) {
	append(
		ps,
		Problem {
			line = line,
			option = strings.clone(option, allocator),
			message = fmt.aprintf(format, ..args, allocator = allocator),
			fatal = fatal,
		},
	)
}

@(private)
has_fatal :: proc(ps: []Problem) -> bool {
	for p in ps {
		if p.fatal {
			return true
		}
	}
	return false
}
