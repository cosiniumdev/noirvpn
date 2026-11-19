// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:mem"
import cnet "core:net"
import "core:strings"
import "noir:proto/acl"

// The text forms of the `allow-inbound` and `forward` rules, and a check of one
// line. The daemon uses them for `acl.get`, and the desktop client for its rule
// builder, so both write and check a line in the same way.

// The destination of a rule as a config line writes it: `:22`, `10.20.0.0/16`,
// `nas.lan:445`, `[fd00::5]:443`. `hosts` are the names of the config
// (`Client_Config.acl_hosts`).
acl_dest_text :: proc(r: acl.Rule, hosts: []string, allocator := context.allocator) -> string {
	port := ""
	switch {
	case r.port_lo == 0:
	case r.port_lo == r.port_hi:
		port = fmt_u16(r.port_lo, context.temp_allocator)
	case:
		port = strings.concatenate({fmt_u16(r.port_lo, context.temp_allocator), "-", fmt_u16(r.port_hi, context.temp_allocator)}, context.temp_allocator)
	}
	switch r.target {
	case .Tunnel:
		return strings.concatenate({":", port}, allocator)
	case .Host:
		name := hosts[r.host] if r.host >= 0 && r.host < len(hosts) else "?"
		if port == "" {
			return strings.clone(name, allocator)
		}
		return strings.concatenate({name, ":", port}, allocator)
	case .Prefix:
	}
	addr: string
	if r.v4 {
		a := cnet.IP4_Address{r.addr[12], r.addr[13], r.addr[14], r.addr[15]}
		addr = cnet.address_to_string(a, context.temp_allocator)
		if r.bits < 128 {
			addr = strings.concatenate({addr, "/", fmt_u16(u16(r.bits) - 96, context.temp_allocator)}, context.temp_allocator)
		}
		if port == "" {
			return strings.clone(addr, allocator)
		}
		return strings.concatenate({addr, ":", port}, allocator)
	}
	addr = cnet.address_to_string(transmute(cnet.IP6_Address)r.addr, context.temp_allocator)
	if r.bits < 128 {
		addr = strings.concatenate({addr, "/", fmt_u16(u16(r.bits), context.temp_allocator)}, context.temp_allocator)
	}
	if port == "" {
		return strings.clone(addr, allocator)
	}
	return strings.concatenate({"[", addr, "]:", port}, allocator)
}

// The protocol words of a set, in the order tcp, udp, icmp, other. The
// strings are constants.
acl_proto_words :: proc(p: acl.Protos, out: ^[4]string) -> []string {
	n := 0
	for w in ([]struct {
			bit:  acl.Proto_Bit,
			name: string,
		}{{.Tcp, "tcp"}, {.Udp, "udp"}, {.Icmp, "icmp"}, {.Other, "other"}}) {
		if w.bit in p {
			out[n] = w.name
			n += 1
		}
	}
	return out[:n]
}

// The target of a forward: `host:port`, or `[address]:port` for IPv6.
forward_target_text :: proc(f: Forward, allocator := context.allocator) -> string {
	host := f.host
	if strings.contains_rune(host, ':') {
		host = strings.concatenate({"[", host, "]"}, context.temp_allocator)
	}
	return strings.concatenate({host, ":", fmt_u16(f.host_port, context.temp_allocator)}, allocator)
}

// Checks one line of a config file that holds `allow-inbound` or `forward`.
// Returns "" when the daemon accepts it, else the problem (allocated), as the
// daemon reports it without the option name.
acl_line_problem :: proc(line: string, allocator := context.allocator) -> string {
	p := parse_text(line, "<line>")
	defer parsed_destroy(&p)
	for d in p.diags {
		if d.severity == .Error {
			return strings.clone(d.message, allocator)
		}
	}
	if len(p.directives) != 1 {
		return strings.clone("must be one line", allocator)
	}
	d := &p.directives[0]
	if d.name != "allow-inbound" && d.name != "forward" {
		return strings.clone("must be an allow-inbound or forward line", allocator)
	}
	if d.has_body {
		return strings.clone("must not be a block", allocator)
	}
	if len(d.args) == 0 {
		if d.name == "forward" {
			return strings.clone("must be `forward <port> [tcp|udp] to <host>:<port>`", allocator)
		}
		return strings.clone("needs a destination", allocator)
	}
	b := new_build(p.store, nil)
	b.role = .Client
	_ = handle_acl(&b, d)
	for g in b.diags {
		if g.severity != .Error {
			continue
		}
		msg := g.message
		prefix := strings.concatenate({d.name, ": "}, context.temp_allocator)
		if strings.has_prefix(msg, prefix) {
			msg = msg[len(prefix):]
		}
		return strings.clone(msg, allocator)
	}
	return ""
}

@(private = "file")
fmt_u16 :: proc(v: u16, allocator: mem.Allocator) -> string {
	buf: [8]u8
	n := len(buf)
	x := v
	for {
		n -= 1
		buf[n] = '0' + u8(x % 10)
		x /= 10
		if x == 0 {
			break
		}
	}
	return strings.clone(string(buf[n:]), allocator)
}
