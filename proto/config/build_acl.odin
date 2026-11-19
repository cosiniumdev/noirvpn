// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "noir:proto/acl"

// `allow-inbound`, `forward` and their limits (client only).

ACL_MAX_FLOWS_DEFAULT :: 16384
ACL_RESOLVE_DEFAULT :: 300
FORWARD_MAX_CONNS_DEFAULT :: 256

// `forward <port> [tcp|udp] to <host>:<port>`.
Forward :: struct {
	port:      u16,
	protos:    acl.Protos, // .Tcp and/or .Udp
	// The target: a host name, or an address in text form.
	host:      string,
	host_port: u16,
}

// Returns false if the option is not one of them.
@(private)
handle_acl :: proc(b: ^Build, d: ^Directive) -> bool {
	cl := &b.client
	switch d.name {
	case "allow-inbound":
		parse_allow_inbound(b, d)
	case "forward":
		parse_forward(b, d)
	case "acl-max-flows":
		if v, ok := arg_num(b, d, 0, 64, 1 << 20, "the number of flows"); ok {
			cl.acl_max_flows = v
		}
	case "acl-resolve-interval":
		if v, ok := arg_num(b, d, 0, 10, 86400, "the interval in seconds"); ok {
			cl.acl_resolve_interval = v
		}
	case "forward-max-conns":
		if v, ok := arg_num(b, d, 0, 1, 65535, "the number of connections"); ok {
			cl.forward_max_conns = v
		}
	case:
		return false
	}
	note_first(b, d)
	return true
}

@(private)
finish_acl :: proc(b: ^Build) {
	cl := &b.client
	cl.allow_inbound = b.acl_rules[:]
	cl.acl_hosts = b.acl_hosts[:]
	cl.forwards = b.forwards[:]
	if cl.acl_max_flows == 0 {
		cl.acl_max_flows = ACL_MAX_FLOWS_DEFAULT
	}
	if cl.acl_resolve_interval == 0 {
		cl.acl_resolve_interval = ACL_RESOLVE_DEFAULT
	}
	if cl.forward_max_conns == 0 {
		cl.forward_max_conns = FORWARD_MAX_CONNS_DEFAULT
	}
	if len(cl.allow_inbound) == 0 {
		for name in ([]string{"acl-max-flows", "acl-resolve-interval"}) {
			if d, ok := b.first[name]; ok {
				bwarn(b, d, "has no effect without allow-inbound")
			}
		}
	}
	if len(cl.forwards) == 0 {
		if d, ok := b.first["forward-max-conns"]; ok {
			bwarn(b, d, "has no effect without forward")
		}
	}
}

@(private)
proto_word :: proc(s: string) -> (p: acl.Proto_Bit, ok: bool) {
	switch s {
	case "tcp":
		return .Tcp, true
	case "udp":
		return .Udp, true
	case "icmp":
		return .Icmp, true
	}
	return {}, false
}

// `allow-inbound <dest>... [tcp|udp|icmp ...]`: the words apply to every
// destination of the line.
@(private)
parse_allow_inbound :: proc(b: ^Build, d: ^Directive) {
	words: acl.Protos
	n := len(d.args)
	for n > 0 {
		p, ok := proto_word(d.args[n - 1])
		if !ok {
			break
		}
		words += {p}
		n -= 1
	}
	if n == 0 {
		berr(b, d, "needs a destination before the protocol, for example `allow-inbound :22 tcp`")
		return
	}
	for s in d.args[:n] {
		if _, ok := proto_word(s); ok {
			berr(b, d, "put the protocol '%s' after all the destinations", s)
			return
		}
		r, host, err := parse_dest(s)
		if err != "" {
			berr(b, d, "'%s' %s", s, err)
			return
		}
		ported := r.port_lo != 0
		switch {
		case words == {}:
			r.protos = acl.PROTOS_PORTS if ported else acl.PROTOS_ALL
		case ported && .Icmp in words:
			berr(b, d, "'%s' has a port, and icmp has no ports: put icmp on a line of its own", s)
			return
		case:
			r.protos = words
		}
		if r.target == .Host {
			r.host = acl_host_index(b, host)
		}
		append(&b.acl_rules, r)
	}
}

@(private)
acl_host_index :: proc(b: ^Build, name: string) -> int {
	for h, i in b.acl_hosts {
		if strings.equal_fold(h, name) {
			return i
		}
	}
	append(&b.acl_hosts, name)
	return len(b.acl_hosts) - 1
}

// One destination. `err` completes the sentence that starts with the text.
@(private)
parse_dest :: proc(s: string) -> (r: acl.Rule, host: string, err: string) {
	if s == "" {
		return r, "", "is empty"
	}
	addr, port := s, ""
	bracket, has_port := false, false
	switch {
	case s[0] == ':' && !strings.has_prefix(s, "::"):
		// `::` starts an IPv6 address, as in `::/0`.
		r.target = .Tunnel
		lo, hi, ok := parse_port_range(s[1:])
		if !ok {
			return r, "", "needs a port from 1 to 65535, or a range such as :8000-8099"
		}
		r.port_lo, r.port_hi = lo, hi
		return r, "", ""
	case s[0] == '[':
		close := strings.index_byte(s, ']')
		if close < 0 {
			return r, "", "has no closing ]"
		}
		addr = s[1:close]
		rest := s[close + 1:]
		if rest != "" {
			if rest[0] != ':' {
				return r, "", "must have :port after the ]"
			}
			port, has_port = rest[1:], true
		}
		bracket = true
	case strings.count(s, ":") >= 2:
	// An IPv6 address or prefix, with no port.
	case:
		if i := strings.index_byte(s, ':'); i >= 0 {
			addr, port, has_port = s[:i], s[i + 1:], true
		}
	}
	if has_port {
		lo, hi, ok := parse_port_range(port)
		if !ok {
			return r, "", "needs a port from 1 to 65535, or a range such as 8000-8099"
		}
		r.port_lo, r.port_hi = lo, hi
	}

	if strings.contains_rune(addr, ':') || bracket {
		// IPv6.
		a6: [16]u8
		bits := 128
		ok: bool
		if strings.contains_rune(addr, '/') {
			a6, bits, ok = ipv6_parse_cidr(addr)
		} else {
			a6, ok = ipv6_parse(addr)
		}
		if !ok {
			return r, "", "is not a valid IPv6 address or prefix"
		}
		if !ipv6_host_part_is_zero(a6, bits) {
			return r, "", "has bits set after the prefix length"
		}
		r.target = .Prefix
		r.addr = a6
		r.bits = u8(bits)
		return r, "", ""
	}
	if strings.contains_rune(addr, '/') {
		a4, bits, ok := ipv4_parse_cidr(addr)
		if !ok {
			return r, "", "is not a valid IPv4 prefix"
		}
		m := ipv4_prefix_mask(bits)
		for i in 0 ..< 4 {
			if a4[i] & ~m[i] != 0 {
				return r, "", "has bits set after the prefix length"
			}
		}
		r.target = .Prefix
		r.v4 = true
		r.addr = acl.map4(a4[:])
		r.bits = u8(96 + bits)
		return r, "", ""
	}
	if a4, ok := ipv4_parse(addr); ok {
		r.target = .Prefix
		r.v4 = true
		r.addr = acl.map4(a4[:])
		r.bits = 128
		return r, "", ""
	}
	if !is_host_name(addr) {
		return r, "", "is not an address, a prefix or a host name"
	}
	r.target = .Host
	return r, addr, ""
}

// "N" or "N-M", 1 to 65535.
@(private)
parse_port_range :: proc(s: string) -> (lo, hi: u16, ok: bool) {
	a, z := s, s
	if i := strings.index_byte(s, '-'); i >= 0 {
		a, z = s[:i], s[i + 1:]
	}
	l := parse_range(a, 1, 65535) or_return
	h := parse_range(z, 1, 65535) or_return
	if h < l {
		return 0, 0, false
	}
	return u16(l), u16(h), true
}

// Letters, digits, '-', '_' and '.', with at least one letter: a name that is
// all digits and dots is a broken IPv4 address.
@(private)
is_host_name :: proc(s: string) -> bool {
	if s == "" || len(s) > 253 || s[0] == '-' || s[0] == '.' {
		return false
	}
	letter := false
	for c in transmute([]u8)s {
		switch c {
		case 'a' ..= 'z', 'A' ..= 'Z':
			letter = true
		case '0' ..= '9', '-', '_', '.':
		case:
			return false
		}
	}
	return letter
}

// `forward <port> [tcp|udp ...] to <host>:<port>`.
@(private)
parse_forward :: proc(b: ^Build, d: ^Directive) {
	a := d.args
	n := len(a)
	if n < 3 || a[n - 2] != "to" {
		berr(b, d, "must be `forward <port> [tcp|udp] to <host>:<port>`, for example `forward 8080 to 127.0.0.1:80`")
		return
	}
	f: Forward
	p, ok := parse_range(a[0], 1, 65535)
	if !ok {
		berr(b, d, "the port must be a number from 1 to 65535, but it is '%s'", a[0])
		return
	}
	f.port = u16(p)
	for w in a[1:n - 2] {
		pb, wok := proto_word(w)
		if !wok || pb == .Icmp {
			berr(b, d, "must be tcp or udp, not '%s'", w)
			return
		}
		f.protos += {pb}
	}
	if f.protos == {} {
		f.protos = {.Tcp}
	}
	target := a[n - 1]
	host, port: string
	if strings.has_prefix(target, "[") {
		close := strings.index_byte(target, ']')
		if close < 0 || close + 1 >= len(target) || target[close + 1] != ':' {
			berr(b, d, "the target '%s' must be [address]:port", target)
			return
		}
		host, port = target[1:close], target[close + 2:]
		if _, v6 := ipv6_parse(host); !v6 {
			berr(b, d, "'%s' is not a valid IPv6 address", host)
			return
		}
	} else {
		i := strings.last_index_byte(target, ':')
		if i < 0 || strings.count(target, ":") > 1 {
			berr(b, d, "the target '%s' must be host:port (an IPv6 address goes in brackets: [::1]:80)", target)
			return
		}
		host, port = target[:i], target[i + 1:]
		if _, v4 := ipv4_parse(host); !v4 && !is_host_name(host) {
			berr(b, d, "'%s' is not an address or a host name", host)
			return
		}
	}
	tp, pok := parse_range(port, 1, 65535)
	if !pok {
		berr(b, d, "the target port must be a number from 1 to 65535, but it is '%s'", port)
		return
	}
	f.host = host
	f.host_port = u16(tp)
	for &o in b.forwards {
		if o.port == f.port && o.protos & f.protos != {} {
			berr(b, d, "port %d is already forwarded", f.port)
			return
		}
	}
	append(&b.forwards, f)
}
