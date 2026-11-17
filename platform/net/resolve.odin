// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import cnet "core:net"
import "core:strings"

// Look up a host name. An IP address (v4, v6, or v6 in brackets) is returned
// as is. A name uses core:net's own resolver: it reads
// /etc/hosts and /etc/resolv.conf and asks the name servers over UDP. No libc,
// so it behaves the same in a static musl binary. It blocks the thread: call
// it at connect time, not from the data path.
//
// The result has every address found: IPv4 first, then IPv6 (a caller that
// prefers IPv6 can reorder; `pref` filters). The slice belongs to the caller:
// `delete(eps, allocator)`.
resolve :: proc(
	host: string,
	port: u16,
	pref := Resolve_Pref.Any,
	allocator := context.allocator,
) -> (
	eps: []Endpoint,
	err: Error,
) {
	name := host
	if len(name) >= 2 && name[0] == '[' && name[len(name) - 1] == ']' {
		name = name[1:len(name) - 1]
	}
	if len(name) == 0 {
		return nil, .Resolve_Failed
	}

	if addr := cnet.parse_address(name); addr != nil {
		_, is_v6 := addr.(IP6_Address)
		if (is_v6 && pref == .V4_Only) || (!is_v6 && pref == .V6_Only) {
			return nil, .Resolve_Failed
		}
		out := make([]Endpoint, 1, allocator)
		out[0] = {
			address = addr,
			port    = int(port),
		}
		return out, .None
	}

	// A name with a colon is not a hostname (a bad v6 literal, or host:port).
	if strings.contains_rune(name, ':') {
		return nil, .Resolve_Failed
	}

	list := make([dynamic]Endpoint, 0, 4, allocator)
	defer if err != .None {
		delete(list)
	}
	if pref != .V6_Only {
		recs, _ := cnet.get_dns_records_from_os(name, .IP4, context.temp_allocator)
		defer cnet.destroy_dns_records(recs, context.temp_allocator)
		for r in recs {
			if a, ok := r.(cnet.DNS_Record_IP4); ok {
				append(&list, Endpoint{address = a.address, port = int(port)})
			}
		}
	}
	if pref != .V4_Only {
		recs, _ := cnet.get_dns_records_from_os(name, .IP6, context.temp_allocator)
		defer cnet.destroy_dns_records(recs, context.temp_allocator)
		for r in recs {
			if a, ok := r.(cnet.DNS_Record_IP6); ok {
				append(&list, Endpoint{address = a.address, port = int(port)})
			}
		}
	}
	if len(list) == 0 {
		return nil, .Resolve_Failed
	}
	return list[:], .None
}
