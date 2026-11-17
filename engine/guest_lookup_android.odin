// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux:android
package engine

// Name lookups on a given network: android_getaddrinfofornetwork (guest_lookup.odin).

import "base:runtime"
import cnet "core:net"
import "core:strings"

import "noir:proto/config"

foreign import libandroid "system:android"
foreign import libc "system:c"

// struct addrinfo of bionic. The order of ai_canonname and ai_addr is the
// BSD one.
@(private = "file")
Bionic_Addrinfo :: struct {
	ai_flags:     i32,
	ai_family:    i32,
	ai_socktype:  i32,
	ai_protocol:  i32,
	ai_addrlen:   u32,
	ai_canonname: cstring,
	ai_addr:      rawptr,
	ai_next:      ^Bionic_Addrinfo,
}

@(private = "file", default_calling_convention = "c")
foreign libandroid {
	// <android/multinetwork.h>, API level 23.
	android_getaddrinfofornetwork :: proc(network: u64, node: cstring, service: cstring, hints: ^Bionic_Addrinfo, res: ^^Bionic_Addrinfo) -> i32 ---
}

@(private = "file", default_calling_convention = "c")
foreign libc {
	freeaddrinfo :: proc(ai: ^Bionic_Addrinfo) ---
}

@(private = "file")
LK_AF_INET :: 2
@(private = "file")
LK_AF_INET6 :: 10
@(private = "file")
SOCK_DGRAM :: 2

// The addresses of `host` on the network `network`, IPv4 first as
// platform/net resolve gives them, without duplicates.
lookup_on_network :: proc(host: string, family: config.Family, network: u64, allocator := context.allocator) -> (addrs: []cnet.Address, ok: bool) {
	hints := Bionic_Addrinfo {
		ai_socktype = SOCK_DGRAM, // one entry for each address
	}
	switch family {
	case .Any:
	case .V4:
		hints.ai_family = LK_AF_INET
	case .V6:
		hints.ai_family = LK_AF_INET6
	}
	name := strings.clone_to_cstring(host, context.temp_allocator)
	res: ^Bionic_Addrinfo
	if android_getaddrinfofornetwork(network, name, nil, &hints, &res) != 0 || res == nil {
		return nil, false
	}
	defer freeaddrinfo(res)
	v4 := make([dynamic]cnet.Address, context.temp_allocator)
	v6 := make([dynamic]cnet.Address, context.temp_allocator)
	for ai := res; ai != nil; ai = ai.ai_next {
		if ai.ai_addr == nil {
			continue
		}
		b := ([^]u8)(ai.ai_addr)
		switch ai.ai_family {
		case LK_AF_INET:
			// sockaddr_in: family (2), port (2), address (4).
			if ai.ai_addrlen < 8 {
				continue
			}
			a: cnet.IP4_Address
			runtime.mem_copy(&a, b[4:], 4)
			append_unique(&v4, cnet.Address(a))
		case LK_AF_INET6:
			// sockaddr_in6: family (2), port (2), flowinfo (4), address (16).
			if ai.ai_addrlen < 24 {
				continue
			}
			raw: [16]u8
			runtime.mem_copy(&raw, b[8:], 16)
			append_unique(&v6, cast(cnet.Address)transmute(cnet.IP6_Address)raw)
		}
	}
	out := make([]cnet.Address, len(v4) + len(v6), allocator)
	copy(out, v4[:])
	copy(out[len(v4):], v6[:])
	return out, len(out) > 0
}

@(private = "file")
append_unique :: proc(list: ^[dynamic]cnet.Address, a: cnet.Address) {
	for x in list {
		if x == a {
			return
		}
	}
	append(list, a)
}
