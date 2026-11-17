// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:fmt"
import "noir:platform/sysnet"

// Host networks. A plan given a list of them keeps host networks off the tunnel:
//   - A pushed route equal to, or inside, a host network is dropped. A wider
//     one stays (the kernel uses the longest prefix).
//   - A tunnel network equal to, or inside, a host network gets its address
//     with no prefix route, so the host route stays. A wider tunnel network
//     keeps its prefix route.
// A plan with no list (a config file) does neither.

// One connected network of the host. `addr` has the host bits cleared. An IPv4
// network uses the first 4 bytes.
Host_Net :: struct {
	v6:   bool,
	addr: [16]u8,
	bits: u8,
}

// IFA_F_NOPREFIXROUTE and the host scope of an address.
@(private)
IFA_F_NOPREFIXROUTE :: u32(0x200)
@(private)
RT_SCOPE_HOST :: u8(254)

// The connected networks of the addresses on links that are up.
// Not counted:
//   - the loopback device
//   - the tunnel device (`tun_ifindex`, 0 for none)
//   - addresses that are only for the host itself
//   - an address with no prefix route
//   - IPv6 link-local addresses (fe80::/10)
// The caller owns the result.
host_nets_of :: proc(
	links: []sysnet.Link_Info,
	addrs: []sysnet.Addr_Info,
	tun_ifindex: u32,
	allocator := context.allocator,
) -> []Host_Net {
	out := make([dynamic]Host_Net, allocator)
	for a in addrs {
		if a.index == tun_ifindex || a.scope == RT_SCOPE_HOST || a.flags & IFA_F_NOPREFIXROUTE != 0 {
			continue
		}
		up := false
		for l in links {
			if l.index == a.index {
				up = .Up in l.flags && .Loopback not_in l.flags
				break
			}
		}
		if !up || a.prefix_len == 0 {
			continue
		}
		if a.prefix_len > (128 if is_v6_addr(a.address) else 32) {
			continue
		}
		// A point-to-point address has a route to the peer.
		base := a.peer.? or_else a.address
		b, v6, ok := addr_bytes(base)
		if !ok {
			continue
		}
		if v6 && b[0] == 0xfe && b[1] & 0xc0 == 0x80 {
			continue
		}
		n := Host_Net {
			v6   = v6,
			addr = mask6(b, int(a.prefix_len)),
			bits = a.prefix_len,
		}
		seen := false
		for x in out {
			if x == n {
				seen = true
				break
			}
		}
		if !seen {
			append(&out, n)
		}
	}
	return out[:]
}

host_nets_destroy :: proc(nets: []Host_Net, allocator := context.allocator) {
	delete(nets, allocator)
}

// True if the network `a/abits` is the network `b/bbits` or inside it.
@(private)
net_inside :: proc "contextless" (a: [16]u8, abits: u8, b: [16]u8, bbits: u8) -> bool {
	a, b := a, b
	return abits >= bbits && prefix_covers(b[:], int(bbits), a[:])
}

// The host network that holds the network `dst/bits`, equal or wider.
@(private)
host_net_holding :: proc(nets: []Host_Net, v6: bool, dst: [16]u8, bits: u8) -> (h: Host_Net, found: bool) {
	for n in nets {
		if n.v6 == v6 && net_inside(dst, bits, n.addr, n.bits) {
			return n, true
		}
	}
	return {}, false
}

@(private)
net_text :: proc(addr: [16]u8, bits: u8, v6: bool) -> string {
	return fmt.tprintf("%s/%d", addr_text(addr, v6), bits)
}

// True if the tunnel network is equal to a host network, or inside one (a note
// says why). The tunnel address then gets no prefix route, so the route of the
// host stays as it is. A wider tunnel network keeps its prefix route: the
// kernel uses the longest prefix, so the host network stays local.
@(private)
tunnel_overlaps_host :: proc(b: ^Builder, v6: bool, tun: []u8, bits: u8) -> bool {
	if len(b.input.host_nets) == 0 {
		return false
	}
	t: [16]u8
	copy(t[:], tun)
	h, found := host_net_holding(b.input.host_nets, v6, t, bits)
	if !found {
		return false
	}
	note(
		b,
		.Tunnel_Host_Net,
		"the tunnel network %s %s the host network %s, so the tunnel address gets no route for its network and the host network stays local",
		net_text(t, bits, v6),
		"is the same as" if bits == h.bits else "is inside",
		net_text(h.addr, h.bits, h.v6),
	)
	return true
}

// True if the pushed route must be dropped because it is equal to a
// network of the host or inside one (a note says which).
@(private)
pushed_route_in_host_net :: proc(b: ^Builder, c: Cand) -> bool {
	if len(b.input.host_nets) == 0 {
		return false
	}
	dst := c.dst
	if c.v6 {
		dst = mask6(c.dst, int(c.bits))
	} else {
		m := mask4({c.dst[0], c.dst[1], c.dst[2], c.dst[3]}, int(c.bits))
		dst = {}
		copy(dst[:], m[:])
	}
	h, found := host_net_holding(b.input.host_nets, c.v6, dst, c.bits)
	if !found {
		return false
	}
	note(
		b,
		.Dropped_Host_Net,
		"pushed route %s was dropped because it is %s the host network %s",
		net_text(dst, c.bits, c.v6),
		"the same as" if c.bits == h.bits else "inside",
		net_text(h.addr, h.bits, h.v6),
	)
	return true
}
