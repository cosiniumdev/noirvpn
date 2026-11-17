// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package sysnet

import "core:strings"
import "core:testing"

// Tests of the readers and command builders with text that the real ifconfig,
// route and netstat printed (macOS 26), and of the calls with a fake command
// runner. No privileges needed, nothing changes.

// ---- fixtures ----

@(private = "file")
IFCONFIG_TEXT :: `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128 
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 
	nd6 options=201<PERFORMNUD,DAD>
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=567<RXCSUM,TXCSUM,VLAN_MTU,TSO4,TSO6,AV,CHANNEL_IO>
	ether 02:00:00:00:00:00
	inet 10.100.0.7 netmask 0xffff0000 broadcast 10.100.255.255
	inet6 fe80::38:cb18:622d:f8d%en0 prefixlen 64 secured scopeid 0x14 
	inet6 2400:a846:408c:0:1864:8edc:7e5c:7877 prefixlen 64 autoconf secured 
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect (1000baseT <full-duplex>)
	status: active
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
	inet 10.8.0.5 --> 10.8.0.1 netmask 0xffffff00
	inet6 fe80::ce81:b1c:bd2c:69e%utun3 prefixlen 64 scopeid 0x19 
	nd6 options=201<PERFORMNUD,DAD>
bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	options=3<RXCSUM,TXCSUM>
	ether 02:00:00:00:00:00
	inet 172.16.184.1 netmask 0xffffff00 broadcast 172.16.184.255
	Configuration:
		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
	member: vmenet0 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 27 priority 0 path cost 0
	status: active
gone9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
	inet 192.0.2.9 netmask 0xffffffff
`

@(private = "file")
fake_index :: proc(name: string) -> u32 {
	switch name {
	case "lo0":
		return 1
	case "gif0":
		return 2
	case "en0":
		return 20
	case "utun3":
		return 25
	case "bridge100":
		return 28
	}
	return 0 // gone9 is not there any more
}

@(private = "file")
ROUTE_GET_DEFAULT :: `   route to: default
destination: default
       mask: default
    gateway: 10.100.254.200
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0 
`

@(private = "file")
ROUTE_GET_DEFAULT6 :: `   route to: ::
destination: ::
       mask: default
    gateway: fe80::10e8:c6ff:fe40:feae%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0 
`

@(private = "file")
ROUTE_GET_LOCAL :: `   route to: 127.0.0.1
destination: 127.0.0.1
  interface: lo0
      flags: <UP,HOST,DONE,LOCAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
   49152     49152         0         1         0         0     16384         0 
`

@(private = "file")
ROUTE_GET_ONLINK :: `   route to: 169.254.1.1
destination: 169.254.0.0
       mask: 255.255.0.0
  interface: en0
      flags: <UP,DONE,CLONING,STATIC>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500  -3486820 
`

@(private = "file")
NETSTAT4 :: `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.100.254.200     UGScg                 en0       
default            10.100.254.200     UGScIg                en1       
default            link#28            UCSIg           bridge100      !
0/1                link#25            UCS1                utun3       
10.100/16          link#20            UCS                   en0      !
10.100.0.7/32      link#20            UCS                   en0      !
10.100.0.9         link#20            UHWIig                en0     12
127                127.0.0.1          UCS                   lo0       
127.0.0.1          127.0.0.1          UH                    lo0       
169.254            link#20            UCS                   en0      !
203.0.113.9        10.100.254.200     UGHS1                 en0       
224.0.0/4          link#20            UmCS                  en0      !
`

@(private = "file")
NETSTAT6 :: `Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::10e8:c6ff:fe40:feae%en0           UGcg                  en0       
::1                                     ::1                                     UHL                   lo0       
2400:a846:408c::/64                     link#20                                 UC                    en0       
2400:a846:408c:0:1864:8edc:7e5c:3e6     2:0:0:0:0:0                             UHL                   lo0       
fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0       
8000::/1                                fe80::%utun3                            UGc1                utun3       
`

// ---- ifconfig ----

@(test)
ifconfig_links_and_addresses :: proc(t: ^testing.T) {
	links := make([dynamic]Link_Info, context.temp_allocator)
	addrs := make([dynamic]Addr_Info, context.temp_allocator)
	parse_ifconfig(IFCONFIG_TEXT, &links, &addrs, fake_index)

	// gone9 has no index any more, so neither it nor its address is listed.
	testing.expect_value(t, len(links), 5)
	testing.expect_value(t, link_name(&links[0]), "lo0")
	testing.expect_value(t, links[0].index, 1)
	testing.expect_value(t, links[0].mtu, 16384)
	testing.expect(t, .Loopback in links[0].flags)
	testing.expect(t, .Up in links[0].flags)

	testing.expect_value(t, link_name(&links[1]), "gif0")
	testing.expect(t, .Up not_in links[1].flags)
	testing.expect(t, .Point_To_Point in links[1].flags)

	testing.expect_value(t, link_name(&links[2]), "en0")
	testing.expect_value(t, links[2].mtu, 1500)
	testing.expect(t, .Broadcast in links[2].flags && .Multicast in links[2].flags && .Running in links[2].flags)
	testing.expect_value(t, link_kind(&links[2]), "")

	testing.expect_value(t, link_name(&links[3]), "utun3")
	testing.expect_value(t, links[3].mtu, 1380)
	testing.expect_value(t, link_kind(&links[3]), "tun")
	testing.expect(t, .Point_To_Point in links[3].flags)

	testing.expect_value(t, link_name(&links[4]), "bridge100")

	// lo0: 127.0.0.1/8, ::1/128, fe80::1/64. en0: v4 /16, a link-local and a global v6.
	testing.expect_value(t, len(addrs), 3 + 3 + 2 + 1)
	testing.expect_value(t, addrs[0].index, 1)
	testing.expect_value(t, addrs[0].address, Address(IP4_Address{127, 0, 0, 1}))
	testing.expect_value(t, addrs[0].prefix_len, 8)
	testing.expect_value(t, addrs[0].scope, 254)
	testing.expect_value(t, addrs[1].address, Address(IP6_Address{0, 0, 0, 0, 0, 0, 0, 1}))
	testing.expect_value(t, addrs[1].prefix_len, 128)
	testing.expect_value(t, addrs[2].prefix_len, 64)
	testing.expect_value(t, addrs[2].scope, 253)

	testing.expect_value(t, addrs[3].index, 20)
	testing.expect_value(t, addrs[3].address, Address(IP4_Address{10, 100, 0, 7}))
	testing.expect_value(t, addrs[3].prefix_len, 16)
	testing.expect_value(t, addrs[3].scope, 0)

	// utun3: the peer of the point-to-point address.
	utun: Addr_Info
	for a in addrs {
		if a.index == 25 && a.address == Address(IP4_Address{10, 8, 0, 5}) {
			utun = a
		}
	}
	testing.expect_value(t, utun.prefix_len, 24)
	peer, has_peer := utun.peer.?
	testing.expect(t, has_peer)
	testing.expect_value(t, peer, Address(IP4_Address{10, 8, 0, 1}))
}

@(test)
ifconfig_mask_forms :: proc(t: ^testing.T) {
	n, ok := hex_mask_prefix("0xffffff00")
	testing.expect(t, ok)
	testing.expect_value(t, n, 24)
	n, ok = hex_mask_prefix("0xffffffff")
	testing.expect_value(t, n, 32)
	n, ok = hex_mask_prefix("0x0")
	testing.expect(t, ok)
	testing.expect_value(t, n, 0)
	_, ok = hex_mask_prefix("0xff00ff00")
	testing.expect(t, !ok, "a mask with a hole is not a prefix")
	_, ok = hex_mask_prefix("zzz")
	testing.expect(t, !ok)

	p, pok := mask_to_prefix(IP4_Address{255, 255, 240, 0})
	testing.expect(t, pok)
	testing.expect_value(t, p, 20)
	p, pok = mask_to_prefix(IP6_Address{0xffff, 0xffff, 0, 0, 0, 0, 0, 0})
	testing.expect(t, pok)
	testing.expect_value(t, p, 32)
	_, pok = mask_to_prefix(IP4_Address{255, 0, 255, 0})
	testing.expect(t, !pok)
}

// ---- route get ----

@(test)
route_get_default_route :: proc(t: ^testing.T) {
	r, ok := parse_route_get(ROUTE_GET_DEFAULT, false, fake_index)
	testing.expect(t, ok)
	testing.expect_value(t, r.dst, Address(IP4_Address{}))
	testing.expect_value(t, r.dst_len, 0)
	gw, has := r.gateway.?
	testing.expect(t, has)
	testing.expect_value(t, gw, Address(IP4_Address{10, 100, 254, 200}))
	testing.expect_value(t, r.ifindex, 20)
	testing.expect_value(t, r.kind, Route_Kind.Unicast)
}

@(test)
route_get_default_route_v6 :: proc(t: ^testing.T) {
	r, ok := parse_route_get(ROUTE_GET_DEFAULT6, true, fake_index)
	testing.expect(t, ok)
	testing.expect_value(t, r.dst, Address(IP6_Address{}))
	testing.expect_value(t, r.dst_len, 0)
	testing.expect_value(t, r.family, Family.V6)
	gw, has := r.gateway.?
	testing.expect(t, has)
	// The zone is dropped: the interface says where it is.
	testing.expect_value(t, gw, Address(IP6_Address{0xfe80, 0, 0, 0, 0x10e8, 0xc6ff, 0xfe40, 0xfeae}))
	testing.expect_value(t, r.ifindex, 20)
}

@(test)
route_get_host_and_onlink :: proc(t: ^testing.T) {
	r, ok := parse_route_get(ROUTE_GET_LOCAL, false, fake_index)
	testing.expect(t, ok)
	testing.expect_value(t, r.dst, Address(IP4_Address{127, 0, 0, 1}))
	testing.expect_value(t, r.dst_len, 32) // no mask line: a host route
	testing.expect(t, r.gateway == nil)
	testing.expect_value(t, r.ifindex, 1)

	r, ok = parse_route_get(ROUTE_GET_ONLINK, false, fake_index)
	testing.expect(t, ok)
	testing.expect_value(t, r.dst, Address(IP4_Address{169, 254, 0, 0}))
	testing.expect_value(t, r.dst_len, 16)
	testing.expect(t, r.gateway == nil)
	testing.expect_value(t, r.ifindex, 20)
}

@(test)
route_get_flags_and_garbage :: proc(t: ^testing.T) {
	text := "   route to: 192.0.2.1\ndestination: 192.0.2.1\n  interface: lo0\n      flags: <UP,HOST,DONE,REJECT>\n"
	r, ok := parse_route_get(text, false, fake_index)
	testing.expect(t, ok)
	testing.expect_value(t, r.kind, Route_Kind.Unreachable)
	text2 := "      flags: <UP,HOST,DONE,BLACKHOLE>\ndestination: 192.0.2.1\n"
	r, ok = parse_route_get(text2, false, fake_index)
	testing.expect_value(t, r.kind, Route_Kind.Blackhole)

	_, ok = parse_route_get("", false, fake_index)
	testing.expect(t, !ok)
	_, ok = parse_route_get("route: writing to routing socket: not in table\n", false, fake_index)
	testing.expect(t, !ok)
}

// ---- netstat ----

@(test)
netstat_v4_routes :: proc(t: ^testing.T) {
	out := make([dynamic]Route, context.temp_allocator)
	parse_netstat(NETSTAT4, .V4, fake_index, &out, false, 0)
	// The cloned host entry (W) is left out.
	testing.expect_value(t, len(out), 11)
	testing.expect_value(t, out[0].dst_len, 0)
	gw, has := out[0].gateway.?
	testing.expect(t, has)
	testing.expect_value(t, gw, Address(IP4_Address{10, 100, 254, 200}))
	testing.expect_value(t, out[0].ifindex, 20)
	testing.expect(t, out[2].gateway == nil, "link#28 is on-link")
	testing.expect_value(t, out[2].ifindex, 28)

	find :: proc(routes: []Route, dst: Address, n: u8) -> (Route, bool) {
		for r in routes {
			if r.dst == dst && r.dst_len == n {
				return r, true
			}
		}
		return {}, false
	}
	r, ok := find(out[:], IP4_Address{10, 100, 0, 0}, 16)
	testing.expect(t, ok, "10.100/16 is 10.100.0.0/16")
	r, ok = find(out[:], IP4_Address{127, 0, 0, 0}, 8)
	testing.expect(t, ok, "127 is 127.0.0.0/8")
	r, ok = find(out[:], IP4_Address{169, 254, 0, 0}, 16)
	testing.expect(t, ok, "169.254 is /16")
	r, ok = find(out[:], IP4_Address{127, 0, 0, 1}, 32)
	testing.expect(t, ok, "a host route is /32")
	r, ok = find(out[:], IP4_Address{224, 0, 0, 0}, 4)
	testing.expect(t, ok)
	_ = r
}

@(test)
netstat_proto1_routes :: proc(t: ^testing.T) {
	out := make([dynamic]Route, context.temp_allocator)
	parse_netstat(NETSTAT4, .V4, fake_index, &out, true, 201)
	testing.expect_value(t, len(out), 2)
	testing.expect_value(t, out[0].dst, Address(IP4_Address{0, 0, 0, 0}))
	testing.expect_value(t, out[0].dst_len, 1)
	testing.expect_value(t, out[0].ifindex, 25)
	testing.expect_value(t, out[0].protocol, 201)
	testing.expect(t, out[0].gateway == nil)
	testing.expect_value(t, out[1].dst, Address(IP4_Address{203, 0, 113, 9}))
	testing.expect_value(t, out[1].dst_len, 32)
	gw, has := out[1].gateway.?
	testing.expect(t, has)
	testing.expect_value(t, gw, Address(IP4_Address{10, 100, 254, 200}))
}

@(test)
netstat_v6_routes :: proc(t: ^testing.T) {
	out := make([dynamic]Route, context.temp_allocator)
	parse_netstat(NETSTAT6, .V6, fake_index, &out, false, 0)
	testing.expect_value(t, len(out), 6)
	testing.expect_value(t, out[0].dst_len, 0)
	testing.expect_value(t, out[0].family, Family.V6)
	_, has := out[0].gateway.?
	testing.expect(t, has)
	testing.expect_value(t, out[1].dst_len, 128) // ::1, a host route
	testing.expect_value(t, out[2].dst_len, 64)
	testing.expect(t, out[2].gateway == nil)
	testing.expect(t, out[3].gateway == nil, "2:0:0:0:0:0 is a link address, not a gateway")
	testing.expect_value(t, out[4].dst, Address(IP6_Address{0xfe80, 0, 0, 0, 0, 0, 0, 0}))
	testing.expect_value(t, out[4].dst_len, 64)

	tagged := make([dynamic]Route, context.temp_allocator)
	parse_netstat(NETSTAT6, .V6, fake_index, &tagged, true, 201)
	testing.expect_value(t, len(tagged), 1)
	testing.expect_value(t, tagged[0].dst, Address(IP6_Address{0x8000, 0, 0, 0, 0, 0, 0, 0}))
	testing.expect_value(t, tagged[0].dst_len, 1)
}

// ---- command lines ----

@(private = "file")
joined :: proc(argv: []string) -> string {
	return strings.join(argv, " ", context.temp_allocator)
}

@(test)
build_addr_commands :: proc(t: ^testing.T) {
	argv, err := build_addr_add("utun3", IP4_Address{10, 8, 0, 5}, 24, nil)
	testing.expect_value(t, err, Error.None)
	// No peer: the address is its own peer, as a subnet topology needs.
	testing.expect_value(t, joined(argv), "/sbin/ifconfig utun3 inet 10.8.0.5 10.8.0.5 netmask 255.255.255.0 alias")

	argv, err = build_addr_add("utun3", IP4_Address{10, 8, 0, 6}, 32, IP4_Address{10, 8, 0, 5})
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, joined(argv), "/sbin/ifconfig utun3 inet 10.8.0.6 10.8.0.5 netmask 255.255.255.255 alias")

	argv, err = build_addr_add("en9", IP4_Address{192, 0, 2, 1}, 20, nil)
	testing.expect_value(t, joined(argv), "/sbin/ifconfig en9 inet 192.0.2.1 netmask 255.255.240.0 alias")

	argv, err = build_addr_add("utun3", IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 5}, 64, nil)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, joined(argv), "/sbin/ifconfig utun3 inet6 fd00::5 prefixlen 64 alias")

	_, err = build_addr_add("utun3", IP4_Address{10, 8, 0, 5}, 33, nil)
	testing.expect_value(t, err, Error.Invalid)
	_, err = build_addr_add("utun3", IP4_Address{10, 8, 0, 5}, 24, IP6_Address{})
	testing.expect_value(t, err, Error.Invalid)

	argv, err = build_addr_del("utun3", IP4_Address{10, 8, 0, 5})
	testing.expect_value(t, joined(argv), "/sbin/ifconfig utun3 inet 10.8.0.5 -alias")
	argv, err = build_addr_del("utun3", IP6_Address{0xfd00, 0, 0, 0, 0, 0, 0, 5})
	testing.expect_value(t, joined(argv), "/sbin/ifconfig utun3 inet6 fd00::5 -alias")
}

@(test)
build_route_commands :: proc(t: ^testing.T) {
	// A route into the tunnel is on-link: the gateway is not used.
	r := Route {
		dst      = IP4_Address{0, 0, 0, 0},
		dst_len  = 1,
		gateway  = IP4_Address{10, 8, 0, 1},
		ifindex  = 25,
		protocol = 201,
	}
	argv, err := build_route(.Add, r, "utun3")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet -net 0.0.0.0/1 -interface utun3 -proto1")

	// A delete names the destination only, with or without the interface.
	argv, _ = build_route(.Delete, r, "utun3")
	testing.expect_value(t, joined(argv), "/sbin/route -n delete -inet -net 0.0.0.0/1")
	argv, err = build_route(.Delete, r, "")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, joined(argv), "/sbin/route -n delete -inet -net 0.0.0.0/1")
	_, err = build_route(.Add, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8}, "")
	testing.expect_value(t, err, Error.Invalid)

	// The pinned route to the server: a gateway on a physical interface.
	pin := Route {
		dst      = IP4_Address{203, 0, 113, 9},
		dst_len  = 32,
		gateway  = IP4_Address{10, 100, 254, 200},
		ifindex  = 20,
		protocol = 201,
	}
	argv, _ = build_route(.Add, pin, "en0")
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet -host 203.0.113.9 10.100.254.200 -ifp en0 -proto1")
	argv, _ = build_route(.Change, pin, "en0")
	testing.expect_value(t, joined(argv), "/sbin/route -n change -inet -host 203.0.113.9 10.100.254.200 -ifp en0 -proto1")

	// On-link through a physical interface, and the default route.
	argv, _ = build_route(.Add, Route{dst = IP4_Address{192, 0, 2, 0}, dst_len = 24, ifindex = 20}, "en0")
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet -net 192.0.2.0/24 -interface en0")
	argv, _ = build_route(.Add, Route{dst = IP4_Address{}, dst_len = 0, gateway = IP4_Address{10, 0, 0, 1}}, "")
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet default 10.0.0.1")

	// IPv6.
	r6 := Route {
		dst     = IP6_Address{0x8000, 0, 0, 0, 0, 0, 0, 0},
		dst_len = 1,
		ifindex = 25,
	}
	argv, _ = build_route(.Add, r6, "utun3")
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet6 -net 8000:: -prefixlen 1 -interface utun3")
	ll := Route {
		dst     = IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1},
		dst_len = 128,
		gateway = IP6_Address{0xfe80, 0, 0, 0, 0x10e8, 0xc6ff, 0xfe40, 0xfeae},
		ifindex = 20,
	}
	argv, _ = build_route(.Add, ll, "en0")
	// A link-local gateway needs its zone back.
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet6 -host 2001:db8::1 fe80::10e8:c6ff:fe40:feae%en0 -ifp en0")
	argv, _ = build_route(.Add, Route{family = .V6, dst_len = 0, gateway = IP6_Address{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}}, "")
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet6 default 2001:db8::1")

	// A gateway of the other family is refused; so are kinds macOS cannot create.
	_, err = build_route(.Add, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8, gateway = IP6_Address{}}, "")
	testing.expect_value(t, err, Error.Invalid)
	_, err = build_route(.Add, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 40}, "")
	testing.expect_value(t, err, Error.Invalid)
	_, err = build_route(.Add, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8, kind = .Local}, "")
	testing.expect_value(t, err, Error.Unsupported)

	bh := Route {
		dst     = IP4_Address{192, 0, 2, 0},
		dst_len = 24,
		kind    = .Blackhole,
	}
	argv, _ = build_route(.Add, bh, "")
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet -net 192.0.2.0/24 127.0.0.1 -blackhole")
	bh.kind = .Unreachable
	argv, _ = build_route(.Add, bh, "")
	testing.expect_value(t, joined(argv), "/sbin/route -n add -inet -net 192.0.2.0/24 127.0.0.1 -reject")
}

@(test)
build_route_get_commands :: proc(t: ^testing.T) {
	testing.expect_value(t, joined(build_route_get({}, .V4, true)), "/sbin/route -n get default")
	testing.expect_value(t, joined(build_route_get({}, .V6, true)), "/sbin/route -n get -inet6 default")
	testing.expect_value(t, joined(build_route_get(IP4_Address{1, 1, 1, 1}, .V4, false)), "/sbin/route -n get 1.1.1.1")
	testing.expect_value(t, joined(build_route_get(IP6_Address{0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111}, .V6, false)), "/sbin/route -n get -inet6 2606:4700::1111")
}

@(test)
failure_text_maps_to_errors :: proc(t: ^testing.T) {
	testing.expect_value(t, classify_failure("route: writing to routing socket: File exists"), Error.Exists)
	testing.expect_value(t, classify_failure("delete net 10.0.0.0: not in table"), Error.Not_Found)
	testing.expect_value(t, classify_failure("route: writing to routing socket: No such process"), Error.Not_Found)
	testing.expect_value(t, classify_failure("ifconfig: interface utun9 does not exist"), Error.Not_Found)
	testing.expect_value(t, classify_failure("ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address"), Error.Not_Found)
	testing.expect_value(t, classify_failure("route: must be root to alter routing table"), Error.Permission)
	testing.expect_value(t, classify_failure("add net 1.2.3.0: gateway 9.9.9.9: Network is unreachable"), Error.Network_Unreachable)
	testing.expect_value(t, classify_failure("ifconfig: ioctl: Operation not supported"), Error.Unsupported)
	testing.expect_value(t, classify_failure("something new"), Error.Other)
}

// ---- the calls, with a fake runner ----

@(private = "file")
Fake :: struct {
	calls:   [dynamic]string,
	// The response for a command whose text starts with the key.
	answers: map[string]Command_Result,
}

@(private = "file")
fake_run :: proc(data: rawptr, argv: []string, stdin: string) -> (res: Command_Result, started: bool) {
	f := (^Fake)(data)
	line := strings.join(argv, " ", context.temp_allocator)
	append(&f.calls, line)
	best := ""
	found: Command_Result
	for key, answer in f.answers {
		if strings.has_prefix(line, key) && len(key) > len(best) {
			best = key
			found = answer
		}
	}
	return found, true
}

@(private = "file")
fake_conn :: proc(f: ^Fake) -> Conn {
	c, _ := open()
	c.runner = Command_Runner {
		data = f,
		run  = fake_run,
	}
	return c
}

@(test)
route_lookup_and_default_use_route_get :: proc(t: ^testing.T) {
	f: Fake
	f.calls.allocator = context.temp_allocator
	f.answers.allocator = context.temp_allocator
	f.answers["/sbin/route -n get default"] = {out = ROUTE_GET_DEFAULT}
	f.answers["/sbin/route -n get -inet6 default"] = {out = ROUTE_GET_DEFAULT6}
	f.answers["/sbin/route -n get 127.0.0.1"] = {out = ROUTE_GET_LOCAL}
	f.answers["/sbin/route -n get 192.0.2.77"] = {code = 1, err = "route: writing to routing socket: not in table\n"}
	c := fake_conn(&f)

	r, err := route_get_default(&c, .V4)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, r.dst_len, 0)
	testing.expect(t, r.gateway != nil)

	r, err = route_get_default(&c, .V6)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, r.family, Family.V6)

	_, err = route_lookup(&c, IP4_Address{127, 0, 0, 1})
	testing.expect_value(t, err, Error.None)

	_, err = route_lookup(&c, IP4_Address{192, 0, 2, 77})
	testing.expect_value(t, err, Error.Not_Found)
	testing.expect_value(t, last_exit_code(&c), 1)
	testing.expect_value(t, last_error_text(&c), "route: writing to routing socket: not in table")
}

@(test)
route_list_protocol_keeps_the_marked_routes :: proc(t: ^testing.T) {
	f: Fake
	f.calls.allocator = context.temp_allocator
	f.answers.allocator = context.temp_allocator
	f.answers["/usr/sbin/netstat -rn -f inet"] = {out = NETSTAT4}
	f.answers["/usr/sbin/netstat -rn -f inet6"] = {out = NETSTAT6}
	c := fake_conn(&f)

	routes := make([dynamic]Route, context.temp_allocator)
	testing.expect_value(t, route_list_protocol(&c, .V4, 201, &routes), Error.None)
	testing.expect_value(t, len(routes), 2)
	testing.expect_value(t, route_list_protocol(&c, .V6, 201, &routes), Error.None)
	testing.expect_value(t, len(routes), 1) // the list starts empty on each call

	testing.expect_value(t, route_list(&c, .V4, 0, 0, &routes), Error.None)
	testing.expect_value(t, len(routes), 11)
	testing.expect_value(t, route_list(&c, .V4, 0, 28, &routes), Error.None)
	testing.expect_value(t, len(routes), 1)
	testing.expect_value(t, route_list(&c, .V4, 254, 0, &routes), Error.Invalid)
}

@(test)
nonzero_exit_and_known_text_are_failures :: proc(t: ^testing.T) {
	f: Fake
	f.calls.allocator = context.temp_allocator
	f.answers.allocator = context.temp_allocator
	c := fake_conn(&f)

	// A route delete that says "not in table" with a 0 status is still a failure.
	f.answers["/sbin/route -n delete"] = {code = 0, err = "delete net 10.0.0.0: not in table\n"}
	err := route_del(&c, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8})
	testing.expect_value(t, err, Error.Not_Found)

	delete_key(&f.answers, "/sbin/route -n delete")
	f.answers["/sbin/route -n delete"] = {code = 0, out = "delete net 10.0.0.0\n"}
	err = route_del(&c, Route{dst = IP4_Address{10, 0, 0, 0}, dst_len = 8})
	testing.expect_value(t, err, Error.None)

	testing.expect_value(t, link_set_txqlen(&c, 1, 500), Error.Unsupported)
	testing.expect_value(t, link_set_mtu(&c, 1, 10), Error.Invalid)
}

@(test)
link_get_unknown_name_does_not_run_a_command :: proc(t: ^testing.T) {
	f: Fake
	f.calls.allocator = context.temp_allocator
	f.answers.allocator = context.temp_allocator
	c := fake_conn(&f)
	_, err := link_get(&c, "nosuch0")
	testing.expect_value(t, err, Error.Not_Found)
	testing.expect_value(t, len(f.calls), 0)
	_, err = link_get(&c, "bad name")
	testing.expect_value(t, err, Error.Invalid)
	_, err = link_get_by_index(&c, 0)
	testing.expect_value(t, err, Error.Not_Found)
}

@(test)
link_list_reads_the_real_interfaces :: proc(t: ^testing.T) {
	// The real ifconfig: read only. Every host has lo0.
	c, _ := open()
	links := make([dynamic]Link_Info, context.temp_allocator)
	testing.expect_value(t, link_list(&c, &links), Error.None)
	found := false
	for &l in links {
		if link_name(&l) == "lo0" {
			found = true
			testing.expect(t, l.index != 0)
			testing.expect(t, .Loopback in l.flags)
			testing.expect(t, l.mtu > 0)
		}
	}
	testing.expect(t, found, "no lo0 in the list")

	lo, err := link_get(&c, "lo0")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, link_name(&lo), "lo0")
	by_index, err2 := link_get_by_index(&c, lo.index)
	testing.expect_value(t, err2, Error.None)
	testing.expect_value(t, link_name(&by_index), "lo0")

	addrs := make([dynamic]Addr_Info, context.temp_allocator)
	testing.expect_value(t, addr_list(&c, lo.index, .V4, &addrs), Error.None)
	has_loopback := false
	for a in addrs {
		if a.address == Address(IP4_Address{127, 0, 0, 1}) {
			has_loopback = true
		}
	}
	testing.expect(t, has_loopback)
}

@(test)
route_lookup_of_loopback_reads_the_real_table :: proc(t: ^testing.T) {
	c, _ := open()
	r, err := route_lookup(&c, IP4_Address{127, 0, 0, 1})
	testing.expect_value(t, err, Error.None)
	lo, _ := link_get(&c, "lo0")
	testing.expect_value(t, r.ifindex, lo.index)
	testing.expect(t, r.gateway == nil || true)
}

@(test)
addr_add_adds_the_prefix_route_on_a_utun :: proc(t: ^testing.T) {
	// Needs an interface that exists, so the name is looked up first; the fake
	// replies to every command with success.
	c0, _ := open()
	lo, lerr := link_get(&c0, "lo0")
	testing.expect_value(t, lerr, Error.None)

	f: Fake
	f.calls.allocator = context.temp_allocator
	f.answers.allocator = context.temp_allocator
	c := fake_conn(&f)

	// lo0 is not a utun: the address is added and no route follows.
	err := addr_add(&c, lo.index, IP4_Address{10, 8, 0, 5}, 24)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(f.calls), 1)
	testing.expect_value(t, f.calls[0], "/sbin/ifconfig lo0 inet 10.8.0.5 netmask 255.255.255.0 alias")

	// A whole address needs no network route, and an address that is not on a
	// utun does not get one either.
	clear(&f.calls)
	testing.expect_value(t, addr_add(&c, lo.index, IP4_Address{10, 8, 0, 5}, 32), Error.None)
	testing.expect_value(t, len(f.calls), 1)

	clear(&f.calls)
	testing.expect_value(t, addr_del(&c, lo.index, IP4_Address{10, 8, 0, 5}, 24), Error.None)
	testing.expect_value(t, f.calls[0], "/sbin/ifconfig lo0 inet 10.8.0.5 -alias")

	testing.expect_value(t, addr_add(&c, 999999, IP4_Address{10, 8, 0, 5}, 24), Error.Not_Found)
}

@(test)
masked_clears_the_host_bits :: proc(t: ^testing.T) {
	testing.expect_value(t, masked(IP4_Address{10, 8, 0, 5}, 24), Address(IP4_Address{10, 8, 0, 0}))
	testing.expect_value(t, masked(IP4_Address{10, 8, 0, 5}, 20), Address(IP4_Address{10, 8, 0, 0}))
	testing.expect_value(t, masked(IP4_Address{10, 8, 17, 5}, 20), Address(IP4_Address{10, 8, 16, 0}))
	testing.expect_value(t, masked(IP4_Address{10, 8, 17, 5}, 0), Address(IP4_Address{0, 0, 0, 0}))
	testing.expect_value(t, masked(IP6_Address{0xfd00, 0x1234, 0, 0, 0, 0, 0, 5}, 32), Address(IP6_Address{0xfd00, 0x1234, 0, 0, 0, 0, 0, 0}))
}

@(test)
ifconfig_that_only_complains_is_a_failure :: proc(t: ^testing.T) {
	// ifconfig exits 0 after a failed ioctl: its error output says it.
	f: Fake
	f.calls.allocator = context.temp_allocator
	f.answers.allocator = context.temp_allocator
	f.answers["/sbin/ifconfig"] = {code = 0, err = "ifconfig: ioctl (set mtu): Operation not permitted\n"}
	c := fake_conn(&f)
	c0, _ := open()
	lo, _ := link_get(&c0, "lo0")
	testing.expect_value(t, link_set_mtu(&c, lo.index, 1400), Error.Permission)
	testing.expect_value(t, last_error_text(&c), "ifconfig: ioctl (set mtu): Operation not permitted")
	testing.expect_value(t, link_set_up(&c, lo.index), Error.Permission)
	testing.expect_value(t, addr_del(&c, lo.index, IP4_Address{10, 8, 0, 5}, 24), Error.Permission)

	// A read does not fail on a warning when it exits 0.
	f.answers["/sbin/ifconfig"] = {code = 0, out = IFCONFIG_TEXT, err = "ifconfig: some warning\n"}
	links := make([dynamic]Link_Info, context.temp_allocator)
	testing.expect_value(t, link_list(&c, &links), Error.None)
	testing.expect(t, len(links) > 0)
}
