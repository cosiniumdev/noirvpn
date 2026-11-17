// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package sysnet

import "core:log"
import "core:slice"
import "core:testing"
import win "core:sys/windows"
import "core:time"
import net "noir:platform/net"
import "noir:platform/tun"

// The sizes and offsets that a C program prints for the Windows SDK
// structures.
@(test)
struct_layouts_match_the_sdk :: proc(t: ^testing.T) {
	testing.expect_value(t, size_of(SOCKADDR_INET), 28)
	testing.expect_value(t, size_of(IP_ADDRESS_PREFIX), 32)

	testing.expect_value(t, size_of(MIB_IPFORWARD_ROW2), 104)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, index), 8)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, destination), 12)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, next_hop), 44)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, site_prefix_len), 72)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, metric), 84)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, protocol), 88)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, loopback), 92)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, immortal), 95)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, age), 96)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_ROW2, origin), 100)
	testing.expect_value(t, offset_of(MIB_IPFORWARD_TABLE2, table), 8)

	testing.expect_value(t, size_of(MIB_UNICASTIPADDRESS_ROW), 80)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, luid), 32)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, index), 40)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, prefix_origin), 44)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, valid_lifetime), 52)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, on_link_prefix_len), 60)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, skip_as_source), 61)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, dad_state), 64)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, scope_id), 68)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_ROW, creation_time), 72)
	testing.expect_value(t, offset_of(MIB_UNICASTIPADDRESS_TABLE, table), 8)

	testing.expect_value(t, size_of(MIB_IPINTERFACE_ROW), 168)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, luid), 8)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, index), 16)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, interface_identifier), 24)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, advertising_enabled), 40)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, use_automatic_metric), 44)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, router_discovery_behavior), 52)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, link_local_address_behavior), 72)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, zone_indices), 80)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, site_prefix_len), 144)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, metric), 148)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, nl_mtu), 152)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, connected), 156)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, reachable_time), 160)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, transmit_offload), 164)
	testing.expect_value(t, offset_of(MIB_IPINTERFACE_ROW, disable_default_routes), 166)

	testing.expect_value(t, size_of(DNS_INTERFACE_SETTINGS), 64)
	testing.expect_value(t, offset_of(DNS_INTERFACE_SETTINGS, flags), 8)
	testing.expect_value(t, offset_of(DNS_INTERFACE_SETTINGS, domain), 16)
	testing.expect_value(t, offset_of(DNS_INTERFACE_SETTINGS, name_server), 24)
	testing.expect_value(t, offset_of(DNS_INTERFACE_SETTINGS, search_list), 32)
	testing.expect_value(t, offset_of(DNS_INTERFACE_SETTINGS, registration_enabled), 40)
	testing.expect_value(t, offset_of(DNS_INTERFACE_SETTINGS, profile_name_server), 56)
}

@(test)
lookups_on_the_running_system :: proc(t: ^testing.T) {
	c, _ := open()
	defer close(&c)

	links := make([dynamic]Link_Info)
	defer delete(links)
	testing.expect_value(t, link_list(&c, &links), Error.None)
	loop_index := u32(0)
	for &l in links {
		if .Loopback in l.flags {
			loop_index = l.index
			by_name, err := link_get(&c, link_name(&l))
			testing.expect_value(t, err, Error.None)
			testing.expect_value(t, by_name.index, l.index)
			testing.expect_value(t, by_name.luid, l.luid)
		}
	}
	testing.expect(t, loop_index != 0, "no loopback interface in the list")
	_, err := link_get(&c, "no such interface here")
	testing.expect_value(t, err, Error.Not_Found)
	_, err = link_get_by_index(&c, 0xfffffff0)
	testing.expect_value(t, err, Error.Not_Found)
	testing.expect(t, len(last_error_text(&c)) > 0, "no error text")

	def, derr := route_get_default(&c, .V4)
	testing.expect_value(t, derr, Error.None)
	if derr != .None {
		return
	}
	testing.expect(t, def.gateway != nil, "the default route has no gateway")
	testing.expect_value(t, def.dst_len, 0)

	r, lerr := route_lookup(&c, IP4_Address{192, 0, 2, 1})
	testing.expect_value(t, lerr, Error.None)
	testing.expect_value(t, r.ifindex, def.ifindex)
	testing.expect_value(t, r.kind, Route_Kind.Unicast)
	src, has_src := r.prefsrc.?
	testing.expect(t, has_src, "no preferred source")
	if has_src {
		own, oerr := route_lookup(&c, src)
		testing.expect_value(t, oerr, Error.None)
		testing.expect_value(t, own.kind, Route_Kind.Local)
	}
	lo, loerr := route_lookup(&c, IP4_Address{127, 0, 0, 1})
	testing.expect_value(t, loerr, Error.None)
	testing.expect_value(t, lo.kind, Route_Kind.Local)

	addrs := make([dynamic]Addr_Info)
	defer delete(addrs)
	testing.expect_value(t, addr_list(&c, def.ifindex, Family.V4, &addrs), Error.None)
	testing.expect(t, slice.any_of_proc(addrs[:], proc(a: Addr_Info) -> bool {
		_, v4 := a.address.(IP4_Address)
		return v4
	}), "the default interface has no IPv4 address")
}

@(test)
bad_routes_are_refused :: proc(t: ^testing.T) {
	c, _ := open()
	defer close(&c)
	testing.expect_value(t, route_add(&c, {dst = IP4_Address{198, 18, 0, 0}, dst_len = 16, kind = .Blackhole, ifindex = 1}), Error.Unsupported)
	testing.expect_value(t, route_add(&c, {dst = IP4_Address{198, 18, 0, 0}, dst_len = 16, table = 100, ifindex = 1}), Error.Unsupported)
	testing.expect_value(t, route_add(&c, {dst = IP4_Address{198, 18, 0, 0}, dst_len = 33, ifindex = 1}), Error.Invalid)
	testing.expect_value(t, route_add(&c, {dst = IP4_Address{198, 18, 0, 0}, dst_len = 16}), Error.Invalid)
	testing.expect_value(t, route_add(&c, {dst = IP4_Address{198, 18, 0, 0}, dst_len = 16, gateway = IP6_Address{0xfe80, 0, 0, 0, 0, 0, 0, 1}, ifindex = 1}), Error.Invalid)
	testing.expect_value(t, addr_add(&c, 1, IP4_Address{198, 18, 0, 1}, 40), Error.Invalid)
}

TEST_IF :: "noirtest-sys"
TEST_PROTOCOL :: 201

@(private = "file")
adapter_or_skip :: proc(t: ^testing.T, name := TEST_IF) -> (dev: tun.Device, ok: bool) {
	err: tun.Error
	dev, err = tun.open({name = name})
	#partial switch err {
	case .None:
		return dev, true
	case .No_Device, .Permission:
		log.infof("skipped: no wintun.dll or no administrator token (%v)", err)
		return dev, false
	}
	testing.expect_value(t, err, tun.Error.None)
	return dev, false
}

@(test)
adapter_link_addresses_and_routes :: proc(t: ^testing.T) {
	dev, ok := adapter_or_skip(t)
	if !ok {
		return
	}
	defer tun.close(&dev)
	c, _ := open()
	defer close(&c)

	l, err := link_get(&c, TEST_IF)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, l.index, dev.ifindex)
	testing.expect_value(t, l.luid, dev.luid)
	testing.expect_value(t, link_name(&l), TEST_IF)
	testing.expect(t, .Up in l.flags, "the adapter is not connected")
	idx := l.index

	testing.expect_value(t, link_set_up(&c, idx), Error.None)
	testing.expect_value(t, link_set_mtu(&c, idx, 1400), Error.None)
	l, _ = link_get_by_index(&c, idx)
	testing.expect_value(t, l.mtu, 1400)
	testing.expect_value(t, link_set_metric(&c, idx, 3), Error.None)
	m, merr := link_get_metric(&c, idx, .V4)
	testing.expect_value(t, merr, Error.None)
	testing.expect_value(t, m, 3)

	a4 := IP4_Address{198, 18, 99, 1}
	testing.expect_value(t, addr_add(&c, idx, a4, 24), Error.None)
	defer addr_del(&c, idx, a4, 24)
	testing.expect_value(t, addr_add(&c, idx, a4, 24), Error.Exists)
	a6 := IP6_Address{0xfd00, 0x99, 0, 0, 0, 0, 0, 1}
	e6 := addr_add(&c, idx, a6, 64)
	testing.expect(t, e6 == .None || e6 == .Unsupported, "IPv6 address")
	if e6 == .None {
		defer addr_del(&c, idx, a6, 64)
	}

	addrs := make([dynamic]Addr_Info)
	defer delete(addrs)
	testing.expect_value(t, addr_list(&c, idx, nil, &addrs), Error.None)
	have4 := false
	for a in addrs {
		if a.address == Address(a4) {
			have4 = true
			testing.expect_value(t, a.prefix_len, 24)
		}
	}
	testing.expect(t, have4, "the address is not in the list")

	r := Route {
		dst      = IP4_Address{198, 18, 100, 0},
		dst_len  = 24,
		gateway  = IP4_Address{198, 18, 99, 2},
		ifindex  = idx,
		metric   = 7,
		protocol = TEST_PROTOCOL,
	}
	testing.expect_value(t, route_add(&c, r), Error.None)
	testing.expect_value(t, route_add(&c, r), Error.Exists)
	testing.expect_value(t, route_add(&c, r, replace = true), Error.None)

	// An on-link route and one without an interface (taken from the gateway).
	onlink := Route{dst = IP4_Address{198, 18, 101, 0}, dst_len = 24, ifindex = idx, protocol = TEST_PROTOCOL}
	testing.expect_value(t, route_add(&c, onlink), Error.None)
	via := Route{dst = IP4_Address{198, 18, 102, 0}, dst_len = 24, gateway = IP4_Address{198, 18, 99, 3}, protocol = TEST_PROTOCOL}
	testing.expect_value(t, route_add(&c, via), Error.None)

	ours := make([dynamic]Route)
	defer delete(ours)
	testing.expect_value(t, route_list_protocol(&c, .V4, TEST_PROTOCOL, &ours), Error.None)
	testing.expect_value(t, len(ours), 3)
	for o in ours {
		testing.expect_value(t, o.ifindex, idx)
		testing.expect_value(t, o.table, MAIN_TABLE)
	}

	all := make([dynamic]Route)
	defer delete(all)
	testing.expect_value(t, route_list(&c, .V4, 0, idx, &all), Error.None)
	testing.expect(t, len(all) >= 3, "the routes of the adapter are missing")

	got, lerr := route_lookup(&c, IP4_Address{198, 18, 100, 9})
	testing.expect_value(t, lerr, Error.None)
	testing.expect_value(t, got.ifindex, idx)
	testing.expect_value(t, got.gateway, Maybe(Address)(IP4_Address{198, 18, 99, 2}))
	testing.expect_value(t, got.dst_len, 24)

	for o in ours {
		testing.expect_value(t, route_del(&c, o), Error.None)
	}
	testing.expect_value(t, route_del(&c, r), Error.Not_Found)
	clear(&ours)
	testing.expect_value(t, route_list_protocol(&c, .V4, TEST_PROTOCOL, &ours), Error.None)
	testing.expect_value(t, len(ours), 0)

	testing.expect_value(t, addr_del(&c, idx, a4, 24), Error.None)
	testing.expect_value(t, addr_del(&c, idx, a4, 24), Error.Not_Found)
}

@(private = "file")
interface_name_servers :: proc(guid: win.GUID, v6: bool) -> string {
	path := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
	if v6 {
		path = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`
	}
	gbuf: [64]u16
	guid := guid
	n := win.StringFromGUID2(&guid, cstring16(raw_data(gbuf[:])), len(gbuf))
	key := make([dynamic]u16, context.temp_allocator)
	append(&key, ..win.utf8_to_utf16(path, context.temp_allocator))
	append(&key, ..gbuf[:n])
	vbuf: [256]u16
	size := u32(size_of(vbuf))
	if win.RegGetValueW(win.HKEY_LOCAL_MACHINE, cstring16(raw_data(key[:])), win.L("NameServer"), win.RRF_RT_REG_SZ, nil, raw_data(vbuf[:]), &size) != 0 {
		return "<none>"
	}
	k := 0
	for k < len(vbuf) && vbuf[k] != 0 {
		k += 1
	}
	s, _ := win.utf16_to_utf8(vbuf[:k], context.temp_allocator)
	return s
}

@(private = "file")
has_rule :: proc(env: DNS_Env, name: string) -> bool {
	rules := dns_nrpt_rules(env, context.temp_allocator)
	for r in rules {
		if r == name {
			return true
		}
	}
	return false
}

@(test)
adapter_dns_and_nrpt :: proc(t: ^testing.T) {
	dev, ok := adapter_or_skip(t)
	if !ok {
		return
	}
	defer tun.close(&dev)
	env := dns_env_default()
	rule := NRPT_PREFIX + TEST_IF
	// Whatever happens, no rule of this test stays behind: a "." rule to a
	// server that does not exist would stop name resolution on this machine.
	defer {
		_ = nrpt_delete(env, TEST_IF)
		notify_dns_client(nil)
	}
	testing.expect_value(t, dns_detect(env), DNS_Backend.Ip_Helper)
	guid, gerr := interface_guid(TEST_IF)
	testing.expect_value(t, gerr, DNS_Error.None)

	servers := []DNS_Server{{address = IP4_Address{198, 18, 99, 53}}, {address = IP4_Address{198, 18, 99, 54}, port = 853}}
	search := []string{"noir.test"}
	routing := []string{"corp.noir.test"}

	// Split DNS: the servers go to the NRPT rule only.
	d: DNS
	err := dns_apply(&d, env, TEST_IF, {servers = servers, search_domains = search, routing_domains = routing}, context.temp_allocator)
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, len(d.warnings) >= 1, "no warning for the server with a port")
	for w in d.warnings {
		log.infof("warning: %s", w)
	}
	testing.expect(t, has_rule(env, rule), "no NRPT rule")
	testing.expect_value(t, interface_name_servers(guid, false), "")
	testing.expect_value(t, dns_revert(&d), DNS_Error.None)
	testing.expect(t, !has_rule(env, rule), "the NRPT rule stayed")
	dns_destroy(&d)

	// Everything through the tunnel: interface servers and a "." rule.
	err = dns_apply(&d, env, TEST_IF, {servers = servers[:1], search_domains = search, default_route = true}, context.temp_allocator)
	testing.expect_value(t, err, DNS_Error.None)
	testing.expect(t, has_rule(env, rule), "no NRPT rule")
	testing.expect_value(t, interface_name_servers(guid, false), "198.18.99.53")
	testing.expect_value(t, dns_revert(&d), DNS_Error.None)
	testing.expect(t, !has_rule(env, rule), "the NRPT rule stayed")
	testing.expect_value(t, interface_name_servers(guid, false), "")
	dns_destroy(&d)
	testing.expect_value(t, dns_revert(&d), DNS_Error.Not_Applied)

	// What a crash leaves is found again.
	testing.expect_value(t, nrpt_write(env, TEST_IF, {"."}, "198.18.99.53"), DNS_Error.None)
	restored, cerr := dns_cleanup_stale(env, TEST_IF)
	testing.expect_value(t, cerr, DNS_Error.None)
	testing.expect(t, restored, "nothing was cleaned up")
	testing.expect(t, !has_rule(env, rule), "the NRPT rule stayed")

	testing.expect_value(t, dns_apply(&d, env, "bad name", {servers = servers}), DNS_Error.Invalid)
	testing.expect_value(t, dns_apply(&d, env, "noirtest-none", {servers = servers}), DNS_Error.Invalid)
}

@(private = "file")
ip_checksum :: proc(b: []u8) -> u16 {
	sum: u32
	for i := 0; i + 1 < len(b); i += 2 {
		sum += u32(b[i]) << 8 | u32(b[i + 1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ~u16(sum)
}

// An IPv4 UDP packet with no UDP checksum.
@(private = "file")
udp4_packet :: proc(buf: []u8, src, dst: [4]u8, sport, dport: u16, payload: []u8) -> []u8 {
	n := 28 + len(payload)
	p := buf[:n]
	for &b in p {
		b = 0
	}
	src, dst := src, dst
	p[0] = 0x45
	p[2] = u8(n >> 8)
	p[3] = u8(n)
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	c := ip_checksum(p[:20])
	p[10] = u8(c >> 8)
	p[11] = u8(c)
	p[20] = u8(sport >> 8)
	p[21] = u8(sport)
	p[22] = u8(dport >> 8)
	p[23] = u8(dport)
	ulen := 8 + len(payload)
	p[24] = u8(ulen >> 8)
	p[25] = u8(ulen)
	copy(p[28:], payload)
	return p
}

@(test)
tun_adapter_passes_packets_both_ways :: proc(t: ^testing.T) {
	dev, ok := adapter_or_skip(t, "noirtest-tun")
	if !ok {
		return
	}
	defer tun.close(&dev)
	testing.expect(t, dev.read_event != nil, "no read event")

	sys, _ := open()
	defer close(&sys)
	local := IP4_Address{198, 18, 98, 1}
	aerr := addr_add(&sys, dev.ifindex, local, 24)
	testing.expect_value(t, aerr, Error.None)
	if aerr != .None {
		return
	}
	defer addr_del(&sys, dev.ifindex, local, 24)

	// Out: a datagram from this machine to 198.18.98.2 leaves through the
	// adapter.
	sock, serr := net.udp_open(.V4)
	testing.expect_value(t, serr, net.Error.None)
	if serr != .None {
		return
	}
	defer net.close(sock)
	testing.expect_value(t, net.bind(sock, net.Endpoint{address = net.IP4_Address{198, 18, 98, 1}, port = 0}), net.Error.None)
	bound, _ := net.local_endpoint(sock)
	port := u16(bound.port)
	msg := "noirvpn tun test"
	peer := net.Endpoint{address = net.IP4_Address{198, 18, 98, 2}, port = 4000}
	found := false
	buf: [2048]u8
	deadline := time.tick_now()
	for !found && time.tick_since(deadline) < 5 * time.Second {
		_ = net.send_to(sock, transmute([]u8)msg, peer)
		win.WaitForSingleObject(dev.read_event, 200)
		for {
			n, rerr := tun.read(&dev, buf[:])
			if rerr == .Would_Block {
				break
			}
			testing.expect_value(t, rerr, tun.Error.None)
			if rerr != .None {
				return
			}
			p := buf[:n]
			if n == 28 + len(msg) && p[0] == 0x45 && p[9] == 17 && p[19] == 2 && string(p[28:]) == msg {
				found = true
			}
		}
	}
	testing.expect(t, found, "the datagram did not come out of the adapter")

	// In: a datagram written to the adapter reaches the socket.
	reply := "reply from the tunnel"
	pkt := udp4_packet(buf[:], {198, 18, 98, 2}, {198, 18, 98, 1}, 4000, port, transmute([]u8)reply)
	got := false
	in_deadline := time.tick_now()
	for !got && time.tick_since(in_deadline) < 3 * time.Second {
		testing.expect_value(t, tun.write(&dev, pkt), tun.Error.None)
		time.sleep(50 * time.Millisecond)
		rbuf: [256]u8
		n, from, rerr := net.recv_from(sock, rbuf[:])
		if rerr == .None {
			testing.expect_value(t, string(rbuf[:n]), reply)
			testing.expect_value(t, from.port, 4000)
			got = true
		}
	}
	testing.expect(t, got, "the written datagram did not reach the socket")
}
