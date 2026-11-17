// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package dco

import "core:testing"
import "noir:platform/netlink"

// Pure tests of the messages for the kernel `ovpn` family. The family number is
// invented; the attribute numbers are those of <linux/ovpn.h>.

FAM :: u16(0x1c)

// The generic payload of a request: after the generic header.
@(private = "file")
bytes_eq :: proc(a, b: []u8) -> bool {
	return string(a) == string(b)
}

@(private = "file")
payload_of :: proc(t: ^testing.T, msg: []u8) -> (cmd: u8, attrs: []u8) {
	it := netlink.msg_iter(msg)
	m, ok := netlink.msg_next(&it)
	testing.expect(t, ok)
	testing.expect_value(t, m.hdr.type, FAM)
	gh, rest, gok := netlink.read_struct(m.payload, netlink.Genlmsghdr)
	testing.expect(t, gok)
	testing.expect_value(t, gh.version, u8(OVPN_VERSION))
	return gh.cmd, rest
}

@(test)
peer_new_udp_p2p :: proc(t: ^testing.T) {
	buf: [512]u8
	a := Peer_New_Args {
		id     = 5,
		sock   = 9,
		remote = endpoint_v4({10, 80, 80, 2}, 11940),
		local  = endpoint_v4({10, 80, 80, 1}, 11940),
		vpn4   = [4]u8{10, 209, 0, 2}, // a P2P device must not get it
	}
	msg, err := build_peer_new(buf[:], FAM, 7, 3, a)
	testing.expect_value(t, err, netlink.Error.None)
	cmd, attrs := payload_of(t, msg)
	testing.expect_value(t, cmd, u8(OVPN_CMD_PEER_NEW))
	ifx, _ := netlink.attr_find(attrs, OVPN_A_IFINDEX)
	v, _ := netlink.attr_u32(ifx)
	testing.expect_value(t, v, u32(3))
	peer, found := netlink.attr_find(attrs, OVPN_A_PEER)
	testing.expect(t, found)
	testing.expect(t, peer.nested)
	id, _ := netlink.attr_find(peer.data, OVPN_A_PEER_ID)
	v, _ = netlink.attr_u32(id)
	testing.expect_value(t, v, u32(5))
	sock, _ := netlink.attr_find(peer.data, OVPN_A_PEER_SOCKET)
	v, _ = netlink.attr_u32(sock)
	testing.expect_value(t, v, u32(9))
	r4, _ := netlink.attr_find(peer.data, OVPN_A_PEER_REMOTE_IPV4)
	testing.expect(t, bytes_eq(r4.data, []u8{10, 80, 80, 2}))
	port, _ := netlink.attr_find(peer.data, OVPN_A_PEER_REMOTE_PORT)
	pv, pok := netlink.attr_u16_be(port)
	testing.expect(t, pok)
	testing.expect_value(t, pv, u16(11940))
	l4, lfound := netlink.attr_find(peer.data, OVPN_A_PEER_LOCAL_IPV4)
	testing.expect(t, lfound)
	testing.expect(t, bytes_eq(l4.data, []u8{10, 80, 80, 1}))
	_, vfound := netlink.attr_find(peer.data, OVPN_A_PEER_VPN_IPV4)
	testing.expect(t, !vfound)
}

@(test)
peer_new_udp_mp_v6 :: proc(t: ^testing.T) {
	buf: [512]u8
	r := Endpoint {
		family = AF_INET6,
		port   = 1194,
	}
	r.addr[0] = 0xfd
	r.addr[15] = 2
	a := Peer_New_Args {
		id     = 1,
		sock   = 4,
		mp     = true,
		remote = r,
		local  = endpoint_v4({1, 2, 3, 4}, 0), // another family: left out
		vpn4   = [4]u8{10, 209, 0, 2},
		vpn6   = [16]u8{0 = 0xfd, 1 = 0x89, 15 = 2},
	}
	msg, err := build_peer_new(buf[:], FAM, 1, 2, a)
	testing.expect_value(t, err, netlink.Error.None)
	_, attrs := payload_of(t, msg)
	peer, _ := netlink.attr_find(attrs, OVPN_A_PEER)
	r6, ok6 := netlink.attr_find(peer.data, OVPN_A_PEER_REMOTE_IPV6)
	testing.expect(t, ok6)
	testing.expect_value(t, len(r6.data), 16)
	_, has4 := netlink.attr_find(peer.data, OVPN_A_PEER_REMOTE_IPV4)
	testing.expect(t, !has4)
	_, hasl := netlink.attr_find(peer.data, OVPN_A_PEER_LOCAL_IPV4)
	testing.expect(t, !hasl)
	_, hasl6 := netlink.attr_find(peer.data, OVPN_A_PEER_LOCAL_IPV6)
	testing.expect(t, !hasl6)
	v4, ok4 := netlink.attr_find(peer.data, OVPN_A_PEER_VPN_IPV4)
	testing.expect(t, ok4)
	testing.expect(t, bytes_eq(v4.data, []u8{10, 209, 0, 2}))
	_, hasv6 := netlink.attr_find(peer.data, OVPN_A_PEER_VPN_IPV6)
	testing.expect(t, hasv6)
}

@(test)
peer_new_tcp_has_no_address :: proc(t: ^testing.T) {
	buf: [512]u8
	a := Peer_New_Args {
		id     = 8,
		sock   = 11,
		tcp    = true,
		remote = endpoint_v4({1, 2, 3, 4}, 5),
	}
	msg, err := build_peer_new(buf[:], FAM, 1, 2, a)
	testing.expect_value(t, err, netlink.Error.None)
	_, attrs := payload_of(t, msg)
	peer, _ := netlink.attr_find(attrs, OVPN_A_PEER)
	_, has := netlink.attr_find(peer.data, OVPN_A_PEER_REMOTE_IPV4)
	testing.expect(t, !has)
	_, has = netlink.attr_find(peer.data, OVPN_A_PEER_REMOTE_PORT)
	testing.expect(t, !has)
}

@(test)
peer_set_and_id_requests :: proc(t: ^testing.T) {
	buf: [128]u8
	msg, err := build_peer_set(buf[:], FAM, 2, 6, 77, 10, 120)
	testing.expect_value(t, err, netlink.Error.None)
	cmd, attrs := payload_of(t, msg)
	testing.expect_value(t, cmd, u8(OVPN_CMD_PEER_SET))
	peer, _ := netlink.attr_find(attrs, OVPN_A_PEER)
	iv, _ := netlink.attr_find(peer.data, OVPN_A_PEER_KEEPALIVE_INTERVAL)
	to, _ := netlink.attr_find(peer.data, OVPN_A_PEER_KEEPALIVE_TIMEOUT)
	a, _ := netlink.attr_u32(iv)
	b, _ := netlink.attr_u32(to)
	testing.expect_value(t, a, u32(10))
	testing.expect_value(t, b, u32(120))

	msg, err = build_peer_id(buf[:], FAM, 3, 6, OVPN_CMD_PEER_GET, 77)
	testing.expect_value(t, err, netlink.Error.None)
	cmd, attrs = payload_of(t, msg)
	testing.expect_value(t, cmd, u8(OVPN_CMD_PEER_GET))
	peer, _ = netlink.attr_find(attrs, OVPN_A_PEER)
	id, _ := netlink.attr_find(peer.data, OVPN_A_PEER_ID)
	a, _ = netlink.attr_u32(id)
	testing.expect_value(t, a, u32(77))
}

@(test)
key_new_layout :: proc(t: ^testing.T) {
	buf: [512]u8
	k := New_Key {
		peer_id = 3,
		slot    = u32(Key_Slot.Secondary),
		key_id  = 2,
		cipher  = u32(Cipher.Aes_Gcm),
		key_len = 32,
	}
	for i in 0 ..< 32 {
		k.enc_key[i] = u8(i)
		k.dec_key[i] = u8(0x80 + i)
	}
	k.enc_nonce = {1, 2, 3, 4, 5, 6, 7, 8}
	k.dec_nonce = {9, 10, 11, 12, 13, 14, 15, 16}
	msg, err := build_key_new(buf[:], FAM, 4, 2, &k)
	testing.expect_value(t, err, netlink.Error.None)
	cmd, attrs := payload_of(t, msg)
	testing.expect_value(t, cmd, u8(OVPN_CMD_KEY_NEW))
	kc, found := netlink.attr_find(attrs, OVPN_A_KEYCONF)
	testing.expect(t, found)
	testing.expect(t, kc.nested)
	get :: proc(data: []u8, type: u16) -> u32 {
		a, _ := netlink.attr_find(data, type)
		v, _ := netlink.attr_u32(a)
		return v
	}
	testing.expect_value(t, get(kc.data, OVPN_A_KEYCONF_PEER_ID), u32(3))
	testing.expect_value(t, get(kc.data, OVPN_A_KEYCONF_SLOT), u32(1))
	testing.expect_value(t, get(kc.data, OVPN_A_KEYCONF_KEY_ID), u32(2))
	testing.expect_value(t, get(kc.data, OVPN_A_KEYCONF_CIPHER_ALG), u32(1))
	enc, _ := netlink.attr_find(kc.data, OVPN_A_KEYCONF_ENCRYPT_DIR)
	dec, _ := netlink.attr_find(kc.data, OVPN_A_KEYCONF_DECRYPT_DIR)
	testing.expect(t, enc.nested && dec.nested)
	ek, _ := netlink.attr_find(enc.data, OVPN_A_KEYDIR_CIPHER_KEY)
	en, _ := netlink.attr_find(enc.data, OVPN_A_KEYDIR_NONCE_TAIL)
	dk, _ := netlink.attr_find(dec.data, OVPN_A_KEYDIR_CIPHER_KEY)
	dn, _ := netlink.attr_find(dec.data, OVPN_A_KEYDIR_NONCE_TAIL)
	testing.expect_value(t, len(ek.data), 32)
	testing.expect_value(t, ek.data[31], u8(31))
	testing.expect_value(t, len(en.data), OVPN_NONCE_TAIL_SIZE)
	testing.expect_value(t, en.data[0], u8(1))
	testing.expect_value(t, dk.data[0], u8(0x80))
	testing.expect_value(t, dn.data[7], u8(16))

	k.key_len = 16
	msg, err = build_key_new(buf[:], FAM, 4, 2, &k)
	testing.expect_value(t, err, netlink.Error.None)
	_, attrs = payload_of(t, msg)
	kc, _ = netlink.attr_find(attrs, OVPN_A_KEYCONF)
	enc, _ = netlink.attr_find(kc.data, OVPN_A_KEYCONF_ENCRYPT_DIR)
	ek, _ = netlink.attr_find(enc.data, OVPN_A_KEYDIR_CIPHER_KEY)
	testing.expect_value(t, len(ek.data), 16)

	small: [64]u8
	_, err = build_key_new(small[:], FAM, 4, 2, &k)
	testing.expect_value(t, err, netlink.Error.Buffer_Too_Small)
}

@(test)
key_swap_and_del :: proc(t: ^testing.T) {
	buf: [128]u8
	msg, err := build_key_slot(buf[:], FAM, 1, 2, OVPN_CMD_KEY_SWAP, 4, .Primary)
	testing.expect_value(t, err, netlink.Error.None)
	cmd, attrs := payload_of(t, msg)
	testing.expect_value(t, cmd, u8(OVPN_CMD_KEY_SWAP))
	kc, _ := netlink.attr_find(attrs, OVPN_A_KEYCONF)
	_, has := netlink.attr_find(kc.data, OVPN_A_KEYCONF_SLOT)
	testing.expect(t, !has)

	msg, err = build_key_slot(buf[:], FAM, 1, 2, OVPN_CMD_KEY_DEL, 4, .Secondary)
	testing.expect_value(t, err, netlink.Error.None)
	cmd, attrs = payload_of(t, msg)
	testing.expect_value(t, cmd, u8(OVPN_CMD_KEY_DEL))
	kc, _ = netlink.attr_find(attrs, OVPN_A_KEYCONF)
	slot, ok := netlink.attr_find(kc.data, OVPN_A_KEYCONF_SLOT)
	testing.expect(t, ok)
	v, _ := netlink.attr_u32(slot)
	testing.expect_value(t, v, u32(1))
}

// A reply as the kernel writes it: integers that fit in 32 bits are 4 bytes.
@(test)
parse_peer_get_reply :: proc(t: ^testing.T) {
	buf: [512]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.put_genl_header(&b, FAM, 0, 5, OVPN_CMD_PEER_GET, 1)
	netlink.put_u32(&b, OVPN_A_IFINDEX, 4)
	nest := netlink.nest_begin(&b, OVPN_A_PEER)
	netlink.put_u32(&b, OVPN_A_PEER_ID, 12)
	netlink.put_attr(&b, OVPN_A_PEER_REMOTE_IPV4, []u8{10, 80, 80, 2})
	netlink.put_u16_be(&b, OVPN_A_PEER_REMOTE_PORT, 11941)
	netlink.put_u32(&b, OVPN_A_PEER_KEEPALIVE_INTERVAL, 10)
	netlink.put_u32(&b, OVPN_A_PEER_KEEPALIVE_TIMEOUT, 60)
	netlink.put_u32(&b, OVPN_A_PEER_VPN_RX_BYTES, 1000)
	netlink.put_u64(&b, OVPN_A_PEER_VPN_TX_BYTES, 1 << 40)
	netlink.put_u32(&b, OVPN_A_PEER_VPN_RX_PACKETS, 7)
	netlink.put_u32(&b, OVPN_A_PEER_VPN_TX_PACKETS, 8)
	netlink.put_u32(&b, OVPN_A_PEER_LINK_RX_BYTES, 1100)
	netlink.put_u32(&b, OVPN_A_PEER_LINK_TX_BYTES, 1200)
	netlink.put_u32(&b, OVPN_A_PEER_LINK_RX_PACKETS, 9)
	netlink.put_u32(&b, OVPN_A_PEER_LINK_TX_PACKETS, 10)
	netlink.nest_end(&b, nest)
	msg, err := netlink.finish(&b)
	testing.expect_value(t, err, netlink.Error.None)
	it := netlink.msg_iter(msg)
	m, _ := netlink.msg_next(&it)
	info, ok := parse_peer_get(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, info.id, u32(12))
	testing.expect_value(t, info.remote, endpoint_v4({10, 80, 80, 2}, 11941))
	testing.expect_value(t, info.ka_interval, u32(10))
	testing.expect_value(t, info.ka_timeout, u32(60))
	testing.expect_value(t, info.stats.vpn_rx_bytes, u64(1000))
	testing.expect_value(t, info.stats.vpn_tx_bytes, u64(1 << 40))
	testing.expect_value(t, info.stats.vpn_rx_packets, u64(7))
	testing.expect_value(t, info.stats.vpn_tx_packets, u64(8))
	testing.expect_value(t, info.stats.link_rx_bytes, u64(1100))
	testing.expect_value(t, info.stats.link_tx_bytes, u64(1200))
	testing.expect_value(t, info.stats.link_rx_packets, u64(9))
	testing.expect_value(t, info.stats.link_tx_packets, u64(10))
	testing.expect_value(t, info.stats.rx_drops, u64(0))

	// A reply with no peer attribute is not a reply.
	_, ok = parse_peer_get([]u8{OVPN_CMD_PEER_GET, 1, 0, 0})
	testing.expect(t, !ok)
}

@(test)
parse_notifications :: proc(t: ^testing.T) {
	buf: [256]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.put_genl_header(&b, FAM, 0, 0, OVPN_CMD_PEER_DEL_NTF, 1)
	netlink.put_u32(&b, OVPN_A_IFINDEX, 9)
	nest := netlink.nest_begin(&b, OVPN_A_PEER)
	netlink.put_u32(&b, OVPN_A_PEER_DEL_REASON, u32(Del_Reason.Expired))
	netlink.put_u32(&b, OVPN_A_PEER_ID, 41)
	netlink.nest_end(&b, nest)
	msg, _ := netlink.finish(&b)
	it := netlink.msg_iter(msg)
	m, _ := netlink.msg_next(&it)
	n, ok := parse_notify(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, n.cmd, u8(OVPN_CMD_PEER_DEL_NTF))
	testing.expect_value(t, n.ifindex, u32(9))
	testing.expect_value(t, n.peer_id, u32(41))
	testing.expect_value(t, n.reason, Del_Reason.Expired)

	// The key id of a swap notification is 2 bytes in the driver.
	netlink.builder_init(&b, buf[:])
	netlink.put_genl_header(&b, FAM, 0, 0, OVPN_CMD_KEY_SWAP_NTF, 1)
	netlink.put_u32(&b, OVPN_A_IFINDEX, 9)
	nest = netlink.nest_begin(&b, OVPN_A_KEYCONF)
	netlink.put_u32(&b, OVPN_A_KEYCONF_PEER_ID, 41)
	netlink.put_u16(&b, OVPN_A_KEYCONF_KEY_ID, 3)
	netlink.nest_end(&b, nest)
	msg, _ = netlink.finish(&b)
	it = netlink.msg_iter(msg)
	m, _ = netlink.msg_next(&it)
	n, ok = parse_notify(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, n.cmd, u8(OVPN_CMD_KEY_SWAP_NTF))
	testing.expect_value(t, n.peer_id, u32(41))
	testing.expect_value(t, n.key_id, u32(3))

	// Another command is not a notification.
	_, ok = parse_notify([]u8{OVPN_CMD_PEER_GET, 1, 0, 0})
	testing.expect(t, !ok)
}

@(test)
endpoints :: proc(t: ^testing.T) {
	ss := sockaddr_v4({10, 0, 0, 1}, 1194)
	e, ok := endpoint_of(&ss)
	testing.expect(t, ok)
	testing.expect_value(t, e, endpoint_v4({10, 0, 0, 1}, 1194))
	back := endpoint_sockaddr(e)
	testing.expect_value(t, back, ss)

	// An IPv4 address in IPv6 form is IPv4.
	mapped := [16]u8{10 = 0xff, 11 = 0xff, 12 = 10, 13 = 0, 14 = 0, 15 = 1}
	ss6 := sockaddr_v6(mapped, 1194)
	e, ok = endpoint_of(&ss6)
	testing.expect(t, ok)
	testing.expect_value(t, e, endpoint_v4({10, 0, 0, 1}, 1194))

	plain := [16]u8{0 = 0xfd, 15 = 1}
	ss6 = sockaddr_v6(plain, 5)
	e, ok = endpoint_of(&ss6)
	testing.expect(t, ok)
	testing.expect_value(t, e.family, AF_INET6)
	testing.expect_value(t, e.addr, plain)

	var: Sockaddr_Storage
	_, ok = endpoint_of(&var)
	testing.expect(t, !ok)
}

@(test)
stream_records_and_partial :: proc(t: ^testing.T) {
	// A control record (opcode 4), a data record (opcode 9), a partial record.
	data := []u8{0, 3, 4 << 3, 1, 2, 0, 2, 9 << 3, 7, 0, 5, 4 << 3, 1}
	off := 0
	rec, ok := stream_next(data, &off)
	testing.expect(t, ok)
	testing.expect_value(t, len(rec), 3)
	testing.expect(t, !record_is_data(rec))
	rec, ok = stream_next(data, &off)
	testing.expect(t, ok)
	testing.expect_value(t, len(rec), 2)
	testing.expect(t, record_is_data(rec))
	_, ok = stream_next(data, &off)
	testing.expect(t, !ok)
	testing.expect_value(t, off, 9)
	// The partial record has 4 of 7 bytes: 3 more are needed.
	testing.expect_value(t, stream_need(data[off:]), 3)
	// One byte: the length is not known.
	testing.expect_value(t, stream_need(data[off:][:1]), -1)
	testing.expect_value(t, stream_need(data[off:][:2]), 5)
	testing.expect_value(t, stream_need(data[0:5]), 0)

	// An empty tail has nothing missing.
	off = len(data)
	_, ok = stream_next(data, &off)
	testing.expect(t, !ok)
	// A record of length 0 is a record.
	zero := []u8{0, 0}
	off = 0
	rec, ok = stream_next(zero, &off)
	testing.expect(t, ok)
	testing.expect_value(t, len(rec), 0)
	testing.expect(t, !record_is_data(rec))
}

@(test)
parse_key_get_reply :: proc(t: ^testing.T) {
	buf: [128]u8
	b: netlink.Builder
	netlink.builder_init(&b, buf[:])
	netlink.put_genl_header(&b, FAM, 0, 5, OVPN_CMD_KEY_GET, 1)
	netlink.put_u32(&b, OVPN_A_IFINDEX, 4)
	nest := netlink.nest_begin(&b, OVPN_A_KEYCONF)
	netlink.put_u32(&b, OVPN_A_KEYCONF_PEER_ID, 12)
	netlink.put_u32(&b, OVPN_A_KEYCONF_SLOT, 1)
	netlink.put_u32(&b, OVPN_A_KEYCONF_KEY_ID, 6)
	netlink.put_u32(&b, OVPN_A_KEYCONF_CIPHER_ALG, 2)
	netlink.nest_end(&b, nest)
	msg, _ := netlink.finish(&b)
	it := netlink.msg_iter(msg)
	m, _ := netlink.msg_next(&it)
	info, ok := parse_key_get(m.payload)
	testing.expect(t, ok)
	testing.expect_value(t, info, Key_Info{peer_id = 12, slot = 1, key_id = 6, cipher = 2})
	_, ok = parse_key_get([]u8{OVPN_CMD_KEY_GET, 1, 0, 0})
	testing.expect(t, !ok)
}
