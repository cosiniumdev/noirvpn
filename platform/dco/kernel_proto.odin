// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package dco

import "noir:platform/netlink"

// Generic netlink interface of the Linux `ovpn` driver (family "ovpn",
// version 1, <linux/ovpn.h>): numbers, message builders and parsers. Pure
// byte work; `kernel_linux.odin` has the backend that sends them.

OVPN_FAMILY :: "ovpn"
OVPN_VERSION :: 1
OVPN_GROUP_PEERS :: "peers"

// Commands.
OVPN_CMD_PEER_NEW :: 1
OVPN_CMD_PEER_SET :: 2
OVPN_CMD_PEER_GET :: 3
OVPN_CMD_PEER_DEL :: 4
OVPN_CMD_PEER_DEL_NTF :: 5
OVPN_CMD_KEY_NEW :: 6
OVPN_CMD_KEY_GET :: 7
OVPN_CMD_KEY_SWAP :: 8
OVPN_CMD_KEY_SWAP_NTF :: 9
OVPN_CMD_KEY_DEL :: 10

// Top level attributes.
OVPN_A_IFINDEX :: 1
OVPN_A_PEER :: 2
OVPN_A_KEYCONF :: 3

// Attributes inside OVPN_A_PEER.
OVPN_A_PEER_ID :: 1
OVPN_A_PEER_REMOTE_IPV4 :: 2
OVPN_A_PEER_REMOTE_IPV6 :: 3
OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID :: 4
OVPN_A_PEER_REMOTE_PORT :: 5
OVPN_A_PEER_SOCKET :: 6
OVPN_A_PEER_SOCKET_NETNSID :: 7
OVPN_A_PEER_VPN_IPV4 :: 8
OVPN_A_PEER_VPN_IPV6 :: 9
OVPN_A_PEER_LOCAL_IPV4 :: 10
OVPN_A_PEER_LOCAL_IPV6 :: 11
OVPN_A_PEER_LOCAL_PORT :: 12
OVPN_A_PEER_KEEPALIVE_INTERVAL :: 13
OVPN_A_PEER_KEEPALIVE_TIMEOUT :: 14
OVPN_A_PEER_DEL_REASON :: 15
OVPN_A_PEER_VPN_RX_BYTES :: 16
OVPN_A_PEER_VPN_TX_BYTES :: 17
OVPN_A_PEER_VPN_RX_PACKETS :: 18
OVPN_A_PEER_VPN_TX_PACKETS :: 19
OVPN_A_PEER_LINK_RX_BYTES :: 20
OVPN_A_PEER_LINK_TX_BYTES :: 21
OVPN_A_PEER_LINK_RX_PACKETS :: 22
OVPN_A_PEER_LINK_TX_PACKETS :: 23

// Attributes inside OVPN_A_KEYCONF.
OVPN_A_KEYCONF_PEER_ID :: 1
OVPN_A_KEYCONF_SLOT :: 2
OVPN_A_KEYCONF_KEY_ID :: 3
OVPN_A_KEYCONF_CIPHER_ALG :: 4
OVPN_A_KEYCONF_ENCRYPT_DIR :: 5
OVPN_A_KEYCONF_DECRYPT_DIR :: 6

// Attributes inside a key direction.
OVPN_A_KEYDIR_CIPHER_KEY :: 1
OVPN_A_KEYDIR_NONCE_TAIL :: 2

OVPN_NONCE_TAIL_SIZE :: 8

// The data packet opcode that the kernel handles. Every other opcode on a TCP
// stream goes to user space.
OPCODE_DATA_V1 :: 6
OPCODE_DATA_V2 :: 9

// An endpoint of a peer, IPv4 or IPv6 (an IPv4-mapped IPv6 address is IPv4).
Endpoint :: struct {
	family: int, // AF_INET, AF_INET6, or 0: none
	addr:   [16]u8, // IPv4: the first 4 bytes
	port:   u16,
}

// The endpoint of a socket address. `ok` is false for another family.
endpoint_of :: proc "contextless" (ss: ^Sockaddr_Storage) -> (e: Endpoint, ok: bool) {
	fam, addr, port, pok := sockaddr_parse(ss)
	if !pok {
		return {}, false
	}
	if fam == AF_INET6 {
		mapped := true
		for i in 0 ..< 10 {
			if addr[i] != 0 {
				mapped = false
			}
		}
		if mapped && addr[10] == 0xff && addr[11] == 0xff {
			e = Endpoint {
				family = AF_INET,
				port   = port,
			}
			copy(e.addr[:4], addr[12:16])
			return e, true
		}
	}
	return Endpoint{family = fam, addr = addr, port = port}, true
}

endpoint_v4 :: proc "contextless" (addr: [4]u8, port: u16) -> Endpoint {
	e := Endpoint {
		family = AF_INET,
		port   = port,
	}
	a := addr
	copy(e.addr[:4], a[:])
	return e
}

endpoint_sockaddr :: proc "contextless" (e: Endpoint) -> Sockaddr_Storage {
	if e.family == AF_INET {
		return sockaddr_v4({e.addr[0], e.addr[1], e.addr[2], e.addr[3]}, e.port)
	}
	return sockaddr_v6(e.addr, e.port)
}

// ----------------------------------------------------------------- requests

// One request: the netlink and generic headers, then the device index.
@(private)
kreq_begin :: proc(b: ^netlink.Builder, buf: []u8, family: u16, seq: u32, cmd: u8, ifindex: u32) {
	netlink.builder_init(b, buf)
	netlink.put_genl_header(b, family, netlink.NLM_F_REQUEST | netlink.NLM_F_ACK, seq, cmd, OVPN_VERSION)
	netlink.put_u32(b, OVPN_A_IFINDEX, ifindex)
}

// What PEER_NEW is given besides the id and the socket.
Peer_New_Args :: struct {
	id:      u32,
	sock:    i32,
	mp:      bool, // the device is multi-peer: VPN addresses are required, else forbidden
	tcp:     bool, // a TCP socket: no remote or local address
	remote:  Endpoint, // UDP: where the peer is
	local:   Endpoint, // UDP: the address to send from (the port is ignored), family 0: none
	vpn4:    Maybe([4]u8),
	vpn6:    Maybe([16]u8),
}

build_peer_new :: proc(buf: []u8, family: u16, seq: u32, ifindex: u32, a: Peer_New_Args) -> (msg: []u8, err: netlink.Error) {
	b: netlink.Builder
	kreq_begin(&b, buf, family, seq, OVPN_CMD_PEER_NEW, ifindex)
	nest := netlink.nest_begin(&b, OVPN_A_PEER)
	netlink.put_u32(&b, OVPN_A_PEER_ID, a.id)
	netlink.put_u32(&b, OVPN_A_PEER_SOCKET, u32(a.sock))
	if !a.tcp && a.remote.family != 0 {
		put_endpoint(&b, a.remote, a.local)
	}
	if a.mp {
		if v, ok := a.vpn4.?; ok {
			put_bytes(&b, OVPN_A_PEER_VPN_IPV4, v[:])
		}
		if v, ok := a.vpn6.?; ok {
			put_bytes(&b, OVPN_A_PEER_VPN_IPV6, v[:])
		}
	}
	netlink.nest_end(&b, nest)
	return netlink.finish(&b)
}

@(private)
put_bytes :: proc(b: ^netlink.Builder, type: u16, v: []u8) {
	netlink.put_attr(b, type, v)
}

// The remote address and port, and the local address of the same family.
@(private)
put_endpoint :: proc(b: ^netlink.Builder, remote_in, local_in: Endpoint) {
	remote := remote_in
	local := local_in
	if remote.family == AF_INET {
		put_bytes(b, OVPN_A_PEER_REMOTE_IPV4, remote.addr[:4])
	} else {
		put_bytes(b, OVPN_A_PEER_REMOTE_IPV6, remote.addr[:])
	}
	netlink.put_u16_be(b, OVPN_A_PEER_REMOTE_PORT, remote.port)
	if local.family == remote.family {
		if local.family == AF_INET {
			put_bytes(b, OVPN_A_PEER_LOCAL_IPV4, local.addr[:4])
		} else {
			put_bytes(b, OVPN_A_PEER_LOCAL_IPV6, local.addr[:])
		}
	}
}

build_peer_set :: proc(buf: []u8, family: u16, seq: u32, ifindex: u32, id, interval, timeout: u32) -> (msg: []u8, err: netlink.Error) {
	b: netlink.Builder
	kreq_begin(&b, buf, family, seq, OVPN_CMD_PEER_SET, ifindex)
	nest := netlink.nest_begin(&b, OVPN_A_PEER)
	netlink.put_u32(&b, OVPN_A_PEER_ID, id)
	netlink.put_u32(&b, OVPN_A_PEER_KEEPALIVE_INTERVAL, interval)
	netlink.put_u32(&b, OVPN_A_PEER_KEEPALIVE_TIMEOUT, timeout)
	netlink.nest_end(&b, nest)
	return netlink.finish(&b)
}

// PEER_GET and PEER_DEL take only the id.
build_peer_id :: proc(buf: []u8, family: u16, seq: u32, ifindex: u32, cmd: u8, id: u32) -> (msg: []u8, err: netlink.Error) {
	b: netlink.Builder
	kreq_begin(&b, buf, family, seq, cmd, ifindex)
	nest := netlink.nest_begin(&b, OVPN_A_PEER)
	netlink.put_u32(&b, OVPN_A_PEER_ID, id)
	netlink.nest_end(&b, nest)
	return netlink.finish(&b)
}

// KEY_NEW from the message of the service protocol. The caller wipes `buf`.
build_key_new :: proc(buf: []u8, family: u16, seq: u32, ifindex: u32, k: ^New_Key) -> (msg: []u8, err: netlink.Error) {
	if k.key_len > 64 {
		return nil, .Oversize
	}
	b: netlink.Builder
	kreq_begin(&b, buf, family, seq, OVPN_CMD_KEY_NEW, ifindex)
	nest := netlink.nest_begin(&b, OVPN_A_KEYCONF)
	netlink.put_u32(&b, OVPN_A_KEYCONF_PEER_ID, k.peer_id)
	netlink.put_u32(&b, OVPN_A_KEYCONF_SLOT, k.slot)
	netlink.put_u32(&b, OVPN_A_KEYCONF_KEY_ID, k.key_id)
	netlink.put_u32(&b, OVPN_A_KEYCONF_CIPHER_ALG, k.cipher)
	enc := netlink.nest_begin(&b, OVPN_A_KEYCONF_ENCRYPT_DIR)
	put_bytes(&b, OVPN_A_KEYDIR_CIPHER_KEY, k.enc_key[:k.key_len])
	put_bytes(&b, OVPN_A_KEYDIR_NONCE_TAIL, k.enc_nonce[:])
	netlink.nest_end(&b, enc)
	dec := netlink.nest_begin(&b, OVPN_A_KEYCONF_DECRYPT_DIR)
	put_bytes(&b, OVPN_A_KEYDIR_CIPHER_KEY, k.dec_key[:k.key_len])
	put_bytes(&b, OVPN_A_KEYDIR_NONCE_TAIL, k.dec_nonce[:])
	netlink.nest_end(&b, dec)
	netlink.nest_end(&b, nest)
	return netlink.finish(&b)
}

// KEY_SWAP (`slot` ignored) and KEY_DEL (`slot` is the one to empty).
build_key_slot :: proc(buf: []u8, family: u16, seq: u32, ifindex: u32, cmd: u8, id: u32, slot: Key_Slot) -> (msg: []u8, err: netlink.Error) {
	b: netlink.Builder
	kreq_begin(&b, buf, family, seq, cmd, ifindex)
	nest := netlink.nest_begin(&b, OVPN_A_KEYCONF)
	netlink.put_u32(&b, OVPN_A_KEYCONF_PEER_ID, id)
	if cmd != OVPN_CMD_KEY_SWAP {
		netlink.put_u32(&b, OVPN_A_KEYCONF_SLOT, u32(slot))
	}
	netlink.nest_end(&b, nest)
	return netlink.finish(&b)
}

// ------------------------------------------------------------------ replies

// What a PEER_GET reply tells.
Peer_Info :: struct {
	id:         u32,
	remote:     Endpoint, // family 0: the reply has none (a TCP peer)
	ka_interval: u32,
	ka_timeout:  u32,
	stats:      Peer_Stats, // the VPN and link counters; the drop fields stay 0
}

// `payload` is the generic message payload (generic header included).
parse_peer_get :: proc "contextless" (payload: []u8) -> (info: Peer_Info, ok: bool) {
	_, attrs := netlink.read_struct(payload, netlink.Genlmsghdr) or_return
	peer := netlink.attr_find(attrs, OVPN_A_PEER) or_return
	it := netlink.attr_iter(peer.data)
	for a in netlink.attr_next(&it) {
		switch a.type {
		case OVPN_A_PEER_ID:
			info.id, _ = netlink.attr_u32(a)
		case OVPN_A_PEER_REMOTE_IPV4:
			if len(a.data) == 4 {
				info.remote.family = AF_INET
				copy(info.remote.addr[:4], a.data)
			}
		case OVPN_A_PEER_REMOTE_IPV6:
			if len(a.data) == 16 {
				info.remote.family = AF_INET6
				copy(info.remote.addr[:], a.data)
			}
		case OVPN_A_PEER_REMOTE_PORT:
			info.remote.port, _ = netlink.attr_u16_be(a)
		case OVPN_A_PEER_KEEPALIVE_INTERVAL:
			v, _ := netlink.attr_uint(a)
			info.ka_interval = u32(v)
		case OVPN_A_PEER_KEEPALIVE_TIMEOUT:
			v, _ := netlink.attr_uint(a)
			info.ka_timeout = u32(v)
		case OVPN_A_PEER_VPN_RX_BYTES:
			info.stats.vpn_rx_bytes, _ = netlink.attr_uint(a)
		case OVPN_A_PEER_VPN_TX_BYTES:
			info.stats.vpn_tx_bytes, _ = netlink.attr_uint(a)
		case OVPN_A_PEER_VPN_RX_PACKETS:
			info.stats.vpn_rx_packets, _ = netlink.attr_uint(a)
		case OVPN_A_PEER_VPN_TX_PACKETS:
			info.stats.vpn_tx_packets, _ = netlink.attr_uint(a)
		case OVPN_A_PEER_LINK_RX_BYTES:
			info.stats.link_rx_bytes, _ = netlink.attr_uint(a)
		case OVPN_A_PEER_LINK_TX_BYTES:
			info.stats.link_tx_bytes, _ = netlink.attr_uint(a)
		case OVPN_A_PEER_LINK_RX_PACKETS:
			info.stats.link_rx_packets, _ = netlink.attr_uint(a)
		case OVPN_A_PEER_LINK_TX_PACKETS:
			info.stats.link_tx_packets, _ = netlink.attr_uint(a)
		}
	}
	return info, true
}

// What a KEY_GET reply tells about the key in a slot (never the key itself).
Key_Info :: struct {
	peer_id: u32,
	slot:    u32,
	key_id:  u32,
	cipher:  u32,
}

parse_key_get :: proc "contextless" (payload: []u8) -> (info: Key_Info, ok: bool) {
	_, attrs := netlink.read_struct(payload, netlink.Genlmsghdr) or_return
	kc := netlink.attr_find(attrs, OVPN_A_KEYCONF) or_return
	it := netlink.attr_iter(kc.data)
	for a in netlink.attr_next(&it) {
		v, _ := netlink.attr_uint(a)
		switch a.type {
		case OVPN_A_KEYCONF_PEER_ID:
			info.peer_id = u32(v)
		case OVPN_A_KEYCONF_SLOT:
			info.slot = u32(v)
		case OVPN_A_KEYCONF_KEY_ID:
			info.key_id = u32(v)
		case OVPN_A_KEYCONF_CIPHER_ALG:
			info.cipher = u32(v)
		}
	}
	return info, true
}

// A notification of the "peers" group.
Notify :: struct {
	cmd:     u8, // OVPN_CMD_PEER_DEL_NTF or OVPN_CMD_KEY_SWAP_NTF
	ifindex: u32,
	peer_id: u32,
	reason:  Del_Reason, // PEER_DEL_NTF
	key_id:  u32, // KEY_SWAP_NTF
}

parse_notify :: proc "contextless" (payload: []u8) -> (n: Notify, ok: bool) {
	gh, attrs := netlink.read_struct(payload, netlink.Genlmsghdr) or_return
	n.cmd = gh.cmd
	if n.cmd != OVPN_CMD_PEER_DEL_NTF && n.cmd != OVPN_CMD_KEY_SWAP_NTF {
		return {}, false
	}
	it := netlink.attr_iter(attrs)
	for a in netlink.attr_next(&it) {
		switch a.type {
		case OVPN_A_IFINDEX:
			n.ifindex, _ = netlink.attr_u32(a)
		case OVPN_A_PEER:
			sub := netlink.attr_iter(a.data)
			for x in netlink.attr_next(&sub) {
				v, _ := netlink.attr_uint(x)
				switch x.type {
				case OVPN_A_PEER_ID:
					n.peer_id = u32(v)
				case OVPN_A_PEER_DEL_REASON:
					n.reason = Del_Reason(v)
				}
			}
		case OVPN_A_KEYCONF:
			sub := netlink.attr_iter(a.data)
			for x in netlink.attr_next(&sub) {
				v, _ := netlink.attr_uint(x)
				switch x.type {
				case OVPN_A_KEYCONF_PEER_ID:
					n.peer_id = u32(v)
				case OVPN_A_KEYCONF_KEY_ID:
					n.key_id = u32(v)
				}
			}
		}
	}
	return n, true
}

// ------------------------------------------------------------ stream bytes

// The next whole record of a TCP stream: a 2-byte big-endian length, then that
// many bytes.
//   b    starts at `off`
//   rec  the record without the length
//   ok   false if the rest of `b` is not a whole record (or is empty)
//   off  moves past the record
stream_next :: proc "contextless" (b: []u8, off: ^int) -> (rec: []u8, ok: bool) {
	rest := b[off^:]
	if len(rest) < 2 {
		return nil, false
	}
	n := int(rest[0]) << 8 | int(rest[1])
	if len(rest) < 2 + n {
		return nil, false
	}
	off^ += 2 + n
	return rest[2:2 + n], true
}

// How many more bytes a partial record needs. `-1`: fewer than 2 bytes are
// there, so the length is not known yet; read 2 - len(partial) first.
stream_need :: proc "contextless" (partial: []u8) -> int {
	if len(partial) < 2 {
		return -1
	}
	return max(0, 2 + (int(partial[0]) << 8 | int(partial[1])) - len(partial))
}

// Does the kernel handle this record (a data packet), so that user space never
// sees it?
record_is_data :: proc "contextless" (rec: []u8) -> bool {
	return len(rec) > 0 && rec[0] >> 3 == OPCODE_DATA_V2
}
