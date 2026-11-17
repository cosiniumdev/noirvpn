// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package dco drives a data channel outside this process: a userspace DCO
// service on a Unix socket (`socket_linux.odin`), and later the kernel `ovpn` driver.
// The daemon keeps the control channel, key derivation and policy. The backend
// owns the tun device, AEAD, replay window and keepalive.
//
// This file has the numbers and layouts of the socket protocol. Fields are in
// host byte order; socket addresses inside them are in network byte order.
// `backend.odin` has the interface a backend implements.
package dco

PROTO_VERSION :: 1
SOCKET_DEFAULT :: "/run/udco/udco.sock"
// The largest message, header and body. Three messages are longer (`MSG_MAX_STREAM`).
MSG_MAX :: 1024
// A record of a TCP stream is at most 65535 bytes (its length prefix is 2 bytes).
STREAM_REC_MAX :: 65535
LOG_MAX :: 512
IFNAME_MAX :: 16

// Message types. A reply has the type of its request and `F_REPLY`.
Msg :: enum u16 {
	Hello     = 1,
	Open      = 2,
	Close     = 3,
	New_Peer  = 4,
	Set_Peer  = 5,
	Del_Peer  = 6,
	Detach    = 7,
	New_Key   = 8,
	Del_Key   = 9,
	Swap_Keys = 10,
	Peer_Stats = 11,
	Link_Set  = 12,
	Addr_Add  = 13,
	Addr_Del  = 14,
	Route_Add = 15,
	Route_Del = 16,
	Ping      = 17,
	Key_Add   = 18, // key table (`CAP_KEY_TABLE`)
	Key_Tx    = 19,
	Key_Drop  = 20,
	Ctrl_Tx   = 21, // a control record for the stream of a TCP peer (`CAP_TCP`)
	Set_Peer_Id = 22, // a peer takes a new id (`CAP_PEER_ID`)
	Set_Peer_Addr = 23, // the VPN addresses of a peer, after it exists (`CAP_PEER_ADDR`)
	Set_Filter = 24, // the packet filter of the device (`CAP_BLOCK_IPV6`)
	Event     = 64,
	Log       = 65,
	Ctrl_Rx   = 66, // service to client: a control record that the stream carried (`CAP_TCP`)
}

F_REPLY :: 1
F_FD :: 2

// `Hello_Reply.caps`: what the service has beyond the base protocol.
CAP_KEY_TABLE :: 1 // Key_Add, Key_Tx, Key_Drop
CAP_STATS_REASONS :: 2 // `Peer_Stats` has the drop reasons
CAP_TCP :: 4 // `New_Peer` takes a TCP stream; `Ctrl_Tx`, `Ctrl_Rx`
CAP_PEER_ID :: 8 // `Set_Peer_Id`: a peer takes a new id (a TCP peer can be created before its id is known)
CAP_PEER_ADDR :: 16 // `Set_Peer_Addr`: the VPN addresses of a peer, after it exists (a server learns them at the login)
CAP_BLOCK_IPV6 :: 32 // `Set_Filter`: the device drops IPv6 packets in both directions (`block-ipv6`)

// The largest peer id: 24 bits. `Set_Peer_Id` with a larger `new_id` is `EINVAL`. The
// id 0x00ffffff means "no peer" in a data packet header, so noirvpn never uses it.
PEER_ID_LIMIT :: 0x00ff_ffff

Dataplane :: enum u32 {
	Openvpn = 1,
}

Mode :: enum u32 {
	P2p = 0,
	Mp  = 1,
}

Cipher :: enum u32 {
	None              = 0,
	Aes_Gcm           = 1,
	Chacha20_Poly1305 = 2,
}

Key_Slot :: enum u32 {
	Primary   = 0,
	Secondary = 1,
}

Del_Reason :: enum u32 {
	Teardown             = 0,
	Userspace            = 1,
	Expired              = 2,
	Transport_Error      = 3, // TCP: a stream error
	Transport_Disconnect = 4, // TCP: the peer closed the stream
}

Event_Kind :: enum u32 {
	Peer_Del   = 1,
	Peer_Float = 2,
	Key_Swap   = 3,
	// Not a wire event: a `Ctrl_Rx` record that `next_event` hands out in its
	// place in the sequence. `peer_id` is the peer, `key_id` the record length
	// (`ctrl_record` returns it).
	Ctrl_Rx    = 66,
}

Log_Level :: enum u32 {
	Error = 0,
	Warn  = 1,
	Info  = 2,
	Debug = 3,
}

// `Open.flags`.
OPT_NO_GSO :: 1
OPT_NO_GRO :: 2
OPT_PIN_CPUS :: 4
OPT_FORCE_EVP :: 8
OPT_NO_TUN_OFFLOAD :: 16
// Drop packets from one peer to another (MP). Only the data channel in this
// process (`In_Process`) reads it.
OPT_NO_C2C :: 64

// `Set_Filter.flags`.
FILTER_IPV6 :: 1 // drop every IPv6 packet, in both directions

// `New_Peer.flags`: which optional fields are set.
PEER_LOCAL :: 1
PEER_REMOTE :: 2
PEER_VPN4 :: 4
PEER_VPN6 :: 8

// Status codes of a reply are 0 or -errno. These are the ones this package
// creates itself or the daemon looks at.
ENOENT :: -2
EIO :: -5
EEXIST :: -17
EINVAL :: -22
EPIPE :: -32
EPROTO :: -71
EMSGSIZE :: -90
ENOBUFS :: -105
EPROTONOSUPPORT :: -93
ECONNRESET :: -104
ENOTCONN :: -107

AF_INET :: 2
AF_INET6 :: 10

// struct sockaddr_storage: 128 bytes, 8-byte aligned. First two bytes: family
// (host order). Rest: `sockaddr_in` or `sockaddr_in6` as in the kernel (port
// and address in network byte order).
Sockaddr_Storage :: struct #align(8) {
	b: [128]u8,
}

Hdr :: struct {
	type:   u16, // `Msg`
	flags:  u16, // F_*
	status: i32, // replies: 0 or -errno; requests: 0
}

Hello :: struct {
	version: u32,
}

Hello_Reply :: struct {
	version:   u32,
	max_pairs: u32,
	daemon:    [32]u8, // name and version, NUL terminated
	caps:      u32, // CAP_*; a service that does not send it has none
}

Open :: struct {
	ifname:    [IFNAME_MAX]u8,
	dataplane: u32,
	mode:      u32,
	n_pairs:   u32, // 0: the service chooses
	flags:     u32,
}

Open_Reply :: struct {
	ifindex: u32,
	n_pairs: u32,
}

New_Peer :: struct {
	peer_id: u32,
	flags:   u32,
	local:   Sockaddr_Storage,
	remote:  Sockaddr_Storage,
	vpn4:    [4]u8,
	vpn6:    [16]u8,
}

Set_Peer :: struct {
	peer_id:            u32,
	keepalive_interval: u32, // seconds, 0: off
	keepalive_timeout:  u32, // seconds, 0: off
	mss:                u32, // TCP MSS to clamp to, 0: off
}

Peer_Id :: struct {
	peer_id: u32,
}

// Set_Peer_Id: the peer `peer_id` is `new_id` from now on. Its keys, stream, counters
// and keepalive stay.
Set_Peer_Id :: struct {
	peer_id: u32,
	new_id:  u32,
}

// Set_Peer_Addr: what `New_Peer.vpn4` and `vpn6` set, at any time after the peer
// exists. `flags` are `PEER_VPN4` and `PEER_VPN6`; an address that is not flagged is cleared.
Set_Peer_Addr :: struct {
	peer_id: u32,
	flags:   u32,
	vpn4:    [4]u8,
	vpn6:    [16]u8,
}

// Set_Filter: the flags that are on from now on (0: no filter). The reply holds the
// counters of the device since `Open`.
Set_Filter :: struct {
	flags: u32, // FILTER_*
}

Filter_Stats :: struct {
	rx_v6: u64, // IPv6 packets from the peers that were dropped before the tun device
	tx_v6: u64, // IPv6 packets read from the tun device that were dropped
}

New_Key :: struct {
	peer_id:   u32,
	slot:      u32,
	key_id:    u32, // 0..7
	cipher:    u32,
	key_len:   u32, // 16, 24 or 32 (AES-GCM); 32 (ChaCha20-Poly1305)
	enc_key:   [64]u8,
	enc_nonce: [8]u8,
	dec_key:   [64]u8,
	dec_nonce: [8]u8,
}

Del_Key :: struct {
	peer_id: u32,
	slot:    u32,
}

// Key_Add: a key of the key table, as `New_Key` without the slot.
Key :: struct {
	peer_id:   u32,
	key_id:    u32, // 0..7
	cipher:    u32,
	key_len:   u32,
	enc_key:   [64]u8,
	enc_nonce: [8]u8,
	dec_key:   [64]u8,
	dec_nonce: [8]u8,
}

// Key_Tx, Key_Drop.
Key_Id :: struct {
	peer_id: u32,
	key_id:  u32,
}

Peer_Stats :: struct {
	vpn_rx_bytes:   u64, // decrypted bytes written to the tun device
	vpn_tx_bytes:   u64, // plaintext bytes read from the tun device and sent
	vpn_rx_packets: u64,
	vpn_tx_packets: u64,
	link_rx_bytes:  u64, // UDP payload bytes received
	link_tx_bytes:  u64,
	link_rx_packets: u64,
	link_tx_packets: u64,
	rx_drops:       u64, // authentication failures, replays, bad packets
	tx_drops:       u64,
	// With `CAP_STATS_REASONS` (else 0): `rx_drops` by reason (the rest of
	// `rx_drops` is the receive queue), and `tx_drops` for want of a key.
	// A service that stops before `rx_src` sends 120 bytes; it reads as 0.
	rx_no_key:      u64, // no key for the key id of the packet
	rx_replay:      u64,
	rx_auth:        u64, // failed authentication
	rx_bad:         u64, // not an IP packet
	tx_no_key:      u64,
	rx_src:         u64, // multi-peer: the inner source address is not the peer's and not behind it
}

Link_Set :: struct {
	up:  u32,
	mtu: u32,
}

Addr :: struct {
	family:   u32,
	plen:     u32,
	has_peer: u32,
	addr:     [16]u8,
	peer:     [16]u8,
}

Route :: struct {
	family: u32,
	plen:   u32,
	has_gw: u32,
	metric: u32,
	dst:    [16]u8,
	gw:     [16]u8,
}

Event :: struct {
	kind:   Event_Kind,
	peer_id: u32,
	key_id: u32,
	reason: Del_Reason,
	addr:   Sockaddr_Storage,
}

Log :: struct {
	level: u32,
	text:  [LOG_MAX]u8,
}

// `Ctrl_Tx` and `Ctrl_Rx`: the peer id, then the record without its 2-byte length
// prefix, to the end of the message.
Ctrl :: struct {
	peer_id: u32,
}

// Messages that may carry a TCP record: `New_Peer` with a stream (read-ahead
// bytes follow its body), `Ctrl_Tx`, `Ctrl_Rx`. Others stay within `MSG_MAX`.
MSG_MAX_STREAM :: size_of(Hdr) + size_of(New_Peer) + STREAM_REC_MAX

#assert(size_of(Hdr) == 8)
#assert(size_of(Hello) == 4)
#assert(size_of(Hello_Reply) == 44)
#assert(size_of(Open) == 32)
#assert(size_of(Open_Reply) == 8)
#assert(size_of(Sockaddr_Storage) == 128)
#assert(align_of(Sockaddr_Storage) == 8)
#assert(size_of(New_Peer) == 288)
#assert(size_of(Set_Peer) == 16)
#assert(size_of(Peer_Id) == 4)
#assert(size_of(Set_Peer_Id) == 8)
#assert(size_of(Set_Peer_Addr) == 28)
#assert(size_of(Set_Filter) == 4)
#assert(size_of(Filter_Stats) == 16)
#assert(size_of(New_Key) == 164)
#assert(size_of(Del_Key) == 8)
#assert(size_of(Key) == 160)
#assert(size_of(Key_Id) == 8)
#assert(size_of(Peer_Stats) == 128)
#assert(offset_of(Peer_Stats, rx_src) == 120)
#assert(size_of(Link_Set) == 8)
#assert(size_of(Addr) == 44)
#assert(size_of(Route) == 48)
#assert(size_of(Event) == 144)
#assert(size_of(Log) == 4 + LOG_MAX)
#assert(size_of(Ctrl) == 4)
#assert(MSG_MAX_STREAM == 8 + 288 + 65535)

// ---------------------------------------------------------------- addresses

// A socket address for an IPv4 endpoint: `sockaddr_in`, port and address in
// network byte order.
sockaddr_v4 :: proc "contextless" (addr: [4]u8, port: u16) -> (ss: Sockaddr_Storage) {
	(^u16)(&ss.b[0])^ = AF_INET // the family is in host order
	ss.b[2] = u8(port >> 8)
	ss.b[3] = u8(port)
	a := addr
	copy(ss.b[4:8], a[:])
	return
}

// A socket address for an IPv6 endpoint: `sockaddr_in6` with flow info and
// scope 0.
sockaddr_v6 :: proc "contextless" (addr: [16]u8, port: u16) -> (ss: Sockaddr_Storage) {
	(^u16)(&ss.b[0])^ = AF_INET6
	ss.b[2] = u8(port >> 8)
	ss.b[3] = u8(port)
	a := addr
	copy(ss.b[8:24], a[:])
	return
}

// The family and the pieces of a socket address of an event. `ok` is false for
// anything but IPv4 and IPv6. For IPv4, `addr` holds the 4 bytes first.
sockaddr_parse :: proc "contextless" (ss: ^Sockaddr_Storage) -> (family: int, addr: [16]u8, port: u16, ok: bool) {
	family = int((^u16)(&ss.b[0])^)
	port = u16(ss.b[2]) << 8 | u16(ss.b[3])
	switch family {
	case AF_INET:
		copy(addr[:4], ss.b[4:8])
		return family, addr, port, true
	case AF_INET6:
		copy(addr[:], ss.b[8:24])
		return family, addr, port, true
	}
	return family, addr, port, false
}

// The text of a status or an errno (a negative number), for logs.
status_text :: proc "contextless" (status: int) -> string {
	switch status {
	case 0:
		return "ok"
	case -1:
		return "EPERM"
	case ENOENT:
		return "ENOENT"
	case ENOBUFS:
		return "ENOBUFS"
	case EIO:
		return "EIO"
	case -11:
		return "EAGAIN"
	case -12:
		return "ENOMEM"
	case -13:
		return "EACCES"
	case EEXIST:
		return "EEXIST"
	case -19:
		return "ENODEV"
	case EINVAL:
		return "EINVAL"
	case -24:
		return "EMFILE"
	case EPIPE:
		return "EPIPE"
	case EPROTO:
		return "EPROTO"
	case EMSGSIZE:
		return "EMSGSIZE"
	case EPROTONOSUPPORT:
		return "EPROTONOSUPPORT"
	case -97:
		return "EAFNOSUPPORT"
	case -98:
		return "EADDRINUSE"
	case ECONNRESET:
		return "ECONNRESET"
	case ENOTCONN:
		return "ENOTCONN"
	case -111:
		return "ECONNREFUSED"
	}
	return "error"
}
