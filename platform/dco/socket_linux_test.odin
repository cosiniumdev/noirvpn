// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package dco

import "core:mem"
import "core:strings"
import "core:sys/linux"
import "core:testing"

// The tests play the service on the other end of a socketpair. SEQPACKET keeps
// messages in order, so a test queues the "service" responses first, calls the
// client, then reads what it sent.

Fake :: struct {
	fd:   i32, // the service's end
	buf:  [MSG_MAX_STREAM]u8, // the last request read by `fake_recv`
	logs: [dynamic]string,
	lvls: [dynamic]Log_Level,
}

fake_start :: proc(t: ^testing.T, f: ^Fake, c: ^Conn) -> bool {
	pair: [2]linux.Fd
	if e := linux.socketpair(.UNIX, .SEQPACKET, .UNSPECIFIED, &pair); e != .NONE {
		testing.fail_now(t, "socketpair failed")
	}
	f.fd = i32(pair[0])
	c.fd = i32(pair[1])
	c.log = proc(user: rawptr, level: Log_Level, text: string) {
		f := (^Fake)(user)
		append(&f.logs, strings.clone(text))
		append(&f.lvls, level)
	}
	c.log_user = f
	return true
}

fake_stop :: proc(f: ^Fake, c: ^Conn) {
	linux.close(linux.Fd(f.fd))
	if c.fd >= 0 {
		disconnect(c)
	}
	for s in f.logs {
		delete(s)
	}
	delete(f.logs)
	delete(f.lvls)
}

// A message from the service. `body` may be nil.
fake_send :: proc(f: ^Fake, type: Msg, flags: u16, status: i32, body: rawptr = nil, body_len := 0) {
	buf: [MSG_MAX_STREAM]u8
	h := Hdr {
		type   = u16(type),
		flags  = flags,
		status = status,
	}
	mem.copy(&buf[0], &h, size_of(h))
	if body_len > 0 {
		mem.copy(&buf[size_of(h)], body, body_len)
	}
	n, _ := linux.send(linux.Fd(f.fd), buf[:size_of(h) + body_len], {})
	assert(n == size_of(h) + body_len)
}

fake_reply :: proc(f: ^Fake, type: Msg, status: i32, body: rawptr = nil, body_len := 0) {
	fake_send(f, type, F_REPLY, status, body, body_len)
}

// `len` is the size of the reply body: 40 is a service from before `caps`.
fake_hello :: proc(f: ^Fake, version: u32 = PROTO_VERSION, caps: u32 = 0, len := size_of(Hello_Reply)) {
	rep: [64]u8
	h := Hello_Reply {
		version   = version,
		max_pairs = 8,
		caps      = caps,
	}
	copy(h.daemon[:], "fake 0.1")
	mem.copy(&rep[0], &h, size_of(h))
	fake_reply(f, .Hello, 0, &rep[0], len)
}

// A request of the client: header, body, and the fd that came with it (-1 if none).
fake_recv :: proc(f: ^Fake) -> (h: Hdr, body: []u8, fd: i32, ok: bool) {
	ctl: [3]u64
	iov := [1]linux.IO_Vec{{base = &f.buf[0], len = len(f.buf)}}
	msg := linux.Msg_Hdr {
		iov     = iov[:],
		control = ([^]u8)(&ctl)[:size_of(ctl)],
	}
	n, e := linux.recvmsg(linux.Fd(f.fd), &msg, {.DONTWAIT})
	if e != .NONE || n < size_of(Hdr) {
		return {}, nil, -1, false
	}
	mem.copy(&h, &f.buf[0], size_of(Hdr))
	fd = -1
	if len(msg.control) >= CMSG_HDR_SIZE + 4 {
		ch: Cmsg_Hdr
		mem.copy(&ch, raw_data(msg.control), size_of(ch))
		if ch.level == SOL_SOCKET && ch.type == SCM_RIGHTS {
			mem.copy(&fd, raw_data(msg.control)[CMSG_HDR_SIZE:], 4)
		}
	}
	return h, f.buf[size_of(Hdr):n], fd, true
}

event_bytes :: proc(ev: ^Event) -> []u8 {
	return ([^]u8)(ev)[:size_of(Event)]
}

// ------------------------------------------------------------------ layouts

@(test)
test_layouts :: proc(t: ^testing.T) {
	testing.expect_value(t, offset_of(Hdr, flags), 2)
	testing.expect_value(t, offset_of(Hdr, status), 4)
	testing.expect_value(t, offset_of(Hello_Reply, max_pairs), 4)
	testing.expect_value(t, offset_of(Hello_Reply, daemon), 8)
	testing.expect_value(t, offset_of(Hello_Reply, caps), 40)
	testing.expect_value(t, offset_of(Open, dataplane), 16)
	testing.expect_value(t, offset_of(Open, flags), 28)
	testing.expect_value(t, offset_of(New_Peer, local), 8)
	testing.expect_value(t, offset_of(New_Peer, remote), 136)
	testing.expect_value(t, offset_of(New_Peer, vpn4), 264)
	testing.expect_value(t, offset_of(New_Peer, vpn6), 268)
	testing.expect_value(t, offset_of(Set_Peer, mss), 12)
	testing.expect_value(t, offset_of(New_Key, key_len), 16)
	testing.expect_value(t, offset_of(New_Key, enc_key), 20)
	testing.expect_value(t, offset_of(New_Key, enc_nonce), 84)
	testing.expect_value(t, offset_of(New_Key, dec_key), 92)
	testing.expect_value(t, offset_of(New_Key, dec_nonce), 156)
	testing.expect_value(t, offset_of(Key, key_len), 12)
	testing.expect_value(t, offset_of(Key, enc_key), 16)
	testing.expect_value(t, offset_of(Key, enc_nonce), 80)
	testing.expect_value(t, offset_of(Key, dec_key), 88)
	testing.expect_value(t, offset_of(Key, dec_nonce), 152)
	testing.expect_value(t, offset_of(Peer_Stats, rx_drops), 64)
	testing.expect_value(t, offset_of(Peer_Stats, tx_drops), 72)
	testing.expect_value(t, offset_of(Peer_Stats, rx_no_key), 80)
	testing.expect_value(t, offset_of(Peer_Stats, tx_no_key), 112)
	testing.expect_value(t, offset_of(Peer_Stats, rx_src), 120)
	testing.expect_value(t, offset_of(Addr, peer), 28)
	testing.expect_value(t, offset_of(Route, gw), 32)
	testing.expect_value(t, offset_of(Event, addr), 16)
	testing.expect_value(t, offset_of(Log, text), 4)
	testing.expect_value(t, size_of(Hdr), 8)
	testing.expect_value(t, size_of(New_Peer), 288)
	testing.expect_value(t, size_of(New_Key), 164)
	testing.expect_value(t, size_of(Event), 144)
	testing.expect_value(t, size_of(Peer_Stats), 128)
	testing.expect_value(t, size_of(Hello_Reply), 44)
	testing.expect_value(t, size_of(Key), 160)
	testing.expect_value(t, size_of(Key_Id), 8)
	testing.expect_value(t, size_of(Ctrl), 4)
	testing.expect_value(t, size_of(Set_Peer_Id), 8)
	testing.expect_value(t, offset_of(Set_Peer_Id, new_id), 4)
	testing.expect_value(t, size_of(Set_Peer_Addr), 28)
	testing.expect_value(t, offset_of(Set_Peer_Addr, flags), 4)
	testing.expect_value(t, offset_of(Set_Peer_Addr, vpn4), 8)
	testing.expect_value(t, offset_of(Set_Peer_Addr, vpn6), 12)
	testing.expect_value(t, size_of(Set_Filter), 4)
	testing.expect_value(t, size_of(Filter_Stats), 16)
	testing.expect_value(t, offset_of(Filter_Stats, tx_v6), 8)
	// The messages that carry a TCP record: header, the largest body (NEW_PEER) and a record.
	testing.expect_value(t, MSG_MAX_STREAM, 8 + 288 + 65535)
	testing.expect_value(t, STREAM_REC_MAX, 65535)
	testing.expect(t, MSG_MAX_STREAM > MSG_MAX)
	// The numbers of the enums.
	testing.expect_value(t, u16(Msg.Hello), 1)
	testing.expect_value(t, u16(Msg.Swap_Keys), 10)
	testing.expect_value(t, u16(Msg.Ping), 17)
	testing.expect_value(t, u16(Msg.Key_Add), 18)
	testing.expect_value(t, u16(Msg.Key_Tx), 19)
	testing.expect_value(t, u16(Msg.Key_Drop), 20)
	testing.expect_value(t, CAP_KEY_TABLE, 1)
	testing.expect_value(t, CAP_STATS_REASONS, 2)
	testing.expect_value(t, CAP_TCP, 4)
	testing.expect_value(t, u16(Msg.Ctrl_Tx), 21)
	testing.expect_value(t, u16(Msg.Set_Peer_Id), 22)
	testing.expect_value(t, CAP_PEER_ID, 8)
	testing.expect_value(t, u16(Msg.Set_Peer_Addr), 23)
	testing.expect_value(t, CAP_PEER_ADDR, 16)
	testing.expect_value(t, u16(Msg.Set_Filter), 24)
	testing.expect_value(t, CAP_BLOCK_IPV6, 32)
	testing.expect_value(t, FILTER_IPV6, 1)
	testing.expect_value(t, PEER_ID_LIMIT, 0xffffff)
	testing.expect_value(t, u16(Msg.Event), 64)
	testing.expect_value(t, u16(Msg.Log), 65)
	testing.expect_value(t, u16(Msg.Ctrl_Rx), 66)
	testing.expect_value(t, u32(Del_Reason.Transport_Error), 3)
	testing.expect_value(t, u32(Cipher.Aes_Gcm), 1)
	testing.expect_value(t, u32(Cipher.Chacha20_Poly1305), 2)
	testing.expect_value(t, u32(Key_Slot.Secondary), 1)
	testing.expect_value(t, u32(Del_Reason.Transport_Disconnect), 4)
	testing.expect_value(t, u32(Event_Kind.Key_Swap), 3)
	testing.expect_value(t, u32(Log_Level.Debug), 3)
	testing.expect_value(t, u32(Mode.Mp), 1)
	testing.expect_value(t, OPT_NO_TUN_OFFLOAD, 16)
	testing.expect_value(t, PEER_VPN6, 8)
}

@(test)
test_sockaddr :: proc(t: ^testing.T) {
	ss := sockaddr_v4({192, 0, 2, 7}, 1194)
	testing.expect_value(t, ss.b[0], 2)
	testing.expect_value(t, ss.b[1], 0)
	testing.expect_value(t, ss.b[2], 0x04) // the port is in network order
	testing.expect_value(t, ss.b[3], 0xaa)
	testing.expect_value(t, ss.b[4], 192)
	testing.expect_value(t, ss.b[7], 7)
	testing.expect_value(t, ss.b[8], 0)
	fam, a, port, ok := sockaddr_parse(&ss)
	testing.expect(t, ok)
	testing.expect_value(t, fam, AF_INET)
	testing.expect_value(t, port, 1194)
	testing.expect_value(t, a[0], 192)
	testing.expect_value(t, a[3], 7)

	a6: [16]u8
	a6[0], a6[1], a6[15] = 0x20, 0x01, 1
	s6 := sockaddr_v6(a6, 443)
	testing.expect_value(t, s6.b[0], 10)
	testing.expect_value(t, s6.b[2], 0x01)
	testing.expect_value(t, s6.b[3], 0xbb)
	testing.expect_value(t, s6.b[8], 0x20)
	testing.expect_value(t, s6.b[23], 1)
	fam, a, port, ok = sockaddr_parse(&s6)
	testing.expect(t, ok)
	testing.expect_value(t, fam, AF_INET6)
	testing.expect_value(t, port, 443)
	testing.expect_value(t, a, a6)

	bad: Sockaddr_Storage
	_, _, _, ok = sockaddr_parse(&bad)
	testing.expect(t, !ok)
}

// -------------------------------------------------------------------- hello

@(test)
test_hello :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	fake_start(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_hello(&f)
	testing.expect_value(t, attach(&c, c.fd), 0)
	testing.expect_value(t, daemon_name(&c), "fake 0.1")
	testing.expect_value(t, c.hello.max_pairs, 8)
	h, body, fd, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Hello))
	testing.expect_value(t, h.flags, 0)
	testing.expect_value(t, h.status, 0)
	testing.expect_value(t, len(body), 4)
	testing.expect_value(t, fd, -1)
	testing.expect_value(t, (^u32)(raw_data(body))^, 1)
}

@(test)
test_hello_caps_and_reply_lengths :: proc(t: ^testing.T) {
	// A service with both capabilities.
	f: Fake
	c: Conn
	fake_start(t, &f, &c)
	fake_hello(&f, caps = CAP_KEY_TABLE | CAP_STATS_REASONS)
	testing.expect_value(t, attach(&c, c.fd), 0)
	testing.expect_value(t, c.hello.caps, CAP_KEY_TABLE | CAP_STATS_REASONS)
	be := socket_backend(&c)
	testing.expect_value(t, be.caps, CAP_KEY_TABLE | CAP_STATS_REASONS)
	fake_stop(&f, &c)

	// An older service: the reply stops after the name, `caps` reads as 0.
	f = {}
	c = {}
	fake_start(t, &f, &c)
	fake_hello(&f, caps = 3, len = 40)
	testing.expect_value(t, attach(&c, c.fd), 0)
	testing.expect_value(t, c.hello.caps, 0)
	testing.expect_value(t, c.hello.max_pairs, 8)
	testing.expect_value(t, daemon_name(&c), "fake 0.1")
	fake_stop(&f, &c)

	// A newer service: more bytes after the fields we know are ignored.
	f = {}
	c = {}
	fake_start(t, &f, &c)
	fake_hello(&f, caps = 1, len = 60)
	testing.expect_value(t, attach(&c, c.fd), 0)
	testing.expect_value(t, c.hello.caps, 1)
	fake_stop(&f, &c)
}

@(test)
test_hello_other_version :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	fake_start(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_hello(&f, 2)
	testing.expect_value(t, attach(&c, c.fd), EPROTONOSUPPORT)
	// The connection is closed after a refusal.
	testing.expect_value(t, c.fd, -1)
}

@(test)
test_hello_refused :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	fake_start(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_reply(&f, .Hello, -1)
	testing.expect_value(t, attach(&c, c.fd), -1)
	testing.expect_value(t, c.fd, -1)
}

@(test)
test_connect_missing_socket :: proc(t: ^testing.T) {
	c: Conn
	st := connect(&c, "/nonexistent/noirvpn-dco-test.sock")
	testing.expect_value(t, st, ENOENT)
	testing.expect_value(t, c.fd, -1)
	testing.expect_value(t, connect(&c, ""), ENAMETOOLONG)
}

// ------------------------------------------------------------ requests

attached :: proc(t: ^testing.T, f: ^Fake, c: ^Conn) {
	fake_start(t, f, c)
	fake_hello(f)
	testing.expect_value(t, attach(c, c.fd), 0)
	fake_recv(f) // the HELLO
}

@(test)
test_open_and_reply_body :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	rep := Open_Reply {
		ifindex = 42,
		n_pairs = 3,
	}
	fake_reply(&f, .Open, 0, &rep, size_of(rep))
	be := socket_backend(&c)
	ifindex, st := be.open(be.user, "tun7", .Mp, OPT_NO_GSO | OPT_NO_TUN_OFFLOAD)
	testing.expect_value(t, st, 0)
	testing.expect_value(t, ifindex, 42)
	h, body, _, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Open))
	testing.expect_value(t, len(body), size_of(Open))
	req: Open
	mem.copy(&req, raw_data(body), size_of(req))
	testing.expect_value(t, string(req.ifname[:4]), "tun7")
	testing.expect_value(t, req.ifname[4], 0)
	testing.expect_value(t, req.dataplane, 1)
	testing.expect_value(t, req.mode, 1)
	testing.expect_value(t, req.n_pairs, 0)
	testing.expect_value(t, req.flags, 17)
}

@(test)
test_open_error_has_no_body :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_reply(&f, .Open, -17) // EEXIST
	_, st := open_device(&c, "tun0", .P2p, 0)
	testing.expect_value(t, st, -17)
	_, st = open_device(&c, "a-name-that-is-too-long", .P2p, 0)
	testing.expect_value(t, st, EINVAL)
	// A reply with status 0 and no body when one is due: the fields read as 0.
	fake_reply(&f, .Open, 0)
	idx: u32
	idx, st = open_device(&c, "tun0", .P2p, 0)
	testing.expect_value(t, st, 0)
	testing.expect_value(t, idx, 0)
}

@(test)
test_new_peer_passes_the_fd :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	// The fd that goes along: one end of a pipe.
	pipe: [2]linux.Fd
	testing.expect_value(t, linux.pipe2(&pipe, {}), linux.Errno.NONE)
	defer linux.close(pipe[0])
	defer linux.close(pipe[1])
	fake_reply(&f, .New_Peer, 0)
	p := New_Peer {
		peer_id = 5,
		flags   = PEER_REMOTE | PEER_VPN4,
		remote  = sockaddr_v4({10, 0, 0, 2}, 1194),
		vpn4    = {10, 8, 0, 2},
	}
	be := socket_backend(&c)
	testing.expect_value(t, be.new_peer(be.user, &p, i32(pipe[0])), 0)
	h, body, fd, ok := fake_recv(&f)
	testing.expect(t, ok)
	defer if fd >= 0 {
		linux.close(linux.Fd(fd))
	}
	testing.expect_value(t, h.type, u16(Msg.New_Peer))
	testing.expect_value(t, h.flags, F_FD)
	testing.expect_value(t, len(body), 288)
	got: New_Peer
	mem.copy(&got, raw_data(body), 288)
	testing.expect_value(t, got.peer_id, 5)
	testing.expect_value(t, got.remote.b[4], 10)
	testing.expect_value(t, got.vpn4, [4]u8{10, 8, 0, 2})
	// The fd that arrived is the read end of our pipe.
	testing.expect(t, fd >= 0 && fd != i32(pipe[0]))
	data := [3]u8{1, 2, 3}
	linux.write(pipe[1], data[:])
	in_buf: [3]u8
	n, _ := linux.read(linux.Fd(fd), in_buf[:])
	testing.expect_value(t, n, 3)
	testing.expect_value(t, in_buf, data)

	// Without an fd the flag is off and there is no control message.
	fake_reply(&f, .New_Peer, 0)
	testing.expect_value(t, new_peer(&c, &p), 0)
	h, _, fd, ok = fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.flags, 0)
	testing.expect_value(t, fd, -1)
}

@(test)
test_new_key_layout_on_the_wire :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	k := New_Key {
		peer_id   = 9,
		slot      = u32(Key_Slot.Secondary),
		key_id    = 3,
		cipher    = u32(Cipher.Chacha20_Poly1305),
		key_len   = 32,
		enc_nonce = {1, 2, 3, 4, 5, 6, 7, 8},
		dec_nonce = {8, 7, 6, 5, 4, 3, 2, 1},
	}
	for i in 0 ..< 32 {
		k.enc_key[i] = u8(i)
		k.dec_key[i] = u8(100 + i)
	}
	fake_reply(&f, .New_Key, 0)
	testing.expect_value(t, new_key(&c, &k), 0)
	h, body, _, _ := fake_recv(&f)
	testing.expect_value(t, h.type, u16(Msg.New_Key))
	testing.expect_value(t, len(body), 164)
	testing.expect_value(t, (^u32)(&body[0])^, 9)
	testing.expect_value(t, (^u32)(&body[4])^, 1)
	testing.expect_value(t, (^u32)(&body[8])^, 3)
	testing.expect_value(t, (^u32)(&body[12])^, 2)
	testing.expect_value(t, (^u32)(&body[16])^, 32)
	testing.expect_value(t, body[20 + 31], 31)
	testing.expect_value(t, body[84], 1)
	testing.expect_value(t, body[92], 100)
	testing.expect_value(t, body[156], 8)
}

@(test)
test_set_peer_swap_del_key_del_peer_detach :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	for ty in ([]Msg{.Set_Peer, .Swap_Keys, .Del_Key, .Del_Peer, .Detach}) {
		fake_reply(&f, ty, 0)
	}
	be := socket_backend(&c)
	sp := Set_Peer {
		peer_id            = 2,
		keepalive_interval = 10,
		keepalive_timeout  = 60,
		mss                = 1300,
	}
	testing.expect_value(t, be.set_peer(be.user, &sp), 0)
	testing.expect_value(t, be.swap_keys(be.user, 2), 0)
	testing.expect_value(t, be.del_key(be.user, 2, .Secondary), 0)
	testing.expect_value(t, be.del_peer(be.user, 2), 0)
	testing.expect_value(t, be.detach(be.user), 0)
	types := []Msg{.Set_Peer, .Swap_Keys, .Del_Key, .Del_Peer, .Detach}
	lens := []int{16, 4, 8, 4, 0}
	for ty, i in types {
		h, body, _, ok := fake_recv(&f)
		testing.expect(t, ok)
		testing.expect_value(t, h.type, u16(ty))
		testing.expect_value(t, len(body), lens[i])
	}
}

@(test)
test_stats_reply :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	st := Peer_Stats {
		vpn_rx_bytes    = 1,
		vpn_tx_bytes    = 2,
		vpn_rx_packets  = 3,
		vpn_tx_packets  = 4,
		link_rx_bytes   = 5,
		link_tx_bytes   = 6,
		link_rx_packets = 7,
		link_tx_packets = 8,
		rx_drops        = 9,
		tx_drops        = 10,
	}
	fake_reply(&f, .Peer_Stats, 0, &st, size_of(st))
	out: Peer_Stats
	be := socket_backend(&c)
	testing.expect_value(t, be.stats(be.user, 7, &out), 0)
	testing.expect_value(t, out, st)
	// An error reply leaves `out` alone.
	fake_reply(&f, .Peer_Stats, ENOENT)
	out = {}
	testing.expect_value(t, be.stats(be.user, 8, &out), ENOENT)
	testing.expect_value(t, out, Peer_Stats{})
}

@(test)
test_stats_reply_lengths :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	st := Peer_Stats {
		rx_drops  = 9,
		tx_drops  = 10,
		rx_no_key = 1,
		rx_replay = 2,
		rx_auth   = 3,
		rx_bad    = 4,
		tx_no_key = 5,
	}
	be := socket_backend(&c)
	// An older service sends the first ten counters only: the reasons are 0.
	fake_reply(&f, .Peer_Stats, 0, &st, 80)
	out := Peer_Stats {
		rx_auth = 77, // what is there is cleared
	}
	testing.expect_value(t, be.stats(be.user, 7, &out), 0)
	testing.expect_value(t, out.rx_drops, 9)
	testing.expect_value(t, out.tx_drops, 10)
	testing.expect_value(t, out.rx_auth, 0)
	testing.expect_value(t, out.tx_no_key, 0)
	// A service from before `rx_src`: 120 bytes, `rx_src` reads as 0.
	st.rx_src = 9
	fake_reply(&f, .Peer_Stats, 0, &st, 120)
	testing.expect_value(t, be.stats(be.user, 7, &out), 0)
	testing.expect_value(t, out.tx_no_key, 5)
	testing.expect_value(t, out.rx_src, 0)
	// A service with the reasons.
	fake_reply(&f, .Peer_Stats, 0, &st, size_of(st))
	testing.expect_value(t, be.stats(be.user, 7, &out), 0)
	testing.expect_value(t, out, st)
	// A newer one with more fields: the rest is cut.
	big: [200]u8
	mem.copy(&big[0], &st, size_of(st))
	fake_reply(&f, .Peer_Stats, 0, &big[0], 200)
	testing.expect_value(t, be.stats(be.user, 7, &out), 0)
	testing.expect_value(t, out, st)
}

@(test)
test_key_table_calls :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	for ty in ([]Msg{.Key_Add, .Key_Tx, .Key_Drop}) {
		fake_reply(&f, ty, 0)
	}
	k := Key {
		peer_id   = 9,
		key_id    = 6,
		cipher    = u32(Cipher.Aes_Gcm),
		key_len   = 16,
		enc_nonce = {1, 2, 3, 4, 5, 6, 7, 8},
		dec_nonce = {8, 7, 6, 5, 4, 3, 2, 1},
	}
	for i in 0 ..< 16 {
		k.enc_key[i] = u8(i)
		k.dec_key[i] = u8(50 + i)
	}
	be := socket_backend(&c)
	testing.expect_value(t, be.key_add(be.user, &k), 0)
	testing.expect_value(t, be.key_tx(be.user, 9, 6), 0)
	testing.expect_value(t, be.key_drop(be.user, 9, 5), 0)

	h, body, _, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Key_Add))
	testing.expect_value(t, len(body), 160)
	testing.expect_value(t, (^u32)(&body[0])^, 9)
	testing.expect_value(t, (^u32)(&body[4])^, 6)
	testing.expect_value(t, (^u32)(&body[8])^, 1)
	testing.expect_value(t, (^u32)(&body[12])^, 16)
	testing.expect_value(t, body[16 + 15], 15)
	testing.expect_value(t, body[80], 1)
	testing.expect_value(t, body[88], 50)
	testing.expect_value(t, body[152], 8)
	h, body, _, ok = fake_recv(&f)
	testing.expect_value(t, h.type, u16(Msg.Key_Tx))
	testing.expect_value(t, len(body), 8)
	testing.expect_value(t, (^u32)(&body[0])^, 9)
	testing.expect_value(t, (^u32)(&body[4])^, 6)
	h, body, _, ok = fake_recv(&f)
	testing.expect_value(t, h.type, u16(Msg.Key_Drop))
	testing.expect_value(t, len(body), 8)
	testing.expect_value(t, (^u32)(&body[4])^, 5)
}

// ------------------------------------------------- events, logs, loss

@(test)
test_events_between_request_and_reply :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	ev1 := Event {
		kind    = .Peer_Del,
		peer_id = 4,
		reason  = .Expired,
	}
	ev2 := Event {
		kind    = .Key_Swap,
		peer_id = 4,
		key_id  = 2,
	}
	ev3 := Event {
		kind    = .Peer_Float,
		peer_id = 5,
		addr    = sockaddr_v4({192, 0, 2, 9}, 4000),
	}
	text := Log {
		level = u32(Log_Level.Warn),
	}
	copy(text.text[:], "a warning")
	fake_send(&f, .Event, 0, 0, &ev1, size_of(ev1))
	fake_send(&f, .Log, 0, 0, &text, 4 + len("a warning") + 1) // up to and with the NUL
	fake_send(&f, .Event, 0, 0, &ev2, size_of(ev2))
	// A reply of some other request (the PING of an earlier call) is dropped.
	fake_reply(&f, .Ping, 0)
	fake_reply(&f, .Set_Peer, 0)
	fake_send(&f, .Event, 0, 0, &ev3, size_of(ev3))
	sp := Set_Peer {
		peer_id = 4,
	}
	testing.expect_value(t, set_peer(&c, &sp), 0)

	// The client asked for a PING, so a poll loop sees the socket readable.
	h, _, _, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Set_Peer))
	h, _, _, ok = fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Ping))
	testing.expect_value(t, h.flags, 0)

	testing.expect_value(t, len(f.logs), 1)
	testing.expect_value(t, f.logs[0], "a warning")
	testing.expect_value(t, f.lvls[0], Log_Level.Warn)

	// The two events that came before the reply are queued, in order; the
	// third is still in the socket and comes after them.
	ev: Event
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Peer_Del)
	testing.expect_value(t, ev.reason, Del_Reason.Expired)
	testing.expect_value(t, ev.peer_id, 4)
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Key_Swap)
	testing.expect_value(t, ev.key_id, 2)
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Peer_Float)
	fam, a, port, pok := sockaddr_parse(&ev.addr)
	testing.expect(t, pok)
	testing.expect_value(t, fam, AF_INET)
	testing.expect_value(t, port, 4000)
	testing.expect_value(t, a[3], 9)
	testing.expect_value(t, next_event(&c, &ev), 0)
}

@(test)
test_no_ping_without_queued_events :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_reply(&f, .Del_Peer, 0)
	testing.expect_value(t, del_peer(&c, 1), 0)
	_, _, _, ok := fake_recv(&f)
	testing.expect(t, ok)
	_, _, _, ok = fake_recv(&f)
	testing.expect(t, !ok)
}

@(test)
test_next_event_reads_the_socket :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	ev: Event
	testing.expect_value(t, next_event(&c, &ev), 0)
	out := Event {
		kind   = .Peer_Del,
		peer_id = 77,
		reason = .Transport_Error,
	}
	logm := Log {
		level = u32(Log_Level.Debug),
	}
	copy(logm.text[:], "hello")
	fake_send(&f, .Log, 0, 0, &logm, 4 + 6)
	fake_send(&f, .Event, 0, 0, &out, size_of(out))
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.peer_id, 77)
	testing.expect_value(t, ev.reason, Del_Reason.Transport_Error)
	testing.expect_value(t, len(f.logs), 1)
	testing.expect_value(t, f.lvls[0], Log_Level.Debug)
	testing.expect_value(t, next_event(&c, &ev), 0)
}

@(test)
test_log_levels_and_odd_messages :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	// A log text without a NUL at the end, a log message with no text, an
	// event that is too short: none of them breaks the reading.
	for lvl in ([]Log_Level{.Error, .Warn, .Info, .Debug}) {
		m := Log {
			level = u32(lvl),
		}
		copy(m.text[:], "x")
		fake_send(&f, .Log, 0, 0, &m, 4 + 1)
	}
	short_log := u32(2)
	fake_send(&f, .Log, 0, 0, &short_log, 4)
	short_ev: [10]u8
	fake_send(&f, .Event, 0, 0, &short_ev, 10)
	// A message with less than a header.
	junk: [3]u8
	linux.send(linux.Fd(f.fd), junk[:], {})
	ev: Event
	testing.expect_value(t, next_event(&c, &ev), 0)
	testing.expect_value(t, len(f.logs), 4)
	testing.expect_value(t, f.lvls[0], Log_Level.Error)
	testing.expect_value(t, f.lvls[3], Log_Level.Debug)
	testing.expect_value(t, f.logs[0], "x")
}

@(test)
test_event_queue_is_bounded :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	// Fill the queue by hand: the socket buffer is smaller than the limit.
	for _ in 0 ..< EVENT_QUEUE_MAX {
		append(&c.events, Event{kind = .Key_Swap})
	}
	ev := Event {
		kind = .Peer_Del,
	}
	fake_send(&f, .Event, 0, 0, &ev, size_of(ev))
	fake_reply(&f, .Del_Peer, 0)
	testing.expect_value(t, del_peer(&c, 1), 0)
	testing.expect_value(t, c.dropped, 1)
	testing.expect_value(t, len(c.events), EVENT_QUEUE_MAX)
	testing.expect_value(t, len(f.logs), 1)
}

@(test)
test_connection_lost :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	ev := Event {
		kind    = .Peer_Del,
		peer_id = 1,
	}
	fake_send(&f, .Event, 0, 0, &ev, size_of(ev))
	// The service goes away before it responds.
	linux.close(linux.Fd(f.fd))
	f.fd = -1
	st := del_peer(&c, 1)
	testing.expect(t, st < 0)
	testing.expect(t, c.lost)
	// The event that came first is still there, then the loss is reported.
	out: Event
	testing.expect_value(t, next_event(&c, &out), 1)
	testing.expect_value(t, out.kind, Event_Kind.Peer_Del)
	testing.expect_value(t, next_event(&c, &out), ECONNRESET)
}

@(test)
test_call_after_disconnect :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	disconnect(&c)
	testing.expect_value(t, del_peer(&c, 1), ENOTCONN)
	ev: Event
	testing.expect_value(t, next_event(&c, &ev), ENOTCONN)
}

// ------------------------------------------------------------- TCP peers

// The body of a CTRL_TX or CTRL_RX message: the peer id, then the record.
ctrl_msg :: proc(peer_id: u32, rec: []u8) -> []u8 {
	b := make([]u8, size_of(Ctrl) + len(rec))
	p := Ctrl {
		peer_id = peer_id,
	}
	mem.copy(&b[0], &p, size_of(p))
	copy(b[size_of(p):], rec)
	return b
}

@(test)
test_new_peer_stream_carries_read_ahead :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	pipe: [2]linux.Fd
	testing.expect_value(t, linux.pipe2(&pipe, {}), linux.Errno.NONE)
	defer linux.close(pipe[0])
	defer linux.close(pipe[1])
	p := New_Peer {
		peer_id = 9,
		flags   = PEER_REMOTE,
		remote  = sockaddr_v4({10, 0, 0, 2}, 1194),
	}
	be := socket_backend(&c)
	ahead := [5]u8{0, 9, 0x38, 1, 2} // part of a record
	fake_reply(&f, .New_Peer, 0)
	testing.expect_value(t, be.new_peer_stream(be.user, &p, i32(pipe[0]), ahead[:]), 0)
	h, body, fd, ok := fake_recv(&f)
	testing.expect(t, ok)
	defer if fd >= 0 {
		linux.close(linux.Fd(fd))
	}
	testing.expect_value(t, h.type, u16(Msg.New_Peer))
	testing.expect_value(t, h.flags, F_FD)
	testing.expect(t, fd >= 0)
	// The body is followed by the bytes, in the same message.
	testing.expect_value(t, len(body), 288 + 5)
	got: New_Peer
	mem.copy(&got, raw_data(body), 288)
	testing.expect_value(t, got.peer_id, 9)
	testing.expect_value(t, string(body[288:]), string(ahead[:]))

	// No bytes read: the message is the plain NEW_PEER. No fd is an error here.
	fake_reply(&f, .New_Peer, 0)
	testing.expect_value(t, new_peer_stream(&c, &p, i32(pipe[0])), 0)
	_, body2, fd2, ok2 := fake_recv(&f)
	testing.expect(t, ok2)
	testing.expect_value(t, len(body2), 288)
	if fd2 >= 0 {
		linux.close(linux.Fd(fd2))
	}
	testing.expect_value(t, new_peer_stream(&c, &p, -1), EINVAL)

	// The largest read-ahead is a whole record: the message is MSG_MAX_STREAM bytes.
	big := make([]u8, STREAM_REC_MAX)
	defer delete(big)
	for i in 0 ..< len(big) {
		big[i] = u8(i * 7)
	}
	fake_reply(&f, .New_Peer, 0)
	testing.expect_value(t, new_peer_stream(&c, &p, i32(pipe[0]), big), 0)
	_, body2, fd2, ok2 = fake_recv(&f)
	testing.expect(t, ok2)
	testing.expect_value(t, len(body2), 288 + STREAM_REC_MAX)
	testing.expect(t, string(body2[288:]) == string(big))
	if fd2 >= 0 {
		linux.close(linux.Fd(fd2))
	}
	// One byte more is too much.
	over := make([]u8, STREAM_REC_MAX + 1)
	defer delete(over)
	testing.expect_value(t, new_peer_stream(&c, &p, i32(pipe[0]), over), EMSGSIZE)
	// A NEW_PEER for a UDP socket has no tail, and every other message stays within MSG_MAX.
	testing.expect_value(t, call(&c, .Set_Peer, &p, 1000, nil, 0, -1, big[:100]), EMSGSIZE)
}

@(test)
test_ctrl_tx_on_the_wire :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	be := socket_backend(&c)
	rec := [4]u8{0x38, 0xaa, 0xbb, 0xcc}
	fake_reply(&f, .Ctrl_Tx, 0)
	testing.expect_value(t, be.ctrl_tx(be.user, 12, rec[:]), 0)
	h, body, fd, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Ctrl_Tx))
	testing.expect_value(t, h.flags, 0)
	testing.expect_value(t, fd, -1)
	testing.expect_value(t, len(body), 4 + 4)
	id: u32
	mem.copy(&id, raw_data(body), 4)
	testing.expect_value(t, id, 12)
	testing.expect_value(t, string(body[4:]), string(rec[:]))

	// The status codes of the reply.
	for st in ([]i32{-2, -107, -105}) {
		fake_reply(&f, .Ctrl_Tx, st)
		testing.expect_value(t, ctrl_tx(&c, 12, rec[:]), int(st))
		fake_recv(&f)
	}
	testing.expect_value(t, status_text(ENOBUFS), "ENOBUFS")

	// A record of 1 to 65535 bytes. Nothing, or more, is refused before it is sent.
	testing.expect_value(t, ctrl_tx(&c, 12, nil), EMSGSIZE)
	big := make([]u8, STREAM_REC_MAX)
	defer delete(big)
	for i in 0 ..< len(big) {
		big[i] = u8(i)
	}
	fake_reply(&f, .Ctrl_Tx, 0)
	testing.expect_value(t, ctrl_tx(&c, 12, big), 0)
	h, body, _, ok = fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, len(body), 4 + STREAM_REC_MAX)
	testing.expect_value(t, string(body[4:]), string(big))
	over := make([]u8, STREAM_REC_MAX + 1)
	defer delete(over)
	testing.expect_value(t, ctrl_tx(&c, 12, over), EMSGSIZE)
	_, _, _, ok = fake_recv(&f)
	testing.expect(t, !ok)
}

@(test)
test_ctrl_rx_joins_the_events :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	rec1 := [3]u8{1, 2, 3}
	rec2 := [2]u8{4, 5}
	m1 := ctrl_msg(7, rec1[:])
	m2 := ctrl_msg(8, rec2[:])
	defer delete(m1)
	defer delete(m2)
	del := Event {
		kind    = .Peer_Del,
		peer_id = 7,
		reason  = .Transport_Disconnect,
	}
	// Records arrive while a request waits, between events: they keep their place.
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m1), len(m1))
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m2), len(m2))
	fake_send(&f, .Event, 0, 0, &del, size_of(del))
	fake_reply(&f, .Set_Peer, 0)
	// One that the socket still has after the reply.
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m1), len(m1))
	sp := Set_Peer {
		peer_id = 7,
	}
	testing.expect_value(t, set_peer(&c, &sp), 0)
	// The call asked for a PING, as for any queued event.
	_, _, _, ok := fake_recv(&f)
	testing.expect(t, ok)
	h, _, _, ok2 := fake_recv(&f)
	testing.expect(t, ok2)
	testing.expect_value(t, h.type, u16(Msg.Ping))

	ev: Event
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Ctrl_Rx)
	testing.expect_value(t, ev.peer_id, 7)
	testing.expect_value(t, ev.key_id, 3)
	testing.expect_value(t, string(ctrl_record(&c)), string(rec1[:]))
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Ctrl_Rx)
	testing.expect_value(t, ev.peer_id, 8)
	testing.expect_value(t, string(ctrl_record(&c)), string(rec2[:]))
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Peer_Del)
	testing.expect_value(t, ev.reason, Del_Reason.Transport_Disconnect)
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Ctrl_Rx)
	testing.expect_value(t, string(ctrl_record(&c)), string(rec1[:]))
	testing.expect_value(t, next_event(&c, &ev), 0)
	testing.expect_value(t, len(c.ctrl), 0)
}

@(test)
test_ctrl_rx_largest_record_is_not_truncated :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	rec := make([]u8, STREAM_REC_MAX)
	defer delete(rec)
	for i in 0 ..< len(rec) {
		rec[i] = u8(i * 13)
	}
	m := ctrl_msg(3, rec)
	defer delete(m)
	testing.expect_value(t, len(m) + HDR_SIZE, 8 + 4 + 65535)
	// While a request waits, and from the socket without one.
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m), len(m))
	fake_reply(&f, .Del_Peer, 0)
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m), len(m))
	testing.expect_value(t, del_peer(&c, 3), 0)
	for _ in 0 ..< 2 {
		ev: Event
		testing.expect_value(t, next_event(&c, &ev), 1)
		testing.expect_value(t, ev.kind, Event_Kind.Ctrl_Rx)
		testing.expect_value(t, ev.key_id, u32(STREAM_REC_MAX))
		testing.expect(t, string(ctrl_record(&c)) == string(rec))
	}
}

@(test)
test_ctrl_rx_odd_messages :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	// A record with no bytes, a message with less than a peer id, and an event of
	// the fake kind: nothing is queued.
	only_id := u32(5)
	fake_send(&f, .Ctrl_Rx, 0, 0, &only_id, 4)
	fake_send(&f, .Ctrl_Rx, 0, 0, &only_id, 2)
	fake_send(&f, .Ctrl_Rx, 0, 0)
	fake := Event {
		kind = .Ctrl_Rx,
	}
	fake_send(&f, .Event, 0, 0, &fake, size_of(fake))
	ev: Event
	testing.expect_value(t, next_event(&c, &ev), 0)
	testing.expect_value(t, len(c.events), 0)
}

@(test)
test_del_peer_forgets_its_records :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	a := [2]u8{1, 1}
	b := [3]u8{2, 2, 2}
	ma := ctrl_msg(4, a[:])
	mb := ctrl_msg(5, b[:])
	defer delete(ma)
	defer delete(mb)
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(ma), len(ma))
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(mb), len(mb))
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(ma), len(ma))
	fake_reply(&f, .Ping, 0)
	fake_reply(&f, .Del_Peer, 0)
	// The first call stashes the records and nothing more; DEL_PEER 4 drops those of peer 4.
	testing.expect_value(t, call(&c, .Ping, nil, 0, nil, 0), 0)
	testing.expect_value(t, del_peer(&c, 4), 0)
	ev: Event
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.peer_id, 5)
	testing.expect_value(t, string(ctrl_record(&c)), string(b[:]))
	testing.expect_value(t, next_event(&c, &ev), 0)
}

@(test)
test_ctrl_queue_is_bounded :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	rec := [4]u8{9, 9, 9, 9}
	m := ctrl_msg(2, rec[:])
	defer delete(m)
	// A queue that holds as many bytes as it may: the next record is lost, with a log line.
	append(&c.events, Event{kind = .Ctrl_Rx, peer_id = CTRL_DEAD, key_id = CTRL_QUEUE_MAX})
	resize(&c.ctrl, CTRL_QUEUE_MAX)
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m), len(m))
	fake_reply(&f, .Del_Peer, 0)
	testing.expect_value(t, del_peer(&c, 1), 0)
	testing.expect_value(t, len(c.events), 1)
	testing.expect_value(t, c.ctrl_lost, 1)
	testing.expect_value(t, len(f.logs), 1)
}

@(test)
test_ctrl_record_survives_calls :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	// The caller handles a record (it may call the service meanwhile, which queues
	// more records and grows the queue): the record it holds does not change.
	rec1 := [3]u8{1, 2, 3}
	m1 := ctrl_msg(7, rec1[:])
	defer delete(m1)
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m1), len(m1))
	ev: Event
	testing.expect_value(t, next_event(&c, &ev), 1)
	held := ctrl_record(&c)
	big := make([]u8, 40000)
	defer delete(big)
	for i in 0 ..< len(big) {
		big[i] = 0xee
	}
	mb := ctrl_msg(7, big)
	defer delete(mb)
	for _ in 0 ..< 3 {
		fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(mb), len(mb))
		fake_reply(&f, .Del_Peer, 0)
		testing.expect_value(t, del_peer(&c, 8), 0)
	}
	testing.expect_value(t, string(held), string(rec1[:]))
	// The next event takes the next record, in order.
	testing.expect_value(t, next_event(&c, &ev), 1)
	testing.expect_value(t, ev.key_id, 40000)
}

@(test)
test_set_peer_id_on_the_wire :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	// A service with the capability: it shows in the backend too.
	fake_start(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_hello(&f, caps = CAP_TCP | CAP_PEER_ID)
	testing.expect_value(t, attach(&c, c.fd), 0)
	fake_recv(&f) // the HELLO
	be := socket_backend(&c)
	testing.expect_value(t, be.caps & CAP_PEER_ID, CAP_PEER_ID)

	fake_reply(&f, .Set_Peer_Id, 0)
	testing.expect_value(t, be.set_peer_id(be.user, 0xfffffe, 7), 0)
	h, body, fd, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Set_Peer_Id))
	testing.expect_value(t, h.flags, 0)
	testing.expect_value(t, fd, -1)
	testing.expect_value(t, len(body), 8)
	ids: [2]u32
	mem.copy(&ids[0], raw_data(body), 8)
	testing.expect_value(t, ids[0], 0xfffffe)
	testing.expect_value(t, ids[1], 7)

	// The status codes of the reply: no such peer, the id is in use, the id is too large.
	for st in ([]i32{-2, -17, -22}) {
		fake_reply(&f, .Set_Peer_Id, st)
		testing.expect_value(t, set_peer_id(&c, 1, 2), int(st))
		fake_recv(&f)
	}
	testing.expect_value(t, status_text(EEXIST), "EEXIST")
}

@(test)
test_events_of_the_old_id_after_the_rename :: proc(t: ^testing.T) {
	// The service's events and records of the peer that were queued before the rename carry
	// the old id and may come after the reply: the client passes them on as they are.
	f: Fake
	c: Conn
	attached(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_reply(&f, .Set_Peer_Id, 0)
	rec := [3]u8{0x20, 1, 2}
	m := ctrl_msg(0xfffffe, rec[:])
	defer delete(m)
	fake_send(&f, .Ctrl_Rx, 0, 0, raw_data(m), len(m))
	ev := Event {
		kind    = .Peer_Del,
		peer_id = 0xfffffe,
		reason  = .Transport_Disconnect,
	}
	fake_send(&f, .Event, 0, 0, &ev, size_of(ev))
	testing.expect_value(t, set_peer_id(&c, 0xfffffe, 7), 0)
	got: Event
	testing.expect_value(t, next_event(&c, &got), 1)
	testing.expect_value(t, got.kind, Event_Kind.Ctrl_Rx)
	testing.expect_value(t, got.peer_id, 0xfffffe)
	testing.expect_value(t, string(ctrl_record(&c)), string(rec[:]))
	testing.expect_value(t, next_event(&c, &got), 1)
	testing.expect_value(t, got.kind, Event_Kind.Peer_Del)
	testing.expect_value(t, got.peer_id, 0xfffffe)
}

@(test)
test_set_peer_addr_on_the_wire :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	fake_start(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_hello(&f, caps = CAP_TCP | CAP_PEER_ID | CAP_PEER_ADDR)
	testing.expect_value(t, attach(&c, c.fd), 0)
	fake_recv(&f) // the HELLO
	be := socket_backend(&c)
	testing.expect_value(t, be.caps & CAP_PEER_ADDR, CAP_PEER_ADDR)

	a := Set_Peer_Addr {
		peer_id = 7,
		flags   = PEER_VPN4 | PEER_VPN6,
		vpn4    = {10, 8, 0, 2},
	}
	a.vpn6[0] = 0xfd
	a.vpn6[15] = 2
	fake_reply(&f, .Set_Peer_Addr, 0)
	testing.expect_value(t, be.set_peer_addr(be.user, &a), 0)
	h, body, fd, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Set_Peer_Addr))
	testing.expect_value(t, h.flags, 0)
	testing.expect_value(t, fd, -1)
	testing.expect_value(t, len(body), 28)
	got: Set_Peer_Addr
	mem.copy(&got, raw_data(body), 28)
	testing.expect_value(t, got.peer_id, 7)
	testing.expect_value(t, got.flags, PEER_VPN4 | PEER_VPN6)
	testing.expect_value(t, got.vpn4, [4]u8{10, 8, 0, 2})
	testing.expect_value(t, got.vpn6[0], 0xfd)
	testing.expect_value(t, got.vpn6[15], 2)

	// No such peer; another peer has the address.
	for st in ([]i32{-2, -17}) {
		fake_reply(&f, .Set_Peer_Addr, st)
		testing.expect_value(t, set_peer_addr(&c, &a), int(st))
		fake_recv(&f)
	}
}

@(test)
test_set_filter_on_the_wire :: proc(t: ^testing.T) {
	f: Fake
	c: Conn
	fake_start(t, &f, &c)
	defer fake_stop(&f, &c)
	fake_hello(&f, caps = CAP_TCP | CAP_BLOCK_IPV6)
	testing.expect_value(t, attach(&c, c.fd), 0)
	fake_recv(&f) // the HELLO
	be := socket_backend(&c)
	testing.expect_value(t, be.caps & CAP_BLOCK_IPV6, CAP_BLOCK_IPV6)

	// The request has the flags only. The reply has the two counters.
	rep := Filter_Stats {
		rx_v6 = 11,
		tx_v6 = 22,
	}
	fake_reply(&f, .Set_Filter, 0, &rep, size_of(rep))
	out: Filter_Stats
	testing.expect_value(t, be.set_filter(be.user, FILTER_IPV6, &out), 0)
	h, body, fd, ok := fake_recv(&f)
	testing.expect(t, ok)
	testing.expect_value(t, h.type, u16(Msg.Set_Filter))
	testing.expect_value(t, h.flags, 0)
	testing.expect_value(t, fd, -1)
	testing.expect_value(t, len(body), 4)
	flags: u32
	mem.copy(&flags, raw_data(body), 4)
	testing.expect_value(t, flags, FILTER_IPV6)
	testing.expect_value(t, out, rep)

	// A reply with no body (a shorter reply) reads as 0.
	fake_reply(&f, .Set_Filter, 0)
	out = rep
	testing.expect_value(t, be.set_filter(be.user, 0, &out), 0)
	fake_recv(&f)
	testing.expect_value(t, out, Filter_Stats{})

	// No device, or a flag that the service does not know.
	for st in ([]i32{-19, -22}) {
		fake_reply(&f, .Set_Filter, st)
		testing.expect_value(t, set_filter(&c, 0x80, &out), int(st))
		fake_recv(&f)
	}
}
