// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package dco

import "core:fmt"
import "core:mem"
import "core:sys/linux"
import "core:time"
import "noir:platform/netlink"
import "noir:platform/sysnet"

// Data channel in the Linux kernel: a `Backend` on the `ovpn` driver (generic
// netlink family "ovpn", `kernel_proto.odin`). The driver creates the tun
// device, holds keys and replay window, does AEAD and keepalive.
//
//   device  RTM_NEWLINK kind "ovpn" (P2P client, MP server) through sysnet.
//           The kernel keeps a device when its owner dies, so a device of that
//           name and kind is removed first (logged).
//   peers   PEER_NEW with the server UDP socket (one for all peers: the first
//           call dups it, later calls may pass -1) or a connected TCP socket.
//           Key slots are the kernel's two (no key table).
//   events  A second netlink socket on group "peers" (PEER_DEL_NTF,
//           KEY_SWAP_NTF) and every TCP peer socket sit in one epoll
//           descriptor (`Backend.fd`); `next_event` drains what is ready.
//           A float is not notified (before Linux 7.1): `stats` compares the
//           endpoint.
//
// TCP: after PEER_NEW the kernel owns the stream framing.
// - A read gives one control packet with its 2-byte length prefix; a write
//   needs the prefix too. Data packets never reach user space.
// - This backend reads control packets (`Ctrl_Rx` events) and writes them
//   (`ctrl_tx`, small queue for a busy socket).
// - The kernel cannot take read-ahead bytes: `new_peer_stream` handles them
//   before PEER_NEW.
//
// A call blocks until the kernel returns. The kernel does not apply `mss`.

// `kernel_connect`: the family "ovpn" is not there (no module).
ENO_OVPN :: -65
// The most bytes of control records that wait for a TCP socket that is not writable.
TX_QUEUE_MAX :: 1 << 20
// How long `new_peer_stream` waits for the rest of a partial record read ahead.
AHEAD_WAIT_MS :: 2000

ENOTSUP :: -95
EBADF :: -9
ENOMEM :: -12

@(private)
Kpeer :: struct {
	id:      u32,
	tcp:     bool,
	fd:      i32, // TCP: our dup of the stream
	remote:  Endpoint, // UDP: the endpoint we know
	has_rem: bool,
	// TCP: framed records (length prefix included) that wait for the socket, from `tx_head`.
	txq:     [dynamic]u8,
	tx_head: int,
	tx_part: int, // bytes of the record at `tx_head` that went out already
	out_armed: bool, // EPOLLOUT is on
}

Kernel :: struct {
	log:       Log_Proc,
	log_user:  rawptr,
	gen:       netlink.Socket, // requests
	ntf:       netlink.Socket, // notifications of the group "peers"
	rt:        sysnet.Conn, // links
	family:    u16,
	ep:        linux.Fd,
	rx:        []u8, // netlink receive buffer
	srx:       []u8, // one TCP control packet
	ifindex:   u32,
	mp:        bool,
	have_dev:  bool,
	udp:       i32, // our dup of the data socket, -1: none
	peers:     [dynamic]Kpeer,
	events:    [dynamic]Event,
	head:      int,
	ctrl:      [dynamic]u8,
	ctrl_off:  int,
	ctrl_cur:  []u8,
	cur:       []u8,
	// Data records of the read-ahead bytes that were dropped, and the control
	// records and events that were lost to a full queue.
	ahead_data: int,
	lost:       int,
	// How often a control record had to wait for a busy TCP socket.
	tx_waits:   int,
	err:        [128]u8,
	err_len:    int,
	up:         bool,
}

// ----------------------------------------------------------------- connect

// Opens the sockets. Returns 0 or a negative errno. `ENO_OVPN`: no family
// "ovpn" in the kernel (module not loaded or not built). EPERM without
// CAP_NET_ADMIN shows only at the first request that changes something.
kernel_connect :: proc(k: ^Kernel, log: Log_Proc = nil, log_user: rawptr = nil) -> int {
	k^ = {}
	k.ep = -1
	k.udp = -1
	k.log = log
	k.log_user = log_user

	gen, gerr := netlink.open(netlink.NETLINK_GENERIC)
	if gerr != .None {
		return -int(gen.errno)
	}
	k.gen = gen
	k.rx = make([]u8, 32768)
	k.srx = make([]u8, 2 + STREAM_REC_MAX)
	if k.rx == nil || k.srx == nil {
		kernel_disconnect(k)
		return ENOMEM
	}
	info, ierr := netlink.genl_resolve(&k.gen, OVPN_FAMILY, k.rx)
	if ierr != .None {
		st := ENO_OVPN
		if !(ierr == .Kernel && k.gen.errno == .ENOENT) {
			st = status_of(&k.gen, ierr)
		}
		kernel_disconnect(k)
		return st
	}
	k.family = info.id
	group, ok := netlink.group_id(&info, OVPN_GROUP_PEERS)
	if !ok {
		kernel_disconnect(k)
		return EPROTO
	}

	// The notification socket never waits: `next_event` reads it when epoll says so.
	ntf, nerr := netlink.open(netlink.NETLINK_GENERIC, 0, 0)
	if nerr != .None {
		kernel_disconnect(k)
		return -int(ntf.errno)
	}
	k.ntf = ntf
	if serr := netlink.subscribe(&k.ntf, group); serr != .None {
		st := -int(k.ntf.errno)
		kernel_disconnect(k)
		return st
	}
	ep, eerr := linux.epoll_create1({.FDCLOEXEC})
	if eerr != .NONE {
		kernel_disconnect(k)
		return -int(eerr)
	}
	k.ep = ep
	ev := linux.EPoll_Event {
		events = {.IN},
		data   = {u64 = 0},
	}
	if e := linux.epoll_ctl(k.ep, .ADD, k.ntf.fd, &ev); e != .NONE {
		kernel_disconnect(k)
		return -int(e)
	}
	rt, rerr := sysnet.open()
	if rerr != .None {
		kernel_disconnect(k)
		return EIO
	}
	k.rt = rt
	k.up = true
	return 0
}

// Removes the device when it is still there, and closes everything.
kernel_disconnect :: proc(k: ^Kernel) {
	if k.have_dev {
		kernel_close(k)
	}
	kernel_free_peers(k)
	if k.udp >= 0 {
		linux.close(linux.Fd(k.udp))
		k.udp = -1
	}
	if k.ep >= 0 {
		linux.close(k.ep)
		k.ep = -1
	}
	netlink.close(&k.gen)
	netlink.close(&k.ntf)
	if k.rt.rx != nil {
		sysnet.close(&k.rt)
	}
	delete(k.rx)
	delete(k.srx)
	delete(k.cur)
	delete(k.events)
	delete(k.ctrl)
	k.rx = nil
	k.srx = nil
	k.cur = nil
	k.events = nil
	k.ctrl = nil
	k.ctrl_cur = nil
	k.head = 0
	k.ctrl_off = 0
	k.up = false
}

@(private)
kernel_free_peers :: proc(k: ^Kernel) {
	for &p in k.peers {
		peer_release(k, &p)
	}
	delete(k.peers)
	k.peers = nil
}

// Takes the TCP socket of a peer out of epoll and closes it.
@(private)
peer_release :: proc(k: ^Kernel, p: ^Kpeer) {
	if p.tcp && p.fd >= 0 {
		linux.epoll_ctl(k.ep, .DEL, linux.Fd(p.fd), nil)
		linux.close(linux.Fd(p.fd))
		p.fd = -1
	}
	delete(p.txq)
	p.txq = nil
}

// ------------------------------------------------------------------ errors

@(private)
klog :: proc(k: ^Kernel, level: Log_Level, text: string) {
	if k.log != nil {
		k.log(k.log_user, level, text)
	}
}

@(private)
set_err :: proc(k: ^Kernel, text: string) {
	k.err_len = min(len(text), len(k.err))
	copy(k.err[:], text[:k.err_len])
}

// The kernel's text for the last failed call, or "".
kernel_error_text :: proc(k: ^Kernel) -> string {
	return string(k.err[:k.err_len])
}

// A netlink error as a negative errno.
@(private)
status_of :: proc(s: ^netlink.Socket, err: netlink.Error) -> int {
	#partial switch err {
	case .None:
		return 0
	case .Kernel, .Io:
		return -int(s.errno)
	case .Timeout:
		return ETIMEDOUT
	}
	return EPROTO
}

// A sysnet error as a negative errno.
@(private)
rt_status :: proc(k: ^Kernel, err: sysnet.Error) -> int {
	if err == .None {
		return 0
	}
	set_err(k, sysnet.last_error_text(&k.rt))
	if e := sysnet.last_errno(&k.rt); e != .NONE {
		return -int(e)
	}
	#partial switch err {
	case .Exists:
		return EEXIST
	case .Not_Found:
		return ENOENT
	case .Permission:
		return -1
	case .Timeout:
		return ETIMEDOUT
	}
	return EIO
}

// One request to the family; `handler` gets the data messages of the reply.
@(private)
kcall :: proc(k: ^Kernel, msg: []u8, handler: netlink.Handler = nil, user: rawptr = nil) -> int {
	k.err_len = 0
	if !k.up {
		return ENOTCONN
	}
	err := netlink.request(&k.gen, msg, k.rx, handler, user)
	if err == .None {
		return 0
	}
	set_err(k, netlink.ext_message(&k.gen))
	return status_of(&k.gen, err)
}

@(private)
build_failed :: proc(k: ^Kernel, err: netlink.Error) -> int {
	return EMSGSIZE if err == .Buffer_Too_Small || err == .Oversize else EINVAL
}

// ------------------------------------------------------------------ device

kernel_open_device :: proc(k: ^Kernel, name: string, mode: Mode, flags: u32) -> (ifindex: u32, status: int) {
	k.err_len = 0
	if !k.up {
		return 0, ENOTCONN
	}
	if k.have_dev {
		return 0, EEXIST
	}
	if len(name) == 0 || len(name) >= IFNAME_MAX {
		return 0, EINVAL
	}
	l, gerr := sysnet.link_get(&k.rt, name)
	#partial switch gerr {
	case .None:
		if sysnet.link_kind(&l) != "ovpn" {
			set_err(k, "a device with this name already exists, and it is not an ovpn device")
			return 0, EEXIST
		}
		klog(k, .Warn, fmt.tprintf("removing the stale ovpn device %s left over from an earlier run", name))
		if derr := sysnet.link_delete(&k.rt, l.index); derr != .None && derr != .Not_Found {
			return 0, rt_status(k, derr)
		}
	case .Not_Found:
	case:
		return 0, rt_status(k, gerr)
	}
	idx, aerr := sysnet.link_add_ovpn(&k.rt, name, mode == .Mp)
	if aerr != .None {
		return 0, rt_status(k, aerr)
	}
	k.ifindex = idx
	k.mp = mode == .Mp
	k.have_dev = true
	return idx, 0
}

// Removes the device and, with it, every peer.
kernel_close :: proc(k: ^Kernel) -> int {
	k.err_len = 0
	kernel_free_peers(k)
	if k.udp >= 0 {
		linux.close(linux.Fd(k.udp))
		k.udp = -1
	}
	if !k.have_dev {
		return 0
	}
	k.have_dev = false
	idx := k.ifindex
	k.ifindex = 0
	if err := sysnet.link_delete(&k.rt, idx); err != .None && err != .Not_Found {
		return rt_status(k, err)
	}
	return 0
}

// ------------------------------------------------------------------- peers

@(private)
find_peer :: proc(k: ^Kernel, id: u32) -> int {
	for p, i in k.peers {
		if p.id == id {
			return i
		}
	}
	return -1
}

@(private)
peer_args :: proc(k: ^Kernel, p: ^New_Peer, sock: i32, tcp: bool) -> (a: Peer_New_Args, st: int) {
	a = Peer_New_Args {
		id   = p.peer_id,
		sock = sock,
		mp   = k.mp,
		tcp  = tcp,
	}
	if !tcp {
		if p.flags & PEER_REMOTE == 0 {
			return a, EINVAL
		}
		ok: bool
		if a.remote, ok = endpoint_of(&p.remote); !ok {
			return a, EINVAL
		}
		if p.flags & PEER_LOCAL != 0 {
			if l, lok := endpoint_of(&p.local); lok {
				a.local = l
			}
		}
	}
	if k.mp {
		if p.flags & PEER_VPN4 != 0 {
			a.vpn4 = p.vpn4
		}
		if p.flags & PEER_VPN6 != 0 {
			a.vpn6 = p.vpn6
		}
	}
	return a, 0
}

@(private)
dup_fd :: proc(fd: i32) -> (i32, int) {
	d, e := linux.fcntl_dupfd_cloexec(linux.Fd(fd), linux.F_DUPFD_CLOEXEC, 0)
	if e != .NONE {
		return -1, -int(e)
	}
	return i32(d), 0
}

kernel_new_peer :: proc(k: ^Kernel, p: ^New_Peer, fd: i32) -> int {
	k.err_len = 0
	if !k.up || !k.have_dev {
		return ENOTCONN
	}
	if find_peer(k, p.peer_id) >= 0 || (!k.mp && len(k.peers) > 0) {
		// A P2P device has one peer: the kernel would replace it.
		return EEXIST
	}
	// The socket of the server is the same for every peer: keep the first one.
	fresh := i32(-1)
	sock := k.udp
	if fd >= 0 {
		d, st := dup_fd(fd)
		if st != 0 {
			return st
		}
		fresh = d
		sock = d
	}
	if sock < 0 {
		return EINVAL
	}
	a, ast := peer_args(k, p, sock, false)
	if ast != 0 {
		if fresh >= 0 {
			linux.close(linux.Fd(fresh))
		}
		return ast
	}
	buf: [512]u8
	msg, berr := build_peer_new(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, a)
	if berr != .None {
		if fresh >= 0 {
			linux.close(linux.Fd(fresh))
		}
		return build_failed(k, berr)
	}
	if st := kcall(k, msg); st != 0 {
		if fresh >= 0 {
			linux.close(linux.Fd(fresh))
		}
		return st
	}
	if fresh >= 0 {
		if k.udp >= 0 {
			linux.close(linux.Fd(k.udp))
		}
		k.udp = fresh
	}
	kp := Kpeer {
		id     = p.peer_id,
		fd     = -1,
		remote = a.remote,
		has_rem = true,
	}
	append(&k.peers, kp)
	return 0
}

// Lets go of the data socket (the peers stay in the kernel).
kernel_detach :: proc(k: ^Kernel) -> int {
	if k.udp >= 0 {
		linux.close(linux.Fd(k.udp))
		k.udp = -1
	}
	return 0
}

kernel_set_peer :: proc(k: ^Kernel, p: ^Set_Peer) -> int {
	if find_peer(k, p.peer_id) < 0 {
		return ENOENT
	}
	buf: [128]u8
	msg, berr := build_peer_set(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, p.peer_id, p.keepalive_interval, p.keepalive_timeout)
	if berr != .None {
		return build_failed(k, berr)
	}
	return kcall(k, msg)
}

kernel_del_peer :: proc(k: ^Kernel, peer_id: u32) -> int {
	i := find_peer(k, peer_id)
	if i < 0 {
		return ENOENT
	}
	buf: [128]u8
	msg, berr := build_peer_id(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, OVPN_CMD_PEER_DEL, peer_id)
	if berr != .None {
		return build_failed(k, berr)
	}
	st := kcall(k, msg)
	peer_remove(k, i)
	if st == ENOENT {
		return 0
	}
	return st
}

// Takes the peer out of the table and closes its stream.
@(private)
peer_remove :: proc(k: ^Kernel, i: int) {
	peer_release(k, &k.peers[i])
	ordered_remove(&k.peers, i)
}

// ------------------------------------------------------------------- keys

kernel_new_key :: proc(k: ^Kernel, key: ^New_Key) -> int {
	if find_peer(k, key.peer_id) < 0 {
		return ENOENT
	}
	switch Cipher(key.cipher) {
	case .Aes_Gcm:
		if key.key_len != 16 && key.key_len != 24 && key.key_len != 32 {
			return EINVAL
		}
	case .Chacha20_Poly1305:
		if key.key_len != 32 {
			return EINVAL
		}
	case .None:
		return EINVAL
	}
	if key.slot > u32(Key_Slot.Secondary) || key.key_id > 7 {
		return EINVAL
	}
	buf: [512]u8
	msg, berr := build_key_new(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, key)
	if berr != .None {
		mem.zero_explicit(&buf, size_of(buf))
		return build_failed(k, berr)
	}
	st := kcall(k, msg)
	mem.zero_explicit(&buf, size_of(buf))
	return st
}

kernel_swap_keys :: proc(k: ^Kernel, peer_id: u32) -> int {
	if find_peer(k, peer_id) < 0 {
		return ENOENT
	}
	buf: [128]u8
	msg, berr := build_key_slot(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, OVPN_CMD_KEY_SWAP, peer_id, .Primary)
	if berr != .None {
		return build_failed(k, berr)
	}
	return kcall(k, msg)
}

kernel_del_key :: proc(k: ^Kernel, peer_id: u32, slot: Key_Slot) -> int {
	if find_peer(k, peer_id) < 0 {
		return ENOENT
	}
	buf: [128]u8
	msg, berr := build_key_slot(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, OVPN_CMD_KEY_DEL, peer_id, slot)
	if berr != .None {
		return build_failed(k, berr)
	}
	return kcall(k, msg)
}

// ------------------------------------------------------------------- stats

@(private)
Get_Result :: struct {
	info: Peer_Info,
	ok:   bool,
}

// Reads the peer from the kernel.
kernel_peer_info :: proc(k: ^Kernel, peer_id: u32) -> (info: Peer_Info, st: int) {
	buf: [128]u8
	msg, berr := build_peer_id(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, OVPN_CMD_PEER_GET, peer_id)
	if berr != .None {
		return {}, build_failed(k, berr)
	}
	res: Get_Result
	handler :: proc(user: rawptr, m: netlink.Msg) {
		r := (^Get_Result)(user)
		if !r.ok {
			r.info, r.ok = parse_peer_get(m.payload)
		}
	}
	if st = kcall(k, msg, handler, &res); st != 0 {
		return {}, st
	}
	if !res.ok {
		return {}, EPROTO
	}
	return res.info, 0
}

// The counters of the peer. When the remote endpoint is not the one we know (the
// peer floated), a `Peer_Float` event is queued; the kernel does not notify it.
kernel_stats :: proc(k: ^Kernel, peer_id: u32, out: ^Peer_Stats) -> int {
	i := find_peer(k, peer_id)
	if i < 0 {
		return ENOENT
	}
	info, st := kernel_peer_info(k, peer_id)
	if st != 0 {
		return st
	}
	out^ = info.stats
	p := &k.peers[i]
	if !p.tcp && info.remote.family != 0 {
		if p.has_rem && p.remote != info.remote {
			ev := Event {
				kind    = .Peer_Float,
				peer_id = peer_id,
				addr    = endpoint_sockaddr(info.remote),
			}
			push_event(k, ev)
		}
		p.remote = info.remote
		p.has_rem = true
	}
	return 0
}

// Which key sits in a slot of a peer (KEY_GET). ENOENT: the slot is empty.
kernel_key_slot_info :: proc(k: ^Kernel, peer_id: u32, slot: Key_Slot) -> (info: Key_Info, st: int) {
	buf: [128]u8
	msg, berr := build_key_slot(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, OVPN_CMD_KEY_GET, peer_id, slot)
	if berr != .None {
		return {}, build_failed(k, berr)
	}
	Res :: struct {
		info: Key_Info,
		ok:   bool,
	}
	res: Res
	handler :: proc(user: rawptr, m: netlink.Msg) {
		r := (^Res)(user)
		if !r.ok {
			r.info, r.ok = parse_key_get(m.payload)
		}
	}
	if st = kcall(k, msg, handler, &res); st != 0 {
		return {}, st
	}
	if !res.ok {
		return {}, EPROTO
	}
	return res.info, 0
}

// ---------------------------------------------------------------- events

@(private)
push_event :: proc(k: ^Kernel, ev: Event) -> bool {
	if len(k.events) - k.head >= EVENT_QUEUE_MAX {
		k.lost += 1
		return false
	}
	append(&k.events, ev)
	return true
}

@(private)
push_ctrl :: proc(k: ^Kernel, id: u32, rec: []u8) {
	if len(rec) == 0 {
		return
	}
	if len(k.events) - k.head >= EVENT_QUEUE_MAX || len(k.ctrl) - k.ctrl_off + len(rec) > CTRL_QUEUE_MAX {
		k.lost += 1
		return
	}
	append(&k.events, Event{kind = .Ctrl_Rx, peer_id = id, key_id = u32(len(rec))})
	append(&k.ctrl, ..rec)
}

kernel_ctrl_record :: proc(k: ^Kernel) -> []u8 {
	return k.ctrl_cur
}

@(private)
kpop_event :: proc(k: ^Kernel, ev: ^Event) {
	ev^ = k.events[k.head]
	k.head += 1
	if ev.kind == .Ctrl_Rx {
		n := int(ev.key_id)
		if k.cur == nil {
			k.cur = make([]u8, STREAM_REC_MAX)
		}
		if k.cur != nil {
			copy(k.cur, k.ctrl[k.ctrl_off:][:n])
			k.ctrl_cur = k.cur[:n]
		} else {
			k.ctrl_cur = nil
		}
		k.ctrl_off += n
	}
	if k.head == len(k.events) {
		clear(&k.events)
		k.head = 0
		clear(&k.ctrl)
		k.ctrl_off = 0
	}
}

// The next event: queued ones first, then what epoll has ready (one source per
// round, so a ready descriptor that gives nothing cannot hold the loop).
// Returns 1: `ev` filled. 0: none now. Below 0: backend not connected.
kernel_next_event :: proc(k: ^Kernel, ev: ^Event) -> int {
	if !k.up {
		return ENOTCONN
	}
	for _ in 0 ..< 64 {
		if k.head < len(k.events) {
			kpop_event(k, ev)
			return 1
		}
		if k.lost > 0 {
			klog(k, .Error, "events or control records were dropped because the queue was full")
			k.lost = 0
		}
		ready: [1]linux.EPoll_Event
		n, e := linux.epoll_wait(k.ep, raw_data(ready[:]), 1, 0)
		if e == .EINTR {
			continue
		}
		if e != .NONE || n <= 0 {
			return 0
		}
		tag := ready[0].data.u64
		if tag == 0 {
			read_notifications(k)
			continue
		}
		i := find_peer(k, u32(tag - 1))
		if i < 0 {
			continue
		}
		set := ready[0].events
		if .OUT in set {
			if st := tcp_flush(k, i); st != 0 {
				peer_gone(k, i, .Transport_Error, true)
				continue
			}
		}
		if set & {.IN, .HUP, .ERR} != {} {
			tcp_read(k, i)
		}
	}
	return 0
}

// One datagram of the notification socket.
@(private)
read_notifications :: proc(k: ^Kernel) {
	n, err := netlink.recv_nowait(&k.ntf, k.rx)
	if err == .Io && k.ntf.errno == .ENOBUFS {
		resync(k)
		return
	}
	if err != .None {
		return
	}
	it := netlink.msg_iter(k.rx[:n])
	for m in netlink.msg_next(&it) {
		if m.hdr.type != k.family || !k.have_dev {
			continue
		}
		note, ok := parse_notify(m.payload)
		if !ok || note.ifindex != k.ifindex {
			continue
		}
		switch note.cmd {
		case OVPN_CMD_PEER_DEL_NTF:
			// What we deleted ourselves is not news.
			if note.reason == .Userspace {
				continue
			}
			if i := find_peer(k, note.peer_id); i >= 0 {
				peer_gone(k, i, note.reason, false)
			}
		case OVPN_CMD_KEY_SWAP_NTF:
			if find_peer(k, note.peer_id) >= 0 {
				push_event(k, Event{kind = .Key_Swap, peer_id = note.peer_id, key_id = note.key_id})
			}
		}
	}
}

// The notification queue overflowed and messages are lost: ask the kernel which
// peers are still there.
@(private)
resync :: proc(k: ^Kernel) {
	klog(k, .Warn, "some ovpn notifications were lost, so the peers will be checked again")
	i := 0
	for i < len(k.peers) {
		if _, st := kernel_peer_info(k, k.peers[i].id); st == ENOENT {
			peer_gone(k, i, .Expired, false)
			continue
		}
		i += 1
	}
}

// The peer is gone: queue the event and forget it. `del`: delete it in the
// kernel too (it is still there).
@(private)
peer_gone :: proc(k: ^Kernel, i: int, reason: Del_Reason, del: bool) {
	id := k.peers[i].id
	peer_remove(k, i)
	if del {
		buf: [128]u8
		if msg, berr := build_peer_id(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, OVPN_CMD_PEER_DEL, id); berr == .None {
			kcall(k, msg)
		}
	}
	push_event(k, Event{kind = .Peer_Del, peer_id = id, reason = reason})
}

// ------------------------------------------------------------------- TCP

kernel_new_peer_stream :: proc(k: ^Kernel, p: ^New_Peer, fd: i32, ahead: []u8) -> int {
	k.err_len = 0
	if !k.up || !k.have_dev {
		return ENOTCONN
	}
	if fd < 0 {
		return EINVAL
	}
	if find_peer(k, p.peer_id) >= 0 || (!k.mp && len(k.peers) > 0) {
		return EEXIST
	}
	if len(ahead) > 2 + 2 * (2 + STREAM_REC_MAX) {
		return EMSGSIZE
	}
	a, ast := peer_args(k, p, 0, true)
	if ast != 0 {
		return ast
	}
	sock, dst := dup_fd(fd)
	if dst != 0 {
		return dst
	}
	a.sock = sock

	// Read-ahead bytes: whole records are ours. A partial record at the end must
	// be completed from the socket, because the kernel starts at a record boundary.
	data := make([dynamic]u8, 0, len(ahead) + 64)
	defer delete(data)
	append(&data, ..ahead)
	off := 0
	for {
		if _, ok := stream_next(data[:], &off); !ok {
			break
		}
	}
	if st := ahead_complete(sock, &data, off, AHEAD_WAIT_MS); st != 0 {
		linux.close(linux.Fd(sock))
		return st
	}

	buf: [512]u8
	msg, berr := build_peer_new(buf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, a)
	if berr != .None {
		linux.close(linux.Fd(sock))
		return build_failed(k, berr)
	}
	if st := kcall(k, msg); st != 0 {
		linux.close(linux.Fd(sock))
		return st
	}
	ev := linux.EPoll_Event {
		events = {.IN},
		data   = {u64 = u64(p.peer_id) + 1},
	}
	if e := linux.epoll_ctl(k.ep, .ADD, linux.Fd(sock), &ev); e != .NONE {
		linux.close(linux.Fd(sock))
		pbuf: [128]u8
		if dmsg, derr := build_peer_id(pbuf[:], k.family, netlink.next_seq(&k.gen), k.ifindex, OVPN_CMD_PEER_DEL, p.peer_id); derr == .None {
			kcall(k, dmsg)
		}
		return -int(e)
	}
	append(&k.peers, Kpeer{id = p.peer_id, tcp = true, fd = sock})

	// The control records read ahead come first, in order.
	off = 0
	for {
		rec, ok := stream_next(data[:], &off)
		if !ok {
			break
		}
		if record_is_data(rec) {
			k.ahead_data += 1
		} else {
			push_ctrl(k, p.peer_id, rec)
		}
	}
	return 0
}

// Reads what a partial record at the end of `data` (from `off`) still needs, so that
// `data` holds whole records only. Waits up to `wait_ms`.
@(private)
ahead_complete :: proc(fd: i32, data: ^[dynamic]u8, off: int, wait_ms: int) -> int {
	if off == len(data) {
		return 0
	}
	deadline := time.tick_add(time.tick_now(), time.Duration(wait_ms) * time.Millisecond)
	need := stream_need(data[off:])
	if need < 0 {
		// Not even the length is there.
		need = 2 - (len(data) - off)
		if st := read_exact(fd, data, need, deadline); st != 0 {
			return st
		}
		need = stream_need(data[off:])
	}
	if need > 0 {
		return read_exact(fd, data, need, deadline)
	}
	return 0
}

// Appends exactly `n` bytes from the socket to `data`.
@(private)
read_exact :: proc(fd: i32, data: ^[dynamic]u8, n: int, deadline: time.Tick) -> int {
	start := len(data)
	resize(data, start + n)
	got := 0
	for got < n {
		r, e := linux.recv(linux.Fd(fd), data[start + got:], {.DONTWAIT})
		#partial switch e {
		case .NONE:
			if r == 0 {
				resize(data, start)
				return ECONNRESET
			}
			got += r
		case .EINTR:
		case .EAGAIN:
			left := time.tick_diff(time.tick_now(), deadline)
			if left <= 0 {
				resize(data, start)
				return ETIMEDOUT
			}
			pfd := [1]linux.Poll_Fd{{fd = linux.Fd(fd), events = {.IN}}}
			linux.poll(pfd[:], i32(min(left / time.Millisecond, 100)))
		case:
			resize(data, start)
			return -int(e)
		}
	}
	return 0
}

// Reads one control packet of a TCP peer from its socket.
@(private)
tcp_read :: proc(k: ^Kernel, i: int) {
	p := &k.peers[i]
	if !p.tcp {
		return
	}
	n, e := linux.recv(linux.Fd(p.fd), k.srx, {.DONTWAIT})
	#partial switch e {
	case .NONE:
	case .EAGAIN, .EINTR:
		return
	case:
		peer_gone(k, i, .Transport_Error, true)
		return
	}
	if n == 0 {
		peer_gone(k, i, .Transport_Disconnect, true)
		return
	}
	// The kernel gives one packet with its length prefix.
	if n < 2 || int(k.srx[0]) << 8 | int(k.srx[1]) != n - 2 {
		klog(k, .Warn, "dropped a control packet from the kernel because its length prefix is wrong")
		return
	}
	push_ctrl(k, p.id, k.srx[2:n])
}

// A control record for the stream (without prefix). The kernel takes one
// record at a time and returns EAGAIN while one is in flight. The rest wait in
// the peer's queue and go out when the socket is writable.
kernel_ctrl_tx :: proc(k: ^Kernel, peer_id: u32, rec: []u8) -> int {
	if len(rec) == 0 || len(rec) > STREAM_REC_MAX {
		return EMSGSIZE
	}
	i := find_peer(k, peer_id)
	if i < 0 || !k.peers[i].tcp {
		return ENOENT
	}
	p := &k.peers[i]
	if len(p.txq) - p.tx_head + 2 + len(rec) > TX_QUEUE_MAX {
		return ENOBUFS
	}
	append(&p.txq, u8(len(rec) >> 8), u8(len(rec)))
	append(&p.txq, ..rec)
	if st := tcp_flush(k, i); st != 0 {
		return st
	}
	return 0
}

// Sends queued records until the socket is busy. EPOLLOUT is on while some
// wait. The kernel driver takes a whole record or none; a stream socket that
// took part of one gets the rest later.
@(private)
tcp_flush :: proc(k: ^Kernel, i: int) -> int {
	p := &k.peers[i]
	for p.tx_head < len(p.txq) {
		rest := p.txq[p.tx_head:]
		n := 2 + (int(rest[0]) << 8 | int(rest[1]))
		w, e := linux.send(linux.Fd(p.fd), rest[p.tx_part:n], {.DONTWAIT, .NOSIGNAL})
		#partial switch e {
		case .NONE:
			p.tx_part += w
			if p.tx_part >= n {
				p.tx_head += n
				p.tx_part = 0
			}
		case .EINTR:
		case .EAGAIN:
			k.tx_waits += 1
			arm_out(k, p, true)
			return 0
		case:
			return -int(e)
		}
	}
	clear(&p.txq)
	p.tx_head = 0
	arm_out(k, p, false)
	return 0
}

@(private)
arm_out :: proc(k: ^Kernel, p: ^Kpeer, on: bool) {
	if p.out_armed == on {
		return
	}
	ev := linux.EPoll_Event {
		events = {.IN, .OUT} if on else {.IN},
		data   = {u64 = u64(p.id) + 1},
	}
	if linux.epoll_ctl(k.ep, .MOD, linux.Fd(p.fd), &ev) == .NONE {
		p.out_armed = on
	}
}

// ----------------------------------------------------------------- backend

// The kernel driver as a `Backend`. `k` must stay where it is for as long as the
// backend is used, and `kernel_connect` must have returned 0.
kernel_backend :: proc(k: ^Kernel) -> Backend {
	return Backend {
		user = k,
		kind = .Kernel,
		fd = i32(k.ep),
		mss_clamp = false,
		caps = CAP_TCP,
		err_text = proc(user: rawptr) -> string {
			return kernel_error_text((^Kernel)(user))
		},
		open = proc(user: rawptr, name: string, mode: Mode, flags: u32) -> (u32, int) {
			return kernel_open_device((^Kernel)(user), name, mode, flags)
		},
		close = proc(user: rawptr) -> int {
			return kernel_close((^Kernel)(user))
		},
		new_peer = proc(user: rawptr, p: ^New_Peer, fd: i32) -> int {
			return kernel_new_peer((^Kernel)(user), p, fd)
		},
		new_peer_stream = proc(user: rawptr, p: ^New_Peer, fd: i32, ahead: []u8) -> int {
			return kernel_new_peer_stream((^Kernel)(user), p, fd, ahead)
		},
		ctrl_tx = proc(user: rawptr, peer_id: u32, rec: []u8) -> int {
			return kernel_ctrl_tx((^Kernel)(user), peer_id, rec)
		},
		ctrl_record = proc(user: rawptr) -> []u8 {
			return kernel_ctrl_record((^Kernel)(user))
		},
		set_peer_id = proc(user: rawptr, peer_id, new_id: u32) -> int {
			return ENOTSUP
		},
		set_peer_addr = proc(user: rawptr, a: ^Set_Peer_Addr) -> int {
			return ENOTSUP
		},
		set_filter = proc(user: rawptr, flags: u32, out: ^Filter_Stats) -> int {
			return ENOTSUP
		},
		set_peer = proc(user: rawptr, p: ^Set_Peer) -> int {
			return kernel_set_peer((^Kernel)(user), p)
		},
		del_peer = proc(user: rawptr, peer_id: u32) -> int {
			return kernel_del_peer((^Kernel)(user), peer_id)
		},
		new_key = proc(user: rawptr, key: ^New_Key) -> int {
			return kernel_new_key((^Kernel)(user), key)
		},
		swap_keys = proc(user: rawptr, peer_id: u32) -> int {
			return kernel_swap_keys((^Kernel)(user), peer_id)
		},
		del_key = proc(user: rawptr, peer_id: u32, slot: Key_Slot) -> int {
			return kernel_del_key((^Kernel)(user), peer_id, slot)
		},
		key_add = proc(user: rawptr, key: ^Key) -> int {
			return ENOTSUP
		},
		key_tx = proc(user: rawptr, peer_id, key_id: u32) -> int {
			return ENOTSUP
		},
		key_drop = proc(user: rawptr, peer_id, key_id: u32) -> int {
			return ENOTSUP
		},
		stats = proc(user: rawptr, peer_id: u32, out: ^Peer_Stats) -> int {
			return kernel_stats((^Kernel)(user), peer_id, out)
		},
		detach = proc(user: rawptr) -> int {
			return kernel_detach((^Kernel)(user))
		},
		next_event = proc(user: rawptr, ev: ^Event) -> int {
			return kernel_next_event((^Kernel)(user), ev)
		},
	}
}
