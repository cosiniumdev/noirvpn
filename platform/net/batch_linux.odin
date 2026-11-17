// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import "core:mem"
import "core:sys/linux"

// Batched UDP: recvmmsg(2) and sendmmsg(2) over arrays that are set up once,
// with UDP GSO on send and UDP GRO on receive.
//
//	rx: net.Batch
//	net.batch_init(&rx, sock.family, 32)
//	for i in 0 ..< 32 { net.batch_set_recv(&rx, i, pool[i][:]) }
//	...
//	n, err := net.recv_batch(sock, &rx)
//	for i in 0 ..< n {
//		block := pool[i][:net.batch_len(&rx, i)]
//		from := net.batch_from(&rx, i)
//		// A socket with `gro` can return several datagrams in one block:
//		seg := net.batch_gro_size(&rx, i) // 0: the block is one datagram
//	}
//
//	tx: net.Batch
//	net.batch_init(&tx, sock.family, 64)
//	net.batch_reset(&tx)
//	for each packet { if !net.batch_push(&tx, pkt, to) { break } }
//	sent, err := net.send_pushed(sock, &tx) // `sent` counts datagrams
//
// A UDP server on a wildcard address must reply from the address the client
// sent to. On a socket with `pktinfo`, `batch_local` gives the local address
// of a received datagram; `batch_push(&tx, pkt, to, local)` sends from it.
//
// Batching needs the real system calls. musl's sendmmsg() and recvmmsg() (and
// glibc fallbacks) can loop over sendmsg()/recvmsg(), one packet per call,
// which loses the point. So this file never calls libc: `linux.sendmmsg` and
// the raw `SYS_recvmmsg` below go straight to the kernel. Do not replace them
// with a `foreign` import or core:sys/posix. platform/net/README.md has a
// strace of a static musl binary as proof.
//
// A batch holds the message headers, so a call only resets the address length.
// Data buffers are the caller's. Use one batch to receive, another to send.
// - Headers go to the kernel as laid out in memory, so the layout must be the
//   kernel's: `msg_iovlen` and `msg_controllen` are size_t (musl's struct uses
//   int), `struct mmsghdr` adds a u32 and padding.
// - Control messages use `Cmsg_Hdr` below, the kernel's `struct cmsghdr`
//   (cmsg_len is a size_t, data starts at the next size_t boundary). Build
//   and read them by hand; do not use libc's CMSG_* macros.
// - Messages: UDP_SEGMENT and UDP_GRO (SOL_UDP), IP_PKTINFO (SOL_IP, IPv4
//   sockets), IPV6_PKTINFO (SOL_IPV6, IPv6 sockets).
when size_of(uintptr) == 8 {
	#assert(size_of(linux.Msg_Hdr) == 56)
	#assert(size_of(linux.MMsg_Hdr) == 64)
} else {
	#assert(size_of(linux.Msg_Hdr) == 28)
	#assert(size_of(linux.MMsg_Hdr) == 32)
}

// ---- control messages ----

// struct cmsghdr as the kernel has it.
@(private)
Cmsg_Hdr :: struct {
	len:   uint, // bytes of header and data, without the end padding
	level: i32,
	type:  i32,
}

// CMSG_ALIGN: round up to a multiple of size_t.
@(private)
cmsg_align :: proc "contextless" (n: int) -> int {
	return (n + size_of(uint) - 1) &~ (size_of(uint) - 1)
}

// Where the data of a control message starts (CMSG_LEN(0)).
@(private)
CMSG_HDR_SIZE :: ((size_of(Cmsg_Hdr) + size_of(uint) - 1) / size_of(uint)) * size_of(uint)

// Room for two control messages at 8 byte alignment:
//   UDP_GRO (int, receive) or UDP_SEGMENT (u16, send)
//   packet info (12 bytes of data for IPv4, 20 for IPv6)
CTRL_SIZE :: 80
@(private)
Ctrl :: [CTRL_SIZE / 8]u64
#assert(CTRL_SIZE >= 2 * CMSG_HDR_SIZE + 8 + 24)

// Packet info: struct in_pktinfo { int ifindex; in_addr spec_dst; in_addr addr; }
// and struct in6_pktinfo { in6_addr addr; unsigned ifindex; }.
@(private)
IP_PKTINFO_SIZE :: 12
@(private)
IP6_PKTINFO_SIZE :: 20
#assert(CTRL_SIZE >= CMSG_HDR_SIZE + 8 + CMSG_HDR_SIZE + 24)

// Writes a UDP_SEGMENT control message (the size of each datagram of a GSO
// message) at byte `off` of `c` and returns the number of bytes used (CMSG_SPACE(2)).
@(private)
cmsg_put_gso :: proc "contextless" (c: ^Ctrl, off: int, gso_size: u16) -> int {
	base := ([^]u8)(c)[off:]
	(^Cmsg_Hdr)(base)^ = {
		len   = CMSG_HDR_SIZE + 2,
		level = SOL_UDP,
		type  = UDP_SEGMENT,
	}
	(^u16)(base[CMSG_HDR_SIZE:])^ = gso_size
	return CMSG_HDR_SIZE + cmsg_align(2)
}

// Finds a UDP_GRO message in the control bytes and gives its datagram size
// (0 if none). Every length is checked, so odd control data never reads
// outside `ctrl`.
@(private)
cmsg_find_gro :: proc "contextless" (ctrl: []u8) -> int {
	off := 0
	for off + CMSG_HDR_SIZE <= len(ctrl) {
		h := (^Cmsg_Hdr)(&ctrl[off])^
		if h.len < CMSG_HDR_SIZE || h.len > uint(len(ctrl)) - uint(off) {
			break
		}
		if h.level == SOL_UDP && h.type == UDP_GRO {
			n := int(h.len) - CMSG_HDR_SIZE
			base := off + CMSG_HDR_SIZE
			if n >= 4 {
				return max(0, int((^i32)(&ctrl[base])^))
			}
			if n >= 2 {
				return int((^u16)(&ctrl[base])^)
			}
			return 0
		}
		off += cmsg_align(int(h.len))
	}
	return 0
}

// ---- local address of a datagram ----

// Writes the packet info control message for `l` at byte `off` of `c`.
// Returns the bytes used (0: nothing written).
// - IPv4 socket: IP_PKTINFO (`ipi_spec_dst` is the source address).
// - IPv6 socket: IPV6_PKTINFO. An IPv4 local goes in mapped form, which the
//   kernel wants for an IPv4 destination on an IPv6 socket.
// - IPv6 local on an IPv4 socket: cannot be sent, nothing written.
@(private)
cmsg_put_pktinfo :: proc "contextless" (c: ^Ctrl, off: int, family: Family, l: Local) -> int {
	if l.len == 0 {
		return 0
	}
	l := l
	base := ([^]u8)(c)[off:]
	switch family {
	case .V4:
		if l.len != 4 {
			return 0
		}
		(^Cmsg_Hdr)(base)^ = {
			len   = CMSG_HDR_SIZE + IP_PKTINFO_SIZE,
			level = IPPROTO_IP,
			type  = IP_PKTINFO,
		}
		d := base[CMSG_HDR_SIZE:][:IP_PKTINFO_SIZE]
		mem.zero_slice(d)
		mem.copy(&d[0], &l.ifindex, 4)
		mem.copy(&d[4], &l.addr[0], 4)
		return CMSG_HDR_SIZE + cmsg_align(IP_PKTINFO_SIZE)
	case .V6:
		(^Cmsg_Hdr)(base)^ = {
			len   = CMSG_HDR_SIZE + IP6_PKTINFO_SIZE,
			level = IPPROTO_IPV6,
			type  = IPV6_PKTINFO,
		}
		d := base[CMSG_HDR_SIZE:][:IP6_PKTINFO_SIZE]
		mem.zero_slice(d)
		if l.len == 4 {
			d[10], d[11] = 0xff, 0xff
			mem.copy(&d[12], &l.addr[0], 4)
		} else {
			mem.copy(&d[0], &l.addr[0], 16)
		}
		mem.copy(&d[16], &l.ifindex, 4)
		return CMSG_HDR_SIZE + cmsg_align(IP6_PKTINFO_SIZE)
	}
	return 0
}

// Finds packet info in the control bytes. Every length is checked. On a
// dual-stack IPv6 socket an IPv4 packet comes as IPV6_PKTINFO with a mapped
// address; it is given as an IPv4 local, like the source address.
@(private)
cmsg_find_local :: proc "contextless" (ctrl: []u8) -> (l: Local) {
	off := 0
	for off + CMSG_HDR_SIZE <= len(ctrl) {
		h := (^Cmsg_Hdr)(&ctrl[off])^
		if h.len < CMSG_HDR_SIZE || h.len > uint(len(ctrl)) - uint(off) {
			break
		}
		n := int(h.len) - CMSG_HDR_SIZE
		d := ctrl[off + CMSG_HDR_SIZE:][:n]
		if h.level == IPPROTO_IP && h.type == IP_PKTINFO && n >= IP_PKTINFO_SIZE {
			l.len = 4
			// ipi_spec_dst: the local address to reply from. For a broadcast packet it
			// differs from the packet's destination (ipi_addr), which cannot be a source.
			// Use ipi_addr only when it is empty.
			mem.copy(&l.addr[0], &d[4], 4)
			if l.addr[0] | l.addr[1] | l.addr[2] | l.addr[3] == 0 {
				mem.copy(&l.addr[0], &d[8], 4)
			}
			mem.copy(&l.ifindex, &d[0], 4)
			return
		}
		if h.level == IPPROTO_IPV6 && h.type == IPV6_PKTINFO && n >= IP6_PKTINFO_SIZE {
			mem.copy(&l.addr[0], &d[0], 16)
			mem.copy(&l.ifindex, &d[16], 4)
			l.len = 16
			if addr_is_mapped(l.addr) {
				l.len = 4
				for i in 0 ..< 4 {
					l.addr[i] = l.addr[12 + i]
				}
				for i in 4 ..< 16 {
					l.addr[i] = 0
				}
			}
			return
		}
		off += cmsg_align(int(h.len))
	}
	return {}
}

// ---- limits of one UDP GSO message ----

// The kernel takes at most 64 datagrams in one UDP GSO message (EINVAL above)
// and the payload must fit one IP packet (EMSGSIZE above 65507 bytes; the IPv4
// figure serves both families).
GSO_MAX_SEGS :: 64
GSO_MAX_BYTES :: 65507

// A datagram that was pushed with `batch_push`.
@(private)
Msg_Span :: struct {
	first: i32, // index of its first datagram
	n:     i32, // number of datagrams
}

Batch :: struct {
	family:     Family,
	hdrs:       []linux.MMsg_Hdr,
	iovs:       []linux.IO_Vec,
	addrs:      []linux.Sock_Addr_Any,
	ctrl:       []Ctrl,
	allocator:  mem.Allocator,

	// Pushed datagrams (`batch_push`, `send_pushed`).
	names:      []u8, // length of the address of datagram i, 0 for none
	locals:     []Local, // the source address of datagram i (`len` 0: the system's choice)
	spans:      []Msg_Span, // the messages built by `send_pushed`
	n_dg:       int,
	n_msg:      int,
	// GSO was refused by the kernel for this batch (the first time: see
	// `batch_take_gso_failure`). Sends are plain from then on.
	gso_off:    bool,
	gso_errno:  linux.Errno,
	gso_unseen: bool,

	// Counters, since `batch_init`.
	gso_msgs:   u64, // GSO messages (two or more datagrams) the kernel took
	gso_dgrams: u64, // datagrams that went out inside them
	tx_msgs:    u64, // sendmmsg entries of all kinds the kernel took
	tx_dgrams:  u64, // datagrams the kernel took
	tx_calls:   u64, // sendmmsg calls
	rx_calls:   u64, // recvmmsg calls that returned messages
	rx_msgs:    u64, // messages they returned
	rx_dgrams:  u64, // datagrams in them (a GRO message counts all of its datagrams)
	rx_gro_msgs: u64, // messages that held two or more datagrams (UDP GRO)
}

// Allocate a batch of `count` slots (once, at start up). A send batch holds up
// to `count` datagrams, a receive batch `count` messages.
batch_init :: proc(b: ^Batch, family: Family, count: int, allocator := context.allocator) -> Error {
	b^ = {
		family    = family,
		allocator = allocator,
	}
	if count <= 0 {
		return .Invalid
	}
	err: mem.Allocator_Error
	ok := true
	if b.hdrs, err = make([]linux.MMsg_Hdr, count, allocator); err != nil {
		ok = false
	}
	if ok {
		if b.iovs, err = make([]linux.IO_Vec, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.addrs, err = make([]linux.Sock_Addr_Any, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.ctrl, err = make([]Ctrl, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.names, err = make([]u8, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.spans, err = make([]Msg_Span, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.locals, err = make([]Local, count, allocator); err != nil {
			ok = false
		}
	}
	if !ok {
		batch_destroy_parts(b, allocator)
		b^ = {}
		return .No_Buffers
	}
	for i in 0 ..< count {
		b.hdrs[i].hdr.iov = b.iovs[i:i + 1]
		b.hdrs[i].hdr.name = &b.addrs[i]
	}
	return .None
}

@(private)
batch_destroy_parts :: proc(b: ^Batch, allocator: mem.Allocator) {
	delete(b.hdrs, allocator)
	delete(b.iovs, allocator)
	delete(b.addrs, allocator)
	delete(b.ctrl, allocator)
	delete(b.names, allocator)
	delete(b.spans, allocator)
	delete(b.locals, allocator)
}

batch_destroy :: proc(b: ^Batch) {
	batch_destroy_parts(b, b.allocator)
	b^ = {}
}

// Number of slots.
batch_cap :: proc "contextless" (b: ^Batch) -> int {
	return len(b.hdrs)
}

// Point slot `i` at a receive buffer. Do it once; the slot keeps it. With
// `gro` the buffer must hold the largest coalesced block, 65535 bytes. A
// smaller one cuts the block and loses the datagrams in the cut part.
batch_set_recv :: proc "contextless" (b: ^Batch, i: int, buf: []u8) {
	b.iovs[i] = {
		base = raw_data(buf),
		len  = uint(len(buf)),
	}
}

// Receive up to `count` messages (all slots if `count` < 0). Never blocks.
// Returns the number received; `.Would_Block`: none waiting. Slots 0..n-1 hold
// the data: see `batch_len`, `batch_from`, `batch_gro_size` (with `gro`),
// `batch_local` (with `pktinfo`).
recv_batch :: proc(s: Socket, b: ^Batch, count := -1) -> (n: int, err: Error) {
	want := len(b.hdrs) if count < 0 else min(count, len(b.hdrs))
	if want == 0 {
		return 0, .None
	}
	for i in 0 ..< want {
		h := &b.hdrs[i]
		// The kernel overwrites these: reset them for each call.
		h.hdr.name = &b.addrs[i]
		h.hdr.namelen = size_of(linux.Sock_Addr_Any)
		h.hdr.iov = b.iovs[i:i + 1]
		if s.gro || s.pktinfo {
			h.hdr.control = ([^]u8)(&b.ctrl[i])[:CTRL_SIZE]
		} else {
			h.hdr.control = nil
		}
		h.hdr.flags = {}
		h.len = 0
	}
	for {
		// The real recvmmsg system call, not libc's (musl loops over recvmsg, one
		// packet per call). linux.recvmmsg in core:sys/linux drops the fifth argument
		// (timeout), so the kernel reads a garbage pointer and fails with EINVAL. Call
		// it directly with a NULL timeout.
		ret := linux.syscall(
			linux.SYS_recvmmsg,
			linux.Fd(s.fd),
			raw_data(b.hdrs),
			want,
			transmute(i32)linux.Socket_Msg{.DONTWAIT},
			uintptr(0),
		)
		if ret == -int(linux.Errno.EINTR) {
			continue
		}
		if ret < 0 {
			return 0, map_errno(linux.Errno(-ret))
		}
		b.rx_calls += 1
		b.rx_msgs += u64(ret)
		for i in 0 ..< ret {
			segs := batch_segments(b, i)
			b.rx_dgrams += u64(segs)
			if segs > 1 {
				b.rx_gro_msgs += 1
			}
		}
		return ret, .None
	}
}

// Bytes received in slot `i`.
batch_len :: proc "contextless" (b: ^Batch, i: int) -> int {
	return int(b.hdrs[i].len)
}

// True if the message was longer than the slot's buffer (the rest is lost).
batch_truncated :: proc "contextless" (b: ^Batch, i: int) -> bool {
	return .TRUNC in b.hdrs[i].hdr.flags
}

// Size of each datagram in slot `i` when the kernel coalesced several
// (UDP GRO), or 0 when the slot holds one. All have this size except the last,
// which may be shorter. Only slots of a `gro` socket can have it. If the
// control data was cut (`CTRUNC`) the size is unknown: treated as 0, and the
// caller sees a bad datagram.
batch_gro_size :: proc "contextless" (b: ^Batch, i: int) -> int {
	h := &b.hdrs[i].hdr
	if len(h.control) == 0 || .CTRUNC in h.flags {
		return 0
	}
	// After the call `control` is as long as the control data the kernel wrote.
	seg := cmsg_find_gro(h.control)
	if seg <= 0 || seg >= int(b.hdrs[i].len) {
		return 0
	}
	return seg
}

// How many datagrams slot `i` holds (1 if it was not coalesced).
batch_segments :: proc "contextless" (b: ^Batch, i: int) -> int {
	total := int(b.hdrs[i].len)
	seg := batch_gro_size(b, i)
	if seg == 0 {
		return 1
	}
	return (total + seg - 1) / seg
}

// Source address of slot `i`. IPv4 sources of a dual-stack socket come back
// as IPv4. A coalesced slot has one source for all its datagrams.
batch_from :: proc "contextless" (b: ^Batch, i: int) -> (ep: Endpoint) {
	ep, _ = from_sockaddr(&b.addrs[i])
	return
}

// Local address that slot `i` was sent to, and the interface it came in on.
// Empty (`len` 0) without `pktinfo`. A coalesced slot shares it. An IPv4
// packet on a dual-stack IPv6 socket gives an IPv4 local.
batch_local :: proc "contextless" (b: ^Batch, i: int) -> Local {
	h := &b.hdrs[i].hdr
	if len(h.control) == 0 {
		return {}
	}
	return cmsg_find_local(h.control)
}

// ---- send: slots set by hand (one datagram per message, no GSO) ----

// Fill slot `i` for sending `data`. `to`: destination, or nil on a connected
// socket. `local`: source address (`len` 0: system picks). Keep `data` valid
// until `send_batch` returns.
batch_set_send :: proc "contextless" (b: ^Batch, i: int, data: []u8, to: Maybe(Endpoint) = nil, local := Local{}) -> Error {
	h := &b.hdrs[i]
	b.iovs[i] = {
		base = raw_data(data),
		len  = uint(len(data)),
	}
	h.hdr.iov = b.iovs[i:i + 1]
	h.hdr.control = nil
	if used := cmsg_put_pktinfo(&b.ctrl[i], 0, b.family, local); used > 0 {
		h.hdr.control = ([^]u8)(&b.ctrl[i])[:used]
	}
	h.hdr.flags = {}
	h.len = 0
	if ep, has := to.?; has {
		sa, size, ok := to_sockaddr(ep, b.family)
		if !ok {
			return .Invalid
		}
		b.addrs[i] = sa
		h.hdr.name = &b.addrs[i]
		h.hdr.namelen = i32(size)
	} else {
		h.hdr.name = nil
		h.hdr.namelen = 0
	}
	return .None
}

// Send slots 0..count-1 in one call, one datagram each. Returns how many were
// sent. A short count is not an error: the socket buffer is full, and the
// caller retries or drops the rest. `.Would_Block`: none sent.
send_batch :: proc(s: Socket, b: ^Batch, count: int) -> (sent: int, err: Error) {
	n := min(count, len(b.hdrs))
	if n <= 0 {
		return 0, .None
	}
	for {
		// core:sys/linux issues the real sendmmsg system call. libc's sendmmsg
		// is not used: musl loops over sendmsg, one packet per call.
		got, e := linux.sendmmsg(linux.Fd(s.fd), b.hdrs[:n], {.NOSIGNAL, .DONTWAIT})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return 0, map_errno(e)
		}
		b.tx_calls += 1
		b.tx_msgs += u64(got)
		b.tx_dgrams += u64(got)
		return got, .None
	}
}

// ---- send: pushed datagrams, with GSO ----

// Empty the list of pushed datagrams.
batch_reset :: proc "contextless" (b: ^Batch) {
	b.n_dg = 0
	b.n_msg = 0
}

// Datagrams pushed since the last `batch_reset`.
batch_pending :: proc "contextless" (b: ^Batch) -> int {
	return b.n_dg
}

// True when no more datagrams fit.
batch_full :: proc "contextless" (b: ^Batch) -> bool {
	return b.n_dg >= len(b.iovs)
}

// Add one datagram to send. `to`: destination, or nil on a connected socket
// (use one kind per batch). `local`: source address (`len` 0: system picks;
// an IPv4 local on an IPv6 socket goes as a mapped address). Returns false if
// the batch is full or `to` does not fit the socket's family. Keep `data`
// valid until `send_pushed` returns.
batch_push :: proc "contextless" (b: ^Batch, data: []u8, to: Maybe(Endpoint) = nil, local := Local{}) -> bool {
	i := b.n_dg
	if i >= len(b.iovs) {
		return false
	}
	if ep, has := to.?; has {
		sa, size, ok := to_sockaddr(ep, b.family)
		if !ok {
			return false
		}
		b.addrs[i] = sa
		b.names[i] = u8(size)
	} else {
		b.names[i] = 0
	}
	if local.len > 0 {
		b.locals[i] = local
	} else {
		b.locals[i].len = 0
	}
	b.iovs[i] = {
		base = raw_data(data),
		len  = uint(len(data)),
	}
	b.n_dg += 1
	return true
}

// Same destination and same source address? One GSO message has one of each.
@(private)
same_dest :: proc "contextless" (b: ^Batch, i, j: int) -> bool {
	li, lj := &b.locals[i], &b.locals[j]
	if li.len != lj.len {
		return false
	}
	if li.len > 0 && (li.ifindex != lj.ifindex || mem.compare_ptrs(&li.addr, &lj.addr, int(li.len)) != 0) {
		return false
	}
	n := int(b.names[i])
	if n != int(b.names[j]) {
		return false
	}
	if n == 0 {
		return true
	}
	return mem.compare_ptrs(&b.addrs[i], &b.addrs[j], n) == 0
}

// Builds the sendmmsg entries for the pushed datagrams. With `gso`, a run to
// one destination becomes one entry with a UDP_SEGMENT control message, if
// every datagram but the last has the size of the first and the last is not
// longer. Without `gso`, each datagram is its own entry.
@(private)
pack_pushed :: proc "contextless" (b: ^Batch, gso: bool) {
	b.n_msg = 0
	i := 0
	for i < b.n_dg {
		size := int(b.iovs[i].len)
		cnt := 1
		if gso && size > 0 {
			total := size
			for i + cnt < b.n_dg && cnt < GSO_MAX_SEGS {
				j := i + cnt
				l := int(b.iovs[j].len)
				// Only the last datagram of a run may be shorter.
				if int(b.iovs[j - 1].len) != size || l == 0 || l > size || total + l > GSO_MAX_BYTES || !same_dest(b, i, j) {
					break
				}
				total += l
				cnt += 1
			}
		}
		m := b.n_msg
		h := &b.hdrs[m]
		h.hdr.iov = b.iovs[i:i + cnt]
		if b.names[i] > 0 {
			h.hdr.name = &b.addrs[i]
			h.hdr.namelen = i32(b.names[i])
		} else {
			h.hdr.name = nil
			h.hdr.namelen = 0
		}
		used := 0
		if b.locals[i].len > 0 {
			used = cmsg_put_pktinfo(&b.ctrl[m], 0, b.family, b.locals[i])
		}
		if cnt > 1 {
			used += cmsg_put_gso(&b.ctrl[m], used, u16(size))
		}
		if used > 0 {
			h.hdr.control = ([^]u8)(&b.ctrl[m])[:used]
		} else {
			h.hdr.control = nil
		}
		h.hdr.flags = {}
		h.len = 0
		b.spans[m] = {
			first = i32(i),
			n     = i32(cnt),
		}
		b.n_msg += 1
		i += cnt
	}
}

// Errors that mean "this kernel, device or path takes no UDP GSO" when a GSO
// message fails: ENOPROTOOPT (no option), EIO (device without checksum
// offload), EINVAL and EMSGSIZE (size or count refused), EOPNOTSUPP.
@(private)
gso_refused :: proc "contextless" (e: linux.Errno) -> bool {
	#partial switch e {
	case .EINVAL, .EIO, .ENOPROTOOPT, .EOPNOTSUPP, .EMSGSIZE:
		return true
	}
	return false
}

// Send the pushed datagrams in one `sendmmsg` call, using UDP GSO for runs of
// equal sized datagrams if the socket has `gso`.
// - Returns how many datagrams the kernel took, counting each inside a GSO
//   entry. Always a prefix of the pushed list, and all datagrams of an entry
//   or none.
// - Less than `batch_pending` is not an error: the socket buffer is full (or
//   a later entry failed; the next call reports it).
// - `.Would_Block`: none sent.
// - The list stays: `batch_reset` it before the next round.
//
// If the kernel refuses a GSO entry (see `gso_refused`), the batch falls back
// to plain datagrams at once, now and for later calls. `batch_take_gso_failure`
// reports it once so the caller can log it.
send_pushed :: proc(s: Socket, b: ^Batch) -> (sent: int, err: Error) {
	if b.n_dg == 0 {
		return 0, .None
	}
	gso := s.gso && !b.gso_off
	pack_pushed(b, gso)
	for {
		got, e := linux.sendmmsg(linux.Fd(s.fd), b.hdrs[:b.n_msg], {.NOSIGNAL, .DONTWAIT})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			if gso && b.spans[0].n > 1 && gso_refused(e) {
				if !b.gso_off {
					b.gso_off = true
					b.gso_errno = e
					b.gso_unseen = true
				}
				gso = false
				pack_pushed(b, false)
				continue
			}
			return 0, map_errno(e)
		}
		b.tx_calls += 1
		b.tx_msgs += u64(got)
		for m in 0 ..< got {
			n := int(b.spans[m].n)
			sent += n
			if n > 1 {
				b.gso_msgs += 1
				b.gso_dgrams += u64(n)
			}
		}
		b.tx_dgrams += u64(sent)
		return sent, .None
	}
}

// Once, after the batch fell back from GSO: the errno of the refused send.
// `fresh` is true on the first call after the failure only.
batch_take_gso_failure :: proc "contextless" (b: ^Batch) -> (errno: int, fresh: bool) {
	if !b.gso_unseen {
		return 0, false
	}
	b.gso_unseen = false
	return int(b.gso_errno), true
}

// True while sends on this batch may use GSO (the socket has it and the kernel
// has not refused it).
batch_gso_active :: proc "contextless" (s: Socket, b: ^Batch) -> bool {
	return s.gso && !b.gso_off
}
