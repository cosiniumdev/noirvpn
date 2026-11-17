// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package noirnet

import "core:c"
import "core:mem"
import "core:sys/posix"

// The batch API of batch_linux.odin on BSD socket calls, one datagram per
// system call. Same definition as batch_windows.odin. macOS has no public recvmmsg
// or sendmmsg, and this package uses no UDP GSO, GRO or packet info there:
// `batch_gro_size` is always 0, `batch_local` always empty. Callers stay the
// same on both systems.

Batch :: struct {
	family:     Family,
	bufs:       [][]u8, // receive buffer of slot i (`batch_set_recv`), or the data to send
	lens:       []int, // bytes received in slot i
	trunc:      []bool, // the datagram in slot i was longer than its buffer
	addrs:      []Sock_Addr,
	names:      []u32, // length of the address of slot i, 0 for none
	sends:      [][]u8, // pushed datagrams and slots set with `batch_set_send`
	allocator:  mem.Allocator,
	n_dg:       int,

	// Counters, since `batch_init`. The GSO and GRO ones stay 0.
	gso_msgs:   u64,
	gso_dgrams: u64,
	tx_msgs:    u64,
	tx_dgrams:  u64,
	tx_calls:   u64,
	rx_calls:   u64,
	rx_msgs:    u64,
	rx_dgrams:  u64,
	rx_gro_msgs: u64,
}

// Allocate a batch of `count` slots (once, at start up).
batch_init :: proc(b: ^Batch, family: Family, count: int, allocator := context.allocator) -> Error {
	b^ = {
		family    = family,
		allocator = allocator,
	}
	if count <= 0 {
		return .Invalid
	}
	ok := true
	err: mem.Allocator_Error
	if b.bufs, err = make([][]u8, count, allocator); err != nil {
		ok = false
	}
	if ok {
		if b.lens, err = make([]int, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.trunc, err = make([]bool, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.addrs, err = make([]Sock_Addr, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.names, err = make([]u32, count, allocator); err != nil {
			ok = false
		}
	}
	if ok {
		if b.sends, err = make([][]u8, count, allocator); err != nil {
			ok = false
		}
	}
	if !ok {
		batch_destroy_parts(b, allocator)
		b^ = {}
		return .No_Buffers
	}
	return .None
}

@(private)
batch_destroy_parts :: proc(b: ^Batch, allocator: mem.Allocator) {
	delete(b.bufs, allocator)
	delete(b.lens, allocator)
	delete(b.trunc, allocator)
	delete(b.addrs, allocator)
	delete(b.names, allocator)
	delete(b.sends, allocator)
}

batch_destroy :: proc(b: ^Batch) {
	batch_destroy_parts(b, b.allocator)
	b^ = {}
}

// Number of slots.
batch_cap :: proc "contextless" (b: ^Batch) -> int {
	return len(b.bufs)
}

// Point slot `i` at a receive buffer. Do it once; the slot keeps it.
batch_set_recv :: proc "contextless" (b: ^Batch, i: int, buf: []u8) {
	b.bufs[i] = buf
}

// Receive up to `count` datagrams (all slots if `count` < 0), one `recvfrom`
// each, until the socket has none. Never blocks. `.Would_Block`: none waiting.
// An error after the first datagram ends the batch early; the next call
// reports it.
recv_batch :: proc(s: Socket, b: ^Batch, count := -1) -> (n: int, err: Error) {
	want := len(b.bufs) if count < 0 else min(count, len(b.bufs))
	for n < want {
		buf := b.bufs[n]
		iov := posix.iovec {
			iov_base = raw_data(buf),
			iov_len  = uint(len(buf)),
		}
		msg := posix.msghdr {
			msg_name    = &b.addrs[n],
			msg_namelen = size_of(Sock_Addr),
			msg_iov     = &iov,
			msg_iovlen  = 1,
		}
		got := posix.recvmsg(posix.FD(s.fd), &msg, {})
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			if n > 0 {
				break
			}
			return 0, map_errno(e)
		}
		b.lens[n] = int(got)
		b.trunc[n] = .TRUNC in msg.msg_flags
		b.names[n] = u32(msg.msg_namelen)
		n += 1
	}
	if n > 0 {
		b.rx_calls += 1
		b.rx_msgs += u64(n)
		b.rx_dgrams += u64(n)
	}
	return n, .None
}

// Bytes received in slot `i`.
batch_len :: proc "contextless" (b: ^Batch, i: int) -> int {
	return b.lens[i]
}

// True if the datagram was longer than the slot's buffer (the rest is lost).
batch_truncated :: proc "contextless" (b: ^Batch, i: int) -> bool {
	return b.trunc[i]
}

// Always 0: no UDP GRO on macOS.
batch_gro_size :: proc "contextless" (b: ^Batch, i: int) -> int {
	return 0
}

// Always 1: no UDP GRO on macOS.
batch_segments :: proc "contextless" (b: ^Batch, i: int) -> int {
	return 1
}

// Source address of slot `i`. IPv4 sources of a dual-stack socket come back
// as IPv4.
batch_from :: proc "contextless" (b: ^Batch, i: int) -> (ep: Endpoint) {
	ep, _ = from_sockaddr(&b.addrs[i])
	return
}

// Always empty: no packet info on macOS.
batch_local :: proc "contextless" (b: ^Batch, i: int) -> Local {
	return {}
}

// ---- send: slots set by hand ----

// Fill slot `i` for sending `data`. `to`: destination, or nil on a connected
// socket. A `local` is `.Unsupported`. Keep `data` valid until `send_batch`
// returns.
batch_set_send :: proc "contextless" (b: ^Batch, i: int, data: []u8, to: Maybe(Endpoint) = nil, local := Local{}) -> Error {
	if local.len > 0 {
		return .Unsupported
	}
	b.sends[i] = data
	if ep, has := to.?; has {
		sa, size, ok := to_sockaddr(ep, b.family)
		if !ok {
			return .Invalid
		}
		b.addrs[i] = sa
		b.names[i] = size
	} else {
		b.names[i] = 0
	}
	return .None
}

// Send slot `i`. Returns the errno, 0 on success.
@(private)
send_slot :: proc "contextless" (s: Socket, b: ^Batch, i: int) -> posix.Errno {
	data := b.sends[i]
	for {
		ret: c.ssize_t
		if b.names[i] > 0 {
			ret = posix.sendto(posix.FD(s.fd), raw_data(data), uint(len(data)), {}, &b.addrs[i].base, posix.socklen_t(b.names[i]))
		} else {
			ret = posix.send(posix.FD(s.fd), raw_data(data), uint(len(data)), {})
		}
		if ret >= 0 {
			return .NONE
		}
		if e := posix.errno(); e != .EINTR {
			return e
		}
	}
}

// Send slots 0..count-1, one call each. Returns how many were sent. A short
// count is not an error. `.Would_Block`: none sent.
send_batch :: proc(s: Socket, b: ^Batch, count: int) -> (sent: int, err: Error) {
	n := min(count, len(b.sends))
	for sent < n {
		if e := send_slot(s, b, sent); e != .NONE {
			if sent == 0 {
				return 0, map_errno(e)
			}
			break
		}
		sent += 1
	}
	if sent > 0 {
		b.tx_calls += u64(sent)
		b.tx_msgs += u64(sent)
		b.tx_dgrams += u64(sent)
	}
	return sent, .None
}

// ---- send: pushed datagrams ----

// Empty the list of pushed datagrams.
batch_reset :: proc "contextless" (b: ^Batch) {
	b.n_dg = 0
}

// Datagrams pushed since the last `batch_reset`.
batch_pending :: proc "contextless" (b: ^Batch) -> int {
	return b.n_dg
}

// True when no more datagrams fit.
batch_full :: proc "contextless" (b: ^Batch) -> bool {
	return b.n_dg >= len(b.sends)
}

// Add one datagram to send. `to`: destination, or nil on a connected socket.
// Returns false if the batch is full, `to` does not fit the socket's family,
// or a `local` is given (unsupported on macOS). Keep `data` valid until
// `send_pushed` returns.
batch_push :: proc "contextless" (b: ^Batch, data: []u8, to: Maybe(Endpoint) = nil, local := Local{}) -> bool {
	i := b.n_dg
	if i >= len(b.sends) {
		return false
	}
	if batch_set_send(b, i, data, to, local) != .None {
		return false
	}
	b.n_dg += 1
	return true
}

// Send the pushed datagrams, one call each. Returns how many were taken, always
// a prefix of the list. Less than `batch_pending` is not an error.
// `.Would_Block`: none sent. The list stays.
send_pushed :: proc(s: Socket, b: ^Batch) -> (sent: int, err: Error) {
	return send_batch(s, b, b.n_dg)
}

// Never reports anything: there is no GSO to fall back from.
batch_take_gso_failure :: proc "contextless" (b: ^Batch) -> (errno: int, fresh: bool) {
	return 0, false
}

// Always false on macOS.
batch_gso_active :: proc "contextless" (s: Socket, b: ^Batch) -> bool {
	return false
}
