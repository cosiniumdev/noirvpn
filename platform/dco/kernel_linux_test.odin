// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package dco

import "core:sys/linux"
import "core:testing"

// Kernel backend parts that need no `ovpn` module: TCP control records (a
// stream socket pair plays the peer socket, no driver behind it) and the event
// queue. The netlink side is tested with cmd/dcoktest.

@(private = "file")
Pair :: struct {
	k:    Kernel,
	ours: linux.Fd, // the end that the backend owns
	far:  linux.Fd, // the other end
}

@(private = "file")
pair_start :: proc(t: ^testing.T, p: ^Pair, sndbuf: i32 = 0) {
	fds: [2]linux.Fd
	if e := linux.socketpair(.UNIX, .STREAM, .UNSPECIFIED, &fds); e != .NONE {
		testing.fail_now(t, "socketpair failed")
	}
	p.ours, p.far = fds[0], fds[1]
	if sndbuf > 0 {
		v := sndbuf
		linux.setsockopt_base(p.ours, 1, 7, &v) // SO_SNDBUF
	}
	k := &p.k
	k.up = true
	k.ep = -1
	k.udp = -1
	k.gen.fd = -1
	k.ntf.fd = -1
	k.mp = true
	k.srx = make([]u8, 2 + STREAM_REC_MAX)
	ep, e := linux.epoll_create1({.FDCLOEXEC})
	if e != .NONE {
		testing.fail_now(t, "epoll_create1 failed")
	}
	k.ep = ep
	ev := linux.EPoll_Event {
		events = {.IN},
		data   = {u64 = 8}, // peer id 7
	}
	linux.epoll_ctl(k.ep, .ADD, p.ours, &ev)
	append(&k.peers, Kpeer{id = 7, tcp = true, fd = i32(p.ours)})
}

@(private = "file")
pair_stop :: proc(p: ^Pair) {
	linux.close(p.far)
	kernel_disconnect(&p.k)
}

@(test)
tcp_record_in_gives_ctrl_rx :: proc(t: ^testing.T) {
	p: Pair
	pair_start(t, &p)
	defer pair_stop(&p)
	// The kernel gives a control packet with its length prefix.
	linux.write(p.far, []u8{0, 3, 0x20, 'a', 'b'})
	ev: Event
	testing.expect_value(t, kernel_next_event(&p.k, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Ctrl_Rx)
	testing.expect_value(t, ev.peer_id, u32(7))
	testing.expect_value(t, ev.key_id, u32(3))
	rec := kernel_ctrl_record(&p.k)
	testing.expect_value(t, string(rec), "\x20ab")
	testing.expect_value(t, kernel_next_event(&p.k, &ev), 0)

	// A record with a wrong prefix is dropped.
	linux.write(p.far, []u8{0, 9, 0x20, 'a'})
	testing.expect_value(t, kernel_next_event(&p.k, &ev), 0)

	// An empty record is nothing.
	linux.write(p.far, []u8{0, 0})
	testing.expect_value(t, kernel_next_event(&p.k, &ev), 0)
}

@(test)
tcp_close_gives_peer_del :: proc(t: ^testing.T) {
	p: Pair
	pair_start(t, &p)
	defer pair_stop(&p)
	linux.shutdown(p.far, .RDWR)
	ev: Event
	testing.expect_value(t, kernel_next_event(&p.k, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Peer_Del)
	testing.expect_value(t, ev.peer_id, u32(7))
	testing.expect_value(t, ev.reason, Del_Reason.Transport_Disconnect)
	testing.expect_value(t, len(p.k.peers), 0)
	testing.expect_value(t, kernel_next_event(&p.k, &ev), 0)
}

@(test)
ctrl_tx_frames_the_record :: proc(t: ^testing.T) {
	p: Pair
	pair_start(t, &p)
	defer pair_stop(&p)
	testing.expect_value(t, kernel_ctrl_tx(&p.k, 7, []u8{0x20, 1, 2, 3}), 0)
	buf: [16]u8
	n, _ := linux.read(p.far, buf[:])
	testing.expect_value(t, string(buf[:n]), "\x00\x04\x20\x01\x02\x03")

	testing.expect_value(t, kernel_ctrl_tx(&p.k, 7, nil), EMSGSIZE)
	big := make([]u8, STREAM_REC_MAX + 1)
	defer delete(big)
	testing.expect_value(t, kernel_ctrl_tx(&p.k, 7, big), EMSGSIZE)
	testing.expect_value(t, kernel_ctrl_tx(&p.k, 8, []u8{1}), ENOENT)
}

@(test)
ctrl_tx_queues_for_a_busy_socket :: proc(t: ^testing.T) {
	p: Pair
	pair_start(t, &p, 4096)
	defer pair_stop(&p)
	// Fill the socket until a record has to wait, then read the other end dry. The
	// records must come out whole and in order.
	rec := make([]u8, 3000)
	defer delete(rec)
	sent := 0
	for i in 0 ..< 200 {
		rec[0] = u8(i)
		rec[1] = u8(i >> 8)
		st := kernel_ctrl_tx(&p.k, 7, rec)
		testing.expect_value(t, st, 0)
		sent += 1
		if len(p.k.peers[0].txq) > 0 {
			break
		}
	}
	testing.expect(t, len(p.k.peers[0].txq) > 0, "the socket never filled")
	testing.expect(t, p.k.tx_waits > 0)
	got := 0
	buf := make([]u8, 3002)
	defer delete(buf)
	ev: Event
	for _ in 0 ..< 20000 {
		for {
			hdr := [2]u8{}
			n, e := linux.recv(p.far, hdr[:], {.DONTWAIT})
			if e != .NONE || n < 2 {
				break
			}
			size := int(hdr[0]) << 8 | int(hdr[1])
			testing.expect_value(t, size, 3000)
			read := 0
			for read < size {
				m, re := linux.recv(p.far, buf[read:size], {})
				if re != .NONE || m <= 0 {
					break
				}
				read += m
			}
			testing.expect_value(t, int(buf[0]) | int(buf[1]) << 8, got)
			got += 1
		}
		kernel_next_event(&p.k, &ev)
		if got == sent {
			break
		}
	}
	testing.expect_value(t, got, sent)
	testing.expect_value(t, len(p.k.peers[0].txq), 0)
	testing.expect(t, !p.k.peers[0].out_armed)
}

@(test)
ctrl_tx_queue_is_bounded :: proc(t: ^testing.T) {
	p: Pair
	pair_start(t, &p, 4096)
	defer pair_stop(&p)
	rec := make([]u8, STREAM_REC_MAX)
	defer delete(rec)
	st := 0
	for _ in 0 ..< 64 {
		if st = kernel_ctrl_tx(&p.k, 7, rec); st != 0 {
			break
		}
	}
	testing.expect_value(t, st, ENOBUFS)
}

@(test)
event_queue_orders_ctrl_and_events :: proc(t: ^testing.T) {
	p: Pair
	pair_start(t, &p)
	defer pair_stop(&p)
	k := &p.k
	push_ctrl(k, 7, []u8{1, 2, 3})
	push_event(k, Event{kind = .Key_Swap, peer_id = 7, key_id = 2})
	push_ctrl(k, 7, []u8{4, 5})
	push_ctrl(k, 7, nil) // nothing
	ev: Event
	testing.expect_value(t, kernel_next_event(k, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Ctrl_Rx)
	testing.expect_value(t, string(kernel_ctrl_record(k)), "\x01\x02\x03")
	testing.expect_value(t, kernel_next_event(k, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Key_Swap)
	testing.expect_value(t, ev.key_id, u32(2))
	testing.expect_value(t, kernel_next_event(k, &ev), 1)
	testing.expect_value(t, ev.kind, Event_Kind.Ctrl_Rx)
	testing.expect_value(t, string(kernel_ctrl_record(k)), "\x04\x05")
	testing.expect_value(t, kernel_next_event(k, &ev), 0)
	testing.expect_value(t, len(k.events), 0)
	testing.expect_value(t, len(k.ctrl), 0)
}

@(test)
ahead_partial_record_is_completed :: proc(t: ^testing.T) {
	p: Pair
	pair_start(t, &p)
	defer pair_stop(&p)
	fd := i32(p.ours)

	// A whole record and 4 of the 7 bytes of the next one. The rest is on the socket.
	data: [dynamic]u8
	defer delete(data)
	append(&data, 0, 3, 0x20, 1, 2, 0, 5, 0x20, 9)
	linux.write(p.far, []u8{7, 7, 7})
	off := 5
	testing.expect_value(t, ahead_complete(fd, &data, off, 500), 0)
	testing.expect_value(t, len(data), 12)
	o := 0
	_, ok := stream_next(data[:], &o)
	testing.expect(t, ok)
	rec, ok2 := stream_next(data[:], &o)
	testing.expect(t, ok2)
	testing.expect_value(t, len(rec), 5)
	testing.expect_value(t, o, len(data))

	// One byte of the length only: the length comes first.
	clear(&data)
	append(&data, 0, 2, 0x20, 1, 0)
	linux.write(p.far, []u8{4, 0x20, 1, 2, 3})
	testing.expect_value(t, ahead_complete(fd, &data, 4, 500), 0)
	testing.expect_value(t, len(data), 10)
	o = 4
	rec, ok = stream_next(data[:], &o)
	testing.expect(t, ok)
	testing.expect_value(t, len(rec), 4)

	// Nothing is missing.
	clear(&data)
	append(&data, 0, 1, 0x20)
	testing.expect_value(t, ahead_complete(fd, &data, 3, 500), 0)
	testing.expect_value(t, len(data), 3)

	// The rest never comes.
	clear(&data)
	append(&data, 0, 9, 0x20)
	testing.expect_value(t, ahead_complete(fd, &data, 0, 150), ETIMEDOUT)
	testing.expect_value(t, len(data), 3)

	// The peer closes while the record is incomplete.
	linux.shutdown(p.far, .RDWR)
	testing.expect_value(t, ahead_complete(fd, &data, 0, 500), ECONNRESET)
}

@(test)
test_kernel_backend_cannot_filter :: proc(t: ^testing.T) {
	k: Kernel
	be := kernel_backend(&k)
	testing.expect_value(t, be.caps & CAP_BLOCK_IPV6, 0)
	out: Filter_Stats
	testing.expect_value(t, be.set_filter(be.user, FILTER_IPV6, &out), ENOTSUP)
}
