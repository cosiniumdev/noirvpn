// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:sys/linux"
import "core:testing"
import "noir:engine"
import "noir:platform/offload"
import "noir:platform/tun"

@(test)
offload_config_switches :: proc(t: ^testing.T) {
	all_on := Off_Config {
		tun = true,
		gso = true,
		gro = true,
	}
	testing.expect_value(t, off_parse_config(""), all_on)
	testing.expect_value(t, off_parse_config("nonsense"), all_on)
	testing.expect_value(t, off_parse_config("gso"), Off_Config{tun = true, gso = false, gro = true})
	testing.expect_value(t, off_parse_config("gro"), Off_Config{tun = true, gso = true, gro = false})
	testing.expect_value(t, off_parse_config("tun"), Off_Config{tun = false, gso = true, gro = true})
	testing.expect_value(t, off_parse_config("gso, gro"), Off_Config{tun = true, gso = false, gro = false})
	testing.expect_value(t, off_parse_config("all"), Off_Config{})
	// An empty word and a trailing comma are not an error.
	testing.expect_value(t, off_parse_config(",tun,"), Off_Config{tun = false, gso = true, gro = true})
}

@(test)
offload_receive_layout :: proc(t: ^testing.T) {
	saved := engine.OFF
	defer engine.OFF = saved

	engine.OFF = {
		tun = true,
		gso = true,
		gro = true,
	}
	msgs, slot := off_rx_layout()
	testing.expect_value(t, msgs, RX_MSGS_GRO)
	testing.expect_value(t, slot, UDP_GRO_SLOT)
	// A slot holds the largest block the kernel generates.
	testing.expect(t, slot >= 65535)

	engine.OFF.gro = false
	msgs, slot = off_rx_layout()
	testing.expect_value(t, msgs, RX_BATCH)
	testing.expect_value(t, slot, RX_SLOT)
}

@(test)
offload_rx_vlen_follows_the_budget :: proc(t: ^testing.T) {
	// No coalescing seen: one message is one datagram.
	testing.expect_value(t, rx_vlen(16, 64, 1), 16)
	testing.expect_value(t, rx_vlen(32, 64, 1), 32)
	testing.expect_value(t, rx_vlen(32, 5, 1), 5)
	// Blocks of 43 datagrams: two messages already fill the budget.
	testing.expect_value(t, rx_vlen(16, 64, 43), 2)
	testing.expect_value(t, rx_vlen(16, 256, 43), 6)
	// Always at least one message, and never more than the buffer has.
	testing.expect_value(t, rx_vlen(16, 1, 43), 1)
	testing.expect_value(t, rx_vlen(16, 100000, 1), 16)
	testing.expect_value(t, rx_vlen(16, 0, 1), 1)
	testing.expect_value(t, rx_vlen(16, 10, 0), 10)
}

@(test)
offload_inside_checks_the_memory_range :: proc(t: ^testing.T) {
	buf: [100]u8
	other: [10]u8
	testing.expect(t, inside(buf[:], buf[:]))
	testing.expect(t, inside(buf[10:20], buf[:]))
	testing.expect(t, inside(buf[90:], buf[:]))
	testing.expect(t, inside(buf[:0], buf[:]))
	testing.expect(t, !inside(other[:], buf[:]))
	testing.expect(t, !inside(buf[:], buf[10:]))
	testing.expect(t, !inside(buf[:], buf[:50]))
}

// ---------------------------------------------------------------- tun writes
//
// The tun side is tested on a socket pair that keeps message boundaries: one
// write to the "tun" is one message on the other end, so the test sees the
// writes the kernel would see (header and packet).

tt_sum :: proc(data: []u8, init: u32 = 0) -> u32 {
	s := init
	i := 0
	for ; i + 1 < len(data); i += 2 {
		s += u32(data[i]) << 8 | u32(data[i + 1])
	}
	if i < len(data) {
		s += u32(data[i]) << 8
	}
	return s
}

tt_fold :: proc(s: u32) -> u16 {
	x := s
	for x > 0xffff {
		x = (x & 0xffff) + (x >> 16)
	}
	return u16(x)
}

// A right IPv4 TCP data segment (ACK, DF, no options) of flow 10.8.0.2:40000 to
// 10.8.0.1:5201, with all checksums.
tt_packet :: proc(buf: []u8, seq: u32, id: u16, payload: []u8) -> []u8 {
	total := 40 + len(payload)
	p := buf[:total]
	for i in 0 ..< total {
		p[i] = 0
	}
	p[0] = 0x45
	p[2], p[3] = u8(total >> 8), u8(total)
	p[4], p[5] = u8(id >> 8), u8(id)
	p[6] = 0x40
	p[8] = 64
	p[9] = 6
	p[12], p[13], p[14], p[15] = 10, 8, 0, 2
	p[16], p[17], p[18], p[19] = 10, 8, 0, 1
	ic := ~tt_fold(tt_sum(p[:20]))
	p[10], p[11] = u8(ic >> 8), u8(ic)
	t := p[20:]
	t[0], t[1] = u8(40000 >> 8), u8(40000 & 0xff)
	t[2], t[3] = u8(5201 >> 8), u8(5201 & 0xff)
	t[4], t[5], t[6], t[7] = u8(seq >> 24), u8(seq >> 16), u8(seq >> 8), u8(seq)
	t[11] = 0x09 // ack 777
	t[10] = 0x03
	t[12] = 5 << 4
	t[13] = 0x10
	t[14], t[15] = 0x01, 0xf6 // window 502
	copy(t[20:], payload)
	pseudo := tt_sum(p[12:20]) + 6 + u32(len(t))
	tc := ~tt_fold(tt_sum(t, pseudo))
	t[16], t[17] = u8(tc >> 8), u8(tc)
	return p
}

Tx_Rig :: struct {
	dev:  tun.Device,
	peer: linux.Fd,
	tx:   Tun_Tx,
	st:   Offload_Stats,
}

// A "tun" on one end of a SEQPACKET pair. With `vnet` it expects the header.
rig_open :: proc(t: ^testing.T, r: ^Tx_Rig, arena: int, vnet := true) -> bool {
	fds: [2]linux.Fd
	if !testing.expect_value(t, linux.socketpair(.UNIX, .SEQPACKET, {}, &fds), linux.Errno.NONE) {
		return false
	}
	dev, err := tun.from_fd(i32(fds[0]), true, true)
	if !testing.expect_value(t, err, tun.Error.None) {
		linux.close(fds[0])
		linux.close(fds[1])
		return false
	}
	r.dev = dev
	r.dev.vnet = vnet
	r.peer = fds[1]
	r.tx.on = vnet
	if arena > 0 {
		r.tx.arena = make([]u8, arena)
	}
	return true
}

rig_close :: proc(r: ^Tx_Rig) {
	tun.close(&r.dev)
	linux.close(r.peer)
	delete(r.tx.arena)
}

// The next message the "tun" got.
rig_read :: proc(r: ^Tx_Rig, buf: []u8) -> (n: int, ok: bool) {
	got, e := linux.recv(r.peer, buf, {.DONTWAIT})
	return got, e == .NONE
}

// A payload that tells its position.
tt_payload :: proc(n, salt: int) -> []u8 {
	p := make([]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		p[i] = u8(i * 7 + salt * 31 + 1)
	}
	return p
}

// Checks one message from the tun: a joined packet of `want_segs` segments of
// `mss` bytes, the first one has payload `pay[0]`, and so on.
expect_joined :: proc(t: ^testing.T, msg: []u8, pays: [][]u8, label: string) {
	mss := len(pays[0])
	total := 0
	for p in pays {
		total += len(p)
	}
	if !testing.expectf(t, len(msg) == 10 + 40 + total, "%s: message of %d bytes, want %d", label, len(msg), 10 + 40 + total) {
		return
	}
	h, ok := offload.vnet_decode(msg[:10])
	testing.expect(t, ok, label)
	testing.expectf(t, h.flags == offload.F_NEEDS_CSUM, "%s: flags %d", label, h.flags)
	testing.expectf(t, h.gso_type == offload.GSO_TCPV4, "%s: gso type %d", label, h.gso_type)
	testing.expectf(t, int(h.gso_size) == mss, "%s: gso size %d, want %d", label, h.gso_size, mss)
	testing.expectf(t, h.hdr_len == 40 && h.csum_start == 20 && h.csum_offset == 16, "%s: header %v", label, h)
	p := msg[10:]
	testing.expectf(t, int(p[2]) << 8 | int(p[3]) == len(p), "%s: IP length", label)
	testing.expectf(t, tt_fold(tt_sum(p[:20])) == 0xffff, "%s: IP header checksum", label)
	// The checksum field holds the pseudo header sum, not inverted.
	pseudo := tt_fold(tt_sum(p[12:20]) + 6 + u32(len(p) - 20))
	testing.expectf(t, int(p[36]) << 8 | int(p[37]) == int(pseudo), "%s: TCP checksum field", label)
	off := 40
	for pay, i in pays {
		same := string(p[off:][:len(pay)]) == string(pay)
		testing.expectf(t, same, "%s: payload of segment %d", label, i)
		off += len(pay)
	}
}

@(test)
tun_tx_joins_the_segments_of_the_receive_buffer :: proc(t: ^testing.T) {
	r := new(Tx_Rig)
	defer free(r)
	if !rig_open(t, r, 0) {
		return
	}
	defer rig_close(r)

	stable := make([]u8, 8000, context.temp_allocator)
	pays: [4][]u8
	off := 0
	for i in 0 ..< 4 {
		pays[i] = tt_payload(1000, i)
		p := tt_packet(stable[off:], u32(5000 + 1000 * i), u16(100 + i), pays[i])
		off += len(p)
		tun_tx_push(&r.dev, &r.tx, &r.st, p, stable)
	}
	// Nothing is written while the run is open.
	buf: [70000]u8
	_, got := rig_read(r, buf[:])
	testing.expect(t, !got, "a write before the flush")
	tun_tx_flush(&r.dev, &r.tx, &r.st)
	n: int
	n, got = rig_read(r, buf[:])
	testing.expect(t, got)
	expect_joined(t, buf[:n], pays[:], "four segments")
	_, got = rig_read(r, buf[:])
	testing.expect(t, !got, "one write for the run")
	testing.expect_value(t, r.st.tun_writes, 1)
	testing.expect_value(t, r.st.tun_coalesced, 1)
	testing.expect_value(t, r.st.tun_coalesced_segs, 4)
	testing.expect_value(t, r.tx.wrote_pkts, 4)
	testing.expect_value(t, r.tx.wrote_bytes, 4040)
	testing.expect_value(t, r.tx.dropped, 0)
}

// The packets of a TCP stream are in memory that the next packet overwrites
// (the stream is reassembled in a buffer of the session): they must be copied.
@(test)
tun_tx_copies_packets_that_are_not_in_the_receive_buffer :: proc(t: ^testing.T) {
	r := new(Tx_Rig)
	defer free(r)
	if !rig_open(t, r, 128 * 1024) {
		return
	}
	defer rig_close(r)

	stable := make([]u8, 100, context.temp_allocator)
	scratch := make([]u8, 2000, context.temp_allocator)
	pays: [4][]u8
	for i in 0 ..< 4 {
		pays[i] = tt_payload(1000, i)
		p := tt_packet(scratch, u32(5000 + 1000 * i), u16(100 + i), pays[i])
		tun_tx_push(&r.dev, &r.tx, &r.st, p, stable)
		// The session reuses the memory for the next packet.
		for k in 0 ..< len(scratch) {
			scratch[k] = 0xee
		}
	}
	tun_tx_flush(&r.dev, &r.tx, &r.st)
	buf: [70000]u8
	n, got := rig_read(r, buf[:])
	testing.expect(t, got)
	expect_joined(t, buf[:n], pays[:], "copied segments")
	testing.expect_value(t, r.tx.wrote_pkts, 4)
	// The copy area is free again.
	testing.expect_value(t, r.tx.arena_used, 0)
}

// With no copy area a packet outside the receive buffer is written at once,
// with the open runs before it, in order.
@(test)
tun_tx_without_a_copy_area_writes_at_once :: proc(t: ^testing.T) {
	r := new(Tx_Rig)
	defer free(r)
	if !rig_open(t, r, 0) {
		return
	}
	defer rig_close(r)

	stable := make([]u8, 4000, context.temp_allocator)
	scratch := make([]u8, 2000, context.temp_allocator)
	pays: [3][]u8
	off := 0
	for i in 0 ..< 2 {
		pays[i] = tt_payload(1000, i)
		p := tt_packet(stable[off:], u32(5000 + 1000 * i), u16(100 + i), pays[i])
		off += len(p)
		tun_tx_push(&r.dev, &r.tx, &r.st, p, stable)
	}
	pays[2] = tt_payload(1000, 2)
	p := tt_packet(scratch, 7000, 102, pays[2])
	tun_tx_push(&r.dev, &r.tx, &r.st, p, stable)
	for k in 0 ..< len(scratch) {
		scratch[k] = 0xee
	}
	// Everything is out already, before the flush.
	buf: [70000]u8
	n, got := rig_read(r, buf[:])
	testing.expect(t, got)
	expect_joined(t, buf[:n], pays[:], "written at once")
	testing.expect_value(t, r.tx.wrote_pkts, 3)
}

// A copy area that is full is written out first.
@(test)
tun_tx_writes_when_the_copy_area_is_full :: proc(t: ^testing.T) {
	r := new(Tx_Rig)
	defer free(r)
	if !rig_open(t, r, 3000) { 	// room for two packets of 1040 bytes
		return
	}
	defer rig_close(r)

	stable := make([]u8, 100, context.temp_allocator)
	scratch := make([]u8, 2000, context.temp_allocator)
	pays: [4][]u8
	for i in 0 ..< 4 {
		pays[i] = tt_payload(1000, i)
		p := tt_packet(scratch, u32(5000 + 1000 * i), u16(100 + i), pays[i])
		tun_tx_push(&r.dev, &r.tx, &r.st, p, stable)
		for k in 0 ..< len(scratch) {
			scratch[k] = 0xee
		}
	}
	tun_tx_flush(&r.dev, &r.tx, &r.st)
	buf: [70000]u8
	n, got := rig_read(r, buf[:])
	testing.expect(t, got)
	expect_joined(t, buf[:n], pays[0:2], "first two")
	n, got = rig_read(r, buf[:])
	testing.expect(t, got)
	expect_joined(t, buf[:n], pays[2:4], "last two")
	_, got = rig_read(r, buf[:])
	testing.expect(t, !got)
	testing.expect_value(t, r.tx.wrote_pkts, 4)
}

// Packets that cannot be joined go out as they are, with a header of zeros.
@(test)
tun_tx_plain_packets_get_a_zero_header :: proc(t: ^testing.T) {
	r := new(Tx_Rig)
	defer free(r)
	if !rig_open(t, r, 0) {
		return
	}
	defer rig_close(r)

	stable := make([]u8, 4000, context.temp_allocator)
	// Not TCP, and a TCP segment with a wrong checksum.
	junk := stable[:28]
	junk[0] = 0x45
	junk[3] = 28
	junk[9] = 17
	bad := tt_packet(stable[100:], 5000, 100, tt_payload(500, 0))
	bad[len(bad) - 1] ~= 0xff
	want_bad := make([]u8, len(bad), context.temp_allocator)
	copy(want_bad, bad)
	tun_tx_push(&r.dev, &r.tx, &r.st, junk, stable)
	tun_tx_push(&r.dev, &r.tx, &r.st, bad, stable)
	tun_tx_flush(&r.dev, &r.tx, &r.st)
	buf: [2000]u8
	n, got := rig_read(r, buf[:])
	testing.expect(t, got)
	testing.expect_value(t, n, 10 + 28)
	for i in 0 ..< 10 {
		testing.expect_value(t, buf[i], 0)
	}
	n, got = rig_read(r, buf[:])
	testing.expect(t, got)
	testing.expect_value(t, n, 10 + len(want_bad))
	testing.expect(t, string(buf[10:n]) == string(want_bad), "the packet with the wrong checksum is not changed")
	testing.expect_value(t, r.st.tun_coalesced, 0)
	testing.expect_value(t, r.tx.wrote_pkts, 2)
}

// The kernel refuses a joined packet: the packets of it are lost, joining goes
// off for good, and the plain path takes over.
@(test)
tun_tx_refused_join_switches_joining_off :: proc(t: ^testing.T) {
	r := new(Tx_Rig)
	defer free(r)
	if !rig_open(t, r, 0) {
		return
	}
	defer rig_close(r)
	// A small send buffer: a message over about 9 KiB gets EMSGSIZE.
	small := i32(4096)
	testing.expect_value(t, linux.setsockopt_sock(linux.Fd(r.dev.fd), .SOCKET, .SNDBUF, &small), linux.Errno.NONE)

	stable := make([]u8, 40 * 1040, context.temp_allocator)
	off := 0
	for i in 0 ..< 20 {
		p := tt_packet(stable[off:], u32(5000 + 1000 * i), u16(100 + i), tt_payload(1000, i))
		off += len(p)
		tun_tx_push(&r.dev, &r.tx, &r.st, p, stable)
	}
	tun_tx_flush(&r.dev, &r.tx, &r.st)
	testing.expect(t, !r.tx.on, "joining is off")
	testing.expect_value(t, r.st.tun_write_errors, 1)
	testing.expect_value(t, r.tx.dropped, 20)
	testing.expect_value(t, r.tx.wrote_pkts, 0)
	buf: [70000]u8
	_, got := rig_read(r, buf[:])
	testing.expect(t, !got, "nothing was written")
}

// The data path of the client with joining off, and with a device that has no
// header at all (the kernel refused the offloads).
@(test)
client_write_tun_plain_paths :: proc(t: ^testing.T) {
	d := new(Daemon)
	defer free(d)
	r := new(Tx_Rig)
	defer free(r)
	pkt_buf: [200]u8
	pkt := tt_packet(pkt_buf[:], 5000, 100, tt_payload(100, 0))

	// A header on the device, joining off: the plain write adds zeros.
	if !rig_open(t, r, 0) {
		return
	}
	d.tun = r.dev
	d.tun_open = true
	d.tun_tx.on = false
	write_tun(d, pkt)
	buf: [2000]u8
	n, got := rig_read(r, buf[:])
	testing.expect(t, got)
	testing.expect_value(t, n, 10 + len(pkt))
	for i in 0 ..< 10 {
		testing.expect_value(t, buf[i], 0)
	}
	testing.expect(t, string(buf[10:n]) == string(pkt))
	testing.expect_value(t, d.stats.tun_write_pkts, 1)
	testing.expect_value(t, d.off.tun_writes, 1)
	rig_close(r)
	r^ = {}

	// No header: the packet as it is.
	if !rig_open(t, r, 0, vnet = false) {
		return
	}
	defer rig_close(r)
	d.tun = r.dev
	write_tun(d, pkt)
	n, got = rig_read(r, buf[:])
	testing.expect(t, got)
	testing.expect_value(t, n, len(pkt))
	testing.expect(t, string(buf[:n]) == string(pkt))
	testing.expect_value(t, d.stats.tun_write_pkts, 2)
}

@(test)
server_tun_write_plain_paths :: proc(t: ^testing.T) {
	d := new(Srv)
	defer free(d)
	r := new(Tx_Rig)
	defer free(r)
	pkt_buf: [200]u8
	pkt := tt_packet(pkt_buf[:], 5000, 100, tt_payload(100, 0))

	if !rig_open(t, r, 0) {
		return
	}
	d.tun = r.dev
	d.tun_open = true
	d.tun_tx.on = false
	tun_write(d, pkt)
	buf: [2000]u8
	n, got := rig_read(r, buf[:])
	testing.expect(t, got)
	testing.expect_value(t, n, 10 + len(pkt))
	testing.expect(t, string(buf[10:n]) == string(pkt))
	testing.expect_value(t, d.stats.tun_write_pkts, 1)
	rig_close(r)
	r^ = {}

	if !rig_open(t, r, 0, vnet = false) {
		return
	}
	defer rig_close(r)
	d.tun = r.dev
	tun_write(d, pkt)
	n, got = rig_read(r, buf[:])
	testing.expect(t, got)
	testing.expect_value(t, n, len(pkt))
	testing.expect_value(t, d.stats.tun_write_pkts, 2)
}
