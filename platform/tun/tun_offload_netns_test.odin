// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package tun

import "core:sys/linux"
import "core:testing"
import "core:time"

// Tests of the virtio header and the offloads on a real tun device. Like the
// other namespace tests they run only with -define:NOIR_NETNS_TESTS=true in a
// private network namespace (platform/run-netns-tests.sh).

// A naive RFC 1071 sum of `data` (16 bit words, an odd last byte is the high
// half of a word), added to `init`. Not folded.
sum16 :: proc(data: []u8, init: u32 = 0) -> u32 {
	sum := init
	i := 0
	for ; i + 1 < len(data); i += 2 {
		sum += u32(data[i]) << 8 | u32(data[i + 1])
	}
	if i < len(data) {
		sum += u32(data[i]) << 8
	}
	return sum
}

fold16 :: proc(sum: u32) -> u16 {
	s := sum
	for s > 0xffff {
		s = (s & 0xffff) + (s >> 16)
	}
	return u16(s)
}

// IPv4 TCP packet: `payload` after a 20 byte header and `opts` (a multiple of
// 4 bytes) of TCP options. The checksums are computed in full.
build_tcp4 :: proc(
	out: []u8,
	src, dst: [4]u8,
	sport, dport: u16,
	seq, ack: u32,
	flags: u8,
	opts: []u8,
	payload: []u8,
) -> int {
	thl := 20 + len(opts)
	total := 20 + thl + len(payload)
	for i in 0 ..< total {
		out[i] = 0
	}
	out[0] = 0x45
	out[2], out[3] = u8(total >> 8), u8(total)
	out[6] = 0x40 // DF
	out[8] = 64
	out[9] = 6
	s, d := src, dst
	copy(out[12:16], s[:])
	copy(out[16:20], d[:])
	c := ~fold16(sum16(out[:20]))
	out[10], out[11] = u8(c >> 8), u8(c)
	t := out[20:total]
	t[0], t[1] = u8(sport >> 8), u8(sport)
	t[2], t[3] = u8(dport >> 8), u8(dport)
	t[4], t[5], t[6], t[7] = u8(seq >> 24), u8(seq >> 16), u8(seq >> 8), u8(seq)
	t[8], t[9], t[10], t[11] = u8(ack >> 24), u8(ack >> 16), u8(ack >> 8), u8(ack)
	t[12] = u8(thl / 4) << 4
	t[13] = flags
	t[14], t[15] = 0xff, 0xff // window
	copy(t[20:], opts)
	copy(t[thl:], payload)
	// pseudo header
	pseudo := sum16(out[12:20]) + 6 + u32(len(t))
	cs := ~fold16(sum16(t, pseudo))
	t[16], t[17] = u8(cs >> 8), u8(cs)
	return total
}

// True if the IPv4 header and the TCP checksum of `pkt` are valid.
tcp4_valid :: proc(pkt: []u8) -> bool {
	if len(pkt) < 40 || pkt[0] != 0x45 {
		return false
	}
	if fold16(sum16(pkt[:20])) != 0xffff {
		return false
	}
	total := int(pkt[2]) << 8 | int(pkt[3])
	if total != len(pkt) {
		return false
	}
	t := pkt[20:]
	pseudo := sum16(pkt[12:20]) + 6 + u32(len(t))
	return fold16(sum16(t, pseudo)) == 0xffff
}

SIOCSIFADDR :: 0x8916
SIOCSIFNETMASK :: 0x891c

// Give the interface an IPv4 address and prefix with the classic ioctls (the
// connected route appears with them).
set_addr4 :: proc(dev: ^Device, addr: [4]u8, prefix: int) -> Error {
	ifr: Ifreq
	copy(ifr.name[:], name(dev))
	a := addr
	ifr._pad[0] = 2 // AF_INET
	copy(ifr._pad[4:8], a[:])
	if e := if_ioctl(SIOCSIFADDR, &ifr); e != .None {
		return e
	}
	mask := u32(0xffffffff) << u32(32 - prefix)
	m := [4]u8{u8(mask >> 24), u8(mask >> 16), u8(mask >> 8), u8(mask)}
	ifr._pad = {}
	ifr._pad[0] = 2
	copy(ifr._pad[4:8], m[:])
	return if_ioctl(SIOCSIFNETMASK, &ifr)
}

// Reads from the device until it has a packet (or about 1 s passed).
read_wait :: proc(dev: ^Device, buf: []u8) -> (n: int, err: Error) {
	for _ in 0 ..< 1000 {
		n, err = read(dev, buf)
		if err != .Would_Block {
			return
		}
		time.sleep(time.Millisecond)
	}
	return 0, .Would_Block
}

// Expects `pkt` to be a valid IPv4 TCP packet (header and TCP checksums).
expect_tcp4_valid :: proc(t: ^testing.T, pkt: []u8, what: string) {
	testing.expect(t, tcp4_valid(pkt), what)
}

close_fd :: proc(fd: linux.Fd) {
	linux.close(fd)
}

when NETNS {

	@(test)
	netns_offload_open_negotiates :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirvh0", offload = true})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)
		testing.expect(t, dev.vnet, "this kernel takes IFF_VNET_HDR")
		testing.expect(t, .Csum in dev.offloads && .Tso4 in dev.offloads && .Tso6 in dev.offloads)

		flags, ferr := get_flags(&dev)
		testing.expect_value(t, ferr, Error.None)
		testing.expect(t, flags & IFF_VNET_HDR != 0)
		sz: i32
		testing.expect_value(t, sys_ioctl(dev.fd, TUNGETVNETHDRSZ, &sz), linux.Errno.NONE)
		testing.expect_value(t, sz, VNET_HDR_LEN)

		// A plain open has neither.
		plain, perr := open({name = "noirvh1"})
		testing.expect_value(t, perr, Error.None)
		defer close(&plain)
		testing.expect(t, !plain.vnet)
		testing.expect_value(t, plain.offloads, Offload_Set{})
		pf, _ := get_flags(&plain)
		testing.expect(t, pf & IFF_VNET_HDR == 0)
	}

	@(test)
	netns_offload_queues_share_the_setting :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		q0, e0 := open({name = "noirvmq0", multi_queue = true, offload = true})
		testing.expect_value(t, e0, Error.None)
		defer close(&q0)
		q1, e1 := open_queue(&q0)
		testing.expect_value(t, e1, Error.None)
		defer close(&q1)
		testing.expect_value(t, q1.vnet, q0.vnet)
		testing.expect_value(t, q1.offloads, q0.offloads)
	}

	@(test)
	netns_offload_write_adds_a_zero_header :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirvw0", offload = true})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)
		if !dev.vnet {
			return
		}
		pkt := ipv4_header({10, 198, 0, 1}, {10, 198, 0, 2}, 0)
		testing.expect_value(t, write(&dev, pkt[:]), Error.Io) // link down
		testing.expect_value(t, set_link(&dev, true), Error.None)
		testing.expect_value(t, write(&dev, pkt[:]), Error.None)
		// The same through write_v, with a header of our own.
		hdr: [VNET_HDR_LEN]u8
		pieces := [2][]u8{hdr[:], pkt[:]}
		testing.expect_value(t, write_v(&dev, pieces[:]), Error.None)
		// A packet cut in pieces is joined.
		pieces3 := [3][]u8{hdr[:], pkt[:7], pkt[7:]}
		testing.expect_value(t, write_v(&dev, pieces3[:]), Error.None)
		testing.expect_value(t, write_v(&dev, nil), Error.Invalid)
		// Not an IP packet: refused.
		junk: [20]u8
		testing.expect_value(t, write(&dev, junk[:]), Error.Invalid)
	}

	// The kernel gives a TCP sender's large packet to the device as one read:
	// a GSO packet with a partial checksum. We play the TCP peer by hand.
	@(test)
	netns_offload_kernel_hands_over_a_tso_packet :: proc(t: ^testing.T) {
		if !require_private_netns(t) {
			return
		}
		dev, err := open({name = "noirvt0", offload = true})
		testing.expect_value(t, err, Error.None)
		defer close(&dev)
		if !dev.vnet || .Tso4 not_in dev.offloads {
			return
		}
		testing.expect_value(t, set_link(&dev, true), Error.None)
		testing.expect_value(t, set_addr4(&dev, {10, 197, 0, 1}, 24), Error.None)

		sock, serr := linux.socket(.INET, .STREAM, {.NONBLOCK, .CLOEXEC}, .TCP)
		testing.expect_value(t, serr, linux.Errno.NONE)
		defer close_fd(sock)
		peer := linux.Sock_Addr_In {
			sin_family = .INET,
			sin_port   = u16be(5000),
			sin_addr   = {10, 197, 0, 2},
		}
		ce := linux.connect(sock, &peer)
		testing.expect_value(t, ce, linux.Errno.EINPROGRESS)

		buf: [VNET_HDR_LEN + 65536]u8
		// The kernel may send IPv6 router solicitations first: skip them.
		syn: []u8
		for _ in 0 ..< 20 {
			n, rerr := read_wait(&dev, buf[:])
			if rerr != .None {
				break
			}
			p := buf[VNET_HDR_LEN:n]
			if len(p) >= 40 && p[0] == 0x45 && p[9] == 6 && p[33] & 0x12 == 0x02 {
				syn = p
				break
			}
		}
		testing.expect(t, len(syn) >= 40, "a SYN")
		if len(syn) < 40 {
			return
		}
		client_port := u16(syn[20]) << 8 | u16(syn[21])
		client_isn := u32(syn[24]) << 24 | u32(syn[25]) << 16 | u32(syn[26]) << 8 | u32(syn[27])
		// The SYN-ACK: MSS 1460, window scale 0, no timestamps.
		opts := [4]u8{2, 4, 0x05, 0xb4}
		reply: [128]u8
		m := build_tcp4(reply[:], {10, 197, 0, 2}, {10, 197, 0, 1}, 5000, client_port, 1000, client_isn + 1, 0x12, opts[:], nil)
		testing.expect_value(t, write(&dev, reply[:m]), Error.None)

		// Wait until the connection is up, then reply to the bare ACK it sends.
		for _ in 0 ..< 1000 {
			e := linux.connect(sock, &peer)
			if e == .EISCONN {
				break
			}
			time.sleep(time.Millisecond)
		}
		// Send 40 kB: the first flight is ten segments.
		data: [40000]u8
		sent := 0
		for sent < len(data) {
			w, we := linux.send(sock, data[sent:], {.DONTWAIT})
			if we != .NONE {
				break
			}
			sent += w
		}
		testing.expect(t, sent > 0)

		found_gso := false
		for _ in 0 ..< 50 {
			rn, re := read_wait(&dev, buf[:])
			if re != .None {
				break
			}
			if rn < VNET_HDR_LEN + 40 {
				continue
			}
			flags := buf[0]
			gso_type := buf[1]
			gso_size := int(buf[4]) | int(buf[5]) << 8
			csum_start := int(buf[6]) | int(buf[7]) << 8
			csum_off := int(buf[8]) | int(buf[9]) << 8
			pkt := buf[VNET_HDR_LEN:rn]
			if gso_type & 0x7f == 1 { 	// GSO_TCPV4
				found_gso = true
				testing.expect(t, flags & 1 != 0, "a GSO packet has NEEDS_CSUM")
				testing.expect_value(t, csum_start, 20)
				testing.expect_value(t, csum_off, 16)
				testing.expect(t, gso_size > 0 && gso_size <= 1460)
				testing.expect(t, len(pkt) > 1500, "larger than the MTU")
				break
			}
		}
		testing.expect(t, found_gso, "the kernel handed over a TCP segmentation offload packet")
	}
}
