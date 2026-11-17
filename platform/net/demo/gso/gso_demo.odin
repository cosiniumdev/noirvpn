// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Small program for the strace check in platform/net/README.md. It sends 16
// datagrams of 1200 bytes on loopback with UDP GSO (one sendmmsg entry with a
// UDP_SEGMENT control message) and receives them with UDP GRO (one recvmmsg
// message with a UDP_GRO control message). Build static with build/musl.sh and
// run under strace: no sendmsg, recvmsg, sendto or recvfrom per packet.
package main

import "core:fmt"
import "core:os"
import net "noir:platform/net"

N :: 16
SIZE :: 1200

main :: proc() {
	rx, e1 := net.udp_open(.V4, {offload = true})
	tx, e2 := net.udp_open(.V4, {offload = true})
	if e1 != .None || e2 != .None {
		fmt.eprintln("udp_open failed", e1, e2)
		os.exit(1)
	}
	defer net.close(rx)
	defer net.close(tx)
	fmt.println("sender: gso", tx.gso, "gro", tx.gro, "; receiver: gso", rx.gso, "gro", rx.gro)
	if err := net.bind(rx, {address = net.IP4_Address{127, 0, 0, 1}, port = 0}); err != .None {
		fmt.eprintln("bind failed", err)
		os.exit(1)
	}
	dst, _ := net.local_endpoint(rx)

	sb, rb: net.Batch
	if net.batch_init(&sb, .V4, N) != .None || net.batch_init(&rb, .V4, 4) != .None {
		fmt.eprintln("batch_init failed")
		os.exit(1)
	}
	defer net.batch_destroy(&sb)
	defer net.batch_destroy(&rb)

	out: [N][SIZE]u8
	for i in 0 ..< N {
		for j in 0 ..< SIZE {
			out[i][j] = u8(i)
		}
		net.batch_push(&sb, out[i][:], dst)
	}
	// One block of up to 64 KiB per message when the socket has GRO.
	big := make([]u8, 4 * 65536)
	defer delete(big)
	for i in 0 ..< 4 {
		net.batch_set_recv(&rb, i, big[i * 65536:][:65536])
	}

	sent, serr := net.send_pushed(tx, &sb)
	fmt.println("send_pushed: datagrams", sent, "sendmmsg entries", sb.tx_msgs, "of them GSO", sb.gso_msgs, "error", serr)
	got, rerr := net.recv_batch(rx, &rb)
	fmt.println("recv_batch: messages", got, "datagrams", rb.rx_dgrams, "GRO messages", rb.rx_gro_msgs, "error", rerr)
	ok := sent == N && serr == .None && rerr == .None
	count := 0
	for m in 0 ..< got {
		size := net.batch_len(&rb, m)
		seg := net.batch_gro_size(&rb, m)
		if seg == 0 {
			seg = size
		}
		for off := 0; off < size; off += seg {
			if seg != SIZE || big[m * 65536 + off] != u8(count) {
				ok = false
			}
			count += 1
		}
	}
	ok = ok && count == N
	if !ok {
		fmt.eprintln("FAILED")
		os.exit(1)
	}
	fmt.println("ok")
}
