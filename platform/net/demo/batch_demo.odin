// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Small program for the strace check in platform/net/README.md. It sends and
// receives a batch of datagrams on loopback and prints how many each batch
// call moved. Build static with build/musl.sh and run under strace: one
// sendmmsg and one recvmmsg carry all, no sendmsg or recvmsg per packet.
package main

import "core:fmt"
import "core:os"
import net "noir:platform/net"

N :: 32
SLOT :: 128

main :: proc() {
	rx, e1 := net.udp_open(.V4)
	tx, e2 := net.udp_open(.V4)
	if e1 != .None || e2 != .None {
		fmt.eprintln("udp_open failed", e1, e2)
		os.exit(1)
	}
	defer net.close(rx)
	defer net.close(tx)
	if err := net.bind(rx, {address = net.IP4_Address{127, 0, 0, 1}, port = 0}); err != .None {
		fmt.eprintln("bind failed", err)
		os.exit(1)
	}
	dst, _ := net.local_endpoint(rx)

	send_batch: net.Batch
	recv_batch: net.Batch
	if net.batch_init(&send_batch, .V4, N) != .None || net.batch_init(&recv_batch, .V4, N) != .None {
		fmt.eprintln("batch_init failed")
		os.exit(1)
	}
	defer net.batch_destroy(&send_batch)
	defer net.batch_destroy(&recv_batch)

	out: [N][SLOT]u8
	in_: [N][SLOT]u8
	for i in 0 ..< N {
		for j in 0 ..< 20 {
			out[i][j] = u8(i)
		}
		net.batch_set_send(&send_batch, i, out[i][:20], dst)
		net.batch_set_recv(&recv_batch, i, in_[i][:])
	}

	sent, serr := net.send_batch(tx, &send_batch, N)
	fmt.println("send_batch: sent", sent, "error", serr)
	got, rerr := net.recv_batch(rx, &recv_batch)
	fmt.println("recv_batch: received", got, "error", rerr)
	ok := sent == N && got == N
	for i in 0 ..< got {
		if net.batch_len(&recv_batch, i) != 20 || in_[i][0] != u8(i) {
			ok = false
		}
	}
	if !ok {
		fmt.eprintln("FAILED")
		os.exit(1)
	}
	fmt.println("ok")
}
