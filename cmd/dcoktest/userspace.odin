// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:sys/linux"
import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/ossl"

// A peer with no device, for the interop check of packet and key layout: data
// packets are sealed and opened with the daemon's data channel code (proto/crypt).
// The kernel on the other host holds the same keys. This end sends ICMP echo
// requests to `--peer-vpn` (the kernel host's address), replies to the ones it
// receives, and counts the replies.

icmp_checksum :: proc(b: []u8) -> u16 {
	sum: u32
	for i := 0; i + 1 < len(b); i += 2 {
		sum += u32(b[i]) << 8 | u32(b[i + 1])
	}
	if len(b) % 2 == 1 {
		sum += u32(b[len(b) - 1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ~u16(sum)
}

// An IPv4 ICMP message (type 8 request or 0 reply) with `payload`.
build_icmp :: proc(src_in, dst_in: [4]u8, typ: u8, id, seq: u16, payload: []u8) -> []u8 {
	src, dst := src_in, dst_in
	total := 20 + 8 + len(payload)
	p := make([]u8, total, context.temp_allocator)
	p[0] = 0x45
	p[2] = u8(total >> 8)
	p[3] = u8(total)
	p[6] = 0x40 // don't fragment
	p[8] = 64
	p[9] = 1
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	ck := icmp_checksum(p[:20])
	p[10], p[11] = u8(ck >> 8), u8(ck)
	p[20] = typ
	p[24], p[25] = u8(id >> 8), u8(id)
	p[26], p[27] = u8(seq >> 8), u8(seq)
	copy(p[28:], payload)
	ik := icmp_checksum(p[20:])
	p[22], p[23] = u8(ik >> 8), u8(ik)
	return p
}

run_userspace :: proc(c: ^Cfg) -> int {
	cipher: ossl.Aead_Cipher
	switch {
	case c.cipher == .Chacha20_Poly1305:
		cipher = .CHACHA20_POLY1305
	case c.key_len == 16:
		cipher = .AES_128_GCM
	case c.key_len == 32:
		cipher = .AES_256_GCM
	case:
		say("this cipher is not supported by the daemon's data channel")
		return 1
	}
	k := derive_key(c, 0, .Primary)
	km: keys.Key_Material
	km.send.key_len = c.key_len
	km.recv.key_len = c.key_len
	copy(km.send.key[:], k.enc_key[:c.key_len])
	copy(km.send.iv[:], k.enc_nonce[:])
	copy(km.recv.key[:], k.dec_key[:c.key_len])
	copy(km.recv.iv[:], k.dec_nonce[:])
	dk: crypt.Data_Key
	if err := crypt.data_key_init(&dk, .Baseline, cipher, 0, &km); err != .None {
		say("data_key_init: %v", err)
		return 1
	}
	defer crypt.data_key_destroy(&dk)

	fd := udp_bind(c.local, c.lport, false)
	if fd < 0 {
		return 1
	}
	defer linux.close(fd)
	sig := open_signals()
	remote := linux.Sock_Addr_In {
		sin_family = .INET,
		sin_port   = u16be(c.rport),
		sin_addr   = c.remote,
	}

	send_plain :: proc(dk: ^crypt.Data_Key, fd: linux.Fd, to: ^linux.Sock_Addr_In, peer_id: u32, plain: []u8) -> bool {
		out: [2048]u8
		n, err := crypt.data_key_seal(dk, peer_id, plain, out[:])
		if err != .None {
			say("seal: %v", err)
			return false
		}
		_, e := linux.sendto(fd, out[:n], {}, to)
		return e == .NONE
	}

	sent, replies, answered, keepalives, bad, other := 0, 0, 0, 0, 0, 0
	rtt_sum: time.Duration
	sent_at := make([]time.Tick, 65536)
	defer delete(sent_at)
	total := time.Duration(c.ping_count) * 200 * time.Millisecond + 3 * time.Second
	if c.duration > 0 {
		total = time.Duration(c.duration) * time.Second
	}
	begin := time.tick_now()
	next_ping := begin
	next_ka := time.tick_add(begin, 5 * time.Second)
	say("userspace peer: sealing with the daemon's data channel code (%v), peer id %d", cipher, c.peer_id)
	for {
		now := time.tick_now()
		if time.tick_diff(begin, now) >= total {
			break
		}
		if sent < c.ping_count && time.tick_diff(next_ping, now) >= 0 {
			next_ping = time.tick_add(now, 200 * time.Millisecond)
			sent += 1
			payload := make([]u8, 56, context.temp_allocator)
			for i in 0 ..< len(payload) {
				payload[i] = u8(i)
			}
			pkt := build_icmp(c.vpn, c.peer_vpn, 8, 0x4e56, u16(sent), payload)
			sent_at[sent] = now
			send_plain(&dk, fd, &remote, c.peer_id, pkt)
		}
		if time.tick_diff(next_ka, now) >= 0 {
			next_ka = time.tick_add(now, 5 * time.Second)
			pb: [16]u8
			if plain, ok := crypt.build_ping(pb[:]); ok {
				send_plain(&dk, fd, &remote, c.peer_id, plain)
			}
		}
		pfds := [2]linux.Poll_Fd{{fd = sig, events = {.IN}}, {fd = fd, events = {.IN}}}
		linux.poll(pfds[:], 50)
		if .IN in pfds[0].revents {
			break
		}
		for _ in 0 ..< 64 {
			buf: [2048]u8
			src: linux.Sock_Addr_In
			n, e := linux.recvfrom(fd, buf[:], {.DONTWAIT}, &src)
			if e != .NONE || n <= 0 {
				break
			}
			out: [2048]u8
			res, oerr := crypt.data_key_open(&dk, buf[:n], out[:])
			if oerr != .None {
				bad += 1
				say("open failed: %v (%d bytes, first byte %#x)", oerr, n, buf[0])
				continue
			}
			if res.peer_id != c.peer_id {
				say("packet has peer id %d, expected %d", res.peer_id, c.peer_id)
			}
			plain := out[:res.n]
			#partial switch crypt.classify_payload(plain) {
			case .Ping:
				keepalives += 1
			case .Ipv4:
				if len(plain) >= 28 && plain[9] == 1 {
					switch plain[20] {
					case 0:
						replies += 1
						seq := int(plain[26]) << 8 | int(plain[27])
						if seq > 0 && seq < len(sent_at) {
							rtt_sum += time.tick_diff(sent_at[seq], time.tick_now())
						}
					case 8:
						// An echo request from the kernel host: reply to it.
						answered += 1
						s := [4]u8{plain[12], plain[13], plain[14], plain[15]}
						d := [4]u8{plain[16], plain[17], plain[18], plain[19]}
						id := u16(plain[24]) << 8 | u16(plain[25])
						seq := u16(plain[26]) << 8 | u16(plain[27])
						reply := build_icmp(d, s, 0, id, seq, plain[28:])
						send_plain(&dk, fd, &remote, c.peer_id, reply)
					}
				} else {
					other += 1
				}
			case:
				other += 1
			}
		}
	}
	avg := f64(0)
	if replies > 0 {
		avg = time.duration_milliseconds(rtt_sum) / f64(replies)
	}
	say("userspace summary: echo requests sent %d, replies opened %d (avg %.3f ms), requests from the kernel replied to %d, keepalives opened %d, open failures %d, other %d", sent, replies, avg, answered, keepalives, bad, other)
	if sent > 0 && replies == sent {
		say("PASS: every packet sealed here was opened by the kernel, and every reply opened here")
		return 0
	}
	if sent == 0 && answered > 0 {
		say("PASS: the kernel's packets open here, and the replies sealed here were accepted by the kernel")
		return 0
	}
	return 1
}
