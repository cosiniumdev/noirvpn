// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "core:testing"
import "noir:proto/keys"
import "noir:proto/ossl"

// Every single-bit change of a genuine packet, and every truncation, must be
// refused, and must leave the receiver as it was: no counter, no replay window.
@(test)
every_bit_flip_is_refused :: proc(t: ^testing.T) {
	for format in keys.Format {
		for cipher in ossl.Aead_Cipher {
			client, server, ok := make_pair(t, format, cipher, 2)
			if !ok {
				continue
			}
			defer data_key_destroy(&client)
			defer data_key_destroy(&server)
			pt := make([]u8, 48, context.temp_allocator)
			for &b, i in pt {
				b = u8(i * 5)
			}
			pt[0] = 0x60
			pkt := make([]u8, 48 + packet_overhead(format), context.temp_allocator)
			n, err := data_key_seal(&client, 0x123456, pt, pkt)
			testing.expect_value(t, err, Error.None)
			out := make([]u8, 64, context.temp_allocator)
			bad := make([]u8, n, context.temp_allocator)

			attempts := 0
			for i in 0 ..< n {
				for bit in 0 ..< 8 {
					copy(bad, pkt[:n])
					bad[i] ~= u8(1) << u8(bit)
					_, oerr := data_key_open(&server, bad, out)
					attempts += 1
					if !testing.expectf(t, oerr != .None, "%v %v: flipping byte %d bit %d was accepted", format, cipher, i, bit) {
						return
					}
					// Which error: the first byte and the epoch are checked
					// early. The tag catches everything else (or it is packet
					// id 0 in the baseline format).
					switch {
					case i == 0 && bit < 3:
						testing.expect_value(t, oerr, Error.Wrong_Key_Id)
					case i == 0:
						testing.expect_value(t, oerr, Error.Not_Data_Packet)
					case format == .Epoch && i >= 4 && i < 6:
						// A different epoch: unknown (outside the window) or a
						// future key whose tag fails.
						testing.expect(t, oerr == .Unknown_Epoch || oerr == .Bad_Tag, "epoch field")
					case:
						testing.expect(t, oerr == .Bad_Tag || oerr == .Bad_Packet_Id, "other field")
					}
				}
			}
			testing.expect_value(t, attempts, n * 8)
			// Nothing was accepted or counted as traffic.
			testing.expect_value(t, server.rx.pkts, 0)
			testing.expect_value(t, rx_usage(&server.rx).pid, 0)
			testing.expect_value(t, rx_usage(&server.rx).blocks, 0)
			testing.expect_value(t, rx_epoch(&server.rx), 1 if format == .Epoch else 0)
			// The genuine packet is still fresh.
			res, gerr := data_key_open(&server, pkt[:n], out)
			testing.expect_value(t, gerr, Error.None)
			expect_bytes(t, out[:res.n], pt, "plaintext")
		}
	}
}

// Shortened and lengthened packets.
@(test)
truncated_and_extended_packets_are_refused :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .AES_256_GCM)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := make([]u8, 30, context.temp_allocator)
		pt[0] = 0x45
		pkt := make([]u8, 30 + packet_overhead(format), context.temp_allocator)
		n, _ := data_key_seal(&client, 0, pt, pkt)
		out := make([]u8, 64, context.temp_allocator)
		min_len := packet_overhead(format)
		for l in 0 ..< n {
			_, err := data_key_open(&server, pkt[:l], out)
			testing.expectf(t, err != .None, "%d of %d bytes were accepted", l, n)
			if l < min_len {
				testing.expect_value(t, err, Error.Too_Short)
			} else {
				testing.expect_value(t, err, Error.Bad_Tag)
			}
		}
		// One more byte on the end.
		longer := make([]u8, n + 1, context.temp_allocator)
		copy(longer, pkt[:n])
		_, err := data_key_open(&server, longer, out)
		testing.expect_value(t, err, Error.Bad_Tag)
		// A packet of exactly the minimum length with a fake tag.
		empty := make([]u8, min_len, context.temp_allocator)
		copy(empty, pkt[:min_len])
		_, err = data_key_open(&server, empty, out)
		testing.expect_value(t, err, Error.Bad_Tag)
		testing.expect_value(t, server.rx.pkts, 0)
	}
}

// A packet opened by the wrong peer: the keys differ, so does the tag check.
@(test)
packets_of_another_session_are_refused :: proc(t: ^testing.T) {
	for format in keys.Format {
		a_client, a_server, ok := make_pair(t, format, .AES_256_GCM, 0, 1)
		if !ok {
			continue
		}
		b_client, b_server, ok2 := make_pair(t, format, .AES_256_GCM, 0, 2)
		if !ok2 {
			data_key_destroy(&a_client)
			data_key_destroy(&a_server)
			continue
		}
		defer data_key_destroy(&a_client)
		defer data_key_destroy(&a_server)
		defer data_key_destroy(&b_client)
		defer data_key_destroy(&b_server)
		pt := make([]u8, 40, context.temp_allocator)
		pt[0] = 0x45
		pkt := make([]u8, 40 + packet_overhead(format), context.temp_allocator)
		n, _ := data_key_seal(&a_client, 0, pt, pkt)
		out := make([]u8, 64, context.temp_allocator)
		_, err := data_key_open(&b_server, pkt[:n], out)
		testing.expect_value(t, err, Error.Bad_Tag)
		// A client's packet does not open with the client's own receive key
		// (that is the other direction).
		_, err = data_key_open(&a_client, pkt[:n], out)
		testing.expect_value(t, err, Error.Bad_Tag)
		_, err = data_key_open(&a_server, pkt[:n], out)
		testing.expect_value(t, err, Error.None)
	}
}

// The peer id is part of the associated data: a wrong peer id is a tag failure.
@(test)
peer_id_is_authenticated :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .CHACHA20_POLY1305)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		pt := make([]u8, 20, context.temp_allocator)
		pt[0] = 0x45
		pkt := make([]u8, 20 + packet_overhead(format), context.temp_allocator)
		n, _ := data_key_seal(&client, 77, pt, pkt)
		out := make([]u8, 32, context.temp_allocator)
		pkt[3] = 78
		_, err := data_key_open(&server, pkt[:n], out)
		testing.expect_value(t, err, Error.Bad_Tag)
		pkt[3] = 77
		_, err = data_key_open(&server, pkt[:n], out)
		testing.expect_value(t, err, Error.None)
	}
}
