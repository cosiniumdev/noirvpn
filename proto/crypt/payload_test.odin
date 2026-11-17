// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "core:testing"
import "noir:proto/keys"

@(test)
ping_magic_bytes :: proc(t: ^testing.T) {
	want := []u8{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
	buf: [32]u8
	ping, ok := build_ping(buf[:])
	testing.expect(t, ok, "build_ping")
	expect_bytes(t, ping, want, "ping")
	testing.expect_value(t, classify_payload(ping), Payload_Kind.Ping)
	_, ok = build_ping(buf[:15])
	testing.expect(t, !ok, "buffer too small")

	// Only the exact 16 bytes count.
	testing.expect_value(t, classify_payload(want[:15]), Payload_Kind.Unknown)
	longer := make([]u8, 17, context.temp_allocator)
	copy(longer, want)
	testing.expect(t, classify_payload(longer) != .Ping, "17 bytes starting with the magic")
	for i in 0 ..< 16 {
		changed := make([]u8, 16, context.temp_allocator)
		copy(changed, want)
		changed[i] ~= 0x10
		testing.expectf(t, classify_payload(changed) != .Ping, "byte %d changed", i)
	}
}

@(test)
occ_messages :: proc(t: ^testing.T) {
	magic := []u8{0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c}
	buf: [32]u8
	exit, ok := build_occ_exit(buf[:])
	testing.expect(t, ok, "build_occ_exit")
	testing.expect_value(t, len(exit), 17)
	expect_bytes(t, exit[:16], magic, "OCC magic")
	testing.expect_value(t, exit[16], 6)
	testing.expect_value(t, classify_payload(exit), Payload_Kind.Occ_Exit)
	testing.expect(t, payload_is_occ(.Occ_Exit), "exit is OCC")
	testing.expect(t, !payload_is_tunnel(.Occ_Exit), "exit is not tunnel traffic")
	_, ok = build_occ_exit(buf[:16])
	testing.expect(t, !ok, "buffer too small")

	// The other opcodes are recognised so they can be dropped.
	kinds := [?]Payload_Kind {
		.Occ_Request,
		.Occ_Reply,
		.Occ_Mtu_Load_Request,
		.Occ_Mtu_Load,
		.Occ_Mtu_Request,
		.Occ_Mtu_Reply,
		.Occ_Exit,
	}
	for kind, op in kinds {
		msg := make([]u8, 40, context.temp_allocator) // padding after the opcode is fine
		copy(msg, magic)
		msg[16] = u8(op)
		testing.expectf(t, classify_payload(msg) == kind, "opcode %d: %v", op, classify_payload(msg))
		testing.expect(t, payload_is_occ(kind), "is OCC")
	}
	// An unknown opcode with the OCC magic is still not a tunnel packet.
	msg := make([]u8, 17, context.temp_allocator)
	copy(msg, magic)
	msg[16] = 7
	testing.expect_value(t, classify_payload(msg), Payload_Kind.Occ_Unknown)
	// The magic alone (16 bytes) has no opcode: not OCC.
	testing.expect(t, !payload_is_occ(classify_payload(magic)), "16 bytes of magic")
	// A different first byte is not OCC.
	msg[0] ~= 1
	msg[16] = 6
	testing.expect(t, !payload_is_occ(classify_payload(msg)), "wrong magic")
}

@(test)
tunnel_payloads :: proc(t: ^testing.T) {
	testing.expect_value(t, classify_payload(nil), Payload_Kind.Empty)
	testing.expect_value(t, classify_payload([]u8{0x45, 0, 0, 20}), Payload_Kind.Ipv4)
	testing.expect_value(t, classify_payload([]u8{0x4F}), Payload_Kind.Ipv4)
	testing.expect_value(t, classify_payload([]u8{0x60, 0, 0, 0}), Payload_Kind.Ipv6)
	for first in ([?]u8{0x00, 0x10, 0x50, 0x70, 0x80, 0xFF, 0x2a}) {
		testing.expectf(t, classify_payload([]u8{first, 1, 2, 3}) == .Unknown, "first byte %02x", first)
	}
	testing.expect(t, payload_is_tunnel(.Ipv4) && payload_is_tunnel(.Ipv6), "tunnel kinds")
	testing.expect(t, !payload_is_tunnel(.Ping) && !payload_is_tunnel(.Unknown), "not tunnel")
}

// A ping and an OCC EXIT go through the real data path in both formats and
// come out recognised.
@(test)
ping_and_exit_through_the_data_path :: proc(t: ^testing.T) {
	for format in keys.Format {
		client, server, ok := make_pair(t, format, .AES_128_GCM)
		if !ok {
			continue
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)
		oh := packet_overhead(format)
		// Build the plaintext in place, where the payload goes, and seal it there.
		pkt := make([]u8, 32 + oh, context.temp_allocator)
		headroom := EPOCH_HEADROOM if format == .Epoch else BASELINE_HEADROOM
		ping, _ := build_ping(pkt[headroom:])
		n, err := data_key_seal(&client, 5, ping, pkt)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, n, 16 + oh)
		out := make([]u8, 32, context.temp_allocator)
		res, oerr := data_key_open(&server, pkt[:n], out)
		testing.expect_value(t, oerr, Error.None)
		testing.expect_value(t, classify_payload(out[:res.n]), Payload_Kind.Ping)

		exit, _ := build_occ_exit(pkt[headroom:])
		n, err = data_key_seal(&server, 5, exit, pkt)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, n, 17 + oh)
		res, oerr = data_key_open(&client, pkt[:n], out)
		testing.expect_value(t, oerr, Error.None)
		testing.expect_value(t, classify_payload(out[:res.n]), Payload_Kind.Occ_Exit)
	}
}
