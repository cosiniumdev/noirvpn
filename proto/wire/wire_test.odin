// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wire

import "core:testing"

// ---- opcode ----

@(test)
opcode_first_byte_examples :: proc(t: ^testing.T) {
	// Worked examples of the first byte.
	testing.expect_value(t, first_byte(.Hard_Reset_Client_V2, 0), 0x38)
	testing.expect_value(t, first_byte(.Control_V1, 0), 0x20)
	testing.expect_value(t, first_byte(.Ack_V1, 0), 0x28)
	testing.expect_value(t, first_byte(.Data_V2, 2), 0x4a)
	testing.expect_value(t, first_byte(.Hard_Reset_Client_V3, 0), 0x50)
	testing.expect_value(t, first_byte(.Control_Wkc_V1, 0), 0x58)
	testing.expect_value(t, first_byte(.Soft_Reset_V1, 3), 0x1b)
}

@(test)
opcode_table_matches_spec :: proc(t: ^testing.T) {
	for b in 0 ..< 256 {
		op, kid := split_first_byte(u8(b))
		testing.expect_value(t, u8(op), u8(b >> 3))
		testing.expect_value(t, kid, u8(b & 7))
		testing.expect_value(t, first_byte(op, kid), u8(b))

		want: Opcode_Class
		switch int(op) {
		case 3, 4, 5, 7, 8, 10, 11:
			want = .Control
		case 9:
			want = .Data
		case 1, 2, 6:
			want = .Rejected
		case:
			want = .Unknown
		}
		testing.expectf(t, opcode_class(op) == want, "opcode %d: class %v, want %v", int(op), opcode_class(op), want)
	}
	testing.expect(t, opcode_is_hard_reset(.Hard_Reset_Client_V2))
	testing.expect(t, opcode_is_hard_reset(.Hard_Reset_Server_V2))
	testing.expect(t, opcode_is_hard_reset(.Hard_Reset_Client_V3))
	testing.expect(t, !opcode_is_hard_reset(.Soft_Reset_V1))
	testing.expect(t, opcode_is_soft_reset(.Soft_Reset_V1))
	testing.expect(t, !opcode_has_msg_id(.Ack_V1))
	testing.expect(t, opcode_has_msg_id(.Control_Wkc_V1))
	testing.expect(t, !opcode_has_msg_id(.Data_V2))
}

@(test)
opcode_direction_rules :: proc(t: ^testing.T) {
	testing.expect(t, !opcode_allowed_for_receiver(.Hard_Reset_Client_V2, .Client))
	testing.expect(t, !opcode_allowed_for_receiver(.Hard_Reset_Client_V3, .Client))
	testing.expect(t, !opcode_allowed_for_receiver(.Control_Wkc_V1, .Client))
	testing.expect(t, opcode_allowed_for_receiver(.Hard_Reset_Client_V2, .Server))
	testing.expect(t, opcode_allowed_for_receiver(.Hard_Reset_Client_V3, .Server))
	testing.expect(t, opcode_allowed_for_receiver(.Control_Wkc_V1, .Server))
	testing.expect(t, !opcode_allowed_for_receiver(.Hard_Reset_Server_V2, .Server))
	testing.expect(t, opcode_allowed_for_receiver(.Hard_Reset_Server_V2, .Client))
	for role in Role {
		testing.expect(t, opcode_allowed_for_receiver(.Control_V1, role))
		testing.expect(t, opcode_allowed_for_receiver(.Ack_V1, role))
		testing.expect(t, opcode_allowed_for_receiver(.Soft_Reset_V1, role))
		testing.expect(t, !opcode_allowed_for_receiver(.Data_V2, role))
		testing.expect(t, !opcode_allowed_for_receiver(.Data_V1, role))
		testing.expect(t, !opcode_allowed_for_receiver(.Hard_Reset_Client_V1, role))
		testing.expect(t, !opcode_allowed_for_receiver(Opcode(20), role))
	}
}

// ---- control header ----

@(test)
control_decode_spec_example_control_v1 :: proc(t: ^testing.T) {
	// msg id 2, acks 0 and 1, payload 16 03 03.
	pkt := unhex("20 a1a2a3a4a5a6a7a8 02 00000000 00000001 b1b2b3b4b5b6b7b8 00000002 160303")
	testing.expect_value(t, len(pkt), 33)
	p: Control_Packet
	testing.expect_value(t, control_decode(pkt, &p), Error.None)
	testing.expect_value(t, p.opcode, Opcode.Control_V1)
	testing.expect_value(t, p.key_id, 0)
	testing.expect_value(t, p.session_id, Session_Id{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8})
	testing.expect_value(t, p.ack_count, 2)
	testing.expect_value(t, p.acks[0], 0)
	testing.expect_value(t, p.acks[1], 1)
	testing.expect_value(t, p.ack_remote_sid, Session_Id{0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8})
	testing.expect_value(t, p.packet_id, 2)
	expect_bytes(t, p.payload, unhex("160303"), "payload")
	// The payload is a slice into the input.
	testing.expect(t, raw_data(p.payload) == raw_data(pkt[30:]), "payload must alias input")
	testing.expect_value(t, control_header_len(.Control_V1, 2), 30)
	testing.expect_value(t, len(control_acks(&p)), 2)

	// And back.
	out: [64]u8
	n, err := control_encode(out[:], &p)
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, out[:n], pkt, "re-encoded")
}

@(test)
control_spec_example_ack :: proc(t: ^testing.T) {
	// 22 bytes.
	pkt := unhex("28 a1a2a3a4a5a6a7a8 01 00000000 b1b2b3b4b5b6b7b8")
	testing.expect_value(t, len(pkt), 22)
	p: Control_Packet
	testing.expect_value(t, control_decode(pkt, &p), Error.None)
	testing.expect_value(t, p.opcode, Opcode.Ack_V1)
	testing.expect_value(t, p.ack_count, 1)
	testing.expect_value(t, len(p.payload), 0)
	out: [64]u8
	n, err := control_encode(out[:], &p)
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, out[:n], pkt, "re-encoded")
}

@(test)
control_spec_example_resets :: proc(t: ^testing.T) {
	// client reset, 14 bytes.
	client := unhex("38 c1c2c3c4c5c6c7c8 00 00000000")
	p: Control_Packet
	testing.expect_value(t, control_decode(client, &p), Error.None)
	testing.expect_value(t, p.opcode, Opcode.Hard_Reset_Client_V2)
	testing.expect_value(t, p.ack_count, 0)
	testing.expect_value(t, p.packet_id, 0)
	testing.expect_value(t, len(p.payload), 0)
	out: [64]u8
	n, err := control_encode(out[:], &p)
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, out[:n], client, "client reset")

	// stateless server reply, 26 bytes.
	server := unhex("40 d1d2d3d4d5d6d7d8 01 00000000 c1c2c3c4c5c6c7c8 00000000")
	testing.expect_value(t, len(server), 26)
	testing.expect_value(t, control_decode(server, &p), Error.None)
	testing.expect_value(t, p.opcode, Opcode.Hard_Reset_Server_V2)
	testing.expect_value(t, p.ack_count, 1)
	testing.expect_value(t, p.acks[0], 0)
	testing.expect_value(t, p.ack_remote_sid, Session_Id{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8})
	n, err = control_encode(out[:], &p)
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, out[:n], server, "server reset")

	// With the early-negotiation TLV: 32 bytes.
	with_tlv := unhex("40 d1d2d3d4d5d6d7d8 01 00000000 c1c2c3c4c5c6c7c8 00000000 000100020001")
	testing.expect_value(t, len(with_tlv), 32)
	testing.expect_value(t, control_decode(with_tlv, &p), Error.None)
	expect_bytes(t, p.payload, unhex("000100020001"), "tlv payload")
	flags, ferr := early_neg_parse(p.payload)
	testing.expect_value(t, ferr, Error.None)
	testing.expect_value(t, flags, EARLY_NEG_FLAG_RESEND_WKC)
}

@(test)
control_round_trip_all_opcodes :: proc(t: ^testing.T) {
	ops := [?]Opcode{.Soft_Reset_V1, .Control_V1, .Ack_V1, .Hard_Reset_Client_V2, .Hard_Reset_Server_V2, .Hard_Reset_Client_V3, .Control_Wkc_V1}
	payload := [?]u8{1, 2, 3, 4, 5, 6, 7}
	out: [128]u8
	for op in ops {
		for kid in u8(0) ..= 7 {
			for nacks in 0 ..= MAX_ACKS {
				if op == .Ack_V1 && nacks == 0 {
					continue
				}
				if op != .Ack_V1 && nacks > MAX_ACKS_WITH_DATA {
					continue
				}
				in_p := Control_Packet {
					opcode         = op,
					key_id         = kid,
					session_id     = {1, 2, 3, 4, 5, 6, 7, 8},
					ack_count      = nacks,
					ack_remote_sid = {9, 9, 9, 9, 9, 9, 9, 9},
					packet_id      = 0xdeadbeef,
				}
				for i in 0 ..< nacks {
					in_p.acks[i] = u32(0x01020304 * (i + 1))
				}
				if opcode_has_msg_id(op) {
					in_p.payload = payload[:]
				}
				n, err := control_encode(out[:], &in_p)
				testing.expect_value(t, err, Error.None)
				testing.expect_value(t, n, control_encoded_len(&in_p))

				got: Control_Packet
				testing.expect_value(t, control_decode(out[:n], &got), Error.None)
				testing.expect_value(t, got.opcode, op)
				testing.expect_value(t, got.key_id, kid)
				testing.expect_value(t, got.session_id, in_p.session_id)
				testing.expect_value(t, got.ack_count, nacks)
				for i in 0 ..< nacks {
					testing.expect_value(t, got.acks[i], in_p.acks[i])
				}
				if nacks > 0 {
					testing.expect_value(t, got.ack_remote_sid, in_p.ack_remote_sid)
				}
				if opcode_has_msg_id(op) {
					testing.expect_value(t, got.packet_id, in_p.packet_id)
					expect_bytes(t, got.payload, payload[:], "payload")
				}

				// Every proper prefix is rejected, and the last byte of the
				// header is where a short packet starts to work.
				hdr := control_header_len(op, nacks)
				for cut in 0 ..< n {
					e := control_decode(out[:cut], &got)
					if cut < hdr {
						testing.expectf(t, e != .None, "op %v cut %d accepted", op, cut)
					} else {
						testing.expectf(t, e == .None, "op %v cut %d: %v", op, cut, e)
					}
				}
			}
		}
	}
}

@(test)
control_decode_negative :: proc(t: ^testing.T) {
	p: Control_Packet
	good := unhex("20 a1a2a3a4a5a6a7a8 00 00000007")

	testing.expect_value(t, control_decode(nil, &p), Error.Truncated)
	testing.expect_value(t, control_decode(good[:8], &p), Error.Truncated)
	testing.expect_value(t, control_decode(good[:9], &p), Error.Truncated) // no ack count byte
	testing.expect_value(t, control_decode(good[:12], &p), Error.Truncated) // msg id cut

	// Opcode classes.
	bad := make([]u8, len(good), context.temp_allocator)
	copy(bad, good)
	for b in 0 ..< 32 {
		bad[0] = u8(b << 3)
		e := control_decode(bad, &p)
		switch b {
		case 3, 4, 5, 7, 8, 10, 11:
			testing.expectf(t, e == .None, "opcode %d: %v", b, e)
		case 9:
			testing.expectf(t, e == .Wrong_Opcode, "opcode 9: %v", e)
		case 1, 2, 6:
			testing.expectf(t, e == .Rejected_Opcode, "opcode %d: %v", b, e)
		case:
			testing.expectf(t, e == .Unknown_Opcode, "opcode %d: %v", b, e)
		}
	}

	// All-zero session id.
	zero_sid := unhex("20 0000000000000000 00 00000007")
	testing.expect_value(t, control_decode(zero_sid, &p), Error.Zero_Session_Id)

	// ACK count 9 (above the limit), with enough bytes behind it.
	nine := make([]u8, 9 + 1 + 36 + 8 + 4, context.temp_allocator)
	nine[0] = 0x20
	for i in 1 ..= 8 {
		nine[i] = 1
	}
	nine[9] = 9
	testing.expect_value(t, control_decode(nine, &p), Error.Bad_Ack_Count)
	nine[9] = 255
	testing.expect_value(t, control_decode(nine, &p), Error.Bad_Ack_Count)
	// Count 8 with the array cut short.
	nine[9] = 8
	testing.expect_value(t, control_decode(nine[:9 + 1 + 32 + 7], &p), Error.Truncated)
	// Count 8 with the array whole but no msg id.
	testing.expect_value(t, control_decode(nine[:9 + 1 + 32 + 8], &p), Error.Truncated)
	testing.expect_value(t, control_decode(nine[:9 + 1 + 32 + 8 + 4], &p), Error.None)

	// Oversize.
	big := make([]u8, MAX_CONTROL_LEN + 1, context.temp_allocator)
	copy(big, good)
	testing.expect_value(t, control_decode(big, &p), Error.Oversize)
	testing.expect_value(t, control_decode(big[:MAX_CONTROL_LEN], &p), Error.None)

	// An empty P_ACK_V1 decodes; the caller ignores it.
	empty_ack := unhex("28 a1a2a3a4a5a6a7a8 00")
	testing.expect_value(t, control_decode(empty_ack, &p), Error.None)
	testing.expect_value(t, p.ack_count, 0)

	// Decode failure leaves a cleared struct.
	testing.expect_value(t, control_decode(nine[:5], &p), Error.Truncated)
	testing.expect_value(t, p.ack_count, 0)
}

@(test)
control_encode_negative :: proc(t: ^testing.T) {
	out: [4096]u8
	base := Control_Packet {
		opcode         = .Control_V1,
		session_id     = {1, 2, 3, 4, 5, 6, 7, 8},
		ack_remote_sid = {9, 9, 9, 9, 9, 9, 9, 9},
	}
	n, err := control_encode(out[:], &base)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 14)

	// Buffer too small, by one byte.
	_, err = control_encode(out[:13], &base)
	testing.expect_value(t, err, Error.Buffer_Too_Small)

	// 5 acks on a data packet; 4 are fine.
	p := base
	p.ack_count = 5
	_, err = control_encode(out[:], &p)
	testing.expect_value(t, err, Error.Bad_Ack_Count)
	p.ack_count = 4
	_, err = control_encode(out[:], &p)
	testing.expect_value(t, err, Error.None)
	p.ack_count = -1
	_, err = control_encode(out[:], &p)
	testing.expect_value(t, err, Error.Bad_Ack_Count)
	p.ack_count = 9
	_, err = control_encode(out[:], &p)
	testing.expect_value(t, err, Error.Bad_Ack_Count)

	// P_ACK_V1: 0 acks is refused, 8 is fine, payload is refused.
	a := base
	a.opcode = .Ack_V1
	_, err = control_encode(out[:], &a)
	testing.expect_value(t, err, Error.Bad_Ack_Count)
	a.ack_count = 8
	_, err = control_encode(out[:], &a)
	testing.expect_value(t, err, Error.None)
	one := [1]u8{1}
	a.payload = one[:]
	_, err = control_encode(out[:], &a)
	testing.expect_value(t, err, Error.Bad_Payload)

	// Opcodes the encoder will not write.
	for op in ([?]Opcode{.Data_V2, .Data_V1, .Hard_Reset_Client_V1, .Hard_Reset_Server_V1, .Unassigned_0, Opcode(12), Opcode(31)}) {
		q := base
		q.opcode = op
		_, err = control_encode(out[:], &q)
		testing.expectf(t, err != .None, "opcode %v was encoded", op)
	}

	// Key id, session ids.
	q := base
	q.key_id = 8
	_, err = control_encode(out[:], &q)
	testing.expect_value(t, err, Error.Bad_Key_Id)
	q = base
	q.session_id = {}
	_, err = control_encode(out[:], &q)
	testing.expect_value(t, err, Error.Zero_Session_Id)
	q = base
	q.ack_count = 1
	q.ack_remote_sid = {}
	_, err = control_encode(out[:], &q)
	testing.expect_value(t, err, Error.Zero_Session_Id)

	// Oversize payload.
	q = base
	q.payload = out[:MAX_CONTROL_LEN]
	_, err = control_encode(out[:], &q)
	testing.expect_value(t, err, Error.Oversize)
}

@(test)
control_encode_payload_in_place :: proc(t: ^testing.T) {
	// The caller may put the payload where it will land and encode over it.
	buf: [64]u8
	hdr := control_header_len(.Control_V1, 1)
	for i in 0 ..< 5 {
		buf[hdr + i] = u8(0x50 + i)
	}
	p := Control_Packet {
		opcode         = .Control_V1,
		session_id     = {1, 1, 1, 1, 1, 1, 1, 1},
		ack_count      = 1,
		ack_remote_sid = {2, 2, 2, 2, 2, 2, 2, 2},
		payload        = buf[hdr:][:5],
	}
	n, err := control_encode(buf[:], &p)
	testing.expect_value(t, err, Error.None)
	got: Control_Packet
	testing.expect_value(t, control_decode(buf[:n], &got), Error.None)
	expect_bytes(t, got.payload, {0x50, 0x51, 0x52, 0x53, 0x54}, "payload")
}

@(test)
peek_header_reads_first_nine_bytes :: proc(t: ^testing.T) {
	pkt := unhex("50 0102030405060708 ffffffff")
	op, kid, sid, err := peek_header(pkt)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, op, Opcode.Hard_Reset_Client_V3)
	testing.expect_value(t, kid, 0)
	testing.expect_value(t, sid, Session_Id{1, 2, 3, 4, 5, 6, 7, 8})
	_, _, _, err = peek_header(pkt[:8])
	testing.expect_value(t, err, Error.Truncated)
	_, _, err = peek_opcode(nil)
	testing.expect_value(t, err, Error.Truncated)
}

// ---- ACK array ----

@(test)
ack_array_round_trip :: proc(t: ^testing.T) {
	sid := Session_Id{1, 2, 3, 4, 5, 6, 7, 8}
	ids := [?]u32{0, 1, 0xffffffff, 7, 8, 9, 10, 11}
	buf: [64]u8
	for n in 0 ..= 8 {
		used, err := ack_array_encode(buf[:], ids[:n], sid)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, used, ack_array_len(n))
		got: [MAX_ACKS]u32
		rsid: Session_Id
		count, consumed, derr := ack_array_decode(buf[:used], &got, &rsid)
		testing.expect_value(t, derr, Error.None)
		testing.expect_value(t, count, n)
		testing.expect_value(t, consumed, used)
		for i in 0 ..< n {
			testing.expect_value(t, got[i], ids[i])
		}
		if n > 0 {
			testing.expect_value(t, rsid, sid)
		}
	}
	testing.expect_value(t, ack_array_len(0), 1)
	testing.expect_value(t, ack_array_len(1), 13)
	testing.expect_value(t, ack_array_len(4), 25)
	testing.expect_value(t, ack_array_len(8), 41)

	_, err := ack_array_encode(buf[:], []u32{1, 2, 3, 4, 5, 6, 7, 8, 9}, sid)
	testing.expect_value(t, err, Error.Bad_Ack_Count)
	_, err = ack_array_encode(buf[:12], []u32{1}, sid)
	testing.expect_value(t, err, Error.Buffer_Too_Small)
}

// ---- P_DATA_V2 ----

@(test)
data_v2_examples :: proc(t: ^testing.T) {
	buf: [8]u8
	// key_id 1, peer-id 300 gives 49 00 01 2c.
	n, err := data_v2_encode(buf[:], 1, 300)
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, buf[:n], {0x49, 0x00, 0x01, 0x2c}, "header")

	hdr, payload, derr := data_v2_decode(unhex("49 00012c aabbcc"))
	testing.expect_value(t, derr, Error.None)
	testing.expect_value(t, hdr.key_id, 1)
	testing.expect_value(t, hdr.peer_id, 300)
	expect_bytes(t, payload, {0xaa, 0xbb, 0xcc}, "payload")

	// Undefined peer id.
	n, err = data_v2_encode(buf[:], 7, PEER_ID_UNDEFINED)
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, buf[:n], {0x4f, 0xff, 0xff, 0xff}, "undefined")
	hdr, payload, derr = data_v2_decode(buf[:n])
	testing.expect_value(t, derr, Error.None)
	testing.expect_value(t, hdr.peer_id, PEER_ID_UNDEFINED)
	testing.expect_value(t, len(payload), 0)

	// Round trip over many ids.
	for id in ([?]u32{0, 1, 255, 256, 65535, 65536, 0xabcdef, PEER_ID_MAX, PEER_ID_UNDEFINED}) {
		for kid in u8(0) ..= 7 {
			n, err = data_v2_encode(buf[:], kid, id)
			testing.expect_value(t, err, Error.None)
			hdr, _, derr = data_v2_decode(buf[:n])
			testing.expect_value(t, derr, Error.None)
			testing.expect_value(t, hdr.peer_id, id)
			testing.expect_value(t, hdr.key_id, kid)
		}
	}
}

@(test)
data_v2_negative :: proc(t: ^testing.T) {
	buf: [8]u8
	_, err := data_v2_encode(buf[:], 0, 0x1000000)
	testing.expect_value(t, err, Error.Bad_Peer_Id)
	_, err = data_v2_encode(buf[:], 8, 0)
	testing.expect_value(t, err, Error.Bad_Key_Id)
	_, err = data_v2_encode(buf[:3], 0, 0)
	testing.expect_value(t, err, Error.Buffer_Too_Small)

	_, _, derr := data_v2_decode(nil)
	testing.expect_value(t, derr, Error.Truncated)
	_, _, derr = data_v2_decode({0x48, 0, 1})
	testing.expect_value(t, derr, Error.Truncated)
	_, _, derr = data_v2_decode({0x20, 0, 1, 2, 3}) // control opcode
	testing.expect_value(t, derr, Error.Wrong_Opcode)
	_, _, derr = data_v2_decode({0x30, 0, 1, 2, 3}) // P_DATA_V1
	testing.expect_value(t, derr, Error.Rejected_Opcode)
	_, _, derr = data_v2_decode({0x60, 0, 1, 2, 3}) // opcode 12
	testing.expect_value(t, derr, Error.Unknown_Opcode)

	// Server lookup rule: short packets count as "undefined".
	testing.expect_value(t, data_v2_lookup_peer_id({0x48, 0, 1}), PEER_ID_UNDEFINED)
	testing.expect_value(t, data_v2_lookup_peer_id(nil), PEER_ID_UNDEFINED)
	testing.expect_value(t, data_v2_lookup_peer_id({0x48, 0, 1, 0x2c}), 300)
}

// ---- TCP framing ----

@(test)
frame_encode_decode :: proc(t: ^testing.T) {
	buf: [64]u8
	n, err := frame_encode(buf[:], unhex("38 0102030405060708"))
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, buf[:n], unhex("0009 38 0102030405060708"), "frame")

	pkt, used, derr := frame_decode(buf[:n], 100)
	testing.expect_value(t, derr, Error.None)
	testing.expect_value(t, used, n)
	expect_bytes(t, pkt, unhex("38 0102030405060708"), "packet")

	// Trailing bytes belong to the next frame.
	two := unhex("0001 aa 0002 bb")
	pkt, used, derr = frame_decode(two, 100)
	testing.expect_value(t, derr, Error.None)
	testing.expect_value(t, used, 3)
	expect_bytes(t, pkt, {0xaa}, "first")

	// Not enough bytes yet.
	_, _, derr = frame_decode(nil, 100)
	testing.expect_value(t, derr, Error.Need_More)
	_, _, derr = frame_decode({0x00}, 100)
	testing.expect_value(t, derr, Error.Need_More)
	_, _, derr = frame_decode({0x00, 0x05, 1, 2, 3, 4}, 100)
	testing.expect_value(t, derr, Error.Need_More)
	// Bad length is known as soon as the prefix is in.
	_, _, derr = frame_decode({0x00, 0x00}, 100)
	testing.expect_value(t, derr, Error.Zero_Length)
	_, _, derr = frame_decode({0x00, 0x65}, 100)
	testing.expect_value(t, derr, Error.Oversize)
	_, _, derr = frame_decode({0x00, 0x64}, 100)
	testing.expect_value(t, derr, Error.Need_More)
	_, _, derr = frame_decode({0xff, 0xff}, 2048)
	testing.expect_value(t, derr, Error.Oversize)

	// Encoder limits.
	_, err = frame_encode(buf[:], nil)
	testing.expect_value(t, err, Error.Zero_Length)
	_, err = frame_encode(buf[:5], unhex("010203 04"))
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	huge := make([]u8, 65536, context.temp_allocator)
	_, err = frame_encode(huge, huge)
	testing.expect_value(t, err, Error.Oversize)
	max_pkt := huge[:65535]
	out := make([]u8, 65537, context.temp_allocator)
	n, err = frame_encode(out, max_pkt)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 65537)
	testing.expect_value(t, out[0], 0xff)
	testing.expect_value(t, out[1], 0xff)
}

@(test)
splitter_byte_by_byte_and_chunks :: proc(t: ^testing.T) {
	// Build a stream of frames of mixed sizes.
	stream := make([dynamic]u8, context.temp_allocator)
	sizes := [?]int{1, 9, 100, 2, 300, 17, 1, 1, 64, 255, 256}
	tmp: [512]u8
	for sz, i in sizes {
		pkt := make([]u8, sz, context.temp_allocator)
		for j in 0 ..< sz {
			pkt[j] = u8(i * 31 + j)
		}
		n, err := frame_encode(tmp[:], pkt)
		testing.expect_value(t, err, Error.None)
		append(&stream, ..tmp[:n])
	}

	// Chunk sizes: 1, 2, 3, 7, whole stream, and pseudo-random.
	rng := Rng{0x9e3779b97f4a7c15}
	for mode in 0 ..< 8 {
		backing: [1024]u8
		s: Stream_Splitter
		testing.expect_value(t, splitter_init(&s, backing[:], 400), Error.None)
		got := 0
		pos := 0
		for pos < len(stream) {
			chunk_len: int
			switch mode {
			case 0:
				chunk_len = 1
			case 1:
				chunk_len = 2
			case 2:
				chunk_len = 3
			case 3:
				chunk_len = 7
			case 4:
				chunk_len = len(stream)
			case:
				chunk_len = 1 + rng_below(&rng, 300)
			}
			chunk := stream[pos:min(pos + chunk_len, len(stream))]
			pos += len(chunk)
			for rest := chunk; len(rest) > 0; {
				taken := splitter_feed(&s, rest)
				testing.expect(t, taken > 0, "feed gave no progress")
				rest = rest[taken:]
				for {
					pkt, err := splitter_next(&s)
					if err == .Need_More {
						break
					}
					testing.expect_value(t, err, Error.None)
					if got < len(sizes) {
						testing.expect_value(t, len(pkt), sizes[got])
						ok := true
						for b, j in pkt {
							if b != u8(got * 31 + j) {
								ok = false
							}
						}
						testing.expectf(t, ok, "packet %d has wrong contents", got)
					}
					got += 1
				}
			}
		}
		testing.expectf(t, got == len(sizes), "mode %d: got %d packets, want %d", mode, got, len(sizes))
		testing.expect_value(t, splitter_pending(&s), 0)
	}
}

@(test)
splitter_errors_are_sticky :: proc(t: ^testing.T) {
	backing: [64]u8
	s: Stream_Splitter
	testing.expect_value(t, splitter_init(&s, backing[:], 10), Error.None)

	// Too-big length: fatal, and stays fatal.
	splitter_feed(&s, {0x00, 0x0b, 1})
	_, err := splitter_next(&s)
	testing.expect_value(t, err, Error.Oversize)
	_, err = splitter_next(&s)
	testing.expect_value(t, err, Error.Oversize)
	testing.expect_value(t, splitter_feed(&s, {1, 2, 3}), 0)

	// Reset starts over.
	splitter_reset(&s)
	splitter_feed(&s, {0x00, 0x02, 7, 8})
	pkt, err2 := splitter_next(&s)
	testing.expect_value(t, err2, Error.None)
	expect_bytes(t, pkt, {7, 8}, "after reset")

	// Zero length is fatal too.
	splitter_feed(&s, {0x00, 0x00, 5})
	_, err = splitter_next(&s)
	testing.expect_value(t, err, Error.Zero_Length)

	// A frame of exactly max_packet is fine.
	splitter_reset(&s)
	frame: [12]u8
	frame[1] = 10
	testing.expect_value(t, splitter_feed(&s, frame[:]), 12)
	pkt, err2 = splitter_next(&s)
	testing.expect_value(t, err2, Error.None)
	testing.expect_value(t, len(pkt), 10)
}

@(test)
splitter_init_checks :: proc(t: ^testing.T) {
	backing: [64]u8
	s: Stream_Splitter
	testing.expect_value(t, splitter_init(&s, backing[:], 0), Error.Oversize)
	testing.expect_value(t, splitter_init(&s, backing[:], 70000), Error.Oversize)
	testing.expect_value(t, splitter_init(&s, backing[:], 63), Error.Buffer_Too_Small)
	testing.expect_value(t, splitter_init(&s, backing[:], 62), Error.None)
}

@(test)
splitter_compacts_when_full :: proc(t: ^testing.T) {
	// A buffer that holds one max-size frame only: feeding the next frame
	// must wait until the first is taken, then compact.
	backing: [12]u8
	s: Stream_Splitter
	testing.expect_value(t, splitter_init(&s, backing[:], 10), Error.None)
	stream := unhex("0003 010203 0003 040506 0004 07080910")
	got := make([dynamic][]u8, context.temp_allocator)
	for rest := stream; len(rest) > 0; {
		taken := splitter_feed(&s, rest)
		rest = rest[taken:]
		for {
			pkt, err := splitter_next(&s)
			if err != .None {
				break
			}
			cp := make([]u8, len(pkt), context.temp_allocator)
			copy(cp, pkt)
			append(&got, cp)
		}
	}
	testing.expect_value(t, len(got), 3)
	if len(got) == 3 {
		expect_bytes(t, got[0], {1, 2, 3}, "pkt 0")
		expect_bytes(t, got[1], {4, 5, 6}, "pkt 1")
		expect_bytes(t, got[2], {7, 8, 9, 0x10}, "pkt 2")
	}
}

// ---- TLV ----

@(test)
early_neg_tlv :: proc(t: ^testing.T) {
	buf: [16]u8
	n, err := early_neg_encode(buf[:], EARLY_NEG_FLAG_RESEND_WKC)
	testing.expect_value(t, err, Error.None)
	expect_bytes(t, buf[:n], {0, 1, 0, 2, 0, 1}, "flags TLV")

	flags, perr := early_neg_parse(buf[:n])
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, flags, EARLY_NEG_FLAG_RESEND_WKC)

	// Empty payload: no flags, no error.
	flags, perr = early_neg_parse(nil)
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, flags, 0)

	// Unknown TLV first, then flags; a zero-length unknown TLV is fine.
	flags, perr = early_neg_parse(unhex("7777 0003 aabbcc 0042 0000 0001 0002 0001"))
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, flags, 1)

	// Unknown flag bits are passed through.
	flags, perr = early_neg_parse(unhex("0001 0002 8001"))
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, flags, 0x8001)

	// Unknown TLV only.
	flags, perr = early_neg_parse(unhex("0002 0001 ff"))
	testing.expect_value(t, perr, Error.None)
	testing.expect_value(t, flags, 0)

	// Iterator yields every entry.
	it := tlv_iter(unhex("0009 0001 aa 0001 0002 0001"))
	count := 0
	for typ, value in tlv_next(&it) {
		if count == 0 {
			testing.expect_value(t, typ, 9)
			expect_bytes(t, value, {0xaa}, "value 0")
		} else {
			testing.expect_value(t, typ, 1)
			testing.expect_value(t, len(value), 2)
		}
		count += 1
	}
	testing.expect_value(t, count, 2)
	testing.expect_value(t, it.err, Error.None)
}

@(test)
early_neg_tlv_negative :: proc(t: ^testing.T) {
	bad := [?]string {
		"00", // fewer than 4 bytes
		"000100", // 3 bytes
		"0001 0002 00", // value cut
		"0001 0002", // value missing
		"0001 0001 01", // flags TLV with length 1
		"0001 0003 000100", // flags TLV with length 3
		"0001 0000", // flags TLV with length 0
		"0001 0002 0001 00", // trailing partial header
		"0001 0002 0001 0009", // trailing partial header (2 bytes)
		"0001 0002 0001 0009 0005 01", // second TLV overruns
		"ffff ffff 00", // length far past the end
	}
	for s in bad {
		_, err := early_neg_parse(unhex(s))
		testing.expectf(t, err == .Bad_Tlv, "payload %q: %v", s, err)
	}

	// Encoder.
	buf: [8]u8
	_, err := tlv_encode(buf[:3], 1, nil)
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	n, err2 := tlv_encode(buf[:], 0x1234, {1, 2, 3})
	testing.expect_value(t, err2, Error.None)
	expect_bytes(t, buf[:n], {0x12, 0x34, 0, 3, 1, 2, 3}, "tlv")
	_, err = tlv_encode(buf[:], 1, buf[:5])
	testing.expect_value(t, err, Error.Buffer_Too_Small)
}

// ---- fuzz-style ----

// Runs every decoder on one buffer. Only checks that nothing crashes and that
// error returns leave the outputs sane.
@(private = "file")
decode_everything :: proc(t: ^testing.T, b: []u8) {
	p: Control_Packet
	if control_decode(b, &p) == .None {
		// Anything decoded must re-encode to the same bytes (P_ACK_V1 may
		// have extra trailing bytes, which are not kept).
		testing.expect(t, p.ack_count >= 0 && p.ack_count <= MAX_ACKS)
		testing.expect(t, len(p.payload) <= len(b))
		if p.opcode != .Ack_V1 && p.ack_count <= MAX_ACKS_WITH_DATA {
			out: [MAX_CONTROL_LEN + 16]u8
			n, err := control_encode(out[:], &p)
			testing.expect_value(t, err, Error.None)
			expect_bytes(t, out[:n], b, "re-encode of fuzz input")
		}
	}
	_, _, _ = data_v2_decode(b)
	_ = data_v2_lookup_peer_id(b)
	_, _ = early_neg_parse(b)
	_, _, _ = frame_decode(b, 2048)
	_, _, _, _ = peek_header(b)

	ids: [MAX_ACKS]u32
	sid: Session_Id
	_, _, _ = ack_array_decode(b, &ids, &sid)

	backing: [2100]u8
	s: Stream_Splitter
	_ = splitter_init(&s, backing[:], 2048)
	for rest := b; len(rest) > 0; {
		taken := splitter_feed(&s, rest)
		if taken == 0 {
			break
		}
		rest = rest[taken:]
		for {
			if _, err := splitter_next(&s); err != .None {
				break
			}
		}
	}
}

@(test)
fuzz_random_buffers :: proc(t: ^testing.T) {
	rng := Rng{0x1234567887654321}
	buf: [2200]u8
	for i in 0 ..< 5000 {
		n := rng_below(&rng, 120)
		if i % 50 == 0 {
			n = rng_below(&rng, len(buf))
		}
		rng_fill(&rng, buf[:n])
		// Steer some inputs toward plausible packets.
		if n > 0 && i % 3 == 0 {
			opcodes := [?]u8{3, 4, 5, 7, 8, 9, 10, 11}
			buf[0] = opcodes[rng_below(&rng, len(opcodes))] << 3 | u8(rng_below(&rng, 8))
		}
		if n > 9 && i % 6 == 0 {
			buf[9] = u8(rng_below(&rng, 10)) // ack count near the limit
		}
		decode_everything(t, buf[:n])
	}
}

@(test)
fuzz_truncated_and_mutated_valid_packets :: proc(t: ^testing.T) {
	rng := Rng{42}
	good := [?]string {
		"20 a1a2a3a4a5a6a7a8 02 00000000 00000001 b1b2b3b4b5b6b7b8 00000002 160303",
		"28 a1a2a3a4a5a6a7a8 01 00000000 b1b2b3b4b5b6b7b8",
		"40 d1d2d3d4d5d6d7d8 01 00000000 c1c2c3c4c5c6c7c8 00000000 000100020001",
		"4a 00012c 0102030405",
		"0009 38 0102030405060708 0003 aabbcc",
	}
	for s in good {
		g := unhex(s)
		for cut in 0 ..= len(g) {
			decode_everything(t, g[:cut])
		}
		mut := make([]u8, len(g), context.temp_allocator)
		for _ in 0 ..< 500 {
			copy(mut, g)
			for _ in 0 ..< 1 + rng_below(&rng, 3) {
				mut[rng_below(&rng, len(mut))] = u8(rng_next(&rng) >> 40)
			}
			decode_everything(t, mut)
		}
	}
}
