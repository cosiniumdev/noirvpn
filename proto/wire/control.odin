// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wire

// Control packet header, inner layout:
//
//   | op/kid:1 | sid:8 | ack-array | msg-id:4 | payload |       P_CONTROL_V1, resets, WKC
//   | op/kid:1 | sid:8 | ack-array |                              P_ACK_V1
//
// ack-array = | count:1 | id:4 * count | remote-sid:8 (only if count > 0) |

// Most ACK ids in one array. A receiver rejects more.
MAX_ACKS :: 8
// Most ACK ids a sender puts on a packet that also carries data.
MAX_ACKS_WITH_DATA :: 4

// Fixed part: opcode byte and session id.
CONTROL_PREFIX_LEN :: 1 + SESSION_ID_LEN
MSG_ID_LEN :: 4

// Bytes taken by an ACK array with `count` ids.
ack_array_len :: proc "contextless" (count: int) -> int {
	if count <= 0 {
		return 1
	}
	return 1 + 4 * count + SESSION_ID_LEN
}

// Decoded or to-be-encoded control packet. Plain fields on purpose: the
// reliability layer fills and reads them directly.
Control_Packet :: struct {
	opcode:         Opcode,
	key_id:         u8,
	session_id:     Session_Id, // sender's own session id
	ack_count:      int, // 0 to MAX_ACKS; `acks[:ack_count]` are valid
	acks:           [MAX_ACKS]u32,
	ack_remote_sid: Session_Id, // the receiver's sid; valid only if ack_count > 0
	packet_id:      u32, // message packet id; unused for P_ACK_V1
	payload:        []u8, // decode: slice into the input
}

// The valid ACK ids of a packet.
control_acks :: proc "contextless" (p: ^Control_Packet) -> []u32 {
	return p.acks[:p.ack_count]
}

// Header size for an opcode and ACK count (everything before the payload).
control_header_len :: proc "contextless" (op: Opcode, ack_count: int) -> int {
	n := CONTROL_PREFIX_LEN + ack_array_len(ack_count)
	if opcode_has_msg_id(op) {
		n += MSG_ID_LEN
	}
	return n
}

// Encoded size of `p`.
control_encoded_len :: proc "contextless" (p: ^Control_Packet) -> int {
	return control_header_len(p.opcode, p.ack_count) + len(p.payload)
}

// Reads opcode, key id and session id from the first 9 bytes. Works on the
// inner packet and on tls-auth / tls-crypt wire packets (these bytes are in
// clear). Checks nothing else.
peek_header :: proc "contextless" (pkt: []u8) -> (op: Opcode, key_id: u8, sid: Session_Id, err: Error) {
	if len(pkt) < CONTROL_PREFIX_LEN {
		err = .Truncated
		return
	}
	op, key_id = split_first_byte(pkt[0])
	copy(sid[:], pkt[1:CONTROL_PREFIX_LEN])
	return
}

// Decodes an ACK array at the start of `b`. Writes ids to `ids` and the remote
// sid to `remote_sid` (untouched when count is 0). Returns the count and the
// bytes consumed.
ack_array_decode :: proc "contextless" (
	b: []u8,
	ids: ^[MAX_ACKS]u32,
	remote_sid: ^Session_Id,
) -> (
	count: int,
	consumed: int,
	err: Error,
) {
	if len(b) < 1 {
		err = .Truncated
		return
	}
	count = int(b[0])
	if count > MAX_ACKS {
		count = 0
		err = .Bad_Ack_Count
		return
	}
	if count == 0 {
		consumed = 1
		return
	}
	need := ack_array_len(count)
	if len(b) < need {
		count = 0
		err = .Truncated
		return
	}
	for i in 0 ..< count {
		ids[i] = get_u32(b[1 + 4 * i:])
	}
	copy(remote_sid[:], b[1 + 4 * count:need])
	consumed = need
	return
}

// Encodes an ACK array. 0 ids writes the single byte 0 and ignores
// `remote_sid`. More than MAX_ACKS ids is `.Bad_Ack_Count`.
ack_array_encode :: proc "contextless" (buf: []u8, ids: []u32, remote_sid: Session_Id) -> (n: int, err: Error) {
	count := len(ids)
	if count > MAX_ACKS {
		return 0, .Bad_Ack_Count
	}
	need := ack_array_len(count)
	if len(buf) < need {
		return 0, .Buffer_Too_Small
	}
	buf[0] = u8(count)
	if count == 0 {
		return 1, .None
	}
	for id, i in ids {
		put_u32(buf[1 + 4 * i:], id)
	}
	sid := remote_sid
	copy(buf[1 + 4 * count:need], sid[:])
	return need, .None
}

// Decodes an inner control packet. `p.payload` points into `pkt`.
//
// Checks:
// - control opcode (unknown, rejected and data opcodes have their own errors)
// - size at most MAX_CONTROL_LEN, session id not all zero
// - ACK count at most 8, no truncation
// A P_ACK_V1 with zero ids decodes fine (the caller ignores it).
//
// The remote sid in the ACK array is NOT compared here. The caller checks it
// against its own session id.
control_decode :: proc "contextless" (pkt: []u8, p: ^Control_Packet) -> Error {
	p^ = {}
	op, kid, err := peek_opcode(pkt)
	if err != .None {
		return err
	}
	switch opcode_class(op) {
	case .Unknown:
		return .Unknown_Opcode
	case .Rejected:
		return .Rejected_Opcode
	case .Data:
		return .Wrong_Opcode
	case .Control:
	}
	if len(pkt) > MAX_CONTROL_LEN {
		return .Oversize
	}
	if len(pkt) < CONTROL_PREFIX_LEN {
		return .Truncated
	}
	sid: Session_Id
	copy(sid[:], pkt[1:CONTROL_PREFIX_LEN])
	if session_id_is_zero(sid) {
		return .Zero_Session_Id
	}

	count, used, aerr := ack_array_decode(pkt[CONTROL_PREFIX_LEN:], &p.acks, &p.ack_remote_sid)
	if aerr != .None {
		p^ = {}
		return aerr
	}
	off := CONTROL_PREFIX_LEN + used
	if opcode_has_msg_id(op) {
		if len(pkt) < off + MSG_ID_LEN {
			p^ = {}
			return .Truncated
		}
		p.packet_id = get_u32(pkt[off:])
		off += MSG_ID_LEN
		p.payload = pkt[off:]
	}
	// P_ACK_V1: nothing is defined after the array. Extra bytes are ignored.
	// SPEC-GAP: the spec says "no msg id and no payload" but not what a
	// receiver does with trailing bytes. Ignoring them is the lenient choice.

	p.opcode = op
	p.key_id = kid
	p.session_id = sid
	p.ack_count = count
	return .None
}

// Encodes `p` into `buf`. Returns the bytes written.
//
// Limits enforced:
// - control opcode, key id 0..7, non-zero session id
// - ACK ids: 0..4 on a packet that carries data, 1..8 on P_ACK_V1
// - non-zero remote sid when there are ACKs
// - total size at most MAX_CONTROL_LEN
// `p.payload` may overlap the destination in `buf`.
control_encode :: proc "contextless" (buf: []u8, p: ^Control_Packet) -> (n: int, err: Error) {
	switch opcode_class(p.opcode) {
	case .Unknown:
		return 0, .Unknown_Opcode
	case .Rejected:
		return 0, .Rejected_Opcode
	case .Data:
		return 0, .Wrong_Opcode
	case .Control:
	}
	if p.key_id > MAX_KEY_ID {
		return 0, .Bad_Key_Id
	}
	if session_id_is_zero(p.session_id) {
		return 0, .Zero_Session_Id
	}
	if p.ack_count < 0 || p.ack_count > MAX_ACKS {
		return 0, .Bad_Ack_Count
	}
	if p.opcode == .Ack_V1 {
		if p.ack_count < 1 {
			return 0, .Bad_Ack_Count
		}
		if len(p.payload) != 0 {
			return 0, .Bad_Payload
		}
	} else if p.ack_count > MAX_ACKS_WITH_DATA {
		return 0, .Bad_Ack_Count
	}
	if p.ack_count > 0 && session_id_is_zero(p.ack_remote_sid) {
		return 0, .Zero_Session_Id
	}
	total := control_encoded_len(p)
	if total > MAX_CONTROL_LEN {
		return 0, .Oversize
	}
	if len(buf) < total {
		return 0, .Buffer_Too_Small
	}

	buf[0] = first_byte(p.opcode, p.key_id)
	copy(buf[1:CONTROL_PREFIX_LEN], p.session_id[:])
	off := CONTROL_PREFIX_LEN
	used, aerr := ack_array_encode(buf[off:], p.acks[:p.ack_count], p.ack_remote_sid)
	if aerr != .None {
		return 0, aerr
	}
	off += used
	if opcode_has_msg_id(p.opcode) {
		put_u32(buf[off:], p.packet_id)
		off += MSG_ID_LEN
		copy(buf[off:total], p.payload)
	}
	return total, .None
}
