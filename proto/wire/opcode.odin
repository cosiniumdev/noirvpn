// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wire

// Opcode: top 5 bits of the first byte of every packet.
// Values 12 to 31 are unassigned. A byte with such an opcode decodes to
// `Opcode(n)`, which `opcode_class` reports as `.Unknown`.
Opcode :: enum u8 {
	Unassigned_0         = 0,
	Hard_Reset_Client_V1 = 1, // key-method 1: rejected
	Hard_Reset_Server_V1 = 2, // key-method 1: rejected
	Soft_Reset_V1        = 3,
	Control_V1           = 4,
	Ack_V1               = 5,
	Data_V1              = 6, // no peer id: rejected
	Hard_Reset_Client_V2 = 7,
	Hard_Reset_Server_V2 = 8,
	Data_V2              = 9,
	Hard_Reset_Client_V3 = 10, // tls-crypt-v2 reset
	Control_Wkc_V1       = 11, // control packet with the wrapped client key appended
}

// What a receiver does with an opcode.
Opcode_Class :: enum {
	Unknown, // unassigned: drop
	Rejected, // key-method 1 resets and P_DATA_V1: drop and count
	Control, // 3, 4, 5, 7, 8, 10, 11
	Data, // 9
}

KEY_ID_MASK :: 0x07
MAX_KEY_ID :: 7

// Joins opcode and key id into the first packet byte. Only the low 3 bits of
// key_id are used.
first_byte :: proc "contextless" (op: Opcode, key_id: u8) -> u8 {
	return u8(op) << 3 | (key_id & KEY_ID_MASK)
}

// Splits the first packet byte.
split_first_byte :: proc "contextless" (b: u8) -> (op: Opcode, key_id: u8) {
	return Opcode(b >> 3), b & KEY_ID_MASK
}

opcode_class :: proc "contextless" (op: Opcode) -> Opcode_Class {
	switch op {
	case .Soft_Reset_V1, .Control_V1, .Ack_V1, .Hard_Reset_Client_V2, .Hard_Reset_Server_V2, .Hard_Reset_Client_V3, .Control_Wkc_V1:
		return .Control
	case .Data_V2:
		return .Data
	case .Hard_Reset_Client_V1, .Hard_Reset_Server_V1, .Data_V1:
		return .Rejected
	case .Unassigned_0:
		return .Unknown
	}
	return .Unknown // 12..31
}

// True for opcodes 3, 4, 5, 7, 8, 10, 11.
opcode_is_control :: proc "contextless" (op: Opcode) -> bool {
	return opcode_class(op) == .Control
}

// Opcodes 7, 8, 10 start a new session.
opcode_is_hard_reset :: proc "contextless" (op: Opcode) -> bool {
	#partial switch op {
	case .Hard_Reset_Client_V2, .Hard_Reset_Server_V2, .Hard_Reset_Client_V3:
		return true
	}
	return false
}

// Opcode 3 starts a renegotiation.
opcode_is_soft_reset :: proc "contextless" (op: Opcode) -> bool {
	return op == .Soft_Reset_V1
}

// True if a packet of this opcode has a message packet id and a payload
// (everything except P_ACK_V1).
opcode_has_msg_id :: proc "contextless" (op: Opcode) -> bool {
	return opcode_is_control(op) && op != .Ack_V1
}

// Which opcodes a client or a server may legally receive.
// Opcode 11 is sent only by clients; opcodes 3, 4, 5 go both ways.
Role :: enum {
	Client,
	Server,
}

// True if a peer in `role` accepts a control packet with this opcode.
// A client drops 7 and 10; a server drops 8. Both drop non-control opcodes.
opcode_allowed_for_receiver :: proc "contextless" (op: Opcode, role: Role) -> bool {
	#partial switch op {
	case .Soft_Reset_V1, .Control_V1, .Ack_V1:
		return true
	case .Hard_Reset_Client_V2, .Hard_Reset_Client_V3, .Control_Wkc_V1:
		return role == .Server
	case .Hard_Reset_Server_V2:
		return role == .Client
	}
	return false
}

// Reads the first byte only. Reports the opcode class and key id so the
// caller can route or reject before any parsing. Empty input is `.Truncated`.
peek_opcode :: proc "contextless" (pkt: []u8) -> (op: Opcode, key_id: u8, err: Error) {
	if len(pkt) < 1 {
		return .Unassigned_0, 0, .Truncated
	}
	op, key_id = split_first_byte(pkt[0])
	return op, key_id, .None
}
