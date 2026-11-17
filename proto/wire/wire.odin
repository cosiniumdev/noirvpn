// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package wire: byte codecs of the OpenVPN-compatible wire protocol: first byte
// (opcode, key id), control packet header with ACK array, P_DATA_V2 header, TCP
// length framing, early-negotiation TLVs.
//
// Rules for the whole package:
//   - Pure byte work. No crypto, no clock, no I/O.
//   - Decoders never allocate. A decoded payload is a slice into the input.
//   - Encoders write into a buffer the caller owns.
//   - Hostile input returns an `Error`. Never panics or asserts on packet bytes.
//
// The control codec works on the "inner" packet: the bytes before wrapping
// (tls-auth, tls-crypt, tls-crypt-v2) or after unwrapping. See package wrap.
package wire

Error :: enum {
	None,
	// Stream framing only: the bytes so far are a valid prefix. Not a fault.
	Need_More,
	// The input ends before the field being read.
	Truncated,
	// The output buffer is too small.
	Buffer_Too_Small,
	// Opcode number is not assigned (0, 12..31).
	Unknown_Opcode,
	// Opcode is known but noirvpn refuses it (key-method 1 resets, P_DATA_V1).
	Rejected_Opcode,
	// Valid opcode, but not the one this codec handles (for example a data
	// opcode given to the control decoder).
	Wrong_Opcode,
	// Key id above 7 given to an encoder.
	Bad_Key_Id,
	// Session id is all zero. It is never valid on the wire.
	Zero_Session_Id,
	// ACK count not allowed. Decoder: count byte above 8. Encoder: more than 4
	// on a packet that carries data, or not 1 to 8 on P_ACK_V1.
	Bad_Ack_Count,
	// P_ACK_V1 given a payload or message id to encode.
	Bad_Payload,
	// Peer id does not fit 24 bits.
	Bad_Peer_Id,
	// TCP frame: length prefix of zero.
	Zero_Length,
	// A packet or frame longer than the allowed maximum.
	Oversize,
	// Early-negotiation TLV list is malformed.
	Bad_Tlv,
}

// Largest control packet a receiver accepts.
MAX_CONTROL_LEN :: 2048

SESSION_ID_LEN :: 8
Session_Id :: [SESSION_ID_LEN]u8

// True if the session id is all zero ("undefined").
session_id_is_zero :: proc "contextless" (sid: Session_Id) -> bool {
	for b in sid {
		if b != 0 {
			return false
		}
	}
	return true
}

@(private)
put_u16 :: #force_inline proc "contextless" (b: []u8, v: u16) {
	b[0] = u8(v >> 8)
	b[1] = u8(v)
}

@(private)
put_u32 :: #force_inline proc "contextless" (b: []u8, v: u32) {
	b[0] = u8(v >> 24)
	b[1] = u8(v >> 16)
	b[2] = u8(v >> 8)
	b[3] = u8(v)
}

@(private)
get_u16 :: #force_inline proc "contextless" (b: []u8) -> u16 {
	return u16(b[0]) << 8 | u16(b[1])
}

@(private)
get_u32 :: #force_inline proc "contextless" (b: []u8) -> u32 {
	return u32(b[0]) << 24 | u32(b[1]) << 16 | u32(b[2]) << 8 | u32(b[3])
}
