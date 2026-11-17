// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wire

// P_DATA_V2 header:
//
//   | 0x48|key_id:1 | peer-id:3 | payload... |

DATA_V2_HEADER_LEN :: 4
// Shortest packet the data path accepts: header plus at least one byte.
// `data_v2_decode` already succeeds at 4 bytes (header only); the data path
// applies this limit.
//
// SPEC-GAP: the spec says "4 to read the header; 5 to pass the data path"
// and also "fewer than 4 bytes follow the opcode byte is an error" (so 5 is the
// shortest good packet). The text is easy to misread, so the codec stays
// lenient and exposes the number.
DATA_V2_MIN_PACKET :: 5

// Peer id meaning "no id yet": the receiver finds the sender by address.
PEER_ID_UNDEFINED :: 0xFFFFFF
// Largest usable peer id.
PEER_ID_MAX :: 0xFFFFFE

Data_V2_Header :: struct {
	key_id:  u8,
	peer_id: u32, // 0 to 0xFFFFFF; PEER_ID_UNDEFINED means none
}

// Writes the 4 header bytes. `peer_id` above 0xFFFFFF is `.Bad_Peer_Id`.
data_v2_encode :: proc "contextless" (buf: []u8, key_id: u8, peer_id: u32) -> (n: int, err: Error) {
	if key_id > MAX_KEY_ID {
		return 0, .Bad_Key_Id
	}
	if peer_id > PEER_ID_UNDEFINED {
		return 0, .Bad_Peer_Id
	}
	if len(buf) < DATA_V2_HEADER_LEN {
		return 0, .Buffer_Too_Small
	}
	buf[0] = first_byte(.Data_V2, key_id)
	buf[1] = u8(peer_id >> 16)
	buf[2] = u8(peer_id >> 8)
	buf[3] = u8(peer_id)
	return DATA_V2_HEADER_LEN, .None
}

// Reads the header. `payload` is the rest of the packet (it may be empty;
// the data path decides whether that is long enough).
data_v2_decode :: proc "contextless" (pkt: []u8) -> (hdr: Data_V2_Header, payload: []u8, err: Error) {
	op, kid, perr := peek_opcode(pkt)
	if perr != .None {
		return {}, nil, perr
	}
	switch opcode_class(op) {
	case .Unknown:
		return {}, nil, .Unknown_Opcode
	case .Rejected:
		return {}, nil, .Rejected_Opcode
	case .Control:
		return {}, nil, .Wrong_Opcode
	case .Data:
	}
	if len(pkt) < DATA_V2_HEADER_LEN {
		return {}, nil, .Truncated
	}
	hdr.key_id = kid
	hdr.peer_id = u32(pkt[1]) << 16 | u32(pkt[2]) << 8 | u32(pkt[3])
	return hdr, pkt[DATA_V2_HEADER_LEN:], .None
}

// The peer id a UDP server uses to find the peer of a data packet. A packet
// shorter than 4 bytes counts as "undefined" (look up by address), as the
// spec says. It fails the length check later in the data path.
data_v2_lookup_peer_id :: proc "contextless" (pkt: []u8) -> u32 {
	if len(pkt) < DATA_V2_HEADER_LEN {
		return PEER_ID_UNDEFINED
	}
	return u32(pkt[1]) << 16 | u32(pkt[2]) << 8 | u32(pkt[3])
}
