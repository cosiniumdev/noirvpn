// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

// What a decrypted data packet carries: a tunnel
// packet, the keepalive ping, or an OCC message (legacy options check; only
// EXIT is still used).

// The keepalive ping: a data packet whose plaintext is exactly these 16 bytes
// (7.2).
PING_MAGIC :: [16]u8{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
PING_LEN :: 16

// An OCC message starts with these 16 bytes; the 17th byte is its opcode (7.3).
OCC_MAGIC :: [16]u8{0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c}
OCC_PREFIX_LEN :: 17

Occ_Opcode :: enum u8 {
	Request          = 0,
	Reply            = 1,
	Mtu_Load_Request = 2,
	Mtu_Load         = 3,
	Mtu_Request      = 4,
	Mtu_Reply        = 5,
	Exit             = 6,
}

Payload_Kind :: enum {
	Empty, // no bytes
	Ipv4, // first nibble 4: write to the tun device
	Ipv6, // first nibble 6: write to the tun device
	Ping, // keepalive: do not write to the tun device
	Occ_Request, // opcodes 0 to 5 are recognised and dropped; noirvpn never sends them
	Occ_Reply,
	Occ_Mtu_Load_Request,
	Occ_Mtu_Load,
	Occ_Mtu_Request,
	Occ_Mtu_Reply,
	Occ_Exit, // the peer is closing
	Occ_Unknown, // OCC magic with an opcode above 6
	Unknown, // anything else: drop (log at a low rate)
}

// Says what a decrypted plaintext is. The match is on the bytes, as the spec
// has it: the ping must be 16 bytes and equal to the magic. An OCC message is
// the 16-byte magic plus an opcode byte.
classify_payload :: proc "contextless" (plain: []u8) -> Payload_Kind {
	if len(plain) == 0 {
		return .Empty
	}
	if len(plain) == PING_LEN && has_prefix16(plain, PING_MAGIC) {
		return .Ping
	}
	if len(plain) >= OCC_PREFIX_LEN && has_prefix16(plain, OCC_MAGIC) {
		switch Occ_Opcode(plain[16]) {
		case .Request:
			return .Occ_Request
		case .Reply:
			return .Occ_Reply
		case .Mtu_Load_Request:
			return .Occ_Mtu_Load_Request
		case .Mtu_Load:
			return .Occ_Mtu_Load
		case .Mtu_Request:
			return .Occ_Mtu_Request
		case .Mtu_Reply:
			return .Occ_Mtu_Reply
		case .Exit:
			return .Occ_Exit
		}
		return .Occ_Unknown
	}
	switch plain[0] >> 4 {
	case 4:
		return .Ipv4
	case 6:
		return .Ipv6
	}
	return .Unknown
}

// True for a plaintext that goes to the tun device.
payload_is_tunnel :: proc "contextless" (k: Payload_Kind) -> bool {
	return k == .Ipv4 || k == .Ipv6
}

// True for any OCC kind.
payload_is_occ :: proc "contextless" (k: Payload_Kind) -> bool {
	#partial switch k {
	case .Occ_Request,
	     .Occ_Reply,
	     .Occ_Mtu_Load_Request,
	     .Occ_Mtu_Load,
	     .Occ_Mtu_Request,
	     .Occ_Mtu_Reply,
	     .Occ_Exit,
	     .Occ_Unknown:
		return true
	}
	return false
}

// Writes the 16-byte keepalive plaintext to the start of `out` and returns it.
// Seal it like any payload.
build_ping :: proc "contextless" (out: []u8) -> (plain: []u8, ok: bool) {
	if len(out) < PING_LEN {
		return nil, false
	}
	magic := PING_MAGIC
	copy(out, magic[:])
	return out[:PING_LEN], true
}

// Writes the 17-byte OCC EXIT plaintext (7.3) to the start of `out` and
// returns it. It is the data-channel form of "I am closing". Used only when
// `explicit-exit-notify` is on and `cc-exit` was not negotiated.
build_occ_exit :: proc "contextless" (out: []u8) -> (plain: []u8, ok: bool) {
	if len(out) < OCC_PREFIX_LEN {
		return nil, false
	}
	magic := OCC_MAGIC
	copy(out, magic[:])
	out[16] = u8(Occ_Opcode.Exit)
	return out[:OCC_PREFIX_LEN], true
}

// True if the first 16 bytes of `a` are `magic` (`a` must have 16 bytes).
@(private)
has_prefix16 :: #force_inline proc "contextless" (a: []u8, magic: [16]u8) -> bool {
	for i in 0 ..< 16 {
		if a[i] != magic[i] {
			return false
		}
	}
	return true
}
