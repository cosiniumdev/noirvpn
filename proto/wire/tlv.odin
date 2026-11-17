// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wire

// Early-negotiation TLVs in the payload of a hard reset with message id 0
//: `type:u16 | length:u16 | value`.

TLV_HEADER_LEN :: 4

// Type 1: early-negotiation flags. Value is one u16 bit set.
TLV_TYPE_EARLY_NEG_FLAGS :: 0x0001
// Flag bit: "resend the wrapped client key in your next packet".
EARLY_NEG_FLAG_RESEND_WKC :: 0x0001

// Iterator over a TLV list. Use with `tlv_next`; check `err` after the loop.
Tlv_Iter :: struct {
	rest: []u8,
	err:  Error,
}

tlv_iter :: proc "contextless" (payload: []u8) -> Tlv_Iter {
	return Tlv_Iter{rest = payload}
}

// Yields the next TLV: `for typ, value in tlv_next(&it) { ... }`.
// The loop ends at the end of the list or at a malformed entry (the latter
// sets `it.err = .Bad_Tlv`). Values point into the payload.
tlv_next :: proc "contextless" (it: ^Tlv_Iter) -> (typ: u16, value: []u8, ok: bool) {
	if it.err != .None || len(it.rest) == 0 {
		return 0, nil, false
	}
	if len(it.rest) < TLV_HEADER_LEN {
		it.err = .Bad_Tlv
		return 0, nil, false
	}
	typ = get_u16(it.rest)
	l := int(get_u16(it.rest[2:]))
	if l > len(it.rest) - TLV_HEADER_LEN {
		it.err = .Bad_Tlv
		return 0, nil, false
	}
	value = it.rest[TLV_HEADER_LEN:][:l]
	it.rest = it.rest[TLV_HEADER_LEN + l:]
	return typ, value, true
}

// Parses the payload of a hard reset. Returns the early-negotiation flags (0 if
// no flags TLV). Unknown TLV types are skipped.
// Errors: truncated TLV, non-empty payload shorter than 4 bytes, flags TLV
// whose length is not 2.
//
// SPEC-GAP: the spec is silent if the flags TLV appears twice. The flags are
// OR-ed together.
early_neg_parse :: proc "contextless" (payload: []u8) -> (flags: u16, err: Error) {
	it := tlv_iter(payload)
	for typ, value in tlv_next(&it) {
		if typ == TLV_TYPE_EARLY_NEG_FLAGS {
			if len(value) != 2 {
				return 0, .Bad_Tlv
			}
			flags |= get_u16(value)
		}
	}
	if it.err != .None {
		return 0, it.err
	}
	return flags, .None
}

// Writes one TLV. Returns the bytes written.
tlv_encode :: proc "contextless" (buf: []u8, typ: u16, value: []u8) -> (n: int, err: Error) {
	if len(value) > 0xFFFF {
		return 0, .Oversize
	}
	total := TLV_HEADER_LEN + len(value)
	if len(buf) < total {
		return 0, .Buffer_Too_Small
	}
	put_u16(buf, typ)
	put_u16(buf[2:], u16(len(value)))
	copy(buf[TLV_HEADER_LEN:total], value)
	return total, .None
}

// Writes the flags TLV, for example `00 01 00 02 00 01` for RESEND_WKC.
early_neg_encode :: proc "contextless" (buf: []u8, flags: u16) -> (n: int, err: Error) {
	v: [2]u8
	put_u16(v[:], flags)
	return tlv_encode(buf, TLV_TYPE_EARLY_NEG_FLAGS, v[:])
}
