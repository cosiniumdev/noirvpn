// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Who is on the other end of a bus connection, and the Windows security id
// (SID) in a form that every platform can parse, print and compare.

import "core:strconv"
import "core:strings"

// The largest binary SID: 8 bytes of header and 15 sub-authorities.
SID_MAX :: 68

// A SID in binary form (the layout Windows uses), held by value. `len` is 0
// for no SID. Windows wants a SID at a 4 byte boundary: `data` comes first.
Sid :: struct #align (4) {
	data: [SID_MAX]u8,
	len:  u8,
}

SID_LOCAL_SYSTEM :: "S-1-5-18"
SID_ADMINISTRATORS :: "S-1-5-32-544"

// The identity of a client. On Unix the kernel gives uid, gid and maybe the
// pid. On Windows `sid` is the user of the client token, and the pid is the
// client process.
Peer_Creds :: struct {
	uid, gid: u32,
	pid:      u32,
	has_pid:  bool,
	sid:      Sid,
}

sid_bytes :: proc(s: ^Sid) -> []u8 {
	return s.data[:s.len]
}

sid_equal :: proc "contextless" (a, b: Sid) -> bool {
	if a.len != b.len {
		return false
	}
	for i in 0 ..< int(a.len) {
		if a.data[i] != b.data[i] {
			return false
		}
	}
	return true
}

// A SID from binary form. False if the bytes are not a valid SID.
sid_from_bytes :: proc(b: []u8) -> (s: Sid, ok: bool) {
	if len(b) < 8 || b[0] != 1 {
		return {}, false
	}
	n := int(b[1])
	if n > 15 || len(b) < 8 + 4 * n {
		return {}, false
	}
	s.len = u8(8 + 4 * n)
	copy(s.data[:], b[:s.len])
	return s, true
}

// Parse "S-1-<authority>-<sub>...". The authority is decimal (or 0x hex, as
// Windows writes one above 2^32). 1 to 15 sub-authorities.
sid_parse :: proc(text: string) -> (s: Sid, ok: bool) {
	if len(text) < 4 || (text[0] != 'S' && text[0] != 's') || text[1] != '-' || text[len(text) - 1] == '-' {
		return {}, false
	}
	rest := text[2:]
	parts: [17]string
	n := 0
	for part in strings.split_iterator(&rest, "-") {
		if n == len(parts) {
			return {}, false
		}
		parts[n] = part
		n += 1
	}
	// Revision, authority, then at least one sub-authority.
	if n < 3 || parts[0] != "1" {
		return {}, false
	}
	auth: u64
	a := parts[1]
	if len(a) > 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X') {
		v, vok := parse_digits(a[2:], 16)
		if !vok {
			return {}, false
		}
		auth = v
	} else {
		v, vok := parse_digits(a, 10)
		if !vok {
			return {}, false
		}
		auth = v
	}
	if auth >= 1 << 48 {
		return {}, false
	}
	subs := n - 2
	s.data[0] = 1
	s.data[1] = u8(subs)
	for i in 0 ..< 6 {
		s.data[2 + i] = u8(auth >> u64(8 * (5 - i)))
	}
	for i in 0 ..< subs {
		v, vok := parse_digits(parts[2 + i], 10)
		if !vok || v > u64(max(u32)) {
			return {}, false
		}
		off := 8 + 4 * i
		s.data[off] = u8(v)
		s.data[off + 1] = u8(v >> 8)
		s.data[off + 2] = u8(v >> 16)
		s.data[off + 3] = u8(v >> 24)
	}
	s.len = u8(8 + 4 * subs)
	return s, true
}

@(private)
parse_digits :: proc(s: string, base: int) -> (v: u64, ok: bool) {
	if len(s) == 0 || len(s) > 20 {
		return 0, false
	}
	for ch in s {
		is_digit := ch >= '0' && ch <= '9'
		is_hex := base == 16 && ((ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
		if !is_digit && !is_hex {
			return 0, false
		}
	}
	return strconv.parse_u64_of_base(s, base)
}

// The text form, "S-1-5-18". "" for no SID.
sid_string :: proc(s: Sid, allocator := context.allocator) -> string {
	if s.len < 8 {
		return ""
	}
	b := strings.builder_make(allocator)
	strings.write_string(&b, "S-1-")
	auth: u64
	for i in 0 ..< 6 {
		auth = auth << 8 | u64(s.data[2 + i])
	}
	if auth >= 1 << 32 {
		strings.write_string(&b, "0x")
		strings.write_u64(&b, auth, 16)
	} else {
		strings.write_u64(&b, auth)
	}
	subs := int(s.data[1])
	for i in 0 ..< subs {
		off := 8 + 4 * i
		v := u32(s.data[off]) | u32(s.data[off + 1]) << 8 | u32(s.data[off + 2]) << 16 | u32(s.data[off + 3]) << 24
		strings.write_byte(&b, '-')
		strings.write_u64(&b, u64(v))
	}
	return strings.to_string(b)
}

// True for text that should be read as a SID.
looks_like_sid :: proc(text: string) -> bool {
	return len(text) > 2 && (text[0] == 'S' || text[0] == 's') && text[1] == '-'
}

@(private)
must_sid :: proc(text: string) -> Sid {
	s, ok := sid_parse(text)
	assert(ok)
	return s
}
