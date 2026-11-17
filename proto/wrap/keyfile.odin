// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

// Key files.

STATIC_KEY_LEN :: 256
// Each of the two keys in a static key file is 128 bytes: a 64-byte cipher
// part, then a 64-byte HMAC part.
KEY_SLOT_LEN :: 128

STATIC_KEY_BEGIN :: "-----BEGIN OpenVPN Static key V1-----"
STATIC_KEY_END :: "-----END OpenVPN Static key V1-----"
SERVER_KEY_LABEL :: "OpenVPN tls-crypt-v2 server key"
CLIENT_KEY_LABEL :: "OpenVPN tls-crypt-v2 client key"

// 256 bytes of key material, laid out as the spec draws it:
//
//   0..63 key[0].cipher   64..127 key[0].hmac   128..191 key[1].cipher   192..255 key[1].hmac
//
// Also the format of Kc (tls-crypt-v2) and of the dynamic tls-crypt key.
Static_Key :: struct {
	bytes: [STATIC_KEY_LEN]u8,
}

// Cipher part of key slot 0 or 1 (64 bytes).
static_key_cipher :: proc "contextless" (k: ^Static_Key, slot: int) -> []u8 {
	return k.bytes[KEY_SLOT_LEN * slot:][:64]
}

// HMAC part of key slot 0 or 1 (64 bytes).
static_key_hmac :: proc "contextless" (k: ^Static_Key, slot: int) -> []u8 {
	return k.bytes[KEY_SLOT_LEN * slot + 64:][:64]
}

static_key_wipe :: proc "contextless" (k: ^Static_Key) {
	wipe(k.bytes[:])
}

// True if the first 16 bytes of any of the four parts are all zero.
static_key_has_zero_slot :: proc "contextless" (k: ^Static_Key) -> bool {
	for part in 0 ..< 4 {
		zero := true
		for i in 0 ..< 16 {
			if k.bytes[64 * part + i] != 0 {
				zero = false
				break
			}
		}
		if zero {
			return true
		}
	}
	return false
}

@(private)
find :: proc "contextless" (hay: []u8, needle: string) -> int {
	n := len(needle)
	if n == 0 || len(hay) < n {
		return -1
	}
	for i in 0 ..= len(hay) - n {
		if string(hay[i:][:n]) == needle {
			return i
		}
	}
	return -1
}

@(private)
has_prefix :: proc "contextless" (b: []u8, prefix: string) -> bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == prefix
}

@(private)
is_space :: proc "contextless" (c: u8) -> bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

@(private)
hex_value :: proc "contextless" (c: u8) -> int {
	switch c {
	case '0' ..= '9':
		return int(c - '0')
	case 'a' ..= 'f':
		return int(c - 'a') + 10
	case 'A' ..= 'F':
		return int(c - 'A') + 10
	}
	return -1
}

// Parses an "OpenVPN Static key V1" file.
//
// Rules:
// - skip everything up to and including the BEGIN line
// - read hex digits, ignoring spaces, tabs, CR and LF; any other character is
//   an error
// - stop at the END line or after 256 bytes; require exactly 256 bytes
// - reject a key whose four parts do not each start with a non-zero 16 bytes
// - missing BEGIN or END line is an error
//
// SPEC-GAP: after 256 bytes the spec says "stop" but also says a missing footer
// is an error. This parser keeps scanning for the END line, ignores extra hex
// digits before it, and requires it. An odd number of hex digits is `.Bad_Hex`.
// BEGIN and END need not start at the beginning of a line.
static_key_parse :: proc "contextless" (text: []u8, key: ^Static_Key) -> Error {
	key^ = {}
	err := static_key_parse_inner(text, key)
	if err != .None {
		static_key_wipe(key)
	}
	return err
}

@(private)
static_key_parse_inner :: proc "contextless" (text: []u8, key: ^Static_Key) -> Error {
	begin := find(text, STATIC_KEY_BEGIN)
	if begin < 0 {
		return .Missing_Header
	}
	i := begin + len(STATIC_KEY_BEGIN)
	for i < len(text) && text[i] != '\n' {
		i += 1
	}

	nbytes := 0
	pending := -1 // high nibble waiting for its partner
	footer := false
	scan: for i < len(text) {
		c := text[i]
		switch {
		case is_space(c):
		case c == '-':
			if has_prefix(text[i:], STATIC_KEY_END) {
				footer = true
				break scan
			}
			return .Bad_Hex
		case:
			v := hex_value(c)
			if v < 0 {
				return .Bad_Hex
			}
			if nbytes < STATIC_KEY_LEN {
				if pending < 0 {
					pending = v
				} else {
					key.bytes[nbytes] = u8(pending << 4 | v)
					nbytes += 1
					pending = -1
				}
			}
		}
		i += 1
	}
	if !footer {
		return .Missing_Footer
	}
	if pending >= 0 {
		return .Bad_Hex
	}
	if nbytes != STATIC_KEY_LEN {
		return .Wrong_Size
	}
	if static_key_has_zero_slot(key) {
		return .Zero_Slot
	}
	return .None
}

static_key_parse_string :: proc "contextless" (text: string, key: ^Static_Key) -> Error {
	return static_key_parse(transmute([]u8)text, key)
}

// ---- PEM ----

@(private)
b64_value :: proc "contextless" (c: u8) -> int {
	switch c {
	case 'A' ..= 'Z':
		return int(c - 'A')
	case 'a' ..= 'z':
		return int(c - 'a') + 26
	case '0' ..= '9':
		return int(c - '0') + 52
	case '+':
		return 62
	case '/':
		return 63
	}
	return -1
}

// Decodes the single PEM block named `label` in `text` into `out`. Returns the
// number of bytes.
// - Text before BEGIN and after END is ignored.
// - Standard base64 with padding. White space (CRLF, blank lines) is skipped
//   anywhere in the body.
// - Other label: `.Wrong_Label`. More decoded bytes than `out` holds:
//   `.Wrong_Size`.
//
// SPEC-GAP: the spec does not say how strict the base64 reader is. This one
// needs complete 4-character groups and padding only at the end, and does not
// check that unused trailing bits are zero. PEM headers ("Proc-Type:") are not
// supported and fail as `.Bad_Base64`.
pem_decode :: proc "contextless" (text: []u8, label: string, out: []u8) -> (n: int, err: Error) {
	BEGIN :: "-----BEGIN "
	b := find(text, BEGIN)
	if b < 0 {
		return 0, .Missing_Header
	}
	i := b + len(BEGIN)
	dashes := find(text[i:], "-----")
	if dashes < 0 {
		return 0, .Missing_Header
	}
	if string(text[i:][:dashes]) != label {
		return 0, .Wrong_Label
	}
	i += dashes + 5

	group: [4]u8
	k := 0 // characters in the current group
	pad := 0 // '=' characters in the current group
	done_data := false // a padded group was completed; only the END line may follow
	end_found := false
	body: for i < len(text) {
		c := text[i]
		switch {
		case is_space(c):
		case c == '-':
			if has_prefix(text[i:], "-----END ") {
				rest := text[i + 9:]
				if has_prefix(rest, label) && has_prefix(rest[len(label):], "-----") {
					end_found = true
					break body
				}
				return n, .Wrong_Label
			}
			return n, .Bad_Base64
		case:
			if done_data {
				return n, .Bad_Base64
			}
			if c == '=' {
				if k < 2 {
					return n, .Bad_Base64
				}
				pad += 1
				group[k] = 0
			} else {
				v := b64_value(c)
				if v < 0 || pad > 0 {
					return n, .Bad_Base64
				}
				group[k] = u8(v)
			}
			k += 1
			if k == 4 {
				produced := 3 - pad
				if n + produced > len(out) {
					return n, .Wrong_Size
				}
				v24 := u32(group[0]) << 18 | u32(group[1]) << 12 | u32(group[2]) << 6 | u32(group[3])
				out[n] = u8(v24 >> 16)
				if produced > 1 {
					out[n + 1] = u8(v24 >> 8)
				}
				if produced > 2 {
					out[n + 2] = u8(v24)
				}
				n += produced
				k = 0
				if pad > 0 {
					done_data = true
				}
				pad = 0
			}
		}
		i += 1
	}
	if !end_found {
		return n, .Missing_Footer
	}
	if k != 0 {
		return n, .Bad_Base64
	}
	return n, .None
}

// ---- tls-crypt-v2 keys ----

SERVER_KEY_LEN :: 128
WKC_MAX_LEN :: 1024

// tls-crypt-v2 server key. Only the two pieces in use are kept: the AES-256
// key (bytes 0..32 of the 128-byte body) and the HMAC-SHA256 key (bytes
// 64..96).
Server_Key :: struct {
	ke: [32]u8,
	ka: [32]u8,
}

server_key_wipe :: proc "contextless" (k: ^Server_Key) {
	wipe(k.ke[:])
	wipe(k.ka[:])
}

// Builds a server key from the 128-byte body.
server_key_from_bytes :: proc "contextless" (body: []u8, k: ^Server_Key) -> Error {
	k^ = {}
	if len(body) != SERVER_KEY_LEN {
		return .Wrong_Size
	}
	copy(k.ke[:], body[0:32])
	copy(k.ka[:], body[64:96])
	return .None
}

// Parses a PEM file with the label "OpenVPN tls-crypt-v2 server key". The body
// must be exactly 128 bytes (a noirvpn rule; the spec marks stock strictness
// UNVERIFIED). No zero-slot check is done.
server_key_parse :: proc "contextless" (text: []u8, k: ^Server_Key) -> Error {
	k^ = {}
	body: [SERVER_KEY_LEN]u8
	defer wipe(body[:])
	n, err := pem_decode(text, SERVER_KEY_LABEL, body[:])
	if err != .None {
		return err
	}
	if n != SERVER_KEY_LEN {
		return .Wrong_Size
	}
	return server_key_from_bytes(body[:], k)
}

server_key_parse_string :: proc "contextless" (text: string, k: ^Server_Key) -> Error {
	return server_key_parse(transmute([]u8)text, k)
}

// tls-crypt-v2 client key: the client's wrap key Kc and the wrapped copy WKc
// that is appended to the first packets.
Client_Key :: struct {
	kc:      Static_Key,
	wkc:     [WKC_MAX_LEN]u8,
	wkc_len: int,
}

// The WKc bytes.
client_key_wkc :: proc "contextless" (k: ^Client_Key) -> []u8 {
	return k.wkc[:k.wkc_len]
}

client_key_wipe :: proc "contextless" (k: ^Client_Key) {
	static_key_wipe(&k.kc)
	wipe(k.wkc[:])
	k.wkc_len = 0
}

// Parses a PEM file with the label "OpenVPN tls-crypt-v2 client key". The body is
// Kc (256 bytes) followed by WKc (1 to 1024 bytes). No zero-slot check on Kc.
//
// SPEC-GAP: the spec gives the WKc size as 1 to 1024 bytes but says a real one is
// at least 290. This parser follows the spec text (1 to 1024) and does not check
// the length field inside WKc. A server drops a bad WKc anyway.
client_key_parse :: proc "contextless" (text: []u8, k: ^Client_Key) -> Error {
	k^ = {}
	body: [STATIC_KEY_LEN + WKC_MAX_LEN]u8
	defer wipe(body[:])
	n, err := pem_decode(text, CLIENT_KEY_LABEL, body[:])
	if err != .None {
		return err
	}
	if n <= STATIC_KEY_LEN {
		return .Wrong_Size
	}
	copy(k.kc.bytes[:], body[:STATIC_KEY_LEN])
	k.wkc_len = n - STATIC_KEY_LEN
	copy(k.wkc[:k.wkc_len], body[STATIC_KEY_LEN:n])
	return .None
}

client_key_parse_string :: proc "contextless" (text: string, k: ^Client_Key) -> Error {
	return client_key_parse(transmute([]u8)text, k)
}
