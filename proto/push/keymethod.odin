// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

// The key-method-2 message. Each side writes
// one as its first TLS message.
//
//   client: | 00 00 00 00 | 02 | random:112 | options | user | pass | peer_info |
//   server: | 00 00 00 00 | 02 | random:64  | options | user | pass | peer_info |
//
// Every string is `length:u16 | bytes`, `length` counts a closing NUL. An empty
// string is length 0 with no bytes.

KEY_METHOD_PREFIX_LEN :: 5 // zero:4, method:1
KEY_METHOD_RANDOM_CLIENT :: 112 // pre_master 48, random1 32, random2 32
KEY_METHOD_RANDOM_SERVER :: 64 // random1 32, random2 32

// Largest message a stock peer reads in one go.
KEY_METHOD_MAX_LEN :: 2048

// Limits on the declared string length, NUL included.
OPTIONS_MAX_LEN :: 512
USERNAME_MAX_LEN :: 128
PASSWORD_MAX_LEN :: 128

// Both directions. For decode, the strings and `random` are slices of the
// input buffer. For encode, the caller fills the fields it needs.
Key_Method :: struct {
	// Who wrote the message. Selects the size of the random block.
	sender:            Role,
	// High four bits of the method byte. A sender writes 0; a reader ignores
	// them. Set only by the decoder.
	flags:             u8,
	// Random material. 112 bytes from a client, 64 from a server.
	random:            []u8,
	// The options string (options.odin), without NUL.
	options:           string,
	// Login. Both empty in a server message.
	username:          string,
	password:          string,
	// Encoder only: write username and password with their NUL even when empty
	// (length 1). A stock client does this with a login or a token; with no login
	// it writes length 0. A server reads an empty username of length 0 as no
	// login, and drops the token.
	login:             bool,
	// Decoder only: the declared length was above the limit. The string is
	// left empty. The stock server keeps parsing and then rejects the login.
	username_too_long: bool,
	password_too_long: bool,
	// Peer-info text (peerinfo.odin), without NUL.
	peer_info:         string,
	// Decoder only: false if the message had no peer-info string, or one of
	// length 0.
	has_peer_info:     bool,
}

// Length of the random block for a sender.
keymethod_random_len :: proc "contextless" (sender: Role) -> int {
	return KEY_METHOD_RANDOM_CLIENT if sender == .Client else KEY_METHOD_RANDOM_SERVER
}

@(private)
string_field_len :: proc "contextless" (s: string) -> int {
	return 2 if len(s) == 0 else 2 + len(s) + 1
}

@(private)
login_field_len :: proc "contextless" (s: string, login: bool) -> int {
	return 2 + len(s) + 1 if login else string_field_len(s)
}

// Bytes `keymethod_encode` writes for `km` (no checks of the field values).
keymethod_encoded_len :: proc "contextless" (km: ^Key_Method) -> int {
	n := KEY_METHOD_PREFIX_LEN + keymethod_random_len(km.sender)
	n += string_field_len(km.options)
	n += login_field_len(km.username, km.login)
	n += login_field_len(km.password, km.login)
	n += string_field_len(km.peer_info)
	return n
}

@(private)
has_nul :: proc "contextless" (s: string) -> bool {
	for c in transmute([]u8)s {
		if c == 0 {
			return true
		}
	}
	return false
}

@(private)
put_string :: proc "contextless" (buf: []u8, i: ^int, s: string) {
	if len(s) == 0 {
		put_u16(buf[i^:], 0)
		i^ += 2
		return
	}
	put_u16(buf[i^:], u16(len(s) + 1))
	copy(buf[i^ + 2:], s)
	buf[i^ + 2 + len(s)] = 0
	i^ += 2 + len(s) + 1
}

@(private)
put_login :: proc "contextless" (buf: []u8, i: ^int, s: string, login: bool) {
	if !login || len(s) > 0 {
		put_string(buf, i, s)
		return
	}
	put_u16(buf[i^:], 1)
	buf[i^ + 2] = 0
	i^ += 3
}

// Writes the message into `buf` and returns its length. The caller writes it to
// TLS in one call.
//
// Checks:
// - random block has the right size, not all zero
// - strings hold no NUL
// - options under 512 bytes with its NUL; username and password under 128
// - a server message carries no login
// - the whole message fits the 2048 bytes a stock peer reads
keymethod_encode :: proc(buf: []u8, km: ^Key_Method) -> (n: int, err: Error) {
	if len(km.random) != keymethod_random_len(km.sender) {
		return 0, .Bad_Argument
	}
	nonzero := false
	for b in km.random {
		if b != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		return 0, .Zero_Random
	}
	for s in ([4]string{km.options, km.username, km.password, km.peer_info}) {
		if has_nul(s) {
			return 0, .Bad_Argument
		}
	}
	if km.sender == .Server && (len(km.username) > 0 || len(km.password) > 0 || km.login) {
		return 0, .Bad_Argument
	}
	if len(km.options) > 0 && len(km.options) + 1 > OPTIONS_MAX_LEN {
		return 0, .Oversize
	}
	if len(km.username) > 0 && len(km.username) + 1 > USERNAME_MAX_LEN {
		return 0, .Oversize
	}
	if len(km.password) > 0 && len(km.password) + 1 > PASSWORD_MAX_LEN {
		return 0, .Oversize
	}
	if len(km.peer_info) + 1 > 0xFFFF {
		return 0, .Oversize
	}
	total := keymethod_encoded_len(km)
	if total > KEY_METHOD_MAX_LEN {
		return 0, .Oversize
	}
	if len(buf) < total {
		return 0, .Buffer_Too_Small
	}
	i := 0
	for k in 0 ..< 4 {
		buf[k] = 0
	}
	buf[4] = 2
	i = KEY_METHOD_PREFIX_LEN
	copy(buf[i:], km.random)
	i += len(km.random)
	put_string(buf, &i, km.options)
	put_login(buf, &i, km.username, km.login)
	put_login(buf, &i, km.password, km.login)
	put_string(buf, &i, km.peer_info)
	return i, .None
}

// Reads one string field at `i`. `limit` is the largest allowed declared length
// (0: only the message limit). Returns the text (cut at the first NUL, last byte
// forced to NUL as the spec says), the new offset, and whether the declared
// length was above `limit`.
@(private)
read_string_field :: proc(buf: []u8, i: int, limit: int, final: bool) -> (s: string, next: int, too_long: bool, err: Error) {
	short := Error.Truncated if final else Error.Need_More
	if len(buf) - i < 2 {
		return "", i, false, short
	}
	l := int(get_u16(buf[i:]))
	if limit > 0 && l > limit {
		too_long = true
	}
	// Stop early on a field that cannot fit the message limit, even if the
	// bytes are not here yet.
	if i + 2 + l > KEY_METHOD_MAX_LEN {
		return "", i, false, .Oversize
	}
	if len(buf) - i - 2 < l {
		return "", i, too_long, short
	}
	next = i + 2 + l
	if l == 0 || too_long {
		return "", next, too_long, .None
	}
	// The reader forces the last byte to NUL: the text is the first l-1 bytes, and
	// ends at an earlier NUL if any.
	// SPEC-GAP: the spec does not say what a NUL inside a string means. We read it
	// as the end of the text (C string); the encoder refuses to write one.
	raw := buf[i + 2:][:l - 1]
	end := len(raw)
	for k in 0 ..< len(raw) {
		if raw[k] == 0 {
			end = k
			break
		}
	}
	return string(raw[:end]), next, false, .None
}

// Decodes a key-method-2 message from the start of `buf`.
//
//   consumed   bytes used. Bytes after it (text commands) are not looked at.
//   .Need_More bytes so far are a valid prefix; call again with more. Also when the
//              message ends right after the password (peer-info may still come).
//   final      true when no more bytes will come (TLS read ended). Then a message
//              ending after the password means "no peer-info"; any other short
//              message is `.Truncated`.
//
// Errors: `.Bad_Key_Method` (method nibble not 2), `.Oversize` (options over 512
// bytes, or message would pass 2048). The leading four bytes and the high nibble
// of the method byte are not checked.
//
// A username or password over 128 bytes is no error: fields are set empty,
// `username_too_long` / `password_too_long` is set, parsing goes on so the
// peer-info can still be read.
keymethod_decode :: proc(buf: []u8, sender: Role, km: ^Key_Method, final := false) -> (consumed: int, err: Error) {
	km^ = {}
	km.sender = sender
	short := Error.Truncated if final else Error.Need_More
	if len(buf) < KEY_METHOD_PREFIX_LEN {
		return 0, short
	}
	if buf[4] & 0x0F != 2 {
		return 0, .Bad_Key_Method
	}
	km.flags = buf[4] >> 4
	rnd := keymethod_random_len(sender)
	i := KEY_METHOD_PREFIX_LEN
	if len(buf) < i + rnd {
		return 0, short
	}
	km.random = buf[i:][:rnd]
	i += rnd

	too_long: bool
	km.options, i, too_long, err = read_string_field(buf, i, OPTIONS_MAX_LEN, final)
	if too_long {
		return 0, .Oversize
	}
	if err != .None {
		return 0, err
	}
	km.username, i, km.username_too_long, err = read_string_field(buf, i, USERNAME_MAX_LEN, final)
	if err != .None {
		return 0, err
	}
	km.password, i, km.password_too_long, err = read_string_field(buf, i, PASSWORD_MAX_LEN, final)
	if err != .None {
		return 0, err
	}
	// Peer-info is optional at the very end.
	if len(buf) == i {
		if final {
			return i, .None
		}
		return 0, .Need_More
	}
	km.peer_info, i, _, err = read_string_field(buf, i, 0, final)
	if err != .None {
		return 0, err
	}
	km.has_peer_info = len(km.peer_info) > 0
	return i, .None
}
