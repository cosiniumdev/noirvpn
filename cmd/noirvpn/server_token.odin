// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:encoding/base64"
import "core:mem"
import "core:strings"
import "noir:proto/ossl"
import "noir:server"

// Session token of a web sign-in (`auth-web`).
//
// After a controller allowed a web login with a `token_lifetime`, the server
// pushes a token as `auth-token`. The client sends it as its password at each
// renegotiation and new connection, so the browser opens only once.
//
//   token = "noirt2." + base64url( version | end | id | tag )
//   version  1 byte (1)
//   end      4 bytes, big endian, seconds since the Unix epoch
//   id       TOKEN_ID_LEN random bytes: the key of the sign-in table
//   tag      first 16 bytes of HMAC-SHA256(key, version | end | id)
//
// - The token has no name. The daemon keeps sign-ins in a memory table (id,
//   name, end), so a name can be as long as an identity (255 bytes) and a
//   sign-in can be ended on the server.
// - The tag key is 32 random bytes generated at daemon start. The table is memory
//   only: a daemon restart ends every sign-in.
// - The token is never logged and never on the bus.
// - Stock OpenVPN clients hold a password of at most 127 bytes, so the token
//   has at most TOKEN_MAX bytes (it has 57).

TOKEN_PREFIX :: "noirt2."
TOKEN_VERSION :: 1
TOKEN_ID_LEN :: 16
TOKEN_TAG_LEN :: 16
TOKEN_MAX :: 127
TOKEN_LIFE_MIN :: 60
TOKEN_LIFE_MAX :: 2592000
// Most sign-ins in the table, one per signed-in system. The table is memory held
// for the controller, so it is bounded: 8192 entries of at most 255 name bytes
// are about 2.5 MiB.
SIGNIN_MAX :: 8192
// Expired entries are looked for at most this often (Unix seconds) when the
// table is not full.
SIGNIN_PRUNE_EVERY :: 60

Token_Key :: [32]u8
Token_Id :: [TOKEN_ID_LEN]u8

Token_Check :: enum u8 {
	Ok,
	Bad_Form, // not a token, or damaged
	Bad_Tag, // the tag is not ours (another key, or a changed token)
	Expired,
}

// True when a password has the form of a token. Such a password is never
// looked at as a password.
token_looks_like :: proc "contextless" (s: string) -> bool {
	return len(s) >= len(TOKEN_PREFIX) && s[:len(TOKEN_PREFIX)] == TOKEN_PREFIX
}

@(private = "file")
B64URL := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

@(private = "file")
b64url_encode :: proc(src: []u8, dst: []u8) -> int {
	n := 0
	i := 0
	for ; i + 3 <= len(src); i += 3 {
		v := u32(src[i]) << 16 | u32(src[i + 1]) << 8 | u32(src[i + 2])
		dst[n] = B64URL[v >> 18 & 63]
		dst[n + 1] = B64URL[v >> 12 & 63]
		dst[n + 2] = B64URL[v >> 6 & 63]
		dst[n + 3] = B64URL[v & 63]
		n += 4
	}
	switch len(src) - i {
	case 1:
		v := u32(src[i]) << 16
		dst[n] = B64URL[v >> 18 & 63]
		dst[n + 1] = B64URL[v >> 12 & 63]
		n += 2
	case 2:
		v := u32(src[i]) << 16 | u32(src[i + 1]) << 8
		dst[n] = B64URL[v >> 18 & 63]
		dst[n + 1] = B64URL[v >> 12 & 63]
		dst[n + 2] = B64URL[v >> 6 & 63]
		n += 3
	}
	return n
}

@(private = "file")
b64url_decode :: proc(src: string, dst: []u8) -> (n: int, ok: bool) {
	if len(src) % 4 == 1 {
		return 0, false
	}
	acc, bits := u32(0), 0
	for c in transmute([]u8)src {
		v: u32
		switch {
		case c >= 'A' && c <= 'Z':
			v = u32(c - 'A')
		case c >= 'a' && c <= 'z':
			v = u32(c - 'a') + 26
		case c >= '0' && c <= '9':
			v = u32(c - '0') + 52
		case c == '-':
			v = 62
		case c == '_':
			v = 63
		case:
			return 0, false
		}
		acc = acc << 6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			if n >= len(dst) {
				return 0, false
			}
			dst[n] = u8(acc >> u32(bits))
			n += 1
			acc &= 1 << u32(bits) - 1
		}
	}
	// The unused bits must be zero, so one token has one spelling.
	return n, acc == 0
}

@(private = "file")
token_tag :: proc(key: ^Token_Key, payload: []u8, tag: ^[TOKEN_TAG_LEN]u8) -> bool {
	full: [32]u8
	defer mem.zero_explicit(&full, size_of(full))
	if !ossl.hmac(.SHA256, key[:], payload, full[:]) {
		return false
	}
	copy(tag[:], full[:TOKEN_TAG_LEN])
	return true
}

// Generates the token of the sign-in `id` that ends at `end` (Unix seconds). `buf`
// must have room for TOKEN_MAX bytes.
token_make :: proc(key: ^Token_Key, id: Token_Id, end: u32, buf: []u8) -> (tok: string, ok: bool) {
	if len(buf) < TOKEN_MAX {
		return "", false
	}
	raw: [5 + TOKEN_ID_LEN + TOKEN_TAG_LEN]u8
	raw[0] = TOKEN_VERSION
	raw[1], raw[2], raw[3], raw[4] = u8(end >> 24), u8(end >> 16), u8(end >> 8), u8(end)
	id := id
	n := 5 + copy(raw[5:], id[:])
	tag: [TOKEN_TAG_LEN]u8
	if !token_tag(key, raw[:n], &tag) {
		return "", false
	}
	n += copy(raw[n:], tag[:])
	m := copy(buf, TOKEN_PREFIX)
	m += b64url_encode(raw[:n], buf[m:])
	return string(buf[:m]), true
}

// Checks a token: the form, the tag (in constant time) and the end. The id is
// still to be found in the sign-in table. `now` is in Unix seconds.
token_check :: proc(key: ^Token_Key, tok: string, now: i64) -> (id: Token_Id, end: u32, res: Token_Check) {
	if !token_looks_like(tok) || len(tok) > TOKEN_MAX {
		return {}, 0, .Bad_Form
	}
	raw: [5 + TOKEN_ID_LEN + TOKEN_TAG_LEN]u8
	n, ok := b64url_decode(tok[len(TOKEN_PREFIX):], raw[:])
	if !ok || n != len(raw) || raw[0] != TOKEN_VERSION {
		return {}, 0, .Bad_Form
	}
	body := n - TOKEN_TAG_LEN
	tag: [TOKEN_TAG_LEN]u8
	if !token_tag(key, raw[:body], &tag) {
		return {}, 0, .Bad_Form
	}
	diff := u8(0)
	for i in 0 ..< TOKEN_TAG_LEN {
		diff |= tag[i] ~ raw[body + i]
	}
	if diff != 0 {
		return {}, 0, .Bad_Tag
	}
	end = u32(raw[1]) << 24 | u32(raw[2]) << 16 | u32(raw[3]) << 8 | u32(raw[4])
	if now < 0 || now >= i64(end) {
		return {}, end, .Expired
	}
	copy(id[:], raw[5:body])
	return id, end, .Ok
}

// ------------------------------------------------------------ sign-in table

Sign_In :: struct {
	// The identity, a copy owned by the table.
	name: string,
	// Unix seconds.
	end:  u32,
}

// The sign-ins of the web logins that have a token (an entry for each signed-in
// system). Memory only. The main loop is the only user.
Sign_In_Table :: struct {
	m:          map[Token_Id]Sign_In,
	next_prune: i64,
}

signin_count :: proc(t: ^Sign_In_Table) -> int {
	return len(t.m)
}

// Removes the entries whose end has come.
signin_prune :: proc(t: ^Sign_In_Table, now: i64) {
	dead := make([dynamic]Token_Id, context.temp_allocator)
	for id, e in t.m {
		if now >= i64(e.end) {
			append(&dead, id)
		}
	}
	for id in dead {
		signin_remove(t, id)
	}
	t.next_prune = now + SIGNIN_PRUNE_EVERY
}

// Creates an entry for `name` ending at `end`. Expired entries go first when the
// table is full (or now and then). False (nothing added) if the table is still
// full, the name is not an identity, or memory is short.
signin_add :: proc(t: ^Sign_In_Table, name: string, end: u32, now: i64) -> (id: Token_Id, ok: bool) {
	if !server.identity_check(name) {
		return {}, false
	}
	if len(t.m) >= SIGNIN_MAX || now >= t.next_prune {
		signin_prune(t, now)
	}
	if len(t.m) >= SIGNIN_MAX {
		return {}, false
	}
	for _ in 0 ..< 4 {
		if !ossl.random_bytes(id[:]) {
			return {}, false
		}
		if id not_in t.m {
			copy_name, err := strings.clone(name)
			if err != nil {
				return {}, false
			}
			t.m[id] = Sign_In{copy_name, end}
			return id, true
		}
	}
	return {}, false
}

// The entry of `id`, or nil when there is none or its end has come (such an
// entry is removed).
signin_find :: proc(t: ^Sign_In_Table, id: Token_Id, now: i64) -> ^Sign_In {
	e, ok := &t.m[id]
	if !ok {
		return nil
	}
	if now >= i64(e.end) {
		signin_remove(t, id)
		return nil
	}
	return e
}

signin_remove :: proc(t: ^Sign_In_Table, id: Token_Id) {
	if e, ok := t.m[id]; ok {
		delete(e.name)
		delete_key(&t.m, id)
	}
}

signin_destroy :: proc(t: ^Sign_In_Table) {
	for _, e in t.m {
		delete(e.name)
	}
	delete(t.m)
	t^ = {}
}

// The `auth-token-user` value for a client that sent no user name: the name
// in base64, as OpenVPN pushes it.
token_user_b64 :: proc(name: string, allocator := context.temp_allocator) -> string {
	enc, err := base64.encode(transmute([]u8)name, allocator = allocator)
	return enc if err == nil else ""
}
