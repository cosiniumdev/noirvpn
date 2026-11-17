// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

// Types shared by the parts of the server: transport address keys, identities
// and reject reasons.

// ---------------------------------------------------------------------------
// Transport address key

// A transport address as opaque bytes, so the peer table does not depend on a
// socket library. The caller builds it. Only `rate_key` looks inside.
// Layout of the helpers:
//   - 16 bytes of address (IPv4 as ::ffff:a.b.c.d)
//   - 2 bytes of port (big endian)
//   - 1 byte for the listening socket (so UDP and TCP, or two `local` lines,
//     never collide)
//   - 1 byte unused
ADDR_KEY_LEN :: 20

Addr_Key :: [ADDR_KEY_LEN]u8

addr_key_v4 :: proc "contextless" (ip: [4]u8, port: u16, sock: u8 = 0) -> (k: Addr_Key) {
	k[10] = 0xff
	k[11] = 0xff
	k[12], k[13], k[14], k[15] = ip[0], ip[1], ip[2], ip[3]
	k[16] = u8(port >> 8)
	k[17] = u8(port)
	k[18] = sock
	return
}

addr_key_v6 :: proc "contextless" (ip: [16]u8, port: u16, sock: u8 = 0) -> (k: Addr_Key) {
	for i in 0 ..< 16 {
		k[i] = ip[i]
	}
	k[16] = u8(port >> 8)
	k[17] = u8(port)
	k[18] = sock
	return
}

addr_key_is_v4 :: proc "contextless" (k: Addr_Key) -> bool {
	for i in 0 ..< 10 {
		if k[i] != 0 {
			return false
		}
	}
	return k[10] == 0xff && k[11] == 0xff
}

// The part of a transport address that a rate limit uses as key: the whole
// IPv4 address, or the /64 of an IPv6 address (one customer owns a /64, so a
// limit per full address would be no limit). Port and socket are dropped.
rate_key :: proc "contextless" (k: Addr_Key) -> (r: [16]u8) {
	for i in 0 ..< 16 {
		r[i] = k[i]
	}
	if !addr_key_is_v4(k) {
		for i in 8 ..< 16 {
			r[i] = 0
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Identity

// The longest identity. It is also the longest file name in client-config-dir.
MAX_IDENTITY_LEN :: 255

// The name a session is known by: the pinned username, or the certificate name
// in CA mode. It is a value type, so a decision never points into memory that
// a reload may free.
Identity :: struct {
	len: u8,
	buf: [MAX_IDENTITY_LEN]u8,
}

// An identity is a file name in client-config-dir and a key in log lines and
// in the pool file, so keep it plain:
//   - 1 to 255 bytes, no control bytes, no path separators, not "." or ".."
//   - bytes of 0x80 and above are fine (UTF-8 names)
//   - nothing is rewritten: two different names must stay different
identity_check :: proc "contextless" (s: string) -> bool {
	if len(s) == 0 || len(s) > MAX_IDENTITY_LEN || s == "." || s == ".." {
		return false
	}
	for c in transmute([]u8)s {
		if c < 0x20 || c == 0x7f || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}

identity_make :: proc "contextless" (s: string) -> (id: Identity, ok: bool) {
	if !identity_check(s) {
		return {}, false
	}
	id.len = u8(len(s))
	copy(id.buf[:], s)
	return id, true
}

// A view of the name. It points into `id`, so `id` must not move or die while
// the string is in use.
identity_str :: proc "contextless" (id: ^Identity) -> string {
	return string(id.buf[:id.len])
}

// User names are compared with ASCII case ignored (the fold covers the ASCII
// letters only, like `strcasecmp` in the C locale). A name with other letters
// matches byte for byte. An identity keeps the form of its source. Only the
// compare and the hash fold.
ascii_lower :: #force_inline proc "contextless" (c: u8) -> u8 {
	return c + 32 if c >= 'A' && c <= 'Z' else c
}

name_equal :: proc "contextless" (a, b: string) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		if ascii_lower(a[i]) != ascii_lower(b[i]) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Rejects

// Why a session was refused. Reasons are for logs and bus events; the client
// only sees `Reject_Kind` (see `reject_client_text`).
Reject_Reason :: enum u8 {
	None,
	// Pin lookup: the key is not in the peers file (normally refused already
	// inside TLS; this is the second check).
	Key_Not_Pinned,
	// The pinned entry has the `disabled` option.
	Key_Disabled,
	// The client sent a username that is not the identity of its certificate
	// (the pinned username, or the certificate name).
	Username_Mismatch,
	// CA mode: the certificate has no usable name field.
	No_Identity,
	// The name is not a valid identity (see `identity_check`).
	Bad_Identity,
	// CA modes: the caller did not confirm that TLS verified the chain.
	Chain_Not_Verified,
	// The hash file needs a password and the client sent none.
	Password_Missing,
	// The hash file check failed: the user is not in the file, or the password
	// is wrong.
	Password_Failed,
	// The hash file check has no room now: its queue is full, or it took too
	// long. The client may try again later.
	Password_Busy,
	// auth-external: the controller said no, or did not respond in time.
	External_Denied,
	External_Timeout,
	// A session token that is wrong, expired, or for another identity (or a
	// password that looks like a token on a login that cannot have one).
	Token_Invalid,
	Rate_Limited,
	Max_Clients,
	// No peer-id is free (all in use or waiting out the reuse delay).
	Id_Exhausted,
	// ccd-exclusive and no client-config-dir file for this client.
	Ccd_Required,
	// `disable` in the ccd file or the peers file entry.
	Client_Disabled,
	// The ccd file has errors.
	Config_Error,
	// ifconfig-push outside the server network, or on a reserved address.
	Bad_Static_Address,
	// Another session holds that static address.
	Address_In_Use,
	Pool_Exhausted,
	Too_Many_Routes,
	// An iroute overlaps the server network.
	Bad_Iroute,
	// An iroute or address already belongs to another client.
	Route_Conflict,
	// A bug or a broken invariant; the session is refused to be safe.
	Internal,
}

// How the client is told:
//   Auth_Failed         - final (`AUTH_FAILED`)
//   Auth_Failed_Temp    - the client tries again later
//                         (`AUTH_FAILED,TEMP[...]`, IV_PROTO bit 8)
//   Auth_Failed_Session - for a token that is not accepted
Reject_Kind :: enum u8 {
	Auth_Failed,
	Auth_Failed_Temp,
	// `AUTH_FAILED,SESSION`: the client drops its token and signs in again.
	Auth_Failed_Session,
}

Reject :: struct {
	reason: Reject_Reason,
	kind:   Reject_Kind,
}

// A reject with the usual kind for the reason: reasons that can go away by
// waiting (limits, full pools, a controller that timed out) are temporary.
reject_make :: proc "contextless" (reason: Reject_Reason) -> Reject {
	kind := Reject_Kind.Auth_Failed
	#partial switch reason {
	case .Password_Busy, .External_Timeout, .Rate_Limited, .Max_Clients, .Id_Exhausted, .Pool_Exhausted, .Address_In_Use:
		kind = .Auth_Failed_Temp
	case .Token_Invalid:
		kind = .Auth_Failed_Session
	}
	return Reject{reason, kind}
}

// Seconds a client waits before it tries again after a temporary reject (the
// `backoff` hint of `AUTH_FAILED,TEMP`). 0 for a final reject. The client uses
// it as a floor and lengthens the wait with each refusal in a row.
reject_backoff :: proc "contextless" (r: Reject) -> int {
	if r.kind != .Auth_Failed_Temp {
		return 0
	}
	#partial switch r.reason {
	case .Password_Busy:
		return 5
	case .External_Timeout, .Rate_Limited:
		return 10
	case .Address_In_Use, .Max_Clients:
		return 30
	case .Id_Exhausted, .Pool_Exhausted:
		return 60
	}
	return 10
}

// For the server log.
reject_text :: proc "contextless" (r: Reject_Reason) -> string {
	switch r {
	case .None:
		return "none"
	case .Key_Not_Pinned:
		return "the client key is not in the peers file"
	case .Key_Disabled:
		return "the client key is disabled in the peers file"
	case .Username_Mismatch:
		return "client username does not match the identity of its certificate"
	case .No_Identity:
		return "the client certificate has no usable name"
	case .Bad_Identity:
		return "the client name is not a valid identity"
	case .Chain_Not_Verified:
		return "the certificate chain could not be verified"
	case .Password_Missing:
		return "the client sent no password"
	case .Password_Failed:
		return "the password check failed"
	case .Password_Busy:
		return "the password check was too busy or took too long"
	case .External_Denied:
		return "the external controller refused the login"
	case .External_Timeout:
		return "the external controller did not respond in time"
	case .Token_Invalid:
		return "the session token is not valid"
	case .Rate_Limited:
		return "too many connection attempts from this address (connect-freq)"
	case .Max_Clients:
		return "too many clients are connected (max-clients)"
	case .Id_Exhausted:
		return "there are no free peer ids left"
	case .Ccd_Required:
		return "there is no client-config-dir file for this client (ccd-exclusive)"
	case .Client_Disabled:
		return "the client is disabled"
	case .Config_Error:
		return "the client-config-dir file has an error"
	case .Bad_Static_Address:
		return "the ifconfig-push address cannot be used"
	case .Address_In_Use:
		return "the static address is already in use by another client"
	case .Pool_Exhausted:
		return "the address pool has run out of addresses"
	case .Too_Many_Routes:
		return "the client has too many iroutes (max-routes-per-client)"
	case .Bad_Iroute:
		return "an iroute overlaps the server network"
	case .Route_Conflict:
		return "the address or an iroute already belongs to another client"
	case .Internal:
		return "internal error"
	}
	return "?"
}

// What goes to the client in `AUTH_FAILED,<text>`. Deliberately vague: the
// reason is for the operator, not for the peer.
reject_client_text :: proc "contextless" (r: Reject) -> string {
	if r.kind == .Auth_Failed_Temp {
		return "server busy, try again later"
	}
	return "authentication failed"
}
