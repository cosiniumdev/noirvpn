// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:strings"
import "core:time"
import "core:unicode/utf8"
import "noir:bus"
import "noir:proto/config"
import "noir:server"

// The pure part of the bus glue: JSON of events and results, maps from daemon
// reasons to bus words, and small text rules. Nothing here touches the daemon,
// so tests can build and read every JSON model.

// ------------------------------------------------------------------- texts

// The instance name from `--name`: characters outside [A-Za-z0-9._-] become
// '_', at most 40 characters, "" gives the default.
clean_instance_name :: proc(name: string, allocator := context.allocator) -> string {
	if name == "" {
		return strings.clone(bus.DEFAULT_NAME, allocator)
	}
	n := min(len(name), 40)
	out := make([]u8, n, allocator)
	for i in 0 ..< n {
		switch c := name[i]; c {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '-', '_':
			out[i] = c
		case:
			out[i] = '_'
		}
	}
	return string(out)
}

// `sha256:` and 64 lower case hex digits. `buf` holds the text.
pin_text_hex :: proc(spki: [32]u8, buf: ^[71]u8) -> string {
	HEX := "0123456789abcdef"
	copy(buf[:7], "sha256:")
	for b, i in spki {
		buf[7 + 2 * i] = HEX[b >> 4]
		buf[7 + 2 * i + 1] = HEX[b & 15]
	}
	return string(buf[:])
}

ts_text :: proc(t: time.Time, buf: ^[24]u8) -> string {
	return bus.format_ts(t, buf)
}

// ------------------------------------------------------------- peer object

// The facts of one session, as plain values. `write_peer` turns it into the
// peer object of the bus protocol.
Peer_View :: struct {
	session:      string,
	peer_id:      Maybe(u32),
	name:         string,
	has_name:     bool,
	// Where the name came from: "pin", "certificate", "username" or "controller".
	name_from:    string,
	pin:          [32]u8,
	has_pin:      bool,
	state:        string,
	real_addr:    string,
	proto:        string,
	backend:      string, // "kernel", "service" or "daemon": who runs the data channel of the peer
	vpn4:         Maybe([4]u8),
	vpn6:         Maybe([16]u8),
	cipher:       string,
	data_format:  string, // "baseline" or "epoch"; empty before the session is active
	connected_at: Maybe(time.Time),
	bytes_in:     u64,
	bytes_out:    u64,
	packets_in:   u64,
	packets_out:  u64,
	// The proofs the daemon checked to let the client in (`pin`, `chain`, `password`).
	proofs:       server.Proof_Set,
}

// The identity fields shared by several events: `name` and `pin` (null when
// not known).
write_who :: proc(w: ^bus.Writer, name: string, has_name: bool, pin: [32]u8, has_pin: bool) {
	bus.kv_str_or_null(w, "name", name, has_name)
	if has_pin {
		buf: [71]u8
		bus.kv_str(w, "pin", pin_text_hex(pin, &buf))
	} else {
		bus.kv_null(w, "pin")
	}
}

// Writes the fields of the peer object into the open object `w`. All keys are
// always there.
write_peer_fields :: proc(w: ^bus.Writer, v: ^Peer_View) {
	bus.kv_str(w, "session", v.session)
	if id, ok := v.peer_id.?; ok {
		bus.kv_u64(w, "peer_id", u64(id))
	} else {
		bus.kv_null(w, "peer_id")
	}
	write_who(w, v.name, v.has_name, v.pin, v.has_pin)
	bus.kv_str_or_null(w, "identity_source", v.name_from, v.has_name && v.name_from != "")
	bus.kv_str(w, "state", v.state)
	bus.kv_str(w, "real_addr", v.real_addr)
	bus.kv_str(w, "proto", v.proto)
	bus.kv_str(w, "backend", v.backend if v.backend != "" else "daemon")
	if a, ok := v.vpn4.?; ok {
		bus.kv_str(w, "vpn4", ip4_str(a))
	} else {
		bus.kv_null(w, "vpn4")
	}
	if a, ok := v.vpn6.?; ok {
		bus.kv_str(w, "vpn6", ip6_str(a))
	} else {
		bus.kv_null(w, "vpn6")
	}
	bus.kv_str_or_null(w, "cipher", v.cipher, v.cipher != "")
	bus.kv_str_or_null(w, "data_format", v.data_format, v.data_format != "")
	if t, ok := v.connected_at.?; ok {
		buf: [24]u8
		bus.kv_str(w, "connected_at", ts_text(t, &buf))
	} else {
		bus.kv_null(w, "connected_at")
	}
	bus.kv_u64(w, "bytes_in", v.bytes_in)
	bus.kv_u64(w, "bytes_out", v.bytes_out)
	bus.kv_u64(w, "packets_in", v.packets_in)
	bus.kv_u64(w, "packets_out", v.packets_out)
	write_proofs(w, v.proofs)
}

// `proofs`: the checks the daemon ran on the client. An empty array means the
// daemon checked nothing (a controller decides alone).
write_proofs :: proc(w: ^bus.Writer, p: server.Proof_Set) {
	bus.kv_arr(w, "proofs")
	for proof in server.Proof {
		if proof in p {
			switch proof {
			case .Pin:
				bus.val_str(w, "pin")
			case .Chain:
				bus.val_str(w, "chain")
			case .Password:
				bus.val_str(w, "password")
			case .Token:
				bus.val_str(w, "token")
			}
		}
	}
	bus.end(w)
}

// The word for `identity_source`: where the name of a session came from.
identity_source_text :: proc "contextless" (s: server.Identity_Source) -> string {
	switch s {
	case .Pin:
		return "pin"
	case .Cert_Name:
		return "certificate"
	case .Username:
		return "username"
	case .Controller:
		return "controller"
	case .None:
	}
	return ""
}

write_peer :: proc(w: ^bus.Writer, v: ^Peer_View) {
	bus.begin_obj(w)
	write_peer_fields(w, v)
	bus.end(w)
}

// ------------------------------------------------------------------ reasons

// `auth.fail` `reason` for a refusal. Reasons the bus document does not list
// (address taken, broken per-user file, ...) become `assignment_failed`;
// `detail` says which.
auth_fail_reason :: proc "contextless" (r: server.Reject_Reason) -> string {
	#partial switch r {
	case .Key_Not_Pinned:
		return "unknown_key"
	case .Key_Disabled, .Client_Disabled, .Ccd_Required:
		return "key_disabled"
	case .Username_Mismatch:
		return "name_mismatch"
	case .No_Identity, .Bad_Identity, .Chain_Not_Verified:
		return "bad_certificate"
	case .Max_Clients, .Id_Exhausted:
		return "max_clients"
	case .Rate_Limited:
		return "rate_limit"
	case .Password_Missing:
		return "password_missing"
	case .Password_Failed:
		return "password_failed"
	case .Password_Busy:
		return "password_busy"
	case .External_Denied:
		return "external_denied"
	case .External_Timeout:
		return "external_timeout"
	case .Token_Invalid:
		return "token_invalid"
	}
	return "assignment_failed"
}

// The `detail` of an `auth.fail`: the caller's text, else the plain text of the
// reason when the event word alone is not enough (`assignment_failed`).
// "" means null.
auth_fail_detail :: proc(r: server.Reject_Reason, detail: string) -> string {
	if detail != "" {
		return detail
	}
	if auth_fail_reason(r) == "assignment_failed" {
		return server.reject_text(r)
	}
	return ""
}

// "s-17" to 17. The session ids of the server are `s-` and a decimal number.
parse_session :: proc "contextless" (s: string) -> (n: u64, ok: bool) {
	if len(s) < 3 || len(s) > 22 || s[0] != 's' || s[1] != '-' {
		return 0, false
	}
	for c in transmute([]u8)s[2:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		next := n * 10 + u64(c - '0')
		if next / 10 != n {
			return 0, false
		}
		n = next
	}
	return n, true
}

// ------------------------------------------------------------ auth.fail data

// The data of an `auth.fail` event.
Auth_Fail_View :: struct {
	session:   string,
	has_sess:  bool,
	name:      string,
	has_name:  bool,
	pin:       [32]u8,
	has_pin:   bool,
	real_addr: string,
	proto:     string,
	reason:    string,
	detail:    string,
	has_detail: bool,
}

// Writes the fields of an `auth.fail` into the open object `w`.
write_auth_fail :: proc(w: ^bus.Writer, v: ^Auth_Fail_View) {
	bus.kv_str_or_null(w, "session", v.session, v.has_sess)
	write_who(w, v.name, v.has_name, v.pin, v.has_pin)
	bus.kv_str(w, "real_addr", v.real_addr)
	bus.kv_str(w, "proto", v.proto)
	bus.kv_str(w, "reason", v.reason)
	bus.kv_str_or_null(w, "detail", v.detail, v.has_detail)
}

// ------------------------------------------------------------- peer-info

PEER_INFO_MAX_KEYS :: 64
PEER_INFO_MAX_VALUE :: 256

// The `peer_info` object of `peer.auth_pending`: the `IV_*` and `UV_*` lines the
// client sent, as strings. At most 64 keys, values cut at 256 bytes. A key whose
// name suggests a secret is left out (a client can put anything in a `UV_`
// variable). `text` is the peer-info block: lines `KEY=value`.
write_peer_info :: proc(w: ^bus.Writer, text: string) {
	bus.begin_obj(w)
	n := 0
	rest := text
	for len(rest) > 0 && n < PEER_INFO_MAX_KEYS {
		line: string
		if i := strings.index_byte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i + 1:]
		} else {
			line, rest = rest, ""
		}
		line = strings.trim_right(line, "\r")
		eq := strings.index_byte(line, '=')
		if eq <= 0 {
			continue
		}
		key, value := line[:eq], line[eq + 1:]
		if !(strings.has_prefix(key, "IV_") || strings.has_prefix(key, "UV_")) || !peer_info_key_ok(key) {
			continue
		}
		if len(value) > PEER_INFO_MAX_VALUE {
			value = value[:PEER_INFO_MAX_VALUE]
		}
		bus.kv_str(w, key, value)
		n += 1
	}
	bus.end(w)
}

@(private = "file")
peer_info_key_ok :: proc(key: string) -> bool {
	if len(key) > 64 {
		return false
	}
	for c in transmute([]u8)key {
		switch c {
		case 'A' ..= 'Z', 'a' ..= 'z', '0' ..= '9', '_', '-', '.':
		case:
			return false
		}
	}
	upper := strings.to_upper(key, context.temp_allocator)
	for bad in ([]string{"PASS", "TOKEN", "SECRET", "KEY", "CRED"}) {
		if strings.contains(upper, bad) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- reasons

DENY_REASON_MAX :: 128

// Text for `auth.decide` `deny` and the `reason` of `peer.kick`: control
// characters removed, at most 128 characters. `ok` is false when it is longer
// (the request is then `bad_request`). The result is on the temp allocator.
clean_reason :: proc(s: string) -> (text: string, ok: bool) {
	if utf8.rune_count_in_string(s) > DENY_REASON_MAX {
		return "", false
	}
	sb := strings.builder_make(context.temp_allocator)
	for r in s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			continue
		}
		strings.write_rune(&sb, r)
	}
	return strings.to_string(sb), true
}

// Selectors of `peer.kick`: exactly one of `session`, `peer_id`, `name`,
// `serial`, `pin`; `name` may also go with `serial` or `pin` as an extra condition.
kick_selectors_ok :: proc "contextless" (session, peer_id, name, serial: bool, pin := false) -> bool {
	if serial {
		return !session && !peer_id && !pin
	}
	if pin {
		return !session && !peer_id
	}
	return int(session) + int(peer_id) + int(name) == 1
}

// Reads a key pin for `peer.kick`, with prefix `sha256:` or `mldsa65-sha256:`
// (the peers file has both). Two forms:
//   - 64 hex digits, any case: what the `pin` field of a peer object shows. That
//     field always has `sha256:` and the SHA-256 of the key, also for a key the
//     peers file pins as `mldsa65-sha256:`.
//   - base64 of the 32 byte hash, as in the peers file.
pin_parse :: proc(text: string) -> (spki: [32]u8, ok: bool) {
	rest: string
	switch {
	case strings.has_prefix(text, "sha256:"):
		rest = text[len("sha256:"):]
	case strings.has_prefix(text, "mldsa65-sha256:"):
		rest = text[len("mldsa65-sha256:"):]
	case:
		return {}, false
	}
	if len(rest) == 64 {
		nibble :: proc "contextless" (c: u8) -> (v: u8, ok: bool) {
			switch c {
			case '0' ..= '9':
				return c - '0', true
			case 'a' ..= 'f':
				return c - 'a' + 10, true
			case 'A' ..= 'F':
				return c - 'A' + 10, true
			}
			return 0, false
		}
		for i in 0 ..< 32 {
			hi, ok1 := nibble(rest[2 * i])
			lo, ok2 := nibble(rest[2 * i + 1])
			if !ok1 || !ok2 {
				return {}, false
			}
			spki[i] = hi << 4 | lo
		}
		return spki, true
	}
	buf: [64]u8
	n, good := config.base64_decode(rest, buf[:])
	if !good || n != 32 {
		return {}, false
	}
	copy(spki[:], buf[:32])
	return spki, true
}
