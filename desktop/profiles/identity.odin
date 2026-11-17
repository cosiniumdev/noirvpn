// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// A new key and certificate request of a profile, and the key pin as the line
// of the peers file.
//
//	peers_line_name(common_name, allocator) -> string   the NAME field of the peers file
//	peers_line(common_name, pin, allocator) -> string   "<name> <pin>", "" with no pin
//	common_name_valid(s) -> bool                         1 to 64 bytes of UTF-8, no control characters
//	request_file_name(common_name, allocator) -> string  "<name>.csr" for the save dialog
//
// The store keeps a request in the folder of its profile (store.odin):
// `request.key` (the new private key, mode 0600, never shown) and
// `request.json` (the request, the pin, the common name, the key type and the
// time; all public).
package profiles

import "core:strings"
import "core:unicode"
import "core:unicode/utf8"

// The longest NAME field of the peers file.
PEERS_NAME_MAX :: 255
// A certificate file is small; a larger file is not read.
CERT_FILE_MAX :: 1024 * 1024

// Key types of a new request, as `request.json` names them.
KEY_P256 :: "p256"

// A request that waits for its certificate (`request.json`). It is public.
Request :: struct {
	csr:         string `json:"csr"`,
	pin:         string `json:"pin"`,
	common_name: string `json:"common_name"`,
	// "ed25519", "p256" or "mldsa65".
	key_type:    string `json:"key_type"`,
	// Unix seconds.
	created:     i64 `json:"created"`,
}

request_destroy :: proc(r: ^Request, allocator := context.allocator) {
	delete(r.csr, allocator)
	delete(r.pin, allocator)
	delete(r.common_name, allocator)
	delete(r.key_type, allocator)
	r^ = {}
}

// NAME field of the peers file of a noirvpn server (docs/server.md): each run
// of white space or control characters, each `/` and `\`,
// and a leading `#` become `_`. Cut to 255 bytes on a character boundary;
// "client" if nothing is left (or "." or "..").
peers_line_name :: proc(common_name: string, allocator := context.allocator) -> string {
	sb := strings.builder_make(context.temp_allocator)
	in_run := false
	for r in common_name {
		if unicode.is_white_space(r) || r < 0x20 || (r >= 0x7f && r < 0xa0) {
			if !in_run {
				strings.write_byte(&sb, '_')
			}
			in_run = true
			continue
		}
		in_run = false
		strings.write_rune(&sb, '_' if r == '/' || r == '\\' else r)
	}
	out := strings.to_string(sb)
	if strings.has_prefix(out, "#") {
		out = strings.concatenate({"_", out[1:]}, context.temp_allocator)
	}
	if len(out) > PEERS_NAME_MAX {
		cut := PEERS_NAME_MAX
		for cut > 0 && !utf8.rune_start(out[cut]) {
			cut -= 1
		}
		out = out[:cut]
	}
	if out == "" || out == "." || out == ".." {
		out = "client"
	}
	return strings.clone(out, allocator)
}

// The line of the peers file: `<name> <pin>`; "" when there is no pin.
peers_line :: proc(common_name, pin: string, allocator := context.allocator) -> string {
	if pin == "" {
		return ""
	}
	return strings.concatenate({peers_line_name(common_name, context.temp_allocator), " ", pin}, allocator)
}

// The common name of a new request: 1 to 64 bytes of UTF-8 with no control
// characters, after the spaces at both ends are taken off.
common_name_valid :: proc(s: string) -> bool {
	t := strings.trim_space(s)
	if len(t) == 0 || len(t) > NAME_MAX || !utf8.valid_string(t) {
		return false
	}
	for r in t {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return false
		}
	}
	return true
}

// Name of a saved request file: letters, digits, dot, hyphen, underscore of the
// common name (others become `_`), no leading dot, at most 64 characters, then
// ".csr". "request.csr" if nothing is left.
request_file_name :: proc(common_name: string, allocator := context.allocator) -> string {
	sb := strings.builder_make(context.temp_allocator)
	n := 0
	for r in common_name {
		if n == NAME_MAX {
			break
		}
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		strings.write_byte(&sb, u8(r) if ok else '_')
		n += 1
	}
	s := strings.trim_left(strings.to_string(sb), ".")
	if strings.trim(s, "_") == "" {
		s = "request"
	}
	return strings.concatenate({s, ".csr"}, allocator)
}
