// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:fmt"
import "core:mem"
import "core:strings"

// The peers file, one key per line:
//
//   # <username>  <pin>                     [options]
//   alice         sha256:3q2+7w...=         ifconfig-push=10.8.0.10
//   alice         sha256:9aBc...=           # second device
//   bob           mldsa65-sha256:Zm9v...=   iroute=192.168.10.0/24
//   carol         sha256:Qk1...=            disabled
//
// Fields are separated by spaces or tabs. A `#` at the start of a field starts a
// comment to the end of the line. A user may have several lines. Options:
//
//   ifconfig-push=ADDR            fixed tunnel IPv4 address
//   ifconfig-ipv6-push=ADDR/BITS  fixed tunnel IPv6 address
//   iroute=NET/LEN                subnet behind the client (repeatable)
//   iroute-ipv6=NET/BITS          IPv6 subnet behind the client (repeatable)
//   disabled                      the key is known but refused

// What a pin is a hash of.
Pin_Kind :: enum u8 {
	// SHA-256 of the SubjectPublicKeyInfo.
	Sha256,
	// SHA-256 of an ML-DSA-65 SubjectPublicKeyInfo.
	Mldsa65_Sha256,
}

PIN_LEN :: 32

Pin :: struct {
	kind:   Pin_Kind,
	digest: [PIN_LEN]u8,
}

Peer_Entry :: struct {
	user:     string,
	pin:      Pin,
	// 1-based line in the peers file.
	line:     int,
	disabled: bool,
	// ifconfig-push, iroutes, ...
	client:   Client_Specific,
}

// A parsed peers file with a lookup by pin.
Peers :: struct {
	// In file order.
	entries: []Peer_Entry,
	// Pin -> index into `entries`.
	by_pin:  map[Pin]int,
	// User name in ASCII lower case -> indexes into `entries`, in file order.
	by_user: map[string][]int,
	diags:   []Diagnostic,
	store:   ^Store,
}

// Parses peers file text. The text is copied. `name` is used in diagnostics.
peers_parse :: proc(text: string, name := "<peers>", allocator := context.allocator) -> Peers {
	store := store_new(allocator)
	a := store_allocator(store)
	return peers_parse_in(store, strings.clone(text, a), strings.clone(name, a))
}

// Reads and parses a peers file. Uses `opts.loader` (default: the OS) and the
// size and line limits of `opts`.
peers_parse_file :: proc(
	path: string,
	opts := Parse_Options{},
	allocator := context.allocator,
) -> Peers {
	store := store_new(allocator)
	a := store_allocator(store)
	loader := opts.loader
	if loader == nil {
		loader = default_loader
	}
	max_file := opts.max_file if opts.max_file > 0 else DEFAULT_MAX_FILE
	file := strings.clone(path, a)
	data: []u8
	ok := false
	if loader != nil {
		data, ok = loader(opts.loader_data, path, a)
	}
	if !ok || len(data) > max_file {
		msg := "cannot read the peers file" if !ok else "the peers file is too large"
		diags := make([]Diagnostic, 1, a)
		diags[0] = Diagnostic{.Error, file, 0, fmt.aprintf("%s '%s'", msg, path, allocator = a)}
		return Peers{diags = diags, store = store}
	}
	return peers_parse_in(store, string(data), file)
}

peers_destroy :: proc(p: ^Peers) {
	store_free(p.store)
	p^ = {}
}

peers_ok :: proc(p: ^Peers) -> bool {
	return !diags_have_error(p.diags)
}

// Finds the entry for a pin. A `disabled` entry is returned too; the caller
// decides what to do with it.
peers_lookup :: proc(p: ^Peers, pin: Pin) -> (e: ^Peer_Entry, found: bool) {
	i, ok := p.by_pin[pin]
	if !ok {
		return nil, false
	}
	return &p.entries[i], true
}

// Indexes (into `entries`) of all keys of a user. The user name is compared
// ignoring ASCII case.
peers_user_entries :: proc(p: ^Peers, user: string) -> []int {
	buf: [256]u8
	if len(user) > len(buf) {
		return nil
	}
	return p.by_user[ascii_lower_into(buf[:], user)]
}

// `s` in ASCII lower case, written into `buf` (which must be as long as `s`).
@(private)
ascii_lower_into :: proc(buf: []u8, s: string) -> string {
	for i in 0 ..< len(s) {
		c := s[i]
		buf[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}
	return string(buf[:len(s)])
}

@(private)
peers_parse_in :: proc(store: ^Store, text: string, file: string) -> Peers {
	a := store_allocator(store)
	diags := make([dynamic]Diagnostic, a)
	entries := make([dynamic]Peer_Entry, a)
	by_pin := make(map[Pin]int, 16, a)
	text := text
	if strings.has_prefix(text, "\xef\xbb\xbf") {
		text = text[3:]
	}
	toks := make([dynamic]string, store.backing)
	defer delete(toks)

	pos, lineno := 0, 0
	for pos < len(text) {
		line := next_line(text, &pos)
		lineno += 1
		err :: proc(
			diags: ^[dynamic]Diagnostic,
			a: mem.Allocator,
			file: string,
			ln: int,
			format: string,
			args: ..any,
		) {
			append(diags, Diagnostic{.Error, file, ln, fmt.aprintf(format, ..args, allocator = a)})
		}
		if len(line) > DEFAULT_MAX_LINE {
			err(&diags, a, file, lineno, "the line is too long (limit %d bytes)", DEFAULT_MAX_LINE)
			continue
		}
		if strings.index_byte(line, 0) >= 0 {
			err(&diags, a, file, lineno, "the line contains a NUL byte")
			continue
		}
		// Fields up to a comment.
		clear(&toks)
		i := 0
		for i < len(line) {
			for i < len(line) && is_space(line[i]) {
				i += 1
			}
			if i >= len(line) || line[i] == '#' {
				break
			}
			start := i
			for i < len(line) && !is_space(line[i]) {
				i += 1
			}
			append(&toks, line[start:i])
		}
		if len(toks) == 0 {
			continue
		}
		if len(toks) < 2 {
			err(
				&diags,
				a,
				file,
				lineno,
				"expected `<username> <pin> [options]`, but the line only has '%s'",
				toks[0],
			)
			continue
		}
		user := toks[0]
		if msg := check_username(user); msg != "" {
			err(&diags, a, file, lineno, "username '%s' is not valid: %s", user, msg)
			continue
		}
		pin, msg := parse_pin(toks[1], a)
		if msg != "" {
			err(&diags, a, file, lineno, "%s", msg)
			continue
		}
		e := Peer_Entry {
			user = user,
			pin  = pin,
			line = lineno,
		}
		if prev, dup := by_pin[pin]; dup {
			err(
				&diags,
				a,
				file,
				lineno,
				"this pin is already used for '%s' on line %d",
				entries[prev].user,
				entries[prev].line,
			)
			continue
		}
		iroutes := make([dynamic]Iroute, a)
		iroutes6 := make([dynamic]Iroute6, a)
		bad := false
		for opt in toks[2:] {
			if !parse_peer_option(&e, &iroutes, &iroutes6, opt, &diags, a, file, lineno) {
				bad = true
			}
		}
		if bad {
			continue
		}
		e.client.iroutes = iroutes[:]
		e.client.iroutes6 = iroutes6[:]
		by_pin[pin] = len(entries)
		append(&entries, e)
	}

	// Per-user index.
	tmp := make(map[string][dynamic]int, 16, a)
	for e, i in entries {
		key_buf: [256]u8
		key := ascii_lower_into(key_buf[:], e.user)
		l, ok := tmp[key]
		if !ok {
			l = make([dynamic]int, a)
		}
		append(&l, i)
		if ok {
			tmp[key] = l
		} else {
			tmp[strings.clone(key, a)] = l
		}
	}
	by_user := make(map[string][]int, len(tmp), a)
	for k, v in tmp {
		by_user[k] = v[:]
	}
	return Peers {
		entries = entries[:],
		by_pin = by_pin,
		by_user = by_user,
		diags = diags[:],
		store = store,
	}
}

// Usernames are file names in client-config-dir and appear in logs, so keep
// them plain: printable, no path characters.
@(private)
check_username :: proc(s: string) -> string {
	if len(s) > 255 {
		return "it is longer than 255 bytes"
	}
	if s == "." || s == ".." {
		return "this name is reserved"
	}
	for ch in transmute([]u8)s {
		if ch < 0x20 || ch == 0x7f {
			return "it contains a control character"
		}
		if ch == '/' || ch == '\\' {
			return "it contains a path separator"
		}
	}
	return ""
}

// Parses `sha256:<base64>` or `mldsa65-sha256:<base64>`. On failure the
// message is allocated with `allocator`.
@(private)
parse_pin :: proc(s: string, allocator: mem.Allocator) -> (pin: Pin, msg: string) {
	colon := strings.index_byte(s, ':')
	if colon < 0 {
		return {}, fmt.aprintf("'%s' is not a valid pin; use the form sha256:<base64> or mldsa65-sha256:<base64>", s, allocator = allocator)
	}
	switch s[:colon] {
	case "sha256":
		pin.kind = .Sha256
	case "mldsa65-sha256":
		pin.kind = .Mldsa65_Sha256
	case:
		return {}, fmt.aprintf("unknown pin type '%s'; use sha256 or mldsa65-sha256", s[:colon], allocator = allocator)
	}
	buf: [64]u8
	n, ok := base64_decode(s[colon + 1:], buf[:])
	if !ok {
		return {}, fmt.aprintf("the pin '%s' is not a valid base64 encoding of a 32-byte hash", s, allocator = allocator)
	}
	if n != PIN_LEN {
		return {}, fmt.aprintf("the pin '%s' decodes to %d bytes, but a pin must be a %d-byte SHA-256 hash", s, n, PIN_LEN, allocator = allocator)
	}
	copy(pin.digest[:], buf[:PIN_LEN])
	return pin, ""
}

// Applies one `name` or `name=value` option to an entry. Returns false (after
// adding a diagnostic) if it is bad.
@(private)
parse_peer_option :: proc(
	e: ^Peer_Entry,
	iroutes: ^[dynamic]Iroute,
	iroutes6: ^[dynamic]Iroute6,
	opt: string,
	diags: ^[dynamic]Diagnostic,
	a: mem.Allocator,
	file: string,
	ln: int,
) -> bool {
	fail :: proc(
		diags: ^[dynamic]Diagnostic,
		a: mem.Allocator,
		file: string,
		ln: int,
		format: string,
		args: ..any,
	) -> bool {
		append(diags, Diagnostic{.Error, file, ln, fmt.aprintf(format, ..args, allocator = a)})
		return false
	}
	name, value := opt, ""
	has_value := false
	if eq := strings.index_byte(opt, '='); eq >= 0 {
		name, value, has_value = opt[:eq], opt[eq + 1:], true
	}
	switch name {
	case "disabled":
		if has_value {
			return fail(diags, a, file, ln, "option 'disabled' does not accept a value")
		}
		e.disabled = true
		e.client.disable = true
	case "ifconfig-push":
		if e.client.ifconfig_push != nil {
			return fail(diags, a, file, ln, "option 'ifconfig-push' is given twice")
		}
		ip, ok := ipv4_parse(value)
		if !has_value || !ok {
			return fail(
				diags,
				a,
				file,
				ln,
				"option 'ifconfig-push' needs an IPv4 address, for example ifconfig-push=10.8.0.10",
			)
		}
		e.client.ifconfig_push = Ifconfig_Push {
			local       = value,
			local_ip    = ip,
			local_is_ip = true,
		}
	case "ifconfig-ipv6-push":
		if e.client.ifconfig_ipv6_push != nil {
			return fail(diags, a, file, ln, "option 'ifconfig-ipv6-push' is given twice")
		}
		addr, bits, ok := ipv6_parse_cidr(value)
		if !has_value || !ok {
			return fail(
				diags,
				a,
				file,
				ln,
				"option 'ifconfig-ipv6-push' needs addr/bits, for example ifconfig-ipv6-push=fd00::10/64",
			)
		}
		e.client.ifconfig_ipv6_push = Ifconfig6_Push {
			addr = addr,
			bits = u8(bits),
		}
	case "iroute":
		net, prefix, ok := ipv4_parse_cidr(value)
		if !has_value || !ok {
			return fail(
				diags,
				a,
				file,
				ln,
				"option 'iroute' needs net/len, for example iroute=192.168.10.0/24",
			)
		}
		if ipv4_to_u32(net) & ~ipv4_to_u32(ipv4_prefix_mask(prefix)) != 0 {
			return fail(diags, a, file, ln, "iroute '%s' has host bits set", value)
		}
		append(iroutes, Iroute{net, u8(prefix)})
	case "iroute-ipv6":
		net, bits, ok := ipv6_parse_cidr(value)
		if !has_value || !ok {
			return fail(
				diags,
				a,
				file,
				ln,
				"option 'iroute-ipv6' needs net/bits, for example iroute-ipv6=fd00:1::/64",
			)
		}
		if !ipv6_host_part_is_zero(net, bits) {
			return fail(diags, a, file, ln, "iroute-ipv6 '%s' has host bits set", value)
		}
		append(iroutes6, Iroute6{net, u8(bits)})
	case:
		return fail(
			diags,
			a,
			file,
			ln,
			"unknown option '%s'; the known options are ifconfig-push, ifconfig-ipv6-push, iroute, iroute-ipv6 and disabled",
			name,
		)
	}
	return true
}
