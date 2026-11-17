// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

// The options string inside the key-method message:
// `V4,dev-type tun,link-mtu 1549,...,key-method 2,tls-client`.
//
// No function in TLS mode. A stock peer compares it with its expected string and
// only logs a difference. noirvpn builds it for the peer's log, and parses the
// peer's for logging and the announced cipher.

DEFAULT_TUN_MTU :: 1500

Options_Params :: struct {
	// Who writes the string. Gives `tls-client` or `tls-server`, and
	// `TCPv4_CLIENT` or `TCPv4_SERVER`.
	role:      Role,
	transport: Transport,
	// 0 means 1500.
	tun_mtu:   int,
	// The data cipher. `.None` writes the legacy form with no `cipher` item
	// (`auth SHA1,keysize 128`); noirvpn does not send that.
	cipher:    Cipher,
	// 0 means `options_link_mtu(...)`.
	link_mtu:  int,
}

// The `link-mtu` number a stock peer prints. No function:
// a wrong value costs only a log line at the peer.
//
// Observed with tun-mtu 1500: AES-GCM +49, CHACHA20-POLY1305 +34, no cipher
// item +41, and 2 more on TCP.
//
// SPEC-GAP: only tun-mtu 1500 was captured, so the sum for other values is an
// assumption. The no-cipher form was captured on UDP only; +2 for TCP is a
// guess.
options_link_mtu :: proc "contextless" (tun_mtu: int, cipher: Cipher, transport: Transport) -> int {
	extra: int
	switch cipher {
	case .Aes_128_Gcm, .Aes_256_Gcm:
		extra = 49
	case .Chacha20_Poly1305:
		extra = 34
	case .None:
		extra = 41
	}
	if transport == .Tcp {
		extra += 2
	}
	return tun_mtu + extra
}

// Writes the options string (no NUL) and returns it as a slice of `buf`.
// The text is under 512 bytes with its NUL, which is the stock limit.
options_build :: proc(buf: []u8, p: ^Options_Params) -> (s: string, err: Error) {
	tun_mtu := p.tun_mtu if p.tun_mtu > 0 else DEFAULT_TUN_MTU
	link_mtu := p.link_mtu if p.link_mtu > 0 else options_link_mtu(tun_mtu, p.cipher, p.transport)
	w := Wr{buf = buf}
	wr_str(&w, "V4,dev-type tun,link-mtu ")
	wr_uint(&w, u64(link_mtu))
	wr_str(&w, ",tun-mtu ")
	wr_uint(&w, u64(tun_mtu))
	wr_str(&w, ",proto ")
	switch {
	case p.transport == .Udp:
		wr_str(&w, "UDPv4")
	case p.role == .Client:
		wr_str(&w, "TCPv4_CLIENT")
	case:
		wr_str(&w, "TCPv4_SERVER")
	}
	if p.cipher != .None {
		wr_str(&w, ",cipher ")
		wr_str(&w, cipher_name(p.cipher))
		wr_str(&w, ",auth [null-digest],keysize ")
		wr_uint(&w, u64(cipher_key_bits(p.cipher)))
	} else {
		wr_str(&w, ",auth SHA1,keysize 128")
	}
	wr_str(&w, ",key-method 2,")
	wr_str(&w, "tls-client" if p.role == .Client else "tls-server")
	if w.over {
		return "", .Buffer_Too_Small
	}
	if w.n + 1 > OPTIONS_MAX_LEN {
		return "", .Oversize
	}
	return string(buf[:w.n]), .None
}

// The items of a peer's options string that noirvpn looks at. Strings are
// slices of the parsed text.
Options_Info :: struct {
	// First item, for example `V4`.
	version:      string,
	dev_type:     string,
	link_mtu:     Maybe(int),
	tun_mtu:      Maybe(int),
	proto:        string,
	// The cipher the peer announces. `[null-cipher]` is mapped to `none`.
	// Empty if the string has no `cipher` item.
	cipher:       string,
	auth:         string,
	keysize:      Maybe(int),
	keydir:       Maybe(int),
	tls_auth:     bool,
	key_method:   Maybe(int),
	// From `tls-client` / `tls-server`.
	role:         Maybe(Role),
	// The peer is set up for compression framing (`comp-lzo`).
	comp_lzo:     bool,
	item_count:   int,
	// Items this parser does not know.
	unknown_count: int,
}

// Splits and reads the options string. Never allocates. An empty string is
// accepted and gives an empty `Options_Info`. A string of 512 bytes or more
// (with the NUL) gives `.Oversize`, as it fails the read at a stock peer.
options_parse :: proc(s: string, info: ^Options_Info) -> Error {
	info^ = {}
	if len(s) + 1 > OPTIONS_MAX_LEN {
		return .Oversize
	}
	rest := s
	first := true
	for len(rest) > 0 {
		comma := -1
		for c, i in transmute([]u8)rest {
			if c == ',' {
				comma = i
				break
			}
		}
		item: string
		if comma < 0 {
			item, rest = rest, ""
		} else {
			item, rest = rest[:comma], rest[comma + 1:]
		}
		if len(item) == 0 {
			continue
		}
		info.item_count += 1
		if first {
			first = false
			info.version = item
			continue
		}
		name, value := item, ""
		for c, i in transmute([]u8)item {
			if c == ' ' {
				name, value = item[:i], item[i + 1:]
				break
			}
		}
		switch name {
		case "dev-type":
			info.dev_type = value
		case "link-mtu":
			if v, ok := scan_uint_prefix(value); ok && v <= 0x7FFFFFFF {
				info.link_mtu = int(v)
			}
		case "tun-mtu":
			if v, ok := scan_uint_prefix(value); ok && v <= 0x7FFFFFFF {
				info.tun_mtu = int(v)
			}
		case "proto":
			info.proto = value
		case "cipher":
			info.cipher = "none" if value == "[null-cipher]" else value
		case "auth":
			info.auth = value
		case "keysize":
			if v, ok := scan_uint_prefix(value); ok && v <= 0x7FFFFFFF {
				info.keysize = int(v)
			}
		case "keydir":
			if v, ok := scan_uint_prefix(value); ok && v <= 1 {
				info.keydir = int(v)
			}
		case "tls-auth":
			info.tls_auth = true
		case "key-method":
			if v, ok := scan_uint_prefix(value); ok && v <= 0x7FFFFFFF {
				info.key_method = int(v)
			}
		case "tls-client":
			info.role = .Client
		case "tls-server":
			info.role = .Server
		case "comp-lzo":
			info.comp_lzo = true
		case "tun-ipv6", "mtu-dynamic", "ifconfig":
		// Known to exist, ignored.
		case:
			info.unknown_count += 1
		}
	}
	return .None
}

Options_Diff :: enum u8 {
	Version,
	Dev_Type,
	Link_Mtu,
	Tun_Mtu,
	Auth,
	Keysize,
	Comp_Lzo,
}

Options_Diffs :: bit_set[Options_Diff;u8]

options_diff_name :: proc "contextless" (d: Options_Diff) -> string {
	switch d {
	case .Version:
		return "version tag"
	case .Dev_Type:
		return "dev-type"
	case .Link_Mtu:
		return "link-mtu"
	case .Tun_Mtu:
		return "tun-mtu"
	case .Auth:
		return "auth"
	case .Keysize:
		return "keysize"
	case .Comp_Lzo:
		return "comp-lzo"
	}
	return "?"
}

// Items that differ between what we would send (`local`) and what the peer sent
// (`remote`), for a log warning. A difference never fails the connection. Like
// a stock peer it ignores key-method, keydir, proto, tls-auth, tun-ipv6, cipher.
options_compare :: proc(local, remote: ^Options_Info) -> (d: Options_Diffs) {
	if local.version != remote.version {
		d += {.Version}
	}
	if local.dev_type != remote.dev_type {
		d += {.Dev_Type}
	}
	if local.link_mtu != remote.link_mtu {
		d += {.Link_Mtu}
	}
	if local.tun_mtu != remote.tun_mtu {
		d += {.Tun_Mtu}
	}
	if local.auth != remote.auth {
		d += {.Auth}
	}
	if local.keysize != remote.keysize {
		d += {.Keysize}
	}
	if local.comp_lzo != remote.comp_lzo {
		d += {.Comp_Lzo}
	}
	return
}
