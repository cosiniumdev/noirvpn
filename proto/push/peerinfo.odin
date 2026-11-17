// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

// Peer-info: the `NAME=value\n` lines at the end of the key-method message
//, and the IV_PROTO bit field (6.5).

// IV_PROTO bits. The value of a member is the bit number; bit 0 is
// deliberately unused (old peers read the field as a number and test >= 2).
Iv_Proto_Bit :: enum u32 {
	Data_V2         = 1, // P_DATA_V2 with peer-id
	Request_Push    = 2, // server may send PUSH_REPLY without a PUSH_REQUEST
	Tls_Key_Export  = 3, // data keys from the TLS exporter
	Auth_Pending_Kw = 4, // `AUTH_PENDING,timeout N` keyword form
	Ncp_P2p         = 5, // static p2p cipher negotiation (not used by noirvpn)
	Dns_Option      = 6, // old `dns` push form (2.6.23 sends this)
	Cc_Exit_Notify  = 7, // EXIT over the control channel, and `protocol-flags`
	Auth_Fail_Temp  = 8, // `AUTH_FAILED,TEMP[...]`
	Dyn_Tls_Crypt   = 9, // dynamic tls-crypt
	Data_Epoch      = 10, // epoch data keys (newer than 2.6)
	Dns_Option_V2   = 11, // `dns` v2 push options (newer than 2.6)
	Push_Update     = 12, // PUSH_UPDATE messages (newer than 2.6)
}

Iv_Proto :: bit_set[Iv_Proto_Bit;u32]

// What noirvpn sends. A bit is set only once the feature
// is built, so the caller builds its own set from this one as it goes.
IV_PROTO_USERSPACE :: Iv_Proto{
	.Data_V2,
	.Request_Push,
	.Tls_Key_Export,
	.Auth_Pending_Kw,
	.Cc_Exit_Notify,
	.Auth_Fail_Temp,
	.Dyn_Tls_Crypt,
	.Data_Epoch,
	.Dns_Option_V2,
	.Push_Update,
}
// Same without the two features Linux kernel offload lacks.
IV_PROTO_DCO :: IV_PROTO_USERSPACE - {.Data_Epoch, .Push_Update}

// The decimal number written to `IV_PROTO=`.
iv_proto_value :: proc "contextless" (p: Iv_Proto) -> u32 {
	return transmute(u32)p
}

// Reads the number from a peer. Bits above 12 are dropped; the caller can
// keep the raw value (`Peer_Info.proto_raw`) if it wants to log them.
iv_proto_from_value :: proc "contextless" (v: u32) -> Iv_Proto {
	mask := transmute(u32)(Iv_Proto{
			.Data_V2,
			.Request_Push,
			.Tls_Key_Export,
			.Auth_Pending_Kw,
			.Ncp_P2p,
			.Dns_Option,
			.Cc_Exit_Notify,
			.Auth_Fail_Temp,
			.Dyn_Tls_Crypt,
			.Data_Epoch,
			.Dns_Option_V2,
			.Push_Update,
		})
	return transmute(Iv_Proto)(v & mask)
}

// Name of a bit, for logs.
iv_proto_bit_name :: proc "contextless" (b: Iv_Proto_Bit) -> string {
	switch b {
	case .Data_V2:
		return "DATA_V2"
	case .Request_Push:
		return "REQUEST_PUSH"
	case .Tls_Key_Export:
		return "TLS_KEY_EXPORT"
	case .Auth_Pending_Kw:
		return "AUTH_PENDING_KW"
	case .Ncp_P2p:
		return "NCP_P2P"
	case .Dns_Option:
		return "DNS_OPTION"
	case .Cc_Exit_Notify:
		return "CC_EXIT_NOTIFY"
	case .Auth_Fail_Temp:
		return "AUTH_FAIL_TEMP"
	case .Dyn_Tls_Crypt:
		return "DYN_TLS_CRYPT"
	case .Data_Epoch:
		return "DATA_EPOCH"
	case .Dns_Option_V2:
		return "DNS_OPTION_V2"
	case .Push_Update:
		return "PUSH_UPDATE"
	}
	return "?"
}

// ---------------------------------------------------------------- build

// What a noirvpn client says about itself (level 2 in the spec's terms).
Peer_Info_Params :: struct {
	// `ID=`: the peer id this side wants to receive on. Userspace data path
	// only. Must be below 0xFFFFFF.
	id:            Maybe(u32),
	// `IV_VER`. Required. Something like "noirvpn-0.1.0". Do not let it look
	// like an old OpenVPN number.
	version:       string,
	// `IV_PLAT`: linux, mac, win, freebsd, openbsd, netbsd, solaris, android.
	platform:      string,
	// `IV_TCPNL=1`.
	tcp_nonlinear: bool,
	// `IV_MTU`: largest tun MTU this side takes. 0 leaves the line out.
	mtu:           int,
	// `IV_NCP=2`. Only worth sending when both AES-GCM names are in `ciphers`.
	ncp:           bool,
	// `IV_CIPHERS`, in preference order. Empty leaves the line out.
	ciphers:       []Cipher,
	// `IV_PROTO`.
	proto:         Iv_Proto,
	// More lines, each `NAME=value` without the newline. For tests and for
	// pass-through values.
	extra:         []string,
}

// Writes the peer-info text into `buf` in a stock client's order: ID, IV_VER,
// IV_PLAT, IV_TCPNL, IV_MTU, IV_NCP, IV_CIPHERS, IV_PROTO, then the extra lines.
// Every line ends with `\n`. The result is a slice of `buf` without NUL
// (`keymethod_encode` adds it).
peer_info_build :: proc(buf: []u8, p: ^Peer_Info_Params) -> (s: string, err: Error) {
	if len(p.version) == 0 || !is_plain_value(p.version) || !is_plain_value(p.platform) {
		return "", .Bad_Argument
	}
	for line in p.extra {
		if !is_plain_value(line) || len(line) < 3 {
			return "", .Bad_Argument
		}
		eq := false
		for c in transmute([]u8)line {
			if c == '=' {
				eq = true
				break
			}
		}
		if !eq || line[0] == '=' {
			return "", .Bad_Argument
		}
	}
	w := Wr{buf = buf}
	if id, ok := p.id.?; ok {
		if id >= 0xFFFFFF {
			return "", .Bad_Argument
		}
		wr_str(&w, "ID=")
		wr_hex(&w, u64(id))
		wr_byte(&w, '\n')
	}
	wr_str(&w, "IV_VER=")
	wr_str(&w, p.version)
	wr_byte(&w, '\n')
	if len(p.platform) > 0 {
		wr_str(&w, "IV_PLAT=")
		wr_str(&w, p.platform)
		wr_byte(&w, '\n')
	}
	if p.tcp_nonlinear {
		wr_str(&w, "IV_TCPNL=1\n")
	}
	if p.mtu > 0 {
		wr_str(&w, "IV_MTU=")
		wr_uint(&w, u64(p.mtu))
		wr_byte(&w, '\n')
	}
	if p.ncp {
		wr_str(&w, "IV_NCP=2\n")
	}
	if len(p.ciphers) > 0 {
		wr_str(&w, "IV_CIPHERS=")
		for c, i in p.ciphers {
			name := cipher_name(c)
			if len(name) == 0 {
				return "", .Bad_Argument
			}
			if i > 0 {
				wr_byte(&w, ':')
			}
			wr_str(&w, name)
		}
		wr_byte(&w, '\n')
	}
	wr_str(&w, "IV_PROTO=")
	wr_uint(&w, u64(iv_proto_value(p.proto)))
	wr_byte(&w, '\n')
	for line in p.extra {
		wr_str(&w, line)
		wr_byte(&w, '\n')
	}
	if w.over {
		return "", .Buffer_Too_Small
	}
	return string(buf[:w.n]), .None
}

// No NUL and no newline.
@(private)
is_plain_value :: proc "contextless" (s: string) -> bool {
	for c in transmute([]u8)s {
		if c == 0 || c == '\n' {
			return false
		}
	}
	return true
}

@(private)
wr_hex :: proc "contextless" (w: ^Wr, v: u64) {
	hexd := "0123456789abcdef"
	started := false
	for sh := 60; sh >= 0; sh -= 4 {
		d := (v >> u32(sh)) & 0xF
		if d != 0 || started || sh == 0 {
			wr_byte(w, hexd[d])
			started = true
		}
	}
}

// ---------------------------------------------------------------- parse

MAX_PEER_INFO_LINES :: 64
MAX_PEER_CIPHERS :: 32

Peer_Info_Line :: struct {
	name:  string,
	value: string,
}

// A peer's peer-info. Strings are slices of the parsed text. The size is
// bounded: past 64 lines or 32 ciphers the rest is only counted.
Peer_Info :: struct {
	// `ID=` (hex), if present and valid.
	id:                Maybe(u32),
	ver:               string, // IV_VER
	plat:              string, // IV_PLAT
	tcp_nonlinear:     bool, // IV_TCPNL present and not 0
	mtu:               int, // IV_MTU, 0 if absent
	ncp:               int, // IV_NCP, 0 if absent
	// IV_CIPHERS as sent, and split at ':'.
	ciphers_raw:       string,
	ciphers:           [MAX_PEER_CIPHERS]string,
	cipher_count:      int,
	ciphers_dropped:   int,
	// IV_PROTO. `proto` has the known bits; `proto_raw` the whole number.
	has_proto:         bool,
	proto_raw:         u32,
	proto:             Iv_Proto,
	// Every line, in order (the raw map). Names are case-sensitive.
	lines:             [MAX_PEER_INFO_LINES]Peer_Info_Line,
	line_count:        int,
	lines_dropped:     int,
}

// Reads a peer-info text. Never allocates.
// - Unknown names are kept in `lines`.
// - The first occurrence of a name wins for typed fields.
// - Numbers as the spec says: garbage after the number is ignored, garbage
//   before it sets the value absent.
// - A line without `=` is skipped.
// Errors: `.Oversize` for text longer than the key-method message limit.
peer_info_parse :: proc(text: string, pi: ^Peer_Info) -> Error {
	pi^ = {}
	if len(text) > KEY_METHOD_MAX_LEN {
		return .Oversize
	}
	rest := text
	seen_id, seen_ver, seen_plat, seen_tcpnl, seen_mtu, seen_ncp, seen_ciphers, seen_proto: bool
	for len(rest) > 0 {
		line: string
		nl := -1
		for c, i in transmute([]u8)rest {
			if c == '\n' {
				nl = i
				break
			}
		}
		if nl < 0 {
			line, rest = rest, ""
		} else {
			line, rest = rest[:nl], rest[nl + 1:]
		}
		eq := -1
		for c, i in transmute([]u8)line {
			if c == '=' {
				eq = i
				break
			}
		}
		if eq <= 0 {
			continue
		}
		name, value := line[:eq], line[eq + 1:]
		if pi.line_count < MAX_PEER_INFO_LINES {
			pi.lines[pi.line_count] = {name, value}
			pi.line_count += 1
		} else {
			pi.lines_dropped += 1
		}
		switch name {
		case "ID":
			if !seen_id {
				seen_id = true
				if v, ok := scan_uint_prefix(value, hex = true); ok && v < 0xFFFFFF {
					pi.id = u32(v)
				}
			}
		case "IV_VER":
			if !seen_ver {
				seen_ver = true
				pi.ver = value
			}
		case "IV_PLAT":
			if !seen_plat {
				seen_plat = true
				pi.plat = value
			}
		case "IV_TCPNL":
			if !seen_tcpnl {
				seen_tcpnl = true
				if v, ok := scan_uint_prefix(value); ok && v != 0 {
					pi.tcp_nonlinear = true
				}
			}
		case "IV_MTU":
			if !seen_mtu {
				seen_mtu = true
				if v, ok := scan_uint_prefix(value); ok && v <= 0x7FFFFFFF {
					pi.mtu = int(v)
				}
			}
		case "IV_NCP":
			if !seen_ncp {
				seen_ncp = true
				if v, ok := scan_uint_prefix(value); ok && v <= 0x7FFFFFFF {
					pi.ncp = int(v)
				}
			}
		case "IV_CIPHERS":
			if !seen_ciphers {
				seen_ciphers = true
				pi.ciphers_raw = value
				split_ciphers(pi)
			}
		case "IV_PROTO":
			if !seen_proto {
				seen_proto = true
				if v, ok := scan_uint_prefix(value); ok && v <= 0xFFFFFFFF {
					pi.has_proto = true
					pi.proto_raw = u32(v)
					pi.proto = iv_proto_from_value(u32(v))
				}
			}
		}
	}
	return .None
}

@(private)
split_ciphers :: proc(pi: ^Peer_Info) {
	rest := pi.ciphers_raw
	for len(rest) > 0 {
		colon := -1
		for c, i in transmute([]u8)rest {
			if c == ':' {
				colon = i
				break
			}
		}
		item: string
		if colon < 0 {
			item, rest = rest, ""
		} else {
			item, rest = rest[:colon], rest[colon + 1:]
		}
		if len(item) == 0 {
			continue
		}
		if pi.cipher_count < MAX_PEER_CIPHERS {
			pi.ciphers[pi.cipher_count] = item
			pi.cipher_count += 1
		} else {
			pi.ciphers_dropped += 1
		}
	}
}

// The peer's cipher names, in the order it sent them.
peer_info_ciphers :: proc(pi: ^Peer_Info) -> []string {
	return pi.ciphers[:pi.cipher_count]
}

// Looks a name up in the raw map. First match wins.
peer_info_get :: proc(pi: ^Peer_Info, name: string) -> (value: string, ok: bool) {
	for i in 0 ..< pi.line_count {
		if pi.lines[i].name == name {
			return pi.lines[i].value, true
		}
	}
	return "", false
}
