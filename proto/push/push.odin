// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package push: messages inside the TLS tunnel after the handshake: key-method-2
// message, options string, peer-info, NUL-terminated text commands (PUSH_REQUEST,
// PUSH_REPLY, AUTH_FAILED, ...), PUSH_REPLY option grammar, cipher negotiation.
//
// Package rules:
//   - Pure parsing and formatting. No I/O, TLS, clock or RNG (the caller supplies
//     random bytes and gets bytes to write to TLS).
//   - Hostile input returns an `Error` (or a note, see `Pushed_Options`). Never
//     panics or asserts on peer bytes.
//   - Fixed-message decoders (`keymethod_decode`, `peer_info_parse`,
//     `options_parse`, `command_parse`) do not allocate. Result strings are slices
//     of the input.
//   - Only `Pushed_Options` and the PUSH_REPLY builder allocate: they take an
//     allocator, bound their sizes, and have a `*_destroy` proc.
//
// Files:
//
//   keymethod.odin    key-method-2 message, both directions
//   options.odin      options string: build, parse, compare, link-mtu
//   peerinfo.odin     IV_PROTO bits, peer-info build and parse
//   command.odin      text command framing, dispatch, typed parse and format
//   tokenize.odin     option word splitter (quotes, escapes, comments)
//   pushed.odin       Pushed_Options, PUSH_REPLY parse, continuation assembler
//   reply_build.odin  server side: struct to PUSH_REPLY messages
//   ncp.odin          cipher negotiation, protocol flags, client checks
//   util.odin         number and address helpers
//
// Session layer duties (this package cannot know them):
//   - Buffer TLS plaintext. Each direction starts with one key-method-2 message:
//     call `keymethod_decode` until it stops returning `.Need_More`, then feed the
//     unused bytes (`consumed` onwards) to a `Cmd_Reader`.
//   - Write each message and command with one TLS write.
//   - Decide when to send PUSH_REQUEST and apply `Pushed_Options`.
package push

Error :: enum {
	None,
	// Decoder: the bytes so far are a valid prefix. Wait for more. Not a fault.
	Need_More,
	// Decoder told the input is final, and it ends inside a field.
	Truncated,
	// The output buffer is too small.
	Buffer_Too_Small,
	// A string, message or command is longer than its limit.
	Oversize,
	// Key-method byte is not method 2.
	Bad_Key_Method,
	// Encoder: a value the format cannot carry (wrong random size, NUL or
	// newline inside a string, ...).
	Bad_Argument,
	// Encoder: the random block is all zero. The spec says to never send zeros.
	Zero_Random,
	// A text command holds a control byte (below 0x20, or 0x7F).
	Bad_Byte,
	// A typed command or option text does not follow its grammar.
	Bad_Syntax,
	// Unbalanced quote in an option.
	Bad_Quoting,
	// An option has more words than allowed.
	Too_Many_Words,
	// More options, parts or bytes than the bounds allow.
	Too_Many_Options,
	// `push-continuation` with a value other than 1 or 2, or used twice.
	Bad_Continuation,
	// The command is valid but this role does not act on it.
	Wrong_Direction,
	// Allocation failed.
	Out_Of_Memory,
}

// Which end wrote (or reads) a message.
Role :: enum u8 {
	Client,
	Server,
}

Transport :: enum u8 {
	Udp,
	Tcp,
}

// Largest plain buffer of a stock peer.
MAX_COMMAND_LEN :: 2048

@(private)
put_u16 :: #force_inline proc "contextless" (b: []u8, v: u16) {
	b[0] = u8(v >> 8)
	b[1] = u8(v)
}

@(private)
get_u16 :: #force_inline proc "contextless" (b: []u8) -> u16 {
	return u16(b[0]) << 8 | u16(b[1])
}
