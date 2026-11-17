// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

import "core:encoding/base64"
import "core:strings"
import "core:testing"

// A static key text with the given 256 bytes.
@(private = "file")
key_text :: proc(b: []u8, header := true, footer := true, eol := "\n") -> string {
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "#\r\n# 2048 bit OpenVPN static key\r\n#\r\n" if eol == "\r\n" else "#\n# 2048 bit OpenVPN static key\n#\n")
	if header {
		strings.write_string(&sb, STATIC_KEY_BEGIN)
		strings.write_string(&sb, eol)
	}
	for i := 0; i < len(b); i += 16 {
		end := min(i + 16, len(b))
		strings.write_string(&sb, string(hex_of(b[i:end])))
		strings.write_string(&sb, eol)
	}
	if footer {
		strings.write_string(&sb, STATIC_KEY_END)
		strings.write_string(&sb, eol)
	}
	return strings.to_string(sb)
}

@(private = "file")
random_bytes_det :: proc(seed: u64, n: int) -> []u8 {
	r := Rng{seed}
	b := make([]u8, n, context.temp_allocator)
	rng_fill(&r, b)
	// Check that no slot starts with 16 zero bytes.
	return b
}

// PEM text for `body` with 64-character lines.
@(private = "file")
pem_text :: proc(label: string, body: []u8, eol := "\n", end_label := "") -> string {
	enc, _ := base64.encode(body, allocator = context.temp_allocator)
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "-----BEGIN ")
	strings.write_string(&sb, label)
	strings.write_string(&sb, "-----")
	strings.write_string(&sb, eol)
	for i := 0; i < len(enc); i += 64 {
		strings.write_string(&sb, enc[i:min(i + 64, len(enc))])
		strings.write_string(&sb, eol)
	}
	strings.write_string(&sb, "-----END ")
	strings.write_string(&sb, label if end_label == "" else end_label)
	strings.write_string(&sb, "-----")
	strings.write_string(&sb, eol)
	return strings.to_string(sb)
}

@(private = "file")
upper_text :: proc(raw: []u8) -> string {
	k: Static_Key
	copy(k.bytes[:], raw)
	return static_key_text(&k, upper = true)
}

@(test)
static_key_parse_valid :: proc(t: ^testing.T) {
	raw := random_bytes_det(1, 256)
	var: Static_Key
	// Plain, CRLF, upper case, without comment lines, extra spaces.
	good := [?]string {
		key_text(raw),
		key_text(raw, eol = "\r\n"),
		upper_text(raw),
		strings.concatenate({STATIC_KEY_BEGIN, "\n", string(hex_of(raw)), "\n", STATIC_KEY_END}, context.temp_allocator),
	}
	for text, i in good {
		err := static_key_parse_string(text, &var)
		testing.expectf(t, err == .None, "case %d: %v", i, err)
		expect_bytes(t, var.bytes[:], raw, "key bytes")
	}

	// Spaces, tabs and line breaks between digits, even inside a byte, are skipped.
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "junk before\n")
	strings.write_string(&sb, STATIC_KEY_BEGIN)
	strings.write_string(&sb, "  trailing words on the header line\n \t")
	for c, i in hex_of(raw) {
		strings.write_byte(&sb, c)
		switch {
		case i % 50 == 49:
			strings.write_string(&sb, "\r\n")
		case i % 7 == 3:
			strings.write_byte(&sb, '\t')
		case i % 3 == 0:
			strings.write_byte(&sb, ' ')
		}
	}
	strings.write_string(&sb, "\n")
	strings.write_string(&sb, STATIC_KEY_END)
	testing.expect_value(t, static_key_parse_string(strings.to_string(sb), &var), Error.None)
	expect_bytes(t, var.bytes[:], raw, "spaced key")

	// Bytes after the 256th are ignored.
	long := strings.concatenate({STATIC_KEY_BEGIN, "\n", string(hex_of(raw)), "00ff00ff\n", STATIC_KEY_END}, context.temp_allocator)
	testing.expect_value(t, static_key_parse_string(long, &var), Error.None)
	expect_bytes(t, var.bytes[:], raw, "long file")

	// The generated text of the helper parses to the same key.
	k := spec_key()
	testing.expect_value(t, static_key_parse_string(static_key_text(&k), &var), Error.None)
	expect_bytes(t, var.bytes[:], k.bytes[:], "spec key")
}

@(private = "file")
HEX_DIGITS := "0123456789abcdef"

@(private = "file")
hex_of :: proc(b: []u8) -> []u8 {
	out := make([]u8, 2 * len(b), context.temp_allocator)
	for x, i in b {
		out[2 * i] = HEX_DIGITS[x >> 4]
		out[2 * i + 1] = HEX_DIGITS[x & 15]
	}
	return out
}

@(test)
static_key_parse_negative :: proc(t: ^testing.T) {
	raw := random_bytes_det(2, 256)
	var: Static_Key

	// Missing header / footer.
	testing.expect_value(t, static_key_parse_string(key_text(raw, header = false), &var), Error.Missing_Header)
	testing.expect_value(t, static_key_parse_string(key_text(raw, footer = false), &var), Error.Missing_Footer)
	testing.expect_value(t, static_key_parse_string("", &var), Error.Missing_Header)
	// A failed parse leaves no key bytes behind.
	testing.expect_value(t, var.bytes, [256]u8{})

	// Wrong sizes: 255, 192, 128, 127, 0 bytes.
	for n in ([?]int{255, 192, 129, 128, 127, 64, 1, 0}) {
		err := static_key_parse_string(key_text(raw[:n]), &var)
		testing.expectf(t, err == .Wrong_Size, "%d bytes: %v", n, err)
	}

	// Odd number of digits.
	odd := strings.concatenate({STATIC_KEY_BEGIN, "\n", string(hex_of(raw)), "a\n", STATIC_KEY_END}, context.temp_allocator)
	testing.expect_value(t, static_key_parse_string(odd, &var), Error.None) // past 256 bytes: ignored
	odd2 := strings.concatenate({STATIC_KEY_BEGIN, "\n", string(hex_of(raw[:255])), "a\n", STATIC_KEY_END}, context.temp_allocator)
	testing.expect_value(t, static_key_parse_string(odd2, &var), Error.Bad_Hex)

	// Characters that are not hex or white space.
	bad_chars := [?]string{"zz", "0x41", "g0", "41,42", "41-42", "\xff"}
	for bc in bad_chars {
		text := strings.concatenate({STATIC_KEY_BEGIN, "\n", string(hex_of(raw[:10])), bc, "\n", string(hex_of(raw[10:])), "\n", STATIC_KEY_END}, context.temp_allocator)
		err := static_key_parse_string(text, &var)
		testing.expectf(t, err == .Bad_Hex, "%q: %v", bc, err)
	}

	// Zero slots: each of the four parts with 16 leading zero bytes.
	for part in 0 ..< 4 {
		z := make([]u8, 256, context.temp_allocator)
		copy(z, raw)
		for i in 0 ..< 16 {
			z[64 * part + i] = 0
		}
		testing.expect_value(t, static_key_parse_string(key_text(z), &var), Error.Zero_Slot)
		// Only 15 zero bytes is fine.
		z[64 * part + 15] = 1
		testing.expect_value(t, static_key_parse_string(key_text(z), &var), Error.None)
	}
	// An all-zero tail of a part does not matter.
	z := make([]u8, 256, context.temp_allocator)
	copy(z, raw)
	for i in 16 ..< 64 {
		z[i] = 0
	}
	testing.expect_value(t, static_key_parse_string(key_text(z), &var), Error.None)
}

@(test)
server_key_pem :: proc(t: ^testing.T) {
	body := random_bytes_det(3, 128)
	sk: Server_Key
	testing.expect_value(t, server_key_parse_string(pem_text(SERVER_KEY_LABEL, body), &sk), Error.None)
	expect_bytes(t, sk.ke[:], body[0:32], "Ke")
	expect_bytes(t, sk.ka[:], body[64:96], "Ka")

	// CRLF, blank lines, text around the block.
	messy := strings.concatenate({"some note\r\n\r\n", pem_text(SERVER_KEY_LABEL, body, "\r\n"), "\r\n\r\ntrailing\r\n"}, context.temp_allocator)
	testing.expect_value(t, server_key_parse_string(messy, &sk), Error.None)
	expect_bytes(t, sk.ka[:], body[64:96], "Ka (messy)")

	// An all-zero server key is accepted (no zero check).
	zero := make([]u8, 128, context.temp_allocator)
	testing.expect_value(t, server_key_parse_string(pem_text(SERVER_KEY_LABEL, zero), &sk), Error.None)

	// Wrong label, either way.
	testing.expect_value(t, server_key_parse_string(pem_text(CLIENT_KEY_LABEL, body), &sk), Error.Wrong_Label)
	testing.expect_value(t, server_key_parse_string(pem_text("PRIVATE KEY", body), &sk), Error.Wrong_Label)
	testing.expect_value(t, server_key_parse_string(pem_text(SERVER_KEY_LABEL, body, end_label = "OTHER"), &sk), Error.Wrong_Label)

	// Sizes.
	for n in ([?]int{0, 1, 96, 127, 129, 256}) {
		err := server_key_parse_string(pem_text(SERVER_KEY_LABEL, random_bytes_det(4, n)), &sk)
		testing.expectf(t, err == .Wrong_Size, "%d bytes: %v", n, err)
	}

	// Broken text.
	testing.expect_value(t, server_key_parse_string("", &sk), Error.Missing_Header)
	testing.expect_value(t, server_key_parse_string("-----BEGIN OpenVPN tls-crypt-v2 server key", &sk), Error.Missing_Header)
	full := pem_text(SERVER_KEY_LABEL, body)
	end_line := len("-----END ") + len(SERVER_KEY_LABEL) + len("-----\n")
	testing.expect_value(t, server_key_parse_string(full[:len(full) - end_line], &sk), Error.Missing_Footer)
	testing.expect(t, server_key_parse_string(full[:len(full) - 10], &sk) != .None) // END line cut short
	// Bad base64: a character outside the alphabet, a data character after
	// padding, short group, URL-safe alphabet.
	enc, _ := base64.encode(body, allocator = context.temp_allocator)
	mk :: proc(enc: string) -> string {
		return strings.concatenate({"-----BEGIN ", SERVER_KEY_LABEL, "-----\n", enc, "\n-----END ", SERVER_KEY_LABEL, "-----\n"}, context.temp_allocator)
	}
	testing.expect_value(t, server_key_parse_string(mk(strings.concatenate({"!", enc[1:]}, context.temp_allocator)), &sk), Error.Bad_Base64)
	testing.expect_value(t, server_key_parse_string(mk(strings.concatenate({enc, "A"}, context.temp_allocator)), &sk), Error.Bad_Base64)
	testing.expect_value(t, server_key_parse_string(mk(strings.concatenate({enc[:len(enc) - 4], "=AAA"}, context.temp_allocator)), &sk), Error.Bad_Base64)
	testing.expect_value(t, server_key_parse_string(mk("A==="), &sk), Error.Bad_Base64)
	testing.expect_value(t, server_key_parse_string(mk("AB=A"), &sk), Error.Bad_Base64)
	testing.expect_value(t, server_key_parse_string(mk("AAAA====\n"), &sk), Error.Bad_Base64)
	testing.expect_value(t, server_key_parse_string(mk("Proc-Type: 4,ENCRYPTED"), &sk), Error.Bad_Base64)
}

@(test)
client_key_pem :: proc(t: ^testing.T) {
	kc := spec_v2_kc()
	wkc := unhex(SPEC_WKC)
	body := make([]u8, 256 + len(wkc), context.temp_allocator)
	copy(body, kc.bytes[:])
	copy(body[256:], wkc)

	ck: Client_Key
	testing.expect_value(t, client_key_parse_string(pem_text(CLIENT_KEY_LABEL, body), &ck), Error.None)
	expect_bytes(t, ck.kc.bytes[:], kc.bytes[:], "Kc")
	expect_bytes(t, client_key_wkc(&ck), wkc, "WKc")
	testing.expect_value(t, ck.wkc_len, 299)

	// CRLF.
	testing.expect_value(t, client_key_parse_string(pem_text(CLIENT_KEY_LABEL, body, "\r\n"), &ck), Error.None)
	expect_bytes(t, client_key_wkc(&ck), wkc, "WKc (CRLF)")

	// Kc gets no zero-slot check.
	zero_body := make([]u8, 256 + 10, context.temp_allocator)
	testing.expect_value(t, client_key_parse_string(pem_text(CLIENT_KEY_LABEL, zero_body), &ck), Error.None)
	testing.expect_value(t, ck.wkc_len, 10)

	// WKc size limits: 1 and 1024 pass; 0 and 1025 fail.
	for n, want in ([?]int{0, 1, 1024, 1025}) {
		b := random_bytes_det(5, 256 + n)
		err := client_key_parse_string(pem_text(CLIENT_KEY_LABEL, b), &ck)
		if n == 0 || n == 1025 {
			testing.expectf(t, err == .Wrong_Size, "WKc %d bytes: %v", n, err)
		} else {
			testing.expectf(t, err == .None, "WKc %d bytes: %v", n, err)
			testing.expect_value(t, ck.wkc_len, n)
		}
		_ = want
	}
	// Too short to hold Kc.
	testing.expect_value(t, client_key_parse_string(pem_text(CLIENT_KEY_LABEL, random_bytes_det(6, 100)), &ck), Error.Wrong_Size)

	// Wrong label.
	testing.expect_value(t, client_key_parse_string(pem_text(SERVER_KEY_LABEL, body), &ck), Error.Wrong_Label)
	testing.expect_value(t, client_key_parse_string("nothing here", &ck), Error.Missing_Header)

	// A failed parse leaves nothing behind.
	testing.expect_value(t, ck.wkc_len, 0)
}
