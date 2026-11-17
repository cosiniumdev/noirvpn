// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

// The text rewrites of profile_text.odin. The engine tests of identity.set and
// credentials.set (engine/lib_identity_test.odin, lib_credentials_test.odin)
// cover the same code through the library.

@(private = "file")
ID_PROFILE :: "# work\n" +
	"client\nremote 192.0.2.1 1194 udp\n" +
	"cert old.crt\nkey old.key\naskpass pw.txt\n" +
	"<connection>\nremote 192.0.2.2 1194 udp\n</connection>\n" +
	"<ca>\nCA LINE\n</ca>\n" +
	"<cert>\nOLD CERT\n</cert>\n" +
	"<key>\nOLD KEY\n</key>\n" +
	"<extra-certs>\nOLD CHAIN\n</extra-certs>\n" +
	"verb 3"

@(test)
test_identity_blocks :: proc(t: ^testing.T) {
	b := identity_blocks("C\n", "K\n", "", context.temp_allocator)
	testing.expect_value(t, b, "<cert>\nC\n</cert>\n<key>\nK\n</key>\n")
	b = identity_blocks("C\n", "K\n", "X\nY\n", context.temp_allocator)
	testing.expect_value(t, b, "<cert>\nC\n</cert>\n<key>\nK\n</key>\n<extra-certs>\nX\nY\n</extra-certs>\n")
}

@(test)
test_identity_text :: proc(t: ^testing.T) {
	blocks := identity_blocks("NEW CERT\n", "NEW KEY\n", "", context.temp_allocator)
	out := identity_text(ID_PROFILE, blocks, context.temp_allocator)
	want := "# work\n" +
		"client\nremote 192.0.2.1 1194 udp\n" +
		"<connection>\nremote 192.0.2.2 1194 udp\n</connection>\n" +
		"<ca>\nCA LINE\n</ca>\n" +
		"verb 3\n" +
		"<cert>\nNEW CERT\n</cert>\n<key>\nNEW KEY\n</key>\n"
	testing.expect_value(t, out, want)

	// CRLF line ends: the new lines get them too; a BOM stays.
	crlf, _ := strings.replace_all("\xef\xbb\xbfclient\n<cert>\nX\n</cert>\nverb 3\n", "\n", "\r\n", context.temp_allocator)
	out = identity_text(crlf, blocks, context.temp_allocator)
	testing.expect_value(t, out, "\xef\xbb\xbfclient\r\nverb 3\r\n<cert>\r\nNEW CERT\r\n</cert>\r\n<key>\r\nNEW KEY\r\n</key>\r\n")

	// "--key" and a quoted option name are key lines too; a line that only
	// starts with the word is not.
	out = identity_text("--key a.key\n\"cert\" b.crt\nkeysize 128\n", "", context.temp_allocator)
	testing.expect_value(t, out, "keysize 128\n")
}

@(private = "file")
LOGIN_TEXT :: "client\n" +
	"<connection>\nremote 192.0.2.2 1194 udp\n<auth-user-pass>\nnot this\nx\n</auth-user-pass>\n</connection>\n" +
	"auth-user-pass\n" +
	"<auth-user-pass>\nalice\nold secret\n</auth-user-pass>\n" +
	"verb 3\n"

@(test)
test_inline_login :: proc(t: ^testing.T) {
	body, found := inline_login(LOGIN_TEXT, context.temp_allocator)
	testing.expect(t, found)
	testing.expect_value(t, body, "alice\nold secret\n")
	// The last auth-user-pass counts: a plain line after the block.
	_, found = inline_login("<auth-user-pass>\na\nb\n</auth-user-pass>\nauth-user-pass\n", context.temp_allocator)
	testing.expect(t, !found)
	_, found = inline_login("client\n", context.temp_allocator)
	testing.expect(t, !found)
}

@(test)
test_login_text :: proc(t: ^testing.T) {
	out, ok := login_text(LOGIN_TEXT, "bob", "new pw", context.temp_allocator)
	testing.expect(t, ok)
	want, _ := strings.replace(LOGIN_TEXT, "alice\nold secret\n", "bob\nnew pw\n", 1, context.temp_allocator)
	testing.expect_value(t, out, want)

	crlf, _ := strings.replace_all(LOGIN_TEXT, "\n", "\r\n", context.temp_allocator)
	out, ok = login_text(crlf, "bob", "new pw", context.temp_allocator)
	testing.expect(t, ok)
	want, _ = strings.replace(crlf, "alice\r\nold secret\r\n", "bob\r\nnew pw\r\n", 1, context.temp_allocator)
	testing.expect_value(t, out, want)

	_, ok = login_text("client\nauth-user-pass\n", "bob", "pw", context.temp_allocator)
	testing.expect(t, !ok)
}

@(test)
test_inline_block_span :: proc(t: ^testing.T) {
	text := "<ca>\nA\n</ca>\n<tls-crypt>\nB\n<ca>\n</tls-crypt>\n<ca>\nC\n</ca>\n"
	s, e, ok := inline_block_span(text, "ca")
	testing.expect(t, ok)
	testing.expect_value(t, text[s:e], "C\n")
	_, _, ok = inline_block_span(text, "cert")
	testing.expect(t, !ok)
	testing.expect_value(t, text_line_end("a\r\nb\n"), "\r\n")
	testing.expect_value(t, text_line_end("a\nb\r\n"), "\n")
}
