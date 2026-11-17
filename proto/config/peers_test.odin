// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

ALICE1 :: "sha256:jzyXE/jd4JYLM3XtvDrr2jXrx7xyEIWhFdFIUlIFeN8="
ALICE2 :: "sha256:9S+BUlQJ6p3MyLP5vDsUcJ8Acg7K2Oq41rk0mqiRTyo="
BOB :: "mldsa65-sha256:gbY32PzSxtpjWeaWMROhFw3nleS3JbhNHgtM/Z7FjOk="
CAROL :: "sha256:TCbZB0wn2J7eWScMCsFLceBxsVI5UZ91R0svO6Y0gfU="

@(test)
test_peers_basic :: proc(t: ^testing.T) {
	text :=
		"# comment\n\nalice " +
		ALICE1 +
		" ifconfig-push=10.8.0.10\nalice " +
		ALICE2 +
		" # second\nbob " +
		BOB +
		" iroute=192.168.10.0/24 iroute=192.168.11.0/24\ncarol " +
		CAROL +
		" disabled\n"
	p := peers_parse(text, "peers")
	defer peers_destroy(&p)
	if !expect_clean(t, p.diags) {
		return
	}
	testing.expect(t, peers_ok(&p))
	testing.expect_value(t, len(p.entries), 4)
	e := p.entries
	testing.expect_value(t, e[0].user, "alice")
	testing.expect_value(t, e[0].line, 3)
	testing.expect_value(t, e[0].pin.kind, Pin_Kind.Sha256)
	testing.expect_value(t, e[0].pin.digest[0], u8(0x8f))
	testing.expect_value(t, e[0].pin.digest[1], u8(0x3c))
	testing.expect_value(t, e[0].pin.digest[31], u8(0xdf))
	ip, ok := e[0].client.ifconfig_push.?
	testing.expect(t, ok)
	testing.expect_value(t, ip.local_ip, [4]u8{10, 8, 0, 10})
	testing.expect(t, ip.local_is_ip)
	testing.expect(t, e[1].client.ifconfig_push == nil)
	testing.expect_value(t, e[2].pin.kind, Pin_Kind.Mldsa65_Sha256)
	testing.expect_value(t, len(e[2].client.iroutes), 2)
	if len(e[2].client.iroutes) == 2 {
		testing.expect_value(t, e[2].client.iroutes[0], Iroute{{192, 168, 10, 0}, 24})
		testing.expect_value(t, e[2].client.iroutes[1].network, [4]u8{192, 168, 11, 0})
	}
	testing.expect(t, e[3].disabled && e[3].client.disable)
	testing.expect(t, !e[0].disabled)
}

@(test)
test_peers_lookup :: proc(t: ^testing.T) {
	text :=
		"alice " +
		ALICE1 +
		"\nalice " +
		ALICE2 +
		"\nbob " +
		BOB +
		"\ncarol " +
		CAROL +
		" disabled\n"
	p := peers_parse(text)
	defer peers_destroy(&p)
	expect_clean(t, p.diags)

	// Look a key up by its digest.
	pin := p.entries[1].pin
	e, found := peers_lookup(&p, pin)
	testing.expect(t, found)
	if found {
		testing.expect_value(t, e.user, "alice")
		testing.expect_value(t, e.line, 2)
	}
	// The same bytes under another pin type are a different key.
	other := pin
	other.kind = .Mldsa65_Sha256
	_, found = peers_lookup(&p, other)
	testing.expect(t, !found)
	_, found = peers_lookup(&p, Pin{})
	testing.expect(t, !found)

	// A disabled key is found, and says so.
	c, cfound := peers_lookup(&p, p.entries[3].pin)
	testing.expect(t, cfound && c.disabled)

	idx := peers_user_entries(&p, "alice")
	testing.expect_value(t, len(idx), 2)
	if len(idx) == 2 {
		testing.expect_value(t, idx[0], 0)
		testing.expect_value(t, idx[1], 1)
	}
	testing.expect_value(t, len(peers_user_entries(&p, "nobody")), 0)
	// Ignoring ASCII case.
	testing.expect_value(t, len(peers_user_entries(&p, "ALICE")), 2)
	testing.expect_value(t, len(peers_user_entries(&p, "Alice")), 2)
}

@(test)
test_peers_ipv6_options_and_tabs :: proc(t: ^testing.T) {
	p := peers_parse(
		"dave\t" + ALICE1 + "\tifconfig-ipv6-push=fd00:8::10/64 iroute-ipv6=fd00:99::/64\n",
	)
	defer peers_destroy(&p)
	if expect_clean(t, p.diags) && len(p.entries) == 1 {
		e := p.entries[0]
		a, ok := e.client.ifconfig_ipv6_push.?
		testing.expect(t, ok)
		testing.expect_value(t, a.bits, u8(64))
		testing.expect_value(t, a.addr[15], u8(0x10))
		testing.expect_value(t, len(e.client.iroutes6), 1)
	}
}

@(test)
test_peers_crlf_bom_and_no_final_newline :: proc(t: ^testing.T) {
	p := peers_parse("\xef\xbb\xbf# hi\r\nalice " + ALICE1 + "\r\nbob " + BOB)
	defer peers_destroy(&p)
	expect_clean(t, p.diags)
	testing.expect_value(t, len(p.entries), 2)
	if len(p.entries) == 2 {
		testing.expect_value(t, p.entries[1].line, 3)
		testing.expect_value(t, p.entries[0].user, "alice")
	}

	empty := peers_parse("")
	defer peers_destroy(&empty)
	testing.expect_value(t, len(empty.entries), 0)
	testing.expect(t, peers_ok(&empty))
}

@(test)
test_peers_errors_have_line_numbers :: proc(t: ^testing.T) {
	text := strings.join(
		{
			"alice " + ALICE1, // 1 fine
			"onlyname", // 2
			"bob sha1:AAAA", // 3 unknown type
			"bob sha256:AAAA", // 4 too short
			"bob sha256:!!!!", // 5 not base64
			"bob nocolon", // 6
			"carol " + CAROL + " frobnicate", // 7 unknown option
			"carol " + CAROL + " ifconfig-push=notanip", // 8
			"carol " + CAROL + " iroute=10.0.0.1/24", // 9 host bits
			"carol " + CAROL + " iroute=10.0.0.0/33", // 10
			"carol " + CAROL + " disabled=yes", // 11
			"alice " + ALICE1, // 12 duplicate pin
			"bad/user " + ALICE2, // 13
			"carol " + CAROL + " ifconfig-push=10.0.0.1 ifconfig-push=10.0.0.2", // 14
			"dave\x01x " + ALICE2, // 15 control character
			"carol " + CAROL, // 16 fine
		},
		"\n",
		context.temp_allocator,
	)
	p := peers_parse(text, "peers.txt")
	defer peers_destroy(&p)
	expect_error(t, p.diags, 2, "expected `<username> <pin> [options]`")
	expect_error(t, p.diags, 3, "unknown pin type 'sha1'")
	expect_error(t, p.diags, 4, "32-byte")
	expect_error(t, p.diags, 5, "not a valid base64 encoding")
	expect_error(t, p.diags, 6, "is not a valid pin")
	expect_error(t, p.diags, 7, "unknown option 'frobnicate'")
	expect_error(t, p.diags, 8, "needs an IPv4 address")
	expect_error(t, p.diags, 9, "host bits set")
	expect_error(t, p.diags, 10, "needs net/len")
	expect_error(t, p.diags, 11, "does not accept a value")
	expect_error(t, p.diags, 12, "already used for 'alice' on line 1")
	expect_error(t, p.diags, 13, "path separator")
	expect_error(t, p.diags, 14, "given twice")
	expect_error(t, p.diags, 15, "control character")
	for d in p.diags {
		testing.expect_value(t, d.file, "peers.txt")
	}
	testing.expect(t, !peers_ok(&p))
	// The good lines are still there.
	testing.expect_value(t, len(p.entries), 2)
	if len(p.entries) == 2 {
		testing.expect_value(t, p.entries[0].user, "alice")
		testing.expect_value(t, p.entries[1].line, 16)
	}
}

@(test)
test_peers_base64_forms :: proc(t: ^testing.T) {
	// 43 characters without padding are accepted too.
	p := peers_parse("alice sha256:jzyXE/jd4JYLM3XtvDrr2jXrx7xyEIWhFdFIUlIFeN8\n")
	defer peers_destroy(&p)
	expect_clean(t, p.diags)
	testing.expect_value(t, len(p.entries), 1)

	// 31 bytes and 33 bytes are wrong.
	short := peers_parse("alice sha256:jzyXE/jd4JYLM3XtvDrr2jXrx7xyEIWhFdFIUlIFeA==\n")
	defer peers_destroy(&short)
	testing.expect(t, diags_have_error(short.diags))
	long := peers_parse("alice sha256:jzyXE/jd4JYLM3XtvDrr2jXrx7xyEIWhFdFIUlIFeN8AAAA\n")
	defer peers_destroy(&long)
	testing.expect(t, diags_have_error(long.diags))
	// Not canonical: leftover bits set.
	noncanon := peers_parse("alice sha256:jzyXE/jd4JYLM3XtvDrr2jXrx7xyEIWhFdFIUlIFeN9=\n")
	defer peers_destroy(&noncanon)
	testing.expect(t, diags_have_error(noncanon.diags))
}

@(test)
test_peers_limits :: proc(t: ^testing.T) {
	long, _ := strings.repeat("x", DEFAULT_MAX_LINE, context.temp_allocator)
	p := peers_parse(
		strings.concatenate({"alice ", long, "\nbob ", BOB, "\n"}, context.temp_allocator),
	)
	defer peers_destroy(&p)
	expect_error(t, p.diags, 1, "too long")
	testing.expect_value(t, len(p.entries), 1)

	nul := peers_parse("alice " + ALICE1 + "\x00\n")
	defer peers_destroy(&nul)
	expect_error(t, nul.diags, 1, "NUL")
}

@(test)
test_peers_file :: proc(t: ^testing.T) {
	p := peers_parse_file(#directory + "testdata/peers.txt")
	defer peers_destroy(&p)
	if expect_clean(t, p.diags) {
		testing.expect_value(t, len(p.entries), 5)
		testing.expect_value(t, len(peers_user_entries(&p, "alice")), 2)
		testing.expect(t, p.entries[3].disabled)
		testing.expect_value(t, p.entries[4].user, "dave")
		testing.expect_value(t, p.entries[0].line, 4)
	}

	missing := peers_parse_file(#directory + "testdata/none.txt")
	defer peers_destroy(&missing)
	testing.expect(t, diags_have_error(missing.diags))
	expect_error(t, missing.diags, 0, "cannot read the peers file")

	files := Mem_Files{}
	defer delete(files)
	files["big"] = "alice " + ALICE1 + "\n"
	big := peers_parse_file(
		"big",
		Parse_Options{loader = mem_loader, loader_data = &files, max_file = 10},
	)
	defer peers_destroy(&big)
	expect_error(t, big.diags, 0, "too large")
	ok := peers_parse_file("big", Parse_Options{loader = mem_loader, loader_data = &files})
	defer peers_destroy(&ok)
	testing.expect_value(t, len(ok.entries), 1)
}

@(test)
test_peers_many_entries :: proc(t: ^testing.T) {
	// A big file: 2000 users, each with a distinct pin.
	sb := strings.builder_make(context.temp_allocator)
	for i in 0 ..< 2000 {
		// Generate 32 distinct bytes in base64 by writing the number into the first bytes.
		raw: [32]u8
		raw[0], raw[1] = u8(i >> 8), u8(i)
		strings.write_string(&sb, "user")
		strings.write_int(&sb, i)
		strings.write_string(&sb, " sha256:")
		write_b64(&sb, raw[:])
		strings.write_byte(&sb, '\n')
	}
	p := peers_parse(strings.to_string(sb))
	defer peers_destroy(&p)
	expect_clean(t, p.diags)
	testing.expect_value(t, len(p.entries), 2000)
	pin := p.entries[1234].pin
	e, found := peers_lookup(&p, pin)
	testing.expect(t, found)
	if found {
		testing.expect_value(t, e.user, "user1234")
	}
}

write_b64 :: proc(sb: ^strings.Builder, raw: []u8) {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := 0
	for i + 3 <= len(raw) {
		v := u32(raw[i]) << 16 | u32(raw[i + 1]) << 8 | u32(raw[i + 2])
		strings.write_byte(sb, alphabet[v >> 18 & 63])
		strings.write_byte(sb, alphabet[v >> 12 & 63])
		strings.write_byte(sb, alphabet[v >> 6 & 63])
		strings.write_byte(sb, alphabet[v & 63])
		i += 3
	}
	rest := len(raw) - i
	if rest == 2 {
		v := u32(raw[i]) << 16 | u32(raw[i + 1]) << 8
		strings.write_byte(sb, alphabet[v >> 18 & 63])
		strings.write_byte(sb, alphabet[v >> 12 & 63])
		strings.write_byte(sb, alphabet[v >> 6 & 63])
		strings.write_byte(sb, '=')
	} else if rest == 1 {
		v := u32(raw[i]) << 16
		strings.write_byte(sb, alphabet[v >> 18 & 63])
		strings.write_byte(sb, alphabet[v >> 12 & 63])
		strings.write_string(sb, "==")
	}
}
