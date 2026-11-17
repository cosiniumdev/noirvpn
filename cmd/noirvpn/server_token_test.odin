// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:strings"
import "core:testing"
import "noir:proto/push"

@(private = "file")
test_key :: proc(fill: u8) -> Token_Key {
	k: Token_Key
	for i in 0 ..< len(k) {
		k[i] = fill + u8(i)
	}
	return k
}

@(private = "file")
test_id :: proc(fill: u8) -> Token_Id {
	id: Token_Id
	for i in 0 ..< len(id) {
		id[i] = fill + u8(i)
	}
	return id
}

@(test)
test_token_round_trip :: proc(t: ^testing.T) {
	key := test_key(1)
	id := test_id(7)
	buf: [TOKEN_MAX]u8
	tok, ok := token_make(&key, id, 2_000_000_000, buf[:])
	testing.expect(t, ok)
	testing.expect(t, token_looks_like(tok))
	testing.expect(t, strings.has_prefix(tok, "noirt2."))
	testing.expect(t, len(tok) <= TOKEN_MAX)
	testing.expect_value(t, len(tok), 57)
	got, end, res := token_check(&key, tok, 1_900_000_000)
	testing.expect_value(t, res, Token_Check.Ok)
	testing.expect_value(t, got, id)
	testing.expect_value(t, end, u32(2_000_000_000))
	// The same id and end give the same token.
	buf2: [TOKEN_MAX]u8
	tok2, _ := token_make(&key, id, 2_000_000_000, buf2[:])
	testing.expect_value(t, tok2, tok)
	// Another id gives another token.
	tok3, _ := token_make(&key, test_id(8), 2_000_000_000, buf2[:])
	testing.expect(t, tok3 != tok)
	// The token does not hold the name: it has the same size for any sign-in.
	testing.expect_value(t, len(tok3), len(tok))
}

@(test)
test_token_expires :: proc(t: ^testing.T) {
	key := test_key(1)
	buf: [TOKEN_MAX]u8
	tok, _ := token_make(&key, test_id(1), 1000, buf[:])
	_, _, res := token_check(&key, tok, 999)
	testing.expect_value(t, res, Token_Check.Ok)
	// The end second itself is over.
	_, end, res2 := token_check(&key, tok, 1000)
	testing.expect_value(t, res2, Token_Check.Expired)
	testing.expect_value(t, end, u32(1000))
	_, _, res = token_check(&key, tok, 5000)
	testing.expect_value(t, res, Token_Check.Expired)
	_, _, res = token_check(&key, tok, -1)
	testing.expect_value(t, res, Token_Check.Expired)
}

@(test)
test_token_wrong_key_and_changes :: proc(t: ^testing.T) {
	key, other := test_key(1), test_key(2)
	buf: [TOKEN_MAX]u8
	tok, _ := token_make(&key, test_id(1), 2_000_000_000, buf[:])
	// A daemon with another key (a restart) refuses it.
	_, _, res := token_check(&other, tok, 1)
	testing.expect_value(t, res, Token_Check.Bad_Tag)
	// Every changed character is refused: the end, the id, the tag.
	changed := 0
	for i in len(TOKEN_PREFIX) ..< len(tok) {
		mod: [TOKEN_MAX]u8
		copy(mod[:], tok)
		mod[i] = 'A' if mod[i] != 'A' else 'B'
		_, _, r := token_check(&key, string(mod[:len(tok)]), 1)
		if r != .Ok {
			changed += 1
		}
	}
	testing.expect_value(t, changed, len(tok) - len(TOKEN_PREFIX))
}

@(test)
test_token_bad_forms :: proc(t: ^testing.T) {
	key := test_key(1)
	cases := [?]string{"", "noirt2.", "noirt2.AAAA", "hunter2", "noirt1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "noirt2.!!!!", "noirt2.AAAAA", "NOIRT2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	for c in cases {
		_, _, res := token_check(&key, c, 1)
		testing.expectf(t, res == .Bad_Form || res == .Bad_Tag, "%q: %v", c, res)
	}
	testing.expect(t, !token_looks_like("NOIRT2.x"))
	testing.expect(t, !token_looks_like("noirt2"))
	testing.expect(t, token_looks_like("noirt2."))
	// The old form (a token with the name in it) is not a token now: it is
	// refused as a damaged one, never as a password.
	testing.expect(t, !token_looks_like("noirt1.AAAA"))
	// Too long for the stock password buffer.
	long := make([]u8, 200, context.temp_allocator)
	copy(long, TOKEN_PREFIX)
	for i in len(TOKEN_PREFIX) ..< len(long) {
		long[i] = 'A'
	}
	_, _, res := token_check(&key, string(long), 1)
	testing.expect_value(t, res, Token_Check.Bad_Form)
}

// ---- the sign-in table

@(test)
test_signin_make_and_check :: proc(t: ^testing.T) {
	tab: Sign_In_Table
	defer signin_destroy(&tab)
	// A name of 255 bytes is held whole.
	long := strings.repeat("n", 255, context.temp_allocator)
	id, ok := signin_add(&tab, long, 5000, 1000)
	testing.expect(t, ok)
	e := signin_find(&tab, id, 1000)
	testing.expect(t, e != nil)
	if e != nil {
		testing.expect_value(t, e.name, long)
		testing.expect_value(t, e.end, u32(5000))
	}
	testing.expect_value(t, signin_count(&tab), 1)
	// Two sign-ins of one name are two entries with two ids.
	id2, ok2 := signin_add(&tab, long, 6000, 1000)
	testing.expect(t, ok2)
	testing.expect(t, id2 != id)
	testing.expect_value(t, signin_count(&tab), 2)
	// A name that is not an identity is refused.
	_, ok = signin_add(&tab, strings.repeat("n", 256, context.temp_allocator), 5000, 1000)
	testing.expect(t, !ok)
	_, ok = signin_add(&tab, "a/b", 5000, 1000)
	testing.expect(t, !ok)
	_, ok = signin_add(&tab, "", 5000, 1000)
	testing.expect(t, !ok)
	testing.expect_value(t, signin_count(&tab), 2)
}

@(test)
test_signin_token_end_to_end_with_long_name :: proc(t: ^testing.T) {
	key := test_key(3)
	tab: Sign_In_Table
	defer signin_destroy(&tab)
	name := strings.repeat("z", 255, context.temp_allocator)
	id, _ := signin_add(&tab, name, 5000, 1000)
	buf: [TOKEN_MAX]u8
	tok, ok := token_make(&key, id, 5000, buf[:])
	testing.expect(t, ok)
	testing.expect(t, len(tok) <= 127)
	got, end, res := token_check(&key, tok, 1500)
	testing.expect_value(t, res, Token_Check.Ok)
	e := signin_find(&tab, got, 1500)
	testing.expect(t, e != nil && e.name == name && e.end == end)
}

@(test)
test_signin_unknown_id_and_expiry :: proc(t: ^testing.T) {
	tab: Sign_In_Table
	defer signin_destroy(&tab)
	testing.expect(t, signin_find(&tab, test_id(1), 1000) == nil)
	id, _ := signin_add(&tab, "erin", 2000, 1000)
	testing.expect(t, signin_find(&tab, id, 1999) != nil)
	// The end second is over, and the entry goes.
	testing.expect(t, signin_find(&tab, id, 2000) == nil)
	testing.expect_value(t, signin_count(&tab), 0)
	testing.expect(t, signin_find(&tab, id, 1000) == nil)
}

@(test)
test_signin_remove :: proc(t: ^testing.T) {
	tab: Sign_In_Table
	defer signin_destroy(&tab)
	a, _ := signin_add(&tab, "erin", 9000, 1000)
	b, _ := signin_add(&tab, "erin", 9000, 1000)
	signin_remove(&tab, a)
	testing.expect(t, signin_find(&tab, a, 1000) == nil)
	testing.expect(t, signin_find(&tab, b, 1000) != nil)
	signin_remove(&tab, a)
	testing.expect_value(t, signin_count(&tab), 1)
}

@(test)
test_signin_full_table :: proc(t: ^testing.T) {
	tab: Sign_In_Table
	defer signin_destroy(&tab)
	// SIGNIN_MAX entries that last, and some that end at 1500.
	for i in 0 ..< SIGNIN_MAX {
		end := u32(9000) if i < SIGNIN_MAX - 10 else 1500
		_, ok := signin_add(&tab, "erin", end, 1000)
		testing.expect(t, ok)
	}
	testing.expect_value(t, signin_count(&tab), SIGNIN_MAX)
	// Full, and nothing has ended: the next one is refused.
	_, ok := signin_add(&tab, "erin", 9000, 1001)
	testing.expect(t, !ok)
	testing.expect_value(t, signin_count(&tab), SIGNIN_MAX)
	// The ended ones go first, then there is room.
	_, ok = signin_add(&tab, "erin", 9000, 1600)
	testing.expect(t, ok)
	testing.expect_value(t, signin_count(&tab), SIGNIN_MAX - 10 + 1)
}

@(test)
test_signin_prune_now_and_then :: proc(t: ^testing.T) {
	tab: Sign_In_Table
	defer signin_destroy(&tab)
	signin_add(&tab, "a", 1100, 1000)
	signin_add(&tab, "b", 1100, 1000)
	signin_add(&tab, "c", 9000, 1000)
	// Not full: the ended entries stay until the next prune time.
	signin_add(&tab, "d", 9000, 1030)
	testing.expect_value(t, signin_count(&tab), 4)
	signin_add(&tab, "e", 9000, 1200)
	testing.expect_value(t, signin_count(&tab), 3)
}

@(test)
test_token_user_is_standard_base64 :: proc(t: ^testing.T) {
	testing.expect_value(t, token_user_b64("erin"), "ZXJpbg==")
}

@(test)
test_web_sso_of :: proc(t: ^testing.T) {
	check :: proc(t: ^testing.T, text: string, want: bool, loc := #caller_location) {
		pi: push.Peer_Info
		_ = push.peer_info_parse(text, &pi)
		testing.expect_value(t, web_sso_of(&pi), want, loc = loc)
	}
	check(t, "IV_VER=2.7.0\nIV_SSO=webauth\n", true)
	check(t, "IV_SSO=openurl,webauth,crtext\n", true)
	check(t, "IV_SSO=webauth,openurl\n", true)
	check(t, "IV_SSO=openurl,crtext\n", false)
	check(t, "IV_SSO=webauthx\n", false)
	check(t, "IV_SSO=\n", false)
	check(t, "IV_VER=2.7.0\n", false)
}

@(test)
test_web_deadline :: proc(t: ^testing.T) {
	testing.expect_value(t, web_deadline(100, 2000, 1000), 100 + 1000 * 1_000_000_000)
	// A token that has ended gives an instant that is not in the future.
	testing.expect(t, web_deadline(100, 1000, 1000) <= 100)
	testing.expect(t, web_deadline(100, 1000, 2000) <= 100)
	testing.expect(t, web_deadline(0, 1000, 2000) != 0)
}
