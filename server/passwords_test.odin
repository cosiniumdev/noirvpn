// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:strings"
import "core:testing"

// 16 bytes of salt and 32 bytes of hash, in base64.
@(private = "file")
SALT :: "AAECAwQFBgcICQoLDA0ODw=="
@(private = "file")
HASH :: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

@(private = "file")
line :: proc(user: string, its := 1000, salt := SALT, hash := HASH) -> string {
	return strings.concatenate({user, "\tpbkdf2-sha256:", itoa_t(its), ":", salt, ":", hash, "\n"}, context.temp_allocator)
}

@(private = "file")
itoa_t :: proc(n: int) -> string {
	buf: [24]u8
	i := len(buf)
	v := n
	if v == 0 {
		return "0"
	}
	for v > 0 {
		i -= 1
		buf[i] = u8('0' + v % 10)
		v /= 10
	}
	return strings.clone(string(buf[i:]), context.temp_allocator)
}

@(test)
test_pw_parse_one_line :: proc(t: ^testing.T) {
	tab := pw_parse(line("alice", 260000))
	defer pw_destroy(tab)
	testing.expect_value(t, pw_len(tab), 1)
	testing.expect_value(t, len(tab.warnings), 0)
	e := pw_find(tab, "alice")
	testing.expect(t, e != nil)
	testing.expect_value(t, e.iterations, 260000)
	testing.expect_value(t, int(e.salt_n), 16)
	testing.expect_value(t, int(e.hash_n), 32)
	testing.expect_value(t, e.salt[15], u8(15))
	testing.expect_value(t, e.hash[31], u8(31))
}

@(test)
test_pw_find_folds_case :: proc(t: ^testing.T) {
	tab := pw_parse(line("Alice"))
	defer pw_destroy(tab)
	for name in ([]string{"alice", "ALICE", "aLiCe", "Alice"}) {
		e := pw_find(tab, name)
		testing.expectf(t, e != nil, "%s", name)
		if e != nil {
			testing.expect_value(t, e.user, "Alice")
		}
	}
	testing.expect(t, pw_find(tab, "alic") == nil)
	testing.expect(t, pw_find(tab, "") == nil)
	testing.expect(t, pw_find(nil, "alice") == nil)
}

@(test)
test_pw_non_ascii_names_match_bytes :: proc(t: ^testing.T) {
	tab := pw_parse(line("Élodie"))
	defer pw_destroy(tab)
	testing.expect(t, pw_find(tab, "Élodie") != nil)
	testing.expect(t, pw_find(tab, "élodie") == nil)
}

@(test)
test_pw_duplicate_names_first_counts :: proc(t: ^testing.T) {
	text := strings.concatenate({line("bob", 1000), line("BOB", 2000), line("carol")}, context.temp_allocator)
	tab := pw_parse(text)
	defer pw_destroy(tab)
	testing.expect_value(t, pw_len(tab), 2)
	testing.expect_value(t, tab.duplicates, 1)
	testing.expect_value(t, len(tab.warnings), 1)
	e := pw_find(tab, "bob")
	testing.expect(t, e != nil && e.iterations == 1000 && e.user == "bob")
}

@(test)
test_pw_bad_lines_left_out :: proc(t: ^testing.T) {
	bad := []string {
		"nobody\n", // no TAB
		"u1\tpbkdf2-sha256:1000:AAECAwQFBgcICQoLDA0ODw==\n", // missing field
		"u2\tpbkdf2-sha1:1000:" + SALT + ":" + HASH + "\n", // scheme
		"u3\tpbkdf2-sha256:0:" + SALT + ":" + HASH + "\n", // iterations
		"u4\tpbkdf2-sha256:10000001:" + SALT + ":" + HASH + "\n",
		"u5\tpbkdf2-sha256:12a:" + SALT + ":" + HASH + "\n",
		"u6\tpbkdf2-sha256:-5:" + SALT + ":" + HASH + "\n",
		"u7\tpbkdf2-sha256:1000:" + SALT + "x:" + HASH + "\n", // base64 length
		"u8\tpbkdf2-sha256:1000:AAECAwQFBgcICQoLDA0ODw:" + HASH + "\n", // no padding
		"u9\tpbkdf2-sha256:1000:" + SALT + ":AAECAwQFBgcI\n", // hash too short
		"/x\tpbkdf2-sha256:1000:" + SALT + ":" + HASH + "\n", // user name
		"\tpbkdf2-sha256:1000:" + SALT + ":" + HASH + "\n", // no user name
		"u10\tpbkdf2-sha256:1000:" + SALT + ":" + HASH + ":extra\n",
	}
	for b in bad {
		tab := pw_parse(b)
		testing.expectf(t, pw_len(tab) == 0, "accepted: %s", b)
		testing.expectf(t, tab.skipped == 1 || len(b) == 0, "not counted: %s", b)
		for w in tab.warnings {
			// A warning never repeats the hash text.
			testing.expect(t, !strings.contains(w, HASH))
		}
		pw_destroy(tab)
	}
}

@(test)
test_pw_salt_and_hash_limits :: proc(t: ^testing.T) {
	// 64 bytes of hash is the most, 65 is refused.
	h64 := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="
	h65 := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A="
	tab := pw_parse(line("a", 1, SALT, h64))
	testing.expect_value(t, pw_len(tab), 1)
	testing.expect_value(t, int(tab.entries[0].hash_n), 64)
	pw_destroy(tab)
	tab = pw_parse(line("a", 1, SALT, h65))
	testing.expect_value(t, pw_len(tab), 0)
	pw_destroy(tab)
	tab = pw_parse(line("a", 1, h64, HASH))
	testing.expect_value(t, int(tab.entries[0].salt_n), 64)
	pw_destroy(tab)
	tab = pw_parse(line("a", 1, h65, HASH))
	testing.expect_value(t, pw_len(tab), 0)
	pw_destroy(tab)
	tab = pw_parse(line("a", PW_MAX_ITERATIONS))
	testing.expect_value(t, pw_len(tab), 1)
	pw_destroy(tab)
}

@(test)
test_pw_comments_blank_and_crlf :: proc(t: ^testing.T) {
	text := strings.concatenate({"# users\n\n   \n", "dave\tpbkdf2-sha256:5:", SALT, ":", HASH, "\r\n", "erin\tpbkdf2-sha256:6:", SALT, ":", HASH}, context.temp_allocator)
	tab := pw_parse(text)
	defer pw_destroy(tab)
	testing.expect_value(t, pw_len(tab), 2)
	testing.expect_value(t, len(tab.warnings), 0)
	testing.expect(t, pw_find(tab, "erin") != nil)
	testing.expect_value(t, pw_find(tab, "dave").iterations, 5)
}

@(test)
test_pw_long_line_left_out :: proc(t: ^testing.T) {
	long := strings.repeat("x", PW_LINE_MAX, context.temp_allocator)
	tab := pw_parse(strings.concatenate({long, "\tpbkdf2-sha256:1:", SALT, ":", HASH, "\n"}, context.temp_allocator))
	defer pw_destroy(tab)
	testing.expect_value(t, pw_len(tab), 0)
	testing.expect_value(t, tab.skipped, 1)
}

@(test)
test_b64_decode :: proc(t: ^testing.T) {
	out: [8]u8
	n, ok := b64_decode("Zm9v", out[:])
	testing.expect(t, ok && n == 3 && string(out[:3]) == "foo")
	n, ok = b64_decode("Zm9vYg==", out[:])
	testing.expect(t, ok && n == 4 && string(out[:4]) == "foob")
	n, ok = b64_decode("Zm9vYmE=", out[:])
	testing.expect(t, ok && n == 5 && string(out[:5]) == "fooba")
	_, ok = b64_decode("Zm9vYh==", out[:]) // spare bits are not zero
	testing.expect(t, !ok)
	_, ok = b64_decode("Zm9=YmE=", out[:]) // padding in the middle
	testing.expect(t, !ok)
	_, ok = b64_decode("Zm9v YmE=", out[:])
	testing.expect(t, !ok)
	_, ok = b64_decode("Zm9vYmFy", out[:2]) // does not fit
	testing.expect(t, !ok)
	_, ok = b64_decode("", out[:])
	testing.expect(t, !ok)
}

@(test)
test_pw_diff :: proc(t: ^testing.T) {
	old := pw_parse(strings.concatenate({line("gone"), line("same"), line("Chg", 1000)}, context.temp_allocator))
	defer pw_destroy(old)
	// "chg" keeps its name in another case and gets a new hash line.
	new_ := pw_parse(strings.concatenate({line("SAME"), line("chg", 2000), line("fresh")}, context.temp_allocator))
	defer pw_destroy(new_)
	ch := pw_diff(old, new_)
	defer pw_changes_destroy(&ch)
	kinds: map[string]Pw_Change_Kind
	kinds.allocator = context.temp_allocator
	for c in ch {
		kinds[c.user] = c.kind
	}
	testing.expect_value(t, len(ch), 3)
	testing.expect_value(t, kinds["gone"], Pw_Change_Kind.Removed)
	testing.expect_value(t, kinds["chg"], Pw_Change_Kind.Changed)
	testing.expect_value(t, kinds["fresh"], Pw_Change_Kind.Added)
	// No old table: every user is new.
	ch2 := pw_diff(nil, new_)
	defer pw_changes_destroy(&ch2)
	testing.expect_value(t, len(ch2), 3)
	// No new table: every user is gone.
	ch3 := pw_diff(old, nil)
	defer pw_changes_destroy(&ch3)
	testing.expect_value(t, len(ch3), 3)
}

@(test)
test_pw_decoy_follows_the_file :: proc(t: ^testing.T) {
	short_salt := "AAECAwQFBgc=" // 8 bytes
	short_hash := "AAECAwQFBgcICQoLDA0ODw==" // 16 bytes
	// The count that most lines have: 5000. The lengths are those of its first line.
	text := strings.concatenate({line("a", 7000, short_salt, short_hash), line("b", 5000), line("c", 5000), line("d", 7000, short_salt, short_hash), line("e", 5000)}, context.temp_allocator)
	tbl := pw_parse(text)
	defer pw_destroy(tbl)
	its, salt_n, hash_n := pw_decoy(tbl)
	testing.expect_value(t, its, 5000)
	testing.expect_value(t, salt_n, 16)
	testing.expect_value(t, hash_n, 32)

	// A tie goes to the larger count and its lengths.
	text2 := strings.concatenate({line("a", 3000), line("b", 9000, short_salt, short_hash), line("c", 3000), line("d", 9000, short_salt, short_hash)}, context.temp_allocator)
	tbl2 := pw_parse(text2)
	defer pw_destroy(tbl2)
	its, salt_n, hash_n = pw_decoy(tbl2)
	testing.expect_value(t, its, 9000)
	testing.expect_value(t, salt_n, 8)
	testing.expect_value(t, hash_n, 16)

	// An empty or missing table: the defaults.
	empty := pw_parse("# nobody\n")
	defer pw_destroy(empty)
	for tb in ([]^Pw_Table{empty, nil}) {
		its, salt_n, hash_n = pw_decoy(tb)
		testing.expect_value(t, its, PW_DECOY_ITERATIONS)
		testing.expect_value(t, salt_n, 16)
		testing.expect_value(t, hash_n, 32)
	}
}
