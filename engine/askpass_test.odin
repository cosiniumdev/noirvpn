// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"
import "noir:proto/config"
import "noir:proto/ossl"

// An encrypted copy of the P-256 test key (passphrase "noir-test-pass"), and
// the key itself. See proto/ossl/testdata/README.md.
@(private = "file")
LOCKED_KEY := #load("../proto/ossl/testdata/keypass_pkcs8_p256.key.pem")
@(private = "file")
PLAIN_KEY := #load("../proto/ossl/testdata/p256_server.key.pem")

@(private = "file")
PRIVATE :: os.Permissions{.Read_User, .Write_User}

@(private = "file")
pass_file :: proc(name, text: string, perm := PRIVATE) -> string {
	dir, err := os.temp_directory(context.temp_allocator)
	if err != nil || dir == "" {
		dir = "/tmp"
	}
	path := fmt.tprintf("%s/noirvpn-askpass-test-%d-%s", dir, os.get_pid(), name)
	_ = os.remove(path)
	_ = os.write_entire_file(path, transmute([]u8)text, perm)
	return path
}

@(private = "file")
has_prefix :: proc(list: []string, prefix: string) -> bool {
	for s in list {
		if strings.has_prefix(s, prefix) {
			return true
		}
	}
	return false
}

@(private = "file")
free_all :: proc(errors, warnings: ^[dynamic]string) {
	for s in errors {
		delete(s)
	}
	for s in warnings {
		delete(s)
	}
	delete(errors^)
	delete(warnings^)
}

@(test)
test_askpass_read_first_line :: proc(t: ^testing.T) {
	buf: [ossl.KEY_PASS_MAX + 2]u8
	cases := [?]struct {
		name, text, want: string,
	}{{"lf", "secret\n", "secret"}, {"crlf", "secret\r\nsecond line\n", "secret"}, {"noeol", "secret", "secret"}, {"spaces", " a b \n", " a b "}}
	for c in cases {
		path := pass_file(c.name, c.text)
		defer os.remove(path)
		n, msg, _ := askpass_read(path, buf[:])
		testing.expectf(t, msg == "", "%s: %s", c.name, msg)
		testing.expectf(t, string(buf[:n]) == c.want, "%s: got %q", c.name, string(buf[:n]))
	}
}

@(test)
test_askpass_read_errors :: proc(t: ^testing.T) {
	buf: [ossl.KEY_PASS_MAX + 2]u8
	_, msg, _ := askpass_read("/nonexistent/key.pass", buf[:])
	testing.expect_value(t, msg, "cannot read /nonexistent/key.pass")

	for text, i in ([]string{"", "\n", "\r\n", "\nsecond line\n"}) {
		path := pass_file(fmt.tprintf("empty%d", i), text)
		defer os.remove(path)
		_, msg, _ = askpass_read(path, buf[:])
		testing.expectf(t, strings.has_suffix(msg, "is empty"), "%q: %s", text, msg)
	}

	long := strings.repeat("x", ossl.KEY_PASS_MAX + 1, context.temp_allocator)
	path := pass_file("long", long)
	defer os.remove(path)
	_, msg, _ = askpass_read(path, buf[:])
	testing.expectf(t, strings.contains(msg, "longer than"), "long: %s", msg)

	path2 := pass_file("max", strings.concatenate({long[1:], "\n"}, context.temp_allocator))
	defer os.remove(path2)
	n, msg2, _ := askpass_read(path2, buf[:])
	testing.expectf(t, msg2 == "" && n == ossl.KEY_PASS_MAX, "max: %d %s", n, msg2)
}

@(test)
test_askpass_read_open_to_others :: proc(t: ^testing.T) {
	when ODIN_OS == .Windows {
		return
	}
	buf: [ossl.KEY_PASS_MAX + 2]u8
	path := pass_file("private", "secret\n")
	defer os.remove(path)
	_, _, open := askpass_read(path, buf[:])
	testing.expect(t, !open)

	path2 := pass_file("shared", "secret\n", PRIVATE + {.Read_Group, .Read_Other})
	defer os.remove(path2)
	_ = os.chmod(path2, PRIVATE + {.Read_Group, .Read_Other}) // past the umask
	_, _, open = askpass_read(path2, buf[:])
	testing.expect(t, open)
}

// One key through `keys_unlock`. The caller frees the key.
@(private = "file")
unlock :: proc(key: []u8, askpass: Maybe(string), ask: Key_Ask, errors, warnings: ^[dynamic]string) -> (out: []u8, wait: bool) {
	out = make([]u8, len(key))
	copy(out, key)
	slots := [1]Key_Slot{{&out, "key"}}
	wait = keys_unlock(askpass, ask, slots[:], errors, warnings)
	return
}

@(test)
test_keys_unlock_with_file :: proc(t: ^testing.T) {
	good := pass_file("good", "noir-test-pass\n")
	defer os.remove(good)
	bad := pass_file("bad", "wrong\n")
	defer os.remove(bad)

	errors, warnings: [dynamic]string
	key, wait := unlock(LOCKED_KEY, good, .Never, &errors, &warnings)
	testing.expectf(t, len(errors) == 0 && len(warnings) == 0, "errors %v, warnings %v", errors, warnings)
	testing.expect(t, !wait)
	testing.expect(t, len(key) > 0 && !ossl.key_pem_encrypted(key))
	delete(key)
	free_all(&errors, &warnings)

	errors, warnings = {}, {}
	key, _ = unlock(LOCKED_KEY, bad, .Never, &errors, &warnings)
	testing.expectf(t, has_prefix(errors[:], "key: the passphrase does not open the key"), "errors %v", errors)
	testing.expect(t, ossl.key_pem_encrypted(key))
	delete(key)
	free_all(&errors, &warnings)

	// An unencrypted key loads as it is; the passphrase has no effect.
	errors, warnings = {}, {}
	key, _ = unlock(PLAIN_KEY, good, .Never, &errors, &warnings)
	testing.expect_value(t, len(errors), 0)
	testing.expect(t, has_prefix(warnings[:], "askpass: no key is encrypted"))
	testing.expect_value(t, string(key), string(PLAIN_KEY))
	delete(key)
	free_all(&errors, &warnings)

	// The file is read even when no key needs it.
	empty := pass_file("emptyfile", "")
	defer os.remove(empty)
	for path in ([]string{empty, "/nonexistent/key.pass"}) {
		errors, warnings = {}, {}
		key, _ = unlock(PLAIN_KEY, path, .Never, &errors, &warnings)
		testing.expectf(t, has_prefix(errors[:], "askpass: "), "%s: errors %v", path, errors)
		delete(key)
		free_all(&errors, &warnings)
	}
}

@(test)
test_keys_unlock_without_file :: proc(t: ^testing.T) {
	errors, warnings: [dynamic]string

	// No askpass at all.
	key, wait := unlock(LOCKED_KEY, nil, .Later, &errors, &warnings)
	testing.expectf(t, has_prefix(errors[:], "key: the key is encrypted, so give its passphrase with askpass FILE"), "errors %v", errors)
	testing.expect(t, !wait)
	delete(key)
	free_all(&errors, &warnings)

	// `askpass` alone: only a terminal can give the passphrase.
	errors, warnings = {}, {}
	key, wait = unlock(LOCKED_KEY, "", .Later, &errors, &warnings)
	testing.expect(t, wait)
	testing.expect_value(t, len(errors), 0)
	delete(key)
	free_all(&errors, &warnings)

	errors, warnings = {}, {}
	key, wait = unlock(LOCKED_KEY, "", .Never, &errors, &warnings)
	testing.expect(t, !wait)
	testing.expectf(t, has_prefix(errors[:], "askpass: the key is encrypted, and there is no terminal") && strings.contains(errors[0], "askpass FILE"), "errors %v", errors)
	delete(key)
	free_all(&errors, &warnings)

	errors, warnings = {}, {}
	key, wait = unlock(LOCKED_KEY, "", .Check, &errors, &warnings)
	testing.expect(t, !wait)
	testing.expect_value(t, len(errors), 0)
	testing.expect(t, has_prefix(warnings[:], "askpass: the passphrase will be typed at the terminal at start"))
	delete(key)
	free_all(&errors, &warnings)

	errors, warnings = {}, {}
	// A profile of the client service: the passphrase comes with `auth.supply`.
	key, wait = unlock(LOCKED_KEY, "", .Profile, &errors, &warnings)
	testing.expect(t, wait)
	testing.expect_value(t, len(errors), 0)
	delete(key)
	free_all(&errors, &warnings)

	// An unencrypted key: nobody is asked.
	errors, warnings = {}, {}
	key, wait = unlock(PLAIN_KEY, "", .Never, &errors, &warnings)
	testing.expect(t, !wait)
	testing.expect_value(t, len(errors), 0)
	delete(key)
	free_all(&errors, &warnings)
}

@(test)
test_settings_load_decrypts_the_key :: proc(t: ^testing.T) {
	good := pass_file("settings", "noir-test-pass\n")
	defer os.remove(good)
	text := fmt.tprintf("client\nremote vpn.example.com 1194\nca /nonexistent/ca.crt\ncert /nonexistent/c.crt\n<key>\n%s</key>\naskpass %s\n", string(LOCKED_KEY), good)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	s: Settings
	defer settings_destroy(&s)
	_ = settings_load(&s, &cfg)
	testing.expect(t, !has_prefix(s.errors[:], "key:") && !has_prefix(s.errors[:], "askpass"))
	testing.expect(t, len(s.key_pem) > 0 && !ossl.key_pem_encrypted(s.key_pem))
	testing.expect(t, !s.key_wait)
}
