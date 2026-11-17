// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:os"
import "core:strings"
import "core:testing"

// A path for a profile line: the lexer reads a backslash as an escape.
@(private = "file")
slashes :: proc(p: string) -> string {
	out, _ := strings.replace_all(p, "\\", "/", context.temp_allocator)
	return out
}

@(test)
test_import_inlines_keys :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_write(t, dir, "ca.crt", PEM_CA)
	test_write(t, dir, "client.key", "-----BEGIN PRIVATE KEY-----\nMIGkey\n-----END PRIVATE KEY-----")
	test_mkdir(t, dir, "keys")
	test_write(t, dir, "keys/tc.key", STATIC_KEY)
	text := "# my profile\r\nclient\r\nremote vpn.example 443 udp\r\n  ca ca.crt   # the CA\r\nkey \"client.key\"\r\n; tls\r\ntls-crypt keys/tc.key\r\nverb 3"
	r := import_text(text, dir)
	defer import_destroy(&r)
	testing.expectf(t, r.ok, "problems: %v", r.problems)
	want :=
		"# my profile\r\nclient\r\nremote vpn.example 443 udp\r\n" +
		"<ca>\n" + PEM_CA + "</ca>\n" +
		"<key>\n-----BEGIN PRIVATE KEY-----\nMIGkey\n-----END PRIVATE KEY-----\n</key>\n" +
		"; tls\r\n" +
		"<tls-crypt>\n" + STATIC_KEY + "</tls-crypt>\n" +
		"verb 3"
	testing.expect_value(t, r.text, want)
	testing.expect_value(t, len(r.problems), 0)
	testing.expect(t, r.summary.has_ca && r.summary.has_key && r.summary.has_tls_crypt)
	testing.expect_value(t, len(r.summary.remotes), 1)
	testing.expect_value(t, r.name, "")
}

@(test)
test_import_tls_auth_direction :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_write(t, dir, "ta.key", STATIC_KEY)
	r := import_text("tls-auth ta.key 1\nremote a\n", dir)
	defer import_destroy(&r)
	testing.expect(t, r.ok)
	testing.expect_value(t, r.text, "<tls-auth>\n" + STATIC_KEY + "</tls-auth>\nkey-direction 1\nremote a\n")
	testing.expect(t, r.summary.has_tls_auth)
}

@(test)
test_import_keeps_inline :: proc(t: ^testing.T) {
	text := "\xef\xbb\xbfclient\nca [inline]\n<ca>\r\nAAA\r\n</ca>\n<cert>\nBBB\n</cert>\n"
	r := import_text(text, "")
	defer import_destroy(&r)
	testing.expect(t, r.ok)
	testing.expect_value(t, r.text, text[3:])
}

@(test)
test_import_bom_lines :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_write(t, dir, "ca.crt", "\xef\xbb\xbf" + PEM_CA)
	r := import_text("\xef\xbb\xbfclient\nca ca.crt\nlog x.log\n", dir)
	defer import_destroy(&r)
	testing.expect(t, !r.ok)
	testing.expect(t, has_problem(r.problems[:], true, 3, MSG_NAMES_FILE))
	testing.expect_value(t, r.text, "")

	r2 := import_text("\xef\xbb\xbfclient\nca ca.crt\n", dir)
	defer import_destroy(&r2)
	testing.expect(t, r2.ok)
	testing.expect_value(t, r2.text, "client\n<ca>\n" + PEM_CA + "</ca>\n")
}

@(test)
test_import_connection_block :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_write(t, dir, "ta.key", STATIC_KEY)
	text := "client\n<connection>\nremote a 1194\ntls-auth ta.key 0\n</connection>\n<connection>\nremote b 443 tcp\n</connection>\n"
	r := import_text(text, dir)
	defer import_destroy(&r)
	testing.expectf(t, r.ok, "problems: %v", r.problems)
	want :=
		"client\n<connection>\nremote a 1194\n<tls-auth>\n" + STATIC_KEY +
		"</tls-auth>\nkey-direction 0\n</connection>\n<connection>\nremote b 443 tcp\n</connection>\n"
	testing.expect_value(t, r.text, want)
	testing.expect_value(t, len(r.summary.remotes), 2)
	testing.expect_value(t, r.summary.remotes[1].proto, "tcp")
}

@(test)
test_import_subfolder_and_absolute :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	sub := test_mkdir(t, dir, "sub")
	abs := test_write(t, sub, "ca.crt", PEM_CA)
	text := strings.concatenate({"ca \"", slashes(abs), "\"\n"}, context.temp_allocator)
	r := import_text(text, dir)
	defer import_destroy(&r)
	testing.expectf(t, r.ok, "problems: %v", r.problems)

	// The same file seen from a folder below it is outside.
	r2 := import_text("ca ../sub/ca.crt\n", test_mkdir(t, dir, "other"))
	defer import_destroy(&r2)
	testing.expect(t, !r2.ok)
	testing.expect(t, has_problem(r2.problems[:], true, 1, "outside the folder"))
}

@(test)
test_import_path_escape :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	inner := test_mkdir(t, dir, "profile")
	outside := test_write(t, dir, "secret.key", PEM_KEY)
	r := import_text("key ../secret.key\n", inner)
	defer import_destroy(&r)
	testing.expect(t, !r.ok)
	testing.expect(t, has_problem(r.problems[:], true, 1, "file '../secret.key' is outside the folder of the profile"))
	testing.expect_value(t, r.problems[0].option, "key")

	text := strings.concatenate({"key \"", slashes(outside), "\"\n"}, context.temp_allocator)
	r2 := import_text(text, inner)
	defer import_destroy(&r2)
	testing.expect(t, has_problem(r2.problems[:], true, 1, "outside the folder"))
}

@(test)
test_import_symlink :: proc(t: ^testing.T) {
	when ODIN_OS == .Windows {
		return
	}
	dir := test_dir(t)
	defer test_dir_remove(dir)
	inner := test_mkdir(t, dir, "profile")
	outside := test_write(t, dir, "secret.key", PEM_KEY)
	link, _ := os.join_path({inner, "client.key"}, context.temp_allocator)
	testing.expect(t, os.symlink(outside, link) == nil)
	r := import_text("key client.key\n", inner)
	defer import_destroy(&r)
	testing.expect(t, !r.ok)
	testing.expect(t, has_problem(r.problems[:], true, 1, "outside the folder"))

	// A link that stays inside is fine.
	real := test_write(t, inner, "real.crt", PEM_CA)
	link2, _ := os.join_path({inner, "ca.crt"}, context.temp_allocator)
	testing.expect(t, os.symlink(real, link2) == nil)
	r2 := import_text("ca ca.crt\n", inner)
	defer import_destroy(&r2)
	testing.expectf(t, r2.ok, "problems: %v", r2.problems)

	// The folder itself may be a link.
	flink, _ := os.join_path({dir, "flink"}, context.temp_allocator)
	testing.expect(t, os.symlink(inner, flink) == nil)
	r3 := import_text("ca ca.crt\n", flink)
	defer import_destroy(&r3)
	testing.expectf(t, r3.ok, "problems: %v", r3.problems)
}

@(test)
test_import_bad_files :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_mkdir(t, dir, "keys")
	test_write(t, dir, "big.crt", strings.repeat("A", FILE_MAX + 1, context.temp_allocator))
	test_write(t, dir, "bin.p12", "\x30\x82\x00\x01")
	test_write(t, dir, "tag.crt", "AAA\n</ca>\nBBB\n")
	r := import_text("ca missing.crt\ncert keys\nca big.crt\npkcs12 bin.p12\nca tag.crt\n", dir)
	defer import_destroy(&r)
	testing.expect(t, !r.ok)
	testing.expect(t, has_problem(r.problems[:], true, 1, "file 'missing.crt' not found"))
	testing.expect(t, has_problem(r.problems[:], true, 2, "'keys' is not a file"))
	testing.expect(t, has_problem(r.problems[:], true, 3, "larger than 1 MiB"))
	testing.expect(t, has_problem(r.problems[:], true, 4, "not a text file"))
	testing.expect(t, has_problem(r.problems[:], true, 5, "contains the line </ca>"))
	testing.expect_value(t, len(r.problems), 5)

	r2 := import_text("ca ca.crt\n", "")
	defer import_destroy(&r2)
	testing.expect(t, has_problem(r2.problems[:], true, 1, "folder of the profile is not known"))
}

@(test)
test_import_file_options :: proc(t: ^testing.T) {
	text := `config other.conf
cd /etc/openvpn
log /tmp/x.log
status /tmp/status 10
askpass pass.txt
management /run/m.sock unix
management 127.0.0.1 7505 pw.txt
http-proxy proxy.example 3128 creds.txt basic
writepid /run/x.pid
crl-verify crl dir
capath /etc/ssl
`
	r := import_text(text, "")
	defer import_destroy(&r)
	testing.expect(t, !r.ok)
	for line in 1 ..= 9 {
		if line == 5 {
			// `askpass FILE` stays: the app reads the file at connect.
			testing.expect(t, has_problem(r.problems[:], false, line, "not a full path"))
			continue
		}
		testing.expectf(t, has_problem(r.problems[:], true, line, MSG_NAMES_FILE), "line %d", line)
	}
	testing.expect(t, has_problem(r.problems[:], true, 10, "CRL directory"))
	testing.expect(t, has_problem(r.problems[:], true, 11, MSG_NAMES_FILE))
	// The refused include gives one problem only.
	testing.expect_value(t, len(r.problems), 11)
	testing.expect_value(t, r.problems[0].option, "config")
}

@(test)
test_import_harmless_options :: proc(t: ^testing.T) {
	text := "askpass\nhttp-proxy p.example 3128 auto basic\nmanagement 127.0.0.1 7505\nverb 3\n"
	r := import_text(text, "")
	defer import_destroy(&r)
	testing.expectf(t, r.ok, "problems: %v", r.problems)
	testing.expect_value(t, r.text, text)
}

@(test)
test_import_auth_user_pass :: proc(t: ^testing.T) {
	// A file: the line stays. The app reads the file at connect; with no
	// folder the relative path cannot be expanded to a full path.
	r := import_text("client\nauth-user-pass creds.txt\nremote a\n", "")
	defer import_destroy(&r)
	testing.expect(t, r.ok)
	testing.expect_value(t, r.text, "client\nauth-user-pass creds.txt\nremote a\n")
	testing.expect(t, has_problem(r.problems[:], false, 2, "not a full path"))
	testing.expect(t, r.summary.user_pass)

	r2 := import_text("client\n<auth-user-pass>\nme\nsecret\n</auth-user-pass>\nremote a\n", "")
	defer import_destroy(&r2)
	testing.expect(t, r2.ok)
	testing.expect_value(t, r2.text, "client\nauth-user-pass\nremote a\n")
	testing.expect_value(t, len(r2.problems), 1)
	testing.expect(t, has_problem(r2.problems[:], false, 2, "add auth-user-pass /path/to/file"))

	r3 := import_text("auth-user-pass\n", "")
	defer import_destroy(&r3)
	testing.expect(t, r3.ok)
	testing.expect_value(t, r3.text, "auth-user-pass\n")
	testing.expect_value(t, len(r3.problems), 0)
}

@(test)
test_import_crl_file :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_write(t, dir, "crl.pem", "-----BEGIN X509 CRL-----\nx\n-----END X509 CRL-----\n")
	r := import_text("crl-verify crl.pem\n", dir)
	defer import_destroy(&r)
	testing.expect(t, r.ok)
	testing.expect(t, strings.has_prefix(r.text, "<crl-verify>\n-----BEGIN X509 CRL-----"))
}

@(test)
test_import_syntax_errors :: proc(t: ^testing.T) {
	r := import_text("client\nremote \"a\n<ca>\nAAA\n", "")
	defer import_destroy(&r)
	testing.expect(t, !r.ok)
	testing.expect(t, has_problem(r.problems[:], true, 2, "quote is not closed"))
	testing.expect(t, has_problem(r.problems[:], true, 3, "not closed"))
}

@(test)
test_import_too_large :: proc(t: ^testing.T) {
	r := import_text(strings.repeat("#", FILE_MAX + 1, context.temp_allocator), "")
	defer import_destroy(&r)
	testing.expect(t, !r.ok)
	testing.expect(t, has_problem(r.problems[:], true, 0, "larger than 1 MiB"))

	dir := test_dir(t)
	defer test_dir_remove(dir)
	block := strings.repeat("A", 100_000, context.temp_allocator)
	test_write(t, dir, "a.crt", block)
	test_write(t, dir, "b.crt", block)
	test_write(t, dir, "c.crt", block)
	r2 := import_text("ca a.crt\ncert b.crt\nextra-certs c.crt\n", dir)
	defer import_destroy(&r2)
	testing.expect(t, !r2.ok)
	testing.expect(t, has_problem(r2.problems[:], true, 0, "larger than 256 KiB"))
}

@(test)
test_import_file :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_write(t, dir, "ca.crt", PEM_CA)
	path := test_write(t, dir, "Office VPN.ovpn", "client\nca ca.crt\n")
	r := import_file(path)
	defer import_destroy(&r)
	testing.expectf(t, r.ok, "problems: %v", r.problems)
	testing.expect_value(t, r.name, "Office VPN")
	testing.expect_value(t, r.text, "client\n<ca>\n" + PEM_CA + "</ca>\n")

	missing, _ := os.join_path({dir, "none.ovpn"}, context.temp_allocator)
	r2 := import_file(missing)
	defer import_destroy(&r2)
	testing.expect(t, !r2.ok)
	testing.expect(t, has_problem(r2.problems[:], true, 0, "not found"))
	testing.expect_value(t, r2.name, "none")

	big := test_write(t, dir, "big.conf", strings.repeat("#", FILE_MAX + 1, context.temp_allocator))
	r3 := import_file(big)
	defer import_destroy(&r3)
	testing.expect(t, has_problem(r3.problems[:], true, 0, "larger than 1 MiB"))

	r4 := import_file(dir)
	defer import_destroy(&r4)
	testing.expect(t, has_problem(r4.problems[:], true, 0, "is not a file"))
}

@(test)
test_import_secret_files :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	test_write(t, dir, "login.txt", "alice\npw\n")
	login := test_write(t, dir, "my key.pass", "pass\n")
	_ = os.chmod(login, {.Read_User, .Write_User})
	r := import_text("client\nauth-user-pass login.txt\naskpass \"my key.pass\"\nremote a\n", dir)
	defer import_destroy(&r)
	testing.expectf(t, r.ok, "%v", r.problems)
	// Relative paths are expanded to full paths, with quotes when they need them.
	testing.expectf(t, strings.contains(r.text, "\nauth-user-pass ") && strings.contains(r.text, "/login.txt\n"), "%s", r.text)
	testing.expectf(t, strings.contains(r.text, "\naskpass \"") && strings.contains(r.text, "/my key.pass\"\n"), "%s", r.text)
	testing.expect(t, strings.has_prefix(r.summary.login_file, "/") && strings.has_suffix(r.summary.pass_file, "/my key.pass"))
	// login.txt has the mode of a new file (0644 or so): a problem, not fatal.
	if p, ok := os.lstat(strings.concatenate({dir, "/login.txt"}, context.temp_allocator), context.temp_allocator); ok == nil && p.mode & {.Read_Group, .Read_Other} != {} {
		testing.expect(t, has_problem(r.problems[:], false, 2, "chmod 600"))
	}
	testing.expect(t, !has_problem(r.problems[:], false, 3, ""))
	// `auth-user-pass username-only` names no file.
	q := import_text("auth-user-pass username-only\n", dir)
	defer import_destroy(&q)
	testing.expect(t, q.ok && q.summary.login_file == "")
}
