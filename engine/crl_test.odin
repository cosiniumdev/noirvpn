// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"
import "noir:proto/config"

// A CRL of the intermediate of the test PKI of proto/ossl, and one that is out of date.
@(private = "file")
GOOD_CRL := #load("../proto/ossl/testdata/crl_sub_empty.crl.pem")
@(private = "file")
EXPIRED_CRL := #load("../proto/ossl/testdata/crl_sub_expired.crl.pem")

// ---- the decision, with no files and no clock ----

@(test)
test_crl_decide :: proc(t: ^testing.T) {
	a := Crl_Stat{ok = true, mtime_ns = 100, size = 10, ino = 7}
	// Nothing changed: keep.
	testing.expect_value(t, crl_decide(a, false, a), Crl_Action.Keep)
	// A new time, size or file: read again.
	b := a
	b.mtime_ns += 1
	testing.expect_value(t, crl_decide(a, false, b), Crl_Action.Reload)
	b = a
	b.size = 11
	testing.expect_value(t, crl_decide(a, false, b), Crl_Action.Reload)
	b = a
	b.ino = 8
	testing.expect_value(t, crl_decide(a, false, b), Crl_Action.Reload)
	// The stat fails: the list is lost, once.
	testing.expect_value(t, crl_decide(a, false, {}), Crl_Action.Lose)
	testing.expect_value(t, crl_decide(a, true, {}), Crl_Action.Keep)
	// A lost list is read again whatever the stat says.
	testing.expect_value(t, crl_decide(a, true, a), Crl_Action.Reload)
	testing.expect_value(t, crl_decide({}, true, a), Crl_Action.Reload)
}

@(test)
test_crl_poll_due :: proc(t: ^testing.T) {
	testing.expect(t, crl_poll_due(0, 5), "the first look is always due")
	testing.expect(t, !crl_poll_due(1_000, 1_000 + CRL_POLL_NS - 1))
	testing.expect(t, crl_poll_due(1_000, 1_000 + CRL_POLL_NS))
	testing.expect(t, crl_poll_due(5_000_000_000, 1_000), "the clock went back")
}

// ---- the config check ----

// The folder for test files: /tmp on Linux, %TEMP% on Windows.
@(private = "file")
tmp_dir :: proc() -> string {
	dir, err := os.temp_directory(context.temp_allocator)
	return dir if err == nil && dir != "" else "/tmp"
}

@(private = "file")
tmp_file :: proc(name: string, data: []u8) -> string {
	path := fmt.aprintf("%s/noirvpn-crl-test-%d-%s", tmp_dir(), os.get_pid(), name)
	_ = os.write_entire_file(path, data)
	return path
}

@(private = "file")
init_with :: proc(path: string, dir: bool, errors, warnings: ^[dynamic]string, cs: ^Crl_State) -> bool {
	c := config.Crl_Verify {
		src = config.Key_Source{path = path},
		dir = dir,
	}
	return crl_init(cs, c, transmute([]u8)string("CA"), true, errors, warnings)
}

@(private = "file")
free_strings :: proc(l: ^[dynamic]string) {
	for s in l {
		delete(s)
	}
	delete(l^)
}

@(test)
test_crl_init_good_file :: proc(t: ^testing.T) {
	path := tmp_file("good.pem", GOOD_CRL)
	defer delete(path)
	defer os.remove(path)
	errors, warnings: [dynamic]string
	defer free_strings(&errors)
	defer free_strings(&warnings)
	cs: Crl_State
	defer crl_destroy(&cs)
	testing.expect(t, init_with(path, false, &errors, &warnings, &cs))
	testing.expect_value(t, len(errors), 0)
	testing.expect_value(t, len(warnings), 0)
	testing.expect_value(t, cs.count, 1)
	testing.expect(t, cs.loaded.ok)
}

@(test)
test_crl_init_missing_file :: proc(t: ^testing.T) {
	errors, warnings: [dynamic]string
	defer free_strings(&errors)
	defer free_strings(&warnings)
	cs: Crl_State
	defer crl_destroy(&cs)
	testing.expect(t, !init_with("/nonexistent/crl.pem", false, &errors, &warnings, &cs))
	testing.expect_value(t, len(errors), 1)
	testing.expect_value(t, errors[0], "crl-verify: cannot read /nonexistent/crl.pem")
}

@(test)
test_crl_init_empty_and_garbage_file :: proc(t: ^testing.T) {
	for data, i in ([]string{"", "this is not a CRL\n", "-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n"}) {
		path := tmp_file(fmt.tprintf("bad%d.pem", i), transmute([]u8)data)
		defer delete(path)
		defer os.remove(path)
		errors, warnings: [dynamic]string
		defer free_strings(&errors)
		defer free_strings(&warnings)
		cs: Crl_State
		defer crl_destroy(&cs)
		testing.expect(t, !init_with(path, false, &errors, &warnings, &cs))
		testing.expect_value(t, len(errors), 1)
		testing.expectf(t, len(errors) == 1 && strings.contains(errors[0], "crl-verify:") && strings.contains(errors[0], "does not contain a CRL"), "case %d: %v", i, errors)
	}
}

@(test)
test_crl_init_expired_crl_warns :: proc(t: ^testing.T) {
	path := tmp_file("expired.pem", EXPIRED_CRL)
	defer delete(path)
	defer os.remove(path)
	errors, warnings: [dynamic]string
	defer free_strings(&errors)
	defer free_strings(&warnings)
	cs: Crl_State
	defer crl_destroy(&cs)
	testing.expect(t, init_with(path, false, &errors, &warnings, &cs), "an expired CRL is not a start-up error")
	testing.expect_value(t, len(warnings), 1)
	testing.expectf(t, len(warnings) == 1 && strings.contains(warnings[0], "has expired") && strings.contains(warnings[0], "noir-test-crl-sub"), "%v", warnings)
}

@(test)
test_crl_init_directory :: proc(t: ^testing.T) {
	errors, warnings: [dynamic]string
	defer free_strings(&errors)
	defer free_strings(&warnings)
	cs: Crl_State
	defer crl_destroy(&cs)
	testing.expect(t, !init_with("/nonexistent/crls", true, &errors, &warnings, &cs))
	testing.expect_value(t, len(errors), 1)
	testing.expect(t, strings.contains(errors[0], "/nonexistent/crls is not a directory"))

	// A directory that exists is fine; a file as the directory is not.
	cs2: Crl_State
	defer crl_destroy(&cs2)
	errors2, warnings2: [dynamic]string
	defer free_strings(&errors2)
	defer free_strings(&warnings2)
	testing.expect(t, init_with(tmp_dir(), true, &errors2, &warnings2, &cs2))
	testing.expect_value(t, len(errors2), 0)
}

@(test)
test_crl_dir_check :: proc(t: ^testing.T) {
	dir := fmt.aprintf("%s/noirvpn-crl-dir-%d", tmp_dir(), os.get_pid())
	defer delete(dir)
	_ = os.make_directory(dir)
	defer os.remove(dir)
	cs := Crl_State {
		on   = true,
		dir  = true,
		path = dir,
	}
	file := fmt.aprintf("%s/3002", dir)
	defer delete(file)
	testing.expect(t, !crl_dir_check("3002", 0, &cs), "no file: not revoked")
	_ = os.write_entire_file(file, nil)
	testing.expect(t, crl_dir_check("3002", 0, &cs), "a file with the serial: revoked")
	testing.expect(t, !crl_dir_check("3001", 0, &cs), "another serial")
	os.remove(file)
	testing.expect(t, !crl_dir_check("3002", 0, &cs), "the file is gone: not revoked any more")
	// A name that does not fit is refused.
	long := strings.repeat("9", 5000, context.temp_allocator)
	testing.expect(t, crl_dir_check(long, 0, &cs))
	testing.expect(t, crl_dir_check("", 0, &cs))
	// A directory that is not there (the directory, not the serial file) is no
	// reason to accept: ENOENT is the only pass, and here the directory is
	// missing, which the start check prevents.
	cs.path = "/dev/null"
	testing.expect(t, crl_dir_check("1", 0, &cs), "ENOTDIR is not a pass")
}

// ---- the lost list, with a real file ----

@(test)
test_crl_poll_loses_and_recovers :: proc(t: ^testing.T) {
	path := tmp_file("poll.pem", GOOD_CRL)
	defer delete(path)
	defer os.remove(path)
	errors, warnings: [dynamic]string
	defer free_strings(&errors)
	defer free_strings(&warnings)
	cs: Crl_State
	defer crl_destroy(&cs)
	testing.expect(t, init_with(path, false, &errors, &warnings, &cs))
	rev := cs.revision

	// Nothing changed.
	testing.expect(t, !crl_poll(&cs, true))
	testing.expect_value(t, cs.revision, rev)

	// A broken file: the list is lost, and the Error is logged once.
	_ = os.write_entire_file(path, transmute([]u8)string("half a fi"))
	testing.expect(t, crl_poll(&cs, true))
	testing.expect(t, cs.lost)
	testing.expect_value(t, cs.revision, rev + 1)
	testing.expect(t, !crl_poll(&cs, true), "a second look at the same broken file says nothing new")
	testing.expect_value(t, cs.revision, rev + 1)

	// The file is gone: still lost.
	os.remove(path)
	testing.expect(t, !crl_poll(&cs, true))
	testing.expect(t, cs.lost)

	// A good file: loaded again.
	_ = os.write_entire_file(path, GOOD_CRL)
	testing.expect(t, crl_poll(&cs, true))
	testing.expect(t, !cs.lost)
	testing.expect_value(t, cs.revision, rev + 2)

	// The file goes away while the list is good: lost at once.
	os.remove(path)
	testing.expect(t, crl_poll(&cs, true))
	testing.expect(t, cs.lost)
}

// ---- the check of the config ----

@(test)
test_crl_verify_with_fingerprint_warns_in_the_client :: proc(t: ^testing.T) {
	fp := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	text := fmt.tprintf("client\nremote 192.0.2.1 1194 udp\npeer-fingerprint %s\ncrl-verify /nonexistent/crl.pem\n", fp)
	cfg := config.build(config.parse_text(text, "test.conf"))
	defer config.destroy(&cfg)
	s: Settings
	defer settings_destroy(&s)
	_ = settings_load(&s, &cfg)
	found := false
	for w in s.warnings {
		found ||= strings.has_prefix(w, "crl-verify has no effect")
	}
	testing.expectf(t, found, "warnings: %v", s.warnings)
}
