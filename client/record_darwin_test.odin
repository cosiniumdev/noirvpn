// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package client

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "noir:platform/sysnet"

// The files of the records: rights, locks, a crash. In a temporary folder; no
// root needed. These are the tests of record_linux_test.odin on core:sys/posix.

@(private = "file")
chmod :: proc(path: string, mode: u32) {
	posix.chmod(strings.clone_to_cstring(path, context.temp_allocator), transmute(posix.mode_t)u16(mode))
}

@(private = "file")
mkdir :: proc(path: string, mode: u32) -> bool {
	return posix.mkdir(strings.clone_to_cstring(path, context.temp_allocator), transmute(posix.mode_t)u16(mode)) == .OK
}

@(private = "file")
temp_state :: proc(t: ^testing.T, tag: string) -> (base, dir: string, ok: bool) {
	tmp, _ := os.temp_directory(context.temp_allocator)
	b, err := os.make_directory_temp(tmp, fmt.tprintf("noir-rec-%s-*", tag), context.temp_allocator)
	if err != nil {
		testing.expectf(t, false, "cannot create a temporary folder: %v", err)
		return "", "", false
	}
	// The parent of a state folder must not be writable by the group.
	chmod(b, 0o700)
	return b, strings.concatenate({b, "/state"}, context.temp_allocator), true
}

@(private = "file")
perm :: proc(path: string) -> u32 {
	st: posix.stat_t
	if posix.lstat(strings.clone_to_cstring(path, context.temp_allocator), &st) != .OK {
		return 0xffff_ffff
	}
	return u32(transmute(u16)st.st_mode) & 0o7777
}

@(test)
record_files_have_closed_rights :: proc(t: ^testing.T) {
	base, dir, ok := temp_state(t, "rights")
	if !ok {
		return
	}
	defer os.remove_all(base)
	f: Record_File
	testing.expect_value(t, record_open(&f, dir, "a", .Client), Record_Open_Error.None)
	id := strings.clone(record_id(&f), context.temp_allocator)
	testing.expect_value(t, perm(dir), 0o700)
	testing.expect_value(t, perm(fmt.tprintf("%s/%s.lock", dir, id)), 0o600)
	testing.expect_value(t, perm(fmt.tprintf("%s/%s.rec", dir, id)), 0o600)
	data, rerr := os.read_entire_file(fmt.tprintf("%s/%s.rec", dir, id), context.temp_allocator)
	testing.expect(t, rerr == nil)
	testing.expect(t, strings.has_prefix(string(data), "noirvpn-state 1\n"))
	record_close(&f)
	testing.expect_value(t, perm(fmt.tprintf("%s/%s.lock", dir, id)), 0xffff_ffff)
	testing.expect_value(t, perm(fmt.tprintf("%s/%s.rec", dir, id)), 0xffff_ffff)
}

@(test)
record_folder_must_be_safe :: proc(t: ^testing.T) {
	base, dir, ok := temp_state(t, "folder")
	if !ok {
		return
	}
	defer os.remove_all(base)
	// Open to the group: refused.
	testing.expect(t, mkdir(dir, 0o700))
	chmod(dir, 0o770)
	f: Record_File
	testing.expect_value(t, record_open(&f, dir, "a", .Client), Record_Open_Error.Dir_Not_Safe)
	// A symbolic link in place of the folder: refused.
	os.remove(dir)
	other := strings.concatenate({base, "/other"}, context.temp_allocator)
	testing.expect(t, mkdir(other, 0o700))
	testing.expect(t, os.symlink(other, dir) == nil)
	testing.expect_value(t, record_open(&f, dir, "a", .Client), Record_Open_Error.Dir_Not_Safe)
	testing.expect_value(t, f.ok, false)
}

// A live record is kept; after its owner dies the next scan finds it dead.
@(test)
record_lock_tells_live_from_dead :: proc(t: ^testing.T) {
	base, dir, ok := temp_state(t, "lock")
	if !ok {
		return
	}
	defer os.remove_all(base)
	a, b: Record_File
	testing.expect_value(t, record_open(&a, dir, "first", .Client), Record_Open_Error.None)
	record_add_dev(&a.rec, 7, "tun0")
	record_add_route(&a.rec, sysnet.Route{dst = sysnet.IP4_Address{198, 51, 100, 7}, dst_len = 32, ifindex = 2, protocol = ROUTE_PROTOCOL}, "eth0")
	testing.expect_value(t, record_write(&a), Record_Error.None)
	a_id := strings.clone(record_id(&a), context.temp_allocator)
	testing.expect_value(t, record_open(&b, dir, "second", .Server), Record_Open_Error.None)
	defer record_close(&b)

	s := record_scan(&b)
	testing.expect_value(t, len(s.live), 1)
	testing.expect_value(t, len(s.dead), 0)
	if len(s.live) == 1 {
		testing.expect_value(t, s.live[0].rec.name, "first")
		testing.expect_value(t, len(s.live[0].rec.routes), 1)
	}
	record_scan_destroy(&s)

	// The owner "dies": its files stay, its lock goes.
	record_release(&a)
	s = record_scan(&b)
	testing.expect_value(t, len(s.live), 0)
	testing.expect_value(t, len(s.dead), 1)
	if len(s.dead) == 1 {
		testing.expect_value(t, s.dead[0].id, a_id)
		testing.expect_value(t, s.dead[0].bad, false)
		testing.expect_value(t, len(s.dead[0].rec.routes), 1)
		// While this scan holds the lock, a third daemon sees the record as live.
		c: Record_File
		testing.expect_value(t, record_open(&c, dir, "third", .Client), Record_Open_Error.None)
		s3 := record_scan(&c)
		found := false
		for f in s3.live {
			if f.id == a_id {
				found = true
			}
		}
		testing.expect(t, found)
		record_scan_destroy(&s3)
		record_close(&c)
		record_forget(&b, &s.dead[0])
	}
	record_scan_destroy(&s)
	testing.expect_value(t, perm(fmt.tprintf("%s/%s.rec", dir, a_id)), 0xffff_ffff)
	testing.expect_value(t, perm(fmt.tprintf("%s/%s.lock", dir, a_id)), 0xffff_ffff)
	s = record_scan(&b)
	testing.expect_value(t, len(s.live) + len(s.dead), 0)
	record_scan_destroy(&s)
}

// Files that are not ours, or that others can read, are neither read nor removed.
@(test)
record_scan_refuses_foreign_files :: proc(t: ^testing.T) {
	base, dir, ok := temp_state(t, "foreign")
	if !ok {
		return
	}
	defer os.remove_all(base)
	f: Record_File
	testing.expect_value(t, record_open(&f, dir, "me", .Client), Record_Open_Error.None)
	defer record_close(&f)
	text := "noirvpn-state 1\npid 5\nname x\nrole client\nroute 4 10.0.0.0/8 - 254 - 2 eth0\nend\n"
	// Readable by others.
	open_rec := fmt.tprintf("%s/1-a.rec", dir)
	testing.expect(t, os.write_entire_file(open_rec, text) == nil)
	chmod(open_rec, 0o644)
	// A symbolic link as the lock.
	target := strings.concatenate({base, "/target"}, context.temp_allocator)
	testing.expect(t, os.write_entire_file(target, "") == nil)
	testing.expect(t, os.symlink(target, fmt.tprintf("%s/2-b.lock", dir)) == nil)
	// A record that is cut short, without its lock: dead, and its lines
	// before the cut count.
	cut := fmt.tprintf("%s/3-c.rec", dir)
	testing.expect(t, os.write_entire_file(cut, text[:40]) == nil)
	chmod(cut, 0o600)

	s := record_scan(&f)
	defer record_scan_destroy(&s)
	testing.expect_value(t, len(s.live), 0)
	testing.expect_value(t, s.bad, 2)
	testing.expect_value(t, len(s.dead), 1)
	if len(s.dead) == 1 {
		testing.expect_value(t, s.dead[0].id, "3-c")
		testing.expect(t, s.dead[0].cut && !s.dead[0].bad)
		testing.expect_value(t, s.dead[0].rec.pid, 5)
		testing.expect_value(t, s.dead[0].rec.name, "x")
		testing.expect_value(t, len(s.dead[0].rec.routes), 0)
	}
	// The refused files are still there.
	testing.expect_value(t, perm(open_rec), 0o644)
	testing.expect(t, perm(fmt.tprintf("%s/2-b.lock", dir)) != 0xffff_ffff)
}

// A live record that cannot be read turns the fallback off.
@(test)
record_scan_live_but_unreadable :: proc(t: ^testing.T) {
	base, dir, ok := temp_state(t, "unknown")
	if !ok {
		return
	}
	defer os.remove_all(base)
	a, b: Record_File
	testing.expect_value(t, record_open(&a, dir, "new", .Client), Record_Open_Error.None)
	defer record_close(&a)
	// A newer version wrote it.
	path := fmt.tprintf("%s/%s.rec", dir, record_id(&a))
	testing.expect(t, os.write_entire_file(path, "noirvpn-state 2\nend\n") == nil)
	chmod(path, 0o600)
	testing.expect_value(t, record_open(&b, dir, "old", .Client), Record_Open_Error.None)
	defer record_close(&b)
	s := record_scan(&b)
	defer record_scan_destroy(&s)
	testing.expect_value(t, len(s.live), 1)
	testing.expect(t, s.live_unknown)
}

// A daemon that has given up root: the folder refuses new files, so the
// record is rewritten in place, and at stop it stays as an empty record.
@(test)
record_rewrite_in_place_without_root :: proc(t: ^testing.T) {
	base, dir, ok := temp_state(t, "inplace")
	if !ok {
		return
	}
	defer os.remove_all(base)
	a: Record_File
	testing.expect_value(t, record_open(&a, dir, "dropped", .Client), Record_Open_Error.None)
	id := strings.clone(record_id(&a), context.temp_allocator)
	path := fmt.tprintf("%s/%s.rec", dir, id)
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	before: posix.stat_t
	posix.stat(cpath, &before)

	// Root ignores the rights of the folder: then the test turns the mode on.
	root := posix.geteuid() == 0
	chmod(dir, 0o500)
	if root {
		a.in_place = true
	}
	record_add_dev(&a.rec, 7, "tun7")
	record_add_route(&a.rec, sysnet.Route{dst = sysnet.IP4_Address{10, 9, 0, 0}, dst_len = 16, ifindex = 7, protocol = ROUTE_PROTOCOL}, "tun7")
	record_add_route(&a.rec, sysnet.Route{dst = sysnet.IP4_Address{10, 10, 0, 0}, dst_len = 16, ifindex = 7, protocol = ROUTE_PROTOCOL}, "tun7")
	testing.expect_value(t, record_write(&a), Record_Error.None)
	testing.expect(t, a.in_place)
	// A shorter text after a longer one: nothing of the old text stays.
	record_clear(&a.rec)
	record_add_dev(&a.rec, 7, "tun7")
	testing.expect_value(t, record_write(&a), Record_Error.None)
	data, _ := os.read_entire_file(path, context.temp_allocator)
	back, err := record_decode(string(data), context.temp_allocator)
	testing.expect_value(t, err, Record_Error.None)
	testing.expect_value(t, len(back.devs), 1)
	testing.expect_value(t, len(back.routes), 0)
	testing.expect_value(t, back.name, "dropped")
	after: posix.stat_t
	posix.stat(cpath, &after)
	testing.expect_value(t, after.st_ino, before.st_ino)
	testing.expect_value(t, perm(path), 0o600)
	testing.expect(t, !os.exists(fmt.tprintf("%s/%s.tmp", dir, id)))

	removed := record_close(&a)
	if !root {
		testing.expect(t, !removed)
		data, _ = os.read_entire_file(path, context.temp_allocator)
		back, err = record_decode(string(data), context.temp_allocator)
		testing.expect_value(t, err, Record_Error.None)
		testing.expect_value(t, len(back.devs) + len(back.routes) + len(back.dns), 0)
	}

	// The next start finds an empty dead record and removes its files.
	chmod(dir, 0o700)
	b: Record_File
	testing.expect_value(t, record_open(&b, dir, "next", .Client), Record_Open_Error.None)
	defer record_close(&b)
	s := record_scan(&b)
	testing.expect_value(t, len(s.dead), 0 if root else 1)
	for &f in s.dead {
		testing.expect(t, !f.bad && !f.cut)
		record_forget(&b, &f)
	}
	record_scan_destroy(&s)
	testing.expect(t, !os.exists(path))
	testing.expect(t, !os.exists(fmt.tprintf("%s/%s.lock", dir, id)))
}

// A record cut in a write in place: the lines before the cut count, for a
// live record and for a dead one.
@(test)
record_cut_record_counts_its_lines :: proc(t: ^testing.T) {
	base, dir, ok := temp_state(t, "cut")
	if !ok {
		return
	}
	defer os.remove_all(base)
	a, b: Record_File
	testing.expect_value(t, record_open(&a, dir, "a", .Client), Record_Open_Error.None)
	testing.expect_value(t, record_open(&b, dir, "b", .Client), Record_Open_Error.None)
	defer record_close(&b)
	record_add_dev(&a.rec, 7, "tun7")
	record_add_route(&a.rec, sysnet.Route{dst = sysnet.IP4_Address{10, 9, 0, 0}, dst_len = 16, ifindex = 7, protocol = ROUTE_PROTOCOL}, "tun7")
	record_add_route(&a.rec, sysnet.Route{dst = sysnet.IP4_Address{10, 10, 0, 0}, dst_len = 16, ifindex = 7, protocol = ROUTE_PROTOCOL}, "tun7")
	text := record_encode(&a.rec, context.temp_allocator)
	// The cut is in the second route line.
	cut := strings.index(text, "route 4 10.10") + 9
	testing.expect(t, write_in_place(&a, text[:cut]))

	s := record_scan(&b)
	testing.expect_value(t, len(s.live), 1)
	testing.expect(t, s.live_unknown)
	testing.expect_value(t, s.bad, 0)
	if len(s.live) == 1 {
		testing.expect(t, s.live[0].cut)
		testing.expect_value(t, len(s.live[0].rec.devs), 1)
		testing.expect_value(t, len(s.live[0].rec.routes), 1)
	}
	record_scan_destroy(&s)

	record_release(&a)
	s = record_scan(&b)
	defer record_scan_destroy(&s)
	testing.expect_value(t, len(s.dead), 1)
	testing.expect(t, !s.live_unknown)
	if len(s.dead) == 1 {
		testing.expect(t, s.dead[0].cut && !s.dead[0].bad)
		testing.expect_value(t, len(s.dead[0].rec.routes), 1)
		testing.expect_value(t, s.dead[0].rec.name, "a")
	}
}
