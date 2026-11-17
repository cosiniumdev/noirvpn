// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "noir:client"
import "noir:proto/config"

@(private = "file")
dir_stat :: proc(path: string) -> (mode: u32, gid: u32, ok: bool) {
	st: posix.stat_t
	if posix.stat(strings.clone_to_cstring(path, context.temp_allocator), &st) != .OK {
		return 0, 0, false
	}
	when size_of(posix.mode_t) == 4 {
		m := transmute(u32)st.st_mode
	} else {
		m := u32(transmute(u16)st.st_mode)
	}
	return m & 0o7777, u32(st.st_gid), true
}

@(private = "file")
temp_dir :: proc(t: ^testing.T, tag: string) -> string {
	dir, err := os.make_directory_temp("/tmp", fmt.tprintf("noir-rec-%s-*", tag), context.allocator)
	testing.expectf(t, err == nil, "cannot create a temp dir: %v", err)
	posix.chmod(strings.clone_to_cstring(dir, context.temp_allocator), {.IRUSR, .IWUSR, .IXUSR})
	return dir
}

// A group of this process other than the primary one when there is one, so
// that the check sees the group of the bus.
@(private = "file")
test_gid :: proc() -> u32 {
	gids: [64]posix.gid_t
	n := posix.getgroups(len(gids), raw_data(gids[:]))
	for i in 0 ..< int(max(n, 0)) {
		if u32(gids[i]) != u32(posix.getegid()) {
			return u32(gids[i])
		}
	}
	return u32(posix.getegid())
}

@(test)
missing_bus_folder_gets_the_bus_mode_before_the_records :: proc(t: ^testing.T) {
	tmp := temp_dir(t, "bus")
	defer {
		os.remove_all(tmp)
		delete(tmp)
	}
	run := fmt.tprintf("%s/run", tmp)
	gid := test_gid()
	c: config.Common_Config
	c.bus_events = {state = .Off}
	c.bus_control = {state = .Custom, path = fmt.tprintf("%s/t.control", run), group = fmt.tprintf("%d", gid)}
	bus_prepare_dirs(&c, .Client, "t")

	f: client.Record_File
	err := client.record_open(&f, fmt.tprintf("%s/state", run), "t", .Client)
	testing.expect_value(t, err, client.Record_Open_Error.None)
	defer client.record_close(&f)
	mode, g, ok := dir_stat(run)
	testing.expect(t, ok)
	testing.expect_value(t, mode, u32(0o750))
	testing.expect_value(t, g, gid)
	mode, _, ok = dir_stat(fmt.tprintf("%s/state", run))
	testing.expect(t, ok)
	testing.expect_value(t, mode, u32(0o700))
}

@(test)
records_keep_their_parent_rules_without_a_bus :: proc(t: ^testing.T) {
	tmp := temp_dir(t, "nobus")
	defer {
		os.remove_all(tmp)
		delete(tmp)
	}
	run := fmt.tprintf("%s/run", tmp)
	c: config.Common_Config
	c.bus_events = {state = .Off}
	c.bus_control = {state = .Off}
	bus_prepare_dirs(&c, .Server, "t")
	_, _, made := dir_stat(run)
	testing.expect(t, !made)

	old := posix.umask({})
	f: client.Record_File
	err := client.record_open(&f, fmt.tprintf("%s/state", run), "t", .Server)
	posix.umask(old)
	testing.expect_value(t, err, client.Record_Open_Error.None)
	client.record_close(&f)
	mode, _, ok := dir_stat(run)
	testing.expect(t, ok)
	testing.expect_value(t, mode, u32(0o755))

	// A folder that exists stays as it is when the bus comes later.
	c.bus_control = {state = .Custom, path = fmt.tprintf("%s/t.control", run)}
	bus_prepare_dirs(&c, .Server, "t")
	mode, _, ok = dir_stat(run)
	testing.expect(t, ok)
	testing.expect_value(t, mode, u32(0o755))
}
