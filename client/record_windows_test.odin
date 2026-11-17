// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package client

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"
import "noir:platform/sysnet"

// The files of the records on Windows: the lock, a crash. In a temporary
// folder; the test runs elevated, as the other Windows tests of this package.

@(test)
record_windows_lock_tells_live_from_dead :: proc(t: ^testing.T) {
	tmp, _ := os.temp_directory(context.temp_allocator)
	base, err := os.make_directory_temp(tmp, "noir-rec-*", context.temp_allocator)
	if err != nil {
		testing.expectf(t, false, "cannot create a temporary folder: %v", err)
		return
	}
	defer os.remove_all(base)
	dir := strings.concatenate({base, `\state`}, context.temp_allocator)

	a, b: Record_File
	testing.expect_value(t, record_open(&a, dir, "first", .Client), Record_Open_Error.None)
	record_add_route(&a.rec, sysnet.Route{dst = sysnet.IP4_Address{198, 51, 100, 7}, dst_len = 32, ifindex = 2, protocol = ROUTE_PROTOCOL}, "Ethernet 2")
	testing.expect_value(t, record_write(&a), Record_Error.None)
	a_id := strings.clone(record_id(&a), context.temp_allocator)
	// A second write replaces the record that the first one created.
	record_add_dns(&a.rec, "ip-helper", "first", "nrpt noirvpn-first")
	testing.expect_value(t, record_write(&a), Record_Error.None)
	testing.expect_value(t, record_open(&b, dir, "second", .Client), Record_Open_Error.None)
	defer record_close(&b)

	s := record_scan(&b)
	testing.expect_value(t, len(s.live), 1)
	testing.expect_value(t, len(s.dead), 0)
	if len(s.live) == 1 {
		testing.expect_value(t, s.live[0].rec.name, "first")
		testing.expect_value(t, len(s.live[0].rec.routes), 1)
		testing.expect_value(t, len(s.live[0].rec.dns), 1)
		if len(s.live[0].rec.routes) == 1 {
			testing.expect_value(t, s.live[0].rec.routes[0].dev, "Ethernet 2")
		}
	}
	record_scan_destroy(&s)

	record_release(&a)
	s = record_scan(&b)
	testing.expect_value(t, len(s.live), 0)
	testing.expect_value(t, len(s.dead), 1)
	if len(s.dead) == 1 {
		testing.expect_value(t, s.dead[0].id, a_id)
		testing.expect_value(t, len(s.dead[0].rec.routes), 1)
		record_forget(&b, &s.dead[0])
	}
	record_scan_destroy(&s)
	testing.expect(t, !os.exists(fmt.tprintf(`%s\%s.rec`, dir, a_id)))
	testing.expect(t, !os.exists(fmt.tprintf(`%s\%s.lock`, dir, a_id)))
	s = record_scan(&b)
	testing.expect_value(t, len(s.live) + len(s.dead), 0)
	record_scan_destroy(&s)
}
