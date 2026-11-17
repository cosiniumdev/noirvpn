// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:testing"
import "noir:client"

@(test)
test_dev_name_pick_default :: proc(t: ^testing.T) {
	buf: [16]u8
	for dev in ([]string{"tun", ""}) {
		name, r := dev_name_pick(dev, nil, buf[:])
		testing.expect_value(t, r, Dev_Pick.Ok)
		testing.expect_value(t, name, "noir0")

		name, r = dev_name_pick(dev, {"lo", "eth0", "tun0", "noir1"}, buf[:])
		testing.expect_value(t, r, Dev_Pick.Ok)
		testing.expect_value(t, name, "noir0")

		// The first free number, also when a lower one is free again.
		name, r = dev_name_pick(dev, {"noir0", "noir1", "noir3"}, buf[:])
		testing.expect_value(t, r, Dev_Pick.Ok)
		testing.expect_value(t, name, "noir2")

		name, r = dev_name_pick(dev, {"noir0", "noir1", "noir2"}, buf[:])
		testing.expect_value(t, r, Dev_Pick.Ok)
		testing.expect_value(t, name, "noir3")
	}
}

@(test)
test_dev_name_pick_none_free :: proc(t: ^testing.T) {
	taken := make([]string, DEV_PICK_LIMIT, context.temp_allocator)
	for i in 0 ..< DEV_PICK_LIMIT {
		taken[i] = fmt.tprintf("noir%d", i)
	}
	buf: [16]u8
	_, r := dev_name_pick("tun", taken, buf[:])
	testing.expect_value(t, r, Dev_Pick.None_Free)
	// The longest default name is an interface name.
	testing.expect(t, len(taken[DEV_PICK_LIMIT - 1]) <= 15)
	// One free name in the middle is found.
	free := taken[:500]
	name, r2 := dev_name_pick("tun", free, buf[:])
	testing.expect_value(t, r2, Dev_Pick.Ok)
	testing.expect_value(t, name, "noir500")
}

@(test)
test_dev_name_pick_explicit :: proc(t: ^testing.T) {
	buf: [16]u8
	name, r := dev_name_pick("work0", {"lo", "eth0", "noir0"}, buf[:])
	testing.expect_value(t, r, Dev_Pick.Ok)
	testing.expect_value(t, name, "work0")

	// A name that exists is refused, whatever the kind of the interface is.
	_, r = dev_name_pick("work0", {"lo", "work0"}, buf[:])
	testing.expect_value(t, r, Dev_Pick.Taken)
	_, r = dev_name_pick("tun0", {"tun0"}, buf[:])
	testing.expect_value(t, r, Dev_Pick.Taken)
	_, r = dev_name_pick("tun5", {"tun0"}, buf[:])
	testing.expect_value(t, r, Dev_Pick.Ok)
	// `noir0` named in the profile is an explicit name: no search for another one.
	_, r = dev_name_pick("noir0", {"noir0"}, buf[:])
	testing.expect_value(t, r, Dev_Pick.Taken)

	small: [4]u8
	_, r = dev_name_pick("work0", nil, small[:])
	testing.expect_value(t, r, Dev_Pick.Bad_Name)
}

@(test)
test_plan_notes_for_the_user :: proc(t: ^testing.T) {
	testing.expect(t, plan_note_for_user(.Dropped_Host_Net))
	testing.expect(t, plan_note_for_user(.Tunnel_Host_Net))
	testing.expect(t, !plan_note_for_user(client.Note_Kind.Info))
	testing.expect(t, !plan_note_for_user(.Skipped_Connected))
}
