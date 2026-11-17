// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:testing"
import "noir:platform/dco"
import "noir:proto/config"

@(private = "file")
start_skipped :: proc(req: dco.Launch_Request) -> (dco.Launch_Status, string, string) {
	return .Skipped, "", ""
}

@(private = "file")
start_ok :: proc(req: dco.Launch_Request) -> (dco.Launch_Status, string, string) {
	return .Started, "/run/udco/own/udco.sock", ""
}

@(private = "file")
start_fail :: proc(req: dco.Launch_Request) -> (dco.Launch_Status, string, string) {
	return .Failed, "", "no binary"
}

// The hook is empty by default: nothing changes.
@(test)
launch_without_a_launcher :: proc(t: ^testing.T) {
	path, wait := dco_launch_start({}, .Udco, "a", "/run/udco/udco.sock", 0)
	testing.expect_value(t, path, "/run/udco/udco.sock")
	testing.expect_value(t, wait, DCO_WAIT_SECS)
	testing.expect(t, !dco_launched)
}

@(test)
launch_only_for_datapath_udco :: proc(t: ^testing.T) {
	l := dco.Launcher {
		start = start_ok,
	}
	for mode in ([]config.Datapath{.Auto, .Dco, .Userspace}) {
		path, wait := dco_launch_start(l, mode, "a", "/run/udco/udco.sock", 0)
		testing.expect_value(t, path, "/run/udco/udco.sock")
		testing.expect_value(t, wait, DCO_WAIT_SECS)
	}
	testing.expect(t, !dco_launched)
}

@(test)
launch_skipped_keeps_the_config :: proc(t: ^testing.T) {
	path, wait := dco_launch_start({start = start_skipped}, .Udco, "a", "/x.sock", 0)
	testing.expect_value(t, path, "/x.sock")
	testing.expect_value(t, wait, DCO_WAIT_SECS)
	testing.expect(t, !dco_launched)
}

@(test)
launch_failed_does_not_wait :: proc(t: ^testing.T) {
	path, wait := dco_launch_start({start = start_fail}, .Udco, "a", "/run/udco/udco.sock", 0)
	testing.expect_value(t, path, "/run/udco/udco.sock")
	testing.expect_value(t, wait, 0)
	testing.expect(t, !dco_launched)
}

@(test)
launch_started_gives_the_new_socket :: proc(t: ^testing.T) {
	path, wait := dco_launch_start({start = start_ok}, .Udco, "a", "/run/udco/udco.sock", 0)
	defer delete(path)
	testing.expect_value(t, path, "/run/udco/own/udco.sock")
	testing.expect_value(t, wait, DCO_WAIT_SECS)
	testing.expect(t, dco_launched)
	dco_launched = false
}
