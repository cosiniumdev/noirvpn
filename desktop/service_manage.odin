// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The app starts its own service (macOS app bundle).
//
// An app bundle can hold a launchd job for the daemon:
// Contents/Library/LaunchDaemons/noirvpn-service.plist (packaging/macos). The app
// registers it with the system (service_manage_darwin.odin: SMAppService). The
// user allows it once under Login Items in System Settings. After that launchd
// runs the daemon as root at each start of the Mac, and again if it ends.
//
// Outside a bundle, and on other systems, there is no such job: the service is
// started by hand or by the service manager of the system.

import "core:fmt"

MANAGE_PLIST :: cstring("noirvpn-service.plist") // the file name in Contents/Library/LaunchDaemons
MANAGE_LOG :: "/var/log/noirvpn-service.log" // the log file that the plist sets

Manage_State :: enum u8 {
	Unavailable, // this system has no job to register
	Not_Found, // the system has not seen the job: the state before the first registration, and outside a bundle
	Not_Registered, // the system knows the job, and it is off
	Requires_Approval, // registered; the user has to allow it in System Settings
	Enabled, // registered and allowed: the system runs the service
}

manage_state_name :: proc(s: Manage_State) -> string {
	switch s {
	case .Unavailable:
		return "unavailable"
	case .Not_Found:
		return "not-found"
	case .Not_Registered:
		return "not-registered"
	case .Requires_Approval:
		return "requires-approval"
	case .Enabled:
		return "enabled"
	}
	return "unavailable"
}

// manage_ensure reads the state of the job and registers it when it is off or the
// system has not seen it yet (the first run) and the program is in a bundle with the
// job file. It registers once for a `tried` of false and sets it to true. `err` is
// why the registration failed, or "" (allocated; the caller deletes it).
manage_ensure :: proc(tried: ^bool) -> (s: Manage_State, err: string) {
	s = manage_status()
	if s != .Not_Registered && s != .Not_Found {
		return
	}
	if tried^ || !manage_has_job_file() {
		return
	}
	tried^ = true
	err = manage_register()
	s = manage_status()
	if s != .Not_Registered && s != .Not_Found {
		delete(err)
		err = ""
	}
	return
}

// service_cli runs --service-status, --service-register and --service-unregister:
// they print the state of the job and return the exit code of the program.
service_cli :: proc(cmd: string) -> int {
	if ODIN_OS != .Darwin {
		fmt.eprintln("noirvpn: the app's own service is only available on macOS")
		return 2
	}
	err: string
	switch cmd {
	case "--service-register":
		err = manage_register()
	case "--service-unregister":
		err = manage_unregister()
	}
	s := manage_status()
	fmt.println(manage_state_name(s))
	if err != "" {
		fmt.eprintln("noirvpn:", err)
		return 1
	}
	if !manage_has_job_file() {
		fmt.eprintln("noirvpn: this program is not running from an app bundle that contains", MANAGE_PLIST)
		return 1
	}
	return 0
}
