// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package main

// The job of the service in the app bundle, through SMAppService (macOS 13 and
// later). See service_manage.odin. Each call has its own autorelease pool: the
// calls come from the worker thread of the link.

import "base:intrinsics"
import "core:os"
import "core:strings"
import NS "core:sys/darwin/Foundation"

@(export, require)
foreign import sm "system:ServiceManagement.framework"

@(objc_class = "SMAppService", objc_superclass = NS.Object)
SMAppService :: struct {
	using _: NS.Object,
}

// SMAppServiceStatus
SM_NOT_REGISTERED :: 0
SM_ENABLED :: 1
SM_REQUIRES_APPROVAL :: 2
SM_NOT_FOUND :: 3

foreign sm {
	@(objc_type = SMAppService, objc_selector = "daemonServiceWithPlistName:", objc_name = "daemonServiceWithPlistName", objc_is_class_method = true)
	SMAppService_daemonServiceWithPlistName :: proc(plistName: ^NS.String) -> ^SMAppService ---

	@(objc_type = SMAppService, objc_selector = "registerAndReturnError:", objc_name = "registerAndReturnError")
	SMAppService_registerAndReturnError :: proc(self: ^SMAppService, error: ^^NS.Error) -> bool ---

	@(objc_type = SMAppService, objc_selector = "unregisterAndReturnError:", objc_name = "unregisterAndReturnError")
	SMAppService_unregisterAndReturnError :: proc(self: ^SMAppService, error: ^^NS.Error) -> bool ---

	@(objc_type = SMAppService, objc_selector = "status", objc_name = "status")
	SMAppService_status :: proc(self: ^SMAppService) -> NS.Integer ---

	@(objc_type = SMAppService, objc_selector = "openSystemSettingsLoginItems", objc_name = "openSystemSettingsLoginItems", objc_is_class_method = true)
	SMAppService_openSystemSettingsLoginItems :: proc() ---
}

// job returns the service object of the job file, or nil on a system without
// SMAppService (before macOS 13).
@(private = "file")
job :: proc() -> ^SMAppService {
	if intrinsics.objc_find_class("SMAppService") == nil {
		return nil
	}
	return SMAppService.daemonServiceWithPlistName(NS.AT(MANAGE_PLIST))
}

// manage_status is the state of the job in the system.
manage_status :: proc() -> Manage_State {
	NS.scoped_autoreleasepool()
	svc := job()
	if svc == nil {
		return .Unavailable
	}
	switch svc->status() {
	case SM_NOT_REGISTERED:
		return .Not_Registered
	case SM_ENABLED:
		return .Enabled
	case SM_REQUIRES_APPROVAL:
		return .Requires_Approval
	}
	return .Not_Found
}

// error_text is the description of an NSError, allocated.
@(private = "file")
error_text :: proc(e: ^NS.Error) -> string {
	if e == nil {
		return strings.clone("the system did not give a reason")
	}
	return strings.clone(e->localizedDescription()->odinString())
}

// manage_register registers the job. The result is "" or the reason of a failure
// (allocated). A job that waits for the user is no failure: the state says so.
manage_register :: proc() -> string {
	NS.scoped_autoreleasepool()
	svc := job()
	if svc == nil {
		return strings.clone("this version of macOS does not support SMAppService")
	}
	e: ^NS.Error
	if svc->registerAndReturnError(&e) {
		return ""
	}
	return error_text(e)
}

// manage_unregister removes the job from the system, and stops the service.
manage_unregister :: proc() -> string {
	NS.scoped_autoreleasepool()
	svc := job()
	if svc == nil {
		return strings.clone("this version of macOS does not support SMAppService")
	}
	e: ^NS.Error
	if svc->unregisterAndReturnError(&e) {
		return ""
	}
	return error_text(e)
}

// exe_dir is the folder of this program (temp allocator), or "".
@(private = "file")
exe_dir :: proc() -> string {
	path, err := os.get_executable_path(context.temp_allocator)
	if err != nil {
		return ""
	}
	i := strings.last_index_byte(path, '/')
	return i < 0 ? "" : path[:i]
}

// manage_has_job_file says whether this program is in an app bundle that has the
// job file: Contents/MacOS/<program> next to Contents/Library/LaunchDaemons/.
manage_has_job_file :: proc() -> bool {
	d := exe_dir()
	if d == "" {
		return false
	}
	return os.exists(strings.concatenate({d, "/../Library/LaunchDaemons/", string(MANAGE_PLIST)}, context.temp_allocator))
}

// manage_daemon_path is the daemon program next to this one, or "".
manage_daemon_path :: proc(allocator := context.allocator) -> string {
	d := exe_dir()
	if d == "" {
		return ""
	}
	p := strings.concatenate({d, "/noirvpn"}, context.temp_allocator)
	return os.exists(p) ? strings.clone(p, allocator) : ""
}

// manage_open_settings shows Login Items in System Settings.
manage_open_settings :: proc() {
	NS.scoped_autoreleasepool()
	if intrinsics.objc_find_class("SMAppService") != nil {
		SMAppService.openSystemSettingsLoginItems()
	}
}
