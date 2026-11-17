// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The calls of the service control manager and of the token checks that
// core:sys/windows does not have.

import win "core:sys/windows"

foreign import advapi32 "system:Advapi32.lib"

SC_HANDLE :: distinct rawptr
SERVICE_STATUS_HANDLE :: distinct rawptr

SERVICE_STATUS :: struct {
	service_type:              u32,
	current_state:             u32,
	controls_accepted:         u32,
	win32_exit_code:           u32,
	service_specific_exit_code: u32,
	check_point:               u32,
	wait_hint:                 u32,
}

Service_Main :: #type proc "system" (argc: u32, argv: [^]win.wstring)
Handler_Ex :: #type proc "system" (control: u32, event_type: u32, event_data: rawptr, ctx: rawptr) -> u32

SERVICE_TABLE_ENTRYW :: struct {
	name: win.wstring,
	proc_: Service_Main,
}

SERVICE_DESCRIPTIONW :: struct {
	description: win.wstring,
}

SC_ACTION :: struct {
	type:  i32,
	delay: u32,
}

SERVICE_FAILURE_ACTIONSW :: struct {
	reset_period:  u32,
	reboot_msg:    win.wstring,
	command:       win.wstring,
	actions_count: u32,
	actions:       [^]SC_ACTION,
}

SC_MANAGER_CONNECT :: 0x0001
SC_MANAGER_CREATE_SERVICE :: 0x0002
SERVICE_QUERY_STATUS :: 0x0004
SERVICE_START :: 0x0010
SERVICE_STOP :: 0x0020
SERVICE_CHANGE_CONFIG :: 0x0002
DELETE :: 0x00010000

SERVICE_WIN32_OWN_PROCESS :: 0x10
SERVICE_AUTO_START :: 2
SERVICE_ERROR_NORMAL :: 1
SERVICE_CONFIG_DESCRIPTION :: 1
SERVICE_CONFIG_FAILURE_ACTIONS :: 2
SC_ACTION_RESTART :: 1

SERVICE_STOPPED :: 1
SERVICE_START_PENDING :: 2
SERVICE_STOP_PENDING :: 3
SERVICE_RUNNING :: 4

SERVICE_ACCEPT_STOP :: 0x1
SERVICE_ACCEPT_SHUTDOWN :: 0x4

SERVICE_CONTROL_STOP :: 1
SERVICE_CONTROL_INTERROGATE :: 4
SERVICE_CONTROL_SHUTDOWN :: 5

ERROR_CALL_NOT_IMPLEMENTED :: 120
ERROR_SERVICE_SPECIFIC_ERROR :: 1066
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT :: 1063
ERROR_SERVICE_DOES_NOT_EXIST :: 1060
ERROR_SERVICE_EXISTS :: 1073
ERROR_SERVICE_NOT_ACTIVE :: 1062
ERROR_SERVICE_MARKED_FOR_DELETE :: 1072

// WELL_KNOWN_SID_TYPE of the Administrators group.
WIN_BUILTIN_ADMINISTRATORS_SID :: 26

SDDL_REVISION_1 :: 1

@(default_calling_convention = "system")
foreign advapi32 {
	StartServiceCtrlDispatcherW :: proc(table: [^]SERVICE_TABLE_ENTRYW) -> win.BOOL ---
	RegisterServiceCtrlHandlerExW :: proc(name: win.wstring, handler: Handler_Ex, ctx: rawptr) -> SERVICE_STATUS_HANDLE ---
	SetServiceStatus :: proc(h: SERVICE_STATUS_HANDLE, status: ^SERVICE_STATUS) -> win.BOOL ---
	OpenSCManagerW :: proc(machine: win.wstring, database: win.wstring, access: u32) -> SC_HANDLE ---
	CreateServiceW :: proc(
		scm: SC_HANDLE,
		name: win.wstring,
		display_name: win.wstring,
		access: u32,
		service_type: u32,
		start_type: u32,
		error_control: u32,
		binary_path: win.wstring,
		load_order_group: win.wstring,
		tag_id: ^u32,
		dependencies: win.wstring,
		start_name: win.wstring,
		password: win.wstring,
	) -> SC_HANDLE ---
	StartServiceW :: proc(service: SC_HANDLE, argc: u32, argv: [^]win.wstring) -> win.BOOL ---
	OpenServiceW :: proc(scm: SC_HANDLE, name: win.wstring, access: u32) -> SC_HANDLE ---
	ChangeServiceConfig2W :: proc(service: SC_HANDLE, info_level: u32, info: rawptr) -> win.BOOL ---
	ControlService :: proc(service: SC_HANDLE, control: u32, status: ^SERVICE_STATUS) -> win.BOOL ---
	QueryServiceStatus :: proc(service: SC_HANDLE, status: ^SERVICE_STATUS) -> win.BOOL ---
	DeleteService :: proc(service: SC_HANDLE) -> win.BOOL ---
	CloseServiceHandle :: proc(h: SC_HANDLE) -> win.BOOL ---
	CheckTokenMembership :: proc(token: win.HANDLE, sid: rawptr, is_member: ^win.BOOL) -> win.BOOL ---
	CreateWellKnownSid :: proc(kind: i32, domain_sid: rawptr, sid: rawptr, size: ^u32) -> win.BOOL ---
	ConvertStringSecurityDescriptorToSecurityDescriptorW :: proc(text: win.wstring, revision: u32, sd: ^rawptr, size: ^u32) -> win.BOOL ---
	SetFileSecurityW :: proc(path: win.wstring, info: u32, sd: rawptr) -> win.BOOL ---
}
