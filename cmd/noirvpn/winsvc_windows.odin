// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:runtime"
import "core:fmt"
import "core:os"
import "core:strings"
import win "core:sys/windows"

// The Windows service.
//
//   noirvpn service install [--name N] [CONFIG]   register noirvpn-N, start it
//   noirvpn service uninstall [--name N]          stop it and remove it
//   noirvpn service run --name N CONFIG           the entry for the service manager
//
// The service runs as LocalSystem and starts with the system. Config:
// %ProgramData%\noirvpn\N.conf; log: N.log in the same folder. Without CONFIG,
// install writes a client service config if there is none. A stop or shutdown
// from the service manager is SIGTERM, as `daemon.shutdown` is.

// The instance name when `--name` is not given: the one the desktop client
// looks for first.
SVC_DEFAULT_NAME :: "desktop"
SVC_PREFIX :: "noirvpn-"
// A log above this size moves to N.log.old when the service starts.
SVC_LOG_MAX :: 8 * 1024 * 1024
// SYSTEM and Administrators: full control; Users: read.
SVC_DIR_SDDL :: "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

SVC_DEFAULT_CONFIG :: `# The noirvpn client service. A user loads a profile over the control bus
# (the desktop client, or noirvpnctl profile set).
client-service
verb 3
# Users who are logged on at this computer may load a profile and connect.
bus-allow sid S-1-5-4 operator
`

USAGE_SERVICE :: `usage:
  noirvpn service install [--name NAME] [CONFIG]
  noirvpn service uninstall [--name NAME]

install registers the service noirvpn-NAME (NAME is desktop if not given),
which runs as LocalSystem and starts with Windows, and then starts it. Its
config is %ProgramData%\noirvpn\NAME.conf: CONFIG is copied there, and without
CONFIG a client service config is written if the file does not exist yet. The
log file is %ProgramData%\noirvpn\NAME.log. Both commands need an elevated
prompt.
`

// The process runs under the service manager.
svc_mode: bool
// The log file of the service, for `status`; "" when the log is stderr.
svc_log_path: string

@(private = "file")
svc: struct {
	name:   string, // the instance name
	config: string,
	handle: SERVICE_STATUS_HANDLE,
	status: SERVICE_STATUS,
	exit:   Exit,
}

// `noirvpn service ...`: the subcommands above.
service_command :: proc(args: []string) -> Exit {
	if len(args) == 0 {
		fmt.eprint(USAGE_SERVICE)
		return .Usage
	}
	name := SVC_DEFAULT_NAME
	rest := make([dynamic]string, context.temp_allocator)
	for i := 1; i < len(args); i += 1 {
		if args[i] == "--name" {
			if i + 1 >= len(args) {
				fmt.eprintln("noirvpn: the --name option requires a value")
				return .Usage
			}
			name = args[i + 1]
			i += 1
			continue
		}
		append(&rest, args[i])
	}
	if !svc_name_ok(name) {
		fmt.eprintfln("noirvpn: the name %q is not valid, because it must be 1 to 40 letters, digits, '.', '-' or '_'", name)
		return .Usage
	}
	switch args[0] {
	case "install":
		if len(rest) > 1 {
			fmt.eprint(USAGE_SERVICE)
			return .Usage
		}
		return svc_install(name, rest[0] if len(rest) == 1 else "")
	case "uninstall":
		if len(rest) > 0 {
			fmt.eprint(USAGE_SERVICE)
			return .Usage
		}
		return svc_uninstall(name)
	case "run":
		if len(rest) != 1 {
			fmt.eprint(USAGE_SERVICE)
			return .Usage
		}
		return svc_run(name, rest[0])
	case "--help", "-h", "help":
		fmt.print(USAGE_SERVICE)
		return .Ok
	}
	fmt.eprint(USAGE_SERVICE)
	return .Usage
}

@(private = "file")
svc_name_ok :: proc(name: string) -> bool {
	if len(name) == 0 || len(name) > 40 {
		return false
	}
	for c in transmute([]u8)name {
		switch c {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '-', '_':
		case:
			return false
		}
	}
	return true
}

// %ProgramData%\noirvpn.
svc_dir :: proc(allocator := context.temp_allocator) -> string {
	base, ok := os.lookup_env("ProgramData", context.temp_allocator)
	if !ok || base == "" {
		base = `C:\ProgramData`
	}
	return strings.concatenate({base, `\noirvpn`}, allocator)
}

@(private = "file")
wide :: proc(s: string) -> win.wstring {
	return win.utf8_to_wstring(s, context.temp_allocator)
}

@(private = "file")
win_error_text :: proc(e: u32) -> string {
	switch e {
	case 5:
		return "access denied (use an elevated prompt)"
	case ERROR_SERVICE_EXISTS:
		return "the service already exists"
	case ERROR_SERVICE_DOES_NOT_EXIST:
		return "the service does not exist"
	case ERROR_SERVICE_MARKED_FOR_DELETE:
		return "the service is marked for deletion, so close the Services window and try again"
	}
	return fmt.tprintf("Windows error %d", e)
}

// Creates the folder with its access list, or puts the list on a folder that
// exists.
@(private = "file")
svc_make_dir :: proc(dir: string) -> bool {
	sd: rawptr
	if !ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(SVC_DIR_SDDL), SDDL_REVISION_1, &sd, nil) {
		fmt.eprintfln("noirvpn: cannot create the access list: %s", win_error_text(win.GetLastError()))
		return false
	}
	defer win.LocalFree(sd)
	sa := win.SECURITY_ATTRIBUTES {
		nLength              = size_of(win.SECURITY_ATTRIBUTES),
		lpSecurityDescriptor = sd,
	}
	if win.CreateDirectoryW(wide(dir), &sa) {
		return true
	}
	if e := win.GetLastError(); e != win.ERROR_ALREADY_EXISTS {
		fmt.eprintfln("noirvpn: cannot create the folder %s: %s", dir, win_error_text(e))
		return false
	}
	if !SetFileSecurityW(wide(dir), win.DACL_SECURITY_INFORMATION | win.PROTECTED_DACL_SECURITY_INFORMATION, sd) {
		fmt.eprintfln("noirvpn: cannot set the access list of %s: %s", dir, win_error_text(win.GetLastError()))
		return false
	}
	return true
}

@(private = "file")
svc_install :: proc(name, config_src: string) -> Exit {
	if !has_net_admin() {
		fmt.eprintln("noirvpn: you need an elevated prompt to install a service")
		return .System
	}
	dir := svc_dir()
	if !svc_make_dir(dir) {
		return .System
	}
	conf := fmt.tprintf(`%s\%s.conf`, dir, name)
	if config_src != "" {
		data, err := os.read_entire_file(config_src, context.temp_allocator)
		if err != nil {
			fmt.eprintfln("noirvpn: cannot read %s: %v", config_src, err)
			return .Config
		}
		if werr := os.write_entire_file(conf, data); werr != nil {
			fmt.eprintfln("noirvpn: cannot write %s: %v", conf, werr)
			return .System
		}
		fmt.printfln("config: %s (copied from %s)", conf, config_src)
	} else if !os.exists(conf) {
		if werr := os.write_entire_file(conf, transmute([]u8)string(SVC_DEFAULT_CONFIG)); werr != nil {
			fmt.eprintfln("noirvpn: cannot write %s: %v", conf, werr)
			return .System
		}
		fmt.printfln("config: %s (for a client service)", conf)
	} else {
		fmt.printfln("config: %s (kept)", conf)
	}

	exe: [win.MAX_PATH_WIDE]u16
	n := win.GetModuleFileNameW(nil, &exe[0], u32(len(exe)))
	if n == 0 || n >= u32(len(exe)) {
		fmt.eprintln("noirvpn: cannot find the path of this program")
		return .System
	}
	exe_path, _ := win.utf16_to_utf8(exe[:n], context.temp_allocator)
	cmd := fmt.tprintf(`"%s" service run --name %s "%s"`, exe_path, name, conf)

	scm := OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)
	if scm == nil {
		fmt.eprintfln("noirvpn: cannot open the service manager: %s", win_error_text(win.GetLastError()))
		return .System
	}
	defer CloseServiceHandle(scm)
	svc_name := strings.concatenate({SVC_PREFIX, name}, context.temp_allocator)
	display := fmt.tprintf("noirvpn (%s)", name)
	s := CreateServiceW(
		scm, wide(svc_name), wide(display),
		SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
		wide(cmd), nil, nil, nil, nil, nil,
	) // fmt: skip
	if s == nil {
		fmt.eprintfln("noirvpn: cannot create the service %s: %s", svc_name, win_error_text(win.GetLastError()))
		return .System
	}
	defer CloseServiceHandle(s)
	desc := SERVICE_DESCRIPTIONW{wide("The noirvpn VPN client: creates the tunnel that a user requests.")}
	ChangeServiceConfig2W(s, SERVICE_CONFIG_DESCRIPTION, &desc)
	// A crash restarts the service twice; a stop with an error code does not.
	actions := [3]SC_ACTION{{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}, {0, 0}}
	fa := SERVICE_FAILURE_ACTIONSW {
		reset_period  = 86400,
		actions_count = len(actions),
		actions       = &actions[0],
	}
	ChangeServiceConfig2W(s, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)
	fmt.printfln("service: %s, %s", svc_name, cmd)
	if !StartServiceW(s, 0, nil) {
		fmt.eprintfln("noirvpn: the service was installed, but it did not start: %s (check the log file %s\\%s.log)", win_error_text(win.GetLastError()), dir, name)
		return .System
	}
	fmt.println("service: started")
	return .Ok
}

@(private = "file")
svc_uninstall :: proc(name: string) -> Exit {
	if !has_net_admin() {
		fmt.eprintln("noirvpn: you need an elevated prompt to remove a service")
		return .System
	}
	scm := OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT)
	if scm == nil {
		fmt.eprintfln("noirvpn: cannot open the service manager: %s", win_error_text(win.GetLastError()))
		return .System
	}
	defer CloseServiceHandle(scm)
	svc_name := strings.concatenate({SVC_PREFIX, name}, context.temp_allocator)
	s := OpenServiceW(scm, wide(svc_name), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE)
	if s == nil {
		fmt.eprintfln("noirvpn: cannot open the service %s: %s", svc_name, win_error_text(win.GetLastError()))
		return .System
	}
	defer CloseServiceHandle(s)
	st: SERVICE_STATUS
	if ControlService(s, SERVICE_CONTROL_STOP, &st) {
		fmt.println("service: stopping")
		for _ in 0 ..< 300 {
			if !QueryServiceStatus(s, &st) || st.current_state == SERVICE_STOPPED {
				break
			}
			win.Sleep(100)
		}
		if st.current_state != SERVICE_STOPPED {
			fmt.eprintln("noirvpn: the service did not stop within 30 seconds, so it will be removed once it stops")
		}
	} else if e := win.GetLastError(); e != ERROR_SERVICE_NOT_ACTIVE {
		fmt.eprintfln("noirvpn: cannot stop the service: %s", win_error_text(e))
	}
	if !DeleteService(s) {
		fmt.eprintfln("noirvpn: cannot remove the service %s: %s", svc_name, win_error_text(win.GetLastError()))
		return .System
	}
	fmt.printfln("service: %s was removed, and its config and log are still in %s", svc_name, svc_dir())
	return .Ok
}

// ---------------------------------------------------------------- the run

@(private = "file")
svc_run :: proc(name, config: string) -> Exit {
	svc.name = name
	svc.config = config
	svc_mode = true
	svc_name := strings.concatenate({SVC_PREFIX, name}, context.temp_allocator)
	table := [2]SERVICE_TABLE_ENTRYW{{wide(svc_name), svc_main}, {}}
	if !StartServiceCtrlDispatcherW(&table[0]) {
		e := win.GetLastError()
		if e == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
			fmt.eprintln("noirvpn: 'service run' is only for the service manager, so use 'noirvpn CONFIG' in a console")
			return .Usage
		}
		fmt.eprintfln("noirvpn: cannot connect to the service manager: %s", win_error_text(e))
		return .System
	}
	return svc.exit
}

@(private = "file")
svc_report :: proc "contextless" (state: u32, exit := Exit.Ok, wait_ms: u32 = 0) {
	svc.status.service_type = SERVICE_WIN32_OWN_PROCESS
	svc.status.current_state = state
	svc.status.controls_accepted = 0 if state == SERVICE_START_PENDING else SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
	svc.status.wait_hint = wait_ms
	svc.status.check_point = 0 if state == SERVICE_RUNNING || state == SERVICE_STOPPED else svc.status.check_point + 1
	if exit != .Ok {
		svc.status.win32_exit_code = ERROR_SERVICE_SPECIFIC_ERROR
		svc.status.service_specific_exit_code = u32(exit)
	} else {
		svc.status.win32_exit_code = 0
		svc.status.service_specific_exit_code = 0
	}
	SetServiceStatus(svc.handle, &svc.status)
}

@(private = "file")
svc_handler :: proc "system" (control: u32, event_type: u32, event_data: rawptr, ctx: rawptr) -> u32 {
	switch control {
	case SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
		svc_report(SERVICE_STOP_PENDING, .Ok, 20_000)
		sig_post(SIGTERM)
		return 0
	case SERVICE_CONTROL_INTERROGATE:
		return 0
	}
	return ERROR_CALL_NOT_IMPLEMENTED
}

// Runs on a thread of the service manager; the dispatcher returns when this
// has reported SERVICE_STOPPED.
@(private = "file")
svc_main :: proc "system" (argc: u32, argv: [^]win.wstring) {
	context = runtime.default_context()
	svc_name := strings.concatenate({SVC_PREFIX, svc.name}, context.temp_allocator)
	svc.handle = RegisterServiceCtrlHandlerExW(wide(svc_name), svc_handler, nil)
	if svc.handle == nil {
		svc.exit = .System
		return
	}
	svc_report(SERVICE_START_PENDING, .Ok, 10_000)
	svc_open_log(svc.name)
	// The NRPT rules and the routes of a run that crashed go at the start of the
	// client, by its clean-up records (records.odin).
	svc.exit = run({"--name", svc.name, svc.config})
	if svc.exit != .Ok {
		logf(.Error, "the service is stopping with exit code %d", int(svc.exit))
	}
	svc_report(SERVICE_STOPPED, svc.exit)
}

// The daemon is up: the service manager may show it as running.
svc_note_running :: proc() {
	if svc_mode {
		svc_report(SERVICE_RUNNING)
	}
}

// Opens %ProgramData%\noirvpn\NAME.log for appending and puts it in place of
// stderr. A log above SVC_LOG_MAX moves to NAME.log.old first.
@(private = "file")
svc_open_log :: proc(name: string) {
	dir := svc_dir()
	path := fmt.tprintf(`%s\%s.log`, dir, name)
	if fi, err := os.stat(path, context.temp_allocator); err == nil && fi.size > SVC_LOG_MAX {
		old := strings.concatenate({path, ".old"}, context.temp_allocator)
		_ = os.remove(old)
		_ = os.rename(path, old)
	}
	f, err := os.open(path, {.Write, .Create, .Append})
	if err != nil {
		return
	}
	os.stderr = f
	svc_log_path = strings.clone(path)
}
