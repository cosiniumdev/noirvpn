// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package sysnet

import "base:runtime"
import "core:io"
import "core:mem"
import "core:os"
import "core:strings"

DNS_Backend :: enum {
	None,
	Systemd_Resolved,
	Resolvconf,
	Resolv_Conf,
}

// Runs a command: `argv[0]` is a full path, the rest are arguments. `stdin` is
// its standard input (empty: nothing). Returns the exit code; `started` is
// false if the process could not start or wait. `data` is passed back on every
// call. A nil `run` means the real runner (`dns_run_command`).
Command_Runner :: struct {
	data: rawptr,
	run:  proc(data: rawptr, argv: []string, stdin: string) -> (exit_code: int, started: bool),
}

// Where things are. The strings must outlive every `DNS` created with them.
DNS_Env :: struct {
	// systemd-resolved is considered running when this directory exists.
	resolved_dir: string,
	// Directories searched for `resolvectl` and `resolvconf`.
	bin_dirs:     []string,
	resolv_conf:  string,
	// Directories where an installed resolvconf keeps one file per record. A
	// record of ours can be left by a crashed run only if a file with its name
	// is in one of them.
	record_dirs:  []string,
	// Where the old resolv.conf is kept while ours is in place.
	backup:       string,
	runner:       Command_Runner,
	// Use this backend and skip detection. `.None`: detect.
	force:        DNS_Backend,
}

// One applied DNS configuration. Zero value = nothing applied.
DNS :: struct {
	env:          DNS_Env,
	backend:      DNS_Backend,
	active:       bool,
	allocator:    mem.Allocator,
	ifname:       string,
	// The resolv.conf text we wrote (resolv.conf backend), to spot changes.
	written:      string,
	had_original: bool,
	// Things the backend could not do, for the log. Valid until the next apply.
	warnings:     [dynamic]string,
}

dns_destroy :: proc(d: ^DNS) {
	delete(d.ifname, d.allocator)
	delete(d.written, d.allocator)
	for w in d.warnings {
		delete(w, d.warnings.allocator)
	}
	delete(d.warnings)
	d^ = {}
}

@(private)
find_binary :: proc(env: DNS_Env, name: string, allocator := context.allocator) -> (path: string, ok: bool) {
	for dir in env.bin_dirs {
		p := strings.concatenate({dir, "/", name}, allocator)
		if os.is_file(p) {
			return p, true
		}
		delete(p, allocator)
	}
	return "", false
}

@(private)
has_binary :: proc(env: DNS_Env, name: string) -> bool {
	_, ok := find_binary(env, name, context.temp_allocator)
	return ok
}

// The backend `dns_apply` would use: systemd-resolved when its directory and
// `resolvectl` are there, else resolvconf when installed, else the file.
dns_detect :: proc(env: DNS_Env) -> DNS_Backend {
	if env.force != .None {
		return env.force
	}
	if os.is_dir(env.resolved_dir) && has_binary(env, "resolvectl") {
		return .Systemd_Resolved
	}
	if has_binary(env, "resolvconf") {
		return .Resolvconf
	}
	return .Resolv_Conf
}

@(private)
run :: proc(env: DNS_Env, argv: []string, stdin := "") -> DNS_Error {
	r := env.runner
	code: int
	started: bool
	if r.run != nil {
		code, started = r.run(r.data, argv, stdin)
	} else {
		code, started = dns_run_command(nil, argv, stdin)
	}
	if !started || code != 0 {
		return .Command_Failed
	}
	return .None
}

// Apply the settings for the link named `ifname`. `d` is set up from scratch.
// On an error nothing stays applied.
dns_apply :: proc(
	d: ^DNS,
	env: DNS_Env,
	ifname: string,
	s: DNS_Settings,
	allocator := context.allocator,
) -> DNS_Error {
	if d.active {
		return .Invalid
	}
	d^ = {}
	d.env = env
	d.allocator = allocator
	d.warnings.allocator = allocator
	if !dns_valid_ifname(ifname) {
		return .Invalid
	}
	if err := dns_settings_check(s); err != .None {
		return err
	}
	d.ifname = strings.clone(ifname, allocator)
	d.backend = dns_detect(env)

	err: DNS_Error
	switch d.backend {
	case .Systemd_Resolved:
		err = apply_resolved(d, s)
	case .Resolvconf:
		err = apply_resolvconf(d, s)
	case .Resolv_Conf:
		err = apply_resolv_conf(d, s)
	case .None:
		err = .Unsupported
	}
	if err != .None {
		dns_destroy(d)
		return err
	}
	d.active = true
	return .None
}

// Take the settings away. Call it before the tunnel closes: systemd-resolved
// forgets a link when it disappears, and then `resolvectl revert` has nothing
// to do and reports a failure. After the call `d` holds nothing applied,
// whatever the result.
dns_revert :: proc(d: ^DNS) -> DNS_Error {
	if !d.active {
		return .Not_Applied
	}
	err: DNS_Error
	switch d.backend {
	case .Systemd_Resolved:
		path, ok := find_binary(d.env, "resolvectl", context.temp_allocator)
		if !ok {
			err = .Command_Failed
		} else {
			err = run(d.env, {path, "revert", d.ifname})
		}
	case .Resolvconf:
		path, ok := find_binary(d.env, "resolvconf", context.temp_allocator)
		if !ok {
			err = .Command_Failed
		} else {
			record := strings.concatenate({d.ifname, RESOLVCONF_SUFFIX}, context.temp_allocator)
			err = run(d.env, {path, "-d", record})
		}
	case .Resolv_Conf:
		err = revert_resolv_conf(d)
	case .None:
		err = .Not_Applied
	}
	d.active = false
	return err
}

// ---- systemd-resolved ----

@(private)
apply_resolved :: proc(d: ^DNS, s: DNS_Settings) -> DNS_Error {
	path, ok := find_binary(d.env, "resolvectl", context.temp_allocator)
	if !ok {
		return .Unsupported
	}
	argv := make([dynamic]string, 0, 3 + len(s.servers), context.temp_allocator)
	append(&argv, path, "dns", d.ifname)
	for sv in s.servers {
		append(&argv, dns_server_text(sv, context.temp_allocator))
	}
	if err := run(d.env, argv[:]); err != .None {
		return err
	}
	domains := dns_resolved_domains(s, context.temp_allocator)
	if len(domains) > 0 {
		clear(&argv)
		append(&argv, path, "domain", d.ifname)
		append(&argv, ..domains)
		if err := run(d.env, argv[:]); err != .None {
			_ = run(d.env, {path, "revert", d.ifname})
			return err
		}
	}
	return .None
}

// ---- resolvconf ----

RESOLVCONF_SUFFIX :: ".noirvpn"

@(private)
apply_resolvconf :: proc(d: ^DNS, s: DNS_Settings) -> DNS_Error {
	path, ok := find_binary(d.env, "resolvconf", context.temp_allocator)
	if !ok {
		return .Unsupported
	}
	text, err := dns_resolv_conf(d.ifname, s, false, &d.warnings, context.temp_allocator)
	if err != .None {
		return err
	}
	record := strings.concatenate({d.ifname, RESOLVCONF_SUFFIX}, context.temp_allocator)
	return run(d.env, {path, "-a", record}, text)
}

// ---- /etc/resolv.conf ----

TMP_SUFFIX :: ".noirvpn-tmp"

@(private)
apply_resolv_conf :: proc(d: ^DNS, s: DNS_Settings) -> DNS_Error {
	env := d.env
	text, terr := dns_resolv_conf(d.ifname, s, true, &d.warnings, d.allocator)
	if terr != .None {
		return terr
	}
	// A file of ours from a crashed run: put the original back first, so the
	// backup below is of the real file.
	if _, cerr := cleanup_resolv_conf(env); cerr != .None {
		delete(text, d.allocator)
		return cerr
	}

	fi, lerr := os.lstat(env.resolv_conf, context.temp_allocator)
	switch {
	case lerr == nil:
		if err := save_backup(env, fi.type); err != .None {
			delete(text, d.allocator)
			return err
		}
		d.had_original = true
	case lerr == os.General_Error.Not_Exist:
		d.had_original = false
		_ = os.remove(env.backup)
	case:
		delete(text, d.allocator)
		return map_os_error(lerr)
	}

	if err := replace_file(env.resolv_conf, text, .Regular); err != .None {
		delete(text, d.allocator)
		return err
	}
	d.written = text
	return .None
}

// Keep the current resolv.conf (a file or a symbolic link) at `env.backup`.
@(private)
save_backup :: proc(env: DNS_Env, kind: os.File_Type) -> DNS_Error {
	_ = os.remove(env.backup)
	switch kind {
	case .Symlink:
		target, rerr := os.read_link(env.resolv_conf, context.temp_allocator)
		if rerr != nil {
			return map_os_error(rerr)
		}
		if serr := os.symlink(target, env.backup); serr != nil {
			return map_os_error(serr)
		}
	case .Regular:
		data, rerr := os.read_entire_file(env.resolv_conf, context.temp_allocator)
		if rerr != nil {
			return map_os_error(rerr)
		}
		if werr := os.write_entire_file(env.backup, data); werr != nil {
			return map_os_error(werr)
		}
	case .Undetermined, .Directory, .Named_Pipe, .Socket, .Block_Device, .Character_Device:
		return .Io
	}
	return .None
}

// Replace `path` atomically: write a temporary file next to it, then rename.
// `kind` is `.Regular` (content = the text) or `.Symlink` (content = target).
@(private)
replace_file :: proc(path, content: string, kind: os.File_Type) -> DNS_Error {
	tmp := strings.concatenate({path, TMP_SUFFIX}, context.temp_allocator)
	_ = os.remove(tmp)
	switch kind {
	case .Symlink:
		if err := os.symlink(content, tmp); err != nil {
			return map_os_error(err)
		}
	case .Regular:
		if err := os.write_entire_file(tmp, content); err != nil {
			return map_os_error(err)
		}
	case .Undetermined, .Directory, .Named_Pipe, .Socket, .Block_Device, .Character_Device:
		return .Io
	}
	if err := os.rename(tmp, path); err != nil {
		_ = os.remove(tmp)
		// A file that is a mount point (the /etc/resolv.conf of a container)
		// cannot be replaced by rename (EBUSY). Rewrite it in place instead.
		// Not atomic, but the only way.
		if code, is_errno := os.is_platform_error(err); is_errno && code == EBUSY && kind == .Regular {
			if werr := os.write_entire_file(path, content); werr != nil {
				return map_os_error(werr)
			}
			return .None
		}
		return map_os_error(err)
	}
	return .None
}

@(private)
EBUSY :: 16

@(private)
map_os_error :: proc(err: os.Error) -> DNS_Error {
	#partial switch e in err {
	case io.Error:
		if e == .Permission_Denied {
			return .Permission
		}
	case runtime.Allocator_Error:
		return .Out_Of_Memory
	}
	if code, ok := os.is_platform_error(err); ok {
		// EPERM 1, EACCES 13, EROFS 30
		if code == 1 || code == 13 || code == 30 {
			return .Permission
		}
	}
	return .Io
}

// Put the saved resolv.conf back. The backup is removed on success.
@(private)
restore_backup :: proc(env: DNS_Env) -> DNS_Error {
	fi, lerr := os.lstat(env.backup, context.temp_allocator)
	if lerr != nil {
		return map_os_error(lerr)
	}
	#partial switch fi.type {
	case .Symlink:
		target, rerr := os.read_link(env.backup, context.temp_allocator)
		if rerr != nil {
			return map_os_error(rerr)
		}
		if err := replace_file(env.resolv_conf, target, .Symlink); err != .None {
			return err
		}
	case .Regular:
		data, rerr := os.read_entire_file(env.backup, context.temp_allocator)
		if rerr != nil {
			return map_os_error(rerr)
		}
		if err := replace_file(env.resolv_conf, string(data), .Regular); err != .None {
			return err
		}
	case:
		return .Io
	}
	_ = os.remove(env.backup)
	return .None
}

@(private)
revert_resolv_conf :: proc(d: ^DNS) -> DNS_Error {
	env := d.env
	cur, rerr := os.read_entire_file(env.resolv_conf, context.temp_allocator)
	switch {
	case rerr == nil:
		if string(cur) != d.written {
			// Somebody else wrote it. Not ours to touch. The backup stays.
			return .Modified_By_Other
		}
	case rerr == os.General_Error.Not_Exist:
	// Gone: nothing of ours to protect. Fall through and restore.
	case:
		return map_os_error(rerr)
	}
	if d.had_original {
		return restore_backup(env)
	}
	if err := os.remove(env.resolv_conf); err != nil && err != os.General_Error.Not_Exist {
		return map_os_error(err)
	}
	return .None
}

// After a crash: if resolv.conf is still the file we wrote, put the backup
// back and return true. If the file is not ours any more, a leftover backup
// is old and is removed.
@(private)
cleanup_resolv_conf :: proc(env: DNS_Env) -> (restored: bool, err: DNS_Error) {
	if _, lerr := os.lstat(env.backup, context.temp_allocator); lerr != nil {
		return false, .None // no backup: nothing to do
	}
	cur, rerr := os.read_entire_file(env.resolv_conf, context.temp_allocator)
	if rerr == nil && strings.has_prefix(string(cur), DNS_MARKER) {
		if e := restore_backup(env); e != .None {
			return false, e
		}
		return true, .None
	}
	if rerr != nil && rerr != os.General_Error.Not_Exist {
		return false, map_os_error(rerr)
	}
	if rerr == os.General_Error.Not_Exist {
		// The file is gone and the backup is all there is.
		if e := restore_backup(env); e != .None {
			return false, e
		}
		return true, .None
	}
	_ = os.remove(env.backup)
	return false, .None
}

// True if a resolvconf record with this name is in one of `env.record_dirs`.
@(private)
resolvconf_record_exists :: proc(env: DNS_Env, record: string) -> bool {
	for dir in env.record_dirs {
		p := strings.concatenate({dir, "/", record}, context.temp_allocator)
		if _, err := os.lstat(p, context.temp_allocator); err == nil {
			return true
		}
	}
	return false
}

// Call once at start-up, before `dns_apply`, to undo a crashed run: our
// resolv.conf (original put back) and our resolvconf record for `ifname`.
// systemd-resolved needs nothing (it drops a link's settings with the link).
// Returns true if a resolv.conf was restored.
//
// `resolvconf -d` runs only if the record exists: it is slow (openresolv locks
// and sleeps 1 second if another copy runs), so clients that start together
// would wait for nothing. A record outside `env.record_dirs` is not found; the
// next `resolvconf -a` of this link replaces it.
dns_cleanup_stale :: proc(env: DNS_Env, ifname: string) -> (restored: bool, err: DNS_Error) {
	if err = dns_cleanup_stale_record(env, ifname); err != .None {
		return false, err
	}
	return cleanup_resolv_conf(env)
}

// Only the resolvconf record for `ifname` of `dns_cleanup_stale`. It does not
// touch /etc/resolv.conf, so it is safe while another client runs a tunnel.
dns_cleanup_stale_record :: proc(env: DNS_Env, ifname: string) -> DNS_Error {
	if !dns_valid_ifname(ifname) {
		return .Invalid
	}
	if path, ok := find_binary(env, "resolvconf", context.temp_allocator); ok && env.force != .Resolv_Conf {
		record := strings.concatenate({ifname, RESOLVCONF_SUFFIX}, context.temp_allocator)
		if resolvconf_record_exists(env, record) {
			_ = run(env, {path, "-d", record}) // gone by now is fine
		}
	}
	return .None
}

// Restores /etc/resolv.conf when it is still the file of a run that ended
// without a revert (our marker is on its first line). The system-wide part of
// `dns_cleanup_stale`.
dns_cleanup_stale_resolv_conf :: proc(env: DNS_Env) -> (restored: bool, err: DNS_Error) {
	return cleanup_resolv_conf(env)
}

// ---- the clean-up records of the daemons ----

// The name of a backend in a clean-up record.
dns_backend_name :: proc "contextless" (b: DNS_Backend) -> string {
	switch b {
	case .Systemd_Resolved:
		return "systemd-resolved"
	case .Resolvconf:
		return "resolvconf"
	case .Resolv_Conf:
		return "resolv.conf"
	case .None:
	}
	return "none"
}

dns_backend_parse :: proc(name: string) -> (b: DNS_Backend, ok: bool) {
	switch name {
	case "systemd-resolved":
		return .Systemd_Resolved, true
	case "resolvconf":
		return .Resolvconf, true
	case "resolv.conf":
		return .Resolv_Conf, true
	}
	return .None, false
}

// True for a backend that changes one thing for the whole system (the
// resolv.conf file), so that two daemons share it.
dns_backend_shared :: proc(name: string) -> bool {
	return name == "resolv.conf"
}

// What the backend changes for `ifname`, for the reader of a record: the
// resolvconf record, the backup of resolv.conf, the link of systemd-resolved.
dns_record_detail :: proc(env: DNS_Env, b: DNS_Backend, ifname: string, allocator := context.temp_allocator) -> string {
	switch b {
	case .Systemd_Resolved:
		return strings.concatenate({"link ", ifname}, allocator)
	case .Resolvconf:
		return strings.concatenate({"record ", ifname, RESOLVCONF_SUFFIX}, allocator)
	case .Resolv_Conf:
		return strings.concatenate({"backup ", env.backup}, allocator)
	case .None:
	}
	return ""
}

// Reverts the DNS change of a dead daemon, from its record. systemd-resolved
// settings go with the link, so `resolvectl revert` runs only when the link
// still exists (`link_exists`). Returns true if resolv.conf was restored.
dns_cleanup_dead :: proc(env: DNS_Env, b: DNS_Backend, ifname: string, link_exists: bool) -> (restored: bool, err: DNS_Error) {
	if !dns_valid_ifname(ifname) {
		return false, .Invalid
	}
	switch b {
	case .Systemd_Resolved:
		if !link_exists {
			return false, .None
		}
		path, ok := find_binary(env, "resolvectl", context.temp_allocator)
		if !ok {
			return false, .Unsupported
		}
		_ = run(env, {path, "revert", ifname}) // gone by now is fine
		return false, .None
	case .Resolvconf:
		return false, dns_cleanup_stale_record(env, ifname)
	case .Resolv_Conf:
		return cleanup_resolv_conf(env)
	case .None:
	}
	return false, .Invalid
}
