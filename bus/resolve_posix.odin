// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package bus

import "core:mem"
import "core:strconv"
import "core:strings"
import "core:sys/posix"
import "noir:proto/config"

// Look a user or group name up in the system database (passwd, group). A
// plain number is accepted too. Used at startup and at a reload.
default_resolver :: proc(kind: config.Bus_Id_Kind, name: string) -> (id: u32, ok: bool) {
	if n, is_num := strconv.parse_u64(name, 10); is_num {
		return u32(n), n <= 0xffff_fffe
	}
	cname := strings.clone_to_cstring(name, context.temp_allocator)
	buf: [4096]byte
	switch kind {
	case .Uid:
		pwd: posix.passwd
		result: ^posix.passwd
		if posix.getpwnam_r(cname, &pwd, raw_data(buf[:]), len(buf), &result) != .NONE || result == nil {
			return 0, false
		}
		return u32(result.pw_uid), true
	case .Gid:
		grp: posix.group
		result: ^posix.group
		if posix.getgrnam_r(cname, &grp, raw_data(buf[:]), len(buf), &result) != .NONE || result == nil {
			return 0, false
		}
		return u32(result.gr_gid), true
	case .Sid:
	}
	return 0, false
}

// True if the user `uid` is a member of the group `gid`: the group is the
// primary group of the user in the passwd database, or the group database
// lists the user name. An unknown uid or gid is no member. Only the reentrant
// lookups are used, because this runs on a worker thread.
default_member :: proc(uid, gid: u32) -> bool {
	pbuf: [4096]byte
	pwd: posix.passwd
	presult: ^posix.passwd
	if posix.getpwuid_r(posix.uid_t(uid), &pwd, raw_data(pbuf[:]), len(pbuf), &presult) != .NONE || presult == nil {
		return false
	}
	if u32(presult.pw_gid) == gid {
		return true
	}
	if presult.pw_name == nil {
		return false
	}
	name := string(presult.pw_name)
	grp: posix.group
	gresult: ^posix.group
	gbuf: [16384]byte
	e := posix.getgrgid_r(posix.gid_t(gid), &grp, raw_data(gbuf[:]), len(gbuf), &gresult)
	// A group with many members needs a larger buffer (ERANGE).
	big: []byte
	defer delete(big)
	for size := 4 * len(gbuf); e == .ERANGE && size <= MEMBER_BUF_MAX; size *= 4 {
		delete(big)
		aerr: mem.Allocator_Error
		big, aerr = make([]byte, size)
		if aerr != nil {
			return false
		}
		e = posix.getgrgid_r(posix.gid_t(gid), &grp, raw_data(big), uint(size), &gresult)
	}
	if e != .NONE || gresult == nil || gresult.gr_mem == nil {
		return false
	}
	for i := 0; gresult.gr_mem[i] != nil; i += 1 {
		if string(gresult.gr_mem[i]) == name {
			return true
		}
	}
	return false
}

// The largest buffer for one group entry.
@(private)
MEMBER_BUF_MAX :: 1024 * 1024

// The effective user id of this process.
euid :: proc() -> u32 {
	return u32(posix.geteuid())
}

// Windows account names have no meaning here: a `sid` rule is ignored.
default_sid_resolver :: proc(name: string) -> (sid: Sid, ok: bool) {
	return {}, false
}
