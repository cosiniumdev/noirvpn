// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:sys/linux"
import "core:sys/posix"

// `user` and `group`: the daemon starts as root, sets everything up, then
// switches to the user and group and keeps only CAP_NET_ADMIN. It needs that
// capability until it stops: routes, addresses and the DCO device change at run
// time, and the stop removes them.
//
// The uid and gid change through libc, which applies to every thread (the crypto
// and bus workers exist by then). The capability set is per thread: only the main
// thread (the event loop) keeps CAP_NET_ADMIN. Workers lose every capability.

Priv_Target :: struct {
	// The names as written in the config, for messages.
	user:       string,
	group:      string,
	uid:        u32,
	gid:        u32,
	change_uid: bool,
	// True when the config names `user` or `group`.
	on:         bool,
}

PRIV: Priv_Target

// True after the switch to a user other than root. The client then does not
// write the system DNS settings (they need root); the bus event
// `client.tunnel_settings` holds them.
privs_dropped: bool

@(private = "file")
CAP_NET_ADMIN :: 12
@(private = "file")
PR_SET_KEEPCAPS :: 8
@(private = "file")
PR_SET_NO_NEW_PRIVS :: 38

@(private = "file")
Cap_Header :: struct {
	version: u32,
	pid:     i32,
}

@(private = "file")
Cap_Data :: struct {
	effective:   u32,
	permitted:   u32,
	inheritable: u32,
}

@(private = "file")
CAP_V3 :: 0x20080522

foreign import libc "system:c"

@(private = "file", default_calling_convention = "c")
foreign libc {
	setresuid :: proc(r, e, s: posix.uid_t) -> i32 ---
	setresgid :: proc(r, e, s: posix.gid_t) -> i32 ---
	setgroups :: proc(n: uint, list: [^]posix.gid_t) -> i32 ---
}

// Finds the uid and gid for `user` and `group`. A number is used as is. `user`
// alone takes the user's primary group from the passwd database. `group` alone
// changes the group only. Returns an error text for the config.
priv_resolve :: proc(user, group: string) -> (t: Priv_Target, err: string) {
	t.user, t.group = user, group
	t.on = user != "" || group != ""
	if !t.on {
		return
	}
	primary_gid: u32
	has_primary := false
	if user != "" {
		pbuf: [4096]byte
		pwd: posix.passwd
		res: ^posix.passwd
		e: posix.Errno
		if n, is_num := strconv.parse_u64(user, 10); is_num {
			if n > 0xffff_fffe {
				return t, fmt.tprintf("user %s: not a valid uid", user)
			}
			t.uid = u32(n)
			e = posix.getpwuid_r(posix.uid_t(n), &pwd, raw_data(pbuf[:]), len(pbuf), &res)
		} else {
			cname := strings.clone_to_cstring(user, context.temp_allocator)
			e = posix.getpwnam_r(cname, &pwd, raw_data(pbuf[:]), len(pbuf), &res)
			if e != .NONE || res == nil {
				return t, fmt.tprintf("user %s: this user does not exist", user)
			}
			t.uid = u32(res.pw_uid)
		}
		if e == .NONE && res != nil {
			primary_gid = u32(res.pw_gid)
			has_primary = true
		}
		t.change_uid = true
	}
	if group != "" {
		if n, is_num := strconv.parse_u64(group, 10); is_num {
			if n > 0xffff_fffe {
				return t, fmt.tprintf("group %s: not a valid gid", group)
			}
			t.gid = u32(n)
		} else {
			gbuf: [16384]byte
			grp: posix.group
			res: ^posix.group
			cname := strings.clone_to_cstring(group, context.temp_allocator)
			if posix.getgrnam_r(cname, &grp, raw_data(gbuf[:]), len(gbuf), &res) != .NONE || res == nil {
				return t, fmt.tprintf("group %s: this group does not exist", group)
			}
			t.gid = u32(res.gr_gid)
		}
	} else if has_primary {
		t.gid = primary_gid
	} else {
		return t, fmt.tprintf("user %s: the uid has no passwd entry, so it has no primary group (add the group option)", user)
	}
	return
}

// The config error for `user` and `group`, or "".
priv_settings_error :: proc(user, group: string) -> string {
	_, err := priv_resolve(user, group)
	return err
}

// Resolves `user` and `group` into PRIV. False with a message on stderr when
// a name is unknown (a config error).
priv_prepare :: proc(user, group: string) -> bool {
	t, err := priv_resolve(user, group)
	if err != "" {
		eprint("noirvpn: %s", err)
		return false
	}
	PRIV = t
	return true
}

// The text for --check-config, or "" when the config names neither option or
// a name is unknown (settings_load reports that).
priv_check_text :: proc(user, group: string) -> string {
	t, err := priv_resolve(user, group)
	if !t.on || err != "" {
		return ""
	}
	if t.change_uid {
		return fmt.tprintf("privileges: after start-up, the daemon will run as uid %d gid %d with only CAP_NET_ADMIN", t.uid, t.gid)
	}
	return fmt.tprintf("privileges: after start-up, the daemon will run with gid %d (the uid stays the same)", t.gid)
}

// Switches to PRIV. Call it on the main thread, after the tun device, sockets,
// DCO device, bus and pid file are open. False with a logged error if a step
// fails: the caller stops the daemon, it never goes on as root. `tun_later` is
// true for a client: it opens its tun device at each connection, so the user
// needs access to /dev/net/tun.
priv_apply :: proc(tun_later := false) -> bool {
	t := PRIV
	if !t.on {
		return true
	}
	ruid, euid, suid, rgid, egid, sgid: u32
	_ = linux.syscall(linux.SYS_getresuid, &ruid, &euid, &suid)
	_ = linux.syscall(linux.SYS_getresgid, &rgid, &egid, &sgid)
	if (!t.change_uid || ruid == t.uid && euid == t.uid && suid == t.uid) && rgid == t.gid && egid == t.gid && sgid == t.gid {
		logf(.Info, "privileges: already running as uid %d gid %d", euid, egid)
		return true
	}
	drop_caps := t.change_uid && t.uid != 0
	if drop_caps && linux.syscall(linux.SYS_prctl, uintptr(PR_SET_KEEPCAPS), uintptr(1)) < 0 {
		logf(.Error, "privileges: prctl(PR_SET_KEEPCAPS) failed")
		return false
	}
	gid := posix.gid_t(t.gid)
	if setgroups(1, &gid) != 0 {
		logf(.Error, "privileges: cannot set the groups to %d: %v", t.gid, posix.errno())
		return false
	}
	if setresgid(gid, gid, gid) != 0 {
		logf(.Error, "privileges: cannot change to group %s (gid %d): %v", t.group if t.group != "" else t.user, t.gid, posix.errno())
		return false
	}
	if t.change_uid {
		uid := posix.uid_t(t.uid)
		if setresuid(uid, uid, uid) != 0 {
			logf(.Error, "privileges: cannot change to user %s (uid %d): %v", t.user, t.uid, posix.errno())
			return false
		}
	}
	if drop_caps {
		hdr := Cap_Header {
			version = CAP_V3,
		}
		data := [2]Cap_Data{{effective = 1 << CAP_NET_ADMIN, permitted = 1 << CAP_NET_ADMIN}, {}}
		if linux.syscall(linux.SYS_capset, &hdr, &data) < 0 {
			logf(.Error, "privileges: cannot keep CAP_NET_ADMIN after the change to uid %d", t.uid)
			return false
		}
		_ = linux.syscall(linux.SYS_prctl, uintptr(PR_SET_KEEPCAPS), uintptr(0))
	}
	if linux.syscall(linux.SYS_prctl, uintptr(PR_SET_NO_NEW_PRIVS), uintptr(1), uintptr(0), uintptr(0), uintptr(0)) < 0 {
		logf(.Error, "privileges: prctl(PR_SET_NO_NEW_PRIVS) failed")
		return false
	}
	if !priv_verify(t, drop_caps) {
		return false
	}
	privs_dropped = drop_caps
	if tun_later && drop_caps && linux.access("/dev/net/tun", {.IROTH, .IWOTH}) != .NONE {
		logf(.Warn, "privileges: user %s cannot open /dev/net/tun, so the tunnel will not open (give the user or its group access to the device node)", t.user)
	}
	if drop_caps {
		logf(.Notice, "privileges: now running as uid %d gid %d with only CAP_NET_ADMIN", t.uid, t.gid)
	} else {
		logf(.Notice, "privileges: now running with gid %d", t.gid)
	}
	return true
}

// Checks what the kernel says after the switch.
@(private = "file")
priv_verify :: proc(t: Priv_Target, drop_caps: bool) -> bool {
	ruid, euid, suid, rgid, egid, sgid: u32
	_ = linux.syscall(linux.SYS_getresuid, &ruid, &euid, &suid)
	_ = linux.syscall(linux.SYS_getresgid, &rgid, &egid, &sgid)
	if rgid != t.gid || egid != t.gid || sgid != t.gid {
		logf(.Error, "privileges: after the change, the gid is %d/%d/%d instead of %d", rgid, egid, sgid, t.gid)
		return false
	}
	if t.change_uid && (ruid != t.uid || euid != t.uid || suid != t.uid) {
		logf(.Error, "privileges: after the change, the uid is %d/%d/%d instead of %d", ruid, euid, suid, t.uid)
		return false
	}
	if !drop_caps {
		return true
	}
	hdr := Cap_Header {
		version = CAP_V3,
	}
	data: [2]Cap_Data
	if linux.syscall(linux.SYS_capget, &hdr, &data) < 0 {
		logf(.Error, "privileges: cannot read the capabilities after the change")
		return false
	}
	want := u32(1 << CAP_NET_ADMIN)
	if data[0].effective != want || data[0].permitted != want || data[0].inheritable != 0 || data[1] != {} {
		logf(.Error, "privileges: after the change, the capabilities are not limited to CAP_NET_ADMIN")
		return false
	}
	return true
}
