// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:time"
import "noir:platform/sysnet"

// Files of the clean-up records on Linux (record.odin has the format).
//   - Folder `/run/noirvpn/state` (`record_default_dir`), owned by the daemon
//     user, mode 0700 when created. Its parent must belong to the same user or root
//     and not be writable by others. The parent is also the default bus folder,
//     so the daemon has the bus create it first (bus mode and group). A missing
//     parent (bus off, or sockets elsewhere) is created with 0755.
//   - Files open relative to the folder, without following a symlink. A file is
//     refused (not read, not removed) if it is not a regular file of the same
//     user, or if group or others can read it.
//   - Lock: `flock` on `<id>.lock`, ends with the process.
//   - A write goes to `<id>.tmp`, then rename. A daemon that gave up root (`user`)
//     cannot create files in the folder: it rewrites `<id>.rec` in place through the
//     file opened before (truncate, write, fsync) and at stop leaves an empty
//     record for the next start to remove. A crash in such a write leaves a record
//     without its `end` line; clean-up still reverts it as far as it goes.

RECORD_DIR :: "/run/noirvpn/state"

// The state folder of a daemon of root. A daemon of another user (with the
// network capability only) uses `$XDG_RUNTIME_DIR/noirvpn/state`, else
// `/tmp/noirvpn-<uid>/state`, like the control bus does for its sockets.
record_default_dir :: proc(allocator := context.temp_allocator) -> string {
	euid := linux.geteuid()
	if euid == 0 {
		return strings.clone(RECORD_DIR, allocator)
	}
	if xdg, ok := os.lookup_env("XDG_RUNTIME_DIR", context.temp_allocator); ok && strings.has_prefix(xdg, "/") {
		return strings.concatenate({strings.trim_right(xdg, "/"), "/noirvpn/state"}, allocator)
	}
	return fmt.aprintf("/tmp/noirvpn-%d/state", euid, allocator = allocator)
}

// The record of this daemon, open.
Record_File :: struct {
	ok:        bool,
	rec:       Record,
	dir_fd:    linux.Fd,
	lock_fd:   linux.Fd,
	// `<id>.rec`, open for a rewrite in place (-1: none).
	rec_fd:    linux.Fd,
	// The folder refused a new file: every write is in place.
	in_place:  bool,
	id_buf:    [64]u8,
	id_len:    int,
	// The text of the last write: an equal record is not written again.
	last:      string,
	allocator: mem.Allocator,
}

Record_Open_Error :: enum u8 {
	None,
	// The folder or its parent is not a folder of this user, or others can
	// write to it.
	Dir_Not_Safe,
	Dir_Failed,
	Lock_Failed,
	Write_Failed,
}

record_id :: proc(f: ^Record_File) -> string {
	return string(f.id_buf[:f.id_len])
}

// Opens the folder `dir` (created when missing), creates the lock of this daemon
// and writes an empty record. On an error nothing stays open.
record_open :: proc(f: ^Record_File, dir: string, name: string, role: Record_Role, allocator := context.allocator) -> Record_Open_Error {
	f^ = {}
	f.dir_fd = -1
	f.lock_fd = -1
	f.rec_fd = -1
	f.allocator = allocator
	dfd, derr := open_state_dir(dir)
	if derr != .None {
		return derr
	}
	f.dir_fd = dfd
	pid := linux.getpid()
	id := fmt.bprintf(f.id_buf[:], "%d-%x", pid, time.now()._nsec)
	f.id_len = len(id)
	lock := cname(f, ".lock")
	fd, oerr := linux.openat(f.dir_fd, lock, {.RDWR, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC}, mode_of(0o600))
	if oerr != .NONE {
		linux.close(f.dir_fd)
		f^ = {}
		return .Lock_Failed
	}
	if linux.flock(fd, {.EX, .NB}) != .NONE {
		linux.close(fd)
		linux.unlinkat(f.dir_fd, lock, {})
		linux.close(f.dir_fd)
		f^ = {}
		return .Lock_Failed
	}
	f.lock_fd = fd
	record_init(&f.rec, allocator)
	f.rec.pid = int(pid)
	f.rec.name = clean_text(name, allocator)
	f.rec.role = role
	f.ok = true
	if record_write(f) != .None {
		record_close(f)
		return .Write_Failed
	}
	return .None
}

// Writes the record if it differs from the last write: temporary file, fsync,
// rename. If the folder refuses the temporary file (the daemon gave up root),
// all later writes are in place.
record_write :: proc(f: ^Record_File) -> Record_Error {
	if !f.ok {
		return .None
	}
	text := record_encode(&f.rec, f.allocator)
	if text == f.last {
		delete(text, f.allocator)
		return .None
	}
	ok: bool
	if !f.in_place {
		switch write_renamed(f, text) {
		case .Done:
			ok = true
		case .No_Access:
			f.in_place = true
		case .Failed:
		}
	}
	if f.in_place {
		ok = write_in_place(f, text)
	}
	if !ok {
		delete(text, f.allocator)
		return .Io
	}
	delete(f.last, f.allocator)
	f.last = text
	return .None
}

// Removes the record and its lock. Call it after the teardown. Returns false
// if the folder refuses it (the daemon gave up root). The record then stays,
// rewritten as empty, and the next start removes it.
record_close :: proc(f: ^Record_File) -> (removed: bool) {
	if !f.ok {
		return true
	}
	removed = true
	if e := linux.unlinkat(f.dir_fd, cname(f, ".rec"), {}); e == .EACCES || e == .EPERM {
		removed = false
		record_clear(&f.rec)
		record_write(f)
	} else {
		linux.unlinkat(f.dir_fd, cname(f, ".tmp"), {})
		linux.unlinkat(f.dir_fd, cname(f, ".lock"), {})
	}
	record_release(f)
	return removed
}

// Closes the files and keeps them, as a crash does: the next start finds the
// record without its lock.
record_release :: proc(f: ^Record_File) {
	if !f.ok {
		return
	}
	linux.close(f.lock_fd)
	if f.rec_fd >= 0 {
		linux.close(f.rec_fd)
	}
	linux.close(f.dir_fd)
	record_destroy(&f.rec)
	delete(f.last, f.allocator)
	f^ = {}
}

// ---- reading the records of other daemons ----

// A record found in the folder.
Record_Found :: struct {
	id:      string,
	rec:     Record,
	// The record could not be read (another version, a bad line).
	bad:     bool,
	// The record ends before its `end` line; `rec` holds the lines before.
	cut:     bool,
	// The lock, held while a dead record is reverted (-1: none).
	lock_fd: linux.Fd,
}

Record_Scan :: struct {
	live:         [dynamic]Record_Found,
	dead:         [dynamic]Record_Found,
	// Records cut short, of another version, or refused.
	bad:          int,
	// A live record could not be read.
	live_unknown: bool,
}

// Reads the records in the folder of `own`, except its own record.
// A record whose lock this process can take is dead. Its lock stays held until
// `record_forget` or `record_scan_destroy`.
record_scan :: proc(own: ^Record_File, allocator := context.allocator) -> (s: Record_Scan) {
	s.live = make([dynamic]Record_Found, allocator)
	s.dead = make([dynamic]Record_Found, allocator)
	if !own.ok {
		return s
	}
	names := list_ids(own.dir_fd, context.temp_allocator)
	for id in names {
		if id == record_id(own) {
			continue
		}
		found := Record_Found {
			id      = strings.clone(id, allocator),
			lock_fd = -1,
		}
		lock := strings.clone_to_cstring(strings.concatenate({id, ".lock"}, context.temp_allocator), context.temp_allocator)
		fd, oerr := linux.openat(own.dir_fd, lock, {.RDWR, .NOFOLLOW, .CLOEXEC})
		live := false
		#partial switch oerr {
		case .NONE:
			if !file_is_ours(fd, 0) {
				linux.close(fd)
				s.bad += 1
				delete(found.id, allocator)
				continue
			}
			ferr := linux.flock(fd, {.EX, .NB})
			if ferr == .EWOULDBLOCK {
				live = true
				linux.close(fd)
			} else if ferr == .NONE {
				found.lock_fd = fd
			} else {
				linux.close(fd)
				s.bad += 1
				delete(found.id, allocator)
				continue
			}
		case .ENOENT:
		// A record without its lock: its owner is gone.
		case:
			// A symbolic link, or no access: not ours.
			s.bad += 1
			delete(found.id, allocator)
			continue
		}
		rec, rerr := read_record(own.dir_fd, id, allocator)
		switch rerr {
		case .None:
			found.rec = rec
		case .Io:
			// No record yet: the owner is between its lock and its first write.
			record_init(&found.rec, allocator)
			if !live {
				found.bad = true
			}
		case .Refused:
			if found.lock_fd >= 0 {
				linux.close(found.lock_fd)
			}
			s.bad += 1
			delete(found.id, allocator)
			continue
		case .Truncated:
			// A write cut short: the lines before the cut count. Of a live
			// daemon the rest is not known.
			found.rec = rec
			found.cut = true
			if live {
				s.live_unknown = true
			}
		case .Bad_Version, .Bad_Line:
			record_init(&found.rec, allocator)
			found.bad = true
			s.bad += 1
			if live {
				s.live_unknown = true
			}
		}
		if live {
			append(&s.live, found)
		} else {
			append(&s.dead, found)
		}
	}
	return s
}

record_scan_destroy :: proc(s: ^Record_Scan) {
	for &f in s.live {
		found_destroy(&f)
	}
	for &f in s.dead {
		found_destroy(&f)
	}
	delete(s.live)
	delete(s.dead)
	s^ = {}
}

@(private)
found_destroy :: proc(f: ^Record_Found) {
	if f.lock_fd >= 0 {
		linux.close(f.lock_fd)
		f.lock_fd = -1
	}
	a := f.rec.allocator
	record_destroy(&f.rec)
	delete(f.id, a)
	f.id = ""
}

// Removes the files of a dead record and lets go of its lock.
record_forget :: proc(own: ^Record_File, f: ^Record_Found) {
	if f.id == "" {
		return
	}
	for suffix in ([]string{".rec", ".tmp", ".lock"}) {
		name := strings.clone_to_cstring(strings.concatenate({f.id, suffix}, context.temp_allocator), context.temp_allocator)
		linux.unlinkat(own.dir_fd, name, {})
	}
	if f.lock_fd >= 0 {
		linux.close(f.lock_fd)
		f.lock_fd = -1
	}
}

// The DNS leftovers of an older version that has no records:
//   - the resolvconf record of `hint`
//   - resolv.conf, if it still has our marker
// Each one goes only if no live record and no device can own it. Returns how
// many were removed.
record_dns_fallback :: proc(env: sysnet.DNS_Env, live: []^Record, links: []Record_Link, hint: string) -> (n: int, err: sysnet.DNS_Error) {
	if hint == "" {
		return 0, .None
	}
	if !record_dns_protected({backend = "resolvconf", ifname = hint}, nil, live, links) {
		if e := sysnet.dns_cleanup_stale_record(env, hint); e != .None {
			err = e
		}
	}
	shared := Record_DNS {
		backend = "resolv.conf",
		ifname  = "",
	}
	if !record_dns_protected(shared, nil, live, links) {
		restored, e := sysnet.dns_cleanup_stale_resolv_conf(env)
		if restored {
			n += 1
		}
		if e != .None && err == .None {
			err = e
		}
	}
	return n, err
}

// ---- helpers ----

@(private)
mode_of :: proc "contextless" (m: u32) -> linux.Mode {
	return transmute(linux.Mode)m
}

@(private)
perm_of :: proc "contextless" (m: linux.Mode) -> u32 {
	return transmute(u32)m & 0o7777
}

@(private)
cname :: proc(f: ^Record_File, suffix: string) -> cstring {
	return strings.clone_to_cstring(strings.concatenate({record_id(f), suffix}, context.temp_allocator), context.temp_allocator)
}

@(private)
write_all :: proc(fd: linux.Fd, data: []u8) -> bool {
	rest := data
	for len(rest) > 0 {
		n, err := linux.write(fd, rest)
		if err == .EINTR {
			continue
		}
		if err != .NONE || n <= 0 {
			return false
		}
		rest = rest[n:]
	}
	return true
}

@(private)
Rename_Result :: enum u8 {
	Done,
	// The folder does not let this process create a file.
	No_Access,
	Failed,
}

// The write through `<id>.tmp` and a rename. After the rename, `rec_fd` is
// the new file, for a later write in place.
@(private)
write_renamed :: proc(f: ^Record_File, text: string) -> Rename_Result {
	tmp := cname(f, ".tmp")
	linux.unlinkat(f.dir_fd, tmp, {})
	fd, oerr := linux.openat(f.dir_fd, tmp, {.WRONLY, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC}, mode_of(0o600))
	if oerr == .EACCES || oerr == .EPERM {
		return .No_Access
	}
	if oerr != .NONE {
		return .Failed
	}
	ok := write_all(fd, transmute([]u8)text) && linux.fsync(fd) == .NONE
	linux.close(fd)
	rec := cname(f, ".rec")
	if !ok || linux.renameat(f.dir_fd, tmp, f.dir_fd, rec) != .NONE {
		linux.unlinkat(f.dir_fd, tmp, {})
		return .Failed
	}
	if f.rec_fd >= 0 {
		linux.close(f.rec_fd)
		f.rec_fd = -1
	}
	if rfd, rerr := linux.openat(f.dir_fd, rec, {.RDWR, .NOFOLLOW, .CLOEXEC}); rerr == .NONE {
		f.rec_fd = rfd
	}
	return .Done
}

// The write in place through `rec_fd`. The file is cut to zero first, so a
// crash in the write leaves a first part of the new text, never a mix of two
// texts.
@(private)
write_in_place :: proc(f: ^Record_File, text: string) -> bool {
	if f.rec_fd < 0 || linux.ftruncate(f.rec_fd, 0) != .NONE {
		return false
	}
	rest := transmute([]u8)text
	off: i64 = 0
	for len(rest) > 0 {
		n, err := linux.pwrite(f.rec_fd, rest, off)
		if err == .EINTR {
			continue
		}
		if err != .NONE || n <= 0 {
			return false
		}
		rest = rest[n:]
		off += i64(n)
	}
	return linux.fsync(f.rec_fd) == .NONE
}

// A regular file of this user that the group and others cannot read, and not
// larger than `max_size` (0: any size).
@(private)
file_is_ours :: proc(fd: linux.Fd, max_size: int) -> bool {
	st: linux.Stat
	if linux.fstat(fd, &st) != .NONE {
		return false
	}
	if !linux.S_ISREG(st.mode) || st.uid != linux.geteuid() || perm_of(st.mode) & 0o077 != 0 {
		return false
	}
	return max_size == 0 || int(st.size) <= max_size
}

// A folder of this user (or of root, for `parent`) that others cannot write to.
@(private)
dir_is_safe :: proc(fd: linux.Fd, private: bool) -> bool {
	st: linux.Stat
	if linux.fstat(fd, &st) != .NONE || !linux.S_ISDIR(st.mode) {
		return false
	}
	me := linux.geteuid()
	perm := perm_of(st.mode)
	if private {
		return st.uid == me && perm & 0o027 == 0
	}
	return (st.uid == me || st.uid == 0) && perm & 0o022 == 0
}

@(private)
open_state_dir :: proc(dir: string) -> (fd: linux.Fd, err: Record_Open_Error) {
	path := strings.trim_right(dir, "/")
	slash := strings.last_index_byte(path, '/')
	if slash < 0 || slash == len(path) - 1 {
		return -1, .Dir_Failed
	}
	parent := path[:slash] if slash > 0 else "/"
	base := strings.clone_to_cstring(path[slash + 1:], context.temp_allocator)
	cparent := strings.clone_to_cstring(parent, context.temp_allocator)
	if e := linux.mkdirat(linux.AT_FDCWD, cparent, mode_of(0o755)); e != .NONE && e != .EEXIST {
		return -1, .Dir_Failed
	}
	pfd, perr := linux.openat(linux.AT_FDCWD, cparent, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
	if perr != .NONE {
		return -1, .Dir_Not_Safe if perr == .ELOOP || perr == .ENOTDIR else .Dir_Failed
	}
	defer linux.close(pfd)
	if !dir_is_safe(pfd, false) {
		return -1, .Dir_Not_Safe
	}
	if e := linux.mkdirat(pfd, base, mode_of(0o700)); e != .NONE && e != .EEXIST {
		return -1, .Dir_Failed
	}
	dfd, derr := linux.openat(pfd, base, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
	if derr != .NONE {
		return -1, .Dir_Not_Safe if derr == .ELOOP || derr == .ENOTDIR else .Dir_Failed
	}
	if !dir_is_safe(dfd, true) {
		linux.close(dfd)
		return -1, .Dir_Not_Safe
	}
	return dfd, .None
}

// The ids of the records in the folder: the names of `.lock` and `.rec` files
// without the suffix, each once.
@(private)
list_ids :: proc(dir_fd: linux.Fd, allocator: mem.Allocator) -> []string {
	out := make([dynamic]string, allocator)
	fd, err := linux.openat(dir_fd, ".", {.DIRECTORY, .CLOEXEC})
	if err != .NONE {
		return out[:]
	}
	defer linux.close(fd)
	buf: [4096]u8
	for {
		n, gerr := linux.getdents(fd, buf[:])
		if gerr != .NONE || n <= 0 {
			break
		}
		off := 0
		for d in linux.dirent_iterate_buf(buf[:n], &off) {
			name := linux.dirent_name(d)
			id: string
			if strings.has_suffix(name, ".lock") {
				id = name[:len(name) - 5]
			} else if strings.has_suffix(name, ".rec") {
				id = name[:len(name) - 4]
			} else {
				continue
			}
			if id == "" {
				continue
			}
			seen := false
			for o in out {
				if o == id {
					seen = true
					break
				}
			}
			if !seen {
				append(&out, strings.clone(id, allocator))
			}
		}
	}
	return out[:]
}

// Reads `<id>.rec`. `.Io` when there is no such file.
@(private)
read_record :: proc(dir_fd: linux.Fd, id: string, allocator: mem.Allocator) -> (r: Record, err: Record_Error) {
	name := strings.clone_to_cstring(strings.concatenate({id, ".rec"}, context.temp_allocator), context.temp_allocator)
	fd, oerr := linux.openat(dir_fd, name, {.NOFOLLOW, .CLOEXEC})
	if oerr == .ENOENT {
		return {}, .Io
	}
	if oerr != .NONE {
		return {}, .Refused
	}
	defer linux.close(fd)
	if !file_is_ours(fd, RECORD_MAX_SIZE) {
		return {}, .Refused
	}
	buf := make([]u8, RECORD_MAX_SIZE + 1, context.temp_allocator)
	total := 0
	for total < len(buf) {
		n, rerr := linux.read(fd, buf[total:])
		if rerr == .EINTR {
			continue
		}
		if rerr != .NONE {
			return {}, .Refused
		}
		if n == 0 {
			break
		}
		total += n
	}
	if total > RECORD_MAX_SIZE {
		return {}, .Refused
	}
	return record_decode_partial(string(buf[:total]), allocator)
}
