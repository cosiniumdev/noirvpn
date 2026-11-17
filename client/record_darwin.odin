// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:c"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "noir:platform/sysnet"

// Files of the clean-up records on macOS (record.odin has the format). Same rules
// and names as record_linux.odin, on core:sys/posix.
//   - Folder `/var/run/noirvpn/state` (`record_default_dir`; macOS has no /run),
//     owned by the daemon user, mode 0700 when created. Its parent must belong to
//     the same user or root and not be writable by others. The parent is also the
//     default bus folder, so the daemon has the bus create it first (bus mode and
//     group). A missing parent (bus off, or sockets elsewhere) is created with 0755.
//   - Files open relative to the folder, without following a symlink. A file is
//     refused (not read, not removed) if it is not a regular file of the same
//     user, or if group or others can read it.
//   - Lock: BSD `flock(2)` on `<id>.lock`, ends with the process. (posix has only
//     per-process `fcntl` locks: two daemons in one process look the same.)
//   - A write goes to `<id>.tmp`, then rename. If the daemon cannot create files in
//     the folder, it rewrites `<id>.rec` in place through the file opened before
//     (truncate, write, fsync) and at stop leaves an empty record for the next
//     start to remove. A crash in such a write leaves a record without its `end`
//     line; clean-up still reverts it as far as it goes.

RECORD_DIR :: "/var/run/noirvpn/state"

foreign import libsystem "system:System"

@(default_calling_convention = "c")
foreign libsystem {
	flock :: proc(fd: c.int, operation: c.int) -> c.int ---
}

@(private)
LOCK_EX :: 0x02
@(private)
LOCK_NB :: 0x04

// The state folder of a daemon of root. A daemon of another user uses
// `$XDG_RUNTIME_DIR/noirvpn/state`, else `/tmp/noirvpn-<uid>/state`, like the
// control bus does for its sockets.
record_default_dir :: proc(allocator := context.temp_allocator) -> string {
	euid := posix.geteuid()
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
	dir_fd:    posix.FD,
	lock_fd:   posix.FD,
	// `<id>.rec`, open for a rewrite in place (-1: none).
	rec_fd:    posix.FD,
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
	pid := posix.getpid()
	id := fmt.bprintf(f.id_buf[:], "%d-%x", pid, time.now()._nsec)
	f.id_len = len(id)
	lock := cname(f, ".lock")
	fd := posix.openat(f.dir_fd, lock, {.RDWR, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC}, mode_of(0o600))
	if fd < 0 {
		posix.close(f.dir_fd)
		f^ = {}
		return .Lock_Failed
	}
	if flock(c.int(fd), LOCK_EX | LOCK_NB) != 0 {
		posix.close(fd)
		posix.unlinkat(f.dir_fd, lock, {})
		posix.close(f.dir_fd)
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
// rename. If the folder refuses the temporary file, all later writes are in
// place.
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
// if the folder refuses it. The record then stays, rewritten as empty, and the
// next start removes it.
record_close :: proc(f: ^Record_File) -> (removed: bool) {
	if !f.ok {
		return true
	}
	removed = true
	if posix.unlinkat(f.dir_fd, cname(f, ".rec"), {}) != .OK {
		if e := posix.errno(); e == .EACCES || e == .EPERM {
			removed = false
			record_clear(&f.rec)
			record_write(f)
		}
	}
	if removed {
		posix.unlinkat(f.dir_fd, cname(f, ".tmp"), {})
		posix.unlinkat(f.dir_fd, cname(f, ".lock"), {})
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
	posix.close(f.lock_fd)
	if f.rec_fd >= 0 {
		posix.close(f.rec_fd)
	}
	posix.close(f.dir_fd)
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
	lock_fd: posix.FD,
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
		fd := posix.openat(own.dir_fd, lock, {.RDWR, .NOFOLLOW, .CLOEXEC})
		live := false
		if fd >= 0 {
			if !file_is_ours(fd, 0) {
				posix.close(fd)
				s.bad += 1
				delete(found.id, allocator)
				continue
			}
			if flock(c.int(fd), LOCK_EX | LOCK_NB) == 0 {
				found.lock_fd = fd
			} else if ferr := posix.errno(); ferr == .EWOULDBLOCK {
				live = true
				posix.close(fd)
			} else {
				posix.close(fd)
				s.bad += 1
				delete(found.id, allocator)
				continue
			}
		} else if oerr := posix.errno(); oerr != .ENOENT {
			// A symbolic link, or no access: not ours. (ENOENT is a record
			// without its lock: its owner is gone.)
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
				posix.close(found.lock_fd)
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
		posix.close(f.lock_fd)
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
		posix.unlinkat(own.dir_fd, name, {})
	}
	if f.lock_fd >= 0 {
		posix.close(f.lock_fd)
		f.lock_fd = -1
	}
	a := f.rec.allocator
	record_destroy(&f.rec)
	delete(f.id, a)
	f.id = ""
}

// The DNS leftovers of an older version, which has no records. macOS has no
// older version: there is nothing to look for.
record_dns_fallback :: proc(env: sysnet.DNS_Env, live: []^Record, links: []Record_Link, hint: string) -> (n: int, err: sysnet.DNS_Error) {
	return 0, .None
}

// ---- helpers ----

@(private)
mode_of :: proc "contextless" (m: u32) -> posix.mode_t {
	return transmute(posix.mode_t)u16(m)
}

@(private)
perm_of :: proc "contextless" (m: posix.mode_t) -> u32 {
	return u32(transmute(u16)m) & 0o7777
}

@(private)
cname :: proc(f: ^Record_File, suffix: string) -> cstring {
	return strings.clone_to_cstring(strings.concatenate({record_id(f), suffix}, context.temp_allocator), context.temp_allocator)
}

@(private)
write_all :: proc(fd: posix.FD, data: []u8) -> bool {
	rest := data
	for len(rest) > 0 {
		n := posix.write(fd, raw_data(rest), uint(len(rest)))
		if n < 0 && posix.errno() == .EINTR {
			continue
		}
		if n <= 0 {
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
	posix.unlinkat(f.dir_fd, tmp, {})
	fd := posix.openat(f.dir_fd, tmp, {.WRONLY, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC}, mode_of(0o600))
	if fd < 0 {
		if e := posix.errno(); e == .EACCES || e == .EPERM {
			return .No_Access
		}
		return .Failed
	}
	ok := write_all(fd, transmute([]u8)text) && posix.fsync(fd) == .OK
	posix.close(fd)
	rec := cname(f, ".rec")
	if !ok || posix.renameat(f.dir_fd, tmp, f.dir_fd, rec) != .OK {
		posix.unlinkat(f.dir_fd, tmp, {})
		return .Failed
	}
	if f.rec_fd >= 0 {
		posix.close(f.rec_fd)
		f.rec_fd = -1
	}
	if rfd := posix.openat(f.dir_fd, rec, {.RDWR, .NOFOLLOW, .CLOEXEC}); rfd >= 0 {
		f.rec_fd = rfd
	}
	return .Done
}

// The write in place through `rec_fd`. The file is cut to zero first, so a
// crash in the write leaves a first part of the new text, never a mix of two
// texts.
@(private)
write_in_place :: proc(f: ^Record_File, text: string) -> bool {
	if f.rec_fd < 0 || posix.ftruncate(f.rec_fd, 0) != .OK {
		return false
	}
	rest := transmute([]u8)text
	off: posix.off_t = 0
	for len(rest) > 0 {
		n := posix.pwrite(f.rec_fd, raw_data(rest), uint(len(rest)), off)
		if n < 0 && posix.errno() == .EINTR {
			continue
		}
		if n <= 0 {
			return false
		}
		rest = rest[n:]
		off += posix.off_t(n)
	}
	return posix.fsync(f.rec_fd) == .OK
}

// A regular file of this user that the group and others cannot read, and not
// larger than `max_size` (0: any size).
@(private)
file_is_ours :: proc(fd: posix.FD, max_size: int) -> bool {
	st: posix.stat_t
	if posix.fstat(fd, &st) != .OK {
		return false
	}
	if !posix.S_ISREG(st.st_mode) || st.st_uid != posix.geteuid() || perm_of(st.st_mode) & 0o077 != 0 {
		return false
	}
	return max_size == 0 || int(st.st_size) <= max_size
}

// A folder of this user (or of root, for `parent`) that others cannot write to.
@(private)
dir_is_safe :: proc(fd: posix.FD, private: bool) -> bool {
	st: posix.stat_t
	if posix.fstat(fd, &st) != .OK || !posix.S_ISDIR(st.st_mode) {
		return false
	}
	me := posix.geteuid()
	perm := perm_of(st.st_mode)
	if private {
		return st.st_uid == me && perm & 0o027 == 0
	}
	return (st.st_uid == me || st.st_uid == 0) && perm & 0o022 == 0
}

@(private)
open_state_dir :: proc(dir: string) -> (fd: posix.FD, err: Record_Open_Error) {
	path := strings.trim_right(dir, "/")
	slash := strings.last_index_byte(path, '/')
	if slash < 0 || slash == len(path) - 1 {
		return -1, .Dir_Failed
	}
	parent := path[:slash] if slash > 0 else "/"
	base := strings.clone_to_cstring(path[slash + 1:], context.temp_allocator)
	cparent := strings.clone_to_cstring(parent, context.temp_allocator)
	if posix.mkdirat(posix.AT_FDCWD, cparent, mode_of(0o755)) != .OK {
		if e := posix.errno(); e != .EEXIST {
			return -1, .Dir_Failed
		}
	}
	pfd := posix.openat(posix.AT_FDCWD, cparent, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
	if pfd < 0 {
		perr := posix.errno()
		return -1, .Dir_Not_Safe if perr == .ELOOP || perr == .ENOTDIR else .Dir_Failed
	}
	defer posix.close(pfd)
	if !dir_is_safe(pfd, false) {
		return -1, .Dir_Not_Safe
	}
	if posix.mkdirat(pfd, base, mode_of(0o700)) != .OK {
		if e := posix.errno(); e != .EEXIST {
			return -1, .Dir_Failed
		}
	}
	dfd := posix.openat(pfd, base, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
	if dfd < 0 {
		derr := posix.errno()
		return -1, .Dir_Not_Safe if derr == .ELOOP || derr == .ENOTDIR else .Dir_Failed
	}
	if !dir_is_safe(dfd, true) {
		posix.close(dfd)
		return -1, .Dir_Not_Safe
	}
	return dfd, .None
}

// The ids of the records in the folder: the names of `.lock` and `.rec` files
// without the suffix, each once.
@(private)
list_ids :: proc(dir_fd: posix.FD, allocator: mem.Allocator) -> []string {
	out := make([dynamic]string, allocator)
	fd := posix.openat(dir_fd, ".", {.DIRECTORY, .CLOEXEC})
	if fd < 0 {
		return out[:]
	}
	dir := posix.fdopendir(fd)
	if dir == nil {
		posix.close(fd)
		return out[:]
	}
	defer posix.closedir(dir) // closes `fd`
	for {
		entry := posix.readdir(dir)
		if entry == nil {
			break
		}
		name := string(cstring(raw_data(entry.d_name[:])))
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
	return out[:]
}

// Reads `<id>.rec`. `.Io` when there is no such file.
@(private)
read_record :: proc(dir_fd: posix.FD, id: string, allocator: mem.Allocator) -> (r: Record, err: Record_Error) {
	name := strings.clone_to_cstring(strings.concatenate({id, ".rec"}, context.temp_allocator), context.temp_allocator)
	fd := posix.openat(dir_fd, name, {.NOFOLLOW, .CLOEXEC})
	if fd < 0 {
		if posix.errno() == .ENOENT {
			return {}, .Io
		}
		return {}, .Refused
	}
	defer posix.close(fd)
	if !file_is_ours(fd, RECORD_MAX_SIZE) {
		return {}, .Refused
	}
	buf := make([]u8, RECORD_MAX_SIZE + 1, context.temp_allocator)
	total := 0
	for total < len(buf) {
		room := buf[total:]
		n := posix.read(fd, raw_data(room), uint(len(room)))
		if n < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			return {}, .Refused
		}
		if n == 0 {
			break
		}
		total += int(n)
	}
	if total > RECORD_MAX_SIZE {
		return {}, .Refused
	}
	return record_decode_partial(string(buf[:total]), allocator)
}
