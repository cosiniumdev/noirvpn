// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import win "core:sys/windows"
import "core:time"
import "noir:platform/sysnet"

// Files of the clean-up records on Windows (record.odin has the format).
// Folder and files:
//   - Folder `%ProgramData%\noirvpn\state` with its own access list: full
//     access for SYSTEM and Administrators, none for others. An existing folder
//     must be owned by SYSTEM, Administrators or the daemon user, and must not
//     be a reparse point. The access list is set again.
//   - Files open without following a reparse point. A file is refused (not read,
//     not removed) if it is not a plain file or its owner is none of the three.
//   - Lock: `LockFileEx` on the first byte of `<id>.lock`, ends with the process.

@(private = "file")
RECORD_DIR_SDDL :: "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

record_default_dir :: proc(allocator := context.temp_allocator) -> string {
	base, ok := os.lookup_env("ProgramData", context.temp_allocator)
	if !ok || base == "" {
		base = `C:\ProgramData`
	}
	return strings.concatenate({base, `\noirvpn\state`}, allocator)
}

// The record of this daemon, open.
Record_File :: struct {
	ok:        bool,
	rec:       Record,
	dir:       string,
	lock:      win.HANDLE,
	id_buf:    [64]u8,
	id_len:    int,
	// The text of the last write: an equal record is not written again.
	last:      string,
	allocator: mem.Allocator,
}

Record_Open_Error :: enum u8 {
	None,
	// The folder is a reparse point or has another owner.
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
	f.allocator = allocator
	if err := open_state_dir(dir); err != .None {
		return err
	}
	pid := win.GetCurrentProcessId()
	id := fmt.bprintf(f.id_buf[:], "%d-%x", pid, time.now()._nsec)
	f.id_len = len(id)
	f.dir = strings.clone(dir, allocator)
	h := win.CreateFileW(
		wpath(f.dir, record_id(f), ".lock"),
		win.GENERIC_READ | win.GENERIC_WRITE,
		win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE,
		nil,
		win.CREATE_NEW,
		win.FILE_ATTRIBUTE_NORMAL | win.FILE_FLAG_OPEN_REPARSE_POINT,
		nil,
	)
	if h == win.INVALID_HANDLE_VALUE {
		delete(f.dir, allocator)
		f^ = {}
		return .Lock_Failed
	}
	if !lock_now(h) {
		win.CloseHandle(h)
		win.DeleteFileW(wpath(f.dir, record_id(f), ".lock"))
		delete(f.dir, allocator)
		f^ = {}
		return .Lock_Failed
	}
	f.lock = h
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

// Writes the record when it differs from the last write: a temporary file,
// a flush, a rename over the old one.
record_write :: proc(f: ^Record_File) -> Record_Error {
	if !f.ok {
		return .None
	}
	text := record_encode(&f.rec, f.allocator)
	if text == f.last {
		delete(text, f.allocator)
		return .None
	}
	tmp := wpath(f.dir, record_id(f), ".tmp")
	h := win.CreateFileW(tmp, win.GENERIC_WRITE, 0, nil, win.CREATE_ALWAYS, win.FILE_ATTRIBUTE_NORMAL | win.FILE_FLAG_OPEN_REPARSE_POINT, nil)
	if h == win.INVALID_HANDLE_VALUE {
		delete(text, f.allocator)
		return .Io
	}
	written: win.DWORD
	ok := win.WriteFile(h, raw_data(text), win.DWORD(len(text)), &written, nil) != win.FALSE && int(written) == len(text)
	ok = ok && win.FlushFileBuffers(h) != win.FALSE
	win.CloseHandle(h)
	if !ok || win.MoveFileExW(tmp, wpath(f.dir, record_id(f), ".rec"), win.MOVEFILE_REPLACE_EXISTING | win.MOVEFILE_WRITE_THROUGH) == win.FALSE {
		win.DeleteFileW(tmp)
		delete(text, f.allocator)
		return .Io
	}
	delete(f.last, f.allocator)
	f.last = text
	return .None
}

// Removes the record and its lock. Call it after the teardown.
record_close :: proc(f: ^Record_File) -> (removed: bool) {
	if !f.ok {
		return true
	}
	win.DeleteFileW(wpath(f.dir, record_id(f), ".rec"))
	win.DeleteFileW(wpath(f.dir, record_id(f), ".tmp"))
	win.CloseHandle(f.lock)
	f.lock = nil
	win.DeleteFileW(wpath(f.dir, record_id(f), ".lock"))
	record_release(f)
	return true
}

// Closes the files and keeps them, as a crash does: the next start finds the
// record without its lock.
record_release :: proc(f: ^Record_File) {
	if !f.ok {
		return
	}
	if f.lock != nil {
		win.CloseHandle(f.lock)
	}
	record_destroy(&f.rec)
	delete(f.last, f.allocator)
	delete(f.dir, f.allocator)
	f^ = {}
}

// ---- reading the records of other daemons ----

// A record found in the folder.
Record_Found :: struct {
	id:   string,
	rec:  Record,
	// The record could not be read (cut short, another version).
	bad:  bool,
	// The lock, held while a dead record is reverted (nil: none).
	lock: win.HANDLE,
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
	for id in list_ids(own.dir, context.temp_allocator) {
		if id == record_id(own) {
			continue
		}
		found := Record_Found {
			id = strings.clone(id, allocator),
		}
		h := win.CreateFileW(
			wpath(own.dir, id, ".lock"),
			win.GENERIC_READ | win.GENERIC_WRITE,
			win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE,
			nil,
			win.OPEN_EXISTING,
			win.FILE_ATTRIBUTE_NORMAL | win.FILE_FLAG_OPEN_REPARSE_POINT,
			nil,
		)
		live := false
		if h == win.INVALID_HANDLE_VALUE {
			e := win.GetLastError()
			if e != win.ERROR_FILE_NOT_FOUND {
				// No access, or the file is being removed: not ours to judge.
				s.bad += 1
				delete(found.id, allocator)
				continue
			}
			// A record without its lock: its owner is gone.
		} else {
			if !file_is_ours(h, 0) {
				win.CloseHandle(h)
				s.bad += 1
				delete(found.id, allocator)
				continue
			}
			if lock_now(h) {
				found.lock = h
			} else if win.GetLastError() == win.ERROR_LOCK_VIOLATION {
				live = true
				win.CloseHandle(h)
			} else {
				win.CloseHandle(h)
				s.bad += 1
				delete(found.id, allocator)
				continue
			}
		}
		rec, rerr := read_record(own.dir, id, allocator)
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
			if found.lock != nil {
				win.CloseHandle(found.lock)
			}
			s.bad += 1
			delete(found.id, allocator)
			continue
		case .Truncated, .Bad_Version, .Bad_Line:
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
	if f.lock != nil {
		win.CloseHandle(f.lock)
		f.lock = nil
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
	win.DeleteFileW(wpath(own.dir, f.id, ".rec"))
	win.DeleteFileW(wpath(own.dir, f.id, ".tmp"))
	if f.lock != nil {
		win.CloseHandle(f.lock)
		f.lock = nil
	}
	win.DeleteFileW(wpath(own.dir, f.id, ".lock"))
}

// The NRPT rules of ours that no record lists, from an older version. A rule
// is removed if no live record and no interface has its interface name.
// Returns how many were removed.
record_dns_fallback :: proc(env: sysnet.DNS_Env, live: []^Record, links: []Record_Link, hint: string) -> (n: int, err: sysnet.DNS_Error) {
	for rule in sysnet.dns_nrpt_rules(env, context.temp_allocator) {
		ifname := rule[len(sysnet.NRPT_PREFIX):]
		if ifname == "" || !sysnet.dns_valid_ifname(ifname) {
			continue
		}
		if record_dns_protected({backend = "ip-helper", ifname = ifname}, nil, live, links) {
			continue
		}
		if e := sysnet.dns_cleanup_stale_record(env, ifname); e == .None {
			n += 1
		} else if err == .None {
			err = e
		}
	}
	return n, err
}

// ---- helpers ----

@(private = "file")
SE_FILE_OBJECT :: 1
@(private = "file")
OWNER_SECURITY_INFORMATION :: 0x1
@(private = "file")
DACL_SECURITY_INFORMATION :: 0x4
@(private = "file")
PROTECTED_DACL_SECURITY_INFORMATION :: 0x80000000
@(private = "file")
SDDL_REVISION_1 :: 1
@(private = "file")
WIN_LOCAL_SYSTEM_SID :: 22
@(private = "file")
WIN_BUILTIN_ADMINISTRATORS_SID :: 26

foreign import advapi32 "system:Advapi32.lib"

@(private = "file")
@(default_calling_convention = "system")
foreign advapi32 {
	GetSecurityInfo :: proc(
		handle: win.HANDLE,
		ObjectType: i32,
		SecurityInfo: u32,
		ppsidOwner: ^rawptr,
		ppsidGroup: ^rawptr,
		ppDacl: ^rawptr,
		ppSacl: ^rawptr,
		ppSecurityDescriptor: ^rawptr,
	) -> u32 ---
	IsWellKnownSid :: proc(pSid: rawptr, WellKnownSidType: i32) -> win.BOOL ---
	EqualSid :: proc(pSid1: rawptr, pSid2: rawptr) -> win.BOOL ---
	ConvertStringSecurityDescriptorToSecurityDescriptorW :: proc(text: win.wstring, revision: u32, sd: ^rawptr, size: ^u32) -> win.BOOL ---
	SetFileSecurityW :: proc(lpFileName: win.wstring, SecurityInformation: u32, pSecurityDescriptor: rawptr) -> win.BOOL ---
}

@(private = "file")
wpath :: proc(dir, id, suffix: string) -> win.wstring {
	return win.utf8_to_wstring(strings.concatenate({dir, `\`, id, suffix}, context.temp_allocator), context.temp_allocator)
}

@(private = "file")
lock_now :: proc(h: win.HANDLE) -> bool {
	ov: win.OVERLAPPED
	return win.LockFileEx(h, win.LOCKFILE_EXCLUSIVE_LOCK | win.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov) != win.FALSE
}

// True when the owner of the object of `h` is SYSTEM, the Administrators
// group or the user of this process.
@(private = "file")
owner_is_ours :: proc(h: win.HANDLE) -> bool {
	owner, sd: rawptr
	if GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nil, nil, nil, &sd) != 0 {
		return false
	}
	defer win.LocalFree(sd)
	if IsWellKnownSid(owner, WIN_LOCAL_SYSTEM_SID) != win.FALSE || IsWellKnownSid(owner, WIN_BUILTIN_ADMINISTRATORS_SID) != win.FALSE {
		return true
	}
	tok: win.HANDLE
	if win.OpenProcessToken(win.GetCurrentProcess(), win.TOKEN_QUERY, &tok) == win.FALSE {
		return false
	}
	defer win.CloseHandle(tok)
	buf: [256]u8
	n: win.DWORD
	if win.GetTokenInformation(tok, .TokenUser, raw_data(buf[:]), win.DWORD(len(buf)), &n) == win.FALSE {
		return false
	}
	tu := (^win.TOKEN_USER)(raw_data(buf[:]))
	return EqualSid(owner, tu.User.Sid) != win.FALSE
}

// A plain file (no folder, no reparse point) of an owner of ours, and not
// larger than `max_size` (0: any size).
@(private = "file")
file_is_ours :: proc(h: win.HANDLE, max_size: int) -> bool {
	info: win.BY_HANDLE_FILE_INFORMATION
	if win.GetFileInformationByHandle(h, &info) == win.FALSE {
		return false
	}
	if info.dwFileAttributes & (win.FILE_ATTRIBUTE_DIRECTORY | win.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return false
	}
	size := int(info.nFileSizeHigh) << 32 | int(info.nFileSizeLow)
	if max_size > 0 && size > max_size {
		return false
	}
	return owner_is_ours(h)
}

@(private = "file")
open_state_dir :: proc(dir: string) -> Record_Open_Error {
	path := strings.trim_right(dir, `\`)
	if i := strings.last_index_byte(path, '\\'); i > 0 {
		// The parent: created with the access list it inherits, as the service
		// install does before it sets its own.
		if !win.CreateDirectoryW(win.utf8_to_wstring(path[:i], context.temp_allocator), nil) && win.GetLastError() != win.ERROR_ALREADY_EXISTS {
			return .Dir_Failed
		}
	}
	sd: rawptr
	if !ConvertStringSecurityDescriptorToSecurityDescriptorW(win.utf8_to_wstring(RECORD_DIR_SDDL, context.temp_allocator), SDDL_REVISION_1, &sd, nil) {
		return .Dir_Failed
	}
	defer win.LocalFree(sd)
	sa := win.SECURITY_ATTRIBUTES {
		nLength              = size_of(win.SECURITY_ATTRIBUTES),
		lpSecurityDescriptor = sd,
	}
	wdir := win.utf8_to_wstring(path, context.temp_allocator)
	if win.CreateDirectoryW(wdir, &sa) {
		return .None
	}
	if win.GetLastError() != win.ERROR_ALREADY_EXISTS {
		return .Dir_Failed
	}
	h := win.CreateFileW(
		wdir,
		win.GENERIC_READ,
		win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE,
		nil,
		win.OPEN_EXISTING,
		win.FILE_FLAG_BACKUP_SEMANTICS | win.FILE_FLAG_OPEN_REPARSE_POINT,
		nil,
	)
	if h == win.INVALID_HANDLE_VALUE {
		return .Dir_Failed
	}
	defer win.CloseHandle(h)
	info: win.BY_HANDLE_FILE_INFORMATION
	if win.GetFileInformationByHandle(h, &info) == win.FALSE {
		return .Dir_Failed
	}
	if info.dwFileAttributes & win.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.dwFileAttributes & win.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return .Dir_Not_Safe
	}
	if !owner_is_ours(h) {
		return .Dir_Not_Safe
	}
	if !SetFileSecurityW(wdir, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd) {
		return .Dir_Not_Safe
	}
	return .None
}

// The ids of the records in the folder: the names of `.lock` and `.rec` files
// without the suffix, each once.
@(private = "file")
list_ids :: proc(dir: string, allocator: mem.Allocator) -> []string {
	out := make([dynamic]string, allocator)
	data: win.WIN32_FIND_DATAW
	h := win.FindFirstFileW(win.utf8_to_wstring(strings.concatenate({dir, `\*`}, context.temp_allocator), context.temp_allocator), &data)
	if h == win.INVALID_HANDLE_VALUE {
		return out[:]
	}
	defer win.FindClose(h)
	for {
		if data.dwFileAttributes & (win.FILE_ATTRIBUTE_DIRECTORY | win.FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
			n := 0
			for n < len(data.cFileName) && data.cFileName[n] != 0 {
				n += 1
			}
			name, _ := win.utf16_to_utf8(data.cFileName[:n], context.temp_allocator)
			id: string
			if strings.has_suffix(name, ".lock") {
				id = name[:len(name) - 5]
			} else if strings.has_suffix(name, ".rec") {
				id = name[:len(name) - 4]
			}
			if id != "" {
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
		if win.FindNextFileW(h, &data) == win.FALSE {
			break
		}
	}
	return out[:]
}

// Reads `<id>.rec`. `.Io` when there is no such file.
@(private = "file")
read_record :: proc(dir, id: string, allocator: mem.Allocator) -> (r: Record, err: Record_Error) {
	h := win.CreateFileW(
		wpath(dir, id, ".rec"),
		win.GENERIC_READ,
		win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE,
		nil,
		win.OPEN_EXISTING,
		win.FILE_ATTRIBUTE_NORMAL | win.FILE_FLAG_OPEN_REPARSE_POINT,
		nil,
	)
	if h == win.INVALID_HANDLE_VALUE {
		if win.GetLastError() == win.ERROR_FILE_NOT_FOUND {
			return {}, .Io
		}
		return {}, .Refused
	}
	defer win.CloseHandle(h)
	if !file_is_ours(h, RECORD_MAX_SIZE) {
		return {}, .Refused
	}
	buf := make([]u8, RECORD_MAX_SIZE + 1, context.temp_allocator)
	total := 0
	for total < len(buf) {
		n: win.DWORD
		if win.ReadFile(h, raw_data(buf[total:]), win.DWORD(len(buf) - total), &n, nil) == win.FALSE {
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
	return record_decode(string(buf[:total]), allocator)
}
