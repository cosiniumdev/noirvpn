// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package bus

// The Windows calls of the pipe transport that core:sys/windows does not
// have, and the helpers for access lists, tokens and SIDs.

import "core:mem"
import win "core:sys/windows"

foreign import advapi32 "system:Advapi32.lib"
foreign import kernel32 "system:Kernel32.lib"

@(private)
@(default_calling_convention = "system")
foreign advapi32 {
	ImpersonateNamedPipeClient :: proc(hNamedPipe: win.HANDLE) -> win.BOOL ---
	RevertToSelf :: proc() -> win.BOOL ---
	InitializeSecurityDescriptor :: proc(pSecurityDescriptor: rawptr, dwRevision: u32) -> win.BOOL ---
	SetSecurityDescriptorDacl :: proc(pSecurityDescriptor: rawptr, bDaclPresent: win.BOOL, pDacl: rawptr, bDaclDefaulted: win.BOOL) -> win.BOOL ---
	SetSecurityDescriptorOwner :: proc(pSecurityDescriptor: rawptr, pOwner: rawptr, bOwnerDefaulted: win.BOOL) -> win.BOOL ---
	InitializeAcl :: proc(pAcl: rawptr, nAclLength: u32, dwAclRevision: u32) -> win.BOOL ---
	AddAccessAllowedAce :: proc(pAcl: rawptr, dwAceRevision: u32, AccessMask: u32, pSid: rawptr) -> win.BOOL ---
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
	@(link_name = "LookupAccountNameW")
	lookup_account_name :: proc(
		lpSystemName: win.wstring,
		lpAccountName: win.wstring,
		Sid: rawptr,
		cbSid: ^u32,
		ReferencedDomainName: [^]u16,
		cchReferencedDomainName: ^u32,
		peUse: ^i32,
	) -> win.BOOL ---
	CreateRestrictedToken :: proc(
		ExistingTokenHandle: win.HANDLE,
		Flags: u32,
		DisableSidCount: u32,
		SidsToDisable: [^]win.SID_AND_ATTRIBUTES,
		DeletePrivilegeCount: u32,
		PrivilegesToDelete: rawptr,
		RestrictedSidCount: u32,
		SidsToRestrict: rawptr,
		NewTokenHandle: ^win.HANDLE,
	) -> win.BOOL ---
	SetThreadToken :: proc(Thread: ^win.HANDLE, Token: win.HANDLE) -> win.BOOL ---
	DuplicateTokenEx :: proc(
		hExistingToken: win.HANDLE,
		dwDesiredAccess: u32,
		lpTokenAttributes: rawptr,
		ImpersonationLevel: i32,
		TokenType: i32,
		phNewToken: ^win.HANDLE,
	) -> win.BOOL ---
}

@(private)
@(default_calling_convention = "system")
foreign kernel32 {
	GetNamedPipeClientProcessId :: proc(Pipe: win.HANDLE, ClientProcessId: ^u32) -> win.BOOL ---
	ExitProcess :: proc(uExitCode: u32) ---
}

// The rights of a client SID on each pipe:
//   - control pipe: FILE_READ_DATA, FILE_WRITE_DATA, FILE_READ_ATTRIBUTES,
//     READ_CONTROL, SYNCHRONIZE
//   - events pipe: the same without FILE_WRITE_DATA
// FILE_CREATE_PIPE_INSTANCE (in GENERIC_WRITE) is never granted.
PIPE_CONTROL_RIGHTS :: u32(0x120083)
PIPE_EVENTS_RIGHTS :: u32(0x120081)

@(private)
FILE_ALL_ACCESS :: u32(0x1F01FF)
@(private)
ACL_REVISION :: 2
@(private)
SECURITY_DESCRIPTOR_REVISION :: 1
@(private)
OWNER_SECURITY_INFORMATION :: 1
@(private)
SE_KERNEL_OBJECT :: 6
@(private)
SE_GROUP_ENABLED :: 0x4
@(private)
SE_GROUP_USE_FOR_DENY_ONLY :: 0x10
@(private)
SECURITY_IDENTIFICATION :: 0x10000
@(private)
SECURITY_SQOS_PRESENT :: 0x100000
@(private)
PIPE_REJECT_REMOTE_CLIENTS :: 0x8
@(private)
FILE_FLAG_FIRST_PIPE_INSTANCE :: 0x80000
@(private)
ERROR_PIPE_BUSY :: 231
@(private)
ERROR_PIPE_CONNECTED :: 535
@(private)
ERROR_IO_PENDING :: 997
@(private)
ERROR_SEM_TIMEOUT :: 121
@(private)
ERROR_MORE_DATA :: 234
@(private)
ERROR_INSUFFICIENT_BUFFER :: 122

// A security descriptor in absolute form with its access list, in one block.
@(private)
Pipe_Security :: struct {
	sd:  [64]u8, // SECURITY_DESCRIPTOR is 40 bytes on 64-bit Windows
	acl: []u8,
	sa:  win.SECURITY_ATTRIBUTES,
}

// LocalSystem and Administrators get full control; each SID in `clients` gets
// `rights`. `owner` replaces the default owner when it is set.
@(private)
pipe_security_make :: proc(ps: ^Pipe_Security, clients: []Sid, rights: u32, owner: ^Sid = nil, allocator := context.allocator) -> bool {
	system := must_sid(SID_LOCAL_SYSTEM)
	admins := must_sid(SID_ADMINISTRATORS)
	// ACL header 8 bytes; each ACE 8 bytes plus the SID.
	size := 8 + 2 * (8 + SID_MAX)
	for _ in clients {
		size += 8 + SID_MAX
	}
	size = (size + 3) &~ 3
	acl, err := make_aligned([]u8, size, 16, allocator)
	if err != nil {
		return false
	}
	ps.acl = acl
	if InitializeAcl(raw_data(acl), u32(size), ACL_REVISION) == win.FALSE {
		return false
	}
	if AddAccessAllowedAce(raw_data(acl), ACL_REVISION, FILE_ALL_ACCESS, &system.data) == win.FALSE {
		return false
	}
	if AddAccessAllowedAce(raw_data(acl), ACL_REVISION, FILE_ALL_ACCESS, &admins.data) == win.FALSE {
		return false
	}
	for &c in clients {
		if sid_equal(c, system) || sid_equal(c, admins) {
			continue
		}
		if AddAccessAllowedAce(raw_data(acl), ACL_REVISION, rights, &c.data) == win.FALSE {
			return false
		}
	}
	if InitializeSecurityDescriptor(&ps.sd, SECURITY_DESCRIPTOR_REVISION) == win.FALSE {
		return false
	}
	if SetSecurityDescriptorDacl(&ps.sd, win.TRUE, raw_data(acl), win.FALSE) == win.FALSE {
		return false
	}
	if owner != nil && SetSecurityDescriptorOwner(&ps.sd, &owner.data, win.FALSE) == win.FALSE {
		return false
	}
	ps.sa = {
		nLength              = size_of(win.SECURITY_ATTRIBUTES),
		lpSecurityDescriptor = &ps.sd,
		bInheritHandle       = win.FALSE,
	}
	return true
}

@(private)
pipe_security_destroy :: proc(ps: ^Pipe_Security, allocator := context.allocator) {
	delete(ps.acl, allocator)
	ps.acl = nil
}

// A SID at a pointer that Windows gave.
@(private)
sid_at :: proc(p: rawptr) -> (s: Sid, ok: bool) {
	if p == nil {
		return {}, false
	}
	b := ([^]u8)(p)
	n := int(b[1])
	if n > 15 {
		return {}, false
	}
	return sid_from_bytes(b[:8 + 4 * n])
}

// The user SID and the enabled groups of a token. A group that is disabled or
// for deny only (the Administrators group of an administrator who is not
// elevated) is left out.
@(private)
token_identity :: proc(tok: win.HANDLE, groups: ^[dynamic]Sid) -> (user: Sid, ok: bool) {
	clear(groups)
	buf := token_info(tok, .TokenUser, context.temp_allocator) or_return
	tu := (^win.TOKEN_USER)(raw_data(buf))
	user = sid_at(tu.User.Sid) or_return
	gbuf := token_info(tok, .TokenGroups, context.temp_allocator) or_return
	count := (^u32)(raw_data(gbuf))^
	// TOKEN_GROUPS: a DWORD count, then the array at pointer alignment.
	list := ([^]win.SID_AND_ATTRIBUTES)(rawptr(uintptr(raw_data(gbuf)) + size_of(rawptr)))
	for i in 0 ..< int(count) {
		g := list[i]
		if g.Attributes & SE_GROUP_ENABLED == 0 || g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			continue
		}
		if s, sok := sid_at(g.Sid); sok {
			append(groups, s)
		}
	}
	return user, true
}

@(private)
token_info :: proc(tok: win.HANDLE, class: win.TOKEN_INFORMATION_CLASS, allocator: mem.Allocator) -> (buf: []u8, ok: bool) {
	need: u32
	win.GetTokenInformation(tok, class, nil, 0, &need)
	if need == 0 || need > 1 << 20 {
		return nil, false
	}
	b, err := make_aligned([]u8, int(need), 16, allocator)
	if err != nil {
		return nil, false
	}
	if win.GetTokenInformation(tok, class, raw_data(b), need, &need) == win.FALSE {
		return nil, false
	}
	return b, true
}

// The identity of the client of a connected pipe: impersonate it, open the
// thread token, and revert, before any other I/O on the pipe. The client
// connects at the identification level, so the token can only be read. If the
// thread cannot revert, it would go on as the client, so the process ends.
@(private)
pipe_client_identity :: proc(h: win.HANDLE, groups: ^[dynamic]Sid) -> (creds: Peer_Creds, ok: bool) {
	if ImpersonateNamedPipeClient(h) == win.FALSE {
		return {}, false
	}
	tok: win.HANDLE
	opened := win.OpenThreadToken(win.GetCurrentThread(), win.TOKEN_QUERY, win.TRUE, &tok)
	if RevertToSelf() == win.FALSE {
		ExitProcess(70)
	}
	if opened == win.FALSE {
		return {}, false
	}
	defer win.CloseHandle(tok)
	user, uok := token_identity(tok, groups)
	if !uok {
		return {}, false
	}
	creds.sid = user
	pid: u32
	if GetNamedPipeClientProcessId(h, &pid) != win.FALSE {
		creds.pid = pid
		creds.has_pid = true
	}
	return creds, true
}

// The owner to give the pipes of the service, so the owner check of the client
// passes: none (the default, LocalSystem) for a service, the Administrators
// group for an elevated administrator. The default owner of an administrator
// can be the user, which the clients refuse.
@(private)
service_owner :: proc() -> (owner: Sid, set: bool) {
	tok: win.HANDLE
	if win.OpenProcessToken(win.GetCurrentProcess(), win.TOKEN_QUERY, &tok) == win.FALSE {
		return {}, false
	}
	defer win.CloseHandle(tok)
	groups := make([dynamic]Sid, context.temp_allocator)
	user := token_identity(tok, &groups) or_return
	if sid_equal(user, must_sid(SID_LOCAL_SYSTEM)) {
		return {}, false
	}
	admins := must_sid(SID_ADMINISTRATORS)
	for g in groups {
		if sid_equal(g, admins) {
			return admins, true
		}
	}
	return {}, false
}

// The owner of the object of a handle.
@(private)
handle_owner :: proc(h: win.HANDLE) -> (owner: Sid, ok: bool) {
	op, sd: rawptr
	if GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &op, nil, nil, nil, &sd) != 0 {
		return {}, false
	}
	defer win.LocalFree(sd)
	return sid_at(op)
}

// The user SID of this process.
current_user_sid :: proc() -> (sid: Sid, ok: bool) {
	tok: win.HANDLE
	if win.OpenProcessToken(win.GetCurrentProcess(), win.TOKEN_QUERY, &tok) == win.FALSE {
		return {}, false
	}
	defer win.CloseHandle(tok)
	buf := token_info(tok, .TokenUser, context.temp_allocator) or_return
	tu := (^win.TOKEN_USER)(raw_data(buf))
	return sid_at(tu.User.Sid)
}
