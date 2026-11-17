// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package tun

import "core:crypto/hash"
import "core:sync"
import win "core:sys/windows"

// Tunnel on Windows: a wintun adapter and one session on it. Declarations
// follow wintun.h of wintun 0.14.
//
// wintun.dll loads at run time, from the program's folder or System32 only.
// Creating the adapter and session needs an administrator token at high
// integrity, or SYSTEM.
//
// No file descriptor. The session has an event, signaled when packets wait:
// register `dev.read_event` with `event.add_handle`, read until
// `.Would_Block`, or call `event.handle_again` if the handler stops early
// (the event resets itself when the wait takes it).

// Longest adapter name in bytes, including a terminating NUL.
IFNAMSIZ :: 128

// The size of each ring of a session (one for each direction). wintun takes
// a power of two from 128 KiB to 64 MiB.
RING_CAPACITY :: 4 * 1024 * 1024

// The largest IP packet wintun takes.
MAX_PACKET :: 0xFFFF

// The tunnel type that `ipconfig` and the adapter list show.
TUNNEL_TYPE :: "noirvpn"

DEFAULT_NAME :: "noirvpn"

// One wintun adapter with a running session.
Device :: struct {
	// Always -1: there is no descriptor on Windows. Use `read_event`.
	fd:         i32,
	name_buf:   [IFNAMSIZ]u8,
	name_len:   int,
	// The session's read event. Do not close it: the session owns it.
	read_event: win.HANDLE,
	// The interface for platform/sysnet: its LUID and its index.
	luid:       u64,
	ifindex:    u32,
	adapter:    rawptr,
	session:    rawptr,
	// Always false and empty on Windows: wintun has no offloads.
	vnet:       bool,
	offloads:   Offload_Set,
}

// Severity of a wintun log message.
Log_Level :: enum i32 {
	Info,
	Warn,
	Error,
}

// Receives wintun's log messages (from any thread). `timestamp` is in 100 ns
// units since 1601 (a FILETIME).
Logger :: #type proc "system" (level: Log_Level, timestamp: u64, message: win.wstring)

@(private)
Api :: struct {
	module:                win.HMODULE,
	create_adapter:        proc "system" (name: win.wstring, tunnel_type: win.wstring, guid: ^win.GUID) -> rawptr,
	open_adapter:          proc "system" (name: win.wstring) -> rawptr,
	close_adapter:         proc "system" (adapter: rawptr),
	get_adapter_luid:      proc "system" (adapter: rawptr, luid: ^u64),
	get_driver_version:    proc "system" () -> u32,
	set_logger:            proc "system" (logger: Logger),
	start_session:         proc "system" (adapter: rawptr, capacity: u32) -> rawptr,
	end_session:           proc "system" (session: rawptr),
	get_read_wait_event:   proc "system" (session: rawptr) -> win.HANDLE,
	receive_packet:        proc "system" (session: rawptr, size: ^u32) -> [^]u8,
	release_receive_packet: proc "system" (session: rawptr, packet: [^]u8),
	allocate_send_packet:  proc "system" (session: rawptr, size: u32) -> [^]u8,
	send_packet:           proc "system" (session: rawptr, packet: [^]u8),
}

@(private)
api: Api
@(private)
api_once: sync.Once
@(private)
api_ok: bool

foreign import iphlpapi "system:iphlpapi.lib"

@(default_calling_convention = "system", private)
foreign iphlpapi {
	ConvertInterfaceLuidToIndex :: proc(luid: ^u64, index: ^u32) -> u32 ---
}

@(private)
load_api :: proc() {
	flags := win.LoadLibraryEx_Flags{.LOAD_LIBRARY_SEARCH_APPLICATION_DIR, .LOAD_LIBRARY_SEARCH_SYSTEM32}
	m := win.LoadLibraryExW(win.L("wintun.dll"), nil, flags)
	if m == nil {
		return
	}
	a := Api {
		module = m,
	}
	ok := true
	get :: proc(m: win.HMODULE, name: cstring, ok: ^bool) -> rawptr {
		p := win.GetProcAddress(m, name)
		if p == nil {
			ok^ = false
		}
		return p
	}
	a.create_adapter = auto_cast get(m, "WintunCreateAdapter", &ok)
	a.open_adapter = auto_cast get(m, "WintunOpenAdapter", &ok)
	a.close_adapter = auto_cast get(m, "WintunCloseAdapter", &ok)
	a.get_adapter_luid = auto_cast get(m, "WintunGetAdapterLUID", &ok)
	a.get_driver_version = auto_cast get(m, "WintunGetRunningDriverVersion", &ok)
	a.set_logger = auto_cast get(m, "WintunSetLogger", &ok)
	a.start_session = auto_cast get(m, "WintunStartSession", &ok)
	a.end_session = auto_cast get(m, "WintunEndSession", &ok)
	a.get_read_wait_event = auto_cast get(m, "WintunGetReadWaitEvent", &ok)
	a.receive_packet = auto_cast get(m, "WintunReceivePacket", &ok)
	a.release_receive_packet = auto_cast get(m, "WintunReleaseReceivePacket", &ok)
	a.allocate_send_packet = auto_cast get(m, "WintunAllocateSendPacket", &ok)
	a.send_packet = auto_cast get(m, "WintunSendPacket", &ok)
	if !ok {
		win.FreeLibrary(m)
		return
	}
	api = a
	api_ok = true
}

// Load wintun.dll if that was not done yet. False if it is missing or
// incomplete.
loaded :: proc() -> bool {
	sync.once_do(&api_once, load_api)
	return api_ok
}

// The version of the running wintun driver (major << 16 | minor), or 0 when
// no driver is loaded yet (before the first adapter exists).
driver_version :: proc() -> u32 {
	if !loaded() {
		return 0
	}
	return api.get_driver_version()
}

// Send wintun's log messages to `logger`; nil turns them off.
set_logger :: proc(logger: Logger) {
	if loaded() {
		api.set_logger(logger)
	}
}

// GUID of the adapter for `name`. The same name gives the same GUID, so
// Windows keeps one network profile, and settings a crashed run left on the
// interface can be found again.
adapter_guid :: proc(name: string) -> (g: win.GUID) {
	buf: [32]u8
	hash.hash_string_to_buffer(.SHA256, name, buf[:])
	b: [16]u8
	copy(b[:], buf[:16])
	b[6] = (b[6] & 0x0F) | 0x50 // version 5 style: derived from a name
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 variant
	g.Data1 = u32(b[0]) << 24 | u32(b[1]) << 16 | u32(b[2]) << 8 | u32(b[3])
	g.Data2 = u16(b[4]) << 8 | u16(b[5])
	g.Data3 = u16(b[6]) << 8 | u16(b[7])
	for i in 0 ..< 8 {
		g.Data4[i] = win.BYTE(b[8 + i])
	}
	return
}

@(private, thread_local)
last_win_error: u32

// The Win32 error of the last failed call of this thread, for the log.
last_error :: proc "contextless" () -> u32 {
	return last_win_error
}

@(private)
map_win_error :: proc "contextless" (e: u32) -> Error {
	last_win_error = e
	e := e
	// wintun passes some errors on as an HRESULT of a Win32 error.
	if e & 0xFFFF0000 == 0x80070000 {
		e &= 0xFFFF
	}
	switch e {
	case 0:
		return .Other
	case win.ERROR_FILE_NOT_FOUND, win.ERROR_PATH_NOT_FOUND, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND:
		return .No_Device
	case win.ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD:
		return .Permission
	case win.ERROR_ALREADY_EXISTS, ERROR_BUSY, win.ERROR_SHARING_VIOLATION, ERROR_OBJECT_ALREADY_EXISTS:
		return .Busy
	case win.ERROR_INVALID_PARAMETER, win.ERROR_INVALID_NAME, ERROR_BUFFER_OVERFLOW:
		return .Invalid
	case win.ERROR_NOT_SUPPORTED:
		return .Unsupported
	case win.ERROR_HANDLE_EOF, win.ERROR_INVALID_DATA:
		return .Io
	}
	return .Other
}

// System error codes that core:sys/windows does not declare.
@(private)
ERROR_MOD_NOT_FOUND :: 126
@(private)
ERROR_PROC_NOT_FOUND :: 127
@(private)
ERROR_BUFFER_OVERFLOW :: 111
@(private)
ERROR_BUSY :: 170
@(private)
ERROR_NO_MORE_ITEMS :: 259
@(private)
ERROR_PRIVILEGE_NOT_HELD :: 1314
@(private)
ERROR_OBJECT_ALREADY_EXISTS :: 5010

// Create the adapter named `opts.name` (or `DEFAULT_NAME`) and start a session
// on it. The adapter disappears when the device closes, and when the process
// ends.
open :: proc(opts: Options = {}) -> (dev: Device, err: Error) {
	dev.fd = -1
	if opts.multi_queue {
		return dev, .Unsupported
	}
	name := opts.name if len(opts.name) > 0 else DEFAULT_NAME
	if len(name) >= IFNAMSIZ {
		return dev, .Invalid
	}
	for c in transmute([]u8)name {
		if c < 0x20 || c == 0x7f {
			return dev, .Invalid
		}
	}
	if !loaded() {
		return dev, .No_Device
	}
	wname := win.utf8_to_wstring(name, context.temp_allocator)
	guid := adapter_guid(name)
	adapter := api.create_adapter(wname, win.L(TUNNEL_TYPE), &guid)
	if adapter == nil {
		return dev, map_win_error(win.GetLastError())
	}
	session := api.start_session(adapter, RING_CAPACITY)
	if session == nil {
		e := win.GetLastError()
		api.close_adapter(adapter)
		return dev, map_win_error(e)
	}
	dev.adapter = adapter
	dev.session = session
	dev.read_event = api.get_read_wait_event(session)
	api.get_adapter_luid(adapter, &dev.luid)
	ConvertInterfaceLuidToIndex(&dev.luid, &dev.ifindex)
	copy(dev.name_buf[:], name)
	dev.name_len = len(name)
	return dev, .None
}

// End the session, then remove the adapter.
close :: proc(dev: ^Device) {
	if dev.session != nil {
		api.end_session(dev.session)
	}
	if dev.adapter != nil {
		api.close_adapter(dev.adapter)
	}
	dev^ = {
		fd = -1,
	}
}

// The adapter name (a view into the Device).
name :: proc "contextless" (dev: ^Device) -> string {
	return string(dev.name_buf[:dev.name_len])
}

is_open :: proc "contextless" (dev: ^Device) -> bool {
	return dev.session != nil
}

// Read one IP packet. `.Would_Block` when none waits: wait for `read_event`.
// A packet longer than `buf` is cut. `.Io` when the adapter is going away.
read :: proc(dev: ^Device, buf: []u8) -> (n: int, err: Error) {
	if dev.session == nil {
		return 0, .Closed
	}
	size: u32
	pkt := api.receive_packet(dev.session, &size)
	if pkt == nil {
		e := win.GetLastError()
		if e == ERROR_NO_MORE_ITEMS {
			return 0, .Would_Block
		}
		return 0, map_win_error(e)
	}
	n = min(int(size), len(buf))
	copy(buf[:n], pkt[:n])
	api.release_receive_packet(dev.session, pkt)
	return n, .None
}

// Write one IP packet. `.Would_Block` when the ring is full (the packet is
// not sent: drop it or try later).
write :: proc(dev: ^Device, pkt: []u8) -> Error {
	pieces := [1][]u8{pkt}
	return write_v(dev, pieces[:])
}

// Write one IP packet given in pieces (copied into the ring in order).
write_v :: proc(dev: ^Device, pieces: [][]u8) -> Error {
	if dev.session == nil {
		return .Closed
	}
	total := 0
	for p in pieces {
		total += len(p)
	}
	if total == 0 {
		return .Invalid
	}
	if total > MAX_PACKET {
		return .Message_Too_Long
	}
	out := api.allocate_send_packet(dev.session, u32(total))
	if out == nil {
		e := win.GetLastError()
		if e == ERROR_BUFFER_OVERFLOW {
			return .Would_Block
		}
		return map_win_error(e)
	}
	off := 0
	for p in pieces {
		copy(out[off:off + len(p)], p)
		off += len(p)
	}
	api.send_packet(dev.session, out)
	return .None
}
