// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package bus

// Client side of the Windows transport: the control pipe and events pipe of an
// instance.
// A client opens a pipe with exactly the rights of its table entry
// (PIPE_CONTROL_RIGHTS, PIPE_EVENTS_RIGHTS) at the identification level: the
// service can read who it is but cannot act as it. Before sending, it reads
// the pipe owner. An owner other than LocalSystem or Administrators is not the
// service (any user can create such a pipe while the service is down): the call
// fails with `Not_Service`.

import "core:mem"
import win "core:sys/windows"
import "core:strings"
import "core:time"

// Tests only: also accept a pipe that the user of this process owns, for a
// test host that runs without elevation in this process.
pipe_trust_own_user := false

@(private)
Pipe_Io :: struct {
	h:  win.HANDLE,
	ev: win.HANDLE,
	ov: win.OVERLAPPED,
}

@(private)
Io_Result :: enum u8 {
	Ok,
	Timeout,
	Failed,
}

@(private)
Sub_Transport :: struct {
	name:      string,
	io:        Pipe_Io,
	connected: bool,
	pending:   bool,
	reader:    Frame_Reader,
	open:      bool,
}

// A connection to a control pipe.
Conn :: struct {
	io:      Pipe_Io,
	timeout: time.Duration,
	open:    bool,
}

@(private)
ms_of :: proc(d: time.Duration) -> u32 {
	if d < 0 {
		return win.INFINITE
	}
	return u32(min(i64(d / time.Millisecond), i64(0x7fff_ffff)))
}

// Open a pipe with `rights`, waiting while all its instances are busy, and
// check its owner.
@(private)
pipe_open :: proc(name: string, rights: u32, timeout: time.Duration) -> (io: Pipe_Io, err: Call_Error) {
	path, ok := socket_file_path(name)
	if !ok {
		return {}, .Bad_Url
	}
	wname := win.utf8_to_wstring(path, context.temp_allocator)
	deadline := mono_now() + timeout
	h: win.HANDLE
	for {
		h = win.CreateFileW(
			wname,
			rights,
			0,
			nil,
			win.OPEN_EXISTING,
			win.FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
			nil,
		)
		if h != win.INVALID_HANDLE_VALUE {
			break
		}
		switch e := win.GetLastError(); e {
		case win.ERROR_FILE_NOT_FOUND, win.ERROR_PATH_NOT_FOUND:
			return {}, .Daemon_Not_Running
		case win.ERROR_ACCESS_DENIED:
			return {}, .Permission_Denied
		case ERROR_PIPE_BUSY:
			left := deadline - mono_now()
			if left <= 0 {
				return {}, .Timeout
			}
			win.WaitNamedPipeW(wname, max(ms_of(left), 1))
		case:
			return {}, .Io
		}
	}
	if !owner_trusted(h) {
		win.CloseHandle(h)
		return {}, .Not_Service
	}
	ev := win.CreateEventW(nil, win.TRUE, win.FALSE, nil)
	if ev == nil {
		win.CloseHandle(h)
		return {}, .No_Memory
	}
	return Pipe_Io{h = h, ev = ev}, .None
}

// LocalSystem or the Administrators group.
@(private)
owner_trusted :: proc(h: win.HANDLE) -> bool {
	owner, ok := handle_owner(h)
	if !ok {
		return false
	}
	if sid_equal(owner, must_sid(SID_LOCAL_SYSTEM)) || sid_equal(owner, must_sid(SID_ADMINISTRATORS)) {
		return true
	}
	if pipe_trust_own_user {
		me, mok := current_user_sid()
		return mok && sid_equal(owner, me)
	}
	return false
}

@(private)
pipe_close :: proc(io: ^Pipe_Io) {
	if io.h != nil {
		win.CloseHandle(io.h)
	}
	if io.ev != nil {
		win.CloseHandle(io.ev)
	}
	io^ = {}
}

// One overlapped read or write that is not yet started, waited for up to
// `timeout`. A timeout cancels it.
@(private)
pipe_transfer :: proc(io: ^Pipe_Io, buf: []u8, write: bool, timeout: time.Duration) -> (n: int, r: Io_Result) {
	io.ov = {}
	io.ov.hEvent = io.ev
	started: win.BOOL
	if write {
		started = win.WriteFile(io.h, raw_data(buf), u32(len(buf)), nil, &io.ov)
	} else {
		started = win.ReadFile(io.h, raw_data(buf), u32(len(buf)), nil, &io.ov)
	}
	if started == win.FALSE && win.GetLastError() != ERROR_IO_PENDING {
		return 0, .Failed
	}
	return pipe_wait(io, timeout)
}

@(private)
pipe_wait :: proc(io: ^Pipe_Io, timeout: time.Duration) -> (n: int, r: Io_Result) {
	if win.WaitForSingleObject(io.ev, ms_of(timeout)) == win.WAIT_TIMEOUT {
		win.CancelIoEx(io.h, &io.ov)
		got: u32
		win.GetOverlappedResult(io.h, &io.ov, &got, win.TRUE)
		return int(got), .Timeout
	}
	got: u32
	if win.GetOverlappedResult(io.h, &io.ov, &got, win.FALSE) == win.FALSE {
		return 0, .Failed
	}
	return int(got), .Ok
}

// Connect to the control pipe. Fails at once if the service is not there.
// `timeout` limits the wait for a free instance, each send and each wait for a
// reply.
connect :: proc(url: string, timeout := DEFAULT_CALL_TIMEOUT) -> (c: Conn, err: Call_Error) {
	io := pipe_open(url, PIPE_CONTROL_RIGHTS, timeout) or_return
	return Conn{io = io, timeout = timeout, open = true}, .None
}

disconnect :: proc(c: ^Conn) {
	if c.open {
		pipe_close(&c.io)
		c.open = false
	}
}

@(private)
conn_exchange :: proc(c: ^Conn, request: []byte, allocator: mem.Allocator) -> (data: []byte, err: Call_Error) {
	if !c.open {
		return nil, .Io
	}
	deadline := mono_now() + c.timeout
	out := make([]u8, FRAME_HEADER + len(request), context.temp_allocator)
	hdr := frame_header(len(request))
	copy(out, hdr[:])
	copy(out[FRAME_HEADER:], request)
	defer mem.zero_explicit(raw_data(out), len(out))
	for off := 0; off < len(out); {
		n, r := pipe_transfer(&c.io, out[off:], true, deadline - mono_now())
		switch r {
		case .Ok:
		case .Timeout:
			return nil, .Timeout
		case .Failed:
			return nil, .Io
		}
		off += n
	}
	fr: Frame_Reader
	frame_reader_init(&fr, FRAME_MAX_REPLY, allocator)
	for {
		left := deadline - mono_now()
		if left <= 0 {
			frame_reader_destroy(&fr)
			return nil, .Timeout
		}
		n, r := pipe_transfer(&c.io, frame_want(&fr), false, left)
		switch r {
		case .Ok:
		case .Timeout:
			frame_reader_destroy(&fr)
			return nil, .Timeout
		case .Failed:
			frame_reader_destroy(&fr)
			return nil, .Io
		}
		switch frame_got(&fr, n) {
		case .More:
		case .Done:
			return frame_take(&fr), .None
		case .Bad_Length:
			frame_reader_destroy(&fr)
			return nil, .Bad_Reply
		case .No_Memory:
			frame_reader_destroy(&fr)
			return nil, .No_Memory
		}
	}
}

// Follow events on topics that start with any of `prefixes` (empty: all). As on
// Unix, the subscriber gets every event and filters after the sequence check.
// `wait`:
//   - false: the service must be there now (`Daemon_Not_Running` otherwise).
//   - true: return at once. `next_event` keeps trying to connect.
// After a lost connection (restart, or full queue in the service) `next_event`
// reconnects by itself.
subscribe :: proc(url: string, prefixes: []string = nil, wait := false) -> (s: Subscriber, err: Call_Error) {
	path, ok := socket_file_path(url)
	if !ok {
		return {}, .Bad_Url
	}
	s.name = strings.clone(path)
	s.open = true
	frame_reader_init(&s.reader, FRAME_MAX_EVENT)
	if !wait {
		io, oerr := pipe_open(path, PIPE_EVENTS_RIGHTS, DEFAULT_CALL_TIMEOUT)
		if oerr != .None {
			delete(s.name)
			return {}, oerr
		}
		s.io = io
		s.connected = true
	}
	for p in prefixes {
		append(&s.prefixes, strings.clone(p))
	}
	return s, .None
}

@(private)
sub_drop :: proc(s: ^Subscriber) {
	if s.pending {
		win.CancelIoEx(s.io.h, &s.io.ov)
		got: u32
		win.GetOverlappedResult(s.io.h, &s.io.ov, &got, win.TRUE)
		s.pending = false
	}
	if s.connected {
		pipe_close(&s.io)
		s.connected = false
	}
	frame_reader_destroy(&s.reader)
}

unsubscribe :: proc(s: ^Subscriber) {
	if s.open {
		sub_drop(s)
		delete(s.name)
		s.name = ""
		s.open = false
	}
	for p in s.prefixes {
		delete(p)
	}
	delete(s.prefixes)
	s.prefixes = nil
}

@(private)
RECONNECT_PAUSE :: 200 * time.Millisecond

@(private)
sub_recv :: proc(s: ^Subscriber, wait: time.Duration, allocator: mem.Allocator) -> (data: []byte, err: Sub_Error) {
	if !s.open {
		return nil, .Closed
	}
	start := mono_now()
	left :: proc(start, wait: time.Duration) -> time.Duration {
		if wait < 0 {
			return -1
		}
		return max(wait - (mono_now() - start), 0)
	}
	if s.reader.body == nil {
		s.reader.allocator = allocator
	}
	for {
		if !s.connected {
			io, oerr := pipe_open(s.name, PIPE_EVENTS_RIGHTS, 0)
			if oerr == .None {
				s.io = io
				s.connected = true
			} else {
				l := left(start, wait)
				if l == 0 {
					return nil, .Timed_Out
				}
				time.sleep(RECONNECT_PAUSE if l < 0 else min(l, RECONNECT_PAUSE))
				continue
			}
		}
		if !s.pending {
			buf := frame_want(&s.reader)
			s.io.ov = {}
			s.io.ov.hEvent = s.io.ev
			if win.ReadFile(s.io.h, raw_data(buf), u32(len(buf)), nil, &s.io.ov) == win.FALSE &&
			   win.GetLastError() != ERROR_IO_PENDING {
				sub_drop(s)
				continue
			}
			s.pending = true
		}
		if win.WaitForSingleObject(s.io.ev, ms_of(left(start, wait))) == win.WAIT_TIMEOUT {
			return nil, .Timed_Out
		}
		got: u32
		ok := win.GetOverlappedResult(s.io.h, &s.io.ov, &got, win.FALSE) != win.FALSE
		s.pending = false
		if !ok {
			sub_drop(s)
			continue
		}
		switch frame_got(&s.reader, int(got)) {
		case .More:
		case .Done:
			return frame_take(&s.reader), .None
		case .Bad_Length, .No_Memory:
			sub_drop(s)
		}
	}
}

// ---- finding a service (tools) ----

@(private)
setup_euid :: proc() -> u32 {
	return 0
}

// Where a tool looks: the pipe namespace. Free the strings and the slice.
candidate_dirs :: proc(allocator := context.allocator) -> []string {
	dirs := make([]string, 1, allocator)
	dirs[0] = strings.clone(PIPE_DIR, allocator)
	return dirs
}

// The pipe namespace has no directory that a user cannot list.
hidden_dir :: proc(allocator := context.allocator) -> string {
	return ""
}

// List the instances whose control pipe exists (`\\.\pipe\noirvpn-NAME-control`).
discover :: proc(allocator := context.allocator) -> []Found {
	out := make([dynamic]Found, allocator)
	fd: win.WIN32_FIND_DATAW
	pattern := win.utf8_to_wstring(PIPE_DIR + "*", context.temp_allocator)
	fh := win.FindFirstFileW(pattern, &fd)
	if fh == win.INVALID_HANDLE_VALUE {
		return out[:]
	}
	defer win.FindClose(fh)
	for {
		name, _ := win.wstring_to_utf8(cstring16(&fd.cFileName[0]), -1, context.temp_allocator)
		if strings.has_prefix(name, PIPE_PREFIX) && strings.has_suffix(name, CONTROL_SUFFIX) &&
		   len(name) > len(PIPE_PREFIX) + len(CONTROL_SUFFIX) {
			inst := name[len(PIPE_PREFIX):len(name) - len(CONTROL_SUFFIX)]
			append(&out, Found {
				name       = strings.clone(inst, allocator),
				url        = strings.concatenate({PIPE_DIR, name}, allocator),
				events_url = strings.concatenate({PIPE_DIR, PIPE_PREFIX, inst, EVENTS_SUFFIX}, allocator),
			})
		}
		if win.FindNextFileW(fh, &fd) == win.FALSE {
			break
		}
	}
	return out[:]
}
