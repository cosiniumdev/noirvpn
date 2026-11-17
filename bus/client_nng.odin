// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package bus

// The client side of the transport on Unix: nng REQ for requests, nng SUB
// for the events, over Unix sockets.

import "core:mem"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "noir:bus/nng"

@(private)
Sub_Transport :: struct {
	sock: nng.Socket,
	open: bool,
}

// Open or fetch the socket file path of a bus URL.
@(private)
check_url :: proc(url: string) -> (path: string, err: Call_Error) {
	p, ok := socket_file_path(url)
	if !ok {
		return "", .Bad_Url
	}
	if e := socket_presence(p); e != .None {
		return "", e
	}
	return p, .None
}

// Is there a socket file at `p` that this user can reach?
//   - A missing file means "not running".
//   - A file this user may not see means "permission denied": a directory of
//     mode 0750 hides its files from users outside its group, and `stat` then
//     fails with EACCES.
socket_presence :: proc(p: string) -> Call_Error {
	cp := strings.clone_to_cstring(p)
	defer delete(cp)
	st: posix.stat_t
	if posix.stat(cp, &st) == .OK {
		return .None
	}
	#partial switch posix.errno() {
	case .EACCES, .EPERM:
		return .Permission_Denied
	}
	return .Daemon_Not_Running
}

@(private)
dial_error :: proc(e: nng.Error) -> Call_Error {
	#partial switch e {
	case .Connection_Refused, .Not_Found:
		return .Daemon_Not_Running
	case .Permission:
		return .Permission_Denied
	}
	if nng.is_system_error(e) {
		// The numbers of errno differ between systems (ECONNREFUSED is 111 on
		// Linux and 61 on macOS), so use the names of posix.Errno. A file where
		// nothing listens (a killed daemon) gives ECONNREFUSED on Linux and
		// ENOTSOCK on macOS.
		#partial switch posix.Errno(nng.system_errno(e)) {
		case .EACCES, .EPERM:
			return .Permission_Denied
		case .ENOENT, .ECONNREFUSED, .ENOTSOCK:
			return .Daemon_Not_Running
		}
	}
	return .Io
}

// A connection to a control socket.
Conn :: struct {
	sock:    nng.Socket,
	timeout: time.Duration,
	open:    bool,
}

// Connect to the control socket. Fails at once if the daemon is not there.
// `timeout` bounds each send and each wait for a reply.
connect :: proc(url: string, timeout := DEFAULT_CALL_TIMEOUT) -> (c: Conn, err: Call_Error) {
	path := check_url(url) or_return
	sock, oerr := nng.open(.Req)
	if oerr != .None {
		return {}, .Io
	}
	nng.set_send_timeout(sock, timeout)
	nng.set_recv_timeout(sock, timeout)
	// No resend on a timer: a retry is the caller's decision (same id).
	nng.set_req_resend_time(sock, -1)
	// Replies can be long (a peer list); the default nng limit is 1 MiB.
	nng.set_recv_max_size(sock, MAX_REPLY_SIZE)
	if derr := nng.dial(sock, nng_url(path)); derr != .None {
		nng.close(sock)
		return {}, dial_error(derr)
	}
	return Conn{sock = sock, timeout = timeout, open = true}, .None
}

@(private)
nng_url :: proc(path: string) -> cstring {
	return strings.clone_to_cstring(socket_url(path, context.temp_allocator), context.temp_allocator)
}

disconnect :: proc(c: ^Conn) {
	if c.open {
		nng.close(c.sock)
		c.open = false
	}
}


@(private)
send_error :: proc(e: nng.Error) -> Call_Error {
	#partial switch e {
	case .Timed_Out:
		return .Timeout
	case .Connection_Refused:
		return .Daemon_Not_Running
	case .No_Memory:
		return .No_Memory
	}
	return .Io
}


// Follow events on topics that start with any of `prefixes` (empty: all). A
// prefix like "peer." matches "peer.connect".
// The sequence number counts all events, whatever the topic. So the subscriber
// gets every event and filters after the sequence check (an nng prefix filter
// would show false gaps). A gap can include topics not asked for.
// `wait`:
//   - false: the daemon must be there now (`Daemon_Not_Running` otherwise).
//   - true: return at once. nng keeps trying to connect, also after a daemon
//     restart (use for long-running tools). A restart shows as `restarted` on
//     the next event.
subscribe :: proc(url: string, prefixes: []string = nil, wait := false) -> (s: Subscriber, err: Call_Error) {
	path, ok := socket_file_path(url)
	if !ok {
		return {}, .Bad_Url
	}
	if !wait {
		if e := socket_presence(path); e != .None {
			return {}, e
		}
	}
	sock, oerr := nng.open(.Sub)
	if oerr != .None {
		return {}, .Io
	}
	nng.subscribe(sock, "")
	if derr := nng.dial(sock, nng_url(path), wait); derr != .None {
		nng.close(sock)
		return {}, dial_error(derr)
	}
	s = Subscriber {
		sock = sock,
		open = true,
	}
	for p in prefixes {
		append(&s.prefixes, strings.clone(p))
	}
	return s, .None
}

unsubscribe :: proc(s: ^Subscriber) {
	if s.open {
		nng.close(s.sock)
		s.open = false
	}
	for p in s.prefixes {
		delete(p)
	}
	delete(s.prefixes)
	s.prefixes = nil
}


// Send one request and wait for its reply.
@(private)
conn_exchange :: proc(c: ^Conn, request: []byte, allocator: mem.Allocator) -> (data: []byte, err: Call_Error) {
	if serr := nng.send(c.sock, request); serr != .None {
		return nil, send_error(serr)
	}
	d, rerr := nng.recv(c.sock, false, allocator)
	if rerr != .None {
		return nil, send_error(rerr)
	}
	return d, .None
}

// One event message, or an error. A negative `wait` waits for ever.
@(private)
sub_recv :: proc(s: ^Subscriber, wait: time.Duration, allocator: mem.Allocator) -> (data: []byte, err: Sub_Error) {
	nng.set_recv_timeout(s.sock, wait)
	d, rerr := nng.recv(s.sock, false, allocator)
	if rerr != .None {
		#partial switch rerr {
		case .Timed_Out:
			return nil, .Timed_Out
		case .Closed:
			return nil, .Closed
		}
		return nil, .Io
	}
	return d, .None
}
