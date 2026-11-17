// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux, darwin, freebsd, openbsd, netbsd
package bus

// The transport of the host on Unix: nng PUB for the events and nng REP for
// the control channel, over Unix sockets. Each worker has its own nng context
// on the REP socket. Nothing runs Odin code on an nng thread.

import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:time"
import "noir:bus/nng"

Transport_Error :: nng.Error

@(private)
Transport :: struct {
	pub_sock: nng.Socket,
	pub_open: bool,
	rep_sock: nng.Socket,
	rep_open: bool,
}

@(private)
Transport_Worker :: struct {
	cx:    nng.Ctx,
	cx_on: bool,
}

// One received request.
@(private)
Incoming :: struct {
	msg: ^nng.Msg,
}

@(private)
Recv_Status :: enum u8 {
	Ok,
	Closed,
	Failed,
}

@(private)
incoming_body :: proc(m: ^Incoming) -> []byte {
	return nng.msg_body(m.msg)
}

// Directories first, then the sockets.
@(private)
transport_prepare :: proc(h: ^Host, opts: Host_Options) -> Open_Error {
	return prepare_dirs(opts)
}

// Creates the socket folders of `opts` as `host_open` does: mode DIR_MODE and the
// group of the control socket (else the events socket). An existing folder is
// only checked. A daemon that keeps other files there calls this first, so the
// folder gets the bus mode and group.
prepare_dirs :: proc(opts: Host_Options) -> Open_Error {
	ev, has_events := opts.events.?
	ctl, has_control := opts.control.?
	gid_for_dir: Maybe(u32)
	if has_control && ctl.group != "" {
		if g, ok := default_resolver(.Gid, ctl.group); ok {
			gid_for_dir = g
		}
	} else if has_events && ev.group != "" {
		if g, ok := default_resolver(.Gid, ev.group); ok {
			gid_for_dir = g
		}
	}
	if has_events {
		if e := ensure_dir(dir_of(ev.path), gid_for_dir); e != .None {
			return e
		}
	}
	if has_control {
		if e := ensure_dir(dir_of(ctl.path), gid_for_dir); e != .None {
			return e
		}
	}
	return .None
}

@(private)
dir_of :: proc(path: string) -> string {
	i := strings.last_index_byte(path, '/')
	if i <= 0 {
		return "/"
	}
	return path[:i]
}

@(private)
mode_to_u32 :: proc(m: posix.mode_t) -> u32 {
	when size_of(posix.mode_t) == 4 {
		return transmute(u32)m
	} else {
		return u32(transmute(u16)m)
	}
}

@(private)
u32_to_mode :: proc(m: u32) -> posix.mode_t {
	when size_of(posix.mode_t) == 4 {
		return transmute(posix.mode_t)m
	} else {
		return transmute(posix.mode_t)u16(m)
	}
}

// Create the directory if it is missing; otherwise check that it is a
// directory owned by root or us and not writable by others (unless sticky).
@(private)
ensure_dir :: proc(dir: string, gid: Maybe(u32)) -> Open_Error {
	if dir == "/" {
		return .None
	}
	cdir := strings.clone_to_cstring(dir, context.temp_allocator)
	st: posix.stat_t
	if posix.stat(cdir, &st) == .OK {
		if !posix.S_ISDIR(st.st_mode) {
			return .Dir_Not_Safe
		}
		owner := u32(st.st_uid)
		if owner != 0 && owner != euid() {
			return .Dir_Not_Safe
		}
		mode := mode_to_u32(st.st_mode)
		if mode & 0o022 != 0 && mode & 0o1000 == 0 {
			return .Dir_Not_Safe
		}
		return .None
	}
	if posix.mkdir(cdir, u32_to_mode(DIR_MODE)) != .OK {
		return .Dir_Create_Failed
	}
	// mkdir applies the umask; set the mode we want.
	posix.chmod(cdir, u32_to_mode(DIR_MODE))
	if g, ok := gid.?; ok {
		posix.chown(cdir, max(posix.uid_t), posix.gid_t(g))
	}
	return .None
}

@(private)
listen_socket :: proc(
	sock: nng.Socket,
	ep: Endpoint,
	in_use, listen_failed, chown_failed: Open_Error,
) -> (
	err: Open_Error,
	nng_err: nng.Error,
) {
	url := socket_url(ep.path, context.temp_allocator)
	mode := int(ep.mode) if ep.mode != 0 else DEFAULT_SOCKET_MODE
	_, lerr := nng.listen(sock, strings.clone_to_cstring(url, context.temp_allocator), mode)
	if lerr != .None {
		if lerr == .Address_In_Use {
			return in_use, lerr
		}
		return listen_failed, lerr
	}
	if ep.group != "" {
		gid, ok := default_resolver(.Gid, ep.group)
		if !ok {
			return .Bad_Group, .None
		}
		cpath := strings.clone_to_cstring(ep.path, context.temp_allocator)
		if posix.chown(cpath, max(posix.uid_t), posix.gid_t(gid)) != .OK {
			return chown_failed, .None
		}
	}
	return .None, .None
}

@(private)
transport_listen_events :: proc(h: ^Host, ep: Endpoint, queue: int) -> (Open_Error, Transport_Error) {
	sock, oerr := nng.open(.Pub)
	if oerr != .None {
		return .Socket_Open_Failed, oerr
	}
	h.tr.pub_sock = sock
	h.tr.pub_open = true
	nng.set_send_buffer(sock, queue)
	return listen_socket(sock, ep, .Events_In_Use, .Events_Listen_Failed, .Events_Chown_Failed)
}

@(private)
transport_listen_control :: proc(h: ^Host, ep: Endpoint, n_workers: int) -> (Open_Error, Transport_Error) {
	sock, oerr := nng.open(.Rep)
	if oerr != .None {
		return .Socket_Open_Failed, oerr
	}
	h.tr.rep_sock = sock
	h.tr.rep_open = true
	// Twice the largest limit: a message between the limit of its operation and
	// this gets a proper reply; a larger one causes nng to drop the connection.
	nng.set_recv_max_size(sock, FRAME_MAX_REQUEST)
	nng.set_send_timeout(sock, 5 * time.Second)
	if e, ne := listen_socket(sock, ep, .Control_In_Use, .Control_Listen_Failed, .Control_Chown_Failed);
	   e != .None {
		return e, ne
	}
	for &w in h.workers {
		cx, cerr := nng.ctx_open(sock)
		if cerr != .None {
			return .Socket_Open_Failed, cerr
		}
		w.tw.cx = cx
		w.tw.cx_on = true
	}
	return .None, .None
}

@(private)
transport_recv :: proc(h: ^Host, w: ^Worker) -> (m: Incoming, st: Recv_Status) {
	msg, err := nng.ctx_recv_msg(w.tw.cx)
	if err != .None {
		return {}, .Closed if err == .Closed else .Failed
	}
	return Incoming{msg = msg}, .Ok
}

// The uid and gid that the kernel reports for the sender, and the roles they
// give. A `gid` rule also asks the group database (without the lock: a lookup
// can read files).
@(private)
peer_identity :: proc(h: ^Host, w: ^Worker, m: ^Incoming) -> (creds: Peer_Creds, roles: Roles, ok: bool) {
	nc, cerr := nng.pipe_peer_creds(nng.msg_pipe(m.msg))
	if cerr != .None {
		return {}, {}, false
	}
	creds = Peer_Creds {
		uid     = nc.uid,
		gid     = nc.gid,
		pid     = nc.pid,
		has_pid = nc.has_pid,
	}
	sync.mutex_lock(&h.mu)
	roles = roles_for(&h.policy, creds.uid, creds.gid)
	roles_group_rules(&h.policy, creds.gid, roles, &w.groups)
	member := h.member
	sync.mutex_unlock(&h.mu)
	if len(w.groups) > 0 {
		roles = roles_with_groups(roles, creds.uid, w.groups[:], member)
	}
	return creds, roles, true
}

// Free the request message (the caller has overwritten its body).
@(private)
transport_release :: proc(h: ^Host, w: ^Worker, m: ^Incoming) {
	nng.msg_free(m.msg)
	m.msg = nil
}

@(private)
transport_send :: proc(h: ^Host, w: ^Worker, m: ^Incoming, reply: []byte) -> bool {
	rm, merr := nng.msg_new(reply)
	if merr != .None {
		return false
	}
	if nng.ctx_send_msg(w.tw.cx, rm) != .None {
		nng.msg_free(rm)
		return false
	}
	return true
}

// Never blocks: nng drops the event for a subscriber whose queue is full.
@(private)
transport_publish :: proc(h: ^Host, topic: string, envelope: []byte) -> bool {
	return nng.publish(h.tr.pub_sock, topic, envelope, true) == .None
}

@(private)
transport_stop :: proc(h: ^Host) {
	for &w in h.workers {
		if w.tw.cx_on {
			nng.ctx_close(w.tw.cx)
			w.tw.cx_on = false
		}
	}
	if h.tr.rep_open {
		nng.close(h.tr.rep_sock)
		h.tr.rep_open = false
	}
}

@(private)
transport_close :: proc(h: ^Host) {
	transport_stop(h)
	if h.tr.pub_open {
		nng.close(h.tr.pub_sock)
		h.tr.pub_open = false
	}
	for path in ([2]string{h.events_path, h.control_path}) {
		if path != "" {
			os.remove(path)
		}
	}
}
