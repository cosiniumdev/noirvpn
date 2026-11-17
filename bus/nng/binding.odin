// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package nng

// Raw bindings to libnng 1.x. The only file that touches the C library.
// - Names, arguments and constants match nng.h exactly (easy to check).
// - Only calls the control bus needs. Left out on purpose: TCP, TLS, WebSocket,
//   HTTP, aio, stats, devices.
// - Calls that change in nng 2.0 are marked "2.0:". See README.md.

import "core:c"

// macOS links the static nng 1.x of build/macos-nng.sh by its path. A Homebrew
// nng 2.x has the same library name and the linker would find it first.
when ODIN_OS == .Darwin {
	foreign import lib "../../out/macos/nng/lib/libnng.a"
} else {
	foreign import lib "system:nng"
}

// Handles. nng wraps each id in a struct so the types cannot be mixed up.
// An id of 0 is never valid.
nng_socket :: struct {
	id: u32,
}

nng_listener :: struct {
	id: u32,
}

nng_dialer :: struct {
	id: u32,
}

nng_pipe :: struct {
	id: u32,
}

nng_ctx :: struct {
	id: u32,
}

// Opaque message.
nng_msg :: struct {}

// Milliseconds.
nng_duration :: i32

NNG_DURATION_INFINITE :: nng_duration(-1)
NNG_DURATION_DEFAULT  :: nng_duration(-2)
NNG_DURATION_ZERO     :: nng_duration(0)

// Flags for send and receive.
// 2.0: NNG_FLAG_ALLOC is removed, so it is not bound here.
NNG_FLAG_NONBLOCK :: c.int(2)

// Error codes (enum nng_errno_enum). NNG_ESYSERR and NNG_ETRANERR are flag
// bits that carry an OS or transport error in the low bits.
// 2.0: NNG_EAMBIGUOUS and NNG_ENOARG are removed. NNG_ESTOPPED is added.
NNG_EINTR        :: 1
NNG_ENOMEM       :: 2
NNG_EINVAL       :: 3
NNG_EBUSY        :: 4
NNG_ETIMEDOUT    :: 5
NNG_ECONNREFUSED :: 6
NNG_ECLOSED      :: 7
NNG_EAGAIN       :: 8
NNG_ENOTSUP      :: 9
NNG_EADDRINUSE   :: 10
NNG_ESTATE       :: 11
NNG_ENOENT       :: 12
NNG_EPROTO       :: 13
NNG_EUNREACHABLE :: 14
NNG_EADDRINVAL   :: 15
NNG_EPERM        :: 16
NNG_EMSGSIZE     :: 17
NNG_ECONNABORTED :: 18
NNG_ECONNRESET   :: 19
NNG_ECANCELED    :: 20
NNG_ENOFILES     :: 21
NNG_ENOSPC       :: 22
NNG_EEXIST       :: 23
NNG_EREADONLY    :: 24
NNG_EWRITEONLY   :: 25
NNG_ECRYPTO      :: 26
NNG_EPEERAUTH    :: 27
NNG_ENOARG       :: 28
NNG_EAMBIGUOUS   :: 29
NNG_EBADTYPE     :: 30
NNG_ECONNSHUT    :: 31
NNG_EINTERNAL    :: 1000
NNG_ESYSERR      :: 0x10000000
NNG_ETRANERR     :: 0x20000000

// Option names. These are C string macros in the header. The type in the
// comment is the type the option takes in nng 1.x.

// Socket options.
NNG_OPT_SOCKNAME   :: cstring("socket-name")        // string
NNG_OPT_RAW        :: cstring("raw")                // bool, read only
NNG_OPT_PROTO      :: cstring("protocol")           // int, read only
NNG_OPT_PROTONAME  :: cstring("protocol-name")      // string, read only
NNG_OPT_PEER       :: cstring("peer")               // int, read only
NNG_OPT_PEERNAME   :: cstring("peer-name")          // string, read only
NNG_OPT_RECVBUF    :: cstring("recv-buffer")        // int, messages
NNG_OPT_SENDBUF    :: cstring("send-buffer")        // int, messages
NNG_OPT_RECVTIMEO  :: cstring("recv-timeout")       // nng_duration
NNG_OPT_SENDTIMEO  :: cstring("send-timeout")       // nng_duration
NNG_OPT_LOCADDR    :: cstring("local-address")      // nng_sockaddr
NNG_OPT_REMADDR    :: cstring("remote-address")     // nng_sockaddr
NNG_OPT_URL        :: cstring("url")                // string
NNG_OPT_MAXTTL     :: cstring("ttl-max")            // int
NNG_OPT_RECVMAXSZ  :: cstring("recv-size-max")      // size_t
NNG_OPT_RECONNMINT :: cstring("reconnect-time-min") // nng_duration
NNG_OPT_RECONNMAXT :: cstring("reconnect-time-max") // nng_duration

// IPC listener option. The value is an int of normal file mode bits, such as
// 0o660. The process umask is not applied. Set it before the listener starts.
NNG_OPT_IPC_PERMISSIONS :: cstring("ipc:permissions") // int, write only

// IPC peer credentials, read from a pipe. In 1.x the type is uint64_t.
// 2.0: the type changes to int.
NNG_OPT_PEER_UID    :: cstring("ipc:peer-uid")    // uint64_t
NNG_OPT_PEER_GID    :: cstring("ipc:peer-gid")    // uint64_t
NNG_OPT_PEER_PID    :: cstring("ipc:peer-pid")    // uint64_t
NNG_OPT_PEER_ZONEID :: cstring("ipc:peer-zoneid") // uint64_t, SunOS only

// Aliases kept in the header for older code.
NNG_OPT_IPC_PEER_UID    :: NNG_OPT_PEER_UID
NNG_OPT_IPC_PEER_GID    :: NNG_OPT_PEER_GID
NNG_OPT_IPC_PEER_PID    :: NNG_OPT_PEER_PID
NNG_OPT_IPC_PEER_ZONEID :: NNG_OPT_PEER_ZONEID

// Pub/sub options.
// 2.0: the SUB_SUBSCRIBE and SUB_UNSUBSCRIBE options are removed. Use
// nng_sub0_socket_subscribe and nng_sub0_socket_unsubscribe, which also work
// in 1.x.
NNG_OPT_SUB_SUBSCRIBE   :: cstring("sub:subscribe")   // bytes, write only
NNG_OPT_SUB_UNSUBSCRIBE :: cstring("sub:unsubscribe") // bytes, write only
NNG_OPT_SUB_PREFNEW     :: cstring("sub:prefnew")     // bool

// Req/rep options.
NNG_OPT_REQ_RESENDTIME :: cstring("req:resend-time") // nng_duration
NNG_OPT_REQ_RESENDTICK :: cstring("req:resend-tick") // nng_duration

@(default_calling_convention = "c")
foreign lib {
	nng_version :: proc() -> cstring ---
	nng_strerror :: proc(err: c.int) -> cstring ---

	// Memory returned by nng (for example by the *_get_string calls).
	nng_free :: proc(ptr: rawptr, size: c.size_t) ---
	nng_strfree :: proc(s: [^]c.char) ---

	// Protocols. The C header also has nng_pub_open etc. as macros for these.
	nng_pub0_open :: proc(s: ^nng_socket) -> c.int ---
	nng_sub0_open :: proc(s: ^nng_socket) -> c.int ---
	nng_req0_open :: proc(s: ^nng_socket) -> c.int ---
	nng_rep0_open :: proc(s: ^nng_socket) -> c.int ---

	nng_sub0_socket_subscribe :: proc(s: nng_socket, buf: rawptr, size: c.size_t) -> c.int ---
	nng_sub0_socket_unsubscribe :: proc(s: nng_socket, buf: rawptr, size: c.size_t) -> c.int ---

	// 2.0: nng_close is renamed nng_socket_close. Use nng_socket_close, which
	// exists in 1.10 and later.
	nng_socket_close :: proc(s: nng_socket) -> c.int ---
	nng_socket_id :: proc(s: nng_socket) -> c.int ---

	// Socket options. The typed set/get calls are kept in 2.0.
	// 2.0: the untyped calls and most _string/_ptr/_uint64 forms are removed.
	nng_socket_set_int :: proc(s: nng_socket, opt: cstring, val: c.int) -> c.int ---
	nng_socket_set_size :: proc(s: nng_socket, opt: cstring, val: c.size_t) -> c.int ---
	nng_socket_set_ms :: proc(s: nng_socket, opt: cstring, val: nng_duration) -> c.int ---
	nng_socket_get_int :: proc(s: nng_socket, opt: cstring, val: ^c.int) -> c.int ---
	nng_socket_get_size :: proc(s: nng_socket, opt: cstring, val: ^c.size_t) -> c.int ---
	nng_socket_get_ms :: proc(s: nng_socket, opt: cstring, val: ^nng_duration) -> c.int ---

	// Endpoints. Flags are 0 or NNG_FLAG_NONBLOCK (dial only).
	nng_listen :: proc(s: nng_socket, url: cstring, l: ^nng_listener, flags: c.int) -> c.int ---
	nng_dial :: proc(s: nng_socket, url: cstring, d: ^nng_dialer, flags: c.int) -> c.int ---
	nng_listener_create :: proc(l: ^nng_listener, s: nng_socket, url: cstring) -> c.int ---
	nng_listener_start :: proc(l: nng_listener, flags: c.int) -> c.int ---
	nng_listener_close :: proc(l: nng_listener) -> c.int ---
	nng_dialer_close :: proc(d: nng_dialer) -> c.int ---
	nng_listener_set_int :: proc(l: nng_listener, opt: cstring, val: c.int) -> c.int ---
	nng_listener_set_ms :: proc(l: nng_listener, opt: cstring, val: nng_duration) -> c.int ---
	nng_listener_set_size :: proc(l: nng_listener, opt: cstring, val: c.size_t) -> c.int ---

	// Messages. Send and receive use messages only (no nng_send / nng_recv).
	// 2.0: these nng_msg_* calls are not listed as changed.
	nng_msg_alloc :: proc(m: ^^nng_msg, size: c.size_t) -> c.int ---
	nng_msg_free :: proc(m: ^nng_msg) ---
	nng_msg_body :: proc(m: ^nng_msg) -> rawptr ---
	nng_msg_len :: proc(m: ^nng_msg) -> c.size_t ---
	nng_msg_append :: proc(m: ^nng_msg, data: rawptr, size: c.size_t) -> c.int ---
	nng_msg_clear :: proc(m: ^nng_msg) ---
	nng_msg_get_pipe :: proc(m: ^nng_msg) -> nng_pipe ---

	// 2.0: nng_sendmsg and nng_recvmsg stay. The flags argument is 0 or
	// NNG_FLAG_NONBLOCK. After a successful send, nng owns the message. After a
	// failure, the caller still owns it.
	nng_sendmsg :: proc(s: nng_socket, m: ^nng_msg, flags: c.int) -> c.int ---
	nng_recvmsg :: proc(s: nng_socket, m: ^^nng_msg, flags: c.int) -> c.int ---

	// Contexts: independent request state on one REP or REQ socket. Each
	// worker thread can own one.
	nng_ctx_open :: proc(ctx: ^nng_ctx, s: nng_socket) -> c.int ---
	nng_ctx_close :: proc(ctx: nng_ctx) -> c.int ---
	nng_ctx_sendmsg :: proc(ctx: nng_ctx, m: ^nng_msg, flags: c.int) -> c.int ---
	nng_ctx_recvmsg :: proc(ctx: nng_ctx, m: ^^nng_msg, flags: c.int) -> c.int ---

	// Pipe options are read only.
	// 2.0: nng_pipe_get_int is the call for the peer uid, gid and pid.
	nng_pipe_get_int :: proc(p: nng_pipe, opt: cstring, val: ^c.int) -> c.int ---
	nng_pipe_get_uint64 :: proc(p: nng_pipe, opt: cstring, val: ^u64) -> c.int ---
	nng_pipe_id :: proc(p: nng_pipe) -> c.int ---
	nng_pipe_close :: proc(p: nng_pipe) -> c.int ---
}
