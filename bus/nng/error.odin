// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package nng

import "core:c"

// Error is an nng error code. None means success.
// Named values map to nng's codes. nng can also wrap an OS or transport error:
// the code then has the System or Transport flag bit and the OS error number in
// the low bits. Such a value has no name but keeps all the information. Use
// is_system_error, system_errno and error_string.
Error :: enum c.int {
	None                = 0,
	Interrupted         = NNG_EINTR,
	No_Memory           = NNG_ENOMEM,
	Invalid             = NNG_EINVAL,
	Busy                = NNG_EBUSY,
	Timed_Out           = NNG_ETIMEDOUT, // receive or send timeout expired
	Connection_Refused  = NNG_ECONNREFUSED,
	Closed              = NNG_ECLOSED, // socket, context or pipe is closed
	Try_Again           = NNG_EAGAIN, // non-blocking call would block
	Not_Supported       = NNG_ENOTSUP,
	Address_In_Use      = NNG_EADDRINUSE,
	State               = NNG_ESTATE, // wrong state, e.g. REP send with no request
	Not_Found           = NNG_ENOENT,
	Protocol            = NNG_EPROTO,
	Unreachable         = NNG_EUNREACHABLE,
	Address_Invalid     = NNG_EADDRINVAL,
	Permission          = NNG_EPERM,
	Message_Size        = NNG_EMSGSIZE,
	Connection_Aborted  = NNG_ECONNABORTED,
	Connection_Reset    = NNG_ECONNRESET,
	Canceled            = NNG_ECANCELED,
	No_Files            = NNG_ENOFILES,
	No_Space            = NNG_ENOSPC,
	Exists              = NNG_EEXIST,
	Read_Only           = NNG_EREADONLY,
	Write_Only          = NNG_EWRITEONLY,
	Crypto              = NNG_ECRYPTO,
	Peer_Auth           = NNG_EPEERAUTH,
	No_Arg              = NNG_ENOARG,
	Ambiguous           = NNG_EAMBIGUOUS,
	Bad_Type            = NNG_EBADTYPE,
	Connection_Shutdown = NNG_ECONNSHUT,
	Internal            = NNG_EINTERNAL,
}

// Turn a C return code into an Error.
@(private)
to_error :: #force_inline proc "contextless" (rc: c.int) -> Error {
	return Error(rc)
}

// True when the error wraps an OS error (errno on POSIX).
is_system_error :: proc "contextless" (e: Error) -> bool {
	return c.int(e) & NNG_ESYSERR != 0
}

// True when the error wraps a transport specific error.
is_transport_error :: proc "contextless" (e: Error) -> bool {
	return c.int(e) & NNG_ETRANERR != 0
}

// The OS error number inside a system error, or 0 for any other error.
system_errno :: proc "contextless" (e: Error) -> int {
	if !is_system_error(e) {
		return 0
	}
	return int(c.int(e) & ~c.int(NNG_ESYSERR))
}

// Human readable text from nng. The string is static: do not free it. For
// codes without a fixed text, nng uses one shared buffer. Copy the string if
// you keep it.
error_string :: proc(e: Error) -> string {
	return string(nng_strerror(c.int(e)))
}
