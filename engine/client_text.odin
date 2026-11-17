// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "base:runtime"
import cnet "core:net"
import "core:strings"
import "noir:bus"
import "noir:client"

// The small texts of the client: addresses, the counters of a struct, and the
// words of `client.state` for the reason that a connection ended.

ip4_str :: proc(a: [4]u8, allocator := context.temp_allocator) -> string {
	return cnet.address_to_string(cnet.IP4_Address(a), allocator)
}

ip6_str :: proc(a: [16]u8, allocator := context.temp_allocator) -> string {
	return cnet.address_to_string(transmute(cnet.IP6_Address)a, allocator)
}

// ---------------------------------------------------------------- counters

// Writes every u64 field of the struct `v` as `"<prefix><name>": value` into
// the open object `w`. Other field types are skipped.
write_u64_fields :: proc(w: ^bus.Writer, v: ^$T, prefix := "") {
	ti := runtime.type_info_base(type_info_of(T))
	st, ok := ti.variant.(^runtime.Type_Info_Struct)
	if !ok {
		return
	}
	for i in 0 ..< int(st.field_count) {
		ft := runtime.type_info_base(st.types[i])
		if _, is_int := ft.variant.(^runtime.Type_Info_Integer); !is_int || ft.size != 8 {
			continue
		}
		val := (^u64)(rawptr(uintptr(v) + st.offsets[i]))^
		key := st.names[i]
		if prefix != "" {
			key = strings.concatenate({prefix, key}, context.temp_allocator)
		}
		bus.kv_u64(w, key, val)
	}
}

// ------------------------------------------------------------ client states

// `client.state` `reason` for a move to `waiting` or `stopped`: why the last
// connection ended. `close`: why a graceful close started. `code`: exit code of
// the daemon so far (setup error). `kernel`: the attempt used the kernel driver,
// so a failed data path is `dco_failed`.
state_reason :: proc "contextless" (o: client.Outcome, close: Close_Reason, code: Exit, kernel := false) -> string {
	switch close {
	case .None:
	case .Disconnect, .Restart:
		return "user_request"
	case .Datapath:
		return "dco_failed" if kernel else "udco_failed"
	case .Stop, .Inactive, .Session_Timeout:
		return "exit"
	case .Fatal:
		#partial switch code {
		case .Config:
			return "config_error"
		case .Network:
			return "network_error"
		}
		return "exit"
	}
	switch o {
	case .Connected:
		return ""
	case .Connect_Failed, .Handshake_Timeout:
		return "network_error"
	case .Handshake_Failed:
		return "tls_failed"
	case .Push_Rejected:
		return "push_rejected"
	case .Auth_Failed, .Auth_Failed_Temp:
		return "auth_failed"
	case .Server_Restart, .Remote_Exit:
		return "server_restart"
	case .Server_Halt:
		return "server_halt"
	case .Ping_Restart:
		return "ping_timeout"
	case .Inactive, .Session_Timeout, .Local_Stop:
		return "exit"
	case .Local_Restart:
		return "user_request"
	case .Datapath_Failed:
		return "dco_failed" if kernel else "udco_failed"
	}
	return ""
}

// The same for a stop the policy decided.
stop_state_reason :: proc "contextless" (r: client.Stop_Reason) -> string {
	switch r {
	case .Auth_Failed:
		return "auth_failed"
	case .Halted:
		return "server_halt"
	case .Retries_Exhausted, .Resolve_Failed:
		return "network_error"
	case .No_Remote:
		return "config_error"
	case .None, .Inactive, .Session_Timeout, .Local_Stop:
		return "exit"
	}
	return "exit"
}
