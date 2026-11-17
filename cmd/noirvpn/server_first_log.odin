// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:hash"
import "core:strings"
import "core:time"
import net "noir:platform/net"
import "noir:proto/session"

// The log of first packets that create no session: drops and odd resets.
//
// A client that cannot get past the stateless handshake retries every second,
// and anyone can send such packets. So one line is written for each source and
// reason per FIRST_LOG_HOLD, and at most FIRST_LOG_MAX lines in that time in all.
// The packets held back are counted in the next line of that source.

FIRST_LOG_HOLD :: 60 * time.Second
FIRST_LOG_MAX :: 20
FIRST_LOG_SLOTS :: 16

First_Note :: enum u8 {
	Drop,
	Odd_Reset,
	Reply,
}

First_Log_Slot :: struct {
	key:  u64,
	at:   time.Duration,
	held: int,
	used: bool,
}

First_Log :: struct {
	slots:        [FIRST_LOG_SLOTS]First_Log_Slot,
	window_start: time.Duration,
	lines:        int,
	held:         int, // held back by FIRST_LOG_MAX
}

@(rodata)
FIRST_DROP_NAME := [session.First_Drop]string {
	.None          = "none",
	.Not_Udp       = "not-udp",
	.Bad_Address   = "bad-address",
	.Out_Too_Small = "out-too-small",
	.Too_Short     = "too-short",
	.Too_Long      = "too-long",
	.Bad_Opcode    = "bad-opcode",
	.Bad_Key_Id    = "bad-key-id",
	.Zero_Sid      = "zero-sid",
	.Wrap_Mode     = "wrap-mode",
	.Unwrap        = "unwrap",
	.Decode        = "decode",
	.Metadata_Age  = "metadata-age",
	.Force_Cookie  = "force-cookie",
	.Bad_Cookie    = "bad-cookie",
	.Bad_Ids       = "bad-ids",
	.Rate_Source   = "rate-source",
	.Rate_Global   = "rate-global",
	.Rate_Sessions = "rate-sessions",
}

// The level of a drop. A wrapping mismatch is a setup error, so it shows at
// verb 1. Rate limits and malformed packets are normal on an open port.
first_drop_level :: proc(why: session.First_Drop) -> Level {
	#partial switch why {
	case .Not_Udp, .Bad_Address, .Out_Too_Small:
		return .Warn
	case .Wrap_Mode, .Unwrap, .Decode, .Metadata_Age:
		return .Notice
	case .Bad_Cookie, .Rate_Source, .Rate_Global, .Rate_Sessions:
		return .Verbose
	}
	return .Verbose
}

// What a drop usually means, for the operator.
first_drop_text :: proc(sh: ^session.Server_Shared, why: session.First_Drop) -> string {
	#partial switch why {
	case .Unwrap:
		switch sh.mode {
		case .Tls_Auth:
			return "the tls-auth check failed: the client has no tls-auth, another key, another auth digest, or the wrong key-direction (the client must use 1)"
		case .Tls_Crypt:
			return "the tls-crypt check failed: the client has no tls-crypt or another key"
		case .Tls_Crypt_V2:
			return "the tls-crypt-v2 client key does not open with the server key"
		case .None:
		}
		return "the packet does not unwrap"
	case .Wrap_Mode:
		if sh.mode == .Tls_Crypt_V2 {
			return "the client does not use tls-crypt-v2 and this server requires it"
		}
		return "the client uses tls-crypt-v2 and this server does not"
	case .Decode:
		if sh.mode == .None {
			return "the packet does not decode: the client probably uses tls-auth or tls-crypt and this server has none"
		}
		return "the packet does not decode"
	case .Metadata_Age:
		return "the tls-crypt-v2 client key is older than tls-crypt-v2-max-age"
	case .Force_Cookie:
		return "the client cannot do the cookie handshake and force-cookie is set"
	case .Bad_Cookie:
		return "the cookie is not valid (a late or spoofed packet)"
	case .Rate_Source:
		return "too many first packets from this address"
	case .Rate_Global:
		return "too many first packets from all addresses"
	case .Rate_Sessions:
		return "too many new sessions (connect-freq)"
	case .Not_Udp, .Bad_Address, .Out_Too_Small:
		return "internal error"
	}
	return "not a valid first packet"
}

// Logs the result of a first packet from `from` (address bytes `fb`).
srv_first_log :: proc(d: ^Srv, sh: ^session.Server_Shared, res: ^session.First_Result, from: net.Endpoint, fb: []u8) {
	note: First_Note
	level: Level
	switch {
	case res.kind == .Drop:
		note, level = .Drop, first_drop_level(res.reason)
	case res.kind == .Reply && res.odd_reset:
		// With wrapping the packet passed the check, so its client is real but odd.
		note = .Odd_Reset
		level = .Notice if sh.mode == .None else .Verbose
	case res.kind == .Reply:
		note, level = .Reply, .Debug
	case:
		return
	}
	if !log_enabled(level) {
		return
	}
	held, ok := first_log_take(&d.first_log, now_srv(d), fb, note, res.reason)
	if !ok {
		return
	}
	text: string
	switch note {
	case .Drop:
		text = fmt.tprintf("first packet from [%s] dropped (%s): %s", endpoint_text(from), FIRST_DROP_NAME[res.reason], first_drop_text(sh, res.reason))
	case .Odd_Reset:
		if sh.mode == .None {
			text = fmt.tprintf("reset from [%s] has acks or a message id: the client probably uses tls-auth or tls-crypt and this server has none, so it cannot read the reply", endpoint_text(from))
		} else {
			text = fmt.tprintf("reset from [%s] has acks or a message id", endpoint_text(from))
		}
	case .Reply:
		text = fmt.tprintf("reset from [%s]: sent the stateless reply", endpoint_text(from))
	}
	if held > 0 {
		text = fmt.tprintf("%s (and %d more since the last line)", text, held)
	}
	logf(level, "%s", text)
}

// Is a line for this source and note due? `held` is the number of packets of
// the same kind since its last line.
first_log_take :: proc(fl: ^First_Log, now: time.Duration, fb: []u8, note: First_Note, why: session.First_Drop) -> (held: int, ok: bool) {
	tag := [2]u8{u8(note), u8(why)}
	key := hash.fnv64a(tag[:], hash.fnv64a(fb))
	slot: ^First_Log_Slot
	oldest: ^First_Log_Slot
	for &s in fl.slots {
		if s.used && s.key == key {
			slot = &s
			break
		}
		if oldest == nil || !s.used || (oldest.used && s.at < oldest.at) {
			oldest = &s
		}
	}
	if slot != nil && now - slot.at < FIRST_LOG_HOLD {
		slot.held += 1
		return 0, false
	}
	if now - fl.window_start >= FIRST_LOG_HOLD {
		if fl.held > 0 {
			logf(.Notice, "%d first-packet log lines held back in the last %d s", fl.held, int(FIRST_LOG_HOLD / time.Second))
		}
		fl.window_start, fl.lines, fl.held = now, 0, 0
	}
	if fl.lines >= FIRST_LOG_MAX {
		fl.held += 1
		return 0, false
	}
	fl.lines += 1
	if slot == nil {
		slot = oldest
		slot^ = {key = key, used = true}
	}
	held = slot.held
	slot.at, slot.held = now, 0
	return held, true
}

// The status line of the first-packet counters of all listeners.
srv_first_status :: proc(d: ^Srv, level: Level, what: string) {
	total: session.First_Stats
	for &sh in d.shared {
		st := &sh.stats
		total.replies += st.replies
		total.accepted += st.accepted
		total.dropped += st.dropped
		total.rate_hit += st.rate_hit
		total.odd_resets += st.odd_resets
		for n, why in st.by_reason {
			total.by_reason[why] += n
		}
	}
	b := strings.builder_make(context.temp_allocator)
	for n, why in total.by_reason {
		if n > 0 {
			fmt.sbprintf(&b, " %s=%d", FIRST_DROP_NAME[why], n)
		}
	}
	logf(
		level,
		"%s: first packets replies=%d odd-resets=%d accepted=%d dropped=%d rate-hit=%d; drops%s",
		what, total.replies, total.odd_resets, total.accepted, total.dropped, total.rate_hit,
		strings.to_string(b) if total.dropped > 0 else " none",
	) // fmt: skip
}
