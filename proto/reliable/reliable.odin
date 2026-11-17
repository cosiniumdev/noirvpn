// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package reliable: control-channel reliability layer between the TLS byte stream
// and the control packets on the wire.
//
// - No I/O, clock or thread. Time-dependent calls take `now` (monotonic
//   `time.Duration`, real or test-driven); `next_wakeup` says when to call again.
// - One `Channel` is one key state. A soft reset creates a new one (`reset`, `init`).
// - Packets are plain data. The wire codec encodes and decodes bytes.
// - Not thread-safe: one thread per `Channel`.
// - Memory: `init` allocates (6 + 12) * max_payload bytes once. Windows are fixed.
//
// Interface, in session-layer order:
//
//	TLS bytes out   send(c, bytes, budget, tag, now) -> consumed    cut into packets
//	                send_packet(c, tag, payload, now)              one packet, may be empty
//	                send_room(c)                                   packets that may be queued now
//	wire out        poll(c, now) -> Tx                             next packet to put on the wire
//	                next_wakeup(c, now) -> time                    when to call poll again
//	wire in         receive(c, Rx, now) -> Rx_Status               one decoded control packet
//	TLS bytes in    pop(c) -> Delivery                             in-order payloads, call until empty
//	failure         error(c) -> Failure                            hand window, retransmit limit
//	lifetime        init, destroy, reset
//
// Typical loop:
//
//	consumed := send(&c, tls_out, budget, tag, now)   // keep the rest in TLS
//	for tx, ok := poll(&c, now); ok; tx, ok = poll(&c, now) {
//		// encode tx and send it; tx.payload is valid until the next call
//	}
//	... later, a datagram arrives ...
//	status := receive(&c, rx, now)
//	for d, ok := pop(&c); ok; d, ok = pop(&c) {
//		// feed d.payload to TLS
//	}
//	then poll again, and sleep until next_wakeup.
//
// The session layer must also:
//   - Check opcode, direction, sid, key id and unwrap before `receive`
//. Call `set_peer_sid` once the sid is accepted,
//     before the first `receive` that carries a message.
//   - Pass `Rx.hard_reset` for opcodes 7, 8 and 10 (a reset with id != 0 is then
//     ignored without an ack).
//   - Treat a delivered reset (id 0, `Delivery.tag` of a reset opcode) as TLV
//     data.
//   - Call `clear_deadline` when the key state becomes ACTIVE.
//
// `tag`: opaque byte stored with each packet, returned on every transmission and
// delivery. The session layer stores the opcode, so a retransmission keeps it (a
// P_CONTROL_WKC_V1 stays one).
package reliable

import "core:mem"
import "core:time"

// Session id: 8 bytes, never all zero when defined.
SID_LEN :: 8
Sid :: [SID_LEN]u8

// Window sizes and list sizes.
SEND_WINDOW :: 6 // packets sent and not yet acked, and the id distance
RECV_WINDOW :: 12 // packets stored ahead of the next expected id
ACK_LIST_MAX :: 8 // ids in one ack array; also the pending and recent lists
ACK_PIGGY_MAX :: 4 // ids on a packet that carries data
FAST_RETRANSMIT_ACKS :: 3 // acks of later packets that set a packet due at once
BACKOFF_CAP_FACTOR :: 64 // the timeout stops doubling at this multiple of the first one

DEFAULT_TIMEOUT :: 2 * time.Second // tls-timeout default
MAX_TIMEOUT :: 65536 * time.Second // tls-timeout upper limit
DEFAULT_MAX_PAYLOAD :: 2048 // receiver limit for control packets
MIN_PIECE :: 16 // a sender cuts pieces of at least this size

// Space a packet needs besides its payload.
IP_UDP_OVERHEAD_V4 :: 28
IP_UDP_OVERHEAD_V6 :: 48 // also used when the family is not known, and on TCP
WRAP_OVERHEAD_TLS_CRYPT :: 56 // tls-crypt and tls-crypt-v2 (the real size added is 40)
TLS_MTU_MIN :: 154
TLS_MTU_MAX :: 2048

// Ids acknowledged in one packet, as plain data. `sid` is the "remote sid" of the
// wire array: the session id of the receiver of the ack. On the wire only when
// `count` > 0.
//
// `Tx`: the peer's sid (set by this layer). `Rx`: what the decoder read; this
// layer compares it with our own sid.
Ack_List :: struct {
	ids:   [ACK_LIST_MAX]u32,
	count: u8, // the wire count byte; a value above 8 is refused by `receive`
	sid:   Sid,
}

Config :: struct {
	// Initial retransmit timeout (`tls-timeout`). 0 means 2 s. Sub-second
	// values are allowed (for tests). The packet is never sent earlier than
	// this after the previous send.
	timeout:         time.Duration,
	// Time from `init`/`reset` to the failure `.Hand_Window`, unless
	// `clear_deadline` is called first. 0 means no
	// deadline.
	//
	// SPEC-GAP: the hand window belongs to the key state, not to this layer. The
	// spec says it starts "when the first packet is generated" (client) or at
	// session creation (server from a cookie). Here it starts at `init`/`reset`;
	// the session layer creates the channel then, or moves the deadline with
	// `set_deadline`.
	hand_window:     time.Duration,
	// Retransmissions allowed per packet before the failure `.Retransmit_Limit`.
	// 0 means no limit, as the spec says ("no limit on the
	// number of retransmissions").
	//
	// SPEC-GAP: the limit is our addition. The packet fails one timeout after its
	// last allowed send.
	max_retransmits: int,
	// Largest payload of one packet, for both send and receive. 0 means 2048.
	max_payload:     int,
	// Our session id and the peer's. The peer sid can be set later with
	// `set_peer_sid` (a client learns it from the server's reset).
	local_sid:       Sid,
	peer_sid:        Sid,
	// First message id each way. 0 for a normal start. A stateful server created
	// from a valid cookie starts both at 1.
	send_first_id:   u32,
	recv_first_id:   u32,
}

Init_Error :: enum {
	None,
	Alloc,
	Bad_Config,
}

// Why the channel stopped. After a failure every call is inert until `reset`.
Failure :: enum {
	None,
	Hand_Window, // the deadline passed (handshake not finished in time)
	Retransmit_Limit, // a packet used up `max_retransmits`
}

// Counters for telemetry and tests.
Stats :: struct {
	tx_control:       int, // data-carrying packets handed out, retransmits included
	tx_ack:           int, // bare ack packets handed out
	retransmits:      int, // tx_control minus first transmissions
	fast_retransmits: int, // retransmits sent early because of later acks
	rx_stored:        int, // new messages stored
	rx_duplicate:     int, // messages seen before (acked again)
	rx_ahead:         int, // too far ahead, dropped
	rx_window_full:   int, // dropped because every slot was in use
	rx_bad_reset:     int, // hard reset with id != 0
	rx_bad_acks:      int, // ack list refused (count or sid)
	rx_oversize:      int,
	acks_applied:     int, // ids that removed a packet
	acks_ignored:     int, // ids outside the window or for nothing outstanding
	pending_full:     int, // ids not queued because the pending list was full
}

@(private)
Send_Slot :: struct {
	used:       bool,
	id:         u32,
	tag:        u8,
	len:        int,
	next_try:   time.Duration, // due when now >= next_try
	timeout:    time.Duration, // wait after the next transmission
	later_acks: int,
	tx_count:   int,
}

@(private)
Recv_Slot :: struct {
	used: bool,
	tag:  u8,
	len:  int,
}

Channel :: struct {
	cfg:            Config,
	failure:        Failure,
	// Time of the last control packet that passed the checks of
	// the receive rules (the creation time before the first one).
	last_rx:        time.Duration,
	stats:          Stats,
	// Next message id to assign, and next id to deliver.
	next_id:        u32,
	next_recv:      u32,
	// Everything below is private to the package.
	allocator:      mem.Allocator,
	buf:            []u8,
	held:           bool,
	deadline:       time.Duration,
	deadline_armed: bool,
	send_slots:     [SEND_WINDOW]Send_Slot,
	recv_head:      int, // ring index of the slot for `next_recv`
	recv_used:      int,
	recv_slots:     [RECV_WINDOW]Recv_Slot,
	pending:        [ACK_LIST_MAX]u32, // to ack, in arrival order
	pending_n:      int,
	recent:         [ACK_LIST_MAX]u32, // acked lately, most recent first
	recent_n:       int,
}

// Sets up a channel. Allocates the payload buffers once, with `allocator`.
init :: proc(c: ^Channel, cfg: Config, now: time.Duration, allocator := context.allocator) -> Init_Error {
	conf := cfg
	if conf.timeout == 0 {
		conf.timeout = DEFAULT_TIMEOUT
	}
	if conf.max_payload == 0 {
		conf.max_payload = DEFAULT_MAX_PAYLOAD
	}
	if conf.timeout < 0 || conf.timeout > MAX_TIMEOUT || conf.hand_window < 0 || conf.max_retransmits < 0 {
		return .Bad_Config
	}
	if conf.max_payload < MIN_PIECE || conf.max_payload > 1 << 20 {
		return .Bad_Config
	}
	buf, err := make([]u8, (SEND_WINDOW + RECV_WINDOW) * conf.max_payload, allocator)
	if err != nil {
		return .Alloc
	}
	c^ = {}
	c.cfg = conf
	c.allocator = allocator
	c.buf = buf
	reset(c, now)
	return .None
}

// Frees the buffers. The channel must not be used afterwards.
destroy :: proc(c: ^Channel) {
	delete(c.buf, c.allocator)
	c^ = {}
}

// Back to the state right after `init`: ids from the config, empty windows
// and lists, failure cleared, deadline re-armed from `now`. Keeps the buffers
// and the sids (including a peer sid set later).
reset :: proc(c: ^Channel, now: time.Duration) {
	c.failure = .None
	c.last_rx = now
	c.stats = {}
	c.held = false
	c.deadline_armed = c.cfg.hand_window > 0
	c.deadline = now + c.cfg.hand_window
	c.next_id = c.cfg.send_first_id
	c.send_slots = {}
	c.next_recv = c.cfg.recv_first_id
	c.recv_head = 0
	c.recv_used = 0
	c.recv_slots = {}
	c.pending = {}
	c.pending_n = 0
	c.recent = {}
	c.recent_n = 0
}

// Why the channel failed, or `.None`.
error :: proc(c: ^Channel) -> Failure {
	return c.failure
}

// Records the peer's session id. Call before the first `receive` of a message,
// and again only if the session layer decides to replace it.
set_peer_sid :: proc(c: ^Channel, sid: Sid) {
	c.cfg.peer_sid = sid
}

// True if the sid is not all zero (an all-zero sid is "undefined").
sid_defined :: proc(sid: Sid) -> bool {
	for b in sid {
		if b != 0 {
			return true
		}
	}
	return false
}

// Moves or sets the failure deadline, for example to extend the wait while
// the peer reports a pending authentication.
set_deadline :: proc(c: ^Channel, at: time.Duration) {
	c.deadline = at
	c.deadline_armed = true
}

// Removes the deadline. Call when the key state is ACTIVE.
clear_deadline :: proc(c: ^Channel) {
	c.deadline_armed = false
}

// Number of packets sent and not yet acknowledged.
outstanding :: proc(c: ^Channel) -> int {
	n := 0
	for s in c.send_slots {
		if s.used {
			n += 1
		}
	}
	return n
}

// True if everything we sent is acknowledged ("our send queue is empty").
all_acked :: proc(c: ^Channel) -> bool {
	return outstanding(c) == 0
}

// Ids received and not yet written into an ack array.
pending_acks :: proc(c: ^Channel) -> int {
	return c.pending_n
}

// Size budget for the payload of one packet.
//
//	min(2048, tls_mtu) - 1 opcode - 8 sid - ack bytes - 4 msg id
//	  - wrap_overhead - ip_overhead
//
// `tls_mtu` is `max-packet-size` (default 1250), clamped to 154..2048.
// `ack_ids` is how many ids the array may hold; leave it at 4 so the budget
// holds for any packet that carries data. The result can be small or zero; `send`
// still cuts pieces of at least 16 bytes.
payload_budget :: proc(tls_mtu, wrap_overhead, ip_overhead: int, ack_ids := ACK_PIGGY_MAX) -> int {
	mtu := clamp(tls_mtu, TLS_MTU_MIN, TLS_MTU_MAX)
	ack_bytes := 1
	if ack_ids > 0 {
		ack_bytes = 1 + 4 * min(ack_ids, ACK_LIST_MAX) + SID_LEN
	}
	return max(mtu - 1 - SID_LEN - ack_bytes - 4 - wrap_overhead - ip_overhead, 0)
}

// Where the payload of send slot `i` lives in the shared buffer.
@(private)
send_payload :: proc(c: ^Channel, i: int) -> []u8 {
	off := i * c.cfg.max_payload
	return c.buf[off:][:c.send_slots[i].len]
}

// Where the payload of receive slot `i` lives in the shared buffer.
@(private)
recv_store :: proc(c: ^Channel, i: int) -> []u8 {
	off := (SEND_WINDOW + i) * c.cfg.max_payload
	return c.buf[off:][:c.cfg.max_payload]
}
