// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package reliable

import "core:time"

// What `poll` hands back.
Tx_Kind :: enum {
	None,
	Control, // a packet that carries a message id (and maybe a payload)
	Ack, // a bare ack packet: no id, no payload
}

// One packet for the wire. The session layer adds the header fields and the
// wrapping. `payload` points into the channel and is valid until the next
// call into the channel.
Tx :: struct {
	kind:    Tx_Kind,
	id:      u32, // Control only: the message id (a retransmission keeps it)
	tag:     u8, // Control only: the tag given when the packet was queued
	payload: []u8, // Control only; may be empty
	acks:    Ack_List, // at most 4 ids on Control, at most 8 on Ack
	attempt: int, // Control only: 1 for the first send, 2 and up for retransmits
	fast:    bool, // Control only: sent early because of later acks
}

// Largest timeout a packet waits.
@(private)
backoff_cap :: proc(c: ^Channel) -> time.Duration {
	return c.cfg.timeout * BACKOFF_CAP_FACTOR
}

// How many new packets may be queued now: a free slot must exist and the
// next id must stay less than 6 above the oldest unacknowledged id
//. One stuck packet blocks the sender after 6 ids.
send_room :: proc(c: ^Channel) -> int {
	if c.failure != .None {
		return 0
	}
	used := 0
	span := 0 // next_id - oldest outstanding id
	for s in c.send_slots {
		if s.used {
			used += 1
			span = max(span, int(c.next_id - s.id))
		}
	}
	return max(SEND_WINDOW - max(used, span), 0)
}

// Queues exactly one packet with this payload (may be empty: an empty control
// packet is legal and uses an id). For resets, an empty packet that must carry
// acks, and a packet with its own budget. Returns the id given. `ok` is false if
// there is no room, the channel failed, or the payload is longer than
// `max_payload`.
send_packet :: proc(c: ^Channel, tag: u8, payload: []u8, now: time.Duration) -> (id: u32, ok: bool) {
	if len(payload) > c.cfg.max_payload || send_room(c) == 0 {
		return 0, false
	}
	for &s, i in c.send_slots {
		if s.used {
			continue
		}
		s = Send_Slot {
			used     = true,
			id       = c.next_id,
			tag      = tag,
			len      = len(payload),
			next_try = now, // a new packet is due at once
			timeout  = c.cfg.timeout,
		}
		copy(c.buf[i * c.cfg.max_payload:], payload)
		id = c.next_id
		c.next_id += 1
		return id, true
	}
	return 0, false
}

// Cuts TLS output into packets of at most `budget` payload bytes and queues as
// many as the window admits.
// - Returns the bytes taken. The caller keeps the rest (in the TLS library) and
//   offers it again later.
// - Piece boundaries ignore TLS records.
// - Budget below 16 is raised to 16; above `max_payload` is lowered.
//
// SPEC-GAP: the spec says "if free * payload_budget is below 16,
// send a 16 byte piece anyway" but not what happens when the budget is 12 and
// several packets are free. We always use a piece size of max(budget, 16).
//
// For a packet with a smaller budget (the one that carries a wrapped client key),
// pass a slice of at most that many bytes: it becomes one packet.
send :: proc(c: ^Channel, data: []u8, budget: int, tag: u8, now: time.Duration) -> (consumed: int) {
	piece := clamp(budget, MIN_PIECE, c.cfg.max_payload)
	for consumed < len(data) {
		n := min(len(data) - consumed, piece)
		if _, ok := send_packet(c, tag, data[consumed:][:n], now); !ok {
			break
		}
		consumed += n
	}
	return consumed
}

// While held, `poll` hands out nothing (acks included; nothing to ack before the
// first packet arrives). A TCP server holds its reset until the client's first
// packet arrives. Timers that fail the channel keep running.
set_hold :: proc(c: ^Channel, held: bool) {
	c.held = held
}

// Marks every queued packet due at once and resets its timeout to the first one
// ("burst"). Call it when the first valid hard reset of a
// link arrives. The layer does not remember the call; the session layer calls it
// at most once per session. Skipping it is allowed.
burst :: proc(c: ^Channel, now: time.Duration) {
	for &s in c.send_slots {
		if s.used {
			s.next_try = now
			s.timeout = c.cfg.timeout
		}
	}
}

// Applies one received ack array to the send half.
@(private)
apply_acks :: proc(c: ^Channel, acks: Ack_List) {
	for k in 0 ..< int(acks.count) {
		a := acks.ids[k]
		back := c.next_id - a // how far below next_id; wraps
		if back < 1 || back > RECV_WINDOW {
			c.stats.acks_ignored += 1
			continue
		}
		found := false
		for &s in c.send_slots {
			if s.used && s.id == a {
				s.used = false
				found = true
				break
			}
		}
		if !found {
			// Already acked, or never sent. It does not count
			// towards fast retransmit (SPEC-GAP).
			c.stats.acks_ignored += 1
			continue
		}
		c.stats.acks_applied += 1
		for &s in c.send_slots {
			if s.used && a - s.id < 1 << 31 && s.id != a {
				s.later_acks += 1
			}
		}
	}
}

// Checks the failure timers. Called at the start of every entry point that
// has a clock.
@(private)
check_timers :: proc(c: ^Channel, now: time.Duration) {
	if c.failure != .None {
		return
	}
	if c.deadline_armed && now >= c.deadline {
		c.failure = .Hand_Window
		return
	}
	if c.cfg.max_retransmits > 0 {
		for s in c.send_slots {
			if s.used && s.tx_count > c.cfg.max_retransmits && now >= s.next_try {
				c.failure = .Retransmit_Limit
				return
			}
		}
	}
}

// Returns the next packet to put on the wire now; `ok` is false if nothing to
// send. One packet per call: call until it says no.
//
// Order:
// 1. Lowest due id first. Due means `now >= next_try` or three acks for later
//    ids. Up to 4 ids from the ack lists go on it.
// 2. No packet due, acks pending: a bare ack packet with up to 8 ids.
// No ack delay: the caller polls right after `receive`. So queue anything that
// must carry the ack (e.g. the opcode 11 packet of a tls-crypt-v2 client, which
// may be empty) before polling. A poll with nothing queued sends a bare ack.
poll :: proc(c: ^Channel, now: time.Duration) -> (tx: Tx, ok: bool) {
	check_timers(c, now)
	if c.failure != .None || c.held {
		return {}, false
	}
	best := -1
	for s, i in c.send_slots {
		if !s.used || (now < s.next_try && s.later_acks < FAST_RETRANSMIT_ACKS) {
			continue
		}
		if best < 0 || i32(s.id - c.send_slots[best].id) < 0 {
			best = i
		}
	}
	if best >= 0 {
		s := &c.send_slots[best]
		fast := s.tx_count > 0 && now < s.next_try
		s.tx_count += 1
		tx = Tx {
			kind    = .Control,
			id      = s.id,
			tag     = s.tag,
			payload = send_payload(c, best),
			acks    = take_acks(c, ACK_PIGGY_MAX),
			attempt = s.tx_count,
			fast    = fast,
		}
		s.next_try = now + s.timeout
		s.timeout = min(s.timeout * 2, backoff_cap(c))
		s.later_acks = 0
		c.stats.tx_control += 1
		if s.tx_count > 1 {
			c.stats.retransmits += 1
		}
		if fast {
			c.stats.fast_retransmits += 1
		}
		return tx, true
	}
	if c.pending_n > 0 {
		c.stats.tx_ack += 1
		return Tx{kind = .Ack, acks = take_acks(c, ACK_LIST_MAX)}, true
	}
	return {}, false
}

// The time at which `poll` will have work (or a failure timer fires). `ok` is
// false if nothing is scheduled. Never before `now`; equal to `now` means "poll
// now". Call it after every `send`, `poll` and `receive`, and sleep until then.
next_wakeup :: proc(c: ^Channel, now: time.Duration) -> (at: time.Duration, ok: bool) {
	check_timers(c, now)
	if c.failure != .None {
		return 0, false
	}
	consider :: proc(at: ^time.Duration, ok: ^bool, t: time.Duration) {
		if !ok^ || t < at^ {
			at^ = t
			ok^ = true
		}
	}
	if c.deadline_armed {
		consider(&at, &ok, c.deadline)
	}
	if !c.held {
		if c.pending_n > 0 {
			consider(&at, &ok, now)
		}
		for s in c.send_slots {
			if !s.used {
				continue
			}
			consider(&at, &ok, now if s.later_acks >= FAST_RETRANSMIT_ACKS else s.next_try)
		}
	}
	return max(at, now), ok
}
