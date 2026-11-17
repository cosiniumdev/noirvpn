// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package reliable

import "core:time"

// One decoded control packet, as the session layer hands it in.
Rx :: struct {
	// The ack array of the packet (count 0 if it has none).
	acks:       Ack_List,
	// False for a bare ack packet: it has no message id and no payload.
	has_msg:    bool,
	id:         u32,
	// Opaque byte kept with the message and returned on delivery (the opcode).
	tag:        u8,
	// The opcode is a hard reset (7, 8 or 10): its id must be 0.
	hard_reset: bool,
	payload:    []u8, // copied into the channel; may be empty
}

// What `receive` did with a packet.
Rx_Status :: enum {
	Stored, // a new message was kept in its slot; its id is queued for an ack
	Duplicate, // already stored, or older than the next expected id; queued for an ack again
	Ack_Only, // a bare ack packet: acks applied, nothing else
	Ahead, // 12 or more ahead of the next expected id: dropped, no ack
	Window_Full, // all 12 slots in use: dropped, no ack (acks were applied)
	Bad_Reset_Id, // hard reset with an id other than 0: ignored, no ack (acks were applied)
	Bad_Ack_List, // count above 8: whole packet dropped
	Bad_Sid, // non-empty ack array with a sid that is not ours: whole packet dropped
	Oversize, // payload longer than `max_payload`: whole packet dropped
	Failed, // the channel is in a failure state
}

// Processes one valid, unwrapped control packet.
//
//  1. Ack list with count > 8, or non-empty with a sid other than `local_sid`:
//     drop the packet.
//  2. Apply the acks (all packets, duplicates included).
//  3. Bare ack: stop.
//  4. Receive window full: drop, no ack.
//  5. Hard reset with id != 0: ignore, no ack.
//  6. Window test, wrap-safe: `id - next_recv` below 12: store (once), ack. Older
//     id: ack. Rest: drop silently.
//
// Delivery is separate: call `pop` until it says no, else slots fill up and new
// messages get `.Window_Full`.
//
// SPEC-GAP notes (the spec is silent):
// - "unconsumed" slot = a slot `pop` has not taken.
// - `last_rx` (time of the last valid control packet) is set for every packet that
//   passes the ack check and is stored, a duplicate, or a bare ack. Not for
//   packets dropped as too far ahead, window full, or a bad reset id.
// - "older" means more than 2^31 behind (signed compare), not the spec's plain
//   `id < next_recv`, so it works across the 2^32 wrap. The two agree until a
//   session sends 2^31 packets.
receive :: proc(c: ^Channel, rx: Rx, now: time.Duration) -> Rx_Status {
	check_timers(c, now)
	if c.failure != .None {
		return .Failed
	}
	if rx.acks.count > ACK_LIST_MAX || (rx.acks.count > 0 && rx.acks.sid != c.cfg.local_sid) {
		c.stats.rx_bad_acks += 1
		return rx.acks.count > ACK_LIST_MAX ? .Bad_Ack_List : .Bad_Sid
	}
	if len(rx.payload) > c.cfg.max_payload {
		c.stats.rx_oversize += 1
		return .Oversize
	}
	apply_acks(c, rx.acks)
	if !rx.has_msg {
		c.last_rx = now
		return .Ack_Only
	}
	if c.recv_used >= RECV_WINDOW {
		c.stats.rx_window_full += 1
		return .Window_Full
	}
	if rx.hard_reset && rx.id != 0 {
		c.stats.rx_bad_reset += 1
		return .Bad_Reset_Id
	}
	d := rx.id - c.next_recv
	switch {
	case d < RECV_WINDOW:
		i := (c.recv_head + int(d)) % RECV_WINDOW
		s := &c.recv_slots[i]
		if s.used {
			c.stats.rx_duplicate += 1
			add_pending(c, rx.id)
			c.last_rx = now
			return .Duplicate
		}
		s^ = Recv_Slot {
			used = true,
			tag  = rx.tag,
			len  = len(rx.payload),
		}
		copy(recv_store(c, i), rx.payload)
		c.recv_used += 1
		c.stats.rx_stored += 1
		add_pending(c, rx.id)
		c.last_rx = now
		return .Stored
	case d >= 1 << 31:
		// Delivered long ago; its ack was probably lost.
		c.stats.rx_duplicate += 1
		add_pending(c, rx.id)
		c.last_rx = now
		return .Duplicate
	}
	c.stats.rx_ahead += 1
	return .Ahead
}

// A message delivered in order.
Delivery :: struct {
	id:      u32,
	tag:     u8,
	payload: []u8, // valid until the next `receive` or `reset`; may be empty
}

// Hands out the next message in id order, if it has arrived, and frees its
// slot. The stream the TLS library sees is the concatenation of the payloads.
// A reset (id 0, the tag of a reset opcode) is TLV data: it never goes to TLS.
pop :: proc(c: ^Channel) -> (d: Delivery, ok: bool) {
	if c.failure != .None {
		return {}, false
	}
	s := &c.recv_slots[c.recv_head]
	if !s.used {
		return {}, false
	}
	d = Delivery {
		id      = c.next_recv,
		tag     = s.tag,
		payload = recv_store(c, c.recv_head)[:s.len],
	}
	s.used = false
	c.recv_used -= 1
	c.recv_head = (c.recv_head + 1) % RECV_WINDOW
	c.next_recv += 1
	return d, true
}
